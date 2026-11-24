package dns_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type uid533UDPServer struct {
	addr    string
	pc      net.PacketConn
	queries atomic.Int64
	silent  bool
}

func newUID533UDPServer(t *testing.T, silent bool) *uid533UDPServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &uid533UDPServer{addr: pc.LocalAddr().String(), pc: pc, silent: silent}
	go s.serve()
	t.Cleanup(func() { pc.Close() })
	return s
}

func (s *uid533UDPServer) serve() {
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		s.queries.Add(1)
		if s.silent {
			continue
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		out, err := resp.Pack()
		if err != nil {
			continue
		}
		_, _ = s.pc.WriteTo(out, from)
	}
}

type uid533TCPServer struct {
	addr              string
	ln                net.Listener
	accepted          atomic.Int64
	queries           atomic.Int64
	closeAfterReply   bool
	silent            bool
	firstConnDone     chan struct{}
	firstConnDoneOnce sync.Once
}

func newUID533TCPServer(t *testing.T, closeAfterReply bool) *uid533TCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	s := &uid533TCPServer{
		addr:            ln.Addr().String(),
		ln:              ln,
		closeAfterReply: closeAfterReply,
		firstConnDone:   make(chan struct{}),
	}
	go s.serveAccept()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *uid533TCPServer) serveAccept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		go s.serveConn(c)
	}
}

func (s *uid533TCPServer) serveConn(c net.Conn) {
	defer c.Close()
	defer s.firstConnDoneOnce.Do(func() { close(s.firstConnDone) })

	for {
		var length uint16
		if err := binary.Read(c, binary.BigEndian, &length); err != nil {
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		s.queries.Add(1)

		req := new(dns.Msg)
		if err := req.Unpack(payload); err != nil {
			return
		}
		if s.silent {
			// Block in the next length read until the client gives up/closes.
			continue
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		out, err := resp.Pack()
		if err != nil {
			return
		}
		frame := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(frame, uint16(len(out)))
		copy(frame[2:], out)
		if _, err := c.Write(frame); err != nil {
			return
		}
		if s.closeAfterReply {
			return
		}
	}
}

func uid533TestQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	return m
}

func TestUID533ExchangeServersFailoverOnTimeout(t *testing.T) {
	silent := newUID533UDPServer(t, true)
	alive := newUID533UDPServer(t, false)

	c := &dns.Client{Timeout: 40 * time.Millisecond}
	start := time.Now()
	r, _, err := c.ExchangeServersContext(context.Background(), uid533TestQuery(), []string{silent.addr, alive.addr})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected failover to alive server, got %v", err)
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected response: %v", r)
	}
	if silent.queries.Load() == 0 {
		t.Error("expected timed-out server to receive at least one query")
	}
	if got := alive.queries.Load(); got != 1 {
		t.Errorf("alive server queries = %d, want 1", got)
	}
	if elapsed > time.Second {
		t.Errorf("failover took %v; per-attempt timeout was not applied", elapsed)
	}
}

func TestUID533ExchangeServersAllFailedKeepsLastError(t *testing.T) {
	silentTCP := newUID533TCPServer(t, false)
	silentTCP.silent = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lastAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	c := &dns.Client{Net: "tcp", Timeout: 30 * time.Millisecond}
	start := time.Now()
	_, _, err = c.ExchangeServersContext(context.Background(), uid533TestQuery(), []string{silentTCP.addr, lastAddr})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected all servers to fail")
	}
	if elapsed > time.Second {
		t.Fatalf("retry took too long: %v", elapsed)
	}

	var retryErr *dns.RetryError
	if !errors.As(err, &retryErr) {
		t.Fatalf("error type %T, want *dns.RetryError", err)
	}
	if !errors.Is(err, dns.ErrAllServersFailed) {
		t.Error("error should match dns.ErrAllServersFailed")
	}
	if retryErr.Server != lastAddr {
		t.Errorf("last server = %q, want %q", retryErr.Server, lastAddr)
	}
	if retryErr.Err == nil || retryErr.LastErr == nil {
		t.Fatalf("last error was not retained: %+v", retryErr)
	}
	if !errors.Is(err, retryErr.Err) {
		t.Error("errors.Is should find the final attempt error")
	}
	if got := retryErr.Err.Error(); !strings.Contains(got, "connection refused") {
		t.Errorf("last error %q does not contain connection refusal details", got)
	}
	if len(retryErr.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(retryErr.Attempts))
	}
}

func TestUID533ExchangeServersTimeoutErrorIsDiscoverable(t *testing.T) {
	first := newUID533UDPServer(t, true)
	second := newUID533UDPServer(t, true)

	c := &dns.Client{Timeout: 20 * time.Millisecond}
	_, _, err := c.ExchangeServersContext(context.Background(), uid533TestQuery(), []string{first.addr, second.addr})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v does not wrap context.DeadlineExceeded", err)
	}
	var retryErr *dns.RetryError
	if !errors.As(err, &retryErr) || len(retryErr.Attempts) != 2 {
		t.Fatalf("expected two RetryError attempts, got %#v", err)
	}
}

func TestUID533RetryClientReusesTCPConnection(t *testing.T) {
	srv := newUID533TCPServer(t, false)
	rc := &dns.RetryClient{
		Client:  dns.Client{Net: "tcp", Timeout: time.Second},
		Servers: []string{srv.addr},
	}
	defer rc.Close()

	for i := 0; i < 2; i++ {
		r, _, err := rc.QueryContext(context.Background(), uid533TestQuery())
		_ = r
		if err != nil {
			t.Fatalf("exchange %d failed: %v", i+1, err)
		}
	}
	if got := srv.accepted.Load(); got != 1 {
		t.Errorf("accepted TCP connections = %d, want 1", got)
	}
	if got := srv.queries.Load(); got != 2 {
		t.Errorf("TCP queries = %d, want 2", got)
	}
}

func TestUID533ClientReuseConnectionsField(t *testing.T) {
	srv := newUID533TCPServer(t, false)
	c := &dns.Client{Net: "tcp", Timeout: time.Second, ReuseConnections: true}
	defer c.CloseIdleConnections()

	for i := 0; i < 2; i++ {
		_, _, err := c.ExchangeContext(context.Background(), uid533TestQuery(), srv.addr)
		if err != nil {
			t.Fatalf("exchange %d failed: %v", i+1, err)
		}
	}
	if got := srv.accepted.Load(); got != 1 {
		t.Errorf("accepted TCP connections = %d, want 1", got)
	}
}

func TestUID533RetryClientDiscardsClosedTCPConnection(t *testing.T) {
	srv := newUID533TCPServer(t, true)
	rc := &dns.RetryClient{
		Client:  dns.Client{Net: "tcp", Timeout: time.Second},
		Servers: []string{srv.addr},
	}
	defer rc.Close()

	if _, _, err := rc.QueryContext(context.Background(), uid533TestQuery()); err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}

	// Give the server's FIN time to become available to the liveness probe.
	time.Sleep(75 * time.Millisecond)

	if _, _, err := rc.QueryContext(context.Background(), uid533TestQuery()); err != nil {
		t.Fatalf("second exchange should redial after stale conn: %v", err)
	}
	if got := srv.accepted.Load(); got != 2 {
		t.Errorf("accepted TCP connections = %d, want replacement dial (2)", got)
	}
	if got := srv.queries.Load(); got != 2 {
		t.Errorf("TCP queries = %d, want 2", got)
	}
}

func TestUID533ExchangeServersAlreadyCanceledDoesNotContactServer(t *testing.T) {
	srv := newUID533UDPServer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := new(dns.Client).ExchangeServersContext(ctx, uid533TestQuery(), []string{srv.addr})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := srv.queries.Load(); got != 0 {
		t.Fatalf("server contacted %d times after cancellation", got)
	}
}

func TestUID533ClientExchangeUsesReusePool(t *testing.T) {
	srv := newUID533TCPServer(t, false)
	c := &dns.Client{Net: "tcp", Timeout: time.Second, ReuseConnections: true}
	defer c.CloseIdleConnections()

	for i := 0; i < 2; i++ {
		_, _, err := c.Exchange(uid533TestQuery(), srv.addr)
		if err != nil {
			t.Fatalf("Exchange %d failed: %v", i+1, err)
		}
	}
	if got := srv.accepted.Load(); got != 1 {
		t.Errorf("accepted TCP connections = %d, want 1", got)
	}
}

func TestUID533ConnPoolConcurrentExchanges(t *testing.T) {
	srv := newUID533TCPServer(t, false)
	c := &dns.Client{Net: "tcp", Timeout: time.Second, ReuseConnections: true}
	defer c.CloseIdleConnections()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				r, _, err := c.ExchangeContext(context.Background(), uid533TestQuery(), srv.addr)
				if err != nil {
					t.Errorf("concurrent exchange failed: %v", err)
					return
				}
				if r == nil {
					t.Error("nil response")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestUID533RetryClientContextCancelClosesConnectionAndStops(t *testing.T) {
	srv := newUID533TCPServer(t, false)
	srv.silent = true
	rc := &dns.RetryClient{
		Client:  dns.Client{Net: "tcp", Timeout: 30 * time.Second},
		Servers: []string{srv.addr},
	}
	defer rc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := rc.QueryContext(ctx, uid533TestQuery())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not wrap context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("cancellation took %v, want immediate return", elapsed)
	}

	select {
	case <-srv.firstConnDone:
	case <-time.After(time.Second):
		t.Fatal("server-side connection was not closed after context cancellation")
	}
}
