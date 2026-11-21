package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeUpstream is a minimal DNS server that listens on UDP and TCP on the
// same address and lets a test decide exactly what to send back. It counts
// the queries received per transport so tests can assert that a failing
// upstream is not contacted again while it is cooling down.
type fakeUpstream struct {
	t    *testing.T
	addr string
	pc   net.PacketConn
	ln   net.Listener

	udpN atomic.Int64
	tcpN atomic.Int64

	// handle returns the messages to send for one query. A nil reply means
	// "stay silent". It runs on the transport's read loop.
	handle func(network string, req *Msg) []*Msg
}

func newFakeUpstream(t *testing.T, handle func(network string, req *Msg) []*Msg) *fakeUpstream {
	t.Helper()
	if handle == nil {
		handle = func(string, *Msg) []*Msg { return nil }
	}

	var (
		ln  net.Listener
		pc  net.PacketConn
		err error
	)
	for i := 0; i < 20; i++ {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err = net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		ln.Close()
		ln = nil
	}
	if pc == nil || ln == nil {
		t.Fatalf("could not bind udp+tcp on one port: %v", err)
	}

	f := &fakeUpstream{t: t, addr: ln.Addr().String(), pc: pc, ln: ln, handle: handle}
	go f.serveUDP()
	go f.serveTCP()
	return f
}

func (f *fakeUpstream) serveUDP() {
	buf := make([]byte, MaxMsgSize)
	for {
		n, from, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := new(Msg)
		if req.Unpack(buf[:n]) != nil {
			continue
		}
		f.udpN.Add(1)
		for _, r := range f.handle("udp", req) {
			if r == nil {
				continue
			}
			out, err := r.Pack()
			if err != nil {
				continue
			}
			f.pc.WriteTo(out, from)
		}
	}
}

func (f *fakeUpstream) serveTCP() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.serveTCPConn(c)
	}
}

func (f *fakeUpstream) serveTCPConn(c net.Conn) {
	defer c.Close()
	for {
		var length uint16
		if err := binary.Read(c, binary.BigEndian, &length); err != nil {
			return
		}
		p := make([]byte, length)
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		req := new(Msg)
		if req.Unpack(p) != nil {
			continue
		}
		f.tcpN.Add(1)
		for _, r := range f.handle("tcp", req) {
			if r == nil {
				continue
			}
			out, err := r.Pack()
			if err != nil {
				continue
			}
			msg := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(msg, uint16(len(out)))
			copy(msg[2:], out)
			if _, err := c.Write(msg); err != nil {
				return
			}
		}
	}
}

func (f *fakeUpstream) close() {
	f.pc.Close()
	f.ln.Close()
}

// closeTCP stops accepting TCP connections while leaving UDP alive.
func (f *fakeUpstream) closeTCP() { f.ln.Close() }

func successfulReply(req *Msg) *Msg {
	m := new(Msg)
	m.SetReply(req)
	m.Answer = []RR{&TXT{
		Hdr: RR_Header{Name: req.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 60},
		Txt: []string{"ok"},
	}}
	return m
}

func rcodeReply(req *Msg, rcode int) *Msg {
	m := new(Msg)
	m.SetReply(req)
	m.Rcode = rcode
	return m
}

func newTestQuery(name string, qtype uint16) *Msg {
	m := new(Msg)
	m.SetQuestion(name, qtype)
	return m
}

func TestPoolFailoverAcrossServers(t *testing.T) {
	// Create the live upstream first and keep it bound, so the port of the
	// dead upstream cannot be reused by the OS when it is released.
	alive := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{successfulReply(req)}
	})
	defer alive.close()

	dead := newFakeUpstream(t, nil)
	deadAddr := dead.addr
	dead.close() // nothing listens on deadAddr any more

	p := &Pool{
		Servers:        []string{deadAddr, alive.addr},
		AttemptTimeout: 500 * time.Millisecond,
	}
	defer p.Close()

	m := newTestQuery("example.org.", TypeTXT)
	res, err := p.Exchange(m)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if res.Msg == nil || res.Msg.Rcode != RcodeSuccess {
		t.Fatalf("unexpected response: %v", res.Msg)
	}
	if res.Server != alive.addr {
		t.Errorf("final source = %q, want %q", res.Server, alive.addr)
	}
	if res.Network != "udp" {
		t.Errorf("final network = %q, want udp", res.Network)
	}
	if res.Attempts < 2 {
		t.Errorf("attempts = %d, want at least 2", res.Attempts)
	}
	if res.Msg.Id != m.Id {
		t.Errorf("response id = %d, want %d", res.Msg.Id, m.Id)
	}
}

func TestPoolCooldownIsPerTypeAndAddress(t *testing.T) {
	silent := newFakeUpstream(t, nil)
	defer silent.close()

	other := newFakeUpstream(t, nil)
	defer other.close()

	p := &Pool{
		Servers:        []string{silent.addr},
		AttemptTimeout: 40 * time.Millisecond,
		CooldownBase:   500 * time.Millisecond,
		CooldownMax:    time.Second,
	}
	defer p.Close()

	if _, err := p.Exchange(newTestQuery("example.org.", TypeTXT)); err == nil {
		t.Fatal("expected the silent upstream to time out")
	}
	if got := silent.udpN.Load(); got != 1 {
		t.Fatalf("udp queries after first exchange = %d, want 1", got)
	}

	// The second query must skip the cooled-down upstream entirely instead
	// of sending it more traffic.
	_, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err == nil {
		t.Fatal("expected the pool to run out of upstreams")
	}
	if !errors.Is(err, ErrNoUpstream) {
		t.Errorf("second exchange error = %v, want ErrNoUpstream", err)
	}
	if got := silent.udpN.Load(); got != 1 {
		t.Errorf("udp queries grew to %d while cooling down", got)
	}

	p.mu.Lock()
	udpState := p.states[stateKey("udp", silent.addr)]
	tcpState := p.stateForLocked("tcp", silent.addr)
	otherState := p.stateForLocked("udp", other.addr)
	udpCooling := udpState != nil && !udpState.cooldownUntil.IsZero()
	tcpCooling := !tcpState.cooldownUntil.IsZero()
	otherCooling := !otherState.cooldownUntil.IsZero()
	p.mu.Unlock()

	if !udpCooling {
		t.Error("udp upstream is not cooling down after a timeout")
	}
	if tcpCooling {
		t.Error("tcp upstream cooled down because of a udp failure")
	}
	if otherCooling {
		t.Error("unrelated address cooled down because of a udp failure")
	}
}

func TestPoolTruncationUpgradesOnceOverTCP(t *testing.T) {
	up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		if network == "udp" {
			m := new(Msg)
			m.SetReply(req)
			m.Truncated = true
			return []*Msg{m}
		}
		return []*Msg{successfulReply(req)}
	})
	defer up.close()

	p := &Pool{
		Servers:        []string{up.addr},
		AttemptTimeout: time.Second,
	}
	defer p.Close()

	m := newTestQuery("example.org.", TypeTXT)
	res, err := p.Exchange(m)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if res.Msg == nil || res.Msg.Truncated {
		t.Fatalf("expected a complete tcp answer, got %v", res.Msg)
	}
	if res.Network != "tcp" {
		t.Errorf("final network = %q, want tcp", res.Network)
	}
	if res.Server != up.addr {
		t.Errorf("final source = %q, want %q", res.Server, up.addr)
	}
	if got := up.udpN.Load(); got != 1 {
		t.Errorf("udp queries = %d, want 1", got)
	}
	if got := up.tcpN.Load(); got != 1 {
		t.Errorf("tcp queries = %d, want 1", got)
	}
}

func TestPoolTruncationUpgradeNotRepeated(t *testing.T) {
	first := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		m := new(Msg)
		m.SetReply(req)
		m.Truncated = true
		return []*Msg{m}
	})
	defer first.close()
	// The TCP upgrade for the first server fails, so the query moves on.
	first.closeTCP()

	second := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		if network == "udp" {
			m := new(Msg)
			m.SetReply(req)
			m.Truncated = true
			return []*Msg{m}
		}
		return []*Msg{successfulReply(req)}
	})
	defer second.close()

	p := &Pool{
		Servers:        []string{first.addr, second.addr},
		AttemptTimeout: time.Second,
	}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
	if res.Msg == nil || !res.Msg.Truncated {
		t.Fatalf("expected the truncated response to be retained, got %v", res.Msg)
	}
	if res.Server != second.addr {
		t.Errorf("final source = %q, want %q", res.Server, second.addr)
	}
	if got := first.udpN.Load(); got != 1 {
		t.Errorf("first udp queries = %d, want 1", got)
	}
	// The TCP upgrade was already spent on the first server; the second
	// truncated answer must not trigger another one.
	if got := second.tcpN.Load(); got != 0 {
		t.Errorf("second tcp queries = %d, want 0 (upgrade repeated)", got)
	}
	if got := second.udpN.Load(); got != 1 {
		t.Errorf("second udp queries = %d, want 1", got)
	}
}

func TestPoolDiscardsLateAndMismatchedPackets(t *testing.T) {
	t.Run("late id", func(t *testing.T) {
		up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
			late := successfulReply(req)
			late.Id = req.Id ^ 0xffff
			return []*Msg{late, successfulReply(req)}
		})
		defer up.close()

		p := &Pool{Servers: []string{up.addr}, AttemptTimeout: time.Second}
		defer p.Close()

		m := newTestQuery("example.org.", TypeTXT)
		res, err := p.Exchange(m)
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}
		if res.Msg == nil || res.Msg.Id != m.Id {
			t.Fatalf("returned id = %v, want %d", res.Msg, m.Id)
		}
	})

	t.Run("mismatched name", func(t *testing.T) {
		up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
			wrong := successfulReply(req)
			wrong.Question[0].Name = "other.example."
			return []*Msg{wrong, successfulReply(req)}
		})
		defer up.close()

		p := &Pool{Servers: []string{up.addr}, AttemptTimeout: time.Second}
		defer p.Close()

		m := newTestQuery("example.org.", TypeTXT)
		res, err := p.Exchange(m)
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}
		if res.Msg == nil || res.Msg.Question[0].Name != "example.org." {
			t.Fatalf("wrong question returned: %v", res.Msg)
		}
	})

	t.Run("mismatched type is never returned", func(t *testing.T) {
		up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
			wrong := successfulReply(req)
			wrong.Question[0].Qtype = TypeA
			return []*Msg{wrong}
		})
		defer up.close()

		p := &Pool{Servers: []string{up.addr}, AttemptTimeout: 60 * time.Millisecond}
		defer p.Close()

		res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
		if err == nil {
			t.Fatal("expected the mismatched answer to be rejected")
		}
		if res.Msg != nil {
			t.Fatalf("mismatched answer was returned: %v", res.Msg)
		}
		if !errors.Is(err, ErrRetriesExhausted) {
			t.Errorf("error = %v, want ErrRetriesExhausted", err)
		}
	})
}

func TestPoolRejectsResponseFromStaleGeneration(t *testing.T) {
	started := make(chan struct{}, 1)
	up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		if network != "udp" {
			return nil
		}
		started <- struct{}{}
		time.Sleep(150 * time.Millisecond)
		return []*Msg{successfulReply(req)}
	})
	defer up.close()

	p := &Pool{
		Servers:        []string{up.addr},
		AttemptTimeout: time.Second,
	}
	defer p.Close()

	type outcome struct {
		res *PoolResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
		ch <- outcome{res, err}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query never reached the upstream")
	}

	// Simulate a concurrent state change (for example another query cooling
	// this upstream down) while the response is still in flight.
	p.mu.Lock()
	p.states[stateKey("udp", up.addr)].generation++
	p.mu.Unlock()

	select {
	case got := <-ch:
		if got.err == nil {
			t.Fatal("a response from a stale generation was accepted")
		}
		if got.res.Msg != nil {
			t.Fatalf("stale response returned: %v", got.res.Msg)
		}
		if !errors.Is(got.err, errStaleResponse) {
			t.Errorf("error = %v, want errStaleResponse in chain", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query did not finish")
	}
}

func TestPoolSharedDeadlineAndRetryBudget(t *testing.T) {
	a := newFakeUpstream(t, nil)
	defer a.close()
	b := newFakeUpstream(t, nil)
	defer b.close()

	p := &Pool{
		Servers:        []string{a.addr, b.addr},
		AttemptTimeout: time.Second, // much larger than the overall budget
		Timeout:        120 * time.Millisecond,
	}
	defer p.Close()

	start := time.Now()
	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the shared deadline to be exhausted")
	}
	if !errors.Is(err, ErrRetriesExhausted) {
		t.Errorf("error = %v, want ErrRetriesExhausted", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded in chain", err)
	}
	if elapsed > time.Second {
		t.Errorf("query took %v, retries did not share the original deadline", elapsed)
	}
	// The first attempt alone consumed the budget; no retry can extend it.
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
}

func TestPoolAttemptBudgetIsShared(t *testing.T) {
	a := newFakeUpstream(t, nil)
	defer a.close()
	b := newFakeUpstream(t, nil)
	defer b.close()

	p := &Pool{
		Servers:        []string{a.addr, b.addr},
		Attempts:       1,
		AttemptTimeout: 40 * time.Millisecond,
	}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err == nil {
		t.Fatal("expected failure")
	}
	if !errors.Is(err, ErrRetriesExhausted) {
		t.Errorf("error = %v, want ErrRetriesExhausted", err)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
	if got := a.udpN.Load() + b.udpN.Load(); got != 1 {
		t.Errorf("upstreams contacted = %d, want 1", got)
	}
}

func TestPoolSERVFAILRetriesOtherUpstream(t *testing.T) {
	bad := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{rcodeReply(req, RcodeServerFailure)}
	})
	defer bad.close()
	good := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{successfulReply(req)}
	})
	defer good.close()

	p := &Pool{Servers: []string{bad.addr, good.addr}, AttemptTimeout: time.Second}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if res.Server != good.addr {
		t.Errorf("final source = %q, want %q", res.Server, good.addr)
	}
	if res.Msg.Rcode != RcodeSuccess {
		t.Errorf("rcode = %v, want success", res.Msg.Rcode)
	}
	if got := bad.udpN.Load(); got != 1 {
		t.Errorf("servfail upstream queried %d times, want 1", got)
	}

	// A server that answered SERVFAIL is reachable and must not be cooled
	// down.
	p.mu.Lock()
	st := p.states[stateKey("udp", bad.addr)]
	cooling := st != nil && !st.cooldownUntil.IsZero()
	p.mu.Unlock()
	if cooling {
		t.Error("servfail upstream was cooled down")
	}
}

func TestPoolReturnsFinalSERVFAILSource(t *testing.T) {
	bad := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{rcodeReply(req, RcodeServerFailure)}
	})
	defer bad.close()

	p := &Pool{Servers: []string{bad.addr}, AttemptTimeout: time.Second}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err != nil {
		t.Fatalf("a SERVFAIL response is still an answer: %v", err)
	}
	if res.Msg == nil || res.Msg.Rcode != RcodeServerFailure {
		t.Fatalf("unexpected response: %v", res.Msg)
	}
	if res.Server != bad.addr {
		t.Errorf("final source = %q, want %q", res.Server, bad.addr)
	}
}

func TestPoolRefusedIsFinal(t *testing.T) {
	refusing := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{rcodeReply(req, RcodeRefused)}
	})
	defer refusing.close()
	other := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{successfulReply(req)}
	})
	defer other.close()

	p := &Pool{Servers: []string{refusing.addr, other.addr}, AttemptTimeout: time.Second}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err != nil {
		t.Fatalf("Exchange returned an error for a final REFUSED: %v", err)
	}
	if res.Msg == nil || res.Msg.Rcode != RcodeRefused {
		t.Fatalf("unexpected response: %v", res.Msg)
	}
	if res.Server != refusing.addr {
		t.Errorf("final source = %q, want %q", res.Server, refusing.addr)
	}
	if got := other.udpN.Load(); got != 0 {
		t.Errorf("permission rejection was retried on %d other upstreams", got)
	}
}

func TestPoolConcurrentCancellationReleasesWaiters(t *testing.T) {
	silent := newFakeUpstream(t, nil)
	defer silent.close()

	p := &Pool{Servers: []string{silent.addr}, AttemptTimeout: 5 * time.Second}
	defer p.Close()

	const n = 8
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.ExchangeContext(ctx, newTestQuery("example.org.", TypeTXT))
			errs[i] = err
		}(i)
	}

	// Give the queries time to block on their reads before cancelling.
	deadline := time.Now().Add(time.Second)
	for silent.udpN.Load() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	cancel()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not release all waiters")
	}

	for i, err := range errs {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waiter %d error = %v, want context.Canceled", i, err)
		}
	}

	p.mu.Lock()
	waiting := len(p.waiters)
	p.mu.Unlock()
	if waiting != 0 {
		t.Errorf("%d waiters still registered after cancellation", waiting)
	}
}

func TestPoolCloseWakesAllWaiters(t *testing.T) {
	silent := newFakeUpstream(t, nil)
	defer silent.close()

	p := &Pool{Servers: []string{silent.addr}, AttemptTimeout: 5 * time.Second}

	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
			errs[i] = err
		}(i)
	}

	deadline := time.Now().Add(time.Second)
	for silent.udpN.Load() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake all waiters")
	}

	for i, err := range errs {
		if !errors.Is(err, ErrPoolClosed) {
			t.Errorf("waiter %d error = %v, want ErrPoolClosed", i, err)
		}
	}

	if _, err := p.Exchange(newTestQuery("example.org.", TypeTXT)); !errors.Is(err, ErrPoolClosed) {
		t.Errorf("Exchange after Close error = %v, want ErrPoolClosed", err)
	}
}

func TestPoolNoServers(t *testing.T) {
	p := &Pool{}
	defer p.Close()

	if _, err := p.Exchange(newTestQuery("example.org.", TypeTXT)); !errors.Is(err, ErrNoUpstream) {
		t.Errorf("error = %v, want ErrNoUpstream", err)
	}
}

func TestPoolPermissionErrorIsFinal(t *testing.T) {
	other := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{successfulReply(req)}
	})
	defer other.close()

	// A local policy failure while dialing: no upstream exchange happens,
	// and the pool must not retry elsewhere.
	p := &Pool{
		Servers: []string{"192.0.2.1:53", other.addr},
		Client: &Client{Dialer: &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				return os.ErrPermission
			},
		}},
		AttemptTimeout: time.Second,
	}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error = %v, want os.ErrPermission", err)
	}
	var perr *PoolError
	if !errors.As(err, &perr) {
		t.Fatalf("error type = %T, want *PoolError", err)
	}
	if perr.Source != "192.0.2.1:53" {
		t.Errorf("final source = %q, want the first upstream", perr.Source)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
	if got := other.udpN.Load(); got != 0 {
		t.Errorf("permission failure was retried on %d other upstreams", got)
	}
}

func TestPoolAllUpstreamsFailRetainsFinalSource(t *testing.T) {
	a := newFakeUpstream(t, nil)
	defer a.close()
	b := newFakeUpstream(t, nil)
	defer b.close()
	c := newFakeUpstream(t, nil)
	defer c.close()

	p := &Pool{
		Servers:        []string{a.addr, b.addr, c.addr},
		AttemptTimeout: 40 * time.Millisecond,
		CooldownBase:   time.Minute,
	}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err == nil {
		t.Fatal("expected all upstreams to fail")
	}
	if !errors.Is(err, ErrRetriesExhausted) {
		t.Errorf("error = %v, want ErrRetriesExhausted", err)
	}
	var perr *PoolError
	if !errors.As(err, &perr) {
		t.Fatalf("error type = %T, want *PoolError", err)
	}
	if perr.Source != c.addr {
		t.Errorf("final source = %q, want %q", perr.Source, c.addr)
	}
	if res.Attempts != 3 || len(perr.Attempts) != 3 {
		t.Errorf("attempts = %d/%d, want 3/3", res.Attempts, len(perr.Attempts))
	}
	for i, want := range []string{a.addr, b.addr, c.addr} {
		if perr.Attempts[i].Server != want {
			t.Errorf("attempt %d server = %q, want %q", i, perr.Attempts[i].Server, want)
		}
	}
	// All three are now cooling down.
	for _, addr := range []string{a.addr, b.addr, c.addr} {
		p.mu.Lock()
		cooling := p.states[stateKey("udp", addr)].cooldownUntil.After(time.Now())
		p.mu.Unlock()
		if !cooling {
			t.Errorf("upstream %s is not cooling down", addr)
		}
	}
}

func TestPoolTCPUpgradeFailureDoesNotCoolUDP(t *testing.T) {
	up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		if network == "udp" {
			m := new(Msg)
			m.SetReply(req)
			m.Truncated = true
			return []*Msg{m}
		}
		return []*Msg{successfulReply(req)}
	})
	up.closeTCP()
	defer up.close()

	p := &Pool{Servers: []string{up.addr}, AttemptTimeout: 200 * time.Millisecond}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
	if res.Msg == nil || !res.Msg.Truncated {
		t.Fatalf("truncated response was not retained: %v", res.Msg)
	}
	if res.Network != "udp" || res.Server != up.addr {
		t.Errorf("final source = %s/%s, want udp/%s", res.Network, res.Server, up.addr)
	}

	p.mu.Lock()
	udpCooling := !p.states[stateKey("udp", up.addr)].cooldownUntil.IsZero()
	tcpCooling := !p.states[stateKey("tcp", up.addr)].cooldownUntil.IsZero()
	p.mu.Unlock()
	if udpCooling {
		t.Error("udp upstream cooled down because the tcp upgrade failed")
	}
	if !tcpCooling {
		t.Error("failed tcp upgrade did not cool the tcp state down")
	}
}

func TestIsPermissionError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"permission", os.ErrPermission, true},
		{"wrapped", fmt.Errorf("dial: %w", os.ErrPermission), true},
		{"timeout", errTimeout{}, false},
	} {
		if got := isPermissionError(tc.err); got != tc.want {
			t.Errorf("%s: isPermissionError = %v, want %v", tc.name, got, tc.want)
		}
	}
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func TestPoolDuplicateServersIgnored(t *testing.T) {
	up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		return []*Msg{successfulReply(req)}
	})
	defer up.close()

	p := &Pool{Servers: []string{up.addr, up.addr}, AttemptTimeout: time.Second}
	defer p.Close()

	res, err := p.Exchange(newTestQuery("example.org.", TypeTXT))
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 (duplicates must be ignored)", res.Attempts)
	}
}

// TestClientExchangeUnaffected guards the compatibility promise: the
// existing Client.Exchange API keeps its original semantics (no retry, no
// TCP fallback).
func TestClientExchangeUnaffected(t *testing.T) {
	up := newFakeUpstream(t, func(network string, req *Msg) []*Msg {
		m := new(Msg)
		m.SetReply(req)
		m.Truncated = true
		return []*Msg{m}
	})
	defer up.close()

	c := new(Client)
	r, _, err := c.Exchange(newTestQuery("example.org.", TypeTXT), up.addr)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if r == nil || !r.Truncated {
		t.Fatalf("Client.Exchange should return the truncated response unchanged, got %v", r)
	}
	if got := up.tcpN.Load(); got != 0 {
		t.Errorf("Client.Exchange unexpectedly used TCP %d times", got)
	}
}
