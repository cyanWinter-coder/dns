package dns

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fallbackServers starts a UDP and a TCP server on the same address, each
// with its own handler, and returns the shared address along with counters
// for the number of queries each server received.
func fallbackServers(t *testing.T, udpHandler, tcpHandler Handler) (addr string, udpQueries, tcpQueries *int32) {
	t.Helper()

	udpCount := new(int32)
	tcpCount := new(int32)

	udpSrv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			atomic.AddInt32(udpCount, 1)
			udpHandler.ServeDNS(w, r)
		})
	})
	if err != nil {
		t.Fatalf("unable to run UDP test server: %v", err)
	}
	t.Cleanup(func() { udpSrv.Shutdown() })

	tcpSrv, _, _, err := RunLocalTCPServer(addr, func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			atomic.AddInt32(tcpCount, 1)
			tcpHandler.ServeDNS(w, r)
		})
	})
	if err != nil {
		t.Fatalf("unable to run TCP test server: %v", err)
	}
	t.Cleanup(func() { tcpSrv.Shutdown() })

	return addr, udpCount, tcpCount
}

func truncatedReply(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetReply(r)
	m.Truncated = true
	w.WriteMsg(m)
}

func answerReply(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetReply(r)
	rr, err := NewRR("miek.nl. 3600 IN A 127.0.0.1")
	if err == nil {
		m.Answer = []RR{rr}
	}
	w.WriteMsg(m)
}

func TestClientTCPFallback(t *testing.T) {
	addr, udpQueries, tcpQueries := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(answerReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	r, rtt, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Truncated {
		t.Error("expected the full TCP response, got a truncated one")
	}
	if len(r.Answer) != 1 {
		t.Errorf("expected 1 answer from the TCP fallback, got %d", len(r.Answer))
	}
	if r.Id != m.Id {
		t.Errorf("expected response ID %d, got %d", m.Id, r.Id)
	}
	if !matchingQuestion(m, r) {
		t.Errorf("response question %v does not match query %v", r.Question, m.Question)
	}
	if rtt <= 0 {
		t.Error("expected a positive RTT covering both exchanges")
	}
	if got := atomic.LoadInt32(udpQueries); got != 1 {
		t.Errorf("expected 1 UDP query, got %d", got)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 1 {
		t.Errorf("expected 1 TCP fallback query, got %d", got)
	}
}

func TestClientTCPFallbackDisabled(t *testing.T) {
	addr, udpQueries, tcpQueries := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(answerReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	// A default client must return the truncated response as-is.
	c := new(Client)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response, got %v", r)
	}
	if got := atomic.LoadInt32(udpQueries); got != 1 {
		t.Errorf("expected 1 UDP query, got %d", got)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 0 {
		t.Errorf("expected no TCP fallback, got %d TCP queries", got)
	}
}

func TestClientTCPFallbackNotTruncated(t *testing.T) {
	addr, _, tcpQueries := fallbackServers(t,
		HandlerFunc(answerReply),
		HandlerFunc(answerReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || r.Truncated || len(r.Answer) != 1 {
		t.Errorf("expected the full UDP response, got %v", r)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 0 {
		t.Errorf("expected no TCP fallback for an untruncated response, got %d TCP queries", got)
	}
}

func TestClientTCPFallbackTruncatedTCPResponse(t *testing.T) {
	// A truncated TCP response must be returned as-is: the fallback is
	// performed at most once and never loops.
	addr, udpQueries, tcpQueries := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(truncatedReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated TCP response, got %v", r)
	}
	if got := atomic.LoadInt32(udpQueries); got != 1 {
		t.Errorf("expected 1 UDP query, got %d", got)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 1 {
		t.Errorf("expected exactly 1 TCP fallback query, got %d", got)
	}
}

func TestClientTCPFallbackTimeout(t *testing.T) {
	// The TCP server accepts the query but never responds; the fallback must
	// fail within the deadline of the original exchange.
	block := make(chan struct{})
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(func(w ResponseWriter, r *Msg) { <-block }),
	)
	defer close(block)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	const timeout = 500 * time.Millisecond
	c := &Client{TCPFallback: true, Timeout: timeout}

	start := time.Now()
	r, rtt, err := c.Exchange(m, addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from the stalled TCP fallback")
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *FallbackError, got %T: %v", err, err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("expected a timeout error from the TCP phase, got %v", fe.Err)
	}
	if fe.UDP == nil || !fe.UDP.Truncated {
		t.Errorf("expected the truncated UDP response in the FallbackError, got %v", fe.UDP)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response to be returned, got %v", r)
	}
	// The whole exchange, UDP and TCP phases combined, is bounded by the
	// original timeout: an unbounded fallback would take up to 2*timeout.
	if elapsed < timeout/2 {
		t.Errorf("exchange returned after %v, expected it to wait for the TCP timeout (%v)", elapsed, timeout)
	}
	if elapsed > timeout+300*time.Millisecond {
		t.Errorf("exchange took %v, exceeding the original deadline (%v)", elapsed, timeout)
	}
	if rtt > elapsed {
		t.Errorf("reported RTT %v exceeds the total elapsed time %v", rtt, elapsed)
	}
}

func TestClientTCPFallbackTCPError(t *testing.T) {
	// Only a UDP server is running; the TCP fallback cannot connect.
	udpSrv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(truncatedReply)
	})
	if err != nil {
		t.Fatalf("unable to run UDP test server: %v", err)
	}
	defer udpSrv.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	r, _, err := c.Exchange(m, addr)
	if err == nil {
		t.Fatal("expected an error from the TCP fallback")
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *FallbackError, got %T: %v", err, err)
	}
	var opErr *net.OpError
	if !errors.As(fe.Err, &opErr) {
		t.Errorf("expected a network error from the TCP phase, got %T: %v", fe.Err, fe.Err)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response to be returned, got %v", r)
	}
}

func TestClientTCPFallbackUDPError(t *testing.T) {
	// A failing UDP exchange must not trigger the fallback; its error is
	// returned unchanged.
	addr, _, tcpQueries := fallbackServers(t,
		HandlerFunc(func(w ResponseWriter, r *Msg) {
			w.Write([]byte{0xff}) // not a valid DNS message
		}),
		HandlerFunc(answerReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	_, _, err := c.Exchange(m, addr)
	if err == nil {
		t.Fatal("expected an error from the UDP exchange")
	}
	var fe *FallbackError
	if errors.As(err, &fe) {
		t.Errorf("expected the plain UDP error, got a *FallbackError: %v", err)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 0 {
		t.Errorf("expected no TCP fallback after a UDP error, got %d TCP queries", got)
	}
}

func TestClientTCPFallbackQuestionMismatch(t *testing.T) {
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(func(w ResponseWriter, r *Msg) {
			m := new(Msg)
			m.SetReply(r)
			m.Question[0].Name = "other.nl."
			w.WriteMsg(m)
		}),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	_, _, err := c.Exchange(m, addr)
	if err == nil {
		t.Fatal("expected an error for a mismatched fallback response")
	}
	if !errors.Is(err, ErrQuestion) {
		t.Errorf("expected ErrQuestion, got %v", err)
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Errorf("expected a *FallbackError, got %T: %v", err, err)
	}
}

func TestClientTCPFallbackIDMismatch(t *testing.T) {
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(func(w ResponseWriter, r *Msg) {
			m := new(Msg)
			m.SetReply(r)
			m.Id++
			w.WriteMsg(m)
		}),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	_, _, err := c.Exchange(m, addr)
	if err == nil {
		t.Fatal("expected an error for a fallback response with a bad ID")
	}
	if !errors.Is(err, ErrId) {
		t.Errorf("expected ErrId, got %v", err)
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Errorf("expected a *FallbackError, got %T: %v", err, err)
	}
}
