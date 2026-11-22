package dns

import (
	"context"
	"errors"
	"net"
	"sync"
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

	// The TCP port is the one the kernel picked for UDP, which may still be
	// held by a previous test's listener in TIME_WAIT. Retry with a fresh
	// UDP port when the TCP bind races.
	for attempt := 0; ; attempt++ {
		udpSrv, udpAddr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
			s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
				atomic.AddInt32(udpCount, 1)
				udpHandler.ServeDNS(w, r)
			})
		})
		if err != nil {
			t.Fatalf("unable to run UDP test server: %v", err)
		}

		tcpSrv, _, _, err := RunLocalTCPServer(udpAddr, func(s *Server) {
			s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
				atomic.AddInt32(tcpCount, 1)
				tcpHandler.ServeDNS(w, r)
			})
		})
		if err == nil {
			t.Cleanup(func() { udpSrv.Shutdown() })
			t.Cleanup(func() { tcpSrv.Shutdown() })
			return udpAddr, udpCount, tcpCount
		}

		udpSrv.Shutdown()
		if attempt == 20 {
			t.Fatalf("unable to run TCP test server: %v", err)
		}
	}
}

func truncatedReply(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetReply(r)
	m.Truncated = true
	w.WriteMsg(m)
}

func answeredReply(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetReply(r)
	rr, err := NewRR("miek.nl. 3600 IN A 127.0.0.1")
	if err == nil {
		m.Answer = []RR{rr}
	}
	w.WriteMsg(m)
}

func TestOutcomeGateDeliversOnce(t *testing.T) {
	gate := newOutcomeGate()
	want := new(Msg)
	want.Id = 1

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gate.deliver(want, nil)
		}()
	}
	wg.Wait()

	got, err := gate.wait()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected the first delivered message, got %v", got)
	}
	// A second completion must be dropped, not block and not replace the
	// result. The channel holds exactly one value.
	gate.deliver(nil, ErrId)
	if n := len(gate.ch); n != 0 {
		t.Fatalf("expected the gate to hold no extra outcome, holds %d", n)
	}
}

func TestMessageIDReassignedOnReuse(t *testing.T) {
	co := new(Conn) // no net.Conn: assignMessageID never touches it

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)
	first := m.Id

	if got := co.assignMessageID(m); got != first || m.Id != first {
		t.Fatalf("first assignment changed the ID: got %d, m.Id %d, want %d", got, m.Id, first)
	}
	second := co.assignMessageID(m)
	if second == first || m.Id != second {
		t.Fatalf("reused ID was not reassigned: got %d, m.Id %d, first %d", second, m.Id, first)
	}
	if len(co.queryIDs) != 2 {
		t.Fatalf("expected both IDs to be remembered, got %d", len(co.queryIDs))
	}

	// A different message keeps its own unused ID.
	other := new(Msg)
	other.SetQuestion("example.nl.", TypeA)
	if got := co.assignMessageID(other); got != other.Id {
		t.Fatalf("unused ID was reassigned: got %d, m.Id %d", got, other.Id)
	}
}

func TestMessageIDKeptForTSIG(t *testing.T) {
	co := new(Conn)
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)
	m.SetTsig("axfr.", HmacSHA256, 300, time.Now().Unix())

	id := m.Id
	co.assignMessageID(m)
	if got := co.assignMessageID(m); got != id {
		t.Fatalf("TSIG message ID was reassigned: got %d, want %d", got, id)
	}
}

func TestExchangeGenerationIsolation(t *testing.T) {
	co := new(Conn)
	g1 := co.beginExchange()
	if !co.generationIs(g1) {
		t.Fatal("fresh generation should be current")
	}
	g2 := co.beginExchange()
	if co.generationIs(g1) {
		t.Fatal("earlier generation must not be current after a new exchange")
	}
	co.endExchange(g1)
	if !co.generationIs(g2) {
		t.Fatal("ending an earlier generation must not retire the current one")
	}
	co.endExchange(g2)
	if co.generationIs(g2) {
		t.Fatal("ended generation must no longer be current")
	}
}

func TestQueryBudgetUsesOriginalDeadline(t *testing.T) {
	c := &Client{Timeout: time.Minute}
	start := time.Now()

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(10*time.Second))
	defer cancel()

	budget, bcancel := c.newQueryBudget(ctx, start)
	defer bcancel()

	want := start.Add(10 * time.Second)
	if !budget.deadline.Equal(want) {
		t.Fatalf("budget deadline = %v, want the caller's deadline %v", budget.deadline, want)
	}

	// The client timeout wins when it expires earlier.
	c = &Client{Timeout: time.Second}
	budget, bcancel = c.newQueryBudget(context.Background(), start)
	defer bcancel()
	if !budget.deadline.Equal(start.Add(time.Second)) {
		t.Fatalf("budget deadline = %v, want %v", budget.deadline, start.Add(time.Second))
	}
}

func TestClientTCPFallback(t *testing.T) {
	addr, udpQueries, tcpQueries := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(answeredReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true}
	r, rtt, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || r.Truncated || len(r.Answer) != 1 {
		t.Fatalf("expected the full TCP answer, got %v", r)
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
		HandlerFunc(answeredReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	r, _, err := new(Client).Exchange(m, addr)
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

func TestClientTCPFallbackOnlyOnce(t *testing.T) {
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

func TestClientTCPFallbackSharedDeadline(t *testing.T) {
	// The TCP server accepts the query but never answers. The fallback must
	// finish within the original timeout, not add a second one.
	block := make(chan struct{})
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(func(w ResponseWriter, r *Msg) { <-block }),
	)
	defer close(block)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	const timeout = 400 * time.Millisecond
	c := &Client{TCPFallback: true, Timeout: timeout}

	start := time.Now()
	r, rtt, err := c.Exchange(m, addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a fallback error")
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *FallbackError, got %T: %v", err, err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("expected a timeout, got %v", fe.Err)
	}
	if fe.UDP == nil || !fe.UDP.Truncated {
		t.Errorf("expected the truncated UDP response in the error, got %v", fe.UDP)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response to be returned, got %v", r)
	}
	if elapsed < timeout/2 {
		t.Errorf("returned after %v, expected to wait for the shared timeout %v", elapsed, timeout)
	}
	if elapsed > timeout+250*time.Millisecond {
		t.Errorf("exchange took %v, exceeding the original deadline %v", elapsed, timeout)
	}
	if rtt > elapsed {
		t.Errorf("reported RTT %v exceeds elapsed %v", rtt, elapsed)
	}
}

func TestClientTCPFallbackCancellation(t *testing.T) {
	// Cancelling the caller during the TCP fallback must abort it promptly
	// and report cancellation, without waiting for the shared deadline.
	release := make(chan struct{})
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(func(w ResponseWriter, r *Msg) { <-release }),
	)
	defer close(release)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Cancel as soon as the TCP phase is underway; the UDP phase
		// returns immediately, so a short delay lands inside the fallback.
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	c := &Client{TCPFallback: true, Timeout: 5 * time.Second}

	start := time.Now()
	r, _, err := c.ExchangeContext(ctx, m, addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *FallbackError, got %T: %v", err, err)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response to be returned, got %v", r)
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took %v, expected a prompt return", elapsed)
	}
}

func TestClientTCPFallbackConnectionError(t *testing.T) {
	// Only a UDP server is running: the TCP fallback cannot connect.
	udpSrv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(truncatedReply)
	})
	if err != nil {
		t.Fatalf("unable to run UDP test server: %v", err)
	}
	defer udpSrv.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	r, _, err := (&Client{TCPFallback: true}).Exchange(m, addr)
	if err == nil {
		t.Fatal("expected a fallback error")
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *FallbackError, got %T: %v", err, err)
	}
	if fe.UDP == nil || !fe.UDP.Truncated {
		t.Errorf("expected the truncated UDP response in the error, got %v", fe.UDP)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated UDP response to be returned, got %v", r)
	}
}

func TestClientTCPFallbackQuestionMismatch(t *testing.T) {
	addr, _, tcpQueries := fallbackServers(t,
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

	_, _, err := (&Client{TCPFallback: true}).Exchange(m, addr)
	if err == nil {
		t.Fatal("expected an error for a mismatched fallback question")
	}
	if !errors.Is(err, ErrQuestion) {
		t.Errorf("expected ErrQuestion, got %v", err)
	}
	var fe *FallbackError
	if !errors.As(err, &fe) {
		t.Errorf("expected a *FallbackError, got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 1 {
		t.Errorf("expected 1 TCP fallback query, got %d", got)
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

	_, _, err := (&Client{TCPFallback: true}).Exchange(m, addr)
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

func TestClientTCPFallbackNotOnTCPClient(t *testing.T) {
	// A TCP client has no UDP phase to truncate, so the fallback must not
	// change network selection.
	addr, _, _ := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(truncatedReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{TCPFallback: true, Net: "tcp"}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || !r.Truncated {
		t.Errorf("expected the truncated TCP response, got %v", r)
	}
}

// TestClientLateResponseNotHandedToNextQuery reuses one connection for two
// queries. The server answers the first query only after the first query has
// timed out and the second query is in flight. The late answer must never be
// returned as the second query's response.
func TestClientLateResponseNotHandedToNextQuery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to listen: %v", err)
	}
	defer pc.Close()

	var (
		mu      sync.Mutex
		staleID uint16
		queries int
	)

	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, MaxMsgSize)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			mu.Lock()
			queries++
			first := queries == 1
			if first {
				staleID = req.Id
			}
			mu.Unlock()

			if first {
				// Answer the stale query after the second one is well
				// underway, and with the first query's ID.
				go func(req *Msg, raddr net.Addr) {
					select {
					case <-time.After(150 * time.Millisecond):
					case <-done:
						return
					}
					m := new(Msg)
					m.SetReply(req)
					rr, _ := NewRR("stale.miek.nl. 60 IN A 192.0.2.1")
					m.Answer = []RR{rr}
					out, err := m.Pack()
					if err == nil {
						pc.WriteTo(out, raddr)
					}
				}(req, raddr)
				continue
			}

			m := new(Msg)
			m.SetReply(req)
			rr, _ := NewRR("fresh.miek.nl. 60 IN A 192.0.2.2")
			m.Answer = []RR{rr}
			out, err := m.Pack()
			if err != nil {
				continue
			}
			// Delay the fresh answer so the stale one can arrive first.
			go func(out []byte, raddr net.Addr) {
				select {
				case <-time.After(350 * time.Millisecond):
				case <-done:
					return
				}
				pc.WriteTo(out, raddr)
			}(out, raddr)
		}
	}()

	c := &Client{Timeout: 100 * time.Millisecond}
	co, err := c.Dial(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("unable to dial: %v", err)
	}
	defer co.Close()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	// First query times out and learns the ID.
	if _, _, err := c.ExchangeWithConn(m, co); err == nil {
		t.Fatal("expected the first query to time out")
	}

	// The second query reuses the same message and therefore the same ID;
	// the connection must assign it a fresh one.
	c = &Client{Timeout: 2 * time.Second}
	r, _, err := c.ExchangeWithConn(m, co)
	if err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	if r == nil || len(r.Answer) != 1 {
		t.Fatalf("expected one answer, got %v", r)
	}
	a, ok := r.Answer[0].(*A)
	if !ok || a.A.String() != "192.0.2.2" {
		t.Fatalf("second query received the stale answer: %v", r.Answer[0])
	}
	mu.Lock()
	stale := staleID
	mu.Unlock()
	if r.Id == stale {
		t.Fatalf("second query kept the reused ID %d", stale)
	}
}

// TestClientExchangeWithConnCancellation verifies that cancelling the context
// unblocks a read on an otherwise healthy persistent connection.
func TestClientExchangeWithConnCancellation(t *testing.T) {
	srv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			// Never answer.
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer srv.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := new(Client)
	co, err := c.Dial(addr)
	if err != nil {
		t.Fatalf("unable to dial: %v", err)
	}
	defer co.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err = c.ExchangeWithConnContext(ctx, m, co)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !isNetworkTimeout(err) {
		t.Fatalf("expected a deadline error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

// TestClientConnReusableAfterCancellation ensures the generation machinery
// leaves a persistent connection usable for the next query.
func TestClientConnReusableAfterCancellation(t *testing.T) {
	var answer atomic.Bool
	srv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			if !answer.Load() {
				return
			}
			answeredReply(w, r)
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer srv.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := new(Client)
	co, err := c.Dial(addr)
	if err != nil {
		t.Fatalf("unable to dial: %v", err)
	}
	defer co.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, _, err := c.ExchangeWithConnContext(ctx, m, co); err == nil {
		t.Fatal("expected the first query to fail")
	}

	answer.Store(true)
	r, _, err := c.ExchangeWithConn(m, co)
	if err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	if r == nil || len(r.Answer) != 1 {
		t.Fatalf("expected the second query to be answered, got %v", r)
	}
}

// TestClientCloseDuringExchange verifies that closing a connection while an
// exchange is waiting unblocks the exchange and completes it exactly once;
// the caller then sees a close error rather than hanging.
func TestClientCloseDuringExchange(t *testing.T) {
	srv, addr, _, err := RunLocalUDPServer("127.0.0.1:0", func(s *Server) {
		s.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			// Never answer.
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer srv.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	c := &Client{Timeout: 5 * time.Second}
	co, err := c.Dial(addr)
	if err != nil {
		t.Fatalf("unable to dial: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, err := c.ExchangeWithConn(m, co)
		result <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := co.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected an error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the in-flight exchange")
	}
}

// TestClientExchangeFallbackPath verifies that the plain Exchange entry point
// performs the TCP fallback when enabled while keeping its signature and
// network selection.
func TestClientExchangeFallbackPath(t *testing.T) {
	addr, udpQueries, tcpQueries := fallbackServers(t,
		HandlerFunc(truncatedReply),
		HandlerFunc(answeredReply),
	)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	r, _, err := (&Client{TCPFallback: true, Net: "udp4"}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil || r.Truncated || len(r.Answer) != 1 {
		t.Fatalf("expected the full TCP answer, got %v", r)
	}
	if got := atomic.LoadInt32(udpQueries); got != 1 {
		t.Errorf("expected 1 UDP query, got %d", got)
	}
	if got := atomic.LoadInt32(tcpQueries); got != 1 {
		t.Errorf("expected 1 TCP query, got %d", got)
	}
}

// TestClientFallbackBudgetNotReset ensures the fallback cannot get a second
// full timeout after the UDP phase has already used most of the budget.
func TestClientFallbackBudgetNotReset(t *testing.T) {
	slow := make(chan struct{})
	addr, _, _ := fallbackServers(t,
		HandlerFunc(func(w ResponseWriter, r *Msg) {
			// Hold the UDP reply for most of the budget before truncating.
			select {
			case <-time.After(300 * time.Millisecond):
			case <-slow:
			}
			truncatedReply(w, r)
		}),
		HandlerFunc(func(w ResponseWriter, r *Msg) { <-slow }),
	)
	defer close(slow)

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeA)

	const timeout = 450 * time.Millisecond
	c := &Client{TCPFallback: true, Timeout: timeout}

	start := time.Now()
	_, _, err := c.Exchange(m, addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the fallback to fail")
	}
	// The remaining allowance is ~150ms, not another full 450ms.
	if elapsed > timeout+250*time.Millisecond {
		t.Errorf("exchange took %v; the fallback appears to have reset the budget (timeout %v)", elapsed, timeout)
	}
}
