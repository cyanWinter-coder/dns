// Repeatable verification for the request-ownership and shutdown state
// machine: frozen per-request identity, a single published terminal state,
// ordered shutdown draining, shared UDP/TCP write error classification and
// interface compatibility.

package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Requirement 1: a request freezes handler, protocol and connection
// identity; after shutdown starts no new request is dispatched.
func TestRequestIdentityFrozen(t *testing.T) {
	const (
		udpProto = "udp"
		tcpProto = "tcp"
	)

	identities := make(chan frozenIdentity, 4)
	handler := HandlerFunc(func(w ResponseWriter, r *Msg) {
		resp := w.(*response)
		identities <- resp.frozen
		m := new(Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})

	s, addr, _, err := RunLocalUDPServer(":0", func(srv *Server) { srv.Handler = handler })
	if err != nil {
		t.Fatalf("unable to run UDP server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatalf("udp exchange: %v", err)
	}

	select {
	case id := <-identities:
		if id.proto != udpProto {
			t.Errorf("frozen proto = %q, want %q", id.proto, udpProto)
		}
		if id.handler == nil {
			t.Error("frozen handler is nil")
		}
		if id.remote == nil || id.local == nil {
			t.Error("frozen connection identity missing addresses")
		}
	case <-time.After(time.Second):
		t.Fatal("handler never observed a frozen identity")
	}

	// TCP: each query on the same connection gets a distinct sequence while
	// the connection identity stays stable. A persistent connection is used
	// because Client.Exchange dials afresh on every call.
	ts, taddr, _, err := RunLocalTCPServer(":0", func(srv *Server) { srv.Handler = handler })
	if err != nil {
		t.Fatalf("unable to run TCP server: %v", err)
	}
	defer ts.Shutdown()

	persistent, err := Dial("tcp", taddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer persistent.Close()
	for i := 0; i < 2; i++ {
		if err := persistent.WriteMsg(m.Copy()); err != nil {
			t.Fatalf("tcp write %d: %v", i, err)
		}
		if _, err := persistent.ReadMsg(); err != nil {
			t.Fatalf("tcp read %d: %v", i, err)
		}
	}

	var got []frozenIdentity
	for i := 0; i < 2; i++ {
		select {
		case id := <-identities:
			got = append(got, id)
		case <-time.After(time.Second):
			t.Fatal("missing frozen TCP identity")
		}
	}
	if got[0].proto != tcpProto || got[0].connID == 0 {
		t.Errorf("first TCP identity = %+v, want tcp with non-zero conn id", got[0])
	}
	if got[0].connID != got[1].connID {
		t.Error("connection identity changed between queries on one connection")
	}
	if got[0].querySeq == 0 || got[0].querySeq >= got[1].querySeq {
		t.Errorf("query sequences not increasing: %d, %d", got[0].querySeq, got[1].querySeq)
	}
}

// Requirement 1 (second half): after shutdown begins, a datagram already in
// flight is drained, but nothing read afterwards is dispatched.
func TestNoDispatchAfterDraining(t *testing.T) {
	var dispatched int32
	gate := make(chan struct{})
	s, addr, _, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			atomic.AddInt32(&dispatched, 1)
			<-gate
			m := new(Msg)
			m.SetReply(r)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}

	c := new(Client)
	c.Timeout = 5 * time.Second
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)

	replyErr := make(chan error, 1)
	go func() {
		_, _, e := c.Exchange(m, addr)
		replyErr <- e
	}()

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&dispatched) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadInt32(&dispatched) != 1 {
		t.Fatal("first request never dispatched")
	}

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr <- s.ShutdownContext(ctx)
	}()

	// Give ShutdownContext time to enter the draining state, then release
	// the in-flight handler.
	time.Sleep(100 * time.Millisecond)
	close(gate)

	if err := <-shutdownErr; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-replyErr; err != nil {
		t.Fatalf("in-flight request not drained: %v", err)
	}

	// Post-shutdown datagrams must be refused by the network, not dispatched.
	if _, _, err := c.Exchange(m, addr); err == nil {
		t.Error("exchange succeeded after shutdown")
	}
	if got := atomic.LoadInt32(&dispatched); got != 1 {
		t.Errorf("dispatched count = %d, want 1", got)
	}
}

// Requirement 2: handler return, panic and disconnect each publish at most
// one terminal state.
func TestTerminalStatePublishedOnce(t *testing.T) {
	t.Run("return", func(t *testing.T) {
		w := &response{}
		if !w.active() {
			t.Fatal("fresh response is not active")
		}
		if !w.finalize(stateTerminalReturn) {
			t.Error("first finalize lost")
		}
		if w.finalize(stateTerminalPanic) {
			t.Error("second finalize overwrote the terminal state")
		}
		cause, ok := w.terminalCause()
		if !ok || cause != stateTerminalReturn {
			t.Errorf("cause = %d ok=%v, want stateTerminalReturn", cause, ok)
		}
	})

	t.Run("panic-before-return", func(t *testing.T) {
		s, addr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
			srv.PanicHandler = func(ResponseWriter, interface{}) {}
			srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
				panic("boom")
			})
		})
		if err != nil {
			t.Fatalf("unable to run server: %v", err)
		}
		defer s.Shutdown()

		c := &Client{Net: "tcp", Timeout: time.Second}
		m := new(Msg)
		m.SetQuestion("example.org.", TypeA)
		if _, _, err := c.Exchange(m, addr); err == nil {
			t.Error("expected connection failure after handler panic")
		}
	})

	t.Run("panic-handler-observed-once", func(t *testing.T) {
		var panics int32
		var seenCause uint32
		s, addr, _, err := RunLocalUDPServer(":0", func(srv *Server) {
			srv.PanicHandler = func(w ResponseWriter, r interface{}) {
				atomic.AddInt32(&panics, 1)
				if r != "boom" {
					t.Errorf("recovered value = %v, want boom", r)
				}
				resp := w.(*response)
				cause, ok := resp.terminalCause()
				if !ok {
					t.Error("request not finalized when PanicHandler ran")
				}
				atomic.StoreUint32(&seenCause, cause)
			}
			srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
				panic("boom")
			})
		})
		if err != nil {
			t.Fatalf("unable to run server: %v", err)
		}
		defer s.Shutdown()

		c := &Client{Timeout: time.Second}
		m := new(Msg)
		m.SetQuestion("example.org.", TypeA)
		_, _, _ = c.Exchange(m, addr) // no reply is expected; panic is recovered

		if got := atomic.LoadInt32(&panics); got != 1 {
			t.Errorf("PanicHandler invocations = %d, want 1", got)
		}
		if atomic.LoadUint32(&seenCause) != stateTerminalPanic {
			t.Errorf("terminal cause = %d, want stateTerminalPanic", seenCause)
		}
	})
}

// Requirement 2: a late write after the terminal state is refused and can
// never reach the transport, on both UDP and TCP.
func TestLateWriteRejected(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			late := make(chan *response, 1)
			s, addr, _, err := func() (*Server, string, chan error, error) {
				if network == "udp" {
					return RunLocalUDPServer(":0", func(srv *Server) {
						srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
							late <- w.(*response)
							m := new(Msg)
							m.SetReply(r)
							w.WriteMsg(m)
						})
					})
				}
				return RunLocalTCPServer(":0", func(srv *Server) {
					srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
						late <- w.(*response)
						m := new(Msg)
						m.SetReply(r)
						w.WriteMsg(m)
					})
				})
			}()
			if err != nil {
				t.Fatalf("unable to run server: %v", err)
			}
			defer s.Shutdown()

			c := &Client{Net: network, Timeout: time.Second}
			m := new(Msg)
			m.SetQuestion("example.org.", TypeA)
			if _, _, err := c.Exchange(m, addr); err != nil {
				t.Fatalf("exchange: %v", err)
			}

			w := <-late
			deadline := time.Now().Add(2 * time.Second)
			for w.active() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if w.active() {
				t.Fatal("request never finalized after handler return")
			}

			// A late write is always refused before the transport. The
			// exact error depends on whether Close ran first: the legacy
			// "called after Close" contract or the finalization sentinel.
			assertLateWriteRefused := func(err error, what string) {
				t.Helper()
				if errors.Is(err, ErrRequestFinalized) {
					return
				}
				if err != nil && strings.Contains(err.Error(), "called after Close") {
					return
				}
				t.Errorf("late %s error = %v, want a refusal error", what, err)
			}
			assertLateWriteRefused(w.WriteMsg(new(Msg)), "WriteMsg")
			assertLateWriteRefused(func() error { _, e := w.Write([]byte{0, 0}); return e }(), "Write")
		})
	}
}

// Requirement 2: on TCP, a late write from one query cannot corrupt the
// framing of the next query because each query owns an isolated response.
func TestTCPLateWriteCannotCorruptNextMessage(t *testing.T) {
	responses := make(chan *response, 4)
	s, addr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			responses <- w.(*response)
			m := new(Msg)
			m.SetReply(r)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer s.Shutdown()

	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	var first *response
	for i := 0; i < 2; i++ {
		if err := conn.WriteMsg(m); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := conn.ReadMsg(); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		w := <-responses
		if i == 0 {
			first = w
		} else if w == first {
			t.Fatal("two queries shared one response wrapper")
		}
	}

	// The stale response from query one must reject writes while query two
	// has already been answered successfully over the same connection.
	_, err = first.Write([]byte{0xde, 0xad})
	if !errors.Is(err, ErrRequestFinalized) &&
		!(err != nil && strings.Contains(err.Error(), "called after Close")) {
		t.Errorf("stale write error = %v, want a refusal error", err)
	}
}

// Requirement 3: shutdown stops Accept first, drains in-flight requests
// within the deadline, then closes the transport.
func TestShutdownDrainOrdering(t *testing.T) {
	const requests = 8
	var inflight int32

	s, addr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			atomic.AddInt32(&inflight, 1)
			testShutdownNotify.L.Lock()
			testShutdownNotify.Wait()
			testShutdownNotify.L.Unlock()
			m := new(Msg)
			m.SetReply(r)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}

	conns := make([]*Conn, requests)
	for i := range conns {
		c, err := (&Client{Net: "tcp"}).Dial(addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns[i] = c
	}
	for i, c := range conns {
		if err := c.WriteMsg(mustQuestion(t)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&inflight) != requests && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadInt32(&inflight) != requests {
		t.Fatalf("only %d requests in flight, want %d", inflight, requests)
	}

	// No new connection can be accepted once draining starts. The accept
	// loop closes the listener before handlers are released.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- s.ShutdownContext(ctx) }()

	time.Sleep(100 * time.Millisecond)
	if d, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond); derr == nil {
		d.Close()
		t.Error("listener still accepting after shutdown began")
	}

	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	s.lock.RLock()
	left := len(s.conns)
	state := s.state
	s.lock.RUnlock()
	if left != 0 {
		t.Errorf("connection map retains %d entries after drain", left)
	}
	if state != serverClosed {
		t.Errorf("server state = %v, want serverClosed", state)
	}
}

// Requirement 3: when the deadline expires, remaining transports are closed
// and ShutdownContext reports the context error.
func TestShutdownDeadlineClosesTransport(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	s, addr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			close(entered)
			<-release
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}

	conn, err := Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.WriteMsg(mustQuestion(t)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started; cannot test deadline drain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	serr := s.ShutdownContext(ctx)
	if !errors.Is(serr, context.DeadlineExceeded) {
		t.Fatalf("ShutdownContext error = %v, want DeadlineExceeded", serr)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("shutdown blocked far beyond the deadline")
	}

	close(release)
	if _, err := conn.ReadMsg(); err == nil {
		t.Error("connection still usable after deadline-driven shutdown")
	}
}

// Requirement 4: UDP and TCP share the same disconnect classification.
func TestSharedWriteErrorClassification(t *testing.T) {
	for name, in := range map[string]error{
		"closed":     net.ErrClosed,
		"reset":      syscall.ECONNRESET,
		"brokenPipe": syscall.EPIPE,
		"plain":      io.EOF,
		"unrelated":  errors.New("pack failed"),
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyWriteError(in)
			wantDisconnect := name != "unrelated"
			if isDisconnect(got) != wantDisconnect {
				t.Errorf("isDisconnect(%v) = %v, want %v", in, !wantDisconnect, wantDisconnect)
			}
			if wantDisconnect && !errors.Is(got, in) {
				t.Errorf("classified error %v no longer wraps original %v", got, in)
			}
			if !wantDisconnect && got != in {
				t.Errorf("unrelated error was rewritten to %v", got)
			}
		})
	}
}

// Requirement 5: the public Server, ServeMux and MsgAcceptFunc surface keeps
// working end-to-end, including double writes from one handler and the
// default mux's REFUSED path.
func TestPublicInterfacesRemainCompatible(t *testing.T) {
	HandleFunc("example.com.", HelloServerBadThenGoodID)
	defer HandleRemove("example.com.")

	s, addr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer s.Shutdown()

	c := new(Client)
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("double-write handler broke compatibility: %v", err)
	}
	if r.Id != m.Id {
		t.Error("good-id reply not received from double-write handler")
	}

	// Default ServeMux REFUSED path for an unregistered pattern.
	m.SetQuestion("unknown.example.", TypeA)
	r, _, err = c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("mux exchange: %v", err)
	}
	if r.Rcode != RcodeRefused {
		t.Errorf("rcode = %v, want RcodeRefused", r.Rcode)
	}

	// A custom MsgAcceptFunc still drives rejection identically.
	s2, addr2, _, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.MsgAcceptFunc = func(Header) MsgAcceptAction { return MsgReject }
	})
	if err != nil {
		t.Fatalf("unable to run second server: %v", err)
	}
	defer s2.Shutdown()
	r, _, err = c.Exchange(m, addr2)
	if err != nil {
		t.Fatalf("accept-func exchange: %v", err)
	}
	if r.Rcode != RcodeFormatError {
		t.Errorf("rcode = %v, want RcodeFormatError", r.Rcode)
	}
}

// Requirement 5: a Server that fails to start rolls back to serverNew and
// can be started successfully afterwards, proving the transition is
// rollback-able.
func TestFailedStartIsRolledBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	bad := &Server{Addr: addr, Net: "tcp", Listener: nil}
	if err := bad.ListenAndServe(); err == nil {
		t.Fatal("expected bind failure")
	}
	bad.lock.RLock()
	state := bad.state
	started := bad.started
	bad.lock.RUnlock()
	if state != serverNew || started {
		t.Fatalf("state = %v started = %v, want serverNew/false", state, started)
	}
	ln.Close()

	good := &Server{Addr: addr, Net: "tcp"}
	wait := make(chan struct{})
	good.NotifyStartedFunc = func() { close(wait) }
	fin := make(chan error, 1)
	go func() { fin <- good.ListenAndServe() }()
	select {
	case <-wait:
	case <-time.After(2 * time.Second):
		t.Fatal("rolled-back server did not restart")
	}
	if err := good.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-fin; err != nil {
		t.Fatalf("restarted server exited with error: %v", err)
	}
}

// Requirement 5: repeated concurrent full lifecycles must stay race free and
// always reach the closed state.
func TestRepeatedLifecycleConvergence(t *testing.T) {
	const iterations = 25
	for i := 0; i < iterations; i++ {
		s, _, _, err := RunLocalUDPServer(":0", func(srv *Server) {
			srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
				m := new(Msg)
				m.SetReply(r)
				w.WriteMsg(m)
			})
		})
		if err != nil {
			t.Fatalf("iteration %d start: %v", i, err)
		}
		if err := s.Shutdown(); err != nil {
			t.Fatalf("iteration %d shutdown: %v", i, err)
		}
		s.lock.RLock()
		state := s.state
		s.lock.RUnlock()
		if state != serverClosed {
			t.Fatalf("iteration %d state = %v, want serverClosed", i, state)
		}
	}
}

func mustQuestion(t *testing.T) *Msg {
	t.Helper()
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	return m
}

// Guard against accidental drift of the terminal-state constants the tests
// rely on.
func TestTerminalStateConstants(t *testing.T) {
	cases := map[uint32]string{
		stateActive:             "active",
		stateTerminalReturn:     "return",
		stateTerminalPanic:      "panic",
		stateTerminalDisconnect: "disconnect",
		stateTerminalClose:      "close",
	}
	if len(cases) != 5 {
		t.Fatalf("terminal state set changed: %v", cases)
	}
	if stateActive != 0 {
		t.Fatal("stateActive must remain the zero value so zero-value responses are writable")
	}
	if ErrRequestFinalized.Error() == "" || ErrConnClosing.Error() == "" {
		t.Fatal("exported sentinel errors must carry a message")
	}
}

// Ensure Shutdown before start keeps its historical error contract.
func TestShutdownBeforeStart(t *testing.T) {
	srv := new(Server)
	if err := srv.Shutdown(); err == nil || err.Error() != "dns: server not started" {
		t.Fatalf("error = %v, want dns: server not started", err)
	}
}

// Parallel panic and clean requests must not disturb each other.
func TestPanicMixedWithHealthyRequests(t *testing.T) {
	var panicCount int32
	s, addr, _, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.PanicHandler = func(ResponseWriter, interface{}) { atomic.AddInt32(&panicCount, 1) }
		srv.Handler = HandlerFunc(func(w ResponseWriter, r *Msg) {
			if r.Question[0].Name == "panic.example." {
				panic("boom")
			}
			m := new(Msg)
			m.SetReply(r)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run server: %v", err)
	}
	defer s.Shutdown()

	var wg sync.WaitGroup
	c := &Client{Timeout: 2 * time.Second}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := new(Msg)
			if i%2 == 0 {
				m.SetQuestion("panic.example.", TypeA)
				c.Exchange(m, addr) // timeout expected, panic must not crash the server
			} else {
				m.SetQuestion("ok.example.", TypeA)
				r, _, err := c.Exchange(m, addr)
				if err != nil {
					t.Errorf("healthy request %d failed: %v", i, err)
					return
				}
				if r.Rcode != RcodeSuccess {
					t.Errorf("healthy request %d rcode = %v", i, r.Rcode)
				}
			}
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&panicCount); got != 10 {
		t.Errorf("panic count = %d, want 10", got)
	}
}
