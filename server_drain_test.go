package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// waitFin waits for the serve loop of a test server to return.
func waitFin(t *testing.T, fin chan error) {
	t.Helper()
	select {
	case err := <-fin:
		if err != nil {
			t.Errorf("serve loop returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("serve loop did not return within 5s")
	}
}

// checkDrainTimeoutError asserts err is a *DrainTimeoutError wrapping
// ErrDrainTimeout and reporting at least wantHandlers handlers.
func checkDrainTimeoutError(t *testing.T, err error, wantHandlers int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected DrainTimeoutError, got nil")
	}
	var derr *DrainTimeoutError
	if !errors.As(err, &derr) {
		t.Fatalf("expected *DrainTimeoutError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrDrainTimeout) {
		t.Errorf("expected ErrDrainTimeout cause, got %v", derr.Err)
	}
	if derr.Handlers < wantHandlers {
		t.Errorf("expected at least %d unfinished handlers, got %d", wantHandlers, derr.Handlers)
	}
}

func TestDrainTimeoutSlowHandlerUDP(t *testing.T) {
	unblock := make(chan struct{})
	handlerErr := make(chan error, 1)
	s, addr, fin, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 200 * time.Millisecond
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			<-unblock
			m := new(Msg)
			m.SetReply(req)
			handlerErr <- w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)

	type exchangeResult struct {
		r   *Msg
		err error
	}
	exch := make(chan exchangeResult, 1)
	go func() {
		r, _, err := c.Exchange(m, addr)
		exch <- exchangeResult{r, err}
	}()

	// Give the query time to reach the handler.
	time.Sleep(100 * time.Millisecond)

	err = s.Shutdown()
	checkDrainTimeoutError(t, err, 1)

	// The client must receive the distinguishable timeout response
	// (SERVFAIL), not just a dropped query.
	select {
	case res := <-exch:
		if res.err != nil {
			t.Errorf("client exchange failed: %v", res.err)
		} else if res.r.Rcode != RcodeServerFailure {
			t.Errorf("expected SERVFAIL timeout response, got %s", RcodeToString[res.r.Rcode])
		}
	case <-time.After(2 * time.Second):
		t.Error("client did not receive a timeout response")
	}

	// New queries after shutdown must not be answered.
	c.Timeout = 300 * time.Millisecond
	if _, _, err := c.Exchange(m, addr); err == nil {
		t.Error("query after shutdown was answered")
	}

	// Let the handler finish; its write must fail with ErrHandlerTimeout.
	close(unblock)
	select {
	case err := <-handlerErr:
		if !errors.Is(err, ErrHandlerTimeout) {
			t.Errorf("expected ErrHandlerTimeout from handler WriteMsg, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("handler did not finish")
	}
	waitFin(t, fin)
}

func TestDrainTimeoutSlowHandlerTCP(t *testing.T) {
	unblock := make(chan struct{})
	handlerErr := make(chan error, 1)
	s, addr, fin, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 200 * time.Millisecond
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			<-unblock
			m := new(Msg)
			m.SetReply(req)
			handlerErr <- w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "tcp", Timeout: 3 * time.Second}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)

	type exchangeResult struct {
		r   *Msg
		err error
	}
	exch := make(chan exchangeResult, 1)
	go func() {
		r, _, err := c.Exchange(m, addr)
		exch <- exchangeResult{r, err}
	}()

	time.Sleep(100 * time.Millisecond)

	err = s.Shutdown()
	var derr *DrainTimeoutError
	checkDrainTimeoutError(t, err, 1)
	if !errors.As(err, &derr) {
		t.Fatalf("expected *DrainTimeoutError, got %T", err)
	}
	if derr.Connections < 1 {
		t.Errorf("expected at least 1 unfinished connection, got %d", derr.Connections)
	}

	// The client gets the framed SERVFAIL timeout response.
	select {
	case res := <-exch:
		if res.err != nil {
			t.Errorf("client exchange failed: %v", res.err)
		} else if res.r.Rcode != RcodeServerFailure {
			t.Errorf("expected SERVFAIL timeout response, got %s", RcodeToString[res.r.Rcode])
		}
	case <-time.After(2 * time.Second):
		t.Error("client did not receive a timeout response")
	}

	close(unblock)
	select {
	case err := <-handlerErr:
		if !errors.Is(err, ErrHandlerTimeout) {
			t.Errorf("expected ErrHandlerTimeout from handler WriteMsg, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("handler did not finish")
	}
	waitFin(t, fin)
}

func TestDrainTimeoutSlowHandlerTLS(t *testing.T) {
	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}

	unblock := make(chan struct{})
	s, addr, fin, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	s.DrainTimeout = 200 * time.Millisecond
	s.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
		<-unblock
		m := new(Msg)
		m.SetReply(req)
		w.WriteMsg(m)
	})

	c := &Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Timeout:   3 * time.Second,
	}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)

	exch := make(chan error, 1)
	go func() {
		_, _, err := c.Exchange(m, addr)
		exch <- err
	}()

	time.Sleep(100 * time.Millisecond)

	err = s.Shutdown()
	checkDrainTimeoutError(t, err, 1)

	close(unblock)
	// The client either got the SERVFAIL timeout response or saw the
	// connection close; it must not hang.
	select {
	case <-exch:
	case <-time.After(2 * time.Second):
		t.Error("client exchange did not terminate")
	}
	waitFin(t, fin)
}

func TestDrainLongLivedIdleConnection(t *testing.T) {
	s, addr, fin, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 200 * time.Millisecond
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	// Open a long-lived connection without sending any query.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// An idle connection must not hold up the shutdown.
	start := time.Now()
	if err := s.Shutdown(); err != nil {
		t.Errorf("shutdown with idle connection failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("shutdown took too long with idle connection: %v", elapsed)
	}
	waitFin(t, fin)
}

func TestDrainPartialWrite(t *testing.T) {
	handlerErr := make(chan error, 1)
	handlerStarted := make(chan struct{})
	s, addr, fin, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 300 * time.Millisecond
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			close(handlerStarted)
			// Stream large messages until the write fails; the client
			// never reads, so this blocks once the buffers are full.
			buf := make([]byte, 60000)
			for {
				if _, err := w.Write(buf); err != nil {
					handlerErr <- err
					return
				}
			}
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadBuffer(1024)
	}

	// Send a proper query, then never read back.
	co := &Conn{Conn: conn}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)
	if err := co.WriteMsg(m); err != nil {
		t.Fatalf("write query failed: %v", err)
	}

	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	// Let the handler fill the kernel buffers and block in Write.
	time.Sleep(300 * time.Millisecond)

	// Shutdown must not hang on the blocked write.
	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()
	select {
	case err := <-done:
		checkDrainTimeoutError(t, err, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on a partially written connection")
	}

	// The blocked write must have been unblocked with an error, not left
	// a half packet behind and kept blocking.
	select {
	case err := <-handlerErr:
		if err == nil {
			t.Error("expected write error in handler after drain timeout")
		}
	case <-time.After(2 * time.Second):
		t.Error("blocked handler write was not unblocked by drain timeout")
	}
	waitFin(t, fin)
}

func TestDrainInProgressAXFR(t *testing.T) {
	handlerDone := make(chan struct{})
	s, addr, fin, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 200 * time.Millisecond
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			defer close(handlerDone)
			soa := &SOA{
				Hdr: RR_Header{Name: "example.com.", Rrtype: TypeSOA, Class: ClassINET},
				Ns:  "ns1.example.com.", Mbox: "hostmaster.example.com.",
				Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			}
			txt := &TXT{Hdr: RR_Header{Name: "example.com.", Rrtype: TypeTXT, Class: ClassINET}, Txt: []string{"x"}}
			// A well-formed but never-ending AXFR stream: SOA first, then
			// records forever, no closing SOA.
			first := true
			for {
				m := new(Msg)
				m.SetReply(req)
				if first {
					m.Answer = []RR{soa}
					first = false
				} else {
					m.Answer = []RR{txt}
				}
				if err := w.WriteMsg(m); err != nil {
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	q := new(Msg)
	q.SetQuestion("example.com.", TypeAXFR)
	tr := &Transfer{}
	env, err := tr.In(q, addr)
	if err != nil {
		t.Fatalf("transfer in failed: %v", err)
	}

	// Drain the envelope channel in the background.
	envDone := make(chan struct{})
	go func() {
		defer close(envDone)
		for range env {
		}
	}()

	// Let the transfer get going.
	time.Sleep(100 * time.Millisecond)

	// Shutdown mid-transfer must terminate, not wait for the endless stream.
	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()
	select {
	case err := <-done:
		checkDrainTimeoutError(t, err, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on in-progress AXFR")
	}

	// The transfer must not keep blocking: the connection is closed, the
	// client channel terminates and the handler returns.
	select {
	case <-envDone:
	case <-time.After(2 * time.Second):
		t.Error("client transfer channel did not terminate")
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Error("AXFR handler did not return after drain timeout")
	}
	waitFin(t, fin)
}

func TestConcurrentShutdown(t *testing.T) {
	unblock := make(chan struct{})
	s, _, fin, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.DrainTimeout = 150 * time.Millisecond
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			<-unblock
			m := new(Msg)
			m.SetReply(req)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	// Fire one query so a handler is in flight during the shutdown race.
	c := &Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)
	go c.Exchange(m, s.PacketConn.LocalAddr().String())
	time.Sleep(100 * time.Millisecond)

	// Hammer Shutdown and ShutdownContext concurrently; repeated calls and
	// the race with the serve loop exiting must be idempotent.
	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				errs[i] = s.Shutdown()
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				errs[i] = s.ShutdownContext(ctx)
			}
		}(i)
	}
	wg.Wait()

	var derr *DrainTimeoutError
	sawDrainTimeout := false
	for i, err := range errs {
		if err == nil {
			continue
		}
		if !errors.As(err, &derr) {
			t.Errorf("caller %d: unexpected error %v", i, err)
			continue
		}
		if errors.Is(err, ErrDrainTimeout) {
			sawDrainTimeout = true
		}
	}
	if !sawDrainTimeout {
		t.Error("expected at least one caller to observe the drain timeout")
	}

	close(unblock)
	waitFin(t, fin)

	// Shutdown after a completed shutdown is idempotent: returns promptly
	// without panicking or double-closing anything.
	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()
	select {
	case err := <-done:
		if err != nil {
			var derr *DrainTimeoutError
			if !errors.As(err, &derr) {
				t.Errorf("repeated Shutdown returned unexpected error: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("repeated Shutdown did not return")
	}
}

func TestDrainNegativeTimeoutWaitsIndefinitely(t *testing.T) {
	unblock := make(chan struct{})
	s, addr, fin, err := RunLocalUDPServer(":0", func(srv *Server) {
		srv.DrainTimeout = -1
		srv.Handler = HandlerFunc(func(w ResponseWriter, req *Msg) {
			<-unblock
			m := new(Msg)
			m.SetReply(req)
			w.WriteMsg(m)
		})
	})
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}

	c := &Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(Msg)
	m.SetQuestion("example.com.", TypeTXT)
	exch := make(chan *Msg, 1)
	go func() {
		r, _, _ := c.Exchange(m, addr)
		exch <- r
	}()
	time.Sleep(100 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()

	// With a negative DrainTimeout, shutdown waits for the handler.
	select {
	case <-done:
		t.Fatal("Shutdown returned while handler was still blocked")
	case <-time.After(300 * time.Millisecond):
	}

	close(unblock)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Shutdown did not return after handler finished")
	}

	// The handler replied normally, no timeout response was sent.
	select {
	case r := <-exch:
		if r == nil {
			t.Error("expected reply, got none")
		} else if r.Rcode != RcodeSuccess {
			t.Errorf("expected successful reply, got %s", RcodeToString[r.Rcode])
		}
	case <-time.After(2 * time.Second):
		t.Error("client did not receive a reply")
	}
	waitFin(t, fin)
}

func TestShutdownNotStarted(t *testing.T) {
	s := &Server{}
	if err := s.Shutdown(); err == nil {
		t.Error("expected error when shutting down a server that was never started")
	}
}
