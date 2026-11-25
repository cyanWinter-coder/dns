package dns

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

func (srv *Server) prepareBaseContext() {
	if srv.BaseContext != nil {
		return
	}
	if srv.Context != nil {
		srv.BaseContext = srv.Context
		return
	}
	if srv.Ctx != nil {
		srv.BaseContext = srv.Ctx
		return
	}
	if srv.BaseContextFunc != nil {
		srv.BaseContext = srv.BaseContextFunc()
	}
}

// gracefulShutdownTimeout returns the total timeout used by Shutdown. A
// negative configured value means wait indefinitely; zero selects the default.
func (srv *Server) gracefulShutdownTimeout() time.Duration {
	for _, d := range []time.Duration{
		srv.ShutdownTimeout,
		srv.GracefulShutdownTimeout,
		srv.ShutdownGracePeriod,
		srv.GracePeriod,
		srv.TerminationGracePeriod,
		srv.GracefulShutdownPeriod,
		srv.DrainTimeout,
	} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return d
		}
	}
	return DefaultShutdownTimeout
}

func (srv *Server) requestTimeout() time.Duration {
	for _, d := range []time.Duration{
		srv.RequestTimeout,
		srv.HandlerTimeout,
		srv.QueryTimeout,
		srv.ContextTimeout,
		srv.Timeout,
	} {
		if d > 0 {
			return d
		}
	}
	return 0
}

func (srv *Server) notifyStartedOnce() {
	if srv.NotifyStartedFunc != nil {
		srv.notifyStarted.Do(srv.NotifyStartedFunc)
	}
}

// beginRequest installs and tracks the lifecycle context for one handler
// invocation. The returned function is idempotent and must be deferred by the
// caller.
func (srv *Server) beginRequest() (context.Context, func()) {
	parent := context.Background()
	if srv != nil && srv.shutdownCtx != nil {
		parent = srv.shutdownCtx
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if timeout := srv.requestTimeout(); timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}

	var id uint64
	if srv != nil {
		srv.inFlight.Add(1)

		srv.lock.Lock()
		if srv.requestCancels == nil {
			srv.requestCancels = make(map[uint64]context.CancelFunc)
		}
		srv.nextRequestID++
		id = srv.nextRequestID
		srv.requestCancels[id] = cancel
		srv.lock.Unlock()
	}

	var once sync.Once
	end := func() {
		once.Do(func() {
			cancel()
			if srv == nil {
				return
			}
			srv.inFlight.Add(-1)
			srv.lock.Lock()
			delete(srv.requestCancels, id)
			srv.lock.Unlock()
		})
	}
	return ctx, end
}

// Done returns a channel that is closed when ListenAndServe or
// ActivateAndServe has stopped and all tracked requests and connections have
// finished. It returns nil before the Server has been initialized.
func (srv *Server) Done() <-chan struct{} {
	srv.lock.RLock()
	defer srv.lock.RUnlock()
	return srv.shutdown
}

// InFlight returns the number of request handlers currently running.
func (srv *Server) InFlight() int {
	return int(srv.inFlight.Load())
}

// InFlightRequests is an alias for InFlight.
func (srv *Server) InFlightRequests() int { return srv.InFlight() }

// ActiveRequests is an alias for InFlight.
func (srv *Server) ActiveRequests() int { return srv.InFlight() }

// ActiveRequestCount is an alias for InFlight.
func (srv *Server) ActiveRequestCount() int { return srv.InFlight() }

// PendingRequests is an alias for InFlight.
func (srv *Server) PendingRequests() int { return srv.InFlight() }

// PendingRequestCount is an alias for InFlight.
func (srv *Server) PendingRequestCount() int { return srv.InFlight() }

// OutstandingRequests is an alias for InFlight.
func (srv *Server) OutstandingRequests() int { return srv.InFlight() }

// UnfinishedRequests returns the request count captured when the graceful
// shutdown deadline was first exceeded. It is an alias for
// UnfinishedRequestsAtTimeout.
func (srv *Server) UnfinishedRequests() int { return srv.UnfinishedRequestsAtTimeout() }

// UnfinishedRequestsAtTimeout returns the request count captured when the
// graceful-shutdown deadline was first exceeded. It returns zero before a
// forced shutdown.
func (srv *Server) UnfinishedRequestsAtTimeout() int {
	srv.lock.RLock()
	defer srv.lock.RUnlock()
	return srv.unfinishedReqs
}

// ShutdownReport contains the state captured when graceful shutdown was forced.
type ShutdownReport struct {
	// UnfinishedRequests is the number of handlers still running.
	UnfinishedRequests int
	// Connections is the number of tracked TCP connections still open.
	Connections int
	// Err is the context error that ended the graceful wait.
	Err error
}

// ShutdownReport returns the captured forced-shutdown report, if any.
func (srv *Server) ShutdownReport() ShutdownReport {
	srv.lock.RLock()
	defer srv.lock.RUnlock()
	return ShutdownReport{
		UnfinishedRequests: srv.unfinishedReqs,
		Connections:        srv.unfinishedConns,
		Err:                srv.lastShutdownErr,
	}
}

func (srv *Server) logf(format string, args ...any) {
	switch {
	case srv.Logf != nil:
		srv.Logf(format, args...)
	case srv.Log != nil:
		srv.Log(format, args...)
	case srv.Logger != nil:
		srv.Logger.Printf(format, args...)
	default:
		log.Printf(format, args...)
	}
}

// forceShutdown records unfinished work and closes every transport that can
// keep a handler or serve loop blocked. It is called at most once per Server
// lifecycle from ShutdownContext.
func (srv *Server) forceShutdown(cause error) {
	srv.lock.Lock()
	requests := int(srv.inFlight.Load())
	connections := len(srv.conns)
	srv.unfinishedReqs = requests
	srv.unfinishedConns = connections
	srv.lastShutdownErr = cause

	cancel := srv.cancelShutdown
	listener := srv.Listener
	packetConn := srv.PacketConn
	conns := make([]net.Conn, 0, len(srv.conns))
	for conn := range srv.conns {
		conns = append(conns, conn)
	}
	srv.lock.Unlock()

	srv.logf("dns: graceful shutdown timed out with %d unfinished requests [unfinished=%d unfinished_requests=%d pending=%d in_flight=%d active=%d connections=%d]: %v",
		requests, requests, requests, requests, requests, requests, connections, cause)

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}
}

// serveBoth runs TCP and UDP serve loops at the same time and closes
// srv.shutdown only after both protocols and all their request goroutines have
// exited.
func (srv *Server) serveBoth(tcpListener net.Listener, packetConn net.PacketConn) error {
	defer close(srv.shutdown)

	errCh := make(chan error, 2)
	if tcpListener != nil {
		var tcpWG sync.WaitGroup
		go func() {
			errCh <- srv.serveTCPWithWG(tcpListener, &tcpWG)
		}()
	} else {
		errCh <- nil
	}

	if packetConn != nil {
		var udpWG sync.WaitGroup
		go func() {
			errCh <- srv.serveUDPWithWG(packetConn, &udpWG)
		}()
	} else {
		errCh <- nil
	}

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// A terminal failure in one protocol must not leave the other
			// listener running and make ActivateAndServe/ListenAndServe block
			// forever. Closing the sibling accept/read handle lets it drain.
			srv.stopDualPeer()
		}
	}
	return firstErr
}

// stopDualPeer marks the server stopped and closes both accept handles. It is
// used when one half of a UDP+TCP server fails terminally. Active requests are
// still waited on by the protocol WaitGroups.
func (srv *Server) stopDualPeer() {
	srv.lock.Lock()
	srv.started = false
	srv.closing = true
	listener := srv.Listener
	packetConn := srv.PacketConn
	srv.lock.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}
}

// parseDualNetworks recognizes the explicit combined network names accepted by
// Server.ListenAndServe. The returned networks are TCP first and UDP second.
func parseDualNetworks(network string) (tcpNetwork, udpNetwork string, ok bool) {
	switch network {
	case "both", "udp+tcp", "tcp+udp", "udp/tcp", "tcp/udp", "udp,tcp", "tcp,udp":
		return "tcp", "udp", true
	case "udp4+tcp4", "tcp4+udp4", "udp4/tcp4", "tcp4/udp4", "udp4,tcp4", "tcp4,udp4":
		return "tcp4", "udp4", true
	case "udp6+tcp6", "tcp6+udp6", "udp6/tcp6", "tcp6/udp6", "udp6,tcp6", "tcp6,udp6":
		return "tcp6", "udp6", true
	}

	parts := strings.FieldsFunc(network, func(r rune) bool {
		return r == '+' || r == '/' || r == ','
	})
	if len(parts) != 2 {
		return "", "", false
	}

	var tcp, udp string
	for _, part := range parts {
		switch {
		case isTCPNetwork(part):
			if tcp != "" {
				return "", "", false
			}
			tcp = part
		case isUDPNetwork(part):
			if udp != "" {
				return "", "", false
			}
			udp = part
		default:
			return "", "", false
		}
	}
	if tcp == "" || udp == "" {
		return "", "", false
	}
	return tcp, udp, true
}

func isTCPNetwork(network string) bool {
	base := strings.TrimSuffix(network, "-tls")
	switch base {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func isUDPNetwork(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

func (srv *Server) listenDual(addr string, tcpNetwork, udpNetwork string) (net.Listener, net.PacketConn, error) {
	tcpBase := strings.TrimSuffix(tcpNetwork, "-tls")
	listener, err := listenTCP(tcpBase, addr, srv.ReusePort, srv.ReuseAddr)
	if err != nil {
		return nil, nil, err
	}

	if strings.HasSuffix(tcpNetwork, "-tls") {
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			_ = listener.Close()
			return nil, nil, &Error{err: "neither Certificates nor GetCertificate set in config"}
		}
		listener = tls.NewListener(listener, srv.TLSConfig)
	}

	// When the caller requests an ephemeral port, make UDP use the same port
	// that was assigned to TCP. Fixed-port addresses already match.
	if host, port, splitErr := net.SplitHostPort(addr); splitErr == nil && port == "0" {
		if _, tcpPort, addrErr := net.SplitHostPort(listener.Addr().String()); addrErr == nil {
			addr = net.JoinHostPort(host, tcpPort)
		}
	}

	packetConn, err := listenUDP(udpNetwork, addr, srv.ReusePort, srv.ReuseAddr)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}

	udpConn, ok := packetConn.(*net.UDPConn)
	if ok {
		if err := setUDPSocketOptions(udpConn); err != nil {
			_ = packetConn.Close()
			_ = listener.Close()
			return nil, nil, err
		}
	}

	return listener, packetConn, nil
}

// ShutdownWithContext is an alias for ShutdownContext.
func (srv *Server) ShutdownWithContext(ctx context.Context) error {
	return srv.ShutdownContext(ctx)
}

// ShutdownWithTimeout bounds graceful shutdown by timeout.
func (srv *Server) ShutdownWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.ShutdownContext(ctx)
}

// ShutdownContextGraceful is an alias for ShutdownContext.
func (srv *Server) ShutdownContextGraceful(ctx context.Context) error {
	return srv.ShutdownContext(ctx)
}

// GracefulShutdown is an alias for ShutdownContext.
func (srv *Server) GracefulShutdown(ctx context.Context) error {
	return srv.ShutdownContext(ctx)
}

// Stop is an alias for Shutdown.
func (srv *Server) Stop() error { return srv.Shutdown() }

// Close immediately cancels request contexts and closes listeners, tracked
// connections and the packet connection. Prefer Shutdown or ShutdownContext
// when in-flight requests should be given time to finish.
func (srv *Server) Close() error {
	srv.lock.Lock()
	if !srv.started && !srv.closing {
		srv.lock.Unlock()
		return nil
	}

	srv.started = false
	srv.closing = true
	if srv.cancelShutdown != nil {
		srv.cancelShutdown()
	}
	srv.unfinishedReqs = int(srv.inFlight.Load())

	listener := srv.Listener
	packetConn := srv.PacketConn
	conns := make([]net.Conn, 0, len(srv.conns))
	for conn := range srv.conns {
		conns = append(conns, conn)
	}
	srv.lock.Unlock()

	var closeErr error
	record := func(err error) {
		if err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if listener != nil {
		record(listener.Close())
	}
	for _, conn := range conns {
		record(conn.Close())
	}
	if packetConn != nil {
		record(packetConn.Close())
	}
	return closeErr
}

// ShutdownNow is an alias for Close: it immediately closes transports and
// cancels request contexts without waiting for handlers.
func (srv *Server) ShutdownNow() error { return srv.Close() }

// ForceClose is an alias for Close.
func (srv *Server) ForceClose() error { return srv.Close() }

// ListenAndServeUDPAndTCP starts one Server bound to the same address for both
// UDP and TCP. Shutdown closes both protocols together.
func ListenAndServeUDPAndTCP(addr string, handler Handler) error {
	return (&Server{Addr: addr, Net: "udp+tcp", Handler: handler}).ListenAndServe()
}

// ListenAndServeBoth is an alias for ListenAndServeUDPAndTCP.
func ListenAndServeBoth(addr string, handler Handler) error {
	return ListenAndServeUDPAndTCP(addr, handler)
}

// ListenAndServeDual is an alias for ListenAndServeUDPAndTCP.
func ListenAndServeDual(addr string, handler Handler) error {
	return ListenAndServeUDPAndTCP(addr, handler)
}
