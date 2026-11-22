// DNS server implementation.

package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default maximum number of TCP queries before we close the socket.
const maxTCPQueries = 128

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(1, 0)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as DNS handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Msg)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) {
	f(w, r)
}

// A ResponseWriter interface is used by an DNS handler to
// construct an DNS response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// WriteMsg writes a reply back to the client.
	WriteMsg(*Msg) error
	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
	// Close closes the connection.
	Close() error
	// TsigStatus returns the status of the Tsig.
	TsigStatus() error
	// TsigTimersOnly sets the tsig timers only boolean.
	TsigTimersOnly(bool)
	// Hijack lets the caller take over the connection.
	// After a call to Hijack(), the DNS package will not do anything with the connection.
	Hijack()
}

// A ConnectionStater interface is used by a DNS Handler to access TLS connection state
// when available.
type ConnectionStater interface {
	ConnectionState() *tls.ConnectionState
}

type response struct {
	// requestState is the per-request terminal-state machine. It is safe
	// for the zero value, which starts in stateActive.
	requestState
	frozen frozenIdentity

	// conn holds the connection-level flags for TCP requests and is shared
	// by every per-query response on the connection. It is nil for UDP.
	conn *connState

	// closed and hijacked remain in use for UDP requests and for zero-value
	// responses constructed directly in tests. TCP requests route through
	// conn so the flags, and the TSIG state, survive the per-query response
	// wrappers.
	closed         bool // connection has been closed
	hijacked       bool // connection has been hijacked by handler
	tsigTimersOnly bool
	tsigStatus     error
	tsigRequestMAC string
	tsigProvider   TsigProvider
	udp            net.PacketConn // i/o connection if UDP was used
	tcp            net.Conn       // i/o connection if TCP was used
	udpSession     *SessionUDP    // oob data to get egress interface right
	pcSession      net.Addr       // address to use when writing to a generic net.PacketConn
	writer         Writer         // writer to output the raw DNS bits
}

// TSIG state accessors. On a TCP connection the state lives in the shared
// connState so signed multi-message conversations (AXFR/IXFR) keep working
// across per-query response wrappers. UDP and zero-value responses keep the
// state on the response itself.
func (w *response) getTsigTimersOnly() bool {
	if w.conn != nil {
		w.conn.tsigMu.RLock()
		b := w.conn.tsigTimersOnly
		w.conn.tsigMu.RUnlock()
		return b
	}
	return w.tsigTimersOnly
}

func (w *response) setTsigTimersOnly(b bool) {
	if w.conn != nil {
		w.conn.tsigMu.Lock()
		w.conn.tsigTimersOnly = b
		w.conn.tsigMu.Unlock()
		return
	}
	w.tsigTimersOnly = b
}

func (w *response) getTsigStatus() error {
	if w.conn != nil {
		w.conn.tsigMu.RLock()
		e := w.conn.tsigStatus
		w.conn.tsigMu.RUnlock()
		return e
	}
	return w.tsigStatus
}

func (w *response) setTsigStatus(e error) {
	if w.conn != nil {
		w.conn.tsigMu.Lock()
		w.conn.tsigStatus = e
		w.conn.tsigMu.Unlock()
		return
	}
	w.tsigStatus = e
}

func (w *response) getTsigRequestMAC() string {
	if w.conn != nil {
		w.conn.tsigMu.RLock()
		mac := w.conn.tsigRequestMAC
		w.conn.tsigMu.RUnlock()
		return mac
	}
	return w.tsigRequestMAC
}

func (w *response) setTsigRequestMAC(mac string) {
	if w.conn != nil {
		w.conn.tsigMu.Lock()
		w.conn.tsigRequestMAC = mac
		w.conn.tsigMu.Unlock()
		return
	}
	w.tsigRequestMAC = mac
}

// isClosed reports the connection-level closed flag regardless of transport.
func (w *response) isClosed() bool {
	if w.conn != nil {
		return w.conn.closed.Load()
	}
	return w.closed
}

// setClosed records the connection-level closed flag regardless of transport.
func (w *response) setClosed(v bool) {
	if w.conn != nil {
		w.conn.closed.Store(v)
		return
	}
	w.closed = v
}

// isHijacked reports the connection-level hijacked flag regardless of transport.
func (w *response) isHijacked() bool {
	if w.conn != nil {
		return w.conn.hijacked.Load()
	}
	return w.hijacked
}

// setHijacked records the connection-level hijacked flag regardless of transport.
func (w *response) setHijacked(v bool) {
	if w.conn != nil {
		w.conn.hijacked.Store(v)
		return
	}
	w.hijacked = v
}

// writable reports whether a write may still reach the transport. A request
// is writable while it is active or once the handler has transferred
// ownership of the connection with Hijack: an asynchronous handler goroutine
// is then the legitimate owner and its writes must continue to work after
// the dispatching handler has returned. A panic, a disconnect or Close all
// leave the response non-writable, so a late write can never contaminate a
// later message on the same TCP connection.
func (w *response) writable() bool {
	if w.active() {
		return true
	}
	cause, ok := w.terminalCause()
	return ok && cause == stateTerminalReturn && w.isHijacked()
}

// handleRefused returns a HandlerFunc that returns REFUSED for every request it gets.
func handleRefused(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeRefused)
	w.WriteMsg(m)
}

// HandleFailed returns a HandlerFunc that returns SERVFAIL for every request it gets.
// Deprecated: This function is going away.
func HandleFailed(w ResponseWriter, r *Msg) {
	m := new(Msg)
	m.SetRcode(r, RcodeServerFailure)
	// does not matter if this write fails
	w.WriteMsg(m)
}

// ListenAndServe Starts a server on address and network specified Invoke handler
// for incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts like http.ListenAndServeTLS, more information in
// http://golang.org/pkg/net/http/#ListenAndServeTLS
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: &config,
		Handler:   handler,
	}

	return server.ListenAndServe()
}

// ActivateAndServe activates a server with a listener from systemd,
// l and p should not both be non-nil.
// If both l and p are not nil only p will be used.
// Invoke handler for incoming queries.
func ActivateAndServe(l net.Listener, p net.PacketConn, handler Handler) error {
	server := &Server{Listener: l, PacketConn: p, Handler: handler}
	return server.ActivateAndServe()
}

// Writer writes raw DNS messages; each call to Write should send an entire message.
type Writer interface {
	io.Writer
}

// Reader reads raw DNS messages; each call to ReadTCP or ReadUDP should return an entire message.
type Reader interface {
	// ReadTCP reads a raw message from a TCP connection. Implementations may alter
	// connection properties, for example the read-deadline.
	ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error)
	// ReadUDP reads a raw message from a UDP connection. Implementations may alter
	// connection properties, for example the read-deadline.
	ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error)
}

// PacketConnReader is an optional interface that Readers can implement to support using generic net.PacketConns.
type PacketConnReader interface {
	Reader

	// ReadPacketConn reads a raw message from a generic net.PacketConn UDP connection. Implementations may
	// alter connection properties, for example the read-deadline.
	ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error)
}

// defaultReader is an adapter for the Server struct that implements the Reader and
// PacketConnReader interfaces using the readTCP, readUDP and readPacketConn funcs
// of the embedded Server.
type defaultReader struct {
	*Server
}

var _ PacketConnReader = defaultReader{}

func (dr defaultReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return dr.readTCP(conn, timeout)
}

func (dr defaultReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error) {
	return dr.readUDP(conn, timeout)
}

func (dr defaultReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	return dr.readPacketConn(conn, timeout)
}

// DecorateReader is a decorator hook for extending or supplanting the functionality of a Reader.
// Implementations should never return a nil Reader.
// Readers should also implement the optional PacketConnReader interface.
// PacketConnReader is required to use a generic net.PacketConn.
type DecorateReader func(Reader) Reader

// DecorateWriter is a decorator hook for extending or supplanting the functionality of a Writer.
// Implementations should never return a nil Writer.
type DecorateWriter func(Writer) Writer

// MsgInvalidFunc is a listener hook for observing incoming messages that were discarded
// because they could not be parsed.
// Every message that is read by a Reader will eventually be provided to the Handler,
// rejected (or ignored) by the MsgAcceptFunc, or passed to this function.
type MsgInvalidFunc func(m []byte, err error)

var DefaultMsgInvalidFunc MsgInvalidFunc = defaultMsgInvalidFunc

func defaultMsgInvalidFunc(m []byte, err error) {}

// A Server defines parameters for running an DNS server.
type Server struct {
	// Address to listen on, ":dns" if empty.
	Addr string
	// if "tcp" or "tcp-tls" (DNS over TLS) it will invoke a TCP listener, otherwise an UDP one
	Net string
	// TCP Listener to use, this is to aid in systemd's socket activation.
	Listener net.Listener
	// TLS connection configuration
	TLSConfig *tls.Config
	// UDP "Listener" to use, this is to aid in systemd's socket activation.
	PacketConn net.PacketConn
	// Handler to invoke, dns.DefaultServeMux if nil.
	Handler Handler
	// Default buffer size to use to read incoming UDP messages. If not set
	// it defaults to MinMsgSize (512 B).
	UDPSize int
	// The net.Conn.SetReadTimeout value for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// The net.Conn.SetWriteTimeout value for new connections, defaults to 2 * time.Second.
	WriteTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout func() time.Duration
	// An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	TsigProvider TsigProvider
	// Secret(s) for Tsig map[<zonename>]<base64 secret>. The zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2).
	TsigSecret map[string]string
	// If NotifyStartedFunc is set it is called once the server has started listening.
	NotifyStartedFunc func()
	// DecorateReader is optional, allows customization of the process that reads raw DNS messages.
	// The decorated reader must not mutate the data read from the conn.
	DecorateReader DecorateReader
	// DecorateWriter is optional, allows customization of the process that writes raw DNS messages.
	DecorateWriter DecorateWriter
	// Maximum number of TCP queries before we close the socket. Default is maxTCPQueries (unlimited if -1).
	MaxTCPQueries int
	// Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReusePort bool
	// Whether to set the SO_REUSEADDR socket option, allowing multiple listeners to be bound to a single address.
	// Crucially this allows binding when an existing server is listening on `0.0.0.0` or `::`.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReuseAddr bool
	// AcceptMsgFunc will check the incoming message and will reject it early in the process.
	// By default DefaultMsgAcceptFunc will be used.
	MsgAcceptFunc MsgAcceptFunc
	// MsgInvalidFunc is optional, will be called if a message is received but cannot be parsed.
	MsgInvalidFunc MsgInvalidFunc

	// PanicHandler is called with the recovered value and the in-flight
	// ResponseWriter when a handler panics. If nil the panic is recovered
	// silently. The server always finalizes the request exactly once and,
	// for TCP, closes the connection so a panic cannot crash the process or
	// leave a half-written message on the stream.
	PanicHandler func(ResponseWriter, interface{})

	// Lifecycle state machine. The transitions are:
	//
	//	serverNew -> serverStarted   (ListenAndServe / ActivateAndServe)
	//	serverStarted -> serverDraining -> serverClosed (ShutdownContext)
	//	serverStarted -> serverNew (fatal accept/serve error or failed
	//	                           startup, rolled back so the Server may be
	//	                           started again)
	//
	// Every transition is taken under lock and an invalid transition leaves
	// the state untouched, so a failed change is effectively rolled back.
	lock     sync.RWMutex
	started  bool
	state    serverState
	shutdown chan struct{}
	conns    map[net.Conn]struct{}

	// activeRequests tracks all in-flight request goroutines. Add happens
	// before the goroutine is spawned and while the server is still in the
	// serverStarted state, so ShutdownContext can rely on it to drain every
	// request that was ever dispatched.
	activeRequests sync.WaitGroup

	// connSeq hands out frozen connection identities.
	connSeq atomic.Uint64

	// A pool for UDP message buffers.
	udpPool sync.Pool
}

// serverState is the lifecycle state of a Server.
type serverState uint32

const (
	serverNew serverState = iota
	serverStarted
	serverDraining
	serverClosed
)

// transition moves the server to want. It must be called with lock held and
// returns an error without mutating state when the transition is not allowed
// in the current state, which makes every state change rollback-able.
func (srv *Server) transition(want serverState) error {
	ok := false
	switch srv.state {
	case serverNew:
		ok = want == serverStarted
	case serverStarted:
		ok = want == serverDraining || want == serverNew
	case serverDraining:
		ok = want == serverClosed
	}
	if !ok {
		return &Error{err: "invalid server state transition"}
	}
	srv.state = want
	return nil
}

func (srv *Server) tsigProvider() TsigProvider {
	if srv.TsigProvider != nil {
		return srv.TsigProvider
	}
	if srv.TsigSecret != nil {
		return tsigSecretProvider(srv.TsigSecret)
	}
	return nil
}

func (srv *Server) isStarted() bool {
	srv.lock.RLock()
	started := srv.started && srv.state == serverStarted
	srv.lock.RUnlock()
	return started
}

func makeUDPBuffer(size int) func() interface{} {
	return func() interface{} {
		return make([]byte, size)
	}
}

func (srv *Server) init() {
	srv.shutdown = make(chan struct{})
	srv.conns = make(map[net.Conn]struct{})

	if srv.UDPSize == 0 {
		srv.UDPSize = MinMsgSize
	}
	if srv.MsgAcceptFunc == nil {
		srv.MsgAcceptFunc = DefaultMsgAcceptFunc
	}
	if srv.MsgInvalidFunc == nil {
		srv.MsgInvalidFunc = DefaultMsgInvalidFunc
	}
	if srv.Handler == nil {
		srv.Handler = DefaultServeMux
	}

	srv.udpPool.New = makeUDPBuffer(srv.UDPSize)
}

func unlockOnce(l sync.Locker) func() {
	var once sync.Once
	return func() { once.Do(l.Unlock) }
}

// beginServe transitions the server from serverNew to serverStarted. It must
// be called with lock held. The transition is rejected while a server is
// already running.
func (srv *Server) beginServe() error {
	if srv.started {
		return &Error{err: "server already started"}
	}
	if err := srv.transition(serverStarted); err != nil {
		return &Error{err: "server already started"}
	}
	srv.started = true
	return nil
}

// endServe is invoked when the accept loop exits. On a clean shutdown the
// state is already serverDraining or serverClosed and is left untouched. On
// a fatal serve error it rolls the state back to serverNew so the Server
// can be started again, and releases any in-flight requests that were
// waiting on the server.
func (srv *Server) endServe() {
	srv.lock.Lock()
	srv.endServeLocked()
	srv.lock.Unlock()
}

// endServeLocked performs the rollback without touching lock. Callers that
// already hold lock (the startup error paths) must use this variant.
func (srv *Server) endServeLocked() {
	if srv.state == serverStarted {
		srv.state = serverNew
		srv.started = false
	}
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	unlock := unlockOnce(&srv.lock)
	srv.lock.Lock()
	defer unlock()

	if srv.started {
		return &Error{err: "server already started"}
	}

	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}

	srv.init()
	if err := srv.beginServe(); err != nil {
		return err
	}

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			srv.endServeLocked()
			return err
		}
		srv.Listener = l
		unlock()
		return srv.serveTCP(l)
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			srv.endServeLocked()
			return errors.New("neither Certificates nor GetCertificate set in config")
		}
		network := strings.TrimSuffix(srv.Net, "-tls")
		l, err := listenTCP(network, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			srv.endServeLocked()
			return err
		}
		l = tls.NewListener(l, srv.TLSConfig)
		srv.Listener = l
		unlock()
		return srv.serveTCP(l)
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			srv.endServeLocked()
			return err
		}
		u := l.(*net.UDPConn)
		if e := setUDPSocketOptions(u); e != nil {
			u.Close()
			srv.endServeLocked()
			return e
		}
		srv.PacketConn = l
		unlock()
		return srv.serveUDP(u)
	}
	srv.endServeLocked()
	return &Error{err: "bad network"}
}

// ActivateAndServe starts a nameserver with the PacketConn or Listener
// configured in *Server. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
	unlock := unlockOnce(&srv.lock)
	srv.lock.Lock()
	defer unlock()

	if srv.started {
		return &Error{err: "server already started"}
	}

	srv.init()
	if err := srv.beginServe(); err != nil {
		return err
	}

	if srv.PacketConn != nil {
		// Check PacketConn interface's type is valid and value
		// is not nil
		if t, ok := srv.PacketConn.(*net.UDPConn); ok && t != nil {
			if e := setUDPSocketOptions(t); e != nil {
				srv.endServeLocked()
				return e
			}
		}
		unlock()
		return srv.serveUDP(srv.PacketConn)
	}
	if srv.Listener != nil {
		unlock()
		return srv.serveTCP(srv.Listener)
	}
	srv.endServeLocked()
	return &Error{err: "bad listeners"}
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe and
// ActivateAndServe will return.
func (srv *Server) Shutdown() error {
	return srv.ShutdownContext(context.Background())
}

// ShutdownContext shuts down a server. After a call to ShutdownContext,
// ListenAndServe and ActivateAndServe will return.
//
// A context.Context may be passed to limit how long to wait for connections
// to terminate.
//
// The shutdown is an explicit, ordered state transition:
//
//  1. the server moves to the draining state and stops accepting new TCP
//     connections and reading new UDP datagrams - no new request is
//     dispatched after this point;
//  2. reads on the listener, packet connection and idle connections are
//     unblocked;
//  3. in-flight requests are drained, bounded by ctx;
//  4. the transports are closed (the listener/packet connection always, and
//     any remaining TCP connections if the deadline expires) before the
//     server reaches the closed state.
//
// Every phase either completes or rolls the context error back to the
// caller; the state itself never moves backwards while the server is
// shutting down.
func (srv *Server) ShutdownContext(ctx context.Context) error {
	// Phase 1: stop dispatching. The transition is rejected unless the
	// server is actually running, which keeps Shutdown idempotent in the
	// sense that a second call waits for the same shutdown to complete.
	srv.lock.Lock()
	if !srv.started {
		srv.lock.Unlock()
		return &Error{err: "server not started"}
	}
	if srv.state != serverStarted {
		// Already draining or closed: wait for completion below.
	} else if err := srv.transition(serverDraining); err != nil {
		srv.lock.Unlock()
		return err
	}
	srv.started = false

	// Phase 2: stop Accept and unblock every read.
	if srv.PacketConn != nil {
		srv.PacketConn.SetReadDeadline(aLongTimeAgo) // Unblock reads
	}

	if srv.Listener != nil {
		srv.Listener.Close()
	}

	for rw := range srv.conns {
		rw.SetReadDeadline(aLongTimeAgo) // Unblock reads
	}

	srv.lock.Unlock()

	if testShutdownNotify != nil {
		testShutdownNotify.Broadcast()
	}

	// Phase 3: drain active requests, bounded by the context.
	var ctxErr error
	done := make(chan struct{})
	go func() {
		srv.activeRequests.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}

	// Phase 4: close the transports. The packet connection is always
	// closed; TCP connections that were still active when the deadline
	// expired are closed here so they cannot be reused afterwards, and
	// removed from the tracking map immediately so Shutdown never returns
	// with stale entries. A later delete by the connection goroutine is a
	// no-op.
	srv.lock.Lock()
	if srv.Listener != nil {
		for rw := range srv.conns {
			rw.Close()
			delete(srv.conns, rw)
		}
	}
	if srv.PacketConn != nil {
		srv.PacketConn.Close()
	}
	if srv.state == serverDraining {
		srv.transition(serverClosed)
	}
	srv.lock.Unlock()

	return ctxErr
}

var testShutdownNotify *sync.Cond

// getReadTimeout is a helper func to use system timeout if server did not intend to change it.
func (srv *Server) getReadTimeout() time.Duration {
	if srv.ReadTimeout != 0 {
		return srv.ReadTimeout
	}
	return dnsTimeout
}

// serveTCP starts a TCP listener for the server.
func (srv *Server) serveTCP(l net.Listener) (err error) {
	defer func() {
		l.Close()
		// On a fatal accept error the server never entered draining: roll
		// back to serverNew so it can be started again. On shutdown the
		// state is already draining or closed and must not be reset.
		srv.endServe()
		close(srv.shutdown)
	}()

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	for srv.isStarted() {
		rw, err := l.Accept()
		if err != nil {
			if !srv.isStarted() {
				return nil
			}
			if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
				continue
			}
			return err
		}
		srv.lock.Lock()
		// Track the connection to allow unblocking reads on shutdown.
		srv.conns[rw] = struct{}{}
		srv.lock.Unlock()
		wg.Add(1)
		go srv.serveTCPConn(&wg, rw)
	}

	return nil
}

// serveUDP starts a UDP listener for the server.
func (srv *Server) serveUDP(l net.PacketConn) (err error) {
	defer func() {
		l.Close()
		srv.endServe()
		close(srv.shutdown)
	}()

	reader := Reader(defaultReader{srv})
	if srv.DecorateReader != nil {
		reader = srv.DecorateReader(reader)
	}

	lUDP, isUDP := l.(*net.UDPConn)
	readerPC, canPacketConn := reader.(PacketConnReader)
	if !isUDP && !canPacketConn {
		return &Error{err: "PacketConnReader was not implemented on Reader returned from DecorateReader but is required for net.PacketConn"}
	}

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	rtimeout := srv.getReadTimeout()
	// deadline is not used here
	for srv.isStarted() {
		var (
			m    []byte
			sPC  net.Addr
			sUDP *SessionUDP
			err  error
		)
		if isUDP {
			m, sUDP, err = reader.ReadUDP(lUDP, rtimeout)
		} else {
			m, sPC, err = readerPC.ReadPacketConn(l, rtimeout)
		}
		if err != nil {
			if !srv.isStarted() {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return err
		}
		if len(m) < headerSize {
			if cap(m) == srv.UDPSize {
				srv.udpPool.Put(m[:srv.UDPSize])
			}
			srv.MsgInvalidFunc(m, ErrShortRead)
			continue
		}
		// Freeze the request before the goroutine starts. Once draining
		// has begun the packet is dropped rather than dispatched.
		if !srv.beginRequest() {
			if cap(m) == srv.UDPSize {
				srv.udpPool.Put(m[:srv.UDPSize])
			}
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer srv.activeRequests.Done()
			srv.serveUDPPacket(m, l, sUDP, sPC)
		}()
	}

	return nil
}

// beginRequest reserves a slot for an in-flight request. It returns false
// once shutdown has started, in which case the request must not be
// dispatched. The Add precedes the goroutine spawn so ShutdownContext's
// Wait observes every request that passes this gate.
func (srv *Server) beginRequest() bool {
	srv.lock.RLock()
	ok := srv.state == serverStarted
	if ok {
		srv.activeRequests.Add(1)
	}
	srv.lock.RUnlock()
	return ok
}

// connState holds the connection-level state that must survive across the
// per-query response wrappers used on a TCP connection. The closed and
// hijacked flags are connection scoped, as is the TSIG state which carries
// request MACs across the messages of a signed connection. The flags are
// atomic because a handler goroutine may still hold a ResponseWriter while
// the connection goroutine tears the connection down.
type connState struct {
	closed         atomic.Bool
	hijacked       atomic.Bool
	tsigTimersOnly bool
	tsigStatus     error
	tsigRequestMAC string
	tsigMu         sync.RWMutex
}

// Serve a new TCP connection.
func (srv *Server) serveTCPConn(wg *sync.WaitGroup, rw net.Conn) {
	connID := srv.connSeq.Add(1)
	cs := &connState{}

	reader := Reader(defaultReader{srv})
	if srv.DecorateReader != nil {
		reader = srv.DecorateReader(reader)
	}

	idleTimeout := tcpIdleTimeout
	if srv.IdleTimeout != nil {
		idleTimeout = srv.IdleTimeout()
	}

	timeout := srv.getReadTimeout()

	limit := srv.MaxTCPQueries
	if limit == 0 {
		limit = maxTCPQueries
	}

	for q := uint64(0); (q < uint64(limit) || limit == -1) && srv.isStarted(); q++ {
		m, err := reader.ReadTCP(rw, timeout)
		if err != nil {
			// TODO(tmthrgd): handle error
			break
		}

		// No new request once shutdown has begun; the read deadline set by
		// ShutdownContext makes this a rare race rather than the common path.
		if !srv.beginRequest() {
			break
		}
		func() {
			defer srv.activeRequests.Done()

			// Each query gets a fresh response with its own terminal-state
			// machine. A late write from a previous query therefore cannot
			// reach the stream and corrupt this one.
			w := srv.newTCPResponse(rw, cs, connID, q+1)
			srv.dispatchRequest(m, w)
		}()
		if cs.closed.Load() {
			break // Close() was called
		}
		if cs.hijacked.Load() {
			break // client will call Close() themselves
		}
		// The first read uses the read timeout, the rest use the
		// idle timeout.
		timeout = idleTimeout
	}

	if !cs.hijacked.Load() {
		// Close through a response so the shared flags are updated.
		srv.newTCPResponse(rw, cs, connID, 0).Close()
	}

	srv.lock.Lock()
	delete(srv.conns, rw)
	srv.lock.Unlock()

	wg.Done()
}

// newTCPResponse builds a per-query ResponseWriter for a TCP connection.
func (srv *Server) newTCPResponse(rw net.Conn, cs *connState, connID, querySeq uint64) *response {
	w := &response{
		tsigProvider: srv.tsigProvider(),
		tcp:          rw,
		conn:         cs,
	}
	w.frozen = frozenIdentity{
		proto:    "tcp",
		connID:   connID,
		querySeq: querySeq,
		handler:  srv.Handler,
		local:    rw.LocalAddr(),
		remote:   rw.RemoteAddr(),
	}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}
	return w
}

// newUDPResponse builds the ResponseWriter for a single UDP datagram.
func (srv *Server) newUDPResponse(u net.PacketConn, udpSession *SessionUDP, pcSession net.Addr) *response {
	w := &response{
		tsigProvider: srv.tsigProvider(),
		udp:          u,
		udpSession:   udpSession,
		pcSession:    pcSession,
	}
	w.frozen = frozenIdentity{
		proto:   "udp",
		handler: srv.Handler,
	}
	switch {
	case udpSession != nil:
		w.frozen.remote = udpSession.RemoteAddr()
	case pcSession != nil:
		w.frozen.remote = pcSession
	}
	if u != nil {
		w.frozen.local = u.LocalAddr()
	}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}
	return w
}

// Serve a new UDP request.
func (srv *Server) serveUDPPacket(m []byte, u net.PacketConn, udpSession *SessionUDP, pcSession net.Addr) {
	w := srv.newUDPResponse(u, udpSession, pcSession)
	srv.dispatchRequest(m, w)
}

// dispatchRequest runs the server-side request pipeline for one request and
// guarantees that exactly one terminal state is published. A handler panic
// is recovered here: it finalizes the request with stateTerminalPanic,
// notifies PanicHandler if configured, and never escapes to the connection
// goroutine.
func (srv *Server) dispatchRequest(m []byte, w *response) {
	defer func() {
		if r := recover(); r != nil {
			w.finalize(stateTerminalPanic)
			if srv.PanicHandler != nil {
				func() {
					defer func() { _ = recover() }()
					srv.PanicHandler(w, r)
				}()
			}
			// A panic may have left a partial TCP message on the stream;
			// the connection cannot be reused safely even when it was
			// hijacked, so it is torn down unconditionally.
			if w.tcp != nil && w.conn != nil {
				w.setClosed(true)
				_ = w.tcp.Close()
			}
		}
	}()

	srv.serveDNS(m, w)

	// Handler returned: publish the terminal state unless a disconnect or
	// Close got there first.
	w.finalize(stateTerminalReturn)
}

func (srv *Server) serveDNS(m []byte, w *response) {
	// Freeze the handler at dispatch time so a concurrent mutation of
	// srv.Handler cannot change which handler serves this request.
	if w.frozen.handler == nil {
		w.frozen.handler = srv.Handler
	}

	dh, off, err := unpackMsgHdr(m, 0)
	if err != nil {
		srv.MsgInvalidFunc(m, err)
		// Let client hang, they are sending crap; any reply can be used to amplify.
		return
	}

	req := new(Msg)
	req.setHdr(dh)

	switch action := srv.MsgAcceptFunc(dh); action {
	case MsgAccept:
		err := req.unpack(dh, m, off)
		if err == nil {
			break
		}

		srv.MsgInvalidFunc(m, err)
		fallthrough
	case MsgReject, MsgRejectNotImplemented:
		opcode := req.Opcode
		req.SetRcodeFormatError(req)
		req.Zero = false
		if action == MsgRejectNotImplemented {
			req.Opcode = opcode
			req.Rcode = RcodeNotImplemented
		}

		// Are we allowed to delete any OPT records here?
		req.Ns, req.Answer, req.Extra = nil, nil, nil

		w.WriteMsg(req)
		fallthrough
	case MsgIgnore:
		if w.udp != nil && cap(m) == srv.UDPSize {
			srv.udpPool.Put(m[:srv.UDPSize])
		}

		return
	}

	w.setTsigStatus(nil)
	if w.tsigProvider != nil {
		if t := req.IsTsig(); t != nil {
			w.setTsigStatus(TsigVerifyWithProvider(m, w.tsigProvider, "", false))
			w.setTsigTimersOnly(false)
			w.setTsigRequestMAC(t.MAC)
		}
	}

	if w.udp != nil && cap(m) == srv.UDPSize {
		srv.udpPool.Put(m[:srv.UDPSize])
	}

	w.frozen.handler.ServeDNS(w, req) // Writes back to the client
}

func (srv *Server) readTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// If we race with ShutdownContext, the read deadline may
	// have been set in the distant past to unblock the read
	// below. We must not override it, otherwise we may block
	// ShutdownContext.
	srv.lock.RLock()
	if srv.started {
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	srv.lock.RUnlock()

	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	m := make([]byte, length)
	if _, err := io.ReadFull(conn, m); err != nil {
		return nil, err
	}

	return m, nil
}

func (srv *Server) readUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *SessionUDP, error) {
	srv.lock.RLock()
	if srv.started {
		// See the comment in readTCP above.
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	srv.lock.RUnlock()

	m := srv.udpPool.Get().([]byte)
	n, s, err := ReadFromSessionUDP(conn, m)
	if err != nil {
		srv.udpPool.Put(m)
		return nil, nil, err
	}
	m = m[:n]
	return m, s, nil
}

func (srv *Server) readPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	srv.lock.RLock()
	if srv.started {
		// See the comment in readTCP above.
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	srv.lock.RUnlock()

	m := srv.udpPool.Get().([]byte)
	n, addr, err := conn.ReadFrom(m)
	if err != nil {
		srv.udpPool.Put(m)
		return nil, nil, err
	}
	m = m[:n]
	return m, addr, nil
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m *Msg) (err error) {
	if w.isClosed() {
		return &Error{err: "WriteMsg called after Close"}
	}
	if !w.writable() {
		return ErrRequestFinalized
	}

	var data []byte
	if w.tsigProvider != nil { // if no provider, dont check for the tsig (which is a longer check)
		if t := m.IsTsig(); t != nil {
			data, mac, err := TsigGenerateWithProvider(m, w.tsigProvider, w.getTsigRequestMAC(), w.getTsigTimersOnly())
			if err != nil {
				return err
			}
			w.setTsigRequestMAC(mac)
			_, err = w.writer.Write(data)
			if err != nil {
				err = classifyWriteError(err)
				if isDisconnect(err) {
					w.finalize(stateTerminalDisconnect)
				}
			}
			return err
		}
	}
	data, err = m.Pack()
	if err != nil {
		return err
	}
	_, err = w.writer.Write(data)
	if err != nil {
		err = classifyWriteError(err)
		if isDisconnect(err) {
			w.finalize(stateTerminalDisconnect)
		}
	}
	return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
	if w.isClosed() {
		return 0, &Error{err: "Write called after Close"}
	}
	if !w.writable() {
		return 0, ErrRequestFinalized
	}

	var (
		n   int
		err error
	)
	switch {
	case w.udp != nil:
		if u, ok := w.udp.(*net.UDPConn); ok {
			n, err = WriteToSessionUDP(u, m, w.udpSession)
		} else {
			n, err = w.udp.WriteTo(m, w.pcSession)
		}
	case w.tcp != nil:
		if len(m) > MaxMsgSize {
			return 0, &Error{err: "message too large"}
		}

		msg := make([]byte, 2+len(m))
		binary.BigEndian.PutUint16(msg, uint16(len(m)))
		copy(msg[2:], m)
		n, err = w.tcp.Write(msg)
	default:
		panic("dns: internal error: udp and tcp both nil")
	}
	if err != nil {
		err = classifyWriteError(err)
		if isDisconnect(err) {
			w.finalize(stateTerminalDisconnect)
		}
	}
	return n, err
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	if w.frozen.local != nil {
		return w.frozen.local
	}
	switch {
	case w.udp != nil:
		return w.udp.LocalAddr()
	case w.tcp != nil:
		return w.tcp.LocalAddr()
	default:
		panic("dns: internal error: udp and tcp both nil")
	}
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr {
	if w.frozen.remote != nil {
		return w.frozen.remote
	}
	switch {
	case w.udpSession != nil:
		return w.udpSession.RemoteAddr()
	case w.pcSession != nil:
		return w.pcSession
	case w.tcp != nil:
		return w.tcp.RemoteAddr()
	default:
		panic("dns: internal error: udpSession, pcSession and tcp are all nil")
	}
}

// TsigStatus implements the ResponseWriter.TsigStatus method.
func (w *response) TsigStatus() error { return w.getTsigStatus() }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.setTsigTimersOnly(b) }

// Hijack implements the ResponseWriter.Hijack method.
//
// Hijack transfers connection ownership to the handler and is deliberately
// not a terminal event: a handler may hand the ResponseWriter to another
// goroutine before returning, so the single terminal state is still
// published when the handler returns (or panics), and writes remain legal
// until then.
func (w *response) Hijack() { w.setHijacked(true) }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	if w.isClosed() {
		return &Error{err: "connection already closed"}
	}
	w.setClosed(true)
	// Close is the one externally observable terminal event: subsequent
	// writes must never reach the transport.
	w.finalize(stateTerminalClose)

	switch {
	case w.udp != nil:
		// Can't close the udp conn, as that is actually the listener.
		return nil
	case w.tcp != nil:
		return w.tcp.Close()
	default:
		panic("dns: internal error: udp and tcp both nil")
	}
}

// ConnectionState() implements the ConnectionStater.ConnectionState() interface.
func (w *response) ConnectionState() *tls.ConnectionState {
	type tlsConnectionStater interface {
		ConnectionState() tls.ConnectionState
	}
	if v, ok := w.tcp.(tlsConnectionStater); ok {
		t := v.ConnectionState()
		return &t
	}
	return nil
}
