// DNS server implementation.

package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default maximum number of TCP queries before we close the socket.
const maxTCPQueries = 128

// DefaultDrainTimeout is the default per-handler drain deadline used during
// Shutdown and ShutdownContext when Server.DrainTimeout is zero.
const DefaultDrainTimeout = 30 * time.Second

var (
	// ErrDrainTimeout is the cause (*DrainTimeoutError.Err) returned by
	// Shutdown and ShutdownContext when the drain deadline expired before
	// all in-flight handlers and connections finished.
	ErrDrainTimeout = errors.New("dns: drain timeout expired")
	// ErrHandlerTimeout is returned by ResponseWriter.Write and
	// ResponseWriter.WriteMsg when the handler's own drain deadline
	// expired while the server was shutting down. It is distinguishable
	// from the global shutdown error returned by ShutdownContext.
	ErrHandlerTimeout = errors.New("dns: handler drain deadline expired")
)

// DrainTimeoutError is returned by Shutdown and ShutdownContext when the
// drain did not complete within the allowed deadline. It reports how many
// connections and handlers had not finished when the deadline expired.
// The cause (ErrDrainTimeout or a context error) is available via Err and
// through errors.Is/errors.As.
type DrainTimeoutError struct {
	// Connections is the number of connections still open when the
	// deadline expired.
	Connections int
	// Handlers is the number of handlers still running when the deadline
	// expired.
	Handlers int
	// Err is the underlying cause: ErrDrainTimeout when the server's
	// drain deadline expired, or the context's error when the context
	// passed to ShutdownContext was done first.
	Err error
}

func (e *DrainTimeoutError) Error() string {
	return fmt.Sprintf("dns: shutdown drain incomplete: %d connections, %d handlers remaining: %v", e.Connections, e.Handlers, e.Err)
}

func (e *DrainTimeoutError) Unwrap() error { return e.Err }

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
	closed         atomic.Int32 // connection has been closed
	hijacked       bool         // connection has been hijacked by handler
	tsigTimersOnly bool
	tsigStatus     error
	tsigRequestMAC string
	tsigProvider   TsigProvider
	udp            net.PacketConn // i/o connection if UDP was used
	tcp            net.Conn       // i/o connection if TCP was used
	udpSession     *SessionUDP    // oob data to get egress interface right
	pcSession      net.Addr       // address to use when writing to a generic net.PacketConn
	writer         Writer         // writer to output the raw DNS bits

	server    *Server     // server this response belongs to
	wmu       sync.Mutex  // guards responded, req and serializes writes
	timedOut  atomic.Bool // the handler's drain deadline expired during shutdown
	responded bool        // the handler has written at least one message
	req       *Msg        // request currently being handled, used for the timeout reply
}

// isClosed reports whether Close has been called on this response.
func (w *response) isClosed() bool { return w.closed.Load() == 1 }

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
	// DrainTimeout bounds how long Shutdown and ShutdownContext wait for in-flight
	// handlers to finish after the server stops accepting new queries. Each
	// in-flight handler is given its own deadline of DrainTimeout, measured from
	// the start of the shutdown. When a handler's deadline expires it is sent a
	// SERVFAIL reply if it has not written anything yet, its connection is closed
	// and any further writes fail with ErrHandlerTimeout; ShutdownContext returns
	// a *DrainTimeoutError reporting the number of unfinished connections and
	// handlers. If zero, DefaultDrainTimeout is used. If negative, shutdown waits
	// indefinitely for handlers to finish.
	DrainTimeout time.Duration

	// Shutdown handling
	lock            sync.RWMutex
	started         bool
	draining        bool // shutdown has been initiated
	shutdown        chan struct{}
	conns           map[net.Conn]struct{}
	responses       map[*response]struct{} // in-flight responses, for drain deadlines
	inFlight        atomic.Int64           // number of handlers currently running
	drainTimer      *time.Timer
	drainExpired    chan struct{} // closed by expireDrain
	expiredConns    int           // unfinished connections when the drain expired
	expiredHandlers int           // unfinished handlers when the drain expired
	listenerOnce    sync.Once     // guards Listener.Close
	packetConnOnce  sync.Once     // guards PacketConn.Close

	// A pool for UDP message buffers.
	udpPool sync.Pool
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
	started := srv.started
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
	srv.responses = make(map[*response]struct{})
	srv.draining = false
	srv.drainTimer = nil
	srv.drainExpired = make(chan struct{})
	srv.expiredConns = 0
	srv.expiredHandlers = 0
	srv.listenerOnce = sync.Once{}
	srv.packetConnOnce = sync.Once{}

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

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.started = true
		unlock()
		return srv.serveTCP(l)
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			return errors.New("neither Certificates nor GetCertificate set in config")
		}
		network := strings.TrimSuffix(srv.Net, "-tls")
		l, err := listenTCP(network, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, srv.TLSConfig)
		srv.Listener = l
		srv.started = true
		unlock()
		return srv.serveTCP(l)
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		u := l.(*net.UDPConn)
		if e := setUDPSocketOptions(u); e != nil {
			u.Close()
			return e
		}
		srv.PacketConn = l
		srv.started = true
		unlock()
		return srv.serveUDP(u)
	}
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

	if srv.PacketConn != nil {
		// Check PacketConn interface's type is valid and value
		// is not nil
		if t, ok := srv.PacketConn.(*net.UDPConn); ok && t != nil {
			if e := setUDPSocketOptions(t); e != nil {
				return e
			}
		}
		srv.started = true
		unlock()
		return srv.serveUDP(srv.PacketConn)
	}
	if srv.Listener != nil {
		srv.started = true
		unlock()
		return srv.serveTCP(srv.Listener)
	}
	return &Error{err: "bad listeners"}
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe and
// ActivateAndServe will return. Shutdown is idempotent: calling it more than
// once, or racing it with the serve loop exiting, is safe and closes every
// listener and connection at most once.
func (srv *Server) Shutdown() error {
	return srv.ShutdownContext(context.Background())
}

// ShutdownContext shuts down a server. After a call to ShutdownContext,
// ListenAndServe and ActivateAndServe will return.
//
// ShutdownContext first stops accepting new queries: reads on the packet
// connection and Accept on the listener are unblocked, but the listeners
// themselves are kept open until all in-flight requests have completed.
// Each in-flight handler then has its own deadline of Server.DrainTimeout
// to finish; when that deadline expires the handler is sent a SERVFAIL
// reply (if it has not responded yet), in-progress transfers and blocked
// writes are aborted by closing the underlying connections exactly once,
// and ShutdownContext returns a *DrainTimeoutError with the number of
// connections and handlers that had not finished.
//
// A context.Context may be passed to limit how long to wait for connections
// to terminate; when it is done first, the returned *DrainTimeoutError wraps
// the context's error.
//
// ShutdownContext is idempotent: concurrent and repeated calls wait for the
// same shutdown and report its result.
func (srv *Server) ShutdownContext(ctx context.Context) error {
	srv.lock.Lock()
	if !srv.started && !srv.draining {
		srv.lock.Unlock()
		return &Error{err: "server not started"}
	}

	if srv.started {
		srv.started = false
		srv.draining = true

		// Stop accepting new queries immediately, but keep the listeners
		// open: they are closed by the serve loops once all in-flight
		// requests have completed.
		if srv.PacketConn != nil {
			srv.PacketConn.SetReadDeadline(aLongTimeAgo) // Unblock reads
		}

		if srv.Listener != nil {
			if l, ok := srv.Listener.(interface{ SetDeadline(time.Time) error }); ok {
				l.SetDeadline(aLongTimeAgo) // Unblock Accept
			} else {
				srv.closeListener()
			}
		}

		for rw := range srv.conns {
			rw.SetReadDeadline(aLongTimeAgo) // Unblock reads
		}

		if timeout := srv.getDrainTimeout(); timeout >= 0 {
			expired := srv.drainExpired
			srv.drainTimer = time.AfterFunc(timeout, func() { srv.expireDrain(expired) })
		}
	}

	shutdown := srv.shutdown
	drainExpired := srv.drainExpired
	srv.lock.Unlock()

	if testShutdownNotify != nil {
		testShutdownNotify.Broadcast()
	}

	if srv.getDrainTimeout() < 0 {
		// No drain deadline: wait indefinitely, like before.
		select {
		case <-shutdown:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	select {
	case <-shutdown:
		// Drained before the deadline. If the deadline fired concurrently
		// the drain did not complete cleanly on its own; report it.
		select {
		case <-drainExpired:
			return srv.drainError(ErrDrainTimeout)
		default:
		}
		srv.lock.Lock()
		if srv.drainTimer != nil {
			srv.drainTimer.Stop()
		}
		srv.lock.Unlock()
		return nil
	case <-drainExpired:
		return srv.drainError(ErrDrainTimeout)
	case <-ctx.Done():
		return srv.drainError(ctx.Err())
	}
}

// getDrainTimeout returns the per-handler drain deadline for shutdown.
func (srv *Server) getDrainTimeout() time.Duration {
	if srv.DrainTimeout == 0 {
		return DefaultDrainTimeout
	}
	return srv.DrainTimeout
}

// drainError builds the *DrainTimeoutError returned when a shutdown drain
// did not finish in time, reporting the unfinished connections and handlers.
func (srv *Server) drainError(cause error) error {
	srv.lock.RLock()
	conns := len(srv.conns)
	handlers := int(srv.inFlight.Load())
	if cause == ErrDrainTimeout {
		// Report the counts captured when the deadline expired; the
		// force-close below may have raced handlers to completion since.
		conns = srv.expiredConns
		handlers = srv.expiredHandlers
	}
	srv.lock.RUnlock()
	return &DrainTimeoutError{
		Connections: conns,
		Handlers:    handlers,
		Err:         cause,
	}
}

// expireDrain runs when the drain deadline expires. It times out every
// in-flight handler (sending a SERVFAIL to the ones that have not responded
// yet) and closes each connection and the packet connection exactly once so
// that blocked reads, writes and in-progress transfers cannot keep blocking.
// expired must be the drain-expired channel of the serve cycle the timer was
// started in; a stale timer from a previous cycle does nothing.
func (srv *Server) expireDrain(expired chan struct{}) {
	srv.lock.Lock()
	if !srv.draining || srv.drainExpired != expired {
		// The server was restarted since this timer was started.
		srv.lock.Unlock()
		return
	}
	select {
	case <-srv.shutdown:
		// The drain already completed cleanly.
		srv.lock.Unlock()
		return
	default:
	}
	responses := make([]*response, 0, len(srv.responses))
	for w := range srv.responses {
		responses = append(responses, w)
	}
	conns := make([]net.Conn, 0, len(srv.conns))
	for rw := range srv.conns {
		conns = append(conns, rw)
	}
	// Capture the unfinished counts before the force-close below races
	// the remaining handlers to completion.
	srv.expiredConns = len(conns)
	srv.expiredHandlers = int(srv.inFlight.Load())
	srv.lock.Unlock()

	// Signal the deadline first: closing the connections below unblocks
	// the remaining handlers, which lets the serve loops close the
	// shutdown channel — waiters must observe the expiry, not a clean
	// drain.
	close(expired)
	for _, w := range responses {
		w.timeout()
	}
	for _, rw := range conns {
		rw.Close()
	}
	srv.closePacketConn()
}

// closeListener closes the server listener at most once.
func (srv *Server) closeListener() {
	srv.listenerOnce.Do(func() {
		if srv.Listener != nil {
			srv.Listener.Close()
		}
	})
}

// closePacketConn closes the server packet connection at most once.
func (srv *Server) closePacketConn() {
	srv.packetConnOnce.Do(func() {
		if srv.PacketConn != nil {
			srv.PacketConn.Close()
		}
	})
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
func (srv *Server) serveTCP(l net.Listener) error {
	defer srv.closeListener()

	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(srv.shutdown)
	}()

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
func (srv *Server) serveUDP(l net.PacketConn) error {
	defer srv.closePacketConn()

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
	defer func() {
		wg.Wait()
		close(srv.shutdown)
	}()

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
		wg.Add(1)
		go srv.serveUDPPacket(&wg, m, l, sUDP, sPC)
	}

	return nil
}

// Serve a new TCP connection.
func (srv *Server) serveTCPConn(wg *sync.WaitGroup, rw net.Conn) {
	w := &response{server: srv, tsigProvider: srv.tsigProvider(), tcp: rw}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}

	srv.lock.Lock()
	// Track the response to enforce per-handler drain deadlines on shutdown.
	srv.responses[w] = struct{}{}
	srv.lock.Unlock()

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

	for q := 0; (q < limit || limit == -1) && srv.isStarted(); q++ {
		m, err := reader.ReadTCP(w.tcp, timeout)
		if err != nil {
			// TODO(tmthrgd): handle error
			break
		}
		srv.serveDNS(m, w)
		if w.isClosed() {
			break // Close() was called
		}
		if w.hijacked {
			break // client will call Close() themselves
		}
		// The first read uses the read timeout, the rest use the
		// idle timeout.
		timeout = idleTimeout
	}

	if !w.hijacked {
		w.Close()
	}

	srv.lock.Lock()
	delete(srv.conns, w.tcp)
	delete(srv.responses, w)
	srv.lock.Unlock()

	wg.Done()
}

// Serve a new UDP request.
func (srv *Server) serveUDPPacket(wg *sync.WaitGroup, m []byte, u net.PacketConn, udpSession *SessionUDP, pcSession net.Addr) {
	w := &response{server: srv, tsigProvider: srv.tsigProvider(), udp: u, udpSession: udpSession, pcSession: pcSession}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}

	srv.lock.Lock()
	// Track the response to enforce per-handler drain deadlines on shutdown.
	srv.responses[w] = struct{}{}
	srv.lock.Unlock()

	srv.serveDNS(m, w)

	srv.lock.Lock()
	delete(srv.responses, w)
	srv.lock.Unlock()

	wg.Done()
}

func (srv *Server) serveDNS(m []byte, w *response) {
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

	w.tsigStatus = nil
	if w.tsigProvider != nil {
		if t := req.IsTsig(); t != nil {
			w.tsigStatus = TsigVerifyWithProvider(m, w.tsigProvider, "", false)
			w.tsigTimersOnly = false
			w.tsigRequestMAC = t.MAC
		}
	}

	if w.udp != nil && cap(m) == srv.UDPSize {
		srv.udpPool.Put(m[:srv.UDPSize])
	}

	// Remember the request so a drain timeout can reply SERVFAIL, and
	// count the in-flight handler for DrainTimeoutError reporting.
	w.wmu.Lock()
	w.req = req
	w.wmu.Unlock()

	srv.inFlight.Add(1)
	srv.Handler.ServeDNS(w, req) // Writes back to the client
	srv.inFlight.Add(-1)
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

	var data []byte
	if w.tsigProvider != nil { // if no provider, dont check for the tsig (which is a longer check)
		if t := m.IsTsig(); t != nil {
			data, w.tsigRequestMAC, err = TsigGenerateWithProvider(m, w.tsigProvider, w.tsigRequestMAC, w.tsigTimersOnly)
			if err != nil {
				return err
			}
			_, err = w.writer.Write(data)
			return err
		}
	}
	data, err = m.Pack()
	if err != nil {
		return err
	}
	_, err = w.writer.Write(data)
	return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
	if w.isClosed() {
		return 0, &Error{err: "Write called after Close"}
	}

	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.timedOut.Load() {
		// The handler's drain deadline expired during shutdown. This is
		// distinguishable from the global shutdown error returned by
		// ShutdownContext.
		return 0, ErrHandlerTimeout
	}

	n, err := w.writeRaw(m)
	if err == nil {
		w.responded = true
	}
	return n, err
}

// writeRaw writes m to the connection. The caller must hold w.wmu, so a
// message is never interleaved with another write or a drain-timeout reply.
func (w *response) writeRaw(m []byte) (int, error) {
	switch {
	case w.udp != nil:
		if u, ok := w.udp.(*net.UDPConn); ok {
			return WriteToSessionUDP(u, m, w.udpSession)
		}
		return w.udp.WriteTo(m, w.pcSession)
	case w.tcp != nil:
		if len(m) > MaxMsgSize {
			return 0, &Error{err: "message too large"}
		}

		msg := make([]byte, 2+len(m))
		binary.BigEndian.PutUint16(msg, uint16(len(m)))
		copy(msg[2:], m)
		// Write the whole framed message; returning early on a short
		// write would leave half a DNS message on the wire.
		written := 0
		for written < len(msg) {
			n, err := w.tcp.Write(msg[written:])
			written += n
			if err != nil {
				return written, err
			}
		}
		return written, nil
	default:
		panic("dns: internal error: udp and tcp both nil")
	}
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
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
func (w *response) TsigStatus() error { return w.tsigStatus }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	if !w.closed.CompareAndSwap(0, 1) {
		return &Error{err: "connection already closed"}
	}

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

// timeout marks the response as timed out because its drain deadline expired
// during a server shutdown. If the handler has not written anything yet, a
// best-effort SERVFAIL reply is sent so clients can distinguish a drain
// timeout from a silently dropped query. Further writes fail with
// ErrHandlerTimeout.
func (w *response) timeout() {
	// Set the flag first and unconditionally: a handler blocked in a
	// write holds wmu, and we must not wait for it here — the connection
	// is closed right after this, which aborts the write.
	w.timedOut.Store(true)

	if !w.wmu.TryLock() {
		// A write is in progress; it is serialized by wmu, so the
		// connection close that follows cannot interleave a half message
		// with another write.
		return
	}
	defer w.wmu.Unlock()

	if w.responded || w.req == nil || w.isClosed() {
		return
	}
	m := new(Msg)
	m.SetRcode(w.req, RcodeServerFailure)
	if data, err := m.Pack(); err == nil {
		w.writeRaw(data) // best effort
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
