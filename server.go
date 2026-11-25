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

// HandlerContext is an optional, context-aware extension of Handler.
// Handlers may implement it directly, or register a HandlerFuncContext.
// The original Handler interface remains unchanged for compatibility.
type HandlerContext interface {
	ServeDNS(context.Context, ResponseWriter, *Msg)
}

// HandlerWithContext is an alias for HandlerContext.
type HandlerWithContext = HandlerContext

// HandlerFuncContext is the context-aware counterpart of HandlerFunc.
type HandlerFuncContext func(context.Context, ResponseWriter, *Msg)

// ServeDNS calls f(ctx, w, r).
func (f HandlerFuncContext) ServeDNS(ctx context.Context, w ResponseWriter, r *Msg) {
	f(ctx, w, r)
}

// HandlerFuncWithContext is an alias for HandlerFuncContext.
type HandlerFuncWithContext = HandlerFuncContext

// ContextHandler is an alternative optional handler interface. It is honored
// when a value does not implement HandlerContext.
type ContextHandler interface {
	ServeDNSContext(context.Context, ResponseWriter, *Msg)
}

// ContextHandlerFunc adapts a function to ContextHandler. It also implements
// HandlerContext for convenience.
type ContextHandlerFunc func(context.Context, ResponseWriter, *Msg)

// ServeDNS calls f(ctx, w, r).
func (f ContextHandlerFunc) ServeDNS(ctx context.Context, w ResponseWriter, r *Msg) {
	f(ctx, w, r)
}

// ServeDNSContext calls f(ctx, w, r).
func (f ContextHandlerFunc) ServeDNSContext(ctx context.Context, w ResponseWriter, r *Msg) {
	f(ctx, w, r)
}

// contextHandlerAdapter exposes a HandlerContext through the original Handler
// interface while retaining the context for context-aware dispatch.
type contextHandlerAdapter struct {
	hc HandlerContext
}

func (h contextHandlerAdapter) ServeDNS(w ResponseWriter, r *Msg) {
	h.hc.ServeDNS(r.Context(), w, r)
}

func (h contextHandlerAdapter) ServeDNSContext(ctx context.Context, w ResponseWriter, r *Msg) {
	h.hc.ServeDNS(ctx, w, r)
}

// dispatchHandler invokes the most context-aware method available while
// preserving the original Handler contract as the fallback.
func dispatchHandler(ctx context.Context, h Handler, w ResponseWriter, r *Msg) {
	switch hh := h.(type) {
	case ContextHandler:
		hh.ServeDNSContext(ctx, w, r)
	case interface {
		ServeDNSWithContext(context.Context, ResponseWriter, *Msg)
	}:
		hh.ServeDNSWithContext(ctx, w, r)
	default:
		h.ServeDNS(w, r)
	}
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

// ResponseWriterWithContext is an optional ResponseWriter implemented by
// servers that attach a lifecycle context to each request. The context is also
// available through Msg.Context.
type ResponseWriterWithContext interface {
	ResponseWriter
	Context() context.Context
}

// ContextResponseWriter is an alias for ResponseWriterWithContext.
type ContextResponseWriter = ResponseWriterWithContext

// ResponseWriterContext is an alias for ResponseWriterWithContext.
type ResponseWriterContext = ResponseWriterWithContext

type response struct {
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
	ctx            context.Context
}

// Context returns the request lifecycle context. It is the same context made
// available through Msg.Context and is safe for handlers and decorators to
// retain until the request returns.
func (w *response) Context() context.Context {
	if w == nil || w.ctx == nil {
		return context.Background()
	}
	return w.ctx
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

// ActivateAndServe activates a server with a listener from systemd.
// l and p may both be non-nil, in which case TCP and UDP are served and shut
// down together. Otherwise the non-nil listener is used.
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
	// if "tcp" or "tcp-tls" (DNS over TLS) it will invoke a TCP listener, otherwise an UDP one.
	// Combined values such as "udp+tcp", "tcp+udp", or "both" bind and serve
	// the same port over both UDP and TCP in one Server.
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

	// HandlerContext is an optional context-aware handler. When non-nil it is
	// invoked instead of Handler. Handlers assigned to Handler may also
	// implement HandlerContext or ContextHandler.
	HandlerContext HandlerContext
	// HandlerWithContext is an alias field for HandlerContext.
	HandlerWithContext HandlerWithContext
	// ContextHandler is an alternative field for a handler implementing
	// ContextHandler. The first non-nil context field wins.
	ContextHandler ContextHandler

	// BaseContext is the parent context for all request contexts. When nil,
	// Context, Ctx, BaseContextFunc or context.Background is used. Canceling it
	// cancels all request contexts.
	BaseContext context.Context
	// Context is an alias for BaseContext.
	Context context.Context
	// Ctx is an alias for BaseContext.
	Ctx context.Context
	// BaseContextFunc, when set, is called once during server initialization to
	// obtain the base context. It is ignored when an explicit context is set.
	BaseContextFunc func() context.Context

	// RequestTimeout bounds the lifetime of an individual handler request. A
	// zero value disables the per-request deadline; a negative value also
	// disables it. The request context is canceled when this deadline expires,
	// when BaseContext is canceled, or when graceful shutdown is initiated.
	RequestTimeout time.Duration
	// HandlerTimeout, QueryTimeout, ContextTimeout and Timeout are accepted as
	// aliases for RequestTimeout. The first positive value wins.
	HandlerTimeout time.Duration
	QueryTimeout   time.Duration
	ContextTimeout time.Duration
	Timeout        time.Duration

	// ShutdownTimeout bounds parameterless Shutdown. If zero,
	// DefaultShutdownTimeout is used. A negative value makes Shutdown wait
	// indefinitely, preserving the historical behavior. ShutdownContext always
	// uses the caller-supplied context and its deadline.
	ShutdownTimeout time.Duration

	// DrainTimeout, GracefulShutdownTimeout, GracePeriod and
	// TerminationGracePeriod are accepted as aliases for ShutdownTimeout. The
	// first non-zero value in that order is used.
	DrainTimeout            time.Duration
	GracefulShutdownTimeout time.Duration
	GracePeriod             time.Duration
	TerminationGracePeriod  time.Duration
	ShutdownGracePeriod     time.Duration
	GracefulShutdownPeriod  time.Duration

	// Logger optionally receives the forced-shutdown log record. When nil, the
	// standard package logger is used.
	Logger Logger
	// Logf optionally receives the forced-shutdown log record. It takes
	// precedence over Logger and the standard logger. Log is an alias.
	Logf func(format string, args ...any)
	Log  func(format string, args ...any)

	// Shutdown handling
	lock            sync.RWMutex
	started         bool
	closing         bool
	shutdown        chan struct{}
	conns           map[net.Conn]struct{}
	requestCancels  map[uint64]context.CancelFunc
	nextRequestID   uint64
	inFlight        atomic.Int64
	shutdownCtx     context.Context
	cancelShutdown  context.CancelFunc
	notifyStarted   sync.Once
	forceOnce       sync.Once
	unfinishedReqs  int
	unfinishedConns int
	lastShutdownErr error

	// A pool for UDP message buffers.
	udpPool sync.Pool
}

// Logger is the minimal logging interface used by Server.
type Logger interface {
	Printf(format string, args ...any)
}

// DefaultShutdownTimeout is used when Server.ShutdownTimeout and its aliases
// are zero.
const DefaultShutdownTimeout = 30 * time.Second

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
	srv.requestCancels = make(map[uint64]context.CancelFunc)
	srv.closing = false
	srv.nextRequestID = 0
	srv.inFlight.Store(0)
	srv.notifyStarted = sync.Once{}
	srv.forceOnce = sync.Once{}
	srv.unfinishedReqs = 0
	srv.unfinishedConns = 0
	srv.lastShutdownErr = nil

	base := srv.BaseContext
	if base == nil {
		base = srv.Context
	}
	if base == nil {
		base = srv.Ctx
	}
	if base == nil && srv.BaseContextFunc != nil {
		base = srv.BaseContextFunc()
	}
	if base == nil {
		base = context.Background()
	}
	srv.shutdownCtx, srv.cancelShutdown = context.WithCancel(base)

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
	srv.prepareBaseContext()

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
	defer srv.cancelShutdown()

	if tcpNetwork, udpNetwork, ok := parseDualNetworks(srv.Net); ok {
		tcpLn, udpConn, err := srv.listenDual(addr, tcpNetwork, udpNetwork)
		if err != nil {
			return err
		}
		srv.Listener = tcpLn
		srv.PacketConn = udpConn
		srv.started = true
		unlock()
		return srv.serveBoth(tcpLn, udpConn)
	}

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

// ActivateAndServe starts a nameserver with the PacketConn and/or Listener
// configured in *Server. When both are set, UDP and TCP run together and are
// shut down together. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
	srv.prepareBaseContext()

	unlock := unlockOnce(&srv.lock)
	srv.lock.Lock()
	defer unlock()

	if srv.started {
		return &Error{err: "server already started"}
	}

	srv.init()
	defer srv.cancelShutdown()

	if srv.PacketConn != nil && srv.Listener != nil {
		// Check PacketConn interface's type is valid and value
		// is not nil
		if t, ok := srv.PacketConn.(*net.UDPConn); ok && t != nil {
			if e := setUDPSocketOptions(t); e != nil {
				return e
			}
		}
		srv.started = true
		unlock()
		return srv.serveBoth(srv.Listener, srv.PacketConn)
	}

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
// ActivateAndServe will return.
//
// Shutdown uses Server.ShutdownTimeout (or one of its compatibility aliases)
// as the total graceful-shutdown limit. A negative value waits indefinitely.
// Use ShutdownContext to supply a caller-owned deadline.
func (srv *Server) Shutdown() error {
	timeout := srv.gracefulShutdownTimeout()
	if timeout < 0 {
		return srv.ShutdownContext(context.Background())
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.ShutdownContext(ctx)
}

// ShutdownContext shuts down a server. After a call to ShutdownContext,
// ListenAndServe and ActivateAndServe will return.
//
// New listeners and connections stop immediately, while already accepted
// requests continue until their handlers return. Request contexts are canceled
// when shutdown begins so cooperative handlers can observe the drain. If ctx
// expires before all work finishes, ShutdownContext closes the remaining
// transports, records the number of unfinished requests, and returns ctx.Err.
//
// A context.Context may be passed to limit how long to wait for requests
// to terminate.
func (srv *Server) ShutdownContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	srv.lock.Lock()
	if !srv.started && !srv.closing {
		srv.lock.Unlock()
		return &Error{err: "server not started"}
	}

	if !srv.closing {
		srv.started = false
		srv.closing = true

		// Cancel request contexts. Handlers that are safe to finish despite
		// cancellation may still write their final response; the transports
		// remain open until the graceful deadline expires.
		if srv.cancelShutdown != nil {
			srv.cancelShutdown()
		}

		if srv.PacketConn != nil {
			srv.PacketConn.SetReadDeadline(aLongTimeAgo) // Unblock reads
		}

		if srv.Listener != nil {
			srv.Listener.Close()
		}

		for rw := range srv.conns {
			rw.SetReadDeadline(aLongTimeAgo) // Unblock reads
		}
	}

	shutdownCh := srv.shutdown
	srv.lock.Unlock()

	if testShutdownNotify != nil {
		testShutdownNotify.Broadcast()
	}

	select {
	case <-shutdownCh:
		// The serve loops close their listeners on exit. Close the packet
		// connection as well to retain the historical Shutdown behavior.
		srv.lock.RLock()
		pc := srv.PacketConn
		srv.lock.RUnlock()
		if pc != nil {
			_ = pc.Close()
		}
		return nil
	case <-ctx.Done():
		// If draining completed at the same instant, prefer the clean result
		// rather than reporting a zero-request forced shutdown.
		select {
		case <-shutdownCh:
			return nil
		default:
		}
		srv.forceOnce.Do(func() {
			srv.forceShutdown(ctx.Err())
		})
		return ctx.Err()
	}
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
	var wg sync.WaitGroup
	defer close(srv.shutdown)
	return srv.serveTCPWithWG(l, &wg)
}

// serveTCPWithWG runs the TCP accept loop and tracks connection goroutines in
// wg. It does not close srv.shutdown; callers composing protocols own that
// final close.
func (srv *Server) serveTCPWithWG(l net.Listener, wg *sync.WaitGroup) error {
	defer l.Close()
	defer wg.Wait()

	srv.notifyStartedOnce()

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
		go srv.serveTCPConn(wg, rw)
	}

	return nil
}

// serveUDP starts a UDP listener for the server.
func (srv *Server) serveUDP(l net.PacketConn) error {
	var wg sync.WaitGroup
	defer close(srv.shutdown)
	return srv.serveUDPWithWG(l, &wg)
}

// serveUDPWithWG runs the UDP read loop and tracks packet goroutines in wg.
// It does not close srv.shutdown; callers composing protocols own that final
// close.
func (srv *Server) serveUDPWithWG(l net.PacketConn, wg *sync.WaitGroup) error {
	defer l.Close()
	defer wg.Wait()

	reader := Reader(defaultReader{srv})
	if srv.DecorateReader != nil {
		reader = srv.DecorateReader(reader)
	}

	lUDP, isUDP := l.(*net.UDPConn)
	readerPC, canPacketConn := reader.(PacketConnReader)
	if !isUDP && !canPacketConn {
		return &Error{err: "PacketConnReader was not implemented on Reader returned from DecorateReader but is required for net.PacketConn"}
	}

	srv.notifyStartedOnce()

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
		// A successful read is treated as admitted work even if Shutdown races
		// immediately afterward. Real transports unblock a blocked Read with
		// an error via the past deadline above, so this does not admit reads
		// started after shutdown.
		if len(m) < headerSize {
			if cap(m) == srv.UDPSize {
				srv.udpPool.Put(m[:srv.UDPSize])
			}
			srv.MsgInvalidFunc(m, ErrShortRead)
			continue
		}
		wg.Add(1)
		go srv.serveUDPPacket(wg, m, l, sUDP, sPC)
	}

	return nil
}

// Serve a new TCP connection.
func (srv *Server) serveTCPConn(wg *sync.WaitGroup, rw net.Conn) {
	w := &response{tsigProvider: srv.tsigProvider(), tcp: rw}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}

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
		if w.closed {
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
	srv.lock.Unlock()

	wg.Done()
}

// Serve a new UDP request.
func (srv *Server) serveUDPPacket(wg *sync.WaitGroup, m []byte, u net.PacketConn, udpSession *SessionUDP, pcSession net.Addr) {
	w := &response{tsigProvider: srv.tsigProvider(), udp: u, udpSession: udpSession, pcSession: pcSession}
	if srv.DecorateWriter != nil {
		w.writer = srv.DecorateWriter(w)
	} else {
		w.writer = w
	}

	srv.serveDNS(m, w)
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

	ctx, endRequest := srv.beginRequest()
	defer endRequest()
	req.ctx = ctx
	w.ctx = ctx

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

	if hc := srv.HandlerContext; hc != nil {
		hc.ServeDNS(ctx, w, req)
		return
	}
	if hc := srv.HandlerWithContext; hc != nil {
		hc.ServeDNS(ctx, w, req)
		return
	}
	if ch := srv.ContextHandler; ch != nil {
		ch.ServeDNSContext(ctx, w, req)
		return
	}

	dispatchHandler(ctx, srv.Handler, w, req) // Writes back to the client
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
	if w.closed {
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
	if w.closed {
		return 0, &Error{err: "Write called after Close"}
	}

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
		return w.tcp.Write(msg)
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
	if w.closed {
		return &Error{err: "connection already closed"}
	}
	w.closed = true

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
