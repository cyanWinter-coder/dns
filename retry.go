package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrNoServers is returned when a failover exchange has no server to query.
var ErrNoServers error = &Error{err: "no DNS servers configured"}

// ErrAllServersFailed can be matched with errors.Is after every server failed.
// RetryError intentionally also wraps the final underlying error.
var ErrAllServersFailed error = &Error{err: "all DNS servers failed"}

// ErrAllFailed is an alias for ErrAllServersFailed.
var ErrAllFailed = ErrAllServersFailed

// ErrRetriesExhausted is an alias for ErrAllServersFailed.
var ErrRetriesExhausted = ErrAllServersFailed

// Attempt records one server exchange performed while satisfying a logical
// query.
type Attempt struct {
	// Server is the normalized host:port address that was contacted.
	Server string

	// Addr is an alias for Server.
	Addr string

	// RTT is the duration of this attempt.
	RTT time.Duration

	// Duration is an alias for RTT.
	Duration time.Duration

	// Err is the attempt error, or nil when it succeeded.
	Err error
}

// RetryError is returned after every configured retry path has failed. It
// retains the last error as Err and also records all prior attempts.
type RetryError struct {
	// Err is the error from the final server attempt.
	Err error

	// LastErr is an alias for Err.
	LastErr error

	// LastError is an alias for Err and LastErr.
	LastError error

	// Cause is an alias for Err.
	Cause error

	// ContextErr is the context cancellation or deadline error, if context
	// ended retry processing before another server could be tried.
	ContextErr error

	// Server is the final server that was tried.
	Server string

	// Addr is an alias for Server.
	Addr string

	// LastServer is an alias for Server.
	LastServer string

	// Errors contains one error per failed attempt, in attempt order.
	Errors []error

	// Attempts contains detailed records for all attempts.
	Attempts []Attempt
}

// FailoverError is an alternative name for RetryError.
type FailoverError = RetryError

// AllServersFailedError is an alternative name for RetryError.
type AllServersFailedError = RetryError

// MultiError is an alternative name for RetryError.
type MultiError = RetryError

// RetryableClient is an alternative name for RetryClient.
type RetryableClient = RetryClient

// ResilientClient is an alternative name for RetryClient.
type ResilientClient = RetryClient

// RetryPool is an alternative name for RetryClient.
type RetryPool = RetryClient

// FailoverPool is an alternative name for RetryClient.
type FailoverPool = RetryClient

// ServerPool is an alternative name for RetryClient.
type ServerPool = RetryClient

// Pool is a short alternative name for RetryClient.
type Pool = RetryClient

func (e *RetryError) Error() string {
	if e == nil {
		return "dns: <nil>"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "dns: all %d DNS server attempts failed", len(e.Attempts))
	if e.Server != "" {
		fmt.Fprintf(&b, "; last server %s", e.Server)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.ContextErr != nil {
		fmt.Fprintf(&b, " (%v)", e.ContextErr)
	}
	return b.String()
}

// Unwrap returns the final attempt error.
func (e *RetryError) Unwrap() error { return e.Err }

// Is makes context.Canceled and context.DeadlineExceeded discoverable even
// though Unwrap intentionally points at the final network error.
func (e *RetryError) Is(target error) bool {
	if target == ErrAllServersFailed || target == ErrAllFailed {
		return true
	}
	return e.ContextErr != nil && errors.Is(e.ContextErr, target)
}

// Timeout reports whether the final error was a timeout. It allows a returned
// *RetryError to satisfy net.Error directly.
func (e *RetryError) Timeout() bool {
	var netErr net.Error
	if errors.As(e.Err, &netErr) {
		return netErr.Timeout()
	}
	return errors.Is(e, context.DeadlineExceeded)
}

// Temporary delegates temporary-error classification to the final error.
func (e *RetryError) Temporary() bool {
	var netErr net.Error
	if errors.As(e.Err, &netErr) {
		return netErr.Temporary()
	}
	return false
}

// normalizeServerAddress adds the default DNS port when address does not
// already contain one. Bare IPv6 addresses are bracketed by JoinHostPort.
func normalizeServerAddress(address string) string {
	return normalizeServerAddressWithPort(address, "53")
}

func normalizeServerAddressWithPort(address, port string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return address
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(address, port)
}

func normalizeServers(servers []string) []string {
	return normalizeServersWithPort(servers, "53")
}

func normalizeServersWithPort(servers []string, port string) []string {
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		server = normalizeServerAddressWithPort(server, port)
		if server != "" {
			out = append(out, server)
		}
	}
	return out
}

// resolveAttemptCount returns the total number of exchanges to perform. A
// non-positive configured value means one attempt per server.
func resolveAttemptCount(configured, serverCount int) int {
	if configured > 0 {
		return configured
	}
	return serverCount
}

// exchangeServers tries servers in order, starting a fresh exchange for each
// timeout or other transport failure. A non-nil pool enables connection reuse;
// otherwise Client.ExchangeContext owns and closes a new connection per
// attempt.
func exchangeServers(
	ctx context.Context,
	c *Client,
	m *Msg,
	servers []string,
	attemptCount int,
	attemptTimeout time.Duration,
	pool *ConnPool,
) (*Msg, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	if c == nil {
		c = new(Client)
	}
	if m == nil {
		return nil, 0, &Error{err: "nil message"}
	}
	if attemptTimeout == 0 {
		attemptTimeout = c.Timeout
	}

	servers = normalizeServers(servers)
	if len(servers) == 0 {
		return nil, 0, ErrNoServers
	}

	attemptCount = resolveAttemptCount(attemptCount, len(servers))

	retryErr := &RetryError{Attempts: make([]Attempt, 0, min(attemptCount, len(servers)*2))}
	var rtt time.Duration

	for i := 0; i < attemptCount; i++ {
		if err := ctx.Err(); err != nil {
			return nil, rtt, err
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return nil, rtt, context.DeadlineExceeded
		}

		server := servers[i%len(servers)]

		// Give every server attempt its own full configured timeout while
		// retaining the caller's deadline/cancellation as the outer bound.
		attemptCtx := ctx
		var cancelAttempt context.CancelFunc
		if attemptTimeout > 0 {
			attemptCtx, cancelAttempt = context.WithTimeout(ctx, attemptTimeout)
		}

		var (
			r   *Msg
			err error
		)
		if pool != nil {
			r, rtt, err = pool.ExchangeContext(attemptCtx, m, server)
		} else {
			r, rtt, err = c.ExchangeContext(attemptCtx, m, server)
		}
		attemptErr := attemptCtx.Err()
		if cancelAttempt != nil {
			cancelAttempt()
		}
		if err != nil && ctx.Err() == nil {
			switch {
			case attemptErr != nil && !errors.Is(err, attemptErr):
				// The context and transport deadlines can race and report
				// different errors for the same timeout.
				err = errors.Join(err, attemptErr)
			case attemptErr == nil && isRetryTimeoutError(err):
				// The socket deadline fired just before the context timer was
				// marked done; make timeout classification explicit anyway.
				err = errors.Join(err, context.DeadlineExceeded)
			}
		}

		if err == nil {
			return r, rtt, nil
		}

		attempt := Attempt{Server: server, Addr: server, RTT: rtt, Duration: rtt, Err: err}
		retryErr.Attempts = append(retryErr.Attempts, attempt)
		retryErr.Errors = append(retryErr.Errors, err)
		retryErr.Server = server
		retryErr.Addr = server
		retryErr.LastServer = server
		retryErr.Err = err
		retryErr.LastErr = err
		retryErr.LastError = err
		retryErr.Cause = err

		// Cancellation is immediate: do not start another dial or retry.
		if ctx.Err() != nil {
			retryErr.ContextErr = ctx.Err()
			return r, rtt, retryErr
		}
	}

	return nil, rtt, retryErr
}

func isRetryTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ExchangeServers sends m to servers in order and retries the next server when
// an exchange fails or times out. Every server is tried once unless c.Attempts
// is positive, in which case attempts wrap around the server list.
//
// The returned error is a *RetryError after all attempts fail. Its Err field is
// the final server error and remains reachable with errors.Is/errors.As.
func (c *Client) ExchangeServers(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return c.ExchangeServersContext(context.Background(), m, servers)
}

// ExchangeServersContext is ExchangeServers with context cancellation and
// deadlines. Cancelling ctx stops retries before the next server is contacted.
func (c *Client) ExchangeServersContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	if c == nil {
		c = new(Client)
	}
	var pool *ConnPool
	if c.ReuseConnections || c.ReuseTCP {
		pool = c.clientConnPool()
	}
	return exchangeServers(ctx, c, m, servers, c.configuredAttempts(), 0, pool)
}

func (c *Client) configuredAttempts() int {
	if c.Attempts > 0 {
		return c.Attempts
	}
	if c.Retries > 0 {
		return c.Retries + 1
	}
	if c.MaxRetries > 0 {
		return c.MaxRetries + 1
	}
	if c.Retry > 0 {
		return c.Retry + 1
	}
	return 0
}

// ExchangeWithRetry is an alias for ExchangeServers.
func (c *Client) ExchangeWithRetry(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return c.ExchangeServers(m, servers)
}

// ExchangeWithRetryContext is an alias for ExchangeServersContext.
func (c *Client) ExchangeWithRetryContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return c.ExchangeServersContext(ctx, m, servers)
}

// ExchangeContextWithRetry is an alias for ExchangeWithRetryContext.
func (c *Client) ExchangeContextWithRetry(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return c.ExchangeWithRetryContext(ctx, m, servers)
}

// ExchangeServers sends m to servers using a zero Client.
func ExchangeServers(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return new(Client).ExchangeServers(m, servers)
}

// ExchangeServersContext sends m to servers using a zero Client and ctx.
func ExchangeServersContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return new(Client).ExchangeServersContext(ctx, m, servers)
}

// ExchangeWithRetry is a package-level alias for ExchangeServers.
func ExchangeWithRetry(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return ExchangeServers(m, servers)
}

// ExchangeWithRetryContext is a package-level alias for
// ExchangeServersContext.
func ExchangeWithRetryContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return ExchangeServersContext(ctx, m, servers)
}

// ExchangeContextWithRetry is an alias for ExchangeWithRetryContext.
func ExchangeContextWithRetry(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return ExchangeWithRetryContext(ctx, m, servers)
}

// NewRetryClientFromConfig builds a RetryClient from resolv.conf-style
// configuration. The configured timeout is interpreted in seconds.
func NewRetryClientFromConfig(config *ClientConfig) *RetryClient {
	if config == nil {
		return NewRetryClient()
	}

	port := config.Port
	if port == "" {
		port = "53"
	}
	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		servers = append(servers, net.JoinHostPort(server, port))
	}

	rc := NewRetryClient(servers...)
	rc.Attempts = config.Attempts
	if config.Timeout > 0 {
		rc.Timeout = time.Duration(config.Timeout) * time.Second
	}
	return rc
}

// RetryClient is a batch-oriented DNS client that fails over between servers
// and can reuse TCP/TLS connections.
//
// The embedded Client supplies all existing transport configuration fields.
// RetryClient adds server selection, retry counting and connection pooling.
// RetryClient is safe for concurrent use; its exported configuration fields
// should be set before the first Exchange call and not mutated afterwards.
type RetryClient struct {
	Client

	// Servers are DNS addresses. Entries without a port use Port or port 53.
	Servers []string

	// Port is appended to bare server addresses. It defaults to 53.
	Port string

	// Attempts is the total number of server exchanges. Zero means one
	// attempt per configured server. Values larger than len(Servers) wrap.
	Attempts int

	// Retry is the number of additional retries after the first attempt.
	Retry int

	// Retries is the number of additional attempts after the first. When
	// positive, Retries+1 takes precedence over Attempts.
	Retries int

	// MaxRetries is an alias for Retries.
	MaxRetries int

	// Timeout optionally sets Client.Timeout for every individual server
	// attempt. A zero value uses the embedded Client's configuration.
	Timeout time.Duration

	// AttemptTimeout is an alias for Timeout.
	AttemptTimeout time.Duration

	// PerAttemptTimeout is an alias for Timeout.
	PerAttemptTimeout time.Duration

	// ReuseConnections enables the connection pool for any transport when
	// true. For TCP and TCP-TLS it is enabled by default; set
	// DisableConnectionReuse to true to dial and close every attempt instead.
	ReuseConnections bool

	// ReuseTCP is an alias for ReuseConnections.
	ReuseTCP bool

	// DisableConnectionReuse turns off persistent connection reuse.
	DisableConnectionReuse bool

	mu   sync.Mutex
	pool *ConnPool
}

// FailoverClient is an alternative name for RetryClient.
type FailoverClient = RetryClient

// BatchClient is an alternative name for RetryClient.
type BatchClient = RetryClient

// Resolver is an alternative name for RetryClient.
type Resolver = RetryClient

// NewRetryClient returns a RetryClient configured with servers.
func NewRetryClient(servers ...string) *RetryClient {
	return &RetryClient{Servers: servers}
}

// NewPool is an alias for NewRetryClient.
func NewPool(servers ...string) *RetryClient {
	return NewRetryClient(servers...)
}

// NewFailoverClient returns a failover client configured with servers.
func NewFailoverClient(servers ...string) *RetryClient {
	return NewRetryClient(servers...)
}

// NewBatchClient returns a batch retry client configured with servers.
func NewBatchClient(servers ...string) *RetryClient {
	return NewRetryClient(servers...)
}

// NewRetryableClient is an alias for NewRetryClient.
func NewRetryableClient(servers ...string) *RetryClient {
	return NewRetryClient(servers...)
}

// NewResilientClient is an alias for NewRetryClient.
func NewResilientClient(servers ...string) *RetryClient {
	return NewRetryClient(servers...)
}

func (r *RetryClient) attemptTimeout() time.Duration {
	for _, d := range []time.Duration{r.Timeout, r.AttemptTimeout, r.PerAttemptTimeout} {
		if d > 0 {
			return d
		}
	}
	return 0
}

func (r *RetryClient) attemptCount() int {
	if r.Retries > 0 {
		return r.Retries + 1
	}
	if r.MaxRetries > 0 {
		return r.MaxRetries + 1
	}
	if r.Retry > 0 {
		return r.Retry + 1
	}
	if r.Attempts > 0 {
		return r.Attempts
	}
	return r.Client.configuredAttempts()
}

func (r *RetryClient) reuseEnabled() bool {
	if r.DisableConnectionReuse {
		return false
	}
	if r.ReuseConnections || r.ReuseTCP || r.Client.ReuseConnections || r.Client.ReuseTCP {
		return true
	}
	return strings.HasPrefix(r.Client.Net, "tcp")
}

func (r *RetryClient) connectionPool() *ConnPool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pool == nil {
		// Per-attempt timeouts are applied by exchangeServers' context, so
		// r.Client remains immutable and safe for concurrent use.
		r.pool = NewConnPool(&r.Client)
	}
	return r.pool
}

// Query performs one logical query against r.Servers.
func (r *RetryClient) Query(m *Msg) (*Msg, time.Duration, error) {
	return r.QueryContext(context.Background(), m)
}

// QueryContext performs one logical query against r.Servers with ctx.
func (r *RetryClient) QueryContext(ctx context.Context, m *Msg) (*Msg, time.Duration, error) {
	return r.ExchangeServersContext(ctx, m, r.Servers)
}

// Exchange is compatible with ordinary one-address calls and also accepts
// zero addresses (use r.Servers) or several failover addresses.
func (r *RetryClient) Exchange(m *Msg, address ...string) (*Msg, time.Duration, error) {
	return r.ExchangeContext(context.Background(), m, address...)
}

// ExchangeContext is the context form of Exchange.
func (r *RetryClient) ExchangeContext(ctx context.Context, m *Msg, address ...string) (*Msg, time.Duration, error) {
	servers := r.Servers
	if len(address) > 0 {
		servers = address
	}
	return r.ExchangeServersContext(ctx, m, servers)
}

// ExchangeServers performs one logical query against servers.
func (r *RetryClient) ExchangeServers(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return r.ExchangeServersContext(context.Background(), m, servers)
}

// ExchangeServersContext performs one logical query against servers with ctx.
func (r *RetryClient) ExchangeServersContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	if r == nil {
		return nil, 0, ErrConnEmpty
	}
	servers = normalizeServersWithPort(servers, r.Port)

	var pool *ConnPool
	if r.reuseEnabled() {
		pool = r.connectionPool()
	}
	return exchangeServers(ctx, &r.Client, m, servers, r.attemptCount(), r.attemptTimeout(), pool)
}

// ExchangeWithRetry is an alias for ExchangeServers.
func (r *RetryClient) ExchangeWithRetry(m *Msg, servers []string) (*Msg, time.Duration, error) {
	return r.ExchangeServers(m, servers)
}

// ExchangeWithRetryContext is an alias for ExchangeServersContext.
func (r *RetryClient) ExchangeWithRetryContext(ctx context.Context, m *Msg, servers []string) (*Msg, time.Duration, error) {
	return r.ExchangeServersContext(ctx, m, servers)
}

// Close releases idle pooled connections. It does not close caller-owned
// connections passed through ExchangeWithConn.
func (r *RetryClient) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	pool := r.pool
	r.pool = nil
	r.mu.Unlock()
	return pool.Close()
}
