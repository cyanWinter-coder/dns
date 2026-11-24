package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// ErrIdleConnData is returned when an idle connection has unread bytes. Such a
// connection cannot safely be reused because the byte stream is no longer
// synchronized with a DNS message exchange.
var ErrIdleConnData error = &Error{err: "unexpected data on idle connection"}

// CheckAlive performs a non-blocking liveness check on an idle stream
// connection. A read deadline in the past is used to detect an orderly close,
// reset or a local close without waiting for new data.
//
// A timeout means the peer did not report a failure and the connection is
// considered alive. EOF, a reset or a closed connection are returned as the
// cause so callers can discard the connection. If data is already buffered,
// ErrIdleConnData is returned because consuming only part of it would desync
// the stream.
//
// CheckAlive must only be called when no exchange is in flight. Exchange
// methods set their own deadlines before reading, so the deadline changes made
// here do not affect the next exchange.
func (co *Conn) CheckAlive() error {
	if co == nil || co.Conn == nil {
		return ErrConnEmpty
	}

	// A past-deadline read is also safe on packet connections: it detects a
	// locally closed socket. UDP peer liveness remains best-effort because the
	// protocol itself is connectionless.
	if err := co.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		return err
	}

	var one [1]byte
	_, err := co.Conn.Read(one[:])
	if err == nil {
		// There should be no bytes waiting at a pool boundary. The byte has
		// already been consumed, so the stream cannot be put back into service.
		return ErrIdleConnData
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		_ = co.SetReadDeadline(time.Time{})
		return nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		_ = co.SetReadDeadline(time.Time{})
		return nil
	}
	return err
}

// Alive reports whether an idle connection appears usable. See CheckAlive for
// the exact semantics.
func (co *Conn) Alive() bool {
	return co.CheckAlive() == nil
}

// ConnPool reuses DNS connections, especially TCP and DNS-over-TLS
// connections. Connections that fail an exchange or their liveness check are
// closed and removed; the next request dials a replacement.
//
// ConnPool is safe for concurrent use. A Conn that is busy with an exchange is
// not handed to another caller; concurrent requests therefore open additional
// connections up to the caller's concurrency and return them to an idle set
// afterwards.
type ConnPool struct {
	// Client is used to dial and run exchanges. A nil Client is equivalent to
	// a zero Client.
	Client *Client

	// MaxIdleConnsPerHost caps idle connections retained for each
	// network/address pair. Zero means two.
	MaxIdleConnsPerHost int

	initOnce sync.Once
	mu       sync.Mutex
	idle     map[string][]*Conn
	active   map[*Conn]string
	closed   bool
}

// NewConnPool returns a connection pool using c for dialing and exchange
// configuration. If c is nil, a zero Client is used.
func NewConnPool(c *Client) *ConnPool {
	if c == nil {
		c = new(Client)
	}
	return &ConnPool{Client: c}
}

func (p *ConnPool) init() {
	p.initOnce.Do(func() {
		p.idle = make(map[string][]*Conn)
		p.active = make(map[*Conn]string)
	})
}

func (p *ConnPool) client() *Client {
	if p == nil || p.Client == nil {
		return new(Client)
	}
	return p.Client
}

func (p *ConnPool) maxIdle() int {
	if p.MaxIdleConnsPerHost > 0 {
		return p.MaxIdleConnsPerHost
	}
	return 2
}

func poolKey(network, address string) string {
	return network + "|" + normalizeServerAddress(address)
}

// Get returns a healthy connection for address, dialing when necessary.
func (p *ConnPool) Get(ctx context.Context, address string) (*Conn, error) {
	if p == nil {
		return nil, ErrConnEmpty
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.init()

	key := poolKey(p.client().Net, address)

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	for len(p.idle[key]) > 0 {
		n := len(p.idle[key]) - 1
		co := p.idle[key][n]
		p.idle[key] = p.idle[key][:n]
		if len(p.idle[key]) == 0 {
			delete(p.idle, key)
		}

		if err := co.CheckAlive(); err != nil {
			delete(p.active, co)
			_ = co.Close()
			continue
		}

		p.active[co] = key
		p.mu.Unlock()
		return co, nil
	}
	p.mu.Unlock()

	co, err := p.client().DialContext(ctx, address)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = co.Close()
		return nil, net.ErrClosed
	}
	p.active[co] = key
	p.mu.Unlock()
	return co, nil
}

// Put returns a healthy, idle connection to the pool. Callers should use
// Discard after an exchange error instead.
func (p *ConnPool) Put(co *Conn) {
	if co == nil {
		return
	}
	p.init()

	p.mu.Lock()
	key, ok := p.active[co]
	if !ok {
		p.mu.Unlock()
		_ = co.Close()
		return
	}
	delete(p.active, co)

	if p.closed || len(p.idle[key]) >= p.maxIdle() {
		p.mu.Unlock()
		_ = co.Close()
		return
	}
	p.idle[key] = append(p.idle[key], co)
	p.mu.Unlock()
}

// Discard closes co and removes it from the pool. It is safe to call for a
// connection that is not currently tracked.
func (p *ConnPool) Discard(co *Conn) {
	if co == nil {
		return
	}
	if p == nil {
		_ = co.Close()
		return
	}
	p.init()

	p.mu.Lock()
	key, ok := p.active[co]
	if ok {
		delete(p.active, co)
	} else {
		for k, conns := range p.idle {
			for i, candidate := range conns {
				if candidate == co {
					p.idle[k] = append(conns[:i], conns[i+1:]...)
					key = k
					break
				}
			}
			if key != "" {
				break
			}
		}
	}
	p.mu.Unlock()
	_ = co.Close()
}

// IsStaleConnError reports whether err indicates that a pooled stream
// connection was closed or reset by its peer and may safely be replaced.
// Timeouts are not considered stale-connection errors: a timeout must follow
// the caller's failover policy rather than silently repeating a request on the
// same server.
func IsStaleConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, ErrIdleConnData) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return false
}

// ExchangeContext obtains a pooled connection, performs one exchange and
// returns the connection to the pool after success. Any exchange error causes
// the connection to be discarded because the DNS stream may be closed or out
// of synchronization. A clean EOF/reset on a reused connection is handled by
// dialing one replacement connection immediately.
func (p *ConnPool) ExchangeContext(ctx context.Context, m *Msg, address string) (*Msg, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r, rtt, co, err := p.exchangeOnce(ctx, m, address)
	if err == nil {
		p.Put(co)
		return r, rtt, nil
	}

	p.Discard(co)

	// The liveness probe in Get normally handles this before the request is
	// written. This second chance covers a FIN/RST that arrived after the
	// probe or a peer that closed between probe and write.
	if ctx.Err() == nil && IsStaleConnError(err) {
		r, rtt, co, err = p.exchangeOnce(ctx, m, address)
		if err == nil {
			p.Put(co)
			return r, rtt, nil
		}
		p.Discard(co)
	}

	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	return r, rtt, err
}

func (p *ConnPool) exchangeOnce(ctx context.Context, m *Msg, address string) (*Msg, time.Duration, *Conn, error) {
	c := p.client()

	co, err := p.Get(ctx, address)
	if err != nil {
		return nil, 0, nil, err
	}

	r, rtt, err := c.ExchangeWithConnContext(ctx, m, co)
	return r, rtt, co, err
}

// Close closes all idle and tracked connections known to the pool. Connections
// currently in use are also closed, which unblocks their exchanges.
func (p *ConnPool) Close() error {
	if p == nil {
		return nil
	}
	p.init()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]*Conn, 0, len(p.active))
	for co := range p.active {
		conns = append(conns, co)
	}
	for _, idle := range p.idle {
		conns = append(conns, idle...)
	}
	p.idle = make(map[string][]*Conn)
	p.active = make(map[*Conn]string)
	p.mu.Unlock()

	var firstErr error
	for _, co := range conns {
		if err := co.Close(); err != nil && firstErr == nil && !errors.Is(err, net.ErrClosed) {
			firstErr = err
		}
	}
	return firstErr
}
