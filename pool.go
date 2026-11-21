package dns

// Multi-upstream query pool.
//
// A Pool sends one logical DNS query to a set of upstream servers. Unlike a
// plain Client, a Pool retries the query on another server when an upstream
// fails. Every attempt that belongs to one logical query shares the caller's
// deadline and a single retry budget, so a broken pool cannot stretch a query
// indefinitely.
//
// Servers that do not answer are cooled down independently per transport type
// and address. While a server is cooling down it is skipped entirely, which
// prevents a dead upstream from receiving (and amplifying) failure traffic
// from every subsequent query.
//
// The failure classes are handled differently:
//
//   - A truncated UDP response triggers exactly one TCP upgrade for the
//     logical query. The upgrade is not repeated by later attempts, and a TCP
//     response is never upgraded again.
//   - SERVFAIL is retried on another upstream, but the server is not cooled
//     down because it did answer.
//   - Timeouts and network errors cool the server down and move on to the
//     next upstream.
//   - REFUSED/NOTAUTH responses, and local permission errors, are final: no
//     retry is attempted, and the server that produced the rejection is
//     retained in the result.
//
// A response is only accepted when its ID, question (name, type and class)
// and the generation of the upstream state all match the query being served.
// Anything else, including a late response from an earlier query or from a
// server whose state has changed while the attempt was in flight, is
// discarded rather than returned to the caller.
//
// A Pool is safe for concurrent use. Its exported configuration fields must
// be set before the first query and must not be mutated afterwards.
//
// The Pool is additive: Client.Exchange and ExchangeContext keep their
// original semantics of a single exchange with no retry and no TCP fallback.

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrPoolClosed is returned when a Pool is used after Close.
	ErrPoolClosed = &Error{err: "pool closed"}
	// ErrNoUpstream is returned when a query cannot be sent because no
	// upstream is usable: every configured server is cooling down.
	ErrNoUpstream = &Error{err: "no upstream available"}
	// ErrRetriesExhausted is returned when the shared retry budget, or the
	// deadline shared by all attempts, ran out before a usable answer was
	// received.
	ErrRetriesExhausted = &Error{err: "retry budget exhausted"}
	// ErrTruncated is returned when the only answers obtained were truncated
	// and the single TCP upgrade did not produce a complete response.
	ErrTruncated = &Error{err: "truncated response"}
	// ErrQuestion indicates that a response's question section does not
	// match the question of the query.
	ErrQuestion = &Error{err: "question mismatch"}
	// ErrNotResponse indicates that a message with the QR bit unset was
	// received where a response was expected.
	ErrNotResponse = &Error{err: "not a response"}
)

// errStaleResponse is used internally to discard a response whose upstream
// generation no longer matches the generation captured when the attempt was
// started. It means the server state changed while the attempt was in flight.
var errStaleResponse = &Error{err: "stale response for upstream generation"}

// PoolAttempt describes one network exchange performed for a logical query.
type PoolAttempt struct {
	Server    string // upstream address
	Network   string // transport network used for this exchange
	Rcode     int    // response code, when a response was received
	Truncated bool   // response had the TC bit set
	Err       error  // transport or validation error, if any
}

// PoolError is returned by Pool.ExchangeContext when no usable answer was
// obtained, or when the only answer was truncated. It retains the final
// source and the per-attempt history so callers can tell which upstream was
// responsible.
type PoolError struct {
	Source   string        // final source, if any
	Attempts []PoolAttempt // exchanges performed, in order
	Err      error         // underlying error
}

func (e *PoolError) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	msg := "dns: pool query failed"
	if e.Source != "" {
		msg += " (last source " + e.Source + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *PoolError) Unwrap() error { return e.Err }

// PoolResult is the outcome of a logical query. When Msg is non-nil, Server
// and Network identify the upstream that produced it, including when the
// error is non-nil (for example, a truncated response).
type PoolResult struct {
	Msg      *Msg
	RTT      time.Duration
	Server   string // upstream that produced Msg
	Network  string // transport that produced Msg
	Attempts int    // number of network exchanges, including TCP upgrades
}

// upstreamState is the per transport/address state of one upstream.
type upstreamState struct {
	key     string
	address string
	network string

	failures      int
	cooldownUntil time.Time
	generation    uint64 // bumped whenever the state changes materially
	lastErr       error
}

// Pool is a multi-upstream DNS query pool. Use NewPool, or populate Servers
// before the first query.
type Pool struct {
	// Servers lists upstream servers as "host:port". Duplicate entries are
	// ignored. Servers are tried in this order.
	Servers []string
	// Client supplies transport configuration (timeouts, TLS, TSIG, UDP
	// size, dialer). A zero Client is used when nil. The Pool sets Net per
	// upstream.
	Client *Client
	// Network is the transport used for the configured servers. It defaults
	// to "udp"; "udp4", "udp6", "tcp" and "tcp-tls" are equally valid. Only
	// UDP networks are upgraded to TCP after truncation.
	Network string
	// Timeout is the deadline shared by every attempt of one logical query.
	// An earlier deadline on the context wins. Zero means the context
	// deadline is the only overall limit.
	Timeout time.Duration
	// Attempts is the maximum number of upstream servers tried for one
	// logical query. Values below one mean "all configured servers". A TCP
	// upgrade after truncation is part of the attempt that produced the
	// truncated response and does not consume an extra slot.
	Attempts int
	// AttemptTimeout bounds a single exchange. It defaults to the Client's
	// read timeout. The overall deadline always wins.
	AttemptTimeout time.Duration
	// CooldownBase is the cooldown applied after the first failure of a
	// server. It doubles on each consecutive failure, up to CooldownMax.
	// Zero means one second.
	CooldownBase time.Duration
	// CooldownMax caps the per-server cooldown. Zero means thirty seconds.
	CooldownMax time.Duration

	mu      sync.Mutex
	inited  bool
	closed  bool
	closeCh chan struct{}
	states  map[string]*upstreamState
	order   []*upstreamState
	waiters map[*waiter]struct{}
}

type waiter struct{}

// NewPool returns a Pool that queries the given "host:port" servers.
func NewPool(servers ...string) *Pool {
	return &Pool{Servers: servers}
}

// Close closes the Pool and wakes every caller waiting inside an Exchange.
// The Pool cannot be used after Close. Close is idempotent.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.closeCh == nil {
		p.closeCh = make(chan struct{})
	}
	close(p.closeCh)
	// Every waiter is watching closeCh or has already left; dropping the
	// registry lets them be collected as they unblock.
	p.waiters = nil
	return nil
}

// Exchange performs one logical DNS query using context.Background.
func (p *Pool) Exchange(m *Msg) (*PoolResult, error) {
	return p.ExchangeContext(context.Background(), m)
}

// ExchangeContext performs one logical query across the configured
// upstreams. The query is retried on other servers until a usable response is
// received, the shared retry budget is spent, or ctx is done. Retries never
// extend the deadline carried by ctx (or Pool.Timeout). Cancellation and
// Close release the caller immediately.
func (p *Pool) ExchangeContext(ctx context.Context, m *Msg) (*PoolResult, error) {
	if m == nil {
		return nil, &Error{err: "nil message"}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	snap, w, err := p.begin()
	if err != nil {
		return nil, err
	}
	defer p.releaseWaiter(w)

	start := time.Now()
	res := &PoolResult{}

	// One context for the whole logical query. It is cancelled either by
	// the caller, by an overall Pool.Timeout, or by Close.
	qctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-snap.closeCh:
			cancel()
		case <-stopWatch:
		}
	}()

	if snap.timeout > 0 {
		var dcancel context.CancelFunc
		qctx, dcancel = context.WithDeadline(qctx, start.Add(snap.timeout))
		defer dcancel()
	}

	if len(snap.order) == 0 {
		return res, &PoolError{Err: ErrNoUpstream}
	}

	budget := snap.attempts
	deadline, hasDeadline := qctx.Deadline()
	var (
		attempts     []PoolAttempt
		servfail     *Msg
		servfailFrom *upstreamState
		truncated    *Msg
		truncFrom    *upstreamState
		lastSource   *upstreamState
		lastErr      error
		upgradeUsed  bool
		usable       int
	)

	for _, st := range snap.order {
		if budget <= 0 {
			break
		}
		// The context timer may not have fired yet even though its deadline
		// has passed; never start another attempt past the shared deadline.
		if hasDeadline && !time.Now().Before(deadline) {
			break
		}
		if qctx.Err() != nil {
			break
		}
		if snap.cooling(st) {
			continue
		}
		usable++
		budget--

		gen := snap.generation(st)
		r, aerr := p.attempt(qctx, snap, st, m, gen)
		res.Attempts++
		res.RTT = time.Since(start)
		lastSource = st

		if aerr != nil {
			attempts = append(attempts, PoolAttempt{Server: st.address, Network: st.network, Err: aerr})
			lastErr = aerr
			if qctx.Err() != nil || snap.closedNow() {
				// Our own cancellation or Close is not the upstream's fault.
				break
			}
			switch {
			case errors.Is(aerr, errStaleResponse):
				// State changed under us; never accept a response produced
				// for the previous generation, and do not blame the server.
			case errors.Is(aerr, ErrId), errors.Is(aerr, ErrQuestion), errors.Is(aerr, ErrNotResponse):
				// A response arrived but did not belong to this query. Move
				// on without cooling the server down.
			case isPermissionError(aerr):
				return res, &PoolError{Source: st.address, Attempts: attempts, Err: aerr}
			default:
				snap.reportFailure(st, aerr)
			}
			continue
		}

		if r == nil {
			attempts = append(attempts, PoolAttempt{Server: st.address, Network: st.network, Err: ErrShortRead})
			snap.reportFailure(st, ErrShortRead)
			continue
		}

		attempts = append(attempts, PoolAttempt{
			Server: st.address, Network: st.network, Rcode: r.Rcode, Truncated: r.Truncated,
		})
		snap.reportReachable(st)

		switch {
		case r.Rcode == RcodeRefused, r.Rcode == RcodeNotAuth:
			// A policy rejection is final; retrying elsewhere would only
			// repeat the same decision.
			res.Msg, res.Server, res.Network = r, st.address, st.network
			return res, nil
		case r.Rcode == RcodeServerFailure:
			// The server answered, so it is reachable. Prefer an answer
			// from another upstream, but keep this as a fallback.
			servfail, servfailFrom = r, st
			continue
		case !r.Truncated:
			res.Msg, res.Server, res.Network = r, st.address, st.network
			return res, nil
		}

		// The UDP response was truncated. Exactly one TCP upgrade is
		// allowed for the whole logical query, no matter how many retries
		// happen afterwards.
		truncated, truncFrom = r, st
		if upgradeUsed {
			continue
		}
		upgradeUsed = true

		tcpNet := tcpNetwork(st.network)
		if tcpNet == "" {
			// The configured transport is not UDP; there is nothing safe to
			// upgrade to.
			continue
		}
		tcpState := snap.stateFor(tcpNet, st.address)
		if snap.cooling(tcpState) {
			continue
		}
		tcpGen := snap.generation(tcpState)
		tr, terr := p.attempt(qctx, snap, tcpState, m, tcpGen)
		res.Attempts++
		res.RTT = time.Since(start)
		if terr != nil {
			attempts = append(attempts, PoolAttempt{Server: tcpState.address, Network: tcpState.network, Err: terr})
			lastErr = terr
			if qctx.Err() == nil && !snap.closedNow() &&
				!errors.Is(terr, errStaleResponse) &&
				!errors.Is(terr, ErrId) && !errors.Is(terr, ErrQuestion) && !errors.Is(terr, ErrNotResponse) {
				snap.reportFailure(tcpState, terr)
			}
			continue
		}
		if tr == nil {
			attempts = append(attempts, PoolAttempt{Server: tcpState.address, Network: tcpState.network, Err: ErrShortRead})
			snap.reportFailure(tcpState, ErrShortRead)
			continue
		}
		attempts = append(attempts, PoolAttempt{
			Server: tcpState.address, Network: tcpState.network, Rcode: tr.Rcode, Truncated: tr.Truncated,
		})
		snap.reportReachable(tcpState)

		switch {
		case tr.Rcode == RcodeRefused, tr.Rcode == RcodeNotAuth:
			res.Msg, res.Server, res.Network = tr, tcpState.address, tcpState.network
			return res, nil
		case tr.Rcode == RcodeServerFailure:
			servfail, servfailFrom = tr, tcpState
			continue
		case tr.Truncated:
			// A TCP response that is still truncated cannot be upgraded
			// again. Keep it as a candidate and try another server.
			truncated, truncFrom = tr, tcpState
			continue
		default:
			res.Msg, res.Server, res.Network = tr, tcpState.address, tcpState.network
			return res, nil
		}
	}

	res.RTT = time.Since(start)

	// A complete SERVFAIL is still a DNS answer and is preferable to a
	// truncated message: it carries the server's final status.
	if servfail != nil {
		res.Msg, res.Server, res.Network = servfail, servfailFrom.address, servfailFrom.network
		return res, nil
	}
	if truncated != nil {
		res.Msg, res.Server, res.Network = truncated, truncFrom.address, truncFrom.network
		return res, &PoolError{Source: truncFrom.address, Attempts: attempts, Err: ErrTruncated}
	}
	if lastSource != nil {
		res.Server, res.Network = lastSource.address, lastSource.network
	}

	switch {
	case snap.closedNow():
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: ErrPoolClosed}
	case errors.Is(qctx.Err(), context.Canceled):
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: context.Canceled}
	case qctx.Err() != nil, hasDeadline && !time.Now().Before(deadline):
		// The shared deadline, not the per-attempt timeout, ended the
		// query. Report it as a spent retry budget.
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: errors.Join(ErrRetriesExhausted, context.DeadlineExceeded)}
	case usable == 0:
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: ErrNoUpstream}
	case lastErr != nil:
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: errors.Join(ErrRetriesExhausted, lastErr)}
	default:
		return res, &PoolError{Source: res.Server, Attempts: attempts, Err: ErrRetriesExhausted}
	}
}

// attempt performs one network exchange and validates the response against
// the query and the upstream generation captured before sending.
func (p *Pool) attempt(ctx context.Context, snap *poolSnapshot, st *upstreamState, m *Msg, gen uint64) (*Msg, error) {
	c := snap.client
	c.Net = st.network

	actx := ctx
	if snap.attemptTimeout > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, snap.attemptTimeout)
		defer cancel()
	}

	co, err := c.DialContext(actx, st.address)
	if err != nil {
		return nil, err
	}
	defer co.Close()

	// DialContext observes cancellation while dialing, but an in-flight
	// read must be unblocked explicitly so cancellation and Close release
	// the caller immediately.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-actx.Done():
			co.SetDeadline(aLongTimeAgo)
		case <-stop:
		}
	}()

	// Mirror Client.ExchangeWithConnContext's deadline and EDNS0 handling.
	t := time.Now()
	writeDeadline := t.Add(c.getTimeoutForRequest(c.writeTimeout()))
	readDeadline := t.Add(c.getTimeoutForRequest(c.readTimeout()))
	if d, ok := actx.Deadline(); ok {
		if d.Before(writeDeadline) {
			writeDeadline = d
		}
		if d.Before(readDeadline) {
			readDeadline = d
		}
	}
	co.SetWriteDeadline(writeDeadline)
	co.SetReadDeadline(readDeadline)

	if opt := m.IsEdns0(); opt != nil && opt.UDPSize() >= MinMsgSize {
		co.UDPSize = opt.UDPSize()
	} else if c.UDPSize >= MinMsgSize {
		co.UDPSize = c.UDPSize
	}
	co.TsigSecret, co.TsigProvider = c.TsigSecret, c.TsigProvider

	if err := co.WriteMsg(m); err != nil {
		return nil, err
	}

	for {
		r, err := co.ReadMsg()
		if err != nil {
			return nil, err
		}

		// A late packet, or a packet injected for a different query, must
		// never be handed to this caller. On a packet connection such
		// messages are ignored and reading continues; on a stream
		// connection they are a protocol error.
		if verr := validateResponse(m, r); verr != nil {
			if isPacketConn(co.Conn) {
				continue
			}
			return nil, verr
		}

		// The server state may have changed (for example another query
		// cooled it down) while this attempt was in flight. Never accept a
		// response across that generation boundary.
		if !snap.generationMatches(st, gen) {
			return nil, errStaleResponse
		}
		return r, nil
	}
}

// validateResponse checks that r is a response to m and echoes its question.
func validateResponse(m, r *Msg) error {
	if r == nil {
		return ErrShortRead
	}
	if !r.Response {
		return ErrNotResponse
	}
	if r.Id != m.Id {
		return ErrId
	}
	if !matchingQuestion(m, r) {
		return ErrQuestion
	}
	return nil
}

// matchingQuestion reports whether r answers the question in m. Names are
// compared case-insensitively and as fully qualified names; type and class
// must match exactly.
func matchingQuestion(m, r *Msg) bool {
	if len(m.Question) != len(r.Question) {
		return false
	}
	for i := range m.Question {
		q, a := m.Question[i], r.Question[i]
		if q.Qtype != a.Qtype || q.Qclass != a.Qclass {
			return false
		}
		if !strings.EqualFold(CanonicalName(q.Name), CanonicalName(a.Name)) {
			return false
		}
	}
	return true
}

// tcpNetwork returns the TCP network corresponding to a UDP network, or ""
// when network is not a UDP network.
func tcpNetwork(network string) string {
	switch network {
	case "", "udp":
		return "tcp"
	case "udp4":
		return "tcp4"
	case "udp6":
		return "tcp6"
	}
	return ""
}

// isPermissionError reports whether err is a local permission failure. Such
// failures are policy decisions and are not retried.
func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES)
}

// --- snapshot -------------------------------------------------------------

// poolSnapshot is an immutable view of the Pool used by one logical query.
type poolSnapshot struct {
	p              *Pool
	closeCh        <-chan struct{}
	order          []*upstreamState
	attempts       int
	attemptTimeout time.Duration
	cooldownBase   time.Duration
	cooldownMax    time.Duration
	timeout        time.Duration
	client         Client
}

func (s *poolSnapshot) cooling(st *upstreamState) bool {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return !st.cooldownUntil.IsZero() && time.Now().Before(st.cooldownUntil)
}

func (s *poolSnapshot) generation(st *upstreamState) uint64 {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return st.generation
}

func (s *poolSnapshot) generationMatches(st *upstreamState, gen uint64) bool {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return st.generation == gen
}

func (s *poolSnapshot) closedNow() bool {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return s.p.closed
}

func (s *poolSnapshot) stateFor(network, address string) *upstreamState {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return s.p.stateForLocked(network, address)
}

func (s *poolSnapshot) reportFailure(st *upstreamState, err error) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.p.closed {
		return
	}
	st.failures++
	st.lastErr = err
	d := s.cooldownBase
	if d <= 0 {
		d = time.Second
	}
	max := s.cooldownMax
	if max <= 0 {
		max = 30 * time.Second
	}
	for i := 1; i < st.failures && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	st.cooldownUntil = time.Now().Add(d)
	st.generation++
}

func (s *poolSnapshot) reportReachable(st *upstreamState) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if st.failures == 0 && st.cooldownUntil.IsZero() {
		return
	}
	st.failures = 0
	st.cooldownUntil = time.Time{}
	st.lastErr = nil
	st.generation++
}

// begin validates the pool, registers a waiter and captures the
// configuration used by one logical query.
func (p *Pool) begin() (*poolSnapshot, *waiter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, nil, ErrPoolClosed
	}
	if !p.inited {
		p.initLocked()
	}
	w := new(waiter)
	if p.waiters == nil {
		p.waiters = make(map[*waiter]struct{})
	}
	p.waiters[w] = struct{}{}

	snap := &poolSnapshot{
		p:              p,
		closeCh:        p.closeCh,
		order:          append([]*upstreamState(nil), p.order...),
		attempts:       p.Attempts,
		attemptTimeout: p.AttemptTimeout,
		cooldownBase:   p.CooldownBase,
		cooldownMax:    p.CooldownMax,
		timeout:        p.Timeout,
	}
	if p.Client != nil {
		snap.client = *p.Client
	}
	if snap.attemptTimeout <= 0 {
		snap.attemptTimeout = snap.client.getTimeoutForRequest(snap.client.readTimeout())
	}
	if snap.attempts < 1 {
		snap.attempts = len(snap.order)
	}
	return snap, w, nil
}

// releaseWaiter removes w from the registry. It is called as soon as the
// caller of ExchangeContext returns, including on cancellation.
func (p *Pool) releaseWaiter(w *waiter) {
	p.mu.Lock()
	delete(p.waiters, w)
	p.mu.Unlock()
}

func (p *Pool) initLocked() {
	p.inited = true
	if p.closeCh == nil {
		p.closeCh = make(chan struct{})
	}
	if p.states == nil {
		p.states = make(map[string]*upstreamState)
	}
	p.order = p.order[:0]
	seen := make(map[string]bool)

	network := p.Network
	if network == "" {
		network = "udp"
	}
	for _, server := range p.Servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		key := stateKey(network, server)
		if seen[key] {
			continue
		}
		seen[key] = true
		p.order = append(p.order, p.stateForLocked(network, server))
	}
}

func stateKey(network, address string) string {
	return network + "\x00" + address
}

func (p *Pool) stateForLocked(network, address string) *upstreamState {
	key := stateKey(network, address)
	if st, ok := p.states[key]; ok {
		return st
	}
	st := &upstreamState{key: key, address: address, network: network}
	p.states[key] = st
	return st
}
