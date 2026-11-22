package dns

// A client implementation.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dnsTimeout     time.Duration = 2 * time.Second
	tcpIdleTimeout time.Duration = 8 * time.Second
)

func isPacketConn(c net.Conn) bool {
	if _, ok := c.(net.PacketConn); !ok {
		return false
	}

	if ua, ok := c.LocalAddr().(*net.UnixAddr); ok {
		return ua.Net == "unixgram" || ua.Net == "unixpacket"
	}

	return true
}

// A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn                         // a net.Conn holding the connection
	UDPSize        uint16            // minimum receive buffer for UDP messages
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	TsigProvider   TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	tsigRequestMAC string

	// generation identifies the exchange currently using this connection.
	// It is bumped for every exchange started on the Conn so that a timer,
	// an aborted read or a late reply belonging to an earlier exchange can
	// never act on a newer one.
	generation uint64
	// queryIDs records the message IDs already handed out on this
	// connection. A caller that reuses a *Msg (and therefore its Id) on a
	// persistent connection gets a fresh ID for every exchange, so a late
	// reply to an earlier exchange cannot be mistaken for the answer to a
	// later one. The map is only used by one exchange at a time; a Conn is
	// not safe for concurrent use.
	queryIDs map[uint16]struct{}
	// mu guards generation and the deadline updates that depend on it. An
	// exchange that ends, or a context that is cancelled, must not change
	// the deadlines of the exchange that comes after it.
	mu sync.Mutex
}

func (co *Conn) tsigProvider() TsigProvider {
	if co.TsigProvider != nil {
		return co.TsigProvider
	}
	// tsigSecretProvider will return ErrSecret if co.TsigSecret is nil.
	return tsigSecretProvider(co.TsigSecret)
}

// Close closes the connection. Closing a connection while an exchange is in
// flight unblocks that exchange immediately; its outcome is still delivered
// exactly once, just as if it had timed out.
func (co *Conn) Close() error {
	if co.Conn == nil {
		return ErrConnEmpty
	}
	co.mu.Lock()
	// Unblock any read or write that is still using the connection. The
	// exchange that is waiting will observe the close through the normal
	// read error.
	co.Conn.SetDeadline(aLongTimeAgo)
	co.mu.Unlock()
	return co.Conn.Close()
}

// A Client defines parameters for a DNS client.
type Client struct {
	Net       string      // if "tcp" or "tcp-tls" (DNS over TLS) a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)
	UDPSize   uint16      // minimum receive buffer for UDP messages
	TLSConfig *tls.Config // TLS connection configuration
	Dialer    *net.Dialer // a net.Dialer used to set local address, timeouts and more
	// Timeout is a cumulative timeout for dial, write and read, defaults to 0 (disabled) - overrides DialTimeout, ReadTimeout,
	// WriteTimeout when non-zero. Can be overridden with net.Dialer.Timeout (see Client.ExchangeWithDialer and
	// Client.Dialer) or context.Context.Deadline (see ExchangeContext)
	Timeout      time.Duration
	DialTimeout  time.Duration     // net.DialTimeout, defaults to 2 seconds, or net.Dialer.Timeout if expiring earlier - overridden by Timeout when that value is non-zero
	ReadTimeout  time.Duration     // net.Conn.SetReadDeadline value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	WriteTimeout time.Duration     // net.Conn.SetWriteDeadline value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	TsigProvider TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.

	// SingleInflight previously serialised multiple concurrent queries for the
	// same Qname, Qtype and Qclass to ensure only one would be in flight at a
	// time.
	//
	// Deprecated: This is a no-op. Callers should implement their own in flight
	// query caching if needed. See github.com/miekg/dns/issues/1449.
	SingleInflight bool

	// TCPFallback, when true and the client uses UDP, retries the query once
	// over TCP when the UDP response is truncated (has the TC bit set). The
	// fallback is performed at most once: a truncated TCP response is
	// returned as-is and is never retried again.
	//
	// The UDP exchange and the TCP fallback belong to the same query and
	// therefore share one transport budget: the original deadline (the
	// earliest of Client.Timeout, the phase timeouts and the context
	// deadline) and the context cancellation signal. The fallback can never
	// extend the time the query may take.
	//
	// When the TCP fallback fails, the returned error is a *FallbackError
	// and the returned message is the truncated UDP response. The returned
	// RTT covers the whole query, including the fallback.
	TCPFallback bool
}

// FallbackError is returned by Client.Exchange and Client.ExchangeContext
// when Client.TCPFallback is enabled, the UDP response was truncated and the
// TCP fallback failed. It lets callers distinguish a failure of the fallback
// phase from a failure of the initial UDP exchange. The wrapped error is
// available through errors.Is and errors.As.
type FallbackError struct {
	// UDP is the truncated UDP response that triggered the fallback.
	UDP *Msg
	// Err is the error returned by the TCP fallback exchange.
	Err error
}

func (e *FallbackError) Error() string {
	if e == nil {
		return "dns: tcp fallback failed"
	}
	if e.Err == nil {
		return "dns: tcp fallback failed: <nil>"
	}
	return "dns: tcp fallback failed: " + e.Err.Error()
}

func (e *FallbackError) Unwrap() error { return e.Err }

// exchangeOutcome is the result of one transport exchange.
type exchangeOutcome struct {
	msg *Msg
	err error
}

// outcomeGate delivers the outcome of one exchange exactly once. A transport
// read, a context cancellation and the deadline timer all race to complete
// the same exchange; only the first one wins and every later attempt to
// deliver is dropped. The buffered channel also lets a completion happen
// after the waiter has already observed a different outcome, so a reader
// unblocked late by Close never blocks forever.
type outcomeGate struct {
	once sync.Once
	ch   chan exchangeOutcome
}

func newOutcomeGate() *outcomeGate {
	return &outcomeGate{ch: make(chan exchangeOutcome, 1)}
}

// deliver completes the gate. Only the first call has any effect.
func (g *outcomeGate) deliver(m *Msg, err error) {
	g.once.Do(func() { g.ch <- exchangeOutcome{msg: m, err: err} })
}

// wait returns the outcome that completed the gate.
func (g *outcomeGate) wait() (*Msg, error) {
	out := <-g.ch
	return out.msg, out.err
}

// errStaleResponse reports that a response belongs to an earlier exchange of
// a connection and must not be handed to the current one.
var errStaleResponse = &Error{err: "stale response for connection generation"}

// maxRememberedIDs bounds the number of message IDs a Conn remembers. The
// history only has to cover replies that can still arrive late; once it is
// full it is reset so a long-lived connection cannot grow without bound.
const maxRememberedIDs = 4096

// beginExchange starts a new exchange on co and returns its generation. An
// exchange, a cancellation watcher or a deadline timer may only act on the
// connection while its generation is still current.
func (co *Conn) beginExchange() uint64 {
	co.mu.Lock()
	defer co.mu.Unlock()
	co.generation++
	return co.generation
}

// generationIs reports whether gen is still the generation of the connection.
func (co *Conn) generationIs(gen uint64) bool {
	co.mu.Lock()
	defer co.mu.Unlock()
	return co.generation == gen
}

// endExchange retires gen. Any cancellation watcher or late reader that still
// holds gen can no longer touch the connection, so a finished query never
// disturbs the one that follows it.
func (co *Conn) endExchange(gen uint64) {
	co.mu.Lock()
	defer co.mu.Unlock()
	if co.generation == gen {
		co.generation++
	}
}

// abortExchange unblocks the exchange identified by gen. It must not affect
// an exchange that has since started on the same connection.
func (co *Conn) abortExchange(gen uint64) {
	co.mu.Lock()
	defer co.mu.Unlock()
	if co.generation != gen || co.Conn == nil {
		return
	}
	co.Conn.SetDeadline(aLongTimeAgo)
}

// assignMessageID makes the message ID unique for this connection and returns
// it. When the caller reuses a message (and therefore its ID) for a later
// query, a fresh ID is chosen so that a late reply to the earlier query cannot
// be matched to the new one. Messages carrying TSIG are left alone: their ID
// is covered by the signature and the signature check rejects a stale reply
// instead.
func (co *Conn) assignMessageID(m *Msg) uint16 {
	co.mu.Lock()
	defer co.mu.Unlock()

	if co.queryIDs == nil {
		co.queryIDs = make(map[uint16]struct{})
	}
	if len(co.queryIDs) >= maxRememberedIDs {
		co.queryIDs = make(map[uint16]struct{})
	}

	id := m.Id
	if _, used := co.queryIDs[id]; used && m.IsTsig() == nil {
		if fresh, ok := co.unusedMessageID(id); ok {
			id = fresh
			m.Id = id
		}
	}
	co.queryIDs[id] = struct{}{}
	return id
}

// unusedMessageID returns an ID that has not been used on the connection,
// excluding skip. It tries a bounded number of random draws first, then scans
// the 16-bit space so that a constant Id override cannot make it spin.
func (co *Conn) unusedMessageID(skip uint16) (uint16, bool) {
	for i := 0; i < 32; i++ {
		if candidate := Id(); candidate != skip {
			if _, used := co.queryIDs[candidate]; !used {
				return candidate, true
			}
		}
	}
	for i := 0; i < 1<<16; i++ {
		candidate := uint16(int(skip) + i + 1)
		if _, used := co.queryIDs[candidate]; !used {
			return candidate, true
		}
	}
	return 0, false
}

// readExchangeResponse reads the response to m on co and validates it against
// the query's ID and the connection generation captured before the write.
//
// gen is the generation the whole query started with. A response read for a
// later exchange on the same connection therefore never satisfies this one,
// and a reply that arrives after the exchange has been aborted is recognised
// as stale instead of being matched against whatever query comes next.
func (co *Conn) readExchangeResponse(m *Msg, gen uint64) (*Msg, error) {
	if !isPacketConn(co.Conn) {
		r, err := co.ReadMsg()
		if err != nil {
			// Keep returning the partially parsed message, as ReadMsg
			// documents and the exchange always has.
			return r, err
		}
		if !co.generationIs(gen) {
			return nil, errStaleResponse
		}
		// Stream transports carry exactly one response per query; an ID
		// mismatch is a protocol error rather than a stray datagram.
		if r.Id != m.Id {
			return r, ErrId
		}
		return r, nil
	}
	for {
		r, err := co.ReadMsg()
		if err != nil {
			return r, err
		}
		if !co.generationIs(gen) {
			return nil, errStaleResponse
		}
		// Ignore replies with mismatched IDs because they might be
		// responses to earlier queries that timed out. They must not be
		// returned to this query even when the caller reused an ID: a
		// reused ID was reassigned before the write (see assignMessageID),
		// so an older reply no longer matches.
		if r.Id != m.Id {
			continue
		}
		return r, nil
	}
}

// queryBudget is the transport budget shared by every phase of one logical
// query. Its deadline is fixed when the query starts and is never recomputed,
// so a UDP attempt, its TCP fallback and any retry all draw from the same
// allowance. The context carries the original cancellation signal, so
// cancelling the caller also stops the fallback.
type queryBudget struct {
	ctx      context.Context
	deadline time.Time
}

// newQueryBudget derives the shared budget for a query starting at t. The
// allowance is the client's request timeout bounded by the context deadline,
// mirroring the deadline a single ExchangeWithConnContext would use.
func (c *Client) newQueryBudget(ctx context.Context, t time.Time) (*queryBudget, context.CancelFunc) {
	deadline := t.Add(c.getTimeoutForRequest(c.readTimeout()))
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	qctx, cancel := context.WithDeadline(ctx, deadline)
	return &queryBudget{ctx: qctx, deadline: deadline}, cancel
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation.
// See client.Exchange for more information on setting larger buffer sizes.
func Exchange(m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.Exchange(m, a)
	return r, err
}

func (c *Client) dialTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	return dnsTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsTimeout
}

// Dial connects to the address on the named network.
func (c *Client) Dial(address string) (conn *Conn, err error) {
	return c.DialContext(context.Background(), address)
}

// DialContext connects to the address on the named network, with a context.Context.
func (c *Client) DialContext(ctx context.Context, address string) (conn *Conn, err error) {
	// create a new dialer with the appropriate timeout
	var d net.Dialer
	if c.Dialer == nil {
		d = net.Dialer{Timeout: c.getTimeoutForRequest(c.dialTimeout())}
	} else {
		d = *c.Dialer
	}

	network := c.Net
	if network == "" {
		network = "udp"
	}

	useTLS := strings.HasPrefix(network, "tcp") && strings.HasSuffix(network, "-tls")

	conn = new(Conn)
	if useTLS {
		network = strings.TrimSuffix(network, "-tls")

		tlsDialer := tls.Dialer{
			NetDialer: &d,
			Config:    c.TLSConfig,
		}
		conn.Conn, err = tlsDialer.DialContext(ctx, network, address)
	} else {
		conn.Conn, err = d.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	conn.UDPSize = c.UDPSize
	return conn, nil
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
// Exchange does not retry a failed query. It does not fall back to TCP in
// case of truncation unless Client.TCPFallback is set; see ExchangeContext for
// how the UDP exchange and the fallback share one transport budget.
// It is up to the caller to create a message that allows for larger responses to be
// returned. Specifically this means adding an EDNS0 OPT RR that will advertise a larger
// buffer, see SetEdns0. Messages without an OPT RR will fallback to the historic limit
// of 512 bytes
// To specify a local address or a timeout, the caller has to set the `Client.Dialer`
// attribute appropriately
func (c *Client) Exchange(m *Msg, address string) (r *Msg, rtt time.Duration, err error) {
	if c.TCPFallback && tcpFallbackNetwork(c.Net) != "" {
		// The fallback needs to dial a second transport, which only
		// ExchangeContext can do without changing Exchange's connection
		// ownership rules.
		return c.ExchangeContext(context.Background(), m, address)
	}
	co, err := c.Dial(address)

	if err != nil {
		return nil, 0, err
	}
	defer co.Close()
	return c.ExchangeWithConn(m, co)
}

// ExchangeWithConn has the same behavior as Exchange, just with a predetermined connection
// that will be used instead of creating a new one.
// Usage pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	// connection management logic goes here
//
//	conn := c.Dial(address)
//	in, rtt, err := c.ExchangeWithConn(message, conn)
//
// This allows users of the library to implement their own connection management,
// as opposed to Exchange, which will always use new connections and incur the added overhead
// that entails when using "tcp" and especially "tcp-tls" clients.
func (c *Client) ExchangeWithConn(m *Msg, conn *Conn) (r *Msg, rtt time.Duration, err error) {
	return c.ExchangeWithConnContext(context.Background(), m, conn)
}

// ExchangeWithConnContext has the same behaviour as ExchangeWithConn and
// additionally obeys deadlines from the passed Context.
//
// The write and the read of the exchange share a single transport budget.
// Cancelling ctx, or reaching its deadline, unblocks the read even while the
// connection stays open; it never waits for a reply that is not coming.
//
// Every exchange on co gets a unique message ID and connection generation. If
// the caller reuses the same *Msg (and therefore the same Id) for a later
// exchange on the same connection, m.Id is updated to a fresh value before it
// is sent, so a late reply to the earlier exchange can never be matched to the
// later one. Messages carrying TSIG are exempt because their Id is covered by
// the signature.
func (c *Client) ExchangeWithConnContext(ctx context.Context, m *Msg, co *Conn) (r *Msg, rtt time.Duration, err error) {
	return c.exchangeConn(ctx, m, co, time.Now(), nil)
}

// exchangeConn performs one transport exchange on co. start is when the
// containing query began; budget, when non-nil, fixes the deadline and
// cancellation signal shared with the query's other phases. When budget is
// nil the exchange derives its own from ctx.
func (c *Client) exchangeConn(ctx context.Context, m *Msg, co *Conn, start time.Time, budget *queryBudget) (r *Msg, rtt time.Duration, err error) {
	if co == nil || co.Conn == nil {
		return nil, 0, ErrConnEmpty
	}
	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && c.UDPSize >= MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	if budget == nil {
		var cancel context.CancelFunc
		budget, cancel = c.newQueryBudget(ctx, time.Now())
		defer cancel()
	}

	// Give this exchange its own generation before touching the
	// connection, so a timer or a late reader left over from an earlier
	// exchange on the same connection can be recognised and ignored.
	gen := co.beginExchange()
	defer co.endExchange(gen)

	// The write keeps the original per-phase policy: its own write timeout,
	// bounded by the caller's context deadline. The read draws from the
	// query's shared budget. The fallback cannot extend the query because
	// its read deadline is already fixed by that budget.
	writeDeadline := time.Now().Add(c.getTimeoutForRequest(c.writeTimeout()))
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(writeDeadline) {
		writeDeadline = deadline
	}
	co.SetWriteDeadline(writeDeadline)
	co.SetReadDeadline(budget.deadline)

	co.TsigSecret, co.TsigProvider = c.TsigSecret, c.TsigProvider

	// The query ID is fixed before the write, once the connection has been
	// told which exchange is current.
	co.assignMessageID(m)

	// The response is delivered through a gate that is completed exactly
	// once. The reader, context cancellation and the connection's deadline
	// all try to complete it; the first one wins and the rest are dropped.
	// The watcher also covers the write, so cancellation applies to both
	// phases of the exchange.
	gate := newOutcomeGate()
	readerDone := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)

	bctx := budget.ctx
	go func() {
		select {
		case <-bctx.Done():
			// Unblock the write or the read, but only for this exchange:
			// if the connection has moved on, the abort is a no-op. A
			// reached deadline is reported by the network operation as a
			// net.Error timeout, which keeps the historical timeout
			// behaviour; caller cancellation is reported as
			// context.Canceled.
			co.abortExchange(gen)
			if bctx.Err() == context.Canceled {
				gate.deliver(nil, context.Canceled)
			}
		case <-stop:
		}
	}()

	if err = co.WriteMsg(m); err != nil {
		co.endExchange(gen)
		if bctx.Err() == context.Canceled {
			return nil, 0, context.Canceled
		}
		return nil, 0, err
	}

	go func() {
		r, err := co.readExchangeResponse(m, gen)
		// Signal completion before publishing the result, so a successful
		// read is never mistaken for a cancellation-completed exchange.
		close(readerDone)
		gate.deliver(r, err)
	}()

	r, err = gate.wait()
	if !readerFinished(readerDone) {
		// The gate was completed by the cancellation watcher: unblock the
		// read and wait for the reader to leave the connection. Otherwise
		// the abandoned reader could consume the next query's response on
		// a reused connection.
		co.abortExchange(gen)
		<-readerDone
	}
	// Retire the generation now that no reader is using the connection, so
	// a cancellation watcher that wakes up later cannot touch the next
	// exchange. The deferred call becomes a no-op.
	co.endExchange(gen)
	if err == nil && r == nil {
		err = ErrShortRead
	}
	rtt = time.Since(start)
	return r, rtt, err
}

// readerFinished reports whether the reader has already returned.
func readerFinished(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*Msg, error) {
	p, err := co.ReadMsgHeader(nil)
	if err != nil {
		return nil, err
	}

	m := new(Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	if t := m.IsTsig(); t != nil {
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerifyWithProvider(p, co.tsigProvider(), co.tsigRequestMAC, false)
	}
	return m, err
}

// ReadMsgHeader reads a DNS message, parses and populates hdr (when hdr is not nil).
// Returns message as a byte slice to be parsed with Msg.Unpack later on.
// Note that error handling on the message body is not possible as only the header is parsed.
func (co *Conn) ReadMsgHeader(hdr *Header) ([]byte, error) {
	var (
		p   []byte
		n   int
		err error
	)

	if isPacketConn(co.Conn) {
		if co.UDPSize > MinMsgSize {
			p = make([]byte, co.UDPSize)
		} else {
			p = make([]byte, MinMsgSize)
		}
		n, err = co.Read(p)
	} else {
		var length uint16
		if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
			return nil, err
		}

		p = make([]byte, length)
		n, err = io.ReadFull(co.Conn, p)
	}

	if err != nil {
		return nil, err
	} else if n < headerSize {
		return nil, ErrShortRead
	}

	p = p[:n]
	if hdr != nil {
		dh, _, err := unpackMsgHdr(p, 0)
		if err != nil {
			return nil, err
		}
		*hdr = dh
	}
	return p, err
}

// Read implements the net.Conn read method.
func (co *Conn) Read(p []byte) (n int, err error) {
	if co.Conn == nil {
		return 0, ErrConnEmpty
	}

	if isPacketConn(co.Conn) {
		// UDP connection
		return co.Conn.Read(p)
	}

	var length uint16
	if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(co.Conn, p[:length])
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		// Set tsigRequestMAC for the next read, although only used in zone transfers.
		out, co.tsigRequestMAC, err = TsigGenerateWithProvider(m, co.tsigProvider(), co.tsigRequestMAC, false)
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	_, err = co.Write(out)
	return err
}

// Write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > MaxMsgSize {
		return 0, &Error{err: "message too large"}
	}

	if isPacketConn(co.Conn) {
		return co.Conn.Write(p)
	}

	msg := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(msg, uint16(len(p)))
	copy(msg[2:], p)
	return co.Conn.Write(msg)
}

// Return the appropriate timeout for a specific request
func (c *Client) getTimeoutForRequest(timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}

// Dial connects to the address on the named network.
func Dial(network, address string) (conn *Conn, err error) {
	conn = new(Conn)
	conn.Conn, err = net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ExchangeContext performs a synchronous UDP query, like Exchange. It
// additionally obeys deadlines from the passed Context.
func ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.ExchangeContext(ctx, m, a)
	// ignoring rtt to leave the original ExchangeContext API unchanged, but
	// this function will go away
	return r, err
}

// ExchangeConn performs a synchronous query. It sends the message m via the connection
// c and waits for a reply. The connection c is not closed by ExchangeConn.
// Deprecated: This function is going away, but can easily be mimicked:
//
//	co := &dns.Conn{Conn: c} // c is your net.Conn
//	co.WriteMsg(m)
//	in, _  := co.ReadMsg()
//	co.Close()
func ExchangeConn(c net.Conn, m *Msg) (r *Msg, err error) {
	println("dns: ExchangeConn: this function is deprecated")
	co := new(Conn)
	co.Conn = c
	if err = co.WriteMsg(m); err != nil {
		return nil, err
	}
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = ErrId
	}
	return r, err
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, timeout time.Duration) (conn *Conn, err error) {
	client := Client{Net: network, Dialer: &net.Dialer{Timeout: timeout}}
	return client.Dial(address)
}

// DialWithTLS connects to the address on the named network with TLS.
func DialWithTLS(network, address string, tlsConfig *tls.Config) (conn *Conn, err error) {
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, TLSConfig: tlsConfig}
	return client.Dial(address)
}

// DialTimeoutWithTLS acts like DialWithTLS but takes a timeout.
func DialTimeoutWithTLS(network, address string, tlsConfig *tls.Config, timeout time.Duration) (conn *Conn, err error) {
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, Dialer: &net.Dialer{Timeout: timeout}, TLSConfig: tlsConfig}
	return client.Dial(address)
}

// ExchangeContext acts like Exchange, but honors the deadline on the provided
// context, if present. If there is both a context deadline and a configured
// timeout on the client, the earliest of the two takes effect.
//
// When Client.TCPFallback is set and the client uses a UDP network, a
// truncated response is retried once over TCP. Both exchanges belong to the
// same query: they share the deadline that was computed before the UDP
// exchange started and the caller's cancellation, and the deadline is never
// recomputed for the fallback.
func (c *Client) ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	tcpNet := ""
	if c.TCPFallback {
		tcpNet = tcpFallbackNetwork(c.Net)
	}

	conn, err := c.DialContext(ctx, a)
	if err != nil {
		return nil, 0, err
	}

	// The budget is fixed when the exchange begins and is shared by the UDP
	// exchange and the TCP fallback, so neither can extend it.
	start := time.Now()
	budget, cancel := c.newQueryBudget(ctx, start)
	defer cancel()

	r, rtt, err = c.exchangeConn(ctx, m, conn, start, budget)
	conn.Close()
	if tcpNet == "" || err != nil || r == nil || !r.Truncated {
		return r, rtt, err
	}

	// The UDP response was truncated: retry the same query exactly once
	// over TCP, inside the same budget. The fallback is dialled with the
	// budget's context so a cancelled query cannot start a new connection.
	tconn, err := c.dialFallback(budget.ctx, tcpNet, a)
	if err != nil {
		return r, time.Since(start), &FallbackError{UDP: r, Err: err}
	}
	if err := budget.ctx.Err(); err != nil {
		// Cancelled or out of time between the two phases.
		tconn.Close()
		return r, time.Since(start), &FallbackError{UDP: r, Err: err}
	}
	tr, rtt, terr := c.exchangeConn(ctx, m, tconn, start, budget)
	tconn.Close()
	if terr != nil {
		return r, rtt, &FallbackError{UDP: r, Err: terr}
	}
	if tr == nil || !matchingQuestion(m, tr) {
		return r, rtt, &FallbackError{UDP: r, Err: ErrQuestion}
	}
	return tr, rtt, nil
}

// dialFallback dials the TCP counterpart of a UDP exchange for the same
// query. It never produces TLS and never changes the client's network.
func (c *Client) dialFallback(ctx context.Context, network, address string) (*Conn, error) {
	fallback := *c
	fallback.Net = network
	fallback.TCPFallback = false // the fallback is never itself retried
	return fallback.DialContext(ctx, address)
}

// tcpFallbackNetwork returns the TCP network corresponding to the given UDP
// network, or "" if network is not a UDP network.
func tcpFallbackNetwork(network string) string {
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

// matchingQuestion reports whether the response r answers the question asked
// in the query m, i.e. whether the question sections agree on name, type and
// class.
func matchingQuestion(m, r *Msg) bool {
	if len(m.Question) == 0 || len(r.Question) == 0 {
		return len(m.Question) == len(r.Question)
	}
	q, a := m.Question[0], r.Question[0]
	return q.Qtype == a.Qtype && q.Qclass == a.Qclass && strings.EqualFold(q.Name, a.Name)
}
