package dns

import (
	"fmt"
	"strings"
)

// EDNSOutcome classifies how a peer answered a query that advertised EDNS.
//
// The distinction matters for retry policy: a peer that ignored EDNS can
// still be used with the classic 512 byte limit, a peer that rejected the
// version should be retried without EDNS, and a truncated response should be
// retried over TCP instead.
type EDNSOutcome uint8

const (
	// EDNSNegotiated means the peer answered with an OPT record of version 0
	// and the exchange is usable as-is.
	EDNSNegotiated EDNSOutcome = iota
	// EDNSIgnored means the peer answered without an OPT record, so the
	// capabilities advertised by the query were not used. The answer itself
	// may still be valid at the classic 512 byte limit.
	EDNSIgnored
	// EDNSBadVers means the peer rejected the EDNS version, either explicitly
	// with RcodeBadVers or with a non-zero version in its OPT record.
	EDNSBadVers
	// EDNSFormatError means the peer answered with RcodeFormatError. It is
	// its own class: a FORMERR without an OPT record is the classic signal of
	// a peer that does not understand EDNS, whereas a FORMERR with an OPT
	// record means the peer does understand EDNS and the request itself was
	// rejected.
	EDNSFormatError
	// EDNSMalformed means the response could not be decoded.
	EDNSMalformed
	// EDNSStale means the response does not belong to the query, for example
	// a late response to an earlier exchange or a response from a different
	// peer. It must not influence negotiation.
	EDNSStale
	// EDNSNotOffered means the query did not advertise EDNS at all, so there
	// is nothing to negotiate. The peer's capabilities are irrelevant to the
	// exchange and are not adopted.
	EDNSNotOffered
)

// String returns the name of the outcome.
func (o EDNSOutcome) String() string {
	switch o {
	case EDNSNegotiated:
		return "negotiated"
	case EDNSIgnored:
		return "ignored"
	case EDNSBadVers:
		return "bad version"
	case EDNSFormatError:
		return "format error"
	case EDNSMalformed:
		return "malformed"
	case EDNSStale:
		return "stale response"
	case EDNSNotOffered:
		return "not offered"
	}
	return "unknown outcome"
}

// EDNSRetry is the recommended action after evaluating a response.
type EDNSRetry uint8

const (
	// EDNSRetryNone means the response can be used as-is, or cannot be fixed
	// by a retry in a different mode.
	EDNSRetryNone EDNSRetry = iota
	// EDNSRetryWithoutEDNS means the same query should be retried with the
	// OPT record removed.
	EDNSRetryWithoutEDNS
	// EDNSRetryOverTCP means the response was truncated and the query should
	// be retried over a stream transport.
	EDNSRetryOverTCP
)

// String returns the name of the retry action.
func (r EDNSRetry) String() string {
	switch r {
	case EDNSRetryNone:
		return "none"
	case EDNSRetryWithoutEDNS:
		return "without EDNS"
	case EDNSRetryOverTCP:
		return "over TCP"
	}
	return "unknown retry"
}

// Errors returned (possibly wrapped in *EDNSError) by EDNS negotiation.
// Use errors.Is to distinguish the categories.
var (
	ErrEDNSIgnored     error = &Error{err: "peer ignored EDNS"}
	ErrEDNSBadVers     error = &Error{err: "peer rejected the EDNS version"}
	ErrEDNSFormatError error = &Error{err: "peer returned FORMERR"}
	ErrEDNSMalformed   error = &Error{err: "malformed DNS response"}
	ErrEDNSStale       error = &Error{err: "response does not belong to the query"}
)

// EDNSError reports why an EDNS negotiation did not succeed. Outcome, Rcode
// and Retry carry the classification; Err is one of ErrEDNS* (or wraps one,
// for malformed responses) so errors.Is works across the categories.
type EDNSError struct {
	// Outcome is the classification of the response.
	Outcome EDNSOutcome
	// Rcode is the response's (possibly extended) RCODE.
	Rcode int
	// Retry is the recommended next action.
	Retry EDNSRetry
	// Err is the underlying cause; it wraps one of the ErrEDNS* sentinels.
	Err error
}

// Error implements the error interface.
func (e *EDNSError) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	s := "dns: edns " + e.Outcome.String()
	if e.Rcode != 0 {
		name, ok := RcodeToString[e.Rcode]
		if !ok {
			name = fmt.Sprintf("rcode %d", e.Rcode)
		}
		// RcodeBadSig and RcodeBadVers share the value 16; in an EDNS
		// context the meaningful name is BADVERS.
		if e.Outcome == EDNSBadVers {
			name = "BADVERS"
		}
		s += " (" + name + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the underlying cause so errors.Is and errors.As can reach
// the ErrEDNS* sentinel.
func (e *EDNSError) Unwrap() error { return e.Err }

// EDNSQuery is an immutable snapshot of the EDNS parameters advertised by an
// outgoing query. It is captured once, before the query is sent, so that
// later changes to the message - or a late response from another exchange -
// cannot alter how its response is interpreted.
//
// Use NewEDNSQuery to build one.
type EDNSQuery struct {
	// Present reports whether the query carried an OPT record.
	Present bool
	// UDPSize is the UDP payload size advertised by the query's OPT record.
	UDPSize uint16
	// Version is the EDNS version advertised by the query's OPT record.
	Version uint8
	// DO reports whether the query set the DNSSEC OK bit.
	DO bool
	// CO reports whether the query set the Compact Answers OK bit.
	CO bool
	// Options holds the option codes advertised by the query, in order. The
	// slice is a copy and is never modified by negotiation.
	Options []uint16

	id          uint16
	question    Question
	hasQuestion bool
}

// NewEDNSQuery snapshots the EDNS parameters of m. It records the message ID
// and first question as well, so that responses can be verified against the
// query they claim to answer. The message m is not modified.
func NewEDNSQuery(m *Msg) EDNSQuery {
	q := EDNSQuery{}
	if m == nil {
		return q
	}
	q.id = m.Id
	if len(m.Question) > 0 {
		q.question = m.Question[0]
		q.hasQuestion = true
	}

	opt := m.IsEdns0()
	if opt == nil {
		return q
	}
	q.Present = true
	q.UDPSize = opt.UDPSize()
	q.Version = opt.Version()
	q.DO = opt.Do()
	q.CO = opt.Co()
	if len(opt.Option) > 0 {
		q.Options = make([]uint16, 0, len(opt.Option))
		for _, o := range opt.Option {
			if o != nil {
				q.Options = append(q.Options, o.Option())
			}
		}
	}
	return q
}

// EDNSNegotiation is the result of matching a response against an EDNSQuery.
//
// A negotiation is always returned, even on error. The error paths return a
// conservative negotiation (Supported false, PayloadSize MinMsgSize) that is
// safe to use for building a fallback reply.
type EDNSNegotiation struct {
	// Outcome classifies the response.
	Outcome EDNSOutcome
	// Supported reports whether the peer confirmed EDNS with a version 0 OPT
	// record. Only then may any advertised extension be used.
	Supported bool
	// Truncated reports whether the response had the TC bit set.
	Truncated bool
	// PayloadSize is the maximum response size the exchange may use. It is
	// the query's advertised UDP size clamped to at least MinMsgSize, or
	// MinMsgSize when EDNS was not negotiated.
	PayloadSize uint16
	// PeerUDPSize is the UDP payload size advertised by the peer's OPT
	// record, clamped to at least MinMsgSize. It is zero when the peer did not
	// send an OPT record.
	PeerUDPSize uint16
	// Version is the EDNS version confirmed by the peer.
	Version uint8
	// DO reports whether the DNSSEC OK bit was negotiated: it is set only if
	// both the query and the peer set it.
	DO bool
	// CO reports whether the Compact Answers OK bit was negotiated: it is set
	// only if both the query and the peer set it.
	CO bool
	// Options holds the option codes that were both advertised by the query
	// and returned by the peer, in peer order. Responses must not use options
	// outside this set.
	Options []uint16
	// Retry is the recommended next action, if any.
	Retry EDNSRetry
}

// HasOption reports whether code was negotiated: it was advertised by the
// query and returned by the peer.
func (n EDNSNegotiation) HasOption(code uint16) bool {
	for _, c := range n.Options {
		if c == code {
			return true
		}
	}
	return false
}

// Negotiate matches the response r against q and reports what was negotiated.
//
// A response is rejected as EDNSStale unless it has the QR bit set, its ID
// matches the query and, when both carry a question, the questions agree on
// name, type and class. This keeps a late response to an earlier exchange, or
// a response from another server, from influencing this negotiation.
//
// The returned negotiation is always safe to use. When the returned error is
// non-nil it is an *EDNSError; ErrEDNSIgnored and ErrEDNSFormatError describe
// peers whose answer may still be usable, while ErrEDNSBadVers, ErrEDNSStale
// and ErrEDNSMalformed invalidate the EDNS capabilities of the exchange.
func (q EDNSQuery) Negotiate(r *Msg) (EDNSNegotiation, error) {
	if r == nil {
		n := EDNSNegotiation{Outcome: EDNSMalformed, PayloadSize: MinMsgSize}
		return n, &EDNSError{Outcome: EDNSMalformed, Err: ErrEDNSMalformed}
	}

	n := EDNSNegotiation{
		PayloadSize: MinMsgSize,
		Truncated:   r.Truncated,
	}

	if !r.Response || r.Id != q.id || (q.hasQuestion && len(r.Question) > 0 && !sameQuestion(q.question, r.Question[0])) {
		n.Outcome = EDNSStale
		return n, &EDNSError{Outcome: EDNSStale, Rcode: r.Rcode, Err: ErrEDNSStale}
	}

	if !q.Present {
		// No EDNS was advertised, so there is nothing to negotiate and no
		// failure to report. The peer's OPT record, if any, is not a
		// capability of this exchange.
		n.Outcome = EDNSNotOffered
		n.Retry = retryForTruncation(r.Truncated)
		return n, nil
	}

	opt := r.IsEdns0()
	switch {
	case r.Rcode == RcodeBadVers:
		n.Outcome = EDNSBadVers
		n.Retry = EDNSRetryWithoutEDNS
		if opt != nil {
			n.Version = opt.Version()
			n.PeerUDPSize = clampUDPSize(opt.UDPSize())
		}
		return n, &EDNSError{Outcome: EDNSBadVers, Rcode: r.Rcode, Retry: n.Retry, Err: ErrEDNSBadVers}

	case opt == nil:
		if r.Rcode == RcodeFormatError {
			// A FORMERR without an OPT record is the classic signal of a
			// server that does not understand EDNS at all.
			n.Outcome = EDNSFormatError
			n.Retry = EDNSRetryWithoutEDNS
			return n, &EDNSError{Outcome: EDNSFormatError, Rcode: r.Rcode, Retry: n.Retry, Err: ErrEDNSFormatError}
		}
		// The peer answered but ignored the OPT record: usable, but only at
		// the classic payload size and without any extension.
		n.Outcome = EDNSIgnored
		n.Retry = retryForTruncation(r.Truncated)
		return n, &EDNSError{Outcome: EDNSIgnored, Rcode: r.Rcode, Retry: n.Retry, Err: ErrEDNSIgnored}

	case opt.Version() != 0:
		n.Outcome = EDNSBadVers
		n.Retry = EDNSRetryWithoutEDNS
		n.PeerUDPSize = clampUDPSize(opt.UDPSize())
		n.Version = opt.Version()
		return n, &EDNSError{Outcome: EDNSBadVers, Rcode: r.Rcode, Retry: n.Retry, Err: ErrEDNSBadVers}

	case r.Rcode == RcodeFormatError:
		// The peer parsed an OPT record, so it does implement EDNS; the
		// FORMERR concerns the message itself. It is still its own category,
		// distinct from BADVERS and from a peer that ignored EDNS, and the
		// standard fallback is still to retry once without EDNS. No
		// capability is negotiated because the exchange did not succeed.
		n.Outcome = EDNSFormatError
		n.Retry = EDNSRetryWithoutEDNS
		return n, &EDNSError{Outcome: EDNSFormatError, Rcode: r.Rcode, Retry: n.Retry, Err: ErrEDNSFormatError}
	}

	n.Outcome = EDNSNegotiated
	n.Supported = true
	n.Version = 0
	n.PeerUDPSize = clampUDPSize(opt.UDPSize())
	n.PayloadSize = clampUDPSize(q.UDPSize)
	n.DO = q.DO && opt.Do()
	n.CO = q.CO && opt.Co()
	n.Options = negotiatedOptions(q.Options, opt.Option)
	n.Retry = retryForTruncation(r.Truncated)
	return n, nil
}

// ReadResponse decodes wire and negotiates it against q. Unlike Msg.Unpack,
// a truncated or malformed response never leaves partially decoded records in
// the returned message: only the verifiable header, question section and (for
// a cleanly parsed truncated response) the OPT record are retained.
//
// The returned message is always non-nil. When decoding fails, the returned
// error is an *EDNSError matching ErrEDNSMalformed and wrapping the decode
// error.
func (q EDNSQuery) ReadResponse(wire []byte) (*Msg, EDNSNegotiation, error) {
	r := new(Msg)
	if err := r.UnpackResponse(wire); err != nil {
		n := EDNSNegotiation{Outcome: EDNSMalformed, PayloadSize: MinMsgSize}
		return r, n, &EDNSError{Outcome: EDNSMalformed, Err: fmt.Errorf("%w: %w", ErrEDNSMalformed, err)}
	}
	n, err := q.Negotiate(r)
	return r, n, err
}

// RewriteResponse returns a new message, based on r, that is safe to send to
// the peer of this negotiation. r itself is never modified.
//
// The returned message only uses negotiated capabilities:
//   - If EDNS was not negotiated, every OPT record is removed and the message
//     is limited to the classic payload size.
//   - Otherwise exactly one OPT record is kept (or inserted before a trailing
//     TSIG record), its version is set to 0, its UDP payload size is set to
//     the negotiated payload size, its DO and CO bits are set to the
//     negotiated values, and its options are reduced to those the peer
//     returned.
//
// The message is then truncated to size, or to the negotiated payload size
// when size is zero or negative. The size argument is the transport limit
// chosen by the caller (MinMsgSize for plain UDP, MaxMsgSize for TCP);
// passing a value above the negotiated payload is only appropriate on a
// transport that can carry it. Truncation keeps the header and question
// sections intact and only removes whole resource records, so the result
// never contains a partially encoded record. As with Msg.Truncate, a message
// carrying a TSIG record is not truncated.
func (n EDNSNegotiation) RewriteResponse(r *Msg, size int) *Msg {
	if r == nil {
		return nil
	}
	out := r.Copy()

	// Collapse the OPT records to at most one, keeping the first.
	var opt *OPT
	kept := out.Extra[:0]
	for _, rr := range out.Extra {
		if rr != nil && rr.Header().Rrtype == TypeOPT {
			if opt != nil {
				continue
			}
			opt = rr.(*OPT)
		}
		kept = append(kept, rr)
	}
	out.Extra = kept

	if !n.Supported {
		if opt != nil {
			for i, rr := range out.Extra {
				if rr == opt {
					out.Extra = append(out.Extra[:i], out.Extra[i+1:]...)
					break
				}
			}
		}
	} else {
		if opt == nil {
			opt = new(OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = TypeOPT
			insertOPT(out, opt)
		}
		opt.SetUDPSize(n.PayloadSize)
		opt.SetVersion(0)
		opt.SetDo(n.DO)
		opt.SetCo(n.CO)
		opt.Option = filterEDNS0Options(opt.Option, n.Options)
	}

	if size <= 0 {
		size = int(n.PayloadSize)
	}
	out.Truncate(size)
	return out
}

// UnpackResponse decodes a DNS response like Msg.Unpack, but guarantees that
// a truncated or malformed response never yields partially decoded records.
//
// The message is reset first, so reusing a Msg value cannot carry records
// over from a previous exchange. When the TC bit is set, or when decoding
// fails, the answer and authority sections are dropped. A truncated response
// keeps the header, the question section and any fully decoded OPT record, so
// the EDNS capabilities of the response remain verifiable; a malformed
// response keeps only the header and the question records that decoded
// completely.
//
// The decode error is returned unchanged when decoding fails.
func (dns *Msg) UnpackResponse(msg []byte) error {
	*dns = Msg{}

	err := dns.Unpack(msg)
	if err == nil && !dns.Truncated {
		return nil
	}
	if err != nil {
		dns.Answer, dns.Ns, dns.Extra = nil, nil, nil
		return err
	}

	// Truncated but parseable: keep the OPT record for negotiation, drop
	// every other record so no incomplete answer set is exposed.
	opt := dns.IsEdns0()
	dns.Answer, dns.Ns, dns.Extra = nil, nil, nil
	if opt != nil {
		dns.Extra = []RR{opt}
	}
	return nil
}

// sameQuestion reports whether two questions agree on name, type and class.
func sameQuestion(a, b Question) bool {
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}

// clampUDPSize applies the RFC 6891 rule that payload sizes below MinMsgSize
// are treated as MinMsgSize.
func clampUDPSize(size uint16) uint16 {
	if size < MinMsgSize {
		return MinMsgSize
	}
	return size
}

// retryForTruncation recommends a TCP retry when the response was truncated.
func retryForTruncation(truncated bool) EDNSRetry {
	if truncated {
		return EDNSRetryOverTCP
	}
	return EDNSRetryNone
}

// negotiatedOptions returns the option codes from responses that were also
// advertised in requested, preserving response order.
func negotiatedOptions(requested []uint16, responses []EDNS0) []uint16 {
	if len(requested) == 0 || len(responses) == 0 {
		return nil
	}
	allowed := make(map[uint16]struct{}, len(requested))
	for _, code := range requested {
		allowed[code] = struct{}{}
	}
	var options []uint16
	seen := make(map[uint16]struct{}, len(responses))
	for _, o := range responses {
		if o == nil {
			continue
		}
		code := o.Option()
		if _, ok := allowed[code]; !ok {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		options = append(options, code)
	}
	return options
}

// filterEDNS0Options keeps only the options whose codes are in allowed.
func filterEDNS0Options(options []EDNS0, allowed []uint16) []EDNS0 {
	if len(options) == 0 || len(allowed) == 0 {
		return nil
	}
	set := make(map[uint16]struct{}, len(allowed))
	for _, code := range allowed {
		set[code] = struct{}{}
	}
	var kept []EDNS0
	for _, o := range options {
		if o == nil {
			continue
		}
		if _, ok := set[o.Option()]; ok {
			kept = append(kept, o)
		}
	}
	return kept
}

// insertOPT appends opt to the additional section, keeping a trailing TSIG
// record last as required by RFC 8945.
func insertOPT(m *Msg, opt *OPT) {
	if m.IsTsig() == nil {
		m.Extra = append(m.Extra, opt)
		return
	}
	last := len(m.Extra) - 1
	m.Extra = append(m.Extra, nil)
	copy(m.Extra[last+1:], m.Extra[last:])
	m.Extra[last] = opt
}
