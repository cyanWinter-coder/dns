package dns

import (
	"errors"
	"fmt"
	"testing"
)

// newEDNSQueryMsg builds a query that advertises EDNS with the given size,
// version, DO/CO bits and option codes.
func newEDNSQueryMsg(t *testing.T, id uint16, size uint16, version uint8, do, co bool, codes ...uint16) *Msg {
	t.Helper()
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.Id = id
	m.SetEdns0(size, do)
	opt := m.IsEdns0()
	opt.SetVersion(version)
	opt.SetCo(co)
	for _, code := range codes {
		opt.Option = append(opt.Option, &EDNS0_LOCAL{Code: code, Data: []byte{1}})
	}
	return m
}

// newEDNSReplyMsg builds a response to q with the given rcode, and an OPT
// record when opt is non-nil.
func newEDNSReplyMsg(q *Msg, rcode int, opt *OPT) *Msg {
	r := new(Msg)
	r.SetReply(q)
	r.Rcode = rcode
	if opt != nil {
		r.Extra = append(r.Extra, opt)
	}
	return r
}

func newEDNSReplyOPT(size uint16, version uint8, do, co bool, codes ...uint16) *OPT {
	opt := new(OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = TypeOPT
	opt.SetUDPSize(size)
	opt.SetVersion(version)
	opt.SetDo(do)
	opt.SetCo(co)
	for _, code := range codes {
		opt.Option = append(opt.Option, &EDNS0_LOCAL{Code: code, Data: []byte{1}})
	}
	return opt
}

// TestEDNSQuerySnapshot covers requirement 1: the query's advertised buffer
// size, version and options are captured once and cannot be changed later by
// mutating the message.
func TestEDNSQuerySnapshot(t *testing.T) {
	m := newEDNSQueryMsg(t, 0x1234, 1232, 0, true, true, EDNS0COOKIE, EDNS0NSID)
	q := NewEDNSQuery(m)

	if !q.Present {
		t.Fatal("query should record that EDNS was advertised")
	}
	if q.UDPSize != 1232 || q.Version != 0 || !q.DO || !q.CO {
		t.Errorf("snapshot mismatch: %+v", q)
	}
	if len(q.Options) != 2 || q.Options[0] != EDNS0COOKIE || q.Options[1] != EDNS0NSID {
		t.Errorf("option snapshot mismatch: %v", q.Options)
	}

	// Mutating the message (and its OPT record) must not change the snapshot.
	m.Id = 0x9999
	m.SetQuestion("other.example.", TypeAAAA)
	opt := m.IsEdns0()
	opt.SetUDPSize(4096)
	opt.SetVersion(1)
	opt.SetDo(false)
	opt.SetCo(false)
	opt.Option = nil

	if q.UDPSize != 1232 || q.Version != 0 || !q.DO || !q.CO {
		t.Errorf("snapshot changed after mutating the message: %+v", q)
	}
	if len(q.Options) != 2 {
		t.Errorf("option snapshot changed after mutating the message: %v", q.Options)
	}
	if q.id != 0x1234 || q.question.Name != "example.org." || q.question.Qtype != TypeA {
		t.Errorf("response matching state changed after mutating the message: %+v", q)
	}
}

// TestEDNSNegotiateOnlyAdvertisedCapabilities covers requirement 1: a
// response only negotiates what the query actually advertised.
func TestEDNSNegotiateOnlyAdvertisedCapabilities(t *testing.T) {
	m := newEDNSQueryMsg(t, 7, 1232, 0, true, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)

	// The peer echoes the cookie, adds NSID that was never advertised, and
	// sets CO which the query did not set.
	r := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(4096, 0, true, true, EDNS0COOKIE, EDNS0NSID))
	n, err := q.Negotiate(r)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	if !n.Supported || n.Outcome != EDNSNegotiated {
		t.Fatalf("expected negotiated EDNS, got %v supported=%v", n.Outcome, n.Supported)
	}
	if !n.HasOption(EDNS0COOKIE) {
		t.Error("cookie was advertised and returned, it must be negotiated")
	}
	if n.HasOption(EDNS0NSID) {
		t.Error("NSID was not advertised and must not be negotiated")
	}
	if n.CO {
		t.Error("CO was not advertised by the query and must not be negotiated")
	}
	if !n.DO {
		t.Error("DO was advertised by both sides, it must be negotiated")
	}
	if n.PayloadSize != 1232 {
		t.Errorf("payload size must be the query's advertised size, got %d", n.PayloadSize)
	}
	if n.PeerUDPSize != 4096 {
		t.Errorf("peer UDP size must be recorded, got %d", n.PeerUDPSize)
	}
}

// TestEDNSNegotiateOutcomes covers requirement 3: BADVERS, FORMERR and an
// ignored OPT record are distinct categories with distinct errors and retry
// recommendations.
func TestEDNSNegotiateOutcomes(t *testing.T) {
	m := newEDNSQueryMsg(t, 21, 1232, 0, true, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)

	tests := []struct {
		name    string
		reply   *Msg
		outcome EDNSOutcome
		wantErr error
		retry   EDNSRetry
	}{
		{
			name:    "negotiated",
			reply:   newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false, EDNS0COOKIE)),
			outcome: EDNSNegotiated,
			retry:   EDNSRetryNone,
		},
		{
			name:    "badvers rcode",
			reply:   newEDNSReplyMsg(m, RcodeBadVers, newEDNSReplyOPT(1232, 0, false, false)),
			outcome: EDNSBadVers,
			wantErr: ErrEDNSBadVers,
			retry:   EDNSRetryWithoutEDNS,
		},
		{
			name:    "badvers version field",
			reply:   newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 1, false, false)),
			outcome: EDNSBadVers,
			wantErr: ErrEDNSBadVers,
			retry:   EDNSRetryWithoutEDNS,
		},
		{
			name:    "formerr without opt",
			reply:   newEDNSReplyMsg(m, RcodeFormatError, nil),
			outcome: EDNSFormatError,
			wantErr: ErrEDNSFormatError,
			retry:   EDNSRetryWithoutEDNS,
		},
		{
			name:    "formerr with opt",
			reply:   newEDNSReplyMsg(m, RcodeFormatError, newEDNSReplyOPT(1232, 0, false, false)),
			outcome: EDNSFormatError,
			wantErr: ErrEDNSFormatError,
			retry:   EDNSRetryWithoutEDNS,
		},
		{
			name:    "ignored opt",
			reply:   newEDNSReplyMsg(m, RcodeSuccess, nil),
			outcome: EDNSIgnored,
			wantErr: ErrEDNSIgnored,
			retry:   EDNSRetryNone,
		},
		{
			name:    "ignored opt truncated",
			reply:   newEDNSReplyMsg(m, RcodeSuccess, nil),
			outcome: EDNSIgnored,
			wantErr: ErrEDNSIgnored,
			retry:   EDNSRetryOverTCP,
		},
	}

	// The truncated case needs the TC bit, which SetReply does not set.
	tests[len(tests)-1].reply.Truncated = true

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := q.Negotiate(tc.reply)
			if n.Outcome != tc.outcome {
				t.Errorf("outcome = %v, want %v", n.Outcome, tc.outcome)
			}
			if n.Retry != tc.retry {
				t.Errorf("retry = %v, want %v", n.Retry, tc.retry)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !n.Supported {
					t.Error("negotiated EDNS should be supported")
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not match %v", err, tc.wantErr)
			}
			var e *EDNSError
			if !errors.As(err, &e) {
				t.Fatalf("error is not an *EDNSError: %T", err)
			}
			if e.Outcome != tc.outcome || e.Retry != tc.retry {
				t.Errorf("EDNSError classification mismatch: %+v", e)
			}
			if tc.outcome != EDNSIgnored && tc.outcome != EDNSFormatError && n.Supported {
				t.Error("EDNS must not be reported as supported")
			}
			if n.PayloadSize != MinMsgSize {
				t.Errorf("unnegotiated payload size must be %d, got %d", MinMsgSize, n.PayloadSize)
			}
		})
	}
}

// TestEDNSNegotiateNoEDNSQuery verifies that a query without EDNS does not
// adopt capabilities from a peer that happens to send an OPT record.
func TestEDNSNegotiateNoEDNSQuery(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.Id = 3
	q := NewEDNSQuery(m)
	if q.Present {
		t.Fatal("query has no OPT record")
	}

	r := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(4096, 0, true, true))
	r.Rcode = RcodeSuccess
	n, err := q.Negotiate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Outcome != EDNSNotOffered {
		t.Errorf("outcome = %v, want not offered", n.Outcome)
	}
	if n.Supported || n.PayloadSize != MinMsgSize || n.HasOption(0) {
		t.Errorf("capabilities must not be adopted without an EDNS query: %+v", n)
	}
}

// TestEDNSNegotiateStale covers requirement 4: a late response from an earlier
// exchange (different ID or question) is rejected and does not influence the
// negotiation of the current one.
func TestEDNSNegotiateStale(t *testing.T) {
	m1 := newEDNSQueryMsg(t, 100, 1232, 0, true, false, EDNS0COOKIE)
	q1 := NewEDNSQuery(m1)

	// A late response to a different ID.
	late := newEDNSReplyMsg(m1, RcodeSuccess, newEDNSReplyOPT(512, 0, false, false))
	late.Id = 200
	if _, err := q1.Negotiate(late); !errors.Is(err, ErrEDNSStale) {
		t.Errorf("response with a foreign ID must be stale, got %v", err)
	}

	// A response to a different question.
	wrongQ := newEDNSReplyMsg(m1, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false))
	wrongQ.Question[0].Name = "evil.example."
	if _, err := q1.Negotiate(wrongQ); !errors.Is(err, ErrEDNSStale) {
		t.Errorf("response with a foreign question must be stale, got %v", err)
	}

	// A query packet is not a response.
	notReply := newEDNSReplyMsg(m1, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false))
	notReply.Response = false
	if _, err := q1.Negotiate(notReply); !errors.Is(err, ErrEDNSStale) {
		t.Errorf("message without QR must be stale, got %v", err)
	}

	// The stale response must not have changed the state used for the next
	// negotiation: a genuine reply still negotiates as before.
	good := newEDNSReplyMsg(m1, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false, EDNS0COOKIE))
	n, err := q1.Negotiate(good)
	if err != nil {
		t.Fatalf("genuine reply after a stale one failed: %v", err)
	}
	if !n.Supported || !n.HasOption(EDNS0COOKIE) || !n.DO {
		t.Errorf("negotiation polluted by earlier stale response: %+v", n)
	}

	// A later query's negotiation must be independent from q1.
	m2 := newEDNSQueryMsg(t, 101, 4096, 0, false, false)
	q2 := NewEDNSQuery(m2)
	n2, err := q2.Negotiate(newEDNSReplyMsg(m2, RcodeSuccess, newEDNSReplyOPT(4096, 0, false, false)))
	if err != nil {
		t.Fatalf("second query negotiation failed: %v", err)
	}
	if n2.DO {
		t.Error("second query did not set DO, negotiation must not inherit it")
	}
	if n2.PayloadSize != 4096 {
		t.Errorf("second query payload size = %d, want 4096", n2.PayloadSize)
	}
}

// TestEDNSReadResponseTruncated covers requirement 2: a truncated response
// keeps a verifiable header and question section, and never exposes
// half-parsed answers.
func TestEDNSReadResponseTruncated(t *testing.T) {
	m := newEDNSQueryMsg(t, 55, 1232, 0, true, false)
	q := NewEDNSQuery(m)

	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false))
	reply.Truncated = true
	for i := 0; i < 4; i++ {
		reply.Answer = append(reply.Answer, testRR(fmt.Sprintf("example.org. 10 IN A 192.0.2.%d", i+1)))
	}
	wire, err := reply.Pack()
	if err != nil {
		t.Fatalf("failed to pack reply: %v", err)
	}

	r, n, err := q.ReadResponse(wire)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.Truncated {
		t.Error("TC bit must be retained")
	}
	if r.Id != m.Id || len(r.Question) != 1 || r.Question[0] != m.Question[0] {
		t.Errorf("header or question section not preserved: %v", r)
	}
	if len(r.Answer) != 0 || len(r.Ns) != 0 {
		t.Errorf("truncated response exposed records: %d answers, %d ns", len(r.Answer), len(r.Ns))
	}
	opt := r.IsEdns0()
	if opt == nil {
		t.Fatal("truncated response lost its OPT record; its EDNS claims cannot be verified")
	}
	if len(r.Extra) != 1 {
		t.Errorf("truncated response kept %d extra records, want only the OPT", len(r.Extra))
	}
	if n.Outcome != EDNSNegotiated || !n.Truncated || n.Retry != EDNSRetryOverTCP {
		t.Errorf("negotiation = %+v, want negotiated+truncated+retry over TCP", n)
	}
	if !n.Supported || n.PayloadSize != 1232 {
		t.Errorf("negotiation lost the payload size: %+v", n)
	}
}

// TestEDNSReadResponseMalformed covers the malformed category: a response cut
// in the middle of a record keeps only the header and the question section.
func TestEDNSReadResponseMalformed(t *testing.T) {
	m := newEDNSQueryMsg(t, 56, 1232, 0, true, false)
	q := NewEDNSQuery(m)

	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false))
	for i := 0; i < 4; i++ {
		reply.Answer = append(reply.Answer, testRR(fmt.Sprintf("example.org. 10 IN A 192.0.2.%d", i+1)))
	}
	wire, err := reply.Pack()
	if err != nil {
		t.Fatalf("failed to pack reply: %v", err)
	}

	// Cut the wire format in the middle of the answer section.
	r, n, err := q.ReadResponse(wire[:headerSize+len(wire)/2])
	if err == nil {
		t.Fatal("cut response should not decode")
	}
	if !errors.Is(err, ErrEDNSMalformed) {
		t.Errorf("error %v does not match ErrEDNSMalformed", err)
	}
	var e *EDNSError
	if !errors.As(err, &e) || e.Outcome != EDNSMalformed {
		t.Errorf("error is not classified as malformed: %v", err)
	}
	if n.Outcome != EDNSMalformed || n.Supported {
		t.Errorf("malformed response must not negotiate: %+v", n)
	}
	if r == nil {
		t.Fatal("ReadResponse must return the decoded header")
	}
	if r.Id != m.Id {
		t.Errorf("header not retained: id %d", r.Id)
	}
	if len(r.Answer) != 0 || len(r.Ns) != 0 {
		t.Errorf("malformed response exposed partially decoded records: %d answers, %d ns", len(r.Answer), len(r.Ns))
	}
}

// TestUnpackResponseResetsSections covers requirement 4: reusing a Msg value
// cannot carry records over from a previous exchange.
func TestUnpackResponseResetsSections(t *testing.T) {
	full := new(Msg)
	full.SetQuestion("example.org.", TypeA)
	full.SetReply(full)
	full.Answer = append(full.Answer, testRR("example.org. 10 IN A 192.0.2.1"))
	fullWire, err := full.Pack()
	if err != nil {
		t.Fatalf("failed to pack full reply: %v", err)
	}

	trunc := new(Msg)
	trunc.SetQuestion("example.org.", TypeA)
	trunc.SetReply(trunc)
	trunc.Truncated = true
	trunc.Answer = append(trunc.Answer, testRR("example.org. 10 IN A 192.0.2.2"))
	truncWire, err := trunc.Pack()
	if err != nil {
		t.Fatalf("failed to pack truncated reply: %v", err)
	}

	var r Msg
	if err := r.UnpackResponse(fullWire); err != nil {
		t.Fatalf("full reply failed to decode: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("full reply should have one answer, got %d", len(r.Answer))
	}

	if err := r.UnpackResponse(truncWire); err != nil {
		t.Fatalf("truncated reply failed to decode: %v", err)
	}
	if len(r.Answer) != 0 {
		t.Errorf("previous answer survived into the truncated response: %v", r.Answer)
	}
	if !r.Truncated || r.Id != trunc.Id {
		t.Errorf("truncated header not decoded correctly: %+v", r.MsgHdr)
	}
}

// TestEDNSRewriteResponse covers requirement 4 (the original message is never
// modified) together with the capability restriction of requirement 1.
func TestEDNSRewriteResponse(t *testing.T) {
	m := newEDNSQueryMsg(t, 77, 1232, 0, true, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)
	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(4096, 0, true, true, EDNS0COOKIE, EDNS0NSID))
	reply.Answer = append(reply.Answer, testRR("example.org. 10 IN A 192.0.2.1"))
	before := reply.Copy()

	n, err := q.Negotiate(reply)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	out := n.RewriteResponse(reply, 0)
	if out == nil {
		t.Fatal("RewriteResponse returned nil")
	}

	// The original response must be untouched.
	if fmt.Sprint(reply) != fmt.Sprint(before) {
		t.Errorf("RewriteResponse modified its input:\n before: %v\n after:  %v", before, reply)
	}
	outOpt := out.IsEdns0()
	if outOpt == nil {
		t.Fatal("rewritten response lost the OPT record")
	}
	if outOpt.UDPSize() != 1232 {
		t.Errorf("rewritten OPT advertises %d, want the negotiated 1232", outOpt.UDPSize())
	}
	if outOpt.Version() != 0 || !outOpt.Do() || outOpt.Co() {
		t.Errorf("rewritten OPT flags/version not negotiated: version=%d do=%v co=%v", outOpt.Version(), outOpt.Do(), outOpt.Co())
	}
	if len(outOpt.Option) != 1 || outOpt.Option[0].Option() != EDNS0COOKIE {
		t.Errorf("rewritten OPT must keep only negotiated options, got %v", outOpt.Option)
	}
	if len(out.Answer) != 1 {
		t.Errorf("small response should keep its answer, got %d", len(out.Answer))
	}
	if out.Truncated {
		t.Error("small response should not be truncated")
	}

	// The rewritten message must be packable.
	if _, err := out.Pack(); err != nil {
		t.Errorf("rewritten response does not pack: %v", err)
	}
}

// TestEDNSRewriteResponseWithoutEDNS verifies that when EDNS was not
// negotiated the rewrite strips the OPT record and enforces the classic limit.
func TestEDNSRewriteResponseWithoutEDNS(t *testing.T) {
	m := newEDNSQueryMsg(t, 78, 1232, 0, false, false)
	q := NewEDNSQuery(m)

	// Peer ignored the OPT: its answer is usable, but without the extension.
	reply := newEDNSReplyMsg(m, RcodeSuccess, nil)
	n, err := q.Negotiate(reply)
	if !errors.Is(err, ErrEDNSIgnored) {
		t.Fatalf("expected ignored EDNS, got %v", err)
	}

	// A server that answers anyway with an OPT record of its own: the
	// rewrite must not echo it back.
	serverReply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(4096, 0, true, true))
	for i := 0; i < 100; i++ {
		serverReply.Answer = append(serverReply.Answer, testRR(
			fmt.Sprintf("example.org. 10 IN TXT %q", fmt.Sprintf("%064d", i))))
	}

	out := n.RewriteResponse(serverReply, 0)
	if out.IsEdns0() != nil {
		t.Error("rewritten response must not carry an OPT record when EDNS was not negotiated")
	}
	if out.Len() > MinMsgSize {
		t.Errorf("rewritten response is %d bytes, classic limit is %d", out.Len(), MinMsgSize)
	}
	if !out.Truncated {
		t.Error("oversized rewritten response must have TC set")
	}
	if len(out.Question) != 1 || out.Question[0] != serverReply.Question[0] {
		t.Errorf("question section not preserved: %v", out.Question)
	}
	if serverReply.Truncated || len(serverReply.Answer) != 100 {
		t.Error("RewriteResponse modified its input")
	}
	if _, err := out.Pack(); err != nil {
		t.Errorf("rewritten response does not pack: %v", err)
	}
}

// TestEDNSRewriteResponseKeepsTSIGLast verifies that inserting an OPT record
// into a response does not displace a trailing TSIG.
func TestEDNSRewriteResponseKeepsTSIGLast(t *testing.T) {
	m := newEDNSQueryMsg(t, 79, 1232, 0, false, false)
	q := NewEDNSQuery(m)
	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, false, false))
	reply.SetTsig("example.org.", HmacSHA256, 300, 1700000000)

	n, err := q.Negotiate(reply)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	out := n.RewriteResponse(reply, 0)
	if out.IsTsig() == nil {
		t.Fatal("rewritten response lost its TSIG record")
	}
	if out.Extra[len(out.Extra)-1].Header().Rrtype != TypeTSIG {
		t.Error("TSIG must remain the last record")
	}
	if out.IsEdns0() == nil {
		t.Error("rewritten response must retain the OPT record")
	}
	if reply.IsEdns0() == nil {
		t.Error("RewriteResponse modified its input")
	}
}

// TestEDNSRewriteCollapsesDuplicateOPT covers the case of a response with more
// than one OPT record: the rewrite keeps exactly one.
func TestEDNSRewriteCollapsesDuplicateOPT(t *testing.T) {
	m := newEDNSQueryMsg(t, 80, 1232, 0, false, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)
	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, false, false, EDNS0COOKIE))
	reply.Extra = append(reply.Extra, newEDNSReplyOPT(4096, 0, false, false, EDNS0NSID))

	n, err := q.Negotiate(reply)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	out := n.RewriteResponse(reply, 0)
	count := 0
	for _, rr := range out.Extra {
		if rr.Header().Rrtype == TypeOPT {
			count++
		}
	}
	if count != 1 {
		t.Errorf("rewritten response has %d OPT records, want 1", count)
	}
	if len(reply.Extra) != 2 {
		t.Error("RewriteResponse modified its input")
	}
}

// TestEDNSRewriteTruncationKeepsQuestionAndPacks covers requirement 2 for
// responses the caller rewrites at an explicit size: truncation keeps the
// header and question sections, drops whole records only, and the result
// always packs within the requested size.
func TestEDNSRewriteTruncationKeepsQuestionAndPacks(t *testing.T) {
	const size = 1232
	m := newEDNSQueryMsg(t, 81, size, 0, true, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)
	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(size, 0, true, false, EDNS0COOKIE))
	for i := 0; i < 200; i++ {
		reply.Answer = append(reply.Answer, testRR(
			fmt.Sprintf("large.example.org. 10 IN TXT %q", fmt.Sprintf("answer-%03d-%s", i, repeat("x", 40)))))
	}
	before := reply.Copy()

	n, err := q.Negotiate(reply)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	out := n.RewriteResponse(reply, size)

	if !out.Truncated {
		t.Error("oversized rewrite must set TC")
	}
	if out.Len() > size {
		t.Errorf("rewritten response is %d bytes, limit is %d", out.Len(), size)
	}
	if len(out.Question) != 1 || out.Question[0] != reply.Question[0] {
		t.Errorf("question section not preserved: %v", out.Question)
	}
	if len(out.Answer) == 0 || len(out.Answer) == len(reply.Answer) {
		t.Errorf("expected a partial answer set, got %d of %d", len(out.Answer), len(reply.Answer))
	}
	if out.IsEdns0() == nil {
		t.Error("rewritten response lost its OPT record")
	}
	wire, err := out.Pack()
	if err != nil {
		t.Fatalf("rewritten response does not pack: %v", err)
	}
	// The packed form must decode cleanly: no half records.
	var decoded Msg
	if err := decoded.Unpack(wire); err != nil {
		t.Fatalf("rewritten response does not unpack: %v", err)
	}
	if len(decoded.Answer) != len(out.Answer) {
		t.Errorf("decoded %d answers, rewrote %d", len(decoded.Answer), len(out.Answer))
	}
	if fmt.Sprint(reply) != fmt.Sprint(before) {
		t.Error("RewriteResponse modified its input")
	}
}

// TestEDNSNegotiationRepeatable covers requirement 5: negotiation and
// rewriting are deterministic, so the same inputs always produce the same
// classification and wire output.
func TestEDNSNegotiationRepeatable(t *testing.T) {
	m := newEDNSQueryMsg(t, 82, 1232, 0, true, false, EDNS0COOKIE)
	q := NewEDNSQuery(m)
	reply := newEDNSReplyMsg(m, RcodeSuccess, newEDNSReplyOPT(1232, 0, true, false, EDNS0COOKIE, EDNS0NSID))
	for i := 0; i < 20; i++ {
		reply.Answer = append(reply.Answer, testRR(
			fmt.Sprintf("large.example.org. 10 IN TXT %q", fmt.Sprintf("answer-%02d-%s", i, repeat("y", 30)))))
	}

	var firstWire []byte
	for i := 0; i < 10; i++ {
		n, err := q.Negotiate(reply)
		if err != nil {
			t.Fatalf("iteration %d: negotiation failed: %v", i, err)
		}
		if n.Outcome != EDNSNegotiated || !n.HasOption(EDNS0COOKIE) || n.HasOption(EDNS0NSID) {
			t.Fatalf("iteration %d: unstable negotiation: %+v", i, n)
		}
		out := n.RewriteResponse(reply, 1232)
		wire, err := out.Pack()
		if err != nil {
			t.Fatalf("iteration %d: pack failed: %v", i, err)
		}
		if firstWire == nil {
			firstWire = wire
			continue
		}
		if string(wire) != string(firstWire) {
			t.Fatalf("iteration %d: rewritten wire output differs", i)
		}
	}
}

// TestEDNSNegotiationCompatibility checks that negotiation does not alter the
// established EDNS0, packing and Truncate behaviours, and that a negotiated
// rewrite round-trips through the ordinary pack/unpack path.
func TestEDNSNegotiationCompatibility(t *testing.T) {
	m := new(Msg)
	m.SetQuestion("example.org.", TypeA)
	m.SetEdns0(DefaultMsgSize, true)
	opt := m.IsEdns0()
	if opt.UDPSize() != DefaultMsgSize || !opt.Do() || opt.Version() != 0 {
		t.Fatalf("SetEdns0 behaviour changed: %+v", opt)
	}

	q := NewEDNSQuery(m)
	reply := new(Msg)
	reply.SetReply(m)
	reply.SetEdns0(DefaultMsgSize, true)
	reply.Rcode = RcodeSuccess
	reply.Answer = append(reply.Answer, testRR("example.org. 10 IN A 192.0.2.1"))

	n, err := q.Negotiate(reply)
	if err != nil {
		t.Fatalf("negotiation failed: %v", err)
	}
	out := n.RewriteResponse(reply, 0)
	wire, err := out.Pack()
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	var decoded Msg
	if err := decoded.Unpack(wire); err != nil {
		t.Fatalf("unpack failed: %v", err)
	}
	if decoded.Rcode != RcodeSuccess || len(decoded.Answer) != 1 {
		t.Errorf("round-trip changed the message: %v", decoded)
	}
	if decoded.IsEdns0() == nil || !decoded.IsEdns0().Do() {
		t.Error("round-trip lost negotiated EDNS capabilities")
	}

	// Rcode packing with an OPT record still round-trips through Unpack.
	bad := new(Msg)
	bad.SetReply(m)
	bad.SetEdns0(1232, false)
	bad.SetRcode(m, RcodeBadVers)
	badWire, err := bad.Pack()
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}
	var badDecoded Msg
	if err := badDecoded.Unpack(badWire); err != nil {
		t.Fatalf("unpack failed: %v", err)
	}
	if badDecoded.Rcode != RcodeBadVers {
		t.Errorf("extended rcode round-trip changed: got %d", badDecoded.Rcode)
	}
	n2, err := q.Negotiate(&badDecoded)
	if !errors.Is(err, ErrEDNSBadVers) {
		t.Errorf("negotiation of decoded BADVERS failed: %v", err)
	}
	if n2.Retry != EDNSRetryWithoutEDNS {
		t.Errorf("BADVERS retry = %v, want without EDNS", n2.Retry)
	}
}

// TestEDNSRewriteNilAndZeroValue guards the zero values used by callers that
// build a fallback reply before any negotiation has happened.
func TestEDNSRewriteNilAndZeroValue(t *testing.T) {
	var n EDNSNegotiation
	if got := n.RewriteResponse(nil, 0); got != nil {
		t.Error("rewriting a nil message must return nil")
	}

	reply := new(Msg)
	reply.SetQuestion("example.org.", TypeA)
	reply.Response = true
	reply.SetEdns0(4096, true)
	out := n.RewriteResponse(reply, 0)
	if out.IsEdns0() != nil {
		t.Error("zero-value negotiation must not keep EDNS capabilities")
	}
	if out.Len() > MinMsgSize {
		t.Errorf("zero-value negotiation must limit the reply to %d bytes, got %d", MinMsgSize, out.Len())
	}
	if reply.IsEdns0() == nil {
		t.Error("RewriteResponse modified its input")
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
