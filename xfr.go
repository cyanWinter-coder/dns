package dns

import (
	"crypto/tls"
	"fmt"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	RR    []RR  // The set of RRs in the answer section of the xfr reply message.
	Error error // If something went wrong, this contains the error.
}

// A Transfer defines parameters that are used during a zone transfer.
type Transfer struct {
	*Conn
	DialTimeout    time.Duration     // net.DialTimeout, defaults to 2 seconds
	ReadTimeout    time.Duration     // net.Conn.SetReadTimeout value for connections, defaults to 2 seconds
	WriteTimeout   time.Duration     // net.Conn.SetWriteTimeout value for connections, defaults to 2 seconds
	TsigProvider   TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	TsigSecret     map[string]string // Secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	tsigTimersOnly bool
	TLS            *tls.Config // TLS config. If Xfr over TLS will be attempted

	// Optional opening-SOA serial verification. Setting VerifySerial or
	// RequireSerialMatch forces exact equality with ExpectedSerial (or the
	// serial in q.Ns[0]). A non-zero ExpectedSerial also enables exact
	// verification. Without strict mode, ordinary IXFR serial progression is
	// accepted while an older server serial is rejected.
	ExpectedSerial     uint32
	ExpectedSOASerial  uint32
	VerifySerial       bool
	RequireSerialMatch bool

	// Optional atomic publication targets used by VerifiedIn/TransferZone.
	Store      *ZoneStore
	ZoneStore  *ZoneStore
	Holder     *AtomicZone
	AtomicZone *AtomicZone
}

func (t *Transfer) tsigProvider() TsigProvider {
	if t.TsigProvider != nil {
		return t.TsigProvider
	}
	if t.TsigSecret != nil {
		return tsigSecretProvider(t.TsigSecret)
	}
	return nil
}

// TODO: Think we need to away to stop the transfer

// In performs an incoming transfer with the server in a.
// If you would like to set the source IP, or some other attribute
// of a Dialer for a Transfer, you can do so by specifying the attributes
// in the Transfer.Conn:
//
//	d := net.Dialer{LocalAddr: transfer_source}
//	con, err := d.Dial("tcp", master)
//	dnscon := &dns.Conn{Conn:con}
//	transfer = &dns.Transfer{Conn: dnscon}
//	channel, err := transfer.In(message, master)
func (t *Transfer) In(q *Msg, a string) (env chan *Envelope, err error) {
	if q == nil || len(q.Question) == 0 {
		return nil, &Error{err: "no transfer question"}
	}
	switch q.Question[0].Qtype {
	case TypeAXFR, TypeIXFR:
	default:
		return nil, &Error{"unsupported question type"}
	}
	if q.Question[0].Qtype == TypeIXFR {
		if len(q.Ns) == 0 {
			return nil, newTransferError("request", ErrSoa, nil)
		}
		if _, ok := q.Ns[0].(*SOA); !ok {
			return nil, newTransferError("request", ErrSoa, nil)
		}
	}

	timeout := dnsTimeout
	if t.DialTimeout != 0 {
		timeout = t.DialTimeout
	}

	if t.Conn == nil {
		if t.TLS != nil {
			t.Conn, err = DialTimeoutWithTLS("tcp-tls", a, t.TLS, timeout)
		} else {
			t.Conn, err = DialTimeout("tcp", a, timeout)
		}
		if err != nil {
			return nil, err
		}
	}

	if err := t.WriteMsg(q); err != nil {
		return nil, err
	}

	env = make(chan *Envelope)
	switch q.Question[0].Qtype {
	case TypeAXFR:
		go t.inAxfr(q, env)
	case TypeIXFR:
		go t.inIxfr(q, env)
	}

	return env, nil
}

func (t *Transfer) expectedXfrSerial(q *Msg) (serial uint32, strict bool) {
	serial = t.ExpectedSerial
	if serial == 0 {
		serial = t.ExpectedSOASerial
	}
	explicitStrict := t.VerifySerial || t.RequireSerialMatch || t.ExpectedSerial != 0 || t.ExpectedSOASerial != 0
	strict = explicitStrict
	if len(q.Ns) > 0 {
		if soa, ok := q.Ns[0].(*SOA); ok {
			if serial == 0 {
				serial = soa.Serial
			}
			// AXFR requests do not normally contain an SOA. If one is
			// present, treat it as the required serial. For IXFR the request
			// SOA is the client's old serial and the opening response SOA is
			// normally newer, so exact equality is only enforced when the
			// caller explicitly requests strict verification.
			if q.Question[0].Qtype != TypeIXFR {
				strict = true
			}
		}
	}
	return serial, strict
}

func (t *Transfer) inAxfr(q *Msg, c chan *Envelope) {
	first := true
	expectedSerial, strictSerial := t.expectedXfrSerial(q)
	partial := &PartialTransfer{
		Zone:           q.Question[0].Name,
		Request:        q,
		ID:             q.Id,
		Qtype:          TypeAXFR,
		ExpectedSerial: expectedSerial,
	}
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on
		// the channel to assume that the connection is closed and no further operations are
		// pending when they resume.
		t.Close()
		close(c)
	}()
	timeout := dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}
	for {
		t.Conn.SetReadDeadline(time.Now().Add(timeout))
		in, err := t.ReadMsg()
		if err != nil {
			err = classifyReadError("axfr", err, partial, partial.EndMarker)
			c <- &Envelope{nil, err}
			return
		}
		if q.Id != in.Id {
			err := newTransferError("axfr", ErrId, partial)
			c <- &Envelope{in.Answer, err}
			return
		}
		if first {
			if in.Rcode != RcodeSuccess {
				rcodeErr := &Error{err: fmt.Sprintf(errXFR, in.Rcode)}
				err := newTransferError("axfr", rcodeErr, partial)
				c <- &Envelope{in.Answer, err}
				return
			}
			if !isSOAFirst(in) {
				err := newTransferError("axfr", ErrSoa, partial)
				c <- &Envelope{in.Answer, err}
				return
			}
			actualSerial := in.Answer[0].(*SOA).Serial
			partial.FirstSerial = actualSerial
			partial.CurrentSerial = actualSerial
			partial.Started = true
			if strictSerial && expectedSerial != actualSerial {
				err := newTransferError("axfr", ErrSerialMismatch, partial)
				c <- &Envelope{in.Answer, err}
				return
			}
			first = !first
			// only one answer that is SOA, receive more
			if len(in.Answer) == 1 {
				t.tsigTimersOnly = true
				partial.RRs = append(partial.RRs, in.Answer...)
				partial.syncAliases()
				c <- &Envelope{in.Answer, nil}
				continue
			}
		}

		partial.RRs = append(partial.RRs, in.Answer...)
		partial.syncAliases()
		if !first {
			t.tsigTimersOnly = true // Subsequent envelopes use this.
			if isSOALast(in) {
				partial.EndMarker = true
				partial.Complete = true
				c <- &Envelope{in.Answer, nil}
				return
			}
			c <- &Envelope{in.Answer, nil}
		}
	}
}

func (t *Transfer) inIxfr(q *Msg, c chan *Envelope) {
	var serial uint32 // The first serial seen is the current server serial
	axfr := false
	rrCount := 0
	currentSerial := uint32(0)
	removeMode := false
	qser := q.Ns[0].(*SOA).Serial
	expectedSerial, strictSerial := t.expectedXfrSerial(q)
	partial := &PartialTransfer{
		Zone:           q.Question[0].Name,
		Request:        q,
		ID:             q.Id,
		Qtype:          TypeIXFR,
		ExpectedSerial: expectedSerial,
		RequestSerial:  qser,
	}
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on
		// the channel to assume that the connection is closed and no further operations are
		// pending when they resume.
		t.Close()
		close(c)
	}()
	timeout := dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}

	fail := func(err error, answer []RR) {
		c <- &Envelope{RR: answer, Error: err}
	}

	for {
		t.SetReadDeadline(time.Now().Add(timeout))
		in, err := t.ReadMsg()
		if err != nil {
			err = classifyReadError("ixfr", err, partial, partial.EndMarker)
			fail(err, nil)
			return
		}
		partial.MessageCount++
		if q.Id != in.Id {
			fail(newTransferError("ixfr", ErrId, partial), in.Answer)
			return
		}
		if in.Rcode != RcodeSuccess {
			rcodeErr := &Error{err: fmt.Sprintf(errXFR, in.Rcode)}
			fail(newTransferError("ixfr", rcodeErr, partial), in.Answer)
			return
		}
		if rrCount == 0 {
			// Check if the returned answer is ok.
			if !isSOAFirst(in) {
				fail(newTransferError("ixfr", ErrSoa, partial), in.Answer)
				return
			}
			// This serial is important.
			serial = in.Answer[0].(*SOA).Serial
			partial.Started = true
			partial.FirstSerial = serial
			partial.CurrentSerial = serial
			// Explicit strict verification requires the opening serial to be
			// exactly the configured/requested serial.
			if strictSerial && expectedSerial != serial {
				fail(newTransferError("ixfr", ErrSerialMismatch, partial), in.Answer)
				return
			}
			// Preserve the historical IXFR behavior: a requested serial at or
			// beyond the server serial is accepted as an up-to-date/no-change
			// response. Strict serial verification above is the opt-in way to
			// reject an older server.
			if qser >= serial {
				partial.EndMarker = true
				partial.Complete = true
				partial.RRs = append(partial.RRs, in.Answer...)
				partial.syncAliases()
				c <- &Envelope{RR: in.Answer}
				return
			}
		}

		partial.RRs = append(partial.RRs, in.Answer...)
		partial.syncAliases()

		// Validate the RFC 1995 add/remove sequence. This is the incremental
		// transfer's message-level sequence check.
		t.tsigTimersOnly = true
		for _, rr := range in.Answer {
			rrCount++
			if v, ok := rr.(*SOA); ok {
				if rrCount == 1 {
					// Already checked above.
					continue
				} else if rrCount == 2 {
					if v.Serial < serial {
						// First difference sequence: removals come first.
						currentSerial = v.Serial
						removeMode = true
						continue
					} else if !axfr {
						// The second record is not older, so this may be AXFR
						// with empty middle content.
						axfr = true
					}
				}

				if axfr {
					if v.Serial != serial {
						fail(newTransferError("ixfr", ErrSoa, partial), in.Answer)
						return
					}
					partial.EndMarker = true
					partial.Complete = true
					c <- &Envelope{RR: in.Answer}
					return
				}

				// Differential sequence SOAs cannot be newer than the current
				// server serial or older than the sequence's starting serial.
				if v.Serial > serial || v.Serial < currentSerial {
					fail(newTransferError("ixfr", ErrSoa, partial), in.Answer)
					return
				}

				// Flip between remove and add sections.
				removeMode = !removeMode

				// Adjacent difference sequences share the same serial.
				if removeMode && currentSerial != v.Serial {
					fail(newTransferError("ixfr", ErrSoa, partial), in.Answer)
					return
				}

				currentSerial = v.Serial

				// The final IXFR SOA starts the remove section and carries the
				// current server serial.
				if removeMode && v.Serial == serial {
					partial.EndMarker = true
					partial.Complete = true
					c <- &Envelope{RR: in.Answer}
					return
				}
			} else if rrCount == 2 {
				// If the second RR is not an SOA this is full AXFR style.
				axfr = true
			}
		}
		c <- &Envelope{RR: in.Answer}
	}
}

// Out performs an outgoing transfer with the client connecting in w.
// Basic use pattern:
//
//	ch := make(chan *dns.Envelope)
//	tr := new(dns.Transfer)
//	var wg sync.WaitGroup
//	wg.Add(1)
//	go func() {
//		tr.Out(w, r, ch)
//		wg.Done()
//	}()
//	ch <- &dns.Envelope{RR: []dns.RR{soa, rr1, rr2, rr3, soa}}
//	close(ch)
//	wg.Wait() // wait until everything is written out
//	w.Close() // close connection
//
// The server is responsible for sending the correct sequence of RRs through the channel ch.
func (t *Transfer) Out(w ResponseWriter, q *Msg, ch chan *Envelope) error {
	for x := range ch {
		r := new(Msg)
		// Compress?
		r.SetReply(q)
		r.Authoritative = true
		// assume it fits TODO(miek): fix
		r.Answer = append(r.Answer, x.RR...)
		if tsig := q.IsTsig(); tsig != nil && w.TsigStatus() == nil {
			r.SetTsig(tsig.Hdr.Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
		}
		if err := w.WriteMsg(r); err != nil {
			return err
		}
		w.TsigTimersOnly(true)
	}
	return nil
}

// ReadMsg reads a message from the transfer connection t.
func (t *Transfer) ReadMsg() (*Msg, error) {
	m := new(Msg)
	p := make([]byte, MaxMsgSize)
	n, err := t.Read(p)
	if err != nil && n == 0 {
		return nil, err
	}
	p = p[:n]
	if err := m.Unpack(p); err != nil {
		return nil, err
	}

	if tp := t.tsigProvider(); tp != nil {
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerifyWithProvider(p, tp, t.tsigRequestMAC, t.tsigTimersOnly)
		if ts := m.IsTsig(); ts != nil {
			t.tsigRequestMAC = ts.MAC
		}
	}
	return m, err
}

// WriteMsg writes a message through the transfer connection t.
func (t *Transfer) WriteMsg(m *Msg) (err error) {
	var out []byte
	if ts, tp := m.IsTsig(), t.tsigProvider(); ts != nil && tp != nil {
		out, t.tsigRequestMAC, err = TsigGenerateWithProvider(m, tp, t.tsigRequestMAC, t.tsigTimersOnly)
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	_, err = t.Write(out)
	return err
}

func isSOAFirst(in *Msg) bool {
	return len(in.Answer) > 0 &&
		in.Answer[0].Header().Rrtype == TypeSOA
}

func isSOALast(in *Msg) bool {
	return len(in.Answer) > 0 &&
		in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
}

const errXFR = "bad xfr rcode: %d"
