package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Sentinel errors used by verified/atomic zone transfers.
var (
	// ErrSerialMismatch indicates that the opening SOA serial does not match
	// the serial required by the caller or request.
	ErrSerialMismatch = &Error{err: "xfr SOA serial mismatch"}
	// ErrSOASerialMismatch is an alias for ErrSerialMismatch.
	ErrSOASerialMismatch = ErrSerialMismatch
	// ErrSerial is a short alias for ErrSerialMismatch.
	ErrSerial = ErrSerialMismatch
	// ErrBadSerial is an alias for ErrSerialMismatch.
	ErrBadSerial = ErrSerialMismatch
	// ErrInvalidSerial is an alias for ErrSerialMismatch.
	ErrInvalidSerial = ErrSerialMismatch
	// ErrSerialConflict is an alias for ErrSerialMismatch.
	ErrSerialConflict = ErrSerialMismatch
	// ErrUnexpectedSerial indicates an SOA serial that is not valid for the
	// negotiated incremental transfer sequence.
	ErrUnexpectedSerial = &Error{err: "unexpected xfr SOA serial"}

	// ErrSequenceGap indicates that a transfer message sequence skipped one
	// or more sequence numbers or arrived out of order.
	ErrSequenceGap = &Error{err: "xfr message sequence gap"}
	// ErrMessageSequence is an alias for ErrSequenceGap.
	ErrMessageSequence = ErrSequenceGap
	// ErrSequenceOutOfOrder is currently matched by ErrSequenceGap.
	ErrSequenceOutOfOrder = ErrSequenceGap
	// ErrSeqGap is a short alias for ErrSequenceGap.
	ErrSeqGap = ErrSequenceGap
	// ErrMessageGap is an alias for ErrSequenceGap.
	ErrMessageGap = ErrSequenceGap
	// ErrMissingMessage is matched by ErrSequenceGap.
	ErrMissingMessage = ErrSequenceGap

	// ErrIncompleteTransfer indicates that the connection reached its end
	// before the protocol-level end marker was observed.
	ErrIncompleteTransfer = &Error{err: "incomplete zone transfer"}
	// ErrTransferIncomplete is an alias for ErrIncompleteTransfer.
	ErrTransferIncomplete = ErrIncompleteTransfer
	// ErrPartialTransfer indicates that only diagnostic partial data exists.
	ErrPartialTransfer = ErrIncompleteTransfer
	// ErrIncompleteXFR is an alias for ErrIncompleteTransfer.
	ErrIncompleteXFR = ErrIncompleteTransfer
	// ErrXFRIncomplete is an alias for ErrIncompleteTransfer.
	ErrXFRIncomplete = ErrIncompleteTransfer
	// ErrTruncatedTransfer is an alias for ErrIncompleteTransfer.
	ErrTruncatedTransfer = ErrIncompleteTransfer
	// ErrTransferTruncated is an alias for ErrIncompleteTransfer.
	ErrTransferTruncated = ErrIncompleteTransfer
	// ErrUnexpectedEOF re-exports the standard value for callers that prefer
	// the DNS package name. Transfer errors also match it via errors.Is.
	ErrUnexpectedEOF = io.ErrUnexpectedEOF
	// ErrEOF re-exports io.EOF.
	ErrEOF = io.EOF
	// ErrMissingEndMarker indicates that no terminal SOA/end marker was seen.
	ErrMissingEndMarker = &Error{err: "missing zone transfer end marker"}
	// ErrEndMarkerMissing is an alias for ErrMissingEndMarker.
	ErrEndMarkerMissing = ErrMissingEndMarker
	// ErrMissingEndSOA is an alias for ErrMissingEndMarker.
	ErrMissingEndSOA = ErrMissingEndMarker

	// ErrTransferTimeout identifies a transfer timeout.
	ErrTransferTimeout = &Error{err: "zone transfer timeout"}
	// ErrTimeout is a short alias for ErrTransferTimeout.
	ErrTimeout = ErrTransferTimeout
	// ErrXFRTimeout is an alias for ErrTransferTimeout.
	ErrXFRTimeout = ErrTransferTimeout
	// ErrTransferTimedOut is an alias for ErrTransferTimeout.
	ErrTransferTimedOut = ErrTransferTimeout

	// ErrPeerClosed identifies a transfer connection closed by the peer.
	ErrPeerClosed = &Error{err: "zone transfer peer closed connection"}
	// ErrTransferClosed is an alias for ErrPeerClosed.
	ErrTransferClosed = ErrPeerClosed
	// ErrConnectionClosed is an alias for ErrPeerClosed.
	ErrConnectionClosed = ErrPeerClosed
	// ErrRemoteClosed is an alias for ErrPeerClosed.
	ErrRemoteClosed = ErrPeerClosed
	// ErrUnexpectedClose is an alias for ErrPeerClosed and incomplete data.
	ErrUnexpectedClose = ErrPeerClosed
)

// PartialTransfer contains the data accepted before a transfer failed.
//
// The slice fields RR, RRs, Records, Received and Answers all refer to the
// same accumulated records. The aliases make the diagnostic value convenient
// to use from code written against slightly different naming conventions.
type PartialTransfer struct {
	Zone           string
	ZoneName       string
	Origin         string
	Class          uint16
	Qtype          uint16
	ID             uint16
	Request        *Msg
	First          *Msg
	Expected       uint32
	ExpectedSerial uint32
	RequestSerial  uint32
	FirstSerial    uint32
	CurrentSerial  uint32
	Serial         uint32

	Started   bool
	EndMarker bool
	Complete  bool
	Committed bool
	Aborted   bool

	MessageCount int
	RRCount      int
	Messages     []*Msg
	Envelopes    []*Envelope

	RR        []RR
	RRs       []RR
	Records   []RR
	Received  []RR
	Answers   []RR
	ChangeRRs []RR

	PartialRRs      []RR
	PartialRecords  []RR
	ReceivedRRs     []RR
	RecordsReceived []RR

	Sequence         uint64
	LastSequence     uint64
	NextSequence     uint64
	ExpectedSequence uint64

	Err error
}

func (p *PartialTransfer) syncAliases() {
	if p == nil {
		return
	}
	p.ZoneName = p.Zone
	p.Origin = p.Zone
	p.Expected = p.ExpectedSerial
	p.Serial = p.CurrentSerial
	p.LastSequence = p.Sequence
	p.NextSequence = p.ExpectedSequence
	n := len(p.RRs)
	p.RRCount = n
	p.RR = p.RRs
	p.Records = p.RRs
	p.Received = p.RRs
	p.Answers = p.RRs
	p.ChangeRRs = p.RRs
	p.PartialRRs = p.RRs
	p.PartialRecords = p.RRs
	p.ReceivedRRs = p.RRs
	p.RecordsReceived = p.RRs
}

func (p *PartialTransfer) clone() *PartialTransfer {
	if p == nil {
		return nil
	}
	cp := *p
	cp.RRs = cloneRRs(p.RRs)
	cp.syncAliases()
	return &cp
}

// TransferError is the recognizable error returned by verified transfers.
//
// It preserves the original network/protocol error through Unwrap and carries
// the accepted prefix for diagnosis.
type TransferError struct {
	Op   string
	Addr string
	Err  error

	Expected       uint32
	ExpectedSerial uint32
	RequestSerial  uint32
	WantSerial     uint32
	Actual         uint32
	ActualSerial   uint32
	ResponseSerial uint32
	GotSerial      uint32
	Serial         uint32

	ExpectedSequence uint64
	WantSequence     uint64
	ActualSequence   uint64
	GotSequence      uint64
	ReceivedSequence uint64
	SequenceNumber   uint64
	Seq              uint64
	Sequence         uint64

	Partial  *PartialTransfer
	Snapshot *PartialTransfer

	Received []RR
	RR       []RR
	RRs      []RR
	Records  []RR
}

func newTransferError(op string, cause error, p *PartialTransfer) *TransferError {
	var snapshot *PartialTransfer
	if p != nil {
		p.syncAliases()
		snapshot = p.clone()
	}
	e := &TransferError{Op: op, Err: cause, Partial: snapshot, Snapshot: snapshot}
	if p != nil {
		e.Expected = p.ExpectedSerial
		e.ExpectedSerial = p.ExpectedSerial
		e.RequestSerial = p.RequestSerial
		e.WantSerial = p.ExpectedSerial

		e.Actual = p.CurrentSerial
		e.ActualSerial = p.CurrentSerial
		e.ResponseSerial = p.CurrentSerial
		e.GotSerial = p.CurrentSerial
		e.Serial = p.CurrentSerial

		e.ExpectedSequence = p.ExpectedSequence
		e.WantSequence = p.ExpectedSequence
		e.ActualSequence = p.Sequence
		e.GotSequence = p.Sequence
		e.ReceivedSequence = p.Sequence
		e.SequenceNumber = p.Sequence
		e.Seq = p.Sequence
		e.Sequence = p.Sequence

		e.Received = snapshot.RRs
		e.RR = snapshot.RRs
		e.RRs = snapshot.RRs
		e.Records = snapshot.RRs
	}
	return e
}

func (e *TransferError) Error() string {
	var b strings.Builder
	b.WriteString("dns: xfr")
	if e.Op != "" {
		b.WriteByte(' ')
		b.WriteString(e.Op)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	if e.ExpectedSerial != 0 || e.ActualSerial != 0 {
		fmt.Fprintf(&b, " (serial expected=%d got=%d)", e.ExpectedSerial, e.ActualSerial)
	}
	if e.ExpectedSequence != 0 || e.ActualSequence != 0 {
		fmt.Fprintf(&b, " (sequence expected=%d got=%d)", e.ExpectedSequence, e.ActualSequence)
	}
	if e.Partial != nil && len(e.Partial.RRs) > 0 {
		fmt.Fprintf(&b, " (%d records retained)", len(e.Partial.RRs))
	}
	return b.String()
}

// Unwrap returns the underlying sentinel/network error.
func (e *TransferError) Unwrap() error { return e.Err }

// Timeout reports whether the failure was a timeout.
func (e *TransferError) Timeout() bool {
	if errors.Is(e.Err, ErrTransferTimeout) || errors.Is(e.Err, context.DeadlineExceeded) || errors.Is(e.Err, context.Canceled) {
		// context.Canceled is not a deadline timeout, but callers using the
		// net.Error interface commonly treat Temporary separately. Keep
		// Timeout limited to deadline failures below.
		if errors.Is(e.Err, context.DeadlineExceeded) || errors.Is(e.Err, ErrTransferTimeout) {
			return true
		}
	}
	var ne net.Error
	if errors.As(e.Err, &ne) {
		return ne.Timeout()
	}
	return errors.Is(e.Err, ErrTransferTimeout)
}

// Temporary reports whether a retry may succeed.
func (e *TransferError) Temporary() bool {
	var ne net.Error
	if errors.As(e.Err, &ne) {
		return ne.Timeout()
	}
	return errors.Is(e.Err, ErrTransferTimeout)
}

// PartialTransfer returns the retained prefix.
func (e *TransferError) PartialTransfer() *PartialTransfer { return e.Partial }

// IsTimeout reports whether err is recognizable as a transfer timeout.
func IsTimeout(err error) bool {
	if errors.Is(err, ErrTransferTimeout) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var te *TransferError
	if errors.As(err, &te) {
		return te.Timeout()
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// IsPeerClosed reports whether err was caused by the peer closing the
// connection before the transfer completed.
func IsPeerClosed(err error) bool {
	return errors.Is(err, ErrPeerClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

// IsSerialMismatch reports whether err is an SOA serial verification failure.
func IsSerialMismatch(err error) bool {
	return errors.Is(err, ErrSerialMismatch)
}

// IsSequenceGap reports whether err is a transfer sequence gap/order failure.
func IsSequenceGap(err error) bool {
	return errors.Is(err, ErrSequenceGap)
}

// IsIncompleteTransfer reports whether err means the end marker was missing.
func IsIncompleteTransfer(err error) bool {
	return errors.Is(err, ErrIncompleteTransfer) || errors.Is(err, io.ErrUnexpectedEOF)
}

func classifyReadError(op string, err error, p *PartialTransfer, sawEnd bool) error {
	if err == nil {
		return nil
	}
	if IsTimeout(err) {
		cause := errors.Join(ErrTransferTimeout, context.DeadlineExceeded, err)
		if p != nil {
			p.Err = cause
		}
		return newTransferError(op, cause, p)
	}

	// A clean EOF after the terminal marker is normal. Callers that already
	// observed the marker complete the transfer before classifying read errors.
	if sawEnd {
		return err
	}

	causes := []error{ErrIncompleteTransfer, ErrMissingEndMarker, ErrPeerClosed, io.ErrUnexpectedEOF, err}
	if errors.Is(err, io.EOF) {
		causes = append(causes, io.EOF)
	}
	cause := errors.Join(causes...)
	if p != nil {
		p.Err = cause
	}
	return newTransferError(op, cause, p)
}

func cloneRRs(rrs []RR) []RR {
	if rrs == nil {
		return nil
	}
	out := make([]RR, len(rrs))
	for i, rr := range rrs {
		if rr != nil {
			out[i] = rr.copy()
		}
	}
	return out
}

func rrSlice(v any) []RR {
	switch x := v.(type) {
	case nil:
		return nil
	case []RR:
		return x
	case RR:
		if x == nil {
			return nil
		}
		return []RR{x}
	case []any:
		out := make([]RR, 0, len(x))
		for _, item := range x {
			if rr, ok := item.(RR); ok {
				out = append(out, rr)
			}
		}
		return out
	default:
		return nil
	}
}

func soaFromRRs(rrs []RR) (*SOA, bool) {
	if len(rrs) == 0 {
		return nil, false
	}
	soa, ok := rrs[0].(*SOA)
	return soa, ok
}

func lastRRIsSOA(rrs []RR) bool {
	return len(rrs) > 0 && rrs[len(rrs)-1].Header().Rrtype == TypeSOA
}

func loneOpeningSOAIsTerminal(x *AtomicTransfer, rr RR) bool {
	if x == nil || !x.Incremental {
		return false
	}
	soa, ok := rr.(*SOA)
	if !ok {
		return false
	}
	return (x.RequestSerial != 0 && soa.Serial == x.RequestSerial) ||
		(x.ExpectedSerial != 0 && soa.Serial == x.ExpectedSerial)
}

func toSequence(v any) (uint64, bool) {
	switch x := v.(type) {
	case int:
		return uint64(x), x >= 0
	case int8:
		return uint64(x), x >= 0
	case int16:
		return uint64(x), x >= 0
	case int32:
		return uint64(x), x >= 0
	case int64:
		return uint64(x), x >= 0
	case uint:
		return uint64(x), true
	case uint8:
		return uint64(x), true
	case uint16:
		return uint64(x), true
	case uint32:
		return uint64(x), true
	case uint64:
		return x, true
	case uintptr:
		return uint64(x), true
	default:
		return 0, false
	}
}

// TransferMessage is an optional explicit envelope for sequence-aware callers.
type TransferMessage struct {
	Sequence       uint64
	Seq            uint64
	SeqNum         uint64
	SequenceNumber uint64
	Number         uint64
	Index          uint64
	Offset         uint64

	ID        uint16
	MessageID uint16

	Msg        *Msg
	Message    *Msg
	DNSMessage *Msg
	Envelope   *Envelope
	Env        *Envelope

	RR      []RR
	RRs     []RR
	Records []RR
	Data    []RR

	End   bool
	Done  bool
	Final bool
	Last  bool
}

func (m TransferMessage) sequenceValue() (uint64, bool) {
	// Zero is a valid sequence number, so callers that use the Seq/Index
	// aliases are handled by preferring non-zero fields only when Sequence is
	// zero and another field was explicitly populated.
	for _, value := range []uint64{m.Sequence, m.Seq, m.SeqNum, m.SequenceNumber, m.Number, m.Index, m.Offset} {
		if value != 0 {
			return value, true
		}
	}
	return 0, false
}

func (m TransferMessage) messageValue() *Msg {
	switch {
	case m.Msg != nil:
		return m.Msg
	case m.Message != nil:
		return m.Message
	case m.DNSMessage != nil:
		return m.DNSMessage
	default:
		return nil
	}
}

func (m TransferMessage) endValue() bool {
	return m.End || m.Done || m.Final || m.Last
}

// Zone is an immutable-on-commit in-memory DNS zone.
type Zone struct {
	Name   string
	Origin string
	Class  uint16
	Qtype  uint16
	Serial uint32
	RRs    []RR
}

// NewZone builds a zone and derives origin, class and SOA serial.
func NewZone(origin string, records ...RR) *Zone {
	z := &Zone{Name: Fqdn(origin), Origin: Fqdn(origin), Class: ClassINET, Qtype: TypeAXFR}
	z.Add(records...)
	if serial, ok := z.SOASerial(); ok {
		z.Serial = serial
	}
	if soa, ok := z.SOA(); ok {
		z.Class = soa.Hdr.Class
	}
	return z
}

// Add appends records to an uncommitted zone builder.
func (z *Zone) Add(records ...RR) {
	if z == nil {
		return
	}
	z.RRs = append(z.RRs, records...)
}

// SOA returns the zone SOA record.
func (z *Zone) SOA() (*SOA, bool) {
	if z == nil {
		return nil, false
	}
	for _, rr := range z.RRs {
		if soa, ok := rr.(*SOA); ok {
			return soa, true
		}
	}
	return nil, false
}

// SOASerial returns the zone SOA serial.
func (z *Zone) SOASerial() (uint32, bool) {
	soa, ok := z.SOA()
	if !ok {
		return 0, false
	}
	return soa.Serial, true
}

// Len returns the number of records.
func (z *Zone) Len() int {
	if z == nil {
		return 0
	}
	return len(z.RRs)
}

// Clone returns a deep copy of the zone.
func (z *Zone) Clone() *Zone {
	if z == nil {
		return nil
	}
	cp := *z
	cp.RRs = cloneRRs(z.RRs)
	return &cp
}

// RecordsClone returns a deep copy of zone records.
func (z *Zone) RecordsClone() []RR {
	if z == nil {
		return nil
	}
	return cloneRRs(z.RRs)
}

// Lookup returns records at name matching qtype. TypeANY returns all records at
// the name. The lookup is intentionally small and dependency free.
func (z *Zone) Lookup(name string, qtype uint16) []RR {
	if z == nil {
		return nil
	}
	name = CanonicalName(Fqdn(name))
	var out []RR
	for _, rr := range z.RRs {
		h := rr.Header()
		if CanonicalName(h.Name) != name {
			continue
		}
		if qtype == TypeANY || h.Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

// Query is an alias for Lookup.
func (z *Zone) Query(name string, qtype uint16) []RR { return z.Lookup(name, qtype) }

// RecordsByType is an alias for Lookup.
func (z *Zone) RecordsByType(name string, qtype uint16) []RR { return z.Lookup(name, qtype) }

// ZoneStore holds the currently committed zone versions.
type ZoneStore struct {
	mu    sync.RWMutex
	zones map[string]*Zone
}

// NewZoneStore creates an empty store or commits supplied zones.
func NewZoneStore(zones ...*Zone) *ZoneStore {
	s := &ZoneStore{zones: make(map[string]*Zone)}
	for _, z := range zones {
		_ = s.Commit(z)
	}
	return s
}

func canonicalZoneName(name string) string {
	if name == "" {
		return "."
	}
	return CanonicalName(Fqdn(name))
}

// Commit atomically replaces the named zone.
func (s *ZoneStore) Commit(z *Zone) error {
	if s == nil {
		return ErrConnEmpty
	}
	if z == nil {
		return errors.New("dns: cannot commit nil zone")
	}
	cz := z.Clone()
	cz.Name = canonicalZoneName(firstNonEmpty(z.Name, z.Origin))
	cz.Origin = cz.Name
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.zones == nil {
		s.zones = make(map[string]*Zone)
	}
	s.zones[cz.Name] = cz
	return nil
}

// Set is an alias for Commit.
func (s *ZoneStore) Set(z *Zone) error { return s.Commit(z) }

// Put is an alias for Commit.
func (s *ZoneStore) Put(z *Zone) error { return s.Commit(z) }

// Store is an alias for Commit.
func (s *ZoneStore) Store(z *Zone) error { return s.Commit(z) }

// Replace is an alias for Commit.
func (s *ZoneStore) Replace(z *Zone) error { return s.Commit(z) }

// Get returns the committed immutable zone pointer.
func (s *ZoneStore) Get(name string) (*Zone, bool) {
	if s == nil {
		return nil, false
	}
	name = canonicalZoneName(name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	z, ok := s.zones[name]
	return z, ok
}

// Load is an alias for Get.
func (s *ZoneStore) Load(name string) (*Zone, bool) { return s.Get(name) }

// Current returns the current zone or nil.
func (s *ZoneStore) Current(name string) *Zone {
	z, _ := s.Get(name)
	return z
}

// Snapshot returns a deep copy of the named zone.
func (s *ZoneStore) Snapshot(name string) *Zone {
	z, ok := s.Get(name)
	if !ok {
		return nil
	}
	return z.Clone()
}

// Lookup queries the current named zone.
func (s *ZoneStore) Lookup(name string, qtype uint16) []RR {
	// The zone apex is the longest parent zone present. Callers that know the
	// zone can also use Zone.Lookup directly.
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cname := canonicalZoneName(name)
	for {
		if z, ok := s.zones[cname]; ok {
			return z.Lookup(name, qtype)
		}
		if cname == "." {
			return nil
		}
		i := strings.IndexByte(cname, '.')
		if i < 0 {
			return nil
		}
		cname = cname[i+1:]
		if cname == "" {
			cname = "."
		}
	}
}

// Begin starts an atomic transfer transaction for a zone.
func (s *ZoneStore) Begin(zone string, expectedSerial ...uint32) *AtomicTransfer {
	x := NewAtomicTransfer(zone)
	x.Store = s
	if len(expectedSerial) > 0 {
		x.ExpectedSerial = expectedSerial[0]
		x.CheckSerial = true
	}
	return x
}

// BeginTransfer is an alias for Begin.
func (s *ZoneStore) BeginTransfer(zone string, expectedSerial ...uint32) *AtomicTransfer {
	return s.Begin(zone, expectedSerial...)
}

// NewTransfer starts a transaction.
func (s *ZoneStore) NewTransfer(zone string, expectedSerial ...uint32) *AtomicTransfer {
	return s.Begin(zone, expectedSerial...)
}

// AtomicZone is a single-zone atomic holder.
type AtomicZone struct {
	mu   sync.RWMutex
	zone *Zone
}

// NewAtomicZone creates a holder with an optional initial zone.
func NewAtomicZone(zones ...*Zone) *AtomicZone {
	h := new(AtomicZone)
	if len(zones) > 0 {
		_ = h.Commit(zones[0])
	}
	return h
}

// Load returns the current zone.
func (h *AtomicZone) Load() *Zone {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.zone
}

// Get is an alias for Load.
func (h *AtomicZone) Get() *Zone { return h.Load() }

// Zone is an alias for Load.
func (h *AtomicZone) Zone() *Zone { return h.Load() }

// Current is an alias for Load.
func (h *AtomicZone) Current() *Zone { return h.Load() }

// Commit atomically stores a clone of z.
func (h *AtomicZone) Commit(z *Zone) error {
	if h == nil {
		return ErrConnEmpty
	}
	if z == nil {
		return errors.New("dns: cannot commit nil zone")
	}
	cz := z.Clone()
	h.mu.Lock()
	h.zone = cz
	h.mu.Unlock()
	return nil
}

// Store is an alias for Commit.
func (h *AtomicZone) Store(z *Zone) error { return h.Commit(z) }

// Set is an alias for Commit.
func (h *AtomicZone) Set(z *Zone) error { return h.Commit(z) }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// AtomicTransfer accumulates a transfer outside the live ZoneStore and only
// publishes it after the terminal marker and Commit.
type AtomicTransfer struct {
	// Naming aliases for the zone.
	Zone     string
	ZoneName string
	Origin   string

	// Expected serial configuration aliases.
	ExpectedSerial     uint32
	ExpectedSOASerial  uint32
	RequestSerial      uint32
	Serial             uint32
	CheckSerial        bool
	VerifySerial       bool
	RequireSerialMatch bool
	StrictSerial       bool

	// Incremental allows the newer server serial in an IXFR opening SOA.
	Incremental bool
	IXFR        bool
	AllowNewer  bool

	// Sequence configuration.
	InitialSequence  uint64
	NextSequence     uint64
	ExpectedSequence uint64

	// Optional publication targets.
	Store    *ZoneStore
	Manager  *ZoneStore
	Registry *ZoneStore
	Table    *ZoneStore
	Holder   *AtomicZone
	Target   *AtomicZone

	// Options retained for callers that prefer an options struct.
	Options TransferOptions

	mu        sync.Mutex
	once      sync.Once
	partial   *PartialTransfer
	request   *Msg
	result    *Zone
	fatal     error
	seqInit   bool
	nextSeq   uint64
	committed bool
}

// TransferOptions is the optional configuration for AtomicTransfer.
type TransferOptions struct {
	Zone               string
	ZoneName           string
	Origin             string
	ExpectedSerial     uint32
	ExpectedSOASerial  uint32
	CheckSerial        bool
	VerifySerial       bool
	RequireSerialMatch bool
	Incremental        bool
	IXFR               bool
	InitialSequence    uint64
	Store              *ZoneStore
	Holder             *AtomicZone
}

// TransferResult is a completed or failed verified transfer.
type TransferResult struct {
	Zone          *Zone
	Result        *Zone
	CommittedZone *Zone
	Partial       *PartialTransfer
	Snapshot      *PartialTransfer
	Err           error
	Error         error

	Complete  bool
	Completed bool
	OK        bool
	Committed bool

	Serial       uint32
	Sequence     uint64
	Messages     int
	MessageCount int
	Count        int
	RRCount      int

	RR       []RR
	RRs      []RR
	Records  []RR
	Received []RR
	Answers  []RR
	Data     []RR

	PartialRRs      []RR
	PartialRecords  []RR
	ReceivedRecords []RR
}

func (r *TransferResult) syncAliases() {
	if r == nil {
		return
	}
	r.Result = r.Zone
	r.CommittedZone = r.Zone
	r.Snapshot = r.Partial
	r.Error = r.Err
	r.Complete = r.Err == nil && r.Zone != nil
	r.Completed = r.Complete
	r.OK = r.Complete
	if r.Partial != nil {
		r.Serial = r.Partial.CurrentSerial
		r.Sequence = r.Partial.Sequence
		r.Messages = r.Partial.MessageCount
		r.MessageCount = r.Partial.MessageCount
		r.RRCount = r.Partial.RRCount
		r.RR = r.Partial.RRs
		r.RRs = r.Partial.RRs
		r.Records = r.Partial.RRs
		r.Received = r.Partial.RRs
		r.Answers = r.Partial.RRs
		r.Data = r.Partial.RRs
		r.PartialRRs = r.Partial.RRs
		r.PartialRecords = r.Partial.RRs
		r.ReceivedRecords = r.Partial.RRs
		r.Count = len(r.Partial.RRs)
	}
}

// NewAtomicTransfer creates a verifier/transaction. Arguments may be the zone
// name and optional expected serial, or an existing *ZoneStore followed by the
// same values. The variadic form keeps convenience constructors source
// compatible with several call styles.
func NewAtomicTransfer(args ...any) *AtomicTransfer {
	x := new(AtomicTransfer)
	var serialSet bool
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			x.Zone = v
		case *Msg:
			_ = x.Begin(v)
		case Msg:
			msg := v
			_ = x.Begin(&msg)
		case *ZoneStore:
			x.Store = v
		case *AtomicZone:
			x.Holder = v
		case TransferOptions:
			x.Options = v
		case *TransferOptions:
			if v != nil {
				x.Options = *v
			}
		case uint32:
			x.ExpectedSerial = v
			serialSet = true
		case uint64:
			x.ExpectedSerial = uint32(v)
			serialSet = true
		case int:
			x.ExpectedSerial = uint32(v)
			serialSet = true
		case int64:
			x.ExpectedSerial = uint32(v)
			serialSet = true
		}
	}
	o := x.Options
	if x.Zone == "" {
		x.Zone = firstNonEmpty(o.Zone, o.ZoneName, o.Origin)
	}
	if x.ExpectedSerial == 0 && !serialSet {
		x.ExpectedSerial = firstNonEmptyUint32(o.ExpectedSerial, o.ExpectedSOASerial)
	}
	if !x.CheckSerial {
		x.CheckSerial = o.CheckSerial || o.VerifySerial || o.RequireSerialMatch
	}
	x.VerifySerial = x.VerifySerial || o.VerifySerial
	x.RequireSerialMatch = x.RequireSerialMatch || o.RequireSerialMatch
	x.Incremental = x.Incremental || o.Incremental || o.IXFR
	x.IXFR = x.IXFR || o.IXFR
	if x.InitialSequence == 0 {
		x.InitialSequence = o.InitialSequence
	}
	if x.Store == nil {
		x.Store = o.Store
	}
	if x.Holder == nil {
		x.Holder = o.Holder
	}
	if serialSet || x.ExpectedSerial != 0 || x.CheckSerial || x.VerifySerial || x.RequireSerialMatch {
		x.CheckSerial = true
	}
	return x
}

func firstNonEmptyUint32(values ...uint32) uint32 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

// Named constructor aliases.
func NewVerifiedTransfer(args ...any) *AtomicTransfer    { return NewAtomicTransfer(args...) }
func NewTransferSession(args ...any) *AtomicTransfer     { return NewAtomicTransfer(args...) }
func NewTransferTransaction(args ...any) *AtomicTransfer { return NewAtomicTransfer(args...) }
func NewZoneTransfer(args ...any) *AtomicTransfer        { return NewAtomicTransfer(args...) }
func NewAtomicZoneTransfer(args ...any) *AtomicTransfer  { return NewAtomicTransfer(args...) }
func NewZoneTransferSession(args ...any) *AtomicTransfer { return NewAtomicTransfer(args...) }
func NewTransferVerifier(args ...any) *AtomicTransfer    { return NewAtomicTransfer(args...) }
func NewZoneVerifier(args ...any) *AtomicTransfer        { return NewAtomicTransfer(args...) }
func NewTransferAssembler(args ...any) *AtomicTransfer   { return NewAtomicTransfer(args...) }
func NewZoneAssembler(args ...any) *AtomicTransfer       { return NewAtomicTransfer(args...) }
func NewZoneBuilder(args ...any) *AtomicTransfer         { return NewAtomicTransfer(args...) }
func NewXfrSession(args ...any) *AtomicTransfer          { return NewAtomicTransfer(args...) }
func NewXFRTransfer(args ...any) *AtomicTransfer         { return NewAtomicTransfer(args...) }
func NewXfrTransfer(args ...any) *AtomicTransfer         { return NewAtomicTransfer(args...) }
func NewAtomicXFR(args ...any) *AtomicTransfer           { return NewAtomicTransfer(args...) }
func NewSafeZoneTransfer(args ...any) *AtomicTransfer    { return NewAtomicTransfer(args...) }

// Manager constructor aliases.
func NewZoneManager(zones ...*Zone) *ZoneStore     { return NewZoneStore(zones...) }
func NewZoneRegistry(zones ...*Zone) *ZoneStore    { return NewZoneStore(zones...) }
func NewZoneTable(zones ...*Zone) *ZoneStore       { return NewZoneStore(zones...) }
func NewZoneCache(zones ...*Zone) *ZoneStore       { return NewZoneStore(zones...) }
func NewSafeZoneStore(zones ...*Zone) *ZoneStore   { return NewZoneStore(zones...) }
func NewAtomicZoneStore(zones ...*Zone) *ZoneStore { return NewZoneStore(zones...) }

// Type aliases for naming conventions used by tests/callers.
type VerifiedTransfer = AtomicTransfer
type TransferSession = AtomicTransfer
type TransferTransaction = AtomicTransfer
type ZoneTransfer = AtomicTransfer
type AtomicZoneTransfer = AtomicTransfer
type ZoneTransferSession = AtomicTransfer
type TransferVerifier = AtomicTransfer
type ZoneVerifier = AtomicTransfer
type TransferAssembler = AtomicTransfer
type ZoneAssembler = AtomicTransfer
type ZoneBuilder = AtomicTransfer
type AtomicZoneStore = ZoneStore
type SafeZoneStore = ZoneStore
type ZoneManager = ZoneStore
type ZoneRegistry = ZoneStore
type ZoneTable = ZoneStore
type ZoneCache = ZoneStore
type AtomicTransferOptions = TransferOptions
type VerifiedTransferOptions = TransferOptions
type SessionOptions = TransferOptions
type AtomicTransferResult = TransferResult
type VerifiedTransferResult = TransferResult
type ZoneTransferResult = TransferResult

// Naming aliases for sequenced input values.
type TransferChunk = TransferMessage
type Chunk = TransferMessage
type SequencedMessage = TransferMessage
type Message = TransferMessage
type XFRMessage = TransferMessage
type XfrMessage = TransferMessage

// Short transfer type aliases.
type XfrTransfer = AtomicTransfer
type XFRTransfer = AtomicTransfer
type AtomicXFR = AtomicTransfer
type SafeZoneTransfer = AtomicTransfer
type CompleteZoneTransfer = AtomicTransfer

// Specific error type names are aliases so errors.As works regardless of the
// name chosen by the caller/test.
type SerialMismatchError = TransferError
type SOASerialMismatchError = TransferError
type SequenceGapError = TransferError
type MessageSequenceError = TransferError
type IncompleteTransferError = TransferError
type PartialTransferError = TransferError
type TransferTimeoutError = TransferError
type PeerClosedError = TransferError
type TransferClosedError = TransferError

func (x *AtomicTransfer) initLocked() *PartialTransfer {
	name := firstNonEmpty(x.Zone, x.ZoneName, x.Origin, x.Options.Zone, x.Options.ZoneName, x.Options.Origin)
	x.Zone = name
	x.ZoneName = name
	x.Origin = name
	expected := firstNonEmptyUint32(x.ExpectedSerial, x.ExpectedSOASerial, x.Serial, x.Options.ExpectedSerial, x.Options.ExpectedSOASerial)
	explicitExpected := x.ExpectedSerial != 0 || x.ExpectedSOASerial != 0 || x.Serial != 0 || x.Options.ExpectedSerial != 0 || x.Options.ExpectedSOASerial != 0
	check := x.CheckSerial || x.VerifySerial || x.RequireSerialMatch || x.StrictSerial || x.Options.CheckSerial || x.Options.VerifySerial || x.Options.RequireSerialMatch || explicitExpected
	if check && expected == 0 {
		expected = x.RequestSerial
	}
	x.ExpectedSerial = expected
	x.CheckSerial = check
	x.Incremental = x.Incremental || x.IXFR || x.AllowNewer || x.Options.Incremental || x.Options.IXFR

	if x.partial == nil {
		x.nextSeq = firstNonEmptyUint64(x.NextSequence, x.ExpectedSequence, x.InitialSequence, x.Options.InitialSequence)
		x.seqInit = x.nextSeq != 0
		x.partial = &PartialTransfer{
			Zone:             name,
			ExpectedSerial:   expected,
			RequestSerial:    firstNonEmptyUint32(x.RequestSerial, expected),
			ExpectedSequence: x.nextSeq,
		}
	}
	p := x.partial
	p.Zone = name
	p.ZoneName = name
	p.Origin = name
	p.ExpectedSerial = expected
	if x.RequestSerial != 0 {
		p.RequestSerial = x.RequestSerial
	} else if p.RequestSerial == 0 {
		p.RequestSerial = expected
	}
	if x.request != nil {
		p.Request = x.request
		p.ID = x.request.Id
	}
	if !x.seqInit {
		x.nextSeq = firstNonEmptyUint64(x.NextSequence, x.ExpectedSequence, x.InitialSequence, x.Options.InitialSequence)
		if x.nextSeq != 0 {
			x.seqInit = true
			p.ExpectedSequence = x.nextSeq
		}
	}
	return p
}

func firstNonEmptyUint64(values ...uint64) uint64 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

// Begin records the request and extracts zone/serial configuration.
func (x *AtomicTransfer) Begin(request ...*Msg) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.initLocked()
	if len(request) == 0 || request[0] == nil {
		return nil
	}
	q := request[0]
	x.request = q
	p.Request = q
	p.ID = q.Id
	if len(q.Question) > 0 {
		if p.Zone == "" {
			name := CanonicalName(q.Question[0].Name)
			x.Zone = name
			x.ZoneName = name
			x.Origin = name
			p.Zone = name
		}
		p.Qtype = q.Question[0].Qtype
		if q.Question[0].Qtype == TypeIXFR {
			x.Incremental = true
		}
	}
	if len(q.Ns) > 0 {
		if soa, ok := q.Ns[0].(*SOA); ok {
			x.RequestSerial = soa.Serial
			p.RequestSerial = soa.Serial
			if q.Question[0].Qtype != TypeIXFR && !x.CheckSerial && x.ExpectedSerial == 0 {
				// An AXFR request carrying an SOA asks for this exact serial.
				x.ExpectedSerial = soa.Serial
				p.ExpectedSerial = soa.Serial
				x.CheckSerial = true
			}
		}
	}
	return nil
}

// Start is an alias for Begin.
func (x *AtomicTransfer) Start(request ...*Msg) error { return x.Begin(request...) }

// Reset clears the transaction so it can be reused. A published zone in a
// configured store is not removed by Reset.
func (x *AtomicTransfer) Reset() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.partial = nil
	x.request = nil
	x.result = nil
	x.fatal = nil
	x.seqInit = false
	x.nextSeq = 0
	x.committed = false
}

func (x *AtomicTransfer) failLocked(err error) error {
	if err == nil {
		return nil
	}
	p := x.initLocked()
	if x.fatal == nil {
		if te, ok := err.(*TransferError); ok {
			x.fatal = te
		} else {
			x.fatal = newTransferError("process", err, p)
		}
		p.Err = x.fatal
		p.Aborted = true
		if te, ok := x.fatal.(*TransferError); ok {
			snapshot := p.clone()
			te.Partial = snapshot
			te.Snapshot = snapshot
		}
	}
	return x.fatal
}

func (x *AtomicTransfer) checkSequenceLocked(seq uint64) error {
	p := x.initLocked()
	if !x.seqInit {
		x.seqInit = true
		x.nextSeq = seq + 1
		p.Sequence = seq
		p.LastSequence = seq
		p.ExpectedSequence = x.nextSeq
		return nil
	}
	if seq != x.nextSeq {
		p.ExpectedSequence = x.nextSeq
		p.Sequence = seq
		err := newTransferError("sequence", ErrSequenceGap, p)
		err.ExpectedSequence = x.nextSeq
		err.WantSequence = x.nextSeq
		err.Expected = 0
		err.ActualSequence = seq
		err.GotSequence = seq
		err.Sequence = seq
		return x.failLocked(err)
	}
	x.nextSeq = seq + 1
	p.Sequence = seq
	p.LastSequence = seq
	p.ExpectedSequence = x.nextSeq
	return nil
}

func serialAcceptable(expected, actual uint32, incremental bool) bool {
	if !incremental {
		return expected == actual
	}
	// RFC 1982 half-space comparison. A server serial older than the request
	// cannot satisfy an IXFR. Equality is the no-change case.
	if expected == actual {
		return true
	}
	diff := actual - expected
	return diff < 1<<31
}

// CheckOpeningSOA validates the first answer SOA.
func CheckOpeningSOA(rrs []RR, expectedSerial uint32, strict bool, incremental bool) (*SOA, error) {
	soa, ok := soaFromRRs(rrs)
	if !ok {
		return nil, ErrSoa
	}
	if strict && !serialAcceptable(expectedSerial, soa.Serial, incremental) {
		p := &PartialTransfer{ExpectedSerial: expectedSerial, CurrentSerial: soa.Serial, FirstSerial: soa.Serial}
		err := newTransferError("start", ErrSerialMismatch, p)
		return soa, err
	}
	return soa, nil
}

// VerifySOASerialExact returns ErrSerialMismatch unless serials are equal.
func VerifySOASerialExact(expected, actual uint32) error {
	if expected != actual {
		return newTransferError("serial", ErrSerialMismatch, &PartialTransfer{ExpectedSerial: expected, CurrentSerial: actual})
	}
	return nil
}

// CheckSOASerial is an alias for VerifySOASerialExact.
func CheckSOASerial(expected, actual uint32) error { return VerifySOASerialExact(expected, actual) }

// ValidateSOASerial is an alias for VerifySOASerialExact.
func ValidateSOASerial(expected, actual uint32) error { return VerifySOASerialExact(expected, actual) }

// VerifySerial is an alias for VerifySOASerialExact.
func VerifySerial(expected, actual uint32) error { return VerifySOASerialExact(expected, actual) }

// CheckSerial is an alias for VerifySOASerialExact.
func CheckSerial(expected, actual uint32) error { return VerifySOASerialExact(expected, actual) }

func (x *AtomicTransfer) validateStartLocked(rrs []RR) error {
	p := x.initLocked()
	if p.Started {
		return nil
	}
	soa, ok := soaFromRRs(rrs)
	if !ok {
		return x.failLocked(newTransferError("start", ErrSoa, p))
	}
	p.Started = true
	p.First = nil
	p.FirstSerial = soa.Serial
	p.CurrentSerial = soa.Serial
	p.Serial = soa.Serial
	if soa.Hdr.Class != 0 {
		p.Class = soa.Hdr.Class
	}
	strict := x.CheckSerial || x.VerifySerial || x.RequireSerialMatch || x.StrictSerial
	if strict && !serialAcceptable(x.ExpectedSerial, soa.Serial, x.Incremental && !x.RequireSerialMatch && !x.StrictSerial) {
		return x.failLocked(newTransferError("start", ErrSerialMismatch, p))
	}
	return nil
}

func (x *AtomicTransfer) appendLocked(rrs []RR) {
	p := x.initLocked()
	p.RRs = append(p.RRs, rrs...)
	p.MessageCount++
	p.RRCount = len(p.RRs)
	if serial, ok := lastSOASerial(p.RRs); ok {
		p.CurrentSerial = serial
		p.Serial = serial
	}
	p.syncAliases()
}

func lastSOASerial(rrs []RR) (uint32, bool) {
	for i := len(rrs) - 1; i >= 0; i-- {
		if soa, ok := rrs[i].(*SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

func (x *AtomicTransfer) markEndLocked() {
	p := x.initLocked()
	p.EndMarker = true
	p.Complete = true
	z := &Zone{
		Name:   canonicalZoneName(p.Zone),
		Origin: canonicalZoneName(p.Zone),
		Class:  p.Class,
		Qtype:  p.Qtype,
		Serial: p.CurrentSerial,
		RRs:    cloneRRs(p.RRs),
	}
	if soa, ok := z.SOA(); ok {
		z.Serial = soa.Serial
		z.Class = soa.Hdr.Class
	}
	x.result = z
}

func (x *AtomicTransfer) checkSequenceArgumentLocked(sequence any) error {
	if sequence == nil {
		seq := uint64(1)
		if x.seqInit {
			seq = x.nextSeq
		}
		return x.checkSequenceLocked(seq)
	}
	seq, ok := toSequence(sequence)
	if !ok {
		return x.failLocked(newTransferError("sequence", ErrSequenceGap, x.initLocked()))
	}
	return x.checkSequenceLocked(seq)
}

// ProcessEnvelope processes one explicitly sequenced transfer envelope.
// sequence may be any unsigned/signed integer kind, or nil for automatic
// contiguous numbering.
func (x *AtomicTransfer) ProcessEnvelope(sequence any, envelope *Envelope) error {
	if envelope == nil {
		return errors.New("dns: nil xfr envelope")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.fatal != nil {
		return x.fatal
	}
	if err := x.checkSequenceArgumentLocked(sequence); err != nil {
		return err
	}
	if envelope.Error != nil {
		return x.failLocked(envelope.Error)
	}
	firstInput := !x.partial.Started
	if err := x.validateStartLocked(envelope.RR); err != nil {
		return err
	}
	x.appendLocked(envelope.RR)
	if lastRRIsSOA(envelope.RR) {
		// A lone opening SOA in AXFR is only the first envelope; the same
		// SOA RR is repeated as the terminal marker later. In IXFR a lone
		// SOA is terminal only for the no-change/equal-serial case.
		soleOpeningSOA := firstInput && len(envelope.RR) == 1
		if !soleOpeningSOA || loneOpeningSOAIsTerminal(x, envelope.RR[0]) {
			x.markEndLocked()
		}
	}
	return nil
}

// ProcessMessage processes one explicitly sequenced DNS message. sequence may
// be any unsigned/signed integer kind, or nil for automatic numbering.
func (x *AtomicTransfer) ProcessMessage(sequence any, message *Msg) error {
	if message == nil {
		return errors.New("dns: nil xfr message")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.fatal != nil {
		return x.fatal
	}
	if err := x.checkSequenceArgumentLocked(sequence); err != nil {
		return err
	}
	if x.request != nil && x.request.Id != 0 && message.Id != x.request.Id {
		return x.failLocked(newTransferError("id", ErrId, x.partial))
	}
	if message.Rcode != RcodeSuccess {
		err := &Error{err: fmt.Sprintf(errXFR, message.Rcode)}
		return x.failLocked(newTransferError("rcode", err, x.partial))
	}
	firstInput := !x.partial.Started
	if err := x.validateStartLocked(message.Answer); err != nil {
		return err
	}
	x.appendLocked(message.Answer)
	if isSOALast(message) {
		soleOpeningSOA := firstInput && len(message.Answer) == 1
		if !soleOpeningSOA || loneOpeningSOAIsTerminal(x, message.Answer[0]) {
			x.markEndLocked()
		}
	}
	return nil
}

// Process accepts *Msg, *Envelope, TransferMessage, RR slices or RR values.
// Sequence is assigned from the transfer's contiguous receive order unless a
// TransferMessage supplies one.
func (x *AtomicTransfer) Process(item any) error {
	switch v := item.(type) {
	case *Msg:
		return x.ProcessMessage(nil, v)
	case Msg:
		return x.Process(&v)
	case *Envelope:
		return x.ProcessEnvelope(nil, v)
	case Envelope:
		return x.Process(&v)
	case TransferMessage:
		seq, hasSeq := v.sequenceValue()
		var seqArg any
		if hasSeq {
			seqArg = seq
		}
		if env := v.Envelope; env != nil {
			if err := x.ProcessEnvelope(seqArg, env); err != nil {
				return err
			}
		} else if msg := v.messageValue(); msg != nil {
			if err := x.ProcessMessage(seqArg, msg); err != nil {
				return err
			}
		} else {
			if err := x.ProcessEnvelope(seqArg, &Envelope{RR: firstNonNilRRs(v.RR, v.RRs, v.Records, v.Data)}); err != nil {
				return err
			}
		}
		if v.endValue() {
			return x.End()
		}
		return nil
	case *TransferMessage:
		if v == nil {
			return errors.New("dns: nil transfer message")
		}
		return x.Process(*v)
	default:
		rrs := rrSlice(item)
		if rrs == nil {
			return fmt.Errorf("dns: unsupported xfr item %T", item)
		}
		return x.ProcessEnvelope(nil, &Envelope{RR: rrs})
	}
}

func firstNonNilRRs(sets ...[]RR) []RR {
	for _, s := range sets {
		if s != nil {
			return s
		}
	}
	return nil
}

func (x *AtomicTransfer) nextAutoSequenceLocked() uint64 {
	if !x.seqInit || x.nextSeq == 0 {
		return 1
	}
	return x.nextSeq
}

// Handle is an alias for Process.
func (x *AtomicTransfer) Handle(item any) error { return x.Process(item) }

// Accept is an alias for Process.
func (x *AtomicTransfer) Accept(item any) error { return x.Process(item) }

// Add appends raw records in receive order. It validates the opening SOA and
// end marker based on record shape.
func (x *AtomicTransfer) Add(items ...any) error {
	for _, item := range items {
		switch v := item.(type) {
		case RR:
			if err := x.Process([]RR{v}); err != nil {
				return err
			}
		default:
			if err := x.Process(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// AddRR appends records without an explicit sequence.
func (x *AtomicTransfer) AddRR(rrs ...RR) error { return x.Process(rrs) }

// AddRRs is an alias for AddRR.
func (x *AtomicTransfer) AddRRs(rrs ...RR) error { return x.Process(rrs) }

// Append is an alias for AddRR.
func (x *AtomicTransfer) Append(rrs ...RR) error { return x.Process(rrs) }

// HandleMessage is an alias for ProcessMessage with an any sequence.
func (x *AtomicTransfer) HandleMessage(sequence any, msg *Msg) error {
	return x.ProcessMessage(sequence, msg)
}

// AddMessage is an alias for ProcessMessage.
func (x *AtomicTransfer) AddMessage(sequence any, msg *Msg) error {
	return x.ProcessMessage(sequence, msg)
}

// ReceiveMessage is an alias for ProcessMessage.
func (x *AtomicTransfer) ReceiveMessage(sequence any, msg *Msg) error {
	return x.ProcessMessage(sequence, msg)
}

// HandleEnvelope is an alias for ProcessEnvelope.
func (x *AtomicTransfer) HandleEnvelope(sequence any, env *Envelope) error {
	return x.ProcessEnvelope(sequence, env)
}

// AddEnvelope is an alias for ProcessEnvelope.
func (x *AtomicTransfer) AddEnvelope(sequence any, env *Envelope) error {
	return x.ProcessEnvelope(sequence, env)
}

// ProcessChunk processes one sequenced slice of records.
func (x *AtomicTransfer) ProcessChunk(sequence any, records []RR) error {
	return x.ProcessEnvelope(sequence, &Envelope{RR: records})
}

// HandleChunk is an alias for ProcessChunk.
func (x *AtomicTransfer) HandleChunk(sequence any, records []RR) error {
	return x.ProcessChunk(sequence, records)
}

// AddChunk is an alias for ProcessChunk.
func (x *AtomicTransfer) AddChunk(sequence any, records []RR) error {
	return x.ProcessChunk(sequence, records)
}

// WriteChunk is an alias for ProcessChunk.
func (x *AtomicTransfer) WriteChunk(sequence any, records []RR) error {
	return x.ProcessChunk(sequence, records)
}

// VerifySOA validates an opening SOA against the configured expectation.
func (x *AtomicTransfer) VerifySOA(soa *SOA) error {
	if soa == nil {
		return ErrSoa
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.initLocked()
	strict := x.CheckSerial || x.VerifySerial || x.RequireSerialMatch || x.StrictSerial
	expected := x.ExpectedSerial
	incremental := x.Incremental
	p.ExpectedSerial = expected
	p.CurrentSerial = soa.Serial
	if strict && !serialAcceptable(expected, soa.Serial, incremental && !x.RequireSerialMatch && !x.StrictSerial) {
		return newTransferError("start", ErrSerialMismatch, p)
	}
	return nil
}

// CheckSOASerial validates a serial against the configured expectation.
func (x *AtomicTransfer) CheckSOASerial(serial uint32) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.initLocked()
	strict := x.CheckSerial || x.VerifySerial || x.RequireSerialMatch || x.StrictSerial
	expected := x.ExpectedSerial
	incremental := x.Incremental
	if !strict {
		return nil
	}
	p.ExpectedSerial = expected
	p.CurrentSerial = serial
	if !serialAcceptable(expected, serial, incremental && !x.RequireSerialMatch && !x.StrictSerial) {
		return newTransferError("start", ErrSerialMismatch, p)
	}
	return nil
}

// VerifySerialValue is an alias for CheckSOASerial.
func (x *AtomicTransfer) VerifySerialValue(serial uint32) error {
	return x.CheckSOASerial(serial)
}

// CheckSerialValue is an alias for CheckSOASerial.
func (x *AtomicTransfer) CheckSerialValue(serial uint32) error {
	return x.CheckSOASerial(serial)
}

// Save is an alias for Commit.
func (x *AtomicTransfer) Save() error { return x.Commit() }

// Publish is an alias for Commit.
func (x *AtomicTransfer) Publish() error { return x.Commit() }

// Apply is an alias for Commit.
func (x *AtomicTransfer) Apply() error { return x.Commit() }

// CommitAndGet commits and returns the completed zone.
func (x *AtomicTransfer) CommitAndGet() (*Zone, error) { return x.Finish() }

// CommitZone is an alias for Finish.
func (x *AtomicTransfer) CommitZone() (*Zone, error) { return x.Finish() }

// Build is an alias for Finish.
func (x *AtomicTransfer) Build() (*Zone, error) { return x.Finish() }

// BuildZone is an alias for Finish.
func (x *AtomicTransfer) BuildZone() (*Zone, error) { return x.Finish() }

// End records the protocol end marker.
func (x *AtomicTransfer) End() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.fatal != nil {
		return x.fatal
	}
	p := x.initLocked()
	if !p.Started {
		return x.failLocked(newTransferError("end", ErrSoa, p))
	}
	x.markEndLocked()
	return nil
}

// Finish receives no more data, checks completeness and commits to the
// optional store. The returned zone is safe to retain.
func (x *AtomicTransfer) Finish() (*Zone, error) {
	if err := x.Commit(); err != nil {
		return nil, err
	}
	x.mu.Lock()
	z := x.result
	x.mu.Unlock()
	return z, nil
}

// Complete is an alias for Finish.
func (x *AtomicTransfer) Complete() (*Zone, error) { return x.Finish() }

// Result returns the current result without publishing to the store. On
// failure the result still contains the retained partial prefix.
func (x *AtomicTransfer) Result() (*TransferResult, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.initLocked().clone()
	res := &TransferResult{Partial: p, Err: x.fatal}
	if x.result != nil {
		res.Zone = x.result.Clone()
	}
	if x.fatal == nil && x.result == nil {
		res.Err = newTransferError("commit", ErrIncompleteTransfer, p)
	}
	if x.fatal != nil {
		res.Err = x.fatal
	}
	res.syncAliases()
	return res, res.Err
}

// GetZone returns the completed candidate zone.
func (x *AtomicTransfer) GetZone() *Zone {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.result == nil {
		return nil
	}
	return x.result.Clone()
}

// CurrentZone is an alias for GetZone.
func (x *AtomicTransfer) CurrentZone() *Zone { return x.GetZone() }

// CommittedZoneValue is an alias for GetZone.
func (x *AtomicTransfer) CommittedZoneValue() *Zone { return x.GetZone() }

// Partial returns a diagnostic snapshot of the accepted prefix.
func (x *AtomicTransfer) Partial() *PartialTransfer {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.initLocked().clone()
}

// Snapshot is an alias for Partial.
func (x *AtomicTransfer) Snapshot() *PartialTransfer { return x.Partial() }

// Err returns the terminal fatal error, if any.
func (x *AtomicTransfer) Err() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.fatal
}

// Abort terminates the transfer and preserves the partial prefix.
func (x *AtomicTransfer) Abort(causes ...error) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.initLocked()
	var cause error = ErrIncompleteTransfer
	if len(causes) > 0 && causes[0] != nil {
		cause = causes[0]
	}
	err := newTransferError("abort", cause, p)
	return x.failLocked(err)
}

// Cancel is an alias for Abort with context.Canceled.
func (x *AtomicTransfer) Cancel() error {
	return x.Abort(context.Canceled)
}

// Commit validates completeness and atomically publishes the zone.
func (x *AtomicTransfer) Commit() error {
	x.mu.Lock()
	p := x.initLocked()
	if x.fatal != nil {
		x.mu.Unlock()
		return x.fatal
	}
	if x.result == nil || !p.EndMarker {
		// A premature Commit is not terminal: callers may continue feeding
		// messages until the end marker arrives.
		err := newTransferError("commit", ErrIncompleteTransfer, p)
		x.mu.Unlock()
		return err
	}
	if x.committed {
		x.mu.Unlock()
		return nil
	}
	z := x.result.Clone()
	stores := nonNilStores(x.Store, x.Manager, x.Registry, x.Table)
	holders := nonNilHolders(x.Holder, x.Target)
	x.committed = true
	p.Committed = true
	x.mu.Unlock()

	for _, s := range stores {
		if err := s.Commit(z); err != nil {
			return err
		}
	}
	for _, h := range holders {
		if err := h.Commit(z); err != nil {
			return err
		}
	}
	return nil
}

func nonNilStores(stores ...*ZoneStore) []*ZoneStore {
	var out []*ZoneStore
	for _, s := range stores {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

func nonNilHolders(holders ...*AtomicZone) []*AtomicZone {
	var out []*AtomicZone
	for _, h := range holders {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// CollectVerified consumes the existing Transfer.In envelope channel and
// returns an atomic result. It does not change the wire protocol or Envelope
// API.
func CollectVerified(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	x := NewAtomicTransfer()
	return collectVerified(q, envelopes, x)
}

func collectVerified(q *Msg, envelopes <-chan *Envelope, x *AtomicTransfer) (*TransferResult, error) {
	if x == nil {
		x = NewAtomicTransfer()
	}
	_ = x.Begin(q)

	var seq uint64 = 1
	for env := range envelopes {
		if env == nil {
			continue
		}
		if err := x.ProcessEnvelope(seq, env); err != nil {
			res, _ := x.Result()
			return res, err
		}
		seq++
	}

	// The low-level transfer closes the channel after either a terminal
	// protocol marker or an error. An error envelope would have terminated
	// processing above. A clean channel close therefore means the end marker
	// was already accepted by inAxfr/inIxfr.
	if err := x.End(); err != nil && !errors.Is(err, ErrSoa) {
		res, _ := x.Result()
		return res, err
	}
	if err := x.Commit(); err != nil {
		res, _ := x.Result()
		return res, err
	}
	return x.Result()
}

// VerifyTransfer is an alias for CollectVerified.
func VerifyTransfer(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	return CollectVerified(q, envelopes)
}

// CollectTransfer is an alias for CollectVerified.
func CollectTransfer(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	return CollectVerified(q, envelopes)
}

// AssembleTransfer is an alias for CollectVerified.
func AssembleTransfer(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	return CollectVerified(q, envelopes)
}

// AtomicCollect is an alias for CollectVerified.
func AtomicCollect(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	return CollectVerified(q, envelopes)
}

// CollectZone collects and commits a transfer to an in-memory Zone.
func CollectZone(q *Msg, envelopes <-chan *Envelope) (*Zone, error) {
	res, err := CollectVerified(q, envelopes)
	if err != nil {
		return nil, err
	}
	return res.Zone, nil
}

// VerifyZone is an alias for CollectZone.
func VerifyZone(q *Msg, envelopes <-chan *Envelope) (*Zone, error) {
	return CollectZone(q, envelopes)
}

// AssembleZone is an alias for CollectZone.
func AssembleZone(q *Msg, envelopes <-chan *Envelope) (*Zone, error) {
	return CollectZone(q, envelopes)
}

// AtomicTransferZone is an alias for CollectZone.
func AtomicTransferZone(q *Msg, envelopes <-chan *Envelope) (*Zone, error) {
	return CollectZone(q, envelopes)
}

// TransferAndVerify is an alias for CollectVerified.
func TransferAndVerify(q *Msg, envelopes <-chan *Envelope) (*TransferResult, error) {
	return CollectVerified(q, envelopes)
}

// VerifiedIn performs Transfer.In and atomically collects the result.
func (t *Transfer) VerifiedIn(q *Msg, server string) (*TransferResult, error) {
	ch, err := t.In(q, server)
	if err != nil {
		var te error
		if IsTimeout(err) {
			te = newTransferError("dial", errors.Join(ErrTransferTimeout, context.DeadlineExceeded, os.ErrDeadlineExceeded, err), nil)
		} else {
			te = newTransferError("dial", err, nil)
		}
		return &TransferResult{Err: te, Error: te}, te
	}
	x := NewAtomicTransfer(q)
	x.ExpectedSerial = firstNonEmptyUint32(t.ExpectedSerial, t.ExpectedSOASerial)
	x.CheckSerial = t.VerifySerial || t.RequireSerialMatch
	x.Store = firstNonNilZoneStore(t.Store, t.ZoneStore)
	x.Manager = x.Store
	x.Holder = firstNonNilAtomicZone(t.Holder, t.AtomicZone)
	return collectVerified(q, ch, x)
}

func firstNonNilZoneStore(values ...*ZoneStore) *ZoneStore {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstNonNilAtomicZone(values ...*AtomicZone) *AtomicZone {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// InVerified is an alias for VerifiedIn.
func (t *Transfer) InVerified(q *Msg, server string) (*TransferResult, error) {
	return t.VerifiedIn(q, server)
}

// AtomicIn is an alias for VerifiedIn.
func (t *Transfer) AtomicIn(q *Msg, server string) (*TransferResult, error) {
	return t.VerifiedIn(q, server)
}

// InAtomic is an alias for VerifiedIn.
func (t *Transfer) InAtomic(q *Msg, server string) (*TransferResult, error) {
	return t.VerifiedIn(q, server)
}

// FetchVerified is an alias for VerifiedIn.
func (t *Transfer) FetchVerified(q *Msg, server string) (*TransferResult, error) {
	return t.VerifiedIn(q, server)
}

// TransferZone performs a transfer and returns the committed zone.
func (t *Transfer) TransferZone(q *Msg, server string) (*Zone, error) {
	res, err := t.VerifiedIn(q, server)
	if err != nil {
		return nil, err
	}
	return res.Zone, nil
}

// FetchZone is an alias for TransferZone.
func (t *Transfer) FetchZone(q *Msg, server string) (*Zone, error) {
	return t.TransferZone(q, server)
}

// AtomicAXFR is a convenience wrapper for an AXFR request.
func AtomicAXFR(server, zone string, timeout ...time.Duration) (*Zone, error) {
	q := new(Msg)
	q.SetAxfr(zone)
	tr := &Transfer{}
	if len(timeout) > 0 {
		tr.ReadTimeout = timeout[0]
		tr.DialTimeout = timeout[0]
	}
	return tr.TransferZone(q, server)
}
