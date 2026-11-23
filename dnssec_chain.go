package dns

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// This file adds a staged DNSSEC validation chain on top of the existing
// RRSIG.Verify primitive. The primitive itself is unchanged, so callers that
// use it directly keep their exact behavior and error values.
//
// A chain is validated in four stages, always in this order:
//
//	DS      a DS record from the parent matches a key in the zone's DNSKEY RRset
//	DNSKEY  the DNSKEY RRset is verified by a key the DS RRset vouches for
//	RRSIG   the answer RRset is verified by the now authenticated zone keys
//	NSEC    the denial of existence is verified by the same zone keys
//
// ValidationResult records the outcome of every stage and the first stage that
// failed. A failure blocks the later stages; it never erases the first
// failure, so an operator can tell whether a bogus answer broke at the
// delegation (DS), at the key set (DNSKEY), at the data signature (RRSIG) or
// at the denial proof (NSEC).

// Errors added for staged validation. They are *Error values, like the errors
// in msg.go, so their strings start with "dns: " and the existing error values
// and strings are left untouched.
var (
	// ErrDSMismatch indicates that no DNSKEY in a zone matches any of the
	// DS records supplied by the parent.
	ErrDSMismatch error = &Error{err: "no DNSKEY matches the DS RRset"}
	// ErrNoDNSKEY indicates that a signed delegation has no DNSKEY RRset.
	ErrNoDNSKEY error = &Error{err: "no DNSKEY RRset"}
	// ErrSigValidity indicates a signature that is not yet or no longer
	// valid at the evaluation time. It is reported as a transient failure,
	// because time alone can make the signature valid.
	ErrSigValidity error = &Error{err: "signature outside its validity period"}
	// ErrDenial indicates a denial of existence proof that does not hold.
	ErrDenial error = &Error{err: "bad denial of existence proof"}
	// ErrNoDenial indicates a negative answer without a denial proof.
	ErrNoDenial error = &Error{err: "no denial of existence proof"}
	// ErrNoAnswer indicates a request with neither an answer RRset nor a
	// denial proof to validate.
	ErrNoAnswer error = &Error{err: "no RRset or denial proof to validate"}
	// ErrNoKey indicates that a key set holds no DNSKEY with the key tag
	// and algorithm of a signature.
	ErrNoKey error = &Error{err: "no DNSKEY with matching keytag and algorithm"}
)

// transientError marks a validation failure that can clear without any change
// to the validated data, for example a signature whose inception time has not
// been reached yet. Transient failures are reported by ValidationResult and
// are never written to a NegativeCache.
type transientError struct{ err error }

func (t *transientError) Error() string { return t.err.Error() }
func (t *transientError) Unwrap() error { return t.err }

func transient(err error) error {
	if err == nil {
		return nil
	}
	return &transientError{err: err}
}

// IsTransient reports whether err is a transient validation failure. Such a
// failure may disappear without the validated data changing, so it is not
// conclusive evidence that the data is bogus.
func IsTransient(err error) bool {
	var t *transientError
	return errors.As(err, &t)
}

// ValidationStage identifies one stage of a DNSSEC validation chain.
type ValidationStage uint8

const (
	// StageDS matches the parent DS RRset against the child DNSKEY RRset.
	StageDS ValidationStage = iota + 1
	// StageDNSKEY verifies the signature on the child DNSKEY RRset.
	StageDNSKEY
	// StageRRSIG verifies the signature on the answer RRset.
	StageRRSIG
	// StageNSEC verifies a denial of existence proof.
	StageNSEC
)

// String returns the name of the stage as used in result strings.
func (s ValidationStage) String() string {
	switch s {
	case StageDS:
		return "DS"
	case StageDNSKEY:
		return "DNSKEY"
	case StageRRSIG:
		return "RRSIG"
	case StageNSEC:
		return "NSEC"
	}
	return "UNKNOWN"
}

// StageStatus is the outcome of a single validation stage.
type StageStatus uint8

const (
	// StageNotRun means the stage was not evaluated, usually because an
	// earlier stage failed or because the chain stopped before it.
	StageNotRun StageStatus = iota
	// StageSkipped means the stage did not apply to the validated chain,
	// for example the NSEC stage of a positive answer.
	StageSkipped
	// StageSecure means the stage completed successfully.
	StageSecure
	// StageInsecure means DNSSEC material was absent or used only
	// algorithms this package cannot validate, so the stage proves
	// nothing (an insecure delegation).
	StageInsecure
	// StageFailed means the stage evaluated the data and rejected it.
	StageFailed
)

// String returns the name of the status as used in result strings.
func (s StageStatus) String() string {
	switch s {
	case StageNotRun:
		return "not-run"
	case StageSkipped:
		return "skipped"
	case StageSecure:
		return "secure"
	case StageInsecure:
		return "insecure"
	case StageFailed:
		return "failed"
	}
	return "unknown"
}

// StageResult is the outcome of one validation stage.
type StageResult struct {
	// Stage is the stage this result belongs to.
	Stage ValidationStage
	// Status is the outcome of the stage.
	Status StageStatus
	// Err is the error that made the stage fail, nil otherwise.
	Err error
	// Detail is a human readable explanation for operators. It is
	// deterministic for the same request and evaluation time.
	Detail string
}

// String returns a stable, single-line representation of the stage result.
func (r StageResult) String() string {
	s := r.Status.String()
	if r.Err != nil {
		s += "(" + r.Err.Error() + ")"
	}
	if r.Detail != "" {
		s += ": " + r.Detail
	}
	return s
}

// ValidationResult is the staged outcome of validating one DNSSEC chain.
//
// A ValidationResult belongs to exactly one validation call. Concurrent
// validations never share one, so failure state cannot leak between queries.
type ValidationResult struct {
	// Stages holds the four stage results in order: DS, DNSKEY, RRSIG, NSEC.
	Stages [4]StageResult

	// FailedStage is the first stage that failed, or 0 when no stage failed.
	FailedStage ValidationStage

	now      time.Time // evaluation time the result was produced for
	err      error     // first failure
	insecure bool      // chain ended in an insecure delegation
	keys     []*DNSKEY // keys authenticated by the DNSKEY stage
	denial   bool      // the chain proved a denial of existence
	proof    *DenialProof
	cached   bool // the denial proof came from the NegativeCache
}

// Cached reports whether a denial proof was served from the NegativeCache
// instead of being validated again.
func (r *ValidationResult) Cached() bool { return r != nil && r.cached }

// Time returns the evaluation time the result was produced for.
func (r *ValidationResult) Time() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.now
}

// Stage returns the result of one stage. An out-of-range stage returns an
// empty StageNotRun result.
func (r *ValidationResult) Stage(s ValidationStage) StageResult {
	if r == nil || s < StageDS || s > StageNSEC {
		return StageResult{Stage: s, Status: StageNotRun}
	}
	return r.Stages[s-1]
}

// Secure reports whether every applicable stage verified and the result is a
// securely validated answer. A denial proof served from the NegativeCache is
// secure as well: the cache only stores proofs that a full chain verified.
func (r *ValidationResult) Secure() bool {
	if r == nil {
		return false
	}
	if r.cached {
		return r.denial && r.FailedStage == 0
	}
	return !r.insecure && r.FailedStage == 0 && r.Stage(StageDS).Status == StageSecure
}

// Insecure reports whether validation stopped because the chain is an
// insecure delegation: no DS record, or only DS digest/algorithm types this
// package cannot validate.
func (r *ValidationResult) Insecure() bool {
	return r != nil && r.insecure && r.FailedStage == 0
}

// Temporary reports whether the first failure is transient. A transient
// failure must not be treated as proof that the data is bogus and must not be
// cached as a denial of existence.
func (r *ValidationResult) Temporary() bool {
	return r != nil && IsTransient(r.err)
}

// Err returns the error of the first failed stage, or nil when the chain was
// secure or insecure.
func (r *ValidationResult) Err() error {
	if r == nil {
		return nil
	}
	return r.err
}

// TrustedKeys returns a copy of the zone keys that were authenticated in the
// DNSKEY stage. It is empty for an insecure chain or when the DNSKEY stage
// never ran.
func (r *ValidationResult) TrustedKeys() []*DNSKEY {
	if r == nil {
		return nil
	}
	keys := make([]*DNSKEY, len(r.keys))
	for i, k := range r.keys {
		keys[i] = k.copy().(*DNSKEY)
	}
	return keys
}

// Denied reports whether the chain proved a denial of existence. When true,
// Proof returns the verified proof.
func (r *ValidationResult) Denied() bool { return r != nil && r.denial }

// Proof returns the verified denial of existence proof, if any, as a copy.
func (r *ValidationResult) Proof() *DenialProof {
	if r == nil || r.proof == nil {
		return nil
	}
	return r.proof.Clone()
}

// String returns a stable, single-line summary of every stage. Two calls with
// the same input and the same evaluation time produce identical strings, which
// makes validation results repeatable.
func (r *ValidationResult) String() string {
	if r == nil {
		return "dnssec <nil>"
	}
	verdict := "bogus"
	switch {
	case r.Secure():
		verdict = "secure"
	case r.Insecure():
		verdict = "insecure"
	case r.Temporary():
		verdict = "transient"
	}
	var b strings.Builder
	b.WriteString("dnssec ")
	b.WriteString(verdict)
	for s := StageDS; s <= StageNSEC; s++ {
		b.WriteString(" ")
		b.WriteString(s.String())
		b.WriteString("=")
		b.WriteString(r.Stage(s).String())
	}
	return b.String()
}

// DenialKind identifies the form of a verified denial of existence.
type DenialKind uint8

const (
	// DenialNone is the zero value and is never a valid proof.
	DenialNone DenialKind = iota
	// DenialNameError proves that a name does not exist (NXDOMAIN).
	DenialNameError
	// DenialNoData proves that a name exists but holds no RRset of the
	// queried type (NODATA).
	DenialNoData
)

// String returns the name of the denial kind.
func (k DenialKind) String() string {
	switch k {
	case DenialNameError:
		return "NXDOMAIN"
	case DenialNoData:
		return "NODATA"
	}
	return "NONE"
}

// DenialProof is a denial of existence that was proven with signed NSEC or
// NSEC3 records.
type DenialProof struct {
	// Kind is what the proof establishes.
	Kind DenialKind
	// Name is the queried name.
	Name string
	// Type is the queried type for a NODATA proof, 0 otherwise.
	Type uint16
	// TTL is the TTL the proof may be cached for, in seconds.
	TTL uint32
	// Records are copies of the NSEC or NSEC3 records that form the proof.
	Records []RR

	// verified reports whether the proof came from a completed NSEC
	// stage. Only verified proofs may enter a NegativeCache.
	verified bool
}

// Clone returns a deep copy of the proof.
func (p *DenialProof) Clone() *DenialProof {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Records = make([]RR, len(p.Records))
	for i, rr := range p.Records {
		cp.Records[i] = rr.copy()
	}
	return &cp
}

// String returns a stable description of the proof.
func (p *DenialProof) String() string {
	if p == nil {
		return "denial <nil>"
	}
	if p.Kind == DenialNoData {
		return fmt.Sprintf("denial %s %s %s ttl=%d", p.Name, Type(p.Type).String(), p.Kind, p.TTL)
	}
	return fmt.Sprintf("denial %s %s ttl=%d", p.Name, p.Kind, p.TTL)
}

// NegativeCache stores only denial-of-existence proofs that have been verified
// with signed NSEC or NSEC3 records. Transient failures are never stored: the
// cache is populated by Validator.Validate only after the NSEC stage verified,
// and Put rejects proofs that were not produced that way.
//
// A zero NegativeCache is usable, and all methods are safe for concurrent use.
type NegativeCache struct {
	mu      sync.RWMutex
	entries map[negKey]negEntry
}

type negKey struct {
	name string
	typ  uint16
}

type negEntry struct {
	proof   *DenialProof
	expires time.Time
}

// NewNegativeCache returns an empty NegativeCache.
func NewNegativeCache() *NegativeCache {
	return &NegativeCache{entries: make(map[negKey]negEntry)}
}

// Put stores a verified denial proof until the given expiry time. It rejects
// nil proofs, proofs of kind DenialNone, proofs without records, proofs
// without a TTL and expiry times that are not in the future relative to now.
//
// Put also rejects proofs that were not produced by a completed NSEC stage,
// so a transient failure can never be turned into a long-lived cache entry
// even by a caller that builds a DenialProof by hand.
func (c *NegativeCache) Put(proof *DenialProof, expires time.Time, now time.Time) error {
	if proof == nil {
		return &Error{err: "nil denial proof"}
	}
	if !proof.verified {
		return &Error{err: "unverified denial proof"}
	}
	if proof.Kind == DenialNone {
		return &Error{err: "denial proof has no kind"}
	}
	if len(proof.Records) == 0 {
		return &Error{err: "denial proof has no records"}
	}
	if proof.TTL == 0 {
		return &Error{err: "denial proof has zero TTL"}
	}
	if !expires.After(now) {
		return &Error{err: "denial proof expires immediately"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[negKey]negEntry)
	}
	// Never let a shorter-lived proof replace a longer-lived one.
	key := negKey{CanonicalName(proof.Name), proof.Type}
	if proof.Kind == DenialNameError {
		// A name that does not exist is absent for every type, so one
		// entry covers all queries for the name.
		key.typ = 0
	}
	if old, ok := c.entries[key]; ok && old.expires.After(expires) {
		return nil
	}
	c.entries[key] = negEntry{proof: proof.Clone(), expires: expires}
	return nil
}

// Get returns a copy of the proof cached for name and type, when it is still
// valid at now. An NXDOMAIN proof proves that the name does not exist at all,
// so it is returned for any queried type. An expired entry is removed.
func (c *NegativeCache) Get(name string, qtype uint16, now time.Time) (*DenialProof, bool) {
	if c == nil {
		return nil, false
	}
	name = CanonicalName(name)
	if p, ok := c.get(negKey{name, qtype}, now); ok {
		return p, true
	}
	// DenialNameError entries are stored with type 0 because they are
	// independent of the queried type.
	return c.get(negKey{name, 0}, now)
}

// get returns one entry, removing it when it has expired.
func (c *NegativeCache) get(key negKey, now time.Time) (*DenialProof, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !e.expires.After(now) {
		c.mu.Lock()
		if cur, ok := c.entries[key]; ok && !cur.expires.After(now) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	return e.proof.Clone(), true
}

// Delete removes the entry for name and type, including an NXDOMAIN entry
// that covers every type.
func (c *NegativeCache) Delete(name string, qtype uint16) {
	if c == nil {
		return
	}
	name = CanonicalName(name)
	c.mu.Lock()
	delete(c.entries, negKey{name, qtype})
	if qtype != 0 {
		delete(c.entries, negKey{name, 0})
	}
	c.mu.Unlock()
}

// Purge removes all expired entries and reports how many were removed.
func (c *NegativeCache) Purge(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, e := range c.entries {
		if !e.expires.After(now) {
			delete(c.entries, key)
			n++
		}
	}
	return n
}

// Len returns the number of cached proofs, including entries that have
// expired but were not yet purged.
func (c *NegativeCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
