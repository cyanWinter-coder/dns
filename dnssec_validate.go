package dns

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoZone indicates a validation request without the zone material needed to
// build a chain.
var ErrNoZone error = &Error{err: "no zone material"}

// KeySet is an immutable set of DNSKEYs. Unlike a map keyed by key tag, a
// KeySet keeps every distinct key, including two different keys that share a
// key tag and algorithm. This is what makes validation during a key rollover
// correct: a signature is always matched against the keys that carry its key
// tag and algorithm, and no key ever overwrites another one that was loaded
// before or after it.
//
// A KeySet is safe for concurrent use. Its methods return copies, so callers
// cannot modify the shared keys.
type KeySet struct {
	keys []*DNSKEY
}

// NewKeySet returns a KeySet holding distinct copies of keys. Nil keys are
// ignored, and exact duplicates are stored once.
func NewKeySet(keys ...*DNSKEY) *KeySet {
	ks := &KeySet{}
	for _, k := range keys {
		ks.add(k)
	}
	return ks
}

// add appends a key unless the same key is already present.
func (ks *KeySet) add(k *DNSKEY) {
	if ks == nil || k == nil {
		return
	}
	tag := k.KeyTag()
	for _, e := range ks.keys {
		if e.KeyTag() == tag && e.Algorithm == k.Algorithm && e.Flags == k.Flags &&
			e.Protocol == k.Protocol && equal(e.Hdr.Name, k.Hdr.Name) && e.PublicKey == k.PublicKey {
			return
		}
	}
	ks.keys = append(ks.keys, k.copy().(*DNSKEY))
}

// Len returns the number of distinct keys in the set.
func (ks *KeySet) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.keys)
}

// Keys returns copies of all keys in insertion order.
func (ks *KeySet) Keys() []*DNSKEY {
	if ks == nil {
		return nil
	}
	out := make([]*DNSKEY, len(ks.keys))
	for i, k := range ks.keys {
		out[i] = k.copy().(*DNSKEY)
	}
	return out
}

// Candidates returns copies of every key whose key tag, algorithm and owner
// name match the signature being checked. A revoked key (the REVOKE bit set,
// RFC 5011) is never a candidate. An empty signer name matches every owner.
//
// Returning a slice rather than a single key is deliberate: two keys in a
// rollover can share a key tag, and both have to be tried instead of only the
// most recently loaded one.
func (ks *KeySet) Candidates(keytag uint16, algorithm uint8, signer string) []*DNSKEY {
	if ks == nil {
		return nil
	}
	var out []*DNSKEY
	for _, k := range ks.keys {
		if k.KeyTag() != keytag || k.Algorithm != algorithm {
			continue
		}
		if k.Flags&REVOKE != 0 {
			continue
		}
		if signer != "" && !equal(k.Hdr.Name, signer) {
			continue
		}
		out = append(out, k.copy().(*DNSKEY))
	}
	return out
}

// Zone is a shared, read-only snapshot of one zone's DNSSEC material: the DS
// RRset from its parent (or an empty slice for an insecure delegation) and its
// own DNSKEY RRset with the signatures over it.
//
// A Zone may be shared by concurrent validations. It is never modified after
// construction, and its accessors return copies. Mutable validation state lives
// in ValidationResult, never in the Zone or the Validator.
type Zone struct {
	// Name is the canonical name of the zone.
	Name string
	// DS is the DS RRset from the parent, if any.
	DS []*DS
	// DNSKEYs is the zone's DNSKEY RRset.
	DNSKEYs []*DNSKEY
	// DNSKEYSignatures holds the RRSIGs over DNSKEYs.
	DNSKEYSignatures []*RRSIG

	keys *KeySet
}

// NewZone returns a Zone holding copies of the supplied material. When name is
// empty it is taken from the first DNSKEY, or from the first DS record. All
// keys are retained, so several keys with the same key tag and algorithm stay
// available to match their own signatures.
func NewZone(name string, ds []*DS, keys []*DNSKEY, sigs []*RRSIG) *Zone {
	z := &Zone{}
	switch {
	case name != "":
		z.Name = CanonicalName(name)
	case len(keys) != 0:
		z.Name = CanonicalName(keys[0].Hdr.Name)
	case len(ds) != 0:
		z.Name = CanonicalName(ds[0].Hdr.Name)
	}
	z.DS = make([]*DS, 0, len(ds))
	for _, d := range ds {
		if d != nil {
			z.DS = append(z.DS, d.copy().(*DS))
		}
	}
	z.DNSKEYs = make([]*DNSKEY, 0, len(keys))
	for _, k := range keys {
		if k != nil {
			z.DNSKEYs = append(z.DNSKEYs, k.copy().(*DNSKEY))
		}
	}
	z.DNSKEYSignatures = make([]*RRSIG, 0, len(sigs))
	for _, s := range sigs {
		if s != nil {
			z.DNSKEYSignatures = append(z.DNSKEYSignatures, s.copy().(*RRSIG))
		}
	}
	z.keys = NewKeySet(z.DNSKEYs...)
	return z
}

// KeySet returns the zone's shared key set. Callers must treat it as
// read-only; every KeySet method returns copies.
func (z *Zone) KeySet() *KeySet {
	if z == nil {
		return NewKeySet()
	}
	if z.keys == nil {
		// A Zone built with a struct literal has no prebuilt set. Build
		// one so such a Zone still validates; NewZone is preferred.
		return NewKeySet(z.DNSKEYs...)
	}
	return z.keys
}

// Keys returns copies of the zone's DNSKEY RRset.
func (z *Zone) Keys() []*DNSKEY {
	if z == nil {
		return nil
	}
	out := make([]*DNSKEY, len(z.DNSKEYs))
	for i, k := range z.DNSKEYs {
		out[i] = k.copy().(*DNSKEY)
	}
	return out
}

// Validator validates DNSSEC chains. It holds only immutable state (trust
// anchors and a clock) plus an optional NegativeCache, which is concurrency
// safe. Every call to Validate creates its own ValidationResult, so concurrent
// validations share the context but never share error state.
type Validator struct {
	anchors []*DS
	cache   *NegativeCache
	clock   func() time.Time
}

// ValidatorOption configures a Validator.
type ValidatorOption func(*Validator)

// WithTrustAnchors configures DS records used when a Zone carries no DS RRset.
// The records are copied.
func WithTrustAnchors(ds ...*DS) ValidatorOption {
	return func(v *Validator) {
		v.anchors = v.anchors[:0]
		for _, d := range ds {
			if d != nil {
				v.anchors = append(v.anchors, d.copy().(*DS))
			}
		}
	}
}

// WithNegativeCache configures the cache that verified denial proofs are
// written to and looked up in. A nil cache disables caching.
func WithNegativeCache(c *NegativeCache) ValidatorOption {
	return func(v *Validator) { v.cache = c }
}

// WithValidationClock configures the clock used by Validate. It must be safe
// for concurrent use. The clock is ignored by ValidateAt.
func WithValidationClock(now func() time.Time) ValidatorOption {
	return func(v *Validator) {
		if now != nil {
			v.clock = now
		}
	}
}

// NewValidator returns a Validator. Without options it has no trust anchor, no
// cache and uses time.Now.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{clock: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(v)
		}
	}
	return v
}

// TrustAnchors returns copies of the configured trust anchors.
func (v *Validator) TrustAnchors() []*DS {
	if v == nil {
		return nil
	}
	out := make([]*DS, len(v.anchors))
	for i, d := range v.anchors {
		out[i] = d.copy().(*DS)
	}
	return out
}

// ChainRequest is one validation request. It is not modified by Validate, so a
// request, and the Zone it points at, can be shared by concurrent validations.
type ChainRequest struct {
	// Name is the queried name.
	Name string
	// Type is the queried type.
	Type uint16
	// Class is the queried class. Zero means ClassINET.
	Class uint16
	// Zone holds the shared delegation and key material. It is required.
	Zone *Zone
	// Answer is the answer RRset of a positive answer.
	Answer []RR
	// AnswerSignatures holds the RRSIGs over Answer.
	AnswerSignatures []*RRSIG
	// Denial holds the NSEC or NSEC3 records of a negative answer.
	Denial []RR
	// DenialSignatures holds the RRSIGs over Denial.
	DenialSignatures []*RRSIG
}

// Validate validates req at the current clock time.
func (v *Validator) Validate(req ChainRequest) *ValidationResult {
	return v.ValidateAt(req, v.now())
}

// ValidateAt validates req at the given time. A zero time means the current
// clock time. Supplying the time explicitly makes validation repeatable: the
// same request and time always produce the same result.
func (v *Validator) ValidateAt(req ChainRequest, now time.Time) *ValidationResult {
	if now.IsZero() {
		now = v.now()
	}
	now = now.UTC()

	res := &ValidationResult{now: now}
	for i := range res.Stages {
		res.Stages[i] = StageResult{Stage: ValidationStage(i + 1), Status: StageNotRun}
	}

	// A negative query can be answered from the cache. Only proofs that the
	// NSEC stage verified are ever stored there, never transient failures.
	if len(req.Answer) == 0 && len(req.Denial) == 0 && v.cache != nil {
		if p, ok := v.cache.Get(req.Name, req.Type, now); ok {
			res.cached = true
			res.denial = true
			res.proof = p
			res.setStage(StageDS, StageSkipped, nil, "satisfied by negative cache")
			res.setStage(StageDNSKEY, StageSkipped, nil, "satisfied by negative cache")
			res.setStage(StageRRSIG, StageSkipped, nil, "satisfied by negative cache")
			res.setStage(StageNSEC, StageSecure, nil, p.String())
			return res
		}
	}

	zone := req.Zone
	if zone == nil {
		res.setStage(StageDS, StageFailed, ErrNoZone, "no zone material in request")
		return res
	}

	if len(zone.DNSKEYs) == 0 {
		if len(zone.DS) == 0 && len(v.anchors) == 0 {
			// No DS and no keys is an insecure delegation, not a failure.
			res.insecure = true
			res.setStage(StageDS, StageInsecure, nil, "no DS record")
			return res
		}
		res.setStage(StageDS, StageFailed, ErrNoDNSKEY, "DS present but the zone has no DNSKEY RRset")
		return res
	}

	anchors := zone.DS
	if len(anchors) == 0 {
		// Trust anchors only apply to the zone they are configured for.
		// A zone without its own DS and without a matching anchor is an
		// insecure delegation, not a bogus one.
		anchors = applicableAnchors(v.anchors, zone.Name)
	}
	if len(anchors) == 0 {
		res.insecure = true
		res.setStage(StageDS, StageInsecure, nil, "no DS record or trust anchor")
		return res
	}

	matched, unsupported, detail := matchDS(anchors, zone.KeySet(), zone.Name)
	if len(matched) == 0 {
		if unsupported {
			res.insecure = true
			res.setStage(StageDS, StageInsecure, nil, "only unsupported DS algorithms or digests")
			return res
		}
		res.setStage(StageDS, StageFailed, ErrDSMismatch, detail)
		return res
	}
	res.setStage(StageDS, StageSecure, nil, detail)

	// The DNSKEY RRset must be signed by a key that a DS record vouches
	// for. All matching keys are tried, which is what keeps a rollover
	// working while both the old and the new key are published.
	dnskeyKey, err := verifySignatureSet(keysAsRR(zone.DNSKEYs), zone.DNSKEYSignatures, NewKeySet(matched...), now)
	if err != nil {
		res.setStage(StageDNSKEY, StageFailed, err, stageDetail(err))
		return res
	}
	res.setStage(StageDNSKEY, StageSecure, nil,
		fmt.Sprintf("DNSKEY RRset signed by keytag=%d algorithm=%s", dnskeyKey.KeyTag(), algorithmName(dnskeyKey.Algorithm)))

	trusted := zone.KeySet()
	res.keys = zone.Keys()

	if len(req.Answer) != 0 {
		if !IsRRset(req.Answer) {
			res.setStage(StageRRSIG, StageFailed, ErrRRset, "answer is not a valid RRset")
			return res
		}
		answerKey, err := verifySignatureSet(req.Answer, req.AnswerSignatures, trusted, now)
		if err != nil {
			res.setStage(StageRRSIG, StageFailed, err, stageDetail(err))
			return res
		}
		res.setStage(StageRRSIG, StageSecure, nil,
			fmt.Sprintf("%s RRset signed by keytag=%d algorithm=%s",
				Type(req.Answer[0].Header().Rrtype), answerKey.KeyTag(), algorithmName(answerKey.Algorithm)))
		res.setStage(StageNSEC, StageSkipped, nil, "positive answer")
		return res
	}

	if len(req.Denial) == 0 {
		res.setStage(StageRRSIG, StageFailed, ErrNoAnswer, "neither an answer RRset nor a denial proof")
		return res
	}

	// Negative answer: the data stage does not apply, the denial proof
	// carries the signatures.
	res.setStage(StageRRSIG, StageSkipped, nil, "negative answer")

	denial, denialSig, err := verifyDenial(req.Denial, req.DenialSignatures, trusted, now)
	if err != nil {
		res.setStage(StageNSEC, StageFailed, err, stageDetail(err))
		return res
	}
	cls := req.Class
	if cls == 0 {
		cls = ClassINET
	}
	proof, err := buildDenialProof(req.Name, req.Type, cls, denial, denialSig, now)
	if err != nil {
		res.setStage(StageNSEC, StageFailed, err, stageDetail(err))
		return res
	}
	proof.verified = true
	res.setStage(StageNSEC, StageSecure, nil, proof.String())
	res.denial = true
	res.proof = proof

	// Only the verified proof reaches the cache, and only until the proof's
	// own TTL or its signature expiry, whichever comes first.
	if v.cache != nil {
		expires := now.Add(time.Duration(proof.TTL) * time.Second)
		_ = v.cache.Put(proof, expires, now)
	}
	return res
}

// now returns the validator clock time.
func (v *Validator) now() time.Time {
	if v == nil || v.clock == nil {
		return time.Now()
	}
	return v.clock()
}

// setStage records the outcome of one stage and remembers the first failure.
// It never overwrites a failure that was recorded earlier.
func (r *ValidationResult) setStage(stage ValidationStage, status StageStatus, err error, detail string) {
	if r == nil || stage < StageDS || stage > StageNSEC {
		return
	}
	r.Stages[stage-1] = StageResult{Stage: stage, Status: status, Err: err, Detail: detail}
	if status == StageFailed && r.FailedStage == 0 {
		r.FailedStage = stage
		r.err = err
	}
}

// applicableAnchors returns the trust anchors whose owner name is zone. A DS
// record with an empty owner is assumed to belong to the configured zone and is
// returned as-is.
func applicableAnchors(anchors []*DS, zone string) []*DS {
	zone = CanonicalName(zone)
	var out []*DS
	for _, ds := range anchors {
		if ds == nil {
			continue
		}
		if ds.Hdr.Name == "" || equal(CanonicalName(ds.Hdr.Name), zone) {
			out = append(out, ds)
		}
	}
	return out
}

// matchDS returns the keys that match a DS record. It reports whether every
// supplied DS used an algorithm or digest this package cannot validate, which
// makes the delegation insecure rather than bogus.
func matchDS(anchors []*DS, keys *KeySet, zone string) (matched []*DNSKEY, unsupported bool, detail string) {
	zone = CanonicalName(zone)
	supported := false
	for _, ds := range anchors {
		if ds == nil {
			continue
		}
		if !supportedDSDigest(ds.DigestType) || !supportedDNSSECAlgorithm(ds.Algorithm) {
			continue
		}
		supported = true
		owner := ds.Hdr.Name
		if owner == "" {
			owner = zone
		}
		if owner != "" && !equal(CanonicalName(owner), zone) && zone != "" {
			continue
		}
		for _, k := range keys.Keys() {
			if k.Algorithm != ds.Algorithm || k.KeyTag() != ds.KeyTag {
				continue
			}
			if !equal(CanonicalName(k.Hdr.Name), CanonicalName(owner)) {
				continue
			}
			computed := k.ToDS(ds.DigestType)
			if computed == nil || !strings.EqualFold(computed.Digest, ds.Digest) {
				continue
			}
			if !containsKey(matched, k) {
				matched = append(matched, k)
			}
			detail = fmt.Sprintf("DS keytag=%d algorithm=%s digest=%s matched",
				ds.KeyTag, algorithmName(ds.Algorithm), HashToString[ds.DigestType])
		}
	}
	if len(matched) != 0 {
		return matched, false, detail
	}
	if !supported {
		return nil, true, ""
	}
	detail = "no DNSKEY matches the DS RRset"
	if zone != "" {
		detail = fmt.Sprintf("no DNSKEY of %s matches the DS RRset", zone)
	}
	return nil, false, detail
}

func containsKey(keys []*DNSKEY, key *DNSKEY) bool {
	for _, k := range keys {
		if k.KeyTag() == key.KeyTag() && k.Algorithm == key.Algorithm && k.PublicKey == key.PublicKey {
			return true
		}
	}
	return false
}

func supportedDSDigest(d uint8) bool {
	switch d {
	case SHA1, SHA256, SHA384, SHA512:
		return true
	}
	return false
}

func supportedDNSSECAlgorithm(a uint8) bool {
	switch a {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519:
		return true
	}
	return false
}

func algorithmName(a uint8) string {
	if s, ok := AlgorithmToString[a]; ok {
		return s
	}
	return fmt.Sprintf("ALG%d", a)
}

// keysAsRR returns the DNSKEY record set as a plain RR slice so the generic
// signature checker can consume it.
func keysAsRR(keys []*DNSKEY) []RR {
	rrs := make([]RR, len(keys))
	for i, k := range keys {
		rrs[i] = k
	}
	return rrs
}

// verifySignatureSet verifies rrset with the signatures in sigs and returns
// the key that verified it. Candidate keys are selected per signature by key
// tag, algorithm and signer name, and each signature is checked against its
// own validity period first. Keys are never collapsed by key tag, so two
// rollover keys with the same tag are both tried.
func verifySignatureSet(rrset []RR, sigs []*RRSIG, keys *KeySet, now time.Time) (*DNSKEY, error) {
	if len(rrset) == 0 {
		return nil, ErrNoAnswer
	}
	h := rrset[0].Header()
	var sawTime, sawCrypto, sawNoKey, sawKey, sawAlg, sawRRset bool
	var checked int
	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		// Ignore signatures that do not cover this RRset.
		if sig.TypeCovered != h.Rrtype || sig.Hdr.Class != h.Class || !equal(sig.Hdr.Name, h.Name) {
			continue
		}
		checked++
		if !sig.ValidityPeriod(now) {
			sawTime = true
			continue
		}
		candidates := keys.Candidates(sig.KeyTag, sig.Algorithm, sig.SignerName)
		if len(candidates) == 0 {
			sawNoKey = true
			continue
		}
		for _, k := range candidates {
			err := sig.Verify(k, rrset)
			if err == nil {
				return k, nil
			}
			switch {
			case errors.Is(err, ErrAlg):
				sawAlg = true
			case errors.Is(err, ErrRRset):
				sawRRset = true
			case errors.Is(err, ErrKey):
				// The key is structurally unusable for this signature
				// (wrong flags, protocol or signer). Report it as a bad
				// key unless another candidate or signature works.
				sawKey = true
			default:
				// crypto/rsa reports its own verification error; the
				// chain normalizes it to ErrSig.
				sawCrypto = true
			}
		}
	}
	switch {
	case checked == 0:
		return nil, ErrNoSig
	case sawRRset:
		return nil, ErrRRset
	case sawAlg:
		return nil, ErrAlg
	case sawCrypto:
		return nil, ErrSig
	case sawKey:
		return nil, ErrKey
	case sawNoKey:
		return nil, ErrNoKey
	case sawTime:
		return nil, transient(ErrSigValidity)
	}
	return nil, ErrNoSig
}

// stageDetail renders the operator-facing detail for a failed stage. The
// transient marker is unwrapped so the detail is stable.
func stageDetail(err error) string {
	if err == nil {
		return ""
	}
	var t *transientError
	if errors.As(err, &t) {
		return t.err.Error() + " (transient)"
	}
	return err.Error()
}

// denialGroup is one RRset inside a denial proof.
type denialGroup struct {
	name   string
	rrtype uint16
	rrs    []RR
}

// verifyDenial verifies the signatures on every NSEC and NSEC3 RRset and
// returns the verified records together with the signatures, in input order.
func verifyDenial(rrs []RR, sigs []*RRSIG, keys *KeySet, now time.Time) ([]RR, []*RRSIG, error) {
	var groups []denialGroup
	all := make([]RR, 0, len(rrs))
	allSigs := make([]*RRSIG, 0, len(sigs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		switch h.Rrtype {
		case TypeNSEC, TypeNSEC3:
		default:
			return nil, nil, fmt.Errorf("%w: unexpected %s record in denial proof", ErrDenial, Type(h.Rrtype))
		}
		all = append(all, rr)
		found := false
		for i := range groups {
			if groups[i].rrtype == h.Rrtype && equal(groups[i].name, h.Name) {
				groups[i].rrs = append(groups[i].rrs, rr)
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, denialGroup{name: h.Name, rrtype: h.Rrtype, rrs: []RR{rr}})
		}
	}
	if len(all) == 0 {
		return nil, nil, ErrNoDenial
	}

	for _, g := range groups {
		var groupSigs []*RRSIG
		for _, sig := range sigs {
			if sig == nil || sig.TypeCovered != g.rrtype || !equal(sig.Hdr.Name, g.name) {
				continue
			}
			groupSigs = append(groupSigs, sig)
			allSigs = append(allSigs, sig)
		}
		if len(groupSigs) == 0 {
			return nil, nil, fmt.Errorf("%w: no RRSIG for %s %s", ErrNoSig, Type(g.rrtype), g.name)
		}
		if _, err := verifySignatureSet(g.rrs, groupSigs, keys, now); err != nil {
			return nil, nil, err
		}
	}
	return all, allSigs, nil
}

// buildDenialProof checks the denial semantics of verified NSEC or NSEC3
// records and returns the proof. The NSEC stage calls it only after every
// record's signature verified.
func buildDenialProof(name string, qtype uint16, class uint16, rrs []RR, sigs []*RRSIG, now time.Time) (*DenialProof, error) {
	name = Fqdn(name)
	var nsecs []*NSEC
	var nsec3s []*NSEC3
	for _, rr := range rrs {
		if rr.Header().Class != class {
			return nil, fmt.Errorf("%w: denial record %s has class %s, want %s",
				ErrDenial, rr.Header().Name, Class(rr.Header().Class), Class(class))
		}
		switch x := rr.(type) {
		case *NSEC:
			nsecs = append(nsecs, x)
		case *NSEC3:
			nsec3s = append(nsec3s, x)
		}
	}

	// The signer name of the verified signatures is the zone apex, which
	// exists by definition and anchors the closest-encloser search.
	zone := ""
	for _, sig := range sigs {
		if sig != nil && sig.SignerName != "" {
			zone = CanonicalName(sig.SignerName)
			break
		}
	}

	var kind DenialKind
	var used []RR
	var detail string
	if len(nsecs) != 0 {
		kind, used, detail = nsecDenial(name, qtype, zone, nsecs)
	}
	if kind == DenialNone && len(nsec3s) != 0 {
		kind, used, detail = nsec3Denial(name, qtype, zone, nsec3s)
	}
	if kind == DenialNone {
		if detail == "" {
			detail = fmt.Sprintf("%s has no denial proof for %s", name, Type(qtype))
		}
		return nil, fmt.Errorf("%w: %s", ErrDenial, detail)
	}

	ttl := proofTTL(used, sigs, now)
	if ttl == 0 {
		return nil, fmt.Errorf("%w: denial proof is already expired", ErrDenial)
	}
	proof := &DenialProof{Kind: kind, Name: name, TTL: ttl}
	if kind == DenialNoData {
		proof.Type = qtype
	}
	for _, rr := range used {
		proof.Records = append(proof.Records, rr.copy())
	}
	return proof, nil
}

// proofTTL returns the number of seconds a proof may be cached for: the
// smallest record TTL, further bounded by the earliest expiry of a signature
// that is valid at now.
func proofTTL(records []RR, sigs []*RRSIG, now time.Time) uint32 {
	ttl := uint32(^uint32(0))
	for _, rr := range records {
		if t := rr.Header().Ttl; t < ttl {
			ttl = t
		}
	}
	if ttl == ^uint32(0) {
		return 0
	}
	expiry := now.Add(time.Duration(ttl) * time.Second)
	for _, sig := range sigs {
		if sig == nil || !sig.ValidityPeriod(now) {
			continue
		}
		if e := rrsigExpiration(sig, now); e.Before(expiry) {
			expiry = e
		}
	}
	d := expiry.Sub(now)
	if d <= 0 {
		return 0
	}
	return uint32(d / time.Second)
}

// rrsigExpiration converts an RRSIG expiration field to absolute time using
// the same RFC 1982 serial arithmetic as ValidityPeriod.
func rrsigExpiration(sig *RRSIG, now time.Time) time.Time {
	utc := now.UTC().Unix()
	mode := (int64(sig.Expiration) - utc) / year68
	return time.Unix(int64(sig.Expiration)+mode*year68, 0).UTC()
}

// nsecDenial checks a proof made of NSEC records.
func nsecDenial(name string, qtype uint16, zone string, nsecs []*NSEC) (DenialKind, []RR, string) {
	name = CanonicalName(name)
	// NODATA at the exact name.
	for _, n := range nsecs {
		if !equal(CanonicalName(n.Hdr.Name), name) {
			continue
		}
		if nsecNoData(n.TypeBitMap, qtype) {
			return DenialNoData, []RR{n}, "NSEC at the queried name omits " + Type(qtype).String()
		}
		return DenialNone, nil, fmt.Sprintf("NSEC at %s does not prove NODATA for %s", name, Type(qtype))
	}

	cover := nsecCovering(name, nsecs)
	if cover == nil {
		return DenialNone, nil, fmt.Sprintf("no NSEC covers %s", name)
	}

	// A wildcard answer, if a wildcard exists, would have been returned
	// instead of a negative answer. Find the closest encloser that some
	// NSEC proves exists, then prove the wildcard below it does not exist.
	ce := closestEncloser(name, zone, func(anc string) bool { return nsecOwnerExists(anc, nsecs) })
	if ce == "" {
		return DenialNone, nil, fmt.Sprintf("no closest encloser proven for %s", name)
	}
	wildcard := wildcardName(ce)

	// Wildcard NODATA: the wildcard exists but omits the type.
	for _, n := range nsecs {
		if equal(CanonicalName(n.Hdr.Name), wildcard) && nsecNoData(n.TypeBitMap, qtype) {
			return DenialNoData, []RR{cover, n}, "wildcard NSEC omits " + Type(qtype).String()
		}
	}
	// NXDOMAIN: the wildcard itself is covered, so it does not exist.
	if wc := nsecCovering(wildcard, nsecs); wc != nil {
		return DenialNameError, []RR{cover, wc}, "NSEC covers the queried name and " + wildcard
	}
	return DenialNone, nil, fmt.Sprintf("no NSEC covers wildcard %s", wildcard)
}

// nsec3Denial checks a proof made of NSEC3 records.
func nsec3Denial(name string, qtype uint16, zone string, nsecs []*NSEC3) (DenialKind, []RR, string) {
	name = CanonicalName(name)
	for _, n := range nsecs {
		if n.Match(name) && nsecNoData(n.TypeBitMap, qtype) {
			return DenialNoData, []RR{n}, "NSEC3 at the queried name omits " + Type(qtype).String()
		}
	}

	var cover *NSEC3
	for _, n := range nsecs {
		if n.Cover(name) {
			cover = n
			break
		}
	}
	if cover == nil {
		return DenialNone, nil, fmt.Sprintf("no NSEC3 covers %s", name)
	}

	ce := closestEncloser(name, zone, func(anc string) bool {
		for _, n := range nsecs {
			if n.Match(anc) {
				return true
			}
		}
		return false
	})
	if ce == "" {
		return DenialNone, nil, fmt.Sprintf("no closest encloser proven for %s", name)
	}
	wildcard := wildcardName(ce)

	for _, n := range nsecs {
		if n.Match(wildcard) && nsecNoData(n.TypeBitMap, qtype) {
			return DenialNoData, []RR{cover, n}, "wildcard NSEC3 omits " + Type(qtype).String()
		}
	}
	for _, n := range nsecs {
		if n.Cover(wildcard) {
			return DenialNameError, []RR{cover, n}, "NSEC3 covers the queried name and " + wildcard
		}
	}
	return DenialNone, nil, fmt.Sprintf("no NSEC3 covers wildcard %s", wildcard)
}

// nsecNoData reports whether bitmap proves that qtype is absent. A CNAME at
// the name means some other type is the answer, and an apex NSEC (SOA bit set)
// cannot serve as the parent-side NODATA proof for a DS query.
func nsecNoData(bitmap []uint16, qtype uint16) bool {
	if bitmapHas(bitmap, qtype) {
		return false
	}
	if qtype != TypeCNAME && bitmapHas(bitmap, TypeCNAME) {
		return false
	}
	if qtype == TypeDS && bitmapHas(bitmap, TypeSOA) {
		return false
	}
	return true
}

func bitmapHas(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

func nsecOwnerExists(name string, nsecs []*NSEC) bool {
	for _, n := range nsecs {
		if equal(CanonicalName(n.Hdr.Name), name) {
			return true
		}
	}
	return false
}

func nsecCovering(name string, nsecs []*NSEC) *NSEC {
	for _, n := range nsecs {
		if nsecCovers(n.Hdr.Name, n.NextDomain, name) {
			return n
		}
	}
	return nil
}

// nsecCovers reports whether name falls strictly between owner and next in
// canonical order, taking the last NSEC of a zone (whose next name sorts
// before its owner) into account.
func nsecCovers(owner, next, name string) bool {
	o := canonicalNameCompare(owner, next)
	nOwner := canonicalNameCompare(name, owner)
	nNext := canonicalNameCompare(name, next)
	switch {
	case o < 0:
		return nOwner > 0 && nNext < 0
	case o > 0:
		return nOwner > 0 || nNext < 0
	default:
		return canonicalNameCompare(name, owner) != 0
	}
}

// closestEncloser returns the longest proper ancestor of name that exists,
// according to exists. The zone apex is always considered to exist, because it
// is the signer name of the verified records; that also bounds the search so a
// query above the zone cannot borrow an ancestor from another zone.
func closestEncloser(name string, zone string, exists func(string) bool) string {
	zone = CanonicalName(zone)
	for _, anc := range ancestors(name) {
		if zone != "" {
			if equal(anc, zone) {
				return anc
			}
			if !IsSubDomain(zone, anc) {
				continue
			}
		}
		if exists(anc) {
			return anc
		}
	}
	return ""
}

// ancestors returns the proper ancestors of name, from its parent up to the
// root, in canonical form.
func ancestors(name string) []string {
	labels := SplitDomainName(CanonicalName(name))
	var out []string
	for i := 1; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], ".")+".")
	}
	if len(out) == 0 || out[len(out)-1] != "." {
		out = append(out, ".")
	}
	return out
}

func wildcardName(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

// canonicalNameCompare compares two names in DNSSEC canonical order: labels
// are compared from the right as unsigned, case-folded octet strings
// (RFC 4034 6.1). Labels are compared in wire form so that escaped
// presentation characters compare by the octet they represent.
func canonicalNameCompare(a, b string) int {
	la := SplitDomainName(CanonicalName(a))
	lb := SplitDomainName(CanonicalName(b))
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 {
		if c := bytes.Compare(canonicalLabel(la[i]), canonicalLabel(lb[j])); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1
	default:
		return 1
	}
}

// canonicalLabel returns the wire octets of one label, lowercased. It falls
// back to the presentation bytes when the label cannot be packed.
func canonicalLabel(label string) []byte {
	buf := make([]byte, 256)
	off, err := PackDomainName(Fqdn(label), buf, 0, nil, false)
	if err != nil || off < 2 {
		return bytes.ToLower([]byte(label))
	}
	wire := buf[:off]
	// Strip the terminating root label and the one-byte label length.
	wire = wire[:len(wire)-1]
	if n := int(wire[0]); n+1 == len(wire) {
		wire = wire[1:]
	}
	return bytes.ToLower(wire)
}
