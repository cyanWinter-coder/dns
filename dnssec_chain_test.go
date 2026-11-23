package dns

import (
	"crypto"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// chainFixture is a self-contained signed zone used by the staged validation
// tests. It is built once per test with freshly generated keys.
type chainFixture struct {
	t       *testing.T
	zone    string
	key     *DNSKEY
	priv    crypto.Signer
	now     time.Time
	soa     *SOA
	soaSig  *RRSIG
	nsec    *NSEC
	nsecSig *RRSIG
}

func newChainFixture(t *testing.T, algorithm uint8, bits int, now time.Time) *chainFixture {
	t.Helper()
	f := &chainFixture{t: t, zone: "example.", now: now}
	f.key = &DNSKEY{
		Hdr:       RR_Header{Name: f.zone, Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
		Flags:     ZONE,
		Protocol:  3,
		Algorithm: algorithm,
	}
	priv, err := f.key.Generate(bits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f.priv = priv.(crypto.Signer)

	f.soa = &SOA{
		Hdr:     RR_Header{Name: f.zone, Rrtype: TypeSOA, Class: ClassINET, Ttl: 3600},
		Ns:      "ns." + f.zone,
		Mbox:    "hostmaster." + f.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	f.soaSig = f.sign(f.soa, algorithm, now)

	f.nsec = &NSEC{
		Hdr:        RR_Header{Name: "www." + f.zone, Rrtype: TypeNSEC, Class: ClassINET, Ttl: 300},
		NextDomain: "zzz." + f.zone,
		TypeBitMap: []uint16{TypeA, TypeRRSIG, TypeNSEC},
	}
	f.nsecSig = f.sign(f.nsec, algorithm, now)
	return f
}

// sign returns an RRSIG over one RR with a validity window around f.now.
func (f *chainFixture) sign(rr RR, algorithm uint8, now time.Time) *RRSIG {
	f.t.Helper()
	return f.signWindow(rr, algorithm, now.Add(-time.Hour), now.Add(time.Hour))
}

// signWindow returns an RRSIG over one RR with an explicit validity window.
func (f *chainFixture) signWindow(rr RR, algorithm uint8, inception, expiration time.Time) *RRSIG {
	f.t.Helper()
	sig := &RRSIG{
		Hdr:         RR_Header{Name: rr.Header().Name, Rrtype: TypeRRSIG, Class: rr.Header().Class, Ttl: rr.Header().Ttl},
		TypeCovered: rr.Header().Rrtype,
		Algorithm:   algorithm,
		Labels:      uint8(CountLabel(rr.Header().Name)),
		OrigTtl:     rr.Header().Ttl,
		Inception:   uint32(inception.Unix()),
		Expiration:  uint32(expiration.Unix()),
		KeyTag:      f.key.KeyTag(),
		SignerName:  f.zone,
	}
	if err := sig.Sign(f.priv, []RR{rr}); err != nil {
		f.t.Fatalf("sign %s: %v", rr, err)
	}
	return sig
}

func (f *chainFixture) ds() *DS {
	return f.key.ToDS(SHA256)
}

func (f *chainFixture) zoneMaterial() *Zone {
	return NewZone(f.zone, []*DS{f.ds()}, []*DNSKEY{f.key}, []*RRSIG{f.sign(f.key, f.key.Algorithm, f.now)})
}

func TestValidationResultStagedPositive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	res := v.ValidateAt(ChainRequest{
		Name:             f.zone,
		Type:             TypeSOA,
		Zone:             f.zoneMaterial(),
		Answer:           []RR{f.soa},
		AnswerSignatures: []*RRSIG{f.soaSig},
	}, now)

	if !res.Secure() {
		t.Fatalf("expected secure chain, got %s", res)
	}
	if res.FailedStage != 0 {
		t.Fatalf("unexpected failure stage %s", res.FailedStage)
	}
	for _, s := range []ValidationStage{StageDS, StageDNSKEY, StageRRSIG} {
		if got := res.Stage(s).Status; got != StageSecure {
			t.Errorf("stage %s: status %s, want secure", s, got)
		}
	}
	if got := res.Stage(StageNSEC).Status; got != StageSkipped {
		t.Errorf("NSEC stage: status %s, want skipped for a positive answer", got)
	}
	if len(res.TrustedKeys()) != 1 {
		t.Errorf("expected one trusted key, got %d", len(res.TrustedKeys()))
	}
}

func TestValidationResultFirstFailureIsStable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	// Break the DS: no DNSKEY matches it.
	badDS := f.ds()
	badDS.Digest = "00" + badDS.Digest[2:]
	zone := NewZone(f.zone, []*DS{badDS}, []*DNSKEY{f.key}, []*RRSIG{f.sign(f.key, f.key.Algorithm, now)})
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)

	if res.FailedStage != StageDS {
		t.Fatalf("failed stage %s, want DS", res.FailedStage)
	}
	if !errors.Is(res.Err(), ErrDSMismatch) {
		t.Fatalf("error %v, want ErrDSMismatch", res.Err())
	}
	if got := res.Stage(StageDNSKEY).Status; got != StageNotRun {
		t.Errorf("DNSKEY stage ran after DS failure: %s", got)
	}
	if res.Secure() || res.Insecure() {
		t.Errorf("expected bogus result, got %s", res)
	}
	want := "dnssec bogus DS=failed(dns: no DNSKEY matches the DS RRset): no DNSKEY of example. matches the DS RRset " +
		"DNSKEY=not-run RRSIG=not-run NSEC=not-run"
	if got := res.String(); got != want {
		t.Errorf("result string\n got %q\nwant %q", got, want)
	}
}

func TestValidationResultDNSKEYStage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	// DS matches, but the DNSKEY RRset is not signed by the DS-matched key.
	other := &DNSKEY{Hdr: RR_Header{Name: f.zone, Rrtype: TypeDNSKEY, Class: ClassINET},
		Flags: ZONE, Protocol: 3, Algorithm: ECDSAP256SHA256}
	if _, err := other.Generate(256); err != nil {
		t.Fatal(err)
	}
	zone := NewZone(f.zone, []*DS{f.ds()}, []*DNSKEY{f.key}, []*RRSIG{f.sign(other, other.Algorithm, now)})
	// f.sign uses f.key's tag; force the other key's tag instead.
	sig := f.sign(f.key, f.key.Algorithm, now)
	sig.KeyTag = other.KeyTag()
	zone.DNSKEYSignatures = []*RRSIG{sig}

	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)

	if res.FailedStage != StageDNSKEY {
		t.Fatalf("failed stage %s, want DNSKEY (%s)", res.FailedStage, res)
	}
	if got := res.Stage(StageDS).Status; got != StageSecure {
		t.Errorf("DS stage %s, want secure", got)
	}
}

func TestValidationResultRRSIGStage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	// Signature over the SOA valid, but the answer was tampered with.
	tampered := f.soa.copy().(*SOA)
	tampered.Serial++

	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: f.zoneMaterial(),
		Answer: []RR{tampered}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)

	if res.FailedStage != StageRRSIG {
		t.Fatalf("failed stage %s, want RRSIG (%s)", res.FailedStage, res)
	}
	if !errors.Is(res.Err(), ErrSig) {
		t.Fatalf("error %v, want ErrSig", res.Err())
	}
}

func TestValidationResultNSECStage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	// NSEC is correctly signed but does not cover the queried name.
	res := v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: []RR{f.nsec}, DenialSignatures: []*RRSIG{f.nsecSig}}, now)

	if res.FailedStage != StageNSEC {
		t.Fatalf("failed stage %s, want NSEC (%s)", res.FailedStage, res)
	}
	if !errors.Is(res.Err(), ErrDenial) {
		t.Fatalf("error %v, want ErrDenial", res.Err())
	}
	if got := res.Stage(StageRRSIG).Status; got != StageSkipped {
		t.Errorf("RRSIG stage %s, want skipped for a negative answer", got)
	}
}

func TestValidationInsecureDelegation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator()

	zone := NewZone(f.zone, nil, []*DNSKEY{f.key}, []*RRSIG{f.sign(f.key, f.key.Algorithm, now)})
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)

	if !res.Insecure() {
		t.Fatalf("expected insecure delegation, got %s", res)
	}
	if res.Stage(StageDS).Status != StageInsecure {
		t.Errorf("DS stage %s, want insecure", res.Stage(StageDS).Status)
	}

	// With no keys and no DS at all it is still insecure, not bogus.
	empty := NewZone(f.zone, nil, nil, nil)
	if res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: empty}, now); !res.Insecure() {
		t.Fatalf("expected insecure, got %s", res)
	}
}

func TestValidationMissingZone(t *testing.T) {
	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: "example."}, time.Unix(1, 0))
	if res.FailedStage != StageDS || !errors.Is(res.Err(), ErrNoZone) {
		t.Fatalf("got %s (%v), want DS/ErrNoZone", res, res.Err())
	}
}

// TestValidationKeyRolloverSameTag covers requirement 2: two keys loaded in
// either order, both carrying the same key tag and algorithm, must both stay
// usable. Neither may overwrite the other.
func TestValidationKeyRolloverSameTag(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	// Find two ECDSA keys with the same key tag. The tag is a 16-bit
	// quantity, so a few hundred keys make a collision very likely.
	type keypair struct {
		key  *DNSKEY
		priv crypto.Signer
	}
	seen := make(map[uint16]keypair)
	var a, b keypair
	found := false
	for i := 0; i < 5000 && !found; i++ {
		k := &DNSKEY{
			Hdr:       RR_Header{Name: "example.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 3600},
			Flags:     ZONE,
			Protocol:  3,
			Algorithm: ECDSAP256SHA256,
		}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		kp := keypair{k, priv.(crypto.Signer)}
		if other, ok := seen[k.KeyTag()]; ok {
			a, b = other, kp
			found = true
			break
		}
		seen[k.KeyTag()] = kp
	}
	if !found {
		t.Skip("no key tag collision found")
	}
	if a.key.PublicKey == b.key.PublicKey {
		t.Fatal("colliding keys have identical material")
	}

	sign := func(f *chainFixture, kp keypair) *RRSIG {
		sig := &RRSIG{
			Hdr:         RR_Header{Name: f.soa.Hdr.Name, Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600},
			TypeCovered: TypeSOA,
			Algorithm:   ECDSAP256SHA256,
			Labels:      uint8(CountLabel(f.soa.Hdr.Name)),
			OrigTtl:     f.soa.Hdr.Ttl,
			Inception:   uint32(now.Add(-time.Hour).Unix()),
			Expiration:  uint32(now.Add(time.Hour).Unix()),
			KeyTag:      kp.key.KeyTag(),
			SignerName:  f.zone,
		}
		if err := sig.Sign(kp.priv, []RR{f.soa}); err != nil {
			t.Fatal(err)
		}
		return sig
	}

	f := &chainFixture{t: t, zone: "example.", now: now, soa: &SOA{
		Hdr:     RR_Header{Name: "example.", Rrtype: TypeSOA, Class: ClassINET, Ttl: 3600},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}}
	// The DNSKEY RRset signature only needs the fixture key slot to
	// carry the right algorithm; build it manually for a colliding key.
	signKeys := func(kp keypair) *RRSIG {
		sig := &RRSIG{
			Hdr:         RR_Header{Name: "example.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 3600},
			TypeCovered: TypeDNSKEY,
			Algorithm:   ECDSAP256SHA256,
			Labels:      1,
			OrigTtl:     3600,
			Inception:   uint32(now.Add(-time.Hour).Unix()),
			Expiration:  uint32(now.Add(time.Hour).Unix()),
			KeyTag:      kp.key.KeyTag(),
			SignerName:  "example.",
		}
		if err := sig.Sign(kp.priv, []RR{a.key, b.key}); err != nil {
			t.Fatal(err)
		}
		return sig
	}

	zone := NewZone("example.", []*DS{a.key.ToDS(SHA256), b.key.ToDS(SHA256)},
		[]*DNSKEY{a.key, b.key}, []*RRSIG{signKeys(a), signKeys(b)})

	if got := zone.KeySet().Len(); got != 2 {
		t.Fatalf("key set length %d, want 2 (a key overwrote another)", got)
	}
	if got := zone.KeySet().Candidates(a.key.KeyTag(), ECDSAP256SHA256, "example."); len(got) != 2 {
		t.Fatalf("candidates for the shared key tag = %d, want both keys", len(got))
	}

	v := NewValidator()
	for name, kp := range map[string]keypair{"first-loaded": a, "last-loaded": b} {
		res := v.ValidateAt(ChainRequest{Name: "example.", Type: TypeSOA, Zone: zone,
			Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{sign(f, kp)}}, now)
		if !res.Secure() {
			t.Errorf("signature of the %s key rejected during rollover: %s", name, res)
		}
	}
	// The same RRset signed by both keys validates too.
	res := v.ValidateAt(ChainRequest{Name: "example.", Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{sign(f, a), sign(f, b)}}, now)
	if !res.Secure() {
		t.Fatalf("dual-signed rollover RRset rejected: %s", res)
	}
}

// TestValidationKeyRolloverUsesValidityPeriod covers requirement 2's time
// component: an expired old signature must be ignored in favour of a valid
// one, and the result must be reproducible for a fixed time.
func TestValidationKeyRolloverUsesValidityPeriod(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	// An expired signature and a current signature over the same RRset.
	expired := f.signWindow(f.soa, ECDSAP256SHA256, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	current := f.sign(f.soa, ECDSAP256SHA256, now)

	zone := f.zoneMaterial()
	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{expired, current}}, now)
	if !res.Secure() {
		t.Fatalf("expected the current signature to be used: %s", res)
	}

	// Only the expired signature present: a transient failure, not bogus.
	res = v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{expired}}, now)
	if res.FailedStage != StageRRSIG {
		t.Fatalf("failed stage %s, want RRSIG", res.FailedStage)
	}
	if !res.Temporary() || !IsTransient(res.Err()) {
		t.Fatalf("expected a transient failure, got %v temporary=%v", res.Err(), res.Temporary())
	}

	// Before inception is transient as well.
	future := f.signWindow(f.soa, ECDSAP256SHA256, now.Add(2*time.Hour), now.Add(3*time.Hour))
	early := now.Add(-time.Hour)
	res = v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{future}}, early)
	if !res.Temporary() {
		t.Fatalf("signature before inception should be transient: %v", res.Err())
	}
}

// denialFixture builds a realistic NXDOMAIN proof for "other.example.":
//
//	example. -> ns.example.       proves the closest encloser exists and,
//	                              since *.example. sorts between them, also
//	                              proves the wildcard does not exist
//	ns.example. -> www.example.   covers the queried name
func denialFixture(t *testing.T, f *chainFixture, now time.Time) ([]RR, []*RRSIG) {
	t.Helper()
	apex := &NSEC{
		Hdr:        RR_Header{Name: f.zone, Rrtype: TypeNSEC, Class: ClassINET, Ttl: 300},
		NextDomain: "ns." + f.zone,
		TypeBitMap: []uint16{TypeNS, TypeSOA, TypeRRSIG, TypeNSEC, TypeDNSKEY},
	}
	cover := &NSEC{
		Hdr:        RR_Header{Name: "ns." + f.zone, Rrtype: TypeNSEC, Class: ClassINET, Ttl: 300},
		NextDomain: "www." + f.zone,
		TypeBitMap: []uint16{TypeA, TypeRRSIG, TypeNSEC},
	}
	return []RR{apex, cover}, []*RRSIG{
		f.sign(apex, f.key.Algorithm, now),
		f.sign(cover, f.key.Algorithm, now),
	}
}

// nsecOrderSanity checks the canonical ordering assumptions the fixtures rely
// on: "*.example." sorts between "example." and "ns.example.", and
// "other.example." between "ns.example." and "www.example.".
func TestCanonicalNameOrder(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"example.", "www.example.", -1},
		{"*.example.", "www.example.", -1},
		{"example.", "*.example.", -1},
		{"*.example.", "ns.example.", -1},
		{"ns.example.", "other.example.", -1},
		{"other.example.", "www.example.", -1},
		{"www.example.", "zzz.example.", -1},
		{"example.", "example.", 0},
	}
	for _, c := range cases {
		got := canonicalNameCompare(c.a, c.b)
		if got != c.want {
			t.Errorf("compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if !nsecCovers("example.", "ns.example.", "*.example.") {
		t.Error("example. -> ns.example. should cover *.example.")
	}
	if !nsecCovers("ns.example.", "www.example.", "other.example.") {
		t.Error("ns.example. -> www.example. should cover other.example.")
	}
}

func TestValidationNXDOMAINProven(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	rrs, sigs := denialFixture(t, f, now)

	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: rrs, DenialSignatures: sigs}, now)

	if !res.Secure() {
		t.Fatalf("expected secure NXDOMAIN proof, got %s", res)
	}
	if !res.Denied() || res.Proof() == nil {
		t.Fatal("expected a denial proof")
	}
	if got := res.Proof().Kind; got != DenialNameError {
		t.Fatalf("denial kind %s, want NXDOMAIN", got)
	}
}

func TestValidationNODATAProven(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	apex := &NSEC{
		Hdr:        RR_Header{Name: f.zone, Rrtype: TypeNSEC, Class: ClassINET, Ttl: 300},
		NextDomain: "www." + f.zone,
		TypeBitMap: []uint16{TypeSOA, TypeRRSIG, TypeNSEC},
	}
	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeMX, Zone: f.zoneMaterial(),
		Denial: []RR{apex}, DenialSignatures: []*RRSIG{f.sign(apex, f.key.Algorithm, now)}}, now)

	if !res.Secure() || !res.Denied() {
		t.Fatalf("expected secure NODATA, got %s", res)
	}
	if got := res.Proof().Kind; got != DenialNoData {
		t.Fatalf("denial kind %s, want NODATA", got)
	}
}

// TestValidationNSEC3NXDOMAIN proves NXDOMAIN with NSEC3. One NSEC3 matches
// the closest encloser (the apex) and, because its successor is the NS
// record's hash, also covers both the queried name's hash and the wildcard's
// hash.
func TestValidationNSEC3NXDOMAIN(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	if canonicalNameCompare("*.example.", "example.") <= 0 {
		t.Fatalf("fixture assumes the wildcard sorts after the apex")
	}
	apexHash := HashName(f.zone, SHA1, 0, "")
	nsHash := HashName("ns."+f.zone, SHA1, 0, "")
	otherHash := HashName("other."+f.zone, SHA1, 0, "")
	wildcardHash := HashName("*."+f.zone, SHA1, 0, "")
	// The proof depends on apex < other's hash < ns's hash, with the
	// wildcard's hash in the same interval.
	for _, h := range []struct {
		name string
		hash string
	}{{"apex", apexHash}, {"other", otherHash}, {"wildcard", wildcardHash}, {"ns", nsHash}} {
		if h.hash == "" {
			t.Fatalf("hash of %s is empty", h.name)
		}
	}
	if !(apexHash < otherHash && otherHash < nsHash) {
		t.Skipf("hash order %s/%s/%s does not form a useful fixture", apexHash, otherHash, nsHash)
	}

	nsec3 := &NSEC3{
		Hdr:        RR_Header{Name: apexHash + "." + f.zone, Rrtype: TypeNSEC3, Class: ClassINET, Ttl: 300},
		Hash:       SHA1,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: nsHash,
		TypeBitMap: []uint16{TypeNS, TypeSOA, TypeRRSIG, TypeDNSKEY},
	}
	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: []RR{nsec3}, DenialSignatures: []*RRSIG{f.sign(nsec3, f.key.Algorithm, now)}}, now)
	if !res.Secure() || !res.Denied() {
		t.Fatalf("expected secure NSEC3 NXDOMAIN, got %s", res)
	}
	if got := res.Proof().Kind; got != DenialNameError {
		t.Fatalf("denial kind %s, want NXDOMAIN", got)
	}

	// An NSEC3 that matches the name but lists the queried type must not
	// be accepted as NODATA.
	nodata := &NSEC3{
		Hdr:        RR_Header{Name: otherHash + "." + f.zone, Rrtype: TypeNSEC3, Class: ClassINET, Ttl: 300},
		Hash:       SHA1,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: nsHash,
		TypeBitMap: []uint16{TypeA, TypeRRSIG},
	}
	res = v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: []RR{nodata}, DenialSignatures: []*RRSIG{f.sign(nodata, f.key.Algorithm, now)}}, now)
	if res.Secure() {
		t.Fatalf("NSEC3 listing the queried type was accepted: %s", res)
	}
	if !errors.Is(res.Err(), ErrDenial) {
		t.Fatalf("error %v, want ErrDenial", res.Err())
	}
}

// TestValidationNSEC3NODATA proves NODATA with an NSEC3 that matches the name
// and omits the queried type.
func TestValidationNSEC3NODATA(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	wwwHash := HashName("www."+f.zone, SHA1, 0, "")
	nsec3 := &NSEC3{
		Hdr:        RR_Header{Name: wwwHash + "." + f.zone, Rrtype: TypeNSEC3, Class: ClassINET, Ttl: 300},
		Hash:       SHA1,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: HashName("zzz."+f.zone, SHA1, 0, ""),
		TypeBitMap: []uint16{TypeA, TypeRRSIG},
	}
	v := NewValidator()
	res := v.ValidateAt(ChainRequest{Name: "www." + f.zone, Type: TypeAAAA, Zone: f.zoneMaterial(),
		Denial: []RR{nsec3}, DenialSignatures: []*RRSIG{f.sign(nsec3, f.key.Algorithm, now)}}, now)
	if !res.Secure() || !res.Denied() {
		t.Fatalf("expected secure NSEC3 NODATA, got %s", res)
	}
	if got := res.Proof().Kind; got != DenialNoData {
		t.Fatalf("denial kind %s, want NODATA", got)
	}
}

// TestNegativeCacheOnlyVerified covers requirement 3.
func TestNegativeCacheOnlyVerified(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	rrs, sigs := denialFixture(t, f, now)

	cache := NewNegativeCache()
	v := NewValidator(WithNegativeCache(cache))

	// A transient failure must not populate the cache. The NSEC records
	// are signed by the zone key, but with a window that has not started
	// yet, so the stage fails transiently rather than cryptographically.
	transientSigs := []*RRSIG{
		f.signWindow(rrs[0], f.key.Algorithm, now.Add(time.Hour), now.Add(2*time.Hour)),
		f.signWindow(rrs[1], f.key.Algorithm, now.Add(time.Hour), now.Add(2*time.Hour)),
	}
	res := v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: rrs, DenialSignatures: transientSigs}, now)
	if !res.Temporary() {
		t.Fatalf("expected transient NSEC failure, got %s", res)
	}
	if cache.Len() != 0 {
		t.Fatalf("transient failure entered the negative cache (%d entries)", cache.Len())
	}

	// A correctly signed proof is cached, and then served without
	// revalidating the chain.
	res = v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: rrs, DenialSignatures: sigs}, now)
	if !res.Secure() || !res.Denied() {
		t.Fatalf("expected secure denial, got %s", res)
	}
	if cache.Len() != 1 {
		t.Fatalf("verified proof not cached (%d entries)", cache.Len())
	}
	res = v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA}, now)
	if !res.Secure() || !res.Cached() || !res.Denied() {
		t.Fatalf("expected a cached denial, got %s cached=%v", res, res.Cached())
	}

	// A bogus proof is never cached.
	if _, ok := cache.Get("missing."+f.zone, TypeA, now); ok {
		t.Fatal("unexpected cache hit for a different name")
	}
	// An NXDOMAIN entry answers a query for any type of the same name.
	if _, ok := cache.Get("other."+f.zone, TypeAAAA, now); !ok {
		t.Fatal("NXDOMAIN proof did not cover another query type")
	}
	// The bounded closest encloser never reaches above the zone apex.
	if ce := closestEncloser("deep.other."+f.zone, f.zone, func(string) bool { return false }); ce != f.zone {
		t.Fatalf("closest encloser %q, want the apex %q", ce, f.zone)
	}
	if ce := closestEncloser("elsewhere.", f.zone, func(string) bool { return true }); ce != "" {
		t.Fatalf("closest encloser %q reached above the zone apex", ce)
	}
}

func TestNegativeCacheRejectsUnverifiedProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cache := NewNegativeCache()
	proof := &DenialProof{
		Kind:    DenialNameError,
		Name:    "other.example.",
		TTL:     300,
		Records: []RR{&NSEC{Hdr: RR_Header{Name: "example.", Rrtype: TypeNSEC, Class: ClassINET}}},
	}
	if err := cache.Put(proof, now.Add(time.Minute), now); err == nil {
		t.Fatal("hand-built, unverified proof was accepted by the cache")
	}
	if err := cache.Put(nil, now.Add(time.Minute), now); err == nil {
		t.Fatal("nil proof accepted")
	}
}

func TestNegativeCacheExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cache := NewNegativeCache()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	rrs, sigs := denialFixture(t, f, now)
	v := NewValidator(WithNegativeCache(cache))

	v.ValidateAt(ChainRequest{Name: "other." + f.zone, Type: TypeA, Zone: f.zoneMaterial(),
		Denial: rrs, DenialSignatures: sigs}, now)
	if cache.Len() != 1 {
		t.Fatal("proof not cached")
	}
	// The fixture signatures expire one hour after now, and the TTL is
	// 300s, so the entry must be gone well after that.
	if got := cache.Purge(now.Add(2 * time.Hour)); got != 1 {
		t.Fatalf("purged %d entries, want 1", got)
	}
	if _, ok := cache.Get("other."+f.zone, TypeA, now.Add(2*time.Hour)); ok {
		t.Fatal("expired proof still served")
	}
}

// TestValidationConcurrentIsolation covers requirement 4: concurrent
// validations share the immutable Zone but never share error state.
func TestValidationConcurrentIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	zone := f.zoneMaterial()
	v := NewValidator()

	tampered := f.soa.copy().(*SOA)
	tampered.Serial++

	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
				Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}
			if i%2 == 1 {
				req.Answer = []RR{tampered}
			}
			res := v.ValidateAt(req, now)
			if i%2 == 0 && !res.Secure() {
				errs[i] = fmt.Errorf("good request %d failed: %s", i, res)
			}
			if i%2 == 1 && (res.Secure() || res.FailedStage != StageRRSIG) {
				errs[i] = fmt.Errorf("tampered request %d not rejected at RRSIG: %s", i, res)
			}
			// Every result string must match the expected verdict for
			// its own request, proving no state leaked across goroutines.
			if i%2 == 0 && res.Stage(StageDS).Status != StageSecure {
				errs[i] = fmt.Errorf("good request %d saw DS %s", i, res.Stage(StageDS).Status)
			}
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// TestValidationIsRepeatable covers requirement 5: the same request and time
// always produce the same staged result, including the operator-facing string.
func TestValidationIsRepeatable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	zone := f.zoneMaterial()
	req := ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}
	v := NewValidator()

	first := v.ValidateAt(req, now).String()
	for i := 0; i < 5; i++ {
		if got := v.ValidateAt(req, now).String(); got != first {
			t.Fatalf("result not repeatable:\n got %q\nwant %q", got, first)
		}
	}

	// A bogus chain is repeatable as well.
	bad := ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.sign(f.soa, ECDSAP256SHA256, now)}}
	bad.AnswerSignatures[0].Signature = "AAAA"
	firstBad := v.ValidateAt(bad, now).String()
	for i := 0; i < 5; i++ {
		if got := v.ValidateAt(bad, now).String(); got != firstBad {
			t.Fatalf("bogus result not repeatable:\n got %q\nwant %q", got, firstBad)
		}
	}
}

// TestValidationClockIsUsed checks that Validate honours WithValidationClock.
func TestValidationClockIsUsed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)
	v := NewValidator(WithValidationClock(func() time.Time { return now }))
	res := v.Validate(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: f.zoneMaterial(),
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}})
	if !res.Secure() {
		t.Fatalf("clock-driven validation failed: %s", res)
	}
	if !res.Time().Equal(now) {
		t.Errorf("result time %s, want %s", res.Time(), now)
	}
}

// TestExistingDNSSECEntrypointsUnchanged covers requirement 5: the existing
// RRSIG.Verify behavior and error values must be preserved exactly.
func TestExistingDNSSECEntrypointsUnchanged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	if err := f.soaSig.Verify(f.key, []RR{f.soa}); err != nil {
		t.Fatalf("RRSIG.Verify rejected a good signature: %v", err)
	}
	if got := f.soaSig.Verify(f.key, []RR{f.soa.copy()}); got != nil {
		_ = got
	}

	bad := f.soa.copy().(*SOA)
	bad.Serial++
	if err := f.soaSig.Verify(f.key, []RR{bad}); err != ErrSig {
		t.Fatalf("RRSIG.Verify error %v, want ErrSig", err)
	}

	mismatch := f.soaSig.copy().(*RRSIG)
	mismatch.KeyTag++
	if err := mismatch.Verify(f.key, []RR{f.soa}); err != ErrKey {
		t.Fatalf("key tag mismatch error %v, want ErrKey", err)
	}
	if !f.soaSig.ValidityPeriod(now) {
		t.Fatal("ValidityPeriod rejected a signature valid at the evaluation time")
	}
}

// TestTrustAnchorScope checks that a configured trust anchor only applies to
// its own zone: another zone without a DS stays insecure.
func TestTrustAnchorScope(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	// The anchor belongs to f.zone.
	v := NewValidator(WithTrustAnchors(f.ds()))
	zone := NewZone(f.zone, nil, []*DNSKEY{f.key}, []*RRSIG{f.sign(f.key, f.key.Algorithm, now)})
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeSOA, Zone: zone,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)
	if !res.Secure() {
		t.Fatalf("trust anchor not applied to its own zone: %s", res)
	}

	// A different zone with the same key material must not pick up the
	// anchor: its delegation is insecure, not bogus.
	other := NewZone("other.", nil, []*DNSKEY{f.key}, []*RRSIG{f.sign(f.key, f.key.Algorithm, now)})
	res = v.ValidateAt(ChainRequest{Name: "other.", Type: TypeSOA, Zone: other,
		Answer: []RR{f.soa}, AnswerSignatures: []*RRSIG{f.soaSig}}, now)
	if !res.Insecure() || res.Secure() {
		t.Fatalf("trust anchor leaked across zones: %s", res)
	}
}

// TestNegativeCacheProofTTLBoundedBySignature checks that a proof is not
// cached past the expiry of the signature that verified it.
func TestNegativeCacheProofTTLBoundedBySignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	f := newChainFixture(t, ECDSAP256SHA256, 256, now)

	apex := &NSEC{
		Hdr:        RR_Header{Name: f.zone, Rrtype: TypeNSEC, Class: ClassINET, Ttl: 3600},
		NextDomain: "ns." + f.zone,
		TypeBitMap: []uint16{TypeNS, TypeSOA, TypeRRSIG, TypeNSEC},
	}
	// The signature expires in 120 seconds; the record TTL is 3600, so the
	// proof may live for at most 120 seconds.
	sig := f.signWindow(apex, f.key.Algorithm, now.Add(-time.Hour), now.Add(120*time.Second))
	cache := NewNegativeCache()
	v := NewValidator(WithNegativeCache(cache))
	res := v.ValidateAt(ChainRequest{Name: f.zone, Type: TypeMX, Zone: f.zoneMaterial(),
		Denial: []RR{apex}, DenialSignatures: []*RRSIG{sig}}, now)
	if !res.Secure() {
		t.Fatalf("expected secure NODATA, got %s", res)
	}
	if got := res.Proof().TTL; got != 120 {
		t.Fatalf("proof TTL %d, want 120 (bounded by the signature)", got)
	}
	if _, ok := cache.Get(f.zone, TypeMX, now.Add(121*time.Second)); ok {
		t.Fatal("proof served past its signature expiry")
	}
}
