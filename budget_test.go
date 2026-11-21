package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// budgetTestMsg returns a compressible message with n answer records.
func budgetTestMsg(n int) *Msg {
	m := new(Msg)
	m.Compress = true
	m.SetQuestion("www.example.org.", TypeA)
	for i := 0; i < n; i++ {
		m.Answer = append(m.Answer, &A{
			Hdr: RR_Header{Name: "www.example.org.", Rrtype: TypeA, Class: ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1").To4(),
		})
	}
	return m
}

// TestBudgetPackBoundary checks that a budget exactly equal to the packed
// size succeeds and that one byte less fails with ErrBudget and no message.
func TestBudgetPackBoundary(t *testing.T) {
	for _, compress := range []bool{false, true} {
		m := budgetTestMsg(10)
		m.Compress = compress

		full, err := m.Pack()
		if err != nil {
			t.Fatalf("compress=%v: Pack failed: %v", compress, err)
		}
		n := len(full)

		got, err := m.PackWithBudget(Budget{MaxBytes: n})
		if err != nil {
			t.Fatalf("compress=%v: PackWithBudget(MaxBytes=%d) failed: %v", compress, n, err)
		}
		if !bytes.Equal(got, full) {
			t.Fatalf("compress=%v: budgeted pack differs from Pack", compress)
		}

		short, err := m.PackWithBudget(Budget{MaxBytes: n - 1})
		if err == nil {
			t.Fatalf("compress=%v: PackWithBudget(MaxBytes=%d) unexpectedly succeeded", compress, n-1)
		}
		if !errors.Is(err, ErrBudget) {
			t.Fatalf("compress=%v: expected ErrBudget, got %v", compress, err)
		}
		if short != nil {
			t.Fatalf("compress=%v: expected nil message on budget failure, got %d bytes", compress, len(short))
		}
	}
}

// TestBudgetPackTinyBudget checks that a budget too small for even the
// header fails with ErrBudget before writing anything.
func TestBudgetPackTinyBudget(t *testing.T) {
	m := budgetTestMsg(1)
	for _, size := range []int{1, headerSize - 1, headerSize} {
		msg, err := m.PackWithBudget(Budget{MaxBytes: size})
		if !errors.Is(err, ErrBudget) {
			t.Fatalf("MaxBytes=%d: expected ErrBudget, got msg=%d bytes, err=%v", size, len(msg), err)
		}
		if msg != nil {
			t.Fatalf("MaxBytes=%d: expected nil message, got %d bytes", size, len(msg))
		}
	}
}

// TestBudgetPackStable checks that repeated packing with the same budget
// is deterministic and identical to Pack and PackBuffer.
func TestBudgetPackStable(t *testing.T) {
	m := budgetTestMsg(10)

	want, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	prev, err := m.PackWithBudget(Budget{MaxBytes: MaxMsgSize})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prev, want) {
		t.Fatal("PackWithBudget differs from Pack")
	}
	for i := 0; i < 10; i++ {
		got, err := m.PackWithBudget(Budget{MaxBytes: MaxMsgSize})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, prev) {
			t.Fatalf("iteration %d: packing not stable", i)
		}
		prev = got
	}

	// PackBuffer with a caller buffer must produce the same bytes.
	buf := make([]byte, MaxMsgSize)
	got, err := m.PackBuffer(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("PackBuffer differs from Pack")
	}
}

// TestBudgetPackBufferNoOverwrite checks that a budgeted pack into a
// caller-supplied buffer never writes beyond the budget.
func TestBudgetPackBufferNoOverwrite(t *testing.T) {
	m := budgetTestMsg(10)
	full, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	n := len(full)

	buf := bytes.Repeat([]byte{0xAB}, 2*n)
	got, err := m.PackBufferWithBudget(buf, Budget{MaxBytes: n})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatal("budgeted PackBuffer differs from Pack")
	}
	if len(got) > n {
		t.Fatalf("returned %d bytes, budget allows %d", len(got), n)
	}
	for i, b := range buf[n:] {
		if b != 0xAB {
			t.Fatalf("buffer overwritten past budget at offset %d", n+i)
		}
	}
}

// TestBudgetUnpackPointerLoop checks that a compression pointer loop is
// rejected with an ErrBudget-wrapped error under a caller budget, while
// the default entry point keeps its historical error.
func TestBudgetUnpackPointerLoop(t *testing.T) {
	// The name at offset 0 is a pointer to itself.
	msg := []byte{0xC0, 0x00}

	_, _, err := UnpackDomainNameWithBudget(msg, 0, Budget{MaxPointers: 4})
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("expected ErrBudget, got %v", err)
	}
	if !errors.Is(err, errTooManyPointers) {
		t.Fatalf("expected too-many-pointers cause, got %v", err)
	}

	_, _, err = UnpackDomainName(msg, 0)
	if err == nil || err.Error() != "dns: too many compression pointers" {
		t.Fatalf("default unpack error changed: %v", err)
	}
	if errors.Is(err, ErrBudget) {
		t.Fatal("default unpack must not report ErrBudget")
	}
}

// TestBudgetUnpackDeepChain checks that a long but loop-free pointer
// chain is allowed up to the declared budget and rejected beyond it.
func TestBudgetUnpackDeepChain(t *testing.T) {
	const n = 8
	msg := make([]byte, 0, 2*n+3)
	for i := 0; i < n; i++ {
		msg = append(msg, 0xC0, byte(2*(i+1)))
	}
	msg = append(msg, 1, 'a', 0)

	name, _, err := UnpackDomainNameWithBudget(msg, 0, Budget{MaxPointers: n})
	if err != nil {
		t.Fatalf("chain of %d pointers within budget failed: %v", n, err)
	}
	if name != "a." {
		t.Fatalf("expected a., got %q", name)
	}

	_, _, err = UnpackDomainNameWithBudget(msg, 0, Budget{MaxPointers: n - 1})
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("expected ErrBudget for chain exceeding budget, got %v", err)
	}
}

// TestBudgetUnpackLongName checks name expansion length budgets: a name
// exceeding the wire limit fails, and a caller-tightened budget fails
// earlier, both recognizably.
func TestBudgetUnpackLongName(t *testing.T) {
	// 4 labels of 63 octets plus the root label: 257 wire octets.
	var wire []byte
	for i := 0; i < 4; i++ {
		wire = append(wire, 63)
		wire = append(wire, bytes.Repeat([]byte{'a'}, 63)...)
	}
	wire = append(wire, 0)

	_, _, err := UnpackDomainNameWithBudget(wire, 0, Budget{})
	if !errors.Is(err, ErrBudget) || !errors.Is(err, ErrLongDomain) {
		t.Fatalf("expected ErrBudget wrapping ErrLongDomain, got %v", err)
	}

	_, _, err = UnpackDomainNameWithBudget(wire, 0, Budget{MaxNameLength: 64})
	if !errors.Is(err, ErrBudget) || !errors.Is(err, ErrLongDomain) {
		t.Fatalf("expected ErrBudget wrapping ErrLongDomain, got %v", err)
	}

	// The default entry point keeps returning plain ErrLongDomain.
	_, _, err = UnpackDomainName(wire, 0)
	if !errors.Is(err, ErrLongDomain) {
		t.Fatalf("expected ErrLongDomain, got %v", err)
	}
	if errors.Is(err, ErrBudget) {
		t.Fatal("default unpack must not report ErrBudget")
	}
}

// TestBudgetLegalLongName checks that the largest legal domain name
// (255 wire octets) still packs and unpacks, with and without budgets.
func TestBudgetLegalLongName(t *testing.T) {
	var name strings.Builder
	var wire []byte
	for _, l := range []int{63, 63, 63, 61} {
		label := strings.Repeat("a", l)
		wire = append(wire, byte(l))
		wire = append(wire, label...)
		name.WriteString(label)
		name.WriteByte('.')
	}
	wire = append(wire, 0)

	got, _, err := UnpackDomainName(wire, 0)
	if err != nil {
		t.Fatalf("legal long name failed to unpack: %v", err)
	}
	if got != name.String() {
		t.Fatalf("expected %q, got %q", name.String(), got)
	}

	if _, _, err := UnpackDomainNameWithBudget(wire, 0, Budget{MaxNameLength: maxDomainNameWireOctets}); err != nil {
		t.Fatalf("legal long name failed with explicit budget: %v", err)
	}
	if _, _, err := UnpackDomainNameWithBudget(wire, 0, Budget{MaxNameLength: maxDomainNameWireOctets - 1}); !errors.Is(err, ErrBudget) {
		t.Fatalf("expected ErrBudget with tightened limit, got %v", err)
	}

	// The same name must pack into a message, compressed or not.
	for _, compress := range []bool{false, true} {
		m := new(Msg)
		m.Compress = compress
		m.SetQuestion(name.String(), TypeA)
		packed, err := m.Pack()
		if err != nil {
			t.Fatalf("compress=%v: packing legal long name failed: %v", compress, err)
		}
		var out Msg
		if err := out.Unpack(packed); err != nil {
			t.Fatalf("compress=%v: unpacking packed long name failed: %v", compress, err)
		}
		if out.Question[0].Name != name.String() {
			t.Fatalf("compress=%v: round trip changed name", compress)
		}
	}
}

// TestBudgetPackOversizedLabel checks that a label exceeding 63 octets
// fails packing with an error and no partial message, with and without a
// budget.
func TestBudgetPackOversizedLabel(t *testing.T) {
	m := new(Msg)
	m.SetQuestion(strings.Repeat("a", 64)+".", TypeA)

	if msg, err := m.Pack(); err == nil || msg != nil {
		t.Fatalf("Pack: expected error and nil message, got %d bytes, %v", len(msg), err)
	}
	msg, err := m.PackWithBudget(Budget{MaxBytes: MaxMsgSize})
	if err == nil || msg != nil {
		t.Fatalf("PackWithBudget: expected error and nil message, got %d bytes, %v", len(msg), err)
	}
}

// TestBudgetPackTruncate checks that truncation mode keeps a parseable
// header, the question section and the OPT record, sets TC, stays within
// the budget and leaves the caller's message untouched.
func TestBudgetPackTruncate(t *testing.T) {
	m := budgetTestMsg(100)
	m.SetEdns0(4096, false)

	full, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(full) <= MinMsgSize {
		t.Fatalf("test message too small: %d bytes", len(full))
	}
	numAnswer := len(m.Answer)

	buf := bytes.Repeat([]byte{0xAB}, len(full)+64)
	packed, err := m.PackBufferWithBudget(buf, Budget{MaxBytes: MinMsgSize, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > MinMsgSize {
		t.Fatalf("truncated message is %d bytes, budget allows %d", len(packed), MinMsgSize)
	}

	var out Msg
	if err := out.Unpack(packed); err != nil {
		t.Fatalf("truncated message does not parse: %v", err)
	}
	if !out.Truncated {
		t.Fatal("TC bit not set on truncated message")
	}
	if len(out.Question) != 1 || out.Question[0].Name != "www.example.org." {
		t.Fatal("question section not retained")
	}
	if out.IsEdns0() == nil {
		t.Fatal("OPT record not retained")
	}
	if len(out.Answer) >= numAnswer {
		t.Fatal("expected some answers to be dropped")
	}

	// The caller's message must be unmodified.
	if len(m.Answer) != numAnswer {
		t.Fatal("caller's message was modified")
	}
	if m.Truncated {
		t.Fatal("caller's message had TC set")
	}
}

// TestBudgetPackTruncateTooSmall checks that a budget below what
// truncation can achieve fails with ErrBudget instead of returning an
// oversized or partial message.
func TestBudgetPackTruncateTooSmall(t *testing.T) {
	m := budgetTestMsg(100)
	msg, err := m.PackWithBudget(Budget{MaxBytes: 100, Truncate: true})
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("expected ErrBudget, got msg=%d bytes, err=%v", len(msg), err)
	}
	if msg != nil {
		t.Fatalf("expected nil message, got %d bytes", len(msg))
	}
}

// TestBudgetPackConcurrent packs the same message from many goroutines
// with various budgets and checks all results are identical.
func TestBudgetPackConcurrent(t *testing.T) {
	m := budgetTestMsg(50)
	want, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, 2*workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Generous budget: must succeed and match.
			got, err := m.PackWithBudget(Budget{MaxBytes: MaxMsgSize})
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", i, err)
				return
			}
			if !bytes.Equal(got, want) {
				errs <- fmt.Errorf("worker %d: packed bytes differ", i)
				return
			}
			// Exact budget: must succeed and match.
			if _, err := m.PackBufferWithBudget(make([]byte, 2*len(want)), Budget{MaxBytes: len(want)}); err != nil {
				errs <- fmt.Errorf("worker %d: exact budget: %w", i, err)
				return
			}
			// Insufficient budget: must fail with ErrBudget.
			if _, err := m.PackWithBudget(Budget{MaxBytes: len(want) - 1}); !errors.Is(err, ErrBudget) {
				errs <- fmt.Errorf("worker %d: expected ErrBudget, got %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
