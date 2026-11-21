package dns

import "fmt"

// ErrBudget is returned, possibly wrapped, when a caller-declared Budget
// is exhausted while packing a message or expanding a compressed domain
// name. Use errors.Is(err, ErrBudget) to recognize it.
var ErrBudget error = &Error{err: "resource budget exceeded"}

// Budget declares resource limits applied when packing a DNS message or
// expanding a compressed domain name. It lets callers bound the memory a
// pack or unpack operation may consume before it starts, so that
// compression pointer loops, overly deep alias chains or maliciously long
// names fail before large buffers are allocated.
//
// The zero value applies the package defaults and exactly preserves the
// behavior of Pack, PackBuffer and UnpackDomainName.
type Budget struct {
	// MaxBytes limits the size of the packed wire-format message. When
	// packing would exceed it, the operation fails with ErrBudget and no
	// partial message is returned. Zero means no limit.
	MaxBytes int

	// MaxNameLength limits the expanded wire-format length of a single
	// domain name. Zero means the RFC 1035 limit of 255 octets.
	MaxNameLength int

	// MaxPointers limits the number of compression pointers followed
	// while expanding a single domain name. Reaching the limit fails
	// even if the pointers do not loop. Zero means the package default.
	MaxPointers int

	// Truncate, when packing a message that exceeds MaxBytes, truncates
	// a copy of the message (see Msg.Truncate) instead of failing. The
	// header, the question section and any OPT record are retained and
	// the TC bit is set when records are dropped. The caller's message
	// is never modified.
	Truncate bool
}

// maxNameLength returns the configured name expansion limit, or the
// package default when unset.
func (b Budget) maxNameLength() int {
	if b.MaxNameLength <= 0 {
		return maxDomainNameWireOctets
	}
	return b.MaxNameLength
}

// maxPointers returns the configured compression pointer limit, or the
// package default when unset.
func (b Budget) maxPointers() int {
	if b.MaxPointers <= 0 {
		return maxCompressionPointers
	}
	return b.MaxPointers
}

// PackWithBudget packs a Msg like Pack, but enforces the resource limits
// declared in b. When b does not allow the message to be packed, a nil
// message and an error matching errors.Is(err, ErrBudget) are returned.
func (dns *Msg) PackWithBudget(b Budget) (msg []byte, err error) {
	return dns.PackBufferWithBudget(nil, b)
}

// PackBufferWithBudget packs a Msg like PackBuffer, but enforces the
// resource limits declared in b. The buffer is never grown beyond
// b.MaxBytes and at most b.MaxBytes bytes of buf are written. When the
// budget is exceeded a nil message is returned, so callers can never
// observe a half-packed message.
func (dns *Msg) PackBufferWithBudget(buf []byte, b Budget) (msg []byte, err error) {
	if b.Truncate && b.MaxBytes > 0 && msgLenWithCompressionMap(dns, nil) > b.MaxBytes {
		// The message does not fit in the budget: truncate a copy so the
		// caller's message is left intact. Truncate keeps the header, the
		// question section and any OPT record, and sets the TC bit when
		// records are dropped.
		truncated := dns.Copy()
		truncated.Truncate(b.MaxBytes)
		dns = truncated
	}

	// If this message can't be compressed, avoid filling the
	// compression map and creating garbage.
	if dns.Compress && dns.isCompressible() {
		compression := make(map[string]uint16) // Compression pointer mappings.
		return dns.packBufferWithCompressionMap(buf, compressionMap{int: compression}, true, b)
	}

	return dns.packBufferWithCompressionMap(buf, compressionMap{}, false, b)
}

// UnpackDomainNameWithBudget unpacks a domain name like UnpackDomainName,
// but enforces the name expansion and compression pointer limits declared
// in b. Budget violations return an error matching both
// errors.Is(err, ErrBudget) and the underlying error (ErrLongDomain or
// the too-many-compression-pointers error).
func UnpackDomainNameWithBudget(msg []byte, off int, b Budget) (string, int, error) {
	name, off1, err := unpackDomainName(msg, off, b.maxNameLength(), b.maxPointers())
	if err == ErrLongDomain || err == errTooManyPointers {
		return "", off1, fmt.Errorf("%w: %w", ErrBudget, err)
	}
	return name, off1, err
}
