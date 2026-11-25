package dnsutil

import "github.com/miekg/dns"

// Re-export the atomic/verified transfer types from package dns for callers
// that use dnsutil as the higher-level helper package.
type (
	Zone             = dns.Zone
	ZoneStore        = dns.ZoneStore
	ZoneManager      = dns.ZoneManager
	AtomicZone       = dns.AtomicZone
	AtomicTransfer   = dns.AtomicTransfer
	VerifiedTransfer = dns.VerifiedTransfer
	TransferSession  = dns.TransferSession
	TransferResult   = dns.TransferResult
	PartialTransfer  = dns.PartialTransfer
	TransferError    = dns.TransferError
	SequenceTracker  = dns.SequenceTracker
	TransferMessage  = dns.TransferMessage
)

// Re-exported sentinel errors.
var (
	ErrSerialMismatch     = dns.ErrSerialMismatch
	ErrSOASerialMismatch  = dns.ErrSOASerialMismatch
	ErrSequenceGap        = dns.ErrSequenceGap
	ErrIncompleteTransfer = dns.ErrIncompleteTransfer
	ErrTransferTimeout    = dns.ErrTransferTimeout
	ErrPeerClosed         = dns.ErrPeerClosed
)

// NewZone delegates to dns.NewZone.
func NewZone(origin string, rrs ...dns.RR) *dns.Zone { return dns.NewZone(origin, rrs...) }

// NewZoneStore delegates to dns.NewZoneStore.
func NewZoneStore(zones ...*dns.Zone) *dns.ZoneStore { return dns.NewZoneStore(zones...) }

// NewZoneManager delegates to dns.NewZoneManager.
func NewZoneManager(zones ...*dns.Zone) *dns.ZoneStore { return dns.NewZoneManager(zones...) }

// NewAtomicZone delegates to dns.NewAtomicZone.
func NewAtomicZone(zones ...*dns.Zone) *dns.AtomicZone { return dns.NewAtomicZone(zones...) }

// NewAtomicTransfer delegates to dns.NewAtomicTransfer.
func NewAtomicTransfer(args ...any) *dns.AtomicTransfer {
	return dns.NewAtomicTransfer(args...)
}

// NewVerifiedTransfer delegates to dns.NewVerifiedTransfer.
func NewVerifiedTransfer(args ...any) *dns.VerifiedTransfer {
	return dns.NewVerifiedTransfer(args...)
}

// NewSequenceTracker delegates to dns.NewSequenceTracker.
func NewSequenceTracker(initial ...uint64) *dns.SequenceTracker {
	return dns.NewSequenceTracker(initial...)
}

// CollectVerified delegates to dns.CollectVerified.
func CollectVerified(q *dns.Msg, envelopes <-chan *dns.Envelope) (*dns.TransferResult, error) {
	return dns.CollectVerified(q, envelopes)
}

// CollectZone delegates to dns.CollectZone.
func CollectZone(q *dns.Msg, envelopes <-chan *dns.Envelope) (*dns.Zone, error) {
	return dns.CollectZone(q, envelopes)
}

// IsTimeout delegates to dns.IsTimeout.
func IsTimeout(err error) bool { return dns.IsTimeout(err) }

// IsPeerClosed delegates to dns.IsPeerClosed.
func IsPeerClosed(err error) bool { return dns.IsPeerClosed(err) }

// IsSerialMismatch delegates to dns.IsSerialMismatch.
func IsSerialMismatch(err error) bool { return dns.IsSerialMismatch(err) }

// IsSequenceGap delegates to dns.IsSequenceGap.
func IsSequenceGap(err error) bool { return dns.IsSequenceGap(err) }

// IsIncompleteTransfer delegates to dns.IsIncompleteTransfer.
func IsIncompleteTransfer(err error) bool { return dns.IsIncompleteTransfer(err) }
