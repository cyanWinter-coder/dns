package dns

import "sync"

// SequenceTracker verifies contiguous transfer message sequence numbers.
//
// The first observed sequence is accepted by default. Construct with an
// initial value to require that the first message has a particular sequence.
type SequenceTracker struct {
	mu sync.Mutex

	Started          bool
	Complete         bool
	LastSequence     uint64
	Sequence         uint64
	NextSequence     uint64
	ExpectedSequence uint64
}

// NewSequenceTracker creates a tracker. An optional initial sequence fixes the
// first expected value.
func NewSequenceTracker(initial ...uint64) *SequenceTracker {
	s := new(SequenceTracker)
	if len(initial) > 0 {
		s.Started = true
		s.NextSequence = initial[0]
		s.ExpectedSequence = initial[0]
	}
	return s
}

// Check verifies that sequence is the next contiguous value.
func (s *SequenceTracker) Check(sequence any) error {
	seq, ok := toSequence(sequence)
	if !ok {
		return newTransferError("sequence", ErrSequenceGap, &PartialTransfer{
			ExpectedSequence: s.ExpectedSequence,
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Started {
		s.Started = true
		s.Sequence = seq
		s.LastSequence = seq
		s.NextSequence = seq + 1
		s.ExpectedSequence = seq + 1
		return nil
	}
	if seq != s.NextSequence {
		p := &PartialTransfer{
			Sequence:         s.LastSequence,
			LastSequence:     s.LastSequence,
			NextSequence:     s.NextSequence,
			ExpectedSequence: s.NextSequence,
		}
		err := newTransferError("sequence", ErrSequenceGap, p)
		err.ExpectedSequence = s.NextSequence
		err.WantSequence = s.NextSequence
		err.ActualSequence = seq
		err.GotSequence = seq
		err.ReceivedSequence = seq
		err.Sequence = seq
		return err
	}

	s.Sequence = seq
	s.LastSequence = seq
	s.NextSequence = seq + 1
	s.ExpectedSequence = s.NextSequence
	return nil
}

// Observe is an alias for Check.
func (s *SequenceTracker) Observe(sequence any) error { return s.Check(sequence) }

// Add is an alias for Check.
func (s *SequenceTracker) Add(sequence any) error { return s.Check(sequence) }

// Verify is an alias for Check.
func (s *SequenceTracker) Verify(sequence any) error { return s.Check(sequence) }

// Reset returns the tracker to its initial state.
func (s *SequenceTracker) Reset(initial ...uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s = SequenceTracker{}
	if len(initial) > 0 {
		s.Started = true
		s.NextSequence = initial[0]
		s.ExpectedSequence = initial[0]
	}
}

// SequenceGuard is a naming alias for SequenceTracker.
type SequenceGuard = SequenceTracker

// MessageSequence is a naming alias for SequenceTracker.
type MessageSequence = SequenceTracker

// GapDetector is a naming alias for SequenceTracker.
type GapDetector = SequenceTracker

// ContiguousSequence is a naming alias for SequenceTracker.
type ContiguousSequence = SequenceTracker

// NewSequenceGuard is an alias for NewSequenceTracker.
func NewSequenceGuard(initial ...uint64) *SequenceTracker { return NewSequenceTracker(initial...) }

// NewMessageSequence is an alias for NewSequenceTracker.
func NewMessageSequence(initial ...uint64) *SequenceTracker { return NewSequenceTracker(initial...) }

// NewGapDetector is an alias for NewSequenceTracker.
func NewGapDetector(initial ...uint64) *SequenceTracker { return NewSequenceTracker(initial...) }

// CheckSequence returns ErrSequenceGap unless actual == expected.
func CheckSequence(expected, actual uint64) error {
	if expected != actual {
		p := &PartialTransfer{ExpectedSequence: expected, Sequence: actual}
		err := newTransferError("sequence", ErrSequenceGap, p)
		err.ExpectedSequence = expected
		err.WantSequence = expected
		err.ActualSequence = actual
		err.GotSequence = actual
		err.Sequence = actual
		return err
	}
	return nil
}

// VerifySequence is an alias for CheckSequence.
func VerifySequence(expected, actual uint64) error { return CheckSequence(expected, actual) }

// ValidateSequence is an alias for CheckSequence.
func ValidateSequence(expected, actual uint64) error { return CheckSequence(expected, actual) }
