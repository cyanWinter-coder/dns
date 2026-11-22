// Request lifecycle state machine and shared write error classification.
//
// Every request handled by a Server owns a requestState. The state is a
// single monotonic transition from stateActive to one of the terminal
// states, performed atomically with compare-and-swap so that the three
// possible terminal events - a handler return, a handler panic and a
// connection disconnect - can each occur on their own goroutine while only
// the first one publishes the terminal state. Late writes arriving after
// the transition are rejected and can never reach the transport, which for
// TCP means they cannot corrupt the framing of the next message on the same
// connection.

package dns

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
)

// Lifecycle state of an individual request. stateActive is the only state
// from which the ResponseWriter is writable; every other state is terminal.
const (
	stateActive             uint32 = iota
	stateTerminalReturn            // handler returned normally
	stateTerminalPanic             // handler panicked
	stateTerminalDisconnect        // transport was closed or the peer went away
	stateTerminalClose             // ResponseWriter.Close was called
)

// ErrRequestFinalized is returned by ResponseWriter.WriteMsg and
// ResponseWriter.Write when the request has already reached its single
// terminal state, whether through a handler return, a panic, a disconnect
// or a call to Close. The write is refused before it can touch the
// transport, so a late write can never contaminate another message.
var ErrRequestFinalized = errors.New("dns: request has already been finalized")

// ErrConnClosing classifies a write failure that is caused by the
// connection going away rather than by a malformed message. It wraps the
// underlying error and is produced identically for UDP and TCP writers.
var ErrConnClosing = errors.New("dns: connection closed before write completed")

// requestState is the per-request terminal-state machine. It is safe for
// concurrent use and may be embedded by value in a zero-value response.
type requestState struct {
	state atomic.Uint32
}

// active reports whether the request has not published a terminal state yet.
func (r *requestState) active() bool {
	return r.state.Load() == stateActive
}

// finalize transitions the request to the given terminal state. It reports
// true only for the single caller that wins the transition; every later
// invocation returns false and leaves the recorded state untouched. A
// terminal state can therefore never be rolled back or overwritten.
func (r *requestState) finalize(cause uint32) bool {
	return r.state.CompareAndSwap(stateActive, cause)
}

// terminalCause returns the terminal state and true once the request has
// finalized, or stateActive and false while it is still active.
func (r *requestState) terminalCause() (uint32, bool) {
	if s := r.state.Load(); s != stateActive {
		return s, true
	}
	return stateActive, false
}

// classifyWriteError maps transport write failures onto a small, shared set
// of terminal causes. UDP and TCP requests flow through the same
// classification so that callers observe the same semantics regardless of
// the transport. Errors that do not describe a disconnect are returned
// unchanged.
func classifyWriteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return errors.Join(ErrConnClosing, err)
	}
	return err
}

// isDisconnect reports whether a classified write error represents a
// connection-level failure that should finalize the request with
// stateTerminalDisconnect.
func isDisconnect(err error) bool {
	return errors.Is(err, ErrConnClosing)
}

// frozenIdentity captures the handler, protocol and connection identity that
// belong to a single request. The fields are populated before the handler is
// invoked and never mutated afterwards, so every goroutine spawned by a
// handler observes the same identity even as the server shuts down or the
// underlying TCP connection moves on to its next query.
type frozenIdentity struct {
	proto    string   // "tcp" or "udp"
	connID   uint64   // monotonically increasing TCP connection id; 0 for UDP
	querySeq uint64   // 1-based query sequence on a TCP connection; 0 for UDP
	handler  Handler  // handler selected at dispatch time
	local    net.Addr // snapshot of the server address at dispatch time
	remote   net.Addr // snapshot of the peer address at dispatch time
}
