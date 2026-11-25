package dns

import (
	"context"
	"sync"
)

// ServeMux is an DNS request multiplexer. It matches the zone name of
// each incoming request against a list of registered patterns add calls
// the handler for the pattern that most closely matches the zone name.
//
// ServeMux is DNSSEC aware, meaning that queries for the DS record are
// redirected to the parent zone (if that is also registered), otherwise
// the child gets the query.
//
// ServeMux is also safe for concurrent access from multiple goroutines.
//
// The zero ServeMux is empty and ready for use.
type ServeMux struct {
	z map[string]Handler
	m sync.RWMutex
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux {
	return new(ServeMux)
}

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

// DefaultServeMuxContext is a context-aware mux with the same method set as
// ServeMuxContext. Registrations on DefaultServeMux remain independent so the
// original global behavior is preserved.
var DefaultServeMuxContext = NewServeMuxContext()

func (mux *ServeMux) match(q string, t uint16) Handler {
	mux.m.RLock()
	defer mux.m.RUnlock()
	if mux.z == nil {
		return nil
	}

	q = CanonicalName(q)

	var handler Handler
	for off, end := 0, false; !end; off, end = NextLabel(q, off) {
		if h, ok := mux.z[q[off:]]; ok {
			if t != TypeDS {
				return h
			}
			// Continue for DS to see if we have a parent too, if so delegate to the parent
			handler = h
		}
	}

	// Wildcard match, if we have found nothing try the root zone as a last resort.
	if h, ok := mux.z["."]; ok {
		return h
	}

	return handler
}

// Handle adds a handler to the ServeMux for pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	if mux.z == nil {
		mux.z = make(map[string]Handler)
	}
	mux.z[CanonicalName(pattern)] = handler
	mux.m.Unlock()
}

// HandleFunc adds a handler function to the ServeMux for pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

// HandleContext adds a context-aware handler to the ServeMux. The original
// Handle method and Handler interface remain unchanged.
func (mux *ServeMux) HandleContext(pattern string, handler HandlerContext) {
	mux.Handle(pattern, contextHandlerAdapter{hc: handler})
}

// HandleWithContext is an alias for HandleContext.
func (mux *ServeMux) HandleWithContext(pattern string, handler HandlerWithContext) {
	mux.HandleContext(pattern, handler)
}

// HandleFuncContext adds a context-aware handler function to the ServeMux.
func (mux *ServeMux) HandleFuncContext(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	mux.HandleContext(pattern, HandlerFuncContext(handler))
}

// HandleFuncWithContext is an alias for HandleFuncContext.
func (mux *ServeMux) HandleFuncWithContext(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	mux.HandleFuncContext(pattern, handler)
}

// HandleContextFunc is an alias for HandleFuncContext.
func (mux *ServeMux) HandleContextFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	mux.HandleFuncContext(pattern, handler)
}

// HandleRemove deregisters the handler specific for pattern from the ServeMux.
func (mux *ServeMux) HandleRemove(pattern string) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	mux.m.Lock()
	delete(mux.z, CanonicalName(pattern))
	mux.m.Unlock()
}

// ServeDNS dispatches the request to the handler whose pattern most
// closely matches the request message.
//
// ServeDNS is DNSSEC aware, meaning that queries for the DS record
// are redirected to the parent zone (if that is also registered),
// otherwise the child gets the query.
//
// If no handler is found, or there is no question, a standard REFUSED
// message is returned
func (mux *ServeMux) ServeDNS(w ResponseWriter, req *Msg) {
	mux.ServeDNSContext(req.Context(), w, req)
}

// ServeDNSContext dispatches a request while preserving its lifecycle context.
// Context-aware handlers receive ctx; original Handler values continue to use
// their unchanged ServeDNS method.
func (mux *ServeMux) ServeDNSContext(ctx context.Context, w ResponseWriter, req *Msg) {
	if req != nil {
		req.ctx = ctx
	}
	var h Handler
	if len(req.Question) >= 1 { // allow more than one question
		h = mux.match(req.Question[0].Name, req.Question[0].Qtype)
	}

	if h != nil {
		dispatchHandler(ctx, h, w, req)
	} else {
		handleRefused(w, req)
	}
}

// Handle registers the handler with the given pattern
// in the DefaultServeMux. The documentation for
// ServeMux explains how patterns are matched.
func Handle(pattern string, handler Handler) { DefaultServeMux.Handle(pattern, handler) }

// HandleRemove deregisters the handle with the given pattern
// in the DefaultServeMux.
func HandleRemove(pattern string) { DefaultServeMux.HandleRemove(pattern) }

// HandleFunc registers the handler function with the given pattern
// in the DefaultServeMux.
func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// HandleContext registers a context-aware handler with the DefaultServeMux.
func HandleContext(pattern string, handler HandlerContext) {
	DefaultServeMux.HandleContext(pattern, handler)
}

// HandleWithContext is an alias for HandleContext.
func HandleWithContext(pattern string, handler HandlerWithContext) {
	DefaultServeMux.HandleWithContext(pattern, handler)
}

// HandleFuncContext registers a context-aware handler function with the
// DefaultServeMux.
func HandleFuncContext(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFuncContext(pattern, handler)
}

// HandleFuncWithContext is an alias for HandleFuncContext.
func HandleFuncWithContext(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFuncWithContext(pattern, handler)
}

// HandleContextFunc is an alias for HandleFuncContext.
func HandleContextFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	DefaultServeMux.HandleContextFunc(pattern, handler)
}

// ServeMuxContext is a context-aware mux. It delegates pattern matching to
// ServeMux while passing the supplied context directly to HandlerContext
// values.
type ServeMuxContext struct {
	mux ServeMux
}

// NewServeMuxContext allocates a context-aware mux.
func NewServeMuxContext() *ServeMuxContext {
	return &ServeMuxContext{}
}

// NewContextServeMux is an alias for NewServeMuxContext.
func NewContextServeMux() *ServeMuxContext {
	return NewServeMuxContext()
}

// Handle registers a context-aware handler.
func (m *ServeMuxContext) Handle(pattern string, handler HandlerContext) {
	m.mux.HandleContext(pattern, handler)
}

// HandleFunc registers a context-aware handler function.
func (m *ServeMuxContext) HandleFunc(pattern string, handler func(context.Context, ResponseWriter, *Msg)) {
	m.mux.HandleFuncContext(pattern, handler)
}

// HandleRemove removes a pattern.
func (m *ServeMuxContext) HandleRemove(pattern string) {
	m.mux.HandleRemove(pattern)
}

// ServeDNS implements HandlerContext.
func (m *ServeMuxContext) ServeDNS(ctx context.Context, w ResponseWriter, req *Msg) {
	m.mux.ServeDNSContext(ctx, w, req)
}
