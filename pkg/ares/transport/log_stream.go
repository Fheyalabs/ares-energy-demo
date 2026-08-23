// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const logRingSize = 4000

// LogStream is a process-wide ring-buffered log capture with SSE fan-out
// at GET /v2/debug/logs. Install once at startup; subsequent log.Printf
// calls land in the ring and stream to subscribers.
type LogStream struct {
	mu   sync.Mutex
	ring []string
	pos  int
	full bool
	subs map[chan string]struct{}
}

// NewLogStream installs itself as the destination for the default Go
// logger (alongside stderr) and returns the stream. Only call this once.
func NewLogStream() *LogStream {
	ls := &LogStream{
		ring: make([]string, logRingSize),
		subs: make(map[chan string]struct{}),
	}
	log.SetOutput(io.MultiWriter(os.Stderr, ls))
	return ls
}

func (ls *LogStream) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	ls.mu.Lock()
	ls.ring[ls.pos] = line
	ls.pos = (ls.pos + 1) % logRingSize
	if ls.pos == 0 {
		ls.full = true
	}
	for ch := range ls.subs {
		select {
		case ch <- line:
		default:
		}
	}
	ls.mu.Unlock()
	return len(p), nil
}

func (ls *LogStream) buffered() []string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	var out []string
	if ls.full {
		for i := ls.pos; i < logRingSize; i++ {
			if ls.ring[i] != "" {
				out = append(out, ls.ring[i])
			}
		}
	}
	for i := 0; i < ls.pos; i++ {
		if ls.ring[i] != "" {
			out = append(out, ls.ring[i])
		}
	}
	return out
}

func (ls *LogStream) subscribe() chan string {
	ch := make(chan string, 512)
	ls.mu.Lock()
	ls.subs[ch] = struct{}{}
	ls.mu.Unlock()
	return ch
}

func (ls *LogStream) unsubscribe(ch chan string) {
	ls.mu.Lock()
	delete(ls.subs, ch)
	ls.mu.Unlock()
}

// RegisterRoutes installs the SSE endpoint at /v2/debug/logs on mux.
// If authz is non-nil, requests for which it returns false are rejected
// with 401. Passing nil preserves the historical unauthenticated access
// (only safe behind a trusted reverse proxy).
func (ls *LogStream) RegisterRoutes(mux *http.ServeMux, authz ...func(*http.Request) bool) {
	var check func(*http.Request) bool
	if len(authz) > 0 {
		check = authz[0]
	}
	mux.HandleFunc("GET /v2/debug/logs", func(w http.ResponseWriter, r *http.Request) {
		if check != nil && !check(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ls.handleStream(w, r)
	})
}

// writeSSE emits one SSE event for `line`. Per the SSE spec, embedded
// newlines must be split into separate `data:` lines and the event is
// terminated by a blank line. Without this split, an attacker who can
// place a newline into a log message can inject a fake event.
func writeSSE(w io.Writer, line string) {
	for _, part := range strings.Split(line, "\n") {
		fmt.Fprintf(w, "data: %s\n", strings.TrimRight(part, "\r"))
	}
	fmt.Fprint(w, "\n")
}

func (ls *LogStream) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := ls.subscribe()
	defer ls.unsubscribe(ch)

	for _, line := range ls.buffered() {
		writeSSE(w, line)
	}
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case line := <-ch:
			writeSSE(w, line)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
