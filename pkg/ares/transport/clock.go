// SPDX-License-Identifier: Apache-2.0

// Package transport provides the WebSocket hub, auth middleware, artifact
// store, HTTP admin surface, and session-lifecycle plumbing that an ARES
// application needs to host a SessionRunner over the network.
//
// The package is intentionally narrow: it knows how to upgrade a WebSocket,
// route messages to a SessionRunner, and expose a small HTTP admin surface
// for health, log streaming, and session creation. Application-specific
// concerns (scoring kernels, persistence schemas, matchmaking policies)
// live elsewhere.
//
// A typical wiring is:
//
//	svc := transport.NewService(transport.Config{
//	    Addr:       ":8000",
//	    Secret:     []byte(os.Getenv("ARES_WS_SECRET")),
//	    Runner:     myRunner,
//	    Trigger:    transport.NewManualAdminTrigger(myRunner),
//	})
//	log.Fatal(svc.Run(ctx))
package transport

import "time"

// Clock is the minimum time interface the transport uses. The default
// implementation calls time.Now(); applications that need virtual clocks
// (for accelerated testing) can supply their own.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

// RealClock returns a Clock backed by time.Now.
func RealClock() Clock { return realClock{} }

func (realClock) Now() time.Time { return time.Now() }
