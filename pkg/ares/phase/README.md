# ARES — A Framework for Blind Ranking and Selective-Reveal Protocols

ARES composes N-party cryptographic sessions from pluggable units called **phases**. Each phase owns one state-machine arc and declares what it needs from the shared session context and what it produces. A **runner** composes a list of phases into a pipeline, validates that every phase's requirements are satisfied, derives the session state machine, and routes inbound WebSocket messages to whichever phase claims the current state.

The framework ships default phases implementing the full ARES v2.4 protocol (threshold CKKS keygen, onion shuffle, verification, encrypted submit, FHE scoring, threshold decrypt, anonymous broadcast). Replace the scoring phase to change who wins; replace the keygen phase to change the trust model; replace the post-result phase to change what happens after the winner is revealed.

Three reference applications are included:

| App | Pipeline | Distinct from Fheya |
|---|---|---|
| `apps/fheya/` | 8 phases (cosine + location + Phase D) | — |
| `examples/sealed_bid_auction/` | 6 phases (scalar bid + argmax, no Phase D) | No onion shuffle, shallower circuit (depth=10), no post-result back-channel |
| `examples/recurring_cohort_ranking/` | 10 phases across 2 runners (cohort formation once, weekly sessions many times) | Amortized keygen across cohort lifetime, scalar ratings, no Phase D |

## Concepts

### Phase

A `Phase` is one unit of session work. It declares:

- **`EntryState / ExitState`** — the session states this phase owns and transitions to. The runner derives the state machine from the declared chain.
- **`ConsumedMessageTypes`** — which WebSocket message types this phase handles. The runner routes inbound messages by intersecting the current phase's declaration.
- **`Requires / Provides`** — typed `SessionContext` keys with constraint annotations. The runner refuses to start a pipeline where a required key is missing or where a consumer's constraints contradict a producer's.
- **`Lifetime`** — `per-session`, `per-cohort`, or `persistent`. Per-cohort phases (like a key bundle generated once) can be skipped when their outputs are already in the context.
- **`RunsAt`** — `registration`, `session-start`, or `inline`. Registration-time phases run once per participant identity; the per-session runner ignores them.
- **`InternalStates`** — sub-states the phase covers internally without advancing. (ARES has `LOCKED → KEYGEN → GOSSIP` as distinct engine sub-states; the framework folds `KEYGEN` into Phase 0a's internal states so the lifecycle tracker stays aligned.)

Lifecycle hooks: `Enter` → `OnMessage` (per consumed message) → `CheckComplete` (polled after each message) → `Exit`. `Exit` fires once, writes the phase's Provides into the session context, and releases in-phase resources.

### SessionRunner

Composes a list of phases into a pipeline. At construction time it validates:

- Phase names are unique.
- The inline state chain is connected (`phase[k].ExitState == phase[k+1].EntryState`).
- No two phases claim the same `EntryState` or `InternalStates`.
- Every `Requires` key with `Required: true` is provided by some preceding phase.
- Numeral constraints follow the `<name>_min` / `<name>` convention: a consumer declares `depth_min: 20` and the runner rejects if the producer declares `depth: 6`.

At runtime: `BeginSession` starts a new session context and fires the first phase's `Enter`. `HandleMessage` routes to the current phase, calls `OnMessage`, polls `CheckComplete`, and on completion fires `Exit` then `Enter` on the next phase.

### SessionContext

Concurrency-safe typed bag of state. Phases read what they need via `MustGet[T](ctx, key)` and write what they produce via `ctx.Set(key, value)`. The runner passes the same context through all phases of one session. Missing keys at `Enter` time return `MissingContextError` rather than silently proceeding.

## Quickstart

A minimal runner that picks the highest of N encrypted scalar bids
(see `examples/sealed_bid_auction/runner.go` for the full source):

```go
package main

import (
    "github.com/Fheyalabs/ares-core/pkg/ares/phase"
    "github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

func NewSimpleRanking() (*phase.SessionRunner, error) {
    return phase.Compose(
        defaults.NewPhase1aSessionInitiation(),  // INVITING   → LOCKED
        defaults.NewPhase0aThresholdKeygen(),    // LOCKED     → GOSSIP
        myScalarSubmitPhase{},                   // GOSSIP     → SCORING   (app phase)
        myArgmaxScoringPhase{},                  // SCORING    → DECRYPTING (app phase)
        defaults.NewPhase3ThresholdDecrypt(),    // DECRYPTING → BROADCASTING
        mySettlePhase{},                         // BROADCASTING → CLOSED   (app phase)
    )
}
```

`myScalarSubmitPhase` implements `Phase`, consumes a message like `"my-app.bid"`, and provides the encrypted inputs into the context. `myArgmaxScoringPhase` reads those inputs, runs the FHE circuit, and produces `CtxResultCiphertext`. `mySettlePhase` emits a signed transcript and `ExitState()` returns `StateNone` (terminal).

## Core Catalog

| Phase | Package | Arc | App-specific? |
|---|---|---|---|
| Session Initiation (Phase 1a) | `defaults` | INVITING → LOCKED | No |
| Threshold Keygen (Phase 0a) | `defaults` | LOCKED → GOSSIP | No |
| SinglePartyKeygen | `keygen` | LOCKED → GOSSIP | No |
| PlaintextKeygen | `keygen` | LOCKED → GOSSIP | No |
| PreSharedKeygen | `keygen` | LOCKED → GOSSIP | No |
| Threshold Decrypt (Phase 3) | `defaults` | DECRYPTING → BROADCASTING | No |
| Encrypted input submission | application package | (varies) | Yes |
| Scoring circuit | application package | SCORING → DECRYPTING | Yes |
| Post-result phase | application package | BROADCASTING → CLOSED | Yes |

## Customizing

**Swap who wins**: replace Phase 2 with your own scoring circuit. Make it implement `Phase` with the same `EntryState/ExitState` arc, `Requires` the crypto contract and eval keys, and `Provides` the winner ciphertext. The rest of the pipeline is untouched.

**Swap the trust model**: replace `Phase0aThresholdKeygen` with `keygen.SinglePartyKeygen` (server holds the private key, weaker privacy, much faster) or `keygen.PlaintextKeygen` (no crypto at all, for testing and audit-friendly use). Both slot into the same LOCKED → GOSSIP arc.

**Skip Phase D**: replace `PhaseDAnonymousBroadcast` with a phase whose `Enter` emits a signed transcript and `CheckComplete` returns `true` immediately. `ExitState` returns `StateNone` (terminal). The session ends after decrypt.

**Amortize keygen**: use `keygen.PreSharedKeygen` for the per-session pipeline. Run a separate out-of-band cohort-formation pipeline once that produces the key bundle into a `SessionContext`. Seed each per-session context with the bundle before `runner.BeginSession`. Per-session keygen cost drops to zero.

**Build a fully custom pipeline**: construct a `SessionRunner` with only your phases. Must start with a phase whose `EntryState` no preceding phase's `ExitState` targets (it becomes the runner's `InitialState`) and end with a phase whose `ExitState` is `StateNone` (terminal). All intermediate phases must chain: `phase[k].ExitState == phase[k+1].EntryState`.
