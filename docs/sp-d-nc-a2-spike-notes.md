# SP-D NC-A2 Bound-Check Phase: Spike Notes

Date: 2026-05-31  
Spike scope: read + throwaway-proof only. No production code committed.

---

## Question 1 — WithHelper crypto pattern

**Constructor pattern:**

```go
// Stub (no real crypto):
func NewPhaseFoo() *PhaseFoo { return &PhaseFoo{} }

// Real CKKS path:
func NewPhaseFooWithHelper(helper *helperclient.Client) *PhaseFoo {
    return &PhaseFoo{helper: helper}
}
```

The pattern is established by `PhaseArgmax` / `PhaseDecrypt` in
`examples/sealed_bid_auction/phases.go`. `helper *helperclient.Client`
is a struct field; methods are dispatched from `Exit` (for compute
phases whose work happens once all inputs are present) or from `Enter`
(for pure server-side compute with no waiting).

**Where the helper is invoked for a bound-check phase:**

The bound-check computation has two server-side moments:

1. `Enter` — server holds all submitted ciphertexts. Compute
   `enc_check_i = EvalProductSumForContract(params, evalKeys, encX_i, encX_i, dim)`
   for each party's ciphertext. Store each check ciphertext in context
   (e.g. `CtxBoundCheckCiphertexts map[string][]byte`) so the transport
   layer can pick it up for per-party unicast.

2. `Exit` — after all `bound_check.partial` messages arrive, call
   `FuseCKKSPartialsForContract(params, partials, 1)` per party,
   evaluate the predicate `fused[0] > threshold²`, and return an error
   to abort if any party violates it.

**Cgo functions confirmed present in `pkg/ares/crypto/cgo/bridge.go`:**

```go
func EvalProductSumForContract(
    params ContractParams, evalKeys EvalKeyFinal,
    leftCiphertext, rightCiphertext []byte, nSlots int,
) ([]byte, error)

func PartialDecryptCKKSForContract(
    params ContractParams, ciphertext []byte,
    secretKeyShare []byte, lead bool,
) ([]byte, error)

func FuseCKKSPartialsForContract(
    params ContractParams, partials [][]byte, nSlots int,
) ([]float64, error)
```

These are `cgo`-layer functions (build tag `openfhe`). They are called
directly from phase code in the same binary; they are not routed
through the `helperclient` IPC subprocess. The `helperclient.Client`
wraps the subprocess for the auction's `Argmax` circuit, but the
bound-check circuit is simpler (one mult + one sum) and fits in a
direct cgo call.

**Consequence:** the bound-check phase field should hold the cgo params
and eval keys fetched from context, NOT a `*helperclient.Client`. The
helper is only needed for deeper circuits (argmax). Alternatively, if
the app already starts the helper, it can add an `eval_product_sum` RPC
to the helper; but the cgo path is self-contained and avoids IPC for
a shallow circuit.

---

## Question 2 — Broadcast of server-computed ciphertext

**The framework has no automatic broadcast of phase context keys to
participants.** Phase `Provides` keys are stored in `SessionContext`
(server-side in-memory bag); nothing in `runner.go`, `runner_lineage.go`,
or the transport package auto-pushes them to WebSocket clients.

**Existing broadcast mechanism:** `transport.Hub.BroadcastToSession` /
`Hub.SendTo` are the only broadcast surfaces. They are called by:

- The `SessionTrigger.Start` implementation (invitation broadcast).
- App code that holds a `*transport.Hub` reference.

**No phase currently holds a Hub reference.** Phases only see
`*phase.SessionContext`. A phase cannot self-broadcast without an
app-supplied callback or out-of-band Hub reference.

**How bound-check delivery must work — two options:**

**Option A (recommended) — phase stores check ciphertexts; app
bridge broadcasts after Enter:**  
The phase's `Enter` calls `EvalProductSumForContract` and writes
`CtxBoundCheckCiphertexts map[string][]byte` into context. The runner
returns from `Enter` normally. The transport layer (or a custom
`SessionTrigger`-like hook) reads that context key and calls
`hub.SendTo(pseudonym, WSMessage{Type: "bound_check.challenge", Payload: …})`
for each participant. Participants reply with `bound_check.partial`;
the phase accumulates via `OnMessage`.

This matches exactly how `PhaseArgmax` (Enter sets
`CtxAuctionCipherWinnerBid`) hands off to `PhaseDecrypt` (Enter=noop;
`OnMessage` accumulates `auction.decrypt.partial`): the phase boundary
doubles as the hand-off point. The only extension here is that the
triggering broadcast happens per-participant (unicast of their own
`enc_check_i`), not a single broadcast of one ciphertext.

**Option B — split into two sub-phases:** A pure-compute phase
(no messages consumed, `CheckComplete=true` immediately) computes and
stores all check ciphertexts, followed by a message-accumulating phase
that waits for partials. The runner's cascade logic naturally walks
through the first into the second. The application still needs to
perform the unicast between the two phases via an `onPhaseComplete`
hook or a custom trigger wrapper.

**The partial-decrypt reply message type** is analogous to
`auction.decrypt.partial`. For Task 5 this should be a new type such
as `bound_check.partial` accumulated into a per-party bucket.

**Key finding:** the framework does NOT auto-broadcast context keys to
participants. The app bridge is responsible for unicasting
`enc_check_i` to party `i` after Enter completes. ARES-core can ship
the circuit library and a declarative phase contract; the consuming app
must wire the unicast step. This is the same pattern as the existing
auction's Settlement phase (which also requires app-side broadcast of
the result).

---

## Question 3 — Partial-decrypt collection

Confirmed idiom from `anon/verify.go` and `PhaseKeygen` / `PhaseDecrypt`:

```go
// OnMessage: accumulate into a named bucket
func (p *PhaseBoundCheck) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
    // Per-party accumulation: each party may send N partial-decrypt responses
    // (one per enc_check_i they were asked to decrypt).
    // Simplest shape: one partial per participant covering their own check ct.
    phase.AccumulateMessage(ctx, bucketBoundCheckPartials, from, payload)
    return nil
}

// CheckComplete: N-of-N quorum
func (p *PhaseBoundCheck) CheckComplete(ctx *phase.SessionContext) bool {
    participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
    if !ok {
        return false
    }
    return phase.QuorumReached(ctx, bucketBoundCheckPartials, len(participants))
}
```

**Participant set:** `phase.TryGet[[]string](ctx, CtxParticipants)` —
the same key used by `PhaseGVerify` and `Phase3ThresholdDecrypt`.
`CtxParticipants` is populated by the keygen/invitation phase and
flows forward.

**Secret shares:** `phase.TryGet[map[string][]byte](ctx, CtxSecretShares)`
— the same key used by `Phase3ThresholdDecrypt`. However, for the
bound-check phase the server does NOT hold individual secret shares
server-side (they are client-side). The server only needs the
accumulated partial-decrypt blobs from the wire, which already contain
the party's contribution. No special share lookup is needed in the phase.

The `FuseCKKSPartialsForContract` call in `Exit` takes the raw partial
blobs directly; it does not need the secret key shares.

---

## Question 4 — Abort signal

**The abort mechanism:** a phase returns a non-nil error from any of
`Enter`, `OnMessage`, or `Exit`. The runner propagates the error
unwrapped to the caller (`HandleMessage`, `AdvanceToState`, etc.).
There is no dedicated `ErrAbort` sentinel; the pattern is:

```go
func (p *PhaseBoundCheck) Exit(ctx *phase.SessionContext) error {
    // … fuse partials, check predicate …
    for pseudonym, val := range fuseResults {
        if val > thresholdSq {
            return fmt.Errorf("%w: bound check failed for party %s (value %.4f > threshold²)",
                phase.ErrAppAttributable, pseudonym, val)
        }
    }
    return nil
}
```

Returning `ErrAppAttributable` is the right sentinel for a protocol
violation caused by a specific counterparty. The runner returns this
error to the transport layer, which logs it and does not advance the
session. The consuming app's dispatch handler in `transport/service.go`
can `errors.Is(err, phase.ErrAppAttributable)` to drive exclusion/penalty
logic.

**Opaque failure + timing jitter:** the phase itself is the right place
to introduce jitter. A `time.Sleep(rand.N(jitterBound))` before
returning the abort error prevents timing oracles. This belongs in
`Exit` (or in `Enter` if the abort can be triggered there), not in the
transport layer, because only the phase knows the predicate result.

**Session cleanup:** the transport layer does not auto-call
`runner.EndSession` on error. The app's dispatch handler must call
`runner.EndSession(sessionID)` on abort to release the tracker and
allow a new session with the same ID.

---

## Throwaway-proof result

Test: `TestSpikeNormSquared` in a temp module at `/tmp/boundcheck_spike/`.

Setup: n=2 threshold keygen, eval-key chain (round 1 lead + round 1
participant + combine + round 2 × 2 + combine), encrypt
`x = {0.5, 0.5, 0.5, 0.5}` under joint PK.

Circuit: `enc_check = EvalProductSumForContract(params, evalKeys, encX, encX, 4)`.

Partial decrypt: `PartialDecryptCKKSForContract` with `lead=true` (party 0)
and `lead=false` (party 1).

Fuse: `FuseCKKSPartialsForContract(params, partials, 1)`.

**Result: fused value = 1.000000, want 1.000000. PASS. Tolerance ±0.01.**

The complete bound-check crypto path is validated end-to-end in-process.
Runtime: 0.16 s for the crypto portion on a local macOS dev machine.

---

## Recommendation for Task 5

### Broadcast (`enc_check_i` delivery)

Use **Option A**: a single phase (`PhaseBoundCheck`) with:

- `Enter` computes `enc_check_i` for every party from `CtxSubmittedCiphertexts`
  and writes `CtxBoundCheckCiphertexts map[string][]byte` to context.
- `ConsumedMessageTypes = []string{"bound_check.partial"}`.
- The app's custom `SessionTrigger` (or a post-Enter hook registered on
  the transport service) reads `CtxBoundCheckCiphertexts` and calls
  `hub.SendTo(pseudonym, bound_check.challenge{ct: hex(enc_check_i)})`.
- `OnMessage` accumulates partials; `CheckComplete` is N-of-N quorum.
- `Exit` fuses, checks predicate, returns `ErrAppAttributable` on violation.

This is the minimal app-bridge surface: one `ctx.Get` + one
`hub.SendTo` per participant, wired in the trigger or a post-Enter
callback. ARES-core ships the phase contract and the circuit; the app
wires the unicast.

### Abort signal

Return `fmt.Errorf("%w: bound violation ...", phase.ErrAppAttributable)`
from `Exit`. Include a configurable jitter sleep before returning on
violation (phase-level, not transport-level). The transport dispatch
handler calls `runner.EndSession` on any non-nil error.

---

## HARD STOP assessment

**HARD STOP did NOT trigger.**

The framework CAN express the bound-check round within a single phase:

- `Enter` → server-side HE compute (cgo, no messages needed).
- `OnMessage` + `CheckComplete` → N-of-N partial-decrypt accumulation.
- `Exit` → fuse + predicate + conditional abort.

The one seam that requires app-specific bridge code is the unicast of
`enc_check_i` to each participant after `Enter`. The runner has no
auto-broadcast hook; the app provides it. This is the same seam as the
auction's invitation/result broadcast — not a fundamental gap, just the
existing ARES-core design boundary between framework and app.

**Fallback (not needed):** if the unicast seam turns out to be too
coupling-heavy, ARES-core could ship a `PhaseContract` struct with a
`ChallengeEmitter` callback field; the phase calls it from Enter. This
keeps the phase self-contained without importing the transport package.
