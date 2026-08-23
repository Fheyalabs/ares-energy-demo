# ARES Core

[![go](https://github.com/Fheyalabs/ARES-core/actions/workflows/go.yml/badge.svg)](https://github.com/Fheyalabs/ARES-core/actions/workflows/go.yml)
[![openfhe](https://github.com/Fheyalabs/ARES-core/actions/workflows/openfhe.yml/badge.svg)](https://github.com/Fheyalabs/ARES-core/actions/workflows/openfhe.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

ARES Core is a cryptographic framework for **blind ranking**,
**sealed-bid auctions**, and **selective-reveal protocols**. It composes
N-party cryptographic sessions from pluggable units called **phases**:

- Threshold CKKS/BFV keygen, FHE scoring, and threshold decrypt — out of the box.
- Pluggable input shapes, scoring circuits, and post-result phases.
- Pluggable trust models — multi-party threshold, single-party trusted,
  plaintext (for testing), or pre-shared / amortized keygen.

The framework intentionally ships **no opinionated default pipeline**.
Applications compose their own via `phase.Compose(...)` from generic
primitives in `pkg/ares/phase/defaults/` and `pkg/ares/phase/keygen/`,
plus their own input-submission / scoring / post-result phases.

> Status: pre-1.0. Minor version bumps may include breaking API
> changes. See [CHANGELOG.md](CHANGELOG.md) for the migration path.

## Reference apps

Worked examples ship under `examples/`:

| App | Path | Pipeline | Depth |
|---|---|---|---|
| Sealed-bid auction | [`examples/sealed_bid_auction/`](examples/sealed_bid_auction/) | 6 phases — scalar bid + argmax | 10 |
| Ride share | [`examples/ride_share/`](examples/ride_share/) | 6 phases — composite score (price × proximity) | 12 |
| Recurring cohort ranking | [`examples/recurring_cohort_ranking/`](examples/recurring_cohort_ranking/) | 10 phases across 2 runners — amortized keygen | 10 |
| Blind voting | [`examples/voting/`](examples/voting/) | 5 phases — `PlaintextKeygen` + sum-weighted tally | n/a |
| Ring-32k BFV payload fuse | [`examples/blind_bfv_payload_fuse/`](examples/blind_bfv_payload_fuse/) | Profile + lineage helpers for additive BFV fallback | 20 |
| Light BFV payload fuse | [`examples/light_bfv_payload_fuse/`](examples/light_bfv_payload_fuse/) | Smaller profile + lineage helpers for local smoke use | 10 |

The dating-app reference implementation built on this framework lives
at [fheya.de](https://fheya.de) — it's not open-source, but exists as
proof the framework supports the most complex shape it's designed for
(cosine + location + reputation scoring across 6 parties at depth 30).

## Encrypted input scoring

v0.9.13 adds a ciphertext-only input path for threshold CKKS scoring. A
client can encrypt fixed-size payload chunks under the collective public key,
derive an encrypted squared distance from encrypted origin scalars and local
coordinates, and submit only those ciphertexts. The evaluator receives
`EncryptedInputFuseRequest.CandidatePayloadCiphertexts` and
`EncryptedInputFuseRequest.CandidateDistanceCiphertexts`. This separate type
has no raw package or coordinate fields, so mixed plaintext/ciphertext input
modes are rejected by the Go type boundary.

Use `ChunkedFuseEncryptedPayloadCKKS` for encrypted payload-only requests or
`ChunkedFuseEncryptedInputsCKKS` when the request also carries encrypted
distance inputs. The corresponding `ChunkedUnionScore...` helpers fan out
comparators without decrypting intermediate inputs. The `WithEvalSumRefs`
forms retain the per-index eval-sum-reference layout for memory-bounded
threshold sessions.

For an exact fallback with the same boundary, use
`BlindFusePayloadBFVForContract`. It accepts collective-key ciphertexts,
client-derived encrypted squared distances, server-owned public offsets, and
encrypted payloads, then returns one threshold-decryptable payload ciphertext.
The request type has no coordinate or plaintext-score fields.

The generic threshold-keygen phase accepts the durable wire sequence
`keygen.share`, `keygen.eval_round1`, and `keygen.eval_share`. Applications
that persist keygen operations should record a framework receipt only after
the runner accepts each exact stage.

## Ciphertext lineage (SC-10, v0.4.0)

New in v0.4.0: a session-rooted Merkle DAG covering every byte payload
at every phase boundary. Each node is signed by its producer (default
Ed25519, pluggable via the `sign.Signer` interface). Opt-out per
output via `phase.ContextKeyType.NoLineage`; secure by default for
runners built with `phase.ComposeWith(...)`.

Closes the SC-5 `C_emb` definition gap and substantially addresses H2
(Phase 2 ciphertext-binding) from the ARES v2.5 ultrareview. Apps
that don't need lineage continue to call `phase.Compose(...)` and
emit v1 wire frames — fully backward-compatible.

Per-package detail:
- [`pkg/ares/sign/`](pkg/ares/sign/) — `Signer` interface +
  `Ed25519Signer` default
- [`pkg/ares/lineage/`](pkg/ares/lineage/) — `DAGNode`, `Commit`,
  `Verify`, `Store` + `InMemoryStore`

Threat-model nuance for the framework's target audience
(financial-grade-with-real-economic-stakes vs Fheya-grade-where-the
-encrypted-profile-removes-the-incentive) is documented in
ARES Spec v2.5 §SC-10.

## Slot anonymization

New in v0.5.0: opt-in inter-participant slot anonymity via
[`pkg/ares/onion`](pkg/ares/onion/) (crypto) and
[`pkg/ares/phase/anon`](pkg/ares/phase/anon/) (phases).

**Property:** the relay and all other participants cannot link an
anonymized submission slot to the identity that created it. Each
participant learns the ordered slot list — and nothing more about who
submitted which slot. This is inter-participant anonymity; the
application's own result phase (e.g. argmax, tally) sees the slots in
permuted order and decides what, if anything, to reveal from there.

**SC-7 collusion bound:** certain deanonymization requires `k >= N-2`
colluders. The floor drops to a 50% probability at `k = N-3`. See
[`pkg/ares/onion`](pkg/ares/onion/) godoc for the full derivation.

**Worked example:** [`examples/voting`](examples/voting/)'s
`PipelineWithShuffle` composes `PhaseGShuffle` + `PhaseGVerify` from
`pkg/ares/phase/anon` over a GOSSIP→VERIFYING arc between `PlaintextKeygen`
and ballot submission. The authority cannot link an anonymized ballot
slot to the voter who produced it.

Applications that don't need slot anonymity — for example, protocols
whose intended output is the winner's public identity — continue to
call `phase.Compose(...)` without the `anon` phases.
[`examples/sealed_bid_auction`](examples/sealed_bid_auction/) is the
canonical opt-out: the winning bidder is an explicit public output, so
there is no slot→identity mapping to hide.

## Quickstart

Legacy path (v1 wire frames, lineage off — fully backward-compatible
with v0.3.x):

```go
import auction "github.com/Fheyalabs/ARES-core/examples/sealed_bid_auction"

runner, err := auction.Pipeline()
ctx, err := runner.BeginSession("auction-1", "")
// Route messages through runner.HandleMessage(...)
```

v0.4.0 lineage path (v2 wire frames, every byte signed):

```go
import (
    auction "github.com/Fheyalabs/ARES-core/examples/sealed_bid_auction"
    "github.com/Fheyalabs/ARES-core/pkg/ares/sign"
)

signer, _ := sign.NewEd25519Signer()
verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

runner, err := auction.PipelineWithLineage(signer, verifiers)
ctx, err := runner.BeginSession("auction-1", "")
// Route messages through runner.HandleLineageMessage(...)
```

Each reference app under `examples/` ships both constructors and a
`tamper_test.go` smoke that demonstrates the lineage path detecting a
server-relay byte swap.

For a hand-composed pipeline see
[`pkg/ares/phase/README.md`](pkg/ares/phase/README.md).

## Build your own app

A complete worked example: an anonymous "highest-rating" picker that
runs without any FHE. Each participant submits an integer rating; the
server tallies them and announces the winner. Five phases — two
provided by the framework, three you write — wired into one runner.
Each phase owns exactly one state-machine arc, which is the framework's
core teaching point.

```go
// myapp/states.go
package myapp

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

const (
    StateInviting phase.SessionState = "INVITING"
    StateLocked   phase.SessionState = "LOCKED"
    StateGossip   phase.SessionState = "GOSSIP"     // PlaintextKeygen reuses this label
    StateScoring  phase.SessionState = "SCORING"
    StateDone     phase.SessionState = "DONE"

    CtxParticipants = "participants"
    CtxRatings      = "ratings"
    CtxWinner       = "winner"
)
```

```go
// myapp/phases.go
package myapp

import (
    "encoding/json"

    "github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// PhaseInvite seeds the participant list. The session-service supplies
// it via the trigger; this phase just transitions to LOCKED.
type PhaseInvite struct{}

func (PhaseInvite) Name() string                                                  { return "myapp-invite" }
func (PhaseInvite) Lifetime() phase.Lifetime                                      { return phase.LifetimePerSession }
func (PhaseInvite) RunsAt() phase.RunsAt                                          { return phase.RunsAtInline }
func (PhaseInvite) EntryState() phase.SessionState                                { return StateInviting }
func (PhaseInvite) ExitState() phase.SessionState                                 { return StateLocked }
func (PhaseInvite) ConsumedMessageTypes() []string                                { return nil }
func (PhaseInvite) InternalStates() []phase.SessionState                          { return nil }
func (PhaseInvite) Requires() phase.ContextSchema                                 { return nil }
func (PhaseInvite) Provides() phase.ContextSchema                                 { return phase.ContextSchema{CtxParticipants: {TypeName: "[]string"}} }
func (PhaseInvite) Enter(*phase.SessionContext) error                             { return nil }
func (PhaseInvite) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseInvite) CheckComplete(*phase.SessionContext) bool                      { return true }
func (PhaseInvite) Exit(*phase.SessionContext) error                              { return nil }

// PhaseCollect accumulates one "myapp.rating" frame per participant
// and exits when the quorum is reached.
type PhaseCollect struct{}

func (PhaseCollect) Name() string                         { return "myapp-collect" }
func (PhaseCollect) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseCollect) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseCollect) EntryState() phase.SessionState       { return StateGossip }
func (PhaseCollect) ExitState() phase.SessionState        { return StateScoring }
func (PhaseCollect) ConsumedMessageTypes() []string       { return []string{"myapp.rating"} }
func (PhaseCollect) InternalStates() []phase.SessionState { return nil }
func (PhaseCollect) Requires() phase.ContextSchema {
    return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseCollect) Provides() phase.ContextSchema {
    return phase.ContextSchema{CtxRatings: {TypeName: "map[string]int"}}
}
func (PhaseCollect) Enter(*phase.SessionContext) error { return nil }
func (PhaseCollect) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
    phase.AccumulateMessage(ctx, "ratings", from, payload)
    return nil
}
func (PhaseCollect) CheckComplete(ctx *phase.SessionContext) bool {
    return phase.QuorumReached(ctx, "ratings", len(phase.MustGet[[]string](ctx, CtxParticipants)))
}
func (PhaseCollect) Exit(ctx *phase.SessionContext) error {
    raw := phase.AccumulatedMessages(ctx, "ratings")
    out := make(map[string]int, len(raw))
    for who, p := range raw {
        var msg struct{ Value int `json:"value"` }
        _ = json.Unmarshal(p, &msg)
        out[who] = msg.Value
    }
    ctx.Set(CtxRatings, out)
    return nil
}

// PhaseAnnounce picks the highest rating and writes the winner.
type PhaseAnnounce struct{}

func (PhaseAnnounce) Name() string                                                  { return "myapp-announce" }
func (PhaseAnnounce) Lifetime() phase.Lifetime                                      { return phase.LifetimePerSession }
func (PhaseAnnounce) RunsAt() phase.RunsAt                                          { return phase.RunsAtInline }
func (PhaseAnnounce) EntryState() phase.SessionState                                { return StateScoring }
func (PhaseAnnounce) ExitState() phase.SessionState                                 { return StateDone }
func (PhaseAnnounce) ConsumedMessageTypes() []string                                { return nil }
func (PhaseAnnounce) InternalStates() []phase.SessionState                          { return nil }
func (PhaseAnnounce) Requires() phase.ContextSchema {
    return phase.ContextSchema{CtxRatings: {TypeName: "map[string]int", Required: true}}
}
func (PhaseAnnounce) Provides() phase.ContextSchema {
    return phase.ContextSchema{CtxWinner: {TypeName: "string"}}
}
func (PhaseAnnounce) Enter(ctx *phase.SessionContext) error {
    ratings := phase.MustGet[map[string]int](ctx, CtxRatings)
    winner, best := "", -1<<31
    for who, v := range ratings {
        if v > best {
            winner, best = who, v
        }
    }
    ctx.Set(CtxWinner, winner)
    return nil
}
func (PhaseAnnounce) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseAnnounce) CheckComplete(*phase.SessionContext) bool                      { return true }
func (PhaseAnnounce) Exit(*phase.SessionContext) error                              { return nil }
```

```go
// myapp/runner.go
package myapp

import (
    "github.com/Fheyalabs/ares-core/pkg/ares/phase"
    "github.com/Fheyalabs/ares-core/pkg/ares/phase/keygen"
)

func Pipeline() (*phase.SessionRunner, error) {
    return phase.Compose(
        PhaseInvite{},               // INVITING → LOCKED
        keygen.NewPlaintextKeygen(), // LOCKED   → GOSSIP   (framework)
        PhaseCollect{},              // GOSSIP   → SCORING
        PhaseAnnounce{},             // SCORING  → DONE
    )
}
```

That's it. Compose with `phase.Compose`, point a `transport.Service`
at the runner, and you have a working app that handles invitations,
participant bootstrap, message accumulation with quorum, deterministic
state-machine validation, and audit logging for free.

To swap in real FHE later, replace `keygen.NewPlaintextKeygen()` with
`defaults.NewPhase0aThresholdKeygen()` and add a
`defaults.NewPhase3ThresholdDecrypt()` step before announce — the
framework's composition guard catches the topology mismatch at
construction time if you mix them up.

The reference apps under `examples/` are larger only because they add
real FHE, signed transcripts, multiple runners, or amortized keygen —
none of which is required to *start*. See
[`examples/voting/`](examples/voting/) for the closest match to this
shape with tests.

## Install

### Go dependency

```bash
go get github.com/Fheyalabs/ARES-core@latest
```

### OpenFHE prerequisite

ARES Core links the **OpenFHE 1.5.x** C++ library for its CKKS and BFV
primitives. Pin to 1.5.1 — earlier versions choose different cyclotomic
primes for the same nominal parameters and ciphertexts won't
interoperate across versions (the framework detects this and refuses to
proceed).

```bash
git clone --branch v1.5.1 --depth 1 https://github.com/openfheorg/openfhe-development.git
cd openfhe-development
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)        # or `sysctl -n hw.ncpu` on macOS
sudo make install
```

ARES Core's cgo paths search `/usr/local`, `/opt/homebrew`, and
`/usr/local/lib64` by default. For other prefixes, override via
`CGO_CXXFLAGS` / `CGO_LDFLAGS` — see
[`pkg/ares/crypto/cgo/bridge.go`](pkg/ares/crypto/cgo/bridge.go) for the
exact override pattern, and `pkg-config/openfhe.pc.in` for a
pkg-config template.

### Build the helper binary

```bash
git clone https://github.com/Fheyalabs/ARES-core.git
cd ARES-core
go build -tags openfhe -o bin/openfhe-helper ./cmd/openfhe-contract-helper
./bin/openfhe-helper --version    # should print v1.5.1
```

### Run tests

```bash
go test ./...                       # Go-only tests; no OpenFHE needed
go test -tags openfhe ./...         # full suite; requires OpenFHE
```

## Documentation

- [Framework concepts and customizing recipes](pkg/ares/phase/README.md)
- [Reference apps overview](#reference-apps) above
- [Python smoke scripts](clients/python/examples/README.md)
- [CHANGELOG.md](CHANGELOG.md)

## Contributing

Pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: please follow [SECURITY.md](SECURITY.md) rather than
filing public issues.

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
