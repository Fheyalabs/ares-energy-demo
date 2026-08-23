<!-- SPDX-License-Identifier: Apache-2.0 -->

# `pkg/ares/lineage`

Session-rooted Merkle DAG implementing **SC-10 (Ciphertext Lineage
Primitive)** from ARES Protocol Specification v2.5. Closes the
ultrareview C1 finding (SC-5 `C_emb` undefined) and substantially
addresses H2 (Phase 2 ciphertext-binding gap) for the framework code
path.

## Concept

Every byte payload at a phase boundary becomes a node in a Merkle
DAG. Each node is content-addressed (SHA-256), signed by its producer
(default Ed25519 via [`pkg/ares/sign`](../sign/)), and references
parent inputs that produced it. Mutating any node changes its hash
and (transitively) every descendant's hash; forging a node requires
the producer's private key.

The framework auto-wraps phases via `phase.ComposeWith(...)`: it
verifies inbound commits before `Phase.OnMessage` and auto-commits
`Phase.Provides` outputs after `Phase.Exit`. Applications opt out
specific outputs via `phase.ContextKeyType.NoLineage: true`.

## Quick start

```go
import (
    "context"

    "github.com/Fheyalabs/ares-core/pkg/ares/lineage"
    "github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

signer, _ := sign.NewEd25519Signer()
store     := lineage.NewInMemoryStore()
verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

// Producer: commit a payload to (session, phase, role).
node, _ := lineage.Commit("session-1", "phase-1b", "profile-ct",
    []byte("payload bytes"), nil, signer)
_ = store.Append(context.Background(), node)

// Verifier: confirm the bytes hash to the committed PayloadHash
// and the signature verifies under the producer's pubkey.
err := lineage.Verify(node, []byte("payload bytes"), verifiers)
```

For production use through the framework runner, see the integration
section below.

## Public API

### Types

- `NodeRef [32]byte` — SHA-256 content hash identifying a `DAGNode`.
- `DAGNode` — one entry in the Merkle DAG. Carries `Hash`,
  `SessionID`, `PhaseID`, `Role`, `Parents []NodeRef`,
  `ParentRoles []string`, `PayloadHash`, `CreatedAt time.Time`,
  `Producer []byte`, `Signature []byte`, `Algorithm string`.
- `Store` interface — 3 methods: `Append(ctx, node) error`,
  `Get(ctx, hash) (DAGNode, error)`,
  `WalkSession(ctx, sessionID) iter.Seq2[DAGNode, error]`.
- `InMemoryStore` — default `Store` implementation, safe for
  concurrent use, supports `Clear(sessionID)` for post-EndSession
  cleanup.
- `*MismatchError` — structured verify failure. `Field` names the
  specific check that failed (`"PayloadHash" | "Signature" |
  "ParentRef" | "Algorithm"`); `Expected` / `Got` / `NodeHash` carry
  forensic detail.

### Sentinel errors

- `ErrNodeNotFound` — `Store.Get` couldn't find the hash. Use
  `errors.Is(err, lineage.ErrNodeNotFound)`.
- `ErrNodeExists` — `Store.Append` was called with a hash already
  present. **This is idempotent and OK** — same content can be
  re-appended without harm; the error is informational for callers
  that care about novelty. The framework's runner treats this as a
  no-op.

### Functions

- `Commit(sessionID, phaseID, role string, payload []byte, parents []DAGNode, signer sign.Signer) (DAGNode, error)`
  — constructs a signed DAGNode for the given payload. Does **not**
  persist; the caller (or framework) passes the result to
  `Store.Append`. Returns error if `signer` is nil.
- `Verify(node DAGNode, payload []byte, verifiers map[string]sign.Signer) error`
  — checks the four invariants (algorithm supported, payload hashes
  to PayloadHash, declared Hash derives canonically from fields,
  signature valid under producer pubkey). Returns `nil` on success
  or `*MismatchError` on failure.
- `DeriveNodeHash(sessionID, phaseID, role string, payload []byte, sortedParents []NodeRef) NodeRef`
  — canonical content hash. Parents must be in canonical sorted
  order (use `NewDAGNode` or `Commit` for sorting).
- `HashPayload(payload []byte) NodeRef` — `sha256(payload)` as a
  `NodeRef`.
- `SigningMessage(hash NodeRef, sessionID, phaseID, role string) []byte`
  — canonical bytes the producer signs (`Hash || SessionID ||
  PhaseID || Role` with length prefixes).
- `NewDAGNode(...)` — direct constructor; `Commit` is the
  Signer-aware convenience wrapper.

## Canonical hash format

`DeriveNodeHash` uses length-prefixed concatenation under SHA-256 to
prevent length-ambiguity collisions:

```
sha256(
    u32_be(len SessionID) || SessionID ||
    u32_be(len PhaseID)   || PhaseID   ||
    u32_be(len Role)      || Role      ||
    u32_be(32)            || PayloadHash[32]  ||
    u32_be(num parents)   || parent[0] || parent[1] || ...
)
```

`CreatedAt` is **deliberately not in the hash** — content-addressing
requires determinism across producers, and N-party clock skew would
break independent verification of "this is the same node".

`SigningMessage` is similarly length-prefixed:

```
Hash[32] ||
u32_be(len SessionID) || SessionID ||
u32_be(len PhaseID)   || PhaseID   ||
u32_be(len Role)      || Role
```

## Framework integration

Applications enable SC-10 lineage by constructing their runner via
`phase.ComposeWith(...)` instead of `phase.Compose(...)`:

```go
import (
    "github.com/Fheyalabs/ares-core/pkg/ares/lineage"
    "github.com/Fheyalabs/ares-core/pkg/ares/phase"
    "github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

mySigner, _ := sign.NewEd25519Signer()
peerVerifiers := map[string]sign.Signer{
    sign.Ed25519Algorithm: mySigner, // verifier wraps Signer; pubkey
                                      // lives on each DAGNode.Producer
}

runner, err := phase.ComposeWith(
    []phase.Phase{phase1, phase2, phase3},
    phase.WithSigner(mySigner),
    phase.WithPeerVerifiers(peerVerifiers),
    phase.WithStore(lineage.NewInMemoryStore()),
    phase.WithLineageFailureHook(func(ev phase.LineageFailureEvent) {
        // app-defined penalty handler (e.g. brownie deduction)
        myBrownieHandler.Apply(ev.Attributee, ev.Kind)
    }),
)
```

The runner auto-wraps every phase. Transport layer calls
`runner.HandleLineageMessage(...)` (not `HandleMessage`) for inbound
v2 frames; the framework's pre-OnMessage hook verifies the embedded
`Lineage *DAGNode` before phase code sees the message.

After each `Phase.Exit`, the runner iterates `Phase.Provides` and
auto-commits each output where:

1. The declared `TypeName` doesn't have `NoLineage: true` (default
   `false` means **lineage enforced**).
2. The actual `ctx.Set(key, val)` value is `[]byte`. **Non-`[]byte`
   values are silently skipped.** Apps wanting to commit struct
   types must serialize to `[]byte` themselves before `ctx.Set`.
   (Future v0.5.0 may add a declarative serializer hook.)

### Opt-out per output

To exempt a specific output from auto-commit, set `NoLineage: true`
on the corresponding `ContextKeyType`:

```go
func (p MyPhase) Provides() phase.ContextSchema {
    return phase.ContextSchema{
        "CtxHeartbeat":     {TypeName: "bool", NoLineage: true},  // public, no binding needed
        "CtxProfileCipher": {TypeName: "[]byte"},                 // default false = lineage enforced
    }
}
```

Auditable: `grep "NoLineage: true"` across the codebase reveals every
escape hatch.

## Verification failure handling

When `runner.HandleLineageMessage` finds a verification failure, it:

1. Returns the error wrapping `*MismatchError` from
   `HandleLineageMessage`.
2. Fires the registered `LineageFailureFn` hook with
   `Kind="mismatch-confirmed"` and `Attributee=node.Producer`.
3. **Does NOT** dispatch to `Phase.OnMessage`.

To attribute a false framing (a party broadcasts a mismatch claim
that other parties cross-verify as unfounded), the transport layer
calls `runner.ReportFalseLineageClaim(...)` which fires the hook
with `Kind="mismatch-false-claim"` and `Attributee=claim.Producer`.

The framework recovers from app-hook panics — a buggy
`LineageFailureFn` cannot crash the runner. The current
implementation silently swallows panics; a planned developer-experience
follow-up will surface them via stderr logging.

## Persistent stores

The `Store` interface is 3 methods (`Append`, `Get`, `WalkSession`).
The default `InMemoryStore` clears on `EndSession`; applications can
swap in Postgres-, Redis-, or S3-backed implementations for
forensic-grade audit without framework changes.

A persistent backend's `Append` may have higher latency or be
transactional; the framework treats `Append` errors (other than
`ErrNodeExists`) as session-fatal. Production deployments should
consider error-classification (transient vs permanent) at the
backend layer.

## Honest scope (what SC-10 closes and what it doesn't)

See ARES Spec v2.5 §SC-10 for the canonical statement. In summary:

**Closes**: byte-level ciphertext substitution detected within the
framework code path; C1 (`C_emb` definition); M3 hardening (OpenFHE
serialization-version pinning is now load-bearing for security).

**Substantially addresses**: H2 (server-side substitution between
phases) when the framework's pre-OnMessage hook actually runs.

**Does not close**: H1 (X25519 ECIES format-check limitation),
wrong-circuit attacks (server runs the wrong FHE function on the
right bytes — requires verifiable computation), H5 (uniform-shuffle
randomness — requires Bayer-Groth ZK shuffle), full M4 (key-share
well-formedness — requires PVSS/DKG primitives), and
fully-malicious-server attacks that bypass the framework's runner
entirely.

## Related

- [`pkg/ares/sign`](../sign/) — pluggable signature primitive backing
  the `Signer` parameter on `Commit` and the verifier-map values on
  `Verify`.
- [`pkg/ares/phase`](../phase/) — runner with auto-wrap dispatch
  (`ComposeWith`, `HandleLineageMessage`, post-Exit commit).
- [`pkg/ares/transport`](../transport/) — `WSMessage.Lineage` field
  carrying the inline `DAGNode`; `ArtifactStore.PutContent` /
  `GetContent` for content-addressed large blobs.
- ARES Spec v2.5 §SC-10 — protocol-layer documentation.
