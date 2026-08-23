<!-- SPDX-License-Identifier: Apache-2.0 -->

# Ride share

Reference app: a one-rider/N-driver ride matching session. The
rider's max price + start/end location and each driver's
encrypted bid + GPS are scored by a composite
`α·price_fitness + β·proximity` function; the winning driver +
agreed price reveal to both parties only.

## What it demonstrates

- Mixed-role pipelines (one rider, N drivers) under a single
  ARES runner.
- Composite scoring (weighted sum of two ciphertext inputs) at
  depth 12.
- v0.4.0 SC-10 ciphertext lineage protecting the
  dispatcher–driver–rider relay path.

## Pipeline

```text
Invite → Keygen → Submit → Score → Decrypt → Settle
```

`PhaseInvite` assigns the rider role to one participant and the
driver role to the rest. `PhaseSubmit` collects two distinct
payload shapes — one rider envelope (price ceiling + locations),
one bid per driver. `PhaseScore` runs the composite scorer
against the encrypted bids.

## Usage

Legacy (no lineage):

```go
runner, err := rideshare.Pipeline()              // stub scorer
runner, err := rideshare.PipelineWithHelper(c, p) // helper-backed
```

v0.4.0 lineage variant:

```go
signer, _   := sign.NewEd25519Signer()
verifiers   := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
runner, err := rideshare.PipelineWithLineage(signer, verifiers)

// helper-backed:
runner, err := rideshare.PipelineWithLineageAndHelper(client, sharpening, signer, verifiers)
```

Both the rider's envelope and each driver's bid become signed
`DAGNode`s. The dispatcher cannot swap a driver bid for one
favoring a different driver because the swap fails payload-hash
verification at the runner.

## Tamper-detection smoke

[`tamper_test.go`](tamper_test.go) — confirms that swapping a
driver's signed bid bytes is rejected with
`*lineage.MismatchError`. Exercises `SessionRunner.HandleLineageMessage`.

## Running as a service

[`cmd/session-service`](cmd/session-service) — standalone
HTTP+WebSocket service. Currently wires `rideshare.Pipeline()` /
`PipelineWithHelper()`; switching to lineage requires generating
a signer + verifiers at startup.

Environment:

| Var | Purpose |
|---|---|
| `SESSION_PORT` | listen port (default `8000`) |
| `ARES_WS_SECRET` | HMAC key (empty → dev bypass) |
| `RIDESHARE_CRYPTO_DEPTH` | CKKS depth (default `12`) |
| `RIDESHARE_RING_DIM` | CKKS ring dimension |
| `ARES_HELPER_BINARY` | helper path (empty → stub scorer) |

## Slot anonymity

**Available but not adopted here.** The ride-share pipeline uses a
custom state arc (`RIDE_INVITE` → `RIDE_KEYGEN` → `RIDE_SUBMIT` →
`RIDE_SCORE` → `RIDE_DECRYPT` → `RIDE_SETTLE`). The generic
`PhaseGShuffle` / `PhaseGVerify` phases from `pkg/ares/phase/anon`
occupy the GOSSIP→VERIFYING arc; this pipeline does not pass through
that arc.

Beyond the arc mismatch, anonymizing submission slots would conflict
with the protocol's design goal: the winning driver's identity and the
agreed price are the explicit outputs of threshold decryption. Both are
revealed to the rider and driver pair by `PhaseSettle`. Hiding the
driver's slot→identity link before scoring would add onion-shuffle
overhead without changing what the matched pair ultimately learns about
each other.

An app that wants to anonymize which driver submitted which encrypted
bid until after scoring can compose `PhaseGShuffle` + `PhaseGVerify`
over a GOSSIP→VERIFYING→submit arc, then wire the RIDE_SCORE /
RIDE_DECRYPT / RIDE_SETTLE phases after. See `examples/voting`'s
`PipelineWithShuffle` for the composition pattern.

## References

- ARES Spec v2.5 §SC-10.
- [`pkg/ares/lineage/`](../../pkg/ares/lineage/),
  [`pkg/ares/sign/`](../../pkg/ares/sign/).
- [`pkg/ares/phase/anon/`](../../pkg/ares/phase/anon/) — opt-in
  onion-shuffle phases (not used here).
- [CHANGELOG `[0.4.0]`](../../CHANGELOG.md).
