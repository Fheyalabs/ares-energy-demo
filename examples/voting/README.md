<!-- SPDX-License-Identifier: Apache-2.0 -->

# Blind voting

Reference app: an anonymous-ballot, sum-weighted tally with no
FHE. Uses `keygen.PlaintextKeygen` (no-op keygen that satisfies
the pipeline's topology requirements) and a plain integer-sum
tally. Threat model: trusted orchestrator, anonymous ballots
between submission and tally.

## What it demonstrates

- ARES app that doesn't need FHE — the framework's value here is
  the state-machine + transport plumbing, not the encrypted
  scoring.
- `keygen.PlaintextKeygen` as the canonical no-crypto keygen
  topology.
- v0.4.0 SC-10 ciphertext lineage protecting **non-FHE byte
  payloads**: lineage binds each ballot's plaintext bytes to its
  submitter so the orchestrator cannot swap ballots between
  collection and tally. Demonstrates SC-10 is a binding-over-
  bytes primitive, not a binding-over-ciphertexts primitive.

## Pipelines

- `Pipeline()` — plaintext, no anonymity (trusted orchestrator).
- `PipelineWithLineage(...)` — adds SC-10 ballot binding.
- `PipelineWithShuffle(...)` — adds inter-participant **slot anonymity**
  via `pkg/ares/phase/anon` so the authority cannot link an anonymized
  ballot slot to the voter. See that package's godoc for the SC-7
  collusion bound (certain deanonymization needs `k >= N-2` colluders).

```text
Invite → PlaintextKeygen → SubmitVote → Tally → Settle
```

## Usage

Legacy (no lineage):

```go
runner, err := voting.Pipeline()
```

v0.4.0 lineage variant:

```go
signer, _   := sign.NewEd25519Signer()
verifiers   := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
runner, err := voting.PipelineWithLineage(signer, verifiers)
```

Each ballot becomes a signed `DAGNode` whose `PayloadHash`
covers the plaintext vote bytes. A tampered ballot fails verify
at the runner before reaching `PhaseTally`.

## Tamper-detection smoke

[`tamper_test.go`](tamper_test.go) — the canonical demonstration
that SC-10 protects byte payloads regardless of whether they are
FHE ciphertexts. Tampers a signed vote and asserts
`*lineage.MismatchError`.

## Running as a service

Unlike the other three examples, voting does not ship a
`cmd/session-service`. Consumers wire the runner into their own
HTTP+WebSocket service using `transport.NewService` directly —
the auction or ride-share session-service files are reasonable
templates.

## References

- ARES Spec v2.5 §SC-10.
- [`pkg/ares/lineage/`](../../pkg/ares/lineage/),
  [`pkg/ares/sign/`](../../pkg/ares/sign/),
  [`pkg/ares/phase/keygen/`](../../pkg/ares/phase/keygen/) for
  `PlaintextKeygen`.
- [CHANGELOG `[0.4.0]`](../../CHANGELOG.md).
