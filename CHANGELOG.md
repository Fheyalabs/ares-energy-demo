# Changelog

All notable changes to ARES Core are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/) (pre-1.0: minor
versions may include breaking changes).

## [Unreleased]

### Added

- **Kotlin BFV encrypted-location input helpers.** `ares-client-fhe` now
  exposes BFV contexts, exact packed-int7 profile encryption, exact packed
  threshold fusion, repeated-scalar origin encryption, and client-side
  encrypted squared-distance construction. Kotlin clients can therefore build
  the ciphertext-only BFV fallback input contract without serializing raw
  location values or decrypting candidate scores.

## [0.9.14] — 2026-07-18

### Added

- **Swift BFV encrypted-location input helpers.** `AresClientFHE` now exposes
  exact repeated-scalar BFV encryption and client-side encrypted squared
  distance construction. The helper accepts serialized encrypted origins plus
  local integer coordinates, so applications can submit the ciphertext-only
  BFV fallback input contract without serializing raw location values.

## [0.9.13] — 2026-07-17

### Added

- **Ciphertext-only CKKS inputs for chunked threshold scoring.**
  `EncryptedInputFuseRequest` carries candidate-major encrypted payload chunks
  and encrypted squared-distance inputs. `ChunkedFuseEncryptedInputsCKKS` and
  its union-scoring variants take this narrow type, which has no plaintext
  package or location fields. The eval-sum reference variants retain the
  b-only key layout for memory-bounded sessions.
- **Client encryption helpers for the encrypted-input path.** Swift and
  Kotlin FHE clients expose payload-chunk encryption, repeated-scalar
  encryption, and local encrypted squared-distance construction. Their native
  bindings share the canonical bridge packing, so the two clients produce the
  same chunk layout.
- **Ciphertext-only exact BFV fallback fusion.** `BFVBlindFuseRequest` accepts
  encrypted profiles, client-derived encrypted squared distances, server-owned
  brownie offsets, and encrypted payloads, then returns only one fused
  threshold ciphertext. It has no coordinate or plaintext-score fields.
  BFV eval-sum combines can resolve artifact-backed shares incrementally, and
  the blind-fusion polynomial path defaults to its lower-residency power cache.
- **Three-stage threshold keygen runner coverage.**
  `Phase0aThresholdKeygen` now explicitly consumes `keygen.eval_round1` in
  addition to `keygen.share` and `keygen.eval_share`, allowing applications to
  durably acknowledge every evaluation-key stage before advancing their
  session state.
- **Single-key evaluator-key transfer APIs.**
  `SingleKeyGenWithEvalKey`, `SingleKeyAuctionServerWithEvalKey`, and
  `SingleKeyAuctionServerEncWithEvalKey` support a separate evaluator context
  without exposing the secret key. The legacy single-key auction entry points
  now fail before evaluation with a migration error because their signatures
  cannot carry this required public evaluation material.

## [0.9.12] — 2026-07-04

### Added

- **Explicit OpenFHE global context-factory release.**
  `ReleaseOpenFHEGlobalContexts` clears OpenFHE's process-global
  `CryptoContextFactory` cache, and `OpenFHEContextCount` exposes the retained
  context count for diagnostics. Long-lived services should call the release
  only at a quiescent boundary where no CryptoContext handles are in use.

## [0.9.11] — 2026-07-04

### Fixed

- **OpenFHE context close now clears inserted eval-key maps.** `CryptoContext`
  reuse inserts eval-mult/eval-sum keys into OpenFHE's static context-keyed
  maps. `FreeCryptoContext` now clears those maps before deleting the wrapper,
  preventing same-parameter contexts from inheriting stale keys and reducing
  post-session native memory residency for Fheya union scoring.

## [0.9.10] — 2026-07-04

### Added

- **Per-index eval-sum refs for norm-style product sums.**
  `EvalProductSumForContractWithEvalSumRefs` lets consumers evaluate
  encrypted dot/norm checks against the b-only / CRS-seeded eval-sum
  key layout used by Fheya's memory-bounded union sessions. This keeps
  server-side normcheck on the same portable per-index key path as
  chunked union scoring instead of requiring a materialized merged
  `EvalSumFinal` blob.

## [0.9.8] — 2026-06-25

### Fixed

- **Empty selector-sharpen schedule no longer injects a hidden 4-pass
  smoothstep (depth-16 fix).** An unset `SelectorSchedule` was defaulted —
  both at the Go fuse boundary (`FullFusePayloadCKKS[WithContext]`,
  `ChunkedFusePayloadCKKS[WithContext]`) and in the native `split_schedule` —
  to `smoothstep5,smoothstep5,smoothstep5,smoothstep7`, adding ~9
  multiplicative levels. For the chunked union's logistic/tanh lanes (which
  need no sharpening) this silently exhausted the depth-16 budget
  (`DropLastElement(): Removing last element of DCRTPoly`). Selector
  sharpening is now strictly opt-in: an empty schedule means no passes (same
  as `"none"`), at both layers.
- **`CKKSRing32KUnionV1` lanes now declare `SelectorSchedule: "none"`.** The
  v0.9.7 default profile shipped its tanh/logistic lanes with an unset
  schedule, so running it through the chunked union at depth 16 hit the bug
  above. The shipped profile now runs the lightweight ring-2^15 / depth-16
  circuit at `HEStd_128_classic` out of the box (validated end-to-end through
  the Fheya server's `openfhe_union` backend: union 6/6, 0 wrong, secure).

## [0.9.7] — 2026-06-25

### Changed

- **Default CKKS union now diversifies by comparator FAMILY, not by gain.**
  `CKKSRing32KUnionV1` swaps the `ss5` selector lane for a tanh lane: the
  new trio is `{tanh_g5_d13, logi_g4_b5_d13, logi_g3_b6_d13}`. A 100-cohort
  full-Fheya-score sweep (7 candidate lanes, post-hoc subset analysis)
  showed the recovery ceiling is set by family diversity: a tanh lane
  uniquely recovers tight near-ties that the entire logistic family —
  including a degree-27 probe — misses, while the old `ss5` selector added
  zero marginal union (every cohort it opened, a logistic also opened). The
  new trio reaches union 98/100 — equal to a 7-lane fanout and one better
  than the prior ss5 trio — with the residual ~2% an irreducible noise
  floor that routes to BFV fallback. Same lane count (3) and
  `ComparatorWorkers`, so this is a default retune, not an API change.

## [0.9.6] — 2026-06-24

### Added

- **Concurrent comparator fanout.**
  `ChunkedUnionScoreCKKSWithConcurrency` runs the union comparator lanes
  concurrently against a single shared CKKS context.
  `ChunkedUnionScoreCKKS` now delegates to it with concurrency 1, so
  existing callers are unchanged. The native chunked and full-fuse entry
  points accept preinserted eval-mult / eval-sum keys (empty serialized
  key fields) so workers reuse context keys instead of re-serializing a
  monolithic blob per lane.

### Fixed

- **Shared-context eval-key race in concurrent fusion.** When more than
  one comparator lane ran against the same context, each call cleared and
  reinserted eval-mult / eval-sum keys, so a concurrent `EvalSum` could
  enter after the automorphism-key map had been cleared
  (`EvalAutomorphism(): Input evaluation key map is empty`). Concurrent
  union scoring now preinserts the eval-mult and eval-sum keys once into
  the shared context before launching workers, and each worker runs with
  empty serialized eval-key fields so the native scorer uses the
  preinserted keys and never mutates the key maps mid-score. Validated by
  a 200-cohort dim-128 / ring-32k full-Fheya-score sweep at
  `CONCURRENCY=4` (union 195/200, 0 wrong openings, 0 ties).

## [0.9.5] — 2026-06-23

### Added

- **Chunked CKKS union scoring.** Added the low-RSS chunked payload
  fusion entry point and made `ChunkedUnionScoreCKKS` the recommended
  union helper. It reuses one context across comparator shots, uses
  eval-sum-only payload chunks, and keeps the full-fuse API available
  for callers that need the older single-ciphertext shape.
- **Distribution-driven comparator tuning.** `DistributionMetadata`
  and `TuneUnion` now derive score amplification plus per-comparator
  input scales from caller-supplied score-margin statistics. Each
  comparator can also carry its own `RangeMargin`, so one union can
  deliberately cover close, middle, and wide score-difference regimes.
- **Additive crypto profiles.** New `pkg/ares/crypto/profiles`
  package defines named CKKS/BFV presets without replacing existing
  configurable modes: `ckks_ring32k_union_v1`,
  `bfv_ring32k_blind_v1`, and `bfv_light_blind_v1`.
- **Threshold BFV packed-integer mode.** The OpenFHE bridge,
  `openfhe-contract-helper`, and Go helperclient now expose BFV
  context creation, threshold keygen, eval-key rounds, packed integer
  encryption, partial decrypt/fusion, and encrypted product-sum
  scoring.
- **Swift BFV client surface.** `AresClientFHE` now supports
  `BFVCryptoContext`, packed integer encryption, and packed integer
  threshold fusion over the existing C bridge.
- **BFV examples.** Added `examples/blind_bfv_payload_fuse` for the
  ring-32k profile and `examples/light_bfv_payload_fuse` for fast
  CI/local smoke use. Both examples bind BFV artifacts through SC-10
  ciphertext lineage roles.

### Fixed

- Fixed `ARESFullFusePayloadCKKS` context selection so default full-fuse
  scoring reuses the caller's submitted-ciphertext context, while compact
  payload-sized batches remain limited to minimal-rotation mode.

### Removed

- Removed local homelab deployment recipes and the historical
  app-migration note from the public framework tree. Runtime examples
  and tested SDKs remain in the repository.
- Pruned dead exported bridge helpers: `DefaultBFVContractParams`
  (superseded by `profiles.BFVRing32KBlindV1`) and the eager
  `CombineEvalKeyRound1PerIndex` (the lazy/per-index combine is the live
  path). No callers in ARES-core, the contract helper, or the Fheya server;
  the private `combineEvalKeyRound1PerIndex` stays for the WithContext path.

## [0.8.0] — 2026-06-14

### Added

- **Single-key (non-threshold) CKKS reverse auction (`pkg/ares/crypto/cgo`,
  blind-price / ride-share).** A single-initiator MVP for sealed-price reverse
  auctions where one party holds the secret key: `SingleKeyEncrypt` +
  `SingleKeyAuctionServerEnc` for blind-price submission, an `n=5` full
  composite-key assembly at ring 2^14 / depth 4, and a server/rider split that
  binds the driver identity into the encrypted bid. `singleKeyGen()` and
  `decryptSingle()` are exposed in the Swift (`AresClientFHE`) and Kotlin
  (`ares-client-fhe`) clients; see `examples/ride_share`.
- **b-only rotation-key wire (CRS optimization).** Multiparty rotation /
  eval-sum key `a`-vectors are byte-identical across parties under the shared
  CRS, so a participant transmits only its `b`-vectors and the combiner rebuilds
  the full share from the shared `a` plus the party `b`: roughly half the
  per-party rotation-key upload, with no new crypto. Core bridge
  (`SerializeRotKeyBVectors` / `SerializeRotKeyAVectors` /
  `ReconstructRotKeyFromAB`) plus client wiring: Swift and Kotlin native
  bindings, and Python `split_rot_share` / `reconstruct_rot_share` ops over the
  contract-helper IPC.
- **Threshold-CKKS keygen amortization + memory-bounded benchmark suite
  (`pkg/ares/crypto/cgo`).** `TestKeygenAmortizationProfile` (stage breakdown and
  sizes), `TestResidentCombineProfile` (byte-path vs resident-in-RAM combine),
  and `TestPerPartyShareGenRAM` / `TestStreamedKeygenRAM` (per-party share-gen
  RAM through the depth-30 / ring-2^17 worst case), plus the
  `MeasureBOnlyRotShare` bridge helper. They are guarded by `testing.Short()`
  and run in a dedicated `keygen-bench.yml` `workflow_dispatch` lane on a
  high-RAM self-hosted runner.
- **Swift `AresClientFHE` is exposed as a SwiftPM library product**, so
  downstream packages can depend on the FHE client directly.

### Fixed

- **Swift `Decrypt.swift`:** corrected the extension braces.

### CI

- The hosted-runner `openfhe` lane now runs `go test -tags openfhe -short`. The
  keygen amortization / RAM benchmarks above were running on every push and
  exhausting the hosted runner, SIGTERM-killing the step (exit 143); the lane had
  been red since the suite landed. `-short` triggers the benchmarks' existing
  skips, and they keep their self-hosted `keygen-bench.yml` lane (which now uses
  the runner's pre-installed OpenFHE instead of building it).
- OpenFHE CI lane now installs to `/opt/openfhe` (instead of
  `/usr/local`) and caches that prefix only. Three concrete wins:
  cache restore drops from ~4 min to ~2 s, the build step is reliably
  skipped on cache hit (was incrementally rebuilding before), and a
  `concurrency: openfhe-${{ github.ref }}` group prevents parallel
  pushes from racing on the cache key. Warm-run wall time drops from
  14-18 min to ~3 min.

### Docs

- `docs/migrations/fheya-server.md` records the durable plan for
  retiring the historical `fheya-server` REST server in favor of an
  ARES-core + Fheya app composition. Surface map for all 25 legacy
  endpoints, six PR-sized migration steps, and the hard preconditions
  blocking most of the work (ARES-core 1.0 stable + Fheya app Phase
  1b/2/D real implementations).

## [0.7.5] — 2026-06-03

### Added

- **Swift ARES client library (`clients/swift`, SwiftPM).** A full client for the
  ARES protocol:
  - *Protocol-crypto (L1):* SC-2 N-layer onion routing (X25519 → HKDF-SHA256 →
    AES-256-GCM), SC-10 lineage DAG nodes with cross-language golden-vector parity
    (Go ≡ Python ≡ Swift), v2 wire frames, and Ed25519 device signing over canonical
    JSON.
  - *Threshold-CKKS FHE (L2, `AresClientFHE`, gated behind `ARES_OPENFHE`):* binds
    the canonical `pkg/ares/crypto/cgo/openfhe_wrapper` C bridge — N-party keygen
    chain, eval-mult + eval-sum key protocols, encrypt, partial-decrypt, fuse, eval
    ops, and full serialization, behind RAII handles.
  - *Transport (L3, `AresTransport`):* WebSocket `Session` / `AdminClient` /
    `Orchestrator` + `GossipParticipant`, proven by local cross-language end-to-end
    runs (sealed-bid auction FHE-ciphertext interop; voting onion-shuffle + lineage
    interop).
- **Kotlin/Android ARES client library (`clients/kotlin`, Gradle).** Mirrors the
  Swift client: L1 (Bouncy Castle X25519/Ed25519/HKDF + JCA) with golden-vector
  parity (signature byte-exact via deterministic Ed25519); L3 transport over OkHttp;
  threshold-CKKS FHE via JNI over the same canonical `openfhe_wrapper`
  (`ares-client-fhe`); voting + auction + bound-check cross-language e2e.
- **Client-side ARES-BC `BoundCheckParticipant` (Swift + Kotlin).** Implicit
  pass/fail verification of the server's `check_commitment` plus the party's
  partial-decrypt contribution; the application sees only a `BoundCheckResult` — the
  integrity check is transparent, and what to do on failure is application policy.
- **`examples/bounded_admission`.** A runnable ARES-BC session-service (invite →
  pre-shared keygen → bound check → settle) that broadcasts the full check-ciphertext
  + commitment set to every party for the N-of-N decryption quorum. Drives the
  cross-language bound-check e2e: in-bound admitted, out-of-bound flagged, tampered
  `enc_check` rejected by the implicit check.

### Changed

- **CKKS contexts are secure-by-default (`HEStd_128_classic`).** The OpenFHE bridge
  previously created contexts with `HEStd_NotSet`, silently disabling 128-bit
  security enforcement; an under-provisioned ring (too small for the requested
  multiplicative depth) is now rejected at context creation. Tests and local dev that
  deliberately use small, fast, sub-128-bit rings opt out via
  `ARES_FHE_ALLOW_INSECURE=1`, which falls back to `HEStd_NotSet` and prints a
  one-time stderr warning (never silent).

### Fixed

- **Transport verifies lineage frames.** v2 frames carrying lineage now route through
  the SC-10 `HandleLineageMessage` verification at the service layer instead of plain
  `HandleMessage` (v1 frames unaffected).
- **Swift transport:** a timed-out `receiveAny` now evicts and resumes its waiter,
  fixing an orphaned-continuation leak.
- **`examples/voting`:** `PhaseSettle.ExitState` corrected from a dead `BROADCASTING`
  state to `StateNone`; the anonymous onion-bucket accessor is exported so a
  WebSocket deployment of the shuffle arc can relay peeled onions.

### Build

- **Kotlin builds pin the Gradle daemon to JDK 17.** The bundled Kotlin compiler
  crashes when run on a host JDK that postdates it (e.g. JDK 26). The daemon-JVM
  criteria (`clients/kotlin/gradle/gradle-daemon-jvm.properties`, resolved via the
  foojay convention) make fresh builds reproducible regardless of the host's default
  JDK.

## [0.7.0] — 2026-05-31

### Added

- **Homomorphic bound check (`pkg/ares/phase/boundcheck`) — ARES-BC.** A generic,
  application-agnostic Phase-1c that, per party uniformly, homomorphically computes
  a single safe-to-decrypt squared magnitude `‖x − c‖²` (public center `c`) over the
  party's encrypted input, threshold-decrypts it across the participant quorum, and
  aborts the session via an application-supplied `ViolationHandler` when the value
  falls outside a committed `[lo, hi]`. Built-in circuits: `NormCircuit` (center 0 —
  the unnormalized-embedding / score-inflation check) and `DistanceBoundCircuit`
  (geographic-radius and multi-dimensional resource budgets). Reuses the existing
  joint eval keys (`EvalProductSum` = 0 added levels to a scoring circuit); circuit
  depth is determined offline with `pkg/ares/crypto/fhecalib`. Each `enc_check` is
  bound to its lineage-committed input via `check_commitment = H(enc_check ‖ H(enc_x)
  ‖ session_id)`. Five security invariants keep the attack surface flat: center-only
  (no projection oracle), one bound per input (no stacking leak), public all-party-
  agreed parameters, opaque jittered abort with a threshold-quorum fuse, and a hard
  refusal of `dim < 2` inputs (a scalar's squared magnitude would leak its value;
  scalar exact-range needs a future homomorphic-comparison circuit). Validated on
  real OpenFHE with an end-to-end n-party keygen → encrypt → partial-decrypt → fuse
  phase round. The server computes with public eval keys only — it never holds a
  secret-key share.
- **`pkg/ares/crypto/fhecalib` extension.** `ContextHandle` gains `EvalSubConst`
  (subtract a public center vector) and `EvalProductSum` (squared magnitude); a new
  `NewContextHandle` constructor lets consumers build a handle from session keys; the
  internal eval-key provisioning now carries the full `EvalKeyFinal` bundle.

### Fixed

- **`cgo` OpenFHE wrapper: idempotent eval-key insertion.** `InsertEvalMultKey` /
  `InsertEvalSumKey` now clear the per-context key slot before inserting, so two
  same-parameter contexts within one operation (e.g. a multi-party bound-check round)
  no longer collide on OpenFHE's process-global eval-key map. No behavioural change
  to existing single-context operations.

## [0.6.0] — 2026-05-31

### Added

- **Python client primitives (`clients/python/ares_client`).** Generic,
  application-agnostic building blocks for ARES clients: an SC-2-correct
  ECIES onion (`onion.py` — N-layer build/peel with ciphertext-memory-match
  self-identification, no skip-self), an SC-10 lineage `DAGNode` builder
  (`lineage.py`, hex/snake_case wire form that reproduces the Go golden
  vectors byte-for-byte), a `GossipParticipant` driving the onion-shuffle →
  slot-submission arc (`gossip.py`), and `WSMessage.lineage` /
  `ARESSession.send(lineage=)` v2-frame support (`session.py`).
  Cross-language parity is locked by `tests/test_lineage_vectors.py`
  against `pkg/ares/lineage/testdata/node_vectors.json`. Python package
  version bumped 0.4.1 → 0.5.0.
- **FHE circuit depth calibrator (`pkg/ares/crypto/fhecalib`).** A generic,
  application-agnostic tool that finds the minimum CKKS multiplicative depth
  a homomorphic circuit needs, by running the real computation at increasing
  depth until the decrypted result matches a plaintext ground truth within
  tolerance. Implement `CircuitUnderTest` for your circuit and call
  `Calibrate` (requires the `openfhe` build tag) to get the minimum viable
  depth plus achieved precision; `ErrModulusCap` signals when a depth would
  exceed the 128-bit-classic ciphertext-modulus budget for the ring
  dimension (so the caller raises the ring). A development/CI tool — run it
  once per use case and bake the resulting depth into context config.

## [0.5.2] — 2026-05-29

### Changed

- **Lineage v2 wire JSON is now hex + snake_case.** `lineage.NodeRef`
  marshals as a lowercase 64-char hex string (was a 32-int array) and
  `lineage.DAGNode` uses snake_case keys with hex-encoded `hash`,
  `payload_hash`, `parents`, `producer`, and `signature` (was base64 /
  PascalCase). Makes the SC-10 v2 frame reproducible by non-Go clients
  (the keystone for the Fheya app's lineage-shuffle adoption). In-memory
  `DAGNode` field types are unchanged; only the JSON form changed. Safe:
  the v2 lineage frame had no external (non-ares-core) consumer yet.

## [0.5.1] — 2026-05-29

### Added

- **`SessionContext.CommitArtifact`** (`pkg/ares/phase`) — new method that
  commits a phase output as a lineage DAG node with **explicit parent edges**
  supplied by the caller, signed by the runner's signer, and appended to the
  session store. Intended for phases whose output's lineage parents are not
  derivable from `Phase.Requires` keys (e.g. a node assembled from accumulated
  WS messages). Returns `ErrPermanent` on `Compose`-built (non-lineage)
  runners; degrades to a no-op when called from a bare context (unit-test
  compatibility). The runner injects the signer into `SessionContext` during
  `BeginSession` so phases can call `CommitArtifact` without importing the
  runner package.
- **`pkg/ares/phase/anon` — `PhaseGVerify` explicit parent edges** —
  `PhaseGVerify.Exit` now calls `CommitArtifact` to bind the assembled slot
  list node to the exact slot-submission nodes that produced it. The
  `CtxAssembledSlotList` output is marked `NoLineage: true` in `Provides()` to
  suppress the runner's parent-less auto-commit. `RoleSlotSubmission` is
  exported as a package constant (replacing the prior inline string literal
  `"slot-submission"`) so both the sender (`Participant.SlotSubmission`) and
  the receiver (`PhaseGVerify`) reference the same value.

## [0.5.0] — 2026-05-29

### Added

- **`pkg/ares/onion`** — client-side slot-anonymization crypto:
  X25519 ECIES envelopes (HKDF-SHA256 `ares_onion_v1` + AES-256-GCM,
  Python wire-parity), SC-2-correct onion construction
  (`BuildOnion`/`PeelBatch` with self-layer + ciphertext-memory-match
  identification), and a deterministic coordinator-free
  `SlotPermutation`. Package godoc documents the SC-7 collusion bound
  (certain deanonymization requires `k >= N-2` colluders; 50% floor at
  `k = N-3`). Foundation for the canonical onion-shuffle phases (next).
- **`pkg/ares/phase/anon`** — composable onion-shuffle phases for
  inter-participant slot anonymity: `PhaseGShuffle` (sequences the
  peel rounds, GOSSIP→VERIFYING) and `PhaseGVerify` (accumulates
  ephemeral-key-signed slot submissions and assembles + lineage-commits
  the ordered slot list, VERIFYING→caller's next state), plus a
  `Participant` client driver. Verification is lineage-native — slot
  submissions are SC-10 DAG nodes signed by ephemeral per-slot keys, so
  the relay/other participants cannot tamper without an attributable
  mismatch, and no participant learns another's slot→identity mapping.
- **`examples/voting` `PipelineWithShuffle`** — worked adopter of the
  onion-shuffle primitive; demonstrates `PhaseGShuffle` + `PhaseGVerify`
  composed over the GOSSIP→VERIFYING arc on a non-FHE pipeline so the
  election authority cannot link an anonymized ballot slot to its voter.

## [0.4.1] — 2026-05-28

Developer-experience patch. No new protocol features, no API breaks.
Cuts the consumer-facing rough edges flagged during the v0.4.0
implementation review so the next consumer integration (Fheya
app's opportunistic ComposeWith migration; external app authors
adopting the framework) reads well-documented, classifiable
errors.

### Added

- **Failure-type sentinels** in `pkg/ares/phase`. Four sentinel
  errors apps use to branch retry / penalty / report-bug policy
  via `errors.Is(err, phase.ErrXxx)` without string-matching:
  - `phase.ErrTransient` — retryable (backend unreachable, lock
    contention, transient network).
  - `phase.ErrPermanent` — non-retryable (config, schema,
    invariant breach, caller misuse).
  - `phase.ErrAppAttributable` — counterparty caused (tampered
    payload, false mismatch claim, malformed commit).
    `errors.As(err, &mismatchErr)` still recovers the typed
    `*lineage.MismatchError` underneath.
  - `phase.ErrFrameworkBug` — unexpected internal condition
    (apps surface, do not silently recover).
- **`phase.SetHookPanicLog(io.Writer) io.Writer`** — process-init
  override for the destination `fireFailureHook` writes to when
  an app-registered `LineageFailureFn` panics. Default
  `os.Stderr`. Pass `io.Discard` to silence; pass a
  `*bytes.Buffer` in tests to capture and assert.

### Changed

- **Every framework-level error from the `SessionRunner` public
  API is now classified with a sentinel.** Apps that previously
  string-matched error messages now branch via `errors.Is`. The
  underlying typed errors (e.g. `*lineage.MismatchError`) remain
  recoverable via `errors.As`. See `errors_classify_test.go` for
  the full classification table.
- **`fireFailureHook` panic-recovery logs to stderr** instead of
  silently swallowing the recovered value. The runner still
  recovers (so a buggy hook doesn't crash the runner), but the
  misbehavior is now observable at runtime.

### Docs

Five load-bearing-but-implicit behaviors now surface in the public
godoc rather than only in the implementation:

- `ComposeWith` auto-commit exemption rules — non-`[]byte` runtime
  values are silently skipped (apps must marshal struct types
  before `ctx.Set`); `NoLineage: true` Provides outputs are
  intentionally skipped.
- `BeginSession` does NOT cascade past the initial phase even if
  `CheckComplete` returns true. The pause exists so
  `SessionTrigger` implementations can seed canonical context
  entries before the second phase's `Enter` runs.
- `AdvanceToState` behavior on the three corner cases:
  target == current (no-op), target ∈ InternalStates of current
  phase (no-op), target == `StateNone` (rejected — callers should
  `EndSession` explicitly).
- `HandleMessage` vs `HandleLineageMessage` on a `ComposeWith`-built
  runner — `HandleMessage` works but skips lineage verification.
- `BuildMismatchClaim`: the `role` parameter is accepted but NOT
  propagated to the resulting `DAGNode` (whose `Role` is
  hardcoded to `"mismatch-claim"` so receivers can distinguish a
  claim from a real commit). Documented as a known v0.5.0
  follow-up rather than fixed in v0.4.1 (would be a behavior
  change to v0.4.0 API surface).

Every public-method godoc now also lists the sentinels its
errors classify with so apps know which branch to take without
reading the implementation.

### Tests

- Per-app **bitflip tests at every lineage-protected stage**
  (15 new subtests across the 4 reference apps). Each subtest
  flips a single payload bit between `lineage.Commit` and
  `HandleLineageMessage` and asserts `*MismatchError{Field:"PayloadHash"}`
  at every phase boundary the framework auto-binds. Strong-form
  SC-10 demonstration: not just "lineage detects tampering at
  the bid stage" but "every stage and any single-bit flip."
- New **helper+lineage combined tests** (5 new subtests across
  the 3 FHE reference apps). `PipelineWithLineageAndHelper`
  constructors had zero prior coverage — a constructor-arg-order
  bug would have shipped silently. Now exercised end-to-end
  with a live OpenFHE helper subprocess.

## [0.4.0] — 2026-05-28

**SC-10 Ciphertext Lineage Primitive** — framework-level Merkle DAG
binding every byte payload at every phase boundary. Closes
ultrareview findings C1 (SC-5 `C_emb` undefined) and substantially
addresses H2 (Phase 2 ciphertext-binding gap) for the framework code
path. See ARES Spec v2.5 §SC-10 for protocol-level documentation;
`pkg/ares/lineage/README.md` and `pkg/ares/sign/README.md` for the
Go-side API.

### Added

- **`pkg/ares/sign/`** — new package. Pluggable `Signer` interface;
  `Ed25519Signer` default (crypto/ed25519 from stdlib). HSM-backed
  and post-quantum schemes substitutable via the interface.
- **`pkg/ares/lineage/`** — new package. `DAGNode`, `Commit`,
  `Verify`, `Store` interface, `InMemoryStore` default; structured
  `*MismatchError` for failure forensics. Idempotent `Append`;
  `WalkSession` returns `iter.Seq2[DAGNode, error]` for lazy
  iteration.
- **`phase.ContextKeyType.NoLineage`** — opt-out field on
  context-key declarations. Default `false` (lineage enforced). Set
  `true` for ephemeral or public outputs that don't need
  cryptographic binding. Auditable from one place: grep
  `"NoLineage: true"`.
- **`phase.ComposeWith(phases, opts...)`** — new constructor for
  lineage-enabled pipelines. Options: `WithSigner` (required),
  `WithPeerVerifiers` (required for multi-party), `WithStore`
  (default `InMemoryStore`), `WithLineageFailureHook`.
- **`phase.LineageFailureEvent` + `phase.LineageFailureFn`** —
  structured callback for app-level penalty handlers (Fheya's
  brownie deductions, etc.). Kinds: `"mismatch-confirmed"`,
  `"mismatch-false-claim"`.
- **`SessionContext.LineageDAG()`** — read-only `iter.Seq[DAGNode]`
  over the session's DAG nodes. Empty on `Compose`-built runners.
- **`SessionRunner.HandleLineageMessage(...)`** — transport-layer
  entry point that verifies + persists inbound lineage before
  dispatching to `Phase.OnMessage`. Compose-built runners fall
  through to the legacy `HandleMessage` path.
- **`SessionRunner.BuildMismatchClaim(...)` /
  `SessionRunner.ReportFalseLineageClaim(...)`** — framework hooks
  for the transport layer's mismatch cross-verification flow.
- **`transport.WSMessage.Lineage *lineage.DAGNode`** — required
  field on v2 frames. Full signed `DAGNode` rides inline with the
  payload (no separate commit frame, no ordering window).
- **`transport.WireProtocolVersionLineage = "2"`** — new wire
  version for ComposeWith-built pipelines. Existing
  `WireProtocolVersion = "1"` preserved for Compose-built
  pipelines.
- **`transport.ArtifactStore.PutContent` /
  `transport.ArtifactStore.GetContent`** — content-addressed methods
  alongside the existing app-keyed API. `GetContent` detects
  in-memory corruption via re-hash, returns `ErrCorrupted` on
  mismatch.
- **`transport.ValidateInboundMessage`** — hub strict-mode validator.
  v2 frames missing `Lineage` are rejected; unknown versions
  rejected; v1 frames accepted regardless of `Lineage` (backward
  compat).
- **`cgo.RoundTripCiphertext`** (`-tags openfhe`) — exported wrapper
  for the OpenFHE serialization golden-hash test
  (`pkg/ares/crypto/cgo/serialization_golden_test.go`) which guards
  the OpenFHE 1.5.1 pin against drift via a checked-in fixture in
  `pkg/ares/crypto/cgo/testdata/`.
- Reference apps migrated:
  - `examples/sealed_bid_auction/` — `PipelineWithLineage` +
    `PipelineWithLineageAndHelper` + tamper smoke test.
  - `examples/ride_share/` — same shape.
  - `examples/recurring_cohort_ranking/` —
    `FormationPipelineWithLineage` +
    `WeeklyPipelineWithLineage` (both take a shared
    `lineage.Store`) + tamper smoke test on the standalone-
    composable formation pipeline.
  - `examples/voting/` — `PipelineWithLineage` + tamper smoke
    (demonstrates SC-10 protects non-FHE byte payloads too).
  - Legacy `Pipeline()` / `PipelineWithHelper()` / `WeeklyPipeline()`
    / `FormationPipeline()` constructors preserved unchanged.

### Compatibility notes

- Existing `phase.Compose(phases...)` call sites unchanged; emit v1
  wire frames; lineage stays off. No breakage for v0.3.x consumers.
- Applications opt into lineage by switching to
  `phase.ComposeWith(...)`. Fail-fast at construction time if
  required options (Signer; PeerVerifiers for multi-party) are
  missing.
- WSMessage v2 frames are accepted by the hub iff `Lineage` is
  non-nil; v1 frames continue working as before.

### Developer-experience follow-ups (deferred to v0.4.x patches)

The first review pass of the v0.4.0 implementation flagged several
DX items that don't block the release but are tracked for a
dedicated pass before the Fheya migration:

- Tighten every framework-layer error message: include phase name,
  context key, root cause; reject generic phrasing.
- Distinguish failure types (transient / permanent /
  app-attributable / framework-bug) via concrete types or sentinels
  so apps can branch policy without string-matching.
- Audit every exported symbol for godoc coverage (what / when /
  when-not / parameters / returns / failure modes).
- Surface load-bearing implicit behaviors explicitly (e.g.,
  non-`[]byte` Provides outputs silently skipped from auto-commit).
- Add stderr logging to `fireFailureHook`'s `recover()` so buggy
  app hooks are visible at runtime, not just postmortem.

## [0.3.1] — 2026-05-19

Patch release: post-launch hardening from the 2026-05-19 audit
follow-up items, plus a "build your own app" tutorial in the README.

### Security

- **Replay protection.** Per-`(session_id, pseudonym, message_type)`
  monotonic sequence-number tracking in `transport.Hub`. Frames whose
  `WSMessage.Seq` is `<=` the highest accepted for the same tuple are
  silently dropped with a `[hub] replay drop` log line; the connection
  stays open. Empty / zero `Seq` bypasses the check for backward
  compatibility with pre-v0.3 clients.

### Added

- `ARESSession.connect(..., ssl_context=...)` accepts an
  `ssl.SSLContext` (or `False` to disable verification, or `None` to
  use the system default for `wss://`). Docs in
  `clients/python/README.md`.
- `pkg/ares/crypto/cgo/bridge.go` documents the "guard before
  `&slice[0]`" invariant + ships `requireNonEmptyBytes` helper for
  future contributors.
- README "Build your own app" tutorial — five-phase worked example
  (Invite + PlaintextKeygen + Collect + Announce + runner) showing the
  minimum viable ARES app shape with one state arc per phase.
  Compile-verified against the live framework before commit.

## [0.3.0] — 2026-05-19

First public release. v0.2 was a private snapshot of the framework
extraction; v0.3 cleans it up, removes app-specific code from the
framework core, and adds the OSS-launch hygiene.

### Security

- **WebSocket Origin allow-list** (`transport.Config.AllowedOrigins`).
  Production deployments now reject browser origins that aren't on the
  list. Non-browser clients (Go / Python) that omit the `Origin` header
  are unaffected. Legacy `NewHub` keeps the permissive default for the
  example apps.
- **Inbound WebSocket message size cap** (`Config.MaxWSMessageSize`,
  default 32 MiB). Replaces gorilla's default 512 KiB while bounding
  peer-driven memory.
- **Artifact PUT body cap** (`Config.MaxArtifactSize`, default 64 MiB).
  Oversized uploads now return `413 Request Entity Too Large` instead
  of silently allocating unbounded memory.
- **SSE log-stream newline-injection fix.** `writeSSE` now splits log
  lines on `\n` and emits each as a separate `data:` line. Optional
  `Config.DebugLogsAuth` gate added; default behavior unchanged
  (suitable for trusted reverse-proxy deployments only).
- **`ARES_ENV=production` refuses `AllowDevBypass=true`.** Hard
  configuration error at `NewService` time when the environment
  declares production and dev bypass is enabled.
- **Keygen-topology composition guard.** `phase.Compose` now rejects
  pipelines that wire `SinglePartyKeygen` (or any keygen tagged
  `topology=single_party` / `plaintext`) into a phase that requires
  `topology=threshold` (e.g. `Phase3ThresholdDecrypt`). Prevents an
  app author from silently substituting a server-trusted keygen into a
  pipeline whose decrypt phase assumes threshold semantics.
- **WSMessage wire-protocol versioning.** `WSMessage.Version` field +
  `WireProtocolVersion = "1"` constant. Frames with a declared major
  that doesn't match are dropped at the hub. Empty version accepted
  for backward compatibility with pre-v0.3 clients.

### Added

- Apache-2.0 LICENSE + `SPDX-License-Identifier` header on every source file.
- `pkg-config/openfhe.pc.in` template for installs that prefer pkg-config.
- `OpenFHEVersion()` Go API and `--version` flag on the helper binary.
- `Client.Version()` returns the helper's linked OpenFHE library version;
  `Client.Start()` warns to stderr if the version doesn't match
  `SupportedOpenFHEVersionPrefix` (`v1.5.`).
- `examples/voting/`: anonymous tally reference app using
  `PlaintextKeygen` + sum-weighted aggregation (new fourth reference
  app demonstrating non-MPC keygen).
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  GitHub issue / PR templates.
- CI workflows: Go-only lane (`.github/workflows/go.yml`) and
  OpenFHE-container lane (`.github/workflows/openfhe.yml`).

### Changed

- **Breaking:** `phase.NewSessionRunner(...)` renamed to `phase.Compose(...)`.
- **Breaking:** Per-app constructors renamed:
  - `auction.NewSealedBidAuctionRunner()` → `auction.Pipeline()`
  - `auction.NewSealedBidAuctionRunnerWithHelper()` → `auction.PipelineWithHelper()`
  - `rideshare.NewRideShareRunner()` → `rideshare.Pipeline()`
  - `rideshare.NewRideShareRunnerWithHelper()` → `rideshare.PipelineWithHelper()`
  - `cohort.NewWeeklyRankingSession()` → `cohort.WeeklyPipeline()`
  - `cohort.NewCohortFormationRunner()` → `cohort.FormationPipeline()`
- **Breaking:** Package renames (directory names unchanged):
  - `package sealedbidauction` → `package auction`
  - `package recurringcohortranking` → `package cohort`
- **Breaking:** Context-key renames in `pkg/ares/phase/defaults`:
  - `CtxCipherWinnerPackage` → `CtxResultCiphertext` (`"ct_winner_pkg"` → `"result_ct"`)
  - `CtxWinnerPackage` → `CtxResultBytes` (`"winner_pkg"` → `"result_bytes"`)
- Python smoke scripts renamed by crypto layer:
  - `*_homelab_smoke.py` → `*_openfhe_smoke.py` (real CKKS)
  - `*_config.py` → `*_stub_smoke.py` (placeholder bytes)
- `DeserializeCiphertext` in the C++ wrapper now verifies the
  deserialized ciphertext's `CryptoContext` matches the local context
  and emits a clear stderr message on mismatch, replacing the opaque
  `rc=-100` error.
- cgo OpenFHE include + library paths split into per-OS files
  (`bridge_darwin.go`, `bridge_linux.go`) covering `/usr/local`,
  `/opt/homebrew`, and `/usr/local/lib64`.

### Removed

- **Breaking:** `defaults.NewARESDefaultRunner()` deleted. ARES-core no
  longer ships an opinionated default pipeline; applications compose
  their own via `phase.Compose(...)`.
- **Breaking:** Matchmaking-shaped phases removed from
  `pkg/ares/phase/defaults`:
  `Phase1bEncryptedSubmit`, `Phase2FHEScoring`, `PhaseGOnionShuffle`,
  `PhaseG2Verification`, `PhaseDAnonymousBroadcast`. These were
  Fheya-app-specific and moved conceptually to consuming apps.
- **Breaking:** Fheya-only context keys removed from defaults:
  `CtxOnionRoundsComplete`, `CtxContribHashes`, `CtxMacSeeds`,
  `CtxSessionMacKey`, `CtxEncryptedInputs`, `CtxPhaseDSchedule`.
  Consuming apps must declare their own equivalents.

### Fixed

- Partial-decrypt placeholder bug in `*_openfhe_smoke.py`: smokes were
  sending `"pd-<name>"` instead of a real partial ciphertext, blocking
  sessions from reaching the SETTLED state. Now run a real
  `helper.partial_decrypt` against a shared target ciphertext.
- Cross-platform OpenFHE build (was hardcoded to `/usr/local`, broke on
  Apple Silicon Homebrew and on RHEL/Fedora's `/usr/local/lib64`).
- OpenFHE version mismatch between client and server now surfaces with
  a clear error at deserialization time instead of as `rc=-100`.

## [0.2.0] — 2026-05-17

Initial framework-extraction snapshot (private). Split ARES into a
generic framework (`Fheyalabs/ARES-core`) and a Fheya app
(`Fheyalabs/ARES`). 30+ tests passing across both repos.

[Unreleased]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.12...HEAD
[0.9.12]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.9...v0.9.10
[0.9.5]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.2...v0.9.5
[0.9.2]: https://github.com/Fheyalabs/ARES-core/compare/v0.9.0...v0.9.2
[0.9.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.7.5...v0.8.0
[0.7.5]: https://github.com/Fheyalabs/ARES-core/compare/v0.7.0...v0.7.5
[0.7.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Fheyalabs/ARES-core/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Fheyalabs/ARES-core/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/Fheyalabs/ARES-core/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.3.2...v0.4.0
[0.3.1]: https://github.com/Fheyalabs/ARES-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Fheyalabs/ARES-core/releases/tag/v0.2.0
