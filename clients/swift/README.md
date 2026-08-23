# AresClient (Swift)

Swift client library for the [ARES-core](https://github.com/Fheyalabs/ARES-core) protocol's
wire-layer crypto primitives. Implements the SC-2 onion shuffle, SC-10 ciphertext-lineage
`DAGNode`, the v2 `WSMessage` frame, and device-key signing — all in pure Swift on top of
[apple/swift-crypto](https://github.com/apple/swift-crypto) (CryptoKit-compatible; runs on
macOS and Linux). Validated byte-for-byte against the cross-language golden vectors shared
with the Go and Python clients.

## Status / scope

This is **L1** — protocol-crypto primitives only. The following are explicitly out of scope
at this layer and are planned for later work:

| Layer | Contents |
|---|---|
| L2 | FHE client operations (threshold CKKS key generation, ciphertext submission) |
| L3 | WS transport, session lifecycle, orchestration |

## Layout

```
Sources/AresClient/
  ByteUtil.swift      — hex encoding, big-endian u32, length-prefix helpers
  Lineage.swift       — SC-10 DAGNode: build slot nodes, serialize v2 wire JSON
  Onion.swift         — SC-2 onion-encrypt and batch-peel
  Signing.swift       — canonical-JSON serialisation + Ed25519 device-key signing
  WireFrame.swift     — JSONValue / RawJSON types; WSMessage v2 frame codec

Tests/AresClientTests/
  ByteUtilTests.swift
  LineageVectorsTests.swift  — golden-vector parity with Go/Python (loads node_vectors.json)
  OnionTests.swift
  SigningTests.swift
  WireFrameTests.swift
  GoldenVectorLoader.swift   — shared fixture loader
```

## Requirements

- Swift 5.9+
- macOS 13+ or any Linux distribution with Swift toolchain

## Usage

Add to `Package.swift`:

```swift
.package(url: "https://github.com/Fheyalabs/ARES-core", from: "0.9.15")
// then in your target:
.product(name: "AresClient", package: "ARES-core")
```

The repository-root package publishes the pure Swift `AresClient` and
`AresTransport` products. `AresClientFHE` remains an in-tree development
target until its OpenFHE bridge is distributed as a checksummed binary
artifact; a release must not advertise that target before then.

### Build a lineage node for a slot submission

```swift
import AresClient

let (node, sk, pk) = try Lineage.buildSlotNode(
    sessionID: "session-abc123",
    payloadBytes: Data(repeating: 0xAB, count: 32),
    parentsHex: [],          // first node in chain — no parents
    phaseID: "anon-g-verify",
    role: "slot-submission"
)
// DAGNode is Codable — encode to v2 wire JSON with the standard encoder
let wireJSON = try JSONEncoder().encode(node)
print(node.hash)            // hex node hash (field is `hash`, not `id`)
print(ByteUtil.hex(pk))     // Ed25519 public key as lowercase hex
```

### Build and peel an onion

```swift
import AresClient

// Peer public keys (Curve25519)
let peerPubs: [Data] = [pubKey0, pubKey1, pubKey2]

// Build onion — selfIndex identifies which layer wraps our own return path
let (onion, selfMemo) = try Onion.build(
    payload: Data("hello".utf8),
    peerPubs: peerPubs,
    selfIndex: 1
)

// Each relay calls peelBatch with its own secret key
let (peeled, ownIndex) = try Onion.peelBatch(
    mySk: mySecretKey,
    selfMemo: selfMemo,
    onions: [onion]
)
```

## Testing

Run all tests from the repo root (the package is tested in-tree):

```bash
cd clients/swift && swift test
```

The lineage golden-vector test (`LineageVectorsTests`) loads
`pkg/ares/lineage/testdata/node_vectors.json` from the repository via `#filePath`-relative
resolution — this is a repo-relative path and the single source of truth for cross-language
parity with the Go and Python clients.

### A note on Ed25519 signatures

`apple/swift-crypto`'s `Curve25519.Signing` uses a randomized Ed25519 implementation, so
signature bytes differ across runs. The signing tests therefore **verify** signatures against
the signer's public key rather than byte-comparing them to the golden vectors. This does not
affect interop: the ARES session service verifies signatures in the same way.

## L2 — `AresClientFHE`: threshold CKKS via OpenFHE

`AresClientFHE` provides safe Swift wrappers over ARES-core's canonical C bridge
(`pkg/ares/crypto/cgo/openfhe_wrapper.{h,cpp}`, reused inside the package via
repo-relative symlinks) for threshold CKKS homomorphic encryption. The layer covers:

- **Context creation** — `CryptoContext(ringDim:scalingFactor:depth:)`
- **N-party keygen chain** — `keyGenFirst()` / `keyGenNext(prev:)` / `multiAddPublicKeys(_:)`
- **Eval-key round protocols** — `genEvalMultKeyShare` / `genRotKeyShare` / `evalKeyRounds`
- **Encrypt / partial-decrypt / fuse** — `encrypt(values:under:)`, `partialDecrypt(_:with:)`, `fuse(_:slotCapacity:)`
- **Serialization** — round-trip serialize/deserialize for `Ciphertext`, `PublicKey`,
  `SecretKeyShare`, `EvalMultKey`, and `RotKey`
- **Homomorphic ops** — add, sub, mult, multConst, sum, `evalChebyshevSign`,
  `evalPolynomial`, `evalArgmax`
- **Version probe** — `AresFHE.openFHEVersion()`

### Requirements and build gating

`AresClientFHE` requires **OpenFHE 1.5.1** installed at `/usr/local` (macOS brew: `/opt/homebrew`).
The target is gated behind the `ARES_OPENFHE` environment variable so that plain `swift test`
(e.g. Linux CI without OpenFHE) only builds the pure-Swift L1 `AresClient` target and stays
green.

```bash
# FHE target + tests (requires OpenFHE installed)
ARES_OPENFHE=1 swift build
ARES_OPENFHE=1 swift test

# L1 only — no OpenFHE needed
swift test
```

### Usage — threshold round-trip

```swift
import AresClientFHE

let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
var pks: [PublicKey] = []
var sks: [SecretKeyShare] = []
let first = try ctx.keyGenFirst()
pks.append(first.publicKey); sks.append(first.secretKey)
for _ in 1..<3 {
    let next = try ctx.keyGenNext(prev: pks.last!)
    pks.append(next.publicKey); sks.append(next.secretKey)
}
let jointPK = pks.last!                       // chained joint public key
let ct = try ctx.encrypt(values: [1.25, -2.5, 3.0, 0.5], under: jointPK)
let partials = try sks.map { try ctx.partialDecrypt(ct, with: $0) }
let recovered = try ctx.fuse(partials, slotCapacity: 8)   // ≈ the input
```

### Testing notes

FHE is randomized — L2 tests assert round-trip correctness within CKKS floating-point
tolerance (no golden vectors, unlike L1). Cross-language ciphertext interop with the Go
and Python stacks is verified at L3.

### Deploy note

At deploy the bridge links against the iOS/Android static OpenFHE build (static `.a` +
C bridge header → xcframework) instead of the system libraries used during development;
see the fork-reconciliation note in the project documentation.

## L3 — `AresTransport` + cross-language e2e

L3 connects the client to a live ARES session-service over WebSocket and proves
cross-language interoperability with the Go server.

### `AresTransport` (Foundation-only — builds without OpenFHE)

A pure-Foundation target (no FHE), so it compiles in CI alongside L1:

- **`Session`** — one WebSocket connection (`URLSessionWebSocketTask`). `connect` derives the
  auth token as `HMAC-SHA256(secret, pseudonym)` hex and dials `ws(s)://host/v2/ws?pseudonym=&auth=`;
  `send` / `expect(type)` / `receiveAny` / `awaitPhase(state)` / `close`, with a background
  receive pump.
- **`AdminClient`** — the HTTP admin surface: `health` / `waitForHealth`, `startSession` (POST
  `/admin/sessions`, with optional `attrs`), `getState`, `pollUntilTerminal`.
- **`Orchestrator`** — connect N participants, then close them all.
- **`GossipParticipant`** — composes the L1 SC-2 onion + SC-10 lineage for the anon gossip arc
  (`buildBatch` / `peelRound` / `slotSubmission`).

### `AresSmoke` CLI (gated behind `ARES_OPENFHE`)

An executable driving two end-to-end flows; exit 0 on success:

```bash
ARES_OPENFHE=1 swift run AresSmoke auction --server http://localhost:8741 --participants 3
ARES_OPENFHE=1 swift run AresSmoke voting  --server http://localhost:8742 --participants 3
```

### Client-agnostic e2e harness (`clients/swift/e2e/`)

Each script starts a local ARES-core example session-service and asserts the client's exit code:

```bash
ARES_OPENFHE=1 ./clients/swift/e2e/auction.sh
ARES_OPENFHE=1 ./clients/swift/e2e/voting.sh
```

The client command is **parameterized** via `ARES_CLIENT_CMD` (default
`swift run --package-path clients/swift AresSmoke`) — the seam a future Kotlin/Android client
plugs into so the *same* harness validates every client against the identical protocol contract.
Knobs: `AUCTION_CRYPTO_DEPTH` (default 12 — the argmax floor, keeps CKKS keys Mac-safe),
`PARTICIPANTS`, `PORT`.

**What each proves:**
- **auction** → cross-language **FHE-ciphertext interop**: client-generated, serialized CKKS keys
  + bid ciphertexts + decrypt partials are accepted and evaluated by the Go helper-backed server
  through to `AUCTION_SETTLED`.
- **voting** → **onion-shuffle + SC-10 lineage interop**: the client's onion peels through the
  server shuffle arc and the ballot `DAGNode`s verify server-side, driving the session to tally.

**Requirements (local only — never CI):** the auction e2e needs Go + system OpenFHE 1.5.1 + a
built `openfhe-contract-helper`; the voting e2e needs only Go.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
