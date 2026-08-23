# AresClient (Kotlin/JVM)

Kotlin/JVM client library for the [ARES-core](https://github.com/Fheyalabs/ARES-core) protocol.
Implements the same L1 protocol-crypto primitives as the Swift client — SC-2 onion shuffle,
SC-10 ciphertext-lineage `DAGNode`, the v2 `WSMessage` frame, and device-key signing — plus
an L3 WebSocket transport layer and a CLI (`ares-smoke`) for live end-to-end validation.
Validated byte-for-byte against the cross-language golden vectors shared with the Go, Python,
and Swift clients.

## Status / scope

This is **Android-A**: L1 + L3 on the JVM.

| Layer | Contents | Status |
|---|---|---|
| L1 | Protocol-crypto primitives (SC-2 onion, SC-10 lineage `DAGNode`, v2 `WSMessage` frame, device signing) | **Included** |
| L3 | WS transport, session lifecycle, gossip orchestration, `ares-smoke` CLI | **Included** |
| L2 / Android-B | FHE client operations (threshold CKKS key generation, ciphertext submission, client-side ARES-BC) | Future slice |

The library is **Android-ready**: all dependencies (Bouncy Castle, OkHttp, Kotlin coroutines)
run on Android. Android-A runs on the JVM; the Android module and FHE/JNI layer are deferred
to Android-B.

## Crypto

All primitives use the **Bouncy Castle lightweight API** (no JCE registration required) together
with **JCA** for AES-GCM:

| Primitive | Implementation |
|---|---|
| X25519 key agreement | BC `X25519Agreement` |
| HKDF-SHA256 | BC `HKDFBytesGenerator` (info `"ares_onion_v1"`) |
| AES-256-GCM (12-byte nonce, 128-bit tag) | JCA `AES/GCM/NoPadding` |
| Ed25519 sign / verify | BC `Ed25519Signer` / `Ed25519PrivateKeyParameters` |
| SHA-256, HMAC-SHA256 | JCA `MessageDigest` / `Mac` |

Bouncy Castle's Ed25519 is **deterministic** (RFC 8032) — the same seed always yields the same
signature bytes. The unit tests therefore assert byte-for-byte equality against the golden
`signature_hex` field, not just verify-correctness. This is intentional and differs from the
Swift client (which uses Apple's randomized `Curve25519.Signing`).

## Layout

```
clients/kotlin/
  ares-client/                   — library module (L1 + transport)
    src/main/kotlin/ares/client/
      ByteUtil.kt                — hex encoding, big-endian u32, length-prefix helpers
      Lineage.kt                 — SC-10 DAGNode: build slot nodes, v2 wire JSON
      Onion.kt                   — SC-2 onion-encrypt and batch-peel (ECIES)
      Signing.kt                 — canonical JSON + Ed25519 device signing + HMAC auth-token
      WireFrame.kt               — v2 WSMessage frame codec (v1/v2, lineage-aware)
      transport/
        Session.kt               — OkHttp WebSocket session (connect/send/expect/awaitPhase)
        AdminClient.kt           — HTTP admin surface (health / startSession / pollUntilTerminal)
        Orchestrator.kt          — connect N participants, orchestrate, close all
        GossipParticipant.kt     — SC-2 onion + SC-10 lineage for the anon gossip arc
    src/test/kotlin/ares/client/
      ByteUtilTest.kt
      LineageVectorsTest.kt      — golden-vector parity with Go / Python / Swift
      OnionTest.kt
      SigningTest.kt
      WireFrameTest.kt
      GossipParticipantTest.kt
      MiniJson.kt                — minimal JSON helper used by tests

  ares-smoke/                    — runnable CLI module
    src/main/kotlin/ares/smoke/
      Main.kt                    — entry point; subcommand dispatch
      VotingFlow.kt              — voting end-to-end flow (onion + lineage)

  e2e/
    voting.sh                    — build fat jar, set ARES_CLIENT_CMD, delegate to shared harness

  build.gradle.kts               — root Gradle build (Kotlin plugin, Maven Central)
  settings.gradle.kts            — includes ares-client, ares-smoke
  gradlew / gradlew.bat          — Gradle wrapper (9.5.1)
```

**Dependencies** (all from Maven Central):

| Artifact | Purpose |
|---|---|
| `org.bouncycastle:bcprov-jdk18on:1.78.1` | X25519, Ed25519, HKDF (BC lightweight API) |
| `com.squareup.okhttp3:okhttp:4.12.0` | WebSocket transport |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1` | Coroutine-safe inbox channel |

## Build and test

Requires **JDK 17+** and the Gradle wrapper (no local Gradle installation needed).

```bash
# From clients/kotlin/
./gradlew :ares-client:test          # unit tests + golden-vector parity (14 tests)
./gradlew clean build                # clean, compile, all unit tests
./gradlew :ares-smoke:fatJar         # produce a self-contained fat jar
```

The lineage golden-vector test (`LineageVectorsTest`) loads
`pkg/ares/lineage/testdata/node_vectors.json` from the repository root — the single source of
truth for cross-language parity with the Go, Python, and Swift clients.

### A note on Ed25519 signatures

Bouncy Castle's Ed25519 is deterministic (RFC 8032), so `LineageVectorsTest` asserts the
`signature_hex` field byte-for-byte against each golden vector. This differs from the Swift
client (which verifies signatures rather than byte-comparing them) and validates that the Kotlin
key-derivation and signing-message construction exactly match the reference implementation.

## Usage

### Build a lineage node for a slot submission

```kotlin
import ares.client.Lineage

val built = Lineage.buildSlotNode(
    sessionID    = "session-abc123",
    payloadBytes = ByteArray(32) { 0xAB.toByte() },
    parentsHex   = emptyList(),         // first node — no parents
    phaseID      = "anon-g-verify",
    role         = "slot-submission",
)
println(built.node.hash)               // lowercase hex node hash
println(ares.client.ByteUtil.hex(built.pk))  // Ed25519 public key as hex
```

### Build and peel an onion

```kotlin
import ares.client.Onion

val peerPubs: List<ByteArray> = listOf(pubKey0, pubKey1, pubKey2)

// Build — selfIndex identifies which layer wraps our own return path
val (onion, selfMemo) = Onion.build(
    payload   = "hello".toByteArray(),
    peerPubs  = peerPubs,
    selfIndex = 1,
)

// Each relay calls peelBatch with its own secret key
val (peeled, ownIndex) = Onion.peelBatch(
    mySk     = mySecretKey,
    selfMemo = selfMemo,
    onions   = listOf(onion),
)
```

### Open a WebSocket session

```kotlin
import ares.client.transport.Session

val session = Session.connect(
    serverURL  = "http://localhost:8080",
    pseudonym  = "alice",
    sessionID  = "session-abc123",
    authSecret = "shared-secret",
)
session.send("vote.ballot", payloadJson = """{"choice":"yes"}""".toByteArray())
val frame = session.expect("vote.ack")
session.close()
```

### Run the CLI

```bash
java -jar ares-smoke/build/libs/ares-smoke-*-all.jar voting \
    --server http://localhost:8742 --participants 3
```

## End-to-end test

`clients/kotlin/e2e/voting.sh` drives a full voting session against a live ARES
session-service:

```bash
./clients/kotlin/e2e/voting.sh
```

The script builds the `ares-smoke` fat jar, sets `ARES_CLIENT_CMD="java -jar <jar>"`, then
delegates to the **shared harness** at `clients/swift/e2e/voting.sh`. The harness starts a
local ARES session-service (Go binary compiled from `cmd/session-service`), runs the client
command, and asserts exit 0.

**What it proves:** the Kotlin client's onion peels through the Go server's shuffle arc and the
ballot `DAGNode`s verify server-side, driving the session to tally. Cross-language SC-2 + SC-10
interoperability from the JVM.

**Requirements:** Go (to build and run the session-service). No OpenFHE required.

## Cross-language parity

The same `pkg/ares/lineage/testdata/node_vectors.json` golden vectors validate all four clients:

| Client | Golden-vector test | Ed25519 behaviour |
|---|---|---|
| Go | `pkg/ares/lineage/lineage_test.go` | deterministic |
| Python | `clients/python/tests/test_lineage_vectors.py` | deterministic |
| Swift | `clients/swift/Tests/AresClientTests/LineageVectorsTests.swift` | verify-only (randomized) |
| **Kotlin** | `ares-client/src/test/kotlin/ares/client/LineageVectorsTest.kt` | **byte-for-byte match** |

## License

Apache-2.0. See [LICENSE](../../LICENSE).
