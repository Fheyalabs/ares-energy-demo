<!-- SPDX-License-Identifier: Apache-2.0 -->

# Sealed-bid auction

Reference app: an N-bidder sealed-bid first-price auction. The
auctioneer learns only the winning bid; every other bid stays
encrypted under a threshold CKKS key shared across the bidders.

## What it demonstrates

- A six-phase ARES pipeline at depth 10 (shorter than Fheya's
  matchmaking depth-30 pipeline because the scoring circuit is a
  scalar argmax rather than cosine-plus-location).
- Both stub-mode wiring (for wire-shape smokes without OpenFHE)
  and helper-backed real CKKS argmax via the
  `openfhe-contract-helper`.
- v0.4.0 SC-10 ciphertext lineage end-to-end: signed bid
  commitments are bound to the producing bidder so the auctioneer
  cannot relay a tampered bid to argmax.

## Pipeline

```text
Invitation → Keygen → ScalarBid → Argmax → Decrypt → Settlement
```

| State arc | Phase | Notes |
|---|---|---|
| `AUCTION_INVITING` → `AUCTION_LOCKED` | `PhaseInvitation` | seeds participants + crypto contract |
| `AUCTION_LOCKED` → `AUCTION_BIDDING` | `PhaseKeygen` | N-party threshold CKKS keygen |
| `AUCTION_BIDDING` → `AUCTION_SCORING` | `PhaseScalarBid` | one encrypted scalar bid per bidder |
| `AUCTION_SCORING` → `AUCTION_DECRYPTING` | `PhaseArgmax` | stub or helper-backed |
| `AUCTION_DECRYPTING` → `AUCTION_SETTLED` | `PhaseDecrypt` | threshold partial decrypts |
| `AUCTION_SETTLED` (terminal) | `PhaseSettlement` | broadcast signed winning bid |

## Usage

Legacy (no lineage, v1 wire frames):

```go
runner, err := auction.Pipeline()              // stub argmax
runner, err := auction.PipelineWithHelper(c, p) // helper-backed
```

v0.4.0 lineage variant (v2 wire frames, every byte signed):

```go
signer, _   := sign.NewEd25519Signer()
verifiers   := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
runner, err := auction.PipelineWithLineage(signer, verifiers)

// helper-backed:
runner, err := auction.PipelineWithLineageAndHelper(client, sharpening, signer, verifiers)
```

The lineage variant fails-fast at construction time if `signer`
or `verifiers` are nil. Bidders submit signed `DAGNode`s inline
on `transport.WSMessage.Lineage`; the runner verifies the
signature + payload hash before dispatching to `PhaseScalarBid`.

## Tamper-detection smoke

[`tamper_test.go`](tamper_test.go) — confirms that swapping a
bidder-signed bid's bytes (server-relay tamper) is rejected by
`SessionRunner.HandleLineageMessage` with a
`*lineage.MismatchError` whose `Field` is `"PayloadHash"`. The
test exercises the full verify-before-dispatch path.

## Running as a service

[`cmd/session-service`](cmd/session-service) — standalone
HTTP+WebSocket service wrapping `Pipeline()` (legacy path).
Currently uses `auction.Pipeline()` / `PipelineWithHelper()`;
switching it to the lineage variant requires populating
`peerVerifiers` per deployment (single-algorithm Ed25519 verifier
suffices for most setups since per-peer pubkeys ride on each
DAGNode).

Environment:

| Var | Purpose |
|---|---|
| `SESSION_PORT` | listen port (default `8000`) |
| `ARES_WS_SECRET` | HMAC key for WS auth tokens (empty → dev bypass) |
| `AUCTION_CRYPTO_DEPTH` | CKKS depth (default `12`) |
| `AUCTION_RING_DIM` | CKKS ring dimension (default `2048`) |
| `ARES_HELPER_BINARY` | path to `openfhe-contract-helper` (empty → stub argmax) |

## Slot anonymity

**Not adopted — intentional opt-out.** The winning bid amount and the
winner's pseudonym are the public outputs of this protocol; they are
broadcast in the signed settlement transcript by design. There is no
slot→identity mapping to hide: every bidder knows who won and for how
much. Adding an onion-shuffle round would protect nothing and would
add unnecessary latency.

This is the canonical "you don't always need slot anonymity" pipeline.
The same conclusion is stated in the package-level godoc (`states.go`):
"Auction skips onion-shuffle (PhaseG) and verification (PhaseG.2)
because slot anonymity is not required — the winning bidder's identity
is intentionally revealed in the settlement transcript."

Applications that do need inter-participant slot anonymity compose
`pkg/ares/phase/anon` (`PhaseGShuffle` + `PhaseGVerify`) over a
GOSSIP→VERIFYING→submit arc, as `examples/voting`'s
`PipelineWithShuffle` shows.

## References

- ARES Spec v2.5 §SC-10 — ciphertext lineage protocol-level
  documentation.
- [`pkg/ares/lineage/`](../../pkg/ares/lineage/) — `DAGNode`,
  `Commit`, `Verify`, `Store`.
- [`pkg/ares/sign/`](../../pkg/ares/sign/) — `Signer` interface
  + Ed25519 default.
- [`pkg/ares/phase/anon/`](../../pkg/ares/phase/anon/) — opt-in
  onion-shuffle phases (not used here).
- [CHANGELOG `[0.4.0]`](../../CHANGELOG.md) — full v0.4.0 surface.
