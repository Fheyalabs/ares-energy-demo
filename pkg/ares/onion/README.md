# `pkg/ares/onion`

Client-side cryptography for ARES slot anonymization.

| Function | Purpose |
|---|---|
| `GenerateSlotKey()` | Fresh X25519 slot delivery keypair (raw 32-byte priv/pub). |
| `ECIESEncrypt(pub, pt)` / `ECIESDecrypt(priv, env)` | X25519 + HKDF-SHA256(`ares_onion_v1`) + AES-256-GCM. Envelope: `ephemeral_pub(32) ‖ nonce(12) ‖ ct`. |
| `BuildOnion(payload, peelOrderPubs, selfIndex)` | N-1-layer onion (SC-2: includes self-layer); returns `(onion, selfMemo)`. |
| `PeelBatch(myPriv, selfMemo, onions)` | Peel one layer off each item; identify own item by ciphertext memory match. |
| `SlotPermutation(seed, n)` | Deterministic coordinator-free slot ordering. |

## Wire parity

`ECIESEncrypt`/`ECIESDecrypt` match the Python reference byte-for-byte,
covered by a parity vector test. The Go `BuildOnion` is
**SC-2-correct**; an older Python `build_onion` that skips the
self-layer is realigned to this package separately.

## Security

See the package godoc for the SC-2 self-layer rationale and the SC-7
collusion bound (`k >= N-2` for certain deanonymization; 50% floor at
`k = N-3`).
