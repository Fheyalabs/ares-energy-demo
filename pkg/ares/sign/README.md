<!-- SPDX-License-Identifier: Apache-2.0 -->

# `pkg/ares/sign`

Pluggable asymmetric signature primitive. The [`lineage`](../lineage/)
package uses it to attest authorship of DAG nodes; applications can
reuse it for any signed-message pattern.

## Quick start

```go
import "github.com/Fheyalabs/ares-core/pkg/ares/sign"

// Producer side: generate a keypair and sign a message.
signer, err := sign.NewEd25519Signer()
if err != nil { /* handle */ }
sig, err := signer.Sign([]byte("hello"))
if err != nil { /* handle */ }

// Verifier side: any party with the producer's public key can verify.
if err := signer.Verify(signer.PublicKey(), []byte("hello"), sig); err != nil {
    // signature did not verify
}
```

## Interface

```go
type Signer interface {
    Sign(msg []byte) ([]byte, error)
    Verify(pubkey, msg, sig []byte) error
    PublicKey() []byte
    Algorithm() string
}
```

Implementations must be safe for concurrent use. The default
`Ed25519Signer` satisfies this — `crypto/ed25519` from stdlib is
re-entrant — and the contract is regression-tested
(`TestEd25519Signer_ConcurrentSignVerify` under `-race`).

## Default: Ed25519

`Ed25519Signer` wraps `crypto/ed25519` from stdlib. Algorithm string
is `"ed25519"` (exported as `sign.Ed25519Algorithm`). No external
dependencies. Two constructors:

- `NewEd25519Signer()` — generates a fresh keypair via `crypto/rand`.
- `NewEd25519SignerFromKey(priv ed25519.PrivateKey)` — wraps an
  existing key (load from secure storage, an HSM clientlib's
  exported handle, etc.).

`PublicKey()` returns a defensive copy — callers can safely mutate
the returned slice without affecting the signer's internal state.

## Substituting alternatives

HSM-backed signing, post-quantum schemes (Dilithium, Ed448), or any
other asymmetric primitive: implement the four-method `Signer`
interface and pass the instance to consumers via their construction
options:

```go
runner, err := phase.ComposeWith(
    phases,
    phase.WithSigner(myHSMSigner),
    phase.WithPeerVerifiers(map[string]sign.Signer{
        "ed25519":   peerEd25519Verifier,
        "dilithium": peerDilithiumVerifier,
    }),
)
```

The `Algorithm()` string is the keying field in the verifier map —
multiple schemes can coexist in one deployment (useful during
algorithm rotations or for heterogeneous federations).

## Failure modes

Each method has a specific failure surface. The current default
implementation returns errors with the prefix `"sign: ..."`:

| Call | Failure cases |
|---|---|
| `NewEd25519Signer()` | `crypto/rand` read failure (extraordinarily rare) |
| `Sign(msg)` | none for `Ed25519Signer` (stdlib `ed25519.Sign` is infallible on a well-formed key) |
| `Verify(pubkey, msg, sig)` | invalid pubkey size, invalid signature size, signature/message mismatch |
| `PublicKey()` | none (returns a defensive copy) |
| `Algorithm()` | none (returns a const string) |

For SC-10 lineage specifically, `Verify` failures surface as
`*lineage.MismatchError{Field: "Signature"}` after the framework
wraps them.

## Related

- [`pkg/ares/lineage`](../lineage/) — the primary consumer of this
  package; uses `Signer.Sign` to attest DAGNode authorship and
  `Signer.Verify` to check inbound commits.
- ARES Spec v2.5 §SC-10 — protocol-level context for why a pluggable
  signer interface lives at the framework layer.
