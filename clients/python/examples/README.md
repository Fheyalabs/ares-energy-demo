# Python smoke scripts

Two families of smoke scripts ship here, one per crypto layer:

| Family | Crypto | Speed | Purpose |
|---|---|---|---|
| `*_stub_smoke.py` | Stub (deterministic placeholder bytes via `ares_client.crypto.StubCrypto`) | Fast (~1 s) | Wire/state-machine coverage. No OpenFHE needed. Good for CI and quick protocol checks. |
| `*_openfhe_smoke.py` | Real CKKS via `OpenFHEHelper` subprocess | Slow (10–60 s) | End-to-end with real threshold keygen, encryption, and partial decrypts. Verifies the full crypto path. |

Pick the family that matches what you're testing.

## Apps covered

| App | Stub smoke | OpenFHE smoke |
|---|---|---|
| Sealed-bid auction | `auction_stub_smoke.py` | `auction_openfhe_smoke.py` |
| Recurring cohort (formation pass) | `cohort_formation_stub_smoke.py` | `cohort_formation_openfhe_smoke.py` |
| Recurring cohort (weekly pass) | `cohort_weekly_stub_smoke.py` | `cohort_openfhe_smoke.py` |
| Ride share | `rideshare_stub_smoke.py` | `rideshare_openfhe_smoke.py` |

## Running

**Stub family** — driven through the `ares_client` CLI:

```bash
export ARES_SERVER=http://localhost:8000
export ARES_WS_SECRET=        # empty for dev-bypass
python -m ares_client --config examples.auction_stub_smoke --participants 3
```

**OpenFHE family** — standalone scripts, require the helper binary:

```bash
export ARES_SERVER=https://api.fheya.de
export ARES_HELPER_BINARY=/path/to/openfhe-helper
python -m examples.auction_openfhe_smoke --participants 3
```

The OpenFHE smokes generate keys + ciphertexts locally and seed them as pre-shared attrs in `POST /admin/sessions`. The server's helper must link the **same OpenFHE version** (1.5.1) — version skew yields a `Ciphertext was not created in this CryptoContext` error from OpenFHE.

## Environment variables

| Var | Used by | Effect |
|---|---|---|
| `ARES_SERVER` | both | Session-service URL. |
| `ARES_WS_SECRET` | both | HMAC key for WS auth tokens. Empty = dev-bypass. |
| `ARES_HELPER_BINARY` | OpenFHE family only | Path to `openfhe-helper`. Without it the OpenFHE smokes fall back to placeholder bytes (wire-only). |
| `AUCTION_CRYPTO_DEPTH`, `AUCTION_RING_DIM` | `auction_openfhe_smoke.py` | Override the CKKS contract. Must match the server's env. |
| `COHORT_CRYPTO_DEPTH`, `COHORT_RING_DIM` | `cohort_openfhe_smoke.py` | Same, for cohort. |
| `RIDESHARE_CRYPTO_DEPTH`, `RIDESHARE_RING_DIM` | `rideshare_openfhe_smoke.py` | Same, for rideshare. |
