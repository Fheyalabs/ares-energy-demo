# ares-client

Generic Python client for [ARES-core](https://github.com/Fheyalabs/ARES-core)
applications. Drives end-to-end smoke runs of any session-service
built on the framework.

## Install

```bash
cd clients/python
pip install -e .
```

## Quickstart

Start one of the example session-services (Go side):

```bash
# From the repo root
go run ./examples/sealed_bid_auction/cmd/session-service
```

In another shell, run the smoke driver:

```bash
python -m ares_client \
    --config examples.auction_stub_smoke \
    --participants 6 \
    --session-id auc-001
```

The driver connects 6 participants, posts `/admin/sessions`, and runs
each participant's flow concurrently. It prints a JSON summary on exit.

## Architecture

```
AppConfig
    name, server_url, invite_type
    auth_secret  (HMAC shared with session-service)
    participant_flow(session, role, total) -> Any
    role_for(participants) -> dict[name -> role]  (optional)
    admin_attrs                                    (optional)

ARESSession
    .send(msg_type, payload)
    .expect(msg_type, timeout)
    .receive_any(timeout)
    .close()

run_smoke(config, n_participants, session_id)
    1. wait for /admin/health
    2. connect N participants via WS
    3. POST /admin/sessions
    4. await invitation per participant
    5. gather participant_flow(s, role, N) for all
    6. return list of results
```

## Writing a new app config

Create a module that exposes a module-level `CONFIG: AppConfig`:

```python
# my_app_config.py
from ares_client import AppConfig, ARESSession

async def my_flow(session: ARESSession, role: str, total: int):
    msg = await session.expect("my.invitation")
    await session.send("my.contribution", {"value": 42})
    return {"sent": 42}

CONFIG = AppConfig(
    name="my-app",
    server_url="http://localhost:8000",
    invite_type="my.invitation",
    participant_flow=my_flow,
)
```

Run it:

```bash
python -m ares_client --config my_app_config --participants 4
```

## CLI reference

```
python -m ares_client \
    --config <dotted.module.path>      [required]
    --participants <N>                 [default 6]
    --session-id <id>                  [default <app>-<epoch>]
    --server <url>                     [override config.server_url]
    --participant-prefix <prefix>      [default 'p']
    --verbose                          [DEBUG logs]
    --no-wait                          [skip /admin/health pre-flight]
```

## Crypto

`ares_client.crypto.StubCrypto` returns deterministic placeholder bytes
so smokes can exercise wire / state-machine logic. The real
`OpenFHECrypto` provider that calls into the existing
`openfhe-contract-helper` lands in Phase 4 of the
example-app deployment work; until then smokes verify transport and
phase transitions but not the homomorphic computation.

## TLS / certificate verification

`ARESSession.connect(server_url, ...)` selects the transport based on
the URL scheme:

| URL scheme | Transport | Cert verification |
|---|---|---|
| `https://` / `wss://` | TLS | System trust store (CA-signed certs) |
| `http://` / `ws://` | Plain WebSocket | None |

For a homelab with a private CA, or any setup that needs a custom
trust bundle, pass an `ssl.SSLContext`:

```python
import ssl
from ares_client import ARESSession

ctx = ssl.create_default_context(cafile="/etc/my-ca.crt")
session = await ARESSession.connect(
    server_url="https://api.fheya.de",
    pseudonym="bidder-01",
    session_id="auction-1",
    ssl_context=ctx,
)
```

To **disable** verification (only for local development against
self-signed certs), pass `ssl_context=False`. Never disable
verification in production — it makes the WS token transmitted over
the connection trivially interceptable.

If `auth_secret` is set against a plain `http://` / `ws://` URL the
WS token is sent in plaintext on the wire. Use `wss://` in any
deployment where the auth token actually authenticates a real
identity.
