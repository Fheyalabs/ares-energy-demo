# Security Policy

ARES Core is a cryptographic framework. We take security reports seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | ✅ |
| < 0.3 | ❌ (pre-release; please upgrade) |

ARES Core is pre-1.0 — API may change between minor versions. Security
fixes are backported to the latest minor only.

## Reporting a vulnerability

**Please do not file public GitHub issues for security problems.**

Send a report to one of:

- **`security@fheya.de`** (preferred — project-scoped inbox)
- `hardikghoshal@gmail.com` (maintainer fallback)
- Or use GitHub's [private vulnerability reporting](https://github.com/Fheyalabs/ARES-core/security/advisories/new)

Include:

- A description of the vulnerability and its impact.
- A minimal reproduction (code, parameters, OpenFHE version).
- Whether the issue is already public or you have a planned disclosure date.

## Response timeline

- **Acknowledgement:** within 3 business days.
- **Initial assessment:** within 7 business days.
- **Fix or mitigation:** target 30 days for high-severity issues; 90 days
  for lower-severity. We'll keep you in the loop if the work takes
  longer.

## Coordinated disclosure

We follow a 90-day disclosure window by default. If you'd like us to
credit you in the release notes, let us know in the report.

## Scope

In scope:
- Vulnerabilities in `pkg/ares/`, `cmd/openfhe-contract-helper`, and the
  reference apps under `examples/`.
- Issues in the cgo wrapper that could lead to memory corruption,
  ciphertext malleability, or key-material leakage.

Out of scope (please report upstream):
- Vulnerabilities in OpenFHE itself — [openfhe.org](https://openfhe.org/).
- Issues in Go runtime, gorilla/websocket, or other third-party deps.
- Issues only reachable by an attacker who already has filesystem or
  process access to the helper binary.
