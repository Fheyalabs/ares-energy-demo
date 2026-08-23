#!/usr/bin/env bash
# Shared helpers for ARES client e2e harnesses. Client-agnostic: the client
# command is ${ARES_CLIENT_CMD:-swift run --package-path <repo>/clients/swift AresSmoke}.
set -euo pipefail

# These local e2e flows use small, fast, sub-128-bit CKKS rings (the bridge is
# secure-by-default and would otherwise reject them). Opt out for the local run;
# the bridge prints a one-time warning. NEVER export this in production.
export ARES_FHE_ALLOW_INSECURE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARES_CLIENT_CMD="${ARES_CLIENT_CMD:-swift run --package-path "$REPO_ROOT/clients/swift" AresSmoke}"
SERVER_PID=""

wait_for_health() {
  local url="$1" tries=60
  for _ in $(seq 1 "$tries"); do
    if curl -fsS "$url/admin/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "server health never came up at $url" >&2; return 1
}

stop_server() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap stop_server EXIT
