#!/usr/bin/env bash
# ARES-BC bound-check cross-language e2e (LOCAL — spins up the Go server; not homelab).
# Default client is Swift (swift run AresSmoke). Kotlin overrides via ARES_CLIENT_CMD.
set -euo pipefail

# Local e2e uses small/reduced CKKS rings; the bridge is secure-by-default, so opt
# out for the local run (one-time warning is printed). NEVER export in production.
export ARES_FHE_ALLOW_INSECURE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARES_CLIENT_CMD="${ARES_CLIENT_CMD:-swift run --package-path $REPO_ROOT/clients/swift AresSmoke}"

DEPTH="${ADMISSION_CRYPTO_DEPTH:-8}"
RING_DIM="${ADMISSION_RING_DIM:-16384}"
DIM="${ADMISSION_DIM:-8}"
PORT="${BOUNDCHECK_PORT:-8742}"
SERVER="$REPO_ROOT/examples/bounded_admission/cmd/session-service"

cleanup() { kill $SVC_PID 2>/dev/null || true; }
trap cleanup EXIT

echo "=== ARES-BC bound-check e2e (depth=$DEPTH ring=$RING_DIM dim=$DIM) ==="

# Ensure helper binary is built
echo "building openfhe-contract-helper..."
( cd "$REPO_ROOT" && go build -tags openfhe -o /dev/null ./cmd/openfhe-contract-helper ) || true

# Build + start the bounded_admission server
echo "building bounded_admission session-service (-tags openfhe)..."
( cd "$REPO_ROOT" && go build -tags openfhe -o "$REPO_ROOT/bin/admission-svc" "$SERVER" )
echo "starting bounded_admission session-service on :$PORT..."
ADMISSION_CRYPTO_DEPTH="$DEPTH" ADMISSION_RING_DIM="$RING_DIM" ADMISSION_DIM="$DIM" \
  SESSION_PORT="$PORT" "$REPO_ROOT/bin/admission-svc" > /tmp/ares-admission-svc.log 2>&1 &
SVC_PID=$!

# Wait for health
for i in $(seq 1 30); do
  if curl -sS "http://localhost:$PORT/admin/health" > /dev/null 2>&1; then
    echo "server healthy on :$PORT"; break
  fi
  [ $i -eq 30 ] && echo "SERVER HEALTH TIMEOUT" && cat /tmp/ares-admission-svc.log && exit 1
  sleep 1
done

SID="bc-e2e-$$"
pass=0; fail=0
run_mode() {
  local mode="$1" desc="$2"
  echo ""; echo "--- mode=$mode ($desc) ---"
  if $ARES_CLIENT_CMD boundcheck --server "http://localhost:$PORT" --participants 2 \
       --mode "$mode" --session-id "${SID}-${mode}" --auth-secret "" 2>&1; then
    echo "PASS: $mode ($desc)"; pass=$((pass+1))
  else
    echo "FAIL: $mode ($desc)"; fail=$((fail+1))
  fi
}

run_mode inbound   "all inputs in-bound → SETTLED, no violations"
run_mode violation "party-0 inflated → server flags violation"
run_mode tamper    "party-0 corrupts enc_check → client passed=false"

echo ""; echo "=== BC e2e: $pass passed, $fail failed ==="
[ $fail -eq 0 ] && exit 0 || exit 1
