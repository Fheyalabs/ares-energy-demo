#!/usr/bin/env bash
# Auction FHE-ciphertext interop e2e: start the sealed_bid_auction helper-backed
# session-service (shallow depth, dev-bypass), run the client auction flow, assert SETTLED.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PORT="${PORT:-8741}"
N="${PARTICIPANTS:-3}"
# depth=12 + ring_dim=2048 match the Python smoke defaults and keep OOM risk low
# on Mac. AUCTION_CRYPTO_DEPTH=6 is too shallow for the degree-3 sharpening
# polynomial used in PhaseArgmax (requires depth_min=8).
export AUCTION_CRYPTO_DEPTH="${AUCTION_CRYPTO_DEPTH:-12}"
export AUCTION_RING_DIM="${AUCTION_RING_DIM:-2048}"

cd "$REPO_ROOT"
echo "building openfhe-contract-helper + auction session-service (-tags openfhe)..."
go build -tags openfhe -o /tmp/ares-helper ./cmd/openfhe-contract-helper
go build -tags openfhe -o /tmp/ares-auction-svc ./examples/sealed_bid_auction/cmd/session-service

echo "starting auction session-service on :$PORT (depth=$AUCTION_CRYPTO_DEPTH)..."
SESSION_PORT="$PORT" ARES_WS_SECRET="" ARES_HELPER_BINARY=/tmp/ares-helper \
  AUCTION_CRYPTO_DEPTH="$AUCTION_CRYPTO_DEPTH" AUCTION_RING_DIM="$AUCTION_RING_DIM" \
  /tmp/ares-auction-svc >/tmp/ares-auction-svc.log 2>&1 &
SERVER_PID=$!

wait_for_health "http://localhost:$PORT"

echo "running client auction flow ($N participants)..."
set +e
AUCTION_CRYPTO_DEPTH="$AUCTION_CRYPTO_DEPTH" AUCTION_RING_DIM="$AUCTION_RING_DIM" ARES_OPENFHE=1 \
  $ARES_CLIENT_CMD auction --server "http://localhost:$PORT" --participants "$N" --auth-secret ""
RC=$?
set -e

if [[ $RC -ne 0 ]]; then echo "=== server log ==="; tail -50 /tmp/ares-auction-svc.log; fi
echo "auction e2e exit code: $RC"
exit $RC
