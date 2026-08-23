#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
PORT="${PORT:-8742}"
N="${PARTICIPANTS:-3}"
cd "$REPO_ROOT"
echo "building voting session-service..."
go build -o /tmp/ares-voting-svc ./examples/voting/cmd/session-service
echo "starting voting session-service on :$PORT..."
SESSION_PORT="$PORT" ARES_WS_SECRET="" /tmp/ares-voting-svc >/tmp/ares-voting-svc.log 2>&1 &
SERVER_PID=$!
wait_for_health "http://localhost:$PORT"
echo "running client voting flow ($N participants)..."
set +e
ARES_OPENFHE=1 $ARES_CLIENT_CMD voting --server "http://localhost:$PORT" --participants "$N" --auth-secret ""
RC=$?
set -e
if [[ $RC -ne 0 ]]; then echo "=== server log ==="; tail -80 /tmp/ares-voting-svc.log; fi
echo "voting e2e exit code: $RC"
exit $RC
