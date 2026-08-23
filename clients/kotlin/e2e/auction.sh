#!/usr/bin/env bash
# Kotlin auction FHE-interop e2e (LOCAL — spins up the Go server; not homelab).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
echo "building native FHE lib + ares-smoke fat jar..."
( cd "$REPO_ROOT/clients/kotlin" && bash scripts/build-native.sh && ./gradlew -q :ares-smoke:fatJar )
JAR="$(ls "$REPO_ROOT"/clients/kotlin/ares-smoke/build/libs/*-all.jar | head -1)"
NATIVE_DIR="$REPO_ROOT/clients/kotlin/ares-client-fhe/build/native"
export ARES_CLIENT_CMD="java -Xmx2g -Djava.library.path=$NATIVE_DIR -jar $JAR"
echo "delegating to shared auction.sh, ARES_CLIENT_CMD=$ARES_CLIENT_CMD"
exec "$REPO_ROOT/clients/swift/e2e/auction.sh"
