#!/usr/bin/env bash
# Kotlin ares-smoke e2e: build fat jar, then delegate to the shared harness.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
echo "building ares-smoke fat jar..."
( cd "$REPO_ROOT/clients/kotlin" && ./gradlew -q :ares-smoke:fatJar )
JAR="$(ls "$REPO_ROOT"/clients/kotlin/ares-smoke/build/libs/*-all.jar | head -1)"
export ARES_CLIENT_CMD="java -jar $JAR"
echo "delegating to shared harness, ARES_CLIENT_CMD=$ARES_CLIENT_CMD"
exec "$REPO_ROOT/clients/swift/e2e/voting.sh"
