#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # clients/kotlin
BUILD="$ROOT/native/build"
OUT="$ROOT/ares-client-fhe/build/native"

# Detect JDK for JNI headers. Prefer JAVA_HOME; fall back to common macOS locations.
if [ -z "${JAVA_HOME:-}" ]; then
    if [ -d /opt/homebrew/opt/openjdk ]; then
        export JAVA_HOME=/opt/homebrew/opt/openjdk
    elif [ -d /Library/Java/JavaVirtualMachines ]; then
        export JAVA_HOME=$(ls -d /Library/Java/JavaVirtualMachines/*/Contents/Home 2>/dev/null | head -1)
    fi
fi
echo "JAVA_HOME=${JAVA_HOME:-unset}"

cmake -S "$ROOT/native" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" --config Release
mkdir -p "$OUT"
# macOS produces libares_fhe_jni.dylib; copy to a stable java.library.path dir.
cp "$BUILD"/libares_fhe_jni.* "$OUT"/ 2>/dev/null || cp "$BUILD"/*/libares_fhe_jni.* "$OUT"/
echo "native lib in: $OUT"
