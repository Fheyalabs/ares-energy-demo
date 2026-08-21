#!/bin/bash
# Build the browser FHE module: OpenFHE 1.5.1 -> WebAssembly, plus
# ARES-core's own C wrapper and a thin embind veneer.
#
# Produces static/wasm/pool_wasm.{js,wasm}. Those are build artifacts and
# are gitignored; run this to regenerate them.
#
# Prerequisites and the non-obvious bits, all learned the hard way:
#
#   emsdk        Needs python >=3.10; Xcode ships 3.9.6, so EMSDK_PYTHON is
#                pinned to homebrew's. On macOS 26 platform.mac_ver() returns
#                empty and emsdk cannot detect the OS, hence EMSDK_OS=macos.
#
#   -Werror      OpenFHE hardcodes "-Wall -Werror" into CXX_COMPILE_FLAGS
#                (CMakeLists.txt:163), a plain set() that -D cannot override,
#                and appends it AFTER CMAKE_CXX_FLAGS. CMAKE_CXX_FLAGS_RELEASE
#                lands after both, and for -W options the last wins. Newer
#                emscripten clang emits -Wunused-template, which OpenFHE's own
#                EMSCRIPTEN_IGNORE_WARNINGS list predates.
#
#   OpenMP       Off. WASM threading needs pthreads + SharedArrayBuffer +
#                COOP/COEP headers; single-threaded is fine here.
#
# OpenFHE already carries a first-class EMSCRIPTEN branch (memory limits,
# exceptions, emmalloc), so this is configuration, not porting.
set -euo pipefail

EMSDK=${EMSDK_ROOT:-/Volumes/Hardik_external_T7/emsdk}
OF_SRC=${OPENFHE_SRC:-$HOME/Fheya/openfhe-development}
OF_BUILD=${OPENFHE_WASM_BUILD:-/Volumes/Hardik_external_T7/openfhe-wasm-build}
OF_PREFIX=${OPENFHE_WASM_PREFIX:-/Volumes/Hardik_external_T7/openfhe-wasm}

HERE=$(cd "$(dirname "$0")" && pwd)
DEMO=$(dirname "$HERE")
REPO=$(cd "$DEMO/../.." && pwd)
WRAP="$REPO/pkg/ares/crypto/cgo"
OUT="$DEMO/static/wasm"

export PATH=/opt/homebrew/bin:$PATH
# shellcheck disable=SC1091
source "$EMSDK/emsdk_env.sh" >/dev/null 2>&1

INC="-I$WRAP -I$OF_PREFIX/include/openfhe -I$OF_PREFIX/include/openfhe/core -I$OF_PREFIX/include/openfhe/pke -I$OF_PREFIX/include/openfhe/binfhe -I$OF_PREFIX/include/openfhe/cereal"
WARN="-Wno-error -Wno-unused-template -Wno-unused-function -Wno-unused-but-set-variable -Wno-unknown-warning-option"

if [ ! -f "$OF_PREFIX/lib/libOPENFHEpke_static.a" ]; then
  echo "=== building OpenFHE for WASM (long) ==="
  mkdir -p "$OF_BUILD"; cd "$OF_BUILD"
  emcmake cmake "$OF_SRC" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$OF_PREFIX" \
    -DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG -Wno-error -Wno-unused-template -Wno-unused-function" \
    -DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG -Wno-error -Wno-unused-function" \
    -DWITH_OPENMP=OFF -DBUILD_SHARED=OFF -DBUILD_STATIC=ON \
    -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
    -DBUILD_EXTRAS=OFF -DWITH_NATIVEOPT=OFF -DNATIVE_SIZE=64
  emmake make -j4
  emmake make install
fi

mkdir -p "$OUT"
echo "=== compiling ARES-core wrapper + veneer ==="
em++ -O2 -std=c++17 -fexceptions $INC $WARN -c "$WRAP/openfhe_wrapper.cpp" -o "$OUT/.openfhe_wrapper.o"
em++ -O2 -std=c++17 -fexceptions $INC $WARN -c "$HERE/pool_wasm.cpp"        -o "$OUT/.pool_wasm.o"

echo "=== linking module ==="
em++ -O2 -std=c++17 -fexceptions \
  "$OUT/.pool_wasm.o" "$OUT/.openfhe_wrapper.o" \
  "$OF_PREFIX/lib/libOPENFHEpke_static.a" \
  "$OF_PREFIX/lib/libOPENFHEbinfhe_static.a" \
  "$OF_PREFIX/lib/libOPENFHEcore_static.a" \
  -lembind \
  -sMODULARIZE=1 -sEXPORT_NAME=PoolWasm -sEXPORT_ES6=0 \
  -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=64MB -sMAXIMUM_MEMORY=4GB \
  -sMALLOC=emmalloc -sDISABLE_EXCEPTION_CATCHING=0 \
  -sENVIRONMENT=web,worker,node \
  -sEXPORTED_RUNTIME_METHODS=ENV,getExceptionMessage \
  -Wno-limited-postlink-optimizations \
  -o "$OUT/pool_wasm.js"

rm -f "$OUT"/.*.o
ls -lh "$OUT"/pool_wasm.js "$OUT"/pool_wasm.wasm
echo "OK"
