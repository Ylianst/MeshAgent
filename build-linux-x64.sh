#!/bin/bash
# Cross-compile meshagent_x86-64 (Linux x64) with _KVM_AUDIO support using dockcross.
# Author: Jugurtha-Green
# Usage: bash build-linux-x64.sh
set -e

AGENT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPUS_VERSION=1.6.1
OPUS_URL="https://downloads.xiph.org/releases/opus/opus-${OPUS_VERSION}.tar.gz"
ARCHID=6
ARCHNAME=x86-64
OUT_BIN="${AGENT_DIR}/meshagent_x86-64"

echo "==> Building Linux x64 meshagent with _KVM_AUDIO via dockcross"

docker run --rm \
  -v "${AGENT_DIR}:/src" \
  -w /src \
  dockcross/linux-x64 \
  bash -ex -c '
set -ex
OPUS_VERSION='"${OPUS_VERSION}"'
OPUS_URL='"${OPUS_URL}"'

# ── 1. Build libopus from source ──────────────────────────────────────────
mkdir -p /tmp/opus-build
cd /tmp/opus-build
if [ ! -f opus-${OPUS_VERSION}.tar.gz ]; then
    curl -fSL -o opus-${OPUS_VERSION}.tar.gz "${OPUS_URL}"
fi
tar xzf opus-${OPUS_VERSION}.tar.gz
cd opus-${OPUS_VERSION}
./configure --host=x86_64-linux-gnu --prefix=/tmp/opus-install \
    --enable-static --disable-shared --disable-doc --disable-extra-programs \
    CFLAGS="-O2 -fPIC"
make -j$(nproc)
make install

# Copy built static lib into the source tree
mkdir -p /src/lib-opus/linux/x86-64
cp /tmp/opus-install/lib/libopus.a /src/lib-opus/linux/x86-64/libopus.a

# ── 2. Stub out commit info if missing ────────────────────────────────────
[ -f /src/microscript/ILibDuktape_Commit.h ] || cat > /src/microscript/ILibDuktape_Commit.h <<HEOF
#define SOURCE_COMMIT_DATE "unknown"
#define SOURCE_COMMIT_HASH "unknown"
HEOF

# ── 3. Build the agent ────────────────────────────────────────────────────
cd /src
make linux ARCHID=6 KVM=1 JPEGVER=v80

echo "==> Linux x64 build complete"
'

if [ -f "${AGENT_DIR}/meshagent_x86-64" ]; then
    echo "==> Output: ${OUT_BIN}"
    ls -la "${OUT_BIN}"
else
    echo "ERROR: meshagent_x86-64 not found after build"
    exit 1
fi
