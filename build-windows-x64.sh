#!/bin/bash
# Cross-compile MeshService64.exe (Windows x64) with _KVM_AUDIO support using dockcross/MXE.
# Usage: bash build-windows-x64.sh
set -e

AGENT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPUS_VERSION=1.6.1
OPUS_URL="https://downloads.xiph.org/releases/opus/opus-${OPUS_VERSION}.tar.gz"
OPENSSL_VERSION=1.1.1w
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
OUT_EXE="${AGENT_DIR}/MeshService64-audio.exe"

echo "==> Building Windows x64 MeshService64 with _KVM_AUDIO via dockcross"

mkdir -p "${AGENT_DIR}/lib-opus/windows/x64"
mkdir -p "${AGENT_DIR}/lib-openssl/windows/x64"

docker run --rm \
  -v "${AGENT_DIR}:/src" \
  -w /src \
  dockcross/windows-static-x64 \
  bash -ex -c '
set -ex
CC=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-gcc
CXX=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-g++
AR=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-ar
SYSROOT=/usr/src/mxe/usr/x86_64-w64-mingw32.static
OPUS_VERSION='"${OPUS_VERSION}"'
OPUS_URL='"${OPUS_URL}"'
OPENSSL_VERSION='"${OPENSSL_VERSION}"'
OPENSSL_URL='"${OPENSSL_URL}"'

# ── 0. Build OpenSSL (skip if already built) ──────────────────────────────
if [ ! -f /src/lib-openssl/windows/x64/libssl.a ]; then
  cd /tmp
  curl -sSLf "$OPENSSL_URL" -o openssl.tar.gz
  tar xzf openssl.tar.gz
  cd openssl-${OPENSSL_VERSION}
  CC=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-gcc \
  AR=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-ar \
  RANLIB=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-ranlib \
  RC=/usr/src/mxe/usr/bin/x86_64-w64-mingw32.static-windres \
  ./Configure mingw64 \
    --prefix=/tmp/openssl-win64 \
    no-shared no-tests no-asm \
    -O2
  make -j$(nproc)
  make install_sw
  mkdir -p /src/lib-openssl/windows/x64
  cp /tmp/openssl-win64/lib/libssl.a    /src/lib-openssl/windows/x64/
  cp /tmp/openssl-win64/lib/libcrypto.a /src/lib-openssl/windows/x64/
  cp -r /tmp/openssl-win64/include /src/lib-openssl/windows/x64/
  echo "OpenSSL built OK: $(ls -lh /src/lib-openssl/windows/x64/lib*.a)"
fi

# ── 1. Build libopus (skip if already built) ──────────────────────────────
if [ ! -f /src/lib-opus/windows/x64/libopus.lib ]; then
  cd /tmp
  curl -sSLf "$OPUS_URL" -o opus.tar.gz
  tar xzf opus.tar.gz
  cd opus-${OPUS_VERSION}
  ./configure --host=x86_64-w64-mingw32.static \
    CC="$CC" CXX="$CXX" AR="$AR" \
    --prefix=/tmp/opus-win64 \
    --enable-static --disable-shared \
    --disable-extra-programs --disable-doc \
    CFLAGS="-O2"
  make -j$(nproc)
  make install
  cp /tmp/opus-win64/lib/libopus.a /src/lib-opus/windows/x64/libopus.lib
  echo "Opus built OK: $(ls -lh /src/lib-opus/windows/x64/libopus.lib)"
fi

# ── 2. Patch files that need source-level fixes ───────────────────────────

# Patch A: resource.h is UTF-16LE — convert to UTF-8 in place
# (compiler searches the source dir first, so -I overrides do not work)
if file /src/meshservice/resource.h | grep -qi UTF-16; then
  iconv -f UTF-16LE -t UTF-8 /src/meshservice/resource.h \
    | sed '"'"'1s/^\xef\xbb\xbf//'"'"' > /tmp/resource_utf8.h
  cp /tmp/resource_utf8.h /src/meshservice/resource.h
  echo "resource.h: UTF-16LE -> UTF-8 OK"
fi

# Patch B: ILibParsers.c — fix conflicting types (header says void*, impl says char*)
python3 /src/patch_ILibParsers.py /src/microstack/ILibParsers.c /tmp/parsersfix/ILibParsers.c

# Patch C: wincrypto.cpp — strip extern "C" wrapper so GCC can compile as C
#   C++ goto-over-init is not allowed; compiling as C lifts this restriction.
#   Also adds missing bcrypt.h/ncrypt.h includes.
python3 /src/patch_wincrypto.py /src/meshcore/wincrypto.cpp /tmp/wincfix/wincrypto.c

# ── 3. Stub out missing headers ────────────────────────────────────────────
mkdir -p /tmp/stubhdrs

# Case-redirect stubs: MXE filesystem is case-sensitive but source uses Windows casing
printf "#include <windows.h>\n"  > /tmp/stubhdrs/Windows.h
printf "#include <winsock2.h>\n" > /tmp/stubhdrs/WinSock2.h
printf "#include <winbase.h>\n"  > /tmp/stubhdrs/WinBase.h
printf "#include <winuser.h>\n"  > /tmp/stubhdrs/Winuser.h
printf "#include <ws2tcpip.h>\n" > /tmp/stubhdrs/WS2tcpip.h
printf "#include <wspiapi.h>\n"  > /tmp/stubhdrs/Wspiapi.h
printf "#include <wtsapi32.h>\n" > /tmp/stubhdrs/WtsApi32.h
printf "#include <shlwapi.h>\n"  > /tmp/stubhdrs/Shlwapi.h
printf "#include <softpub.h>\n"  > /tmp/stubhdrs/Softpub.h
printf "#include <psapi.h>\n"    > /tmp/stubhdrs/Psapi.h
printf "#include <iphlpapi.h>\n" > /tmp/stubhdrs/IPHlpApi.h
printf "#include <dbghelp.h>\n"  > /tmp/stubhdrs/Dbghelp.h
printf "#include <aclapi.h>\n"   > /tmp/stubhdrs/AclAPI.h
printf "#include <stddef.h>\n"   > /tmp/stubhdrs/STDDEF.h
printf "#include <stddef.h>\n"   > /tmp/stubhdrs/STDDEF.H

# shellscalingapi.h does not exist in MXE — provide a minimal stub
cat > /tmp/stubhdrs/shellscalingapi.h <<'"'"'HEOF'"'"'
/* MXE stub for shellscalingapi.h */
#pragma once
#ifndef _SHELLSCALINGAPI_H_
#define _SHELLSCALINGAPI_H_
#include <windows.h>
/* Redefine UNREFERENCED_PARAMETER to void-cast form — array-safe */
#ifdef UNREFERENCED_PARAMETER
#undef UNREFERENCED_PARAMETER
#endif
#define UNREFERENCED_PARAMETER(x) ((void)(x))
typedef enum { PROCESS_DPI_UNAWARE = 0, PROCESS_SYSTEM_DPI_AWARE = 1, PROCESS_PER_MONITOR_DPI_AWARE = 2 } PROCESS_DPI_AWARENESS;
typedef enum { MDT_EFFECTIVE_DPI = 0, MDT_ANGULAR_DPI = 1, MDT_RAW_DPI = 2, MDT_DEFAULT = MDT_EFFECTIVE_DPI } MONITOR_DPI_TYPE;
static inline HRESULT GetProcessDpiAwareness(HANDLE h, PROCESS_DPI_AWARENESS *v) { (void)h; if(v) *v=PROCESS_DPI_UNAWARE; return S_OK; }
static inline HRESULT SetProcessDpiAwareness(PROCESS_DPI_AWARENESS v) { (void)v; return S_OK; }
#endif
HEOF

# Stub out commit info header if missing
[ -f /src/microscript/ILibDuktape_Commit.h ] || cat > /src/microscript/ILibDuktape_Commit.h <<'"'"'HDR'"'"'
#define SOURCE_COMMIT_DATE "unknown"
#define SOURCE_COMMIT_HASH "unknown"
HDR

# ── 4. Compile ────────────────────────────────────────────────────────────
DEFINES="-DMESH_AGENTID=4 -DDUK_USE_DATE_NOW_WINDOWS -DNOLMSCOMMANDER -DMICROSTACK_PROXY"
DEFINES="$DEFINES -D_LINKVM -D_KVM_AUDIO -DWIN32 -DWIN64 -D_WINSERVICE -DNDEBUG"
DEFINES="$DEFINES -DWINSOCK2 -DMICROSTACK_NO_STDAFX -DMICROSTACK_TLS_DETECT"
DEFINES="$DEFINES -DILibChain_WATCHDOG_TIMEOUT=600000 -D_REMOTELOGGING -D_REMOTELOGGINGSERVER"
DEFINES="$DEFINES -DDUK_USE_DEBUGGER_SUPPORT -DDUK_USE_INTERRUPT_COUNTER"
DEFINES="$DEFINES -DDUK_USE_DEBUGGER_INSPECT -DDUK_USE_DEBUGGER_PAUSE_UNCAUGHT"
DEFINES="$DEFINES -DDUK_USE_DEBUGGER_DUMPHEAP -D__STDC__ -D_CRT_SECURE_NO_WARNINGS"
DEFINES="$DEFINES -D_MSC_PLATFORM_TOOLSET_MINGW"

# /tmp/stubhdrs — shellscalingapi.h stub (must come before sysroot includes)
INCS="-I/tmp/stubhdrs"
INCS="$INCS -I/src -I/src/lib-opus/includes -I/src/lib-openssl/windows/x64/include"
INCS="$INCS -I${SYSROOT}/include"

# Force-include shellscalingapi.h before any source so PROCESS_DPI_AWARENESS is defined
# early enough for agentcore.h:161 (which uses it without including shellscalingapi.h first).
# Then include the SEH compat shim for __try/__except stubs.
SEH="-include /tmp/stubhdrs/shellscalingapi.h -include /src/mingw_seh_compat.h"

SRCS="
meshservice/ServiceMain.c
meshservice/firewall.cpp
meshcore/agentcore.c
meshcore/KVM/Windows/input.c
meshcore/KVM/Windows/kvm.c
meshcore/KVM/Windows/tile.cpp
meshcore/KVM/Windows/windows_audio.c
meshcore/meshinfo.c
meshcore/zlib/adler32.c meshcore/zlib/deflate.c meshcore/zlib/inffast.c
meshcore/zlib/inflate.c meshcore/zlib/inftrees.c meshcore/zlib/trees.c meshcore/zlib/zutil.c
microscript/duktape.c microscript/duk_module_duktape.c
microscript/ILibDuktapeModSearch.c
microscript/ILibDuktape_ChildProcess.c microscript/ILibDuktape_CompressedStream.c
microscript/ILibDuktape_Debugger.c microscript/ILibDuktape_Dgram.c
microscript/ILibDuktape_DuplexStream.c microscript/ILibDuktape_EncryptionStream.c
microscript/ILibduktape_EventEmitter.c microscript/ILibDuktape_fs.c
microscript/ILibDuktape_GenericMarshal.c microscript/ILibDuktape_Helpers.c
microscript/ILibDuktape_HttpStream.c microscript/ILibDuktape_MemoryStream.c
microscript/ILibDuktape_net.c microscript/ILibDuktape_NetworkMonitor.c
microscript/ILibDuktape_Polyfills.c microscript/ILibDuktape_ReadableStream.c
microscript/ILibDuktape_ScriptContainer.c microscript/ILibDuktape_SHA256.c
microscript/ILibDuktape_SimpleDataStore.c microscript/ILibDuktape_WebRTC.c
microscript/ILibDuktape_WritableStream.c
microstack/ILibAsyncServerSocket.c microstack/ILibAsyncSocket.c
microstack/ILibAsyncUDPSocket.c microstack/ILibCrypto.c
microstack/ILibIPAddressMonitor.c microstack/ILibMulticastSocket.c
microstack/ILibProcessPipe.c
microstack/ILibRemoteLogging.c microstack/ILibSimpleDataStore.c
microstack/ILibWebClient.c microstack/ILibWebRTC.c
microstack/ILibWebServer.c microstack/ILibWrapperWebRTC.c
"

# wincrypto.cpp and ILibParsers.c are compiled from patched copies; wasapi_guids.c defines WASAPI GUIDs
EXTRA_SRCS_C="/tmp/wincfix/wincrypto.c /tmp/parsersfix/ILibParsers.c /src/wasapi_guids.c /src/winmain_shim.c"

CFLAGS="-O2 -std=c11 $DEFINES $INCS $SEH -fno-strict-aliasing -Wno-implicit-function-declaration"
CXXFLAGS="-O2 $DEFINES $INCS $SEH -fno-strict-aliasing"

# OpenSSL and Opus are linked explicitly by full path in the link command below
LIBS="-lmmdevapi -lole32 -loleaut32 -luuid -lsetupapi -lws2_32 -lpsapi -ldbghelp"
LIBS="$LIBS -liphlpapi -lwintrust -lversion -lwtsapi32 -lcrypt32 -lncrypt -lbcrypt"
LIBS="$LIBS -lgdi32 -lgdiplus -lwinhttp -lcomctl32 -lshlwapi -lm"

mkdir -p /tmp/obj64
OBJS=""

for src in $SRCS; do
  obj="/tmp/obj64/$(echo $src | tr / _).o"
  echo "  CC  $src"
  case "$src" in
    *.cpp) "$CXX" $CXXFLAGS -c /src/$src -o "$obj" ;;
    *)     "$CC"  $CFLAGS   -c /src/$src -o "$obj" ;;
  esac
  OBJS="$OBJS $obj"
done

# Patched C files — extra -I for wincrypto.c which lives in /tmp but includes "wincrypto.h"
for src in $EXTRA_SRCS_C; do
  base=$(basename "$src")
  obj="/tmp/obj64/${base%.c}.o"
  echo "  CC  $src (patched)"
  "$CC" $CFLAGS -I/src/meshcore -I/src/microstack -c "$src" -o "$obj"
  OBJS="$OBJS $obj"
done

echo "==> Linking MeshService64-audio.exe"
"$CXX" $CXXFLAGS -mconsole $OBJS \
  /src/lib-opus/windows/x64/libopus.lib \
  /src/lib-openssl/windows/x64/libssl.a \
  /src/lib-openssl/windows/x64/libcrypto.a \
  $LIBS \
  -o /src/MeshService64-audio.exe \
  -static

echo "DONE: $(ls -lh /src/MeshService64-audio.exe)"
'
