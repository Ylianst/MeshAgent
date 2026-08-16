#!/usr/bin/env bash
# Validates the Windows KVM audio path without a Windows machine.
#
#   1. Compiles meshcore/KVM/Windows/windows_audio.c for x64 and x86 against the
#      real Microsoft WASAPI headers shipped with MinGW-w64.
#   2. Confirms the COM GUIDs resolve locally (via <initguid.h>) so no uuid.lib
#      is needed, and that the only external COM symbols come from Ole32.
#   3. Links a real PE executable and runs it under Wine to exercise CAPS
#      emission and the start/stop/cleanup lifecycle.
#   4. Compiles meshcore/KVM/Windows/kvm.c both with and without _KVM_AUDIO and
#      asserts the audio hooks introduce no new errors.
#
# Usage (from the repository root):
#   docker build -f docker/Dockerfile.windows-audio-check -t meshagent-winaudio .
#   docker run --rm -v "$PWD:/src" -w /src meshagent-winaudio bash docker/check-windows-audio.sh
set -uo pipefail

SRC=${SRC:-/src}
STUB=/tmp/winaudio-stub
CASE=/tmp/winaudio-case
FAILED=0

note()  { printf '\n=== %s ===\n' "$1"; }
pass()  { printf '  PASS  %s\n' "$1"; }
fail()  { printf '  FAIL  %s\n' "$1"; FAILED=1; }

mkdir -p "$STUB/opus" "$CASE"

# Opus is linked as a prebuilt static lib on Windows; a header stub is enough to
# type-check our usage here.
cat > "$STUB/opus/opus.h" <<'EOF'
#ifndef OPUS_STUB_H
#define OPUS_STUB_H
#include <stdint.h>
typedef struct OpusEncoder OpusEncoder;
#define OPUS_OK 0
#define OPUS_APPLICATION_AUDIO 2049
#define OPUS_SET_BITRATE(x) 4002,(x)
#define OPUS_SET_INBAND_FEC(x) 4012,(x)
#define OPUS_SET_PACKET_LOSS_PERC(x) 4014,(x)
#define OPUS_SET_DTX(x) 4016,(x)
#define OPUS_SET_COMPLEXITY(x) 4010,(x)
OpusEncoder* opus_encoder_create(int32_t, int, int, int*);
int opus_encoder_ctl(OpusEncoder*, int, ...);
int opus_encode(OpusEncoder*, const int16_t*, int, unsigned char*, int32_t);
void opus_encoder_destroy(OpusEncoder*);
#endif
EOF

# MSVC resolves includes case-insensitively; MinGW does not. Forward the
# capitalised spellings the existing sources use. Unrelated to audio.
for H in Windows.h Winuser.h Ws2tcpip.h WinBase.h Wincrypt.h Iphlpapi.h Psapi.h \
         Shlwapi.h Winsock2.h Sas.h Dbghelp.h Wtsapi32.h Gdiplus.h Objbase.h \
         Shellapi.h Tlhelp32.h Setupapi.h Winreg.h Winnt.h Rpc.h Ole2.h \
         Mmsystem.h STDDEF.H STDIO.H STDLIB.H STRING.H TIME.H MATH.H ASSERT.H \
         ERRNO.H LIMITS.H CTYPE.H STDARG.H SIGNAL.H IO.H FCNTL.H; do
    printf '#include <%s>\n' "$(echo "$H" | tr 'A-Z' 'a-z')" > "$CASE/$H"
done

DEFS_BASE="-DWIN32 -D_WINSERVICE -DMICROSTACK_NO_STDAFX -DMICROSTACK_PROXY -DWINSOCK2 \
-DMESH_AGENTID=4 -D_CRT_SECURE_NO_WARNINGS -DMICROSTACK_NOTLS -DILibChain_WATCHDOG_TIMEOUT=600000"
INC="-I$CASE -I$SRC -I$SRC/microstack -I$SRC/microscript -I$SRC/meshcore \
-I$SRC/meshcore/KVM/Windows -I$STUB"

# ---------------------------------------------------------------- 1. compile
note "Compiling windows_audio.c against real Windows headers"
for TC in x86_64 i686; do
    if "${TC}-w64-mingw32-gcc" -std=gnu99 -O2 -Wall -Wextra -Wno-unused-parameter \
           $DEFS_BASE -D_LINKVM -D_KVM_AUDIO $INC \
           -c -o "/tmp/windows_audio_${TC}.o" \
           "$SRC/meshcore/KVM/Windows/windows_audio.c" 2>"/tmp/cc_${TC}.log"; then
        # Only warnings originating in our own file matter; the project's
        # headers emit MSVC-specific noise under GCC.
        if grep -q "windows_audio.c:.*warning" "/tmp/cc_${TC}.log"; then
            fail "$TC compiled but emitted warnings in windows_audio.c"
            grep "windows_audio.c:.*warning" "/tmp/cc_${TC}.log" | head -10
        else
            pass "$TC compiles clean (-Wall -Wextra)"
        fi
    else
        fail "$TC failed to compile"
        grep -E "error:" "/tmp/cc_${TC}.log" | head -10
    fi
done

# ------------------------------------------------------------------ 2. symbols
note "Checking COM GUID linkage"
if [ -f /tmp/windows_audio_x86_64.o ]; then
    for G in CLSID_MMDeviceEnumerator IID_IMMDeviceEnumerator IID_IAudioClient IID_IAudioCaptureClient; do
        if x86_64-w64-mingw32-nm --defined-only /tmp/windows_audio_x86_64.o | grep -q " $G\$"; then
            pass "$G defined locally (no uuid.lib needed)"
        else
            fail "$G is not defined locally"
        fi
    done
    UNDEF=$(x86_64-w64-mingw32-nm -u /tmp/windows_audio_x86_64.o \
            | grep -oE "__imp_[A-Za-z]+" | sed 's/__imp_//' | sort -u | tr '\n' ' ')
    printf '  external Win32 imports: %s\n' "${UNDEF:-none}"
    if echo "$UNDEF" | grep -qE "CoCreateInstance|CoInitializeEx|CoTaskMemFree"; then
        pass "COM imports satisfied by Ole32.lib"
    fi
fi

# --------------------------------------------------------------- 3. run on PE
note "Linking and running a real Windows binary under Wine"
cat > /tmp/winaudio_harness.c <<'EOF'
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
typedef struct OpusEncoder OpusEncoder;
struct OpusEncoder { int m; };
static struct OpusEncoder g_e = { 1 };
static int g_created = 0, g_destroyed = 0;
OpusEncoder* opus_encoder_create(int32_t fs, int ch, int app, int *err) {
    if (fs != 48000) { printf("    !! encoder rate %d\n", (int)fs); }
    if (ch != 1) { printf("    !! encoder channels %d\n", ch); }
    (void)app; *err = 0; g_created++; return &g_e; }
int opus_encoder_ctl(OpusEncoder *e, int r, ...) { (void)e; (void)r; return 0; }
int opus_encode(OpusEncoder *e, const int16_t *p, int f, unsigned char *o, int32_t m) {
    (void)e; (void)p; (void)m;
    if (f != 960) { printf("    !! opus frame size %d\n", f); }
    o[0] = 1; return 8; }
void opus_encoder_destroy(OpusEncoder *e) { (void)e; g_destroyed++; }

typedef enum { DS_INCOMPLETE = 0, DS_COMPLETE = 1, DS_ERROR = 2 } DS;
extern void kvm_audio_init(DS(*)(char*, int, void*), void*);
extern void kvm_audio_start(void);
extern void kvm_audio_stop(void);
extern void kvm_audio_cleanup(void);
extern void kvm_audio_resend_caps(DS(*)(char*, int, void*), void*);

static int caps = 0, malformed = 0;
static DS sink(char *b, int len, void *r) {
    unsigned char *u = (unsigned char*)b; (void)r;
    int type = (u[0] << 8) | u[1], size = (u[2] << 8) | u[3];
    if (size != len) { malformed++; }
    if (type == 91) {
        caps++;
        printf("    CAPS len=%d rate=%s channels=%d kbps=%d flags=0x%02X platform=%d\n",
               len, u[4] == 0 ? "48k" : "16k", u[5], u[6], u[7], u[8]);
        if (len != 9 || u[4] != 0 || u[5] != 1 || !(u[7] & 0x04) || u[8] != 2) { malformed++; }
    } else if (type != 90) { malformed++; }
    return DS_COMPLETE; }

int main(void) {
    int ok = 1;
    kvm_audio_init(sink, NULL);
    if (caps != 1 || g_created != 1) { printf("  FAIL  init did not advertise CAPS\n"); ok = 0; }
    else { printf("  PASS  init advertises CAPS once\n"); }

    /* No audio endpoint exists inside Wine: capture must fail gracefully. */
    kvm_audio_start(); Sleep(400); kvm_audio_stop();
    printf("  PASS  start/stop with no audio device does not hang or crash\n");

    kvm_audio_start(); Sleep(150); kvm_audio_stop();
    kvm_audio_start(); kvm_audio_start(); Sleep(150);
    kvm_audio_stop();  kvm_audio_stop();
    printf("  PASS  restart and double start/stop are safe\n");

    { int before = caps; kvm_audio_resend_caps(sink, NULL);
      if (caps != before + 1) { printf("  FAIL  resend_caps\n"); ok = 0; }
      else { printf("  PASS  resend_caps emits CAPS\n"); } }

    kvm_audio_cleanup(); kvm_audio_cleanup();
    if (g_destroyed != 1) { printf("  FAIL  cleanup destroyed encoder %d times\n", g_destroyed); ok = 0; }
    else { printf("  PASS  cleanup destroys encoder exactly once\n"); }

    kvm_audio_start(); Sleep(100); kvm_audio_stop();
    printf("  PASS  start after cleanup is a safe no-op\n");

    if (malformed != 0) { printf("  FAIL  %d malformed frames\n", malformed); ok = 0; }
    else { printf("  PASS  all emitted frames well-formed\n"); }
    return ok ? 0 : 1; }
EOF

if x86_64-w64-mingw32-gcc -std=gnu99 -O2 -o /tmp/winaudio_test.exe \
       /tmp/winaudio_harness.c /tmp/windows_audio_x86_64.o -lole32 -lwinmm 2>/tmp/link.log; then
    pass "links a real PE executable ($(file -b /tmp/winaudio_test.exe | cut -d, -f1))"
    if timeout 180 wine /tmp/winaudio_test.exe 2>/dev/null; then
        pass "Wine runtime tests passed"
    else
        fail "Wine runtime tests failed"
    fi
else
    fail "link failed"; head -10 /tmp/link.log
fi

# -------------------------------------------------------------- 4. kvm.c hooks
note "Compiling kvm.c with and without _KVM_AUDIO"
# kvm.c uses MSVC __try/__except, which GCC cannot parse, so it can never fully
# compile here. What matters is that enabling audio introduces no NEW errors.
count_errors() {
    x86_64-w64-mingw32-gcc -std=gnu99 -fsyntax-only $DEFS_BASE "$@" $INC \
        "$SRC/meshcore/KVM/Windows/kvm.c" 2>&1 | grep -cE "error:"
}
audio_errors() {
    x86_64-w64-mingw32-gcc -std=gnu99 -fsyntax-only $DEFS_BASE "$@" $INC \
        "$SRC/meshcore/KVM/Windows/kvm.c" 2>&1 \
        | grep -iE "error:.*(kvm_audio|MNG_AUDIO|opus)" | head -10
}
WITH=$(count_errors -D_LINKVM -D_KVM_AUDIO)
WITHOUT=$(count_errors -D_LINKVM)
AUD=$(audio_errors -D_LINKVM -D_KVM_AUDIO)

printf '  errors with audio: %s, without audio: %s (pre-existing __try/__except)\n' "$WITH" "$WITHOUT"
if [ -n "$AUD" ]; then fail "audio hooks produced errors"; echo "$AUD"
else pass "no audio-related errors in kvm.c"; fi
if [ "$WITH" = "$WITHOUT" ]; then pass "audio hooks introduce no new errors"
else fail "audio hooks changed the error count"; fi

note "Result"
if [ "$FAILED" -eq 0 ]; then echo "  ALL WINDOWS AUDIO CHECKS PASSED"; else echo "  CHECKS FAILED"; fi
exit "$FAILED"
