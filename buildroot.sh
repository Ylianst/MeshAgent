#!/bin/bash
# Provision $BUILDROOT: download+verify+extract every toolchain/sysroot/source
# fetchable from a stable public URL; prints manual instructions for the rest
# (see openssl/libstatic/build/README.md's "Sources"). Also used by the
# makefile itself (PATH_MIPS24KC/PATH_MIPSEL24KC ARCHIDs), which is why this
# lives at the repo root instead of under openssl/. Safe to re-run.
#
#   ./buildroot.sh                # everything fetchable
#   ./buildroot.sh list            # show status, fetch nothing
. "$(dirname "$(readlink -f "$0")")/openssl/libstatic/build/env.sh"

mkdir -p "$BR_DOWNLOADS" "$BR_SYSROOTS" "$BR_TOOLCHAINS"

STATUS_LOG="$(mktemp)"
trap 'rm -f "$STATUS_LOG"' EXIT
log_status() { echo "$1: $2" | tee -a "$STATUS_LOG" >&2; }

# True if dest reads clean as an archive (xz/gzip's own checksum) - catches a
# truncated download that a checksum-less fetch can't. Unknown ext = pass.
archive_ok() {
    case "$1" in
        *.tar.xz|*.txz|*.xz)  xz -t "$1"    >/dev/null 2>&1 ;;
        *.tar.gz|*.tgz|*.gz)  gzip -t "$1"   >/dev/null 2>&1 ;;
        *) return 0 ;;
    esac
}

# download URL sha256 dest_file - skips if dest already matches sha256, or
# (no sha256 published) passes archive_ok; else deleted and re-fetched.
fetch() {
    local url="$1" sha="$2" dest="$3"
    if [ -f "$dest" ]; then
        if [ -n "$sha" ]; then
            if echo "$sha  $dest" | sha256sum -c - >/dev/null 2>&1; then
                return 0
            fi
            echo "  $dest exists but fails checksum - re-downloading"
        elif archive_ok "$dest"; then
            return 0
        else
            echo "  $dest exists but fails archive integrity check - re-downloading"
        fi
        rm -f "$dest"
    fi
    echo "  downloading $url"
    curl -sSL --fail -o "$dest" "$url" || { echo "  FETCH FAILED: $url" >&2; return 1; }
    if [ -n "$sha" ]; then
        echo "$sha  $dest" | sha256sum -c - || { echo "  CHECKSUM MISMATCH: $dest" >&2; rm -f "$dest"; return 1; }
    elif ! archive_ok "$dest"; then
        echo "  CORRUPT ARCHIVE (failed integrity check): $dest" >&2; rm -f "$dest"; return 1
    fi
}

# ---------------------------------------------------------------- OpenSSL ----
p_openssl() {
    [ -f "$OPENSSL_TARBALL" ] && echo "$OPENSSL_SHA256  $OPENSSL_TARBALL" | sha256sum -c - >/dev/null 2>&1 && { log_status openssl "already present"; return 0; }
    fetch "https://github.com/openssl/openssl/releases/download/OpenSSL_${OPENSSL_VERSION//./_}/openssl-$OPENSSL_VERSION.tar.gz" \
        "$OPENSSL_SHA256" "$OPENSSL_TARBALL" \
        && log_status openssl "OK" || { log_status openssl "FAILED"; return 1; }
}

# True if $1 (a cross-gcc) can actually compile, not just exist - a truncated
# tarball can extract a working bin/*-gcc wrapper while cc1 is still empty.
toolchain_smoke_ok() {
    [ -x "$1" ] || return 1
    echo 'typedef int x;' | "$1" -c -x c -o /dev/null - >/dev/null 2>&1
}

# -------------------------------------------------------------- OpenWrt SDKs -
# No published checksum for 18.06.9 - verified via toolchain_smoke_ok instead.
p_openwrt() {
    local name="$1" wtarget="$2" wsubtarget="$3" destvar="$4" ccbin="$5"
    local file="openwrt-sdk-18.06.9-${wtarget}-${wsubtarget}_gcc-7.3.0_musl.Linux-x86_64.tar.xz"
    local tarball="$BR_DOWNLOADS/$file"
    local destdir="${!destvar}"
    toolchain_smoke_ok "$destdir/bin/$ccbin" && { log_status "$name" "already present"; return 0; }
    [ -e "$destdir" ] && { echo "  $destdir present but fails a smoke compile - re-fetching" >&2; rm -rf "$destdir"; }
    fetch "https://downloads.openwrt.org/releases/18.06.9/targets/$wtarget/$wsubtarget/$file" "" "$tarball" || { log_status "$name" "FAILED (download)"; return 1; }
    mkdir -p "$BR_TOOLCHAINS" && tar xf "$tarball" -C "$BR_TOOLCHAINS" || { log_status "$name" "FAILED (extract)"; return 1; }
    toolchain_smoke_ok "$destdir/bin/$ccbin" \
        && log_status "$name" "OK" \
        || { log_status "$name" "FAILED (extracted, but $destdir/bin/$ccbin fails a smoke compile - archive layout changed, or extraction incomplete?)"; return 1; }
}

# ------------------------------------------------------------ bootlin toolchains
# Bootlin does publish a per-tarball .sha256 (unlike most others) - pinned here.
p_bootlin() {
    local name="$1" arch="$2" tag="$3" destvar="$4"
    local file="$arch--$tag.tar.xz"
    local tarball="$BR_DOWNLOADS/$file"
    local destdir="${!destvar}"
    [ -d "$destdir" ] && { log_status "$name" "already present"; return 0; }
    local base="https://toolchains.bootlin.com/downloads/releases/toolchains/$arch/tarballs"
    local sha; sha=$(curl -sSL --fail "$base/${file%.tar.xz}.sha256" | awk '{print $1}')
    [ -n "$sha" ] || { log_status "$name" "FAILED (couldn't fetch .sha256 manifest)"; return 1; }
    fetch "$base/$file" "$sha" "$tarball" || { log_status "$name" "FAILED (download)"; return 1; }
    tar xf "$tarball" -C "$BR_TOOLCHAINS" || { log_status "$name" "FAILED (extract)"; return 1; }
    [ -d "$destdir" ] && log_status "$name" "OK" || { log_status "$name" "FAILED (extracted, but $destdir missing - archive top-level dir name changed?)"; return 1; }
}

# ------------------------------------------------------------- Arm GNU toolchain
# Unused by any target - fetched per README's layout, renamed to match env.sh.
p_armgnu() {
    [ -d "$TC_ARMGNU_HF" ] && { log_status armgnu "already present"; return 0; }
    local file="arm-gnu-toolchain-15.2.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz"
    local tarball="$BR_DOWNLOADS/$file"
    fetch "https://developer.arm.com/-/media/Files/downloads/gnu/15.2.rel1/binrel/$file" "" "$tarball" || { log_status armgnu "FAILED (download)"; return 1; }
    tar xf "$tarball" -C "$BR_TOOLCHAINS" || { log_status armgnu "FAILED (extract)"; return 1; }
    mv "$BR_TOOLCHAINS/${file%.tar.xz}" "$TC_ARMGNU_HF" \
        && log_status armgnu "OK" \
        || { log_status armgnu "FAILED (extracted, but rename to $TC_ARMGNU_HF failed)"; return 1; }
}

# --------------------------------------------------------------- BSD sysroots
# usr/include + usr/lib + lib/ - usr/lib's libfoo.so symlinks need that last one.
p_freebsd() {
    [ -d "$SYSROOT_FREEBSD/usr/include" ] && { log_status freebsd "already present"; return 0; }
    local rel="https://download.freebsd.org/releases/amd64/amd64/14.3-RELEASE"
    local sha; sha=$(curl -sSL --fail "$rel/MANIFEST" | awk '$1=="base.txz"{print $2}')
    [ -n "$sha" ] || { log_status freebsd "FAILED (couldn't fetch MANIFEST)"; return 1; }
    fetch "$rel/base.txz" "$sha" "$BR_DOWNLOADS/freebsd-14.3-base.txz" || { log_status freebsd "FAILED (download)"; return 1; }
    mkdir -p "$SYSROOT_FREEBSD"
    tar xf "$BR_DOWNLOADS/freebsd-14.3-base.txz" -C "$SYSROOT_FREEBSD" ./usr/include ./usr/lib ./lib \
        && log_status freebsd "OK" \
        || { log_status freebsd "FAILED (extract)"; return 1; }
}

# OpenBSD splits base79.tgz (runtime) from comp79.tgz (headers/crt objects) -
# base79 alone has an EMPTY usr/include, so both sets are fetched here.
p_openbsd() {
    [ -d "$SYSROOT_OPENBSD/usr/include" ] && { log_status openbsd "already present"; return 0; }
    local rel="https://cdn.openbsd.org/pub/OpenBSD/7.9/amd64"
    local sha_manifest; sha_manifest=$(curl -sSL --fail "$rel/SHA256") || { log_status openbsd "FAILED (couldn't fetch SHA256 manifest)"; return 1; }
    local sha_base; sha_base=$(echo "$sha_manifest" | awk '/^SHA256 \(base79.tgz\)/{print $4}')
    local sha_comp; sha_comp=$(echo "$sha_manifest" | awk '/^SHA256 \(comp79.tgz\)/{print $4}')
    [ -n "$sha_base" ] && [ -n "$sha_comp" ] || { log_status openbsd "FAILED (couldn't parse SHA256 manifest)"; return 1; }
    fetch "$rel/base79.tgz" "$sha_base" "$BR_DOWNLOADS/openbsd-7.9-base79.tgz" || { log_status openbsd "FAILED (download base)"; return 1; }
    fetch "$rel/comp79.tgz" "$sha_comp" "$BR_DOWNLOADS/openbsd-7.9-comp79.tgz" || { log_status openbsd "FAILED (download comp)"; return 1; }
    mkdir -p "$SYSROOT_OPENBSD"
    tar xzf "$BR_DOWNLOADS/openbsd-7.9-base79.tgz" -C "$SYSROOT_OPENBSD" ./usr/include ./usr/lib \
        && tar xzf "$BR_DOWNLOADS/openbsd-7.9-comp79.tgz" -C "$SYSROOT_OPENBSD" ./usr/include ./usr/lib \
        && log_status openbsd "OK" \
        || { log_status openbsd "FAILED (extract)"; return 1; }
}

# ------------------------------------------------------------ dd-wrt toolchains
# One 4.2GB tar.xz, no checksum; server aborts often, so downloads resume.
p_ddwrt() {
    [ -d "$TC_MIPS32EL_MUSL" ] && [ -d "$TC_AARCH64_CORTEXA53_MUSL" ] && [ -d "$TC_ARMV7_CORTEXA9_MUSL" ] \
        && { log_status ddwrt "already present"; return 0; }
    local url="https://download1.dd-wrt.com/dd-wrtv2/downloads/toolchains/toolchains.tar.xz"
    local tarball="$BR_DOWNLOADS/dd-wrt-toolchains.tar.xz"
    local i
    for i in $(seq 1 50); do
        curl --http1.1 -sS -C - --connect-timeout 20 --max-time 300 -o "$tarball" "$url" && break
    done
    [ -f "$tarball" ] || { log_status ddwrt "FAILED (download)"; return 1; }
    tar xf "$tarball" -C "$BR_TOOLCHAINS" \
        "$(basename "$TC_MIPS32EL_MUSL")" "$(basename "$TC_AARCH64_CORTEXA53_MUSL")" "$(basename "$TC_ARMV7_CORTEXA9_MUSL")" \
        || { log_status ddwrt "FAILED (extract)"; return 1; }
    [ -d "$TC_MIPS32EL_MUSL" ] && [ -d "$TC_AARCH64_CORTEXA53_MUSL" ] && [ -d "$TC_ARMV7_CORTEXA9_MUSL" ] \
        && log_status ddwrt "OK" \
        || { log_status ddwrt "FAILED (extracted, but an expected dir is missing - archive layout changed?)"; return 1; }
}

# ---------------------------------------------------------- not fetchable ----
# No stable public URL for these - genuinely bring-your-own, reported only.

# apt package list, shared between check_host_deps's message and print_manual.
APT_PACKAGES="gcc gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi gcc-arm-linux-gnueabihf libc6-dev-i386 lib32gcc-14-dev musl-tools clang lld make curl tar xz-utils"

print_manual() {
    echo
    echo "NOT fetchable by this script - bring your own (see README.md 'Sources'):"
    [ -d "$OSXCROSS_BIN" ]            || echo "  - $OSXCROSS_BIN  (osxcross, built from an Apple-distributed Xcode .xip)"
    echo
    echo "Host apt prerequisites (not installed by this script - run manually):"
    echo "  sudo apt-get install -y $APT_PACKAGES"
    echo "  (NOT gcc-multilib - on Debian trixie/Ubuntu 24.10+ that metapackage's"
    echo "  gcc-14-multilib dependency Conflicts with every gcc-14-<target>-linux-gnu"
    echo "  cross package. libc6-dev-i386 + lib32gcc-14-dev are the same underlying"
    echo "  32-bit runtime gcc-multilib pulls in - 'gcc -m32' works identically -"
    echo "  without the metapackage-level conflict.)"
}

# Needs curl (fetch) + tar/xz (extract) - checked upfront instead of failing
# halfway through a component with a bare "command not found".
check_host_deps() {
    local missing="" cmd
    for cmd in curl tar xz; do
        command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
    done
    [ -z "$missing" ] && return 0
    echo "ERROR: missing required command(s):$missing" >&2
    echo >&2
    print_manual >&2
    exit 1
}

# ---------------------------------------------------------- makefile wiring -
# Symlinks the 2 OpenWrt toolchains `make ARCHID=28`/`40` need; others aren't.
wire_makefile_toolchains() {
    local tc_dir; tc_dir="$(cd "$REPO/.." && pwd)/ToolChains"
    mkdir -p "$tc_dir"
    local name src
    for pair in "toolchain-mips_24kc_gcc-7.3.0_musl:$TC_OWRT_MIPS24KC" \
                "toolchain-mipsel_24kc_gcc-7.3.0_musl:$TC_OWRT_MIPSEL24KC"; do
        name="${pair%%:*}"; src="${pair#*:}"
        if [ -d "$src" ]; then
            ln -sfn "$src" "$tc_dir/$name"
            log_status "makefile-wiring:$name" "-> $src (enables agent ARCHID build)"
        fi
    done
}

# --------------------------------------------------------------------- main --
check_host_deps

ALL="openssl openwrt-mips24kc openwrt-mipsel24kc openwrt-openwrt_x86_64 bootlin-mips32el bootlin-riscv64 armgnu freebsd openbsd ddwrt"

run_one() {
    case "$1" in
        openssl)                p_openssl ;;
        openwrt-mips24kc)       p_openwrt mips24kc       ar71xx generic TC_OWRT_MIPS24KC   mips-openwrt-linux-musl-gcc ;;
        openwrt-mipsel24kc)     p_openwrt mipsel24kc      ramips mt7621  TC_OWRT_MIPSEL24KC mipsel-openwrt-linux-musl-gcc ;;
        openwrt-openwrt_x86_64) p_openwrt openwrt_x86_64  x86    64      TC_OWRT_X86_64      x86_64-openwrt-linux-musl-gcc ;;
        bootlin-mips32el)       p_bootlin bootlin-mips32el mips32el uclibc--stable-2025.08-1 TC_MIPS32EL_UCLIBC ;;
        bootlin-riscv64)        p_bootlin bootlin-riscv64  riscv64-lp64d musl--stable-2025.08-1 TC_RISCV64_MUSL ;;
        armgnu)                 p_armgnu ;;
        freebsd)                p_freebsd ;;
        openbsd)                p_openbsd ;;
        ddwrt)                  p_ddwrt ;;
        *) echo "unknown component: $1 (known: $ALL)" >&2; return 2 ;;
    esac
}

if [ "$1" = "list" ]; then
    br_check
    exit $?
fi

list="$*"; [ -z "$list" ] && list="$ALL"
rc=0
for c in $list; do
    echo "=== $c ==="
    run_one "$c" || rc=1
done
wire_makefile_toolchains

echo
echo "================= SUMMARY ================="
cat "$STATUS_LOG"
print_manual
exit $rc
