#!/bin/bash
# Fetches an OpenBSD sysroot for cross-compiling the agent with clang on Linux: usr/lib and usr/include only.
# Usage: fetch-openbsd-sysroot.sh <release> <dir>, for example fetch-openbsd-sysroot.sh 7.9 "$RUNNER_TEMP/openbsd-7.9".
# A directory that already holds libc.so and stdio.h is kept, so a restored cache costs nothing.
# Needs signify-openbsd, and the release's base public key in openbsd-base.pub next to this script, one '<NN>  <pubkey>' line per release.
set -euo pipefail

rel="$1"
dir="$2"
nodot="${rel//./}"
keys="$(cd "$(dirname "$0")" && pwd)/openbsd-base.pub"

# On GitHub Actions the ::error:: prefix turns the message into an annotation on the run summary
fail() { echo "${GITHUB_ACTIONS:+::error::}openbsd-$rel: $*"; exit 1; }

# OpenBSD ships no unversioned libNAME.so links and ld.lld does not do OpenBSD's version search.
# Without these links the linker silently takes the static .a for every -l and the binary has no PT_DYNAMIC.
so_links() {
    local f base
    for f in "$1"/usr/lib/lib*.so.*.*; do
        [ -e "$f" ] || continue
        base="$(basename "$f" | sed -E 's/(\.so)\.[0-9]+\.[0-9]+$/\1/')"
        [ -e "$1/usr/lib/$base" ] || ln -s "$(basename "$f")" "$1/usr/lib/$base"
    done
}

is_complete() {
    ls "$1"/usr/lib/libc.so.* >/dev/null 2>&1 && [ -f "$1/usr/include/stdio.h" ]
}

fetch_archive() {
    echo "Downloading: $url/$1"
    curl -Ss --location --fail --retry 3 --connect-timeout 5 --speed-limit 50000 --speed-time 30 --max-time 240 "$url/$1" -o "$work/$1"
}

if is_complete "$dir"; then
    so_links "$dir"
    echo "openbsd-$rel: sysroot already present in $dir"
    exit 0
fi
pubkey="$(awk -v r="$nodot" '$1 == r { print $2 }' "$keys")"
[ -n "$pubkey" ] || fail "no public key in $keys, add '$nodot  <pubkey>' from the release's etc/signify/openbsd-$nodot-base.pub"

# OpenBSD has no per-package base system, so the whole comp and base sets are fetched and only the sysroot paths are kept.
# The headers and crt objects are in comp<NN>.tgz, the shared libraries in base<NN>.tgz.
# Each set is checked against the signed SHA256.sig before tar reads it, because a plain SHA256 from the same CDN proves nothing about the CDN.
url="https://cdn.openbsd.org/pub/OpenBSD/$rel/amd64"
work="$(mktemp -d)"
trap 'rm -rf "$work" "$dir.tmp"' EXIT
# signify only reads a key file whose first line is the untrusted comment
key="$work/openbsd-$nodot-base.pub"
printf 'untrusted comment: openbsd %s base public key\n%s\n' "$rel" "$pubkey" > "$key"
fetch_archive "SHA256.sig" || fail "download of SHA256.sig failed"
rm -rf "$dir.tmp"
mkdir -p "$dir.tmp"
for set in comp base; do
    # GNU tar fails on a pattern that matches nothing, so each set gets only the paths it has. OpenBSD has no top-level /lib.
    paths=('./usr/lib/*')
    [ "$set" = comp ] && paths=('./usr/include/*' './usr/lib/*')
    fetch_archive "$set$nodot.tgz" || fail "download of $set$nodot.tgz failed"
    (cd "$work" && signify-openbsd -C -q -p "$key" -x SHA256.sig "$set$nodot.tgz") \
        || fail "$set$nodot.tgz does not match the signed SHA256.sig"
    tar xzf "$work/$set$nodot.tgz" -C "$dir.tmp" --wildcards "${paths[@]}"
    rm -f "$work/$set$nodot.tgz"
    echo "openbsd-$rel: $set$nodot.tgz OK"
done
# remove unnecessary static libs and clang util
find "$dir.tmp" -name '*.a' ! -name libcompiler_rt.a -delete
rm -rf "$dir.tmp/usr/lib/clang" "$dir.tmp"/usr/lib/libLLVM.so*
so_links "$dir.tmp"
is_complete "$dir.tmp" || fail "extracted, but libc.so or stdio.h is missing"
# Moved into place only when complete, so a run that fails halfway never leaves a directory the check above would accept.
rm -rf "$dir"
mv "$dir.tmp" "$dir"
echo "openbsd-$rel: sysroot ready in $dir"
