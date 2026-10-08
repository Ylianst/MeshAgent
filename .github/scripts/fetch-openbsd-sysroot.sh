#!/bin/bash
# Fetches an OpenBSD sysroot for cross-compiling the agent with clang on Linux: usr/lib and usr/include only.
# Usage: fetch-openbsd-sysroot.sh <release> <dir>, for example fetch-openbsd-sysroot.sh 7.9 "$RUNNER_TEMP/openbsd-7.9".
# A directory that already holds libc.so and stdio.h is kept, so a restored cache costs nothing.
# Needs signify-openbsd, and the release's base public key next to this script as openbsd-<NN>-base.pub.
set -euo pipefail

rel="$1"
dir="$2"
nodot="${rel//./}"
key="$(cd "$(dirname "$0")" && pwd)/openbsd-$nodot-base.pub"

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

if is_complete "$dir"; then
    so_links "$dir"
    echo "openbsd-$rel: sysroot already present in $dir"
    exit 0
fi
[ -f "$key" ] || { echo "openbsd-$rel: no public key $key, add the release's etc/signify/openbsd-$nodot-base.pub" >&2; exit 1; }

# OpenBSD has no per-package base system, so the whole comp and base sets are fetched and only the sysroot paths are kept.
# The headers and crt objects are in comp<NN>.tgz, the shared libraries in base<NN>.tgz.
# Each set is checked against the signed SHA256.sig before tar reads it, because a plain SHA256 from the same CDN proves nothing about the CDN.
url="https://cdn.openbsd.org/pub/OpenBSD/$rel/amd64"
work="$(mktemp -d)"
trap 'rm -rf "$work" "$dir.tmp"' EXIT
curl -sSL --fail --retry 3 "$url/SHA256.sig" -o "$work/SHA256.sig"
rm -rf "$dir.tmp"
mkdir -p "$dir.tmp"
for set in comp base; do
    # GNU tar fails on a pattern that matches nothing, so each set gets only the paths it has. OpenBSD has no top-level /lib.
    paths=('./usr/lib/*')
    [ "$set" = comp ] && paths=('./usr/include/*' './usr/lib/*')
    curl -sSL --fail --retry 3 "$url/$set$nodot.tgz" -o "$work/$set$nodot.tgz"
    (cd "$work" && signify-openbsd -C -q -p "$key" -x SHA256.sig "$set$nodot.tgz") \
        || { echo "openbsd-$rel: $set$nodot.tgz does not match the signed SHA256.sig" >&2; exit 1; }
    tar xzf "$work/$set$nodot.tgz" -C "$dir.tmp" --wildcards "${paths[@]}"
    rm -f "$work/$set$nodot.tgz"
    echo "openbsd-$rel: $set$nodot.tgz OK"
done
so_links "$dir.tmp"
is_complete "$dir.tmp" || { echo "openbsd-$rel: extracted, but libc.so or stdio.h is missing" >&2; exit 1; }
# Moved into place only when complete, so a run that fails halfway never leaves a directory the check above would accept.
rm -rf "$dir"
mv "$dir.tmp" "$dir"
echo "openbsd-$rel: sysroot ready in $dir"
