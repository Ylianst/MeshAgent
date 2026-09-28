#!/bin/bash
# Fetches an OpenBSD sysroot for cross-compiling the agent with clang on Linux: lib/, usr/lib and usr/include only.
# Usage: fetch-openbsd-sysroot.sh <release> <dir>, for example fetch-openbsd-sysroot.sh 7.9 "$RUNNER_TEMP/openbsd-7.9".
# A directory that already holds libc.so and stdio.h is kept, so a restored cache costs nothing.
set -euo pipefail

rel="$1"
dir="$2"

# OpenBSD ships no unversioned libNAME.so links and ld.lld does not do OpenBSD's version search.
# Without these links the linker silently takes the static .a for every -l and the binary has no PT_DYNAMIC.
so_links() {
    local f base
    for f in "$dir"/usr/lib/lib*.so.*.*; do
        [ -e "$f" ] || continue
        base="$(basename "$f" | sed -E 's/(\.so)\.[0-9]+\.[0-9]+$/\1/')"
        [ -e "$dir/usr/lib/$base" ] || ln -s "$(basename "$f")" "$dir/usr/lib/$base"
    done
}

if ls "$dir"/usr/lib/libc.so.* >/dev/null 2>&1 && [ -f "$dir/usr/include/stdio.h" ]; then
    so_links
    echo "openbsd-$rel: sysroot already present in $dir"
    exit 0
fi

# OpenBSD has no per-package base system, so the whole comp and base sets are streamed through tar and only the three sysroot paths are kept.
# The headers and crt objects are in comp<NN>.tgz, the shared libraries in base<NN>.tgz. Each set's sha256 is checked against the release's SHA256 file.
url="https://cdn.openbsd.org/pub/OpenBSD/$rel/amd64"
nodot="${rel//./}"
manifest="$(curl -sSL --fail --retry 3 "$url/SHA256")"
rm -rf "$dir"
mkdir -p "$dir"
for set in comp base; do
    want="$(echo "$manifest" | awk -v f="($set$nodot.tgz)" '$2 == f {print $4}')"
    [ -n "$want" ] || { echo "openbsd-$rel: $set$nodot.tgz is not in $url/SHA256" >&2; exit 1; }
    # GNU tar fails on a pattern that matches nothing, so each set gets only the paths it has. OpenBSD has no top-level /lib.
    paths='usr/lib/*'
    [ "$set" = comp ] && paths='usr/include/* usr/lib/*'
    sum="$(mktemp)"
    set -f
    curl -sSL --fail --retry 3 "$url/$set$nodot.tgz" | tee >(sha256sum | awk '{print $1}' > "$sum") \
        | tar xzf - -C "$dir" --wildcards --no-anchored $paths
    set +f
    # The hash is written by a process substitution, which can finish a moment after tar does.
    for i in $(seq 50); do [ -s "$sum" ] && break; sleep 0.1; done
    got="$(cat "$sum")"
    rm -f "$sum"
    [ "$got" = "$want" ] || { echo "openbsd-$rel: $set$nodot.tgz has sha256 $got, the manifest says $want" >&2; rm -rf "$dir"; exit 1; }
    echo "openbsd-$rel: $set$nodot.tgz OK"
done
so_links
ls "$dir"/usr/lib/libc.so.* >/dev/null 2>&1 && [ -f "$dir/usr/include/stdio.h" ] \
    || { echo "openbsd-$rel: extracted, but libc.so or stdio.h is missing" >&2; exit 1; }
echo "openbsd-$rel: sysroot ready in $dir"
