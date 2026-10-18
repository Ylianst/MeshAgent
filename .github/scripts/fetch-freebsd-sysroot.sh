#!/bin/bash
# Fetches a FreeBSD sysroot for cross-compiling the agent with clang on Linux: lib, usr/lib and usr/include only.
# Usage: fetch-freebsd-sysroot.sh <release> <dir>, for example fetch-freebsd-sysroot.sh 15.1 "$RUNNER_TEMP/freebsd-sysroot".
# A directory that already holds the headers and the libraries libc.so names is kept, so a restored cache costs nothing.
# Needs the release's base.txz SHA256 in freebsd-base.sha256 next to this script, one '<release>  <sha256>  <file>' line per release.
set -euo pipefail

rel="$1"
dir="$2"
sums="$(cd "$(dirname "$0")" && pwd)/freebsd-base.sha256"
url="https://download.freebsd.org/releases/amd64/$rel-RELEASE"
# Releases past their EoL move here. It has no valid certificate, which is no problem because the archive is checked against the committed hash
# slow/often unavailable: archive="http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/$rel-RELEASE"
archive="http://ftp3.us.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/$rel-RELEASE"

# On GitHub Actions the ::error:: prefix turns the message into an annotation on the run summary
fail() { echo "${GITHUB_ACTIONS:+::error::}freebsd-$rel: $*"; exit 1; }

# usr/lib/libc.so is a linker script that names the real libc by absolute path, which ld.lld looks up inside the sysroot.
# Checking the paths it names keeps the soname out of this script, and a script that names no path counts as incomplete.
is_complete() {
    local f n=0
    [ -f "$1/usr/lib/libc.so" ] && [ -f "$1/usr/include/stdio.h" ] || return 1
    for f in $(sed -n 's/^GROUP *( *\(.*\) *)/\1/p' "$1/usr/lib/libc.so"); do
        [ -f "$1$f" ] || return 1
        n=$((n + 1))
    done
    [ "$n" -gt 0 ]
}

if is_complete "$dir"; then
    echo "freebsd-$rel: sysroot already present in $dir"
    exit 0
fi
line="$(awk -v r="$rel" '$1 == r && $3 == "base.txz" { print $2 "  " $3 }' "$sums")"
[ -n "$line" ] || fail "no base.txz line in $sums, add '$rel  <sha256>  base.txz' with the hash from $url/MANIFEST"

# FreeBSD signs no checksum of its distribution sets, and the MANIFEST next to them comes from the same CDN, so it proves nothing about the CDN.
# The SHA256 is therefore committed per release, and the set is checked against it before tar reads it.
work="$(mktemp -d)"
trap 'rm -rf "$work" "$dir.tmp"' EXIT
# A download that makes no connection in 3x5 s, drops below 50 kB/s for 30 s or runs past 4 minutes fails, so a stalled download does not hold the job.
fetch-archive() {
    echo "Downloading: $1/base.txz"
    curl -Ss --location --fail --retry 3 --connect-timeout 5 --speed-limit 50000 --speed-time 30 --max-time 240 "$1/base.txz" -o "$work/base.txz" 2> "$work/err"
}
rc=0
fetch-archive "$url" || rc=$?
if [ "$rc" != 0 ]; then
    echo "freebsd-$rel: download.freebsd.org failed ($(cat "$work/err")), trying archive"
    fetch-archive "$archive" || fail "archive failed ($(tr '\n' ' ' < "$work/err"))"
fi
(cd "$work" && echo "$line" | sha256sum -c --quiet) \
    || fail "base.txz does not match $sums"
rm -rf "$dir.tmp"
mkdir -p "$dir.tmp"
# Unlike OpenBSD, the headers, crt objects and libraries are all in base.txz.
# GNU tar does not know the SCHILY.fflags header FreeBSD writes, and would warn once for every file.
echo "Extracting base.txz"
tar xJf "$work/base.txz" -C "$dir.tmp" --warning=no-unknown-keyword --wildcards './lib/*' './usr/lib/*' './usr/include/*'
# Remove unnecessary static archives and clang util for smaller cached archive
find "$dir.tmp" -name '*.a' ! -name libc_nonshared.a ! -name libssp_nonshared.a ! -name libgcc.a ! -name libcompiler_rt.a ! -name libgcc_eh.a -delete
rm -rf "$dir.tmp/usr/lib/clang" "$dir.tmp"/usr/lib/libprivate*
rm -f "$work/base.txz"
echo "freebsd-$rel: base.txz OK"
is_complete "$dir.tmp" || fail "extracted, but stdio.h, libc.so or a library it names is missing"
# Moved into place only when complete, so a run that fails halfway never leaves a directory the check above would accept.
rm -rf "$dir"
mv "$dir.tmp" "$dir"
echo "freebsd-$rel: sysroot ready in $dir"
