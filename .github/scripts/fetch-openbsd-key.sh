#!/bin/bash
# Gets the signify base public key of an OpenBSD release through a chain of signed base sets.
# Usage: fetch-openbsd-key.sh <release> [<keys-file>], for example fetch-openbsd-key.sh 8.0 .github/scripts/openbsd-base.pub
# With a keys file, the release's '<NN>  <pubkey>' line is added to it or replaces the old one. Without, the line is printed.
# The chain starts at the newest key at or below the release, taken from the distro's signify-openbsd-keys package
# (which apt already trusts) or from openbsd-base.pub next to this script. Every base<NN>.tgz ships the next
# release's key in etc/signify/, and each set is checked against its signed SHA256.sig before the key is taken from
# it, so nothing from the CDN is trusted unverified. Each hop downloads about 300 MB. Ubuntu 24.04 ships keys up to 7.6.
# Needs signify-openbsd. SIGNIFY_KEYS overrides the package's key directory.
set -euo pipefail


rel="$1"
out="${2:-}"
keydir="${SIGNIFY_KEYS:-/usr/share/signify-openbsd-keys}"
here="$(cd "$(dirname "$0")" && pwd)"
target="${rel//./}"
[[ "$rel" =~ ^[0-9]+\.[0-9]$ ]] || { echo "openbsd-$rel: expected a release like 7.9" >&2; exit 1; }
command -v signify-openbsd >/dev/null || { echo "openbsd-$rel: signify-openbsd not found, install the signify-openbsd package" >&2; exit 1; }

# OpenBSD counts 7.8, 7.9, 8.0, so the release after x.9 is (x+1).0
next_rel() {
    local maj="${1%.*}" min="${1#*.}"
    if [ "$min" = 9 ]; then echo "$((maj + 1)).0"; else echo "$maj.$((min + 1))"; fi
}
rel_of() { echo "${1:0:1}.${1:1}"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Each line of openbsd-base.pub becomes a key file in $work, because signify only reads a file whose first line is the untrusted comment
mkdir -p "$work/committed"
if [ -f "$here/openbsd-base.pub" ]; then
    while read -r n pk; do
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        printf 'untrusted comment: openbsd %s base public key\n%s\n' "$(rel_of "$n")" "$pk" > "$work/committed/openbsd-$n-base.pub"
    done < "$here/openbsd-base.pub"
fi

# The newest key at or below the target is the shortest chain
start=""
startkey=""
for k in "$keydir"/openbsd-*-base.pub "$work"/committed/openbsd-*-base.pub; do
    [ -e "$k" ] || continue
    n="$(basename "$k")"
    n="${n#openbsd-}"
    n="${n%-base.pub}"
    [[ "$n" =~ ^[0-9]+$ ]] || continue
    [ "$n" -le "$target" ] || continue
    if [ -z "$start" ] || [ "$n" -gt "$start" ]; then
        start="$n"
        startkey="$k"
    fi
done
[ -n "$startkey" ] || { echo "openbsd-$rel: no base key at or below $rel in $keydir or $here/openbsd-base.pub, install signify-openbsd-keys" >&2; exit 1; }
echo "openbsd-$rel: chain starts at the $(rel_of "$start") key from $(dirname "$startkey" | sed "s|$work/committed|$here/openbsd-base.pub|")" >&2

key="$startkey"
cur="$start"
while [ "$cur" -lt "$target" ]; do
    r="$(rel_of "$cur")"
    nxt="$(next_rel "$r")"
    nxtn="${nxt//./}"
    url="https://cdn.openbsd.org/pub/OpenBSD/$r/amd64"
    echo "openbsd-$rel: fetching base$cur.tgz to take the $nxt key from it" >&2
    curl -sSL --fail --retry 3 "$url/SHA256.sig" -o "$work/SHA256.sig"
    curl -sSL --fail --retry 3 "$url/base$cur.tgz" -o "$work/base$cur.tgz"
    (cd "$work" && signify-openbsd -C -q -p "$key" -x SHA256.sig "base$cur.tgz") \
        || { echo "openbsd-$r: base$cur.tgz does not match the signed SHA256.sig" >&2; exit 1; }
    tar xzf "$work/base$cur.tgz" -C "$work" "./etc/signify/openbsd-$nxtn-base.pub"
    rm -f "$work/base$cur.tgz"
    key="$work/etc/signify/openbsd-$nxtn-base.pub"
    cur="$nxtn"
done

line="$target  $(sed -n 2p "$key")"
if [ -n "$out" ]; then
    # Replaces an existing line for the release, and keeps the file sorted by release
    { [ -f "$out" ] && awk -v r="$target" '$1 != r' "$out"; echo "$line"; } | sort -n > "$work/keys"
    cp "$work/keys" "$out"
    echo "openbsd-$rel: key line written to $out" >&2
else
    echo "$line"
fi
