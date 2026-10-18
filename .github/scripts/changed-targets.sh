#!/bin/bash
# Decides which builds a push or pull request needs, from the list of files it changed.
# Prints one "<group>=true|false" line per group, and appends them to $GITHUB_OUTPUT when that is set.
# Without a usable base commit (first push of a branch, force push, manual or scheduled run) every group is true.
set -eu

base="${1:-}"
head="${2:-HEAD}"

# Sources every platform compiles. modules/ is not listed because the build only uses the copies embedded in microscript/ILibDuktape_Polyfills.c.
COMMON=(microstack/ microscript/ meshconsole/ meshcore/agentcore meshcore/meshinfo meshcore/meshdefines.h meshcore/zlib/ openssl/include/ .github/scripts/changed-targets.sh)

# What each group needs on top of COMMON. LINUX_KVM is only what the KVM builds need in addition to LINUX.
LINUX=(makefile openssl/libstatic/linux/ .github/workflows/linux-build.yml)
LINUX_KVM=(meshcore/KVM/Linux/ lib-jpeg-turbo/linux/ lib-jpeg-turbo/includes/)
FREEBSD=(makefile openssl/libstatic/bsd/freebsd_x86-64/ .github/workflows/freebsd-build.yml)
OPENBSD=(makefile openssl/1.1.1w/include/ openssl/1.1.1w/openbsd-x86_64/ .github/workflows/openbsd-build.yml .github/scripts/fetch-openbsd-sysroot.sh .github/scripts/openbsd-)
MAC=(makefile openssl/libstatic/macos/ lib-jpeg-turbo/macos/ lib-jpeg-turbo/includes/ meshcore/KVM/MacOS/ meshcore/KVM/Linux/linux_compression .github/workflows/mac-build.yml)
WINDOWS=(MeshAgent-2022.sln meshservice/ meshcore/KVM/Windows/ meshcore/wincrypto openssl/libstatic/lib .github/workflows/windows-build.yml)

# --no-renames lists a moved file under its old and its new path, so moving a file out of a watched folder still counts.
all=false
changed=""
if [ -z "$base" ] || [ "$base" = 0000000000000000000000000000000000000000 ] || ! changed="$(git diff --name-only --no-renames "$base" "$head" 2>/dev/null)"; then
    all=true
fi

# Prints true when any changed file starts with one of the given path prefixes.
hit() {
    [ "$all" = true ] && { echo true; return; }
    local f p
    while IFS= read -r f; do
        for p in "$@"; do
            case "$f" in "$p"*) echo true; return;; esac
        done
    done <<< "$changed"
    echo false
}

{
    echo "linux=$(hit "${COMMON[@]}" "${LINUX[@]}")"
    echo "linux_kvm=$(hit "${COMMON[@]}" "${LINUX[@]}" "${LINUX_KVM[@]}")"
    echo "freebsd=$(hit "${COMMON[@]}" "${FREEBSD[@]}")"
    echo "openbsd=$(hit "${COMMON[@]}" "${OPENBSD[@]}")"
    echo "mac=$(hit "${COMMON[@]}" "${MAC[@]}")"
    echo "windows=$(hit "${COMMON[@]}" "${WINDOWS[@]}")"
} | tee -a "${GITHUB_OUTPUT:-/dev/null}"
