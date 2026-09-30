#!/usr/bin/env bash
# Verifies the microphone consent gate in meshcore/KVM/Linux/linux_mic.c.
#
# The gate is what stops a remote operator being played through a device's
# speakers without the local user agreeing, so it is worth asserting directly
# rather than trusting that the callers always ask first. The real
# implementation is compiled against stub Opus and PulseAudio so the test needs
# no sound hardware and can run anywhere.
#
# Usage: test/mic/run.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -r "$here/stub/"* "$work/"
cp "$here/test_consent_gate.c" "$work/"
cp "$root/meshcore/KVM/kvm_mic.h" "$work/meshcore/KVM/"

cd "$work"
# linux_mic.c dlopens libpulse-simple, so provide a stand-in.
gcc -shared -fPIC -o libpulse-simple.so.0 fakepulse.c
gcc -std=gnu99 -Wall -D_KVM_AUDIO -I. \
    -o consent_gate test_consent_gate.c stubs.c \
    "$root/meshcore/KVM/Linux/linux_mic.c" \
    -lpthread -ldl

LD_LIBRARY_PATH="$work" PULSE_SERVER=dummy ./consent_gate
