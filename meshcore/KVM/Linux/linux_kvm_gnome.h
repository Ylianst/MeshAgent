/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LINUX_KVM_GNOME_H_
#define LINUX_KVM_GNOME_H_
#include <stdint.h>
#include <stddef.h>
#include "linux_kvm_wayland.h"
#define KVM_GNOME_HEADER_SIZE 60
#define KVM_GNOME_MAX_MONITORS 16
#define KVM_GNOME_MAX_PIXELS 16777216u
#define KVM_GNOME_MAX_PAYLOAD 16777216u
typedef struct kvm_gnome_monitor { int32_t x, y; uint32_t width, height; } kvm_gnome_monitor;
typedef struct kvm_gnome_reply
{
    uint32_t op, result, revision, flags, width, height, count, payload_size;
    unsigned char epoch[16];
    kvm_gnome_monitor monitors[KVM_GNOME_MAX_MONITORS];
} kvm_gnome_reply;
/* Connect and authenticate without reading user-controlled bytes while root.
 * Returns 1 for a prepared endpoint; 0 when absent/untrusted. No global fallback
 * is permitted after activate() starts receiving compositor data. */
int kvm_gnome_prepare(const kvm_wayland_console_session *session);
/* Metadata-only availability probe for a worker that started before Shell.
 * Reads no replies and changes no module state. A positive result requires a
 * fresh root worker, full authentication and privilege drop before activation. */
int kvm_gnome_endpoint_available(const kvm_wayland_console_session *session);
/* Caller must first drop all UID/GID identities, capabilities, and set NNP. */
int kvm_gnome_activate(kvm_gnome_reply *status);
/* Prepared root worker only. On failure the caller must exit, never fall back. */
int kvm_gnome_drop_and_activate(kvm_gnome_reply *status);
/* 0: unavailable/no text attempted, 1: reply received, -1: discard/no retry. */
int kvm_gnome_type_unicode(uint32_t codepoint);
/* 0: not offered, 1: acknowledged, -1: discard/no fallback or replay. */
int kvm_gnome_key_action(uint32_t evdev_code, int value);
/* Newer Shells without the qualified compositor-key API use paced uinput. */
int kvm_gnome_uses_uinput_keys(void);
/* 0: failed, 1: RGB frame, 2: authoritative inactive/unknown power state.
 * RGB pixels are owned by this module until the next frame or shutdown. */
int kvm_gnome_frame(const unsigned char **rgb, uint32_t *width, uint32_t *height,
    kvm_gnome_reply *layout);
void kvm_gnome_shutdown(void);
/* Bounded protocol decoder, also used by the native regression harness. */
int kvm_gnome_decode_header(const unsigned char *data, size_t size, kvm_gnome_reply *out);
int kvm_gnome_process_identity_matches(const kvm_wayland_console_session *session,
    const char *cgroup, const char *cmdline, size_t cmdline_size);
#endif
