/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LINUX_KVM_PIPEWIRE_H
#define LINUX_KVM_PIPEWIRE_H

#include <stdint.h>

typedef struct kvm_pipewire_capture kvm_pipewire_capture;
typedef struct kvm_pipewire_stream kvm_pipewire_stream;

/* Checks installed symbols and the current user's socket without initializing
 * PipeWire configuration/plugins. Does not authorize a compositor stream. */
int kvm_pipewire_capture_available(void);

/* Optional, dynamically loaded PipeWire consumer. The caller must first drop
 * root and ALL permitted/effective/inheritable capabilities and saved root IDs.
 * Session-owned configuration/plugin overrides are excluded; this worker sets
 * no-new-privileges and uses the installed vendor PipeWire configuration.
 * One capture owns one loop/core and all its streams. Calls stay on one thread.
 * The caller owns compositor authorization, output identity and session checks.
 */
kvm_pipewire_capture *kvm_pipewire_capture_new(void);
kvm_pipewire_stream *kvm_pipewire_capture_add(kvm_pipewire_capture *capture, uint64_t serial);
/* Nonblocking event dispatch; 1 healthy, -1 terminal failure. */
int kvm_pipewire_capture_pump(kvm_pipewire_capture *capture);
/* RGB24, already in compositor orientation. Valid until next pump/destroy.
 * 1 complete frame, 0 waiting/paused, -1 failure. Never returns a stale frame
 * after pause, disconnect, malformed input or format renegotiation.
 */
int kvm_pipewire_capture_frame(kvm_pipewire_stream *stream, const unsigned char **rgb,
    uint32_t *width, uint32_t *height);
/* After an externally observed output wake, require a new buffer within the
 * normal bounded first-frame timeout. Does not disconnect or reauthorize. */
uint64_t kvm_pipewire_capture_revision(kvm_pipewire_stream *stream);
void kvm_pipewire_capture_discard_frame(kvm_pipewire_stream *stream);
void kvm_pipewire_capture_destroy(kvm_pipewire_capture *capture);

#endif
