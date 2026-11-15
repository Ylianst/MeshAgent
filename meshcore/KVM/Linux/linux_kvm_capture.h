/*
Copyright 2010 - 2011 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef LINUX_KVM_CAPTURE_H_
#define LINUX_KVM_CAPTURE_H_

#include <stddef.h>
#include <stdint.h>

// Capture allocations are bounded independently of untrusted/changing DRM metadata.
#define KVM_CAPTURE_MAX_DIMENSION 32768u
#define KVM_CAPTURE_MAX_BUFFER_BYTES (512u * 1024u * 1024u)

typedef enum kvm_capture_state
{
	KVM_CAPTURE_STATE_DETACHED = 0,
	KVM_CAPTURE_STATE_DISCOVERING,
	KVM_CAPTURE_STATE_CAPTURING,
	KVM_CAPTURE_STATE_SUSPENDED,
	KVM_CAPTURE_STATE_RECOVERING,
	KVM_CAPTURE_STATE_FAILED
} kvm_capture_state;

const char *kvm_capture_state_name(kvm_capture_state state);

int kvm_capture_checked_rgb_size(uint32_t width, uint32_t height, size_t *size_out);
// Copy a validated linear device mapping while the caller holds CPU access.
// Uses streaming loads where supported; other CPUs retain memcpy.
void kvm_capture_copy_linear(void *dst, const void *src, size_t length);
// Convert a validated, non-overlapping ordinary-RAM row; channel indices are
// byte positions in each four-byte source pixel. No device mapping is read here.
void kvm_capture_rgb32_row(unsigned char *dst, const unsigned char *src, size_t pixels,
    unsigned red, unsigned green, unsigned blue);
int kvm_capture_checked_pixel_size(uint32_t width, uint32_t height, uint32_t bytes_per_pixel,
	size_t *size_out);
int kvm_capture_checked_map_size(uint32_t offset, uint32_t pitch, uint32_t height, size_t *size_out);
int kvm_capture_checked_layout_size(int64_t min_x, int64_t min_y, int64_t max_x, int64_t max_y,
	uint32_t *width_out, uint32_t *height_out);

// The current DRM converter can publish exactly one complete non-cursor image plane per CRTC.
int kvm_capture_plane_topology_supported(int image_planes, int unknown_active_planes);

// Retry the existing display-wake action only during confirmed, complete display inactivity.
// The short grace filters scanout transitions; retries stop after ten seconds.
int kvm_capture_wake_due(uint64_t inactive_since_ms, uint64_t now_ms, uint64_t *last_wake_ms,
    int all_outputs_inactive, int input_available, int session_confirmed);

// Time only continuous hard capture failure, excluding ordinary display suspension.
// Call with hard_failure == 0 on a complete frame or a suspended-only iteration.
// Keep the separate overall outage/session timers running across these transitions.
int kvm_capture_failure_due(uint64_t *hard_since_ms, uint64_t now_ms,
    int hard_failure, uint64_t retry_ms);

uint32_t kvm_capture_source_coordinate(uint32_t coordinate, uint32_t source, uint32_t output);
int kvm_capture_scaled_size(uint32_t width, uint32_t height, int factor, uint32_t *out_width, uint32_t *out_height);
void kvm_capture_scale_rgb(const unsigned char *src, uint32_t width, uint32_t height, unsigned char *dst, uint32_t out_width, uint32_t out_height);
#endif
