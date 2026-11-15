/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_KVM_GALA_H
#define MESH_KVM_GALA_H
#include <stdint.h>
#include "linux_kvm_wayland.h"
typedef struct {kvm_wayland_console_session session;int pid;char display[64];} kvm_gala_target;
/* Discovery only: requires one trusted Gala Wayland peer in the active seat0
 * session. Multiple eligible peers are ambiguous, not a reason to pick one. */
int kvm_gala_find_target(kvm_gala_target *target);
/* Root capture-child preparation: authenticate the endpoint without reading
 * replies. Normal input calls occur only after the worker's UID/capability
 * drop. Preparation never edits Gala's plugin or session configuration. */
int kvm_gala_prepare(const kvm_wayland_console_session *session);
/* Out-of-layout text only. 0 = absent/explicit pre-injection refusal,
 * 1 = acknowledged, -1 = invalid/uncertain; never replay -1 through uinput.
 * Mapped keys, shortcuts, X11 and XWayland keep their established routes. */
int kvm_gala_type_unicode(uint32_t cp);
/* Short-lived status probe; does not leave an input connection prepared. */
int kvm_gala_available(void);
/* Close and forget this session's endpoint, epoch and failure latch. */
void kvm_gala_shutdown(void);
#endif
