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

#ifndef LINUX_KVM_DRM_H_
#define LINUX_KVM_DRM_H_

#include <stddef.h>

// The DRM screen capture system uses the Linux DRM (Direct Rendering Manager) subsystem to capture the screen.
// This is used when running under Wayland, as a catch-all mechanism that operates at a lower level than
// the screen compositor.

extern int g_kvmBackendDRM;

void* kvm_server_mainloop_drm(void* parm);

// Reaches libdrm's drmPrimeHandleToFD via the single dlopen in linux_kvm_drm.c.
int kvm_drm_prime_handle_to_fd(int fd, unsigned int handle, unsigned int flags, int *prime_fd);

// Render-node path for a card fd (libdrm via the same dlopen). Returns 0 if unavailable.
int kvm_drm_render_node_for_fd(int fd, char *out, size_t out_len);

#endif
