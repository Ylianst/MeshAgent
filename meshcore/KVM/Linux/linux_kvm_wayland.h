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

#ifndef LINUX_KVM_WAYLAND_H_
#define LINUX_KVM_WAYLAND_H_

typedef struct kvm_wayland_console_session
{
	char id[64];
	int uid;
	char type[32];
	char state[32];
} kvm_wayland_console_session;

typedef enum kvm_screenreader_mode_t
{
	KVM_SCREENREADER_MODE_X11 = 0,
	KVM_SCREENREADER_MODE_DRM = 1
} kvm_screenreader_mode_t;

kvm_screenreader_mode_t kvm_screenreader_mode();
kvm_screenreader_mode_t kvm_screenreader_mode_for_uid(int uid);
int kvm_is_wayland_session_for_uid(int uid);

// Snapshot seat0's active logind session. The session id, not just the uid, identifies the
// incarnation and lets capture retire state across same-user logout/login or compositor restart.
// Uses libsystemd's supported sd-login interface when present, with a bounded /run fallback for
// installations where MeshAgent must remain independent of libsystemd.
int kvm_wayland_active_console_session(kvm_wayland_console_session *session);

// Returns nonzero only when both snapshots identify the same console incarnation and type.
int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a,
	const kvm_wayland_console_session *b);

// Read the active console session through the file-backed fallback; runRoot is normally "/run".
int kvm_wayland_read_console_session_files(const char *runRoot, kvm_wayland_console_session *session);

// Uid of seat0's active logind session (greeters included); -1 when unknown. Lets the DRM capture
// child recover the session owner when the master could only pass uid 0 (display-manager greeter).
int kvm_wayland_active_console_uid(void);

#endif
