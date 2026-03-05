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

#include "linux_kvm_wayland.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

// The "are we running under Wayland" detection is made more complicated by the fact that
// meshagent is usually running as a root daemon. If simply running in the context of a
// regular user in a desktop session, then you could just check one or two environment
// variables.

static int kvm_wayland_socket_exists(const char *runtimeDir, const char *socketName)
{
	char socketPath[PATH_MAX];
	struct stat st;
	int len = 0;

	if (runtimeDir == NULL || runtimeDir[0] == 0 || socketName == NULL || socketName[0] == 0) { return 0; }
	len = snprintf(socketPath, sizeof(socketPath), "%s/%s", runtimeDir, socketName);
	if (len <= 0 || len >= (int)sizeof(socketPath)) { return 0; }
	if (stat(socketPath, &st) != 0) { return 0; }
	return S_ISSOCK(st.st_mode) ? 1 : 0;
}

int kvm_is_wayland_session_for_uid(int uid)
{
	char *sessionType = getenv("XDG_SESSION_TYPE");
	char *waylandDisplay = getenv("WAYLAND_DISPLAY");
	char *runtimeDir = getenv("XDG_RUNTIME_DIR");
	char fallbackRuntimeDir[64];
	int len = 0;
	int fallbackUid = uid;

	if (fallbackUid < 0)
	{
		fallbackUid = (int)getuid();
	}

	if ((sessionType != NULL && strcasecmp(sessionType, "wayland") == 0) ||
		(waylandDisplay != NULL && waylandDisplay[0] != 0))
	{
		return 1;
	}

	if (runtimeDir != NULL)
	{
		if (waylandDisplay != NULL && kvm_wayland_socket_exists(runtimeDir, waylandDisplay)) { return 1; }
		if (kvm_wayland_socket_exists(runtimeDir, "wayland-0") || kvm_wayland_socket_exists(runtimeDir, "wayland-1")) { return 1; }
	}

	len = snprintf(fallbackRuntimeDir, sizeof(fallbackRuntimeDir), "/run/user/%d", fallbackUid);
	if (len > 0 && len < (int)sizeof(fallbackRuntimeDir))
	{
		if (waylandDisplay != NULL && kvm_wayland_socket_exists(fallbackRuntimeDir, waylandDisplay)) { return 1; }
		if (kvm_wayland_socket_exists(fallbackRuntimeDir, "wayland-0") || kvm_wayland_socket_exists(fallbackRuntimeDir, "wayland-1")) { return 1; }
	}

	return 0;
}

kvm_screenreader_mode_t kvm_screenreader_mode()
{
	return kvm_screenreader_mode_for_uid(-1);
}

kvm_screenreader_mode_t kvm_screenreader_mode_for_uid(int uid)
{
	if (kvm_is_wayland_session_for_uid(uid))
	{
		printf("Using DRM/libevdev mode\n");
		return KVM_SCREENREADER_MODE_DRM;
	}
	
	printf("Using X11 mode\n");
	return KVM_SCREENREADER_MODE_X11;
}
