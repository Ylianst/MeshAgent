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
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// The "are we running under Wayland" detection is made more complicated by the fact that
// meshagent is usually running as a root daemon. If simply running in the context of a
// regular user in a desktop session, then you could just check one or two environment
// variables.

// Retain the last proven Wayland mode only while logind cannot provide an active seat0 session.
// An authoritative X11 greeter/session must still select X11, while a transient handover gap must
// not fall back to the root service's unrelated environment.
static int g_kvmWaylandSticky = 0;

static int kvm_read_systemd_value(const char *path, const char *key, char *value, size_t valueLen)
{
	FILE *f = NULL;
	char line[512];
	size_t keyLen = 0;

	if (path == NULL || key == NULL || value == NULL || valueLen == 0) { return 0; }
	f = fopen(path, "r");
	if (f == NULL) { return 0; }
	keyLen = strlen(key);
	while (fgets(line, sizeof(line), f) != NULL)
	{
		if (strncmp(line, key, keyLen) == 0)
		{
			char *tmp = line + keyLen;
			tmp[strcspn(tmp, "\r\n")] = 0;
			snprintf(value, valueLen, "%s", tmp);
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

typedef int (*kvm_sd_seat_get_active_fn)(const char *seat, char **session, uid_t *uid);
typedef int (*kvm_sd_session_get_string_fn)(const char *session, char **value);

typedef struct kvm_sd_login_exports
{
	void *library;
	kvm_sd_seat_get_active_fn seat_get_active;
	kvm_sd_session_get_string_fn session_get_type;
	kvm_sd_session_get_string_fn session_get_state;
} kvm_sd_login_exports;

static kvm_sd_login_exports g_kvmSdLogin = {0};
static int g_kvmSdLoginAttempted = 0;

static int kvm_wayland_valid_session_id(const char *id)
{
	size_t i;
	if (id == NULL || id[0] == 0 || strlen(id) >= sizeof(((kvm_wayland_console_session *)0)->id)) { return 0; }
	for (i = 0; id[i] != 0; ++i)
	{
		unsigned char ch = (unsigned char)id[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-')) { return 0; }
	}
	return 1;
}

static int kvm_wayland_load_sd_login(void)
{
	void *h;
	if (g_kvmSdLoginAttempted) { return g_kvmSdLogin.library != NULL; }
	g_kvmSdLoginAttempted = 1;
	h = dlopen("libsystemd.so.0", RTLD_NOW | RTLD_LOCAL);
	if (h == NULL) { return 0; }
	g_kvmSdLogin.seat_get_active = (kvm_sd_seat_get_active_fn)dlsym(h, "sd_seat_get_active");
	g_kvmSdLogin.session_get_type = (kvm_sd_session_get_string_fn)dlsym(h, "sd_session_get_type");
	g_kvmSdLogin.session_get_state = (kvm_sd_session_get_string_fn)dlsym(h, "sd_session_get_state");
	if (g_kvmSdLogin.seat_get_active == NULL || g_kvmSdLogin.session_get_type == NULL ||
		g_kvmSdLogin.session_get_state == NULL)
	{
		dlclose(h);
		memset(&g_kvmSdLogin, 0, sizeof(g_kvmSdLogin));
		return 0;
	}
	g_kvmSdLogin.library = h;
	return 1;
}

static int kvm_wayland_read_console_session_sd_login(kvm_wayland_console_session *session)
{
	char *id = NULL;
	char *type = NULL;
	char *state = NULL;
	uid_t uid = (uid_t)-1;
	int ok = 0;

	if (session == NULL || !kvm_wayland_load_sd_login()) { return 0; }
	if (g_kvmSdLogin.seat_get_active("seat0", &id, &uid) < 0 || !kvm_wayland_valid_session_id(id)) { goto cleanup; }
	if ((uint64_t)uid > (uint64_t)INT_MAX) { goto cleanup; }
	if (g_kvmSdLogin.session_get_type(id, &type) < 0 || type == NULL || type[0] == 0) { goto cleanup; }
	if (g_kvmSdLogin.session_get_state(id, &state) < 0 || state == NULL || state[0] == 0) { goto cleanup; }

	memset(session, 0, sizeof(*session));
	snprintf(session->id, sizeof(session->id), "%s", id);
	session->uid = (int)uid;
	snprintf(session->type, sizeof(session->type), "%s", type);
	snprintf(session->state, sizeof(session->state), "%s", state);
	ok = 1;

cleanup:
	free(id);
	free(type);
	free(state);
	return ok;
}

int kvm_wayland_read_console_session_files(const char *runRoot, kvm_wayland_console_session *session)
{
	char activeSession[64];
	char uidStr[32];
	char seatPath[PATH_MAX];
	char sessionPath[PATH_MAX];
	char *end = NULL;
	long uid;
	int len;

	if (runRoot == NULL || runRoot[0] != '/' || session == NULL) { return 0; }
	memset(session, 0, sizeof(*session));
	session->uid = -1;
	memset(activeSession, 0, sizeof(activeSession));
	len = snprintf(seatPath, sizeof(seatPath), "%s/systemd/seats/seat0", runRoot);
	if (len <= 0 || len >= (int)sizeof(seatPath)) { return 0; }
	if (!kvm_read_systemd_value(seatPath, "ACTIVE=", activeSession, sizeof(activeSession)) ||
		!kvm_wayland_valid_session_id(activeSession)) { return 0; }

	len = snprintf(sessionPath, sizeof(sessionPath), "%s/systemd/sessions/%s", runRoot, activeSession);
	if (len <= 0 || len >= (int)sizeof(sessionPath)) { return 0; }
	if (!kvm_read_systemd_value(sessionPath, "UID=", uidStr, sizeof(uidStr))) { return 0; }
	errno = 0;
	uid = strtol(uidStr, &end, 10);
	if (errno != 0 || end == uidStr || *end != 0 || uid < 0 || uid > INT_MAX) { return 0; }
	if (!kvm_read_systemd_value(sessionPath, "TYPE=", session->type, sizeof(session->type))) { return 0; }
	if (!kvm_read_systemd_value(sessionPath, "STATE=", session->state, sizeof(session->state)))
	{
		// Older logind runtime files do not always carry STATE. The active seat binding still
		// provides a usable session identity; mark the missing field explicitly.
		snprintf(session->state, sizeof(session->state), "unknown");
	}
	snprintf(session->id, sizeof(session->id), "%s", activeSession);
	session->uid = (int)uid;
	return 1;
}

int kvm_wayland_active_console_session(kvm_wayland_console_session *session)
{
	if (session == NULL) { return 0; }
	if (kvm_wayland_read_console_session_sd_login(session)) { return 1; }
	return kvm_wayland_read_console_session_files("/run", session);
}

int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a,
	const kvm_wayland_console_session *b)
{
	if (a == NULL || b == NULL) { return 0; }
	return a->uid == b->uid && strcmp(a->id, b->id) == 0 && strcasecmp(a->type, b->type) == 0;
}

// Uid of seat0's active logind session, greeter sessions included; -1 when unknown. The JS-side
// consoleUid() only reports sessions with uid >= the login floor, so at a display-manager greeter
// the master hands the capture child uid 0 — this recovers the real (system-uid) session owner.
int kvm_wayland_active_console_uid(void)
{
	kvm_wayland_console_session session;
	return kvm_wayland_active_console_session(&session) ? session.uid : -1;
}

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

// Pop!_OS/Fedora COSMIC's stock PAM greeter reports TYPE=tty. Only its validated logind
// greeter role may use this exception; an ordinary tty retains its old path.
static int kvm_wayland_cosmic_greeter_role(const char *runRoot,
    const kvm_wayland_console_session *session)
{
    char path[PATH_MAX], role[32], service[64];
    if (!runRoot || runRoot[0] != '/' || !session || session->uid <= 0 ||
        strcmp(session->type, "tty") != 0 || !kvm_wayland_valid_session_id(session->id) ||
        snprintf(path, sizeof(path), "%s/systemd/sessions/%s", runRoot, session->id) >= (int)sizeof(path)) { return 0; }
    return kvm_read_systemd_value(path, "CLASS=", role, sizeof(role)) && !strcmp(role, "greeter") &&
        kvm_read_systemd_value(path, "SERVICE=", service, sizeof(service)) && !strcmp(service, "cosmic-greeter");
}

static int kvm_wayland_owned_console_socket(int uid)
{
    char root[64], path[96];
    struct stat st;
    snprintf(root, sizeof(root), "/run/user/%d", uid);
    if (lstat(root, &st) || !S_ISDIR(st.st_mode) || st.st_uid != (uid_t)uid || (st.st_mode & 0077)) { return 0; }
    for (int n = 0; n < 2; ++n)
    {
        snprintf(path, sizeof(path), "%s/wayland-%d", root, n);
        if (!lstat(path, &st) && S_ISSOCK(st.st_mode) && st.st_uid == (uid_t)uid) { return 1; }
    }
    return 0;
}

int kvm_is_wayland_session_for_uid(int uid)
{
	kvm_wayland_console_session activeSession;
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

	if (kvm_wayland_active_console_session(&activeSession))
	{
		if (strcasecmp(activeSession.type, "wayland") == 0)
		{
			g_kvmWaylandSticky = 1;
			return 1;
		}
		if (strcasecmp(activeSession.type, "x11") == 0) { return 0; }
        if (kvm_wayland_cosmic_greeter_role("/run", &activeSession) &&
            kvm_wayland_owned_console_socket(activeSession.uid))
        {
            g_kvmWaylandSticky = 1;
            return 1;
        }
	}

	// Environment detection is only valid for an agent running in that same user's context. A root
	// service can inherit DISPLAY/WAYLAND_DISPLAY from an administrator and must not bind to it.
	if ((int)geteuid() == fallbackUid &&
		((sessionType != NULL && strcasecmp(sessionType, "wayland") == 0) ||
		(waylandDisplay != NULL && waylandDisplay[0] != 0)))
	{
		g_kvmWaylandSticky = 1;
		return 1;
	}

	if ((int)geteuid() == fallbackUid && runtimeDir != NULL)
	{
		if (waylandDisplay != NULL && kvm_wayland_socket_exists(runtimeDir, waylandDisplay)) { g_kvmWaylandSticky = 1; return 1; }
		if (kvm_wayland_socket_exists(runtimeDir, "wayland-0") || kvm_wayland_socket_exists(runtimeDir, "wayland-1")) { g_kvmWaylandSticky = 1; return 1; }
	}

	len = snprintf(fallbackRuntimeDir, sizeof(fallbackRuntimeDir), "/run/user/%d", fallbackUid);
	if (len > 0 && len < (int)sizeof(fallbackRuntimeDir))
	{
		if ((int)geteuid() == fallbackUid && waylandDisplay != NULL &&
			kvm_wayland_socket_exists(fallbackRuntimeDir, waylandDisplay)) { g_kvmWaylandSticky = 1; return 1; }
		if (kvm_wayland_socket_exists(fallbackRuntimeDir, "wayland-0") || kvm_wayland_socket_exists(fallbackRuntimeDir, "wayland-1")) { g_kvmWaylandSticky = 1; return 1; }
	}

	return g_kvmWaylandSticky != 0 ? 1 : 0;
}

kvm_screenreader_mode_t kvm_screenreader_mode()
{
	return kvm_screenreader_mode_for_uid(-1);
}

kvm_screenreader_mode_t kvm_screenreader_mode_for_uid(int uid)
{
	// stderr, not stdout: the service nulls stdout, and the picked backend is the first clue when a screen comes up black.
	if (kvm_is_wayland_session_for_uid(uid))
	{
		fprintf(stderr, "Using DRM/libevdev mode\n"); fflush(stderr);
		return KVM_SCREENREADER_MODE_DRM;
	}

	fprintf(stderr, "Using X11 mode\n"); fflush(stderr);
	return KVM_SCREENREADER_MODE_X11;
}
