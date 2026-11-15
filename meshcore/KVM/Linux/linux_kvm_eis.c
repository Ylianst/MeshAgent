/* SPDX-License-Identifier: Apache-2.0 */
/* KWin input adapter: libei/EIS provides the virtual device and keymap, while
 * the optional Agent input-method relay supplies ordered text/key requests.
 * These are separate completion boundaries; an EIS pong alone does not prove
 * that KWin and its stock input method have processed a shortcut.
 *
 * Keep the native-endian local protocol in sync with wire_bridge.py. Neither
 * the EIS API nor the relay uses a distro/RPM version allowlist. See the bridge
 * README and docs/Wayland-Maintenance.md before changing routing or barriers.
 */
#include "linux_kvm_eis.h"
#if defined(__linux__)
#include "linux_kvm_wayland.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "linux_kvm_bridge_auth.h"
#ifndef KVM_BRIDGE_SERVER_AUTH
#define KVM_BRIDGE_SERVER_AUTH kvm_bridge_server
#endif
#ifndef KVM_EIS_RUNTIME_ROOT
#define KVM_EIS_RUNTIME_ROOT "/run/user"
#endif

/* Optional stock libei and sd-bus ABIs; no link-time or build-host dependency.
 * KWin's RemoteDesktop owner and runtime capabilities are authenticated before
 * use. The agent never creates a portal session or changes desktop policy.
 */
struct ei_keymap; struct ei; struct ei_event; struct ei_seat; struct ei_device; struct ei_ping;
struct sd_bus; struct sd_bus_message; struct sd_bus_error;
#define EI_TEXT 64
#define EI_KEYBOARD 4
#define EIS_MAX_KEY 0x2ffu
#define EIS_TIMEOUT_MS 250
#define EIS_RETRY_MS 10000
#define EIS_API(_) \
 _(struct ei *, ei_new_sender, (void *)) \
 _(struct ei *, ei_unref, (struct ei *)) \
 _(void, ei_configure_name, (struct ei *, const char *)) \
 _(int, ei_setup_backend_fd, (struct ei *, int)) \
 _(int, ei_get_fd, (struct ei *)) \
 _(void, ei_dispatch, (struct ei *)) \
 _(struct ei_event *, ei_get_event, (struct ei *)) \
 _(struct ei_event *, ei_event_unref, (struct ei_event *)) \
 _(int, ei_event_get_type, (struct ei_event *)) \
 _(struct ei_seat *, ei_event_get_seat, (struct ei_event *)) \
 _(bool, ei_seat_has_capability, (struct ei_seat *, int)) \
 _(void, ei_seat_bind_capabilities, (struct ei_seat *, ...)) \
 _(struct ei_device *, ei_event_get_device, (struct ei_event *)) \
 _(bool, ei_device_has_capability, (struct ei_device *, int)) \
 _(struct ei_device *, ei_device_ref, (struct ei_device *)) \
 _(struct ei_device *, ei_device_unref, (struct ei_device *)) \
 _(void, ei_device_close, (struct ei_device *)) \
 _(void, ei_device_start_emulating, (struct ei_device *, uint32_t)) \
 _(void, ei_device_stop_emulating, (struct ei_device *)) \
 _(void, ei_device_frame, (struct ei_device *, uint64_t)) \
 _(void, ei_device_keyboard_key, (struct ei_device *, uint32_t, bool)) \
 _(uint64_t, ei_now, (struct ei *)) \
 _(struct ei_ping *, ei_new_ping, (struct ei *)) \
 _(void, ei_ping, (struct ei_ping *)) \
 _(struct ei_ping *, ei_ping_unref, (struct ei_ping *)) \
 _(struct ei_ping *, ei_event_pong_get_ping, (struct ei_event *)) \
 _(uint32_t, ei_event_keyboard_get_xkb_mods_depressed, (struct ei_event *)) \
 _(uint32_t, ei_event_keyboard_get_xkb_mods_latched, (struct ei_event *)) \
 _(uint32_t, ei_event_keyboard_get_xkb_mods_locked, (struct ei_event *)) \
 _(uint32_t, ei_event_keyboard_get_xkb_group, (struct ei_event *))
#define EIS_KEYMAP_API(_) \
 _(struct ei_keymap *, ei_device_keyboard_get_keymap, (struct ei_device *)) \
 _(size_t, ei_keymap_get_size, (struct ei_keymap *)) \
 _(int, ei_keymap_get_type, (struct ei_keymap *)) \
 _(int, ei_keymap_get_fd, (struct ei_keymap *))
#define XKB_API(_) \
 _(void *, xkb_context_new, (int)) \
 _(void, xkb_context_unref, (void *)) \
 _(void *, xkb_keymap_new_from_string, (void *, const char *, int, int)) \
 _(void, xkb_keymap_unref, (void *)) \
 _(void *, xkb_state_new, (void *)) \
 _(void, xkb_state_unref, (void *)) \
 _(uint32_t, xkb_state_key_get_one_sym, (void *, uint32_t)) \
 _(int, xkb_state_update_key, (void *, uint32_t, int)) \
 _(int, xkb_state_update_mask, (void *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)) \
 _(uint32_t, xkb_state_serialize_mods, (void *, int)) \
 _(uint32_t, xkb_state_serialize_layout, (void *, int))
#define BUS_API(_) \
 _(int, sd_session_get_class, (const char *, char **)) \
 _(int, sd_bus_new, (struct sd_bus **)) \
 _(int, sd_bus_set_address, (struct sd_bus *, const char *)) \
 _(int, sd_bus_set_bus_client, (struct sd_bus *, int)) \
 _(int, sd_bus_set_method_call_timeout, (struct sd_bus *, uint64_t)) \
 _(int, sd_bus_start, (struct sd_bus *)) \
 _(struct sd_bus *, sd_bus_close_unref, (struct sd_bus *)) \
 _(int, sd_bus_call_method, (struct sd_bus *, const char *, const char *, const char *, const char *, struct sd_bus_error *, struct sd_bus_message **, const char *, ...)) \
 _(int, sd_bus_message_read, (struct sd_bus_message *, const char *, ...)) \
 _(struct sd_bus_message *, sd_bus_message_unref, (struct sd_bus_message *))
#define DECL(ret, name, args) static ret (*p_##name) args;
EIS_API(DECL)
BUS_API(DECL)
EIS_KEYMAP_API(DECL)
XKB_API(DECL)
#undef DECL
static void (*p_ei_device_text_utf8)(struct ei_device *, const char *);

static void *g_eisLib, *g_busLib;
static int g_eisUnavailable;
static struct sd_bus *g_eisBus;
static struct ei *g_eis;
static struct ei_device *g_eisDevice;
static struct ei_device *g_eisKeyboard;
static int g_eisKeyboardOffered, g_eisTextOffered;
static unsigned long long g_eisCompositorStart;
static uint32_t g_eisMods[4], g_eisBridgeNonce, g_eisCompositorPid;
static int g_eisModsValid, g_eisBridgeGrab, g_eisBridgeCommit, g_eisBridgePendingContext;
static char g_eisOwner[128];
/* A release must follow its press: 1 = EIS device, 2 = input-method relay.
 * In particular, locking the desktop mid-chord must not move a held key. */
static unsigned char g_eisKeyRoute[EIS_MAX_KEY + 1];
static int g_eisGlobalChord;
static void *g_xkbLib, *g_xkbContext, *g_xkbMap, *g_xkbKeys;
static struct stat g_xkbMapInfo;
static uint64_t g_eisBridgeEpoch;
static unsigned char g_eisKeys[EIS_MAX_KEY + 1];
static struct ei_ping *g_eisPing;
static int g_eisPong;
static uint64_t g_eisLastAttempt;
static uint32_t g_eisSequence;
static kvm_wayland_console_session g_eisSession;
/* Once this console has selected EIS, a lost connection is not permission to
 * move the following keys/text to uinput while reconnect is throttled. */
static kvm_wayland_console_session g_eisSelectedSession;
static int g_eisSelected;

static void eis_note(const char *stage)
{
    const char *level = getenv("MESH_KVM_DRM_DEBUG");
    if (level != NULL && atoi(level) > 0) { fprintf(stderr, "EIS: %s\n", stage); }
}

static uint64_t eis_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int eis_load(void)
{
    void *h;
    if (g_eisUnavailable) { return 0; }
    if (g_eisLib != NULL && g_busLib != NULL) { return 1; }
    if ((h = dlopen("libei.so.1", RTLD_NOW | RTLD_LOCAL)) == NULL) { goto fail; }
#define LOAD(ret, name, args) p_##name = (__typeof__(p_##name))dlsym(h, #name); if (!p_##name) { dlclose(h); goto fail; }
    EIS_API(LOAD)
    EIS_KEYMAP_API(LOAD)
    p_ei_device_text_utf8 = (void *)dlsym(h, "ei_device_text_utf8");
    g_eisLib = h;
    if ((h = dlopen("libsystemd.so.0", RTLD_NOW | RTLD_LOCAL)) == NULL) { goto fail; }
    BUS_API(LOAD)
    g_busLib = h;
#undef LOAD
    return 1;
fail:
    eis_note("optional library/symbol unavailable");
    if (g_eisLib != NULL) { dlclose(g_eisLib); g_eisLib = NULL; }
    g_eisUnavailable = 1;
    return 0;
}

/* Let KWin remove the virtual keyboard while its EIS context is still alive.
 * Destroying the D-Bus caller first can release a held modifier from inside
 * context destruction and re-enter KWin's modifier forwarding on that context.
 * This drain never binds seats, resumes devices, or sends/replays input. */
static void eis_close_devices(void)
{
    struct ei_device *text = g_eisDevice, *keyboard = g_eisKeyboard;
    uint64_t deadline = eis_now_ms() + EIS_TIMEOUT_MS;
    int count = 0;
    if (g_eis == NULL || (text == NULL && keyboard == NULL)) { return; }
    if (text != NULL) { p_ei_device_close(text); }
    if (keyboard != NULL && keyboard != text) { p_ei_device_close(keyboard); }
    while (text != NULL || keyboard != NULL)
    {
        struct ei_event *event;
        struct pollfd pfd;
        uint64_t now;
        int ret;
        p_ei_dispatch(g_eis);
        while ((event = p_ei_get_event(g_eis)) != NULL)
        {
            int type = p_ei_event_get_type(event);
            struct ei_device *device = p_ei_event_get_device(event);
            if (type == 6) /* DEVICE_REMOVED acknowledges ei_device_close. */
            {
                if (device == text) { text = NULL; }
                if (device == keyboard) { keyboard = NULL; }
            }
            /* A device may resume during a partial handshake or teardown.
             * Close it instead of enabling input on that resumed device. */
            else if (type == 8 && device != NULL) { p_ei_device_close(device); }
            p_ei_event_unref(event);
            if (type == 2 || (text == NULL && keyboard == NULL)) { return; }
            if (++count >= 128 || eis_now_ms() >= deadline) { goto incomplete; }
        }
        now = eis_now_ms();
        if (now >= deadline) { goto incomplete; }
        pfd.fd = p_ei_get_fd(g_eis); pfd.events = POLLIN; pfd.revents = 0;
        ret = poll(&pfd, 1, (int)(deadline - now));
        if (ret < 0 && errno == EINTR) { continue; }
        if (ret <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) { goto incomplete; }
    }
    return;
incomplete:
    eis_note("device close acknowledgement incomplete");
}

static void eis_disconnect(void)
{
    memset(g_eisMods, 0, sizeof(g_eisMods)); g_eisModsValid = 0; g_eisBridgeEpoch = 0; g_eisCompositorPid = 0;
    g_eisOwner[0] = 0; g_eisBridgePendingContext = 0;
    if (g_eisPing != NULL) { p_ei_ping_unref(g_eisPing); g_eisPing = NULL; }
    eis_close_devices();
    if (g_eisDevice != NULL) { p_ei_device_unref(g_eisDevice); g_eisDevice = NULL; }
    if (g_eisKeyboard != NULL) { p_ei_device_unref(g_eisKeyboard); g_eisKeyboard = NULL; }
    if (g_eis != NULL) { p_ei_unref(g_eis); g_eis = NULL; }
    /* Closing the unique D-Bus caller also destroys its KWin EIS context. */
    if (g_eisBus != NULL) { p_sd_bus_close_unref(g_eisBus); g_eisBus = NULL; }
    g_eisKeyboardOffered = 0; g_eisTextOffered = 0;
    memset(g_eisKeys, 0, sizeof(g_eisKeys));
    memset(g_eisKeyRoute, 0, sizeof(g_eisKeyRoute)); g_eisBridgeGrab = 0; g_eisBridgeCommit = 0;
    g_eisGlobalChord = 0;
    if (g_xkbKeys) { p_xkb_state_unref(g_xkbKeys); g_xkbKeys = NULL; }
    if (g_xkbMap) { p_xkb_keymap_unref(g_xkbMap); g_xkbMap = NULL; memset(&g_xkbMapInfo, 0, sizeof(g_xkbMapInfo)); }
    memset(&g_eisSession, 0, sizeof(g_eisSession));
    g_eisPong = 0;
}

void kvm_eis_shutdown(void)
{
    kvm_eis_release_keys();
    eis_disconnect();
    g_eisLastAttempt = 0;
    g_eisSequence = 0;
    g_eisSelected = 0;
    memset(&g_eisSelectedSession, 0, sizeof(g_eisSelectedSession));
}

/* Complete Unicode scalar encoding. Controls retain the existing raw-key path. */
static int eis_utf8(uint32_t cp, char out[5])
{
    int n;
    if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0) ||
        (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) { return 0; }
    if (cp < 0x80) { out[0] = (char)cp; n = 1; }
    else if (cp < 0x800)
    { out[0] = (char)(0xc0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 63)); n = 2; }
    else if (cp < 0x10000)
    { out[0] = (char)(0xe0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 63)); out[2] = (char)(0x80 | (cp & 63)); n = 3; }
    else
    { out[0] = (char)(0xf0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 63)); out[2] = (char)(0x80 | ((cp >> 6) & 63)); out[3] = (char)(0x80 | (cp & 63)); n = 4; }
    out[n] = 0;
    return n;
}

/* KWin can run outside a logind session scope and protects /proc/environ.
 * Its public --socket argument identifies the Wayland display. Pair it with
 * the unique bus owner's Unix UID and the capture worker's validated socket.
 * Unknown launch conventions disable this optional adapter.
 */
static int eis_socket_argument(const char *args, size_t size, const char *display)
{
    size_t offset = 0, len;
    int wantSocket = 0;
    while (offset < size)
    {
        len = strnlen(args + offset, size - offset);
        if (len == size - offset) { return 0; }
        if (wantSocket) { return strcmp(args + offset, display) == 0; }
        if (strncmp(args + offset, "--socket=", 9) == 0)
        { return strcmp(args + offset + 9, display) == 0; }
        wantSocket = strcmp(args + offset, "--socket") == 0;
        offset += len + 1;
    }
    return 0;
}

static int eis_process_socket(uint32_t pid, const char *display)
{
    char path[64], args[8192];
    ssize_t n;
    int fd;
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { return 0; }
    n = read(fd, args, sizeof(args));
    close(fd);
    return n > 0 && n < (ssize_t)sizeof(args) && eis_socket_argument(args, (size_t)n, display);
}

static int eis_socket_peer(uint32_t pid, const char *path)
{
    struct sockaddr_un addr;
    struct { pid_t pid; uid_t uid; gid_t gid; } peer;
    socklen_t size = sizeof(peer);
    int fd, matched = 0;
    if (strlen(path) >= sizeof(addr.sun_path)) { return 0; }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { return 0; }
    /* Local Unix connect is nonblocking; a full backlog disables this attempt.
     * The greeter creates its own socket. User KWin may inherit the listener
     * from its wrapper, in which case the explicit --socket binding is used.
     */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && size == sizeof(peer))
    { matched = peer.pid == (pid_t)pid && peer.uid == geteuid(); }
    close(fd);
    return matched;
}

/* Drain is bounded even if a broken peer continuously produces events. */
static int eis_drain(void)
{
    struct ei_event *event;
    int count = 0, good = 1;
    p_ei_dispatch(g_eis);
    while (count++ < 128 && (event = p_ei_get_event(g_eis)) != NULL)
    {
        int type = p_ei_event_get_type(event);
        if (type == 2 || type == 4) { good = 0; } /* disconnect / seat removed */
        else if (type == 3)
        {
            struct ei_seat *seat = p_ei_event_get_seat(event);
            g_eisTextOffered = p_ei_device_text_utf8 && p_ei_seat_has_capability(seat, EI_TEXT);
            g_eisKeyboardOffered = p_ei_seat_has_capability(seat, EI_KEYBOARD);
            if (g_eisTextOffered)
            {
                if (g_eisKeyboardOffered) { p_ei_seat_bind_capabilities(seat, EI_TEXT, EI_KEYBOARD, NULL); }
                else { p_ei_seat_bind_capabilities(seat, EI_TEXT, NULL); }
            }
            else if (g_eisKeyboardOffered) { p_ei_seat_bind_capabilities(seat, EI_KEYBOARD, NULL); }
            else { good = 0; }
        }
        else if (type == 8)
        {
            struct ei_device *dev = p_ei_event_get_device(event);
            if (!g_eisDevice && p_ei_device_has_capability(dev, EI_TEXT)) { g_eisDevice = p_ei_device_ref(dev); }
            if (!g_eisKeyboard && p_ei_device_has_capability(dev, EI_KEYBOARD)) { g_eisKeyboard = p_ei_device_ref(dev); }
        }
        else if ((type == 6 || type == 7) && (p_ei_event_get_device(event) == g_eisDevice ||
            p_ei_event_get_device(event) == g_eisKeyboard))
        { good = 0; } /* removed / paused: do not queue input for a later resume */
        else if (type == 9)
        {
            g_eisMods[0] = p_ei_event_keyboard_get_xkb_mods_depressed(event);
            g_eisMods[1] = p_ei_event_keyboard_get_xkb_mods_latched(event);
            g_eisMods[2] = p_ei_event_keyboard_get_xkb_mods_locked(event);
            g_eisMods[3] = p_ei_event_keyboard_get_xkb_group(event);
            g_eisModsValid = 1;
        }
        else if (type == 90 && p_ei_event_pong_get_ping(event) == g_eisPing)
        { g_eisPong = 1; }
        p_ei_event_unref(event);
        if (!good) { return 0; }
    }
    return count <= 128;
}

static int eis_devices_ready(void)
{
    return g_eisDevice ? (!g_eisKeyboardOffered || g_eisKeyboard != NULL) :
        (!g_eisTextOffered && g_eisKeyboard != NULL);
}

static int eis_wait(int wantPong, uint64_t deadline)
{
    for (;;)
    {
        struct pollfd pfd;
        uint64_t now;
        int ret;
        if (!eis_drain()) { return 0; }
        if (wantPong == 2 ? g_eisModsValid : (wantPong ? g_eisPong : eis_devices_ready())) { return 1; }
        now = eis_now_ms();
        if (now >= deadline) { return 0; }
        pfd.fd = p_ei_get_fd(g_eis); pfd.events = POLLIN; pfd.revents = 0;
        ret = poll(&pfd, 1, (int)(deadline - now));
        if (ret < 0 && errno == EINTR) { continue; }
        if (ret <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) { return 0; }
    }
}

static int eis_connect(const kvm_wayland_console_session *session)
{
    struct sd_bus_message *reply = NULL;
    struct stat st;
    char path[192], displayPath[192], address[224], owner[128];
    const char *display = getenv("WAYLAND_DISPLAY");
    const char *name = NULL;
    uint32_t pid = 0, ownerUid = (uint32_t)-1;
    int fd = -1, cookie;
    const char *stage = "session bus initialization";
    if (!eis_load()) { return 0; }
    snprintf(path, sizeof(path), "/run/user/%u", (unsigned)geteuid());
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) { eis_note("runtime ownership/mode rejected"); return 0; }
    if (display == NULL || display[0] == 0 || strchr(display, '/') != NULL || strlen(display) >= 64) { return 0; }
    snprintf(path, sizeof(path), "/run/user/%u/%s", (unsigned)geteuid(), display);
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) { return 0; }
    strcpy(displayPath, path);
    snprintf(path, sizeof(path), "/run/user/%u/bus", (unsigned)geteuid());
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) { eis_note("session bus socket rejected"); return 0; }
    snprintf(address, sizeof(address), "unix:path=%s", path);
    if (p_sd_bus_new(&g_eisBus) < 0 ||
        p_sd_bus_set_address(g_eisBus, address) < 0 ||
        p_sd_bus_set_bus_client(g_eisBus, 1) < 0 ||
        p_sd_bus_set_method_call_timeout(g_eisBus, EIS_TIMEOUT_MS * 1000ULL) < 0 ||
        p_sd_bus_start(g_eisBus) < 0) { goto fail; }
    /* GetNameOwner does not activate KWin; only use an already-running instance. */
    stage = "KWin bus owner lookup";
    if (p_sd_bus_call_method(g_eisBus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetNameOwner", NULL, &reply, "s", "org.kde.KWin") < 0 ||
        p_sd_bus_message_read(reply, "s", &name) < 0 || name == NULL || name[0] != ':' || strlen(name) >= sizeof(owner)) { goto fail; }
    strcpy(owner, name);
    reply = p_sd_bus_message_unref(reply);
    stage = "KWin process/session validation";
    if (p_sd_bus_call_method(g_eisBus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID", NULL, &reply, "s", owner) < 0 ||
        p_sd_bus_message_read(reply, "u", &pid) < 0 || pid == 0 ||
        (!eis_socket_peer(pid, displayPath) && !eis_process_socket(pid, display))) { goto fail; }
    reply = p_sd_bus_message_unref(reply);
    stage = "KWin bus owner UID validation";
    if (p_sd_bus_call_method(g_eisBus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixUser", NULL, &reply, "s", owner) < 0 ||
        p_sd_bus_message_read(reply, "u", &ownerUid) < 0 || ownerUid != (uint32_t)geteuid()) { goto fail; }
    reply = p_sd_bus_message_unref(reply);
    g_eisCompositorPid = pid;
    { pid_t parent; if (!kvm_bridge_process(pid, &parent, &g_eisCompositorStart)) goto fail; }
    strcpy(g_eisOwner, owner);
    stage = "KWin connectToEIS";
    if (p_sd_bus_call_method(g_eisBus, owner, "/org/kde/KWin/EIS/RemoteDesktop",
        "org.kde.KWin.EIS.RemoteDesktop", "connectToEIS", NULL, &reply, "i", 1) < 0 ||
        p_sd_bus_message_read(reply, "hi", &fd, &cookie) < 0 || fd < 0) { goto fail; }
    stage = "libei sender initialization";
    if ((g_eis = p_ei_new_sender(NULL)) == NULL) { goto fail; }
    p_ei_configure_name(g_eis, "MeshCentral Agent");
    /* sd-bus owns its FD; libei takes ownership of a separate close-on-exec FD. */
    fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) { goto fail; }
    if (p_ei_setup_backend_fd(g_eis, fd) < 0) { goto fail; }
    reply = p_sd_bus_message_unref(reply);
    stage = "libei text device handshake";
    if (!eis_wait(0, eis_now_ms() + EIS_TIMEOUT_MS)) { goto fail; }
    g_eisSession = *session;
    eis_note("text device connected");
    return 1;
fail:
    eis_note(stage);
    if (reply != NULL) { p_sd_bus_message_unref(reply); }
    eis_disconnect();
    return 0;
}

/* Retain one EIS context for the active console. The relay-specific barriers
 * below additionally order work sent over the input-method connection. */
static int eis_ready(void)
{
    kvm_wayland_console_session session;
    uint64_t now;
    if (!kvm_wayland_active_console_session(&session) || session.uid != (int)geteuid() || strcmp(session.type, "wayland") != 0)
    { eis_disconnect(); return g_eisSelected ? -1 : 0; }
    if (g_eisSelected && !kvm_wayland_console_session_equal(&session, &g_eisSelectedSession))
    { eis_disconnect(); g_eisSelected = 0; return -1; }
    if (g_eis != NULL && !kvm_wayland_console_session_equal(&session, &g_eisSession))
    { eis_disconnect(); return -1; } /* never replay a stale session's input */
    if (g_eis != NULL) { g_eisSelectedSession = session; g_eisSelected = 1; }
    if (g_eis != NULL && !eis_drain()) { eis_disconnect(); return -1; }
    if (g_eis == NULL)
    {
        now = eis_now_ms();
        if (g_eisUnavailable || (g_eisLastAttempt != 0 && now - g_eisLastAttempt < EIS_RETRY_MS)) { return g_eisSelected ? -1 : 0; }
        g_eisLastAttempt = now;
        if (!eis_connect(&session)) { return g_eisSelected ? -1 : 0; }
        g_eisSelectedSession = g_eisSession; g_eisSelected = 1;
        if (!kvm_wayland_active_console_session(&session) || !kvm_wayland_console_session_equal(&session, &g_eisSession))
        { eis_disconnect(); return -1; }
    }
    return 1;
}

static int eis_acknowledge(void)
{
    p_ei_ping(g_eisPing);
    if (!eis_wait(1, eis_now_ms() + EIS_TIMEOUT_MS))
    { eis_disconnect(); return -1; }
    g_eisPing = p_ei_ping_unref(g_eisPing);
    return 1;
}

static int eis_keys_held(void)
{
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i)
    { if (g_eisKeys[i]) { return 1; } }
    return 0;
}

static int eis_device_keys_held(void)
{
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i)
    { if (g_eisKeys[i] && g_eisKeyRoute[i] == 1) { return 1; } }
    return 0;
}

static int eis_relay_keys_held(void)
{
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i)
    { if (g_eisKeys[i] && g_eisKeyRoute[i] == 2) { return 1; } }
    return 0;
}

static void eis_finish_global_chord(void)
{
    if (g_eisGlobalChord && !eis_keys_held())
    {
        g_eisGlobalChord = 0;
        g_eisModsValid = 0; g_eisBridgeEpoch = 0;
        if (g_xkbKeys) { p_xkb_state_unref(g_xkbKeys); g_xkbKeys = NULL; }
    }
}

/* Same-host uint32 protocol shared with wire_bridge.py; never send externally.
 * Probe/barrier request (6 words): magic, nonce, depressed, latched, locked,
 * group. A zero nonce probes capabilities and seeds the modifier snapshot.
 * Input request (12 words): magic, nonce, operation, key/scalar, pressed,
 * monotonic-ms stamp, those four modifiers, epoch-low, epoch-high.
 * Reply (9 words): magic, nonce, status, epoch-low, epoch-high, four modifiers.
 *
 * HELLO status 3 offers an ordered keyboard grab; 6 has no grab/owned commit;
 * 7 offers owned text commits; 8 offers that route but needs fresh text state.
 * Status 4 completes an input request; 1/2 complete modifier barriers.
 * Nonce, live context epoch, caller UID and expected modifiers must all match.
 * No compositor ABI, keymap assumptions, or Fedora package version checks. */
static int eis_bridge_request(const char *path, const uint32_t mods[4], uint32_t operation, uint32_t key, uint32_t pressed)
{
    struct sockaddr_un address;
    struct stat st;
    struct { pid_t pid; uid_t uid; gid_t gid; } peer;
    socklen_t peerSize = sizeof(peer);
    struct pollfd pfd;
    uint32_t request[12], reply[9];
    size_t requestSize = operation ? sizeof(request) : 6 * sizeof(uint32_t);
    uint64_t deadline, epoch;
    int fd, result = -1;
    if (lstat(path, &st) != 0) { return errno == ENOENT ? 0 : -1; }
    if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0600 ||
        strlen(path) >= sizeof(address.sun_path)) { return -1; }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { return -1; }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peerSize) != 0 ||
        peerSize != sizeof(peer) || peer.uid != geteuid() ||
        !KVM_BRIDGE_SERVER_AUTH(peer.pid, g_eisCompositorPid, g_eisCompositorStart)) { goto done; }
    if (mods != NULL && ++g_eisBridgeNonce == 0) { ++g_eisBridgeNonce; }
    request[0] = 0x4d414233u; /* MAB3: requires worker-authorized relay. */
    request[1] = mods != NULL ? g_eisBridgeNonce : 0;
    memset(request + 2, 0, 4 * sizeof(uint32_t));
    if (mods != NULL) { memcpy(request + 2, mods, 4 * sizeof(uint32_t)); }
    if (operation)
    {
        request[2] = operation; request[3] = key; request[4] = pressed; request[5] = (uint32_t)eis_now_ms();
        memcpy(request + 6, mods, sizeof(g_eisMods));
        request[10] = (uint32_t)g_eisBridgeEpoch; request[11] = (uint32_t)(g_eisBridgeEpoch >> 32);
    }
    if (send(fd, request, requestSize, MSG_NOSIGNAL) != (ssize_t)requestSize) { goto done; }
    deadline = eis_now_ms() + EIS_TIMEOUT_MS;
    for (;;)
    {
        uint64_t now = eis_now_ms();
        int ready;
        if (now >= deadline) { goto done; }
        pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
        ready = poll(&pfd, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) { continue; }
        if (ready <= 0 || !(pfd.revents & POLLIN)) { goto done; }
        break;
    }
    if (!KVM_BRIDGE_SERVER_AUTH(peer.pid, g_eisCompositorPid, g_eisCompositorStart) ||
        recv(fd, reply, sizeof(reply), MSG_TRUNC) != sizeof(reply) ||
        reply[0] != request[0] || reply[1] != request[1] ||
        (mods != NULL ? ((operation ? reply[2] != 4 : (reply[2] != 1 && reply[2] != 2)) || memcmp(reply + 5, mods, 4 * sizeof(uint32_t)) != 0) : (reply[2] != 3 && reply[2] != 6 && reply[2] != 7 && reply[2] != 8)))
    { goto done; }
    epoch = (uint64_t)reply[3] | ((uint64_t)reply[4] << 32);
    if (!epoch || (g_eisBridgeEpoch != 0 && epoch != g_eisBridgeEpoch)) { goto done; }
    g_eisBridgeEpoch = epoch;
    if (mods == NULL)
    { memcpy(g_eisMods, reply + 5, sizeof(g_eisMods)); g_eisModsValid = 1; g_eisBridgeGrab = reply[2] == 3; g_eisBridgeCommit = reply[2] == 7 || reply[2] == 8; g_eisBridgePendingContext = reply[2] == 8; }
    result = 1;
done:
    close(fd);
    return result;
}

static int eis_bridge_exchange(const char *path, const uint32_t mods[4])
{ return eis_bridge_request(path, mods, 0, 0, 0); }

/* 0 absent, 1 stock relay, 2 owned text-only method, -1 invalid. The marker is
 * a hint only: the socket peer and fresh capability/epoch are checked afterward. */
static int eis_bridge_marker_path(const char *path)
{
    struct stat info;
    uint32_t marker = 0;
    int required = 0, descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0)
    {
        required = fstat(descriptor, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
            info.st_nlink == 1 && (info.st_mode & 0777) == 0600 && info.st_size == sizeof(marker) &&
            read(descriptor, &marker, sizeof(marker)) == sizeof(marker) &&
            (marker == 0x4d414233u || marker == 0x4d414234u) ? (marker == 0x4d414234u ? 2 : 1) : -1;
        close(descriptor);
    }
    else if (errno != ENOENT) { required = -1; }
    return required;
}
static int eis_bridge_marker(void)
{
    char path[108];
    snprintf(path, sizeof(path), "%s/%u/meshagent-ime-bridge.%u.required", KVM_EIS_RUNTIME_ROOT, (unsigned)geteuid(), g_eisCompositorPid);
    return eis_bridge_marker_path(path);
}
static int eis_modifier_barrier(void)
{
    char path[108];
    int required = eis_bridge_marker(), result;
    if (required < 0)
    { eis_disconnect(); return -1; }
    snprintf(path, sizeof(path), "%s/%u/meshagent-ime-bridge.%u.sock", KVM_EIS_RUNTIME_ROOT, (unsigned)geteuid(), g_eisCompositorPid);
    /* Missing bridge preserves the legacy installation path. The installer
     * makes the bridge durable before retiring the owned native companion. */
    /* KWin sends EIS modifiers on changes, not necessarily at device creation.
     * Seed the initial state with a fresh round-trip through the trusted IME. */
    result = eis_bridge_exchange(path, g_eisModsValid ? g_eisMods : NULL);
    if (result < 0 || (result == 0 && (required || g_eisBridgeEpoch)))
    {
        eis_note("input-method modifier barrier failed or bridge replaced");
        eis_disconnect();
        return -1;
    }
    return 1;
}


/* ScreenSaver is already provided by the active desktop. Resolve its unique
 * owner first so querying lock state never starts another desktop service. */
static int eis_console_uses_ordered_input(void)
{
    struct sd_bus_message *reply = NULL;
    const char *owner; char unique[128]; int locked = 0;
    char *sessionClass = NULL;
    if (p_sd_session_get_class && g_eisSession.id[0] && p_sd_session_get_class(g_eisSession.id, &sessionClass) >= 0)
    {
        int greeter = sessionClass && strcmp(sessionClass, "greeter") == 0;
        free(sessionClass);
        if (greeter) { return 1; }
    }
    if (!p_sd_bus_call_method || !p_sd_bus_message_read || !p_sd_bus_message_unref) { return 0; }
    if (p_sd_bus_call_method(g_eisBus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", NULL, &reply, "s", "org.freedesktop.ScreenSaver") < 0 ||
        p_sd_bus_message_read(reply, "s", &owner) < 0 || !owner || owner[0] != ':' || strlen(owner) >= sizeof(unique)) { goto done; }
    strcpy(unique, owner); reply = p_sd_bus_message_unref(reply);
    if (p_sd_bus_call_method(g_eisBus, unique, "/ScreenSaver", "org.freedesktop.ScreenSaver", "GetActive", NULL, &reply, "") < 0 ||
        p_sd_bus_message_read(reply, "b", &locked) < 0) { locked = 0; }
done:
    if (reply) { p_sd_bus_message_unref(reply); }
    return locked != 0;
}

/* Identify modifier actions from the actual EIS keymap, including remapped
 * keys and layout/group switches. No evdev modifier list or mask assumptions. */
static int eis_key_is_modifier(uint32_t key)
{
    struct ei_keymap *source; struct stat info;
    size_t size; int fd, components; void *state; char *text;
    if (!g_xkbLib)
    {
        void *h = dlopen("libxkbcommon.so.0", RTLD_NOW | RTLD_LOCAL);
        if (!h) { return -1; }
#define LOAD_XKB(ret, name, args) p_##name = (__typeof__(p_##name))dlsym(h, #name); if (!p_##name) { dlclose(h); return -1; }
        XKB_API(LOAD_XKB)
#undef LOAD_XKB
        g_xkbLib = h; g_xkbContext = p_xkb_context_new(0);
    }
    if (!g_xkbContext || !p_ei_device_keyboard_get_keymap || !(source = p_ei_device_keyboard_get_keymap(g_eisKeyboard)) ||
        p_ei_keymap_get_type(source) != 1 || (size = p_ei_keymap_get_size(source)) == 0 || size > 4 * 1024 * 1024 ||
        (fd = p_ei_keymap_get_fd(source)) < 0 || fstat(fd, &info) != 0 || info.st_size < (off_t)size) { return -1; }
    if (!g_xkbMap || g_xkbMapInfo.st_ino != info.st_ino || g_xkbMapInfo.st_dev != info.st_dev || g_xkbMapInfo.st_size != info.st_size || g_xkbMapInfo.st_ctim.tv_sec != info.st_ctim.tv_sec || g_xkbMapInfo.st_ctim.tv_nsec != info.st_ctim.tv_nsec)
    {
        void *map;
        if (g_xkbKeys) { return -1; } /* Never reinterpret a held chord with a replacement map. */
        text = malloc(size + 1); if (!text) { return -1; }
        if (pread(fd, text, size, 0) != (ssize_t)size) { free(text); return -1; }
        text[size] = 0;
        map = p_xkb_keymap_new_from_string(g_xkbContext, text, 1, 0); free(text);
        if (!map) { return -1; }
        if (g_xkbMap) { p_xkb_keymap_unref(g_xkbMap); }
        g_xkbMap = map; g_xkbMapInfo = info;
    }
    state = p_xkb_state_new(g_xkbMap); if (!state) { return -1; }
    components = p_xkb_state_update_key(state, key + 8, 1);
    components |= p_xkb_state_update_key(state, key + 8, 0);
    p_xkb_state_unref(state);
    return (components & (1 | 2 | 4 | 16 | 32 | 64)) != 0;
}

/* Global shortcuts must enter KWin's normal keyboard filters. Sending their
 * non-modifier keys through an input-method context bypasses those filters.
 * Resolve semantics from the installed map, including remapped modifiers;
 * ISO_Level3_Shift/AltGr remains on the ordinary text-input route. */
static int eis_key_is_global_modifier(uint32_t key)
{
    void *state; uint32_t symbol;
    if (eis_key_is_modifier(key) < 0) { return -1; }
    state = p_xkb_state_new(g_xkbMap); if (!state) { return -1; }
    if (g_eisModsValid) { p_xkb_state_update_mask(state, g_eisMods[0], g_eisMods[1], g_eisMods[2], 0, 0, g_eisMods[3]); }
    symbol = p_xkb_state_key_get_one_sym(state, key + 8);
    p_xkb_state_unref(state);
    return symbol >= 0xffe7u && symbol <= 0xffeeu; /* Meta, Alt, Super, Hyper */
}

/* Predict the owned chord from the compositor's actual keymap, not assumed
 * Ctrl/Shift masks. Older KWin does not echo modifiers on the EIS connection;
 * waiting for the expected stock-IME echo prevents a stale pressed modifier
 * from being restored after its raw release. Seed physical/lock state once
 * before the chord, and keep the same state until every owned key is up. */
static int eis_chord_modifiers(uint32_t key, int pressed, uint32_t wanted[4])
{
    if (eis_key_is_modifier(key) < 0) { return -1; }
    if (!g_xkbKeys)
    {
        if (!g_eisModsValid || !(g_xkbKeys = p_xkb_state_new(g_xkbMap))) { return -1; }
        p_xkb_state_update_mask(g_xkbKeys, g_eisMods[0], g_eisMods[1], g_eisMods[2], 0, 0, g_eisMods[3]);
    }
    p_xkb_state_update_key(g_xkbKeys, key + 8, pressed);
    wanted[0] = p_xkb_state_serialize_mods(g_xkbKeys, 1);
    wanted[1] = p_xkb_state_serialize_mods(g_xkbKeys, 2);
    wanted[2] = p_xkb_state_serialize_mods(g_xkbKeys, 4);
    wanted[3] = p_xkb_state_serialize_layout(g_xkbKeys, 128);
    return 1;
}

/* Refresh capabilities before a new chord/text operation. Debian's older KWin
 * can activate our headless method without a commit-state serial. Capability
 * 8 permits the already authenticated owner to refresh state, before any text
 * is queued; it is not permission to resend an uncertain text operation. */
static int eis_bridge_prepare(void)
{
    char path[108]; uint32_t saved[4]; int valid = g_eisModsValid, result;
    memcpy(saved, g_eisMods, sizeof(saved));
    if (!eis_keys_held()) { g_eisBridgeEpoch = 0; }
    snprintf(path, sizeof(path), "%s/%u/meshagent-ime-bridge.%u.sock", KVM_EIS_RUNTIME_ROOT, (unsigned)geteuid(), g_eisCompositorPid);
    result = eis_bridge_exchange(path, NULL);
    if (result == 1 && g_eisBridgePendingContext)
    {
        struct sd_bus_message *reply = NULL;
        /* Request fresh text state only from the already authenticated KWin
         * owner and only for the owned headless method's explicit capability.
         * This does not focus a window, show an OSK, or persist a setting. No
         * text has been queued, so an unavailable state can fail closed. */
        if (eis_keys_held() || !g_eisOwner[0] || p_sd_bus_call_method(g_eisBus, g_eisOwner, "/VirtualKeyboard",
            "org.freedesktop.DBus.Properties", "Set", NULL, &reply, "ssv",
            "org.kde.kwin.VirtualKeyboard", "active", "b", 1) < 0)
        { if (reply) { p_sd_bus_message_unref(reply); } eis_disconnect(); return -1; }
        p_sd_bus_message_unref(reply);
        /* The requested adoption may legitimately replace the empty context.
         * No keys are held and no text has been sent; establish its new epoch
         * now, rather than rejecting the first character as stale delivery. */
        g_eisBridgeEpoch = 0;
        result = eis_bridge_exchange(path, NULL);
        if (result != 1 || g_eisBridgePendingContext) { eis_disconnect(); return -1; }
    }
    /* A new stock-IME chord must adopt its fresh physical/lock snapshot.
     * During an owned chord, or with the text-only method, preserve the EIS
     * snapshot instead of replacing it with an unrelated IME baseline. */
    if (valid && (eis_keys_held() || eis_bridge_marker() != 1))
    { memcpy(g_eisMods, saved, sizeof(saved)); g_eisModsValid = 1; }
    if (result == 0) { return eis_modifier_barrier() < 0 ? -1 : 0; }
    if (result < 0) { eis_disconnect(); return -1; }
    return g_eisBridgeGrab;
}

static int eis_bridge_input(uint32_t operation, uint32_t key, uint32_t pressed)
{
    char path[108]; int result;
    snprintf(path, sizeof(path), "%s/%u/meshagent-ime-bridge.%u.sock", KVM_EIS_RUNTIME_ROOT, (unsigned)geteuid(), g_eisCompositorPid);
    result = eis_bridge_request(path, g_eisMods, operation, key, pressed);
    if (result != 1) { eis_note("ordered lock input failed"); eis_disconnect(); return -1; }
    return 1;
}

int kvm_eis_key_action(uint32_t keycode, int pressed)
{
    uint32_t before[4], wanted[4];
    int ready, beforeValid, stock, marker, modifier = 0;
    if (!keycode || keycode > EIS_MAX_KEY || (pressed != 0 && pressed != 1)) { return 0; }
    /* An unmatched release belongs to the uinput fallback. Do not connect just
     * to release a key that was never pressed on this virtual keyboard. */
    if (!pressed && !g_eisKeys[keycode]) { return 0; }
    ready = eis_ready();
    if (ready != 1) { return ready; }
    if (!g_eisKeyboard) { return 0; }
    if (g_eisKeys[keycode] == pressed) { return 1; }
    marker = eis_bridge_marker();
    if (marker < 0) { eis_disconnect(); return -1; }
    stock = marker == 1;
    if (marker && pressed && !g_eisGlobalChord && !eis_relay_keys_held())
    {
        int global = eis_key_is_global_modifier(keycode);
        if (global < 0) { eis_disconnect(); return -1; }
        if (global && !eis_console_uses_ordered_input()) { g_eisGlobalChord = 1; }
    }
    /* Focus can replace the owned headless context between chords too. Adopt
     * its authenticated readiness before emitting a modifier, rather than
     * disconnecting that modifier at the post-send stale-epoch barrier.
     * A held chord must still reject a changed epoch without replay. */
    if (marker && pressed && !eis_keys_held() && eis_bridge_prepare() < 0) { return -1; }
    if (!pressed && g_eisKeyRoute[keycode] == 2)
    {
        int result = eis_bridge_input(0x4b455931u, keycode, 0);
        if (result == 1) { g_eisKeys[keycode] = 0; g_eisKeyRoute[keycode] = 0; }
        return result;
    }
    if (pressed && !g_eisGlobalChord && (stock || eis_console_uses_ordered_input()))
    {
        int bridge = eis_keys_held() ? g_eisBridgeGrab : eis_bridge_prepare();
        if (bridge < 0) { return -1; }
        if (bridge)
        {
            int modifier = eis_key_is_modifier(keycode);
            if (modifier < 0) { eis_note("installed keymap unavailable for locked input"); return -1; }
            if (!modifier)
            {
                int result = eis_bridge_input(0x4b455931u, keycode, 1);
                if (result == 1) { g_eisKeys[keycode] = 1; g_eisKeyRoute[keycode] = 2; }
                return result;
            }
        }
    }
    if (stock)
    {
        modifier = eis_key_is_modifier(keycode);
        if (modifier < 0 || eis_chord_modifiers(keycode, pressed, wanted) < 0) { eis_disconnect(); return -1; }
    }
    memcpy(before, g_eisMods, sizeof(before)); beforeValid = g_eisModsValid;
    g_eisPing = p_ei_new_ping(g_eis);
    if (!g_eisPing) { eis_disconnect(); return -1; }
    g_eisPong = 0;
    /* Stopping emulation while a key is down arms KWin's delayed release.
     * Keep one emulation sequence for the entire chord, including idle holds. */
    if (!eis_device_keys_held()) { p_ei_device_start_emulating(g_eisKeyboard, ++g_eisSequence); }
    p_ei_device_keyboard_key(g_eisKeyboard, keycode, pressed != 0);
    g_eisKeys[keycode] = (unsigned char)pressed; g_eisKeyRoute[keycode] = pressed ? 1 : 0;
    p_ei_device_frame(g_eisKeyboard, p_ei_now(g_eis));
    if (!eis_device_keys_held()) { p_ei_device_stop_emulating(g_eisKeyboard); }
    if (eis_acknowledge() != 1) { return -1; }
    if (g_eisGlobalChord)
    {
        if (stock)
        {
            /* The vendor IME can asynchronously restore an older modifier
             * snapshot. Cross its ordered echo before the shortcut key, but
             * never bind releases to a text context the shortcut may replace. */
            memcpy(g_eisMods, wanted, sizeof(wanted)); g_eisModsValid = 1;
            if (modifier && pressed && eis_modifier_barrier() < 0) { return -1; }
        }
        eis_finish_global_chord();
        return 1;
    }
    if (stock)
    {
        int result = 1;
        memcpy(g_eisMods, wanted, sizeof(wanted)); g_eisModsValid = 1;
        if (modifier) { result = eis_modifier_barrier(); }
        if (!eis_keys_held() && g_xkbKeys) { p_xkb_state_unref(g_xkbKeys); g_xkbKeys = NULL; }
        return result;
    }
    /* An EIS pong acknowledges libeis transport dispatch, not necessarily
     * KWin's queued keyboard events. Before the owned headless method can
     * deliver Unicode on its separate Wayland connection, cross the compositor
     * event loop through that method's existing authenticated sync barrier.
     * Stock input methods retain their established modifier-echo route. */
    if (eis_bridge_marker() == 2) { return eis_modifier_barrier(); }
    /* An IME round-trip belongs after a real modifier transition. Repeating
     * it for ordinary keys can publish an older IME snapshot between raw key
     * delivery and text commits. EIS orders modifier events before its pong. */
    return g_eisModsValid && (!beforeValid || memcmp(before, g_eisMods, sizeof(before))) ? eis_modifier_barrier() : 1;
}

void kvm_eis_release_keys(void)
{
    unsigned int count = 0;
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i) { count += g_eisKeys[i] != 0; }
    if (!count || !g_eis || !g_eisKeyboard) { return; }
    /* Never deliver stale releases to a replacement console incarnation. */
    if (eis_ready() != 1) { return; }
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i)
    {
        if (g_eisKeys[i] && g_eisKeyRoute[i] == 2)
        {
            if (eis_bridge_input(0x4b455931u, i, 0) != 1) { return; }
            g_eisKeys[i] = g_eisKeyRoute[i] = 0;
        }
    }
    if (!eis_keys_held()) { return; }
    g_eisPing = p_ei_new_ping(g_eis);
    if (!g_eisPing) { eis_disconnect(); return; }
    g_eisPong = 0;
    /* Held keys already belong to an active emulation sequence. */
    for (unsigned int i = 1; i <= EIS_MAX_KEY; ++i)
    {
        if (g_eisKeys[i]) { p_ei_device_keyboard_key(g_eisKeyboard, i, false); g_eisKeys[i] = 0; }
    }
    p_ei_device_frame(g_eisKeyboard, p_ei_now(g_eis));
    p_ei_device_stop_emulating(g_eisKeyboard);
    (void)eis_acknowledge();
    eis_finish_global_chord();
}

int kvm_eis_type_unicode(uint32_t codepoint)
{
    char text[5];
    int ready, marker;
    if (!eis_utf8(codepoint, text)) { return 0; }
    ready = eis_ready();
    if (ready != 1) { return ready; }
    marker = eis_bridge_marker();
    if (marker < 0) { eis_disconnect(); return -1; }
    if ((marker == 2 || !g_eisDevice || !p_ei_device_text_utf8) && eis_bridge_prepare() < 0) { return -1; }
    if (marker == 2 && !g_eisBridgeCommit) { eis_disconnect(); return -1; }
    if (marker == 2 || !g_eisDevice || !p_ei_device_text_utf8)
    {
        /* Older stock libei/KWin expose keyboard only. The bridge delivers
         * Unicode through the public input-method protocol. */
        return eis_bridge_input(0x434d5431u, codepoint, 0);
    }
    if (marker == 1 || eis_console_uses_ordered_input())
    {
        int bridge = eis_keys_held() ? g_eisBridgeGrab : eis_bridge_prepare();
        if (bridge < 0) { return -1; }
        if (bridge) { return eis_bridge_input(0x54585431u, codepoint, 0); }
    }
    g_eisPing = p_ei_new_ping(g_eis);
    if (g_eisPing == NULL) { eis_disconnect(); return -1; }
    g_eisPong = 0;
    p_ei_device_start_emulating(g_eisDevice, ++g_eisSequence);
    p_ei_device_text_utf8(g_eisDevice, text);
    p_ei_device_frame(g_eisDevice, p_ei_now(g_eis));
    p_ei_device_stop_emulating(g_eisDevice);
    return eis_acknowledge();
}
#else
int kvm_eis_type_unicode(uint32_t codepoint) { (void)codepoint; return 0; }

/* ScreenSaver is already provided by the active desktop. Resolve its unique
 * owner first so querying lock state never starts another desktop service. */
static int eis_console_uses_ordered_input(void)
{
    struct sd_bus_message *reply = NULL;
    const char *owner; char unique[128]; int locked = 0;
    char *sessionClass = NULL;
    if (p_sd_session_get_class && g_eisSession.id[0] && p_sd_session_get_class(g_eisSession.id, &sessionClass) >= 0)
    {
        int greeter = sessionClass && strcmp(sessionClass, "greeter") == 0;
        free(sessionClass);
        if (greeter) { return 1; }
    }
    if (!p_sd_bus_call_method || !p_sd_bus_message_read || !p_sd_bus_message_unref) { return 0; }
    if (p_sd_bus_call_method(g_eisBus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", NULL, &reply, "s", "org.freedesktop.ScreenSaver") < 0 ||
        p_sd_bus_message_read(reply, "s", &owner) < 0 || !owner || owner[0] != ':' || strlen(owner) >= sizeof(unique)) { goto done; }
    strcpy(unique, owner); reply = p_sd_bus_message_unref(reply);
    if (p_sd_bus_call_method(g_eisBus, unique, "/ScreenSaver", "org.freedesktop.ScreenSaver", "GetActive", NULL, &reply, "") < 0 ||
        p_sd_bus_message_read(reply, "b", &locked) < 0) { locked = 0; }
done:
    if (reply) { p_sd_bus_message_unref(reply); }
    return locked != 0;
}

/* Identify modifier actions from the actual EIS keymap, including remapped
 * keys and layout/group switches. No evdev modifier list or mask assumptions. */
static int eis_key_is_modifier(uint32_t key)
{
    struct ei_keymap *source; struct stat info;
    size_t size; int fd, components; void *state; char *text;
    if (!g_xkbLib)
    {
        void *h = dlopen("libxkbcommon.so.0", RTLD_NOW | RTLD_LOCAL);
        if (!h) { return -1; }
#define LOAD_XKB(ret, name, args) p_##name = (__typeof__(p_##name))dlsym(h, #name); if (!p_##name) { dlclose(h); return -1; }
        XKB_API(LOAD_XKB)
#undef LOAD_XKB
        g_xkbLib = h; g_xkbContext = p_xkb_context_new(0);
    }
    if (!g_xkbContext || !p_ei_device_keyboard_get_keymap || !(source = p_ei_device_keyboard_get_keymap(g_eisKeyboard)) ||
        p_ei_keymap_get_type(source) != 1 || (size = p_ei_keymap_get_size(source)) == 0 || size > 4 * 1024 * 1024 ||
        (fd = p_ei_keymap_get_fd(source)) < 0 || fstat(fd, &info) != 0 || info.st_size < (off_t)size) { return -1; }
    if (!g_xkbMap || g_xkbMapInfo.st_ino != info.st_ino || g_xkbMapInfo.st_dev != info.st_dev || g_xkbMapInfo.st_size != info.st_size || g_xkbMapInfo.st_ctim.tv_sec != info.st_ctim.tv_sec || g_xkbMapInfo.st_ctim.tv_nsec != info.st_ctim.tv_nsec)
    {
        void *map;
        text = malloc(size + 1); if (!text) { return -1; }
        if (pread(fd, text, size, 0) != (ssize_t)size) { free(text); return -1; }
        text[size] = 0;
        map = p_xkb_keymap_new_from_string(g_xkbContext, text, 1, 0); free(text);
        if (!map) { return -1; }
        if (g_xkbMap) { p_xkb_keymap_unref(g_xkbMap); }
        g_xkbMap = map; g_xkbMapInfo = info;
    }
    state = p_xkb_state_new(g_xkbMap); if (!state) { return -1; }
    components = p_xkb_state_update_key(state, key + 8, 1);
    components |= p_xkb_state_update_key(state, key + 8, 0);
    p_xkb_state_unref(state);
    return (components & (1 | 2 | 4 | 16 | 32 | 64)) != 0;
}

static int eis_bridge_prepare(void)
{
    char path[108]; uint32_t saved[4]; int valid = g_eisModsValid, result;
    memcpy(saved, g_eisMods, sizeof(saved));
    if (!eis_keys_held()) { g_eisBridgeEpoch = 0; }
    snprintf(path, sizeof(path), "/run/user/%u/meshagent-ime-bridge.%u.sock", (unsigned)geteuid(), g_eisCompositorPid);
    result = eis_bridge_exchange(path, NULL);
    if (valid) { memcpy(g_eisMods, saved, sizeof(saved)); g_eisModsValid = 1; }
    if (result == 0) { return eis_modifier_barrier() < 0 ? -1 : 0; }
    if (result < 0) { eis_disconnect(); return -1; }
    return g_eisBridgeGrab;
}

static int eis_bridge_input(uint32_t operation, uint32_t key, uint32_t pressed)
{
    char path[108]; int result;
    snprintf(path, sizeof(path), "/run/user/%u/meshagent-ime-bridge.%u.sock", (unsigned)geteuid(), g_eisCompositorPid);
    result = eis_bridge_request(path, g_eisMods, operation, key, pressed);
    if (result != 1) { eis_note("ordered lock input failed"); eis_disconnect(); return -1; }
    return 1;
}

int kvm_eis_key_action(uint32_t keycode, int pressed) { (void)keycode; (void)pressed; return 0; }
void kvm_eis_release_keys(void) { }
void kvm_eis_shutdown(void) { }
#endif
