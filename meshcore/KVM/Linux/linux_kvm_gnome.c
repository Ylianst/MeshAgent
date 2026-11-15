/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_kvm_gnome.h"
#include "linux_kvm_peer_message.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <png.h>

static struct
{
    int fd, active, failed;
    pid_t peer;
    kvm_wayland_console_session session;
    kvm_gnome_reply status;
    unsigned char *rgb;
    void *png_library;
    int (*png_begin)(png_imagep, png_const_voidp, size_t);
    int (*png_finish)(png_imagep, png_const_colorp, void *, png_int_32, void *);
    void (*png_free)(png_imagep);
} g_gnome = { .fd = -1 };

static uint32_t gnome_u32(const unsigned char *p)
{ uint32_t v; memcpy(&v, p, 4); return ntohl(v); }

int kvm_gnome_decode_header(const unsigned char *data, size_t size, kvm_gnome_reply *out)
{
    kvm_gnome_reply r;
    int64_t minx = INT64_MAX, miny = INT64_MAX, maxx = INT64_MIN, maxy = INT64_MIN;
    if (!data || !out || size < KVM_GNOME_HEADER_SIZE || memcmp(data, "AGN1", 4) != 0) { return 0; }
    memset(&r, 0, sizeof(r));
    r.op = gnome_u32(data + 4); r.result = gnome_u32(data + 8);
    memcpy(r.epoch, data + 12, sizeof(r.epoch));
    r.revision = gnome_u32(data + 28); r.flags = gnome_u32(data + 32);
    r.width = gnome_u32(data + 36); r.height = gnome_u32(data + 40);
    r.count = gnome_u32(data + 44); r.payload_size = gnome_u32(data + 48);
    if (r.op < 1 || r.op > 5 || r.result > 3 || (r.result == 3 && r.op != 4) || !r.revision || (r.flags & ~127u) ||
        !r.width || !r.height || r.width > 16384 || r.height > 16384 ||
        (uint64_t)r.width * r.height > KVM_GNOME_MAX_PIXELS ||
        !r.count || r.count > KVM_GNOME_MAX_MONITORS ||
        size != KVM_GNOME_HEADER_SIZE + (size_t)r.count * 16 ||
        r.payload_size > KVM_GNOME_MAX_PAYLOAD ||
        ((r.op != 3 || r.result != 0) && r.payload_size != 0) ||
        (r.op == 3 && r.result == 0 && !r.payload_size) ||
        gnome_u32(data + 52) || gnome_u32(data + 56)) { return 0; }
    for (uint32_t i = 0; i < r.count; i++)
    {
        const unsigned char *p = data + KVM_GNOME_HEADER_SIZE + i * 16;
        kvm_gnome_monitor *m = &r.monitors[i];
        m->x = (int32_t)gnome_u32(p); m->y = (int32_t)gnome_u32(p + 4);
        m->width = gnome_u32(p + 8); m->height = gnome_u32(p + 12);
        if (m->x < -32768 || m->x > 32768 || m->y < -32768 || m->y > 32768 ||
            !m->width || !m->height || m->width > 16384 || m->height > 16384) { return 0; }
        if (m->x < minx) { minx = m->x; } if (m->y < miny) { miny = m->y; }
        if ((int64_t)m->x + m->width > maxx) { maxx = (int64_t)m->x + m->width; }
        if ((int64_t)m->y + m->height > maxy) { maxy = (int64_t)m->y + m->height; }
    }
    if (maxx - minx != r.width || maxy - miny != r.height) { return 0; }
    *out = r;
    return 1;
}

static uint64_t gnome_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int gnome_wait(int fd, short events, uint64_t deadline)
{
    for (;;)
    {
        uint64_t now = gnome_now();
        struct pollfd p = { fd, events, 0 };
        int r;
        if (!now || now >= deadline) { return 0; }
        r = poll(&p, 1, (int)(deadline - now));
        if (r < 0 && errno == EINTR) { continue; }
        return r > 0 && (p.revents & events) != 0 && !(p.revents & (POLLERR | POLLNVAL));
    }
}

static int gnome_io(int write_data, unsigned char *data, size_t size, uint64_t deadline)
{
    size_t offset = 0;
    while (offset < size)
    {
        ssize_t n;
        if (!gnome_wait(g_gnome.fd, write_data ? POLLOUT : POLLIN, deadline)) { return 0; }
        n = write_data ? send(g_gnome.fd, data + offset, size - offset, MSG_NOSIGNAL) :
            kvm_peer_recv(g_gnome.fd, data + offset, size - offset, g_gnome.peer, (uid_t)g_gnome.session.uid);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { continue; }
        if (n <= 0) { return 0; }
        offset += (size_t)n;
    }
    return 1;
}

static int gnome_session_valid(void)
{
    kvm_wayland_console_session current;
    return g_gnome.fd >= 0 && kvm_wayland_active_console_session(&current) &&
        kvm_wayland_console_session_equal(&current, &g_gnome.session);
}

static int gnome_connect(const char *path, struct ucred *peer)
{
    struct sockaddr_un addr;
    socklen_t size = sizeof(*peer);
    int fd, error = 0;
    socklen_t error_size = sizeof(error);
    uint64_t now = gnome_now();
    if (!now || strlen(path) >= sizeof(addr.sun_path)) { return -1; }
    memset(&addr, 0, sizeof(addr)); addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path) + 1);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { return -1; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 &&
        (errno != EINPROGRESS || !gnome_wait(fd, POLLOUT, now + 250) ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size) != 0 || error != 0)) { goto fail; }
    int passcred = 1;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, peer, &size) != 0 || size != sizeof(*peer) ||
        setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred)) != 0) { goto fail; }
    return fd;
fail:
    close(fd); return -1;
}

static int gnome_root_file(const char *path, int directory)
{
    struct stat st;
    return lstat(path, &st) == 0 && st.st_uid == 0 && !(st.st_mode & 0022) &&
        (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
}

static int gnome_assets_trusted(void)
{
    const char *dirs[] = { "/", "/usr", "/usr/share", "/usr/share/gnome-shell",
        "/usr/share/gnome-shell/extensions",
        "/usr/share/gnome-shell/extensions/meshagent-console@meshcentral.com" };
    const char *files[] = { "metadata.json", "extension.js", "protocol.js" };
    char path[256];
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    { if (!gnome_root_file(dirs[i], 1)) { return 0; } }
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
    {
        if (snprintf(path, sizeof(path), "%s/%s", dirs[5], files[i]) >= (int)sizeof(path) ||
            !gnome_root_file(path, 0)) { return 0; }
    }
    return 1;
}

int kvm_gnome_process_identity_matches(const kvm_wayland_console_session *session,
    const char *cgroup, const char *cmdline, size_t cmdline_size)
{
    char scope[192], service[192], user_service[192], ubuntu_service[192], classic_service[192];
    const char *line;
    int matched = 0;
    if (!session || session->uid <= 0 || !session->id[0] || !cgroup || !cmdline ||
        !cmdline_size || cmdline_size > 4096 || cmdline[cmdline_size - 1] != 0) { return 0; }
    for (size_t offset = 0; offset < cmdline_size;)
    {
        size_t n = strnlen(cmdline + offset, cmdline_size - offset);
        const char *arg = cmdline + offset;
        if (!n || n == cmdline_size - offset ||
            (offset == 0 && strcmp(arg, "/usr/bin/gnome-shell") != 0) ||
            strncmp(arg, "--nested", 8) == 0 || strcmp(arg, "-n") == 0 ||
            strncmp(arg, "--headless", 10) == 0 || strncmp(arg, "--virtual-monitor", 17) == 0 ||
            strncmp(arg, "--x11", 5) == 0) { return 0; }
        offset += n + 1;
    }
    snprintf(scope, sizeof(scope), "/user.slice/user-%d.slice/session-%s.scope", session->uid, session->id);
    snprintf(service, sizeof(service),
        "/user.slice/user-%d.slice/user@%d.service/session.slice/org.gnome.Shell@wayland.service",
        session->uid, session->uid);
    // GNOME 51 names its Wayland-only user compositor @user.service.
    // Retain exact unit/UID matching; the remaining peer checks still bind it
    // to the active seat, stock executable, PID and compositor socket.
    snprintf(user_service, sizeof(user_service),
        "/user.slice/user-%d.slice/user@%d.service/session.slice/org.gnome.Shell@user.service",
        session->uid, session->uid);
    // Ubuntu's stock GNOME 50 session uses its named Shell mode as the unit
    // instance. Keep exact matching; active-seat and Wayland-peer checks remain.
    snprintf(ubuntu_service, sizeof(ubuntu_service),
        "/user.slice/user-%d.slice/user@%d.service/session.slice/org.gnome.Shell@ubuntu.service",
        session->uid, session->uid);
    // GNOME Classic runs the stock Shell under its own named mode instance.
    snprintf(classic_service, sizeof(classic_service),
        "/user.slice/user-%d.slice/user@%d.service/session.slice/org.gnome.Shell@classic.service",
        session->uid, session->uid);
    line = cgroup;
    while (*line)
    {
        const char *end = strchr(line, '\n');
        const char *first = strchr(line, ':');
        const char *second;
        size_t length = end ? (size_t)(end - line) : strlen(line);
        if (first && first < line + length && (second = strchr(first + 1, ':')) != NULL && second < line + length)
        {
            size_t n = (size_t)(line + length - second - 1);
            if ((n == strlen(scope) && memcmp(second + 1, scope, n) == 0) ||
                (n == strlen(service) && memcmp(second + 1, service, n) == 0) ||
                (n == strlen(user_service) && memcmp(second + 1, user_service, n) == 0) ||
                (n == strlen(ubuntu_service) && memcmp(second + 1, ubuntu_service, n) == 0) ||
                (n == strlen(classic_service) && memcmp(second + 1, classic_service, n) == 0)) { matched = 1; }
        }
        if (!end) { break; }
        line = end + 1;
    }
    return matched;
}

static int gnome_read_proc(pid_t pid, const char *name, char *data, size_t capacity, size_t *length)
{
    char path[64];
    int fd;
    ssize_t n;
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, name);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { return 0; }
    n = read(fd, data, capacity);
    close(fd);
    if (n <= 0 || (size_t)n >= capacity) { return 0; }
    *length = (size_t)n; data[n] = 0; return 1;
}

static int gnome_peer_trusted(const struct ucred *peer, const char *runtime,
    const kvm_wayland_console_session *session)
{
    char path[256], exe[PATH_MAX];
    char cgroup[2048], cmdline[4097];
    size_t cgroup_size, cmdline_size;
    struct stat expected, actual;
    DIR *dir;
    struct dirent *entry;
    int matched = 0, scanned = 0;
    uint64_t deadline = gnome_now() + 1000;
    ssize_t size;
    if (peer->uid != (uid_t)session->uid || peer->pid <= 1 || !gnome_root_file("/usr/bin/gnome-shell", 0)) { return 0; }
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)peer->pid);
    size = readlink(path, exe, sizeof(exe) - 1);
    if (size <= 0 || size >= (ssize_t)sizeof(exe) - 1) { return 0; }
    exe[size] = 0;
    if (strcmp(exe, "/usr/bin/gnome-shell") != 0 || stat(path, &actual) != 0 ||
        stat("/usr/bin/gnome-shell", &expected) != 0 ||
        actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino ||
        !gnome_read_proc(peer->pid, "cgroup", cgroup, sizeof(cgroup), &cgroup_size) ||
        !gnome_read_proc(peer->pid, "cmdline", cmdline, sizeof(cmdline), &cmdline_size) ||
        !kvm_gnome_process_identity_matches(session, cgroup, cmdline, cmdline_size)) { return 0; }
    dir = opendir(runtime);
    if (!dir) { return 0; }
    while ((entry = readdir(dir)) != NULL && ++scanned <= 256 && gnome_now() < deadline)
    {
        struct ucred other;
        struct stat st;
        int fd, good = 1;
        const char *suffix;
        if (strncmp(entry->d_name, "wayland-", 8) != 0) { continue; }
        suffix = entry->d_name + 8;
        if (!*suffix) { continue; }
        for (const char *p = suffix; *p; p++) { if (*p < '0' || *p > '9') { good = 0; break; } }
        if (!good || snprintf(path, sizeof(path), "%s/%s", runtime, entry->d_name) >= (int)sizeof(path) ||
            lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != peer->uid) { continue; }
        fd = gnome_connect(path, &other);
        if (fd >= 0)
        {
            matched = other.pid == peer->pid && other.uid == peer->uid;
            close(fd);
            if (matched) { break; }
        }
    }
    closedir(dir);
    return matched;
}

void kvm_gnome_shutdown(void)
{
    if (g_gnome.fd >= 0) { close(g_gnome.fd); }
    free(g_gnome.rgb);
    if (g_gnome.png_library) { dlclose(g_gnome.png_library); }
    memset(&g_gnome, 0, sizeof(g_gnome)); g_gnome.fd = -1;
}

/* Keep an invalidated selected route distinct from an unavailable adapter.
 * Remaining events in this worker must not split a chord or text sequence
 * across GNOME and a fallback keyboard after an ambiguous delivery. Explicit
 * worker teardown/prepare resets this latch through kvm_gnome_shutdown(). */
static void gnome_invalidate(void)
{
    kvm_gnome_shutdown();
    g_gnome.failed = 1;
}

/* Authenticate using filesystem and kernel identity only. Never read endpoint
 * bytes here: the DRM fallback may still retain its capture capability. */
static int gnome_open_endpoint(const kvm_wayland_console_session *session, struct ucred *peer)
{
    char runtime[64], path[128];
    struct stat st;
    int fd;
    if (!session || session->uid <= 0 || !session->id[0] ||
        strcmp(session->type, "wayland") != 0 || !gnome_assets_trusted()) { return -1; }
    snprintf(runtime, sizeof(runtime), "/run/user/%d", session->uid);
    snprintf(path, sizeof(path), "%s/meshagent-gnome-prototype.sock", runtime);
    if (lstat(runtime, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != (uid_t)session->uid ||
        (st.st_mode & 0077) || lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        st.st_uid != (uid_t)session->uid || (st.st_mode & 0077)) { return -1; }
    fd = gnome_connect(path, peer);
    if (fd < 0) { return -1; }
    if (!gnome_peer_trusted(peer, runtime, session)) { close(fd); return -1; }
    return fd;
}

int kvm_gnome_endpoint_available(const kvm_wayland_console_session *session)
{
    struct ucred peer;
    kvm_wayland_console_session current;
    int fd, valid;
    if (!session || !kvm_wayland_active_console_session(&current) ||
        !kvm_wayland_console_session_equal(session, &current)) { return 0; }
    fd = gnome_open_endpoint(session, &peer);
    if (fd < 0) { return 0; }
    valid = kvm_wayland_active_console_session(&current) &&
        kvm_wayland_console_session_equal(session, &current);
    close(fd);
    return valid;
}

int kvm_gnome_prepare(const kvm_wayland_console_session *session)
{
    struct ucred peer;
    int fd;
    kvm_gnome_shutdown();
    if (geteuid() != 0) { return 0; }
    fd = gnome_open_endpoint(session, &peer);
    if (fd < 0) { return 0; }
    g_gnome.fd = fd; g_gnome.peer = peer.pid; g_gnome.session = *session;
    if (!gnome_session_valid()) { kvm_gnome_shutdown(); return 0; }
    return 1;
}

static int gnome_unprivileged(void)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct caps[2] = {{0}};
    uid_t r, e, s;
    gid_t gr, ge, gs;
    struct passwd *pw = getpwuid((uid_t)g_gnome.session.uid);
    if (!pw || getresuid(&r, &e, &s) != 0 || getresgid(&gr, &ge, &gs) != 0 ||
        r == 0 || r != (uid_t)g_gnome.session.uid || r != e || r != s ||
        gr != pw->pw_gid || gr != ge || gr != gs ||
        prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1 ||
        syscall(SYS_capget, &header, caps) != 0) { return 0; }
    for (int i = 0; i < 2; i++)
    { if (caps[i].effective || caps[i].permitted || caps[i].inheritable) { return 0; } }
    return 1;
}

static int gnome_read_reply(uint32_t op, kvm_gnome_reply *reply, uint64_t deadline)
{
    unsigned char header[KVM_GNOME_HEADER_SIZE + KVM_GNOME_MAX_MONITORS * 16];
    uint32_t count;
    if (!gnome_io(0, header, KVM_GNOME_HEADER_SIZE, deadline)) { return 0; }
    count = gnome_u32(header + 44);
    return count && count <= KVM_GNOME_MAX_MONITORS &&
        gnome_io(0, header + KVM_GNOME_HEADER_SIZE, (size_t)count * 16, deadline) &&
        kvm_gnome_decode_header(header, KVM_GNOME_HEADER_SIZE + (size_t)count * 16, reply) && reply->op == op;
}

static int gnome_send_frame_fd(int frame_fd, uint64_t deadline)
{
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    unsigned char marker = 0;
    struct iovec iov = { &marker, 1 };
    struct msghdr message = {0};
    struct cmsghdr *cmsg;
    memset(&control, 0, sizeof(control));
    message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    cmsg = CMSG_FIRSTHDR(&message); cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &frame_fd, sizeof(frame_fd));
    for (;;)
    {
        ssize_t n;
        if (!gnome_wait(g_gnome.fd, POLLOUT, deadline)) { return 0; }
        n = sendmsg(g_gnome.fd, &message, MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { continue; }
        return n == 1;
    }
}

static int gnome_request(const char *request, uint32_t op, kvm_gnome_reply *reply,
    unsigned char **payload)
{
    uint64_t now = gnome_now(), deadline;
    char timed_request[256];
    int frame_fd = -1;
    if (payload) { *payload = NULL; }
    if (!now || !gnome_session_valid() || !gnome_unprivileged()) { goto fail; }
    // The first request may arrive while a freshly logged-in Shell is still
    // loading its session. Bound that bootstrap separately from interactive
    // text roundtrips; no compositor data is read until the full privilege drop.
    deadline = now + (op == 1 && !g_gnome.active ? 5000 : (op == 3 || op == 4 ? 1500 : 400));
    if (op == 2 || op == 5)
    {
        size_t length = strlen(request);
        int written;
        if (length < 2 || request[length - 2] != '}' || request[length - 1] != '\n') { goto fail; }
        written = snprintf(timed_request, sizeof(timed_request), "%.*s,\"deadlineMs\":%llu}\n",
            (int)(length - 2), request, (unsigned long long)deadline);
        if (written < 0 || (size_t)written >= sizeof(timed_request)) { goto fail; }
        request = timed_request;
    }
    if (!gnome_io(1, (unsigned char *)request, strlen(request), deadline) ||
        !gnome_read_reply(op, reply, deadline) || !gnome_session_valid()) { goto fail; }
    if (op == 4 && reply->result == 3)
    {
        kvm_gnome_reply ready = *reply;
        off_t length;
        if (!payload || !(ready.flags & 16u) ||
            memcmp(ready.epoch, g_gnome.status.epoch, 16) || ready.revision != g_gnome.status.revision)
        { goto fail; }
#ifdef SYS_memfd_create
        frame_fd = (int)syscall(SYS_memfd_create, "meshagent-gnome-frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
#endif
        if (frame_fd < 0 || fchmod(frame_fd, 0600) || ftruncate(frame_fd, KVM_GNOME_MAX_PAYLOAD) ||
            fcntl(frame_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) ||
            !gnome_send_frame_fd(frame_fd, deadline) || !gnome_read_reply(op, reply, deadline) ||
            reply->result == 3 || !(reply->flags & 16u) || !gnome_session_valid() ||
            memcmp(reply->epoch, ready.epoch, 16) || reply->revision != ready.revision ||
            reply->width != ready.width || reply->height != ready.height || reply->count != ready.count ||
            memcmp(reply->monitors, ready.monitors, ready.count * sizeof(ready.monitors[0]))) { goto fail; }
        if (reply->result == 0)
        {
            // Make all future writes impossible before reading/decoding. A peer
            // retaining a writable mapping makes this fail, not race the parser.
            if (fcntl(frame_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SEAL) ||
                (length = lseek(frame_fd, 0, SEEK_CUR)) <= 0 || length > KVM_GNOME_MAX_PAYLOAD ||
                (*payload = malloc((size_t)length)) == NULL) { goto fail; }
            size_t offset = 0;
            while (offset < (size_t)length)
            {
                ssize_t n = pread(frame_fd, *payload + offset, (size_t)length - offset, (off_t)offset);
                if (n < 0 && errno == EINTR) { continue; }
                if (n <= 0) { goto fail; }
                offset += (size_t)n;
            }
            reply->payload_size = (uint32_t)length;
        }
        close(frame_fd); frame_fd = -1;
        return 1;
    }
    if (op == 4 && reply->result == 0) { goto fail; } // READY is mandatory.
    if (reply->payload_size)
    {
        if (!payload || (*payload = malloc(reply->payload_size)) == NULL ||
            !gnome_io(0, *payload, reply->payload_size, deadline) || !gnome_session_valid()) { goto fail; }
    }
    return 1;
fail:
    if (frame_fd >= 0) { close(frame_fd); }
    if (payload) { free(*payload); *payload = NULL; }
    if (g_gnome.active || g_gnome.failed) { gnome_invalidate(); }
    else { kvm_gnome_shutdown(); }
    return 0;
}

int kvm_gnome_activate(kvm_gnome_reply *status)
{
    if (!status || !gnome_request("{\"op\":\"status\",\"wire\":1,\"features\":7}\n", 1, status, NULL) || status->result || !(status->flags & 64u))
    { kvm_gnome_shutdown(); return 0; }
    g_gnome.status = *status; g_gnome.active = 1;
    return 1;
}

int kvm_gnome_drop_and_activate(kvm_gnome_reply *status)
{
    struct passwd *pw;
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct caps[2] = {{0}};
    if (geteuid() != 0 || !gnome_session_valid() ||
        (pw = getpwuid((uid_t)g_gnome.session.uid)) == NULL ||
        prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) != 0 ||
        setgroups(0, NULL) != 0 || setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0 ||
        setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0 ||
        syscall(SYS_capset, &header, caps) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
    { kvm_gnome_shutdown(); return 0; }
    if (pw->pw_dir && *pw->pw_dir) { setenv("HOME", pw->pw_dir, 1); }
    return kvm_gnome_activate(status);
}

int kvm_gnome_uses_uinput_keys(void)
{
    return g_gnome.active && !g_gnome.failed && !(g_gnome.status.flags & 32u);
}

int kvm_gnome_key_action(uint32_t code, int value)
{
    kvm_gnome_reply status, reply;
    char request[192], epoch[33];
    if (g_gnome.failed) { return -1; }
    if (!g_gnome.active || !(g_gnome.status.flags & 32u)) { return 0; }
    if (!code || code > 0x2ff || (value != 0 && value != 1)) { goto fail; }
    if (!gnome_request("{\"op\":\"status\",\"wire\":1}\n", 1, &status, NULL) || status.result ||
        !(status.flags & 32u) || !(status.flags & 64u) || memcmp(status.epoch, g_gnome.status.epoch, 16)) { goto fail; }
    for (int i = 0; i < 16; i++) { snprintf(epoch + i * 2, 3, "%02x", status.epoch[i]); }
    snprintf(request, sizeof(request), "{\"op\":\"key\",\"wire\":1,\"epoch\":\"%s\",\"revision\":%u,\"code\":%u,\"value\":%d}\n",
        epoch, status.revision, code, value);
    if (!gnome_request(request, 5, &reply, NULL) || reply.result || !(reply.flags & 64u) || memcmp(reply.epoch, status.epoch, 16)) { goto fail; }
    /* A key can itself lock the same Shell and advance its revision. It is
     * already delivered; acknowledge that transition without replay. */
    g_gnome.status = reply; return 1;
fail:
    gnome_invalidate(); return -1;
}

int kvm_gnome_type_unicode(uint32_t cp)
{
    char request[192], epoch[33], text[13];
    kvm_gnome_reply status, reply;
    if (g_gnome.failed) { return -1; }
    if (!g_gnome.active || cp < 0x20 || cp == 0x7f || cp > 0x10ffff ||
        (cp >= 0xd800 && cp <= 0xdfff)) { return 0; }
    if (!gnome_request("{\"op\":\"status\",\"wire\":1}\n", 1, &status, NULL) || status.result || !(status.flags & 64u)) { gnome_invalidate(); return -1; }
    if (memcmp(status.epoch, g_gnome.status.epoch, 16) != 0) { gnome_invalidate(); return -1; }
    for (int i = 0; i < 16; i++) { snprintf(epoch + i * 2, 3, "%02x", status.epoch[i]); }
    if (cp <= 0xffff) { snprintf(text, sizeof(text), "\\u%04x", cp); }
    else
    { cp -= 0x10000; snprintf(text, sizeof(text), "\\u%04x\\u%04x", 0xd800 + (cp >> 10), 0xdc00 + (cp & 1023)); }
    snprintf(request, sizeof(request), "{\"op\":\"text\",\"wire\":1,\"epoch\":\"%s\",\"revision\":%u,\"text\":\"%s\"}\n",
        epoch, status.revision, text);
    /* Once text is sent, any decline, timeout or broken reply means discard.
     * Never fall back and risk duplicate or cross-generation delivery. */
    if (!gnome_request(request, 2, &reply, NULL) || reply.result || !(reply.flags & 64u) ||
        memcmp(reply.epoch, status.epoch, 16) != 0 || reply.revision != status.revision) { return -1; }
    g_gnome.status = reply; return 1;
}

int kvm_gnome_frame(const unsigned char **rgb, uint32_t *width, uint32_t *height, kvm_gnome_reply *layout)
{
    kvm_gnome_reply reply;
    unsigned char *png = NULL, *pixels = NULL;
    png_image image;
    char request[192], epoch[33];
    uint32_t op = g_gnome.status.flags & 16u ? 4 : 3;
    for (int i = 0; i < 16; i++) { snprintf(epoch + i * 2, 3, "%02x", g_gnome.status.epoch[i]); }
    snprintf(request, sizeof(request), "{\"op\":\"%s\",\"wire\":1,\"epoch\":\"%s\",\"revision\":%u}\n",
        op == 4 ? "captureFd" : "capture", epoch, g_gnome.status.revision);
    if (rgb) { *rgb = NULL; }
    if (!g_gnome.active || !rgb || !width || !height || !layout ||
        !gnome_request(request, op, &reply, &png) ||
        memcmp(reply.epoch, g_gnome.status.epoch, 16) != 0) { goto fail; }
    if (reply.result == 2 && (reply.flags & 12u))
    { *layout = reply; g_gnome.status = reply; return 2; }
    if (reply.result) { goto fail; }
    if (!g_gnome.png_library)
    {
        g_gnome.png_library = dlopen("libpng16.so.16", RTLD_NOW | RTLD_LOCAL);
        if (!g_gnome.png_library) { goto fail; }
        *(void **)(&g_gnome.png_begin) = dlsym(g_gnome.png_library, "png_image_begin_read_from_memory");
        *(void **)(&g_gnome.png_finish) = dlsym(g_gnome.png_library, "png_image_finish_read");
        *(void **)(&g_gnome.png_free) = dlsym(g_gnome.png_library, "png_image_free");
        if (!g_gnome.png_begin || !g_gnome.png_finish || !g_gnome.png_free) { goto fail; }
    }
    memset(&image, 0, sizeof(image)); image.version = PNG_IMAGE_VERSION;
    if (!g_gnome.png_begin(&image, png, reply.payload_size)) { g_gnome.png_free(&image); goto fail; }
    image.format = PNG_FORMAT_RGB;
    if (!image.width || !image.height || image.width > 16384 || image.height > 16384 ||
        (uint64_t)image.width * image.height > KVM_GNOME_MAX_PIXELS ||
        (uint64_t)image.width * reply.height != (uint64_t)image.height * reply.width ||
        (pixels = malloc((size_t)image.width * image.height * 3)) == NULL ||
        !g_gnome.png_finish(&image, NULL, pixels, 0, NULL) || !gnome_session_valid())
    { g_gnome.png_free(&image); goto fail; }
    *width = image.width; *height = image.height; g_gnome.png_free(&image);
    free(png); free(g_gnome.rgb); g_gnome.rgb = pixels;
    g_gnome.status = reply; *layout = reply; *rgb = pixels;
    return 1;
fail:
    free(png); free(pixels); gnome_invalidate(); return 0;
}
