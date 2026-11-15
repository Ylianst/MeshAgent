/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_kvm_pipewire.h"

#if defined(__linux__)
#include "linux_kvm_capture.h"
#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>
#include <spa/param/buffers.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define KVM_PW_MAX_STREAMS 32
#define KVM_PW_START_TIMEOUT_MS 5000
#define KVM_PW_PING_INTERVAL_MS 1000
#define KVM_PW_PING_TIMEOUT_MS 2000
#define KVM_PW_API(X) X(pw_init) X(pw_main_loop_new) X(pw_main_loop_get_loop) \
    X(pw_main_loop_destroy) X(pw_context_new) X(pw_context_destroy) \
    X(pw_context_connect_fd) X(pw_core_disconnect) X(pw_properties_new) \
    X(pw_stream_new) X(pw_stream_add_listener) X(pw_stream_connect) \
    X(pw_stream_update_params) X(pw_stream_dequeue_buffer) X(pw_stream_queue_buffer) \
    X(pw_stream_destroy)
#define DECLARE(name) static __typeof__(&name) p_##name;
KVM_PW_API(DECLARE)
#undef DECLARE
static void *pw_library;
static int pw_unavailable;
static int pw_initialized;

static void pwcap_note(const char *stage)
{
    const char *debug = getenv("MESH_KVM_DRM_DEBUG");
    if (debug != NULL && atoi(debug) > 0) { fprintf(stderr, "PipeWire capture: %s\n", stage); }
}

struct kvm_pipewire_stream
{
    struct kvm_pipewire_capture *capture;
    struct pw_stream *stream;
    struct spa_hook listener;
    struct spa_video_info_raw format;
    unsigned char *rgb;
    size_t rgb_size;
    uint64_t serial, waiting_since_ms, revision;
    int ready, streaming;
};

struct kvm_pipewire_capture
{
    struct pw_main_loop *mainloop;
    struct pw_loop *loop;
    struct pw_context *context;
    struct pw_core *core;
    struct spa_hook listener;
    struct kvm_pipewire_stream streams[KVM_PW_MAX_STREAMS];
    size_t allocated;
    unsigned int count;
    uint64_t last_ping_ms, pending_since_ms;
    int failed, pending, sequence;
};

static uint64_t pwcap_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int pwcap_unprivileged(void)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {{0}};
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid == 0 || real_uid != effective_uid || real_uid != saved_uid ||
        real_gid != effective_gid || real_gid != saved_gid ||
        syscall(SYS_capget, &header, data) != 0) { return 0; }
    return !(data[0].effective | data[0].permitted | data[0].inheritable |
        data[1].effective | data[1].permitted | data[1].inheritable);
}

/* A capture worker may hold uinput/DRM descriptors even after dropping caps.
 * Do not execute session-owned PipeWire configuration or plugin overrides in
 * that process. An absolute prefix selects the installed vendor client config
 * and its vendor drop-ins, excluding HOME, XDG_CONFIG_HOME and /etc overrides.
 * This affects this worker's environment only, never desktop configuration.
 */
static int pwcap_environment(void)
{
    extern char **environ;
    for (size_t i = 0; environ[i] != NULL; )
    {
        if (strncmp(environ[i], "PIPEWIRE_", 9) == 0 || strncmp(environ[i], "SPA_", 4) == 0)
        {
            const char *equals = strchr(environ[i], '=');
            char *name;
            int result;
            if (equals == NULL || (name = strndup(environ[i], (size_t)(equals - environ[i]))) == NULL) { return 0; }
            result = unsetenv(name);
            free(name);
            if (result != 0) { return 0; }
            i = 0;
        }
        else { ++i; }
    }
    return setenv("PIPEWIRE_CONFIG_PREFIX", "/usr/share/pipewire", 1) == 0 &&
        setenv("PIPEWIRE_CONFIG_NAME", "client.conf", 1) == 0;
}

static int pwcap_vendor_path(const char *path, int directory)
{
    struct stat st;
    if (lstat(path, &st) != 0) { return 0; }
    if (st.st_uid != 0 || (st.st_mode & 0022) ||
        !(directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode)))
    { errno = EACCES; return 0; }
    return 1;
}

static int pwcap_vendor_config(void)
{
    DIR *directory;
    struct dirent *entry;
    char path[512];
    int good = 1;
    if (!pwcap_vendor_path("/usr", 1) || !pwcap_vendor_path("/usr/share", 1) ||
        !pwcap_vendor_path("/usr/share/pipewire", 1) ||
        !pwcap_vendor_path("/usr/share/pipewire/client.conf", 0)) { return 0; }
    if (!pwcap_vendor_path("/usr/share/pipewire/client.conf.d", 1)) { return errno == ENOENT; }
    directory = opendir("/usr/share/pipewire/client.conf.d");
    if (directory == NULL) { return 0; }
    for (;;)
    {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) { if (errno != 0) { good = 0; } break; }
        size_t length = strlen(entry->d_name);
        if (length < 5 || strcmp(entry->d_name + length - 5, ".conf") != 0) { continue; }
        if (snprintf(path, sizeof(path), "/usr/share/pipewire/client.conf.d/%s", entry->d_name) >= (int)sizeof(path) ||
            !pwcap_vendor_path(path, 0)) { good = 0; break; }
    }
    closedir(directory);
    return good;
}

static int pwcap_load(void)
{
    void *library;
    if (pw_library != NULL) { return 1; }
    if (pw_unavailable || !pwcap_vendor_config() || !pwcap_environment()) { return 0; }
    library = dlopen("libpipewire-0.3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) { pw_unavailable = 1; return 0; }
#define LOAD(name) p_##name = (__typeof__(p_##name))dlsym(library, #name); if (p_##name == NULL) { goto fail; }
    KVM_PW_API(LOAD)
#undef LOAD
    pw_library = library;
    return 1;
fail:
    dlclose(library);
    pw_unavailable = 1;
    return 0;
}

/* Connect the validated per-user socket ourselves instead of allowing remote
 * selection through environment/configuration. connect_fd takes its ownership.
 */
static int pwcap_socket(void)
{
    struct sockaddr_un address;
    struct ucred peer;
    struct stat st;
    socklen_t size = sizeof(peer);
    char runtime[64];
    int fd;
    snprintf(runtime, sizeof(runtime), "/run/user/%u", (unsigned)geteuid());
    if (lstat(runtime, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077)) { return -1; }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/pipewire-0", runtime);
    if (lstat(address.sun_path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) { return -1; }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { return -1; }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        size != sizeof(peer) || peer.uid != geteuid())
    { close(fd); return -1; }
    return fd;
}

int kvm_pipewire_capture_available(void)
{
    int fd;
    if (geteuid() == 0 || !pwcap_load() || (fd = pwcap_socket()) < 0) { return 0; }
    close(fd);
    return 1;
}

static void pwcap_done(void *data, uint32_t id, int seq)
{
    kvm_pipewire_capture *capture = data;
    if (id == PW_ID_CORE && capture->pending && seq == capture->sequence)
    { capture->pending = 0; }
}

static void pwcap_error(void *data, uint32_t id, int seq, int res, const char *message)
{
    kvm_pipewire_capture *capture = data;
    (void)id; (void)seq; (void)res; (void)message;
    capture->failed = 1;
}

static const struct pw_core_events pwcap_core_events = {
    .version = PW_VERSION_CORE_EVENTS, .done = pwcap_done, .error = pwcap_error
};

static void pwcap_state(void *data, enum pw_stream_state old, enum pw_stream_state state, const char *error)
{
    kvm_pipewire_stream *stream = data;
    (void)error;
    if (state == PW_STREAM_STATE_ERROR ||
        (state == PW_STREAM_STATE_UNCONNECTED && old != PW_STREAM_STATE_UNCONNECTED))
    { stream->capture->failed = 1; }
    stream->streaming = state == PW_STREAM_STATE_STREAMING;
    if (!stream->streaming)
    {
        stream->ready = 0;
        if (!stream->waiting_since_ms) { stream->waiting_since_ms = pwcap_now(); }
    }
}

static void pwcap_format(void *data, uint32_t id, const struct spa_pod *param)
{
    kvm_pipewire_stream *stream = data;
    struct spa_video_info_raw next = {0};
    unsigned char storage[512];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(storage, sizeof(storage));
    const struct spa_pod *params[1];
    size_t size;
    if (id != SPA_PARAM_Format) { return; }
    stream->ready = 0;
    stream->waiting_since_ms = pwcap_now();
    memset(&stream->format, 0, sizeof(stream->format));
    if (param == NULL) { return; }
    if (spa_format_video_raw_parse(param, &next) < 0 ||
        (next.format != SPA_VIDEO_FORMAT_BGRx && next.format != SPA_VIDEO_FORMAT_BGRA) ||
        !kvm_capture_checked_pixel_size(next.size.width, next.size.height, 4, &size))
    { stream->capture->failed = 1; return; }
    stream->format = next;
    params[0] = spa_pod_builder_add_object(&builder, SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
        SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(4, 2, 8),
        SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(1),
        SPA_PARAM_BUFFERS_size, SPA_POD_Int((int32_t)size),
        SPA_PARAM_BUFFERS_stride, SPA_POD_Int(next.size.width * 4),
        SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int((1 << SPA_DATA_MemFd) | (1 << SPA_DATA_MemPtr)));
    if (params[0] == NULL || p_pw_stream_update_params(stream->stream, params, 1) < 0)
    { stream->capture->failed = 1; }
}

/* Validate the complete image before reading even one pixel. Positive padded
 * strides and nonzero offsets are supported; wrapping, partial, empty and
 * corrupt frames are never presented as a complete desktop.
 */
static int pwcap_buffer_view(const struct spa_buffer *buffer, uint32_t width, uint32_t height,
    const unsigned char **pixels, uint32_t *stride)
{
    const struct spa_data *data;
    uint64_t required;
    size_t size;
    if (!kvm_capture_checked_pixel_size(width, height, 4, &size) || buffer == NULL ||
        buffer->n_datas != 1 || buffer->datas == NULL ||
        buffer->n_metas > 64 || (buffer->n_metas && buffer->metas == NULL)) { return 0; }
    data = buffer->datas;
    if ((data->type != SPA_DATA_MemFd && data->type != SPA_DATA_MemPtr) ||
        data->data == NULL || data->chunk == NULL ||
        data->chunk->flags != SPA_CHUNK_FLAG_NONE ||
        data->chunk->stride < (int32_t)(width * 4) ||
        data->maxsize > KVM_CAPTURE_MAX_BUFFER_BYTES) { return 0; }
    required = (uint64_t)(height - 1) * (uint32_t)data->chunk->stride + width * 4;
    if (data->chunk->offset > data->maxsize || required > data->maxsize - data->chunk->offset ||
        required > data->chunk->size || data->chunk->size > data->maxsize - data->chunk->offset) { return 0; }
    for (uint32_t i = 0; i < buffer->n_metas; ++i)
    {
        const struct spa_meta *meta = &buffer->metas[i];
        if (meta->type == SPA_META_Header)
        {
            const struct spa_meta_header *header = meta->data;
            if (header == NULL || meta->size < sizeof(*header) ||
                (header->flags & (SPA_META_HEADER_FLAG_CORRUPTED | SPA_META_HEADER_FLAG_GAP | SPA_META_HEADER_FLAG_DELTA_UNIT))) { return 0; }
        }
        /* Cropped/transformed streams need explicit coordinate handling. The
         * output source we request already supplies the composed orientation.
         * Refuse unexpected metadata rather than silently mis-map input.
         */
        else if (meta->type == SPA_META_VideoCrop || meta->type == SPA_META_VideoTransform)
        { return 0; }
    }
    *pixels = (const unsigned char *)data->data + data->chunk->offset;
    *stride = (uint32_t)data->chunk->stride;
    return 1;
}

static void pwcap_process(void *data)
{
    kvm_pipewire_stream *stream = data;
    kvm_pipewire_capture *capture = stream->capture;
    struct pw_buffer *buffer = p_pw_stream_dequeue_buffer(stream->stream);
    const unsigned char *pixels;
    uint32_t stride, width = stream->format.size.width, height = stream->format.size.height;
    size_t size;
    if (buffer == NULL) { return; }
    if (capture->failed) { goto out; }
    if (!pwcap_buffer_view(buffer->buffer, width, height, &pixels, &stride) ||
        !kvm_capture_checked_rgb_size(width, height, &size)) { goto fail; }
    if (size != stream->rgb_size)
    {
        unsigned char *next;
        if (size > KVM_CAPTURE_MAX_BUFFER_BYTES - (capture->allocated - stream->rgb_size)) { goto fail; }
        next = realloc(stream->rgb, size);
        if (next == NULL) { goto fail; }
        capture->allocated = capture->allocated - stream->rgb_size + size;
        stream->rgb = next;
        stream->rgb_size = size;
    }
    for (uint32_t y = 0; y < height; ++y)
    {
        const unsigned char *src = pixels + (size_t)y * stride;
        unsigned char *dst = stream->rgb + (size_t)y * width * 3;
        kvm_capture_rgb32_row(dst, src, width, 2, 1, 0);
    }
    if (++stream->revision == 0) ++stream->revision;
    stream->ready = 1;
    stream->waiting_since_ms = 0;
    goto out;
fail:
    stream->ready = 0;
    capture->failed = 1;
out:
    if (p_pw_stream_queue_buffer(stream->stream, buffer) < 0) { capture->failed = 1; }
}

static const struct pw_stream_events pwcap_stream_events = {
    .version = PW_VERSION_STREAM_EVENTS, .state_changed = pwcap_state,
    .param_changed = pwcap_format, .process = pwcap_process
};

kvm_pipewire_capture *kvm_pipewire_capture_new(void)
{
    kvm_pipewire_capture *capture;
    struct pw_properties *properties;
    struct stat original, after;
    int fd, transferred;
    if (!pwcap_unprivileged() || prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        !pwcap_load() || (fd = pwcap_socket()) < 0) { return NULL; }
    pwcap_note("initializing installed libraries");
    if (!pw_initialized) { p_pw_init(NULL, NULL); pw_initialized = 1; }
    capture = calloc(1, sizeof(*capture));
    if (capture == NULL) { close(fd); return NULL; }
    pwcap_note("creating event loop");
    if ((capture->mainloop = p_pw_main_loop_new(NULL)) == NULL) { goto fail_fd; }
    capture->loop = p_pw_main_loop_get_loop(capture->mainloop);
    pwcap_note("creating vendor-configured context");
    /* Video is consumed on this worker's ordinary event loop. Do not request
     * real-time scheduling or make portal/RTKit authorization calls. */
    properties = p_pw_properties_new("module.rt", "false", "support.dbus", "false", NULL);
    if (properties == NULL || (capture->context = p_pw_context_new(capture->loop, properties, 0)) == NULL) { goto fail_fd; }
    /* Some supported PipeWire versions leave the fd open if core allocation
     * fails, but close it on later failures. Keep a reference and compare the
     * socket inode before reclaiming a failed transfer; never close a reused fd.
     */
    if (fstat(fd, &original) != 0 || (transferred = fcntl(fd, F_DUPFD_CLOEXEC, 3)) < 0) { goto fail_fd; }
    pwcap_note("connecting validated PipeWire socket");
    capture->core = p_pw_context_connect_fd(capture->context, transferred, NULL, 0);
    if (capture->core == NULL && fstat(transferred, &after) == 0 &&
        S_ISSOCK(after.st_mode) && original.st_dev == after.st_dev && original.st_ino == after.st_ino)
    { close(transferred); }
    close(fd);
    if (capture->core == NULL) { kvm_pipewire_capture_destroy(capture); return NULL; }
    pw_core_add_listener(capture->core, &capture->listener, &pwcap_core_events, capture);
    return capture;
fail_fd:
    close(fd);
    kvm_pipewire_capture_destroy(capture);
    return NULL;
}

kvm_pipewire_stream *kvm_pipewire_capture_add(kvm_pipewire_capture *capture, uint64_t serial)
{
    kvm_pipewire_stream *stream;
    struct pw_properties *properties;
    unsigned char storage[1024];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(storage, sizeof(storage));
    const struct spa_pod *params[1];
    char target[32];
    if (capture == NULL || capture->failed || serial == 0 || capture->count >= KVM_PW_MAX_STREAMS) { return NULL; }
    for (unsigned int i = 0; i < capture->count; ++i)
    { if (capture->streams[i].serial == serial) { return NULL; } }
    stream = &capture->streams[capture->count++];
    stream->capture = capture;
    stream->serial = serial;
    stream->waiting_since_ms = pwcap_now();
    snprintf(target, sizeof(target), "%" PRIu64, serial);
    properties = p_pw_properties_new(PW_KEY_MEDIA_TYPE, "Video", PW_KEY_MEDIA_CATEGORY, "Capture",
        PW_KEY_MEDIA_ROLE, "Screen", PW_KEY_TARGET_OBJECT, target, NULL);
    if (properties == NULL) { goto fail; }
    stream->stream = p_pw_stream_new(capture->core, "MeshCentral console", properties);
    if (stream->stream == NULL) { goto fail; }
    p_pw_stream_add_listener(stream->stream, &stream->listener, &pwcap_stream_events, stream);
    params[0] = spa_pod_builder_add_object(&builder, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
        SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video), SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        SPA_FORMAT_VIDEO_format, SPA_POD_CHOICE_ENUM_Id(3, SPA_VIDEO_FORMAT_BGRx, SPA_VIDEO_FORMAT_BGRx, SPA_VIDEO_FORMAT_BGRA),
        SPA_FORMAT_VIDEO_size, SPA_POD_CHOICE_RANGE_Rectangle(&SPA_RECTANGLE(1024, 768), &SPA_RECTANGLE(1, 1), &SPA_RECTANGLE(KVM_CAPTURE_MAX_DIMENSION, KVM_CAPTURE_MAX_DIMENSION)),
        SPA_FORMAT_VIDEO_framerate, SPA_POD_CHOICE_RANGE_Fraction(&SPA_FRACTION(30, 1), &SPA_FRACTION(0, 1), &SPA_FRACTION(60, 1)));
    if (params[0] == NULL || p_pw_stream_connect(stream->stream, PW_DIRECTION_INPUT, PW_ID_ANY,
        PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_DONT_RECONNECT, params, 1) < 0) { goto fail; }
    return stream;
fail:
    capture->failed = 1;
    return NULL;
}

int kvm_pipewire_capture_pump(kvm_pipewire_capture *capture)
{
    uint64_t now;
    int result;
    if (capture == NULL || capture->failed) { return -1; }
    pw_loop_enter(capture->loop);
    result = pw_loop_iterate(capture->loop, 0);
    pw_loop_leave(capture->loop);
    now = pwcap_now();
    if ((result < 0 && result != -EINTR) || now == 0 ||
        (capture->pending && (now < capture->pending_since_ms || now - capture->pending_since_ms >= KVM_PW_PING_TIMEOUT_MS)))
    { capture->failed = 1; }
    for (unsigned int i = 0; i < capture->count; ++i)
    {
        uint64_t started = capture->streams[i].waiting_since_ms;
        if (started && (now < started || now - started >= KVM_PW_START_TIMEOUT_MS)) { capture->failed = 1; }
    }
    if (!capture->failed && !capture->pending &&
        (capture->last_ping_ms == 0 || now - capture->last_ping_ms >= KVM_PW_PING_INTERVAL_MS))
    {
        capture->sequence = pw_core_sync(capture->core, PW_ID_CORE, capture->sequence);
        if (capture->sequence < 0) { capture->failed = 1; }
        else
        {
            capture->pending = 1;
            capture->last_ping_ms = capture->pending_since_ms = now;
        }
    }
    return capture->failed ? -1 : 1;
}

int kvm_pipewire_capture_frame(kvm_pipewire_stream *stream, const unsigned char **rgb, uint32_t *width, uint32_t *height)
{
    if (rgb == NULL || width == NULL || height == NULL) { return -1; }
    *rgb = NULL; *width = *height = 0;
    if (stream == NULL || stream->capture->failed) { return -1; }
    if (!stream->ready || !stream->streaming) { return 0; }
    *rgb = stream->rgb;
    *width = stream->format.size.width;
    *height = stream->format.size.height;
    return 1;
}

uint64_t kvm_pipewire_capture_revision(kvm_pipewire_stream *stream)
{ return stream && stream->ready && stream->streaming ? stream->revision : 0; }

void kvm_pipewire_capture_discard_frame(kvm_pipewire_stream *stream)
{
    if (stream == NULL) { return; }
    stream->ready = 0;
    stream->waiting_since_ms = pwcap_now();
}

void kvm_pipewire_capture_destroy(kvm_pipewire_capture *capture)
{
    if (capture == NULL) { return; }
    for (unsigned int i = 0; i < capture->count; ++i)
    {
        if (capture->streams[i].stream != NULL) { p_pw_stream_destroy(capture->streams[i].stream); }
        free(capture->streams[i].rgb);
    }
    if (capture->core != NULL) { p_pw_core_disconnect(capture->core); }
    if (capture->context != NULL) { p_pw_context_destroy(capture->context); }
    if (capture->mainloop != NULL) { p_pw_main_loop_destroy(capture->mainloop); }
    free(capture);
}
#else
#include <stddef.h>
uint64_t kvm_pipewire_capture_revision(kvm_pipewire_stream *s) { (void)s; return 0; }
int kvm_pipewire_capture_available(void) { return 0; }
kvm_pipewire_capture *kvm_pipewire_capture_new(void) { return NULL; }
kvm_pipewire_stream *kvm_pipewire_capture_add(kvm_pipewire_capture *c, uint64_t s) { (void)c; (void)s; return NULL; }
int kvm_pipewire_capture_pump(kvm_pipewire_capture *c) { (void)c; return -1; }
int kvm_pipewire_capture_frame(kvm_pipewire_stream *s, const unsigned char **p, uint32_t *w, uint32_t *h)
{ (void)s; if (p) *p = NULL; if (w) *w = 0; if (h) *h = 0; return -1; }
void kvm_pipewire_capture_discard_frame(kvm_pipewire_stream *s) { (void)s; }
void kvm_pipewire_capture_destroy(kvm_pipewire_capture *c) { (void)c; }
#endif
