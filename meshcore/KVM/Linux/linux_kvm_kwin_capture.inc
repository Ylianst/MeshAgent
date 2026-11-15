/* SPDX-License-Identifier: Apache-2.0 */
/* Included by linux_kvm_drm.c to share its validated output/layout types and
 * optional Wayland ABI. KWin screencast v6 supplies stable PipeWire serials.
 * This private protocol requires independent compositor-version qualification.
 */

typedef struct kvm_drm_kwin_capture kvm_drm_kwin_capture;
typedef struct kvm_drm_kwin_stream
{
    kvm_drm_kwin_capture *capture;
    struct wl_proxy *proxy;
    kvm_pipewire_stream *consumer;
    uint64_t serial;
    int created;
} kvm_drm_kwin_stream;

struct kvm_drm_kwin_capture
{
    kvm_drm_wayland_layout_context layout;
    kvm_drm_wayland_output snapshot[KVM_DRM_MAX_OUTPUTS];
    kvm_drm_kwin_stream streams[KVM_DRM_MAX_OUTPUTS];
    kvm_wayland_console_session session;
    kvm_pipewire_capture *pipewire;
    struct wl_proxy *manager;
    struct wl_callback *sync;
    uint32_t manager_name;
    uint64_t started_ms, sync_started_ms, last_sync_ms;
    int output_map[KVM_DRM_MAX_OUTPUTS];
    int sealed, failed;
};

static const struct wl_interface kvm_kwin_stream_interface;
static const struct wl_interface *kvm_kwin_output_types[] = { &kvm_kwin_stream_interface, NULL, NULL };
static const struct wl_interface *kvm_kwin_window_types[] = { &kvm_kwin_stream_interface, NULL, NULL };
/* Only the first three request opcodes are used; no virtual outputs/windows are created. */
static const struct wl_message kvm_kwin_requests[] = {
    { "stream_output", "nou", kvm_kwin_output_types },
    { "stream_window", "nsu", kvm_kwin_window_types },
    { "destroy", "", NULL }
};
static const struct wl_interface kvm_kwin_manager_interface = {
    "zkde_screencast_unstable_v1", 6, 3, kvm_kwin_requests, 0, NULL
};
static const struct wl_message kvm_kwin_stream_requests[] = { { "close", "", NULL } };
static const struct wl_message kvm_kwin_stream_events[] = {
    { "closed", "", NULL }, { "created", "u", NULL },
    { "failed", "s", NULL }, { "serial", "6uu", NULL }
};
static const struct wl_interface kvm_kwin_stream_interface = {
    "zkde_screencast_stream_unstable_v1", 6, 1, kvm_kwin_stream_requests, 4, kvm_kwin_stream_events
};

static void kvm_kwin_closed(void *data, struct wl_proxy *proxy)
{ (void)proxy; ((kvm_drm_kwin_stream *)data)->capture->failed = 1; }
static void kvm_kwin_created(void *data, struct wl_proxy *proxy, uint32_t node)
{
    kvm_drm_kwin_stream *stream = data;
    (void)proxy; (void)node;
    if (stream->created || stream->serial == 0) { stream->capture->failed = 1; }
    stream->created = 1;
}
static void kvm_kwin_failed(void *data, struct wl_proxy *proxy, const char *message)
{ (void)message; kvm_kwin_closed(data, proxy); }
static void kvm_kwin_serial(void *data, struct wl_proxy *proxy, uint32_t high, uint32_t low)
{
    kvm_drm_kwin_stream *stream = data;
    (void)proxy;
    if (stream->serial != 0 || stream->created) { stream->capture->failed = 1; }
    stream->serial = ((uint64_t)high << 32) | low;
}
static const struct {
    void (*closed)(void *, struct wl_proxy *);
    void (*created)(void *, struct wl_proxy *, uint32_t);
    void (*failed)(void *, struct wl_proxy *, const char *);
    void (*serial)(void *, struct wl_proxy *, uint32_t, uint32_t);
} kvm_kwin_stream_listener = { kvm_kwin_closed, kvm_kwin_created, kvm_kwin_failed, kvm_kwin_serial };

static void kvm_kwin_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
    kvm_drm_kwin_capture *capture = data;
    if (strcmp(interface, "zkde_screencast_unstable_v1") == 0)
    {
        /* Newer servers retain the v6 wire contract. Bind only that known
         * version; do not reject a compatible server for advertising more. */
        if (version < 6 || capture->manager != NULL) { return; }
        capture->manager = kvm_wl_registry_bind(registry, name, &kvm_kwin_manager_interface, 6);
        capture->manager_name = name;
    }
    else if (strcmp(interface, "wl_output") == 0 || strcmp(interface, "zxdg_output_manager_v1") == 0)
    {
        if (capture->sealed ||
            (strcmp(interface, "wl_output") == 0 && capture->layout.output_count >= KVM_DRM_MAX_OUTPUTS))
        { capture->failed = 1; return; }
        kvm_drm_registry_global(&capture->layout, registry, name, interface, version);
    }
}
static void kvm_kwin_removed(void *data, struct wl_registry *registry, uint32_t name)
{
    kvm_drm_kwin_capture *capture = data;
    (void)registry;
    if (name == capture->manager_name) { capture->failed = 1; }
    for (int i = 0; i < capture->layout.output_count; ++i)
    { if (name == capture->layout.outputs[i].global_name) { capture->failed = 1; } }
}
static const struct wl_registry_listener kvm_kwin_registry_listener = { kvm_kwin_global, kvm_kwin_removed };

static struct wl_display *kvm_kwin_connect_display(const kvm_wayland_console_session *session)
{
    int fd = kvm_capture_worker_connect(session, getenv("WAYLAND_DISPLAY"));
    if (fd < 0) return NULL;
    /* libwayland owns fd on both success and failure. */
    return p_wl_display_connect_to_fd(fd);
}

static void kvm_kwin_destroy(kvm_drm_kwin_capture *capture)
{
    if (capture == NULL) { return; }
    kvm_pipewire_capture_destroy(capture->pipewire);
    if (capture->sync != NULL) { wl_proxy_destroy((struct wl_proxy *)capture->sync); }
    for (int i = 0; i < capture->layout.output_count; ++i)
    {
        if (capture->streams[i].proxy != NULL)
        {
            wl_proxy_marshal_array(capture->streams[i].proxy, 0, NULL);
            wl_proxy_destroy(capture->streams[i].proxy);
        }
    }
    if (capture->manager != NULL)
    {
        wl_proxy_marshal_array(capture->manager, 2, NULL);
        wl_proxy_destroy(capture->manager);
    }
    kvm_drm_wayland_layout_context_cleanup(&capture->layout);
    kvm_capture_worker_release();
    free(capture);
}

static int kvm_kwin_session_valid(const kvm_drm_kwin_capture *capture)
{
    kvm_wayland_console_session current;
    return kvm_wayland_active_console_session(&current) &&
        kvm_wayland_console_session_equal(&current, &capture->session);
}

static int kvm_kwin_match_outputs(kvm_drm_kwin_capture *capture, const kvm_drm_output *outputs, int output_count)
{
    if (outputs == NULL || output_count <= 0 || output_count > KVM_DRM_MAX_OUTPUTS ||
        capture->layout.output_count != output_count) { return 0; }
    for (int i = 0; i < output_count; ++i)
    {
        int match = -1;
        for (int j = 0; j < output_count; ++j)
        {
            const kvm_drm_wayland_output *output = &capture->layout.outputs[j];
            if (output->have_name && kvm_drm_connector_name_equal(outputs[i].connector_name, output->name))
            {
                if (match >= 0) { return 0; }
                match = j;
            }
        }
        if (match < 0) { return 0; }
        const kvm_drm_wayland_output *output = &capture->layout.outputs[match];
        if (!output->have_position || !output->have_size || outputs[i].x != output->x || outputs[i].y != output->y ||
            outputs[i].width != output->width || outputs[i].height != output->height ||
            outputs[i].rotation != kvm_drm_rotation_from_wl_transform(output->transform)) { return 0; }
        for (int j = 0; j < i; ++j) { if (capture->output_map[j] == match) { return 0; } }
        capture->output_map[i] = match;
    }
    return 1;
}

/* Returns 0 if unavailable, 1 selected, -1 after committing to the capability-
 * free compositor path and encountering an error. No DRM fallback in that
 * worker after its DRM capability has been removed; normal worker recovery
 * opens a new generation. This never changes installed packages or settings.
 */
static int kvm_kwin_open(kvm_drm_kwin_capture **out, const kvm_drm_output *outputs, int output_count,
    const kvm_wayland_console_session *session)
{
    kvm_drm_kwin_capture *capture;
    uint64_t deadline;
    int committed = 0;
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct caps[2] = {{0}};
    *out = NULL;
    if (session->id[0] == 0 || session->uid <= 0 || session->uid != (int)geteuid() ||
        strcmp(session->type, "wayland") != 0 || !kvm_drm_load_wayland()) { return 0; }
    capture = calloc(1, sizeof(*capture));
    if (capture == NULL) { return 0; }
    capture->session = *session;
    if (drm_debug) { fprintf(stderr, "KWin: connecting validated display\n"); }
    capture->layout.display = kvm_kwin_connect_display(session);
    if (capture->layout.display == NULL) { goto fail; }
    capture->layout.registry = kvm_wl_display_get_registry(capture->layout.display);
    if (capture->layout.registry == NULL ||
        kvm_wl_registry_add_listener(capture->layout.registry, &kvm_kwin_registry_listener, capture) < 0) { goto fail; }
    deadline = kvm_drm_now_ms() + KVM_DRM_XDG_QUERY_TIMEOUT_MS;
    if (drm_debug) { fprintf(stderr, "KWin: querying capture protocol and outputs\n"); }
    if (!kvm_drm_wl_roundtrip_deadline(capture->layout.display, deadline) || capture->manager == NULL ||
        capture->layout.output_count != output_count || capture->layout.xdg_output_manager == NULL ||
        !kvm_pipewire_capture_available()) { goto fail; }
    if (!kvm_capture_worker_seal()) { goto fail; }
    if (drm_debug) { fprintf(stderr, "KWin: querying logical output identities\n"); }
    for (int i = 0; i < output_count; ++i)
    {
        kvm_drm_wayland_output *output = &capture->layout.outputs[i];
        if (output->wl_output == NULL) { goto fail; }
        output->xdg_output = zxdg_output_manager_v1_get_xdg_output(capture->layout.xdg_output_manager, output->wl_output);
        if (output->xdg_output == NULL ||
            zxdg_output_v1_add_listener(output->xdg_output, &kvm_drm_xdg_output_listener, output) < 0) { goto fail; }
    }
    for (int i = 0; i < 3; ++i)
    { if (!kvm_drm_wl_roundtrip_deadline(capture->layout.display, deadline)) { goto fail; } }
    if (capture->failed || !kvm_kwin_session_valid(capture) ||
        !kvm_kwin_match_outputs(capture, outputs, output_count)) { goto fail; }
    memcpy(capture->snapshot, capture->layout.outputs, sizeof(capture->snapshot));
    capture->sealed = 1;
    committed = 1;
    if (drm_debug) { fprintf(stderr, "KWin: dropping capture capabilities and opening PipeWire\n"); }
    if (syscall(SYS_capset, &header, caps) != 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_GET_DUMPABLE) != 0 ||
        (capture->pipewire = kvm_pipewire_capture_new()) == NULL || !kvm_kwin_session_valid(capture)) { goto fail; }
    if (drm_debug) { fprintf(stderr, "KWin: requesting composed output streams\n"); }
    kvm_kwin_output_types[1] = p_wl_output_interface;
    for (int i = 0; i < output_count; ++i)
    {
        union wl_argument args[3];
        kvm_drm_kwin_stream *stream = &capture->streams[i];
        stream->capture = capture;
        args[0].o = NULL;
        args[1].o = (struct wl_object *)capture->layout.outputs[i].wl_output;
        args[2].u = 2; /* compositor-embedded cursor */
        stream->proxy = wl_proxy_marshal_array_constructor_versioned(capture->manager, 0, args, &kvm_kwin_stream_interface, 6);
        if (stream->proxy == NULL || wl_proxy_add_listener(stream->proxy, (void (**)(void))&kvm_kwin_stream_listener, stream) < 0) { goto fail; }
    }
    capture->started_ms = kvm_drm_now_ms();
    *out = capture;
    if (drm_debug) { fprintf(stderr, "KWin: selected compositor capture for %d output(s); capture capabilities cleared\n", output_count); }
    return 1;
fail:
    kvm_kwin_destroy(capture);
    return committed ? -1 : 0;
}

static void kvm_kwin_synced(void *data, struct wl_callback *callback, uint32_t serial)
{
    kvm_drm_kwin_capture *capture = data;
    (void)serial;
    wl_proxy_destroy((struct wl_proxy *)callback);
    capture->sync = NULL;
}
static const struct wl_callback_listener kvm_kwin_sync_listener = { kvm_kwin_synced };

static int kvm_kwin_pump(kvm_drm_kwin_capture *capture)
{
    struct wl_display *display = capture->layout.display;
    struct pollfd pfd = { .fd = wl_display_get_fd(display), .events = POLLIN };
    uint64_t now = kvm_drm_now_ms();
    int prepared = 0, result;
    if (capture->failed || !kvm_kwin_session_valid(capture) || !kvm_capture_worker_alive() || now == 0) { return 0; }
    if (wl_display_dispatch_pending(display) < 0) { return 0; }
    for (int i = 0; i < 4; ++i)
    {
        if (wl_display_prepare_read(display) == 0) { prepared = 1; break; }
        if (wl_display_dispatch_pending(display) < 0) { return 0; }
    }
    if (!prepared) { return 0; }
    result = wl_display_flush(display);
    if (result < 0 && errno != EAGAIN) { wl_display_cancel_read(display); return 0; }
    result = poll(&pfd, 1, 0);
    if (result < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
    { wl_display_cancel_read(display); return result < 0 && errno == EINTR; }
    if (pfd.revents & POLLIN)
    {
        if (wl_display_read_events(display) < 0 || wl_display_dispatch_pending(display) < 0) { return 0; }
    }
    else { wl_display_cancel_read(display); }
    if (capture->failed || memcmp(capture->snapshot, capture->layout.outputs, sizeof(capture->snapshot)) != 0) { return 0; }
    if (capture->sync != NULL && (now < capture->sync_started_ms || now - capture->sync_started_ms >= 2000)) { return 0; }
    if (capture->sync == NULL && (capture->last_sync_ms == 0 || now - capture->last_sync_ms >= 1000))
    {
        union wl_argument args[1]; args[0].o = NULL;
        capture->sync = (struct wl_callback *)wl_proxy_marshal_array_constructor((struct wl_proxy *)display, 0, args, p_wl_callback_interface);
        if (capture->sync == NULL || wl_proxy_add_listener((struct wl_proxy *)capture->sync,
            (void (**)(void))&kvm_kwin_sync_listener, capture) < 0) { return 0; }
        capture->last_sync_ms = capture->sync_started_ms = now;
    }
    for (int i = 0; i < capture->layout.output_count; ++i)
    {
        kvm_drm_kwin_stream *stream = &capture->streams[i];
        if (stream->created && stream->consumer == NULL)
        {
            stream->consumer = kvm_pipewire_capture_add(capture->pipewire, stream->serial);
            if (stream->consumer == NULL) { return 0; }
        }
        else if (!stream->created && (now < capture->started_ms || now - capture->started_ms >= 5000)) { return 0; }
    }
    return kvm_pipewire_capture_pump(capture->pipewire) > 0;
}

static void kvm_kwin_discard_frame(kvm_drm_kwin_capture *capture, int index)
{
    kvm_drm_kwin_stream *stream = &capture->streams[capture->output_map[index]];
    kvm_pipewire_capture_discard_frame(stream->consumer);
}

static int kvm_kwin_frame(kvm_drm_kwin_capture *capture, int index, const unsigned char **rgb, uint32_t *width, uint32_t *height)
{
    kvm_drm_kwin_stream *stream = &capture->streams[capture->output_map[index]];
    if (stream->consumer == NULL) { return 0; }
    return kvm_pipewire_capture_frame(stream->consumer, rgb, width, height);
}

static uint64_t kvm_kwin_revision(kvm_drm_kwin_capture *capture, int index)
{ return kvm_pipewire_capture_revision(capture->streams[capture->output_map[index]].consumer); }
