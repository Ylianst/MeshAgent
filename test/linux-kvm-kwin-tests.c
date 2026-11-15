/* SPDX-License-Identifier: Apache-2.0 */
/* Pure output identity and protocol state tests using the actual integration. */
#define _GNU_SOURCE
#include "../meshcore/KVM/Linux/linux_kvm_drm.c"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/wait.h>

static int passed, failed;
int ILibMemory_Copy_s(void *dst, size_t capacity, void *src, size_t length)
{
    if (length > capacity) { abort(); }
    memcpy(dst, src, length); return 0;
}
#define CHECK(expr) do { if (expr) ++passed; else { ++failed; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

static int bind_calls, manager_token;
static struct wl_proxy *test_bind(struct wl_proxy *registry, uint32_t opcode, union wl_argument *args, const struct wl_interface *interface, uint32_t version)
{
    (void)registry;
    CHECK(opcode == 0 && args[0].u == 99);
    CHECK(version == 6 && args[2].u == 6 && interface == &kvm_kwin_manager_interface);
    ++bind_calls; return (struct wl_proxy *)&manager_token;
}
static void test_protocol_negotiation(void)
{
    kvm_drm_kwin_capture capture = {0};
    p_wl_proxy_marshal_array_constructor_versioned = test_bind;
    kvm_kwin_global(&capture, NULL, 99, "zkde_screencast_unstable_v1", 5);
    CHECK(!capture.manager && bind_calls == 0);
    kvm_kwin_global(&capture, NULL, 99, "zkde_screencast_unstable_v1", 6);
    CHECK(capture.manager && bind_calls == 1);
    capture.manager = NULL;
    kvm_kwin_global(&capture, NULL, 99, "zkde_screencast_unstable_v1", 7);
    CHECK(capture.manager && bind_calls == 2);
    kvm_kwin_global(&capture, NULL, 99, "zkde_screencast_unstable_v1", 8);
    CHECK(bind_calls == 2);
    p_wl_proxy_marshal_array_constructor_versioned = NULL;
}

static void test_outputs(void)
{
    kvm_drm_kwin_capture capture = {0};
    kvm_drm_output outputs[2] = {{0}};
    capture.layout.output_count = 2;
    strcpy(outputs[0].connector_name, "DP-1");
    strcpy(outputs[1].connector_name, "HDMI-A-1");
    outputs[0].x = -1280; outputs[0].y = -20; outputs[0].width = 1280; outputs[0].height = 720;
    outputs[1].width = 1920; outputs[1].height = 1080;
    for (int i = 0; i < 2; ++i)
    {
        int j = 1 - i;
        kvm_drm_wayland_output *output = &capture.layout.outputs[j];
        strcpy(output->name, outputs[i].connector_name);
        output->have_name = output->have_position = output->have_size = 1;
        output->x = outputs[i].x; output->y = outputs[i].y;
        output->width = outputs[i].width; output->height = outputs[i].height;
    }
    CHECK(kvm_kwin_match_outputs(&capture, outputs, 2));
    CHECK(capture.output_map[0] == 1 && capture.output_map[1] == 0);
    strcpy(capture.layout.outputs[0].name, "HDMI-1"); CHECK(kvm_kwin_match_outputs(&capture, outputs, 2));
    CHECK(!kvm_kwin_match_outputs(&capture, outputs, 1));
    CHECK(!kvm_kwin_match_outputs(&capture, outputs, 0));
    CHECK(!kvm_kwin_match_outputs(&capture, NULL, 2));
    capture.layout.outputs[0].have_name = 0; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2)); capture.layout.outputs[0].have_name = 1;
    capture.layout.outputs[0].have_position = 0; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2)); capture.layout.outputs[0].have_position = 1;
    capture.layout.outputs[0].have_size = 0; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2)); capture.layout.outputs[0].have_size = 1;
    capture.layout.outputs[0].x = 1; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2)); capture.layout.outputs[0].x = 0;
    capture.layout.outputs[0].height = 1079; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2)); capture.layout.outputs[0].height = 1080;
    capture.layout.outputs[0].transform = WL_OUTPUT_TRANSFORM_90; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2));
    outputs[1].rotation = kvm_drm_rotation_from_wl_transform(WL_OUTPUT_TRANSFORM_90);
    CHECK(kvm_kwin_match_outputs(&capture, outputs, 2));
    strcpy(capture.layout.outputs[1].name, "HDMI-1"); CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2));
    strcpy(capture.layout.outputs[1].name, "DP-1");
    strcpy(outputs[0].connector_name, "HDMI-A-1"); CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2));
    capture.layout.output_count = 1; CHECK(!kvm_kwin_match_outputs(&capture, outputs, 2));
}

static void test_stream_state(void)
{
    kvm_drm_kwin_capture capture = {0};
    kvm_drm_kwin_stream stream = { .capture = &capture };
    kvm_kwin_serial(&stream, NULL, 2, 3);
    CHECK(stream.serial == (((uint64_t)2 << 32) | 3) && !capture.failed);
    kvm_kwin_created(&stream, NULL, 42); CHECK(stream.created && !capture.failed);
    kvm_kwin_created(&stream, NULL, 42); CHECK(capture.failed);
    capture.failed = 0; stream.created = 0; stream.serial = 0;
    kvm_kwin_created(&stream, NULL, 42); CHECK(capture.failed);
    capture.failed = 0; stream.created = 0;
    kvm_kwin_serial(&stream, NULL, 0, 44); kvm_kwin_serial(&stream, NULL, 0, 45); CHECK(capture.failed);
    capture.failed = 0; kvm_kwin_closed(&stream, NULL); CHECK(capture.failed);
    capture.failed = 0; kvm_kwin_failed(&stream, NULL, NULL); CHECK(capture.failed);
    capture.failed = 0; capture.manager_name = 7;
    kvm_kwin_removed(&capture, NULL, 8); CHECK(!capture.failed);
    kvm_kwin_removed(&capture, NULL, 7); CHECK(capture.failed);
    capture.failed = 0; capture.layout.output_count = 1; capture.layout.outputs[0].global_name = 9;
    kvm_kwin_removed(&capture, NULL, 9); CHECK(capture.failed);
}


static drmModeConnector fake_connector;
static drmModeCrtc fake_crtc;
static uint32_t fake_plane_ids[] = {7, 8};
static drmModePlaneRes fake_planes = { .count_planes = 2, .planes = fake_plane_ids };
static drmModePlane fake_plane[2];
static int query_failure, objects_acquired, objects_freed;
static drmModeConnector *query_connector(int fd, uint32_t id)
{ (void)fd; (void)id; if (query_failure == 1) return NULL; ++objects_acquired; return &fake_connector; }
static drmModeCrtc *query_crtc(int fd, uint32_t id)
{ (void)fd; (void)id; if (query_failure == 2) return NULL; ++objects_acquired; return &fake_crtc; }
static drmModePlaneRes *query_planes(int fd)
{ (void)fd; if (query_failure == 3) return NULL; ++objects_acquired; return &fake_planes; }
static drmModePlane *query_plane(int fd, uint32_t id)
{ (void)fd; if (query_failure == (int)id) return NULL; ++objects_acquired; return &fake_plane[id - 7]; }
static void free_connector(drmModeConnector *p) { (void)p; ++objects_freed; }
static void free_crtc(drmModeCrtc *p) { (void)p; ++objects_freed; }
static void free_planes(drmModePlaneRes *p) { (void)p; ++objects_freed; }
static void free_plane(drmModePlane *p) { (void)p; ++objects_freed; }
static void scanout_case(kvm_drm_output *output, int expected)
{
    objects_acquired = objects_freed = 0;
    CHECK(kvm_drm_output_scanout_state(9, output) == expected);
    CHECK(objects_acquired == objects_freed);
}
static void test_scanout_state(void)
{
    kvm_drm_output output = { .connector_id = 39, .crtc_id = 37, .crtc_index = 0 };
    p_drmModeGetConnector = query_connector; p_drmModeFreeConnector = free_connector;
    p_drmModeGetCrtc = query_crtc; p_drmModeFreeCrtc = free_crtc;
    p_drmModeGetPlaneResources = query_planes; p_drmModeFreePlaneResources = free_planes;
    p_drmModeGetPlane = query_plane; p_drmModeFreePlane = free_plane;
    fake_connector.connection = DRM_MODE_CONNECTED;
    scanout_case(NULL, -1);
    output.crtc_index = -1; scanout_case(&output, -1);
    output.crtc_index = 32; scanout_case(&output, -1); output.crtc_index = 0;
    query_failure = 1; scanout_case(&output, -1); query_failure = 0;
    fake_connector.connection = DRM_MODE_DISCONNECTED; scanout_case(&output, -1);
    fake_connector.connection = DRM_MODE_CONNECTED;
    query_failure = 2; scanout_case(&output, -1); query_failure = 0;
    fake_crtc.buffer_id = 42; scanout_case(&output, 1); fake_crtc.buffer_id = 0;
    query_failure = 3; scanout_case(&output, -1); query_failure = 0;
    scanout_case(&output, 0); // successfully inspected, connected and all planes inactive
    query_failure = 7; scanout_case(&output, -1); query_failure = 0;
    fake_plane[1].crtc_id = 37; fake_plane[1].possible_crtcs = 1; fake_plane[1].fb_id = 42;
    scanout_case(&output, 1); // active plane when legacy CRTC buffer is zero
    query_failure = 7; scanout_case(&output, 1); query_failure = 0;
    fake_plane[1].crtc_id = 38; scanout_case(&output, 0); fake_plane[1].crtc_id = 37;
    fake_plane[1].possible_crtcs = 2; scanout_case(&output, 0);
}

static void test_linear_snapshot(void)
{
    kvm_drm_scanout_frame frame = {0}, previous;
    kvm_drm_output output = {0}, moved;
    unsigned char source[32] = {0}, saved[32] = {0};
    frame.width = 3; frame.height = 2; frame.pitch = 16;
    frame.format = DRM_FORMAT_XRGB8888; frame.plane_count = 1;
    frame.modifier = DRM_FORMAT_MOD_LINEAR; previous = frame; moved = output;
#define MATCH() kvm_drm_linear_snapshot_matches(&frame, &previous, &output, &moved, source, saved, sizeof(saved))
    CHECK(MATCH());
    // Same framebuffer/handle, newly painted pixel, including the last pixel.
    source[0] = 1; CHECK(!MATCH()); source[0] = 0;
    source[27] = 1; CHECK(!MATCH()); source[27] = 0;
    source[15] = 1; CHECK(MATCH()); // row padding is not visible
    CHECK(!kvm_drm_linear_snapshot_matches(&frame, &previous, &output, &moved, source, saved, 31));
    CHECK(!kvm_drm_linear_snapshot_matches(&frame, &previous, &output, &moved, NULL, saved, 32));
    frame.rotation = KVM_DRM_ROTATION_90; CHECK(!MATCH()); frame = previous;
    frame.format = DRM_FORMAT_XBGR8888; CHECK(!MATCH()); frame = previous;
    frame.offset = 64; CHECK(!MATCH()); frame = previous;
    frame.width = 2; CHECK(!MATCH()); frame = previous;
    // GETFB can return different GEM handles for identical content. Neither
    // handle equality nor a buffer flip is evidence about changed pixels.
    frame.fb_id++; frame.handle++; CHECK(MATCH());
    source[0] = 1; CHECK(!MATCH()); source[0] = 0; frame = previous;
    moved.x++; CHECK(!MATCH()); moved = output;
    moved.rotation = KVM_DRM_ROTATION_90; CHECK(!MATCH()); moved = output;
    frame.plane_count = 2; previous = frame; CHECK(!MATCH());
    frame.plane_count = 1; frame.modifier = 123; previous = frame; CHECK(!MATCH());
    frame.modifier = DRM_FORMAT_MOD_LINEAR; frame.format = 0; previous = frame; CHECK(!MATCH());
    frame.format = DRM_FORMAT_XRGB8888; frame.pitch = 11; previous = frame; CHECK(!MATCH());
    frame.pitch = 16; frame.height = 0; previous = frame; CHECK(!MATCH());
    frame.height = UINT32_MAX; previous = frame; CHECK(!MATCH());
#undef MATCH
}

static int mapBacking, otherBacking, gemCloses, dumbAllowed, exportFails;
static int separateDescription;
static int map_export(int fd, uint32_t handle, uint32_t flags, int *result)
{
    (void)fd; (void)flags;
    if (exportFails) { return -1; }
    if (separateDescription)
    {
        char path[64]; snprintf(path, sizeof(path), "/proc/self/fd/%d", mapBacking);
        *result = open(path, O_RDWR | O_CLOEXEC); return *result < 0 ? -1 : 0;
    }
    *result = dup(handle >= 200 ? otherBacking : mapBacking);
    return *result < 0 ? -1 : 0;
}
static int map_ioctl(int fd, unsigned long request, void *argument)
{
    (void)fd;
    if (request == DRM_IOCTL_GEM_CLOSE) { ++gemCloses; return 0; }
    if (request == DRM_IOCTL_MODE_MAP_DUMB && dumbAllowed)
    { ((struct drm_mode_map_dumb *)argument)->offset = 0; return 0; }
    return -1;
}
static void test_map_identity(void)
{
    FILE *a = tmpfile(), *b = tmpfile();
    CHECK(a && b); if (!a || !b) { return; }
    mapBacking = fileno(a); otherBacking = fileno(b);
    CHECK(ftruncate(mapBacking, 8192) == 0 && ftruncate(otherBacking, 8192) == 0);
    CHECK(pwrite(mapBacking, "A", 1, 0) == 1 && pwrite(otherBacking, "B", 1, 0) == 1);
    p_drmPrimeHandleToFD = map_export; p_drmIoctl = map_ioctl;
    kvm_drm_frame_map map = { .dma_fd = -1, .identity_fd = -1, .drm_fd = -1 };
    char error[256];
    dumbAllowed = 1; exportFails = 0; gemCloses = 0;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 1, 4096, &map, error, sizeof(error)));
    CHECK(map.addr[0] == 'A' && map.dma_fd == -1 && map.identity_fd >= 0);
    uint8_t *address = map.addr;
    int identity = map.identity_fd;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 2, 4096, &map, error, sizeof(error)));
    CHECK(map.addr == address && map.handle == 1 && map.identity_fd == identity && gemCloses == 1);
    CHECK(pwrite(mapBacking, "C", 1, 0) == 1 && map.addr[0] == 'C'); // reused map sees repaint
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 1, 8192, &map, error, sizeof(error)));
    CHECK(map.size == 8192 && map.addr[0] == 'C' && gemCloses == 1); // retained handle on resize
    dumbAllowed = 0;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 200, 4096, &map, error, sizeof(error)));
    CHECK(map.addr[0] == 'B' && map.handle == 200 && map.dma_fd >= 0 && map.identity_fd == -1 && gemCloses == 2);
    address = map.addr;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 201, 4096, &map, error, sizeof(error)));
    CHECK(map.addr == address && map.handle == 200 && gemCloses == 3);
    // Matching DMA-BUF inode on a different DRM device does not authorize map reuse.
    CHECK(kvm_drm_map_framebuffer_handle(otherBacking, 202, 4096, &map, error, sizeof(error)));
    CHECK(map.drm_fd == otherBacking && map.handle == 202 && gemCloses == 4);
    int retainedFd = map.dma_fd;
    kvm_drm_destroy_map(&map);
    CHECK(fcntl(retainedFd, F_GETFD) == -1 && map.addr == NULL && gemCloses == 5);
    dumbAllowed = 1; exportFails = 1;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 3, 4096, &map, error, sizeof(error)));
    CHECK(map.addr[0] == 'C' && map.dma_fd == -1 && map.identity_fd == -1);
    kvm_drm_destroy_map(&map);
    CHECK(gemCloses == 6);
    fclose(a); fclose(b);
}

static void test_distinct_file_description(void)
{
    FILE *a = tmpfile(); CHECK(a != NULL); if (!a) { return; }
    mapBacking = fileno(a); CHECK(ftruncate(mapBacking, 4096) == 0);
    kvm_drm_frame_map map = { .dma_fd = -1, .identity_fd = -1, .drm_fd = -1 };
    char error[256];
    dumbAllowed = 1; exportFails = 0; gemCloses = 0;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 10, 4096, &map, error, sizeof(error)));
    separateDescription = 1; // same device/inode, different kernel file identity
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 11, 4096, &map, error, sizeof(error)));
    CHECK(map.handle == 11 && gemCloses == 1);
    separateDescription = 0;
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 12, 4096, &map, error, sizeof(error)));
    CHECK(map.handle == 12 && gemCloses == 2);
    kvm_drm_destroy_map(&map); fclose(a);
}

#if defined(SYS_kcmp)
static void test_denied_map_comparison(void)
{
    FILE *a = tmpfile(); CHECK(a != NULL); if (!a) { return; }
    mapBacking = fileno(a); CHECK(ftruncate(mapBacking, 4096) == 0);
    dumbAllowed = 1; exportFails = 0; gemCloses = 0;
    kvm_drm_frame_map map = { .dma_fd = -1, .identity_fd = -1, .drm_fd = -1 };
    char error[256];
    CHECK(kvm_drm_map_framebuffer_handle(mapBacking, 10, 4096, &map, error, sizeof(error)));
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0)
    {
        struct sock_filter code[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_kcmp, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        };
        struct sock_fprog filter = { .len = 4, .filter = code };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)) { _exit(2); }
        int ok = kvm_drm_map_framebuffer_handle(mapBacking, 11, 4096, &map, error, sizeof(error));
        _exit(ok && map.handle == 11 && gemCloses == 1 ? 0 : 3);
    }
    if (child > 0)
    {
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    kvm_drm_destroy_map(&map); fclose(a);
}
#endif

int main(void)
{
    CHECK(kvm_drm_frame_covers_desktop(4,3,0,0,4,3,4,3));
    CHECK(!kvm_drm_frame_covers_desktop(4,3,1,0,4,3,4,3));
    CHECK(!kvm_drm_frame_covers_desktop(4,3,0,1,4,3,4,3));
    CHECK(!kvm_drm_frame_covers_desktop(8,6,0,0,4,3,4,3));
    CHECK(!kvm_drm_frame_covers_desktop(4,3,0,0,2,3,4,3));
    CHECK(!kvm_drm_frame_covers_desktop(4,3,0,0,4,3,8,3));
    CHECK(!kvm_drm_frame_covers_desktop(0,0,0,0,0,0,0,0));
    unsigned char privateRgb[36], composed[36];
    for(unsigned i=0;i<sizeof(privateRgb);++i)privateRgb[i]=(unsigned char)(i*17u);
    memset(composed,0,sizeof(composed));
    kvm_drm_copy_frame_to_desktop(privateRgb,4,3,composed,4,3,0,0,4,3);
    CHECK(memcmp(privateRgb,composed,sizeof(composed))==0);
#if defined(SYS_kcmp)
    test_map_identity();
    test_distinct_file_description();
    test_denied_map_comparison();
#endif
    test_linear_snapshot();
    test_protocol_negotiation(); test_outputs(); test_stream_state(); test_scanout_state();
    printf("KWin capture identity/state: %d passed, %d failed\n", passed, failed);
    return failed != 0;
}
