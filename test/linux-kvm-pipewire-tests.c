/* SPDX-License-Identifier: Apache-2.0 */
/* Protocol-boundary checks; these do not simulate compositor/GPU behavior. */
#include "../meshcore/KVM/Linux/linux_kvm_pipewire.c"

static int passed, failed;
#define CHECK(expr) do { if (expr) { ++passed; } else { ++failed; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

static struct pw_buffer test_buffer;
static int returned_buffers, queue_result;
static struct pw_buffer *take_buffer(struct pw_stream *stream) { (void)stream; return &test_buffer; }
static int return_buffer(struct pw_stream *stream, struct pw_buffer *buffer)
{ (void)stream; CHECK(buffer == &test_buffer); ++returned_buffers; return queue_result; }

static void test_bounds(void)
{
    unsigned char memory[64] = {0};
    const unsigned char *pixels = NULL;
    uint32_t stride = 0;
    struct spa_chunk chunk = { .offset = 4, .size = 24, .stride = 16 };
    struct spa_data data = { .type = SPA_DATA_MemFd, .data = memory, .maxsize = sizeof(memory), .chunk = &chunk };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &data };
    struct spa_meta_header header = {0};
    struct spa_meta meta = { .type = SPA_META_Header, .data = &header, .size = sizeof(header) };
    CHECK(pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride) && pixels == memory + 4 && stride == 16);
    CHECK(!pwcap_buffer_view(&buffer, 0, 2, &pixels, &stride));
    CHECK(!pwcap_buffer_view(&buffer, 2, UINT32_MAX, &pixels, &stride));
    CHECK(!pwcap_buffer_view(&buffer, 32768, 32768, &pixels, &stride));
    CHECK(!pwcap_buffer_view(NULL, 2, 2, &pixels, &stride));
    buffer.n_datas = 2; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); buffer.n_datas = 1;
    buffer.datas = NULL; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); buffer.datas = &data;
    data.type = SPA_DATA_DmaBuf; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); data.type = SPA_DATA_MemPtr;
    data.data = NULL; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); data.data = memory;
    data.chunk = NULL; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); data.chunk = &chunk;
    chunk.stride = -16; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    chunk.stride = 7; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); chunk.stride = 16;
    chunk.offset = UINT32_MAX; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); chunk.offset = 4;
    chunk.size = 23; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    chunk.size = 61; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); chunk.size = 24;
    data.maxsize = 27; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); data.maxsize = sizeof(memory);
    chunk.flags = SPA_CHUNK_FLAG_CORRUPTED; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    chunk.flags = SPA_CHUNK_FLAG_EMPTY; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); chunk.flags = 0;
    buffer.n_metas = 1; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); buffer.metas = &meta;
    CHECK(pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    header.flags = SPA_META_HEADER_FLAG_DISCONT; CHECK(pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    header.flags = SPA_META_HEADER_FLAG_CORRUPTED; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    header.flags = SPA_META_HEADER_FLAG_DELTA_UNIT; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); header.flags = 0;
    meta.size = sizeof(header) - 1; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); meta.size = sizeof(header);
    meta.data = NULL; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride)); meta.data = &header;
    meta.type = SPA_META_VideoCrop; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    meta.type = SPA_META_VideoTransform; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
    buffer.n_metas = 65; CHECK(!pwcap_buffer_view(&buffer, 2, 2, &pixels, &stride));
}

static void test_frames(void)
{
    unsigned char memory[24] = {0, 0, 0, 0, 3, 2, 1, 255, 6, 5, 4, 255,
        0, 0, 0, 0, 9, 8, 7, 255, 12, 11, 10, 255};
    unsigned char expected[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    struct spa_chunk chunk = { .offset = 4, .size = 20, .stride = 12 };
    struct spa_data data = { .type = SPA_DATA_MemFd, .data = memory, .maxsize = sizeof(memory), .chunk = &chunk };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &data };
    kvm_pipewire_capture capture = {0};
    kvm_pipewire_stream stream = { .capture = &capture, .streaming = 1 };
    const unsigned char *rgb = NULL;
    uint32_t width, height;
    stream.format.size.width = stream.format.size.height = 2;
    p_pw_stream_dequeue_buffer = take_buffer;
    p_pw_stream_queue_buffer = return_buffer;
    test_buffer.buffer = &buffer;
    pwcap_process(&stream);
    CHECK(returned_buffers == 1 && !capture.failed && capture.allocated == sizeof(expected));
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 1 && width == 2 && height == 2);
    CHECK(rgb != NULL && memcmp(rgb, expected, sizeof(expected)) == 0);
    pwcap_state(&stream, PW_STREAM_STATE_STREAMING, PW_STREAM_STATE_PAUSED, NULL);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 0 && rgb == NULL);
    pwcap_state(&stream, PW_STREAM_STATE_PAUSED, PW_STREAM_STATE_STREAMING, NULL);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 0);
    pwcap_process(&stream);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 1);
    pwcap_format(&stream, SPA_PARAM_Format, NULL);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 0);
    stream.format.size.width = stream.format.size.height = 2;
    pwcap_process(&stream);
    chunk.size = 19;
    pwcap_process(&stream);
    CHECK(capture.failed && kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == -1 && rgb == NULL);
    CHECK(returned_buffers == 4);
    capture.failed = 0; chunk.size = 20; queue_result = -EPIPE;
    pwcap_process(&stream);
    CHECK(capture.failed && returned_buffers == 5);
    queue_result = 0; capture.failed = 0;
    pwcap_state(&stream, PW_STREAM_STATE_STREAMING, PW_STREAM_STATE_UNCONNECTED, NULL);
    CHECK(capture.failed);
    capture.failed = 0;
    pwcap_state(&stream, PW_STREAM_STATE_CONNECTING, PW_STREAM_STATE_ERROR, NULL);
    CHECK(capture.failed);
    CHECK(kvm_pipewire_capture_frame(NULL, &rgb, &width, &height) == -1);
    CHECK(kvm_pipewire_capture_frame(&stream, NULL, &width, &height) == -1);
    free(stream.rgb);
}

static void test_padded_conversion(void)
{
    /* An unaligned, odd-width source exercises vector blocks and the scalar
     * tail without consuming stride padding or the next frame's allocation. */
    enum { WIDTH = 17, HEIGHT = 3, STRIDE = WIDTH * 4 + 11, OFFSET = 5 };
    unsigned char memory[OFFSET + STRIDE * HEIGHT], before[sizeof(memory)];
    struct spa_chunk chunk = { .offset = OFFSET, .size = (HEIGHT - 1) * STRIDE + WIDTH * 4, .stride = STRIDE };
    struct spa_data data = { .type = SPA_DATA_MemPtr, .data = memory, .maxsize = sizeof(memory), .chunk = &chunk };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &data };
    kvm_pipewire_capture capture = {0};
    kvm_pipewire_stream stream = { .capture = &capture, .streaming = 1 };
    stream.format.size.width = WIDTH; stream.format.size.height = HEIGHT;
    p_pw_stream_dequeue_buffer = take_buffer; p_pw_stream_queue_buffer = return_buffer;
    test_buffer.buffer = &buffer;
    for (unsigned frame = 0; frame < 2; ++frame)
    {
        stream.format.format = frame ? SPA_VIDEO_FORMAT_BGRA : SPA_VIDEO_FORMAT_BGRx;
        memset(memory, 0xa5, sizeof(memory));
        for (unsigned y = 0; y < HEIGHT; ++y)
            for (unsigned x = 0; x < WIDTH; ++x)
            {
                unsigned char *pixel = memory + OFFSET + y * STRIDE + x * 4;
                pixel[0] = x + frame; pixel[1] = y + 40; pixel[2] = x + y + 80;
                pixel[3] = frame ? 255 : 0; /* BGRx and BGRA retain identical RGB. */
            }
        memcpy(before, memory, sizeof(memory));
        pwcap_process(&stream);
        CHECK(!capture.failed && stream.ready && stream.revision == frame + 1);
        CHECK(memcmp(before, memory, sizeof(memory)) == 0);
        for (unsigned y = 0; y < HEIGHT; ++y)
            for (unsigned x = 0; x < WIDTH; ++x)
            {
                const unsigned char *pixel = stream.rgb + (y * WIDTH + x) * 3;
                CHECK(pixel[0] == x + y + 80 && pixel[1] == y + 40 && pixel[2] == x + frame);
            }
    }
    free(stream.rgb);
}

static void test_health(void)
{
    kvm_pipewire_capture capture = { .pending = 1, .sequence = 42 };
    pwcap_done(&capture, PW_ID_CORE, 41); CHECK(capture.pending);
    pwcap_done(&capture, 4, 42); CHECK(capture.pending);
    pwcap_done(&capture, PW_ID_CORE, 42); CHECK(!capture.pending);
    pwcap_error(&capture, PW_ID_CORE, 42, -EPIPE, "test"); CHECK(capture.failed);
    CHECK(kvm_pipewire_capture_pump(&capture) == -1);
    CHECK(kvm_pipewire_capture_add(&capture, 42) == NULL);
    capture.failed = 0;
    CHECK(kvm_pipewire_capture_add(&capture, 0) == NULL);
    capture.count = 1; capture.streams[0].serial = 42;
    CHECK(kvm_pipewire_capture_add(&capture, 42) == NULL);
    capture.count = KVM_PW_MAX_STREAMS;
    CHECK(kvm_pipewire_capture_add(&capture, 43) == NULL);
    kvm_pipewire_capture_destroy(NULL);
}

static void test_environment(void)
{
    setenv("PIPEWIRE_CONFIG_NAME", "/tmp/untrusted.conf", 1);
    setenv("PIPEWIRE_MODULE_DIR", "/tmp/untrusted", 1);
    setenv("SPA_PLUGIN_DIR", "/tmp/untrusted", 1);
    setenv("SPA_SUPPORT_LIB", "/tmp/untrusted.so", 1);
    setenv("PIPEWIRE_REMOTE", "wrong-session", 1);
    setenv("MESH_KVM_TEST_PRESERVED", "yes", 1);
    CHECK(pwcap_environment());
    CHECK(strcmp(getenv("PIPEWIRE_CONFIG_NAME"), "client.conf") == 0 && getenv("PIPEWIRE_MODULE_DIR") == NULL);
    CHECK(getenv("SPA_PLUGIN_DIR") == NULL && getenv("SPA_SUPPORT_LIB") == NULL);
    CHECK(getenv("PIPEWIRE_REMOTE") == NULL);
    CHECK(getenv("PIPEWIRE_NO_CONFIG") == NULL && strcmp(getenv("PIPEWIRE_CONFIG_PREFIX"), "/usr/share/pipewire") == 0);
    CHECK(strcmp(getenv("MESH_KVM_TEST_PRESERVED"), "yes") == 0);
    CHECK(pwcap_environment());
    unsetenv("MESH_KVM_TEST_PRESERVED");
}


static void test_discard(void)
{
    unsigned char pixel[4] = {3, 2, 1, 255};
    struct spa_chunk chunk = { .size = 4, .stride = 4 };
    struct spa_data data = { .type = SPA_DATA_MemPtr, .data = pixel, .maxsize = 4, .chunk = &chunk };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &data };
    kvm_pipewire_capture capture = {0};
    kvm_pipewire_stream stream = { .capture = &capture, .streaming = 1 };
    const unsigned char *rgb = NULL;
    uint32_t width, height;
    stream.format.size.width = stream.format.size.height = 1;
    test_buffer.buffer = &buffer;
    pwcap_process(&stream);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 1);
    CHECK(kvm_pipewire_capture_revision(&stream) == 1);
    CHECK(kvm_pipewire_capture_revision(&stream) == 1); /* reading cached content never advances revision */
    kvm_pipewire_capture_discard_frame(&stream);
    CHECK(kvm_pipewire_capture_revision(&stream) == 0);
    CHECK(stream.waiting_since_ms > 0);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 0 && rgb == NULL);
    // Merely asking again cannot revive the stale buffer.
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 0 && rgb == NULL);
    pixel[0] = 6; pixel[1] = 5; pixel[2] = 4;
    pwcap_process(&stream);
    CHECK(kvm_pipewire_capture_frame(&stream, &rgb, &width, &height) == 1);
    CHECK(kvm_pipewire_capture_revision(&stream) == 2);
    CHECK(stream.waiting_since_ms == 0 && rgb[0] == 4 && rgb[1] == 5 && rgb[2] == 6);
    kvm_pipewire_capture_discard_frame(NULL);
    free(stream.rgb);
}

int main(void)
{
    test_bounds(); test_frames(); test_discard(); test_padded_conversion(); test_health(); test_environment();
    printf("PipeWire capture boundary: %d passed, %d failed\n", passed, failed);
    return failed != 0;
}
