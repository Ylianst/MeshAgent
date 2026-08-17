/*
Copyright 2024 Intel Corporation

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

/*
 * Linux capture of the device's microphone, streamed to the operator.
 *
 * This is the sibling of linux_audio.c and travels in the same direction
 * (device -> browser); the difference is the source. linux_audio.c captures
 * the monitor of the output, so the operator hears what the machine plays.
 * This file captures the default input, so the operator hears the room: the
 * user speaking, and noises worth diagnosing such as fans or clicking drives.
 *
 * Listening to a room is not something a user should discover after the fact,
 * so capture only runs once the local user has agreed. The agent's JavaScript
 * layer shows the prompt; the gate is enforced here as well, because a caller
 * that skipped the handshake must still get silence rather than audio.
 *
 * libpulse-simple is loaded with dlopen so a single binary keeps working on
 * systems with no PulseAudio, where the feature simply reports itself
 * unavailable.
 */

#if defined(_KVM_AUDIO)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>

#include "meshcore/meshdefines.h"
#include "meshcore/KVM/kvm_mic.h"
#include "opus/opus.h"

/* Only for type/struct/enum definitions (pa_source_info, pa_context_state_t,
 * the callback typedefs, ...) -- every function is still resolved at runtime
 * via dlsym(), same as the pa_simple family below, and this file is never
 * linked against -lpulse. That keeps the "no PulseAudio = feature reports
 * itself unavailable" portability the pa_simple half already has, while
 * getting pa_source_info's layout from the real header instead of
 * hand-transcribing a struct this file does not own. Needs libpulse-dev at
 * build time only (see .github/workflows/linux-build.yml); nothing at
 * runtime beyond libpulse.so.0 itself, which is dlopen'd below exactly like
 * libpulse-simple.so.0 already is. */
#include <pulse/pulseaudio.h>

#define MIC_SAMPLE_RATE   48000
#define MIC_CHANNELS      1
#define MIC_FRAME_MS      20     /* default frame size until MNG_MIC_START says otherwise */
#define MIC_FRAME_SAMPLES (MIC_SAMPLE_RATE * MIC_FRAME_MS / 1000)   /* 960 */
#define MIC_MAX_FRAME_MS      60 /* largest frame size MNG_MIC_START may request */
#define MIC_MAX_FRAME_SAMPLES (MIC_SAMPLE_RATE * MIC_MAX_FRAME_MS / 1000)   /* 2880 */
#define MIC_MAX_PKT       1500   /* Opus worst-case output at the bitrates/frame sizes this now allows */
#define MIC_HEADER_LEN    7      /* type(2) len(2) seq(2) flags(1) */
#define MIC_CAPS_LEN      10

#define MIC_DEVICE_MAX_COUNT  32  /* MNG_MIC_DEVICE_LIST's count byte is also this bounded */
#define MIC_DEVICE_NAME_MAX   63  /* display name sent to the browser; truncated, not rejected */
#define MIC_SOURCE_NAME_MAX   255 /* real PulseAudio source name, used locally to (re)open the stream */
#define MIC_ENUM_TIMEOUT_MS   3000 /* bounds kvm_mic_query_devices() against a hung/missing daemon */
#define MIC_ENUM_POLL_MS      20

/* PulseAudio simple API. Only pa_simple itself is hand-declared (opaque,
 * pulse/pulseaudio.h's umbrella of async-API headers doesn't pull in
 * pulse/simple.h, which owns it) -- pa_stream_direction_t, pa_sample_spec
 * and PA_SAMPLE_S16LE now come from that real header instead of being
 * transcribed here, since transcribing them a second time is exactly what
 * would go subtly wrong (padding, a wrong enum value) without a compiler to
 * check it against the original. All of it, simple and full API alike, is
 * still resolved at runtime via dlsym() -- see the load_pulse()/
 * load_pulse_full() pair below -- never linked, so a system without
 * PulseAudio at all still runs everything else in this binary. */
typedef struct pa_simple pa_simple;

typedef pa_simple* (*pa_simple_new_t)(const char*, const char*, pa_stream_direction_t,
                                      const char*, const char*, const pa_sample_spec*,
                                      const void*, const void*, int*);
typedef int  (*pa_simple_read_t)(pa_simple*, void*, size_t, int*);
typedef void (*pa_simple_free_t)(pa_simple*);

/* Full (non-simple) libpulse, dlopen'd separately from libpulse-simple.so.0
 * above: source enumeration needs the async context API, which pa_simple
 * does not expose at all. Independently optional -- a system with capture
 * but no enumeration support (unlikely, but not impossible) still gets
 * audio, just with only "System Default" ever selectable. */
typedef pa_mainloop*        (*pa_mainloop_new_t)(void);
typedef pa_mainloop_api*    (*pa_mainloop_get_api_t)(pa_mainloop*);
typedef int                 (*pa_mainloop_iterate_t)(pa_mainloop*, int, int*);
typedef void                 (*pa_mainloop_free_t)(pa_mainloop*);
typedef pa_context*         (*pa_context_new_t)(pa_mainloop_api*, const char*);
typedef int                 (*pa_context_connect_t)(pa_context*, const char*, pa_context_flags_t, const pa_spawn_api*);
typedef pa_context_state_t  (*pa_context_get_state_t)(pa_context*);
typedef void                 (*pa_context_set_state_callback_t)(pa_context*, pa_context_notify_cb_t, void*);
typedef pa_operation*       (*pa_context_get_source_info_list_t)(pa_context*, pa_source_info_cb_t, void*);
typedef pa_operation_state_t (*pa_operation_get_state_t)(pa_operation*);
typedef void                 (*pa_operation_unref_t)(pa_operation*);
typedef void                 (*pa_context_disconnect_t)(pa_context*);
typedef void                 (*pa_context_unref_t)(pa_context*);

static OpusEncoder *g_enc = NULL;
static void *g_pa_lib = NULL;
static void *g_pa_full_lib = NULL;
static int g_application = OPUS_APPLICATION_VOIP; /* application mode the live g_enc was created with */
static int g_frameSamples = MIC_FRAME_SAMPLES;     /* runtime frame size; MNG_MIC_START may change it */
static int g_bitrateKbps = 28;                     /* currently-applied bitrate, for caps reporting */
/* Enumerated by kvm_mic_query_devices(), indexed exactly as sent in
 * MNG_MIC_DEVICE_LIST. g_deviceLabels are for display (browser-facing,
 * truncated); g_deviceSources are the real PulseAudio source names used
 * locally to open the stream, never sent anywhere. */
static char g_deviceLabels[MIC_DEVICE_MAX_COUNT][MIC_DEVICE_NAME_MAX + 1];
static char g_deviceSources[MIC_DEVICE_MAX_COUNT][MIC_SOURCE_NAME_MAX + 1];
static int g_deviceCount = 0;
static int g_currentDeviceIndex = -1;              /* -1 = system default; else index into g_deviceSources */
static char g_currentSourceName[MIC_SOURCE_NAME_MAX + 1] = {0}; /* resolved from g_currentDeviceIndex; capture_thread reads this once at start */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_consent = 0;      /* only kvm_mic_set_consent() sets this */
/* 1 between asking the JS layer to prompt and that prompt being resolved, so
 * a cancel is only ever sent for a prompt that is actually on screen. */
static volatile int g_promptOutstanding = 0;
static volatile int g_shutdown = 1;     /* 1 = capture thread not running */
static pthread_t g_thread = (pthread_t)0;
static uint16_t g_seq = 0;
static int g_slave_pipe_fd = -1;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;

/* Mirrors linux_audio.c: a service has no XDG_RUNTIME_DIR, so find the
 * logged-in user's PulseAudio socket. */
static void discover_pulse_server(void)
{
    DIR *d;
    struct dirent *ent;

    if (getenv("PULSE_SERVER") != NULL) { return; }
    d = opendir("/run/user");
    if (d == NULL) { return; }
    while ((ent = readdir(d)) != NULL)
    {
        char path[sizeof("/run/user/") + 255 + sizeof("/pulse/native")];
        if (ent->d_name[0] == '.') { continue; }
        snprintf(path, sizeof(path), "/run/user/%s/pulse/native", ent->d_name);
        if (access(path, R_OK) == 0)
        {
            char server[sizeof("unix:") + sizeof(path)];
            snprintf(server, sizeof(server), "unix:%s", path);
            setenv("PULSE_SERVER", server, 1);
            break;
        }
    }
    closedir(d);
}

static int load_pulse(void)
{
    if (g_pa_lib != NULL) { return 1; }
    g_pa_lib = dlopen("libpulse-simple.so.0", RTLD_LAZY);
    if (g_pa_lib == NULL) { g_pa_lib = dlopen("libpulse-simple.so", RTLD_LAZY); }
    return (g_pa_lib != NULL);
}

static int load_pulse_full(void)
{
    if (g_pa_full_lib != NULL) { return 1; }
    g_pa_full_lib = dlopen("libpulse.so.0", RTLD_LAZY);
    if (g_pa_full_lib == NULL) { g_pa_full_lib = dlopen("libpulse.so", RTLD_LAZY); }
    return (g_pa_full_lib != NULL);
}

void kvm_mic_set_slave_fd(int fd)
{
    g_slave_pipe_fd = fd;
}

/* Send one framed packet. Matches linux_audio.c's transport choice: inside the
 * forked slave the parent is reached through the pipe, otherwise directly. */
static void mic_send(const unsigned char *payload, int payloadLen, int type)
{
    int total = MIC_HEADER_LEN + payloadLen;
    char *buf = (char*)malloc((size_t)total);
    if (buf == NULL) { return; }

    ((unsigned short*)buf)[0] = htons((unsigned short)type);
    ((unsigned short*)buf)[1] = htons((unsigned short)total);
    ((unsigned short*)buf)[2] = htons(g_seq++);
    buf[6] = 0x00;
    if (payloadLen > 0) { memcpy(buf + MIC_HEADER_LEN, payload, (size_t)payloadLen); }

    if (g_slave_pipe_fd >= 0)
    {
        ssize_t written = write(g_slave_pipe_fd, buf, (size_t)total);
        (void)written;
        fsync(g_slave_pipe_fd);
    }
    else if (g_writeHandler != NULL)
    {
        g_writeHandler(buf, total, g_reserved);
    }
    free(buf);
}

static void send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    unsigned char caps[MIC_CAPS_LEN];
    int available, granted, bitrateKbps;

    pthread_mutex_lock(&g_lock);
    available = (g_enc != NULL) && load_pulse();
    granted = g_consent;
    bitrateKbps = g_bitrateKbps;
    pthread_mutex_unlock(&g_lock);

    caps[0] = (unsigned char)((MNG_MIC_CAPS >> 8) & 0xFF);
    caps[1] = (unsigned char)(MNG_MIC_CAPS & 0xFF);
    caps[2] = 0x00;
    caps[3] = (unsigned char)MIC_CAPS_LEN;
    caps[4] = 0;                          /* sample rate: 0 = 48 kHz */
    caps[5] = (unsigned char)MIC_CHANNELS;
    caps[6] = (unsigned char)bitrateKbps; /* currently-applied bitrate, kbps */
    caps[7] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00));
    caps[8] = 1;                          /* platform: Linux */
    caps[9] = 1;                          /* protocol version: MNG_MIC_START accepts a settings payload */

    /* Send through the same path as audio frames so ordering is preserved. */
    if (g_slave_pipe_fd >= 0)
    {
        ssize_t written = write(g_slave_pipe_fd, (char*)caps, MIC_CAPS_LEN);
        (void)written;
        fsync(g_slave_pipe_fd);
    }
    else if (writeHandler != NULL)
    {
        writeHandler((char*)caps, MIC_CAPS_LEN, reserved);
    }
}

/* Tell the agent's JS layer a consent prompt is needed. Sent from
 * kvm_mic_start() instead of opening the microphone, when consent is
 * specifically the reason it refused. Carries no payload: the plain 4-byte
 * KVM command frame is all a pure signal needs. */
static void notify_js(int command)
{
    unsigned char frame[4];

    frame[0] = (unsigned char)((command >> 8) & 0xFF);
    frame[1] = (unsigned char)(command & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x04;

    if (g_slave_pipe_fd >= 0)
    {
        ssize_t written = write(g_slave_pipe_fd, (char*)frame, sizeof(frame));
        (void)written;
        fsync(g_slave_pipe_fd);
    }
    else if (g_writeHandler != NULL)
    {
        g_writeHandler((char*)frame, (int)sizeof(frame), g_reserved);
    }
}

static void *capture_thread(void *arg)
{
    void *lib = NULL;
    pa_simple *s = NULL;
    pa_simple_new_t fn_new = NULL;
    pa_simple_read_t fn_read = NULL;
    pa_simple_free_t fn_free = NULL;
    pa_sample_spec ss;
    int16_t pcm[MIC_MAX_FRAME_SAMPLES * MIC_CHANNELS]; /* sized for the largest MNG_MIC_START may request */
    unsigned char opus[MIC_MAX_PKT];
    int err = 0;
    char sourceName[MIC_SOURCE_NAME_MAX + 1];
    const char *devArg;

    (void)arg;
    discover_pulse_server();

    pthread_mutex_lock(&g_lock);
    lib = g_pa_lib;
    /* Read once at thread start, not per-frame like g_frameSamples: unlike
     * encoder settings, PulseAudio has no "switch source on a live stream"
     * primitive, so a device change is handled by kvm_mic_start() stopping
     * and restarting this thread entirely -- there is never a live value to
     * race with here. */
    strncpy(sourceName, g_currentSourceName, sizeof(sourceName) - 1);
    sourceName[sizeof(sourceName) - 1] = '\0';
    pthread_mutex_unlock(&g_lock);
    if (lib == NULL) { goto done; }
    devArg = (sourceName[0] != '\0') ? sourceName : NULL;

    fn_new  = (pa_simple_new_t) dlsym(lib, "pa_simple_new");
    fn_read = (pa_simple_read_t)dlsym(lib, "pa_simple_read");
    fn_free = (pa_simple_free_t)dlsym(lib, "pa_simple_free");
    if (fn_new == NULL || fn_read == NULL || fn_free == NULL) { goto done; }

    ss.format = PA_SAMPLE_S16LE;
    ss.rate = MIC_SAMPLE_RATE;
    ss.channels = MIC_CHANNELS;

    /* devArg NULL = PulseAudio's default input; otherwise the specific
     * source the operator picked (see kvm_mic_query_devices()). Deliberately
     * never "@DEFAULT_MONITOR@" as in linux_audio.c: a monitor carries what
     * the machine is playing, whereas the point here is to hear the room. */
    s = fn_new(NULL, "MeshAgent", PA_STREAM_RECORD, devArg, "Remote Support Microphone",
               &ss, NULL, NULL, &err);
    if (s == NULL) { goto done; }

    for (;;)
    {
        int bytes, frameSamples;

        /* Re-check consent every frame so a revocation takes effect at once,
         * rather than after some buffer drains. Snapshot the frame size once
         * per iteration so a live MNG_MIC_START settings change can't shift
         * it between the read and the encode call within the same frame --
         * it takes effect on the next iteration instead. */
        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent || g_enc == NULL) { pthread_mutex_unlock(&g_lock); break; }
        frameSamples = g_frameSamples;
        pthread_mutex_unlock(&g_lock);

        if (fn_read(s, pcm, (size_t)frameSamples * MIC_CHANNELS * sizeof(int16_t), &err) < 0) { break; }

        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent || g_enc == NULL) { pthread_mutex_unlock(&g_lock); break; }
        bytes = opus_encode(g_enc, pcm, frameSamples, opus, MIC_MAX_PKT);
        pthread_mutex_unlock(&g_lock);

        /* Opus returns 1 for a pure-DTX packet, which carries no audio. */
        if (bytes > 1) { mic_send(opus, bytes, MNG_MIC_DATA); }
    }

done:
    if (s != NULL && fn_free != NULL) { fn_free(s); }
    pthread_mutex_lock(&g_lock);
    g_shutdown = 1;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    pthread_mutex_lock(&g_lock);
    g_writeHandler = writeHandler;
    g_reserved = reserved;
    if (g_enc == NULL)
    {
        int err = 0;
        OpusEncoder *enc = opus_encoder_create(MIC_SAMPLE_RATE, MIC_CHANNELS,
                                               OPUS_APPLICATION_VOIP, &err);
        if (enc != NULL && err == OPUS_OK)
        {
            /* Tuned for speech rather than music: this carries a voice and
             * room noise, and should stay intelligible on a poor link. */
            opus_encoder_ctl(enc, OPUS_SET_BITRATE(28000));
            opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(1));
            opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(10));
            opus_encoder_ctl(enc, OPUS_SET_DTX(1));
            opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(5));
            g_enc = enc;
            g_application = OPUS_APPLICATION_VOIP;
            g_frameSamples = MIC_FRAME_SAMPLES;
            g_bitrateKbps = 28;
        }
        else if (enc != NULL) { opus_encoder_destroy(enc); }
    }
    load_pulse();
    /* Consent never carries over from a previous session, and neither does a
     * device selection from before -- the list itself is re-queried fresh
     * per session anyway (see p22QueryDevices() in default.handlebars). */
    g_consent = 0;
    g_deviceCount = 0;
    g_currentDeviceIndex = -1;
    g_currentSourceName[0] = '\0';
    pthread_mutex_unlock(&g_lock);

    send_caps(writeHandler, reserved);
}

void kvm_mic_set_consent(int granted)
{
    pthread_t thread = (pthread_t)0;

    pthread_mutex_lock(&g_lock);
    g_consent = (granted != 0);
    /* The prompt has been answered either way, so there is nothing left to
     * cancel. */
    g_promptOutstanding = 0;
    if (!g_consent && !g_shutdown)
    {
        g_shutdown = 1;
        thread = g_thread;
        g_thread = (pthread_t)0;
    }
    pthread_mutex_unlock(&g_lock);

    /* Join outside the lock: the capture thread takes it on every frame. */
    if (thread != (pthread_t)0) { pthread_join(thread, NULL); }

    send_caps(g_writeHandler, g_reserved);
}

int kvm_mic_has_consent(void)
{
    int granted;
    pthread_mutex_lock(&g_lock);
    granted = g_consent;
    pthread_mutex_unlock(&g_lock);
    return granted;
}

struct mic_enum_state
{
    int done;
};

/* pa_context_notify_cb_t: state changes are polled directly against
 * pa_context_get_state() in the wait loops below rather than trusted from
 * this callback alone, since the callback and the poll can otherwise race
 * under pa_mainloop_iterate(). Kept only because pa_context_set_state_callback
 * requires *some* callback to be registered. */
static void mic_enum_context_state_cb(pa_context *c, void *userdata)
{
    (void)c; (void)userdata;
}

static void mic_enum_source_info_cb(pa_context *c, const pa_source_info *info, int eol, void *userdata)
{
    struct mic_enum_state *st = (struct mic_enum_state*)userdata;
    const char *label;
    size_t len;

    (void)c;
    if (eol) { st->done = 1; return; }
    if (info == NULL || info->name == NULL) { return; }
    /* Every sink implicitly has a "monitor" source (listen to what it's
     * playing) -- that is audio *output* looped back, not a microphone, and
     * would otherwise flood this list on any machine with a few playback
     * devices. */
    if (info->monitor_of_sink != PA_INVALID_INDEX) { return; }

    /* g_deviceCount/g_deviceLabels/g_deviceSources are also touched by
     * mic_apply_params() (reads) elsewhere; both only ever run from the same
     * single KVM command-dispatch thread today, one command fully processed
     * before the next, so this lock is defense-in-depth against that
     * assumption changing rather than a currently-live race. Cheap enough
     * either way -- enumeration is not a hot path. */
    pthread_mutex_lock(&g_lock);
    if (g_deviceCount >= MIC_DEVICE_MAX_COUNT) { pthread_mutex_unlock(&g_lock); return; }

    label = (info->description != NULL) ? info->description : info->name;
    len = strlen(label);
    if (len > MIC_DEVICE_NAME_MAX) { len = MIC_DEVICE_NAME_MAX; }
    memcpy(g_deviceLabels[g_deviceCount], label, len);
    g_deviceLabels[g_deviceCount][len] = '\0';

    len = strlen(info->name);
    if (len > MIC_SOURCE_NAME_MAX) { len = MIC_SOURCE_NAME_MAX; }
    memcpy(g_deviceSources[g_deviceCount], info->name, len);
    g_deviceSources[g_deviceCount][len] = '\0';

    g_deviceCount++;
    pthread_mutex_unlock(&g_lock);
}

void kvm_mic_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    pa_mainloop *loop = NULL;
    pa_mainloop_api *api;
    pa_context *ctx = NULL;
    pa_operation *op = NULL;
    struct mic_enum_state st;
    int elapsedMs;
    unsigned char *outFrame;
    int outLen, i, count;

    pa_mainloop_new_t fn_loop_new;
    pa_mainloop_get_api_t fn_loop_api;
    pa_mainloop_iterate_t fn_loop_iterate;
    pa_mainloop_free_t fn_loop_free;
    pa_context_new_t fn_ctx_new;
    pa_context_connect_t fn_ctx_connect;
    pa_context_get_state_t fn_ctx_state;
    pa_context_set_state_callback_t fn_ctx_state_cb;
    pa_context_get_source_info_list_t fn_get_sources;
    pa_operation_get_state_t fn_op_state;
    pa_operation_unref_t fn_op_unref;
    pa_context_disconnect_t fn_ctx_disconnect;
    pa_context_unref_t fn_ctx_unref;

    pthread_mutex_lock(&g_lock);
    g_deviceCount = 0;
    pthread_mutex_unlock(&g_lock);

    discover_pulse_server();
    if (!load_pulse_full()) { goto send; }

    fn_loop_new       = (pa_mainloop_new_t)                dlsym(g_pa_full_lib, "pa_mainloop_new");
    fn_loop_api       = (pa_mainloop_get_api_t)             dlsym(g_pa_full_lib, "pa_mainloop_get_api");
    fn_loop_iterate   = (pa_mainloop_iterate_t)             dlsym(g_pa_full_lib, "pa_mainloop_iterate");
    fn_loop_free      = (pa_mainloop_free_t)                dlsym(g_pa_full_lib, "pa_mainloop_free");
    fn_ctx_new        = (pa_context_new_t)                  dlsym(g_pa_full_lib, "pa_context_new");
    fn_ctx_connect    = (pa_context_connect_t)              dlsym(g_pa_full_lib, "pa_context_connect");
    fn_ctx_state      = (pa_context_get_state_t)            dlsym(g_pa_full_lib, "pa_context_get_state");
    fn_ctx_state_cb   = (pa_context_set_state_callback_t)   dlsym(g_pa_full_lib, "pa_context_set_state_callback");
    fn_get_sources    = (pa_context_get_source_info_list_t) dlsym(g_pa_full_lib, "pa_context_get_source_info_list");
    fn_op_state       = (pa_operation_get_state_t)          dlsym(g_pa_full_lib, "pa_operation_get_state");
    fn_op_unref       = (pa_operation_unref_t)              dlsym(g_pa_full_lib, "pa_operation_unref");
    fn_ctx_disconnect = (pa_context_disconnect_t)           dlsym(g_pa_full_lib, "pa_context_disconnect");
    fn_ctx_unref      = (pa_context_unref_t)                dlsym(g_pa_full_lib, "pa_context_unref");

    if (!fn_loop_new || !fn_loop_api || !fn_loop_iterate || !fn_loop_free || !fn_ctx_new ||
        !fn_ctx_connect || !fn_ctx_state || !fn_ctx_state_cb || !fn_get_sources ||
        !fn_op_state || !fn_op_unref || !fn_ctx_disconnect || !fn_ctx_unref)
    {
        goto send;
    }

    memset(&st, 0, sizeof(st));
    loop = fn_loop_new();
    if (loop == NULL) { goto send; }

    api = fn_loop_api(loop);
    ctx = fn_ctx_new(api, "MeshAgent");
    if (ctx == NULL) { fn_loop_free(loop); loop = NULL; goto send; }

    fn_ctx_state_cb(ctx, mic_enum_context_state_cb, &st);
    if (fn_ctx_connect(ctx, NULL, PA_CONTEXT_NOFLAGS, NULL) < 0) { goto cleanup; }

    /* Wait for the context to become ready (or fail), bounded so a hung or
     * missing daemon can never block the KVM command thread indefinitely.
     * block=0 + our own sleep, not block=1: gives this loop sole ownership
     * of the timeout instead of trusting however long libpulse's internal
     * poll() might take per call. */
    for (elapsedMs = 0; ; elapsedMs += MIC_ENUM_POLL_MS)
    {
        pa_context_state_t cs;
        fn_loop_iterate(loop, 0, NULL);
        cs = fn_ctx_state(ctx);
        if (cs == PA_CONTEXT_READY) { break; }
        if (cs == PA_CONTEXT_FAILED || cs == PA_CONTEXT_TERMINATED) { goto cleanup; }
        if (elapsedMs >= MIC_ENUM_TIMEOUT_MS) { goto cleanup; }
        usleep(MIC_ENUM_POLL_MS * 1000);
    }

    op = fn_get_sources(ctx, mic_enum_source_info_cb, &st);
    if (op == NULL) { goto cleanup; }

    for (elapsedMs = 0; ; elapsedMs += MIC_ENUM_POLL_MS)
    {
        fn_loop_iterate(loop, 0, NULL);
        if (st.done || fn_op_state(op) != PA_OPERATION_RUNNING) { break; }
        if (elapsedMs >= MIC_ENUM_TIMEOUT_MS) { break; }
        usleep(MIC_ENUM_POLL_MS * 1000);
    }
    fn_op_unref(op);

cleanup:
    fn_ctx_disconnect(ctx);
    fn_ctx_unref(ctx);
    fn_loop_free(loop);

send:
    pthread_mutex_lock(&g_lock);
    count = g_deviceCount;

    outLen = 5; /* header(4) + count(1) */
    for (i = 0; i < count; i++) { outLen += 1 + (int)strlen(g_deviceLabels[i]); }

    outFrame = (unsigned char*)malloc((size_t)outLen);
    if (outFrame == NULL) { pthread_mutex_unlock(&g_lock); return; }

    outFrame[0] = (unsigned char)((MNG_MIC_DEVICE_LIST >> 8) & 0xFF);
    outFrame[1] = (unsigned char)(MNG_MIC_DEVICE_LIST & 0xFF);
    outFrame[2] = (unsigned char)((outLen >> 8) & 0xFF);
    outFrame[3] = (unsigned char)(outLen & 0xFF);
    outFrame[4] = (unsigned char)count;
    {
        int ptr = 5;
        for (i = 0; i < count; i++)
        {
            size_t len = strlen(g_deviceLabels[i]);
            outFrame[ptr] = (unsigned char)len; ptr++;
            memcpy(outFrame + ptr, g_deviceLabels[i], len);
            ptr += (int)len;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (g_slave_pipe_fd >= 0)
    {
        ssize_t written = write(g_slave_pipe_fd, (char*)outFrame, (size_t)outLen);
        (void)written;
        fsync(g_slave_pipe_fd);
    }
    else if (writeHandler != NULL)
    {
        writeHandler((char*)outFrame, outLen, reserved);
    }
    free(outFrame);
}

/* Apply an optional MNG_MIC_START settings payload. frame/size are the whole
 * wire frame (cmd+len header included), matching every other case in the KVM
 * command switch (see e.g. MNG_KVM_PAUSE in linux_kvm.c) -- fields therefore
 * start at frame[4], not frame[0]. A NULL frame, or one shorter than the
 * 13-byte extended form, leaves everything untouched: this is what makes a
 * legacy 4-byte START (or one from a server that predates this feature)
 * behave exactly as before. Must be called with g_lock held, and only when
 * g_enc is known non-NULL.
 *
 * Every field except application mode and input device can be changed on a
 * live encoder/stream. Application mode is not safe to assume is
 * live-updatable, so a change there destroys and recreates the encoder
 * instead -- this only happens on an operator-initiated profile change,
 * never per-frame, so the recreation cost is irrelevant. Input device has no
 * live-switch primitive in PulseAudio's API at all, so a change there is
 * reported back to the caller (return value 1), which is kvm_mic_start()'s
 * cue to stop and restart the capture thread on the new source.
 *
 * Returns 1 if the input device selection changed (capture thread needs a
 * restart to pick it up), 0 otherwise. */
static int mic_apply_params(const unsigned char *frame, int size)
{
    int bitrateKbps, application, vbr, vbrConstrained, bandwidth, frameMs, complexity, dtx, fec, lossPct;
    int deviceIndex, deviceChanged;

    if (frame == NULL || size < 13) { return 0; }

    bitrateKbps = frame[4];
    if (bitrateKbps == 0) { bitrateKbps = 28; }
    else if (bitrateKbps < 6) { bitrateKbps = 6; }

    switch (frame[5])
    {
        case 1:  application = OPUS_APPLICATION_AUDIO; break;
        case 2:  application = OPUS_APPLICATION_RESTRICTED_LOWDELAY; break;
        default: application = OPUS_APPLICATION_VOIP; break;
    }

    vbr = (frame[6] & 0x01) ? 1 : 0;
    vbrConstrained = (frame[6] & 0x02) ? 1 : 0;

    switch (frame[7])
    {
        case 1:  bandwidth = OPUS_BANDWIDTH_NARROWBAND; break;
        case 2:  bandwidth = OPUS_BANDWIDTH_MEDIUMBAND; break;
        case 3:  bandwidth = OPUS_BANDWIDTH_WIDEBAND; break;
        case 4:  bandwidth = OPUS_BANDWIDTH_SUPERWIDEBAND; break;
        case 5:  bandwidth = OPUS_BANDWIDTH_FULLBAND; break;
        default: bandwidth = OPUS_AUTO; break;
    }

    frameMs = frame[8];
    if (frameMs != 10 && frameMs != 20 && frameMs != 40 && frameMs != 60) { frameMs = 20; }

    complexity = frame[9];
    if (complexity > 10) { complexity = 10; }

    dtx = (frame[10] & 0x01) ? 1 : 0;
    fec = (frame[10] & 0x02) ? 1 : 0;

    lossPct = frame[11];
    if (lossPct > 100) { lossPct = 100; }

    /* 0xFF (or anything past the last enumerated device) = system default.
     * Out-of-range falls back rather than refusing, since the operator's
     * list may simply be stale (nothing re-queried since a device vanished). */
    deviceIndex = frame[12];
    if (deviceIndex >= g_deviceCount) { deviceIndex = -1; }

    if (application != g_application)
    {
        int err = 0;
        OpusEncoder *newEnc = opus_encoder_create(MIC_SAMPLE_RATE, MIC_CHANNELS, application, &err);
        if (newEnc != NULL && err == OPUS_OK)
        {
            opus_encoder_destroy(g_enc);
            g_enc = newEnc;
            g_application = application;
        }
        /* else: keep capturing with the existing encoder/application rather
         * than losing the session over one bad request. */
    }

    opus_encoder_ctl(g_enc, OPUS_SET_BITRATE(bitrateKbps * 1000));
    opus_encoder_ctl(g_enc, OPUS_SET_VBR(vbr));
    opus_encoder_ctl(g_enc, OPUS_SET_VBR_CONSTRAINT(vbrConstrained));
    opus_encoder_ctl(g_enc, OPUS_SET_BANDWIDTH(bandwidth));
    opus_encoder_ctl(g_enc, OPUS_SET_COMPLEXITY(complexity));
    opus_encoder_ctl(g_enc, OPUS_SET_DTX(dtx));
    opus_encoder_ctl(g_enc, OPUS_SET_INBAND_FEC(fec));
    opus_encoder_ctl(g_enc, OPUS_SET_PACKET_LOSS_PERC(lossPct));

    g_frameSamples = (MIC_SAMPLE_RATE * frameMs) / 1000;
    g_bitrateKbps = bitrateKbps;

    deviceChanged = (deviceIndex != g_currentDeviceIndex);
    if (deviceChanged)
    {
        g_currentDeviceIndex = deviceIndex;
        if (deviceIndex >= 0)
        {
            strncpy(g_currentSourceName, g_deviceSources[deviceIndex], sizeof(g_currentSourceName) - 1);
            g_currentSourceName[sizeof(g_currentSourceName) - 1] = '\0';
        }
        else
        {
            g_currentSourceName[0] = '\0';
        }
    }
    return deviceChanged;
}

/* frame/size: the whole MNG_MIC_START wire frame, or NULL/0 when starting
 * without a settings payload (e.g. from MNG_MIC_CONSENT) -- see
 * mic_apply_params() above for the format and the legacy-compatibility rule. */
void kvm_mic_start(const unsigned char *frame, int size)
{
    int needConsentPrompt;
    int deviceChanged;
    pthread_t restartThread = (pthread_t)0;

    pthread_mutex_lock(&g_lock);

    /* Fail closed: never open the microphone without a local decision. */
    if (!g_consent || g_enc == NULL || g_pa_lib == NULL)
    {
        /* Only ask the JS layer to prompt when consent is genuinely why this
         * refused: not when there is no microphone to prompt for. */
        needConsentPrompt = (!g_consent && g_enc != NULL && g_pa_lib != NULL && g_shutdown);
        if (needConsentPrompt) { g_promptOutstanding = 1; }
        pthread_mutex_unlock(&g_lock);
        if (needConsentPrompt) { notify_js(MNG_MIC_CONSENT_NEEDED); }
        return;
    }

    deviceChanged = mic_apply_params(frame, size);

    if (!g_shutdown)
    {
        if (!deviceChanged)
        {
            /* Already capturing on the requested device: the settings above
             * were applied to the live session; nothing else to do. Avoids
             * repeating a full stop/start on every duplicate MNG_MIC_START a
             * browser sends, and is what lets the operator change profile
             * without interrupting audio. */
            pthread_mutex_unlock(&g_lock);
            return;
        }
        /* PulseAudio has no live "switch source" primitive: restart the
         * capture thread on the new device, without touching consent (this
         * is not kvm_mic_stop() -- the session's permission stands). Falls
         * through to the same spawn path a fresh start uses below. */
        g_shutdown = 1;
        restartThread = g_thread;
        g_thread = (pthread_t)0;
    }

    pthread_mutex_unlock(&g_lock);
    if (restartThread != (pthread_t)0) { pthread_join(restartThread, NULL); }
    pthread_mutex_lock(&g_lock);

    g_shutdown = 0;
    if (pthread_create(&g_thread, NULL, capture_thread, NULL) != 0)
    {
        g_shutdown = 1;
        g_thread = (pthread_t)0;
    }
    pthread_mutex_unlock(&g_lock);
}

void kvm_mic_stop(void)
{
    pthread_t thread;
    int wasAwaitingConsent;

    pthread_mutex_lock(&g_lock);
    /* Only when a prompt we raised is still unanswered: stopping when nothing
     * is outstanding must not emit a stray cancel, which would take down an
     * unrelated prompt raised later. */
    wasAwaitingConsent = g_promptOutstanding;
    g_promptOutstanding = 0;
    g_shutdown = 1;
    /* Stopping ends the session's permission; the next start prompts again. */
    g_consent = 0;
    thread = g_thread;
    g_thread = (pthread_t)0;
    pthread_mutex_unlock(&g_lock);

    if (thread != (pthread_t)0) { pthread_join(thread, NULL); }
    g_seq = 0;

    /* Take down that stale prompt before reporting the new state. */
    if (wasAwaitingConsent) { notify_js(MNG_MIC_CONSENT_CANCEL); }

    send_caps(g_writeHandler, g_reserved);
}

/* Kept so the KVM command switch can stay symmetrical with the audio path.
 * Nothing is fed to the microphone: audio only ever travels device -> browser
 * here, and anything arriving on MNG_MIC_DATA is discarded. */
void kvm_mic_feed(char *buffer, int bufferLen)
{
    (void)buffer;
    (void)bufferLen;
}

void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    send_caps(writeHandler, reserved);
}

void kvm_mic_cleanup(void)
{
    OpusEncoder *enc;

    kvm_mic_stop();

    pthread_mutex_lock(&g_lock);
    enc = g_enc;
    g_enc = NULL;
    g_writeHandler = NULL;
    g_reserved = NULL;
    if (g_pa_lib != NULL) { dlclose(g_pa_lib); g_pa_lib = NULL; }
    if (g_pa_full_lib != NULL) { dlclose(g_pa_full_lib); g_pa_full_lib = NULL; }
    pthread_mutex_unlock(&g_lock);

    if (enc != NULL) { opus_encoder_destroy(enc); }
}

#endif /* _KVM_AUDIO */
