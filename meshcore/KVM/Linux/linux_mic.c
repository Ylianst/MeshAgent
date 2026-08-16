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

#define MIC_SAMPLE_RATE   48000
#define MIC_CHANNELS      1
#define MIC_FRAME_MS      20
#define MIC_FRAME_SAMPLES (MIC_SAMPLE_RATE * MIC_FRAME_MS / 1000)   /* 960 */
#define MIC_MAX_PKT       512
#define MIC_HEADER_LEN    7      /* type(2) len(2) seq(2) flags(1) */
#define MIC_CAPS_LEN      9

/* PulseAudio simple API, resolved at runtime. */
typedef struct pa_simple pa_simple;
typedef enum { PA_STREAM_RECORD = 2 } pa_stream_direction_t;
typedef struct { uint32_t format; uint32_t rate; uint8_t channels; } pa_sample_spec;
#define PA_SAMPLE_S16LE 3

typedef pa_simple* (*pa_simple_new_t)(const char*, const char*, pa_stream_direction_t,
                                      const char*, const char*, const pa_sample_spec*,
                                      const void*, const void*, int*);
typedef int  (*pa_simple_read_t)(pa_simple*, void*, size_t, int*);
typedef void (*pa_simple_free_t)(pa_simple*);

static OpusEncoder *g_enc = NULL;
static void *g_pa_lib = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_consent = 0;      /* only kvm_mic_set_consent() sets this */
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
    int available, granted;

    pthread_mutex_lock(&g_lock);
    available = (g_enc != NULL) && load_pulse();
    granted = g_consent;
    pthread_mutex_unlock(&g_lock);

    caps[0] = (unsigned char)((MNG_MIC_CAPS >> 8) & 0xFF);
    caps[1] = (unsigned char)(MNG_MIC_CAPS & 0xFF);
    caps[2] = 0x00;
    caps[3] = (unsigned char)MIC_CAPS_LEN;
    caps[4] = 0;                          /* sample rate: 0 = 48 kHz */
    caps[5] = (unsigned char)MIC_CHANNELS;
    caps[6] = 28;                         /* bitrate, kbps */
    caps[7] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00));
    caps[8] = 1;                          /* platform: Linux */

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

static void *capture_thread(void *arg)
{
    void *lib = NULL;
    pa_simple *s = NULL;
    pa_simple_new_t fn_new = NULL;
    pa_simple_read_t fn_read = NULL;
    pa_simple_free_t fn_free = NULL;
    pa_sample_spec ss;
    int16_t pcm[MIC_FRAME_SAMPLES * MIC_CHANNELS];
    unsigned char opus[MIC_MAX_PKT];
    int err = 0;

    (void)arg;
    discover_pulse_server();

    pthread_mutex_lock(&g_lock);
    lib = g_pa_lib;
    pthread_mutex_unlock(&g_lock);
    if (lib == NULL) { goto done; }

    fn_new  = (pa_simple_new_t) dlsym(lib, "pa_simple_new");
    fn_read = (pa_simple_read_t)dlsym(lib, "pa_simple_read");
    fn_free = (pa_simple_free_t)dlsym(lib, "pa_simple_free");
    if (fn_new == NULL || fn_read == NULL || fn_free == NULL) { goto done; }

    ss.format = PA_SAMPLE_S16LE;
    ss.rate = MIC_SAMPLE_RATE;
    ss.channels = MIC_CHANNELS;

    /* NULL source = PulseAudio's default input. Deliberately NOT
     * "@DEFAULT_MONITOR@" as in linux_audio.c: the monitor carries what the
     * machine is playing, whereas the point here is to hear the room. */
    s = fn_new(NULL, "MeshAgent", PA_STREAM_RECORD, NULL, "Remote Support Microphone",
               &ss, NULL, NULL, &err);
    if (s == NULL) { goto done; }

    for (;;)
    {
        int bytes;

        /* Re-check consent every frame so a revocation takes effect at once,
         * rather than after some buffer drains. */
        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent || g_enc == NULL) { pthread_mutex_unlock(&g_lock); break; }
        pthread_mutex_unlock(&g_lock);

        if (fn_read(s, pcm, sizeof(pcm), &err) < 0) { break; }

        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent || g_enc == NULL) { pthread_mutex_unlock(&g_lock); break; }
        bytes = opus_encode(g_enc, pcm, MIC_FRAME_SAMPLES, opus, MIC_MAX_PKT);
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
        }
        else if (enc != NULL) { opus_encoder_destroy(enc); }
    }
    load_pulse();
    /* Consent never carries over from a previous session. */
    g_consent = 0;
    pthread_mutex_unlock(&g_lock);

    send_caps(writeHandler, reserved);
}

void kvm_mic_set_consent(int granted)
{
    pthread_t thread = (pthread_t)0;

    pthread_mutex_lock(&g_lock);
    g_consent = (granted != 0);
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

void kvm_mic_start(void)
{
    pthread_mutex_lock(&g_lock);

    /* Fail closed: never open the microphone without a local decision. */
    if (!g_consent || g_enc == NULL || !g_shutdown || g_pa_lib == NULL)
    {
        pthread_mutex_unlock(&g_lock);
        return;
    }
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

    pthread_mutex_lock(&g_lock);
    g_shutdown = 1;
    /* Stopping ends the session's permission; the next start prompts again. */
    g_consent = 0;
    thread = g_thread;
    g_thread = (pthread_t)0;
    pthread_mutex_unlock(&g_lock);

    if (thread != (pthread_t)0) { pthread_join(thread, NULL); }
    g_seq = 0;

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
    pthread_mutex_unlock(&g_lock);

    if (enc != NULL) { opus_encoder_destroy(enc); }
}

#endif /* _KVM_AUDIO */
