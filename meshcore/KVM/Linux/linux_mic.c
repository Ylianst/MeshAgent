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
 * Linux playback of the operator's microphone (browser -> device).
 *
 * Mirrors meshcore/KVM/Linux/linux_audio.c but in the opposite direction:
 * Opus frames arrive from the browser, are decoded to 48 kHz mono and written
 * to PulseAudio for playback.
 *
 * Playback is gated on consent obtained by the agent's JavaScript layer. The
 * gate is enforced here, not only upstream, so that a caller which skips the
 * handshake still cannot make sound: kvm_mic_feed() discards every frame while
 * g_consent is 0, and stopping playback revokes consent again.
 *
 * libpulse-simple is loaded with dlopen for the same reason as the capture
 * path: the agent ships as a single binary and must run on systems that have
 * no PulseAudio at all, where this feature simply reports itself unavailable.
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
#define MIC_HEADER_LEN    7      /* type(2) len(2) seq(2) flags(1) */
#define MIC_CAPS_LEN      9

/* PulseAudio simple API, resolved at runtime. */
typedef struct pa_simple pa_simple;
typedef enum { PA_STREAM_PLAYBACK = 1 } pa_stream_direction_t;
typedef struct { uint32_t format; uint32_t rate; uint8_t channels; } pa_sample_spec;
#define PA_SAMPLE_S16LE 3

typedef pa_simple* (*pa_simple_new_t)(const char*, const char*, pa_stream_direction_t,
                                      const char*, const char*, const pa_sample_spec*,
                                      const void*, const void*, int*);
typedef int  (*pa_simple_write_t)(pa_simple*, const void*, size_t, int*);
typedef int  (*pa_simple_drain_t)(pa_simple*, int*);
typedef int  (*pa_simple_flush_t)(pa_simple*, int*);
typedef void (*pa_simple_free_t)(pa_simple*);

static OpusDecoder *g_dec = NULL;
static void *g_pa_lib = NULL;
static pa_simple *g_pa = NULL;
static pa_simple_write_t g_pa_write = NULL;
static pa_simple_flush_t g_pa_flush = NULL;
static pa_simple_free_t g_pa_free = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_consent = 0;      /* set only by kvm_mic_set_consent() */
static int g_playing = 0;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;

/* Mirrors discover_pulse_server() in linux_audio.c: when the agent runs as a
 * service there is no XDG_RUNTIME_DIR, so locate an active user's socket. */
static void discover_pulse_server(void)
{
    DIR *d;
    struct dirent *ent;

    if (getenv("PULSE_SERVER") != NULL) { return; }
    d = opendir("/run/user");
    if (d == NULL) { return; }
    while ((ent = readdir(d)) != NULL)
    {
        /* NAME_MAX for the entry plus the fixed prefix and suffix, so the
         * compiler can see the buffer is always large enough. */
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
    if (g_pa_lib == NULL) { return 0; }

    g_pa_write = (pa_simple_write_t)dlsym(g_pa_lib, "pa_simple_write");
    g_pa_flush = (pa_simple_flush_t)dlsym(g_pa_lib, "pa_simple_flush");
    g_pa_free  = (pa_simple_free_t) dlsym(g_pa_lib, "pa_simple_free");
    if (g_pa_write == NULL || g_pa_free == NULL)
    {
        dlclose(g_pa_lib);
        g_pa_lib = NULL;
        return 0;
    }
    return 1;
}

/* Caller must hold g_lock. */
static void close_stream(void)
{
    if (g_pa != NULL)
    {
        int err = 0;
        /* Flush rather than drain: on revoked consent the buffered audio must
         * not be played out. */
        if (g_pa_flush != NULL) { g_pa_flush(g_pa, &err); }
        g_pa_free(g_pa);
        g_pa = NULL;
    }
    g_playing = 0;
}

static void send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    unsigned char caps[MIC_CAPS_LEN];
    int available;

    if (writeHandler == NULL) { return; }

    pthread_mutex_lock(&g_lock);
    available = (g_dec != NULL) && load_pulse();
    caps[7] = (unsigned char)((available ? 0x01 : 0x00) | (g_consent ? 0x02 : 0x00));
    pthread_mutex_unlock(&g_lock);

    caps[0] = (unsigned char)((MNG_MIC_CAPS >> 8) & 0xFF);
    caps[1] = (unsigned char)(MNG_MIC_CAPS & 0xFF);
    caps[2] = 0x00;
    caps[3] = (unsigned char)MIC_CAPS_LEN;
    caps[4] = 0;                          /* sample rate: 0 = 48 kHz */
    caps[5] = (unsigned char)MIC_CHANNELS;
    caps[6] = 28;                         /* expected bitrate, kbps */
    /* caps[7] set above: bit0 playback available, bit1 consent granted */
    caps[8] = 1;                          /* platform: Linux */

    writeHandler((char*)caps, MIC_CAPS_LEN, reserved);
}

void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    int err = 0;

    pthread_mutex_lock(&g_lock);
    g_writeHandler = writeHandler;
    g_reserved = reserved;
    if (g_dec == NULL)
    {
        OpusDecoder *dec = opus_decoder_create(MIC_SAMPLE_RATE, MIC_CHANNELS, &err);
        if (dec != NULL && err == OPUS_OK) { g_dec = dec; }
        else if (dec != NULL) { opus_decoder_destroy(dec); }
    }
    /* Consent always starts denied, even if a previous session granted it. */
    g_consent = 0;
    pthread_mutex_unlock(&g_lock);

    send_caps(writeHandler, reserved);
}

void kvm_mic_set_consent(int granted)
{
    pthread_mutex_lock(&g_lock);
    g_consent = (granted != 0);
    if (!g_consent) { close_stream(); }
    pthread_mutex_unlock(&g_lock);

    /* Tell the browser so its button can reflect the user's decision. */
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
    pa_sample_spec ss;
    pa_simple_new_t fn_new;
    int err = 0;

    pthread_mutex_lock(&g_lock);

    /* Fail closed: never open the speaker without a local decision. */
    if (!g_consent || g_dec == NULL || g_playing) { pthread_mutex_unlock(&g_lock); return; }
    if (!load_pulse()) { pthread_mutex_unlock(&g_lock); return; }

    discover_pulse_server();

    fn_new = (pa_simple_new_t)dlsym(g_pa_lib, "pa_simple_new");
    if (fn_new == NULL) { pthread_mutex_unlock(&g_lock); return; }

    ss.format = PA_SAMPLE_S16LE;
    ss.rate = MIC_SAMPLE_RATE;
    ss.channels = MIC_CHANNELS;

    g_pa = fn_new(NULL, "MeshAgent", PA_STREAM_PLAYBACK, NULL,
                  "Remote Operator", &ss, NULL, NULL, &err);
    g_playing = (g_pa != NULL);

    pthread_mutex_unlock(&g_lock);
}

void kvm_mic_stop(void)
{
    pthread_mutex_lock(&g_lock);
    close_stream();
    /* Stopping ends the session's permission; the next start prompts again. */
    g_consent = 0;
    pthread_mutex_unlock(&g_lock);

    send_caps(g_writeHandler, g_reserved);
}

void kvm_mic_feed(char *buffer, int bufferLen)
{
    int16_t pcm[MIC_FRAME_SAMPLES * MIC_CHANNELS];
    int samples;
    int err = 0;

    if (buffer == NULL || bufferLen <= MIC_HEADER_LEN) { return; }

    pthread_mutex_lock(&g_lock);

    /* The security gate. Without consent the frame is discarded before it can
     * reach the decoder or the speaker. */
    if (!g_consent || !g_playing || g_dec == NULL || g_pa == NULL)
    {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    samples = opus_decode(g_dec,
                          (const unsigned char*)(buffer + MIC_HEADER_LEN),
                          bufferLen - MIC_HEADER_LEN,
                          pcm, MIC_FRAME_SAMPLES, 0);
    if (samples > 0)
    {
        g_pa_write(g_pa, pcm, (size_t)samples * MIC_CHANNELS * sizeof(int16_t), &err);
    }

    pthread_mutex_unlock(&g_lock);
}

void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    send_caps(writeHandler, reserved);
}

void kvm_mic_cleanup(void)
{
    OpusDecoder *dec;

    pthread_mutex_lock(&g_lock);
    close_stream();
    g_consent = 0;
    dec = g_dec;
    g_dec = NULL;
    g_writeHandler = NULL;
    g_reserved = NULL;
    if (g_pa_lib != NULL) { dlclose(g_pa_lib); g_pa_lib = NULL; g_pa_write = NULL; g_pa_flush = NULL; g_pa_free = NULL; }
    pthread_mutex_unlock(&g_lock);

    if (dec != NULL) { opus_decoder_destroy(dec); }
}

#endif /* _KVM_AUDIO */
