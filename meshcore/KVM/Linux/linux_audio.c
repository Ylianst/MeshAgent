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

#if defined(_KVM_AUDIO)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <arpa/inet.h>

#include "meshcore/meshdefines.h"
#include "meshcore/KVM/kvm_audio.h"
#include "opus/opus.h"

/* -----------------------------------------------------------------------
 * Opus encoder globals
 * ---------------------------------------------------------------------- */
#define AUDIO_SAMPLE_RATE   48000
#define AUDIO_CHANNELS      1
#define AUDIO_FRAME_MS      20
#define AUDIO_FRAME_SAMPLES (AUDIO_SAMPLE_RATE * AUDIO_FRAME_MS / 1000)  /* 960 */
#define AUDIO_MAX_PKT       512   /* max opus packet bytes */

static OpusEncoder *g_enc = NULL;
static ILibTransport_DoneState (*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;
static volatile int g_audio_shutdown = 1;
static pthread_t g_audio_thread = (pthread_t)0;
static uint16_t g_seq = 0;
static int g_slave_pipe_fd = -1;   /* slave2master[1] registered after fork */

/* -----------------------------------------------------------------------
 * PulseAudio simple API (loaded at runtime via dlopen)
 * ---------------------------------------------------------------------- */
typedef struct pa_simple pa_simple;
typedef enum { PA_STREAM_RECORD = 2 } pa_stream_direction_t;
typedef struct { uint32_t format; uint32_t rate; uint8_t channels; } pa_sample_spec;
#define PA_SAMPLE_S16LE 3

typedef pa_simple* (*pa_simple_new_t)(const char*, const char*, pa_stream_direction_t,
                                      const char*, const char*, const pa_sample_spec*,
                                      const void*, const void*, int*);
typedef int  (*pa_simple_read_t)(pa_simple*, void*, size_t, int*);
typedef void (*pa_simple_free_t)(pa_simple*);

/* -----------------------------------------------------------------------
 * PipeWire simple capture (minimal, loaded at runtime via dlopen)
 * For now we fall back to PulseAudio; PipeWire support can be added later
 * once the PipeWire simple API stabilises in distribution packages.
 * ---------------------------------------------------------------------- */

/* -----------------------------------------------------------------------
 * Send MNG_AUDIO_DATA frame to browser
 * ---------------------------------------------------------------------- */
static void audio_send_frame(const unsigned char *opus_data, int opus_len)
{
    /* 7-byte header: [type 2B][total_len 2B][seq 2B][flags 1B] */
    int total = 7 + opus_len;
    char *buf = (char*)malloc(total);
    if (!buf) return;

    ((unsigned short*)buf)[0] = htons((unsigned short)MNG_AUDIO_DATA);
    ((unsigned short*)buf)[1] = htons((unsigned short)total);
    ((unsigned short*)buf)[2] = htons(g_seq++);
    buf[6] = 0x00; /* flags: not DTX/silence */
    memcpy(buf + 7, opus_data, opus_len);

    if (g_slave_pipe_fd >= 0) {
        write(g_slave_pipe_fd, buf, total);
        fsync(g_slave_pipe_fd);
    } else if (g_writeHandler) {
        /* fallback: parent-mode (before fork) or non-Linux platforms */
        g_writeHandler(buf, total, g_reserved);
    }
    free(buf);
}

void kvm_audio_set_slave_fd(int fd)
{
    g_slave_pipe_fd = fd;
}

/* -----------------------------------------------------------------------
 * Capture thread: PulseAudio monitor source → Opus → browser
 * ---------------------------------------------------------------------- */
static void *audio_capture_thread(void *arg)
{
    (void)arg;
    void *pa_lib = NULL;
    pa_simple *s = NULL;
    int16_t pcm_buf[AUDIO_FRAME_SAMPLES * AUDIO_CHANNELS];
    unsigned char opus_buf[AUDIO_MAX_PKT];
    int err = 0;

    /* Try to load libpulse-simple */
    pa_lib = dlopen("libpulse-simple.so.0", RTLD_LAZY);
    if (!pa_lib) pa_lib = dlopen("libpulse-simple.so", RTLD_LAZY);
    if (!pa_lib) { fprintf(stderr, "MeshAudio: dlopen libpulse-simple failed: %s\n", dlerror()); goto done; }

    pa_simple_new_t  fn_new  = (pa_simple_new_t) dlsym(pa_lib, "pa_simple_new");
    pa_simple_read_t fn_read = (pa_simple_read_t)dlsym(pa_lib, "pa_simple_read");
    pa_simple_free_t fn_free = (pa_simple_free_t)dlsym(pa_lib, "pa_simple_free");
    if (!fn_new || !fn_read || !fn_free) { fprintf(stderr, "MeshAudio: dlsym pa_simple symbols failed\n"); goto done; }

    pa_sample_spec ss = { PA_SAMPLE_S16LE, AUDIO_SAMPLE_RATE, AUDIO_CHANNELS };

    /* Try "@DEFAULT_MONITOR@" first (PipeWire / modern PulseAudio).
     * This captures system audio output (loopback monitor), not the microphone.
     * Fall back to NULL (legacy PulseAudio default input) if unavailable. */
    s = fn_new(NULL, "MeshAgent", PA_STREAM_RECORD,
               "@DEFAULT_MONITOR@", "KVM Audio",
               &ss, NULL, NULL, &err);
    int using_monitor = (s != NULL);
    if (!s) {
        err = 0;
        s = fn_new(NULL, "MeshAgent", PA_STREAM_RECORD,
                   NULL, "KVM Audio",
                   &ss, NULL, NULL, &err);
    }
    if (!s) { fprintf(stderr, "MeshAudio: pa_simple_new failed (both sources), XDG_RUNTIME_DIR=%s\n", getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "(unset)"); goto done; }
    fprintf(stderr, "MeshAudio: pa_simple connected OK source=%s XDG_RUNTIME_DIR=%s\n",
            using_monitor ? "@DEFAULT_MONITOR@" : "default-input",
            getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "(unset)");

    int frame_count = 0;
    while (!g_audio_shutdown)
    {
        if (fn_read(s, pcm_buf, sizeof(pcm_buf), &err) < 0)
        {
            fprintf(stderr, "MeshAudio: pa_simple_read FAILED err=%d after %d frames\n", err, frame_count);
            break;
        }

        int bytes = opus_encode(g_enc, pcm_buf, AUDIO_FRAME_SAMPLES,
                                opus_buf, AUDIO_MAX_PKT);
        if (bytes > 0)
        {
            audio_send_frame(opus_buf, bytes);
            if (++frame_count % 100 == 0)
                fprintf(stderr, "MeshAudio: %d frames captured (opus_len=%d)\n", frame_count, bytes);
        }
    }
    fprintf(stderr, "MeshAudio: capture loop exited after %d frames\n", frame_count);

done:
    if (s && fn_free) fn_free(s);
    if (pa_lib) dlclose(pa_lib);
    return NULL;
}

/* -----------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */
void kvm_audio_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    g_writeHandler = writeHandler;
    g_reserved     = reserved;

    int err = 0;
    g_enc = opus_encoder_create(AUDIO_SAMPLE_RATE, AUDIO_CHANNELS,
                                OPUS_APPLICATION_AUDIO, &err);
    if (!g_enc) return;

    opus_encoder_ctl(g_enc, OPUS_SET_BITRATE(28000));
    opus_encoder_ctl(g_enc, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(g_enc, OPUS_SET_PACKET_LOSS_PERC(10));
    opus_encoder_ctl(g_enc, OPUS_SET_DTX(1));
    opus_encoder_ctl(g_enc, OPUS_SET_COMPLEXITY(5));

    /* Send MNG_AUDIO_CAPS (91):
     * [type 2B][len 2B][sample_rate 1B:0=48kHz][channels 1B][bitrate_kbps 1B][flags 1B][platform 1B]
     * flags: bit0=DTX, bit1=FEC, bit2=capture_available, bit3=mono
     * platform: 1 = Linux
     */
    char caps[9];
    ((unsigned short*)caps)[0] = htons((unsigned short)MNG_AUDIO_CAPS);
    ((unsigned short*)caps)[1] = htons((unsigned short)9);
    caps[4] = 0;    /* sample_rate: 0 = 48 kHz */
    caps[5] = (char)AUDIO_CHANNELS;
    caps[6] = 28;   /* bitrate kbps */
    caps[7] = 0x07; /* DTX | FEC | capture_available */
    caps[8] = 1;    /* platform: Linux */
    if (g_writeHandler) { g_writeHandler(caps, 9, g_reserved); }
}

void kvm_audio_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    if (!writeHandler) return;
    char caps[9];
    ((unsigned short*)caps)[0] = htons((unsigned short)MNG_AUDIO_CAPS);
    ((unsigned short*)caps)[1] = htons((unsigned short)9);
    caps[4] = 0;    /* sample_rate: 0 = 48 kHz */
    caps[5] = (char)AUDIO_CHANNELS;
    caps[6] = 28;   /* bitrate kbps */
    caps[7] = 0x07; /* DTX | FEC | capture_available */
    caps[8] = 1;    /* platform: Linux */
    writeHandler(caps, 9, reserved);
}

void kvm_audio_start(void)
{
    if (g_audio_shutdown == 0) return; /* already running */
    if (!g_enc) return;
    g_audio_shutdown = 0;
    pthread_create(&g_audio_thread, NULL, audio_capture_thread, NULL);
}

void kvm_audio_stop(void)
{
    if (g_audio_shutdown == 1) return;
    g_audio_shutdown = 1;
    if (g_audio_thread != (pthread_t)0)
    {
        pthread_join(g_audio_thread, NULL);
        g_audio_thread = (pthread_t)0;
    }
    /* Do NOT destroy g_enc here — it must survive for audio toggle re-enable.
     * Final destruction is done in kvm_audio_cleanup() called from kvm_cleanup(). */
    g_seq = 0;
}

void kvm_audio_cleanup(void)
{
    kvm_audio_stop();
    if (g_enc) { opus_encoder_destroy(g_enc); g_enc = NULL; }
}

#endif /* _KVM_AUDIO */
