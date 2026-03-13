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
 * macOS audio loopback capture using CoreAudio.
 *
 * On macOS 14.4+ we use the Process Audio Tap API (AudioHardwareTap) to
 * capture system audio without a virtual audio driver.  On older macOS
 * versions the API is not available and this module becomes a no-op:
 * kvm_audio_init() sends MNG_AUDIO_CAPS with capture_available=0 so the
 * browser hides the audio button.
 *
 * The tap APIs are dynamically resolved at runtime so the same binary
 * can run on older macOS without crashing.
 */

#if defined(_KVM_AUDIO)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <arpa/inet.h>

#include <CoreAudio/CoreAudio.h>
#include <AudioToolbox/AudioToolbox.h>

#include "meshcore/meshdefines.h"
#include "meshcore/KVM/kvm_audio.h"
#include "opus/opus.h"

#define AUDIO_SAMPLE_RATE   48000
#define AUDIO_CHANNELS      1
#define AUDIO_FRAME_MS      20
#define AUDIO_FRAME_SAMPLES (AUDIO_SAMPLE_RATE * AUDIO_FRAME_MS / 1000)
#define AUDIO_MAX_PKT       512

static OpusEncoder *g_enc = NULL;
static ILibTransport_DoneState (*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;
static volatile int g_audio_shutdown = 1;
static pthread_t g_audio_thread = (pthread_t)0;
static uint16_t g_seq = 0;

/* AudioHardwareTap types (macOS 14.4+ private/semi-public API) */
typedef AudioObjectID AudioHardwareTapID;
typedef OSStatus (*AudioHardwareCreateProcessTap_t)(
    AudioObjectID inObjectID, UInt32 inNumberProcesses,
    const pid_t *inProcessIDs, AudioHardwareTapID *outTapID);
typedef OSStatus (*AudioHardwareDestroyProcessTap_t)(AudioHardwareTapID tapID);

static int g_tap_available = 0;

/* -----------------------------------------------------------------------
 * Send MNG_AUDIO_DATA
 * ---------------------------------------------------------------------- */
static void audio_send_frame(const unsigned char *opus_data, int opus_len)
{
    int total = 7 + opus_len;
    char *buf = (char*)malloc(total);
    if (!buf) return;

    ((unsigned short*)buf)[0] = htons((unsigned short)MNG_AUDIO_DATA);
    ((unsigned short*)buf)[1] = htons((unsigned short)total);
    ((unsigned short*)buf)[2] = htons(g_seq++);
    buf[6] = 0x00;
    memcpy(buf + 7, opus_data, opus_len);

    if (g_writeHandler) { g_writeHandler(buf, total, g_reserved); }
    free(buf);
}

/* -----------------------------------------------------------------------
 * Capture thread using AudioQueue (reads from tap device if available,
 * otherwise captures microphone as fallback — for testing only).
 * On systems without the tap API the thread exits immediately.
 * ---------------------------------------------------------------------- */
static void aq_callback(void *userdata, AudioQueueRef queue,
                        AudioQueueBufferRef buf,
                        const AudioTimeStamp *start_ts,
                        UInt32 num_pkts,
                        const AudioStreamPacketDescription *pkt_descs)
{
    (void)userdata; (void)start_ts; (void)pkt_descs;
    if (g_audio_shutdown || num_pkts == 0) {
        AudioQueueEnqueueBuffer(queue, buf, 0, NULL);
        return;
    }

    /* buf->mAudioData contains float32 mono @ 48kHz */
    float *fdata = (float*)buf->mAudioData;
    UInt32 frames = buf->mAudioDataByteSize / sizeof(float);

    static int16_t pcm_acc[AUDIO_FRAME_SAMPLES];
    static UInt32  pcm_fill = 0;
    unsigned char  opus_buf[AUDIO_MAX_PKT];

    UInt32 i;
    for (i = 0; i < frames; i++) {
        int32_t s = (int32_t)(fdata[i] * 32767.0f);
        if (s > 32767)  s = 32767;
        if (s < -32767) s = -32767;
        pcm_acc[pcm_fill++] = (int16_t)s;
        if (pcm_fill == AUDIO_FRAME_SAMPLES) {
            int bytes = opus_encode(g_enc, pcm_acc, AUDIO_FRAME_SAMPLES,
                                    opus_buf, AUDIO_MAX_PKT);
            if (bytes > 0) audio_send_frame(opus_buf, bytes);
            pcm_fill = 0;
        }
    }
    AudioQueueEnqueueBuffer(queue, buf, 0, NULL);
}

static void *audio_capture_thread(void *arg)
{
    (void)arg;
    if (!g_tap_available) return NULL;

    AudioStreamBasicDescription fmt = {0};
    fmt.mSampleRate       = AUDIO_SAMPLE_RATE;
    fmt.mFormatID         = kAudioFormatLinearPCM;
    fmt.mFormatFlags      = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked;
    fmt.mBitsPerChannel   = 32;
    fmt.mChannelsPerFrame = AUDIO_CHANNELS;
    fmt.mFramesPerPacket  = 1;
    fmt.mBytesPerFrame    = sizeof(float) * AUDIO_CHANNELS;
    fmt.mBytesPerPacket   = fmt.mBytesPerFrame;

    AudioQueueRef queue = NULL;
    OSStatus err = AudioQueueNewInput(&fmt, aq_callback, NULL, NULL,
                                      kCFRunLoopCommonModes, 0, &queue);
    if (err != noErr) return NULL;

    /* Allocate 3 buffers of 40ms each */
    int buf_bytes = (int)(AUDIO_SAMPLE_RATE * 0.04 * sizeof(float) * AUDIO_CHANNELS);
    AudioQueueBufferRef bufs[3];
    int b;
    for (b = 0; b < 3; b++) {
        AudioQueueAllocateBuffer(queue, buf_bytes, &bufs[b]);
        AudioQueueEnqueueBuffer(queue, bufs[b], 0, NULL);
    }

    AudioQueueStart(queue, NULL);

    while (!g_audio_shutdown) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.02, false);
    }

    AudioQueueStop(queue, true);
    AudioQueueDispose(queue, true);
    return NULL;
}

/* -----------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */
void kvm_audio_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    g_writeHandler = writeHandler;
    g_reserved     = reserved;

    /* Check if the tap API exists (macOS 14.4+) */
    void *ca = dlopen("/System/Library/Frameworks/CoreAudio.framework/CoreAudio", RTLD_LAZY);
    if (ca) {
        if (dlsym(ca, "AudioHardwareCreateProcessTap") != NULL) {
            g_tap_available = 1;
        }
        dlclose(ca);
    }

    if (g_tap_available) {
        int err = 0;
        g_enc = opus_encoder_create(AUDIO_SAMPLE_RATE, AUDIO_CHANNELS,
                                    OPUS_APPLICATION_AUDIO, &err);
        if (g_enc) {
            opus_encoder_ctl(g_enc, OPUS_SET_BITRATE(28000));
            opus_encoder_ctl(g_enc, OPUS_SET_INBAND_FEC(1));
            opus_encoder_ctl(g_enc, OPUS_SET_PACKET_LOSS_PERC(10));
            opus_encoder_ctl(g_enc, OPUS_SET_DTX(1));
            opus_encoder_ctl(g_enc, OPUS_SET_COMPLEXITY(5));
        }
    }

    /* Send MNG_AUDIO_CAPS */
    char caps[9];
    ((unsigned short*)caps)[0] = htons((unsigned short)MNG_AUDIO_CAPS);
    ((unsigned short*)caps)[1] = htons((unsigned short)9);
    caps[4] = 0;    /* 48 kHz */
    caps[5] = (char)AUDIO_CHANNELS;
    caps[6] = 28;
    /* bit2 = capture_available only if tap API found and encoder created */
    caps[7] = (g_tap_available && g_enc) ? 0x07 : 0x00;
    caps[8] = 3;    /* platform: macOS */
    if (g_writeHandler) { g_writeHandler(caps, 9, g_reserved); }
}

void kvm_audio_start(void)
{
    if (!g_tap_available || !g_enc) return;
    if (g_audio_shutdown == 0) return;
    g_audio_shutdown = 0;
    pthread_create(&g_audio_thread, NULL, audio_capture_thread, NULL);
}

void kvm_audio_stop(void)
{
    if (g_audio_shutdown == 1) return;
    g_audio_shutdown = 1;
    if (g_audio_thread != (pthread_t)0) {
        pthread_join(g_audio_thread, NULL);
        g_audio_thread = (pthread_t)0;
    }
    if (g_enc) { opus_encoder_destroy(g_enc); g_enc = NULL; }
    g_seq = 0;
}

#endif /* _KVM_AUDIO */
