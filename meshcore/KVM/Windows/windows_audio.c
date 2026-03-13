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

#if defined(_LINKVM) && defined(_KVM_AUDIO)

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdint.h>
#include <stdio.h>

#include "meshcore/meshdefines.h"
#include "meshcore/KVM/kvm_audio.h"
#include "opus/opus.h"

#pragma comment(lib, "ole32.lib")

/* -----------------------------------------------------------------------
 * Opus encoder globals
 * ---------------------------------------------------------------------- */
#define AUDIO_SAMPLE_RATE   48000
#define AUDIO_CHANNELS      1
#define AUDIO_FRAME_MS      20
#define AUDIO_FRAME_SAMPLES (AUDIO_SAMPLE_RATE * AUDIO_FRAME_MS / 1000)  /* 960 */
#define AUDIO_MAX_PKT       512

static OpusEncoder *g_enc = NULL;
static ILibTransport_DoneState (*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;
static volatile int g_audio_shutdown = 1;
static HANDLE g_audio_thread = NULL;
static uint16_t g_seq = 0;

/* -----------------------------------------------------------------------
 * Send MNG_AUDIO_DATA frame
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
 * WASAPI loopback capture thread
 * ---------------------------------------------------------------------- */
static DWORD WINAPI audio_capture_thread(LPVOID param)
{
    (void)param;
    HRESULT hr;
    IMMDeviceEnumerator *pEnum = NULL;
    IMMDevice *pDevice = NULL;
    IAudioClient *pClient = NULL;
    IAudioCaptureClient *pCapture = NULL;
    WAVEFORMATEX *pwfx = NULL;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
                          &IID_IMMDeviceEnumerator, (void**)&pEnum);
    if (FAILED(hr)) goto done;

    hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eRender, eConsole, &pDevice);
    if (FAILED(hr)) goto done;

    hr = pDevice->lpVtbl->Activate(pDevice, &IID_IAudioClient, CLSCTX_ALL,
                                   NULL, (void**)&pClient);
    if (FAILED(hr)) goto done;

    hr = pClient->lpVtbl->GetMixFormat(pClient, &pwfx);
    if (FAILED(hr)) goto done;

    /* WASAPI loopback = AUDCLNT_STREAMFLAGS_LOOPBACK */
    hr = pClient->lpVtbl->Initialize(pClient, AUDCLNT_SHAREMODE_SHARED,
                                     AUDCLNT_STREAMFLAGS_LOOPBACK,
                                     200 * 10000LL, /* 200ms buffer */
                                     0, pwfx, NULL);
    if (FAILED(hr)) goto done;

    hr = pClient->lpVtbl->GetService(pClient, &IID_IAudioCaptureClient,
                                     (void**)&pCapture);
    if (FAILED(hr)) goto done;

    hr = pClient->lpVtbl->Start(pClient);
    if (FAILED(hr)) goto done;

    /* Rolling PCM accumulator (convert to mono s16 @ 48kHz) */
    int16_t pcm_acc[AUDIO_FRAME_SAMPLES];
    int pcm_acc_fill = 0;
    unsigned char opus_buf[AUDIO_MAX_PKT];

    while (!g_audio_shutdown)
    {
        UINT32 pktsz = 0;
        hr = pCapture->lpVtbl->GetNextPacketSize(pCapture, &pktsz);
        if (FAILED(hr)) break;

        if (pktsz == 0) { Sleep(5); continue; }

        BYTE *pData = NULL;
        UINT32 numFrames = 0;
        DWORD flags = 0;
        hr = pCapture->lpVtbl->GetBuffer(pCapture, &pData, &numFrames, &flags, NULL, NULL);
        if (FAILED(hr)) break;

        /* Down-mix to mono s16 at whatever the mix format provides.
         * We handle float32 (most common on Win10/11) and s16. */
        UINT32 i;
        for (i = 0; i < numFrames && pcm_acc_fill < AUDIO_FRAME_SAMPLES; i++)
        {
            int32_t mono = 0;
            if (pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
               (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
                pwfx->nChannels >= 1))
            {
                /* Assume float32 interleaved */
                float *fptr = (float*)(pData + i * pwfx->nBlockAlign);
                float acc = 0;
                WORD ch;
                for (ch = 0; ch < pwfx->nChannels; ch++) acc += fptr[ch];
                acc /= pwfx->nChannels;
                mono = (int32_t)(acc * 32767.0f);
            }
            else
            {
                /* s16 interleaved */
                int16_t *sptr = (int16_t*)(pData + i * pwfx->nBlockAlign);
                int32_t acc = 0;
                WORD ch;
                for (ch = 0; ch < pwfx->nChannels; ch++) acc += sptr[ch];
                mono = acc / pwfx->nChannels;
            }
            if (mono > 32767)  mono = 32767;
            if (mono < -32767) mono = -32767;
            pcm_acc[pcm_acc_fill++] = (int16_t)mono;

            if (pcm_acc_fill == AUDIO_FRAME_SAMPLES)
            {
                int bytes = opus_encode(g_enc, pcm_acc, AUDIO_FRAME_SAMPLES,
                                        opus_buf, AUDIO_MAX_PKT);
                if (bytes > 0) audio_send_frame(opus_buf, bytes);
                pcm_acc_fill = 0;
            }
        }

        pCapture->lpVtbl->ReleaseBuffer(pCapture, numFrames);
    }

done:
    if (pClient) pClient->lpVtbl->Stop(pClient);
    if (pCapture) pCapture->lpVtbl->Release(pCapture);
    if (pClient)  pClient->lpVtbl->Release(pClient);
    if (pDevice)  pDevice->lpVtbl->Release(pDevice);
    if (pEnum)    pEnum->lpVtbl->Release(pEnum);
    if (pwfx)     CoTaskMemFree(pwfx);
    CoUninitialize();
    return 0;
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

    /* Send MNG_AUDIO_CAPS */
    char caps[9];
    ((unsigned short*)caps)[0] = htons((unsigned short)MNG_AUDIO_CAPS);
    ((unsigned short*)caps)[1] = htons((unsigned short)9);
    caps[4] = 0;    /* 48 kHz */
    caps[5] = (char)AUDIO_CHANNELS;
    caps[6] = 28;
    caps[7] = 0x07; /* DTX | FEC | capture_available */
    caps[8] = 2;    /* platform: Windows */
    if (g_writeHandler) { g_writeHandler(caps, 9, g_reserved); }
}

void kvm_audio_start(void)
{
    if (g_audio_shutdown == 0) return;
    if (!g_enc) return;
    g_audio_shutdown = 0;
    g_audio_thread = CreateThread(NULL, 0, audio_capture_thread, NULL, 0, NULL);
}

void kvm_audio_stop(void)
{
    if (g_audio_shutdown == 1) return;
    g_audio_shutdown = 1;
    if (g_audio_thread != NULL)
    {
        WaitForSingleObject(g_audio_thread, 3000);
        CloseHandle(g_audio_thread);
        g_audio_thread = NULL;
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
    caps[8] = 2;    /* platform: Windows */
    writeHandler(caps, 9, reserved);
}

#endif /* _LINKVM && _KVM_AUDIO */
