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
 * Windows playback of the operator's microphone (browser -> device).
 *
 * The mirror of windows_audio.c: Opus frames arrive from the browser, are
 * decoded to 48 kHz mono and rendered through WASAPI on the default output.
 *
 * Playback is gated on consent obtained by the agent's JavaScript layer, and
 * that gate is enforced here rather than only upstream: kvm_mic_feed() drops
 * every frame while consent is absent, so a caller that skips the handshake
 * still cannot produce sound.
 *
 * Notes matching windows_audio.c:
 *   - The COM GUIDs are defined locally instead of relying on <initguid.h>,
 *     because mmdeviceapi.h is reached indirectly through ILibParsers.h ->
 *     windows.h, so INITGUID cannot be guaranteed to precede it under MSVC.
 *   - The render format is whatever WASAPI reports, so decoded mono 48 kHz is
 *     converted to the mix format's rate, channel count and sample type.
 */

#if defined(_LINKVM) && defined(_KVM_AUDIO)

#include "meshcore/KVM/kvm_mic.h"
#include "meshcore/meshdefines.h"

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "opus/opus.h"

#ifndef WAVE_FORMAT_PCM
#define WAVE_FORMAT_PCM 0x0001
#endif
#ifndef WAVE_FORMAT_IEEE_FLOAT
#define WAVE_FORMAT_IEEE_FLOAT 0x0003
#endif
#ifndef WAVE_FORMAT_EXTENSIBLE
#define WAVE_FORMAT_EXTENSIBLE 0xFFFE
#endif

/* See the note above: declared here so the link does not depend on include
 * order or on uuid.lib. Values are fixed in the Windows SDK. */
static const CLSID MESHMIC_CLSID_MMDeviceEnumerator =
	{ 0xbcde0395, 0xe52f, 0x467c, { 0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e } };
static const IID MESHMIC_IID_IMMDeviceEnumerator =
	{ 0xa95664d2, 0x9614, 0x4f35, { 0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6 } };
static const IID MESHMIC_IID_IAudioClient =
	{ 0x1cb9ad4c, 0xdbfa, 0x4c32, { 0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2 } };
static const IID MESHMIC_IID_IAudioRenderClient =
	{ 0xf294acfc, 0x3146, 0x4483, { 0xa7, 0xbf, 0xad, 0xdc, 0xa7, 0xc2, 0x60, 0xe2 } };

#define MIC_DECODE_RATE   48000
#define MIC_DECODE_CHANS  1
#define MIC_FRAME_MS      20
#define MIC_FRAME_SAMPLES (MIC_DECODE_RATE * MIC_FRAME_MS / 1000)   /* 960 */
#define MIC_HEADER_LEN    7
#define MIC_CAPS_LEN      9
#define MIC_BUFFER_MS     200

static OpusDecoder *g_dec = NULL;
static IMMDeviceEnumerator *g_enum = NULL;
static IMMDevice *g_device = NULL;
static IAudioClient *g_client = NULL;
static IAudioRenderClient *g_render = NULL;
static WAVEFORMATEX *g_fmt = NULL;
static CRITICAL_SECTION g_lock;
static volatile LONG g_lockReady = 0;
static int g_consent = 0;      /* only kvm_mic_set_consent() may set this */
static int g_playing = 0;
static int g_comInit = 0;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;

static void lock_init(void)
{
	if (InterlockedCompareExchange(&g_lockReady, 1, 0) == 0)
	{
		InitializeCriticalSection(&g_lock);
		InterlockedExchange(&g_lockReady, 2);
	}
	while (InterlockedCompareExchange(&g_lockReady, 2, 2) != 2) { Sleep(0); }
}
static void lock(void)   { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { EnterCriticalSection(&g_lock); } }
static void unlock(void) { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { LeaveCriticalSection(&g_lock); } }

static WORD format_tag(const WAVEFORMATEX *fmt)
{
	if (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE && fmt->cbSize >= 22)
	{
		const WAVEFORMATEXTENSIBLE *ext = (const WAVEFORMATEXTENSIBLE*)fmt;
		return (WORD)(ext->SubFormat.Data1 & 0xFFFF);
	}
	return fmt->wFormatTag;
}

/* Write one mono int16 sample into every channel of a render frame. */
static void write_frame(BYTE *dest, double sample, const WAVEFORMATEX *fmt, WORD tag, int bytesPerSample)
{
	WORD ch;
	for (ch = 0; ch < fmt->nChannels; ++ch)
	{
		BYTE *p = dest + ((size_t)ch * (size_t)bytesPerSample);
		if (tag == WAVE_FORMAT_IEEE_FLOAT)
		{
			float f = (float)(sample / 32768.0);
			if (f > 1.0f) { f = 1.0f; } else if (f < -1.0f) { f = -1.0f; }
			memcpy(p, &f, sizeof(float));
		}
		else if (bytesPerSample == 2)
		{
			int16_t s = (int16_t)sample;
			memcpy(p, &s, sizeof(int16_t));
		}
		else if (bytesPerSample == 3)
		{
			int32_t s = (int32_t)(sample * 256.0);
			p[0] = (BYTE)(s & 0xFF); p[1] = (BYTE)((s >> 8) & 0xFF); p[2] = (BYTE)((s >> 16) & 0xFF);
		}
		else
		{
			int32_t s = (int32_t)(sample * 65536.0);
			memcpy(p, &s, sizeof(int32_t));
		}
	}
}

/* Caller must hold the lock. */
static void close_stream(void)
{
	if (g_client != NULL && g_playing) { g_client->lpVtbl->Stop(g_client); }
	if (g_render != NULL) { g_render->lpVtbl->Release(g_render); g_render = NULL; }
	if (g_client != NULL) { g_client->lpVtbl->Release(g_client); g_client = NULL; }
	if (g_device != NULL) { g_device->lpVtbl->Release(g_device); g_device = NULL; }
	if (g_enum != NULL) { g_enum->lpVtbl->Release(g_enum); g_enum = NULL; }
	if (g_fmt != NULL) { CoTaskMemFree(g_fmt); g_fmt = NULL; }
	g_playing = 0;
}

static int playback_available(void)
{
	/* Presence of a render endpoint is the honest answer to "can this device
	 * play the operator's voice?", so probe rather than assume. */
	IMMDeviceEnumerator *en = NULL;
	IMMDevice *dev = NULL;
	HRESULT hr, co;
	int ok = 0;

	co = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = CoCreateInstance(&MESHMIC_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
	                      &MESHMIC_IID_IMMDeviceEnumerator, (void**)&en);
	if (SUCCEEDED(hr) && en != NULL)
	{
		hr = en->lpVtbl->GetDefaultAudioEndpoint(en, eRender, eConsole, &dev);
		if (SUCCEEDED(hr) && dev != NULL) { ok = 1; dev->lpVtbl->Release(dev); }
		en->lpVtbl->Release(en);
	}
	if (SUCCEEDED(co)) { CoUninitialize(); }
	return ok;
}

static void send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	unsigned char caps[MIC_CAPS_LEN];
	int available, granted;

	if (writeHandler == NULL) { return; }

	lock();
	granted = g_consent;
	available = (g_dec != NULL);
	unlock();
	if (available) { available = playback_available(); }

	caps[0] = (unsigned char)((MNG_MIC_CAPS >> 8) & 0xFF);
	caps[1] = (unsigned char)(MNG_MIC_CAPS & 0xFF);
	caps[2] = 0x00;
	caps[3] = (unsigned char)MIC_CAPS_LEN;
	caps[4] = 0;                       /* sample rate: 0 = 48 kHz */
	caps[5] = (unsigned char)MIC_DECODE_CHANS;
	caps[6] = 28;                      /* expected bitrate, kbps */
	caps[7] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00));
	caps[8] = 2;                       /* platform: Windows */

	writeHandler((char*)caps, MIC_CAPS_LEN, reserved);
}

void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	lock_init();

	lock();
	g_writeHandler = writeHandler;
	g_reserved = reserved;
	if (g_dec == NULL)
	{
		int err = 0;
		OpusDecoder *dec = opus_decoder_create(MIC_DECODE_RATE, MIC_DECODE_CHANS, &err);
		if (dec != NULL && err == OPUS_OK) { g_dec = dec; }
		else if (dec != NULL) { opus_decoder_destroy(dec); }
	}
	/* Consent always starts denied, regardless of any previous session. */
	g_consent = 0;
	unlock();

	send_caps(writeHandler, reserved);
}

void kvm_mic_set_consent(int granted)
{
	lock();
	g_consent = (granted != 0);
	if (!g_consent) { close_stream(); }
	unlock();

	send_caps(g_writeHandler, g_reserved);
}

int kvm_mic_has_consent(void)
{
	int granted;
	lock();
	granted = g_consent;
	unlock();
	return granted;
}

void kvm_mic_start(void)
{
	HRESULT hr, co;

	lock();

	/* Fail closed: never open the speaker without a local decision. */
	if (!g_consent || g_dec == NULL || g_playing) { unlock(); return; }

	co = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	g_comInit = SUCCEEDED(co) ? 1 : 0;

	hr = CoCreateInstance(&MESHMIC_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
	                      &MESHMIC_IID_IMMDeviceEnumerator, (void**)&g_enum);
	if (FAILED(hr) || g_enum == NULL) { goto fail; }

	hr = g_enum->lpVtbl->GetDefaultAudioEndpoint(g_enum, eRender, eConsole, &g_device);
	if (FAILED(hr) || g_device == NULL) { goto fail; }

	hr = g_device->lpVtbl->Activate(g_device, &MESHMIC_IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&g_client);
	if (FAILED(hr) || g_client == NULL) { goto fail; }

	hr = g_client->lpVtbl->GetMixFormat(g_client, &g_fmt);
	if (FAILED(hr) || g_fmt == NULL || g_fmt->nChannels == 0 || g_fmt->nBlockAlign == 0) { goto fail; }

	hr = g_client->lpVtbl->Initialize(g_client, AUDCLNT_SHAREMODE_SHARED, 0,
	                                  (REFERENCE_TIME)MIC_BUFFER_MS * 10000, 0, g_fmt, NULL);
	if (FAILED(hr)) { goto fail; }

	hr = g_client->lpVtbl->GetService(g_client, &MESHMIC_IID_IAudioRenderClient, (void**)&g_render);
	if (FAILED(hr) || g_render == NULL) { goto fail; }

	hr = g_client->lpVtbl->Start(g_client);
	if (FAILED(hr)) { goto fail; }

	g_playing = 1;
	unlock();
	return;

fail:
	close_stream();
	if (g_comInit) { CoUninitialize(); g_comInit = 0; }
	unlock();
}

void kvm_mic_stop(void)
{
	lock();
	close_stream();
	if (g_comInit) { CoUninitialize(); g_comInit = 0; }
	/* Stopping ends the session's permission; the next start prompts again. */
	g_consent = 0;
	unlock();

	send_caps(g_writeHandler, g_reserved);
}

void kvm_mic_feed(char *buffer, int bufferLen)
{
	int16_t pcm[MIC_FRAME_SAMPLES * MIC_DECODE_CHANS];
	int samples;
	UINT32 padding = 0, bufferFrames = 0, available;
	BYTE *dest = NULL;
	HRESULT hr;
	WORD tag;
	int bytesPerSample;
	double pos, step;
	UINT32 i, toWrite;

	if (buffer == NULL || bufferLen <= MIC_HEADER_LEN) { return; }

	lock();

	/* The security gate: without consent the frame never reaches the decoder. */
	if (!g_consent || !g_playing || g_dec == NULL || g_render == NULL || g_client == NULL || g_fmt == NULL)
	{
		unlock();
		return;
	}

	samples = opus_decode(g_dec,
	                      (const unsigned char*)(buffer + MIC_HEADER_LEN),
	                      bufferLen - MIC_HEADER_LEN,
	                      pcm, MIC_FRAME_SAMPLES, 0);
	if (samples <= 0) { unlock(); return; }

	if (FAILED(g_client->lpVtbl->GetBufferSize(g_client, &bufferFrames))) { unlock(); return; }
	if (FAILED(g_client->lpVtbl->GetCurrentPadding(g_client, &padding))) { unlock(); return; }
	available = bufferFrames - padding;
	if (available == 0) { unlock(); return; }   /* drop rather than block the caller */

	/* Resample the decoded 48 kHz mono into the endpoint's mix rate. */
	step = (double)MIC_DECODE_RATE / (double)g_fmt->nSamplesPerSec;
	toWrite = (UINT32)((double)samples / step);
	if (toWrite > available) { toWrite = available; }
	if (toWrite == 0) { unlock(); return; }

	hr = g_render->lpVtbl->GetBuffer(g_render, toWrite, &dest);
	if (FAILED(hr) || dest == NULL) { unlock(); return; }

	tag = format_tag(g_fmt);
	bytesPerSample = g_fmt->nBlockAlign / g_fmt->nChannels;
	pos = 0.0;
	for (i = 0; i < toWrite; ++i)
	{
		int idx = (int)pos;
		double s;
		if (idx >= samples) { idx = samples - 1; }
		s = (double)pcm[idx];
		write_frame(dest + ((size_t)i * g_fmt->nBlockAlign), s, g_fmt, tag, bytesPerSample);
		pos += step;
	}

	g_render->lpVtbl->ReleaseBuffer(g_render, toWrite, 0);

	unlock();
}

void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	send_caps(writeHandler, reserved);
}

void kvm_mic_cleanup(void)
{
	OpusDecoder *dec;

	lock();
	close_stream();
	if (g_comInit) { CoUninitialize(); g_comInit = 0; }
	g_consent = 0;
	dec = g_dec;
	g_dec = NULL;
	g_writeHandler = NULL;
	g_reserved = NULL;
	unlock();

	if (dec != NULL) { opus_decoder_destroy(dec); }
}

#endif /* _LINKVM && _KVM_AUDIO */
