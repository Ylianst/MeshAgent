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
 * Windows capture of the device's microphone, streamed to the operator.
 *
 * The sibling of windows_audio.c, travelling in the same direction
 * (device -> browser). The difference is the endpoint: windows_audio.c uses
 * loopback on the render device so the operator hears what the machine plays,
 * while this opens the default capture device so the operator hears the room -
 * the user speaking, and noises worth diagnosing such as fans or drives.
 *
 * Listening to a room is not something a user should discover afterwards, so
 * capture only runs once the local user has agreed. The agent's JavaScript
 * layer shows the prompt; the gate is enforced here too, because a caller that
 * skipped the handshake must still get silence rather than audio.
 *
 * Implementation notes carried over from windows_audio.c:
 *   - The loop polls rather than using AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
 *     which Windows does not reliably signal on an idle stream.
 *   - COM GUIDs are defined locally because mmdeviceapi.h is reached
 *     indirectly through ILibParsers.h -> windows.h, so INITGUID cannot be
 *     guaranteed to precede it under MSVC.
 *   - The sample format is inspected at runtime, since the mix format is
 *     chosen by the OS and varies widely between machines.
 */

#if defined(_LINKVM) && defined(_KVM_AUDIO)

/* kvm_mic.h pulls in ILibParsers.h, which establishes the winsock2 include
 * order before <windows.h> is reached. Keep it first. */
#include "meshcore/KVM/kvm_mic.h"
#include "meshcore/meshdefines.h"

#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <propsys.h>
/* PROPVARIANT/PropVariantInit/PropVariantClear: propsys.h itself only
 * declares IPropertyStore, not the PROPVARIANT helpers used to read a value
 * out of one -- pull those in explicitly rather than depend on windows.h
 * happening to have reached propidl.h by some other transitive path. */
#include <propidl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "opus/opus.h"

/* Define the COM identifiers this file uses. The headers above only declare
 * them (MSVC emits definitions solely when INITGUID was defined before the
 * header was first included, which we cannot guarantee here — see the note at
 * the top of the file). Values are from the Windows SDK and are fixed forever.
 * Guarded so this stays correct if a future include order does define them. */
#ifndef __IMMDeviceEnumerator_INTERFACE_DEFINED_GUIDS__
static const CLSID MESHMIC_CLSID_MMDeviceEnumerator =
	{ 0xbcde0395, 0xe52f, 0x467c, { 0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e } };
static const IID MESHMIC_IID_IMMDeviceEnumerator =
	{ 0xa95664d2, 0x9614, 0x4f35, { 0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6 } };
static const IID MESHMIC_IID_IAudioClient =
	{ 0x1cb9ad4c, 0xdbfa, 0x4c32, { 0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2 } };
static const IID MESHMIC_IID_IAudioCaptureClient =
	{ 0xc8adbd64, 0xe71e, 0x48a0, { 0xa4, 0xde, 0x18, 0x5c, 0x39, 0x5c, 0xd3, 0x17 } };
/* Used only by device enumeration (kvm_mic_query_devices / the deviceIndex
 * half of MNG_MIC_START). Same reasoning as the four above -- defined by
 * hand rather than trusting INITGUID's include-order requirement. */
static const IID MESHMIC_IID_IMMDeviceCollection =
	{ 0x0bd7a1be, 0x7a1a, 0x44db, { 0x83, 0x97, 0xcc, 0x53, 0x92, 0x38, 0x7b, 0x5e } };
static const IID MESHMIC_IID_IPropertyStore =
	{ 0x886d8eeb, 0x8cf2, 0x4446, { 0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99 } };
static const PROPERTYKEY MESHMIC_PKEY_Device_FriendlyName =
	{ { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 14 };
#endif

#ifndef WAVE_FORMAT_PCM
#define WAVE_FORMAT_PCM 0x0001
#endif
#ifndef WAVE_FORMAT_IEEE_FLOAT
#define WAVE_FORMAT_IEEE_FLOAT 0x0003
#endif
#ifndef WAVE_FORMAT_EXTENSIBLE
#define WAVE_FORMAT_EXTENSIBLE 0xFFFE
#endif

/* Opus/stream parameters. These MUST stay in sync with the values advertised
 * in MNG_MIC_CAPS and with the Linux implementation. */
#define MIC_RATE        48000
#define MIC_CHANNELS    1
#define MIC_FRAME_MS        20     /* default frame size until MNG_MIC_START says otherwise */
#define MIC_FRAME_SAMPLES   (MIC_RATE * MIC_FRAME_MS / 1000)   /* 960 */
#define MIC_MAX_FRAME_MS      60   /* largest frame size MNG_MIC_START may request */
#define MIC_MAX_FRAME_SAMPLES (MIC_RATE * MIC_MAX_FRAME_MS / 1000)   /* 2880 */
#define MIC_MAX_PKT         1500   /* Opus worst-case output at the bitrates/frame sizes this now allows */
#define MIC_BITRATE_BPS     28000
#define MIC_BITRATE_KBPS    28
#define MIC_CAPS_LEN        10
#define MIC_POLL_MS         10

#define MIC_DEVICE_MAX_COUNT  32  /* MNG_MIC_DEVICE_LIST's count byte is also this bounded */
#define MIC_DEVICE_NAME_MAX   63  /* display name sent to the browser; truncated, not rejected */
#define MIC_DEVICE_ID_MAX     255 /* real WASAPI endpoint ID, used locally to reopen the device */

/* ~250 ms of mono 48 kHz headroom before we start discarding. */
#define MIC_RING_SAMPLES    (MIC_FRAME_SAMPLES * 12)

typedef struct MicRing
{
	int16_t samples[MIC_RING_SAMPLES];
	int readPos;
	int writePos;
	int count;
} MicRing;

/* Resampler state. Lives on the capture thread stack so that every capture
 * session starts from a clean phase; keeping this in file scope was a bug that
 * made the first frames after a restart use stale interpolation state. */
typedef struct MicResampler
{
	double pos;   /* fractional read cursor carried across buffers */
	double prev;  /* last mono sample of the previous buffer */
} MicResampler;

static OpusEncoder *g_enc = NULL;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;
static int g_application = OPUS_APPLICATION_VOIP; /* application mode the live g_enc was created with */
static int g_frameSamples = MIC_FRAME_SAMPLES;     /* runtime frame size; MNG_MIC_START may change it */
static int g_bitrateKbps = MIC_BITRATE_KBPS;       /* currently-applied bitrate, for caps reporting */
static CRITICAL_SECTION g_lock;
static volatile LONG g_lockReady = 0;
static volatile LONG g_micShutdown = 1;   /* 1 = not capturing */
static HANDLE g_thread = NULL;
static uint16_t g_seq = 0;
static int g_consent = 0;      /* only kvm_mic_set_consent() may set this */
/* 1 between asking the JS layer to prompt and that prompt being resolved, so
 * a cancel is only ever sent for a prompt that is actually on screen. */
static int g_promptOutstanding = 0;
/* Enumerated by kvm_mic_query_devices(), indexed exactly as sent in
 * MNG_MIC_DEVICE_LIST. g_deviceLabels are for display (browser-facing,
 * truncated); g_deviceIds are the real WASAPI endpoint IDs (UTF-8, from
 * IMMDevice::GetId) used locally to reopen a specific device, never sent
 * anywhere. */
static char g_deviceLabels[MIC_DEVICE_MAX_COUNT][MIC_DEVICE_NAME_MAX + 1];
static char g_deviceIds[MIC_DEVICE_MAX_COUNT][MIC_DEVICE_ID_MAX + 1];
static int g_deviceCount = 0;
static int g_currentDeviceIndex = -1;   /* -1 = system default; else index into g_deviceIds */
static char g_currentDeviceId[MIC_DEVICE_ID_MAX + 1] = {0}; /* resolved from g_currentDeviceIndex; capture thread reads this once at start */
static int g_enumInProgress = 0;                    /* guards against two concurrent kvm_mic_query_devices() calls; lock-protected like g_deviceCount */

/* ------------------------------------------------------------------------ */
/* Locking                                                                    */
/* ------------------------------------------------------------------------ */

static void mic_lock_init(void)
{
	/* kvm_mic_init() is the only entry point that runs before any other
	 * audio call, and the KVM starts it from a single thread, but guard the
	 * one-time init anyway so a stray early call cannot race. */
	if (InterlockedCompareExchange(&g_lockReady, 1, 0) == 0)
	{
		InitializeCriticalSection(&g_lock);
		InterlockedExchange(&g_lockReady, 2);
	}
	while (InterlockedCompareExchange(&g_lockReady, 2, 2) != 2) { Sleep(0); }
}

static void mic_lock(void)   { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { EnterCriticalSection(&g_lock); } }
static void mic_unlock(void) { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { LeaveCriticalSection(&g_lock); } }

/* ------------------------------------------------------------------------ */
/* Ring buffer                                                                */
/* ------------------------------------------------------------------------ */

static void ring_init(MicRing *r)
{
	r->readPos = 0;
	r->writePos = 0;
	r->count = 0;
}

static void ring_push(MicRing *r, int16_t sample)
{
	r->samples[r->writePos] = sample;
	r->writePos = (r->writePos + 1) % MIC_RING_SAMPLES;
	if (r->count < MIC_RING_SAMPLES)
	{
		r->count++;
	}
	else
	{
		/* Overrun: the transport is slower than capture. Drop the oldest
		 * sample rather than blocking the WASAPI callback path. */
		r->readPos = (r->readPos + 1) % MIC_RING_SAMPLES;
	}
}

static int ring_pop_frame(MicRing *r, int16_t *out, int count)
{
	int i;
	if (r->count < count) { return 0; }
	for (i = 0; i < count; ++i)
	{
		out[i] = r->samples[r->readPos];
		r->readPos = (r->readPos + 1) % MIC_RING_SAMPLES;
	}
	r->count -= count;
	return 1;
}

/* ------------------------------------------------------------------------ */
/* Format handling                                                            */
/* ------------------------------------------------------------------------ */

static int16_t clamp_s16(double v)
{
	if (v >= 32767.0) { return (int16_t)32767; }
	if (v <= -32768.0) { return (int16_t)(-32768); }
	return (int16_t)v;
}

/* Resolve the effective sample encoding. For WAVE_FORMAT_EXTENSIBLE the
 * SubFormat GUID's Data1 field carries the classic wFormatTag value
 * (1 = PCM, 3 = IEEE float), so we can classify without depending on the
 * KSDATAFORMAT_SUBTYPE_* symbols from ksmedia.h. */
static WORD format_tag(const WAVEFORMATEX *fmt)
{
	if (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE && fmt->cbSize >= 22)
	{
		const WAVEFORMATEXTENSIBLE *ext = (const WAVEFORMATEXTENSIBLE*)fmt;
		return (WORD)(ext->SubFormat.Data1 & 0xFFFF);
	}
	return fmt->wFormatTag;
}

static int format_is_supported(const WAVEFORMATEX *fmt)
{
	WORD tag;
	int bytesPerSample;

	if (fmt == NULL) { return 0; }
	if (fmt->nChannels == 0 || fmt->nBlockAlign == 0) { return 0; }
	if (fmt->nSamplesPerSec == 0) { return 0; }

	bytesPerSample = fmt->nBlockAlign / fmt->nChannels;
	if (bytesPerSample <= 0) { return 0; }

	tag = format_tag(fmt);
	if (tag == WAVE_FORMAT_IEEE_FLOAT) { return (bytesPerSample >= 4); }
	if (tag == WAVE_FORMAT_PCM) { return (bytesPerSample == 2 || bytesPerSample == 3 || bytesPerSample == 4); }
	return 0;
}

/* Read one channel of one frame and normalise it to the int16 domain. */
static double read_sample(const BYTE *frame, WORD channel, const WAVEFORMATEX *fmt, WORD tag, int bytesPerSample)
{
	const BYTE *p = frame + ((size_t)channel * (size_t)bytesPerSample);

	if (tag == WAVE_FORMAT_IEEE_FLOAT)
	{
		float f;
		memcpy(&f, p, sizeof(float));
		if (f > 1.0f) { f = 1.0f; }
		else if (f < -1.0f) { f = -1.0f; }
		return (double)f * 32767.0;
	}

	if (bytesPerSample == 2)
	{
		int16_t s;
		memcpy(&s, p, sizeof(int16_t));
		return (double)s;
	}

	if (bytesPerSample == 3)
	{
		int32_t s = (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16));
		if ((s & 0x00800000) != 0) { s |= (int32_t)0xFF000000; }
		return (double)s / 256.0;   /* 24-bit -> 16-bit */
	}

	/* 32-bit PCM */
	{
		int32_t s;
		memcpy(&s, p, sizeof(int32_t));
		return (double)s / 65536.0;  /* 32-bit -> 16-bit */
	}
}

static double downmix_mono(const BYTE *frame, const WAVEFORMATEX *fmt, WORD tag, int bytesPerSample)
{
	WORD ch;
	double sum = 0.0;
	for (ch = 0; ch < fmt->nChannels; ++ch)
	{
		sum += read_sample(frame, ch, fmt, tag, bytesPerSample);
	}
	return sum / (double)fmt->nChannels;
}

/* ------------------------------------------------------------------------ */
/* Transport                                                                  */
/* ------------------------------------------------------------------------ */

static void mic_send_frame(const unsigned char *opus, int opusLen)
{
	ILibTransport_DoneState(*writeHandler)(char*, int, void*);
	void *reserved;
	unsigned char header[7];
	char *buf;
	int total;

	if (opus == NULL || opusLen <= 0 || opusLen > MIC_MAX_PKT) { return; }

	mic_lock();
	writeHandler = g_writeHandler;
	reserved = g_reserved;
	mic_unlock();
	if (writeHandler == NULL) { return; }

	total = 7 + opusLen;

	/* [type 2B][total_len 2B][seq 2B][flags 1B] — big endian, written byte by
	 * byte so we never depend on struct alignment of the outgoing buffer. */
	header[0] = (unsigned char)((MNG_MIC_DATA >> 8) & 0xFF);
	header[1] = (unsigned char)(MNG_MIC_DATA & 0xFF);
	header[2] = (unsigned char)((total >> 8) & 0xFF);
	header[3] = (unsigned char)(total & 0xFF);
	header[4] = (unsigned char)((g_seq >> 8) & 0xFF);
	header[5] = (unsigned char)(g_seq & 0xFF);
	header[6] = 0x00;   /* flags: not DTX/silence */
	g_seq++;

	buf = (char*)malloc((size_t)total);
	if (buf == NULL) { return; }
	memcpy(buf, header, sizeof(header));
	memcpy(buf + 7, opus, (size_t)opusLen);

	writeHandler(buf, total, reserved);
	free(buf);
}

/* Report whether a capture endpoint actually exists, rather than assuming one
 * does: a desktop with no microphone should hide the control instead of
 * offering a button that can never work. */
static int microphone_available(void)
{
	IMMDeviceEnumerator *en = NULL;
	IMMDevice *dev = NULL;
	HRESULT hr, co;
	int ok = 0;

	co = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = CoCreateInstance(&MESHMIC_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
	                      &MESHMIC_IID_IMMDeviceEnumerator, (void**)&en);
	if (SUCCEEDED(hr) && en != NULL)
	{
		hr = en->lpVtbl->GetDefaultAudioEndpoint(en, eCapture, eConsole, &dev);
		if (SUCCEEDED(hr) && dev != NULL) { ok = 1; dev->lpVtbl->Release(dev); }
		en->lpVtbl->Release(en);
	}
	if (SUCCEEDED(co)) { CoUninitialize(); }
	return ok;
}

typedef struct
{
	ILibTransport_DoneState(*writeHandler)(char*, int, void*);
	void *reserved;
} MicEnumThreadArgs;

/* Enumerate active capture endpoints and send MNG_MIC_DEVICE_LIST: mirrors
 * linux_mic.c's kvm_mic_query_devices() wire format and index semantics
 * (the returned order is this session's index space for a later
 * MNG_MIC_START's device-index byte, valid only until the next call here).
 * Every step is individually NULL/HRESULT-checked and simply contributes
 * nothing on failure rather than aborting the whole enumeration -- one
 * device this system finds troublesome (a bad property store, say)
 * shouldn't hide every other one from the operator.
 *
 * Runs on its own thread -- see kvm_mic_query_devices() below for why this
 * must never run directly on the caller's thread. */
static DWORD WINAPI mic_query_devices_worker(LPVOID param)
{
	MicEnumThreadArgs *targs = (MicEnumThreadArgs*)param;
	ILibTransport_DoneState(*writeHandler)(char*, int, void*);
	void *reserved;
	IMMDeviceEnumerator *pEnum = NULL;
	IMMDeviceCollection *pCollection = NULL;
	HRESULT hr, co;
	UINT count = 0, i;
	int sentCount = 0;
	unsigned char *outFrame;
	int outLen, ptr;

	writeHandler = targs->writeHandler;
	reserved = targs->reserved;
	free(targs);

	co = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = CoCreateInstance(&MESHMIC_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
	                      &MESHMIC_IID_IMMDeviceEnumerator, (void**)&pEnum);
	if (SUCCEEDED(hr) && pEnum != NULL)
	{
		hr = pEnum->lpVtbl->EnumAudioEndpoints(pEnum, eCapture, DEVICE_STATE_ACTIVE, &pCollection);
		if (SUCCEEDED(hr) && pCollection != NULL)
		{
			hr = pCollection->lpVtbl->GetCount(pCollection, &count);
			if (FAILED(hr)) { count = 0; }

			for (i = 0; i < count && sentCount < MIC_DEVICE_MAX_COUNT; i++)
			{
				IMMDevice *pDevice = NULL;
				hr = pCollection->lpVtbl->Item(pCollection, i, &pDevice);
				if (FAILED(hr) || pDevice == NULL) { continue; }

				{
					LPWSTR devId = NULL;
					IPropertyStore *pStore = NULL;
					char label[MIC_DEVICE_NAME_MAX + 1];
					int haveLabel = 0;

					hr = pDevice->lpVtbl->GetId(pDevice, &devId);
					if (FAILED(hr) || devId == NULL) { pDevice->lpVtbl->Release(pDevice); continue; }

					hr = pDevice->lpVtbl->OpenPropertyStore(pDevice, STGM_READ, &pStore);
					if (SUCCEEDED(hr) && pStore != NULL)
					{
						PROPVARIANT var;
						PropVariantInit(&var);
						hr = pStore->lpVtbl->GetValue(pStore, &MESHMIC_PKEY_Device_FriendlyName, &var);
						if (SUCCEEDED(hr) && var.vt == VT_LPWSTR && var.pwszVal != NULL)
						{
							int n = WideCharToMultiByte(CP_UTF8, 0, var.pwszVal, -1, label, sizeof(label), NULL, NULL);
							haveLabel = (n > 0);
						}
						PropVariantClear(&var);
						pStore->lpVtbl->Release(pStore);
					}
					if (!haveLabel)
					{
						/* WideCharToMultiByte truncates silently at the
						 * buffer size, which is exactly the behaviour
						 * wanted here (see MIC_DEVICE_NAME_MAX) -- reuse it
						 * for the fallback label too instead of a second
						 * ad-hoc truncation. */
						WideCharToMultiByte(CP_UTF8, 0, devId, -1, label, sizeof(label), NULL, NULL);
					}
					label[sizeof(label) - 1] = '\0';

					strncpy(g_deviceLabels[sentCount], label, MIC_DEVICE_NAME_MAX);
					g_deviceLabels[sentCount][MIC_DEVICE_NAME_MAX] = '\0';
					WideCharToMultiByte(CP_UTF8, 0, devId, -1, g_deviceIds[sentCount], sizeof(g_deviceIds[sentCount]), NULL, NULL);
					g_deviceIds[sentCount][MIC_DEVICE_ID_MAX] = '\0';
					sentCount++;

					CoTaskMemFree(devId);
				}
				pDevice->lpVtbl->Release(pDevice);
			}
			pCollection->lpVtbl->Release(pCollection);
		}
		pEnum->lpVtbl->Release(pEnum);
	}
	if (SUCCEEDED(co)) { CoUninitialize(); }

	/* mic_lock_init() already ran on the dispatch thread before this worker
	 * was spawned (see kvm_mic_query_devices() below), so the lock is
	 * guaranteed ready here. */
	mic_lock();
	g_deviceCount = sentCount;

	outLen = 5; /* header(4) + count(1) */
	for (i = 0; i < (UINT)sentCount; i++) { outLen += 1 + (int)strlen(g_deviceLabels[i]); }

	outFrame = (unsigned char*)malloc((size_t)outLen);
	if (outFrame == NULL) { g_enumInProgress = 0; mic_unlock(); return 0; }

	outFrame[0] = (unsigned char)((MNG_MIC_DEVICE_LIST >> 8) & 0xFF);
	outFrame[1] = (unsigned char)(MNG_MIC_DEVICE_LIST & 0xFF);
	outFrame[2] = (unsigned char)((outLen >> 8) & 0xFF);
	outFrame[3] = (unsigned char)(outLen & 0xFF);
	outFrame[4] = (unsigned char)sentCount;
	ptr = 5;
	for (i = 0; i < (UINT)sentCount; i++)
	{
		size_t len = strlen(g_deviceLabels[i]);
		outFrame[ptr] = (unsigned char)len; ptr++;
		memcpy(outFrame + ptr, g_deviceLabels[i], len);
		ptr += (int)len;
	}
	mic_unlock();

	if (writeHandler != NULL) { writeHandler((char*)outFrame, outLen, reserved); }
	free(outFrame);

	mic_lock();
	g_enumInProgress = 0;
	mic_unlock();
	return 0;
}

/* Dispatch-thread-facing entry point: only spawns mic_query_devices_worker()
 * and returns immediately, never blocking. This is called synchronously
 * from the same single-threaded KVM command dispatch that also processes
 * MNG_MIC_START -- running enumeration inline here would delay every other
 * KVM command (mouse, keyboard, and critically the very mic-start that
 * triggers the consent prompt) behind however long WASAPI/COM enumeration
 * takes, exactly the class of bug mic_capture_thread already exists to
 * avoid for the streaming side. A rapid double-click (or the browser's own
 * auto-refresh) that arrives while a query is still in flight is coalesced
 * into a no-op rather than started concurrently, since two overlapping
 * enumerations would stomp each other's g_deviceCount/g_deviceLabels/
 * g_deviceIds. */
void kvm_mic_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	MicEnumThreadArgs *targs;
	HANDLE thread;

	mic_lock_init();

	mic_lock();
	if (g_enumInProgress) { mic_unlock(); return; }
	g_enumInProgress = 1;
	mic_unlock();

	targs = (MicEnumThreadArgs*)malloc(sizeof(MicEnumThreadArgs));
	if (targs == NULL)
	{
		mic_lock();
		g_enumInProgress = 0;
		mic_unlock();
		return;
	}
	targs->writeHandler = writeHandler;
	targs->reserved = reserved;

	thread = CreateThread(NULL, 0, mic_query_devices_worker, targs, 0, NULL);
	if (thread == NULL)
	{
		free(targs);
		mic_lock();
		g_enumInProgress = 0;
		mic_unlock();
		return;
	}
	CloseHandle(thread); /* fire-and-forget: nothing needs to join this */
}

static void mic_send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	unsigned char caps[MIC_CAPS_LEN];
	int available, granted, bitrateKbps;

	if (writeHandler == NULL) { return; }

	mic_lock();
	granted = g_consent;
	available = (g_enc != NULL);
	bitrateKbps = g_bitrateKbps;
	mic_unlock();
	if (available) { available = microphone_available(); }

	caps[0] = (unsigned char)((MNG_MIC_CAPS >> 8) & 0xFF);
	caps[1] = (unsigned char)(MNG_MIC_CAPS & 0xFF);
	caps[2] = 0x00;
	caps[3] = (unsigned char)MIC_CAPS_LEN;
	caps[4] = 0;                              /* sample_rate: 0 = 48 kHz */
	caps[5] = (unsigned char)MIC_CHANNELS;
	caps[6] = (unsigned char)bitrateKbps;      /* currently-applied bitrate, kbps */
	/* bit0 microphone available, bit1 local user has granted consent.
	 * The browser reads exactly these two bits to decide whether to show the
	 * button and whether audio is expected. */
	caps[7] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00));
	caps[8] = 2;                              /* platform: Windows */
	caps[9] = 1;                               /* protocol version: MNG_MIC_START accepts a settings payload */

	writeHandler((char*)caps, MIC_CAPS_LEN, reserved);
}

/* Tell the agent's JS layer a consent prompt is needed. Sent from
 * kvm_mic_start() instead of opening the microphone, when consent is
 * specifically the reason it refused. Carries no payload: the plain 4-byte
 * KVM command frame is all a pure signal needs. */
static void notify_js(int command)
{
	ILibTransport_DoneState(*writeHandler)(char*, int, void*);
	void *reserved;
	unsigned char frame[4];

	mic_lock();
	writeHandler = g_writeHandler;
	reserved = g_reserved;
	mic_unlock();
	if (writeHandler == NULL) { return; }

	frame[0] = (unsigned char)((command >> 8) & 0xFF);
	frame[1] = (unsigned char)(command & 0xFF);
	frame[2] = 0x00;
	frame[3] = 0x04;

	writeHandler((char*)frame, (int)sizeof(frame), reserved);
}

/* Same signal as notify_js(MNG_MIC_CONSENT_NEEDED), extended with one byte:
 * whether the browser request that triggered this asked to skip the
 * interactive local-user prompt entirely (the Mic panel, as opposed to the
 * Desktop panel's own mic button -- see agent-desktop-0.0.2.js's
 * SendMicStart()). This is a *request*, not a grant: native still never
 * opens the microphone without g_consent regardless of this flag, and the
 * actual decision to honour it is made by the trusted agent JS layer
 * (agents/meshcore.js's micConsentHandleStart(), the same place that
 * already decides whether server policy requires a prompt at all) rather
 * than by native code trusting a byte the browser supplied directly. */
static void notify_js_consent_needed(int skipPrompt)
{
	ILibTransport_DoneState(*writeHandler)(char*, int, void*);
	void *reserved;
	unsigned char frame[5];

	mic_lock();
	writeHandler = g_writeHandler;
	reserved = g_reserved;
	mic_unlock();
	if (writeHandler == NULL) { return; }

	frame[0] = (unsigned char)((MNG_MIC_CONSENT_NEEDED >> 8) & 0xFF);
	frame[1] = (unsigned char)(MNG_MIC_CONSENT_NEEDED & 0xFF);
	frame[2] = 0x00;
	frame[3] = 0x05;
	frame[4] = (unsigned char)(skipPrompt ? 1 : 0);

	writeHandler((char*)frame, (int)sizeof(frame), reserved);
}

/* ------------------------------------------------------------------------ */
/* Capture thread                                                             */
/* ------------------------------------------------------------------------ */

static void encode_pending(MicRing *ring, int16_t *pcm, unsigned char *opusBuf)
{
	int frameSamples;

	/* One snapshot per call: a live MNG_MIC_START settings change takes
	 * effect starting with the next call rather than mid-drain here. */
	mic_lock();
	frameSamples = g_frameSamples;
	mic_unlock();

	while (ring_pop_frame(ring, pcm, frameSamples))
	{
		OpusEncoder *enc;
		int bytes;

		mic_lock();
		enc = g_enc;
		mic_unlock();
		if (enc == NULL) { return; }

		bytes = opus_encode(enc, pcm, frameSamples, opusBuf, MIC_MAX_PKT);
		/* Opus returns 1 for a pure-DTX "nothing to send" packet; only frames
		 * larger than that carry audio worth transmitting. */
		if (bytes > 1) { mic_send_frame(opusBuf, bytes); }
	}
}

static void push_resampled(const BYTE *data, UINT32 frames, DWORD flags,
                           const WAVEFORMATEX *fmt, WORD tag, int bytesPerSample,
                           MicResampler *rs, MicRing *ring)
{
	double step;

	if (frames == 0) { return; }
	step = (double)fmt->nSamplesPerSec / (double)MIC_RATE;

	if ((flags & AUDCLNT_BUFFERFLAGS_SILENT) != 0 || data == NULL)
	{
		/* The buffer contents are undefined when SILENT is set. Emit digital
		 * silence using the exact same cursor arithmetic as the normal path so
		 * the output sample count and the carried phase stay consistent. */
		while (rs->pos < (double)frames)
		{
			ring_push(ring, 0);
			rs->pos += step;
		}
		rs->pos -= (double)frames;
		rs->prev = 0.0;
		return;
	}

	while (rs->pos < (double)frames)
	{
		UINT32 idx = (UINT32)rs->pos;
		double frac = rs->pos - (double)idx;
		double s0 = (idx == 0)
			? rs->prev
			: downmix_mono(data + ((size_t)(idx - 1) * fmt->nBlockAlign), fmt, tag, bytesPerSample);
		double s1 = downmix_mono(data + ((size_t)idx * fmt->nBlockAlign), fmt, tag, bytesPerSample);
		ring_push(ring, clamp_s16(s0 + ((s1 - s0) * frac)));
		rs->pos += step;
	}

	rs->prev = downmix_mono(data + ((size_t)(frames - 1) * fmt->nBlockAlign), fmt, tag, bytesPerSample);
	rs->pos -= (double)frames;
}

static DWORD WINAPI mic_capture_thread(LPVOID param)
{
	HRESULT hr;
	HRESULT coHr;
	int comInitialised = 0;
	IMMDeviceEnumerator *pEnum = NULL;
	IMMDevice *pDevice = NULL;
	IAudioClient *pClient = NULL;
	IAudioCaptureClient *pCapture = NULL;
	WAVEFORMATEX *pwfx = NULL;
	int started = 0;
	WORD tag = 0;
	int bytesPerSample = 0;
	MicResampler rs;
	MicRing ring;
	int16_t pcm[MIC_MAX_FRAME_SAMPLES]; /* sized for the largest MNG_MIC_START may request */
	unsigned char opusBuf[MIC_MAX_PKT];
	char deviceId[MIC_DEVICE_ID_MAX + 1];
	WCHAR deviceIdW[MIC_DEVICE_ID_MAX + 1];

	UNREFERENCED_PARAMETER(param);

	ring_init(&ring);
	rs.pos = 0.0;
	rs.prev = 0.0;

	/* Read once at thread start, not per-frame like g_frameSamples: unlike
	 * encoder settings, WASAPI has no "switch endpoint on a live stream"
	 * primitive, so a device change is handled by kvm_mic_start() stopping
	 * and restarting this thread entirely -- there is never a live value to
	 * race with here. */
	mic_lock_init();
	mic_lock();
	strncpy(deviceId, g_currentDeviceId, MIC_DEVICE_ID_MAX);
	deviceId[MIC_DEVICE_ID_MAX] = '\0';
	mic_unlock();

	coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (coHr == RPC_E_CHANGED_MODE)
	{
		/* Another COM mode is already active on this thread; we can still use
		 * the apartment but must not balance it with CoUninitialize. */
		comInitialised = 0;
	}
	else if (FAILED(coHr))
	{
		goto done;
	}
	else
	{
		comInitialised = 1;
	}

	hr = CoCreateInstance(&MESHMIC_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
	                      &MESHMIC_IID_IMMDeviceEnumerator, (void**)&pEnum);
	if (FAILED(hr) || pEnum == NULL) { goto done; }

	if (deviceId[0] != '\0' && MultiByteToWideChar(CP_UTF8, 0, deviceId, -1, deviceIdW, MIC_DEVICE_ID_MAX + 1) > 0)
	{
		/* A specific device was selected (see kvm_mic_query_devices()); fall
		 * back to the default endpoint if it no longer exists (unplugged
		 * since selection) rather than failing the session outright. */
		hr = pEnum->lpVtbl->GetDevice(pEnum, deviceIdW, &pDevice);
		if (FAILED(hr) || pDevice == NULL) { hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eCapture, eConsole, &pDevice); }
	}
	else
	{
		hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eCapture, eConsole, &pDevice);
	}
	if (FAILED(hr) || pDevice == NULL) { goto done; }

	hr = pDevice->lpVtbl->Activate(pDevice, &MESHMIC_IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&pClient);
	if (FAILED(hr) || pClient == NULL) { goto done; }

	hr = pClient->lpVtbl->GetMixFormat(pClient, &pwfx);
	if (FAILED(hr) || pwfx == NULL) { goto done; }
	if (!format_is_supported(pwfx)) { goto done; }

	tag = format_tag(pwfx);
	bytesPerSample = pwfx->nBlockAlign / pwfx->nChannels;

	/* Shared-mode loopback on the render endpoint, 200 ms of buffer. */
	/* No AUDCLNT_STREAMFLAGS_LOOPBACK: this is a real capture endpoint, so the
	 * client reads the microphone directly rather than the render mix. */
	hr = pClient->lpVtbl->Initialize(pClient, AUDCLNT_SHAREMODE_SHARED, 0,
	                                 200 * 10000LL, 0, pwfx, NULL);
	if (FAILED(hr)) { goto done; }

	hr = pClient->lpVtbl->GetService(pClient, &MESHMIC_IID_IAudioCaptureClient, (void**)&pCapture);
	if (FAILED(hr) || pCapture == NULL) { goto done; }

	hr = pClient->lpVtbl->Start(pClient);
	if (FAILED(hr)) { goto done; }
	started = 1;

	while (InterlockedCompareExchange(&g_micShutdown, 0, 0) == 0)
	{
		UINT32 pktsz = 0;

		hr = pCapture->lpVtbl->GetNextPacketSize(pCapture, &pktsz);
		if (FAILED(hr)) { break; }

		if (pktsz == 0)
		{
			Sleep(MIC_POLL_MS);
			continue;
		}

		while (pktsz != 0 && InterlockedCompareExchange(&g_micShutdown, 0, 0) == 0)
		{
			BYTE *pData = NULL;
			UINT32 numFrames = 0;
			DWORD flags = 0;

			hr = pCapture->lpVtbl->GetBuffer(pCapture, &pData, &numFrames, &flags, NULL, NULL);
			if (hr == AUDCLNT_S_BUFFER_EMPTY) { break; }
			if (FAILED(hr)) { goto done; }

			push_resampled(pData, numFrames, flags, pwfx, tag, bytesPerSample, &rs, &ring);

			/* ReleaseBuffer must always pair with a successful GetBuffer. */
			pCapture->lpVtbl->ReleaseBuffer(pCapture, numFrames);

			encode_pending(&ring, pcm, opusBuf);

			if (FAILED(pCapture->lpVtbl->GetNextPacketSize(pCapture, &pktsz))) { goto done; }
		}
	}

done:
	if (pClient != NULL && started) { pClient->lpVtbl->Stop(pClient); }
	if (pCapture != NULL) { pCapture->lpVtbl->Release(pCapture); }
	if (pClient != NULL) { pClient->lpVtbl->Release(pClient); }
	if (pDevice != NULL) { pDevice->lpVtbl->Release(pDevice); }
	if (pEnum != NULL) { pEnum->lpVtbl->Release(pEnum); }
	if (pwfx != NULL) { CoTaskMemFree(pwfx); }
	if (comInitialised) { CoUninitialize(); }

	/* Mark the session as finished so a later kvm_mic_start() can spawn a
	 * fresh thread even if capture aborted on its own (no device, etc). */
	InterlockedExchange(&g_micShutdown, 1);
	return 0;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                 */
/* ------------------------------------------------------------------------ */

static void encoder_configure(OpusEncoder *enc)
{
	opus_encoder_ctl(enc, OPUS_SET_BITRATE(MIC_BITRATE_BPS));
	opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(1));
	opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(10));
	opus_encoder_ctl(enc, OPUS_SET_DTX(1));
	opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(5));
}

void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	int haveEncoder;

	mic_lock_init();

	mic_lock();
	g_writeHandler = writeHandler;
	g_reserved = reserved;
	if (g_enc == NULL)
	{
		int err = 0;
		/* VOIP, not AUDIO: this captures speech and room noise, not music --
		 * matches linux_mic.c, which this used to disagree with. */
		OpusEncoder *enc = opus_encoder_create(MIC_RATE, MIC_CHANNELS,
		                                       OPUS_APPLICATION_VOIP, &err);
		if (enc != NULL && err == OPUS_OK)
		{
			encoder_configure(enc);
			g_enc = enc;
			g_application = OPUS_APPLICATION_VOIP;
			g_frameSamples = MIC_FRAME_SAMPLES;
			g_bitrateKbps = MIC_BITRATE_KBPS;
		}
		else if (enc != NULL)
		{
			opus_encoder_destroy(enc);
		}
	}
	/* Neither a device selection nor its enumerated list carries over from a
	 * previous session -- the list itself is re-queried fresh per session
	 * anyway (see p22QueryDevices() in default.handlebars). */
	g_deviceCount = 0;
	g_currentDeviceIndex = -1;
	g_currentDeviceId[0] = '\0';
	haveEncoder = (g_enc != NULL);
	mic_unlock();

	/* Advertise capability so the browser can show the audio button. */
	if (haveEncoder) { mic_send_caps(writeHandler, reserved); }
}

/* Apply an optional MNG_MIC_START settings payload. frame/size are the whole
 * wire frame (cmd+len header included), matching every other case in the KVM
 * command switch -- fields therefore start at frame[4], not frame[0]. A NULL
 * frame, or one shorter than the 13-byte extended form, leaves everything
 * untouched: this is what makes a legacy 4-byte START (or one from a server
 * that predates this feature) behave exactly as before. Must be called with
 * g_lock held (via mic_lock()), and only when g_enc is known non-NULL.
 *
 * Every field except application mode and input device can be changed on a
 * live encoder/stream. Application mode is not safe to assume is
 * live-updatable, so a change there destroys and recreates the encoder
 * instead -- this only happens on an operator-initiated profile change,
 * never per-frame, so the recreation cost is irrelevant. Input device has no
 * live-switch primitive in WASAPI either, so a change there is reported back
 * to the caller (return value 1), which is kvm_mic_start()'s cue to stop and
 * restart the capture thread on the new endpoint. Mirrors linux_mic.c's
 * mic_apply_params().
 *
 * Returns 1 if the input device selection changed (capture thread needs a
 * restart to pick it up), 0 otherwise. */
static int mic_apply_params(const unsigned char *frame, int size)
{
	int bitrateKbps, application, vbr, vbrConstrained, bandwidth, frameMs, complexity, dtx, fec, lossPct;
	int deviceIndex, deviceChanged;

	if (frame == NULL || size < 13) { return 0; }

	bitrateKbps = frame[4];
	if (bitrateKbps == 0) { bitrateKbps = MIC_BITRATE_KBPS; }
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
		OpusEncoder *newEnc = opus_encoder_create(MIC_RATE, MIC_CHANNELS, application, &err);
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

	g_frameSamples = (MIC_RATE * frameMs) / 1000;
	g_bitrateKbps = bitrateKbps;

	deviceChanged = (deviceIndex != g_currentDeviceIndex);
	if (deviceChanged)
	{
		g_currentDeviceIndex = deviceIndex;
		if (deviceIndex >= 0)
		{
			strncpy(g_currentDeviceId, g_deviceIds[deviceIndex], MIC_DEVICE_ID_MAX);
			g_currentDeviceId[MIC_DEVICE_ID_MAX] = '\0';
		}
		else
		{
			g_currentDeviceId[0] = '\0';
		}
	}
	return deviceChanged;
}

/* frame/size: the whole MNG_MIC_START wire frame, or NULL/0 when starting
 * without a settings payload (e.g. from MNG_MIC_CONSENT) -- see
 * mic_apply_params() above for the format and the legacy-compatibility rule. */
void kvm_mic_start(const unsigned char *frame, int size)
{
	HANDLE thread;
	HANDLE restartThread = NULL;
	int deviceChanged;
	int skipConsentPrompt = 0;

	/* Read before mic_apply_params() ever runs: this must still be seen on
	 * the very request that finds !g_consent and refuses below, which is
	 * exactly the frame mic_apply_params() never gets called for. */
	if (frame != NULL && size >= 13) { skipConsentPrompt = (frame[10] & 0x04) ? 1 : 0; }

	mic_lock_init();

	mic_lock();
	if (g_enc == NULL)
	{
		mic_unlock();
		return;
	}
	/* Fail closed: never open the microphone without a local decision, and
	 * never ask for one on a machine that has no microphone at all -- caps
	 * already hides the button for exactly that case (see
	 * microphone_available() above), so a prompt here would be asking about
	 * a device the operator was never even offered. */
	if (!g_consent)
	{
		mic_unlock();
		/* microphone_available() does COM work, so it is called outside the
		 * lock; re-take it only to record that a prompt is now outstanding. */
		if (microphone_available())
		{
			mic_lock();
			g_promptOutstanding = 1;
			mic_unlock();
			notify_js_consent_needed(skipConsentPrompt);
		}
		return;
	}

	deviceChanged = mic_apply_params(frame, size);

	if (g_thread != NULL)
	{
		if (!deviceChanged)
		{
			/* Already capturing on the requested device: the settings above
			 * were applied to the live session; nothing else to do. Avoids
			 * repeating a full stop/start on every duplicate MNG_MIC_START a
			 * browser sends, and is what lets the operator change profile
			 * without interrupting audio. */
			mic_unlock();
			return;
		}
		/* WASAPI has no live "switch endpoint" primitive: restart the
		 * capture thread on the new device, without touching consent (this
		 * is not kvm_mic_stop() -- the session's permission stands). Falls
		 * through to the same spawn path a fresh start uses below. */
		InterlockedExchange(&g_micShutdown, 1);
		restartThread = g_thread;
		g_thread = NULL;
	}

	mic_unlock();
	if (restartThread != NULL) { WaitForSingleObject(restartThread, 3000); CloseHandle(restartThread); }
	mic_lock();

	InterlockedExchange(&g_micShutdown, 0);
	thread = CreateThread(NULL, 0, mic_capture_thread, NULL, 0, NULL);
	if (thread == NULL)
	{
		InterlockedExchange(&g_micShutdown, 1);
	}
	g_thread = thread;
	mic_unlock();
}

void kvm_mic_set_consent(int granted)
{
	HANDLE thread = NULL;

	mic_lock_init();

	mic_lock();
	g_consent = (granted != 0);
	/* The prompt has been answered either way, so there is nothing left to
	 * cancel. */
	g_promptOutstanding = 0;
	if (!g_consent)
	{
		/* Revoking stops capture immediately rather than at the next frame. */
		InterlockedExchange(&g_micShutdown, 1);
		thread = g_thread;
		g_thread = NULL;
	}
	mic_unlock();

	if (thread != NULL) { WaitForSingleObject(thread, 3000); CloseHandle(thread); }

	mic_send_caps(g_writeHandler, g_reserved);
}

int kvm_mic_has_consent(void)
{
	int granted;
	mic_lock_init();
	mic_lock();
	granted = g_consent;
	mic_unlock();
	return granted;
}

/* Kept so the KVM command switch stays symmetrical with the audio path.
 * Audio only ever travels device -> browser here, so anything arriving on
 * MNG_MIC_DATA is discarded. */
void kvm_mic_feed(char *buffer, int bufferLen)
{
	(void)buffer;
	(void)bufferLen;
}

void kvm_mic_stop(void)
{
	HANDLE thread;
	int wasAwaitingConsent;

	mic_lock_init();

	mic_lock();
	/* Only when a prompt we raised is still unanswered: stopping when nothing
	 * is outstanding must not emit a stray cancel, which would take down an
	 * unrelated prompt raised later. */
	wasAwaitingConsent = g_promptOutstanding;
	g_promptOutstanding = 0;
	/* Stopping ends the session's permission; the next start prompts again. */
	g_consent = 0;
	thread = g_thread;
	g_thread = NULL;
	InterlockedExchange(&g_micShutdown, 1);
	mic_unlock();

	/* Take down that stale prompt. */
	if (wasAwaitingConsent) { notify_js(MNG_MIC_CONSENT_CANCEL); }

	if (thread != NULL)
	{
		/* Poll interval is 10 ms, so the thread exits promptly; the generous
		 * timeout only covers a wedged WASAPI call. */
		WaitForSingleObject(thread, 3000);
		CloseHandle(thread);
	}
	g_seq = 0;
}

void kvm_mic_cleanup(void)
{
	OpusEncoder *enc;

	/* Joins the capture thread first, so nothing can touch g_enc afterwards. */
	kvm_mic_stop();

	mic_lock();
	enc = g_enc;
	g_enc = NULL;
	g_writeHandler = NULL;
	g_reserved = NULL;
	mic_unlock();

	if (enc != NULL) { opus_encoder_destroy(enc); }
}

void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
	/* Deliberately does not create an encoder or mutate shared state: this can
	 * be called from the agent's control path in response to MNG_AUDIO_QUERY
	 * before (or without) a capture session existing. */
	mic_send_caps(writeHandler, reserved);
}

#endif /* _LINKVM && _KVM_AUDIO */
