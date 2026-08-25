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
 * Windows capture of the device's webcam, streamed to the operator.
 *
 * The visual sibling of windows_mic.c, and deliberately built the same way: a
 * fail-closed consent gate the agent's JavaScript layer drives, enumeration
 * that never runs on the KVM command thread, and (for the still-photo path) a
 * device open/negotiate/capture sequence that mirrors linux_cam.c function for
 * function. See kvm_cam.h for the wire formats and for why this streams JPEG
 * frames instead of a video codec.
 *
 * Two platform libraries do the work V4L2's ioctls and libjpeg-turbo do on
 * Linux:
 *
 *   - Media Foundation (Mf.lib/Mfplat.lib/Mfreadwrite.lib/Mfuuid.lib) opens
 *     the camera and hands back frames. Unlike V4L2, MF has no driver-side
 *     "closest fit" format negotiation -- cam_pick_native_type() below has to
 *     walk the device's native types itself. The live stream uses the Source
 *     Reader's asynchronous mode (a callback invoked on MF's own worker
 *     threads) rather than blocking reads, because a synchronous read has no
 *     timeout and would let a wedged or unplugged camera hang session
 *     teardown indefinitely; the still-photo path stays synchronous, exactly
 *     mirroring linux_cam.c's cam_dev_grab() loop, since a snapshot is
 *     already bounded by its own small attempt count.
 *   - Windows Imaging Component (Windowscodecs.lib) encodes raw frames to
 *     JPEG and produces the scaled-down grayscale thumbnail that drives
 *     static-scene suppression, in place of libjpeg-turbo. WIC is COM-based
 *     like everything else in this file; a fresh IWICImagingFactory is
 *     created per call, mirroring linux_cam.c's own per-call
 *     tjInitCompress()/tjDestroy() pattern rather than introducing a
 *     shared-lifetime object to reason about.
 *
 * MJPEG passthrough is still the common case and still costs zero CPU: when
 * the camera's native type is already MFVideoFormat_MJPG, SetCurrentMediaType
 * is given that exact type with nothing rebuilt, so MF has no reason to insert
 * a decode/convert transform -- the bytes handed to send_frame() are the
 * sensor's own JPEG, same as V4L2_PIX_FMT_MJPEG on Linux. Cameras that only
 * offer raw output fall back through YUY2 then NV12 (MF exposes whichever raw
 * subtype the sensor actually uses, so both are needed for real-world
 * coverage; V4L2 only ever needs YUYV because the kernel driver normalises to
 * it).
 */

#if defined(_LINKVM) && defined(_KVM_CAMERA)

/* kvm_cam.h pulls in ILibParsers.h, which establishes the winsock2 include
 * order before <windows.h> is reached -- keep it first, exactly as
 * windows_mic.c does for kvm_mic.h. */
#include "meshcore/KVM/kvm_cam.h"
#include "meshcore/meshdefines.h"

#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <wincodec.h>
/* VariantInit/VARIANT: used to set the JPEG encoder's quality property.
 * Pulled in explicitly rather than trusted to some other header's transitive
 * include, matching windows_mic.c's own explicit-include stance on propidl.h. */
#include <oleauto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Windows Imaging Component GUIDs, defined locally for the same reason
 * windows_mic.c defines its own audio-endpoint GUIDs: mmdeviceapi.h (there)
 * and wincodec.h (here) are both reached indirectly through
 * ILibParsers.h -> windows.h, so an INITGUID define placed here cannot be
 * guaranteed to precede the header's first inclusion under MSVC. Values are
 * from the Windows SDK (Microsoft Learn's "WIC GUIDs and CLSIDs" reference)
 * and are fixed forever. Media Foundation's own GUIDs (MFVideoFormat_MJPG,
 * MF_MT_SUBTYPE, and the rest) do not need this treatment: they are declared
 * extern in mfapi.h/mfidl.h/mfreadwrite.h and *defined* in Mfuuid.lib, not
 * gated behind INITGUID, so linking that lib is sufficient.
 */
#ifndef __MESHCAM_WIC_GUIDS_DEFINED__
#define __MESHCAM_WIC_GUIDS_DEFINED__
static const CLSID MESHCAM_CLSID_WICImagingFactory =
    { 0xcacaf262, 0x9370, 0x4615, { 0xa1, 0x3b, 0x9f, 0x55, 0x39, 0xda, 0x4c, 0x0a } };
static const IID MESHCAM_IID_IWICImagingFactory =
    { 0xec5ec8a9, 0xc0ff, 0x4541, { 0xa4, 0x01, 0xcd, 0x33, 0x67, 0xf6, 0xb5, 0x0b } };
static const GUID MESHCAM_GUID_ContainerFormatJpeg =
    { 0x19e4a5aa, 0x5662, 0x4fc5, { 0xa0, 0xc0, 0x17, 0x58, 0x02, 0x8e, 0x10, 0x57 } };
static const GUID MESHCAM_GUID_WICPixelFormat24bppRGB =
    { 0x6fddc324, 0x4e03, 0x4bfe, { 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0d } };
static const GUID MESHCAM_GUID_WICPixelFormat8bppGray =
    { 0x6fddc324, 0x4e03, 0x4bfe, { 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x08 } };
#endif

#define CAM_DEFAULT_WIDTH     640
#define CAM_DEFAULT_HEIGHT    480
#define CAM_DEFAULT_FPS       15
#define CAM_DEFAULT_QUALITY   75
#define CAM_SNAPSHOT_QUALITY  100  /* a still is sent once, so it always defaults to the camera's best */
#define CAM_DEFAULT_THRESHOLD 3    /* mean absolute luma difference; sensor noise alone sits well under this */

#define CAM_MAX_FPS           60
#define CAM_MAX_WIDTH         4096
#define CAM_MAX_HEIGHT        2160
#define CAM_CAPS_LEN          14
#define CAM_SNAP_HEADER       16  /* see kvm_cam.h for the field layout */
#define CAM_JUMBO_THRESHOLD   65500 /* same cutover desktop tiles use */

#define CAM_DEVICE_MAX_COUNT  16
#define CAM_DEVICE_NAME_MAX   63
/* A real MF symbolic-link device path (e.g. \\?\usb#vid_...#{...}\global),
 * used locally to reopen a specific device and never sent anywhere -- much
 * longer than V4L2's /dev/videoN, hence wider than linux_cam.c's equivalent. */
#define CAM_DEVICE_ID_MAX     255

/* Bounded wait for the live stream's Flush() to complete when stopping or
 * restarting it -- see cam_teardown_live(). Not carried over from any Linux
 * precedent (V4L2's teardown is a pthread_join with no separate timeout of
 * its own); chosen a little wider than windows_mic.c's 3000ms WASAPI-thread
 * join since a camera's frame interval can itself be slower than an audio
 * buffer's. */
#define CAM_STOP_WAIT_MS      5000

#define CAM_PENDING_START     0x01
#define CAM_PENDING_SNAPSHOT  0x02
#define CAM_START_FRAME_LEN   14

/* Enumerated by kvm_cam_query_devices(), indexed exactly as sent in
 * MNG_CAM_DEVICE_LIST. Labels are browser-facing and truncated; IDs are the
 * real MF symbolic links, used locally and never sent anywhere -- the direct
 * translation of linux_cam.c's g_deviceLabels/g_devicePaths pair. */
static char g_deviceLabels[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_NAME_MAX + 1];
static char g_deviceIds[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_ID_MAX + 1];
static int g_deviceCount = 0;
static int g_currentDeviceIndex = -1;                        /* -1 = system default */
static char g_currentDeviceId[CAM_DEVICE_ID_MAX + 1] = {0};  /* resolved from the index; read once at setup */

static int g_width = CAM_DEFAULT_WIDTH;
static int g_height = CAM_DEFAULT_HEIGHT;
static int g_fps = CAM_DEFAULT_FPS;
static int g_quality = CAM_DEFAULT_QUALITY;
static int g_suppress = 1;                       /* static-scene suppression enabled */
static int g_threshold = CAM_DEFAULT_THRESHOLD;
static int g_forceRaw = 0;                       /* skip MJPEG passthrough even when offered */
static int g_passthroughActive = 0;              /* what the live stream actually ended up doing */

static CRITICAL_SECTION g_lock;
static volatile LONG g_lockReady = 0;
static int g_consent = 0;                        /* only kvm_cam_set_consent() may set this */
/* 1 between asking the JS layer to prompt and that prompt being resolved, so a
 * cancel is only ever sent for a prompt that is actually on screen. */
static int g_promptOutstanding = 0;
static int g_enumInProgress = 0;
static int g_initialised = 0;
static uint16_t g_seq = 0;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;

/* Media Foundation / COM lifetime. MFStartup requires a matching MFShutdown,
 * and is safe to call once per process the way this session-per-process agent
 * already assumes for kvm_mic_init()'s CoInitializeEx calls. */
static int g_mfStarted = 0;

/* The live stream's state. Unlike linux_cam.c's g_thread (a pthread the KVM
 * session owns end to end), there is no dedicated OS thread for the running
 * stream here: cam_capture_setup_thread() only performs the open/negotiate
 * step and then exits, after which frames arrive on Media Foundation's own
 * worker threads via g_liveCallback's OnReadSample. "Is a stream running" is
 * therefore tracked by g_liveReader being non-NULL, not by a thread handle. */
static IMFSourceReader *g_liveReader = NULL;
static void *g_liveCallback = NULL;   /* CamReaderCallback*; void* so this header block needn't forward-declare the struct */
static volatile LONG g_liveShutdown = 1;  /* 1 = no live stream armed */
static HANDLE g_liveStopEvent = NULL;     /* signalled from OnFlush()/a declining OnReadSample() -- see cam_teardown_live() */
static int g_setupInProgress = 0;         /* guards kvm_cam_start() from racing its own setup thread */

/* A snapshot always captures independently, at its own requested resolution
 * (by default, the camera's largest) rather than whatever the live stream
 * happens to be running at. MF sources are single-open per physical device
 * exactly like V4L2, so if the stream is running when a snapshot is asked
 * for, the worker pauses it for the moment it takes to grab one frame, then
 * restarts it -- see g_snapshotPausedStream below. */
static volatile int g_snapshotPending = 0;
static int g_snapshotQuality = CAM_SNAPSHOT_QUALITY;
/* The resolution this snapshot -- in flight, or waiting on consent -- was
 * actually asked for; 0x0 means "the camera's best", resolved by
 * cam_find_max_resolution() in the worker. Deliberately separate from
 * g_width/g_height, which describe the stream. */
static int g_pendingSnapWidth = 0;
static int g_pendingSnapHeight = 0;
/* -1 = system default, matching g_currentDeviceIndex's convention; else an
 * index into the last enumeration, already bounds-checked when stashed. */
static int g_pendingSnapDeviceIndex = -1;
/* 1 while a snapshot has the live stream paused to reuse the (single-open)
 * device at its own resolution -- guards kvm_cam_start() from racing it to
 * open a second reader for the same device. See cam_snapshot_worker(). */
static volatile int g_snapshotPausedStream = 0;

/* MNG_CAM_CONSENT (the local user's answer) is one generic signal shared by
 * every kind of request that can need it; see kvm_cam.h and linux_cam.c for
 * the full rationale -- this pair is a verbatim port of the Linux globals. */
static volatile int g_pendingAction = 0;
static unsigned char g_pendingStartFrame[CAM_START_FRAME_LEN];
static int g_pendingStartFrameLen = 0;

/* Previous frame reduced to 1/8-scale luma, for static-scene suppression.
 * Reallocated only when the dimensions change. */
static unsigned char *g_prevThumb = NULL;
static int g_prevThumbW = 0, g_prevThumbH = 0;
static int g_prevThumbValid = 0;

typedef struct
{
    ILibTransport_DoneState(*writeHandler)(char*, int, void*);
    void *reserved;
} cam_thread_args_t;

/* ------------------------------------------------------------------------ */
/* Locking                                                                    */
/* ------------------------------------------------------------------------ */

/* Verbatim port of windows_mic.c's mic_lock_init/mic_lock/mic_unlock, renamed
 * for this module. See that file for why the lazy InterlockedCompareExchange
 * dance is used instead of a plain static initializer. */
static void cam_lock_init(void)
{
    if (InterlockedCompareExchange(&g_lockReady, 1, 0) == 0)
    {
        InitializeCriticalSection(&g_lock);
        InterlockedExchange(&g_lockReady, 2);
    }
    while (InterlockedCompareExchange(&g_lockReady, 2, 2) != 2) { Sleep(0); }
}

static void cam_lock(void)   { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { EnterCriticalSection(&g_lock); } }
static void cam_unlock(void) { if (InterlockedCompareExchange(&g_lockReady, 2, 2) == 2) { LeaveCriticalSection(&g_lock); } }

/* ------------------------------------------------------------------------ */
/* Transport                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Every outbound frame goes through here, serialized on its own critical
 * section rather than g_lock -- exactly linux_cam.c's g_sendLock split, and
 * for the same reason: a frame write must never block a settings check
 * behind it, and two writers (the live stream and a snapshot worker) really
 * can land on this at once. There is no slave-pipe branch: Windows KVM
 * sessions do not fork, so g_writeHandler is always the whole story here.
 */
static CRITICAL_SECTION g_sendLock;
static volatile LONG g_sendLockReady = 0;

static void cam_send_lock_init(void)
{
    if (InterlockedCompareExchange(&g_sendLockReady, 1, 0) == 0)
    {
        InitializeCriticalSection(&g_sendLock);
        InterlockedExchange(&g_sendLockReady, 2);
    }
    while (InterlockedCompareExchange(&g_sendLockReady, 2, 2) != 2) { Sleep(0); }
}

static void cam_write_out(const char *buf, int len)
{
    ILibTransport_DoneState(*writeHandler)(char*, int, void*);
    void *reserved;

    cam_lock();
    writeHandler = g_writeHandler;
    reserved = g_reserved;
    cam_unlock();
    if (writeHandler == NULL) { return; }

    cam_send_lock_init();
    EnterCriticalSection(&g_sendLock);
    writeHandler((char*)buf, len, reserved);
    LeaveCriticalSection(&g_sendLock);
}

/*
 * Send one command frame, transparently using MNG_JUMBO when the payload is
 * too large for the KVM header's 16-bit length -- a JPEG at any useful
 * resolution routinely is. Verbatim port of linux_cam.c's cam_send(): this is
 * wire-format logic, not platform-specific.
 */
static void cam_send(int cmd, const unsigned char *hdr, int hdrLen, const unsigned char *payload, int payloadLen)
{
    int innerLen = 4 + hdrLen + payloadLen;
    int jumbo = (innerLen > CAM_JUMBO_THRESHOLD);
    int total = jumbo ? (8 + innerLen) : innerLen;
    char *buf;
    int p;

    if (payloadLen < 0 || hdrLen < 0) { return; }
    buf = (char*)malloc((size_t)total);
    if (buf == NULL) { return; }

    p = 0;
    if (jumbo)
    {
        ((unsigned short*)buf)[0] = htons((unsigned short)MNG_JUMBO);
        ((unsigned short*)buf)[1] = htons((unsigned short)8);
        ((unsigned int*)buf)[1] = htonl((unsigned int)innerLen);
        p = 8;
    }

    ((unsigned short*)(buf + p))[0] = htons((unsigned short)cmd);
    /* Meaningless once wrapped -- the receiver takes the length from the
     * JUMBO header -- so mirror what the desktop tile path writes there: zero. */
    ((unsigned short*)(buf + p))[1] = jumbo ? 0 : htons((unsigned short)innerLen);
    if (hdrLen > 0) { memcpy(buf + p + 4, hdr, (size_t)hdrLen); }
    if (payloadLen > 0) { memcpy(buf + p + 4 + hdrLen, payload, (size_t)payloadLen); }

    cam_write_out(buf, total);
    free(buf);
}

/* Report whether a capture device actually exists, rather than assuming one
 * does -- mirrors windows_mic.c's microphone_available(). A cheap probe: ask
 * Media Foundation to enumerate video capture sources and see if the count is
 * non-zero, without activating (opening) any of them. */
static int camera_available(void)
{
    IMFAttributes *pAttributes = NULL;
    IMFActivate **ppDevices = NULL;
    UINT32 count = 0;
    HRESULT hr;
    int ok = 0;

    hr = MFCreateAttributes(&pAttributes, 1);
    if (FAILED(hr) || pAttributes == NULL) { return 0; }

    hr = pAttributes->lpVtbl->SetGUID(pAttributes, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                                      &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (SUCCEEDED(hr))
    {
        hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count);
        if (SUCCEEDED(hr)) { ok = (count > 0); }
    }

    if (ppDevices != NULL)
    {
        UINT32 i;
        for (i = 0; i < count; i++) { if (ppDevices[i] != NULL) { ppDevices[i]->lpVtbl->Release(ppDevices[i]); } }
        CoTaskMemFree(ppDevices);
    }
    pAttributes->lpVtbl->Release(pAttributes);
    return ok;
}

static void send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    unsigned char caps[CAM_CAPS_LEN];
    int available, granted, passthrough, w, h, fps, quality, devCount;

    cam_lock();
    available = (g_deviceCount > 0);
    granted = g_consent;
    passthrough = g_passthroughActive;
    w = g_width; h = g_height; fps = g_fps; quality = g_quality;
    devCount = g_deviceCount;
    cam_unlock();
    /* Only pay for a live enumeration probe when the cached count says
     * nothing was found yet -- mirrors send_caps()'s access("/dev/video0")
     * fallback on Linux, which is likewise skipped once g_deviceCount says a
     * camera is already known to exist. */
    if (!available) { available = camera_available(); }

    caps[0] = (unsigned char)((MNG_CAM_CAPS >> 8) & 0xFF);
    caps[1] = (unsigned char)(MNG_CAM_CAPS & 0xFF);
    caps[2] = 0x00;
    caps[3] = (unsigned char)CAM_CAPS_LEN;
    caps[4] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00) | (passthrough ? 0x04 : 0x00));
    caps[5] = 2;    /* platform: Windows */
    caps[6] = (unsigned char)((w >> 8) & 0xFF);
    caps[7] = (unsigned char)(w & 0xFF);
    caps[8] = (unsigned char)((h >> 8) & 0xFF);
    caps[9] = (unsigned char)(h & 0xFF);
    caps[10] = (unsigned char)fps;
    caps[11] = 1;   /* protocol version */
    caps[12] = (unsigned char)quality;
    caps[13] = (unsigned char)devCount;

    if (writeHandler != NULL)
    {
        cam_send_lock_init();
        EnterCriticalSection(&g_sendLock);
        writeHandler((char*)caps, CAM_CAPS_LEN, reserved);
        LeaveCriticalSection(&g_sendLock);
    }
    else
    {
        cam_write_out((char*)caps, CAM_CAPS_LEN);
    }
}

/* Pure signal to the agent's JS layer; carries no payload. */
static void notify_js(int command)
{
    unsigned char frame[4];

    frame[0] = (unsigned char)((command >> 8) & 0xFF);
    frame[1] = (unsigned char)(command & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x04;
    cam_write_out((char*)frame, (int)sizeof(frame));
}

/*
 * Same signal as notify_js(MNG_CAM_CONSENT_NEEDED) plus one byte: whether the
 * browser request that triggered this asked to skip the interactive prompt.
 * That is a *request*, not a grant -- native never opens the camera without
 * g_consent regardless of it. Verbatim port of linux_cam.c's equivalent.
 */
static void notify_js_consent_needed(int skipPrompt)
{
    unsigned char frame[5];

    frame[0] = (unsigned char)((MNG_CAM_CONSENT_NEEDED >> 8) & 0xFF);
    frame[1] = (unsigned char)(MNG_CAM_CONSENT_NEEDED & 0xFF);
    frame[2] = 0x00;
    frame[3] = 0x05;
    frame[4] = (unsigned char)(skipPrompt ? 1 : 0);
    cam_write_out((char*)frame, (int)sizeof(frame));
}

static void send_frame(const unsigned char *jpeg, unsigned long jpegLen, int passthrough)
{
    unsigned char hdr[4];

    hdr[0] = (unsigned char)((g_seq >> 8) & 0xFF);
    hdr[1] = (unsigned char)(g_seq & 0xFF);
    hdr[2] = (unsigned char)(passthrough ? 0x01 : 0x00);
    hdr[3] = 0x00;
    g_seq++;

    cam_send(MNG_CAM_DATA, hdr, (int)sizeof(hdr), jpeg, (int)jpegLen);
}

static void send_snapshot(const unsigned char *jpeg, unsigned long jpegLen, int width, int height,
                          int passthrough, unsigned int captureMs)
{
    unsigned char hdr[CAM_SNAP_HEADER - 4];
    uint32_t now = (uint32_t)time(NULL);

    if (captureMs > 65535) { captureMs = 65535; }

    hdr[0] = (unsigned char)((width >> 8) & 0xFF);
    hdr[1] = (unsigned char)(width & 0xFF);
    hdr[2] = (unsigned char)((height >> 8) & 0xFF);
    hdr[3] = (unsigned char)(height & 0xFF);
    hdr[4] = (unsigned char)((now >> 24) & 0xFF);
    hdr[5] = (unsigned char)((now >> 16) & 0xFF);
    hdr[6] = (unsigned char)((now >> 8) & 0xFF);
    hdr[7] = (unsigned char)(now & 0xFF);
    hdr[8] = 1;     /* format: JPEG */
    hdr[9] = (unsigned char)(passthrough ? 0x01 : 0x00);
    hdr[10] = (unsigned char)((captureMs >> 8) & 0xFF);
    hdr[11] = (unsigned char)(captureMs & 0xFF);

    cam_send(MNG_CAM_SNAPSHOT_DATA, hdr, (int)sizeof(hdr), jpeg, (int)jpegLen);
}

static uint64_t now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

/* ------------------------------------------------------------------------ */
/* Media Foundation device handling                                          */
/* ------------------------------------------------------------------------ */

/* One open MF capture session -- the structural analogue of linux_cam.c's
 * cam_dev_t, minus the mmap buffer bookkeeping V4L2 needs and MF does not:
 * IMFSample/IMFMediaBuffer own frame memory internally. Shared by the live
 * setup path and the one-shot snapshot path so device setup exists in
 * exactly one place, exactly as on Linux. */
typedef struct
{
    IMFMediaSource *source;
    IMFSourceReader *reader;
    int width;
    int height;
    GUID subtype;
    int isMjpeg;
} cam_dev_t;

static void cam_dev_close(cam_dev_t *d)
{
    if (d == NULL) { return; }
    if (d->reader != NULL) { d->reader->lpVtbl->Release(d->reader); d->reader = NULL; }
    if (d->source != NULL)
    {
        /* Shutdown() releases the underlying hardware/driver resources
         * deterministically rather than waiting on refcounted teardown --
         * load-bearing for cam_snapshot_worker()'s pause/resume, which
         * depends on the device being genuinely free the moment this
         * returns, not just eventually once COM gets around to it. */
        d->source->lpVtbl->Shutdown(d->source);
        d->source->lpVtbl->Release(d->source);
        d->source = NULL;
    }
}

/*
 * Find the largest native type on stream 0 matching a specific subtype.
 * Returns S_OK and fills outType/outW/outH (caller must Release outType) on
 * success, or a failure HRESULT if the device offers nothing in this
 * subtype. When wantW/wantH are both > 0, an exact match wins outright over
 * anything merely larger.
 *
 * This is the one piece of device negotiation that has no V4L2 equivalent:
 * VIDIOC_S_FMT lets the driver silently pick its own closest fit for
 * whatever width/height it is handed, but MF's SetCurrentMediaType requires
 * the caller to hand back one of the device's own native IMFMediaType
 * objects verbatim (see this file's header comment on why -- it is what
 * keeps MF from inserting a decode/convert transform). So the matching has
 * to happen here instead of inside the driver.
 */
static HRESULT cam_pick_native_type(IMFSourceReader *reader, DWORD streamIndex, const GUID *subtype,
                                    int wantW, int wantH, IMFMediaType **outType, int *outW, int *outH)
{
    IMFMediaType *best = NULL;
    int bestW = 0, bestH = 0;
    int haveExact = 0;
    DWORD i;

    for (i = 0; ; i++)
    {
        IMFMediaType *t = NULL;
        GUID sub;
        UINT32 w = 0, h = 0;
        HRESULT hr = reader->lpVtbl->GetNativeMediaType(reader, streamIndex, i, &t);
        if (hr == MF_E_NO_MORE_TYPES || FAILED(hr) || t == NULL) { break; }

        if (SUCCEEDED(t->lpVtbl->GetGUID(t, &MF_MT_SUBTYPE, &sub)) && IsEqualGUID(&sub, subtype) &&
            SUCCEEDED(MFGetAttributeSize(t, &MF_MT_FRAME_SIZE, &w, &h)) && w > 0 && h > 0)
        {
            int exact = (wantW > 0 && wantH > 0 && (int)w == (UINT32)wantW && (int)h == (UINT32)wantH);
            long area = (long)w * (long)h;
            long bestArea = (long)bestW * (long)bestH;

            if ((exact && !haveExact) || (!haveExact && area > bestArea))
            {
                if (best != NULL) { best->lpVtbl->Release(best); }
                best = t;
                t = NULL;
                bestW = (int)w;
                bestH = (int)h;
                if (exact) { haveExact = 1; }
            }
        }
        if (t != NULL) { t->lpVtbl->Release(t); }
    }

    if (best == NULL) { return E_FAIL; }
    *outType = best;
    *outW = bestW;
    *outH = bestH;
    return S_OK;
}

/*
 * Open one capture device and negotiate a format, without starting capture
 * (that happens on the caller's first ReadSample() -- see the file header
 * comment). Returns 0 on success, non-zero on failure (with everything
 * cleaned up).
 *
 *   deviceId: an MF symbolic link from the last enumeration, or NULL/"" for
 *             the system's first enumerated device (MF has no
 *             GetDefaultAudioEndpoint-style "the default camera" concept the
 *             way WASAPI does for microphones).
 *   width/height: requested size, or 0/0 for the camera's largest.
 *   forceRaw: skip MJPEG even when the camera offers it.
 *   callback: non-NULL arms the Source Reader in asynchronous mode for the
 *             live stream; NULL creates a synchronous reader for the
 *             snapshot path.
 *
 * MJPEG is tried first and the raw subtypes only when the camera cannot
 * provide it, because an MJPEG frame is already a finished JPEG and can be
 * forwarded without spending any CPU on it -- see cam_dev_open()'s Linux
 * counterpart for the identical reasoning. YUY2 is tried before NV12 simply
 * because it is the more common raw UVC output; nothing depends on the
 * ordering between the two.
 */
static int cam_dev_open(cam_dev_t *d, const char *deviceId, int width, int height, int forceRaw,
                        IMFSourceReaderCallback *callback)
{
    IMFAttributes *pAttributes = NULL;
    IMFAttributes *pReaderAttrs = NULL;
    IMFActivate *pActivate = NULL;
    IMFActivate **ppDevices = NULL;
    IMFMediaType *pType = NULL;
    WCHAR idW[CAM_DEVICE_ID_MAX + 1];
    UINT32 count = 0, j;
    HRESULT hr;
    int ok;

    memset(d, 0, sizeof(*d));

    hr = MFCreateAttributes(&pAttributes, 1);
    if (FAILED(hr) || pAttributes == NULL) { return -1; }
    hr = pAttributes->lpVtbl->SetGUID(pAttributes, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                                      &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (SUCCEEDED(hr) && deviceId != NULL && deviceId[0] != '\0' &&
        MultiByteToWideChar(CP_UTF8, 0, deviceId, -1, idW, CAM_DEVICE_ID_MAX + 1) > 0)
    {
        /* A specific device was selected. If it no longer exists (unplugged
         * since selection), enumeration below simply will not find it and
         * this call fails outright -- unlike the microphone side, there is
         * no "fall back to the default device" here because a *different*
         * physical camera is not an equivalent substitute the way a
         * different audio endpoint is. */
        hr = pAttributes->lpVtbl->SetString(pAttributes, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, idW);
    }

    if (SUCCEEDED(hr)) { hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count); }
    pAttributes->lpVtbl->Release(pAttributes);
    if (FAILED(hr) || count == 0 || ppDevices == NULL)
    {
        if (ppDevices != NULL) { CoTaskMemFree(ppDevices); }
        return -1;
    }

    pActivate = ppDevices[0];
    pActivate->lpVtbl->AddRef(pActivate);
    for (j = 0; j < count; j++) { if (ppDevices[j] != NULL) { ppDevices[j]->lpVtbl->Release(ppDevices[j]); } }
    CoTaskMemFree(ppDevices);

    hr = pActivate->lpVtbl->ActivateObject(pActivate, &IID_IMFMediaSource, (void**)&d->source);
    pActivate->lpVtbl->ShutdownObject(pActivate);
    pActivate->lpVtbl->Release(pActivate);
    if (FAILED(hr) || d->source == NULL) { return -1; }

    if (callback != NULL)
    {
        hr = MFCreateAttributes(&pReaderAttrs, 1);
        if (SUCCEEDED(hr)) { hr = pReaderAttrs->lpVtbl->SetUnknown(pReaderAttrs, &MF_SOURCE_READER_ASYNC_CALLBACK, (IUnknown*)callback); }
        if (FAILED(hr)) { if (pReaderAttrs != NULL) { pReaderAttrs->lpVtbl->Release(pReaderAttrs); } cam_dev_close(d); return -1; }
    }

    hr = MFCreateSourceReaderFromMediaSource(d->source, pReaderAttrs, &d->reader);
    if (pReaderAttrs != NULL) { pReaderAttrs->lpVtbl->Release(pReaderAttrs); }
    if (FAILED(hr) || d->reader == NULL) { cam_dev_close(d); return -1; }

    ok = 0;
    if (!forceRaw &&
        SUCCEEDED(cam_pick_native_type(d->reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, &MFVideoFormat_MJPG,
                                       width, height, &pType, &d->width, &d->height)))
    {
        d->subtype = MFVideoFormat_MJPG;
        d->isMjpeg = 1;
        ok = 1;
    }
    if (!ok &&
        SUCCEEDED(cam_pick_native_type(d->reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, &MFVideoFormat_YUY2,
                                       width, height, &pType, &d->width, &d->height)))
    {
        d->subtype = MFVideoFormat_YUY2;
        d->isMjpeg = 0;
        ok = 1;
    }
    if (!ok &&
        SUCCEEDED(cam_pick_native_type(d->reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, &MFVideoFormat_NV12,
                                       width, height, &pType, &d->width, &d->height)))
    {
        d->subtype = MFVideoFormat_NV12;
        d->isMjpeg = 0;
        ok = 1;
    }
    if (!ok) { cam_dev_close(d); return -1; }

    /* Handed back exactly as GetNativeMediaType() produced it -- see the
     * file header comment on why nothing here is rebuilt or partially
     * modified before this call. */
    hr = d->reader->lpVtbl->SetCurrentMediaType(d->reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, NULL, pType);
    pType->lpVtbl->Release(pType);
    if (FAILED(hr)) { cam_dev_close(d); return -1; }

    return 0;
}

/*
 * Find a device's largest resolution across the same MJPEG-then-raw fallback
 * cam_dev_open() itself uses. Returns 0 and fills outW/outH on success.
 *
 * Unlike linux_cam.c's cam_find_max_resolution() (a lightweight
 * VIDIOC_ENUM_FRAMESIZES ioctl probe with no separate call per fallback
 * family), this opens and immediately closes a throwaway reader: Media
 * Foundation has no enumerate-without-a-reader equivalent this codebase
 * relies elsewhere on being correct, and creating a reader plus negotiating
 * a type does not itself start capture (that only happens on the first
 * ReadSample(), which this never calls) -- so the device is never actually
 * engaged, only asked about. One call already walks the full MJPEG/YUY2/NV12
 * chain, where Linux needs two (MJPEG, then YUYV) because V4L2's ioctl has
 * no such fallback built in.
 */
static int cam_find_max_resolution(const char *deviceId, int forceRaw, int *outW, int *outH)
{
    cam_dev_t probe;
    if (cam_dev_open(&probe, deviceId, 0, 0, forceRaw, NULL) != 0) { return -1; }
    *outW = probe.width;
    *outH = probe.height;
    cam_dev_close(&probe);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Raw frame conversion                                                       */
/* ------------------------------------------------------------------------ */

/*
 * Packed YUY2 (4:2:2) to RGB24. Identical byte packing and arithmetic to
 * linux_cam.c's yuyv_to_rgb() -- YUY2 and YUYV are the same format under two
 * different fourcc naming conventions -- kept as an integer-only per-pixel
 * loop for the same reason: this runs per frame on machines without an FPU
 * worth relying on.
 */
static void yuy2_to_rgb(const unsigned char *src, unsigned char *dst, int width, int height)
{
    int i, total = width * height;

    for (i = 0; i < total; i += 2)
    {
        int y0 = src[0], u = src[1], y1 = src[2], v = src[3];
        int c, d, e, j;
        const int yv[2] = { y0, y1 };

        d = u - 128;
        e = v - 128;
        for (j = 0; j < 2; j++)
        {
            int r, g, b;
            c = yv[j] - 16;
            if (c < 0) { c = 0; }
            r = (298 * c + 409 * e + 128) >> 8;
            g = (298 * c - 100 * d - 208 * e + 128) >> 8;
            b = (298 * c + 516 * d + 128) >> 8;
            if (r < 0) { r = 0; } else if (r > 255) { r = 255; }
            if (g < 0) { g = 0; } else if (g > 255) { g = 255; }
            if (b < 0) { b = 0; } else if (b > 255) { b = 255; }
            dst[0] = (unsigned char)r;
            dst[1] = (unsigned char)g;
            dst[2] = (unsigned char)b;
            dst += 3;
        }
        src += 4;
    }
}

/*
 * Planar NV12 (4:2:0) to RGB24: a full-resolution Y plane followed by a
 * half-resolution-in-both-dimensions interleaved U/V plane. No V4L2/UVC
 * fallback ever needs this on Linux (the kernel driver normalises everything
 * to YUYV), but MF hands back whichever raw subtype the sensor actually
 * produces, and NV12 is common enough on Windows webcams to need direct
 * support rather than forcing every such camera down the (slower, and not
 * guaranteed available) format-converter path.
 */
static void nv12_to_rgb(const unsigned char *src, unsigned char *dst, int width, int height)
{
    const unsigned char *yPlane = src;
    const unsigned char *uvPlane = src + ((size_t)width * (size_t)height);
    int x, y;

    for (y = 0; y < height; y++)
    {
        const unsigned char *yRow = yPlane + (size_t)y * (size_t)width;
        const unsigned char *uvRow = uvPlane + (size_t)(y / 2) * (size_t)width;
        unsigned char *dstRow = dst + (size_t)y * (size_t)width * 3;

        for (x = 0; x < width; x++)
        {
            int c = yRow[x] - 16;
            int d = uvRow[(x / 2) * 2] - 128;
            int e = uvRow[(x / 2) * 2 + 1] - 128;
            int r, g, b;

            if (c < 0) { c = 0; }
            r = (298 * c + 409 * e + 128) >> 8;
            g = (298 * c - 100 * d - 208 * e + 128) >> 8;
            b = (298 * c + 516 * d + 128) >> 8;
            if (r < 0) { r = 0; } else if (r > 255) { r = 255; }
            if (g < 0) { g = 0; } else if (g > 255) { g = 255; }
            if (b < 0) { b = 0; } else if (b > 255) { b = 255; }

            dstRow[x * 3 + 0] = (unsigned char)r;
            dstRow[x * 3 + 1] = (unsigned char)g;
            dstRow[x * 3 + 2] = (unsigned char)b;
        }
    }
}

/* ------------------------------------------------------------------------ */
/* WIC encoding helpers                                                      */
/* ------------------------------------------------------------------------ */

static IWICImagingFactory *wic_get_factory(void)
{
    IWICImagingFactory *factory = NULL;
    HRESULT hr = CoCreateInstance(&MESHCAM_CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                                  &MESHCAM_IID_IWICImagingFactory, (void**)&factory);
    return SUCCEEDED(hr) ? factory : NULL;
}

/*
 * Encode an already-converted RGB24 buffer to JPEG via WIC. Returns a
 * malloc'd buffer the caller must free(), or NULL. Both raw subtypes
 * (YUY2/NV12) share this single encode backend rather than duplicating the
 * WIC call sequence per subtype -- linux_cam.c only ever has one raw
 * fallback (YUYV), so its encode_yuyv_jpeg() folds conversion and encoding
 * into a single function; here the conversion step (yuy2_to_rgb/nv12_to_rgb,
 * above) happens in the caller instead, before this is reached.
 */
static unsigned char *wic_encode_rgb_jpeg(const unsigned char *rgb, int width, int height, int quality, unsigned long *outLen)
{
    IWICImagingFactory *factory = NULL;
    IStream *stream = NULL;
    IWICBitmapEncoder *encoder = NULL;
    IWICBitmapFrameEncode *frame = NULL;
    IPropertyBag2 *options = NULL;
    WICPixelFormatGUID fmt = MESHCAM_GUID_WICPixelFormat24bppRGB;
    unsigned char *result = NULL;
    HRESULT hr;

    if (width <= 0 || height <= 0 || rgb == NULL) { return NULL; }

    factory = wic_get_factory();
    if (factory == NULL) { return NULL; }

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr) || stream == NULL) { factory->lpVtbl->Release(factory); return NULL; }

    hr = factory->lpVtbl->CreateEncoder(factory, &MESHCAM_GUID_ContainerFormatJpeg, NULL, &encoder);
    if (SUCCEEDED(hr)) { hr = encoder->lpVtbl->Initialize(encoder, stream, WICBitmapEncoderNoCache); }
    if (SUCCEEDED(hr)) { hr = encoder->lpVtbl->CreateNewFrame(encoder, &frame, &options); }
    if (SUCCEEDED(hr))
    {
        /* Best-effort: a quality setting that fails to apply still leaves a
         * perfectly valid JPEG at the codec's default quality, so this is
         * not treated as a hard failure -- mirrors how V4L2_S_PARM's
         * advisory fps hint is treated on the capture side. */
        if (options != NULL)
        {
            PROPBAG2 opt;
            VARIANT var;
            memset(&opt, 0, sizeof(opt));
            opt.pstrName = (LPOLESTR)L"ImageQuality";
            VariantInit(&var);
            var.vt = VT_R4;
            var.fltVal = (FLOAT)quality / 100.0f;
            options->lpVtbl->Write(options, 1, &opt, &var);
        }
        hr = frame->lpVtbl->Initialize(frame, options);
    }
    if (SUCCEEDED(hr)) { hr = frame->lpVtbl->SetSize(frame, (UINT)width, (UINT)height); }
    if (SUCCEEDED(hr)) { hr = frame->lpVtbl->SetPixelFormat(frame, &fmt); }
    if (SUCCEEDED(hr) && !IsEqualGUID(&fmt, &MESHCAM_GUID_WICPixelFormat24bppRGB))
    {
        /* The encoder substituted a different pixel format than asked for.
         * Rather than guess what it wants, wrap the buffer already in hand
         * as a bitmap source in its original format and let WriteSource's
         * own internal conversion handle it -- see this file's header
         * comment on why SetPixelFormat's exact override behaviour is not
         * assumed. */
        IWICBitmap *bitmap = NULL;
        hr = factory->lpVtbl->CreateBitmapFromMemory(factory, (UINT)width, (UINT)height,
                                                      &MESHCAM_GUID_WICPixelFormat24bppRGB,
                                                      (UINT)(width * 3), (UINT)(width * height * 3),
                                                      (BYTE*)rgb, &bitmap);
        if (SUCCEEDED(hr) && bitmap != NULL)
        {
            hr = frame->lpVtbl->WriteSource(frame, (IWICBitmapSource*)bitmap, NULL);
            bitmap->lpVtbl->Release(bitmap);
        }
    }
    else if (SUCCEEDED(hr))
    {
        hr = frame->lpVtbl->WritePixels(frame, (UINT)height, (UINT)(width * 3), (UINT)(width * height * 3), (BYTE*)rgb);
    }
    if (SUCCEEDED(hr)) { hr = frame->lpVtbl->Commit(frame); }
    if (SUCCEEDED(hr)) { hr = encoder->lpVtbl->Commit(encoder); }

    if (SUCCEEDED(hr))
    {
        HGLOBAL hGlobal = NULL;
        if (SUCCEEDED(GetHGlobalFromStream(stream, &hGlobal)) && hGlobal != NULL)
        {
            SIZE_T size = GlobalSize(hGlobal);
            void *locked = GlobalLock(hGlobal);
            if (locked != NULL && size > 0)
            {
                result = (unsigned char*)malloc(size);
                if (result != NULL) { memcpy(result, locked, size); *outLen = (unsigned long)size; }
                GlobalUnlock(hGlobal);
            }
        }
    }

    if (options != NULL) { options->lpVtbl->Release(options); }
    if (frame != NULL) { frame->lpVtbl->Release(frame); }
    if (encoder != NULL) { encoder->lpVtbl->Release(encoder); }
    if (stream != NULL) { stream->lpVtbl->Release(stream); }
    factory->lpVtbl->Release(factory);
    return result;
}

/*
 * Reduce a JPEG to a small grayscale thumbnail using WIC's scaled decode --
 * the direct equivalent of jpeg_thumbnail()'s libjpeg-turbo scaling factors
 * on Linux, though WIC does not expose a scale-during-entropy-decode knob of
 * its own the way libjpeg-turbo's TJSCALED does; WICBitmapInterpolationModeFant
 * is its cheap, purpose-built downscale filter. Returns a malloc'd buffer
 * plus its dimensions, or NULL.
 */
static unsigned char *wic_jpeg_thumbnail(const unsigned char *jpeg, unsigned long jpegLen, int *outW, int *outH)
{
    IWICImagingFactory *factory = NULL;
    IWICStream *stream = NULL;
    IWICBitmapDecoder *decoder = NULL;
    IWICBitmapFrameDecode *srcFrame = NULL;
    IWICBitmapScaler *scaler = NULL;
    IWICFormatConverter *converter = NULL;
    UINT fullW = 0, fullH = 0, sw = 0, sh = 0;
    unsigned char *thumb = NULL;
    HRESULT hr;

    if (jpeg == NULL || jpegLen == 0) { return NULL; }

    factory = wic_get_factory();
    if (factory == NULL) { return NULL; }

    hr = factory->lpVtbl->CreateStream(factory, &stream);
    if (SUCCEEDED(hr)) { hr = stream->lpVtbl->InitializeFromMemory(stream, (BYTE*)jpeg, (DWORD)jpegLen); }
    if (SUCCEEDED(hr))
    {
        hr = factory->lpVtbl->CreateDecoderFromStream(factory, (IStream*)stream, NULL,
                                                       WICDecodeMetadataCacheOnDemand, &decoder);
    }
    if (SUCCEEDED(hr)) { hr = decoder->lpVtbl->GetFrame(decoder, 0, &srcFrame); }
    if (SUCCEEDED(hr)) { hr = srcFrame->lpVtbl->GetSize(srcFrame, &fullW, &fullH); }
    if (SUCCEEDED(hr) && (fullW == 0 || fullH == 0)) { hr = E_FAIL; }

    if (SUCCEEDED(hr))
    {
        sw = fullW / 8; if (sw == 0) { sw = 1; }
        sh = fullH / 8; if (sh == 0) { sh = 1; }
        hr = factory->lpVtbl->CreateBitmapScaler(factory, &scaler);
    }
    if (SUCCEEDED(hr)) { hr = scaler->lpVtbl->Initialize(scaler, (IWICBitmapSource*)srcFrame, sw, sh, WICBitmapInterpolationModeFant); }
    if (SUCCEEDED(hr)) { hr = factory->lpVtbl->CreateFormatConverter(factory, &converter); }
    if (SUCCEEDED(hr))
    {
        hr = converter->lpVtbl->Initialize(converter, (IWICBitmapSource*)scaler, &MESHCAM_GUID_WICPixelFormat8bppGray,
                                           WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom);
    }
    if (SUCCEEDED(hr))
    {
        void *copy = malloc((size_t)sw * (size_t)sh);
        if (copy == NULL) { hr = E_OUTOFMEMORY; }
        else
        {
            hr = converter->lpVtbl->CopyPixels(converter, NULL, sw, (UINT)((size_t)sw * (size_t)sh), (BYTE*)copy);
            if (SUCCEEDED(hr)) { thumb = (unsigned char*)copy; *outW = (int)sw; *outH = (int)sh; }
            else { free(copy); }
        }
    }

    if (converter != NULL) { converter->lpVtbl->Release(converter); }
    if (scaler != NULL) { scaler->lpVtbl->Release(scaler); }
    if (srcFrame != NULL) { srcFrame->lpVtbl->Release(srcFrame); }
    if (decoder != NULL) { decoder->lpVtbl->Release(decoder); }
    if (stream != NULL) { stream->lpVtbl->Release(stream); }
    factory->lpVtbl->Release(factory);
    return thumb;
}

/* Subsample packed YUY2 straight to a luma thumbnail. No decode needed: in
 * YUY2 every even byte is already a luma sample. Verbatim port of
 * linux_cam.c's yuyv_thumbnail() -- YUY2 and YUYV share byte packing. */
static unsigned char *yuy2_thumbnail(const unsigned char *yuy2, int width, int height, int *outW, int *outH)
{
    int sw = width / 8, sh = height / 8, x, y;
    unsigned char *thumb;

    if (sw <= 0 || sh <= 0) { return NULL; }
    thumb = (unsigned char*)malloc((size_t)sw * (size_t)sh);
    if (thumb == NULL) { return NULL; }

    for (y = 0; y < sh; y++)
    {
        const unsigned char *row = yuy2 + (size_t)(y * 8) * (size_t)width * 2;
        for (x = 0; x < sw; x++) { thumb[y * sw + x] = row[(size_t)(x * 8) * 2]; }
    }
    *outW = sw;
    *outH = sh;
    return thumb;
}

/* Subsample NV12's Y plane straight to a luma thumbnail. No Linux
 * counterpart: the Y plane is already a standalone 8bpp grayscale image at
 * full resolution, so this needs no chroma involvement at all -- simpler
 * than YUY2's interleaved packing. */
static unsigned char *nv12_thumbnail(const unsigned char *nv12, int width, int height, int *outW, int *outH)
{
    int sw = width / 8, sh = height / 8, x, y;
    unsigned char *thumb;

    if (sw <= 0 || sh <= 0) { return NULL; }
    thumb = (unsigned char*)malloc((size_t)sw * (size_t)sh);
    if (thumb == NULL) { return NULL; }

    for (y = 0; y < sh; y++)
    {
        const unsigned char *row = nv12 + (size_t)(y * 8) * (size_t)width;
        for (x = 0; x < sw; x++) { thumb[y * sw + x] = row[x * 8]; }
    }
    *outW = sw;
    *outH = sh;
    return thumb;
}

/* ------------------------------------------------------------------------ */
/* Static-scene suppression                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Decide whether this frame is worth sending. Returns 1 to send. Verbatim
 * port of linux_cam.c's scene_changed(): pure comparison logic with zero
 * platform dependency. Compares against the previously *sent* frame rather
 * than the previous captured one, so a scene drifting slowly (changing
 * daylight) still eventually crosses the threshold instead of never
 * triggering. Takes ownership of nothing; updates the stored thumbnail when
 * it says send.
 */
static int scene_changed(unsigned char *thumb, int tw, int th, int threshold)
{
    long total = 0;
    int i, count = tw * th;
    int changed;

    if (thumb == NULL || count <= 0) { return 1; }

    if (!g_prevThumbValid || g_prevThumb == NULL || g_prevThumbW != tw || g_prevThumbH != th)
    {
        free(g_prevThumb);
        g_prevThumb = thumb;
        g_prevThumbW = tw;
        g_prevThumbH = th;
        g_prevThumbValid = 1;
        return 1;   /* first frame at these dimensions always goes */
    }

    for (i = 0; i < count; i++)
    {
        int diff = (int)thumb[i] - (int)g_prevThumb[i];
        total += (diff < 0) ? -diff : diff;
    }

    changed = ((total / count) >= threshold);
    if (changed)
    {
        free(g_prevThumb);
        g_prevThumb = thumb;
        g_prevThumbW = tw;
        g_prevThumbH = th;
        return 1;
    }
    free(thumb);
    return 0;
}

static void reset_scene_state(void)
{
    free(g_prevThumb);
    g_prevThumb = NULL;
    g_prevThumbW = g_prevThumbH = 0;
    g_prevThumbValid = 0;
}

/* ------------------------------------------------------------------------ */
/* Live capture -- asynchronous Source Reader callback                       */
/* ------------------------------------------------------------------------ */

/*
 * A hand-rolled IMFSourceReaderCallback, the one genuinely new pattern this
 * module introduces relative to linux_cam.c (V4L2 has nothing like it: a
 * select()/DQBUF loop on a thread this code owns end to end). One instance
 * exists per live-stream session, created by cam_capture_setup_thread() and
 * released once the stream is fully torn down -- see cam_teardown_live().
 *
 * width/height/subtype/isMjpeg are set once, before the reader is armed, and
 * never change for this instance's lifetime: a resolution/fps/device change
 * while streaming tears the whole reader and callback down and builds a
 * fresh pair (see kvm_cam_start()), rather than mutating a live one. That is
 * what lets OnReadSample() below read them without taking g_lock.
 */
typedef struct CamReaderCallback
{
    const IMFSourceReaderCallbackVtbl *lpVtbl;
    volatile LONG refCount;
    uint64_t nextDue;    /* software frame pacing state, mirrors capture_thread()'s stack-local nextDue/interval */
    uint64_t interval;
    int width;
    int height;
    GUID subtype;
    int isMjpeg;
} CamReaderCallback;

static HRESULT STDMETHODCALLTYPE camcb_QueryInterface(IMFSourceReaderCallback *self, REFIID riid, void **ppv)
{
    if (ppv == NULL) { return E_POINTER; }
    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IMFSourceReaderCallback))
    {
        *ppv = self;
        self->lpVtbl->AddRef(self);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE camcb_AddRef(IMFSourceReaderCallback *self)
{
    CamReaderCallback *cb = (CamReaderCallback*)self;
    return (ULONG)InterlockedIncrement(&cb->refCount);
}

static ULONG STDMETHODCALLTYPE camcb_Release(IMFSourceReaderCallback *self)
{
    CamReaderCallback *cb = (CamReaderCallback*)self;
    LONG count = InterlockedDecrement(&cb->refCount);
    if (count == 0) { free(cb); }
    return (ULONG)count;
}

/*
 * Convert/encode/suppress/send one sample. The per-frame body of
 * linux_cam.c's capture_thread() loop, translated into a function called
 * once per OnReadSample() rather than once per loop iteration -- same
 * logic, same ordering (pacing gate, then MJPEG-passthrough-or-raw-encode,
 * each with its own suppression check).
 */
static void cam_process_sample(CamReaderCallback *cb, IMFSample *pSample)
{
    IMFMediaBuffer *pBuffer = NULL;
    BYTE *data = NULL;
    DWORD maxLen = 0, curLen = 0;
    HRESULT hr;
    int quality, suppress, threshold;
    uint64_t nowT;

    cam_lock();
    quality = g_quality;
    suppress = g_suppress;
    threshold = g_threshold;
    cam_unlock();

    nowT = now_ms();
    if (cb->nextDue != 0 && nowT < cb->nextDue) { return; }   /* software pacing: driver frame rate hints are advisory */
    cb->nextDue = nowT + cb->interval;

    hr = pSample->lpVtbl->ConvertToContiguousBuffer(pSample, &pBuffer);
    if (FAILED(hr) || pBuffer == NULL) { return; }

    hr = pBuffer->lpVtbl->Lock(pBuffer, &data, &maxLen, &curLen);
    if (FAILED(hr) || data == NULL || curLen == 0)
    {
        pBuffer->lpVtbl->Release(pBuffer);
        return;
    }

    if (cb->isMjpeg)
    {
        /* The camera already produced a JPEG. Do not re-encode it. */
        int send = 1;
        if (suppress && threshold > 0)
        {
            int tw = 0, th = 0;
            unsigned char *thumb = wic_jpeg_thumbnail((const unsigned char*)data, (unsigned long)curLen, &tw, &th);
            if (thumb != NULL) { send = scene_changed(thumb, tw, th, threshold); }
        }
        if (send) { send_frame((const unsigned char*)data, (unsigned long)curLen, 1); }
    }
    else
    {
        unsigned char *rgb = (unsigned char*)malloc((size_t)cb->width * (size_t)cb->height * 3);
        if (rgb != NULL)
        {
            int isNv12 = IsEqualGUID(&cb->subtype, &MFVideoFormat_NV12);
            int send = 1;

            if (isNv12) { nv12_to_rgb(data, rgb, cb->width, cb->height); }
            else { yuy2_to_rgb(data, rgb, cb->width, cb->height); }

            if (suppress && threshold > 0)
            {
                int tw = 0, th = 0;
                unsigned char *thumb = isNv12
                    ? nv12_thumbnail(data, cb->width, cb->height, &tw, &th)
                    : yuy2_thumbnail(data, cb->width, cb->height, &tw, &th);
                if (thumb != NULL) { send = scene_changed(thumb, tw, th, threshold); }
            }

            if (send)
            {
                unsigned long jlen = 0;
                unsigned char *jpeg = wic_encode_rgb_jpeg(rgb, cb->width, cb->height, quality, &jlen);
                if (jpeg != NULL) { send_frame(jpeg, jlen, 0); free(jpeg); }
            }
            free(rgb);
        }
    }

    pBuffer->lpVtbl->Unlock(pBuffer);
    pBuffer->lpVtbl->Release(pBuffer);
}

/*
 * Called once for every ReadSample() this module issues -- MF does not
 * self-perpetuate the stream, so the last thing this does on every path that
 * is not stopping is call ReadSample() again. Stopping is "do not re-arm",
 * not a separate cancellation call: cam_teardown_live() below is what issues
 * Flush() to reclaim a read that is already in flight when a stop is
 * requested asynchronously from another thread.
 *
 * Re-checks both g_liveShutdown and g_consent after processing a sample, not
 * just before: a revocation that lands while cam_process_sample() is running
 * must not re-arm one more read, exactly mirroring capture_thread()'s
 * post-grab re-check of g_shutdown/g_consent on Linux.
 */
static HRESULT STDMETHODCALLTYPE camcb_OnReadSample(IMFSourceReaderCallback *self, HRESULT hrStatus,
                                                     DWORD dwStreamIndex, DWORD dwStreamFlags,
                                                     LONGLONG llTimestamp, IMFSample *pSample)
{
    CamReaderCallback *cb = (CamReaderCallback*)self;
    int stopping;

    UNREFERENCED_PARAMETER(dwStreamIndex);
    UNREFERENCED_PARAMETER(llTimestamp);

    stopping = (InterlockedCompareExchange(&g_liveShutdown, 0, 0) != 0);

    if (!stopping && SUCCEEDED(hrStatus) && pSample != NULL)
    {
        cam_process_sample(cb, pSample);
    }
    else if (!stopping && FAILED(hrStatus))
    {
        /* Streaming error -- e.g. the device was unplugged. Mirrors
         * capture_thread()'s cam_dev_grab() < 0 break: give up on this
         * stream rather than looping against a dead source. */
        stopping = 1;
        InterlockedExchange(&g_liveShutdown, 1);
        cam_lock(); g_passthroughActive = 0; cam_unlock();
        send_caps(g_writeHandler, g_reserved);
    }

    if (!stopping && (dwStreamFlags & MF_SOURCE_READERF_ENDOFSTREAM) != 0)
    {
        /* Webcams do not meaningfully end-of-stream, but handle it as a
         * clean stop rather than silently going quiet. */
        stopping = 1;
        InterlockedExchange(&g_liveShutdown, 1);
        cam_lock(); g_passthroughActive = 0; cam_unlock();
        send_caps(g_writeHandler, g_reserved);
    }

    if (!stopping)
    {
        int consent;
        cam_lock();
        consent = g_consent;
        cam_unlock();
        if (!consent) { stopping = 1; InterlockedExchange(&g_liveShutdown, 1); }
    }

    if (!stopping)
    {
        IMFSourceReader *reader;
        cam_lock();
        reader = g_liveReader;
        cam_unlock();
        if (reader != NULL)
        {
            reader->lpVtbl->ReadSample(reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, NULL, NULL, NULL, NULL);
        }
        else { stopping = 1; }
    }

    if (stopping && g_liveStopEvent != NULL) { SetEvent(g_liveStopEvent); }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE camcb_OnFlush(IMFSourceReaderCallback *self, DWORD dwStreamIndex)
{
    UNREFERENCED_PARAMETER(self);
    UNREFERENCED_PARAMETER(dwStreamIndex);
    if (g_liveStopEvent != NULL) { SetEvent(g_liveStopEvent); }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE camcb_OnEvent(IMFSourceReaderCallback *self, DWORD dwStreamIndex, IMFMediaEvent *pEvent)
{
    UNREFERENCED_PARAMETER(self);
    UNREFERENCED_PARAMETER(dwStreamIndex);
    UNREFERENCED_PARAMETER(pEvent);
    return S_OK;
}

/* Field names, not position, tie these to the interface's actual methods --
 * deliberately order-independent since this project has no local Windows SDK
 * to confirm IMFSourceReaderCallbackVtbl's declared field order against. */
static const IMFSourceReaderCallbackVtbl g_camCallbackVtbl =
{
    .QueryInterface = camcb_QueryInterface,
    .AddRef         = camcb_AddRef,
    .Release        = camcb_Release,
    .OnReadSample   = camcb_OnReadSample,
    .OnFlush        = camcb_OnFlush,
    .OnEvent        = camcb_OnEvent
};

/*
 * Tear down the live stream if one is running: stop re-arming, Flush() to
 * reclaim anything already in flight, wait bounded on completion (signalled
 * from either OnFlush() or a declining OnReadSample() -- belt-and-suspenders,
 * since this file does not depend on knowing which one fires first), then
 * release the reader/callback. Returns 1 if a stream was actually torn down,
 * 0 if nothing was running (a safe no-op either way).
 *
 * Must be called WITHOUT g_lock held: Flush()'s completion can take real
 * time, and this must never block another thread's settings check behind
 * it -- exactly why linux_cam.c's pthread_join() calls for its capture
 * thread always happen outside g_lock too.
 */
static int cam_teardown_live(void)
{
    IMFSourceReader *reader;
    void *callback;

    cam_lock();
    reader = g_liveReader;
    callback = g_liveCallback;
    g_liveReader = NULL;
    g_liveCallback = NULL;
    cam_unlock();

    if (reader == NULL) { return 0; }

    InterlockedExchange(&g_liveShutdown, 1);
    if (g_liveStopEvent != NULL) { ResetEvent(g_liveStopEvent); }
    reader->lpVtbl->Flush(reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM);
    if (g_liveStopEvent != NULL) { WaitForSingleObject(g_liveStopEvent, CAM_STOP_WAIT_MS); }

    reader->lpVtbl->Release(reader);
    if (callback != NULL) { ((IMFSourceReaderCallback*)callback)->lpVtbl->Release((IMFSourceReaderCallback*)callback); }
    return 1;
}

/*
 * Open the device, negotiate a format, and arm the first ReadSample() --
 * the open/negotiate step can take a noticeable moment, so exactly like
 * kvm_cam_query_devices()'s enumeration worker, this never runs on the KVM
 * command dispatch thread. Runs to completion and exits; every frame after
 * the first arrives via g_camCallbackVtbl's OnReadSample on Media
 * Foundation's own worker threads, not on a thread this file keeps alive for
 * the stream's duration -- see the CamReaderCallback comment above.
 *
 * Fire-and-forget, mirroring mic_query_devices_worker()/
 * cam_query_devices_worker(): nothing needs to join this thread, since
 * "is a stream running" is tracked via g_liveReader, not a thread handle.
 */
static DWORD WINAPI cam_capture_setup_thread(LPVOID param)
{
    cam_thread_args_t *targs = (cam_thread_args_t*)param;
    cam_dev_t dev;
    char deviceId[CAM_DEVICE_ID_MAX + 1];
    int width, height, fps, forceRaw;
    CamReaderCallback *cb = NULL;
    HRESULT coHr;
    int comInitialised = 0;

    free(targs);
    memset(&dev, 0, sizeof(dev));

    coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (coHr == RPC_E_CHANGED_MODE) { comInitialised = 0; }
    else if (FAILED(coHr)) { goto fail; }
    else { comInitialised = 1; }

    cam_lock();
    strncpy(deviceId, g_currentDeviceId, CAM_DEVICE_ID_MAX);
    deviceId[CAM_DEVICE_ID_MAX] = '\0';
    width = g_width; height = g_height; fps = g_fps; forceRaw = g_forceRaw;
    reset_scene_state();
    cam_unlock();
    if (fps <= 0) { fps = CAM_DEFAULT_FPS; }

    cb = (CamReaderCallback*)malloc(sizeof(CamReaderCallback));
    if (cb == NULL) { goto fail; }
    memset(cb, 0, sizeof(*cb));
    cb->lpVtbl = &g_camCallbackVtbl;
    cb->refCount = 1;
    cb->interval = (uint64_t)(1000 / fps);

    if (cam_dev_open(&dev, deviceId, width, height, forceRaw, (IMFSourceReaderCallback*)cb) != 0)
    {
        ((IMFSourceReaderCallback*)cb)->lpVtbl->Release((IMFSourceReaderCallback*)cb);
        goto fail;
    }

    cb->width = dev.width;
    cb->height = dev.height;
    cb->subtype = dev.subtype;
    cb->isMjpeg = dev.isMjpeg;

    cam_lock();
    /* Publish what was actually negotiated, which may differ from what was
     * asked for; the browser shows these, so they must be the truth --
     * mirrors capture_thread()'s identical post-open publish on Linux. */
    g_width = dev.width;
    g_height = dev.height;
    g_passthroughActive = dev.isMjpeg;
    g_liveReader = dev.reader;
    g_liveCallback = cb;
    InterlockedExchange(&g_liveShutdown, 0);
    g_setupInProgress = 0;
    cam_unlock();
    send_caps(g_writeHandler, g_reserved);

    /* Kick off the async chain; every subsequent frame re-arms itself from
     * within camcb_OnReadSample. Nothing further happens on this thread. */
    dev.reader->lpVtbl->ReadSample(dev.reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, NULL, NULL, NULL, NULL);

    /* dev.reader now holds its own reference to dev.source (see
     * MFCreateSourceReaderFromMediaSource's standard COM ownership
     * contract), so this function's own reference to it can be dropped --
     * do NOT call cam_dev_close(&dev) here, which would Shutdown() the
     * source out from under the reader just handed off to g_liveReader. */
    dev.source->lpVtbl->Release(dev.source);

    if (comInitialised) { CoUninitialize(); }
    return 0;

fail:
    cam_lock();
    g_passthroughActive = 0;
    InterlockedExchange(&g_liveShutdown, 1);
    g_setupInProgress = 0;
    cam_unlock();
    send_caps(g_writeHandler, g_reserved);
    if (comInitialised) { CoUninitialize(); }
    return 0;
}

/*
 * Guarded fire-and-forget spawn of cam_capture_setup_thread(), coalescing
 * concurrent callers exactly like kvm_cam_query_devices() coalesces
 * concurrent enumeration requests -- necessary here because, unlike
 * linux_cam.c's g_shutdown, g_liveShutdown alone cannot distinguish "nothing
 * running" from "a setup thread is already mid-flight, about to publish
 * g_liveReader": both look identical (g_liveShutdown == 1, g_liveReader ==
 * NULL) from the outside for the whole open/negotiate window. Without this
 * guard, two overlapping kvm_cam_start() calls (a double-click, or a start
 * racing a snapshot's resume) could each open the same physical device and
 * then stomp one another's g_liveReader.
 */
static void cam_spawn_setup_thread(void)
{
    cam_thread_args_t *targs;
    HANDLE t;

    cam_lock();
    if (g_setupInProgress) { cam_unlock(); return; }
    g_setupInProgress = 1;
    cam_unlock();

    targs = (cam_thread_args_t*)malloc(sizeof(cam_thread_args_t));
    if (targs == NULL)
    {
        cam_lock(); g_setupInProgress = 0; cam_unlock();
        return;
    }
    cam_lock();
    targs->writeHandler = g_writeHandler;
    targs->reserved = g_reserved;
    cam_unlock();

    t = CreateThread(NULL, 0, cam_capture_setup_thread, targs, 0, NULL);
    if (t == NULL)
    {
        free(targs);
        cam_lock(); g_setupInProgress = 0; cam_unlock();
        return;
    }
    CloseHandle(t); /* fire-and-forget: "is a stream running" is tracked via g_liveReader, not this handle */
}

/* ------------------------------------------------------------------------ */
/* Snapshot                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Ends a snapshot attempt: clears the pending flag and, if a live stream was
 * paused to free up the (single-open) device, hands it back by spawning a
 * fresh setup thread. Called from every exit out of cam_snapshot_worker() so
 * a failed capture never leaves the stream stopped forever. Verbatim port of
 * linux_cam.c's cam_snapshot_finish(), adapted to spawn-a-fresh-setup-thread
 * in place of restarting a persistent capture thread.
 */
static void cam_snapshot_finish(int wasStreaming)
{
    int consent;

    cam_lock();
    g_snapshotPending = 0;
    g_snapshotPausedStream = 0;
    consent = g_consent;
    cam_unlock();

    if (wasStreaming && consent)
    {
        /* cam_capture_setup_thread() re-reads g_width/g_height/g_fps/
         * g_currentDeviceId fresh at its own startup, so any MNG_CAM_START
         * that arrived while this snapshot had the device (and was held off
         * by g_snapshotPausedStream in kvm_cam_start()) is picked up
         * correctly here without this function needing to know about it. */
        cam_spawn_setup_thread();
    }
}

/*
 * One-shot capture, independent of whatever the live stream is doing. Runs
 * on its own thread for the same reason enumeration and live setup do:
 * opening a camera and waiting for its first usable frame can take a
 * noticeable moment, and the KVM command thread must not be parked for it.
 *
 * Always captures at its own resolution (the operator's request, or the
 * camera's true maximum when none was given) rather than reusing whatever
 * the stream happens to be running at -- if the stream owns the device, it
 * is paused via cam_teardown_live() for the moment this takes and then
 * restarted via cam_snapshot_finish().
 */
static DWORD WINAPI cam_snapshot_worker(LPVOID param)
{
    cam_thread_args_t *targs = (cam_thread_args_t*)param;
    cam_dev_t dev;
    char deviceId[CAM_DEVICE_ID_MAX + 1];
    int width, height, quality, forceRaw, deviceIndex;
    int wasStreaming;
    HRESULT coHr;
    int comInitialised = 0;
    uint64_t started;
    int attempts;

    free(targs);
    memset(&dev, 0, sizeof(dev));

    cam_lock();
    if (!g_consent)
    {
        /* Consent was withdrawn between the request and this thread starting. */
        g_snapshotPending = 0;
        cam_unlock();
        return 0;
    }
    cam_unlock();

    /* Pause any running live stream first -- MF sources are single-open per
     * physical device exactly like V4L2, so this and a live stream cannot
     * both hold the same camera open at once. Shared with kvm_cam_start()'s
     * restart path rather than duplicating the Flush()/wait/release dance
     * here. */
    wasStreaming = cam_teardown_live();
    cam_lock();
    g_snapshotPausedStream = wasStreaming;
    cam_unlock();

    coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (coHr == RPC_E_CHANGED_MODE) { comInitialised = 0; }
    else if (FAILED(coHr)) { cam_snapshot_finish(wasStreaming); return 0; }
    else { comInitialised = 1; }

    cam_lock();
    deviceIndex = g_pendingSnapDeviceIndex;
    if (deviceIndex >= 0 && deviceIndex < g_deviceCount) { strncpy(deviceId, g_deviceIds[deviceIndex], CAM_DEVICE_ID_MAX); }
    else { strncpy(deviceId, g_currentDeviceId, CAM_DEVICE_ID_MAX); }
    deviceId[CAM_DEVICE_ID_MAX] = '\0';
    width = g_pendingSnapWidth;
    height = g_pendingSnapHeight;
    quality = g_snapshotQuality;
    forceRaw = g_forceRaw;
    cam_unlock();

    /* 0x0 means "the camera's best": resolve its true maximum rather than
     * falling back to CAM_DEFAULT_*, which is what used to make a snapshot
     * silently inherit whatever (often lower) resolution the stream
     * happened to be running at. */
    if (width <= 0 || height <= 0)
    {
        if (cam_find_max_resolution(deviceId, forceRaw, &width, &height) != 0)
        {
            width = CAM_DEFAULT_WIDTH;
            height = CAM_DEFAULT_HEIGHT;
        }
    }

    started = now_ms();
    if (cam_dev_open(&dev, deviceId, width, height, forceRaw, NULL) != 0)
    {
        if (comInitialised) { CoUninitialize(); }
        cam_snapshot_finish(wasStreaming);
        return 0;
    }

    /* Cameras routinely hand back a few dark or half-exposed frames while
     * auto exposure and white balance settle, so take a short run and keep
     * the last one rather than shipping the first thing that arrives --
     * verbatim port of the same 8-attempt/skip-3 loop on Linux, driven by
     * synchronous ReadSample() calls instead of select()+DQBUF. */
    for (attempts = 0; attempts < 8; attempts++)
    {
        IMFSample *pSample = NULL;
        DWORD streamFlags = 0;
        HRESULT hr = dev.reader->lpVtbl->ReadSample(dev.reader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0,
                                                    NULL, &streamFlags, NULL, &pSample);
        if (FAILED(hr)) { break; }
        if ((streamFlags & (MF_SOURCE_READERF_ERROR | MF_SOURCE_READERF_ENDOFSTREAM)) != 0)
        {
            if (pSample != NULL) { pSample->lpVtbl->Release(pSample); }
            break;
        }
        if (pSample == NULL) { continue; }
        if (attempts < 3) { pSample->lpVtbl->Release(pSample); continue; }

        {
            int consent;
            cam_lock();
            consent = g_consent;
            cam_unlock();
            if (!consent) { pSample->lpVtbl->Release(pSample); break; }
        }

        {
            IMFMediaBuffer *pBuffer = NULL;
            if (SUCCEEDED(pSample->lpVtbl->ConvertToContiguousBuffer(pSample, &pBuffer)) && pBuffer != NULL)
            {
                BYTE *data = NULL;
                DWORD maxLen = 0, curLen = 0;
                if (SUCCEEDED(pBuffer->lpVtbl->Lock(pBuffer, &data, &maxLen, &curLen)) && data != NULL && curLen > 0)
                {
                    if (dev.isMjpeg)
                    {
                        send_snapshot((const unsigned char*)data, (unsigned long)curLen, dev.width, dev.height, 1,
                                     (unsigned int)(now_ms() - started));
                    }
                    else
                    {
                        unsigned char *rgb = (unsigned char*)malloc((size_t)dev.width * (size_t)dev.height * 3);
                        if (rgb != NULL)
                        {
                            unsigned long jlen = 0;
                            unsigned char *jpeg;
                            if (IsEqualGUID(&dev.subtype, &MFVideoFormat_NV12)) { nv12_to_rgb(data, rgb, dev.width, dev.height); }
                            else { yuy2_to_rgb(data, rgb, dev.width, dev.height); }
                            jpeg = wic_encode_rgb_jpeg(rgb, dev.width, dev.height, quality, &jlen);
                            if (jpeg != NULL) { send_snapshot(jpeg, jlen, dev.width, dev.height, 0, (unsigned int)(now_ms() - started)); free(jpeg); }
                            free(rgb);
                        }
                    }
                    pBuffer->lpVtbl->Unlock(pBuffer);
                }
                pBuffer->lpVtbl->Release(pBuffer);
            }
        }
        pSample->lpVtbl->Release(pSample);
        break;
    }

    cam_dev_close(&dev);
    if (comInitialised) { CoUninitialize(); }
    cam_snapshot_finish(wasStreaming);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Device enumeration                                                        */
/* ------------------------------------------------------------------------ */

/*
 * Enumerate video capture sources and send MNG_CAM_DEVICE_LIST: mirrors
 * linux_cam.c's cam_query_devices_worker() wire format and index semantics,
 * and windows_mic.c's mic_query_devices_worker() structurally (the same
 * "proceed regardless of a CoInitializeEx failure and let the downstream MF
 * call fail cleanly" stance, appropriate here because callers expect a
 * MNG_CAM_DEVICE_LIST response either way, even an empty one -- unlike
 * cam_capture_setup_thread()/cam_snapshot_worker(), which abort early since
 * nothing useful can happen there without COM).
 *
 * Runs on its own thread -- see kvm_cam_query_devices() below for why this
 * must never run directly on the KVM command dispatch thread.
 */
static DWORD WINAPI cam_query_devices_worker(LPVOID param)
{
    cam_thread_args_t *targs = (cam_thread_args_t*)param;
    ILibTransport_DoneState(*writeHandler)(char*, int, void*);
    void *reserved;
    IMFAttributes *pAttributes = NULL;
    IMFActivate **ppDevices = NULL;
    UINT32 count = 0, i;
    int sentCount = 0;
    unsigned char *outFrame;
    int outLen, ptr;
    HRESULT hr, co;
    char labels[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_NAME_MAX + 1];
    char ids[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_ID_MAX + 1];

    writeHandler = targs->writeHandler;
    reserved = targs->reserved;
    free(targs);

    co = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = MFCreateAttributes(&pAttributes, 1);
    if (SUCCEEDED(hr) && pAttributes != NULL)
    {
        hr = pAttributes->lpVtbl->SetGUID(pAttributes, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                                          &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
        if (SUCCEEDED(hr)) { hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count); }

        if (SUCCEEDED(hr) && ppDevices != NULL)
        {
            for (i = 0; i < count && sentCount < CAM_DEVICE_MAX_COUNT; i++)
            {
                if (ppDevices[i] == NULL) { continue; }

                {
                    WCHAR *nameW = NULL;
                    WCHAR *idW = NULL;
                    UINT32 len = 0;
                    char label[CAM_DEVICE_NAME_MAX + 1];
                    int haveLabel = 0;

                    if (SUCCEEDED(ppDevices[i]->lpVtbl->GetAllocatedString(ppDevices[i],
                            &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &nameW, &len)) && nameW != NULL)
                    {
                        int n = WideCharToMultiByte(CP_UTF8, 0, nameW, -1, label, sizeof(label), NULL, NULL);
                        haveLabel = (n > 0);
                        CoTaskMemFree(nameW);
                    }

                    /* The symbolic link is what lets this device be reopened
                     * later by kvm_cam_start()/kvm_cam_snapshot() -- a
                     * device this cannot be resolved for is skipped
                     * entirely rather than offered as a choice that could
                     * never actually be selected. */
                    if (SUCCEEDED(ppDevices[i]->lpVtbl->GetAllocatedString(ppDevices[i],
                            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, &idW, &len)) && idW != NULL)
                    {
                        if (!haveLabel)
                        {
                            /* Mirrors windows_mic.c's own fallback: reuse
                             * WideCharToMultiByte's silent truncation at the
                             * buffer size for the fallback label too,
                             * instead of a second ad-hoc truncation. */
                            WideCharToMultiByte(CP_UTF8, 0, idW, -1, label, sizeof(label), NULL, NULL);
                        }
                        label[sizeof(label) - 1] = '\0';

                        strncpy(labels[sentCount], label, CAM_DEVICE_NAME_MAX);
                        labels[sentCount][CAM_DEVICE_NAME_MAX] = '\0';
                        WideCharToMultiByte(CP_UTF8, 0, idW, -1, ids[sentCount], sizeof(ids[sentCount]), NULL, NULL);
                        ids[sentCount][CAM_DEVICE_ID_MAX] = '\0';
                        sentCount++;
                        CoTaskMemFree(idW);
                    }
                }
                ppDevices[i]->lpVtbl->Release(ppDevices[i]);
            }
        }
        pAttributes->lpVtbl->Release(pAttributes);
    }
    if (ppDevices != NULL) { CoTaskMemFree(ppDevices); }
    if (SUCCEEDED(co)) { CoUninitialize(); }

    cam_lock();
    g_deviceCount = sentCount;
    for (i = 0; i < (UINT32)sentCount; i++)
    {
        memcpy(g_deviceLabels[i], labels[i], sizeof(labels[i]));
        memcpy(g_deviceIds[i], ids[i], sizeof(ids[i]));
    }

    outLen = 5;
    for (i = 0; i < (UINT32)sentCount; i++) { outLen += 1 + (int)strlen(g_deviceLabels[i]); }

    outFrame = (unsigned char*)malloc((size_t)outLen);
    if (outFrame == NULL) { g_enumInProgress = 0; cam_unlock(); return 0; }

    outFrame[0] = (unsigned char)((MNG_CAM_DEVICE_LIST >> 8) & 0xFF);
    outFrame[1] = (unsigned char)(MNG_CAM_DEVICE_LIST & 0xFF);
    outFrame[2] = (unsigned char)((outLen >> 8) & 0xFF);
    outFrame[3] = (unsigned char)(outLen & 0xFF);
    outFrame[4] = (unsigned char)sentCount;
    ptr = 5;
    for (i = 0; i < (UINT32)sentCount; i++)
    {
        size_t len = strlen(g_deviceLabels[i]);
        outFrame[ptr] = (unsigned char)len; ptr++;
        memcpy(outFrame + ptr, g_deviceLabels[i], len);
        ptr += (int)len;
    }
    cam_unlock();

    if (writeHandler != NULL)
    {
        cam_send_lock_init();
        EnterCriticalSection(&g_sendLock);
        writeHandler((char*)outFrame, outLen, reserved);
        LeaveCriticalSection(&g_sendLock);
    }
    free(outFrame);

    cam_lock();
    g_enumInProgress = 0;
    cam_unlock();
    return 0;
}

void kvm_cam_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    cam_thread_args_t *targs;
    HANDLE thread;

    cam_lock_init();

    cam_lock();
    if (g_enumInProgress) { cam_unlock(); return; }
    g_enumInProgress = 1;
    cam_unlock();

    targs = (cam_thread_args_t*)malloc(sizeof(cam_thread_args_t));
    if (targs == NULL)
    {
        cam_lock(); g_enumInProgress = 0; cam_unlock();
        return;
    }
    targs->writeHandler = writeHandler;
    targs->reserved = reserved;

    thread = CreateThread(NULL, 0, cam_query_devices_worker, targs, 0, NULL);
    if (thread == NULL)
    {
        free(targs);
        cam_lock(); g_enumInProgress = 0; cam_unlock();
        return;
    }
    CloseHandle(thread); /* fire-and-forget: nothing needs to join this */
}

/* ------------------------------------------------------------------------ */
/* Settings                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Apply an MNG_CAM_START payload. Must be called with g_lock held. Returns 1
 * when something changed that requires restarting capture (resolution,
 * frame rate, device or the passthrough override); quality and suppression
 * settings take effect in place and do not. Verbatim port of
 * linux_cam.c's cam_apply_params(): wire-protocol parsing, not
 * platform-specific, except for the device-index-to-ID resolution.
 */
static int cam_apply_params(const unsigned char *frame, int size)
{
    int width, height, fps, quality, flags, threshold, deviceIndex;
    int restart = 0;

    if (frame == NULL || size < 14) { return 0; }

    width = (frame[4] << 8) | frame[5];
    height = (frame[6] << 8) | frame[7];
    fps = frame[8];
    quality = frame[9];
    flags = frame[10];
    threshold = frame[11];
    deviceIndex = frame[12];

    if (width == 0) { width = CAM_DEFAULT_WIDTH; }
    if (height == 0) { height = CAM_DEFAULT_HEIGHT; }
    if (width < 32) { width = 32; } else if (width > CAM_MAX_WIDTH) { width = CAM_MAX_WIDTH; }
    if (height < 32) { height = 32; } else if (height > CAM_MAX_HEIGHT) { height = CAM_MAX_HEIGHT; }
    if (fps == 0) { fps = CAM_DEFAULT_FPS; } else if (fps > CAM_MAX_FPS) { fps = CAM_MAX_FPS; }
    if (quality == 0) { quality = CAM_DEFAULT_QUALITY; } else if (quality > 100) { quality = 100; }

    if (width != g_width || height != g_height || fps != g_fps) { restart = 1; }
    g_width = width;
    g_height = height;
    g_fps = fps;
    g_quality = quality;
    g_suppress = (flags & 0x01) ? 1 : 0;
    g_threshold = threshold;
    if (((flags & 0x04) ? 1 : 0) != g_forceRaw) { restart = 1; }
    g_forceRaw = (flags & 0x04) ? 1 : 0;

    /* 0xFF means "system default"; anything else indexes the most recent
     * enumeration, with an out-of-range value falling back rather than
     * failing -- the list is only valid until the next query, and a stale
     * index must not leave the operator with no camera at all. */
    if (deviceIndex == 0xFF) { deviceIndex = -1; }
    else if (deviceIndex >= g_deviceCount) { deviceIndex = -1; }

    if (deviceIndex != g_currentDeviceIndex)
    {
        restart = 1;
        g_currentDeviceIndex = deviceIndex;
        if (deviceIndex >= 0 && deviceIndex < g_deviceCount)
        {
            strncpy(g_currentDeviceId, g_deviceIds[deviceIndex], CAM_DEVICE_ID_MAX);
            g_currentDeviceId[CAM_DEVICE_ID_MAX] = '\0';
        }
        else
        {
            g_currentDeviceId[0] = '\0';
        }
    }
    return restart;
}

/* ------------------------------------------------------------------------ */
/* Public entry points                                                       */
/* ------------------------------------------------------------------------ */

void kvm_cam_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    HRESULT hr;

    cam_lock_init();
    cam_send_lock_init();

    /* Created once for the session and reused across every live-stream
     * start/stop/restart -- see cam_teardown_live(). Auto-reset: each wait
     * consumes exactly one signal, matching Microsoft's own reference
     * IMFSourceReaderCallback sample. */
    if (g_liveStopEvent == NULL) { g_liveStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL); }

    /* Reference-counted and process-wide; safe to call once per session the
     * same way kvm_mic_init()'s per-call CoInitializeEx calls already assume
     * for this session-per-process agent. Camera capture is simply
     * unavailable for this session if it fails -- every MF call below then
     * fails cleanly and send_caps() reports no camera, exactly as if none
     * were plugged in. */
    if (!g_mfStarted)
    {
        hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
        g_mfStarted = SUCCEEDED(hr);
    }

    cam_lock();
    g_writeHandler = writeHandler;
    g_reserved = reserved;
    /* Consent never carries over from a previous session, and neither does a
     * device selection: the list is re-queried fresh per session anyway. */
    g_consent = 0;
    g_promptOutstanding = 0;
    g_deviceCount = 0;
    g_currentDeviceIndex = -1;
    g_currentDeviceId[0] = '\0';
    g_width = CAM_DEFAULT_WIDTH;
    g_height = CAM_DEFAULT_HEIGHT;
    g_fps = CAM_DEFAULT_FPS;
    g_quality = CAM_DEFAULT_QUALITY;
    g_suppress = 1;
    g_threshold = CAM_DEFAULT_THRESHOLD;
    g_forceRaw = 0;
    g_passthroughActive = 0;
    g_snapshotPending = 0;
    g_snapshotQuality = CAM_SNAPSHOT_QUALITY;
    g_pendingSnapWidth = 0;
    g_pendingSnapHeight = 0;
    g_pendingSnapDeviceIndex = -1;
    g_snapshotPausedStream = 0;
    g_pendingAction = 0;
    g_pendingStartFrameLen = 0;
    g_setupInProgress = 0;
    g_initialised = 1;
    reset_scene_state();
    cam_unlock();

    send_caps(writeHandler, reserved);
}

void kvm_cam_set_consent(int granted)
{
    cam_lock_init();

    cam_lock();
    g_consent = (granted != 0);
    g_promptOutstanding = 0;
    cam_unlock();

    if (!granted)
    {
        /* Revoking stops capture promptly rather than at some later frame --
         * cam_teardown_live() is a safe no-op if nothing was running. */
        cam_teardown_live();
        cam_lock(); g_passthroughActive = 0; cam_unlock();
    }

    send_caps(g_writeHandler, g_reserved);
}

int kvm_cam_has_consent(void)
{
    int granted;
    cam_lock_init();
    cam_lock();
    granted = g_consent;
    cam_unlock();
    return granted;
}

/*
 * frame/size: the whole MNG_CAM_START wire frame, or NULL/0 to (re)start
 * with whatever settings are already in effect -- see kvm_cam.h. Verbatim
 * port of the control flow in linux_cam.c's kvm_cam_start(), with
 * cam_teardown_live() + cam_spawn_setup_thread() standing in for Linux's
 * pthread_join(restartThread) + pthread_create(&g_thread, ...): both paths
 * end up tearing down anything currently running (a safe no-op when nothing
 * is) and then (re)opening fresh off the KVM command dispatch thread.
 */
void kvm_cam_start(const unsigned char *frame, int size)
{
    int restart;
    int skipConsentPrompt = 0;
    int stashLen;
    int needConsentPrompt;
    int consent;

    cam_lock_init();

    /* Read before cam_apply_params() ever runs: this must still be seen on
     * the very request that finds !g_consent and refuses below, which is
     * exactly the frame cam_apply_params() never gets called for. */
    if (frame != NULL && size >= 14) { skipConsentPrompt = (frame[10] & 0x02) ? 1 : 0; }

    cam_lock();

    /* Fail closed: never open the camera without a local decision. */
    consent = g_consent;
    if (!consent)
    {
        /* Remembered so kvm_cam_consent_granted() can apply the settings
         * this request actually asked for once the local user answers,
         * instead of silently falling back to whatever was in effect
         * before. */
        g_pendingAction |= CAM_PENDING_START;
        stashLen = (frame != NULL && size > 0) ? size : 0;
        if (stashLen > CAM_START_FRAME_LEN) { stashLen = CAM_START_FRAME_LEN; }
        if (stashLen > 0) { memcpy(g_pendingStartFrame, frame, (size_t)stashLen); }
        g_pendingStartFrameLen = stashLen;

        needConsentPrompt = g_initialised && (InterlockedCompareExchange(&g_liveShutdown, 0, 0) != 0);
        if (needConsentPrompt) { g_promptOutstanding = 1; }
        cam_unlock();
        if (needConsentPrompt) { notify_js_consent_needed(skipConsentPrompt); }
        return;
    }

    restart = cam_apply_params(frame, size);

    if (g_snapshotPausedStream)
    {
        /* A snapshot is using the (single-open) device right now. The
         * settings above were still applied, and
         * cam_capture_setup_thread() reads g_width/g_height/g_fps/
         * g_currentDeviceId fresh when it starts, so there is nothing left
         * to do here -- spawning a setup thread now would race the
         * snapshot worker for the same device. */
        cam_unlock();
        return;
    }

    if (InterlockedCompareExchange(&g_liveShutdown, 0, 0) == 0 && !restart)
    {
        /* Already capturing with a compatible configuration: quality and
         * suppression were applied above and cam_process_sample() reads
         * them fresh every frame. Nothing else to do -- this is what lets
         * the operator retune without interrupting the stream, and what
         * makes a duplicate START from the browser harmless. */
        cam_unlock();
        return;
    }
    cam_unlock();

    /* MF cannot be reconfigured while streaming any more than V4L2 can, so
     * tear down and rebuild on the new settings without touching consent --
     * this is not kvm_cam_stop(), the session's permission stands.
     * cam_teardown_live() is a safe no-op on a cold start, when nothing was
     * running yet. */
    cam_teardown_live();
    cam_spawn_setup_thread();
}

/*
 * kvm_cam_consent_granted - the local user just said yes to a prompt this
 * module raised itself. Ports verbatim from linux_cam.c: pure state-replay
 * over g_pendingAction/g_pendingStartFrame, with zero platform dependency --
 * this, unchanged, is what keeps Windows from ever reintroducing the "taking
 * a photo also starts the live stream" bug already fixed on Linux. A
 * snapshot fires before a start so a Snapshot-while-stream-is-off click
 * never gets upgraded into a stream the operator never asked for.
 */
void kvm_cam_consent_granted(void)
{
    int action;
    unsigned char startFrame[CAM_START_FRAME_LEN];
    int startFrameLen;

    cam_lock();
    action = g_pendingAction;
    g_pendingAction = 0;
    startFrameLen = g_pendingStartFrameLen;
    if (startFrameLen > 0) { memcpy(startFrame, g_pendingStartFrame, (size_t)startFrameLen); }
    g_pendingStartFrameLen = 0;
    cam_unlock();

    if (action & CAM_PENDING_SNAPSHOT) { kvm_cam_snapshot(NULL, 0, g_writeHandler, g_reserved); }
    if ((action & CAM_PENDING_START) || action == 0)
    {
        kvm_cam_start(startFrameLen > 0 ? startFrame : NULL, startFrameLen);
    }
}

void kvm_cam_snapshot(const unsigned char *frame, int size, ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    int skipConsentPrompt = 0;
    int needConsentPrompt;
    int haveRequest = (frame != NULL && size >= 12);
    int reqWidth = 0, reqHeight = 0, reqQuality = 0, reqDeviceIndex = -1;
    cam_thread_args_t *targs;
    HANDLE t;

    cam_lock_init();

    if (haveRequest)
    {
        reqWidth = (frame[4] << 8) | frame[5];
        reqHeight = (frame[6] << 8) | frame[7];
        reqQuality = frame[8];
        reqDeviceIndex = frame[9];
        skipConsentPrompt = (frame[10] & 0x02) ? 1 : 0;
    }

    cam_lock();

    /* Stashed unconditionally, even when consent turns out to be missing
     * below: kvm_cam_consent_granted() replays this call with frame==NULL
     * once the local user answers, and it must see the operator's actual
     * request rather than whatever a previous snapshot (or nothing) left
     * behind. */
    if (haveRequest)
    {
        g_pendingSnapWidth = reqWidth;
        g_pendingSnapHeight = reqHeight;
        g_snapshotQuality = (reqQuality > 0 && reqQuality <= 100) ? reqQuality : CAM_SNAPSHOT_QUALITY;
        if (reqDeviceIndex >= 0 && reqDeviceIndex < g_deviceCount) { g_pendingSnapDeviceIndex = reqDeviceIndex; }
        else { g_pendingSnapDeviceIndex = -1; }
    }

    /* A still is not a lesser intrusion than a stream: same gate. */
    if (!g_consent)
    {
        g_pendingAction |= CAM_PENDING_SNAPSHOT;
        needConsentPrompt = g_initialised;
        if (needConsentPrompt) { g_promptOutstanding = 1; }
        cam_unlock();
        if (needConsentPrompt) { notify_js_consent_needed(skipConsentPrompt); }
        return;
    }

    if (g_snapshotPending) { cam_unlock(); return; }   /* coalesce rapid clicks */
    g_snapshotPending = 1;
    cam_unlock();

    /* Always its own capture -- see cam_snapshot_worker(), which pauses and
     * resumes a live stream around it rather than diverting one of the
     * stream's own frames, so a still lands at the resolution actually
     * asked for even while a lower-resolution stream is running. */
    targs = (cam_thread_args_t*)malloc(sizeof(cam_thread_args_t));
    if (targs == NULL)
    {
        cam_lock(); g_snapshotPending = 0; cam_unlock();
        return;
    }
    targs->writeHandler = writeHandler;
    targs->reserved = reserved;

    t = CreateThread(NULL, 0, cam_snapshot_worker, targs, 0, NULL);
    if (t == NULL)
    {
        free(targs);
        cam_lock(); g_snapshotPending = 0; cam_unlock();
        return;
    }
    CloseHandle(t);
}

void kvm_cam_stop(void)
{
    int wasAwaitingConsent;

    cam_lock_init();

    cam_lock();
    /* Only when a prompt we raised is still unanswered: stopping when
     * nothing is outstanding must not emit a stray cancel, which would take
     * down an unrelated prompt raised later. */
    wasAwaitingConsent = g_promptOutstanding;
    g_promptOutstanding = 0;
    /* Stopping ends the session's permission; the next start prompts again. */
    g_consent = 0;
    g_snapshotPending = 0;
    g_pendingAction = 0;
    g_pendingStartFrameLen = 0;
    cam_unlock();

    cam_teardown_live();
    g_seq = 0;

    cam_lock();
    g_passthroughActive = 0;
    reset_scene_state();
    cam_unlock();

    /* Take down that stale prompt before reporting the new state. */
    if (wasAwaitingConsent) { notify_js(MNG_CAM_CONSENT_CANCEL); }
    send_caps(g_writeHandler, g_reserved);
}

void kvm_cam_feed(char *buffer, int bufferLen)
{
    /* Video only travels device -> browser; anything inbound is discarded so
     * the KVM command switch can stay symmetrical with the microphone and
     * audio paths. */
    (void)buffer;
    (void)bufferLen;
}

void kvm_cam_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    send_caps(writeHandler, reserved);
}

void kvm_cam_cleanup(void)
{
    int waited = 0;

    cam_lock_init();

    /* If a start requested just before this call spawned a setup thread
     * that is still opening/negotiating the device, give it a bounded
     * window to finish (or fail) before g_writeHandler/g_liveStopEvent are
     * torn down out from under it -- otherwise a stray success arriving
     * after this function returns would publish a live reader nothing is
     * left to tear down. Bounded rather than joined outright: there is no
     * thread handle here to join by design (see cam_spawn_setup_thread()),
     * and cleanup must still return promptly even in the pathological case
     * of a genuinely wedged device. */
    while (waited < CAM_STOP_WAIT_MS)
    {
        int inProgress;
        cam_lock();
        inProgress = g_setupInProgress;
        cam_unlock();
        if (!inProgress) { break; }
        Sleep(20);
        waited += 20;
    }

    cam_lock();
    g_consent = 0;
    g_promptOutstanding = 0;
    g_snapshotPending = 0;
    g_pendingAction = 0;
    g_pendingStartFrameLen = 0;
    cam_unlock();

    cam_teardown_live();

    cam_lock();
    reset_scene_state();
    g_deviceCount = 0;
    g_passthroughActive = 0;
    g_initialised = 0;
    g_writeHandler = NULL;
    g_reserved = NULL;
    cam_unlock();

    if (g_mfStarted) { MFShutdown(); g_mfStarted = 0; }
    if (g_liveStopEvent != NULL) { CloseHandle(g_liveStopEvent); g_liveStopEvent = NULL; }
}

#endif /* _LINKVM && _KVM_CAMERA */
