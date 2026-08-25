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
 * Linux capture of the device's webcam, streamed to the operator.
 *
 * The visual sibling of linux_mic.c, and deliberately built the same way: a
 * capture thread that owns the device, a fail-closed consent gate that the
 * agent's JavaScript layer drives, and enumeration that never runs on the KVM
 * command thread. See kvm_cam.h for the wire formats and for why this streams
 * JPEG frames instead of a video codec.
 *
 * V4L2 needs no library: it is ioctls on a kernel UAPI header, so unlike
 * PulseAudio in linux_mic.c there is nothing to dlopen and nothing that can be
 * missing at runtime. A machine with no camera simply reports the feature
 * unavailable.
 *
 * libjpeg-turbo is already linked for desktop tiles, and is used here for two
 * things only: encoding the fallback path for cameras that cannot produce
 * MJPEG themselves, and the cheap 1/8-scale decode that drives static-scene
 * suppression. The common MJPEG path touches neither.
 */

#if defined(_KVM_CAMERA)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <linux/videodev2.h>

#include "meshcore/meshdefines.h"
#include "meshcore/KVM/kvm_cam.h"

/* Vendored rather than the system copy so the header always matches the
 * libturbojpeg.a this build links (see the makefile's KVM block). */
#include "lib-jpeg-turbo/includes/turbojpeg.h"

#define CAM_DEFAULT_WIDTH    640
#define CAM_DEFAULT_HEIGHT   480
#define CAM_DEFAULT_FPS      15
#define CAM_DEFAULT_QUALITY  75
#define CAM_SNAPSHOT_QUALITY 100  /* a still is sent once, so it always defaults to the camera's best */
#define CAM_DEFAULT_THRESHOLD 3   /* mean absolute luma difference; sensor noise alone sits well under this */
/* Frames to discard at the start of every fresh live-stream open before the
 * first one is eligible to be sent, mirroring cam_snapshot_worker()'s
 * existing "skip the first 3" exposure-settling wait -- without this the
 * stream's very first visible frame(s) can be dark or half-exposed on
 * cameras with real auto-exposure/white-balance settling time, and static-
 * scene suppression would otherwise lock onto that bad frame as its baseline
 * until the next genuine scene change happened to clear it. */
#define CAM_WARMUP_FRAMES    3

#define CAM_MAX_FPS          60
#define CAM_MAX_WIDTH        4096
#define CAM_MAX_HEIGHT       2160
#define CAM_BUF_COUNT        4
#define CAM_CAPS_LEN         14
#define CAM_DATA_HEADER      8    /* cmd(2) len(2) seq(2) flags(1) reserved(1) */
#define CAM_SNAP_HEADER      16   /* see kvm_cam.h for the field layout */
#define CAM_JUMBO_THRESHOLD  65500 /* same cutover desktop tiles use */

#define CAM_DEVICE_MAX_COUNT 16
#define CAM_DEVICE_NAME_MAX  63
#define CAM_DEVICE_PATH_MAX  63
#define CAM_DEVICE_SCAN_MAX  64   /* /dev/video0 .. /dev/video63 */
#define CAM_SELECT_TIMEOUT_S 2    /* bounded so the thread notices shutdown promptly */

/* Enumerated by kvm_cam_query_devices(), indexed exactly as sent in
 * MNG_CAM_DEVICE_LIST. Labels are browser-facing and truncated; paths are the
 * real /dev/video* nodes, used locally and never sent anywhere. */
static char g_deviceLabels[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_NAME_MAX + 1];
static char g_devicePaths[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_PATH_MAX + 1];
static int g_deviceCount = 0;
static int g_currentDeviceIndex = -1;                     /* -1 = system default */
static char g_currentPath[CAM_DEVICE_PATH_MAX + 1] = {0}; /* resolved from the index; read once at thread start */

static int g_width = CAM_DEFAULT_WIDTH;
static int g_height = CAM_DEFAULT_HEIGHT;
static int g_fps = CAM_DEFAULT_FPS;
static int g_quality = CAM_DEFAULT_QUALITY;
static int g_suppress = 1;                       /* static-scene suppression enabled */
static int g_threshold = CAM_DEFAULT_THRESHOLD;
static int g_forceRaw = 0;                       /* skip MJPEG passthrough even when offered */
static int g_passthroughActive = 0;              /* what the live stream actually ended up doing */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_consent = 0;               /* only kvm_cam_set_consent() sets this */
/* 1 between asking the JS layer to prompt and that prompt being resolved, so a
 * cancel is only ever sent for a prompt that is actually on screen. */
static volatile int g_promptOutstanding = 0;
static volatile int g_shutdown = 1;              /* 1 = capture thread not running */
static volatile int g_enumInProgress = 0;
static pthread_t g_thread = (pthread_t)0;
static uint16_t g_seq = 0;
static int g_slave_pipe_fd = -1;
static int g_initialised = 0;
static ILibTransport_DoneState(*g_writeHandler)(char*, int, void*) = NULL;
static void *g_reserved = NULL;

/* A snapshot always captures independently, at its own requested resolution
 * (by default, the camera's largest) rather than whatever the live stream
 * happens to be running at. V4L2 devices are single-open, so if the stream is
 * running when a snapshot is asked for, cam_snapshot_worker() pauses it for
 * the moment it takes to grab one frame, then restarts it -- see
 * g_snapshotPausedStream below. */
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
/* 1 while a snapshot has the stream paused to reuse the (single-open) device
 * at its own resolution -- guards kvm_cam_start() from racing it to spawn a
 * second capture thread for the same device. See cam_snapshot_worker(). */
static volatile int g_snapshotPausedStream = 0;

/* MNG_CAM_CONSENT (the local user's answer) is one generic signal shared by
 * every kind of request that can need it, since the agent's JS layer has no
 * way to know -- and no business deciding -- which kind originally asked.
 * Native remembers that itself: whichever of kvm_cam_start()/kvm_cam_snapshot
 * found consent missing ORs its bit in here, and kvm_cam_consent_granted()
 * acts on exactly what is set, nothing more. A bitmask rather than one
 * pending "kind" so a rapid Start-then-Snapshot click before the local user
 * answers does not silently lose whichever request came first. */
#define CAM_PENDING_START    0x01
#define CAM_PENDING_SNAPSHOT 0x02
static volatile int g_pendingAction = 0;
/* The whole MNG_CAM_START frame that triggered the currently-outstanding
 * consent prompt, so kvm_cam_consent_granted() can apply the settings it
 * actually asked for. kvm_cam_start()'s fail-closed branch deliberately never
 * calls cam_apply_params() -- nothing should be touched before consent is
 * real -- so without this, the operator's chosen profile would silently be
 * replaced by whatever the encoder's compiled-in defaults happen to be. */
#define CAM_START_FRAME_LEN 14
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

/* One open V4L2 capture session. Shared by the streaming thread and the
 * one-shot snapshot path so the device setup exists in exactly one place. */
typedef struct
{
    int fd;
    void *bufStart[CAM_BUF_COUNT];
    size_t bufLength[CAM_BUF_COUNT];
    int bufCount;
    int width;
    int height;
    int isMjpeg;
    /* The actual V4L2 fourcc granted (V4L2_PIX_FMT_MJPEG/YUYV/UYVY/NV12) --
     * isMjpeg alone used to be enough when raw meant "YUYV, no other option",
     * but cam_dev_open() now falls back through several raw formats for
     * wider real-hardware coverage, so the non-MJPEG path needs to know
     * which one it actually got. */
    unsigned int pixfmt;
} cam_dev_t;

/* ------------------------------------------------------------------------ */
/* Transport                                                                 */
/* ------------------------------------------------------------------------ */

/*
 * Every outbound frame goes through here, and it is serialized on its own
 * mutex rather than g_lock.
 *
 * Serialization is required, not defensive: a pipe write is only atomic up to
 * PIPE_BUF (4 KiB), and a camera frame is far larger, so two threads writing
 * at once would interleave their bytes and corrupt both frames. That can
 * genuinely happen -- the one-shot snapshot worker only spawns when nothing is
 * streaming, but the operator can start the stream while that worker is still
 * in flight, putting two writers on this fd at the same moment.
 *
 * A separate mutex is used because callers reach this both holding and not
 * holding g_lock, and because a frame write must never block the capture
 * thread's settings checks behind it.
 */
static pthread_mutex_t g_sendLock = PTHREAD_MUTEX_INITIALIZER;

static void cam_write_out(const char *buf, int len)
{
    pthread_mutex_lock(&g_sendLock);
    if (g_slave_pipe_fd >= 0)
    {
        ssize_t written = write(g_slave_pipe_fd, buf, (size_t)len);
        (void)written;
        fsync(g_slave_pipe_fd);
    }
    else if (g_writeHandler != NULL)
    {
        g_writeHandler((char*)buf, len, g_reserved);
    }
    pthread_mutex_unlock(&g_sendLock);
}

/*
 * Send one command frame, transparently using MNG_JUMBO when the payload is
 * too large for the KVM header's 16-bit length -- which a JPEG at any useful
 * resolution routinely is. Both receivers already understand JUMBO
 * generically (kvm_relay_readSink here, agent-redir-ws-0.1.1.js in the
 * browser), so nothing downstream needs to know which form was used.
 *
 * hdr is the per-command header that follows cmd+len; payload is the image.
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
    /* Meaningless once wrapped -- the receiver takes the length from the JUMBO
     * header -- so mirror what the desktop tile path writes there: zero. */
    ((unsigned short*)(buf + p))[1] = jumbo ? 0 : htons((unsigned short)innerLen);
    if (hdrLen > 0) { memcpy(buf + p + 4, hdr, (size_t)hdrLen); }
    if (payloadLen > 0) { memcpy(buf + p + 4 + hdrLen, payload, (size_t)payloadLen); }

    cam_write_out(buf, total);
    free(buf);
}

static void send_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    unsigned char caps[CAM_CAPS_LEN];
    int available, granted, passthrough, w, h, fps, quality, devCount;

    pthread_mutex_lock(&g_lock);
    /* A camera "exists" if the last enumeration found one, or if we have never
     * enumerated and at least one node is openable. The cheap proxy below
     * avoids opening devices from the caps path, which the browser polls. */
    available = (g_deviceCount > 0) || (access("/dev/video0", F_OK) == 0);
    granted = g_consent;
    passthrough = g_passthroughActive;
    w = g_width; h = g_height; fps = g_fps; quality = g_quality;
    devCount = g_deviceCount;
    pthread_mutex_unlock(&g_lock);

    caps[0] = (unsigned char)((MNG_CAM_CAPS >> 8) & 0xFF);
    caps[1] = (unsigned char)(MNG_CAM_CAPS & 0xFF);
    caps[2] = 0x00;
    caps[3] = (unsigned char)CAM_CAPS_LEN;
    caps[4] = (unsigned char)((available ? 0x01 : 0x00) | (granted ? 0x02 : 0x00) | (passthrough ? 0x04 : 0x00));
    caps[5] = 1;    /* platform: Linux */
    caps[6] = (unsigned char)((w >> 8) & 0xFF);
    caps[7] = (unsigned char)(w & 0xFF);
    caps[8] = (unsigned char)((h >> 8) & 0xFF);
    caps[9] = (unsigned char)(h & 0xFF);
    caps[10] = (unsigned char)fps;
    caps[11] = 1;   /* protocol version */
    caps[12] = (unsigned char)quality;
    caps[13] = (unsigned char)devCount;

    /* Through cam_write_out() like every other frame, so this cannot land in
     * the middle of one the capture thread is writing. writeHandler/reserved
     * are the same pair stashed at init; honour an explicitly supplied one
     * only when there is no slave pipe to prefer. */
    if ((g_slave_pipe_fd < 0) && (writeHandler != NULL) && (writeHandler != g_writeHandler))
    {
        pthread_mutex_lock(&g_sendLock);
        writeHandler((char*)caps, CAM_CAPS_LEN, reserved);
        pthread_mutex_unlock(&g_sendLock);
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
 * g_consent regardless of it, and the decision to honour it is made by the
 * trusted agent JS layer, never by native trusting a browser-supplied byte.
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

/* ------------------------------------------------------------------------ */
/* V4L2 device handling                                                      */
/* ------------------------------------------------------------------------ */

/* ioctl retried across signal interruption; every V4L2 call goes through it. */
static int xioctl(int fd, unsigned long request, void *arg)
{
    int r;
    do { r = ioctl(fd, request, arg); } while (r == -1 && errno == EINTR);
    return r;
}

static void cam_dev_close(cam_dev_t *d)
{
    int i;
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    if (d == NULL) { return; }
    if (d->fd >= 0)
    {
        xioctl(d->fd, VIDIOC_STREAMOFF, &type);
    }
    for (i = 0; i < d->bufCount; i++)
    {
        if (d->bufStart[i] != NULL && d->bufStart[i] != MAP_FAILED)
        {
            munmap(d->bufStart[i], d->bufLength[i]);
        }
        d->bufStart[i] = NULL;
        d->bufLength[i] = 0;
    }
    d->bufCount = 0;
    if (d->fd >= 0) { close(d->fd); d->fd = -1; }
}

/*
 * Open one capture device and start streaming from it.
 * Returns 0 on success, non-zero on failure (with everything cleaned up).
 *
 * Tries pixel formats in order of decreasing cheapness/likelihood rather
 * than just "MJPEG, then one raw fallback": MJPEG first, since it is already
 * a finished JPEG and can be forwarded without spending any CPU on it at
 * all; then YUYV, the common raw format on plain USB UVC webcams; then
 * UYVY, a near-identical byte-order variant some webcams and USB capture
 * dongles report instead; then NV12, the ISP-native planar format on many
 * ARM/CSI-connected cameras -- relevant because ARM boards are an explicit
 * target for this agent (see kvm_cam.h). forceRaw simply drops MJPEG from
 * the list instead of special-casing it, so the raw fallback order is
 * identical whether or not MJPEG was ever tried.
 */
static int cam_dev_open(cam_dev_t *d, const char *path, int width, int height, int fps, int forceRaw)
{
    struct v4l2_capability cap;
    struct v4l2_format fmt;
    struct v4l2_requestbuffers req;
    struct v4l2_streamparm parm;
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    unsigned int caps;
    unsigned int candidates[4];
    int candidateCount = 0;
    int fmtIndex;
    int i;

    memset(d, 0, sizeof(*d));
    d->fd = -1;

    d->fd = open(path, O_RDWR | O_NONBLOCK, 0);
    if (d->fd < 0) { return -1; }

    memset(&cap, 0, sizeof(cap));
    if (xioctl(d->fd, VIDIOC_QUERYCAP, &cap) < 0) { goto fail; }
    caps = (cap.capabilities & V4L2_CAP_DEVICE_CAPS) ? cap.device_caps : cap.capabilities;
    if (!(caps & V4L2_CAP_VIDEO_CAPTURE)) { goto fail; }
    if (!(caps & V4L2_CAP_STREAMING)) { goto fail; }

    if (!forceRaw) { candidates[candidateCount++] = V4L2_PIX_FMT_MJPEG; }
    candidates[candidateCount++] = V4L2_PIX_FMT_YUYV;
    candidates[candidateCount++] = V4L2_PIX_FMT_UYVY;
    candidates[candidateCount++] = V4L2_PIX_FMT_NV12;

    for (fmtIndex = 0; fmtIndex < candidateCount; fmtIndex++)
    {
        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.width = (unsigned int)width;
        fmt.fmt.pix.height = (unsigned int)height;
        fmt.fmt.pix.field = V4L2_FIELD_ANY;
        fmt.fmt.pix.pixelformat = candidates[fmtIndex];
        if (xioctl(d->fd, VIDIOC_S_FMT, &fmt) == 0) { break; }
    }
    if (fmtIndex >= candidateCount) { goto fail; }

    /* The driver rewrites S_FMT with what it actually granted, which may be a
     * different size than asked for; everything downstream must use these. */
    d->width = (int)fmt.fmt.pix.width;
    d->height = (int)fmt.fmt.pix.height;
    d->pixfmt = fmt.fmt.pix.pixelformat;
    d->isMjpeg = (fmt.fmt.pix.pixelformat == V4L2_PIX_FMT_MJPEG) ? 1 : 0;
    if (d->width <= 0 || d->height <= 0) { goto fail; }

    /* Advisory: many drivers ignore it, so the capture loop throttles in
     * software as well rather than trusting this to have taken effect. */
    memset(&parm, 0, sizeof(parm));
    parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    parm.parm.capture.timeperframe.numerator = 1;
    parm.parm.capture.timeperframe.denominator = (unsigned int)(fps > 0 ? fps : CAM_DEFAULT_FPS);
    xioctl(d->fd, VIDIOC_S_PARM, &parm);

    memset(&req, 0, sizeof(req));
    req.count = CAM_BUF_COUNT;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(d->fd, VIDIOC_REQBUFS, &req) < 0) { goto fail; }
    if (req.count < 2) { goto fail; }

    for (i = 0; i < (int)req.count && i < CAM_BUF_COUNT; i++)
    {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = (unsigned int)i;
        if (xioctl(d->fd, VIDIOC_QUERYBUF, &buf) < 0) { goto fail; }

        d->bufLength[i] = (size_t)buf.length;
        d->bufStart[i] = mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, d->fd, (off_t)buf.m.offset);
        if (d->bufStart[i] == MAP_FAILED) { d->bufStart[i] = NULL; goto fail; }
        d->bufCount = i + 1;

        if (xioctl(d->fd, VIDIOC_QBUF, &buf) < 0) { goto fail; }
    }
    if (d->bufCount < 2) { goto fail; }

    if (xioctl(d->fd, VIDIOC_STREAMON, &type) < 0) { goto fail; }
    return 0;

fail:
    cam_dev_close(d);
    return -1;
}

/*
 * Wait for and dequeue one frame. Returns 0 and fills bufIndex/data/len on
 * success; the caller must call cam_dev_release() once done with the bytes,
 * which stay owned by the driver's mmap'd buffer until then.
 * Returns 1 on timeout (no frame yet, not an error) and -1 on failure.
 */
static int cam_dev_grab(cam_dev_t *d, struct v4l2_buffer *buf, unsigned char **data, size_t *len)
{
    fd_set fds;
    struct timeval tv;
    int r;

    FD_ZERO(&fds);
    FD_SET(d->fd, &fds);
    tv.tv_sec = CAM_SELECT_TIMEOUT_S;
    tv.tv_usec = 0;

    r = select(d->fd + 1, &fds, NULL, NULL, &tv);
    if (r < 0) { return (errno == EINTR) ? 1 : -1; }
    if (r == 0) { return 1; }

    memset(buf, 0, sizeof(*buf));
    buf->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf->memory = V4L2_MEMORY_MMAP;
    if (xioctl(d->fd, VIDIOC_DQBUF, buf) < 0)
    {
        /* EAGAIN just means the frame is not ready yet on a non-blocking fd. */
        return (errno == EAGAIN) ? 1 : -1;
    }
    if (buf->index >= (unsigned int)d->bufCount) { return -1; }

    *data = (unsigned char*)d->bufStart[buf->index];
    *len = (size_t)buf->bytesused;
    return 0;
}

static void cam_dev_release(cam_dev_t *d, struct v4l2_buffer *buf)
{
    xioctl(d->fd, VIDIOC_QBUF, buf);
}

/*
 * Find a device's largest resolution for one pixel format via
 * VIDIOC_ENUM_FRAMESIZES. Returns 0 and fills outW/outH on success, non-zero
 * if the device can't be opened or offers nothing in this format.
 *
 * A UVC webcam (the common case) enumerates a short list of exact DISCRETE
 * sizes, so every one is checked and the largest by area kept. A device that
 * reports STEPWISE or CONTINUOUS sizing instead exposes its bounds directly
 * in a single entry -- there is nothing to iterate, and every later index
 * would just describe the same range.
 */
static int cam_find_max_resolution(const char *path, unsigned int pixelformat, int *outW, int *outH)
{
    int fd, i, found = 0;
    int bestW = 0, bestH = 0;
    long bestArea = 0;

    fd = open(path, O_RDWR | O_NONBLOCK, 0);
    if (fd < 0) { return -1; }

    for (i = 0; i < 64; i++)
    {
        struct v4l2_frmsizeenum fse;
        memset(&fse, 0, sizeof(fse));
        fse.index = (unsigned int)i;
        fse.pixel_format = pixelformat;
        if (xioctl(fd, VIDIOC_ENUM_FRAMESIZES, &fse) < 0) { break; }

        if (fse.type == V4L2_FRMSIZE_TYPE_DISCRETE)
        {
            long area = (long)fse.discrete.width * (long)fse.discrete.height;
            if (area > bestArea)
            {
                bestArea = area;
                bestW = (int)fse.discrete.width;
                bestH = (int)fse.discrete.height;
                found = 1;
            }
        }
        else
        {
            bestW = (int)fse.stepwise.max_width;
            bestH = (int)fse.stepwise.max_height;
            found = 1;
            break;
        }
    }

    close(fd);
    if (!found || bestW <= 0 || bestH <= 0) { return -1; }
    if (bestW > CAM_MAX_WIDTH) { bestW = CAM_MAX_WIDTH; }
    if (bestH > CAM_MAX_HEIGHT) { bestH = CAM_MAX_HEIGHT; }
    *outW = bestW;
    *outH = bestH;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Encoding helpers                                                          */
/* ------------------------------------------------------------------------ */

/*
 * Packed YUYV (4:2:2) to RGB24, for cameras that cannot produce MJPEG.
 * Deliberately integer-only: this runs per frame on machines without an FPU
 * worth relying on.
 */
static void yuyv_to_rgb(const unsigned char *src, unsigned char *dst, int width, int height)
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
 * Packed UYVY (4:2:2) to RGB24 -- the same format as YUYV with the four bytes
 * in a different order (U Y0 V Y1 instead of Y0 U Y1 V), reported by some
 * webcams and USB capture dongles instead of YUYV. Identical math to
 * yuyv_to_rgb(), just reading the bytes at their UYVY offsets.
 */
static void uyvy_to_rgb(const unsigned char *src, unsigned char *dst, int width, int height)
{
    int i, total = width * height;

    for (i = 0; i < total; i += 2)
    {
        int u = src[0], y0 = src[1], v = src[2], y1 = src[3];
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
 * half-resolution-in-both-dimensions interleaved U/V plane. No plain USB UVC
 * webcam needs this (they overwhelmingly offer MJPEG or YUYV), but it is the
 * ISP-native output format on many ARM/CSI-connected cameras -- boards this
 * agent explicitly targets (see kvm_cam.h) -- so without this fallback such
 * a camera would enumerate successfully in V4L2 yet be entirely unusable
 * here.
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

/*
 * Dispatch to the right *_to_rgb() converter for whatever raw format
 * cam_dev_open() actually negotiated. Shared by capture_thread() and
 * cam_snapshot_worker() so the format list lives in exactly one place.
 * V4L2_PIX_FMT_YUYV is the fallback default for any pixfmt this doesn't
 * otherwise recognise, matching this function's behaviour before UYVY/NV12
 * existed.
 */
static void raw_to_rgb(unsigned int pixfmt, const unsigned char *src, unsigned char *dst, int width, int height)
{
    if (pixfmt == V4L2_PIX_FMT_UYVY) { uyvy_to_rgb(src, dst, width, height); }
    else if (pixfmt == V4L2_PIX_FMT_NV12) { nv12_to_rgb(src, dst, width, height); }
    else { yuyv_to_rgb(src, dst, width, height); }
}

/*
 * Encode an already-converted RGB24 frame to JPEG. Returns a tjAlloc'd
 * buffer the caller must free with tjFree(), or NULL. Conversion is the
 * caller's job (see raw_to_rgb()) rather than folded in here, since there
 * are now three raw source formats sharing this one encode step.
 */
static unsigned char *encode_rgb_jpeg(const unsigned char *rgb, int width, int height, int quality, unsigned long *outLen)
{
    tjhandle enc = NULL;
    unsigned char *jpeg = NULL;
    unsigned long jpegLen = 0;

    if (width <= 0 || height <= 0 || rgb == NULL) { return NULL; }

    enc = tjInitCompress();
    if (enc == NULL) { return NULL; }

    if (tjCompress2(enc, rgb, width, 0, height, TJPF_RGB, &jpeg, &jpegLen,
                    TJSAMP_420, quality, TJFLAG_FASTDCT) < 0)
    {
        if (jpeg != NULL) { tjFree(jpeg); jpeg = NULL; }
        jpegLen = 0;
    }

    tjDestroy(enc);
    if (jpeg == NULL || jpegLen == 0) { return NULL; }
    *outLen = jpegLen;
    return jpeg;
}

/*
 * Reduce a JPEG to a small grayscale thumbnail using libjpeg-turbo's scaled
 * decode, which is dramatically cheaper than decoding at full size because the
 * DCT coefficients are downscaled during entropy decoding rather than after.
 * Returns a malloc'd buffer plus its dimensions, or NULL.
 */
static unsigned char *jpeg_thumbnail(const unsigned char *jpeg, unsigned long jpegLen, int *outW, int *outH)
{
    tjhandle dec = NULL;
    int w = 0, h = 0, subsamp = 0, colorspace = 0;
    int nfactors = 0, i, chosen = -1;
    tjscalingfactor *factors = NULL;
    int sw = 0, sh = 0;
    unsigned char *thumb = NULL;

    dec = tjInitDecompress();
    if (dec == NULL) { return NULL; }

    if (tjDecompressHeader3(dec, jpeg, jpegLen, &w, &h, &subsamp, &colorspace) < 0) { goto fail; }
    if (w <= 0 || h <= 0) { goto fail; }

    /* Prefer exactly 1/8; fall back to whatever the smallest offered scale is
     * so this still works if the library's factor table ever differs. */
    factors = tjGetScalingFactors(&nfactors);
    if (factors == NULL || nfactors <= 0) { goto fail; }
    for (i = 0; i < nfactors; i++)
    {
        if (factors[i].num == 1 && factors[i].denom == 8) { chosen = i; break; }
    }
    if (chosen < 0)
    {
        int bestW = 0;
        for (i = 0; i < nfactors; i++)
        {
            int cw = TJSCALED(w, factors[i]);
            if (chosen < 0 || cw < bestW) { chosen = i; bestW = cw; }
        }
    }
    if (chosen < 0) { goto fail; }

    sw = TJSCALED(w, factors[chosen]);
    sh = TJSCALED(h, factors[chosen]);
    if (sw <= 0 || sh <= 0) { goto fail; }

    thumb = (unsigned char*)malloc((size_t)sw * (size_t)sh);
    if (thumb == NULL) { goto fail; }

    if (tjDecompress2(dec, jpeg, jpegLen, thumb, sw, 0, sh, TJPF_GRAY, TJFLAG_FASTDCT) < 0)
    {
        free(thumb);
        thumb = NULL;
        goto fail;
    }

    tjDestroy(dec);
    *outW = sw;
    *outH = sh;
    return thumb;

fail:
    tjDestroy(dec);
    return NULL;
}

/* Subsample packed YUYV straight to a luma thumbnail. No decode needed: in
 * YUYV every even byte is already a luma sample. */
static unsigned char *yuyv_thumbnail(const unsigned char *yuyv, int width, int height, int *outW, int *outH)
{
    int sw = width / 8, sh = height / 8, x, y;
    unsigned char *thumb;

    if (sw <= 0 || sh <= 0) { return NULL; }
    thumb = (unsigned char*)malloc((size_t)sw * (size_t)sh);
    if (thumb == NULL) { return NULL; }

    for (y = 0; y < sh; y++)
    {
        const unsigned char *row = yuyv + (size_t)(y * 8) * (size_t)width * 2;
        for (x = 0; x < sw; x++)
        {
            thumb[y * sw + x] = row[(size_t)(x * 8) * 2];
        }
    }
    *outW = sw;
    *outH = sh;
    return thumb;
}

/* Subsample packed UYVY straight to a luma thumbnail. Same idea as
 * yuyv_thumbnail(), but the luma byte sits at offset 1 in each pair rather
 * than offset 0. */
static unsigned char *uyvy_thumbnail(const unsigned char *uyvy, int width, int height, int *outW, int *outH)
{
    int sw = width / 8, sh = height / 8, x, y;
    unsigned char *thumb;

    if (sw <= 0 || sh <= 0) { return NULL; }
    thumb = (unsigned char*)malloc((size_t)sw * (size_t)sh);
    if (thumb == NULL) { return NULL; }

    for (y = 0; y < sh; y++)
    {
        const unsigned char *row = uyvy + (size_t)(y * 8) * (size_t)width * 2;
        for (x = 0; x < sw; x++)
        {
            thumb[y * sw + x] = row[(size_t)(x * 8) * 2 + 1];
        }
    }
    *outW = sw;
    *outH = sh;
    return thumb;
}

/* Subsample NV12's Y plane straight to a luma thumbnail. The Y plane is
 * already a standalone 8bpp grayscale image at full resolution, so this
 * needs no chroma involvement at all -- simpler than YUYV/UYVY's
 * interleaved packing. */
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
        for (x = 0; x < sw; x++)
        {
            thumb[y * sw + x] = row[x * 8];
        }
    }
    *outW = sw;
    *outH = sh;
    return thumb;
}

/* Dispatch to the right *_thumbnail() for whatever raw format was
 * negotiated -- the thumbnail-side counterpart of raw_to_rgb(). */
static unsigned char *raw_thumbnail(unsigned int pixfmt, const unsigned char *src, int width, int height, int *outW, int *outH)
{
    if (pixfmt == V4L2_PIX_FMT_UYVY) { return uyvy_thumbnail(src, width, height, outW, outH); }
    if (pixfmt == V4L2_PIX_FMT_NV12) { return nv12_thumbnail(src, width, height, outW, outH); }
    return yuyv_thumbnail(src, width, height, outW, outH);
}

/*
 * Decide whether this frame is worth sending. Returns 1 to send.
 *
 * Compares against the previously *sent* frame rather than the previous
 * captured one, so a scene drifting slowly (changing daylight) still
 * eventually crosses the threshold instead of never triggering.
 * Takes ownership of nothing; updates the stored thumbnail when it says send.
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
/* Sending frames                                                            */
/* ------------------------------------------------------------------------ */

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
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

/* ------------------------------------------------------------------------ */
/* Capture thread                                                            */
/* ------------------------------------------------------------------------ */

static void *capture_thread(void *arg)
{
    cam_dev_t dev;
    char path[CAM_DEVICE_PATH_MAX + 1];
    int width, height, fps, forceRaw;
    uint64_t nextDue = 0;
    uint64_t interval;
    int framesSeen = 0;

    (void)arg;

    pthread_mutex_lock(&g_lock);
    /* Read once at thread start: a change to any of these restarts the thread
     * rather than mutating a live V4L2 stream, which cannot be reconfigured
     * without stopping it anyway. */
    strncpy(path, g_currentPath, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    width = g_width; height = g_height; fps = g_fps; forceRaw = g_forceRaw;
    reset_scene_state();
    pthread_mutex_unlock(&g_lock);

    if (path[0] == '\0') { strncpy(path, "/dev/video0", sizeof(path) - 1); }
    if (fps <= 0) { fps = CAM_DEFAULT_FPS; }
    interval = (uint64_t)(1000 / fps);

    if (cam_dev_open(&dev, path, width, height, fps, forceRaw) != 0)
    {
        pthread_mutex_lock(&g_lock);
        g_shutdown = 1;
        g_passthroughActive = 0;
        pthread_mutex_unlock(&g_lock);
        send_caps(g_writeHandler, g_reserved);
        return NULL;
    }

    pthread_mutex_lock(&g_lock);
    /* Publish what the driver actually granted, which may differ from what was
     * asked for; the browser shows these, so they must be the truth. */
    g_width = dev.width;
    g_height = dev.height;
    g_passthroughActive = dev.isMjpeg;
    pthread_mutex_unlock(&g_lock);
    send_caps(g_writeHandler, g_reserved);

    for (;;)
    {
        struct v4l2_buffer buf;
        unsigned char *data = NULL;
        size_t len = 0;
        int r, quality, suppress, threshold;
        uint64_t nowT;

        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent) { pthread_mutex_unlock(&g_lock); break; }
        quality = g_quality;
        suppress = g_suppress;
        threshold = g_threshold;
        pthread_mutex_unlock(&g_lock);

        r = cam_dev_grab(&dev, &buf, &data, &len);
        if (r < 0) { break; }
        if (r > 0) { continue; }        /* timeout: loop back and re-check shutdown */
        if (data == NULL || len == 0) { cam_dev_release(&dev, &buf); continue; }

        /* Re-check consent after the blocking wait: a revocation that landed
         * while we were parked in select() must not produce one more frame. */
        pthread_mutex_lock(&g_lock);
        if (g_shutdown || !g_consent) { pthread_mutex_unlock(&g_lock); cam_dev_release(&dev, &buf); break; }
        pthread_mutex_unlock(&g_lock);

        /* Discard the first few real frames unconditionally -- see
         * CAM_WARMUP_FRAMES. Counted on every grabbed frame regardless of
         * pacing, matching cam_snapshot_worker()'s own "attempts", not just
         * the ones that would otherwise be sent at the requested fps. */
        if (framesSeen < CAM_WARMUP_FRAMES)
        {
            framesSeen++;
            cam_dev_release(&dev, &buf);
            continue;
        }

        nowT = now_ms();

        /* Software frame pacing. V4L2's S_PARM is advisory and widely ignored,
         * so the rate the operator asked for is enforced here regardless of
         * what the driver decided to deliver. */
        if (nextDue != 0 && nowT < nextDue)
        {
            cam_dev_release(&dev, &buf);
            continue;
        }
        nextDue = nowT + interval;

        if (dev.isMjpeg)
        {
            /* The camera already produced a JPEG. Do not re-encode it. */
            int send = 1;
            if (suppress && threshold > 0)
            {
                int tw = 0, th = 0;
                unsigned char *thumb = jpeg_thumbnail(data, (unsigned long)len, &tw, &th);
                if (thumb != NULL) { send = scene_changed(thumb, tw, th, threshold); }
            }
            if (send) { send_frame(data, (unsigned long)len, 1); }
        }
        else
        {
            unsigned long jlen = 0;
            unsigned char *jpeg;
            unsigned char *rgb;
            int send = 1;

            if (suppress && threshold > 0)
            {
                int tw = 0, th = 0;
                unsigned char *thumb = raw_thumbnail(dev.pixfmt, data, dev.width, dev.height, &tw, &th);
                if (thumb != NULL) { send = scene_changed(thumb, tw, th, threshold); }
            }

            if (send)
            {
                rgb = (unsigned char*)malloc((size_t)dev.width * (size_t)dev.height * 3);
                if (rgb != NULL)
                {
                    raw_to_rgb(dev.pixfmt, data, rgb, dev.width, dev.height);
                    jpeg = encode_rgb_jpeg(rgb, dev.width, dev.height, quality, &jlen);
                    if (jpeg != NULL)
                    {
                        send_frame(jpeg, jlen, 0);
                        tjFree(jpeg);
                    }
                    free(rgb);
                }
            }
        }

        cam_dev_release(&dev, &buf);
    }

    cam_dev_close(&dev);
    pthread_mutex_lock(&g_lock);
    g_shutdown = 1;
    g_passthroughActive = 0;
    reset_scene_state();
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* Device enumeration                                                        */
/* ------------------------------------------------------------------------ */

static void *cam_query_devices_worker(void *arg)
{
    cam_thread_args_t *targs = (cam_thread_args_t*)arg;
    ILibTransport_DoneState(*writeHandler)(char*, int, void*) = targs->writeHandler;
    void *reserved = targs->reserved;
    int i, count = 0, outLen, ptr;
    unsigned char *outFrame;
    char labels[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_NAME_MAX + 1];
    char paths[CAM_DEVICE_MAX_COUNT][CAM_DEVICE_PATH_MAX + 1];

    free(targs);

    for (i = 0; i < CAM_DEVICE_SCAN_MAX && count < CAM_DEVICE_MAX_COUNT; i++)
    {
        char path[CAM_DEVICE_PATH_MAX + 1];
        struct v4l2_capability cap;
        struct v4l2_fmtdesc fmtdesc;
        unsigned int caps;
        int fd, hasFormat = 0;

        snprintf(path, sizeof(path), "/dev/video%d", i);
        if (access(path, F_OK) != 0) { continue; }

        fd = open(path, O_RDWR | O_NONBLOCK, 0);
        if (fd < 0) { continue; }

        memset(&cap, 0, sizeof(cap));
        if (xioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) { close(fd); continue; }
        caps = (cap.capabilities & V4L2_CAP_DEVICE_CAPS) ? cap.device_caps : cap.capabilities;

        /* Modern kernels expose several nodes per physical camera (capture,
         * metadata, ...). Requiring both capture and streaming, plus at least
         * one advertised format, keeps the non-capture siblings out of a list
         * the operator has to choose from. */
        if (!(caps & V4L2_CAP_VIDEO_CAPTURE) || !(caps & V4L2_CAP_STREAMING)) { close(fd); continue; }

        memset(&fmtdesc, 0, sizeof(fmtdesc));
        fmtdesc.index = 0;
        fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (xioctl(fd, VIDIOC_ENUM_FMT, &fmtdesc) >= 0) { hasFormat = 1; }
        close(fd);
        if (!hasFormat) { continue; }

        snprintf(labels[count], sizeof(labels[count]), "%s", (const char*)cap.card);
        if (labels[count][0] == '\0') { snprintf(labels[count], sizeof(labels[count]), "Camera %d", i); }
        snprintf(paths[count], sizeof(paths[count]), "%s", path);
        count++;
    }

    pthread_mutex_lock(&g_lock);
    g_deviceCount = count;
    for (i = 0; i < count; i++)
    {
        memcpy(g_deviceLabels[i], labels[i], sizeof(labels[i]));
        memcpy(g_devicePaths[i], paths[i], sizeof(paths[i]));
    }

    outLen = 5;
    for (i = 0; i < count; i++) { outLen += 1 + (int)strlen(g_deviceLabels[i]); }

    outFrame = (unsigned char*)malloc((size_t)outLen);
    if (outFrame == NULL) { g_enumInProgress = 0; pthread_mutex_unlock(&g_lock); return NULL; }

    outFrame[0] = (unsigned char)((MNG_CAM_DEVICE_LIST >> 8) & 0xFF);
    outFrame[1] = (unsigned char)(MNG_CAM_DEVICE_LIST & 0xFF);
    outFrame[2] = (unsigned char)((outLen >> 8) & 0xFF);
    outFrame[3] = (unsigned char)(outLen & 0xFF);
    outFrame[4] = (unsigned char)count;
    ptr = 5;
    for (i = 0; i < count; i++)
    {
        size_t len = strlen(g_deviceLabels[i]);
        outFrame[ptr] = (unsigned char)len; ptr++;
        memcpy(outFrame + ptr, g_deviceLabels[i], len);
        ptr += (int)len;
    }
    pthread_mutex_unlock(&g_lock);

    /* Serialized like every other frame -- see cam_write_out(). */
    if ((g_slave_pipe_fd < 0) && (writeHandler != NULL) && (writeHandler != g_writeHandler))
    {
        pthread_mutex_lock(&g_sendLock);
        writeHandler((char*)outFrame, outLen, reserved);
        pthread_mutex_unlock(&g_sendLock);
    }
    else
    {
        cam_write_out((char*)outFrame, outLen);
    }
    free(outFrame);

    pthread_mutex_lock(&g_lock);
    g_enumInProgress = 0;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

void kvm_cam_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    cam_thread_args_t *targs;
    pthread_t t;

    pthread_mutex_lock(&g_lock);
    if (g_enumInProgress) { pthread_mutex_unlock(&g_lock); return; }
    g_enumInProgress = 1;
    pthread_mutex_unlock(&g_lock);

    targs = (cam_thread_args_t*)malloc(sizeof(cam_thread_args_t));
    if (targs == NULL)
    {
        pthread_mutex_lock(&g_lock);
        g_enumInProgress = 0;
        pthread_mutex_unlock(&g_lock);
        return;
    }
    targs->writeHandler = writeHandler;
    targs->reserved = reserved;

    if (pthread_create(&t, NULL, cam_query_devices_worker, targs) != 0)
    {
        free(targs);
        pthread_mutex_lock(&g_lock);
        g_enumInProgress = 0;
        pthread_mutex_unlock(&g_lock);
        return;
    }
    pthread_detach(t);
}

/* ------------------------------------------------------------------------ */
/* Settings                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Apply an MNG_CAM_START payload. Must be called with g_lock held.
 * Returns 1 when something changed that requires restarting capture
 * (resolution, frame rate, device or the passthrough override); quality and
 * suppression settings take effect in place and do not.
 *
 * A frame shorter than the full extended form is left entirely alone, which
 * is what keeps a short START from an older server behaving as before.
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
            strncpy(g_currentPath, g_devicePaths[deviceIndex], sizeof(g_currentPath) - 1);
            g_currentPath[sizeof(g_currentPath) - 1] = '\0';
        }
        else
        {
            g_currentPath[0] = '\0';
        }
    }
    return restart;
}

/* ------------------------------------------------------------------------ */
/* Public entry points                                                       */
/* ------------------------------------------------------------------------ */

void kvm_cam_set_slave_fd(int fd)
{
    g_slave_pipe_fd = fd;
}

void kvm_cam_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    pthread_mutex_lock(&g_lock);
    g_writeHandler = writeHandler;
    g_reserved = reserved;
    /* Consent never carries over from a previous session, and neither does a
     * device selection: the list is re-queried fresh per session anyway. */
    g_consent = 0;
    g_promptOutstanding = 0;
    g_deviceCount = 0;
    g_currentDeviceIndex = -1;
    g_currentPath[0] = '\0';
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
    g_initialised = 1;
    reset_scene_state();
    pthread_mutex_unlock(&g_lock);

    send_caps(writeHandler, reserved);
}

void kvm_cam_set_consent(int granted)
{
    pthread_t thread = (pthread_t)0;

    pthread_mutex_lock(&g_lock);
    g_consent = (granted != 0);
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

int kvm_cam_has_consent(void)
{
    int granted;
    pthread_mutex_lock(&g_lock);
    granted = g_consent;
    pthread_mutex_unlock(&g_lock);
    return granted;
}

void kvm_cam_start(const unsigned char *frame, int size)
{
    int needConsentPrompt;
    int restart;
    int skipConsentPrompt = 0;
    int stashLen;
    pthread_t restartThread = (pthread_t)0;

    /* Read before cam_apply_params() ever runs: this must still be seen on the
     * very request that finds !g_consent and refuses below, which is exactly
     * the frame cam_apply_params() never gets called for. */
    if (frame != NULL && size >= 14) { skipConsentPrompt = (frame[10] & 0x02) ? 1 : 0; }

    pthread_mutex_lock(&g_lock);

    /* Fail closed: never open the camera without a local decision. */
    if (!g_consent)
    {
        /* Remembered so kvm_cam_consent_granted() can apply the settings this
         * request actually asked for once the local user answers, instead of
         * silently falling back to whatever was in effect before. */
        g_pendingAction |= CAM_PENDING_START;
        stashLen = (frame != NULL && size > 0) ? size : 0;
        if (stashLen > CAM_START_FRAME_LEN) { stashLen = CAM_START_FRAME_LEN; }
        if (stashLen > 0) { memcpy(g_pendingStartFrame, frame, (size_t)stashLen); }
        g_pendingStartFrameLen = stashLen;

        needConsentPrompt = g_initialised && g_shutdown;
        if (needConsentPrompt) { g_promptOutstanding = 1; }
        pthread_mutex_unlock(&g_lock);
        if (needConsentPrompt) { notify_js_consent_needed(skipConsentPrompt); }
        return;
    }

    restart = cam_apply_params(frame, size);

    if (g_snapshotPausedStream)
    {
        /* A snapshot is using the (single-open) device right now. The
         * settings above were still applied, and cam_snapshot_worker() reads
         * g_width/g_height/g_fps fresh when it restarts capture, so there is
         * nothing left to do here -- spawning a second thread would race the
         * worker for the same device. */
        pthread_mutex_unlock(&g_lock);
        return;
    }

    if (!g_shutdown)
    {
        if (!restart)
        {
            /* Already capturing with a compatible configuration: quality and
             * suppression were applied above and the live thread picks them up
             * on its next frame. Nothing else to do -- this is what lets the
             * operator retune without interrupting the stream, and what makes
             * a duplicate START from the browser harmless. */
            pthread_mutex_unlock(&g_lock);
            return;
        }
        /* V4L2 cannot be reconfigured while streaming, so restart the thread
         * on the new settings without touching consent -- this is not
         * kvm_cam_stop(), the session's permission stands. */
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

/*
 * Ends a snapshot attempt: clears the pending flag and, if a live stream was
 * paused to free up the (single-open) device, hands it back. Called from
 * every exit out of cam_snapshot_worker() so a failed capture never leaves
 * the stream stopped forever.
 */
static void cam_snapshot_finish(int wasStreaming)
{
    pthread_mutex_lock(&g_lock);
    g_snapshotPending = 0;
    if (wasStreaming && g_consent)
    {
        /* capture_thread() re-reads g_width/g_height/g_fps/g_currentPath
         * fresh at its own startup, so any MNG_CAM_START that arrived while
         * this snapshot had the device (and was held off by
         * g_snapshotPausedStream in kvm_cam_start()) is picked up correctly
         * here without this function needing to know about it. */
        g_shutdown = 0;
        g_snapshotPausedStream = 0;
        if (pthread_create(&g_thread, NULL, capture_thread, NULL) != 0)
        {
            g_shutdown = 1;
            g_thread = (pthread_t)0;
        }
    }
    else
    {
        g_snapshotPausedStream = 0;
    }
    pthread_mutex_unlock(&g_lock);
}

/*
 * One-shot capture, independent of whatever the live stream is doing. Runs
 * on its own thread for the same reason enumeration does: opening a camera
 * and waiting for its first usable frame can take a noticeable moment, and
 * the KVM command thread must not be parked for it.
 *
 * Always captures at its own resolution (the operator's request, or the
 * camera's true maximum when none was given) rather than reusing whatever
 * the stream happens to be running at -- if the stream owns the device, it
 * is paused for the moment this takes and then restarted.
 */
static void *cam_snapshot_worker(void *arg)
{
    cam_thread_args_t *targs = (cam_thread_args_t*)arg;
    cam_dev_t dev;
    char path[CAM_DEVICE_PATH_MAX + 1];
    int width, height, quality, forceRaw, attempts, deviceIndex;
    int wasStreaming;
    pthread_t oldThread = (pthread_t)0;
    uint64_t started;

    free(targs);

    pthread_mutex_lock(&g_lock);
    if (!g_consent)
    {
        /* Consent was withdrawn between the request and this thread starting. */
        g_snapshotPending = 0;
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    wasStreaming = !g_shutdown;
    if (wasStreaming)
    {
        g_shutdown = 1;
        g_snapshotPausedStream = 1;
        oldThread = g_thread;
        g_thread = (pthread_t)0;
    }

    deviceIndex = g_pendingSnapDeviceIndex;
    if (deviceIndex >= 0 && deviceIndex < g_deviceCount)
    {
        strncpy(path, g_devicePaths[deviceIndex], sizeof(path) - 1);
    }
    else
    {
        strncpy(path, g_currentPath, sizeof(path) - 1);
    }
    path[sizeof(path) - 1] = '\0';
    width = g_pendingSnapWidth;
    height = g_pendingSnapHeight;
    quality = g_snapshotQuality;
    forceRaw = g_forceRaw;
    pthread_mutex_unlock(&g_lock);

    /* Join outside the lock: capture_thread() takes it on every frame. */
    if (oldThread != (pthread_t)0) { pthread_join(oldThread, NULL); }

    if (path[0] == '\0') { strncpy(path, "/dev/video0", sizeof(path) - 1); path[sizeof(path) - 1] = '\0'; }

    /* 0x0 means "the camera's best": resolve its true maximum via
     * VIDIOC_ENUM_FRAMESIZES rather than falling back to CAM_DEFAULT_*,
     * which is what used to make a snapshot silently inherit whatever
     * (often lower) resolution the stream happened to be running at. */
    if (width <= 0 || height <= 0)
    {
        if (cam_find_max_resolution(path, V4L2_PIX_FMT_MJPEG, &width, &height) != 0 &&
            cam_find_max_resolution(path, V4L2_PIX_FMT_YUYV, &width, &height) != 0 &&
            cam_find_max_resolution(path, V4L2_PIX_FMT_UYVY, &width, &height) != 0 &&
            cam_find_max_resolution(path, V4L2_PIX_FMT_NV12, &width, &height) != 0)
        {
            width = CAM_DEFAULT_WIDTH;
            height = CAM_DEFAULT_HEIGHT;
        }
    }

    started = now_ms();
    if (cam_dev_open(&dev, path, width, height, CAM_DEFAULT_FPS, forceRaw) != 0)
    {
        cam_snapshot_finish(wasStreaming);
        return NULL;
    }

    /* Cameras routinely hand back a few dark or half-exposed frames while auto
     * exposure and white balance settle, so take a short run and keep the last
     * one rather than shipping the first thing that arrives. */
    for (attempts = 0; attempts < 8; attempts++)
    {
        struct v4l2_buffer buf;
        unsigned char *data = NULL;
        size_t len = 0;
        int r = cam_dev_grab(&dev, &buf, &data, &len);

        if (r < 0) { break; }
        if (r > 0) { continue; }
        if (data == NULL || len == 0) { cam_dev_release(&dev, &buf); continue; }

        if (attempts < 3) { cam_dev_release(&dev, &buf); continue; }

        pthread_mutex_lock(&g_lock);
        if (!g_consent) { pthread_mutex_unlock(&g_lock); cam_dev_release(&dev, &buf); break; }
        pthread_mutex_unlock(&g_lock);

        if (dev.isMjpeg)
        {
            send_snapshot(data, (unsigned long)len, dev.width, dev.height, 1, (unsigned int)(now_ms() - started));
        }
        else
        {
            unsigned long jlen = 0;
            unsigned char *jpeg;
            unsigned char *rgb = (unsigned char*)malloc((size_t)dev.width * (size_t)dev.height * 3);
            if (rgb != NULL)
            {
                raw_to_rgb(dev.pixfmt, data, rgb, dev.width, dev.height);
                jpeg = encode_rgb_jpeg(rgb, dev.width, dev.height, quality, &jlen);
                if (jpeg != NULL)
                {
                    send_snapshot(jpeg, jlen, dev.width, dev.height, 0, (unsigned int)(now_ms() - started));
                    tjFree(jpeg);
                }
                free(rgb);
            }
        }
        cam_dev_release(&dev, &buf);
        break;
    }

    cam_dev_close(&dev);
    cam_snapshot_finish(wasStreaming);
    return NULL;
}

void kvm_cam_snapshot(const unsigned char *frame, int size, ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    int skipConsentPrompt = 0;
    int needConsentPrompt;
    int haveRequest = (frame != NULL && size >= 12);
    int reqWidth = 0, reqHeight = 0, reqQuality = 0, reqDeviceIndex = -1;
    cam_thread_args_t *targs;
    pthread_t t;

    if (haveRequest)
    {
        reqWidth = (frame[4] << 8) | frame[5];
        reqHeight = (frame[6] << 8) | frame[7];
        reqQuality = frame[8];
        reqDeviceIndex = frame[9];
        skipConsentPrompt = (frame[10] & 0x02) ? 1 : 0;
    }

    pthread_mutex_lock(&g_lock);

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
        pthread_mutex_unlock(&g_lock);
        if (needConsentPrompt) { notify_js_consent_needed(skipConsentPrompt); }
        return;
    }

    if (g_snapshotPending) { pthread_mutex_unlock(&g_lock); return; }   /* coalesce rapid clicks */
    g_snapshotPending = 1;
    pthread_mutex_unlock(&g_lock);

    /* Always its own capture -- see cam_snapshot_worker(), which pauses and
     * resumes a live stream around it rather than diverting one of the
     * stream's own frames, so a still lands at the resolution actually
     * asked for even while a lower-resolution stream is running. */
    targs = (cam_thread_args_t*)malloc(sizeof(cam_thread_args_t));
    if (targs == NULL)
    {
        pthread_mutex_lock(&g_lock);
        g_snapshotPending = 0;
        pthread_mutex_unlock(&g_lock);
        return;
    }
    targs->writeHandler = writeHandler;
    targs->reserved = reserved;

    if (pthread_create(&t, NULL, cam_snapshot_worker, targs) != 0)
    {
        free(targs);
        pthread_mutex_lock(&g_lock);
        g_snapshotPending = 0;
        pthread_mutex_unlock(&g_lock);
        return;
    }
    pthread_detach(t);
}

/*
 * kvm_cam_consent_granted - the local user just said yes to a prompt this
 * module raised itself. Acts on exactly what g_pendingAction records was
 * actually being asked for -- MNG_CAM_CONSENT carries no payload of its own
 * to say which, so native has to remember. A snapshot fires before a start
 * so a Snapshot-while-stream-is-off click never gets upgraded into a stream
 * the operator never asked for.
 */
void kvm_cam_consent_granted(void)
{
    int action;
    unsigned char startFrame[CAM_START_FRAME_LEN];
    int startFrameLen;

    pthread_mutex_lock(&g_lock);
    action = g_pendingAction;
    g_pendingAction = 0;
    startFrameLen = g_pendingStartFrameLen;
    if (startFrameLen > 0) { memcpy(startFrame, g_pendingStartFrame, (size_t)startFrameLen); }
    g_pendingStartFrameLen = 0;
    pthread_mutex_unlock(&g_lock);

    if (action & CAM_PENDING_SNAPSHOT) { kvm_cam_snapshot(NULL, 0, g_writeHandler, g_reserved); }
    if ((action & CAM_PENDING_START) || action == 0)
    {
        kvm_cam_start(startFrameLen > 0 ? startFrame : NULL, startFrameLen);
    }
}

void kvm_cam_stop(void)
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
    g_snapshotPending = 0;
    g_pendingAction = 0;
    g_pendingStartFrameLen = 0;
    thread = g_thread;
    g_thread = (pthread_t)0;
    pthread_mutex_unlock(&g_lock);

    if (thread != (pthread_t)0) { pthread_join(thread, NULL); }
    g_seq = 0;

    pthread_mutex_lock(&g_lock);
    g_passthroughActive = 0;
    reset_scene_state();
    pthread_mutex_unlock(&g_lock);

    /* Take down that stale prompt before reporting the new state. */
    if (wasAwaitingConsent) { notify_js(MNG_CAM_CONSENT_CANCEL); }
    send_caps(g_writeHandler, g_reserved);
}

void kvm_cam_feed(char *buffer, int bufferLen)
{
    /* Video only travels device -> browser; anything inbound is discarded so
     * the KVM command switch can stay symmetrical with the audio paths. */
    (void)buffer;
    (void)bufferLen;
}

void kvm_cam_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved)
{
    send_caps(writeHandler, reserved);
}

void kvm_cam_cleanup(void)
{
    pthread_t thread;

    pthread_mutex_lock(&g_lock);
    g_shutdown = 1;
    g_consent = 0;
    g_promptOutstanding = 0;
    g_snapshotPending = 0;
    g_pendingAction = 0;
    g_pendingStartFrameLen = 0;
    thread = g_thread;
    g_thread = (pthread_t)0;
    pthread_mutex_unlock(&g_lock);

    if (thread != (pthread_t)0) { pthread_join(thread, NULL); }

    pthread_mutex_lock(&g_lock);
    reset_scene_state();
    g_deviceCount = 0;
    g_passthroughActive = 0;
    g_initialised = 0;
    g_writeHandler = NULL;
    g_reserved = NULL;
    pthread_mutex_unlock(&g_lock);
}

#endif /* _KVM_CAMERA */
