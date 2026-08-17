/*
Copyright 2010 - 2011 Intel Corporation

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

#include "linux_kvm_drm.h"
#include "linux_kvm_drm_egl.h"
#include "linux_kvm.h"
#include "linux_kvm_rotated.h"
#include "linux_kvm_wayland.h"
#include "linux_compression.h"
#include "linux_tile.h"
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <poll.h>
#include <fcntl.h>

#if defined(__linux__)
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <drm_fourcc.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#include <wayland-client.h>

// libdrm is dlopen'd rather than linked, so the agent still runs where it's absent (like libX11).
#define KVM_DRM_LIBDRM_SYMBOLS(_) \
	_(drmModeGetResources) _(drmModeFreeResources) \
	_(drmModeGetConnector) _(drmModeFreeConnector) \
	_(drmModeGetEncoder) _(drmModeFreeEncoder) \
	_(drmModeGetCrtc) _(drmModeFreeCrtc) \
	_(drmModeGetPlane) _(drmModeFreePlane) \
	_(drmModeGetPlaneResources) _(drmModeFreePlaneResources) \
	_(drmModeGetFB) _(drmModeFreeFB) \
	_(drmModeGetFB2) _(drmModeFreeFB2) \
	_(drmIoctl) _(drmPrimeHandleToFD) _(drmDropMaster) _(drmGetRenderDeviceNameFromFd) \
	_(drmModeObjectGetProperties) _(drmModeFreeObjectProperties) \
	_(drmModeGetProperty) _(drmModeFreeProperty) _(drmSetClientCap)

#define KVM_DRM_DECL_PTR(s) static __typeof__(s) *p_##s = NULL;
KVM_DRM_LIBDRM_SYMBOLS(KVM_DRM_DECL_PTR)
#undef KVM_DRM_DECL_PTR

static void *g_libdrm_handle = NULL;
static int kvm_drm_load_libdrm(void)
{
	void *h;
	if (g_libdrm_handle != NULL) { return 1; }
	if ((h = dlopen("libdrm.so.2", RTLD_NOW)) == NULL && (h = dlopen("libdrm.so", RTLD_NOW)) == NULL)
	{
		return 0;
	}
#define KVM_DRM_LOAD_PTR(s) p_##s = (__typeof__(p_##s))dlsym(h, #s); if (p_##s == NULL) { dlclose(h); return 0; }
	KVM_DRM_LIBDRM_SYMBOLS(KVM_DRM_LOAD_PTR)
#undef KVM_DRM_LOAD_PTR
	g_libdrm_handle = h;
	return 1;
}

// Must follow the __typeof__ declarations above (they need the real prototypes).
#define drmModeGetResources p_drmModeGetResources
#define drmModeFreeResources p_drmModeFreeResources
#define drmModeGetConnector p_drmModeGetConnector
#define drmModeFreeConnector p_drmModeFreeConnector
#define drmModeGetEncoder p_drmModeGetEncoder
#define drmModeFreeEncoder p_drmModeFreeEncoder
#define drmModeGetCrtc p_drmModeGetCrtc
#define drmModeFreeCrtc p_drmModeFreeCrtc
#define drmModeGetPlane p_drmModeGetPlane
#define drmModeFreePlane p_drmModeFreePlane
#define drmModeGetPlaneResources p_drmModeGetPlaneResources
#define drmModeFreePlaneResources p_drmModeFreePlaneResources
#define drmModeGetFB p_drmModeGetFB
#define drmModeFreeFB p_drmModeFreeFB
#define drmModeGetFB2 p_drmModeGetFB2
#define drmModeFreeFB2 p_drmModeFreeFB2
#define drmIoctl p_drmIoctl
#define drmPrimeHandleToFD p_drmPrimeHandleToFD
#define drmDropMaster p_drmDropMaster
#define drmGetRenderDeviceNameFromFd p_drmGetRenderDeviceNameFromFd
#define drmModeObjectGetProperties p_drmModeObjectGetProperties
#define drmModeFreeObjectProperties p_drmModeFreeObjectProperties
#define drmModeGetProperty p_drmModeGetProperty
#define drmModeFreeProperty p_drmModeFreeProperty
#define drmSetClientCap p_drmSetClientCap

// Old sysroots may predate these in drm.h/drm_mode.h; the values are kernel ABI.
#ifndef DRM_CLIENT_CAP_UNIVERSAL_PLANES
#define DRM_CLIENT_CAP_UNIVERSAL_PLANES 2
#endif
#ifndef DRM_MODE_ROTATE_0
#define DRM_MODE_ROTATE_0   (1<<0)
#define DRM_MODE_ROTATE_90  (1<<1)
#define DRM_MODE_ROTATE_180 (1<<2)
#define DRM_MODE_ROTATE_270 (1<<3)
#endif
#ifndef DRM_MODE_REFLECT_X
#define DRM_MODE_REFLECT_X  (1<<4)
#define DRM_MODE_REFLECT_Y  (1<<5)
#endif
#ifndef DRM_PLANE_TYPE_PRIMARY
#define DRM_PLANE_TYPE_PRIMARY 1
#endif

// Lets linux_kvm_drm_egl.c reach libdrm through the single dlopen here.
int kvm_drm_prime_handle_to_fd(int fd, unsigned int handle, unsigned int flags, int *prime_fd)
{
	return drmPrimeHandleToFD(fd, (uint32_t)handle, (uint32_t)flags, prime_fd);
}

// Render-node path for a card fd, so the EGL layer can match an EGL device that only reports its
// render node (e.g. NVIDIA). Returns 0 if unavailable.
int kvm_drm_render_node_for_fd(int fd, char *out, size_t out_len)
{
	char *name = drmGetRenderDeviceNameFromFd(fd);
	if (name == NULL) { return 0; }
	snprintf(out, out_len, "%s", name);
	free(name);
	return 1;
}

// libwayland-client is dlopen'd rather than linked, so the agent runs where it's absent. It's
// used only for the xdg-output layout query, which falls back to KWin/raw DRM positions.
// Array marshallers instead of wl_proxy_marshal_flags: flags needs libwayland >= 1.20 (2021),
// which would silently lose the xdg-output layout on Debian 11 / Ubuntu 20.04-era systems.
#define KVM_DRM_WAYLAND_SYMBOLS(_) \
	_(wl_display_connect) _(wl_display_disconnect) \
	_(wl_display_flush) _(wl_display_dispatch_pending) _(wl_display_prepare_read) \
	_(wl_display_read_events) _(wl_display_cancel_read) _(wl_display_get_fd) \
	_(wl_proxy_marshal_array) _(wl_proxy_marshal_array_constructor) _(wl_proxy_marshal_array_constructor_versioned) \
	_(wl_proxy_add_listener) _(wl_proxy_destroy)

#define KVM_DRM_WL_DECL_PTR(s) static __typeof__(s) *p_##s = NULL;
KVM_DRM_WAYLAND_SYMBOLS(KVM_DRM_WL_DECL_PTR)
#undef KVM_DRM_WL_DECL_PTR

static const struct wl_interface *p_wl_registry_interface = NULL;
static const struct wl_interface *p_wl_output_interface = NULL;
static const struct wl_interface *p_wl_callback_interface = NULL;
static void *g_libwayland_handle = NULL;

#define wl_display_connect p_wl_display_connect
#define wl_display_disconnect p_wl_display_disconnect
#define wl_display_flush p_wl_display_flush
#define wl_display_dispatch_pending p_wl_display_dispatch_pending
#define wl_display_prepare_read p_wl_display_prepare_read
#define wl_display_read_events p_wl_display_read_events
#define wl_display_cancel_read p_wl_display_cancel_read
#define wl_display_get_fd p_wl_display_get_fd
#define wl_proxy_marshal_array p_wl_proxy_marshal_array
#define wl_proxy_marshal_array_constructor p_wl_proxy_marshal_array_constructor
#define wl_proxy_marshal_array_constructor_versioned p_wl_proxy_marshal_array_constructor_versioned
#define wl_proxy_add_listener p_wl_proxy_add_listener
#define wl_proxy_destroy p_wl_proxy_destroy

// Hand-rolled versions of the <wayland-client-protocol.h> inline wrappers; the originals bake in
// link-time wl_proxy_*/wl_registry_interface references that would keep libwayland in NEEDED.
static struct wl_registry *kvm_wl_display_get_registry(struct wl_display *display)
{
	union wl_argument args[1];
	args[0].o = NULL;
	return (struct wl_registry *)wl_proxy_marshal_array_constructor((struct wl_proxy *)display,
		1 /*WL_DISPLAY_GET_REGISTRY*/, args, p_wl_registry_interface);
}
static int kvm_wl_registry_add_listener(struct wl_registry *registry, const struct wl_registry_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *)registry, (void (**)(void))listener, data);
}
static void *kvm_wl_registry_bind(struct wl_registry *registry, uint32_t name, const struct wl_interface *interface, uint32_t version)
{
	union wl_argument args[4];
	args[0].u = name;
	args[1].s = interface->name;
	args[2].u = version;
	args[3].o = NULL;
	return (void *)wl_proxy_marshal_array_constructor_versioned((struct wl_proxy *)registry,
		0 /*WL_REGISTRY_BIND*/, args, interface, version);
}
static int kvm_wl_output_add_listener(struct wl_output *output, const struct wl_output_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *)output, (void (**)(void))listener, data);
}

static const struct wl_interface *kvm_xdg_output_types[]; // defined below; slot [3] patched at load
static int kvm_drm_load_wayland(void)
{
	void *h;
	if (g_libwayland_handle != NULL) { return 1; }
	if ((h = dlopen("libwayland-client.so.0", RTLD_NOW)) == NULL && (h = dlopen("libwayland-client.so", RTLD_NOW)) == NULL)
	{
		return 0;
	}
#define KVM_DRM_WL_LOAD_PTR(s) p_##s = (__typeof__(p_##s))dlsym(h, #s); if (p_##s == NULL) { dlclose(h); return 0; }
	KVM_DRM_WAYLAND_SYMBOLS(KVM_DRM_WL_LOAD_PTR)
#undef KVM_DRM_WL_LOAD_PTR
	p_wl_registry_interface = (const struct wl_interface *)dlsym(h, "wl_registry_interface");
	p_wl_output_interface = (const struct wl_interface *)dlsym(h, "wl_output_interface");
	p_wl_callback_interface = (const struct wl_interface *)dlsym(h, "wl_callback_interface");
	if (p_wl_registry_interface == NULL || p_wl_output_interface == NULL || p_wl_callback_interface == NULL) { dlclose(h); return 0; }
	kvm_xdg_output_types[3] = p_wl_output_interface; // get_xdg_output's wl_output arg type
	g_libwayland_handle = h;
	return 1;
}

#ifndef O_CLOEXEC
#define KVM_DRM_O_CLOEXEC 0
#else
#define KVM_DRM_O_CLOEXEC O_CLOEXEC
#endif
#endif

#define KVM_DRM_MAX_ERROR 256
#define KVM_DRM_MAX_OUTPUTS 16
#define KVM_DRM_DISPLAY_WAKE_TIMEOUT_MS 10000

int g_kvmBackendDRM = 0;
static int drm_debug = 0;

static void kvm_drm_init_debug()
{
	const char *value = getenv("MESH_KVM_DRM_DEBUG");
	if (value == NULL || value[0] == 0)
	{
		drm_debug = 0;
		return;
	}
	drm_debug = atoi(value);
	if (drm_debug < 0) { drm_debug = 0; }
}

extern int SCREEN_NUM;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_DEPTH;
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;
extern int COMPRESSION_RATIO;
extern int FRAME_RATE_TIMER;
extern struct tileInfo_t **g_tileInfo;
extern int g_remotepause;
extern int g_pause;
extern int g_shutdown;
extern int change_display;
extern int master2slave[2];
extern int slave2master[2];
extern int CURRENT_DISPLAY_ID;
extern int g_enableEvents;
extern void *tilebuffer;
extern unsigned char *jpeg_buffer;
extern int jpeg_buffer_length;

extern void kvm_send_error(char *msg);
extern void kvm_send_resolution();
extern void kvm_send_display();
extern void kvm_send_display_list();
extern int kvm_server_inputdata(char *block, int blocklen);
extern void kvm_server_sighandler(int signum, siginfo_t *info, void *context);

// Viewer input read off master2slave but not yet parsed. Parsing only happens between outbound
// packets (kvm_drm_process_pending_input): input handlers reply via kvm_send_* onto the same pipe,
// which would interleave into a half-written tile if run from inside kvm_drm_write_all.
static char g_drmInputBuf[262144];
static int g_drmInputLen = 0;

// Write one whole packet to the (non-blocking) slave->master pipe, draining viewer input while
// stalled. Under tunnel backpressure the master deliberately stops reading this pipe; a plain
// blocking write() here then also stopped our master2slave reads, the master's event thread
// blocked writing input into that second full pipe, and with the event loop dead the resume that
// would drain everything could never arrive: both processes deadlocked until killed. Keeping the
// input pipe drained while we wait keeps the master's event loop alive, so backpressure stays
// what it is meant to be - a stall, not a hang.
static int kvm_drm_write_all(int fd, const char *buffer, size_t len)
{
	size_t offset = 0;

	while (offset < len)
	{
		struct pollfd pfd[2];
		nfds_t nfds = 1;
		int inputSlot = -1;

		if (g_shutdown) { return -1; }

		pfd[0].fd = fd;
		pfd[0].events = POLLOUT;
		pfd[0].revents = 0;
		if (master2slave[0] > 0)
		{
			if (g_drmInputLen >= (int)sizeof(g_drmInputBuf))
			{
				// Only reachable if the viewer streams input for minutes into one stalled write.
				// Give up so the parent restarts the session instead of re-arming the deadlock.
				return -1;
			}
			inputSlot = (int)nfds;
			pfd[nfds].fd = master2slave[0];
			pfd[nfds].events = POLLIN;
			pfd[nfds].revents = 0;
			nfds++;
		}

		if (poll(pfd, nfds, 1000) < 0)
		{
			if (errno == EINTR) { continue; }	// SIGTERM lands here; g_shutdown is re-checked above
			return -1;
		}

		if (inputSlot >= 0 && (pfd[inputSlot].revents & (POLLIN | POLLHUP | POLLERR)) != 0)
		{
			ssize_t rd = read(master2slave[0], g_drmInputBuf + g_drmInputLen, sizeof(g_drmInputBuf) - (size_t)g_drmInputLen);
			if (rd > 0)
			{
				g_drmInputLen += (int)rd;
			}
			else if (rd == 0)
			{
				g_shutdown = 1;	// master closed its end: the session is going away
				return -1;
			}
			else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			{
				g_shutdown = 1;
				return -1;
			}
		}

		if ((pfd[0].revents & (POLLERR | POLLNVAL)) != 0) { return -1; }
		if ((pfd[0].revents & POLLOUT) != 0)
		{
			ssize_t written = write(fd, buffer + offset, len - offset);
			if (written < 0)
			{
				if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
				return -1;
			}
			offset += (size_t)written;
		}
	}
	return 0;
}

// Entry point for the shared kvm_send_* helpers in linux_kvm.c: in DRM mode every write to the
// pipe must take the draining path above, both for the deadlock and because the pipe is left
// non-blocking for the slave's lifetime (a raw write() could truncate and desync the stream).
int kvm_drm_slave_write(const void *buffer, size_t len)
{
	return kvm_drm_write_all(slave2master[1], (const char *)buffer, len);
}

// Parse whatever complete input messages have accumulated. A handler's kvm_send_* reply re-enters
// the drain in kvm_drm_write_all and can grow g_drmInputLen mid-loop; appends land beyond
// 'consumed', so re-reading g_drmInputLen each pass stays correct and leftovers keep any partial
// trailing message intact for the next read to complete.
static void kvm_drm_process_pending_input(void)
{
	int consumed = 0;
	int msgLen = 0;

	while ((msgLen = kvm_server_inputdata(g_drmInputBuf + consumed, g_drmInputLen - consumed)) != 0)
	{
		consumed += msgLen;
	}
	if (consumed > 0)
	{
		if (consumed < g_drmInputLen)
		{
			memmove(g_drmInputBuf, g_drmInputBuf + consumed, (size_t)(g_drmInputLen - consumed));
		}
		g_drmInputLen -= consumed;
	}
}

static int kvm_drm_send_dirty_tiles(const unsigned char *rgbBuffer, size_t rgbSize, char **desktopBuffer, long long *desktopBufferSize)
{
	int r = 0;
	int c = 0;
	int x = 0;
	int y = 0;
	int width = 0;
	int height = 0;
	int paddedWidth = 0;
	int paddedHeight = 0;
	size_t rowBytes = 0;
	size_t rowPaddedBytes = 0;
	size_t requiredSize = 0;

	if (SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0 || TILE_WIDTH_COUNT <= 0 || TILE_HEIGHT_COUNT <= 0)
	{
		return 0;
	}

	rowBytes = ((size_t)SCREEN_WIDTH) * 3u;
	requiredSize = ((size_t)SCREEN_WIDTH) * ((size_t)SCREEN_HEIGHT) * 3u;
	if (rgbBuffer == NULL || rgbSize < requiredSize)
	{
		return -1;
	}

	paddedWidth = adjust_screen_size(SCREEN_WIDTH);
	paddedHeight = adjust_screen_size(SCREEN_HEIGHT);
	rowPaddedBytes = ((size_t)paddedWidth) * 3u;
	requiredSize = ((size_t)paddedWidth) * ((size_t)paddedHeight) * 3u;

	if (*desktopBufferSize != (long long)requiredSize)
	{
		char *tmp = NULL;
		if (*desktopBuffer != NULL)
		{
			free(*desktopBuffer);
			*desktopBuffer = NULL;
		}
		tmp = (char *)malloc(requiredSize);
		if (tmp == NULL) ILIBCRITICALEXIT(254);
		*desktopBuffer = tmp;
		*desktopBufferSize = (long long)requiredSize;
	}

	for (y = 0; y < SCREEN_HEIGHT; ++y)
	{
		char *dst = *desktopBuffer + (((size_t)y) * rowPaddedBytes);
		const char *src = (const char *)rgbBuffer + (((size_t)y) * rowBytes);
		memcpy_s(dst, rowPaddedBytes, src, rowBytes);
		if (rowPaddedBytes > rowBytes)
		{
			memset(dst + rowBytes, 0, rowPaddedBytes - rowBytes);
		}
	}

	if (paddedHeight > SCREEN_HEIGHT)
	{
		char *dst = *desktopBuffer + (((size_t)SCREEN_HEIGHT) * rowPaddedBytes);
		size_t bytes = ((size_t)(paddedHeight - SCREEN_HEIGHT)) * rowPaddedBytes;
		memset(dst, 0, bytes);
	}

	for (r = 0; r < TILE_HEIGHT_COUNT; ++r)
	{
		for (c = 0; c < TILE_WIDTH_COUNT; ++c)
		{
			g_tileInfo[r][c].flag = TILE_TODO;
#ifdef KVM_ALL_TILES
			g_tileInfo[r][c].crc = 0xFF;
#endif
		}
	}

	for (y = 0; y < TILE_HEIGHT_COUNT; ++y)
	{
		for (x = 0; x < TILE_WIDTH_COUNT; ++x)
		{
			void *tilePacket = NULL;
			long long tilePacketSize = 0;

			height = TILE_HEIGHT * y;
			width = TILE_WIDTH * x;

			if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND)
			{
				continue;
			}

			getTileAt(width, height, &tilePacket, &tilePacketSize, *desktopBuffer, *desktopBufferSize, y, x);
			if (tilePacket != NULL && tilePacketSize > 0)
			{
				if (kvm_drm_write_all(slave2master[1], (char *)tilePacket, (size_t)tilePacketSize) != 0)
				{
					free(tilePacket);
					return -1;
				}
				free(tilePacket);
			}
		}
	}

	return 0;
}

#if defined(__linux__)

typedef struct kvm_drm_output
{
	char device_path[64];
	char connector_name[32];
	uint32_t connector_id;
	uint32_t crtc_id;
	int crtc_index;
	int x;
	int y;
	uint32_t width;
	uint32_t height;
	int device_index;
	// Un-rotation that maps the panel-native scanout buffer back into this output's logical
	// orientation (from the wl_output transform); width/height above stay logical.
	kvm_drm_rotation rotation;
} kvm_drm_output;

typedef struct kvm_drm_desktop_layout
{
	int min_x;
	int min_y;
	int max_x;
	int max_y;
	uint32_t width;
	uint32_t height;
} kvm_drm_desktop_layout;

typedef struct kvm_drm_frame_map
{
	uint32_t handle;
	uint8_t *addr;
	size_t size;
	int dma_fd;
	int drm_fd;
} kvm_drm_frame_map;

#define KVM_DRM_MAX_DEVICES 8

// One open GPU. A multi-GPU desktop spans several of these; every output carries the
// device_index it belongs to. EGL and the CPU-readback map are per-device because a card's
// scanout buffers can only be imported/mapped through that same card's fd.
typedef struct kvm_drm_device
{
	int fd;
	char path[64];
	kvm_drm_egl_context eglCtx;
	kvm_drm_frame_map map;
} kvm_drm_device;

typedef struct kvm_drm_scanout_frame
{
	uint32_t fb_id;
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t offset;
	uint32_t format;
	uint32_t handle;
	uint64_t modifier;
	kvm_drm_rotation rotation;
	// Extra planes for render-compressed scanout (e.g. Intel Y-tiled CCS = data plane + metadata
	// plane). plane[0] mirrors handle/pitch/offset above; the GPU/EGL path imports every plane so
	// the driver decompresses during the blit. The CPU/linear path only ever sees plane_count==1.
	int plane_count;
	uint32_t plane_handles[4];
	uint32_t plane_pitches[4];
	uint32_t plane_offsets[4];
} kvm_drm_scanout_frame;

static uint32_t kvm_drm_get_plane_fb_id(int fd, uint32_t crtc_id, int crtc_index);
static uint32_t kvm_drm_get_scanout_fb_id(int fd, uint32_t crtc_id, int crtc_index, bool *out_have_crtc, bool *out_used_plane_fb);

static void kvm_drm_copy_error_message(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0)
	{
		return;
	}
	if (src == NULL)
	{
		dst[0] = 0;
		return;
	}

	size_t n = strnlen_s(src, dst_size - 1);
	memcpy_s(dst, dst_size, src, n);
	dst[n] = 0;
}

static void kvm_drm_format_fourcc(char *dst, size_t dst_size, uint32_t format)
{
	char code[5];
	int i;

	if (dst == NULL || dst_size == 0)
	{
		return;
	}

	for (i = 0; i < 4; ++i)
	{
		unsigned char ch = (unsigned char)((format >> (i * 8)) & 0xFFu);
		code[i] = (char)((ch >= 32 && ch <= 126) ? ch : '.');
	}
	code[4] = 0;
	snprintf(dst, dst_size, "%s/0x%08X", code, format);
}

static void kvm_drm_debug_log_scanout_frame(const char *prefix, const kvm_drm_scanout_frame *frame)
{
	char format[32];

	if (!drm_debug || frame == NULL)
	{
		return;
	}

	kvm_drm_format_fourcc(format, sizeof(format), frame->format);
	fprintf(stderr,
		"DRM: %s fb_id=%u size=%ux%u pitch=%u offset=%u format=%s modifier=0x%016" PRIx64 " handle=%u rotation=%s\n",
		(prefix != NULL) ? prefix : "scanout",
		frame->fb_id,
		frame->width,
		frame->height,
		frame->pitch,
		frame->offset,
		format,
		frame->modifier,
		frame->handle,
		kvm_drm_rotation_name(frame->rotation));
}

static void kvm_drm_close_gem_handle(int fd, uint32_t handle)
{
	struct drm_gem_close closeReq;

	if (fd < 0 || handle == 0)
	{
		return;
	}

	memset(&closeReq, 0, sizeof(closeReq));
	closeReq.handle = handle;
	if (drmIoctl(fd, DRM_IOCTL_GEM_CLOSE, &closeReq) != 0 && drm_debug)
	{
		fprintf(stderr, "DRM: DRM_IOCTL_GEM_CLOSE failed for handle=%u (errno=%d)\n", handle, errno);
	}
}

// Close each unique plane handle once (CCS data + metadata can share one GEM handle). Every
// drmModeGetFB/GetFB2 call creates fresh handle references that pin the underlying BO until
// closed; drmModeFreeFB/FreeFB2 only free the struct.
static void kvm_drm_close_frame_handles(int fd, kvm_drm_scanout_frame *frame)
{
	int pi, pj;
	for (pi = 0; pi < frame->plane_count && pi < 4; ++pi)
	{
		uint32_t h = frame->plane_handles[pi];
		int dup = 0;
		if (h == 0) { continue; }
		for (pj = 0; pj < pi; ++pj) { if (frame->plane_handles[pj] == h) { dup = 1; break; } }
		if (!dup) { kvm_drm_close_gem_handle(fd, h); }
	}
	for (pi = 0; pi < frame->plane_count && pi < 4; ++pi) { frame->plane_handles[pi] = 0; }
	frame->handle = 0;
}

static void kvm_drm_reset_logged_scanout_state(uint32_t *lastLoggedFbId,
	uint32_t *lastLoggedWidth,
	uint32_t *lastLoggedHeight,
	uint32_t *lastLoggedPitch,
	uint32_t *lastLoggedOffset,
	uint32_t *lastLoggedFormat,
	uint32_t *lastLoggedHandle,
	uint64_t *lastLoggedModifier,
	int *lastLoggedPath)
{
	if (lastLoggedFbId != NULL) { *lastLoggedFbId = 0; }
	if (lastLoggedWidth != NULL) { *lastLoggedWidth = 0; }
	if (lastLoggedHeight != NULL) { *lastLoggedHeight = 0; }
	if (lastLoggedPitch != NULL) { *lastLoggedPitch = 0; }
	if (lastLoggedOffset != NULL) { *lastLoggedOffset = 0; }
	if (lastLoggedFormat != NULL) { *lastLoggedFormat = 0; }
	if (lastLoggedHandle != NULL) { *lastLoggedHandle = 0; }
	if (lastLoggedModifier != NULL) { *lastLoggedModifier = UINT64_MAX; }
	if (lastLoggedPath != NULL) { *lastLoggedPath = -1; }
}

static bool kvm_drm_is_transient_scanout_error(const char *err)
{
	if (err == NULL)
	{
		return false;
	}

	return strcmp(err, "Active CRTC has no framebuffer") == 0 ||
		strcmp(err, "drmModeGetCrtc failed") == 0;
}

static bool kvm_drm_is_expected_suspended_refresh_error(const char *err)
{
	static const char *noOutputPrefix = "No connected display with active CRTC on ";

	if (err == NULL)
	{
		return false;
	}

	return strcmp(err, "No active DRM framebuffer available yet") == 0 ||
		strncmp(err, noOutputPrefix, strlen(noOutputPrefix)) == 0;
}

static const char *kvm_drm_connector_type_name(uint32_t t)
{
	switch (t)
	{
	case DRM_MODE_CONNECTOR_Unknown:
		return "Unknown";
	case DRM_MODE_CONNECTOR_VGA:
		return "VGA";
	case DRM_MODE_CONNECTOR_DVII:
		return "DVI-I";
	case DRM_MODE_CONNECTOR_DVID:
		return "DVI-D";
	case DRM_MODE_CONNECTOR_DVIA:
		return "DVI-A";
	case DRM_MODE_CONNECTOR_Composite:
		return "Composite";
	case DRM_MODE_CONNECTOR_SVIDEO:
		return "SVIDEO";
	case DRM_MODE_CONNECTOR_LVDS:
		return "LVDS";
	case DRM_MODE_CONNECTOR_Component:
		return "Component";
	case DRM_MODE_CONNECTOR_9PinDIN:
		return "DIN";
	case DRM_MODE_CONNECTOR_DisplayPort:
		return "DP";
	case DRM_MODE_CONNECTOR_HDMIA:
		return "HDMI-A";
	case DRM_MODE_CONNECTOR_HDMIB:
		return "HDMI-B";
	case DRM_MODE_CONNECTOR_TV:
		return "TV";
	case DRM_MODE_CONNECTOR_eDP:
		return "eDP";
	case DRM_MODE_CONNECTOR_VIRTUAL:
		return "Virtual";
	case DRM_MODE_CONNECTOR_DSI:
		return "DSI";
	default:
		return "Connector";
	}
}

static void kvm_drm_destroy_map(kvm_drm_frame_map *map)
{
	if (map->addr != NULL && map->size > 0)
	{
		munmap(map->addr, map->size);
	}
	if (map->dma_fd >= 0)
	{
		close(map->dma_fd);
	}
	if (map->handle != 0)
	{
		kvm_drm_close_gem_handle(map->drm_fd, map->handle);
	}
	map->handle = 0;
	map->addr = NULL;
	map->size = 0;
	map->dma_fd = -1;
	map->drm_fd = -1;
}

static bool kvm_drm_map_framebuffer_handle(int fd, uint32_t handle, size_t min_size, kvm_drm_frame_map *map, char *out_error, size_t out_error_size)
{
	if (map->handle == handle && map->addr != NULL && map->size >= min_size)
	{
		return true;
	}

	kvm_drm_destroy_map(map);

	struct drm_mode_map_dumb map_dumb;
	memset(&map_dumb, 0, sizeof(map_dumb));
	map_dumb.handle = handle;
	if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map_dumb) == 0)
	{
		void *ptr = mmap(NULL, min_size, PROT_READ, MAP_SHARED, fd, map_dumb.offset);
		if (ptr != MAP_FAILED)
		{
			map->handle = handle;
			map->addr = (uint8_t *)ptr;
			map->size = min_size;
			map->drm_fd = fd;
			return true;
		}
	}

	int dma_fd = -1;
	if (drmPrimeHandleToFD(fd, handle, DRM_CLOEXEC | DRM_RDWR, &dma_fd) == 0)
	{
		void *ptr = mmap(NULL, min_size, PROT_READ, MAP_SHARED, dma_fd, 0);
		if (ptr != MAP_FAILED)
		{
			map->handle = handle;
			map->addr = (uint8_t *)ptr;
			map->size = min_size;
			map->dma_fd = dma_fd;
			map->drm_fd = fd;
			return true;
		}
		close(dma_fd);
	}

	kvm_drm_copy_error_message(out_error, out_error_size,
							   "Failed to map scanout buffer (requires mappable dumb/linear buffer and DRM access)");
	return false;
}

static uint32_t kvm_drm_pick_crtc_for_connector(int fd, const drmModeRes *res, const drmModeConnector *conn)
{
	uint32_t crtc_id = 0;
	int i;
	if (conn->encoder_id != 0)
	{
		drmModeEncoder *enc = drmModeGetEncoder(fd, conn->encoder_id);
		if (enc != NULL)
		{
			crtc_id = enc->crtc_id;
			drmModeFreeEncoder(enc);
			if (crtc_id != 0)
			{
				for (i = 0; i < res->count_crtcs; ++i)
				{
					if (res->crtcs[i] == crtc_id)
					{
						return crtc_id;
					}
				}
			}
		}
	}

	for (i = 0; i < conn->count_encoders; ++i)
	{
		drmModeEncoder *enc = drmModeGetEncoder(fd, conn->encoders[i]);
		if (enc == NULL)
		{
			continue;
		}
		crtc_id = enc->crtc_id;
		drmModeFreeEncoder(enc);
		if (crtc_id != 0)
		{
			int j;
			for (j = 0; j < res->count_crtcs; ++j)
			{
				if (res->crtcs[j] == crtc_id)
				{
					return crtc_id;
				}
			}
		}
	}

	return 0;
}

static int kvm_drm_output_index_by_crtc(kvm_drm_output *outputs, int output_count, uint32_t crtc_id)
{
	int i;
	for (i = 0; i < output_count; ++i)
	{
		if (outputs[i].crtc_id == crtc_id)
		{
			return i;
		}
	}
	return -1;
}

static int kvm_drm_compare_outputs(const void *a, const void *b)
{
	const kvm_drm_output *oa = (const kvm_drm_output *)a;
	const kvm_drm_output *ob = (const kvm_drm_output *)b;
	if (oa->y != ob->y) { return oa->y < ob->y ? -1 : 1; }
	if (oa->x != ob->x) { return oa->x < ob->x ? -1 : 1; }
	if (oa->connector_id != ob->connector_id) { return oa->connector_id < ob->connector_id ? -1 : 1; }
	// connector_id is per-card, so two GPUs can collide; device_index keeps the sort stable.
	if (oa->device_index != ob->device_index) { return oa->device_index < ob->device_index ? -1 : 1; }
	return 0;
}

static bool kvm_drm_collect_active_outputs_on_fd(int fd, const char *path, kvm_drm_output *outputs, int max_outputs, int *out_count, bool require_scanout, bool logSelection, char *out_error, size_t out_error_size)
{
	drmModeRes *res = drmModeGetResources(fd);
	if (res == NULL)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "drmModeGetResources failed");
		return false;
	}

	int count = 0;
	int connected = 0;
	int i;
	for (i = 0; i < res->count_connectors && count < max_outputs; ++i)
	{
		drmModeConnector *conn = drmModeGetConnector(fd, res->connectors[i]);
		if (conn == NULL)
		{
			continue;
		}

		if (conn->connection != DRM_MODE_CONNECTED || conn->count_modes <= 0)
		{
			drmModeFreeConnector(conn);
			continue;
		}
		connected++;

		uint32_t crtc_id = kvm_drm_pick_crtc_for_connector(fd, res, conn);
		if (crtc_id == 0)
		{
			drmModeFreeConnector(conn);
			continue;
		}

		int c;
		int crtc_index = -1;
		for (c = 0; c < res->count_crtcs; ++c)
		{
			if (res->crtcs[c] == crtc_id)
			{
				crtc_index = c;
				break;
			}
		}
		if (crtc_index < 0 || kvm_drm_output_index_by_crtc(outputs, count, crtc_id) >= 0)
		{
			drmModeFreeConnector(conn);
			continue;
		}

		drmModeCrtc *crtc = drmModeGetCrtc(fd, crtc_id);
		if (crtc == NULL)
		{
			drmModeFreeConnector(conn);
			continue;
		}

		uint32_t fb_id = kvm_drm_get_scanout_fb_id(fd, crtc_id, crtc_index, NULL, NULL);
		if (require_scanout && fb_id == 0)
		{
			drmModeFreeCrtc(crtc);
			drmModeFreeConnector(conn);
			continue;
		}

		kvm_drm_output candidate;
		memset(&candidate, 0, sizeof(candidate));
		snprintf(candidate.device_path, sizeof(candidate.device_path), "%s", path);
		snprintf(candidate.connector_name, sizeof(candidate.connector_name), "%s-%u", kvm_drm_connector_type_name(conn->connector_type), conn->connector_type_id);
		candidate.connector_id = conn->connector_id;
		candidate.crtc_id = crtc_id;
		candidate.crtc_index = crtc_index;
		candidate.x = crtc->x;
		candidate.y = crtc->y;
		candidate.width = crtc->width;
		candidate.height = crtc->height;
		outputs[count++] = candidate;

		drmModeFreeCrtc(crtc);
		drmModeFreeConnector(conn);
	}

	drmModeFreeResources(res);

	if (count <= 0)
	{
		char err[KVM_DRM_MAX_ERROR];
		snprintf(err, sizeof(err), "%s on %s",
			connected > 0 ? "No connected display with active scanout" : "No connected display with active CRTC",
			path);
		kvm_drm_copy_error_message(out_error, out_error_size, err);
		return false;
	}

	qsort(outputs, (size_t)count, sizeof(kvm_drm_output), kvm_drm_compare_outputs);
	*out_count = count;

	if (drm_debug && logSelection)
	{
		fprintf(stderr, "DRM: Selected %d output(s) on %s\n", count, path);
		for (i = 0; i < count; ++i)
		{
			fprintf(stderr, "DRM:   output[%d] %s connector=%u crtc=%u index=%d pos=%d,%d size=%ux%u\n",
				i, outputs[i].connector_name, outputs[i].connector_id, outputs[i].crtc_id,
				outputs[i].crtc_index, outputs[i].x, outputs[i].y, outputs[i].width, outputs[i].height);
		}
	}
	return true;
}

static void kvm_drm_close_all_devices(kvm_drm_device *devices, int count)
{
	int i, j;
	// A default-display fallback can hand the same EGLDisplay to multiple devices; EGL doesn't
	// refcount eglTerminate, so detach duplicates and let only the first owner tear the display down.
	for (i = 0; i < count; ++i)
	{
		for (j = 0; j < i; ++j)
		{
			if (devices[i].eglCtx.dpy != EGL_NO_DISPLAY && devices[i].eglCtx.dpy == devices[j].eglCtx.dpy)
			{
				devices[i].eglCtx.dpy = EGL_NO_DISPLAY;
				break;
			}
		}
	}
	for (i = 0; i < count; ++i)
	{
		kvm_drm_egl_destroy_context(&devices[i].eglCtx);
		kvm_drm_destroy_map(&devices[i].map);
		if (devices[i].fd >= 0) { close(devices[i].fd); devices[i].fd = -1; }
	}
}

// Returns true only if the card contributed active outputs (not merely that it opened).
static bool kvm_drm_try_device(const char *path, kvm_drm_device *devices, int max_devices, int *device_count,
	kvm_drm_output *outputs, int max_outputs, int *out_count, char *out_error, size_t out_error_size)
{
	int fd, collected = 0, base = *out_count, k;

	if (*device_count >= max_devices || base >= max_outputs) { return false; }
	if ((fd = open(path, O_RDWR | KVM_DRM_O_CLOEXEC | O_NONBLOCK)) < 0) { return false; }
	// Without this cap the kernel hides primary planes from GetPlaneResources, and the
	// plane-rotation query (and the plane-fb fallback) would only ever see overlays.
	drmSetClientCap(fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);
	if (!kvm_drm_collect_active_outputs_on_fd(fd, path, &outputs[base], max_outputs - base, &collected, true, true, out_error, out_error_size))
	{
		close(fd);
		return false;
	}

	for (k = 0; k < collected; ++k) { outputs[base + k].device_index = *device_count; }
	memset(&devices[*device_count], 0, sizeof(devices[*device_count]));
	devices[*device_count].fd = fd;
	devices[*device_count].map.dma_fd = -1;
	devices[*device_count].map.drm_fd = -1;
	snprintf(devices[*device_count].path, sizeof(devices[*device_count].path), "%s", path);
	*out_count += collected;
	(*device_count)++;
	return true;
}

// Merge every GPU's outputs so a multi-card desktop is one capture; sort by position for stable monitor numbering.
static bool kvm_drm_open_all_devices(const char *explicit_device, kvm_drm_device *devices, int max_devices,
	int *out_device_count, kvm_drm_output *outputs, int max_outputs, int *out_count, char *out_error, size_t out_error_size)
{
	*out_device_count = 0;
	*out_count = 0;

	if (explicit_device != NULL && explicit_device[0] != 0)
	{
		kvm_drm_try_device(explicit_device, devices, max_devices, out_device_count, outputs, max_outputs, out_count, out_error, out_error_size);
	}
	else
	{
		int i;
		for (i = 0; i < 16; ++i)
		{
			char path[64];
			snprintf(path, sizeof(path), "/dev/dri/card%d", i);
			kvm_drm_try_device(path, devices, max_devices, out_device_count, outputs, max_outputs, out_count, out_error, out_error_size);
		}
	}

	if (*out_device_count == 0)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "No usable /dev/dri/card* device with active connector/CRTC scanout");
		return false;
	}

	qsort(outputs, (size_t)*out_count, sizeof(kvm_drm_output), kvm_drm_compare_outputs);
	return true;
}

// 1s refresh path: picks up resolution/hotplug changes without reopening; a card with no scanout is skipped, not fatal.
static bool kvm_drm_refresh_all_devices(kvm_drm_device *devices, int deviceCount, kvm_drm_output *outputs,
	int max_outputs, int *out_count, char *out_error, size_t out_error_size)
{
	int di, k;
	*out_count = 0;
	out_error[0] = 0; // collect only writes this on failure; clear it so the empty-result check below is reliable
	for (di = 0; di < deviceCount; ++di)
	{
		int collected = 0, base = *out_count;
		if (base >= max_outputs) { break; }
		if (!kvm_drm_collect_active_outputs_on_fd(devices[di].fd, devices[di].path, &outputs[base], max_outputs - base, &collected, true, false, out_error, out_error_size))
		{
			continue;
		}
		for (k = 0; k < collected; ++k) { outputs[base + k].device_index = di; }
		*out_count += collected;
	}
	if (*out_count == 0)
	{
		if (out_error[0] == 0) { kvm_drm_copy_error_message(out_error, out_error_size, "No active scanout on any device"); }
		return false;
	}
	qsort(outputs, (size_t)*out_count, sizeof(kvm_drm_output), kvm_drm_compare_outputs);
	return true;
}

// We only read scanout state; holding DRM master can block the compositor from
// taking GPU ownership during greeter/user-session handoff.
static int kvm_drm_drop_master_if_held(int fd)
{
	if (fd < 0) { return 0; }
	if (drmDropMaster(fd) == 0) { return 0; }

	// Not master, or driver doesn't implement master semantics for this fd.
	if (errno == EINVAL || errno == ENOTTY || errno == ENOSYS)
	{
		return 0;
	}
	return -1;
}

static uint32_t kvm_drm_get_plane_fb_id(int fd, uint32_t crtc_id, int crtc_index)
{
	drmModePlaneRes *pres = drmModeGetPlaneResources(fd);
	if (pres == NULL)
	{
		return 0;
	}

	uint32_t best_fb_id = 0;
	uint64_t best_area = 0;
	uint32_t i;

	for (i = 0; i < pres->count_planes; ++i)
	{
		drmModePlane *plane = drmModeGetPlane(fd, pres->planes[i]);
		if (plane == NULL)
		{
			continue;
		}
		if (plane->crtc_id == crtc_id && plane->fb_id != 0 &&
			(plane->possible_crtcs & (1u << (uint32_t)crtc_index)))
		{
			drmModeFB *fb = drmModeGetFB(fd, plane->fb_id);
			if (fb != NULL)
			{
				uint64_t area = ((uint64_t)fb->width) * ((uint64_t)fb->height);
				if (area > best_area)
				{
					best_area = area;
					best_fb_id = plane->fb_id;
				}
				// Only the fb_id is kept; release the handle reference GETFB just created, or this
				// leaks one handle per plane per frame whenever the plane-fb fallback is active.
				kvm_drm_close_gem_handle(fd, fb->handle);
				drmModeFreeFB(fb);
			}
		}
		drmModeFreePlane(plane);
	}

	drmModeFreePlaneResources(pres);
	return best_fb_id;
}

static kvm_drm_rotation kvm_drm_get_scanout_rotation()
{
	kvm_drm_rotation forced = KVM_DRM_ROTATION_0;
	if (kvm_drm_get_forced_rotation(&forced, drm_debug))
	{
		return forced;
	}
	return KVM_DRM_ROTATION_0;
}

static uint32_t kvm_drm_get_scanout_fb_id(int fd, uint32_t crtc_id, int crtc_index, bool *out_have_crtc, bool *out_used_plane_fb)
{
	drmModeCrtc *crtc = drmModeGetCrtc(fd, crtc_id);
	uint32_t fb_id = 0;

	if (out_have_crtc != NULL) { *out_have_crtc = false; }
	if (out_used_plane_fb != NULL) { *out_used_plane_fb = false; }

	if (crtc == NULL)
	{
		return 0;
	}

	if (out_have_crtc != NULL) { *out_have_crtc = true; }

	fb_id = crtc->buffer_id;
	drmModeFreeCrtc(crtc);

	if (fb_id == 0)
	{
		fb_id = kvm_drm_get_plane_fb_id(fd, crtc_id, crtc_index);
		if (fb_id != 0 && out_used_plane_fb != NULL)
		{
			*out_used_plane_fb = true;
		}
	}

	return fb_id;
}

static bool kvm_drm_get_scanout_frame(int fd, uint32_t crtc_id, int crtc_index, kvm_drm_scanout_frame *out, char *out_error, size_t out_error_size)
{
	bool have_crtc = false;
	bool used_plane_fb = false;
	uint32_t fb_id = kvm_drm_get_scanout_fb_id(fd, crtc_id, crtc_index, &have_crtc, &used_plane_fb);

	out->rotation = KVM_DRM_ROTATION_0;

	if (!have_crtc)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "drmModeGetCrtc failed");
		return false;
	}
	if (fb_id == 0)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "Active CRTC has no framebuffer");
		return false;
	}
	if (drm_debug && used_plane_fb)
	{
		fprintf(stderr, "DRM: CRTC %u has no direct buffer_id, using plane framebuffer %u\n", crtc_id, fb_id);
	}

	bool have_fb2_meta = false;
	drmModeFB2 *fb2 = drmModeGetFB2(fd, fb_id);
	if (fb2 != NULL)
	{
		int planeCount = 1;
		while (planeCount < 4 &&
			(fb2->handles[planeCount] != 0 || fb2->pitches[planeCount] != 0 || fb2->offsets[planeCount] != 0))
		{
			++planeCount;
		}

		if (drm_debug >= 2)
		{
			char format[32];
			kvm_drm_format_fourcc(format, sizeof(format), fb2->pixel_format);
			fprintf(stderr,
				"DRM: FB2 fb_id=%u planes=%d size=%ux%u format=%s modifier=0x%016" PRIx64
				" handles=[%u,%u,%u,%u] pitches=[%u,%u,%u,%u] offsets=[%u,%u,%u,%u]\n",
				fb_id,
				planeCount,
				fb2->width,
				fb2->height,
				format,
				fb2->modifier,
				fb2->handles[0], fb2->handles[1], fb2->handles[2], fb2->handles[3],
				fb2->pitches[0], fb2->pitches[1], fb2->pitches[2], fb2->pitches[3],
				fb2->offsets[0], fb2->offsets[1], fb2->offsets[2], fb2->offsets[3]);
		}

		// Capture every plane. Render-compressed scanout (Intel Y-tiled CCS) presents a data plane
		// plus a metadata plane; the EGL importer hands all planes to eglCreateImageKHR so the GPU
		// decompresses during the blit. Rejecting planeCount>1 here is what turned CCS scanout black.
		out->plane_count = planeCount;
		for (int p = 0; p < planeCount && p < 4; ++p)
		{
			out->plane_handles[p] = fb2->handles[p];
			out->plane_pitches[p] = fb2->pitches[p];
			out->plane_offsets[p] = fb2->offsets[p];
		}

		out->width = fb2->width;
		out->height = fb2->height;
		out->pitch = fb2->pitches[0];
		out->offset = fb2->offsets[0];
		out->format = fb2->pixel_format;
		out->modifier = fb2->modifier;
		if (fb2->handles[0] != 0)
		{
			out->fb_id = fb_id;
			out->handle = fb2->handles[0];
			out->rotation = kvm_drm_get_scanout_rotation();
			drmModeFreeFB2(fb2);
			return true;
		}
		have_fb2_meta = true;
		drmModeFreeFB2(fb2);
	}

	drmModeFB *fb = drmModeGetFB(fd, fb_id);
	if (fb == NULL)
	{
		kvm_drm_close_frame_handles(fd, out);	// fb2 metadata may have carried handle references
		kvm_drm_copy_error_message(out_error, out_error_size, "drmModeGetFB failed");
		return false;
	}

	out->fb_id = fb_id;
	if (!have_fb2_meta)
	{
		out->width = fb->width;
		out->height = fb->height;
		out->pitch = fb->pitch;
		out->offset = 0;
		out->format = DRM_FORMAT_XRGB8888;
		out->modifier = DRM_FORMAT_MOD_LINEAR;
	}
	out->handle = fb->handle;
	if (!have_fb2_meta)
	{
		out->plane_count = 1;
		out->plane_handles[0] = fb->handle;
		out->plane_pitches[0] = out->pitch;
		out->plane_offsets[0] = out->offset;
	}
	out->rotation = kvm_drm_get_scanout_rotation();
	drmModeFreeFB(fb);
	return true;
}

static uint32_t kvm_drm_bytes_per_pixel(uint32_t format)
{
	switch (format)
	{
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
	case DRM_FORMAT_RGBX8888:
	case DRM_FORMAT_RGBA8888:
	case DRM_FORMAT_BGRX8888:
	case DRM_FORMAT_BGRA8888:
	case DRM_FORMAT_XRGB2101010:
	case DRM_FORMAT_XBGR2101010:
	case DRM_FORMAT_ARGB2101010:
	case DRM_FORMAT_ABGR2101010:
	case DRM_FORMAT_RGBX1010102:
	case DRM_FORMAT_BGRX1010102:
	case DRM_FORMAT_RGBA1010102:
	case DRM_FORMAT_BGRA1010102:
		return 4;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		return 3;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		return 2;
	default:
		return 0;
	}
}

static bool kvm_drm_convert_to_rgb24(const kvm_drm_scanout_frame *f, const uint8_t *src, uint8_t *rgb, size_t rgb_capacity, size_t *rgb_size_out, char *out_error, size_t out_error_size)
{
	static uint8_t expand5[32];
	static uint8_t expand6[64];
	static int expandTablesReady = 0;
	uint32_t i;

	if (rgb_size_out != NULL)
	{
		*rgb_size_out = 0;
	}
	if (f->modifier != DRM_FORMAT_MOD_INVALID && f->modifier != DRM_FORMAT_MOD_LINEAR)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "Non-linear DRM modifier is not supported by CPU readback path");
		return false;
	}

	uint32_t bpp = kvm_drm_bytes_per_pixel(f->format);
	if (bpp == 0)
	{
		char err[KVM_DRM_MAX_ERROR];
		snprintf(err, sizeof(err), "Unsupported DRM pixel format: 0x%08X", f->format);
		kvm_drm_copy_error_message(out_error, out_error_size, err);
		return false;
	}

	if (f->pitch < f->width * bpp)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "Invalid pitch for framebuffer");
		return false;
	}

	size_t rgb_size = (size_t)f->width * (size_t)f->height * 3u;
	if (rgb == NULL || rgb_capacity < rgb_size)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "Output RGB buffer too small");
		return false;
	}

	uint32_t y;
	if (expandTablesReady == 0)
	{
		for (i = 0; i < 32; ++i) { expand5[i] = (uint8_t)((i * 255u) / 31u); }
		for (i = 0; i < 64; ++i) { expand6[i] = (uint8_t)((i * 255u) / 63u); }
		expandTablesReady = 1;
	}

	switch (f->format)
	{
		case DRM_FORMAT_XRGB8888:
		case DRM_FORMAT_ARGB8888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[2];
					d[1] = s[1];
					d[2] = s[0];
					s += 4;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_XBGR8888:
		case DRM_FORMAT_ABGR8888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[0];
					d[1] = s[1];
					d[2] = s[2];
					s += 4;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_RGBX8888:
		case DRM_FORMAT_RGBA8888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[3];
					d[1] = s[2];
					d[2] = s[1];
					s += 4;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_BGRX8888:
		case DRM_FORMAT_BGRA8888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[1];
					d[1] = s[2];
					d[2] = s[3];
					s += 4;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_XRGB2101010:
		case DRM_FORMAT_ARGB2101010:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
					while (x-- > 0)
					{
						uint32_t v = ((uint32_t)s[0]) | (((uint32_t)s[1]) << 8) | (((uint32_t)s[2]) << 16) | (((uint32_t)s[3]) << 24);
						d[0] = (uint8_t)(((v >> 20) & 0x3FFu) >> 2);
						d[1] = (uint8_t)(((v >> 10) & 0x3FFu) >> 2);
						d[2] = (uint8_t)(((v >> 0) & 0x3FFu) >> 2);
						s += 4;
						d += 3;
					}
			}
			break;
		}
		case DRM_FORMAT_XBGR2101010:
		case DRM_FORMAT_ABGR2101010:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
					while (x-- > 0)
					{
						uint32_t v = ((uint32_t)s[0]) | (((uint32_t)s[1]) << 8) | (((uint32_t)s[2]) << 16) | (((uint32_t)s[3]) << 24);
						d[0] = (uint8_t)(((v >> 0) & 0x3FFu) >> 2);
						d[1] = (uint8_t)(((v >> 10) & 0x3FFu) >> 2);
						d[2] = (uint8_t)(((v >> 20) & 0x3FFu) >> 2);
						s += 4;
						d += 3;
					}
			}
			break;
		}
		case DRM_FORMAT_RGBX1010102:
		case DRM_FORMAT_RGBA1010102:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
					while (x-- > 0)
					{
						uint32_t v = ((uint32_t)s[0]) | (((uint32_t)s[1]) << 8) | (((uint32_t)s[2]) << 16) | (((uint32_t)s[3]) << 24);
						d[0] = (uint8_t)(((v >> 22) & 0x3FFu) >> 2);
						d[1] = (uint8_t)(((v >> 12) & 0x3FFu) >> 2);
						d[2] = (uint8_t)(((v >> 2) & 0x3FFu) >> 2);
						s += 4;
						d += 3;
					}
			}
			break;
		}
		case DRM_FORMAT_BGRX1010102:
		case DRM_FORMAT_BGRA1010102:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
					while (x-- > 0)
					{
						uint32_t v = ((uint32_t)s[0]) | (((uint32_t)s[1]) << 8) | (((uint32_t)s[2]) << 16) | (((uint32_t)s[3]) << 24);
						d[0] = (uint8_t)(((v >> 2) & 0x3FFu) >> 2);
						d[1] = (uint8_t)(((v >> 12) & 0x3FFu) >> 2);
						d[2] = (uint8_t)(((v >> 22) & 0x3FFu) >> 2);
						s += 4;
						d += 3;
					}
			}
			break;
		}
		case DRM_FORMAT_RGB888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[2];
					d[1] = s[1];
					d[2] = s[0];
					s += 3;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_BGR888:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					d[0] = s[0];
					d[1] = s[1];
					d[2] = s[2];
					s += 3;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_RGB565:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					uint16_t v = ((uint16_t)s[0]) | (((uint16_t)s[1]) << 8);
					d[0] = expand5[(v >> 11) & 0x1Fu];
					d[1] = expand6[(v >> 5) & 0x3Fu];
					d[2] = expand5[(v >> 0) & 0x1Fu];
					s += 2;
					d += 3;
				}
			}
			break;
		}
		case DRM_FORMAT_BGR565:
		{
			for (y = 0; y < f->height; ++y)
			{
				const uint8_t *s = src + ((size_t)y * (size_t)f->pitch);
				uint8_t *d = rgb + ((size_t)y * (size_t)f->width * 3u);
				uint32_t x = f->width;
				while (x-- > 0)
				{
					uint16_t v = ((uint16_t)s[0]) | (((uint16_t)s[1]) << 8);
					d[0] = expand5[(v >> 0) & 0x1Fu];
					d[1] = expand6[(v >> 5) & 0x3Fu];
					d[2] = expand5[(v >> 11) & 0x1Fu];
					s += 2;
					d += 3;
				}
			}
			break;
		}
		default:
		{
			char err[KVM_DRM_MAX_ERROR];
			snprintf(err, sizeof(err), "Unsupported DRM pixel format: 0x%08X", f->format);
			kvm_drm_copy_error_message(out_error, out_error_size, err);
			return false;
		}
	}

	if (rgb_size_out != NULL)
	{
		*rgb_size_out = rgb_size;
	}
	return true;
}

static void kvm_drm_get_rotated_dimensions(const kvm_drm_scanout_frame *frame, uint32_t *out_width, uint32_t *out_height)
{
	*out_width = frame->width;
	*out_height = frame->height;
	if (frame->rotation == KVM_DRM_ROTATION_90 || frame->rotation == KVM_DRM_ROTATION_270)
	{
		*out_width = frame->height;
		*out_height = frame->width;
	}
}

// Map a DRM plane "rotation" property bitmask to quarter turns in the same angular direction as
// the wl_output transform (both are specified counter-clockwise). Both reflections together are
// exactly an extra 180; a single-axis mirror is not expressible as a rotation, so reject it.
static int kvm_drm_plane_rotation_value_to_quarters(uint64_t value)
{
	int quarters;
	uint64_t reflects = value & (DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y);
	if (value & DRM_MODE_ROTATE_0) { quarters = 0; }
	else if (value & DRM_MODE_ROTATE_90) { quarters = 1; }
	else if (value & DRM_MODE_ROTATE_180) { quarters = 2; }
	else if (value & DRM_MODE_ROTATE_270) { quarters = 3; }
	else { return -1; }
	if (reflects == (DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y)) { quarters = (quarters + 2) % 4; }
	else if (reflects != 0) { return -1; }
	return quarters;
}

// Find the named property on a plane; returns the property id (0 if absent) and its current value.
static uint32_t kvm_drm_find_plane_prop(int fd, uint32_t plane_id, const char *name, uint64_t *out_value)
{
	uint32_t prop_id = 0;
	uint32_t i;
	drmModeObjectProperties *props = drmModeObjectGetProperties(fd, plane_id, DRM_MODE_OBJECT_PLANE);
	if (props == NULL) { return 0; }
	for (i = 0; i < props->count_props && prop_id == 0; ++i)
	{
		drmModePropertyRes *prop = drmModeGetProperty(fd, props->props[i]);
		if (prop == NULL) { continue; }
		if (strcmp(prop->name, name) == 0)
		{
			prop_id = prop->prop_id;
			if (out_value != NULL) { *out_value = props->prop_values[i]; }
		}
		drmModeFreeProperty(prop);
	}
	drmModeFreeObjectProperties(props);
	return prop_id;
}

// Re-read the current value of a known property id on a plane.
static int kvm_drm_read_plane_prop_value(int fd, uint32_t plane_id, uint32_t prop_id, uint64_t *out_value)
{
	int found = 0;
	uint32_t i;
	drmModeObjectProperties *props = drmModeObjectGetProperties(fd, plane_id, DRM_MODE_OBJECT_PLANE);
	if (props == NULL) { return 0; }
	for (i = 0; i < props->count_props; ++i)
	{
		if (props->props[i] == prop_id)
		{
			*out_value = props->prop_values[i];
			found = 1;
			break;
		}
	}
	drmModeFreeObjectProperties(props);
	return found;
}

// The scanout plane feeding a CRTC and its "rotation" property id are stable across frames, so the
// per-frame cost is one plane fetch (rebind check) plus one property-values fetch.
typedef struct kvm_drm_plane_rotation_cache
{
	int fd;
	uint32_t crtc_id;
	uint32_t plane_id;
	uint32_t prop_id;
	int last_logged_quarters;
} kvm_drm_plane_rotation_cache;
static kvm_drm_plane_rotation_cache g_planeRotationCache[KVM_DRM_MAX_OUTPUTS];
static int g_planeRotationCacheCount = 0;

// Current rotation the scanout hardware applies to the buffer feeding crtc_id, in quarter turns;
// -1 when unknown (no matching plane, no "rotation" property, or a value we cannot express).
// Prefers the plane presenting fb_id (the buffer we actually captured), falling back to the
// CRTC's primary plane, so fullscreen direct scanout on an overlay plane resolves correctly.
static int kvm_drm_get_plane_rotation_quarters(int fd, uint32_t crtc_id, uint32_t fb_id)
{
	uint64_t value = 0;
	int slot = -1;
	int i;
	kvm_drm_plane_rotation_cache *entry = NULL;
	drmModePlaneRes *pres = NULL;
	uint32_t match_plane = 0, match_prop = 0;
	uint32_t primary_plane = 0, primary_prop = 0;
	uint64_t match_value = 0, primary_value = 0;

	for (i = 0; i < g_planeRotationCacheCount; ++i)
	{
		if (g_planeRotationCache[i].fd == fd && g_planeRotationCache[i].crtc_id == crtc_id)
		{
			slot = i;
			break;
		}
	}

	if (slot >= 0 && g_planeRotationCache[slot].plane_id != 0)
	{
		entry = &g_planeRotationCache[slot];
		drmModePlane *plane = drmModeGetPlane(fd, entry->plane_id);
		if (plane != NULL && plane->crtc_id == crtc_id)
		{
			drmModeFreePlane(plane);
			if (kvm_drm_read_plane_prop_value(fd, entry->plane_id, entry->prop_id, &value))
			{
				return kvm_drm_plane_rotation_value_to_quarters(value);
			}
		}
		else if (plane != NULL)
		{
			drmModeFreePlane(plane);
		}
		entry->plane_id = 0;	// stale binding: rescan below
	}

	pres = drmModeGetPlaneResources(fd);
	if (pres == NULL) { return -1; }
	for (i = 0; i < (int)pres->count_planes && match_plane == 0; ++i)
	{
		drmModePlane *plane = drmModeGetPlane(fd, pres->planes[i]);
		if (plane == NULL) { continue; }
		if (plane->crtc_id == crtc_id && plane->fb_id != 0)
		{
			uint64_t rot = 0, type = 0;
			uint32_t prop = kvm_drm_find_plane_prop(fd, plane->plane_id, "rotation", &rot);
			if (prop != 0)
			{
				if (fb_id != 0 && plane->fb_id == fb_id)
				{
					match_plane = plane->plane_id;
					match_prop = prop;
					match_value = rot;
				}
				else if (primary_plane == 0 &&
					kvm_drm_find_plane_prop(fd, plane->plane_id, "type", &type) != 0 &&
					type == DRM_PLANE_TYPE_PRIMARY)
				{
					primary_plane = plane->plane_id;
					primary_prop = prop;
					primary_value = rot;
				}
			}
		}
		drmModeFreePlane(plane);
	}
	drmModeFreePlaneResources(pres);

	if (match_plane == 0)
	{
		match_plane = primary_plane;
		match_prop = primary_prop;
		match_value = primary_value;
	}
	if (match_plane == 0) { return -1; }

	if (slot < 0 && g_planeRotationCacheCount < KVM_DRM_MAX_OUTPUTS)
	{
		slot = g_planeRotationCacheCount++;
		g_planeRotationCache[slot].last_logged_quarters = -2;
	}
	if (slot >= 0)
	{
		g_planeRotationCache[slot].fd = fd;
		g_planeRotationCache[slot].crtc_id = crtc_id;
		g_planeRotationCache[slot].plane_id = match_plane;
		g_planeRotationCache[slot].prop_id = match_prop;
	}
	return kvm_drm_plane_rotation_value_to_quarters(match_value);
}

static kvm_drm_rotation kvm_drm_effective_output_rotation(int fd, const kvm_drm_output *output, const kvm_drm_scanout_frame *frame)
{
	if (output->rotation != KVM_DRM_ROTATION_0)
	{
		// The transform only says how the logical image relates to the panel, not who rotates it.
		// When the compositor offloads the rotation to the plane hardware the scanout buffer stays
		// in logical orientation (mutter does this for 180 on i915, which can't offload 90/270
		// here), so compose the plane's own rotation with the transform-derived un-rotation:
		// whatever the hardware already turns must not be turned again in software.
		int planeQuarters = kvm_drm_get_plane_rotation_quarters(fd, output->crtc_id, frame->fb_id);
		if (planeQuarters >= 0)
		{
			kvm_drm_rotation effective = (kvm_drm_rotation)((((int)output->rotation) + planeQuarters) % 4);
			if (drm_debug >= 2)
			{
				int i;
				for (i = 0; i < g_planeRotationCacheCount; ++i)
				{
					if (g_planeRotationCache[i].fd == fd && g_planeRotationCache[i].crtc_id == output->crtc_id &&
						g_planeRotationCache[i].last_logged_quarters != planeQuarters)
					{
						fprintf(stderr, "DRM: CRTC %u plane %u rotation property=%d quarter(s); un-rotation %d -> effective %d\n",
							output->crtc_id, g_planeRotationCache[i].plane_id, planeQuarters,
							(int)output->rotation, (int)effective);
						g_planeRotationCache[i].last_logged_quarters = planeQuarters;
						break;
					}
				}
			}
			return effective;
		}
	}
	if (output->rotation == KVM_DRM_ROTATION_90 || output->rotation == KVM_DRM_ROTATION_270)
	{
		// Fallback when the rotation property is unreadable: a 90/270 transform swaps the logical
		// aspect relative to the scanout buffer. If the buffer orientation already matches the
		// logical rect, the plane hardware is doing the rotation and the content needs no software
		// pass. Square shapes give no signal; trust the transform then (compositors pre-rotate in
		// the renderer on virtually all hardware). 180 has no aspect signal at all, which is why
		// the property query above is the primary source.
		if (frame->width != frame->height && output->width != output->height &&
			(frame->width > frame->height) == (output->width > output->height))
		{
			return KVM_DRM_ROTATION_0;
		}
	}
	return output->rotation;
}

static bool kvm_drm_compute_desktop_layout(const kvm_drm_output *outputs, int output_count, kvm_drm_desktop_layout *layout)
{
	int i;
	int min_x = INT_MAX;
	int min_y = INT_MAX;
	int max_x = INT_MIN;
	int max_y = INT_MIN;

	if (outputs == NULL || output_count <= 0 || layout == NULL)
	{
		return false;
	}

	for (i = 0; i < output_count; ++i)
	{
		int right = outputs[i].x + (int)outputs[i].width;
		int bottom = outputs[i].y + (int)outputs[i].height;
		if (outputs[i].width == 0 || outputs[i].height == 0)
		{
			continue;
		}
		if (outputs[i].x < min_x) { min_x = outputs[i].x; }
		if (outputs[i].y < min_y) { min_y = outputs[i].y; }
		if (right > max_x) { max_x = right; }
		if (bottom > max_y) { max_y = bottom; }
	}

	if (min_x == INT_MAX || min_y == INT_MAX || max_x <= min_x || max_y <= min_y)
	{
		return false;
	}

	layout->min_x = min_x;
	layout->min_y = min_y;
	layout->max_x = max_x;
	layout->max_y = max_y;
	layout->width = (uint32_t)(max_x - min_x);
	layout->height = (uint32_t)(max_y - min_y);
	return true;
}

static void kvm_drm_publish_monitor_layout(const kvm_drm_output *outputs, int output_count, const kvm_drm_desktop_layout *layout)
{
	kvm_monitor_info monitors[KVM_MAX_MONITORS];
	int i;
	int monitorCount = output_count;

	if (outputs == NULL || layout == NULL)
	{
		kvm_update_monitor_layout(NULL, 0, 0, 0);
		return;
	}
	if (monitorCount > KVM_MAX_MONITORS) { monitorCount = KVM_MAX_MONITORS; }

	memset(monitors, 0, sizeof(monitors));
	for (i = 0; i < monitorCount; ++i)
	{
		monitors[i].id = i + 1;
		monitors[i].x = outputs[i].x - layout->min_x;
		monitors[i].y = outputs[i].y - layout->min_y;
		monitors[i].width = (int)outputs[i].width;
		monitors[i].height = (int)outputs[i].height;
	}
	kvm_update_monitor_layout(monitors, monitorCount, (int)layout->width, (int)layout->height);
}

static void kvm_drm_update_tile_geometry()
{
	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH)
	{
		TILE_WIDTH_COUNT++;
	}
	if (SCREEN_HEIGHT % TILE_HEIGHT)
	{
		TILE_HEIGHT_COUNT++;
	}
}

// mutter names an HDMI type-A connector "HDMI-<id>", but the kernel, libdrm, and our own
// kvm_drm_connector_type_name() call it "HDMI-A-<id>". Without tolerating that the xdg-output name
// never matches the DRM connector on GNOME, the whole layout is discarded, and every monitor falls
// back to 0,0. HDMI type-B stays "HDMI-B-<id>" on both sides, so keep it out of the type-A fixup.
static int kvm_drm_connector_name_equal(const char *drmName, const char *wlName)
{
	if (drmName == NULL || wlName == NULL) { return 0; }
	if (strcmp(drmName, wlName) == 0) { return 1; }
	if (strncmp(drmName, "HDMI-A-", 7) == 0 && strncmp(wlName, "HDMI-", 5) == 0 && strncmp(wlName, "HDMI-B-", 7) != 0)
	{
		return strcmp(drmName + 7, wlName + 5) == 0;
	}
	return 0;
}

static int kvm_drm_find_output_by_name(const kvm_drm_output *outputs, int output_count, const char *name, const bool *claimed)
{
	int i;
	if (outputs == NULL || name == NULL || name[0] == 0)
	{
		return -1;
	}
	for (i = 0; i < output_count; ++i)
	{
		if (claimed != NULL && claimed[i]) { continue; } // a prior compositor entry already took this output
		if (kvm_drm_connector_name_equal(outputs[i].connector_name, name))
		{
			return i;
		}
	}
	return -1;
}

static int kvm_drm_apply_kwin_screen(kvm_drm_output *outputs, int output_count, const char *name, int enabled, int x, int y, uint32_t width, uint32_t height, kvm_drm_rotation rotation, int *matched, bool *claimed)
{
	int index;
	if (enabled != 1 || width == 0 || height == 0)
	{
		return 0;
	}
	// connector_name is per-card, so two GPUs can both report e.g. "DP-1"; claimed[] stops two
	// compositor entries from both landing on the same output (and leaving the other unplaced).
	index = kvm_drm_find_output_by_name(outputs, output_count, name, claimed);
	if (index < 0)
	{
		return 0;
	}

	outputs[index].x = x;
	outputs[index].y = y;
	outputs[index].width = width;
	outputs[index].height = height;
	outputs[index].rotation = rotation;
	if (claimed != NULL) { claimed[index] = true; }
	if (matched != NULL) { (*matched)++; }
	return 1;
}

struct zxdg_output_manager_v1;
struct zxdg_output_v1;

struct zxdg_output_v1_listener
{
	void (*logical_position)(void *data, struct zxdg_output_v1 *zxdg_output_v1, int32_t x, int32_t y);
	void (*logical_size)(void *data, struct zxdg_output_v1 *zxdg_output_v1, int32_t width, int32_t height);
	void (*done)(void *data, struct zxdg_output_v1 *zxdg_output_v1);
	void (*name)(void *data, struct zxdg_output_v1 *zxdg_output_v1, const char *name);
	void (*description)(void *data, struct zxdg_output_v1 *zxdg_output_v1, const char *description);
};

static const struct wl_interface zxdg_output_v1_interface;

static const struct wl_interface *kvm_xdg_output_types[] =
{
	NULL,
	NULL,
	&zxdg_output_v1_interface,
	NULL, /* wl_output_interface — patched in at load */
};

static const struct wl_message zxdg_output_manager_v1_requests[] =
{
	{ "destroy", "", kvm_xdg_output_types + 0 },
	{ "get_xdg_output", "no", kvm_xdg_output_types + 2 },
};

static const struct wl_interface zxdg_output_manager_v1_interface =
{
	"zxdg_output_manager_v1", 3,
	2, zxdg_output_manager_v1_requests,
	0, NULL,
};

static const struct wl_message zxdg_output_v1_requests[] =
{
	{ "destroy", "", kvm_xdg_output_types + 0 },
};

static const struct wl_message zxdg_output_v1_events[] =
{
	{ "logical_position", "ii", kvm_xdg_output_types + 0 },
	{ "logical_size", "ii", kvm_xdg_output_types + 0 },
	{ "done", "", kvm_xdg_output_types + 0 },
	{ "name", "2s", kvm_xdg_output_types + 0 },
	{ "description", "2s", kvm_xdg_output_types + 0 },
};

static const struct wl_interface zxdg_output_v1_interface =
{
	"zxdg_output_v1", 3,
	1, zxdg_output_v1_requests,
	5, zxdg_output_v1_events,
};

static struct zxdg_output_v1 *zxdg_output_manager_v1_get_xdg_output(struct zxdg_output_manager_v1 *manager, struct wl_output *output)
{
	union wl_argument args[2];
	args[0].o = NULL;
	args[1].o = (struct wl_object *)output;
	return (struct zxdg_output_v1 *)wl_proxy_marshal_array_constructor((struct wl_proxy *)manager,
		1 /*get_xdg_output*/, args, &zxdg_output_v1_interface);
}

static void zxdg_output_manager_v1_destroy(struct zxdg_output_manager_v1 *manager)
{
	wl_proxy_marshal_array((struct wl_proxy *)manager, 0 /*destroy*/, NULL);
	wl_proxy_destroy((struct wl_proxy *)manager);
}

static int zxdg_output_v1_add_listener(struct zxdg_output_v1 *output, const struct zxdg_output_v1_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *)output, (void (**)(void))listener, data);
}

static void zxdg_output_v1_destroy(struct zxdg_output_v1 *output)
{
	wl_proxy_marshal_array((struct wl_proxy *)output, 0 /*destroy*/, NULL);
	wl_proxy_destroy((struct wl_proxy *)output);
}

typedef struct kvm_drm_wayland_output
{
	struct wl_output *wl_output;
	struct zxdg_output_v1 *xdg_output;
	uint32_t global_name;
	uint32_t version;
	char name[64];
	int have_name;
	int have_position;
	int have_size;
	int x;
	int y;
	uint32_t width;
	uint32_t height;
	int32_t transform; // WL_OUTPUT_TRANSFORM_* from wl_output.geometry
	// Core-protocol fallback data for compositors without zxdg_output_manager_v1 (minimal greeter
	// compositors): geometry position + current mode size describe the compositor space at scale 1.
	int geom_x;
	int geom_y;
	int have_geometry;
	uint32_t mode_width;
	uint32_t mode_height;
	int have_mode;
} kvm_drm_wayland_output;

typedef struct kvm_drm_wayland_layout_context
{
	struct wl_display *display;
	struct wl_registry *registry;
	struct zxdg_output_manager_v1 *xdg_output_manager;
	kvm_drm_wayland_output outputs[KVM_DRM_MAX_OUTPUTS];
	int output_count;
} kvm_drm_wayland_layout_context;

static void kvm_drm_wl_output_geometry(void *data, struct wl_output *wl_output, int32_t x, int32_t y, int32_t physical_width, int32_t physical_height, int32_t subpixel, const char *make, const char *model, int32_t transform)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)wl_output; (void)physical_width; (void)physical_height; (void)subpixel; (void)make; (void)model;
	if (output != NULL)
	{
		output->transform = transform;
		output->geom_x = x;
		output->geom_y = y;
		output->have_geometry = 1;
	}
}

static void kvm_drm_wl_output_mode(void *data, struct wl_output *wl_output, uint32_t flags, int32_t width, int32_t height, int32_t refresh)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)wl_output; (void)refresh;
	if (output != NULL && (flags & WL_OUTPUT_MODE_CURRENT) != 0 && width > 0 && height > 0)
	{
		output->mode_width = (uint32_t)width;
		output->mode_height = (uint32_t)height;
		output->have_mode = 1;
	}
}

static void kvm_drm_wl_output_done(void *data, struct wl_output *wl_output)
{
	(void)data; (void)wl_output;
}

static void kvm_drm_wl_output_scale(void *data, struct wl_output *wl_output, int32_t factor)
{
	(void)data; (void)wl_output; (void)factor;
}

static void kvm_drm_wl_output_name(void *data, struct wl_output *wl_output, const char *name)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)wl_output;
	if (output != NULL && name != NULL && output->have_name == 0)
	{
		snprintf(output->name, sizeof(output->name), "%s", name);
		output->have_name = 1;
	}
}

static void kvm_drm_wl_output_description(void *data, struct wl_output *wl_output, const char *description)
{
	(void)data; (void)wl_output; (void)description;
}

static const struct wl_output_listener kvm_drm_wl_output_listener =
{
	kvm_drm_wl_output_geometry,
	kvm_drm_wl_output_mode,
	kvm_drm_wl_output_done,
	kvm_drm_wl_output_scale,
	kvm_drm_wl_output_name,
	kvm_drm_wl_output_description,
};

static void kvm_drm_xdg_output_position(void *data, struct zxdg_output_v1 *xdg_output, int32_t x, int32_t y)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)xdg_output;
	if (output == NULL) { return; }
	output->x = x;
	output->y = y;
	output->have_position = 1;
}

static void kvm_drm_xdg_output_size(void *data, struct zxdg_output_v1 *xdg_output, int32_t width, int32_t height)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)xdg_output;
	if (output == NULL || width <= 0 || height <= 0) { return; }
	output->width = (uint32_t)width;
	output->height = (uint32_t)height;
	output->have_size = 1;
}

static void kvm_drm_xdg_output_done(void *data, struct zxdg_output_v1 *xdg_output)
{
	(void)data; (void)xdg_output;
}

static void kvm_drm_xdg_output_name(void *data, struct zxdg_output_v1 *xdg_output, const char *name)
{
	kvm_drm_wayland_output *output = (kvm_drm_wayland_output *)data;
	(void)xdg_output;
	if (output != NULL && name != NULL)
	{
		snprintf(output->name, sizeof(output->name), "%s", name);
		output->have_name = 1;
	}
}

static void kvm_drm_xdg_output_description(void *data, struct zxdg_output_v1 *xdg_output, const char *description)
{
	(void)data; (void)xdg_output; (void)description;
}

static const struct zxdg_output_v1_listener kvm_drm_xdg_output_listener =
{
	kvm_drm_xdg_output_position,
	kvm_drm_xdg_output_size,
	kvm_drm_xdg_output_done,
	kvm_drm_xdg_output_name,
	kvm_drm_xdg_output_description,
};

static void kvm_drm_registry_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
	kvm_drm_wayland_layout_context *ctx = (kvm_drm_wayland_layout_context *)data;
	if (ctx == NULL || interface == NULL) { return; }

	if (strcmp(interface, "wl_output") == 0)
	{
		kvm_drm_wayland_output *output;
		uint32_t bind_version;
		if (ctx->output_count >= KVM_DRM_MAX_OUTPUTS) { return; }
		output = &ctx->outputs[ctx->output_count++];
		memset(output, 0, sizeof(*output));
		output->global_name = name;
		output->version = version;
		// Cap at v4 (name event); never bind above what the compositor advertises.
		bind_version = version >= 4 ? 4 : version;
		output->wl_output = (struct wl_output *)kvm_wl_registry_bind(registry, name, p_wl_output_interface, bind_version);
		if (output->wl_output != NULL)
		{
			kvm_wl_output_add_listener(output->wl_output, &kvm_drm_wl_output_listener, output);
		}
		return;
	}

	if (strcmp(interface, "zxdg_output_manager_v1") == 0)
	{
		uint32_t bind_version = version >= 3 ? 3 : version;
		ctx->xdg_output_manager = (struct zxdg_output_manager_v1 *)kvm_wl_registry_bind(registry, name, &zxdg_output_manager_v1_interface, bind_version);
	}
}

static void kvm_drm_registry_global_remove(void *data, struct wl_registry *registry, uint32_t name)
{
	(void)data; (void)registry; (void)name;
}

static const struct wl_registry_listener kvm_drm_registry_listener =
{
	kvm_drm_registry_global,
	kvm_drm_registry_global_remove,
};

static void kvm_drm_wayland_layout_context_cleanup(kvm_drm_wayland_layout_context *ctx)
{
	int i;
	if (ctx == NULL) { return; }
	for (i = 0; i < ctx->output_count; ++i)
	{
		if (ctx->outputs[i].xdg_output != NULL)
		{
			zxdg_output_v1_destroy(ctx->outputs[i].xdg_output);
			ctx->outputs[i].xdg_output = NULL;
		}
		if (ctx->outputs[i].wl_output != NULL)
		{
			wl_proxy_destroy((struct wl_proxy *)ctx->outputs[i].wl_output);
			ctx->outputs[i].wl_output = NULL;
		}
	}
	if (ctx->xdg_output_manager != NULL)
	{
		zxdg_output_manager_v1_destroy(ctx->xdg_output_manager);
		ctx->xdg_output_manager = NULL;
	}
	if (ctx->registry != NULL)
	{
		wl_proxy_destroy((struct wl_proxy *)ctx->registry);
		ctx->registry = NULL;
	}
	if (ctx->display != NULL)
	{
		wl_display_disconnect(ctx->display);
		ctx->display = NULL;
	}
}

// Maps a wl_output transform onto the pass that brings the captured scanout buffer back into
// logical orientation. The compositor rotates the logical desktop counter-clockwise by the
// transform angle when rendering into the panel-native buffer (verified on mutter 43: with
// transform=1 the top bar lands on the buffer's left edge), so the un-rotation is the inverse,
// and kvm_drm_rotate_rgb24's ROTATION_90 pass is itself counter-clockwise — hence 1->270, 3->90.
// The flipped variants (4..7) also mirror, which kvm_drm_rotate_rgb24 can't express; use their
// rotation component so the image is at least oriented correctly.
static kvm_drm_rotation kvm_drm_rotation_from_wl_transform(int32_t transform)
{
	switch (transform & 3)
	{
	case 1: return KVM_DRM_ROTATION_270;
	case 2: return KVM_DRM_ROTATION_180;
	case 3: return KVM_DRM_ROTATION_90;
	default: return KVM_DRM_ROTATION_0;
	}
}

static uint64_t kvm_drm_now_ms();

static void kvm_drm_on_sync_done(void *data, struct wl_callback *callback, uint32_t serial)
{
	(void)callback; (void)serial;
	*(int *)data = 1;
}
static const struct wl_callback_listener kvm_drm_sync_listener = { kvm_drm_on_sync_done };

// Deadline-bounded wl_display_roundtrip replacement. The layout query runs on the capture thread
// (at startup and from the 1 Hz refresh); an unbounded roundtrip against a hung compositor would
// stop the master2slave input drain and re-arm the agent-wide pipe stall that kvm_drm_write_all
// exists to prevent. Returns 1 when the sync callback fired, 0 on timeout/error.
static int kvm_drm_wl_roundtrip_deadline(struct wl_display *display, uint64_t deadlineMs)
{
	union wl_argument args[1];
	struct wl_callback *cb;
	int done = 0;

	args[0].o = NULL;
	cb = (struct wl_callback *)wl_proxy_marshal_array_constructor((struct wl_proxy *)display,
		0 /*WL_DISPLAY_SYNC*/, args, p_wl_callback_interface);
	if (cb == NULL) { return 0; }
	wl_proxy_add_listener((struct wl_proxy *)cb, (void (**)(void))&kvm_drm_sync_listener, &done);

	while (!done && !g_shutdown)
	{
		struct pollfd pfd;
		uint64_t now;
		int pr;

		if (wl_display_dispatch_pending(display) < 0) { break; }
		if (done) { break; }
		while (wl_display_prepare_read(display) != 0)
		{
			if (wl_display_dispatch_pending(display) < 0) { goto out; }
		}
		wl_display_flush(display);

		now = kvm_drm_now_ms();
		pfd.fd = wl_display_get_fd(display);
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = (now >= deadlineMs) ? 0 : poll(&pfd, 1, (int)(deadlineMs - now));
		if (pr <= 0)
		{
			int savedErrno = errno;
			wl_display_cancel_read(display);
			if (pr < 0 && savedErrno == EINTR && kvm_drm_now_ms() < deadlineMs) { continue; }
			break;
		}
		if (wl_display_read_events(display) < 0) { break; }
	}
out:
	// Destroy before returning: the listener writes into this frame's 'done'.
	wl_proxy_destroy((struct wl_proxy *)cb);
	return done;
}

#define KVM_DRM_XDG_QUERY_TIMEOUT_MS 1500
#define KVM_DRM_XDG_BACKOFF_MS 30000

static bool kvm_drm_apply_xdg_output_layout(kvm_drm_output *outputs, int output_count, bool logSelection)
{
	// After a roundtrip timeout, skip the query for a while: the 1 Hz refresh must not pay the
	// full timeout every second against a wedged compositor.
	static uint64_t backoffUntilMs = 0;
	kvm_drm_wayland_layout_context ctx;
	kvm_drm_output tmp[KVM_DRM_MAX_OUTPUTS];
	bool claimed[KVM_DRM_MAX_OUTPUTS] = { false };
	uint64_t deadline;
	int rtFailed = 0;
	int matched = 0;
	int i;

	if (outputs == NULL || output_count <= 0 || output_count > KVM_DRM_MAX_OUTPUTS)
	{
		return false;
	}
	if (backoffUntilMs != 0 && kvm_drm_now_ms() < backoffUntilMs)
	{
		return false;
	}

	if (!kvm_drm_load_wayland())
	{
		return false; // no libwayland → caller falls back to KWin/raw positions
	}

	memset(&ctx, 0, sizeof(ctx));
	memcpy_s(tmp, sizeof(tmp), outputs, sizeof(kvm_drm_output) * (size_t)output_count);

	ctx.display = wl_display_connect(NULL);
	if (ctx.display == NULL)
	{
		if (drm_debug)
		{
			fprintf(stderr, "DRM: xdg-output query: wl_display_connect(NULL) failed (errno=%d, WAYLAND_DISPLAY=%s, XDG_RUNTIME_DIR=%s, euid=%d)\n",
				errno,
				getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(unset)",
				getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "(unset)",
				(int)geteuid());
		}
		return false;
	}
	ctx.registry = kvm_wl_display_get_registry(ctx.display);
	if (ctx.registry == NULL)
	{
		kvm_drm_wayland_layout_context_cleanup(&ctx);
		return false;
	}
	kvm_wl_registry_add_listener(ctx.registry, &kvm_drm_registry_listener, &ctx);
	deadline = kvm_drm_now_ms() + KVM_DRM_XDG_QUERY_TIMEOUT_MS;
	rtFailed = !kvm_drm_wl_roundtrip_deadline(ctx.display, deadline);
	if (rtFailed || ctx.output_count <= 0)
	{
		if (drm_debug) { fprintf(stderr, "DRM: xdg-output query: registry roundtrip failed or no wl_outputs (rtFailed=%d wl_outputs=%d)\n", rtFailed, ctx.output_count); }
		if (rtFailed) { backoffUntilMs = kvm_drm_now_ms() + KVM_DRM_XDG_BACKOFF_MS; }
		kvm_drm_wayland_layout_context_cleanup(&ctx);
		return false;
	}
	if (ctx.xdg_output_manager == NULL && drm_debug)
	{
		fprintf(stderr, "DRM: compositor has no zxdg_output_manager_v1; using wl_output geometry fallback\n");
	}

	if (ctx.xdg_output_manager != NULL)
	{
		for (i = 0; i < ctx.output_count; ++i)
		{
			if (ctx.outputs[i].wl_output == NULL) { continue; }
			ctx.outputs[i].xdg_output = zxdg_output_manager_v1_get_xdg_output(ctx.xdg_output_manager, ctx.outputs[i].wl_output);
			if (ctx.outputs[i].xdg_output != NULL)
			{
				zxdg_output_v1_add_listener(ctx.outputs[i].xdg_output, &kvm_drm_xdg_output_listener, &ctx.outputs[i]);
			}
		}
	}

	// Also needed without the xdg manager: the wl_output geometry/mode/name events for outputs
	// bound during the registry dispatch only arrive on a further roundtrip.
	for (i = 0; i < 3; ++i)
	{
		if (!kvm_drm_wl_roundtrip_deadline(ctx.display, deadline))
		{
			backoffUntilMs = kvm_drm_now_ms() + KVM_DRM_XDG_BACKOFF_MS;
			kvm_drm_wayland_layout_context_cleanup(&ctx);
			return false;
		}
	}
	backoffUntilMs = 0;

	for (i = 0; i < ctx.output_count; ++i)
	{
		if (drm_debug)
		{
			fprintf(stderr, "DRM: xdg-output query: wl-output[%d] name='%s' have_name=%d have_pos=%d(%d,%d) have_size=%d(%ux%u) geom=%d(%d,%d) mode=%d(%ux%u) transform=%d\n",
				i, ctx.outputs[i].name, ctx.outputs[i].have_name, ctx.outputs[i].have_position,
				ctx.outputs[i].x, ctx.outputs[i].y, ctx.outputs[i].have_size, ctx.outputs[i].width, ctx.outputs[i].height,
				ctx.outputs[i].have_geometry, ctx.outputs[i].geom_x, ctx.outputs[i].geom_y,
				ctx.outputs[i].have_mode, ctx.outputs[i].mode_width, ctx.outputs[i].mode_height,
				ctx.outputs[i].transform);
		}
		if (ctx.xdg_output_manager != NULL)
		{
			if (ctx.outputs[i].have_name == 0 || ctx.outputs[i].have_position == 0 || ctx.outputs[i].have_size == 0)
			{
				continue;
			}
			kvm_drm_apply_kwin_screen(tmp, output_count, ctx.outputs[i].name, 1, ctx.outputs[i].x, ctx.outputs[i].y, ctx.outputs[i].width, ctx.outputs[i].height,
				kvm_drm_rotation_from_wl_transform(ctx.outputs[i].transform), &matched, claimed);
		}
		else if (ctx.outputs[i].have_geometry && ctx.outputs[i].have_mode)
		{
			// No xdg-output: geometry position + current-mode size describe the compositor space at
			// scale 1 (greeters). A 90/270 transform swaps the output's extent in compositor space,
			// which the panel-native mode size does not reflect.
			uint32_t fw = ctx.outputs[i].mode_width;
			uint32_t fh = ctx.outputs[i].mode_height;
			if ((ctx.outputs[i].transform & 1) != 0) { uint32_t t = fw; fw = fh; fh = t; }
			if (ctx.outputs[i].have_name)
			{
				kvm_drm_apply_kwin_screen(tmp, output_count, ctx.outputs[i].name, 1,
					ctx.outputs[i].geom_x, ctx.outputs[i].geom_y, fw, fh,
					kvm_drm_rotation_from_wl_transform(ctx.outputs[i].transform), &matched, claimed);
			}
			else if (ctx.output_count == 1 && output_count == 1 && !claimed[0])
			{
				// wl_output v3 and older has no name event; with one output on both sides the
				// pairing is unambiguous anyway.
				tmp[0].x = ctx.outputs[i].geom_x;
				tmp[0].y = ctx.outputs[i].geom_y;
				tmp[0].width = fw;
				tmp[0].height = fh;
				tmp[0].rotation = kvm_drm_rotation_from_wl_transform(ctx.outputs[i].transform);
				claimed[0] = true;
				matched++;
			}
		}
	}

	if (matched != output_count)
	{
		if (drm_debug) { fprintf(stderr, "DRM: xdg-output query: matched %d of %d DRM output(s) by name -> discarding xdg layout\n", matched, output_count); }
		kvm_drm_wayland_layout_context_cleanup(&ctx);
		return false;
	}

	memcpy_s(outputs, sizeof(kvm_drm_output) * (size_t)output_count, tmp, sizeof(kvm_drm_output) * (size_t)output_count);
	qsort(outputs, (size_t)output_count, sizeof(kvm_drm_output), kvm_drm_compare_outputs);
	if (drm_debug && logSelection)
	{
		fprintf(stderr, "DRM: Using Wayland xdg-output logical layout\n");
		for (i = 0; i < output_count; ++i)
		{
			fprintf(stderr, "DRM:   xdg-output[%d] %s pos=%d,%d size=%ux%u rotation=%s\n",
				i, outputs[i].connector_name, outputs[i].x, outputs[i].y, outputs[i].width, outputs[i].height,
				kvm_drm_rotation_name(outputs[i].rotation));
		}
	}

	kvm_drm_wayland_layout_context_cleanup(&ctx);
	return true;
}

static bool kvm_drm_apply_kwin_layout(kvm_drm_output *outputs, int output_count, bool logSelection)
{
	FILE *pipe;
	char line[256];
	kvm_drm_output tmp[KVM_DRM_MAX_OUTPUTS];
	bool claimed[KVM_DRM_MAX_OUTPUTS] = { false };
	int in_screens = 0;
	int have_screen = 0;
	char name[32];
	int enabled = -1;
	int x = 0;
	int y = 0;
	uint32_t width = 0;
	uint32_t height = 0;
	int matched = 0;
	int i;

	if (outputs == NULL || output_count <= 0 || output_count > KVM_DRM_MAX_OUTPUTS)
	{
		return false;
	}

	memcpy_s(tmp, sizeof(tmp), outputs, sizeof(kvm_drm_output) * (size_t)output_count);
	memset(name, 0, sizeof(name));

	pipe = popen("(qdbus6 org.kde.KWin /KWin org.kde.KWin.supportInformation 2>/dev/null || qdbus org.kde.KWin /KWin org.kde.KWin.supportInformation 2>/dev/null)", "r");
	if (pipe == NULL)
	{
		return false;
	}

	while (fgets(line, sizeof(line), pipe) != NULL)
	{
		if (!in_screens)
		{
			if (strncmp(line, "Screens", 7) == 0)
			{
				in_screens = 1;
			}
			continue;
		}
		if (strncmp(line, "Compositing", 11) == 0)
		{
			break;
		}
		if (strncmp(line, "Screen ", 7) == 0)
		{
			if (have_screen)
			{
				// supportInformation exposes no transform; a rotated output keeps rotation 0 here.
				kvm_drm_apply_kwin_screen(tmp, output_count, name, enabled, x, y, width, height, KVM_DRM_ROTATION_0, &matched, claimed);
			}
			have_screen = 1;
			name[0] = 0;
			enabled = -1;
			x = y = 0;
			width = height = 0;
			continue;
		}
		if (!have_screen)
		{
			continue;
		}
		if (sscanf(line, "Name: %31s", name) == 1)
		{
			continue;
		}
		if (sscanf(line, "Enabled: %d", &enabled) == 1)
		{
			continue;
		}
		if (sscanf(line, "Geometry: %d,%d,%ux%u", &x, &y, &width, &height) == 4)
		{
			continue;
		}
	}
	if (have_screen)
	{
		kvm_drm_apply_kwin_screen(tmp, output_count, name, enabled, x, y, width, height, KVM_DRM_ROTATION_0, &matched, claimed);
	}
	pclose(pipe);

	if (matched != output_count)
	{
		return false;
	}

	memcpy_s(outputs, sizeof(kvm_drm_output) * (size_t)output_count, tmp, sizeof(kvm_drm_output) * (size_t)output_count);
	qsort(outputs, (size_t)output_count, sizeof(kvm_drm_output), kvm_drm_compare_outputs);
	if (drm_debug && logSelection)
	{
		fprintf(stderr, "DRM: Using KWin logical output layout\n");
		for (i = 0; i < output_count; ++i)
		{
			fprintf(stderr, "DRM:   kwin[%d] %s pos=%d,%d size=%ux%u\n",
				i, outputs[i].connector_name, outputs[i].x, outputs[i].y, outputs[i].width, outputs[i].height);
		}
	}
	return true;
}

// A socket FILE existing does not mean a compositor is behind it: a crashed/previous session can
// leave a stale wayland-0 while the live one listens on wayland-1. Only a successful connect() is
// proof of life.
static int kvm_drm_wayland_socket_alive(const char *runtimeDir, const char *name)
{
	struct sockaddr_un addr;
	int fd, r, len;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	len = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", runtimeDir, name);
	if (len <= 0 || len >= (int)sizeof(addr.sun_path)) { return 0; }
	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) { return 0; }
	r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);
	return r == 0 ? 1 : 0;
}

static void kvm_drm_prepare_session_environment(int sessionUid)
{
	char runtimeDir[64];
	char busAddress[96];
	char *envDisplay;
	DIR *dir = NULL;
	struct dirent *ent = NULL;
	if (sessionUid <= 0)
	{
		return;
	}
	snprintf(runtimeDir, sizeof(runtimeDir), "/run/user/%d", sessionUid);
	snprintf(busAddress, sizeof(busAddress), "unix:path=/run/user/%d/bus", sessionUid);
	if (getenv("XDG_RUNTIME_DIR") == NULL) { setenv("XDG_RUNTIME_DIR", runtimeDir, 1); }
	if (getenv("DBUS_SESSION_BUS_ADDRESS") == NULL) { setenv("DBUS_SESSION_BUS_ADDRESS", busAddress, 1); }

	envDisplay = getenv("WAYLAND_DISPLAY");
	if (envDisplay != NULL && kvm_drm_wayland_socket_alive(runtimeDir, envDisplay))
	{
		return;
	}
	if (envDisplay != NULL && drm_debug)
	{
		fprintf(stderr, "DRM: WAYLAND_DISPLAY=%s does not accept connections in %s; scanning for a live socket\n", envDisplay, runtimeDir);
	}
	dir = opendir(runtimeDir);
	if (dir != NULL)
	{
		while ((ent = readdir(dir)) != NULL)
		{
			if (strncmp(ent->d_name, "wayland-", 8) == 0 && strstr(ent->d_name, ".lock") == NULL &&
				kvm_drm_wayland_socket_alive(runtimeDir, ent->d_name))
			{
				if (drm_debug) { fprintf(stderr, "DRM: using live Wayland socket %s/%s\n", runtimeDir, ent->d_name); }
				setenv("WAYLAND_DISPLAY", ent->d_name, 1);
				break;
			}
		}
		closedir(dir);
	}
}

static void kvm_drm_copy_frame_to_desktop(const unsigned char *src, uint32_t src_width, uint32_t src_height, unsigned char *dst, uint32_t dst_width, uint32_t dst_height, int dst_x, int dst_y, uint32_t output_width, uint32_t output_height)
{
	uint32_t y;
	if (src == NULL || dst == NULL || src_width == 0 || src_height == 0 || dst_width == 0 || dst_height == 0 || output_width == 0 || output_height == 0)
	{
		return;
	}

	if (src_width == output_width && src_height == output_height)
	{
		for (y = 0; y < src_height; ++y)
		{
			int target_y = dst_y + (int)y;
			if (target_y < 0 || target_y >= (int)dst_height)
			{
				continue;
			}

			int copy_x = dst_x;
			uint32_t src_x = 0;
			uint32_t copy_width = src_width;
			if (copy_x < 0)
			{
				src_x = (uint32_t)(-copy_x);
				if (src_x >= copy_width) { continue; }
				copy_width -= src_x;
				copy_x = 0;
			}
			if (copy_x >= (int)dst_width)
			{
				continue;
			}
			if (copy_width > dst_width - (uint32_t)copy_x)
			{
				copy_width = dst_width - (uint32_t)copy_x;
			}

			memcpy_s(dst + ((((size_t)target_y * (size_t)dst_width) + (size_t)copy_x) * 3u),
				((size_t)(dst_width - (uint32_t)copy_x)) * 3u,
				src + ((((size_t)y * (size_t)src_width) + (size_t)src_x) * 3u),
				((size_t)copy_width) * 3u);
		}
		return;
	}

	for (y = 0; y < output_height; ++y)
	{
		int target_y = dst_y + (int)y;
		if (target_y < 0 || target_y >= (int)dst_height)
		{
			continue;
		}

		uint32_t x;
		uint32_t src_y = (uint32_t)(((uint64_t)y * (uint64_t)src_height) / (uint64_t)output_height);
		for (x = 0; x < output_width; ++x)
		{
			int target_x = dst_x + (int)x;
			if (target_x < 0 || target_x >= (int)dst_width)
			{
				continue;
			}
			uint32_t src_x = (uint32_t)(((uint64_t)x * (uint64_t)src_width) / (uint64_t)output_width);
			const unsigned char *s = src + ((((size_t)src_y * (size_t)src_width) + (size_t)src_x) * 3u);
			unsigned char *d = dst + ((((size_t)target_y * (size_t)dst_width) + (size_t)target_x) * 3u);
			d[0] = s[0];
			d[1] = s[1];
			d[2] = s[2];
		}
	}
}

static uint64_t kvm_drm_now_ms()
{
	struct timespec tsNow;
	if (clock_gettime(CLOCK_MONOTONIC, &tsNow) != 0)
	{
		return 0;
	}
	return (((uint64_t)tsNow.tv_sec) * 1000ULL) + (((uint64_t)tsNow.tv_nsec) / 1000000ULL);
}

// MESH_KVM_DRM_DUMP=<path> writes the composed desktop as a PPM (P6) about every 2 seconds, so
// orientation/layout problems can be inspected without a viewer attached.
static void kvm_drm_debug_dump_frame(const unsigned char *rgb, uint32_t width, uint32_t height)
{
	static const char *path = NULL;
	static int initialized = 0;
	static uint64_t lastDumpMs = 0;
	char tmpPath[512];
	uint64_t nowMs;
	int fd;
	FILE *f;

	if (!initialized)
	{
		path = getenv("MESH_KVM_DRM_DUMP");
		if (path != NULL && path[0] == 0) { path = NULL; }
		initialized = 1;
	}
	if (path == NULL || rgb == NULL || width == 0 || height == 0)
	{
		return;
	}
	nowMs = kvm_drm_now_ms();
	if (lastDumpMs != 0 && nowMs - lastDumpMs < 2000)
	{
		return;
	}
	lastDumpMs = nowMs;

	if (snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", path) >= (int)sizeof(tmpPath))
	{
		return;
	}
	fd = open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
	{
		return;
	}
	f = fdopen(fd, "wb");
	if (f == NULL)
	{
		close(fd);
		return;
	}
	fprintf(f, "P6\n%u %u\n255\n", width, height);
	fwrite(rgb, 1, (size_t)width * (size_t)height * 3u, f);
	fclose(f);
	ignore_result(rename(tmpPath, path));
}

// How long scanout must stay unavailable before we treat it as a real session teardown rather than
// a momentary display sleep. The child freezes the last frame (no error to the viewer) during this
// window, then exits so the root parent can re-fork against the current session.
#define KVM_DRM_SESSION_LOST_GRACE_MS 3000

// True while the captured session's XDG runtime dir still exists. On logout/user-switch systemd
// tears down /run/user/<uid> entirely, so its disappearance is our definitive "this session ended"
// signal. A display merely in DPMS sleep keeps its runtime dir, so we do not mistake sleep for
// logout. For uid<=0 (greeter/root/unknown) we can't use this signal, so report "present".
static int kvm_drm_session_runtime_present(int sessionUid)
{
	char path[64];
	if (sessionUid <= 0) { return 1; }
	if (snprintf(path, sizeof(path), "/run/user/%d", sessionUid) <= 0) { return 1; }
	return access(path, F_OK) == 0 ? 1 : 0;
}

static int kvm_drm_set_only_sys_admin_cap()
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct data[2];
	int cap = CAP_SYS_ADMIN;

	memset(&header, 0, sizeof(header));
	memset(data, 0, sizeof(data));

	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;

	data[cap / 32].permitted = (1u << (cap % 32));
	data[cap / 32].effective = (1u << (cap % 32));
	data[cap / 32].inheritable = 0;

	return syscall(SYS_capset, &header, data);
}

// After the setuid below we lose CAP_DAC_OVERRIDE, so opening /dev/dri/* (root:video/root:render, 0660) needs real
// group membership. libEGL opens those nodes itself, so add the groups now (root-only) or GPU capture comes out black.
static void kvm_drm_add_dri_supplementary_groups(void)
{
	static const char *names[] = { "video", "render" };
	long maxGroups = sysconf(_SC_NGROUPS_MAX);
	gid_t *groups;
	int count;
	int changed = 0;
	size_t ni;

	if (maxGroups < 0 || maxGroups > 65536) { maxGroups = 65536; }
	groups = (gid_t *)malloc(sizeof(gid_t) * (size_t)(maxGroups + (long)(sizeof(names) / sizeof(names[0]))));
	if (groups == NULL) { return; }

	count = getgroups((int)maxGroups, groups);
	if (count < 0) { count = 0; }

	for (ni = 0; ni < sizeof(names) / sizeof(names[0]); ++ni)
	{
		struct group *gr = getgrnam(names[ni]);
		int present = 0, k;
		if (gr == NULL) { continue; }
		for (k = 0; k < count; ++k) { if (groups[k] == gr->gr_gid) { present = 1; break; } }
		if (!present) { groups[count++] = gr->gr_gid; changed = 1; }
	}

	if (changed) { ignore_result(setgroups((size_t)count, groups)); }
	free(groups);
}

// Dropping caps with our DRM screen capture method requires more work than a simple setuid, because we need to
// retain CAP_SYS_ADMIN in order to scrape the screen.
static int kvm_drm_drop_to_session_uid_with_caps(int sessionUid, char *err, size_t errLen)
{
	struct passwd *pw = NULL;
	uid_t targetUid = (uid_t)sessionUid;
	uid_t currentUid = getuid();
	uid_t currentEuid = geteuid();

	if (sessionUid == 0) { return 0; }
	if (sessionUid < 0)
	{
		snprintf(err, errLen, "Invalid target uid: %d", sessionUid);
		return -1;
	}
	if (targetUid == currentUid && currentEuid != 0)
	{
		// If we are already the requested user (eg, started directly from a shell), don't call
		// initgroups()/setgid()/setuid() as those are root-only. Best-effort trim to CAP_SYS_ADMIN.
		if (kvm_drm_set_only_sys_admin_cap() != 0)
		{
			snprintf(err, errLen, "capset(CAP_SYS_ADMIN) warning (errno=%d)", errno);
		}
		return 0;
	}
	if (currentEuid != 0)
	{
		snprintf(err, errLen, "Need root to switch to uid %d from uid %d", sessionUid, (int)currentUid);
		return -1;
	}

	pw = getpwuid(targetUid);
	if (pw == NULL)
	{
		snprintf(err, errLen, "Unable to resolve passwd entry for uid %d (errno=%d)", sessionUid, errno);
		return -1;
	}

	if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) != 0)
	{
		snprintf(err, errLen, "PR_SET_KEEPCAPS failed (errno=%d)", errno);
		return -1;
	}
	if (initgroups(pw->pw_name, pw->pw_gid) != 0)
	{
		snprintf(err, errLen, "initgroups(%s,%d) failed (errno=%d)", pw->pw_name, (int)pw->pw_gid, errno);
		return -1;
	}
	kvm_drm_add_dri_supplementary_groups(); // initgroups() replaced our set with the user's; re-add video/render for DRI access
	if (setgid(pw->pw_gid) != 0)
	{
		snprintf(err, errLen, "setgid(%d) failed (errno=%d)", (int)pw->pw_gid, errno);
		return -1;
	}
	if (setuid(targetUid) != 0)
	{
		snprintf(err, errLen, "setuid(%d) failed (errno=%d)", sessionUid, errno);
		return -1;
	}
	if (kvm_drm_set_only_sys_admin_cap() != 0)
	{
		snprintf(err, errLen, "capset(CAP_SYS_ADMIN) failed (errno=%d)", errno);
		return -1;
	}

	ignore_result(prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L));
	// HOME is inherited from the root service; point it at the session user so Mesa's shader
	// cache works instead of warning about /root ("Failed to create /root/.cache ... denied").
	if (pw->pw_dir != NULL && pw->pw_dir[0] != 0) { setenv("HOME", pw->pw_dir, 1); }
	return 0;
}

#endif

void *kvm_server_mainloop_drm(void *parm)
{
	int sessionUid = (int)(intptr_t)parm;
	ssize_t cbBytesRead = 0;
	int r = 0;
	struct sigaction action;
	int displayListSent = 0;
	uint64_t lastFrameTimeMs = 0;
	int lastCaptureError = 0;
	int scanoutSuspended = 0;
	int forceTileReset = 0;
	uint64_t captureLostSinceMs = 0;	// when scanout first went unavailable (0 = capturing normally)
	int reportedScreenWidth = 0;
	int reportedScreenHeight = 0;
	int reportedScreenSel = -1;
	uint64_t lastOutputRefreshMs = 0;
	uint64_t lastRefreshFailureLogMs = 0;
	int consoleUidMismatch = 0;
	char lastRefreshFailure[KVM_DRM_MAX_ERROR];

	kvm_drm_init_debug();
	g_kvmBackendDRM = 1;
	{
		// Trust logind's notion of the console over the uid the master derived. The master passes
		// uid 0 at a display-manager greeter (consoleUid() only reports sessions at or above the
		// login uid floor), and right after a logout it can still see the dying user session and
		// pass THAT uid — either way this child would point at a runtime dir with no compositor,
		// so the logical-layout and keymap queries fail: monitors pile up at 0,0 and unicode input
		// turns ASCII-only. When logind cannot answer, keep whatever the master passed.
		int derivedUid = kvm_wayland_active_console_uid();
		if (derivedUid > 0 && derivedUid != sessionUid)
		{
			if (drm_debug) { fprintf(stderr, "DRM: using logind seat0 active uid %d (master passed %d)\n", derivedUid, sessionUid); }
			sessionUid = derivedUid;
		}
	}
	// Non-blocking for the slave's lifetime: kvm_drm_write_all() relies on it to multiplex tile
	// writes against master2slave input drains, and every sender routes through there in DRM mode.
	fcntl(slave2master[1], F_SETFL, fcntl(slave2master[1], F_GETFL, 0) | O_NONBLOCK);
	g_enableEvents = kvm_events_evdev_init();
	if (!g_enableEvents)
	{
		kvm_send_error("evdev input injection unavailable");
	}
	else
	{
		// Initial lock state for the viewer indicator (the X11 path does this in kvm_init). The
		// compositor pushed the current LED state while evdev init's post-create settle ran.
		char ksbuf[5];
		((unsigned short*)ksbuf)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);
		((unsigned short*)ksbuf)[1] = (unsigned short)htons((unsigned short)5);
		ksbuf[4] = (char)kvm_events_evdev_lock_state();
		ignore_result(kvm_drm_slave_write(ksbuf, sizeof(ksbuf)));
	}
	CURRENT_DISPLAY_ID = 0;
	SCREEN_NUM = 0;
	SCREEN_DEPTH = 24;
	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	COMPRESSION_RATIO = 50;
	FRAME_RATE_TIMER = 33;
	g_shutdown = 0;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = kvm_server_sighandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO;
	ignore_result(sigaction(SIGTERM, &action, NULL));

#if !defined(__linux__)
	kvm_send_error("DRM capture backend is only supported on Linux");
	kvm_events_evdev_shutdown();
	g_enableEvents = 0;
	g_kvmBackendDRM = 0;
	return (void *)-1;
#else
	kvm_drm_device devices[KVM_DRM_MAX_DEVICES];
	int deviceCount = 0;
	char err[KVM_DRM_MAX_ERROR];
	kvm_drm_output outputs[KVM_DRM_MAX_OUTPUTS];
	int outputCount = 0;
	kvm_drm_desktop_layout layout;
	unsigned char *rgbBuffer = NULL;
	size_t rgbBufferSize = 0;
	unsigned char *rgbRotatedBuffer = NULL;
	size_t rgbRotatedBufferSize = 0;
	unsigned char *desktopRgbBuffer = NULL;
	size_t desktopRgbBufferSize = 0;
	char *desktopBuffer = NULL;
	long long desktopBufferSize = 0;
	uint32_t lastLoggedFbId = 0;
	uint32_t lastLoggedWidth = 0;
	uint32_t lastLoggedHeight = 0;
	uint32_t lastLoggedPitch = 0;
	uint32_t lastLoggedOffset = 0;
	uint32_t lastLoggedFormat = 0;
	uint32_t lastLoggedHandle = 0;
	uint64_t lastLoggedModifier = UINT64_MAX;
	int lastLoggedPath = -1;
	int lastLoggedRotation = -1;
	memset(outputs, 0, sizeof(outputs));
	memset(&layout, 0, sizeof(layout));
	memset(devices, 0, sizeof(devices));
	memset(lastRefreshFailure, 0, sizeof(lastRefreshFailure));

	if (!kvm_drm_load_libdrm())
	{
		kvm_send_error("libdrm is not installed; DRM capture backend unavailable");
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		return (void *)-1;
	}

	char *explicitDevice = getenv("MESH_KVM_DRM_DEVICE");
	int haveLayout = kvm_drm_open_all_devices(explicitDevice, devices, KVM_DRM_MAX_DEVICES, &deviceCount, outputs, KVM_DRM_MAX_OUTPUTS, &outputCount, err, sizeof(err)) &&
		kvm_drm_compute_desktop_layout(outputs, outputCount, &layout);
	if (!haveLayout)
	{
		// No scanout usually means the displays are in DPMS sleep; nudge them awake and retry.
		uint64_t wakeStartMs = kvm_drm_now_ms();
		if (drm_debug) { fprintf(stderr, "DRM: no active scanout (%s); nudging displays awake and retrying\n", err[0] ? err : "displays asleep?"); }
		while (!haveLayout && !g_shutdown && (kvm_drm_now_ms() - wakeStartMs) < KVM_DRM_DISPLAY_WAKE_TIMEOUT_MS)
		{
			if (g_enableEvents) { kvm_events_evdev_wake(); }
			usleep(500 * 1000);
			kvm_drm_close_all_devices(devices, deviceCount);
			deviceCount = 0;
			haveLayout = kvm_drm_open_all_devices(explicitDevice, devices, KVM_DRM_MAX_DEVICES, &deviceCount, outputs, KVM_DRM_MAX_OUTPUTS, &outputCount, err, sizeof(err)) &&
				kvm_drm_compute_desktop_layout(outputs, outputCount, &layout);
		}
	}
	if (!haveLayout)
	{
		kvm_send_error(err[0] ? err : "Unable to compute DRM desktop layout");
		kvm_drm_close_all_devices(devices, deviceCount);
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		return (void *)-1;
	}
	for (int di = 0; di < deviceCount; ++di)
	{
		if (kvm_drm_drop_master_if_held(devices[di].fd) != 0)
		{
			snprintf(err, sizeof(err), "drmDropMaster failed on %s (errno=%d)", devices[di].path, errno);
			kvm_send_error(err);
			kvm_drm_close_all_devices(devices, deviceCount);
			kvm_events_evdev_shutdown();
			g_enableEvents = 0;
			g_kvmBackendDRM = 0;
			return (void *)-1;
		}
	}

	if (kvm_drm_drop_to_session_uid_with_caps(sessionUid, err, sizeof(err)) != 0)
	{
		fprintf(stderr, "DRM privilege setup failed: %s\n", err);
		kvm_send_error(err);
		kvm_drm_close_all_devices(devices, deviceCount);
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		return (void *)-1;
	}
	kvm_drm_prepare_session_environment(sessionUid);
	if (kvm_drm_apply_xdg_output_layout(outputs, outputCount, true) || kvm_drm_apply_kwin_layout(outputs, outputCount, true))
	{
		if (!kvm_drm_compute_desktop_layout(outputs, outputCount, &layout))
		{
			kvm_send_error("Unable to compute Wayland DRM desktop layout");
			kvm_drm_close_all_devices(devices, deviceCount);
			kvm_events_evdev_shutdown();
			g_enableEvents = 0;
			g_kvmBackendDRM = 0;
			return (void *)-1;
		}
	}
	kvm_drm_publish_monitor_layout(outputs, outputCount, &layout);
	kvm_drm_update_tile_geometry();

	while (!g_shutdown)
	{
		struct timeval tv;
		fd_set readset;
		fd_set errorset;
		fd_set writeset;
		int selectResult = 0;

		FD_ZERO(&readset);
		FD_ZERO(&errorset);
		FD_ZERO(&writeset);
		tv.tv_sec = 0;
		tv.tv_usec = 20000;
		FD_SET(master2slave[0], &readset);

		selectResult = select(master2slave[0] + 1, &readset, &writeset, &errorset, &tv);
		if (selectResult < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			g_shutdown = 1;
			break;
		}

		if (selectResult > 0 && FD_ISSET(master2slave[0], &readset) && g_drmInputLen < (int)sizeof(g_drmInputBuf))
		{
			cbBytesRead = read(master2slave[0], g_drmInputBuf + g_drmInputLen, sizeof(g_drmInputBuf) - (size_t)g_drmInputLen);
			if (cbBytesRead <= 0)
			{
				g_shutdown = 1;
				break;
			}
			g_drmInputLen += (int)cbBytesRead;
		}
		// Also covers input drained into the buffer while a frame write was stalled: those bytes
		// don't wake select() again, so parse whenever anything is pending.
		kvm_drm_process_pending_input();

		if (change_display)
		{
			SCREEN_SEL = SCREEN_SEL_TARGET;
			kvm_apply_monitor_selection();
			change_display = 0;
			forceTileReset = 1;
			displayListSent = 0;
		}

		uint64_t nowMs = kvm_drm_now_ms();
		uint64_t frameInterval = FRAME_RATE_TIMER < 20 ? 20 : (uint64_t)FRAME_RATE_TIMER;
		if (nowMs == 0 || (lastFrameTimeMs != 0 && nowMs - lastFrameTimeMs < frameInterval))
		{
			continue;
		}
		lastFrameTimeMs = nowMs;

		if (g_pause || g_remotepause)
		{
			continue;
		}

		if (lastOutputRefreshMs == 0 || nowMs - lastOutputRefreshMs >= 1000)
		{
			// Session handover while capture keeps working (logout -> greeter, user switch): the
			// runtime-dir check in the capturedOutputs<=0 block only runs when scanout is lost, but
			// DRM captures straight across a handover, so this child would stay bound to the dead
			// session's uid/env forever. Exit for re-fork once logind consistently reports a
			// different console owner; consecutive checks filter the flapping mid-transition.
			int liveConsoleUid = kvm_wayland_active_console_uid();
			if (liveConsoleUid > 0 && liveConsoleUid != sessionUid)
			{
				if (++consoleUidMismatch >= 3)
				{
					if (drm_debug) { fprintf(stderr, "DRM: console session uid changed %d -> %d; exiting for re-fork\n", sessionUid, liveConsoleUid); }
					g_shutdown = 1;
					break;
				}
			}
			else
			{
				consoleUidMismatch = 0;
			}
			kvm_drm_output refreshed[KVM_DRM_MAX_OUTPUTS];
			kvm_drm_desktop_layout refreshedLayout;
			int refreshedCount = 0;
			char refreshErr[KVM_DRM_MAX_ERROR];
			memset(refreshed, 0, sizeof(refreshed));
			memset(&refreshedLayout, 0, sizeof(refreshedLayout));
			if (kvm_drm_refresh_all_devices(devices, deviceCount, refreshed, KVM_DRM_MAX_OUTPUTS, &refreshedCount, refreshErr, sizeof(refreshErr)))
			{
				if (!kvm_drm_apply_xdg_output_layout(refreshed, refreshedCount, false))
				{
					ignore_result(kvm_drm_apply_kwin_layout(refreshed, refreshedCount, false));
				}
				if (kvm_drm_compute_desktop_layout(refreshed, refreshedCount, &refreshedLayout))
				{
					if (refreshedCount != outputCount ||
						memcmp(outputs, refreshed, sizeof(kvm_drm_output) * (size_t)refreshedCount) != 0 ||
						memcmp(&layout, &refreshedLayout, sizeof(layout)) != 0)
					{
						memcpy_s(outputs, sizeof(outputs), refreshed, sizeof(kvm_drm_output) * (size_t)refreshedCount);
						outputCount = refreshedCount;
						layout = refreshedLayout;
						kvm_drm_publish_monitor_layout(outputs, outputCount, &layout);
						forceTileReset = 1;
						displayListSent = 0;
						// Keep each device's EGL context across a layout change (same GPU; the convert
						// resizes its own readback target). Only the framebuffer maps need resetting.
						for (int di = 0; di < deviceCount; ++di)
						{
							kvm_drm_destroy_map(&devices[di].map);
						}
						kvm_drm_reset_logged_scanout_state(&lastLoggedFbId, &lastLoggedWidth, &lastLoggedHeight,
							&lastLoggedPitch, &lastLoggedOffset, &lastLoggedFormat, &lastLoggedHandle,
							&lastLoggedModifier, &lastLoggedPath);
						lastLoggedRotation = -1;
						if (drm_debug)
						{
							fprintf(stderr, "DRM: Refreshed desktop layout: %d output(s), origin=%d,%d size=%ux%u\n",
								outputCount, layout.min_x, layout.min_y, layout.width, layout.height);
						}
					}
					lastRefreshFailure[0] = 0;
					lastRefreshFailureLogMs = 0;
				}
			}
			else if (drm_debug && !kvm_drm_is_expected_suspended_refresh_error(refreshErr) &&
				(lastRefreshFailure[0] == 0 ||
				 strcmp(lastRefreshFailure, refreshErr) != 0 ||
				 nowMs - lastRefreshFailureLogMs >= 5000))
			{
				fprintf(stderr, "DRM: Output refresh failed: %s\n", refreshErr);
				kvm_drm_copy_error_message(lastRefreshFailure, sizeof(lastRefreshFailure), refreshErr);
				lastRefreshFailureLogMs = nowMs;
			}
			lastOutputRefreshMs = nowMs;
		}

		size_t desktopRgbSize = (size_t)SCREEN_WIDTH * (size_t)SCREEN_HEIGHT * 3u;
		if (desktopRgbBufferSize < desktopRgbSize)
		{
			unsigned char *tmp = (unsigned char *)realloc(desktopRgbBuffer, desktopRgbSize);
			if (tmp == NULL) ILIBCRITICALEXIT(254);
			desktopRgbBuffer = tmp;
			desktopRgbBufferSize = desktopRgbSize;
		}
		memset(desktopRgbBuffer, 0, desktopRgbSize);

		int capturedOutputs = 0;
		int outputIndex = 0;
		for (outputIndex = 0; outputIndex < outputCount; ++outputIndex)
		{
			kvm_drm_scanout_frame frame;
			size_t rgbSize = 0;
			bool converted = false;
			uint32_t effectiveWidth = 0;
			uint32_t effectiveHeight = 0;
			kvm_drm_device *dev = &devices[outputs[outputIndex].device_index];
			memset(&frame, 0, sizeof(frame));

			if (!kvm_drm_get_scanout_frame(dev->fd, outputs[outputIndex].crtc_id, outputs[outputIndex].crtc_index, &frame, err, sizeof(err)))
			{
				// Scanout acquisition failing mid-session is the logout / display-sleep symptom. Freeze
				// the last frame quietly instead of pushing a fatal error to the viewer; the grace +
				// runtime-dir check in the capturedOutputs<=0 block below distinguishes a transient
				// display sleep (keep waiting) from a real session teardown (exit so the parent re-forks).
				if (!kvm_drm_is_transient_scanout_error(err) && drm_debug)
				{
					fprintf(stderr, "DRM: scanout acquisition failed (%s); suspending\n", err);
				}
				scanoutSuspended = 1;
				forceTileReset = 1;
				if (captureLostSinceMs == 0) { captureLostSinceMs = nowMs; }
				continue;
			}

			if (frame.handle == 0 || frame.width == 0 || frame.height == 0)
			{
				kvm_drm_close_frame_handles(dev->fd, &frame);
				// No readable framebuffer handle: same handover/sleep symptom as above, suspend quietly.
				scanoutSuspended = 1;
				forceTileReset = 1;
				if (captureLostSinceMs == 0) { captureLostSinceMs = nowMs; }
				continue;
			}

			{
				// On a rotated output the compositor pre-rotates the logical desktop into the
				// panel-native buffer, so undo that per output. MESH_KVM_ROTATION (already applied
				// by kvm_drm_get_scanout_frame) stays a global manual override, including "0".
				kvm_drm_rotation forcedRotation = KVM_DRM_ROTATION_0;
				if (!kvm_drm_get_forced_rotation(&forcedRotation, 0))
				{
					frame.rotation = kvm_drm_effective_output_rotation(dev->fd, &outputs[outputIndex], &frame);
				}
			}

			if (drm_debug >= 2 &&
				(frame.width != lastLoggedWidth ||
				 frame.height != lastLoggedHeight ||
				 frame.pitch != lastLoggedPitch ||
				 frame.offset != lastLoggedOffset ||
				 frame.format != lastLoggedFormat ||
				 frame.modifier != lastLoggedModifier ||
				 (int)frame.rotation != lastLoggedRotation))
			{
				fprintf(stderr, "DRM: Output %s at %d,%d\n", outputs[outputIndex].connector_name, outputs[outputIndex].x, outputs[outputIndex].y);
				kvm_drm_debug_log_scanout_frame("Using scanout framebuffer", &frame);
				lastLoggedWidth = frame.width;
				lastLoggedHeight = frame.height;
				lastLoggedPitch = frame.pitch;
				lastLoggedOffset = frame.offset;
				lastLoggedFormat = frame.format;
				lastLoggedModifier = frame.modifier;
				lastLoggedRotation = (int)frame.rotation;
			}

			rgbSize = (size_t)frame.width * (size_t)frame.height * 3u;
			if (rgbBufferSize < rgbSize)
			{
				unsigned char *tmp = (unsigned char *)realloc(rgbBuffer, rgbSize);
				if (tmp == NULL) ILIBCRITICALEXIT(254);
				rgbBuffer = tmp;
				rgbBufferSize = rgbSize;
			}

			// Multi-plane framebuffers (CCS) must take the GPU path even if the modifier looked linear;
			// the CPU readback below only understands a single contiguous plane.
			if (frame.plane_count > 1 || (frame.modifier != DRM_FORMAT_MOD_INVALID && frame.modifier != DRM_FORMAT_MOD_LINEAR))
			{
				if (drm_debug >= 2 && lastLoggedPath != 1)
				{
					fprintf(stderr, "DRM: Using GPU-assisted conversion for modifier 0x%016" PRIx64 " (%d plane(s))\n", frame.modifier, frame.plane_count);
					lastLoggedPath = 1;
				}

				converted = kvm_drm_egl_convert_to_rgb24_gpu(&dev->eglCtx, dev->fd, frame.width, frame.height,
															 frame.plane_count, frame.plane_handles, frame.plane_pitches, frame.plane_offsets,
															 frame.format, frame.modifier,
															 rgbBuffer, rgbBufferSize, &rgbSize, err, sizeof(err));
				kvm_drm_close_frame_handles(dev->fd, &frame);
			}
			else
			{
				size_t required_bytes = (size_t)frame.offset + ((size_t)frame.pitch * (size_t)frame.height);
				if (!kvm_drm_map_framebuffer_handle(dev->fd, frame.handle, required_bytes, &dev->map, err, sizeof(err)))
				{
					kvm_drm_close_gem_handle(dev->fd, frame.handle);
					// "Failed to map scanout buffer" is the classic post-logout symptom: the session's
					// buffers / DRM access are gone. Suspend quietly (freeze last frame) and let the
					// grace + runtime-dir check decide, rather than spamming a fatal error during handover.
					scanoutSuspended = 1;
					forceTileReset = 1;
					if (captureLostSinceMs == 0) { captureLostSinceMs = nowMs; }
					continue;
				}
				else
				{
					if (drm_debug >= 2 && lastLoggedPath != 0)
					{
						char format[32];
						kvm_drm_format_fourcc(format, sizeof(format), frame.format);
						fprintf(stderr, "DRM: Using CPU readback conversion for format %s\n", format);
						lastLoggedPath = 0;
					}

					const uint8_t *src = dev->map.addr + frame.offset;
					converted = kvm_drm_convert_to_rgb24(&frame, src, rgbBuffer, rgbBufferSize, &rgbSize, err, sizeof(err));
				}
			}

			if (!converted)
			{
				if (lastCaptureError == 0)
				{
					kvm_send_error(err);
					lastCaptureError = 1;
				}
				continue;
			}

			const unsigned char *rgbFrame = rgbBuffer;
			kvm_drm_get_rotated_dimensions(&frame, &effectiveWidth, &effectiveHeight);
			if (frame.rotation != KVM_DRM_ROTATION_0)
			{
				if (rgbRotatedBufferSize < rgbSize)
				{
					unsigned char *tmp = (unsigned char *)realloc(rgbRotatedBuffer, rgbSize);
					if (tmp == NULL) ILIBCRITICALEXIT(254);
					rgbRotatedBuffer = tmp;
					rgbRotatedBufferSize = rgbSize;
				}
				kvm_drm_rotate_rgb24(rgbBuffer, frame.width, frame.height, frame.rotation, rgbRotatedBuffer);
				rgbFrame = rgbRotatedBuffer;
			}

			kvm_drm_copy_frame_to_desktop(rgbFrame, effectiveWidth, effectiveHeight, desktopRgbBuffer, (uint32_t)SCREEN_WIDTH, (uint32_t)SCREEN_HEIGHT,
				outputs[outputIndex].x - layout.min_x - CAPTURE_X, outputs[outputIndex].y - layout.min_y - CAPTURE_Y,
				outputs[outputIndex].width, outputs[outputIndex].height);
			capturedOutputs++;
		}

		if (capturedOutputs <= 0)
		{
			// Scanout has been unavailable on every output for longer than the grace period. If the
			// captured session's runtime dir is also gone, the user has logged out / switched away:
			// exit cleanly so the (still-root) parent re-forks against the CURRENT active session uid.
			// If the runtime dir is still present the display is only asleep (DPMS) — keep waiting.
			if (captureLostSinceMs != 0 &&
				(kvm_drm_now_ms() - captureLostSinceMs) >= KVM_DRM_SESSION_LOST_GRACE_MS &&
				!kvm_drm_session_runtime_present(sessionUid))
			{
				if (drm_debug)
				{
					fprintf(stderr, "DRM: session uid %d runtime dir gone; exiting for re-derive/re-fork\n", sessionUid);
				}
				g_shutdown = 1;	// leave the loop; the parent detects the child exit and re-forks
				break;
			}
			if (scanoutSuspended && drm_debug)
			{
				fprintf(stderr, "DRM: Scanout unavailable on all outputs, waiting for display resume\n");
			}
			continue;
		}
		scanoutSuspended = 0;
		lastCaptureError = 0;
		captureLostSinceMs = 0;	// captured a frame again; clear the session-loss grace timer
		kvm_drm_debug_dump_frame(desktopRgbBuffer, (uint32_t)SCREEN_WIDTH, (uint32_t)SCREEN_HEIGHT);

		if (SCREEN_WIDTH != reportedScreenWidth || SCREEN_HEIGHT != reportedScreenHeight || SCREEN_SEL != reportedScreenSel)
		{
			int oldTileHeightCount = TILE_HEIGHT_COUNT;
			kvm_drm_update_tile_geometry();
			kvm_send_resolution();
			kvm_send_display();
			reset_tile_info(oldTileHeightCount);
			forceTileReset = 0;
			reportedScreenWidth = SCREEN_WIDTH;
			reportedScreenHeight = SCREEN_HEIGHT;
			reportedScreenSel = SCREEN_SEL;
		}

		if (!displayListSent)
		{
			kvm_send_display_list();
			displayListSent = 1;
		}

		if (g_tileInfo == NULL)
		{
			reset_tile_info(0);
			forceTileReset = 0;
		}
		else if (forceTileReset)
		{
			reset_tile_info(TILE_HEIGHT_COUNT);
			forceTileReset = 0;
		}

		if (kvm_drm_send_dirty_tiles(desktopRgbBuffer, desktopRgbSize, &desktopBuffer, &desktopBufferSize) != 0)
		{
			g_shutdown = 1;
		}
	}

	if (desktopBuffer != NULL)
	{
		free(desktopBuffer);
		desktopBuffer = NULL;
		desktopBufferSize = 0;
	}
	if (jpeg_buffer != NULL)
	{
		free(jpeg_buffer);
		jpeg_buffer = NULL;
		jpeg_buffer_length = 0;
	}

	if (rgbBuffer != NULL)
	{
		free(rgbBuffer);
		rgbBuffer = NULL;
	}
	if (rgbRotatedBuffer != NULL)
	{
		free(rgbRotatedBuffer);
		rgbRotatedBuffer = NULL;
	}
	if (desktopRgbBuffer != NULL)
	{
		free(desktopRgbBuffer);
		desktopRgbBuffer = NULL;
	}
	kvm_drm_close_all_devices(devices, deviceCount);

	close(slave2master[1]);
	close(master2slave[0]);
	slave2master[1] = 0;
	master2slave[0] = 0;

	if (g_tileInfo != NULL)
	{
		for (r = 0; r < TILE_HEIGHT_COUNT; r++)
		{
			free(g_tileInfo[r]);
		}
		free(g_tileInfo);
		g_tileInfo = NULL;
	}
	if (tilebuffer != NULL)
	{
		free(tilebuffer);
		tilebuffer = NULL;
	}
	kvm_events_evdev_shutdown();
	g_enableEvents = 0;
	g_kvmBackendDRM = 0;

	return (void *)0;
#endif
}
