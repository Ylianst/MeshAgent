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
	_(drmIoctl) _(drmPrimeHandleToFD) _(drmDropMaster)

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

// Lets linux_kvm_drm_egl.c reach libdrm through the single dlopen here.
int kvm_drm_prime_handle_to_fd(int fd, unsigned int handle, unsigned int flags, int *prime_fd)
{
	return drmPrimeHandleToFD(fd, (uint32_t)handle, (uint32_t)flags, prime_fd);
}

// libwayland-client is dlopen'd rather than linked, so the agent runs where it's absent. It's
// used only for the xdg-output layout query, which falls back to KWin/raw DRM positions.
#define KVM_DRM_WAYLAND_SYMBOLS(_) \
	_(wl_display_connect) _(wl_display_disconnect) _(wl_display_roundtrip) \
	_(wl_proxy_marshal_flags) _(wl_proxy_get_version) _(wl_proxy_add_listener) _(wl_proxy_destroy)

#define KVM_DRM_WL_DECL_PTR(s) static __typeof__(s) *p_##s = NULL;
KVM_DRM_WAYLAND_SYMBOLS(KVM_DRM_WL_DECL_PTR)
#undef KVM_DRM_WL_DECL_PTR

static const struct wl_interface *p_wl_registry_interface = NULL;
static const struct wl_interface *p_wl_output_interface = NULL;
static void *g_libwayland_handle = NULL;

#define wl_display_connect p_wl_display_connect
#define wl_display_disconnect p_wl_display_disconnect
#define wl_display_roundtrip p_wl_display_roundtrip
#define wl_proxy_marshal_flags p_wl_proxy_marshal_flags
#define wl_proxy_get_version p_wl_proxy_get_version
#define wl_proxy_add_listener p_wl_proxy_add_listener
#define wl_proxy_destroy p_wl_proxy_destroy

// Hand-rolled versions of the <wayland-client-protocol.h> inline wrappers; the originals bake in
// link-time wl_proxy_*/wl_registry_interface references that would keep libwayland in NEEDED.
static struct wl_registry *kvm_wl_display_get_registry(struct wl_display *display)
{
	return (struct wl_registry *)wl_proxy_marshal_flags((struct wl_proxy *)display, 1 /*WL_DISPLAY_GET_REGISTRY*/,
		p_wl_registry_interface, wl_proxy_get_version((struct wl_proxy *)display), 0, NULL);
}
static int kvm_wl_registry_add_listener(struct wl_registry *registry, const struct wl_registry_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *)registry, (void (**)(void))listener, data);
}
static void *kvm_wl_registry_bind(struct wl_registry *registry, uint32_t name, const struct wl_interface *interface, uint32_t version)
{
	return (void *)wl_proxy_marshal_flags((struct wl_proxy *)registry, 0 /*WL_REGISTRY_BIND*/, interface, version, 0,
		name, interface->name, version, NULL);
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
	if (p_wl_registry_interface == NULL || p_wl_output_interface == NULL) { dlclose(h); return 0; }
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

int g_kvmBackendDRM = 0;
static int drm_debug = 0;

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

static int kvm_drm_write_all(int fd, const char *buffer, size_t len)
{
	size_t offset = 0;
	ssize_t written = 0;

	while (offset < len)
	{
		written = write(fd, buffer + offset, len - offset);
		if (written < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return -1;
		}
		if (written == 0)
		{
			return -1;
		}
		offset += (size_t)written;
	}
	return 0;
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

static bool kvm_drm_open_device_with_outputs(const char *explicit_device, int *out_fd, kvm_drm_output *outputs, int max_outputs, int *out_count, char *out_error, size_t out_error_size)
{
	int i;

	if (explicit_device != NULL && explicit_device[0] != 0)
	{
		int fd = open(explicit_device, O_RDWR | KVM_DRM_O_CLOEXEC | O_NONBLOCK);
		if (fd < 0)
		{
			char err[KVM_DRM_MAX_ERROR];
			snprintf(err, sizeof(err), "Unable to open DRM device: %s", explicit_device);
			kvm_drm_copy_error_message(out_error, out_error_size, err);
			return false;
		}
		if (kvm_drm_collect_active_outputs_on_fd(fd, explicit_device, outputs, max_outputs, out_count, true, true, out_error, out_error_size))
		{
			*out_fd = fd;
			return true;
		}
		close(fd);
		return false;
	}

	for (i = 0; i < 16; ++i)
	{
		char path[64];
		snprintf(path, sizeof(path), "/dev/dri/card%d", i);
		int fd = open(path, O_RDWR | KVM_DRM_O_CLOEXEC | O_NONBLOCK);
		if (fd < 0)
		{
			continue;
		}
		if (kvm_drm_collect_active_outputs_on_fd(fd, path, outputs, max_outputs, out_count, true, true, out_error, out_error_size))
		{
			*out_fd = fd;
			return true;
		}
		close(fd);
	}

	kvm_drm_copy_error_message(out_error, out_error_size, "No usable /dev/dri/card* device with active connector/CRTC scanout");
	return false;
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

		if (planeCount > 1)
		{
			char err[KVM_DRM_MAX_ERROR];
			char format[32];
			kvm_drm_format_fourcc(format, sizeof(format), fb2->pixel_format);
			snprintf(err, sizeof(err),
				"Framebuffer %u uses %d DRM planes (%s, modifier=0x%016" PRIx64 "); multi-plane scanout is not supported by this capture path",
				fb_id, planeCount, format, fb2->modifier);
			drmModeFreeFB2(fb2);
			kvm_drm_copy_error_message(out_error, out_error_size, err);
			return false;
		}

		if (fb2->handles[1] == 0 && fb2->handles[2] == 0 && fb2->handles[3] == 0)
		{
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
		}
		drmModeFreeFB2(fb2);
	}

	drmModeFB *fb = drmModeGetFB(fd, fb_id);
	if (fb == NULL)
	{
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

static int kvm_drm_find_output_by_name(const kvm_drm_output *outputs, int output_count, const char *name)
{
	int i;
	if (outputs == NULL || name == NULL || name[0] == 0)
	{
		return -1;
	}
	for (i = 0; i < output_count; ++i)
	{
		if (strcmp(outputs[i].connector_name, name) == 0)
		{
			return i;
		}
	}
	return -1;
}

static int kvm_drm_apply_kwin_screen(kvm_drm_output *outputs, int output_count, const char *name, int enabled, int x, int y, uint32_t width, uint32_t height, int *matched)
{
	int index;
	if (enabled != 1 || width == 0 || height == 0)
	{
		return 0;
	}
	index = kvm_drm_find_output_by_name(outputs, output_count, name);
	if (index < 0)
	{
		return 0;
	}

	outputs[index].x = x;
	outputs[index].y = y;
	outputs[index].width = width;
	outputs[index].height = height;
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
	struct wl_proxy *id = wl_proxy_marshal_flags((struct wl_proxy *)manager, 1, &zxdg_output_v1_interface, wl_proxy_get_version((struct wl_proxy *)manager), 0, NULL, output);
	return (struct zxdg_output_v1 *)id;
}

static void zxdg_output_manager_v1_destroy(struct zxdg_output_manager_v1 *manager)
{
	wl_proxy_marshal_flags((struct wl_proxy *)manager, 0, NULL, wl_proxy_get_version((struct wl_proxy *)manager), WL_MARSHAL_FLAG_DESTROY);
}

static int zxdg_output_v1_add_listener(struct zxdg_output_v1 *output, const struct zxdg_output_v1_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *)output, (void (**)(void))listener, data);
}

static void zxdg_output_v1_destroy(struct zxdg_output_v1 *output)
{
	wl_proxy_marshal_flags((struct wl_proxy *)output, 0, NULL, wl_proxy_get_version((struct wl_proxy *)output), WL_MARSHAL_FLAG_DESTROY);
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
	(void)data; (void)wl_output; (void)x; (void)y; (void)physical_width; (void)physical_height; (void)subpixel; (void)make; (void)model; (void)transform;
}

static void kvm_drm_wl_output_mode(void *data, struct wl_output *wl_output, uint32_t flags, int32_t width, int32_t height, int32_t refresh)
{
	(void)data; (void)wl_output; (void)flags; (void)width; (void)height; (void)refresh;
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
		bind_version = version >= 4 ? 4 : version;
		if (bind_version < 2) { bind_version = 2; }
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

static bool kvm_drm_apply_xdg_output_layout(kvm_drm_output *outputs, int output_count, bool logSelection)
{
	kvm_drm_wayland_layout_context ctx;
	kvm_drm_output tmp[KVM_DRM_MAX_OUTPUTS];
	int matched = 0;
	int i;

	if (outputs == NULL || output_count <= 0 || output_count > KVM_DRM_MAX_OUTPUTS)
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
		return false;
	}
	ctx.registry = kvm_wl_display_get_registry(ctx.display);
	if (ctx.registry == NULL)
	{
		kvm_drm_wayland_layout_context_cleanup(&ctx);
		return false;
	}
	kvm_wl_registry_add_listener(ctx.registry, &kvm_drm_registry_listener, &ctx);
	if (wl_display_roundtrip(ctx.display) < 0 || ctx.xdg_output_manager == NULL || ctx.output_count <= 0)
	{
		kvm_drm_wayland_layout_context_cleanup(&ctx);
		return false;
	}

	for (i = 0; i < ctx.output_count; ++i)
	{
		if (ctx.outputs[i].wl_output == NULL) { continue; }
		ctx.outputs[i].xdg_output = zxdg_output_manager_v1_get_xdg_output(ctx.xdg_output_manager, ctx.outputs[i].wl_output);
		if (ctx.outputs[i].xdg_output != NULL)
		{
			zxdg_output_v1_add_listener(ctx.outputs[i].xdg_output, &kvm_drm_xdg_output_listener, &ctx.outputs[i]);
		}
	}

	for (i = 0; i < 3; ++i)
	{
		if (wl_display_roundtrip(ctx.display) < 0)
		{
			kvm_drm_wayland_layout_context_cleanup(&ctx);
			return false;
		}
	}

	for (i = 0; i < ctx.output_count; ++i)
	{
		if (ctx.outputs[i].have_name == 0 || ctx.outputs[i].have_position == 0 || ctx.outputs[i].have_size == 0)
		{
			continue;
		}
		kvm_drm_apply_kwin_screen(tmp, output_count, ctx.outputs[i].name, 1, ctx.outputs[i].x, ctx.outputs[i].y, ctx.outputs[i].width, ctx.outputs[i].height, &matched);
	}

	if (matched != output_count)
	{
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
			fprintf(stderr, "DRM:   xdg-output[%d] %s pos=%d,%d size=%ux%u\n",
				i, outputs[i].connector_name, outputs[i].x, outputs[i].y, outputs[i].width, outputs[i].height);
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
				kvm_drm_apply_kwin_screen(tmp, output_count, name, enabled, x, y, width, height, &matched);
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
		kvm_drm_apply_kwin_screen(tmp, output_count, name, enabled, x, y, width, height, &matched);
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

static void kvm_drm_prepare_session_environment(int sessionUid)
{
	char runtimeDir[64];
	char busAddress[96];
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
	if (getenv("WAYLAND_DISPLAY") == NULL)
	{
		dir = opendir(runtimeDir);
		if (dir != NULL)
		{
			while ((ent = readdir(dir)) != NULL)
			{
				if (strncmp(ent->d_name, "wayland-", 8) == 0 && strstr(ent->d_name, ".lock") == NULL)
				{
					setenv("WAYLAND_DISPLAY", ent->d_name, 1);
					break;
				}
			}
			closedir(dir);
		}
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
	return 0;
}

#endif

void *kvm_server_mainloop_drm(void *parm)
{
	int sessionUid = (int)(intptr_t)parm;
	char pchRequest2[30000];
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	ssize_t cbBytesRead = 0;
	int r = 0;
	struct sigaction action;
	int displayListSent = 0;
	uint64_t lastFrameTimeMs = 0;
	int lastCaptureError = 0;
	int scanoutSuspended = 0;
	int forceTileReset = 0;
	int reportedScreenWidth = 0;
	int reportedScreenHeight = 0;
	int reportedScreenSel = -1;
	uint64_t lastOutputRefreshMs = 0;
	uint64_t lastRefreshFailureLogMs = 0;
	char lastRefreshFailure[KVM_DRM_MAX_ERROR];

	kvm_drm_init_debug();
	g_kvmBackendDRM = 1;
	g_enableEvents = kvm_events_evdev_init();
	if (!g_enableEvents)
	{
		kvm_send_error("evdev input injection unavailable");
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
	int fd = -1;
	char err[KVM_DRM_MAX_ERROR];
	kvm_drm_output outputs[KVM_DRM_MAX_OUTPUTS];
	int outputCount = 0;
	kvm_drm_desktop_layout layout;
	kvm_drm_frame_map map;
	kvm_drm_egl_context eglCtx;
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
	memset(&map, 0, sizeof(map));
	memset(&eglCtx, 0, sizeof(eglCtx));
	memset(lastRefreshFailure, 0, sizeof(lastRefreshFailure));
	map.dma_fd = -1;
	map.drm_fd = -1;

	if (!kvm_drm_load_libdrm())
	{
		kvm_send_error("libdrm is not installed; DRM capture backend unavailable");
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		return (void *)-1;
	}

	char *explicitDevice = getenv("MESH_KVM_DRM_DEVICE");
	if (!kvm_drm_open_device_with_outputs(explicitDevice, &fd, outputs, KVM_DRM_MAX_OUTPUTS, &outputCount, err, sizeof(err)) ||
		!kvm_drm_compute_desktop_layout(outputs, outputCount, &layout))
	{
		kvm_send_error(err[0] ? err : "Unable to compute DRM desktop layout");
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		return (void *)-1;
	}
	if (kvm_drm_drop_master_if_held(fd) != 0)
	{
		snprintf(err, sizeof(err), "drmDropMaster failed (errno=%d)", errno);
		kvm_send_error(err);
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		close(fd);
		return (void *)-1;
	}

	if (kvm_drm_drop_to_session_uid_with_caps(sessionUid, err, sizeof(err)) != 0)
	{
		fprintf(stderr, "DRM privilege setup failed: %s\n", err);
		kvm_send_error(err);
		kvm_events_evdev_shutdown();
		g_enableEvents = 0;
		g_kvmBackendDRM = 0;
		close(fd);
		return (void *)-1;
	}
	kvm_drm_prepare_session_environment(sessionUid);
	if (kvm_drm_apply_xdg_output_layout(outputs, outputCount, true) || kvm_drm_apply_kwin_layout(outputs, outputCount, true))
	{
		if (!kvm_drm_compute_desktop_layout(outputs, outputCount, &layout))
		{
			kvm_send_error("Unable to compute Wayland DRM desktop layout");
			kvm_events_evdev_shutdown();
			g_enableEvents = 0;
			g_kvmBackendDRM = 0;
			close(fd);
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

		if (selectResult > 0 && FD_ISSET(master2slave[0], &readset))
		{
			cbBytesRead = read(master2slave[0], pchRequest2 + len, sizeof(pchRequest2) - len);
			if (cbBytesRead <= 0)
			{
				g_shutdown = 1;
				break;
			}

			len += (int)cbBytesRead;
			ptr = 0;
			while ((ptr2 = kvm_server_inputdata((char *)pchRequest2 + ptr, len - ptr)) != 0)
			{
				ptr += ptr2;
			}
			if (ptr == len)
			{
				len = 0;
				ptr = 0;
			}
			else if (ptr > 0)
			{
				memmove(pchRequest2, pchRequest2 + ptr, len - ptr);
				len -= ptr;
				ptr = 0;
			}
		}

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
			kvm_drm_output refreshed[KVM_DRM_MAX_OUTPUTS];
			kvm_drm_desktop_layout refreshedLayout;
			int refreshedCount = 0;
			char refreshErr[KVM_DRM_MAX_ERROR];
			memset(refreshed, 0, sizeof(refreshed));
			memset(&refreshedLayout, 0, sizeof(refreshedLayout));
			if (kvm_drm_collect_active_outputs_on_fd(fd, outputs[0].device_path, refreshed, KVM_DRM_MAX_OUTPUTS, &refreshedCount, true, false, refreshErr, sizeof(refreshErr)))
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
						kvm_drm_destroy_map(&map);
						kvm_drm_egl_destroy_context(&eglCtx);
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
			memset(&frame, 0, sizeof(frame));

			if (!kvm_drm_get_scanout_frame(fd, outputs[outputIndex].crtc_id, outputs[outputIndex].crtc_index, &frame, err, sizeof(err)))
			{
				if (kvm_drm_is_transient_scanout_error(err))
				{
					scanoutSuspended = 1;
					forceTileReset = 1;
					continue;
				}
				if (lastCaptureError == 0)
				{
					kvm_send_error(err);
					lastCaptureError = 1;
				}
				continue;
			}

			if (frame.handle == 0 || frame.width == 0 || frame.height == 0)
			{
				if (lastCaptureError == 0)
				{
					kvm_send_error("DRM framebuffer is not readable (missing handle)");
					lastCaptureError = 1;
				}
				continue;
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

			if (frame.modifier != DRM_FORMAT_MOD_INVALID && frame.modifier != DRM_FORMAT_MOD_LINEAR)
			{
				if (drm_debug >= 2 && lastLoggedPath != 1)
				{
					fprintf(stderr, "DRM: Using GPU-assisted conversion for modifier 0x%016" PRIx64 "\n", frame.modifier);
					lastLoggedPath = 1;
				}

				converted = kvm_drm_egl_convert_to_rgb24_gpu(&eglCtx, fd, frame.width, frame.height, frame.pitch,
															 frame.offset, frame.format, frame.handle, frame.modifier,
															 rgbBuffer, rgbBufferSize, &rgbSize, err, sizeof(err));
				kvm_drm_close_gem_handle(fd, frame.handle);
				frame.handle = 0;
			}
			else
			{
				size_t required_bytes = (size_t)frame.offset + ((size_t)frame.pitch * (size_t)frame.height);
				if (!kvm_drm_map_framebuffer_handle(fd, frame.handle, required_bytes, &map, err, sizeof(err)))
				{
					kvm_drm_close_gem_handle(fd, frame.handle);
					converted = false;
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

					const uint8_t *src = map.addr + frame.offset;
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
			if (scanoutSuspended && drm_debug)
			{
				fprintf(stderr, "DRM: Scanout unavailable on all outputs, waiting for display resume\n");
			}
			continue;
		}
		scanoutSuspended = 0;
		lastCaptureError = 0;

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
	kvm_drm_destroy_map(&map);
	kvm_drm_egl_destroy_context(&eglCtx);
	if (fd >= 0)
	{
		close(fd);
		fd = -1;
	}

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
