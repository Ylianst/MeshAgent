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
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <drm_fourcc.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#ifndef O_CLOEXEC
#define KVM_DRM_O_CLOEXEC 0
#else
#define KVM_DRM_O_CLOEXEC O_CLOEXEC
#endif
#endif

#define KVM_DRM_MAX_ERROR 256

int g_kvmBackendDRM = 0;
static int drm_debug = 1;

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
} kvm_drm_output;

typedef struct kvm_drm_frame_map
{
	uint32_t handle;
	uint8_t *addr;
	size_t size;
	int dma_fd;
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
} kvm_drm_scanout_frame;

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
	map->handle = 0;
	map->addr = NULL;
	map->size = 0;
	map->dma_fd = -1;
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

static bool kvm_drm_find_active_output_on_fd(int fd, const char *path, kvm_drm_output *out, char *out_error, size_t out_error_size)
{
	drmModeRes *res = drmModeGetResources(fd);
	if (res == NULL)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "drmModeGetResources failed");
		return false;
	}

	bool found = false;
	int i;
	for (i = 0; i < res->count_connectors; ++i)
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
		if (crtc_index < 0)
		{
			drmModeFreeConnector(conn);
			continue;
		}

		snprintf(out->device_path, sizeof(out->device_path), "%s", path);
		snprintf(out->connector_name, sizeof(out->connector_name), "%s-%u", kvm_drm_connector_type_name(conn->connector_type), conn->connector_type_id);
		out->connector_id = conn->connector_id;
		out->crtc_id = crtc_id;
		out->crtc_index = crtc_index;

		found = true;
		drmModeFreeConnector(conn);
		break;
	}

	drmModeFreeResources(res);

	if (!found)
	{
		char err[KVM_DRM_MAX_ERROR];
		snprintf(err, sizeof(err), "No connected display with active CRTC on %s", path);
		kvm_drm_copy_error_message(out_error, out_error_size, err);
	}
	return found;
}

static bool kvm_drm_open_device_with_output(const char *explicit_device, int *out_fd, kvm_drm_output *out, char *out_error, size_t out_error_size)
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
		if (kvm_drm_find_active_output_on_fd(fd, explicit_device, out, out_error, out_error_size))
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
		if (kvm_drm_find_active_output_on_fd(fd, path, out, out_error, out_error_size))
		{
			*out_fd = fd;
			return true;
		}
		close(fd);
	}

	kvm_drm_copy_error_message(out_error, out_error_size, "No usable /dev/dri/card* device with an active connector/CRTC");
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

static bool kvm_drm_get_scanout_frame(int fd, uint32_t crtc_id, int crtc_index, kvm_drm_scanout_frame *out, char *out_error, size_t out_error_size)
{
	drmModeCrtc *crtc = drmModeGetCrtc(fd, crtc_id);
	if (crtc == NULL)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "drmModeGetCrtc failed");
		return false;
	}

	uint32_t fb_id = crtc->buffer_id;
	drmModeFreeCrtc(crtc);

	if (fb_id == 0)
	{
		fb_id = kvm_drm_get_plane_fb_id(fd, crtc_id, crtc_index);
	}
	if (fb_id == 0)
	{
		kvm_drm_copy_error_message(out_error, out_error_size, "Active CRTC has no framebuffer");
		return false;
	}

	bool have_fb2_meta = false;
	drmModeFB2 *fb2 = drmModeGetFB2(fd, fb_id);
	if (fb2 != NULL)
	{
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
	int64_t nFramesConverted = 0;

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
	kvm_drm_output output;
	kvm_drm_frame_map map;
	kvm_drm_egl_context eglCtx;
	unsigned char *rgbBuffer = NULL;
	size_t rgbBufferSize = 0;
	char *desktopBuffer = NULL;
	long long desktopBufferSize = 0;
	memset(&output, 0, sizeof(output));
	memset(&map, 0, sizeof(map));
	memset(&eglCtx, 0, sizeof(eglCtx));
	map.dma_fd = -1;

	char *explicitDevice = getenv("MESH_KVM_DRM_DEVICE");
	if (!kvm_drm_open_device_with_output(explicitDevice, &fd, &output, err, sizeof(err)))
	{
		kvm_send_error(err);
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

		kvm_drm_scanout_frame frame;
		size_t rgbSize = 0;
		bool converted = false;
		memset(&frame, 0, sizeof(frame));

		if (!kvm_drm_get_scanout_frame(fd, output.crtc_id, output.crtc_index, &frame, err, sizeof(err)))
		{
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

		if (SCREEN_WIDTH != (int)frame.width || SCREEN_HEIGHT != (int)frame.height)
		{
			int oldTileHeightCount = TILE_HEIGHT_COUNT;
			SCREEN_WIDTH = (int)frame.width;
			SCREEN_HEIGHT = (int)frame.height;
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
			kvm_send_resolution();
			kvm_send_display();
			reset_tile_info(oldTileHeightCount);
		}

		if (!displayListSent)
		{
			kvm_send_display_list();
			displayListSent = 1;
		}

		rgbSize = (size_t)frame.width * (size_t)frame.height * 3u;
		if (rgbBufferSize < rgbSize)
		{
			unsigned char *tmp = (unsigned char *)realloc(rgbBuffer, rgbSize);
			if (tmp == NULL)
				ILIBCRITICALEXIT(254);
			rgbBuffer = tmp;
			rgbBufferSize = rgbSize;
		}

		if (frame.modifier != DRM_FORMAT_MOD_INVALID && frame.modifier != DRM_FORMAT_MOD_LINEAR)
		{
			if (drm_debug && nFramesConverted == 0)
				printf("Attempting GPU-assisted conversion for modifier 0x%016" PRIx64 "\n", frame.modifier);

			converted = kvm_drm_egl_convert_to_rgb24_gpu(&eglCtx, fd, frame.width, frame.height, frame.pitch,
														 frame.offset, frame.format, frame.handle, frame.modifier,
														 rgbBuffer, rgbBufferSize, &rgbSize, err, sizeof(err));
		}
		else
		{
			size_t required_bytes = (size_t)frame.offset + ((size_t)frame.pitch * (size_t)frame.height);
			if (!kvm_drm_map_framebuffer_handle(fd, frame.handle, required_bytes, &map, err, sizeof(err)))
			{
				converted = false;
			}
			else
			{
				if (drm_debug && nFramesConverted == 0)
					printf("Performing CPU readback conversion for format 0x%08X\n", frame.format);

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
		lastCaptureError = 0;
		nFramesConverted++;

		if (g_tileInfo == NULL)
		{
			reset_tile_info(0);
		}

		if (kvm_drm_send_dirty_tiles(rgbBuffer, rgbSize, &desktopBuffer, &desktopBufferSize) != 0)
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
