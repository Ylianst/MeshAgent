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

// Detecting rotation on Wayland turns out to be really platform-specific.
// I tried first reading the data via the official DRM APIs, but that didn't
// work on a Raspberry Pi or a qemu VM, so I gave up on that. It seems like
// the only practical solution is to support the various Wayland compositors,
// and read their state out directly.
// So right now the only way to get screen rotation to work on Wayland
// is to specify it via an env var, with 0,90,180,270, eg:
// For portrait-right:
// MESH_KVM_ROTATION=270

#include "linux_kvm_rotated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void kvm_send_error(char *msg);

const char *kvm_drm_rotation_name(kvm_drm_rotation rotation)
{
	switch (rotation)
	{
	case KVM_DRM_ROTATION_90:
		return "90";
	case KVM_DRM_ROTATION_180:
		return "180";
	case KVM_DRM_ROTATION_270:
		return "270";
	case KVM_DRM_ROTATION_0:
	default:
		return "0";
	}
}

int kvm_drm_get_forced_rotation(kvm_drm_rotation *out_rotation, int log_enabled)
{
	static int initialized = 0;
	static int have_forced = 0;
	static kvm_drm_rotation forced_rotation = KVM_DRM_ROTATION_0;

	if (!initialized)
	{
		const char *value = getenv("MESH_KVM_ROTATION");
		static kvm_drm_rotation fromenv = (kvm_drm_rotation) -1;
		initialized = 1;
		if (value != NULL && value[0] != 0)
		{
			if (strcmp(value, "0") == 0)
			{
				fromenv = KVM_DRM_ROTATION_0;
			}
			else if (strcmp(value, "90") == 0)
			{
				fromenv = KVM_DRM_ROTATION_90;
			}
			else if (strcmp(value, "180") == 0)
			{
				fromenv = KVM_DRM_ROTATION_180;
			}
			else if (strcmp(value, "270") == 0)
			{
				fromenv = KVM_DRM_ROTATION_270;
			}

			if (fromenv != (kvm_drm_rotation) -1)
			{
				have_forced = 1;
				forced_rotation = fromenv;
				if (log_enabled)
				{
					fprintf(stderr, "DRM: forced rotation enabled via MESH_KVM_ROTATION=%s\n", value);
				}
			}
			else if (log_enabled)
			{
				fprintf(stderr, "DRM: invalid MESH_KVM_ROTATION value '%s' (expected 0/90/180/270)\n", value);
			}
		}
	}

	if (!have_forced)
	{
		return 0;
	}

	*out_rotation = forced_rotation;
	return 1;
}

void kvm_drm_rotate_rgb24(const uint8_t *src, uint32_t src_width, uint32_t src_height, kvm_drm_rotation rotation, uint8_t *dst)
{
	size_t src_stride = ((size_t)src_width) * 3u;
	size_t dst_stride = ((size_t)((rotation == KVM_DRM_ROTATION_90 || rotation == KVM_DRM_ROTATION_270) ? src_height : src_width)) * 3u;
	uint32_t x;
	uint32_t y;

	if (src == NULL || dst == NULL)
	{
		kvm_send_error("Invalid RGB rotation buffer");
		return;
	}

	switch (rotation)
	{
	case KVM_DRM_ROTATION_90:
		for (y = 0; y < src_height; ++y)
		{
			const uint8_t *s = src + (((size_t)y) * src_stride);
			uint8_t *d = dst + (((size_t)(src_width - 1u)) * dst_stride) + (((size_t)y) * 3u);
			for (x = 0; x < src_width; ++x)
			{
				d[0] = s[0];
				d[1] = s[1];
				d[2] = s[2];
				s += 3;
				d -= dst_stride;
			}
		}
		break;
	case KVM_DRM_ROTATION_180:
		for (y = 0; y < src_height; ++y)
		{
			const uint8_t *s = src + (((size_t)y) * src_stride);
			uint8_t *d = dst + (((size_t)(src_height - 1u - y)) * dst_stride) + (((size_t)(src_width - 1u)) * 3u);
			for (x = 0; x < src_width; ++x)
			{
				d[0] = s[0];
				d[1] = s[1];
				d[2] = s[2];
				s += 3;
				d -= 3;
			}
		}
		break;
	case KVM_DRM_ROTATION_270:
		for (y = 0; y < src_height; ++y)
		{
			const uint8_t *s = src + (((size_t)y) * src_stride);
			uint8_t *d = dst + (((size_t)(src_height - 1u - y)) * 3u);
			for (x = 0; x < src_width; ++x)
			{
				d[0] = s[0];
				d[1] = s[1];
				d[2] = s[2];
				s += 3;
				d += dst_stride;
			}
		}
		break;
	case KVM_DRM_ROTATION_0:
	default:
		break;
	}
}
