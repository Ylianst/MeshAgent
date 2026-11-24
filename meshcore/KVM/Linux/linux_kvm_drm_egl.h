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

#ifndef LINUX_KVM_DRM_EGL_H_
#define LINUX_KVM_DRM_EGL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__linux__)
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#endif

// What does this EGL code have to do with DRM screen capture?
// All we're doing here is blitting the entire screen from the GPU-native memory layout into
// a simple linear RGB buffer. At the point where we capture the frame via DRM, the memory
// can be in a GPU-native tiled memory layout. Instead of trying to cater for every possible
// GPU memory layout in present and future, we rather just use EGL to perform a full screen
// copy for us.
// This is not always required. Sometimes the DRM buffer is already in a linear format,
// in which case we skip this, and just perform pixel format conversion.

#define KVM_DRM_EGL_MAX_ERROR 256

#if defined(__linux__)
#define KVM_DRM_EGL_TARGETS 16
typedef struct kvm_drm_egl_target
{
	GLuint out_tex;
	GLuint prev_tex;
	GLuint diff_tex;
	// The linear buffers behind out_tex and prev_tex, swapped with them. NULL when the texture is an ordinary one.
	void *out_bo;
	void *prev_bo;
	EGLImageKHR out_img;
	EGLImageKHR prev_img;
	int w;
	int h;
	int diff_w;
	int diff_h;
	bool have_prev;
} kvm_drm_egl_target;
#endif

typedef struct kvm_drm_egl_context
{
	bool initialized;
	bool permanently_failed;
	char fail_reason[KVM_DRM_EGL_MAX_ERROR];

#if defined(__linux__)
	EGLDisplay dpy;
	EGLContext ctx;
	EGLSurface surf;
	EGLConfig cfg;
	int surf_w;
	int surf_h;

	PFNEGLCREATEIMAGEKHRPROC eglCreateImageKHRFn;
	PFNEGLDESTROYIMAGEKHRPROC eglDestroyImageKHRFn;
	PFNGLEGLIMAGETARGETTEXTURE2DOESPROC glEGLImageTargetTexture2DOESFn;

	GLuint program;
	GLuint vbo;
	GLuint fbo;
	GLint attr_pos;
	GLint attr_tex;
	GLint u_tex;

	// Changed-tile readback: a second pass compares a frame with the previous one of the same output and writes one value per tile
	bool es3;
	GLuint diff_program;
	GLint diff_attr_pos;
	GLint diff_u_cur;
	GLint diff_u_prev;
	GLint diff_u_size;
	GLint diff_u_tile;
	// Render targets per output, because the previous frame of each output stays on the GPU. Target 0 also serves the RGB24 path.
	kvm_drm_egl_target targets[KVM_DRM_EGL_TARGETS];
	// A GBM device on the DRM node, for render targets in linear buffers. linear_off is set when that does not work on this driver.
	int drm_fd;
	void *gbm;
	bool linear_off;
#endif

	uint8_t *rgba_readback;
	size_t rgba_readback_cap;

	// Set by the caller for a call without an RGB24 buffer. The frame is read back into direct_dest, a 4 byte per pixel buffer
	// with the bottom row first that can hold several outputs: direct_dest_row_length pixels per row, this output at
	// column direct_dest_x, its bottom row in buffer row direct_dest_row0.
	int direct_target;
	uint8_t *direct_dest;
	int direct_dest_row_length;
	int direct_dest_x;
	int direct_dest_row0;
	int direct_tile_size;	// The tile size, or 0 to read the whole frame back
	int direct_force_full;	// 1 when direct_dest does not hold this output's previous frame
	// After such a call, when changed_valid is set: one byte per tile of this output, row by row from the top, 0 where the tile equals the previous frame.
	// direct_dest then got new pixels only for the changed tiles.
	bool changed_valid;
	uint8_t *changed_tiles;
	size_t changed_tiles_cap;
	uint8_t *diff_readback;
} kvm_drm_egl_context;

bool kvm_drm_egl_convert_to_rgb24_gpu(kvm_drm_egl_context *ctx, int drm_fd, uint32_t width, uint32_t height,
	int plane_count, const uint32_t *plane_handles, const uint32_t *plane_pitches, const uint32_t *plane_offsets,
	uint32_t format, uint64_t modifier, uint8_t *rgb,
	size_t rgb_capacity, size_t *rgb_size_out, char *out_error, size_t out_error_size);
void kvm_drm_egl_destroy_context(kvm_drm_egl_context *ctx);

#endif
