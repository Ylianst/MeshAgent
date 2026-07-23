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
	GLuint out_tex;
	GLint attr_pos;
	GLint attr_tex;
	GLint u_tex;
#endif

	uint8_t *rgba_readback;
	size_t rgba_readback_cap;
} kvm_drm_egl_context;

bool kvm_drm_egl_convert_to_rgb24_gpu(kvm_drm_egl_context *ctx, int drm_fd, uint32_t width, uint32_t height, uint32_t pitch,
	uint32_t offset, uint32_t format, uint32_t handle, uint64_t modifier, uint8_t *rgb,
	size_t rgb_capacity, size_t *rgb_size_out, char *out_error, size_t out_error_size);
void kvm_drm_egl_destroy_context(kvm_drm_egl_context *ctx);

#endif
