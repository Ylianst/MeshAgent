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

#include "linux_kvm_drm_egl.h"
#include "meshcore/meshdefines.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <drm_fourcc.h>
#include <xf86drm.h>
#endif

#if defined(__linux__)
#ifndef O_CLOEXEC
#define KVM_DRM_EGL_CLOEXEC 0
#else
#define KVM_DRM_EGL_CLOEXEC O_CLOEXEC
#endif
#endif

static void kvm_drm_egl_copy_error_message(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0) { return; }
	if (src == NULL)
	{
		dst[0] = '\0';
		return;
	}

	size_t n = strlen(src);
	if (n >= dst_size) { n = dst_size - 1; }
	memcpy(dst, src, n);
	dst[n] = '\0';
}

#if defined(__linux__)

static void kvm_drm_egl_format_egl_error(char *dst, size_t dst_size, const char *prefix, EGLint err)
{
	snprintf(dst, dst_size, "%s: 0x%04x", prefix, (unsigned int)err);
}

static bool kvm_drm_egl_fail_with_persistent_error(kvm_drm_egl_context *g, char *out_error, size_t out_error_size, const char *msg)
{
	g->permanently_failed = true;
	kvm_drm_egl_copy_error_message(g->fail_reason, sizeof(g->fail_reason), msg);
	kvm_drm_egl_copy_error_message(out_error, out_error_size, msg);
	return false;
}

static GLuint kvm_drm_egl_compile_shader(GLenum type, const char *src, char *log_out, size_t log_size)
{
	GLuint shader = glCreateShader(type);
	if (shader == 0) { return 0; }

	glShaderSource(shader, 1, &src, NULL);
	glCompileShader(shader);

	GLint ok = GL_FALSE;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &ok);
	if (ok != GL_TRUE)
	{
		if (log_out != NULL && log_size > 0)
		{
			GLint info_len = 0;
			glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &info_len);
			if (info_len > 1)
			{
				GLint read_len = info_len;
				if ((size_t)read_len >= log_size) { read_len = (GLint)(log_size - 1); }
				glGetShaderInfoLog(shader, read_len, NULL, log_out);
				log_out[read_len] = '\0';
			}
			else
			{
				kvm_drm_egl_copy_error_message(log_out, log_size, "Shader compilation failed");
			}
		}

		glDeleteShader(shader);
		return 0;
	}

	return shader;
}

static bool kvm_drm_egl_init_gpu_readback(kvm_drm_egl_context *g, char *out_error, size_t out_error_size)
{
	if (g->initialized) { return true; }
	if (g->permanently_failed)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, g->fail_reason);
		return false;
	}

	PFNEGLGETPLATFORMDISPLAYEXTPROC eglGetPlatformDisplayEXTFn =
		(PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
	if (eglGetPlatformDisplayEXTFn != NULL)
	{
		g->dpy = eglGetPlatformDisplayEXTFn(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
	}
	if (g->dpy == EGL_NO_DISPLAY)
	{
		g->dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
	}
	if (g->dpy == EGL_NO_DISPLAY)
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, "Failed to acquire EGL display");
	}

	EGLint major = 0;
	EGLint minor = 0;
	if (!eglInitialize(g->dpy, &major, &minor))
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglInitialize failed", eglGetError());
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}

	if (!eglBindAPI(EGL_OPENGL_ES_API))
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglBindAPI(EGL_OPENGL_ES_API) failed", eglGetError());
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}

	const EGLint cfg_attribs[] = {
		EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
		EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
		EGL_RED_SIZE, 8,
		EGL_GREEN_SIZE, 8,
		EGL_BLUE_SIZE, 8,
		EGL_ALPHA_SIZE, 8,
		EGL_NONE
	};
	EGLint num_cfg = 0;
	if (!eglChooseConfig(g->dpy, cfg_attribs, &g->cfg, 1, &num_cfg) || num_cfg != 1)
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, "eglChooseConfig failed");
	}

	const EGLint ctx_attribs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
	g->ctx = eglCreateContext(g->dpy, g->cfg, EGL_NO_CONTEXT, ctx_attribs);
	if (g->ctx == EGL_NO_CONTEXT)
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglCreateContext failed", eglGetError());
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}

	const EGLint surf_attribs[] = { EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE };
	g->surf = eglCreatePbufferSurface(g->dpy, g->cfg, surf_attribs);
	if (g->surf == EGL_NO_SURFACE)
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglCreatePbufferSurface failed", eglGetError());
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}
	g->surf_w = 1;
	g->surf_h = 1;

	if (!eglMakeCurrent(g->dpy, g->surf, g->surf, g->ctx))
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglMakeCurrent failed", eglGetError());
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}

	g->eglCreateImageKHRFn = (PFNEGLCREATEIMAGEKHRPROC)eglGetProcAddress("eglCreateImageKHR");
	g->eglDestroyImageKHRFn = (PFNEGLDESTROYIMAGEKHRPROC)eglGetProcAddress("eglDestroyImageKHR");
	g->glEGLImageTargetTexture2DOESFn =
		(PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)eglGetProcAddress("glEGLImageTargetTexture2DOES");
	if (g->eglCreateImageKHRFn == NULL || g->eglDestroyImageKHRFn == NULL || g->glEGLImageTargetTexture2DOESFn == NULL)
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size,
			"Missing required EGL/GLES extension entrypoints for dma-buf import");
	}

	const char *vs_src = "attribute vec2 aPos;\n"
		"attribute vec2 aTex;\n"
		"varying vec2 vTex;\n"
		"void main(){ gl_Position=vec4(aPos,0.0,1.0); vTex=aTex; }\n";
	const char *fs_src = "precision mediump float;\n"
		"varying vec2 vTex;\n"
		"uniform sampler2D uTex;\n"
		"void main(){ gl_FragColor = texture2D(uTex, vTex); }\n";

	char vs_log[128] = { 0 };
	char fs_log[128] = { 0 };
	GLuint vs = kvm_drm_egl_compile_shader(GL_VERTEX_SHADER, vs_src, vs_log, sizeof(vs_log));
	GLuint fs = kvm_drm_egl_compile_shader(GL_FRAGMENT_SHADER, fs_src, fs_log, sizeof(fs_log));
	if (vs == 0 || fs == 0)
	{
		if (vs != 0) { glDeleteShader(vs); }
		if (fs != 0) { glDeleteShader(fs); }

		char err[512] = { 0 };
		if (vs_log[0] != '\0' && fs_log[0] != '\0')
		{
			snprintf(err, sizeof(err), "Failed to compile GLES shaders [VS: %s] [FS: %s]", vs_log, fs_log);
		}
		else if (vs_log[0] != '\0')
		{
			snprintf(err, sizeof(err), "Failed to compile GLES shaders [VS: %s]", vs_log);
		}
		else if (fs_log[0] != '\0')
		{
			snprintf(err, sizeof(err), "Failed to compile GLES shaders [FS: %s]", fs_log);
		}
		else
		{
			kvm_drm_egl_copy_error_message(err, sizeof(err), "Failed to compile GLES shaders");
		}

		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, err);
	}

	g->program = glCreateProgram();
	glAttachShader(g->program, vs);
	glAttachShader(g->program, fs);
	glLinkProgram(g->program);
	glDeleteShader(vs);
	glDeleteShader(fs);

	GLint linked = GL_FALSE;
	glGetProgramiv(g->program, GL_LINK_STATUS, &linked);
	if (linked != GL_TRUE)
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size, "Failed to link GLES program");
	}

	g->attr_pos = glGetAttribLocation(g->program, "aPos");
	g->attr_tex = glGetAttribLocation(g->program, "aTex");
	g->u_tex = glGetUniformLocation(g->program, "uTex");
	if (g->attr_pos < 0 || g->attr_tex < 0 || g->u_tex < 0)
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size,
			"Failed to resolve shader attribute/uniform locations");
	}

	const GLfloat quad[] = {
		-1.0f, -1.0f, 0.0f, 1.0f,
		1.0f, -1.0f, 1.0f, 1.0f,
		-1.0f, 1.0f, 0.0f, 0.0f,
		1.0f, 1.0f, 1.0f, 0.0f
	};
	glGenBuffers(1, &g->vbo);
	glBindBuffer(GL_ARRAY_BUFFER, g->vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(quad), quad, GL_STATIC_DRAW);

	glGenFramebuffers(1, &g->fbo);
	glGenTextures(1, &g->out_tex);

	g->initialized = true;
	return true;
}

static bool kvm_drm_egl_ensure_gpu_target_size(kvm_drm_egl_context *g, int width, int height, char *out_error, size_t out_error_size)
{
	if (g->surf_w == width && g->surf_h == height) { return true; }

	if (g->surf != EGL_NO_SURFACE)
	{
		eglDestroySurface(g->dpy, g->surf);
		g->surf = EGL_NO_SURFACE;
	}

	const EGLint surf_attribs[] = { EGL_WIDTH, width, EGL_HEIGHT, height, EGL_NONE };
	g->surf = eglCreatePbufferSurface(g->dpy, g->cfg, surf_attribs);
	if (g->surf == EGL_NO_SURFACE)
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglCreatePbufferSurface(size) failed", eglGetError());
		kvm_drm_egl_copy_error_message(out_error, out_error_size, err);
		return false;
	}
	g->surf_w = width;
	g->surf_h = height;

	if (!eglMakeCurrent(g->dpy, g->surf, g->surf, g->ctx))
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglMakeCurrent(size) failed", eglGetError());
		kvm_drm_egl_copy_error_message(out_error, out_error_size, err);
		return false;
	}

	glBindTexture(GL_TEXTURE_2D, g->out_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);

	glBindFramebuffer(GL_FRAMEBUFFER, g->fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, g->out_tex, 0);
	if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "GPU readback framebuffer is incomplete");
		return false;
	}

	return true;
}

#endif

bool kvm_drm_egl_convert_to_rgb24_gpu(kvm_drm_egl_context *ctx, int drm_fd, uint32_t width, uint32_t height, uint32_t pitch,
	uint32_t offset, uint32_t format, uint32_t handle, uint64_t modifier, uint8_t *rgb,
	size_t rgb_capacity, size_t *rgb_size_out, char *out_error, size_t out_error_size)
{
#if !defined(__linux__)
	UNREFERENCED_PARAMETER(ctx);
	UNREFERENCED_PARAMETER(drm_fd);
	UNREFERENCED_PARAMETER(width);
	UNREFERENCED_PARAMETER(height);
	UNREFERENCED_PARAMETER(pitch);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(format);
	UNREFERENCED_PARAMETER(handle);
	UNREFERENCED_PARAMETER(modifier);
	UNREFERENCED_PARAMETER(rgb);
	UNREFERENCED_PARAMETER(rgb_capacity);
	UNREFERENCED_PARAMETER(rgb_size_out);
	kvm_drm_egl_copy_error_message(out_error, out_error_size, "DRM EGL GPU conversion is not supported on this platform");
	return false;
#else
	if (ctx == NULL)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "kvm_drm_egl context is null");
		return false;
	}

	if (rgb_size_out != NULL) { *rgb_size_out = 0; }

	if (width == 0 || height == 0)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "Invalid frame dimensions");
		return false;
	}
	if (width > (uint32_t)INT_MAX || height > (uint32_t)INT_MAX)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "Frame dimensions are too large");
		return false;
	}

	if (!kvm_drm_egl_init_gpu_readback(ctx, out_error, out_error_size)) { return false; }
	if (!kvm_drm_egl_ensure_gpu_target_size(ctx, (int)width, (int)height, out_error, out_error_size)) { return false; }

	int dmabuf_fd = -1;
	if (drmPrimeHandleToFD(drm_fd, handle, KVM_DRM_EGL_CLOEXEC | DRM_RDWR, &dmabuf_fd) != 0 || dmabuf_fd < 0)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "drmPrimeHandleToFD failed for GPU path");
		return false;
	}

	EGLint attrs[20];
	int a = 0;
	attrs[a++] = EGL_WIDTH;
	attrs[a++] = (EGLint)width;
	attrs[a++] = EGL_HEIGHT;
	attrs[a++] = (EGLint)height;
	attrs[a++] = EGL_LINUX_DRM_FOURCC_EXT;
	attrs[a++] = (EGLint)format;
	attrs[a++] = EGL_DMA_BUF_PLANE0_FD_EXT;
	attrs[a++] = dmabuf_fd;
	attrs[a++] = EGL_DMA_BUF_PLANE0_OFFSET_EXT;
	attrs[a++] = (EGLint)offset;
	attrs[a++] = EGL_DMA_BUF_PLANE0_PITCH_EXT;
	attrs[a++] = (EGLint)pitch;
	if (modifier != DRM_FORMAT_MOD_INVALID)
	{
		attrs[a++] = EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT;
		attrs[a++] = (EGLint)(modifier & 0xFFFFFFFFu);
		attrs[a++] = EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT;
		attrs[a++] = (EGLint)((modifier >> 32) & 0xFFFFFFFFu);
	}
	attrs[a++] = EGL_NONE;

	EGLImageKHR image = ctx->eglCreateImageKHRFn(ctx->dpy, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, NULL, attrs);
	close(dmabuf_fd);
	if (image == EGL_NO_IMAGE_KHR)
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		kvm_drm_egl_format_egl_error(err, sizeof(err), "eglCreateImageKHR(dma-buf) failed", eglGetError());
		kvm_drm_egl_copy_error_message(out_error, out_error_size, err);
		return false;
	}

	GLuint src_tex = 0;
	glGenTextures(1, &src_tex);
	glBindTexture(GL_TEXTURE_2D, src_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	ctx->glEGLImageTargetTexture2DOESFn(GL_TEXTURE_2D, (GLeglImageOES)image);

	glBindFramebuffer(GL_FRAMEBUFFER, ctx->fbo);
	glViewport(0, 0, (GLsizei)width, (GLsizei)height);
	glUseProgram(ctx->program);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, src_tex);
	glUniform1i(ctx->u_tex, 0);
	glBindBuffer(GL_ARRAY_BUFFER, ctx->vbo);
	glEnableVertexAttribArray((GLuint)ctx->attr_pos);
	glEnableVertexAttribArray((GLuint)ctx->attr_tex);
	glVertexAttribPointer((GLuint)ctx->attr_pos, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(GLfloat), (void*)(0));
	glVertexAttribPointer((GLuint)ctx->attr_tex, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(GLfloat), (void*)(2 * sizeof(GLfloat)));
	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
	glDisableVertexAttribArray((GLuint)ctx->attr_pos);
	glDisableVertexAttribArray((GLuint)ctx->attr_tex);
	glFinish();

	const size_t rgba_size = (size_t)width * (size_t)height * 4u;
	if (ctx->rgba_readback_cap < rgba_size)
	{
		uint8_t *tmp = (uint8_t*)realloc(ctx->rgba_readback, rgba_size);
		if (tmp == NULL)
		{
			ctx->eglDestroyImageKHRFn(ctx->dpy, image);
			glDeleteTextures(1, &src_tex);
			kvm_drm_egl_copy_error_message(out_error, out_error_size, "Failed to allocate temporary RGBA readback buffer");
			return false;
		}
		ctx->rgba_readback = tmp;
		ctx->rgba_readback_cap = rgba_size;
	}

	glReadPixels(0, 0, (GLsizei)width, (GLsizei)height, GL_RGBA, GL_UNSIGNED_BYTE, ctx->rgba_readback);

	ctx->eglDestroyImageKHRFn(ctx->dpy, image);
	glDeleteTextures(1, &src_tex);

	const size_t rgb_size = (size_t)width * (size_t)height * 3u;
	if (rgb == NULL)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "Output RGB pointer is null");
		return false;
	}
	if (rgb_capacity < rgb_size)
	{
		char msg[KVM_DRM_EGL_MAX_ERROR];
		snprintf(msg, sizeof(msg), "Output RGB buffer too small: need=%zu have=%zu", rgb_size, rgb_capacity);
		kvm_drm_egl_copy_error_message(out_error, out_error_size, msg);
		return false;
	}

	for (uint32_t y = 0; y < height; ++y)
	{
		const uint8_t *src_row = ctx->rgba_readback + ((size_t)(height - 1u - y) * (size_t)width * 4u);
		uint8_t *dst = rgb + ((size_t)y * (size_t)width * 3u);
		for (uint32_t x = 0; x < width; ++x)
		{
			dst[0] = src_row[0];
			dst[1] = src_row[1];
			dst[2] = src_row[2];
			dst += 3;
			src_row += 4;
		}
	}

	if (rgb_size_out != NULL) { *rgb_size_out = rgb_size; }

	return true;
#endif
}

void kvm_drm_egl_destroy_context(kvm_drm_egl_context *ctx)
{
	if (ctx == NULL) { return; }

	free(ctx->rgba_readback);
	ctx->rgba_readback = NULL;
	ctx->rgba_readback_cap = 0;

#if defined(__linux__)
	if (ctx->program != 0)
	{
		glDeleteProgram(ctx->program);
		ctx->program = 0;
	}
	if (ctx->vbo != 0)
	{
		glDeleteBuffers(1, &ctx->vbo);
		ctx->vbo = 0;
	}
	if (ctx->fbo != 0)
	{
		glDeleteFramebuffers(1, &ctx->fbo);
		ctx->fbo = 0;
	}
	if (ctx->out_tex != 0)
	{
		glDeleteTextures(1, &ctx->out_tex);
		ctx->out_tex = 0;
	}

	if (ctx->dpy != EGL_NO_DISPLAY)
	{
		if (ctx->ctx != EGL_NO_CONTEXT)
		{
			eglMakeCurrent(ctx->dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
			eglDestroyContext(ctx->dpy, ctx->ctx);
			ctx->ctx = EGL_NO_CONTEXT;
		}
		if (ctx->surf != EGL_NO_SURFACE)
		{
			eglDestroySurface(ctx->dpy, ctx->surf);
			ctx->surf = EGL_NO_SURFACE;
		}
		eglTerminate(ctx->dpy);
		ctx->dpy = EGL_NO_DISPLAY;
	}

	ctx->cfg = (EGLConfig)0;
	ctx->surf_w = 0;
	ctx->surf_h = 0;
	ctx->eglCreateImageKHRFn = NULL;
	ctx->eglDestroyImageKHRFn = NULL;
	ctx->glEGLImageTargetTexture2DOESFn = NULL;
	ctx->attr_pos = 0;
	ctx->attr_tex = 0;
	ctx->u_tex = 0;
#endif

	ctx->initialized = false;
	ctx->permanently_failed = false;
	ctx->fail_reason[0] = '\0';
}
