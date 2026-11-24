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
#include "linux_kvm_drm.h"
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
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

// EGL_EXT_device_drm_render_node postdates some distro EGL headers (Raspbian bullseye / Mesa
// 20.3); define its token so the DRM device match still builds against them.
#ifndef EGL_DRM_RENDER_NODE_FILE_EXT
#define EGL_DRM_RENDER_NODE_FILE_EXT 0x3377
#endif

#if defined(__linux__)
#include <dlfcn.h>

// libEGL/libGLESv2 are dlopen'd rather than linked, so the agent runs without a GL stack.
// The *KHR/*OES extension entry points come from eglGetProcAddress, not this list.
#define KVM_DRM_EGL_SYMBOLS(_) \
	_(eglGetProcAddress) _(eglGetDisplay) _(eglGetError) _(eglInitialize) _(eglTerminate) \
	_(eglChooseConfig) _(eglCreateContext) _(eglDestroyContext) _(eglCreatePbufferSurface) \
	_(eglDestroySurface) _(eglMakeCurrent) _(eglBindAPI) _(eglQueryString)
#define KVM_DRM_GLES_SYMBOLS(_) \
	_(glActiveTexture) _(glAttachShader) _(glBindBuffer) _(glBindFramebuffer) _(glBindTexture) \
	_(glBufferData) _(glCheckFramebufferStatus) _(glCompileShader) _(glCreateProgram) _(glCreateShader) \
	_(glDeleteBuffers) _(glDeleteFramebuffers) _(glDeleteProgram) _(glDeleteShader) _(glDeleteTextures) \
	_(glDisableVertexAttribArray) _(glDrawArrays) _(glEnableVertexAttribArray) _(glFinish) \
	_(glFramebufferTexture2D) _(glGenBuffers) _(glGenFramebuffers) _(glGenTextures) _(glGetAttribLocation) \
	_(glGetError) _(glGetProgramiv) _(glGetShaderInfoLog) _(glGetShaderiv) _(glGetUniformLocation) \
	_(glLinkProgram) _(glReadPixels) _(glShaderSource) _(glTexImage2D) _(glTexParameteri) \
	_(glUniform1i) _(glUseProgram) _(glVertexAttribPointer) _(glViewport) _(glPixelStorei) _(glUniform2i)

#define KVM_DRM_EGL_DECL_PTR(s) static __typeof__(s) *p_##s = NULL;
KVM_DRM_EGL_SYMBOLS(KVM_DRM_EGL_DECL_PTR)
KVM_DRM_GLES_SYMBOLS(KVM_DRM_EGL_DECL_PTR)
#undef KVM_DRM_EGL_DECL_PTR

// libgbm is loaded on first use. Only these five functions are used, so no header is needed.
static void *g_libgbm_handle = NULL;
static void *(*p_gbm_create_device)(int fd) = NULL;
static void (*p_gbm_device_destroy)(void *gbm) = NULL;
static void *(*p_gbm_bo_create)(void *gbm, uint32_t width, uint32_t height, uint32_t format, uint32_t flags) = NULL;
static int (*p_gbm_bo_get_fd)(void *bo) = NULL;
static uint32_t (*p_gbm_bo_get_stride)(void *bo) = NULL;
static void (*p_gbm_bo_destroy)(void *bo) = NULL;

static int kvm_drm_egl_load_gbm(void)
{
	void *h;
	if (g_libgbm_handle != NULL) { return 1; }
	if ((h = dlopen("libgbm.so.1", RTLD_NOW)) == NULL) { return 0; }
	p_gbm_create_device = (void *(*)(int))dlsym(h, "gbm_create_device");
	p_gbm_device_destroy = (void (*)(void *))dlsym(h, "gbm_device_destroy");
	p_gbm_bo_create = (void *(*)(void *, uint32_t, uint32_t, uint32_t, uint32_t))dlsym(h, "gbm_bo_create");
	p_gbm_bo_get_fd = (int (*)(void *))dlsym(h, "gbm_bo_get_fd");
	p_gbm_bo_get_stride = (uint32_t (*)(void *))dlsym(h, "gbm_bo_get_stride");
	p_gbm_bo_destroy = (void (*)(void *))dlsym(h, "gbm_bo_destroy");
	if (p_gbm_create_device == NULL || p_gbm_device_destroy == NULL || p_gbm_bo_create == NULL || p_gbm_bo_get_fd == NULL || p_gbm_bo_get_stride == NULL || p_gbm_bo_destroy == NULL)
	{
		dlclose(h);
		return 0;
	}
	g_libgbm_handle = h;
	return 1;
}

static void *g_libEGL_handle = NULL;
static void *g_libGLES_handle = NULL;
static int kvm_drm_egl_load_libs(void)
{
	void *e, *g;
	if (g_libEGL_handle != NULL && g_libGLES_handle != NULL) { return 1; }
	if ((e = dlopen("libEGL.so.1", RTLD_NOW)) == NULL && (e = dlopen("libEGL.so", RTLD_NOW)) == NULL) { return 0; }
	if ((g = dlopen("libGLESv2.so.2", RTLD_NOW)) == NULL && (g = dlopen("libGLESv2.so", RTLD_NOW)) == NULL) { dlclose(e); return 0; }
#define KVM_DRM_EGL_LOAD_PTR(s) p_##s = (__typeof__(p_##s))dlsym(e, #s); if (p_##s == NULL) { dlclose(e); dlclose(g); return 0; }
	KVM_DRM_EGL_SYMBOLS(KVM_DRM_EGL_LOAD_PTR)
#undef KVM_DRM_EGL_LOAD_PTR
#define KVM_DRM_GLES_LOAD_PTR(s) p_##s = (__typeof__(p_##s))dlsym(g, #s); if (p_##s == NULL) { dlclose(e); dlclose(g); return 0; }
	KVM_DRM_GLES_SYMBOLS(KVM_DRM_GLES_LOAD_PTR)
#undef KVM_DRM_GLES_LOAD_PTR
	g_libEGL_handle = e;
	g_libGLES_handle = g;
	return 1;
}

#define eglGetProcAddress p_eglGetProcAddress
#define eglGetDisplay p_eglGetDisplay
#define eglGetError p_eglGetError
#define eglInitialize p_eglInitialize
#define eglTerminate p_eglTerminate
#define eglChooseConfig p_eglChooseConfig
#define eglCreateContext p_eglCreateContext
#define eglDestroyContext p_eglDestroyContext
#define eglCreatePbufferSurface p_eglCreatePbufferSurface
#define eglDestroySurface p_eglDestroySurface
#define eglMakeCurrent p_eglMakeCurrent
#define eglBindAPI p_eglBindAPI
#define eglQueryString p_eglQueryString
#define glActiveTexture p_glActiveTexture
#define glAttachShader p_glAttachShader
#define glBindBuffer p_glBindBuffer
#define glBindFramebuffer p_glBindFramebuffer
#define glBindTexture p_glBindTexture
#define glBufferData p_glBufferData
#define glCheckFramebufferStatus p_glCheckFramebufferStatus
#define glCompileShader p_glCompileShader
#define glCreateProgram p_glCreateProgram
#define glCreateShader p_glCreateShader
#define glDeleteBuffers p_glDeleteBuffers
#define glDeleteFramebuffers p_glDeleteFramebuffers
#define glDeleteProgram p_glDeleteProgram
#define glDeleteShader p_glDeleteShader
#define glDeleteTextures p_glDeleteTextures
#define glDisableVertexAttribArray p_glDisableVertexAttribArray
#define glDrawArrays p_glDrawArrays
#define glEnableVertexAttribArray p_glEnableVertexAttribArray
#define glFinish p_glFinish
#define glFramebufferTexture2D p_glFramebufferTexture2D
#define glGenBuffers p_glGenBuffers
#define glGenFramebuffers p_glGenFramebuffers
#define glGenTextures p_glGenTextures
#define glGetAttribLocation p_glGetAttribLocation
#define glGetError p_glGetError
#define glGetProgramiv p_glGetProgramiv
#define glGetShaderInfoLog p_glGetShaderInfoLog
#define glGetShaderiv p_glGetShaderiv
#define glGetUniformLocation p_glGetUniformLocation
#define glLinkProgram p_glLinkProgram
#define glReadPixels p_glReadPixels
#define glShaderSource p_glShaderSource
#define glTexImage2D p_glTexImage2D
#define glTexParameteri p_glTexParameteri
#define glUniform1i p_glUniform1i
#define glUseProgram p_glUseProgram
#define glVertexAttribPointer p_glVertexAttribPointer
#define glViewport p_glViewport
#define glPixelStorei p_glPixelStorei
#define glUniform2i p_glUniform2i
#endif // __linux__

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

static void kvm_drm_egl_format_fourcc(char *dst, size_t dst_size, uint32_t format)
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
	code[4] = '\0';
	snprintf(dst, dst_size, "%s/0x%08X", code, format);
}

static void kvm_drm_egl_format_egl_error(char *dst, size_t dst_size, const char *prefix, EGLint err)
{
	snprintf(dst, dst_size, "%s: 0x%04x", prefix, (unsigned int)err);
}

static const char *kvm_drm_egl_gl_error_name(GLenum err)
{
	switch (err)
	{
	case GL_INVALID_ENUM:
		return "GL_INVALID_ENUM";
	case GL_INVALID_VALUE:
		return "GL_INVALID_VALUE";
	case GL_INVALID_OPERATION:
		return "GL_INVALID_OPERATION";
	case GL_INVALID_FRAMEBUFFER_OPERATION:
		return "GL_INVALID_FRAMEBUFFER_OPERATION";
	case GL_OUT_OF_MEMORY:
		return "GL_OUT_OF_MEMORY";
	default:
		return "GL_UNKNOWN_ERROR";
	}
}

static bool kvm_drm_egl_check_gl_error(const char *stage, char *out_error, size_t out_error_size)
{
	GLenum err = glGetError();
	if (err == GL_NO_ERROR)
	{
		return true;
	}

	snprintf(out_error, out_error_size, "%s failed: %s (0x%04x)",
		stage,
		kvm_drm_egl_gl_error_name(err),
		(unsigned int)err);
	while (glGetError() != GL_NO_ERROR) {}
	return false;
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

// Device number of a DRM node a vendor reported, 0 when it is not in /dev (container, udev rules)
static dev_t kvm_drm_egl_node_dev(const char *path)
{
	struct stat st;
	return (path != NULL && stat(path, &st) == 0) ? st.st_rdev : 0;
}

// Two reported nodes name the same device: by device number when both are in /dev, else by path
static int kvm_drm_egl_same_node(dev_t a, const char *aPath, dev_t b, const char *bPath)
{
	if (a != 0 && b != 0) { return a == b; }
	return aPath != NULL && bPath != NULL && strcmp(aPath, bPath) == 0;
}

// Opens and initializes one EGL device. A vendor that lists a GPU it cannot drive fails here instead of in
// the caller, so the next vendor claiming the same card gets its turn.
static EGLDisplay kvm_drm_egl_init_device_display(PFNEGLGETPLATFORMDISPLAYEXTPROC getPlatformDisplay, EGLDeviceEXT device, int debug)
{
	EGLint major = 0, minor = 0;
	EGLDisplay dpy = getPlatformDisplay(EGL_PLATFORM_DEVICE_EXT, device, NULL);
	if (dpy == EGL_NO_DISPLAY) { return EGL_NO_DISPLAY; }
	if (eglInitialize(dpy, &major, &minor)) { return dpy; }
	if (debug) { fprintf(stderr, "DRM EGL: eglInitialize failed on an EGL device for the capture GPU: 0x%04x\n", (unsigned int)eglGetError()); }
	return EGL_NO_DISPLAY;
}

// Pin EGL to the GPU we capture from (by DRM node) so the loader uses the vendor that can import
// its buffers (NVIDIA) instead of falling back to Mesa/swrast, which imports the tiles as black.
// Sets *out_gpu_mismatch when a device for our card was identified but none initializes, or when nothing matched
// our card and it either renders itself or several GPUs are present, so the caller fails instead of routing
// this card through a foreign vendor.
static EGLDisplay kvm_drm_egl_open_device_display(int drm_fd, bool *out_gpu_mismatch)
{
	PFNEGLQUERYDEVICESEXTPROC queryDevices = (PFNEGLQUERYDEVICESEXTPROC)eglGetProcAddress("eglQueryDevicesEXT");
	PFNEGLQUERYDEVICESTRINGEXTPROC queryDeviceString = (PFNEGLQUERYDEVICESTRINGEXTPROC)eglGetProcAddress("eglQueryDeviceStringEXT");
	PFNEGLGETPLATFORMDISPLAYEXTPROC getPlatformDisplay = (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
	EGLDeviceEXT devices[16];
	EGLDeviceEXT candidates[16];      // every device that matched our card, in vendor order
	EGLDeviceEXT firstHardware = EGL_NO_DEVICE_EXT;
	struct { dev_t card, render; const char *cardPath, *renderPath; } seen[16]; // distinct GPUs
	EGLint count = 0;
	EGLDisplay dpy;
	struct stat cardSt, renderSt;
	char renderPath[64];
	int haveCard, cardIsRenderer, haveRender, hardwareCount = 0, candidateCount = 0;
	int debug = (getenv("MESH_KVM_DRM_DEBUG") != NULL && atoi(getenv("MESH_KVM_DRM_DEBUG")) > 0);
	int i, j;

	if (out_gpu_mismatch != NULL) { *out_gpu_mismatch = false; }
	if (queryDevices == NULL || queryDeviceString == NULL || getPlatformDisplay == NULL) { return EGL_NO_DISPLAY; }
	if (!queryDevices((EGLint)(sizeof(devices) / sizeof(devices[0])), devices, &count) || count <= 0) { return EGL_NO_DISPLAY; }

	// The capture fd is a card node; an EGL device may report only its card node (Mesa) or only its
	// render node (NVIDIA), so match against either by device-number.
	haveCard = (drm_fd >= 0 && fstat(drm_fd, &cardSt) == 0) ? 1 : 0;
	// libdrm answers from /sys/dev/char/<maj>:<min>/device/drm, so a name means the kernel driver renders
	// even when the node is hidden in /dev (container, udev rules). The stat only serves the match below.
	cardIsRenderer = (drm_fd >= 0 && kvm_drm_render_node_for_fd(drm_fd, renderPath, sizeof(renderPath))) ? 1 : 0;
	haveRender = (cardIsRenderer && stat(renderPath, &renderSt) == 0) ? 1 : 0;
	for (i = 0; i < count; ++i)
	{
		const char *cardNode = queryDeviceString(devices[i], EGL_DRM_DEVICE_FILE_EXT);
		const char *renderNode = queryDeviceString(devices[i], EGL_DRM_RENDER_NODE_FILE_EXT);
		dev_t cardDev, renderDev;
		int duplicate = 0;
		if (cardNode == NULL && renderNode == NULL) { continue; } // software device: no DRM node
		if (firstHardware == EGL_NO_DEVICE_EXT) { firstHardware = devices[i]; }
		cardDev = kvm_drm_egl_node_dev(cardNode);
		renderDev = kvm_drm_egl_node_dev(renderNode);
		// With glvnd one GPU is listed once per vendor that claims it (Mesa lists every render node, driver or
		// not), so count hardware, not entries.
		for (j = 0; j < hardwareCount && !duplicate; ++j)
		{
			duplicate = kvm_drm_egl_same_node(cardDev, cardNode, seen[j].card, seen[j].cardPath) ||
				kvm_drm_egl_same_node(renderDev, renderNode, seen[j].render, seen[j].renderPath);
		}
		if (!duplicate)
		{
			seen[hardwareCount].card = cardDev;
			seen[hardwareCount].render = renderDev;
			seen[hardwareCount].cardPath = cardNode;
			seen[hardwareCount].renderPath = renderNode;
			hardwareCount++;
		}
		if ((haveCard && cardDev != 0 && cardDev == cardSt.st_rdev) || (haveRender && renderDev != 0 && renderDev == renderSt.st_rdev))
		{
			candidates[candidateCount++] = devices[i];
		}
	}

	// Try every vendor that claims our card, in list order. Mesa lists the NVIDIA render node too and cannot
	// initialize it, so taking the first match would depend on the ICD file order.
	for (i = 0; i < candidateCount; ++i)
	{
		if ((dpy = kvm_drm_egl_init_device_display(getPlatformDisplay, candidates[i], debug)) != EGL_NO_DISPLAY) { return dpy; }
	}
	if (candidateCount > 0 || (haveCard && (cardIsRenderer || hardwareCount > 1)))
	{
		// Our card is an EGL device no vendor can initialize, or it renders itself (or several GPUs are present) and
		// nothing matched it. The default display would import its buffers through a foreign vendor (black) — flag it
		// so the caller fails. Only guess when the card was never identified, or it is display-only and one GPU exists.
		if (firstHardware != EGL_NO_DEVICE_EXT && out_gpu_mismatch != NULL) { *out_gpu_mismatch = true; }
		if (debug) { fprintf(stderr, "DRM EGL: %d EGL device(s) matched the capture GPU, none usable (%d GPUs present)\n", candidateCount, hardwareCount); }
		return EGL_NO_DISPLAY;
	}
	if (firstHardware == EGL_NO_DEVICE_EXT) { return EGL_NO_DISPLAY; }
	// A display controller without a render node, like rockchip-drm on RK3588, is never an EGL device itself.
	// With a single GPU present that GPU is what imports its scanout buffers.
	dpy = kvm_drm_egl_init_device_display(getPlatformDisplay, firstHardware, debug);
	// The one GPU that should import exists but will not initialize: the default display can only do worse
	if (dpy == EGL_NO_DISPLAY && out_gpu_mismatch != NULL) { *out_gpu_mismatch = true; }
	return dpy;
}

static bool kvm_drm_egl_init_gpu_readback(kvm_drm_egl_context *g, int drm_fd, char *out_error, size_t out_error_size)
{
	if (g->initialized) { return true; }
	if (g->permanently_failed)
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, g->fail_reason);
		return false;
	}

	if (!kvm_drm_egl_load_libs())
	{
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size,
			"libEGL/libGLESv2 not installed; GPU-assisted DRM conversion unavailable");
	}

	bool gpuMismatch = false;
	g->dpy = kvm_drm_egl_open_device_display(drm_fd, &gpuMismatch);
	if (g->dpy == EGL_NO_DISPLAY && gpuMismatch)
	{
		// This card's tiled buffers would read back black through another GPU's vendor, or no vendor drives it at all.
		// Fail for good, since its outputs can't be GPU-converted, instead of trying the default display.
		return kvm_drm_egl_fail_with_persistent_error(g, out_error, out_error_size,
			"no usable EGL device for the capture GPU (foreign vendor or driver missing)");
	}
	if (g->dpy == EGL_NO_DISPLAY)
	{
		PFNEGLGETPLATFORMDISPLAYEXTPROC eglGetPlatformDisplayEXTFn =
			(PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
		if (eglGetPlatformDisplayEXTFn != NULL)
		{
			g->dpy = eglGetPlatformDisplayEXTFn(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
		}
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
	if (getenv("MESH_KVM_DRM_DEBUG") != NULL && atoi(getenv("MESH_KVM_DRM_DEBUG")) > 0)
	{
		fprintf(stderr, "DRM EGL: Initialized EGL %d.%d vendor=%s version=%s\n",
			(int)major,
			(int)minor,
			eglQueryString(g->dpy, EGL_VENDOR) != NULL ? eglQueryString(g->dpy, EGL_VENDOR) : "unknown",
			eglQueryString(g->dpy, EGL_VERSION) != NULL ? eglQueryString(g->dpy, EGL_VERSION) : "unknown");
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

	// ES 3 when the driver has it, for the changed-tile readback (texelFetch, GL_PACK_ROW_LENGTH). The ES 2 path is unchanged in an ES 3 context.
	EGLint ctx_attribs[] = { EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE };
	g->ctx = eglCreateContext(g->dpy, g->cfg, EGL_NO_CONTEXT, ctx_attribs);
	g->es3 = (g->ctx != EGL_NO_CONTEXT);
	if (!g->es3)
	{
		ctx_attribs[1] = 2;
		g->ctx = eglCreateContext(g->dpy, g->cfg, EGL_NO_CONTEXT, ctx_attribs);
	}
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
	memset(g->targets, 0, sizeof(g->targets));
	g->gbm = NULL;
	g->linear_off = false;

	// The tile compare pass. Without it every frame is read back whole, as before.
	g->diff_program = 0;
	if (g->es3)
	{
		// One fragment per tile: 1 when any pixel of the tile differs between the two frames. The frames are stored bottom row first.
		const char *dvs_src = "#version 300 es\n"
			"in vec2 aPos;\n"
			"void main(){ gl_Position=vec4(aPos,0.0,1.0); }\n";
		const char *dfs_src = "#version 300 es\n"
			"precision highp float;\n"
			"precision highp int;\n"
			"uniform sampler2D uCur;\n"
			"uniform sampler2D uPrev;\n"
			"uniform ivec2 uSize;\n"
			"uniform int uTile;\n"
			"out vec4 o;\n"
			"void main(){\n"
			" ivec2 t = ivec2(gl_FragCoord.xy) * uTile;\n"
			" bool d = false;\n"
			" for (int y = 0; y < uTile; y++) {\n"
			"  int gy = uSize.y - 1 - min(t.y + y, uSize.y - 1);\n"
			"  for (int x = 0; x < uTile; x++) {\n"
			"   ivec2 p = ivec2(min(t.x + x, uSize.x - 1), gy);\n"
			"   if (texelFetch(uCur, p, 0) != texelFetch(uPrev, p, 0)) { d = true; }\n"
			"  }\n"
			" }\n"
			" o = vec4(d ? 1.0 : 0.0);\n"
			"}\n";
		char dlog[128] = { 0 };
		GLuint dvs = kvm_drm_egl_compile_shader(GL_VERTEX_SHADER, dvs_src, dlog, sizeof(dlog));
		GLuint dfs = kvm_drm_egl_compile_shader(GL_FRAGMENT_SHADER, dfs_src, dlog, sizeof(dlog));
		if (dvs != 0 && dfs != 0)
		{
			GLint dlinked = GL_FALSE;
			g->diff_program = glCreateProgram();
			glAttachShader(g->diff_program, dvs);
			glAttachShader(g->diff_program, dfs);
			glLinkProgram(g->diff_program);
			glGetProgramiv(g->diff_program, GL_LINK_STATUS, &dlinked);
			if (dlinked == GL_TRUE)
			{
				g->diff_attr_pos = glGetAttribLocation(g->diff_program, "aPos");
				g->diff_u_cur = glGetUniformLocation(g->diff_program, "uCur");
				g->diff_u_prev = glGetUniformLocation(g->diff_program, "uPrev");
				g->diff_u_size = glGetUniformLocation(g->diff_program, "uSize");
				g->diff_u_tile = glGetUniformLocation(g->diff_program, "uTile");
			}
			if (dlinked != GL_TRUE || g->diff_attr_pos < 0 || g->diff_u_cur < 0 || g->diff_u_prev < 0 || g->diff_u_size < 0 || g->diff_u_tile < 0)
			{
				glDeleteProgram(g->diff_program);
				g->diff_program = 0;
			}
		}
		if (dvs != 0) { glDeleteShader(dvs); }
		if (dfs != 0) { glDeleteShader(dfs); }
		(void)glGetError();
	}

	g->initialized = true;
	return true;
}

static void kvm_drm_egl_free_linear(kvm_drm_egl_context *g, void **bo, EGLImageKHR *img)
{
	if (*img != NULL && *img != EGL_NO_IMAGE_KHR && g->eglDestroyImageKHRFn != NULL) { g->eglDestroyImageKHRFn(g->dpy, *img); }
	*img = NULL;
	if (*bo != NULL) { p_gbm_bo_destroy(*bo); }
	*bo = NULL;
}

// Backs the texture with a linear buffer from GBM. Reading a linear render target back costs less CPU time than the driver's own tiled layout.
// Returns false when that is not possible, and the caller then uses an ordinary texture.
static bool kvm_drm_egl_linear_texture(kvm_drm_egl_context *g, GLuint *tex, void **bo, EGLImageKHR *img, int width, int height)
{
	EGLint attrs[24];
	int a = 0, fd;

	kvm_drm_egl_free_linear(g, bo, img);
	if (g->linear_off || g->drm_fd < 0 || !kvm_drm_egl_load_gbm()) { return false; }
	if (g->gbm == NULL && (g->gbm = p_gbm_create_device(g->drm_fd)) == NULL) { g->linear_off = true; return false; }

	// GBM_BO_USE_RENDERING | GBM_BO_USE_LINEAR
	if ((*bo = p_gbm_bo_create(g->gbm, (uint32_t)width, (uint32_t)height, DRM_FORMAT_ABGR8888, (1u << 2) | (1u << 4))) == NULL) { g->linear_off = true; return false; }
	if ((fd = p_gbm_bo_get_fd(*bo)) < 0) { kvm_drm_egl_free_linear(g, bo, img); g->linear_off = true; return false; }
	attrs[a++] = EGL_WIDTH; attrs[a++] = width;
	attrs[a++] = EGL_HEIGHT; attrs[a++] = height;
	attrs[a++] = EGL_LINUX_DRM_FOURCC_EXT; attrs[a++] = (EGLint)DRM_FORMAT_ABGR8888;
	attrs[a++] = EGL_DMA_BUF_PLANE0_FD_EXT; attrs[a++] = fd;
	attrs[a++] = EGL_DMA_BUF_PLANE0_OFFSET_EXT; attrs[a++] = 0;
	attrs[a++] = EGL_DMA_BUF_PLANE0_PITCH_EXT; attrs[a++] = (EGLint)p_gbm_bo_get_stride(*bo);
	attrs[a++] = EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT; attrs[a++] = (EGLint)(DRM_FORMAT_MOD_LINEAR & 0xFFFFFFFFu);
	attrs[a++] = EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT; attrs[a++] = (EGLint)(DRM_FORMAT_MOD_LINEAR >> 32);
	attrs[a++] = EGL_NONE;
	*img = g->eglCreateImageKHRFn(g->dpy, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, NULL, attrs);
	close(fd);
	if (*img == EGL_NO_IMAGE_KHR) { *img = NULL; kvm_drm_egl_free_linear(g, bo, img); g->linear_off = true; return false; }

	if (*tex == 0) { glGenTextures(1, tex); }
	glBindTexture(GL_TEXTURE_2D, *tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	(void)glGetError();
	g->glEGLImageTargetTexture2DOESFn(GL_TEXTURE_2D, (GLeglImageOES)*img);
	if (glGetError() != GL_NO_ERROR) { kvm_drm_egl_free_linear(g, bo, img); g->linear_off = true; return false; }
	return true;
}

static void kvm_drm_egl_alloc_target_texture(GLuint *tex, int width, int height)
{
	if (*tex == 0) { glGenTextures(1, tex); }
	glBindTexture(GL_TEXTURE_2D, *tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
}

// Makes the render target t the given size. resize_surface also brings the pbuffer surface to that size, as before.
// Further outputs leave the surface alone, because everything is drawn into the framebuffer object and two sizes would recreate it twice per frame.
static bool kvm_drm_egl_ensure_gpu_target_size(kvm_drm_egl_context *g, kvm_drm_egl_target *t, bool resize_surface, int width, int height, char *out_error, size_t out_error_size)
{
	if (resize_surface && (g->surf_w != width || g->surf_h != height))
	{
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
			// Also reset the cached size: a stale surf_w/h would make the next call at the old size
			// short-circuit "true" with no surface at all.
			g->surf_w = 0;
			g->surf_h = 0;
			kvm_drm_egl_format_egl_error(err, sizeof(err), "eglCreatePbufferSurface(size) failed", eglGetError());
			kvm_drm_egl_copy_error_message(out_error, out_error_size, err);
			return false;
		}
		g->surf_w = width;
		g->surf_h = height;

		if (!eglMakeCurrent(g->dpy, g->surf, g->surf, g->ctx))
		{
			char err[KVM_DRM_EGL_MAX_ERROR];
			g->surf_w = 0;
			g->surf_h = 0;
			kvm_drm_egl_format_egl_error(err, sizeof(err), "eglMakeCurrent(size) failed", eglGetError());
			kvm_drm_egl_copy_error_message(out_error, out_error_size, err);
			return false;
		}
	}

	if (t->out_tex != 0 && t->w == width && t->h == height) { return true; }

	// Linear buffers where the driver can render into them, ordinary textures otherwise.
	// The second render target has the same size, and the two swap roles every frame, so the previous frame stays on the GPU without a copy.
	t->have_prev = false;
	if (kvm_drm_egl_linear_texture(g, &t->out_tex, &t->out_bo, &t->out_img, width, height))
	{
		glBindFramebuffer(GL_FRAMEBUFFER, g->fbo);
		glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->out_tex, 0);
		if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE ||
			(g->diff_program != 0 && !kvm_drm_egl_linear_texture(g, &t->prev_tex, &t->prev_bo, &t->prev_img, width, height)))
		{
			g->linear_off = true;
		}
	}
	if (t->out_bo == NULL || g->linear_off)
	{
		kvm_drm_egl_free_linear(g, &t->out_bo, &t->out_img);
		kvm_drm_egl_free_linear(g, &t->prev_bo, &t->prev_img);
		kvm_drm_egl_alloc_target_texture(&t->out_tex, width, height);
		if (g->diff_program != 0) { kvm_drm_egl_alloc_target_texture(&t->prev_tex, width, height); }
	}
	t->w = width;
	t->h = height;

	glBindFramebuffer(GL_FRAMEBUFFER, g->fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->out_tex, 0);
	if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
	{
		t->w = 0;
		t->h = 0;
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "GPU readback framebuffer is incomplete");
		return false;
	}

	return true;
}

#endif

#if defined(__linux__)
// Compares out_tex with prev_tex tile by tile on the GPU and reads back the changed tiles into their place in dest,
// which has row_length pixels per row and holds this output's bottom left pixel at dest.
// Returns false when it could not, and then the caller reads the whole frame.
static bool kvm_drm_egl_read_changed_tiles(kvm_drm_egl_context *ctx, kvm_drm_egl_target *t, int width, int height, int tile, uint8_t *dest, int row_length)
{
	int tw = (width + tile - 1) / tile;
	int th = (height + tile - 1) / tile;
	size_t tiles = (size_t)tw * (size_t)th;
	uint8_t *done;
	int r, c;

	if (ctx->changed_tiles_cap < tiles)
	{
		uint8_t *a = (uint8_t*)realloc(ctx->changed_tiles, tiles);
		uint8_t *b = (a != NULL) ? (uint8_t*)realloc(ctx->diff_readback, tiles * 4u) : NULL;
		if (a != NULL) { ctx->changed_tiles = a; }
		if (b != NULL) { ctx->diff_readback = b; }
		if (a == NULL || b == NULL) { ctx->changed_tiles_cap = 0; return false; }
		ctx->changed_tiles_cap = tiles;
	}

	(void)glGetError();
	if (t->diff_tex == 0 || t->diff_w != tw || t->diff_h != th)
	{
		kvm_drm_egl_alloc_target_texture(&t->diff_tex, tw, th);
		t->diff_w = tw;
		t->diff_h = th;
	}

	// Pass 2: one fragment per tile. Fragment row 0 is the top tile row, the shader turns the rows over.
	glBindFramebuffer(GL_FRAMEBUFFER, ctx->fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->diff_tex, 0);
	if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) { (void)glGetError(); return false; }
	glViewport(0, 0, tw, th);
	glUseProgram(ctx->diff_program);
	glActiveTexture(GL_TEXTURE1);
	glBindTexture(GL_TEXTURE_2D, t->prev_tex);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, t->out_tex);
	glUniform1i(ctx->diff_u_cur, 0);
	glUniform1i(ctx->diff_u_prev, 1);
	glUniform2i(ctx->diff_u_size, width, height);
	glUniform1i(ctx->diff_u_tile, tile);
	glBindBuffer(GL_ARRAY_BUFFER, ctx->vbo);
	glEnableVertexAttribArray((GLuint)ctx->diff_attr_pos);
	glVertexAttribPointer((GLuint)ctx->diff_attr_pos, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(GLfloat), (void*)(0));
	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
	glDisableVertexAttribArray((GLuint)ctx->diff_attr_pos);
	glReadPixels(0, 0, tw, th, GL_RGBA, GL_UNSIGNED_BYTE, ctx->diff_readback);
	glActiveTexture(GL_TEXTURE1);
	glBindTexture(GL_TEXTURE_2D, 0);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, 0);
	if (glGetError() != GL_NO_ERROR) { return false; }
	for (r = 0; r < (int)tiles; r++) { ctx->changed_tiles[r] = (ctx->diff_readback[(size_t)r * 4u] != 0) ? 1 : 0; }
	// The compare result is not needed anymore, so its buffer serves as the map of tiles that are already read
	done = ctx->diff_readback;

	// Read back the changed tiles as rectangles, straight into their place in the bottom-up destination.
	// A run of changed tiles is extended down over the tile rows that have changed across its whole width, so a changed window is one read and not one per tile row.
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->out_tex, 0);
	glPixelStorei(0x0D02 /* GL_PACK_ROW_LENGTH */, row_length);
	memset(done, 0, tiles);
	for (r = 0; r < th; r++)
	{
		const uint8_t *row = ctx->changed_tiles + (size_t)r * (size_t)tw;
		for (c = 0; c < tw; c++)
		{
			int c0 = c, r1 = r, i, x0, x1, top, bottom, glY;
			if (!row[c] || done[(size_t)r * (size_t)tw + (size_t)c]) { continue; }
			while (c + 1 < tw && row[c + 1] && !done[(size_t)r * (size_t)tw + (size_t)c + 1]) { c++; }
			while (r1 + 1 < th)
			{
				const uint8_t *below = ctx->changed_tiles + (size_t)(r1 + 1) * (size_t)tw;
				const uint8_t *belowDone = done + (size_t)(r1 + 1) * (size_t)tw;
				for (i = c0; i <= c && below[i] && !belowDone[i]; i++) { }
				if (i <= c) { break; }
				r1++;
			}
			for (i = r; i <= r1; i++) { memset(done + (size_t)i * (size_t)tw + (size_t)c0, 1, (size_t)(c - c0 + 1)); }
			x0 = c0 * tile;
			x1 = ((c + 1) * tile > width) ? width : (c + 1) * tile;
			top = r * tile;
			bottom = ((r1 + 1) * tile > height) ? height : (r1 + 1) * tile;
			glY = height - bottom;
			glReadPixels(x0, glY, x1 - x0, bottom - top, GL_RGBA, GL_UNSIGNED_BYTE, dest + ((size_t)glY * (size_t)row_length + (size_t)x0) * 4u);
		}
	}
	glPixelStorei(0x0D02 /* GL_PACK_ROW_LENGTH */, 0);
	return (glGetError() == GL_NO_ERROR);
}
#endif

bool kvm_drm_egl_convert_to_rgb24_gpu(kvm_drm_egl_context *ctx, int drm_fd, uint32_t width, uint32_t height,
	int plane_count, const uint32_t *plane_handles, const uint32_t *plane_pitches, const uint32_t *plane_offsets,
	uint32_t format, uint64_t modifier, uint8_t *rgb,
	size_t rgb_capacity, size_t *rgb_size_out, char *out_error, size_t out_error_size)
{
#if !defined(__linux__)
	UNREFERENCED_PARAMETER(ctx);
	UNREFERENCED_PARAMETER(drm_fd);
	UNREFERENCED_PARAMETER(width);
	UNREFERENCED_PARAMETER(height);
	UNREFERENCED_PARAMETER(plane_count);
	UNREFERENCED_PARAMETER(plane_handles);
	UNREFERENCED_PARAMETER(plane_pitches);
	UNREFERENCED_PARAMETER(plane_offsets);
	UNREFERENCED_PARAMETER(format);
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

	if (!kvm_drm_egl_init_gpu_readback(ctx, drm_fd, out_error, out_error_size)) { return false; }
	// Each GPU has its own context; bind this one before any GL/EGL for this frame so a
	// multi-GPU desktop doesn't issue card B's work against card A's still-current context.
	if (!eglMakeCurrent(ctx->dpy, ctx->surf, ctx->surf, ctx->ctx))
	{
		kvm_drm_egl_format_egl_error(out_error, out_error_size, "eglMakeCurrent failed", eglGetError());
		return false;
	}
	// A call without an RGB24 buffer uses the caller's target, so each output keeps its own previous frame. The RGB24 path uses target 0.
	kvm_drm_egl_target *t = &ctx->targets[(rgb == NULL && ctx->direct_target > 0 && ctx->direct_target < KVM_DRM_EGL_TARGETS) ? ctx->direct_target : 0];
	if (rgb == NULL && (ctx->direct_dest == NULL || ctx->direct_dest_row_length < (int)width || (!ctx->es3 && ctx->direct_dest_row_length != (int)width)))
	{
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "No usable destination for the GPU readback");
		return false;
	}
	if (ctx->gbm == NULL) { ctx->drm_fd = drm_fd; }
	if (!kvm_drm_egl_ensure_gpu_target_size(ctx, t, (t == &ctx->targets[0]), (int)width, (int)height, out_error, out_error_size)) { return false; }

	static const EGLint planeFdAttr[4]     = { EGL_DMA_BUF_PLANE0_FD_EXT,         EGL_DMA_BUF_PLANE1_FD_EXT,         EGL_DMA_BUF_PLANE2_FD_EXT,         EGL_DMA_BUF_PLANE3_FD_EXT };
	static const EGLint planeOffsetAttr[4] = { EGL_DMA_BUF_PLANE0_OFFSET_EXT,     EGL_DMA_BUF_PLANE1_OFFSET_EXT,     EGL_DMA_BUF_PLANE2_OFFSET_EXT,     EGL_DMA_BUF_PLANE3_OFFSET_EXT };
	static const EGLint planePitchAttr[4]  = { EGL_DMA_BUF_PLANE0_PITCH_EXT,      EGL_DMA_BUF_PLANE1_PITCH_EXT,      EGL_DMA_BUF_PLANE2_PITCH_EXT,      EGL_DMA_BUF_PLANE3_PITCH_EXT };
	static const EGLint planeModLoAttr[4]  = { EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT, EGL_DMA_BUF_PLANE1_MODIFIER_LO_EXT, EGL_DMA_BUF_PLANE2_MODIFIER_LO_EXT, EGL_DMA_BUF_PLANE3_MODIFIER_LO_EXT };
	static const EGLint planeModHiAttr[4]  = { EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT, EGL_DMA_BUF_PLANE1_MODIFIER_HI_EXT, EGL_DMA_BUF_PLANE2_MODIFIER_HI_EXT, EGL_DMA_BUF_PLANE3_MODIFIER_HI_EXT };

	int planes = plane_count;
	if (planes < 1) { planes = 1; }
	if (planes > 4) { planes = 4; }

	int dmabuf_fd[4] = { -1, -1, -1, -1 };
	EGLint attrs[48];
	int a = 0;
	attrs[a++] = EGL_WIDTH;
	attrs[a++] = (EGLint)width;
	attrs[a++] = EGL_HEIGHT;
	attrs[a++] = (EGLint)height;
	attrs[a++] = EGL_LINUX_DRM_FOURCC_EXT;
	attrs[a++] = (EGLint)format;
	for (int p = 0; p < planes; ++p)
	{
		// Export each plane's GEM handle to its own dma-buf fd. Render-compressed scanout (CCS)
		// splits the image into a data plane + a metadata plane; every plane carries the same
		// framebuffer modifier so EGL/Mesa can decompress it while sampling.
		if (kvm_drm_prime_handle_to_fd(drm_fd, plane_handles[p], KVM_DRM_EGL_CLOEXEC | DRM_RDWR, &dmabuf_fd[p]) != 0 || dmabuf_fd[p] < 0)
		{
			char msg[KVM_DRM_EGL_MAX_ERROR];
			int q;
			snprintf(msg, sizeof(msg), "drmPrimeHandleToFD failed for GPU path (plane=%d handle=%u errno=%d)", p, plane_handles[p], errno);
			for (q = 0; q < p; ++q) { if (dmabuf_fd[q] >= 0) { close(dmabuf_fd[q]); } }
			kvm_drm_egl_copy_error_message(out_error, out_error_size, msg);
			return false;
		}
		attrs[a++] = planeFdAttr[p];
		attrs[a++] = dmabuf_fd[p];
		attrs[a++] = planeOffsetAttr[p];
		attrs[a++] = (EGLint)plane_offsets[p];
		attrs[a++] = planePitchAttr[p];
		attrs[a++] = (EGLint)plane_pitches[p];
		if (modifier != DRM_FORMAT_MOD_INVALID)
		{
			attrs[a++] = planeModLoAttr[p];
			attrs[a++] = (EGLint)(modifier & 0xFFFFFFFFu);
			attrs[a++] = planeModHiAttr[p];
			attrs[a++] = (EGLint)((modifier >> 32) & 0xFFFFFFFFu);
		}
	}
	attrs[a++] = EGL_NONE;

	EGLImageKHR image = ctx->eglCreateImageKHRFn(ctx->dpy, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, NULL, attrs);
	for (int p = 0; p < planes; ++p) { if (dmabuf_fd[p] >= 0) { close(dmabuf_fd[p]); } }
	if (image == EGL_NO_IMAGE_KHR)
	{
		char err[KVM_DRM_EGL_MAX_ERROR];
		char formatName[32];
		kvm_drm_egl_format_fourcc(formatName, sizeof(formatName), format);
		snprintf(err, sizeof(err),
			"eglCreateImageKHR(dma-buf) failed for %s modifier=0x%016" PRIx64 ": 0x%04x",
			formatName,
			modifier,
			(unsigned int)eglGetError());
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
	if (!kvm_drm_egl_check_gl_error("glEGLImageTargetTexture2DOES", out_error, out_error_size))
	{
		ctx->eglDestroyImageKHRFn(ctx->dpy, image);
		glDeleteTextures(1, &src_tex);
		return false;
	}

	glBindFramebuffer(GL_FRAMEBUFFER, ctx->fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->out_tex, 0);
	if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
	{
		t->have_prev = false;
		ctx->eglDestroyImageKHRFn(ctx->dpy, image);
		glDeleteTextures(1, &src_tex);
		kvm_drm_egl_copy_error_message(out_error, out_error_size, "GPU readback framebuffer became incomplete");
		return false;
	}
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
	if (!kvm_drm_egl_check_gl_error("GPU draw/readback pass", out_error, out_error_size))
	{
		ctx->eglDestroyImageKHRFn(ctx->dpy, image);
		glDeleteTextures(1, &src_tex);
		return false;
	}

	const size_t rgba_size = (size_t)width * (size_t)height * 4u;
	ctx->changed_valid = false;
	if (rgb == NULL)
	{
		uint8_t *dest = ctx->direct_dest + ((size_t)ctx->direct_dest_row0 * (size_t)ctx->direct_dest_row_length + (size_t)ctx->direct_dest_x) * 4u;

		// Reading the whole frame back costs most of the CPU time of this path (measured 15 of 21 ms per 1920x1080 frame on a Mali-G610),
		// so when the previous frame is on the GPU, the tiles are compared there and only the changed ones are read back.
		if (t->have_prev && !ctx->direct_force_full && ctx->diff_program != 0 && ctx->direct_tile_size > 0)
		{
			ctx->changed_valid = kvm_drm_egl_read_changed_tiles(ctx, t, (int)width, (int)height, ctx->direct_tile_size, dest, ctx->direct_dest_row_length);
		}
		if (!ctx->changed_valid)
		{
			glBindFramebuffer(GL_FRAMEBUFFER, ctx->fbo);
			glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->out_tex, 0);
			if (ctx->es3) { glPixelStorei(0x0D02 /* GL_PACK_ROW_LENGTH */, ctx->direct_dest_row_length); }
			glReadPixels(0, 0, (GLsizei)width, (GLsizei)height, GL_RGBA, GL_UNSIGNED_BYTE, dest);
			if (ctx->es3) { glPixelStorei(0x0D02 /* GL_PACK_ROW_LENGTH */, 0); }
		}
	}
	else
	{
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
	}
	if (!kvm_drm_egl_check_gl_error("glReadPixels", out_error, out_error_size))
	{
		t->have_prev = false;
		ctx->changed_valid = false;
		ctx->eglDestroyImageKHRFn(ctx->dpy, image);
		glDeleteTextures(1, &src_tex);
		return false;
	}

	ctx->eglDestroyImageKHRFn(ctx->dpy, image);
	glDeleteTextures(1, &src_tex);

	// This frame becomes the previous one of its target. Only a caller that takes the readback as it is keeps its destination in step with it.
	if (rgb == NULL && ctx->diff_program != 0)
	{
		GLuint swap = t->out_tex;
		void *swapBo = t->out_bo;
		EGLImageKHR swapImg = t->out_img;
		t->out_tex = t->prev_tex;
		t->prev_tex = swap;
		t->out_bo = t->prev_bo;
		t->prev_bo = swapBo;
		t->out_img = t->prev_img;
		t->prev_img = swapImg;
		t->have_prev = true;
	}
	else
	{
		t->have_prev = false;
	}

	const size_t rgb_size = (size_t)width * (size_t)height * 3u;
	if (rgb == NULL)
	{
		// The frame is in the caller's destination: RGBA, 4 bytes per pixel, bottom row first
		if (rgb_size_out != NULL) { *rgb_size_out = rgba_size; }
		return true;
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
	free(ctx->changed_tiles);
	ctx->changed_tiles = NULL;
	ctx->changed_tiles_cap = 0;
	free(ctx->diff_readback);
	ctx->diff_readback = NULL;
	ctx->changed_valid = false;

#if defined(__linux__)
	// dpy is nulled on a device sharing another's EGLDisplay, so only the owner terminates it (and
	// frees the GL objects, which live on dpy); bind this context first since multi-GPU teardown can
	// leave another card's context current.
	if (ctx->dpy != EGL_NO_DISPLAY)
	{
		if (ctx->ctx != EGL_NO_CONTEXT) { eglMakeCurrent(ctx->dpy, ctx->surf, ctx->surf, ctx->ctx); }
		if (ctx->program != 0) { glDeleteProgram(ctx->program); ctx->program = 0; }
		if (ctx->vbo != 0) { glDeleteBuffers(1, &ctx->vbo); ctx->vbo = 0; }
		if (ctx->fbo != 0) { glDeleteFramebuffers(1, &ctx->fbo); ctx->fbo = 0; }
		for (int i = 0; i < KVM_DRM_EGL_TARGETS; i++)
		{
			kvm_drm_egl_free_linear(ctx, &ctx->targets[i].out_bo, &ctx->targets[i].out_img);
			kvm_drm_egl_free_linear(ctx, &ctx->targets[i].prev_bo, &ctx->targets[i].prev_img);
			if (ctx->targets[i].out_tex != 0) { glDeleteTextures(1, &ctx->targets[i].out_tex); }
			if (ctx->targets[i].prev_tex != 0) { glDeleteTextures(1, &ctx->targets[i].prev_tex); }
			if (ctx->targets[i].diff_tex != 0) { glDeleteTextures(1, &ctx->targets[i].diff_tex); }
		}
		memset(ctx->targets, 0, sizeof(ctx->targets));
		if (ctx->diff_program != 0) { glDeleteProgram(ctx->diff_program); ctx->diff_program = 0; }
		eglMakeCurrent(ctx->dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
		if (ctx->ctx != EGL_NO_CONTEXT) { eglDestroyContext(ctx->dpy, ctx->ctx); ctx->ctx = EGL_NO_CONTEXT; }
		if (ctx->surf != EGL_NO_SURFACE) { eglDestroySurface(ctx->dpy, ctx->surf); ctx->surf = EGL_NO_SURFACE; }
		if (ctx->gbm != NULL) { p_gbm_device_destroy(ctx->gbm); ctx->gbm = NULL; }
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

	ctx->direct_dest = NULL;
	ctx->initialized = false;
}
