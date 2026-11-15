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

#include "linux_kvm_capture.h"
#include <string.h>

#if defined(__i386__) || defined(__x86_64__)
#if defined(__clang__)
#if __has_builtin(__builtin_cpu_supports) && __has_attribute(target)
#define KVM_CAPTURE_STREAMING_X86
#endif
#elif defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))
#define KVM_CAPTURE_STREAMING_X86
#endif
#endif

#if defined(KVM_CAPTURE_STREAMING_X86)
#include <smmintrin.h>
__attribute__((target("sse4.1")))
static void kvm_capture_stream_copy(unsigned char *dst, const unsigned char *src, size_t length)
{
	_mm_mfence();
	size_t prefix = (16u - ((uintptr_t)src & 15u)) & 15u;
	if (prefix > length) { prefix = length; }
	memcpy(dst, src, prefix); dst += prefix; src += prefix; length -= prefix;
	while (length >= 64u)
	{
		__m128i a = _mm_stream_load_si128((__m128i *)src);
		__m128i b = _mm_stream_load_si128((__m128i *)(src + 16));
		__m128i c = _mm_stream_load_si128((__m128i *)(src + 32));
		__m128i d = _mm_stream_load_si128((__m128i *)(src + 48));
		_mm_storeu_si128((__m128i *)dst, a);
		_mm_storeu_si128((__m128i *)(dst + 16), b);
		_mm_storeu_si128((__m128i *)(dst + 32), c);
		_mm_storeu_si128((__m128i *)(dst + 48), d);
		src += 64; dst += 64; length -= 64;
	}
	while (length >= 16u)
	{
		_mm_storeu_si128((__m128i *)dst, _mm_stream_load_si128((__m128i *)src));
		src += 16; dst += 16; length -= 16;
	}
	memcpy(dst, src, length);
	// Order WC streaming reads before conversion or the end of DMA-BUF CPU access.
	_mm_mfence();
}
#endif

void kvm_capture_copy_linear(void *dst, const void *src, size_t length)
{
	if (length == 0) { return; }
#if defined(KVM_CAPTURE_STREAMING_X86)
	if (__builtin_cpu_supports("sse4.1"))
	{
		kvm_capture_stream_copy(dst, src, length);
		return;
	}
#endif
	memcpy(dst, src, length);
}

#if defined(KVM_CAPTURE_STREAMING_X86) && !defined(KVM_CAPTURE_SCALAR_RGB)
__attribute__((target("ssse3")))
static size_t kvm_capture_rgb32_shuffle(unsigned char *dst, const unsigned char *src,
    size_t pixels, unsigned r, unsigned g, unsigned b)
{
    __m128i order = _mm_setr_epi8(r,g,b,r+4,g+4,b+4,r+8,g+8,b+8,r+12,g+12,b+12,-1,-1,-1,-1);
    size_t done = 0;
    for (; pixels - done >= 4; done += 4, src += 16, dst += 12)
    {
        __m128i packed = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)src), order);
        _mm_storel_epi64((__m128i *)dst, packed);
        uint32_t tail = (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(packed, 8));
        memcpy(dst + 8, &tail, sizeof(tail));
    }
    return done;
}
#endif

void kvm_capture_rgb32_row(unsigned char *dst, const unsigned char *src, size_t pixels,
    unsigned red, unsigned green, unsigned blue)
{
    if (red > 3 || green > 3 || blue > 3) { return; }
    size_t done = 0;
#if defined(KVM_CAPTURE_STREAMING_X86) && !defined(KVM_CAPTURE_SCALAR_RGB)
    if (__builtin_cpu_supports("ssse3"))
        done = kvm_capture_rgb32_shuffle(dst, src, pixels, red, green, blue);
#endif
    src += done * 4; dst += done * 3;
    for (; done < pixels; ++done, src += 4, dst += 3)
    {
        dst[0] = src[red]; dst[1] = src[green]; dst[2] = src[blue];
    }
}

#include <limits.h>

const char *kvm_capture_state_name(kvm_capture_state state)
{
	switch (state)
	{
	case KVM_CAPTURE_STATE_DETACHED: return "detached";
	case KVM_CAPTURE_STATE_DISCOVERING: return "discovering";
	case KVM_CAPTURE_STATE_CAPTURING: return "capturing";
	case KVM_CAPTURE_STATE_SUSPENDED: return "temporarily-suspended";
	case KVM_CAPTURE_STATE_RECOVERING: return "recovering";
	case KVM_CAPTURE_STATE_FAILED: return "failed";
	default: return "unknown";
	}
}

int kvm_capture_checked_rgb_size(uint32_t width, uint32_t height, size_t *size_out)
{
	return kvm_capture_checked_pixel_size(width, height, 3, size_out);
}

int kvm_capture_checked_pixel_size(uint32_t width, uint32_t height, uint32_t bytes_per_pixel,
	size_t *size_out)
{
	uint64_t bytes;
	if (size_out == NULL || width == 0 || height == 0 || bytes_per_pixel == 0 ||
		width > KVM_CAPTURE_MAX_DIMENSION || height > KVM_CAPTURE_MAX_DIMENSION) { return 0; }
	bytes = (uint64_t)width * (uint64_t)height * (uint64_t)bytes_per_pixel;
	if (bytes > KVM_CAPTURE_MAX_BUFFER_BYTES || bytes > SIZE_MAX) { return 0; }
	*size_out = (size_t)bytes;
	return 1;
}

int kvm_capture_checked_map_size(uint32_t offset, uint32_t pitch, uint32_t height, size_t *size_out)
{
	uint64_t bytes;
	if (size_out == NULL || pitch == 0 || height == 0 || height > KVM_CAPTURE_MAX_DIMENSION) { return 0; }
	bytes = (uint64_t)offset + ((uint64_t)pitch * (uint64_t)height);
	if (bytes == 0 || bytes > KVM_CAPTURE_MAX_BUFFER_BYTES || bytes > SIZE_MAX) { return 0; }
	*size_out = (size_t)bytes;
	return 1;
}

int kvm_capture_checked_layout_size(int64_t min_x, int64_t min_y, int64_t max_x, int64_t max_y,
	uint32_t *width_out, uint32_t *height_out)
{
	uint64_t width;
	uint64_t height;
	size_t ignored;
	if (width_out == NULL || height_out == NULL || max_x <= min_x || max_y <= min_y) { return 0; }
	// Unsigned subtraction yields the exact non-negative span even when the signed endpoints
	// straddle their representable range; reject the resulting oversized span below.
	width = (uint64_t)max_x - (uint64_t)min_x;
	height = (uint64_t)max_y - (uint64_t)min_y;
	if (width > UINT32_MAX || height > UINT32_MAX ||
		!kvm_capture_checked_rgb_size((uint32_t)width, (uint32_t)height, &ignored)) { return 0; }
	*width_out = (uint32_t)width;
	*height_out = (uint32_t)height;
	return 1;
}

int kvm_capture_plane_topology_supported(int image_planes, int unknown_active_planes)
{
	if (image_planes < 0 || unknown_active_planes < 0) { return 0; }
	return image_planes + unknown_active_planes <= 1;
}

int kvm_capture_wake_due(uint64_t inactive_since_ms, uint64_t now_ms, uint64_t *last_wake_ms,
    int all_outputs_inactive, int input_available, int session_confirmed)
{
    uint64_t inactive_ms;
    if (last_wake_ms == NULL || inactive_since_ms == 0 || now_ms < inactive_since_ms ||
        !all_outputs_inactive || !input_available || !session_confirmed) { return 0; }
    inactive_ms = now_ms - inactive_since_ms;
    if (inactive_ms < 500 || inactive_ms >= 10000) { return 0; }
    if (*last_wake_ms != 0 && (now_ms < *last_wake_ms || now_ms - *last_wake_ms < 1000)) { return 0; }
    *last_wake_ms = now_ms;
    return 1;
}

int kvm_capture_failure_due(uint64_t *hard_since_ms, uint64_t now_ms,
    int hard_failure, uint64_t retry_ms)
{
    if (hard_since_ms == NULL) { return 0; }
    if (!hard_failure) { *hard_since_ms = 0; return 0; }
    // A failed monotonic clock must not create an unbounded recovery window.
    if (now_ms == 0 || (*hard_since_ms != 0 && now_ms < *hard_since_ms)) { return 1; }
    if (*hard_since_ms == 0) { *hard_since_ms = now_ms; }
    return now_ms - *hard_since_ms >= retry_ms;
}

int kvm_capture_scaled_size(uint32_t width, uint32_t height, int factor, uint32_t *ow, uint32_t *oh)
{
    size_t bytes;
    if (!width || !height || factor < 64 || factor > 4096) return 0;
    uint64_t w = (uint64_t)width * factor / 1024, h = (uint64_t)height * factor / 1024;
    if (!w) w = 1;
    if (!h) h = 1;
    if (w > UINT32_MAX || h > UINT32_MAX || !kvm_capture_checked_rgb_size(w,h,&bytes)) return 0;
    *ow = w; *oh = h; return 1;
}
void kvm_capture_scale_rgb(const unsigned char *src, uint32_t w, uint32_t h, unsigned char *dst, uint32_t ow, uint32_t oh)
{
    if (!src || !dst || !w || !h || !ow || !oh) return;
    uint64_t numerator = (uint64_t)(w-1)*65536;
    uint64_t step = ow>1 ? numerator/(ow-1) : 0;
    uint32_t remainderStep = ow>1 ? numerator%(ow-1) : 0;
    for (uint32_t y=0; y<oh; ++y) {
        uint64_t fy = oh > 1 ? (uint64_t)y * (h-1) * 65536 / (oh-1) : 0;
        uint32_t y0=fy>>16, y1=y0+1<h?y0+1:y0, wy=fy&65535;
        uint64_t fx=0; uint32_t remainder=0;
        for (uint32_t x=0; x<ow; ++x) {
            uint32_t x0=fx>>16,x1=x0+1<w?x0+1:x0,wx=fx&65535;
            for (int c=0;c<3;++c) {
                uint64_t a=src[((size_t)y0*w+x0)*3+c]*(65536-wx)+(uint64_t)src[((size_t)y0*w+x1)*3+c]*wx;
                uint64_t b=src[((size_t)y1*w+x0)*3+c]*(65536-wx)+(uint64_t)src[((size_t)y1*w+x1)*3+c]*wx;
                dst[((size_t)y*ow+x)*3+c]=(a*(65536-wy)+b*wy+(1ULL<<31))>>32;
            }
            fx += step; remainder += remainderStep;
            if (ow>1 && remainder >= ow-1) { ++fx; remainder -= ow-1; }
        }
    }
}

uint32_t kvm_capture_source_coordinate(uint32_t coordinate, uint32_t source, uint32_t output)
{
    if (source < 2 || output < 2) return 0;
    if (coordinate >= output) coordinate = output-1;
    return (uint64_t)coordinate*(source-1)/(output-1);
}
