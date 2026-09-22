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

#include "linux_compression.h"
#include "../../../microstack/ILibParsers.h"
#include <time.h>
#if defined(KVM_WEBP) || defined(KVM_AVIF)
#include <dlfcn.h>
#include <limits.h>
#endif
#ifdef KVM_WEBP
#include <webp/encode.h>
#endif
#ifdef KVM_AVIF
#include <avif/avif.h>
#include <unistd.h>
#endif

#if defined(JPEGMAXBUF)
	#define MAX_TILE_SIZE JPEGMAXBUF
#else
	#define MAX_TILE_SIZE 65500
#endif

unsigned char *jpeg_buffer = NULL;
int jpeg_buffer_length = 0;
char jpegLastError[JMSG_LENGTH_MAX];
JPEG_error_handler default_JPEG_error_handler = NULL;

#ifdef KVM_WEBP
static struct
{
	int initialized, available;
	__typeof__(&WebPConfigInitInternal) config_init;
	__typeof__(&WebPConfigLosslessPreset) lossless_preset;
	__typeof__(&WebPPictureInitInternal) picture_init;
	__typeof__(&WebPPictureImportRGB) import_rgb;
	__typeof__(&WebPEncode) encode;
	__typeof__(&WebPPictureFree) picture_free;
} webp;

static int load_webp(void)
{
	if (webp.initialized) return webp.available;
	webp.initialized = 1;
#ifdef __APPLE__
	void *library = dlopen("libwebp.7.dylib", RTLD_NOW | RTLD_LOCAL);
	if (library == NULL) library = dlopen("libwebp.dylib", RTLD_NOW | RTLD_LOCAL);
#else
	void *library = dlopen("libwebp.so.7", RTLD_NOW | RTLD_LOCAL);
	if (library == NULL) library = dlopen("libwebp.so", RTLD_NOW | RTLD_LOCAL);
#endif
	if (library == NULL) return 0;
#define WEBP_LOAD(member, symbol) webp.member = (__typeof__(webp.member))dlsym(library, #symbol); if (webp.member == NULL) { dlclose(library); return 0; }
	WEBP_LOAD(config_init, WebPConfigInitInternal);
	WEBP_LOAD(lossless_preset, WebPConfigLosslessPreset);
	WEBP_LOAD(picture_init, WebPPictureInitInternal);
	WEBP_LOAD(import_rgb, WebPPictureImportRGB);
	WEBP_LOAD(encode, WebPEncode);
	WEBP_LOAD(picture_free, WebPPictureFree);
#undef WEBP_LOAD
	webp.available = 1;
	return 1;
}

struct webp_buffer
{
	unsigned char *data;
	size_t length, capacity;
};

static int write_webp_chunk(const unsigned char *data, size_t length, const WebPPicture *picture)
{
	struct webp_buffer *buffer = picture->custom_ptr;
	if (length == 0) return 1;
	if (length > (size_t)(INT_MAX - 16) - buffer->length) return 0;
	size_t needed = buffer->length + length;
	if (needed > buffer->capacity)
	{
		size_t capacity = buffer->capacity * 2;
		if (capacity < needed || capacity > INT_MAX - 16) capacity = needed;
		unsigned char *resized = realloc(buffer->data, capacity);
		if (resized == NULL) return 0;
		buffer->data = resized;
		buffer->capacity = capacity;
	}
	memcpy(buffer->data + buffer->length, data, length);
	buffer->length += length;
	return 1;
}

static int write_WEBP_buffer(JSAMPLE *pixels, int width, int height, size_t stride, int quality)
{
	if (width < 1 || height < 1 || width > WEBP_MAX_DIMENSION || height > WEBP_MAX_DIMENSION || stride > INT_MAX || !load_webp()) return 0;
	WebPConfig config;
	WebPPicture picture;
	struct webp_buffer output = { 0 };
	if (!webp.config_init(&config, WEBP_PRESET_DEFAULT, (float)quality, WEBP_ENCODER_ABI_VERSION)) return 0;
	if (quality == 100)
	{
		if (!webp.lossless_preset(&config, 1)) return 0;
	}
	else { config.method = 0; }
	config.thread_level = 0;
	if (!webp.picture_init(&picture, WEBP_ENCODER_ABI_VERSION)) return 0;
	picture.width = width;
	picture.height = height;
	picture.use_argb = config.lossless;
	picture.writer = write_webp_chunk;
	picture.custom_ptr = &output;
	int success = webp.import_rgb(&picture, pixels, (int)stride) && webp.encode(&config, &picture);
	webp.picture_free(&picture);
	if (!success || output.length == 0) { free(output.data); return 0; }
	free(jpeg_buffer);
	jpeg_buffer = output.data;
	jpeg_buffer_length = (int)output.length;
#if MAX_TILE_SIZE > 0
	if (jpeg_buffer_length > MAX_TILE_SIZE) { free(jpeg_buffer); jpeg_buffer = NULL; }
#endif
	return 1;
}
#endif

#ifdef KVM_AVIF
static struct
{
	int initialized, available, codec_svt, codec_aom, screen_checked, screen_ok;
	__typeof__(&avifVersion) version;
	__typeof__(&avifCodecName) codec_name;
	__typeof__(&avifImageCreate) image_create;
	__typeof__(&avifImageDestroy) image_destroy;
	__typeof__(&avifRGBImageSetDefaults) rgb_defaults;
	__typeof__(&avifImageRGBToYUV) rgb_to_yuv;
	__typeof__(&avifEncoderCreate) encoder_create;
	__typeof__(&avifEncoderDestroy) encoder_destroy;
	__typeof__(&avifEncoderSetCodecSpecificOption) set_option;
	__typeof__(&avifEncoderWrite) encode;
	__typeof__(&avifRWDataFree) data_free;
} avif;

static int load_avif(void)
{
	if (avif.initialized) return avif.available;
	avif.initialized = 1;
#ifdef __APPLE__
	const char *names[] = { "libavif.16.dylib", "libavif.15.dylib", "libavif.13.dylib", "libavif.dylib" };
#else
	const char *names[] = { "libavif.so.16", "libavif.so.15", "libavif.so.13", "libavif.so" };
#endif
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
	{
		void *library = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
		if (library == NULL) continue;
#define AVIF_LOAD(member, symbol) avif.member = (__typeof__(avif.member))dlsym(library, #symbol); if (avif.member == NULL) { dlclose(library); continue; }
		AVIF_LOAD(version, avifVersion);
		char version[48];
		snprintf(version, sizeof(version), "%d.%d.%d", AVIF_VERSION_MAJOR, AVIF_VERSION_MINOR, AVIF_VERSION_PATCH);
		// libavif exposes structs without the versioned initialization used by libwebp.
		if (strcmp(avif.version(), version) != 0) { dlclose(library); continue; }
		AVIF_LOAD(codec_name, avifCodecName);
		// libaom is faster and smaller than SVT-AV1 on still tiles (measured), so it is preferred below;
		// SVT is only a fallback when a libavif build ships without libaom.
		avif.codec_svt = avif.codec_name(AVIF_CODEC_CHOICE_SVT, AVIF_CODEC_FLAG_CAN_ENCODE) != NULL;
		avif.codec_aom = avif.codec_name(AVIF_CODEC_CHOICE_AOM, AVIF_CODEC_FLAG_CAN_ENCODE) != NULL;
		if (!avif.codec_svt && !avif.codec_aom) { dlclose(library); continue; }
		AVIF_LOAD(image_create, avifImageCreate);
		AVIF_LOAD(image_destroy, avifImageDestroy);
		AVIF_LOAD(rgb_defaults, avifRGBImageSetDefaults);
		AVIF_LOAD(rgb_to_yuv, avifImageRGBToYUV);
		AVIF_LOAD(encoder_create, avifEncoderCreate);
		AVIF_LOAD(encoder_destroy, avifEncoderDestroy);
		AVIF_LOAD(set_option, avifEncoderSetCodecSpecificOption);
		AVIF_LOAD(encode, avifEncoderWrite);
		AVIF_LOAD(data_free, avifRWDataFree);
#undef AVIF_LOAD
		avif.available = 1;
		return 1;
	}
	return 0;
}

// libaom hard-fails avifEncoderWrite on an unknown codec option, so confirm "tune-content=screen"
// encodes once (older fleet libaom may lack the key) before enabling it on real tiles.
static int avif_screen_content_ok(void)
{
	if (avif.screen_checked) return avif.screen_ok;
	avif.screen_checked = 1;
	if (!avif.codec_aom) return 0;
	avifImage *image = avif.image_create(64, 64, 8, AVIF_PIXEL_FORMAT_YUV420);
	if (image == NULL) return 0;
	image->colorPrimaries = AVIF_COLOR_PRIMARIES_BT709;
	image->transferCharacteristics = AVIF_TRANSFER_CHARACTERISTICS_SRGB;
	image->matrixCoefficients = AVIF_MATRIX_COEFFICIENTS_BT601;
	image->yuvRange = AVIF_RANGE_FULL;
	unsigned char pixels[64 * 64 * 3] = { 0 };
	avifRGBImage rgb;
	avif.rgb_defaults(&rgb, image);
	rgb.format = AVIF_RGB_FORMAT_RGB;
	rgb.pixels = pixels;
	rgb.rowBytes = 64 * 3;
	avifEncoder *encoder = NULL;
	avifRWData output = { NULL, 0 };
	if (avif.rgb_to_yuv(image, &rgb) == AVIF_RESULT_OK && (encoder = avif.encoder_create()) != NULL)
	{
		encoder->codecChoice = AVIF_CODEC_CHOICE_AOM;
		encoder->speed = 10;
		encoder->maxThreads = 1;
		avif.set_option(encoder, "tune-content", "screen");
		avif.screen_ok = avif.encode(encoder, image, &output) == AVIF_RESULT_OK;
	}
	avif.data_free(&output);
	if (encoder != NULL) avif.encoder_destroy(encoder);
	avif.image_destroy(image);
	return avif.screen_ok;
}

static int write_AVIF_buffer(JSAMPLE *pixels, int width, int height, size_t stride, int quality)
{
	if (width < 1 || height < 1 || (size_t)width > 2097152 / (size_t)height || stride > UINT32_MAX || stride < (size_t)width * 3 || !load_avif()) return 0;
	avifImage *image = avif.image_create(width, height, 8, quality == 100 ? AVIF_PIXEL_FORMAT_YUV444 : AVIF_PIXEL_FORMAT_YUV420);
	if (image == NULL) return 0;
	image->colorPrimaries = AVIF_COLOR_PRIMARIES_BT709;
	image->transferCharacteristics = AVIF_TRANSFER_CHARACTERISTICS_SRGB;
	image->matrixCoefficients = quality == 100 ? AVIF_MATRIX_COEFFICIENTS_IDENTITY : AVIF_MATRIX_COEFFICIENTS_BT601;
	image->yuvRange = AVIF_RANGE_FULL;
	avifRGBImage rgb;
	avif.rgb_defaults(&rgb, image);
	rgb.format = AVIF_RGB_FORMAT_RGB;
	rgb.pixels = pixels;
	rgb.rowBytes = (uint32_t)stride;
	avifEncoder *encoder = NULL;
	avifRWData output = { NULL, 0 };
	int success = 0;
	if (avif.rgb_to_yuv(image, &rgb) != AVIF_RESULT_OK) goto done;
	encoder = avif.encoder_create();
	if (encoder == NULL) goto done;
	long threads = sysconf(_SC_NPROCESSORS_ONLN);
	// Prefer libaom (best speed and size for still tiles); SVT is a fallback and cannot do lossless 4:4:4.
	int use_svt = !avif.codec_aom && avif.codec_svt;
	encoder->codecChoice = use_svt ? AVIF_CODEC_CHOICE_SVT : AVIF_CODEC_CHOICE_AOM;
	encoder->quality = quality;
	// libaom speed 8 roughly halves encode time versus 6 at the same size; lossless keeps 6.
	encoder->speed = quality < 100 ? 8 : 6;
	encoder->maxThreads = threads < 1 ? 1 : threads > 4 ? 4 : (int)threads;
	// AV1 screen-content tools (palette, intra block copy) cut desktop-tile size ~11%; lossy libaom only.
	if (!use_svt && quality < 100 && avif_screen_content_ok()) avif.set_option(encoder, "tune-content", "screen");
	if (avif.encode(encoder, image, &output) != AVIF_RESULT_OK || output.size == 0 || output.size > INT_MAX - 16) goto done;
	unsigned char *buffer = malloc(output.size);
	if (buffer == NULL) goto done;
	memcpy(buffer, output.data, output.size);
	free(jpeg_buffer);
	jpeg_buffer = buffer;
	jpeg_buffer_length = (int)output.size;
#if MAX_TILE_SIZE > 0
	if (jpeg_buffer_length > MAX_TILE_SIZE) { free(jpeg_buffer); jpeg_buffer = NULL; }
#endif
	success = 1;
done:
	avif.data_free(&output);
	if (encoder != NULL) avif.encoder_destroy(encoder);
	avif.image_destroy(image);
	return success;
}
#endif

static struct
{
	int formats, quality, selected, wins;
	int avif_active, avif_wins;
	double rate, decode[3], feedback_time, probe_time;
	double avif_probe_time, avif_retry_time, large_time, baseline_time;
} automatic;

static double image_time(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0;
}

int image_auto_configure(int formats, int quality)
{
	int available = 1;
#ifdef KVM_WEBP
	if (load_webp()) available |= 2;
#endif
#ifdef KVM_AVIF
	if (avif.available || ((formats & 4) && load_avif())) available |= 4;
#endif
	formats &= available;
	if (automatic.formats != formats || automatic.quality != quality)
	{
		memset(&automatic, 0, sizeof(automatic));
		automatic.formats = formats;
		automatic.quality = quality;
		automatic.selected = 1;
	}
	return available;
}

void image_auto_feedback(unsigned int bytes_per_second, unsigned short jpeg_ms, unsigned short webp_ms, unsigned short avif_ms)
{
	if (!automatic.formats) return;
	if (bytes_per_second < 1024) bytes_per_second = 1024;
	if (bytes_per_second > 125000000) bytes_per_second = 125000000;
	double now = image_time();
	if (automatic.rate > 0 && bytes_per_second <= automatic.rate * 0.5)
	{
		// Reprice the next update without bypassing an encoder failure backoff.
		if (automatic.probe_time <= now) automatic.probe_time = 0;
		automatic.avif_probe_time = 0;
		automatic.wins = automatic.avif_wins = 0;
	}
	automatic.rate = bytes_per_second;
	automatic.decode[0] = jpeg_ms > 1000 ? 1000 : jpeg_ms;
	automatic.decode[1] = webp_ms > 1000 ? 1000 : webp_ms;
	automatic.decode[2] = avif_ms > 1000 ? 1000 : avif_ms ? avif_ms : 50;
	automatic.feedback_time = now;
}

#ifdef KVM_WEBP
static void image_auto_consider(const double cost[2])
{
	int current = automatic.selected == 4 ? 1 : 0;
	if (cost[1 - current] < cost[current] * 0.8)
	{
		if ((current == 0 && automatic.rate <= 250000 && cost[1] < cost[0] * 0.6) || ++automatic.wins >= 2) { automatic.selected = current ? 1 : 4; automatic.wins = 0; }
	}
	else { automatic.wins = 0; }
}

static int select_image_type(JSAMPLE *pixels, int width, int height, size_t stride, int quality)
{
	double now = image_time();
	if (!(automatic.formats & 2) || width > WEBP_MAX_DIMENSION || height > WEBP_MAX_DIMENSION) return 1;
	// Quality 100 retains WebP's lossless policy; it is not a JPEG/WebP race.
	if (quality == 100) return 4;
	if (automatic.rate == 0 || now - automatic.feedback_time > 10000) { automatic.selected = 1; automatic.wins = 0; return 1; }
	if (automatic.probe_time != 0 && now - automatic.probe_time < 3000) return automatic.selected;
	automatic.probe_time = now;
	double cost[2] = { 0, 0 };
	int w = width < 128 ? width : 128, h = height < 128 ? height : 128;
	// Sample separate parts of the same region, with a fixed CPU and allocation bound.
	for (int i = 0; i < 3; ++i)
	{
		JSAMPLE *sample = pixels + ((height - h) * i / 2) * stride + ((width - w) * i / 2) * 3;
		for (int codec = 0; codec < 2; ++codec)
		{
			double start = image_time();
			if (codec == 0) { write_JPEG_buffer(sample, w, h, stride, quality); }
			else if (!write_WEBP_buffer(sample, w, h, stride, quality))
			{
				automatic.selected = 1;
				automatic.wins = 0;
				automatic.probe_time = now + 27000;
				return 1;
			}
			cost[codec] += image_time() - start + jpeg_buffer_length * 1000.0 / automatic.rate + automatic.decode[codec] * w * h / 1000000.0;
		}
	}
	image_auto_consider(cost);
	return automatic.selected;
}
#endif

#ifdef KVM_AVIF
static int image_auto_avif_consider(double cost, double baseline_cost)
{
	if (cost < baseline_cost * (automatic.avif_active ? 0.9 : 0.8))
	{
		// A full encode has already paid the probe cost; use a decisive win immediately.
		if (automatic.avif_active || cost < baseline_cost * 0.6 || ++automatic.avif_wins >= 2)
		{
			automatic.avif_active = 1;
			automatic.avif_wins = 0;
			return 1;
		}
	}
	else { automatic.avif_active = automatic.avif_wins = 0; }
	return 0;
}

static void image_auto_avif(JSAMPLE *pixels, int width, int height, size_t stride, int quality, int type, double baseline_ms)
{
	double now = image_time(), area = (double)width * height;
	if (area < 262144) return;
	double interval = automatic.large_time == 0 ? 1000 : now - automatic.large_time;
	automatic.large_time = now;
	if (!(automatic.formats & 4) || quality >= 100 || area > 2097152 || automatic.rate == 0 || automatic.rate > 250000 || now - automatic.feedback_time > 10000)
	{
		automatic.avif_active = automatic.avif_wins = 0;
		automatic.baseline_time = now;
		return;
	}
	if (interval < 1000 || now < automatic.avif_retry_time || (!automatic.avif_active && now < automatic.avif_probe_time)) return;
	// Periodic baseline tiles avoid estimating a recovered fast link from tiny AVIF payloads.
	if (automatic.avif_active && now - automatic.baseline_time > 15000) { automatic.baseline_time = now; return; }
	if (jpeg_buffer == NULL || jpeg_buffer_length * 1000.0 / automatic.rate < 500) return;
	automatic.avif_probe_time = now + 5000;
	unsigned char *baseline = jpeg_buffer;
	int baseline_length = jpeg_buffer_length;
	jpeg_buffer = NULL;
	jpeg_buffer_length = 0;
	double started = image_time();
	int success = write_AVIF_buffer(pixels, width, height, stride, quality < 90 ? quality + 10 : 99);
	double elapsed = image_time() - started;
	double cost = baseline_ms + elapsed + jpeg_buffer_length * 1000.0 / automatic.rate + automatic.decode[2] * area / 1000000.0;
	double baseline_cost = baseline_ms + baseline_length * 1000.0 / automatic.rate + automatic.decode[type == 4 ? 1 : 0] * area / 1000000.0;
	if (!success || jpeg_buffer == NULL || elapsed > 500)
	{
		automatic.avif_active = automatic.avif_wins = 0;
		automatic.avif_retry_time = now + 30000;
	}
	else if (image_auto_avif_consider(cost, baseline_cost))
	{
		free(baseline);
		return;
	}
	free(jpeg_buffer);
	jpeg_buffer = baseline;
	jpeg_buffer_length = baseline_length;
	automatic.baseline_time = now;
}
#endif

int write_image_buffer(JSAMPLE *image_buffer, int image_width, int image_height, size_t row_stride, int type, int quality)
{
	int is_auto = type == 0;
#ifdef KVM_WEBP
	if (type == 0) type = select_image_type(image_buffer, image_width, image_height, row_stride, quality);
#endif
	double started = image_time();
#ifdef KVM_AVIF
	if (type == 5 && write_AVIF_buffer(image_buffer, image_width, image_height, row_stride, quality)) return 0;
#endif
#ifdef KVM_WEBP
	// Keep JPEG available when the optional library is missing or cannot encode this region.
	if (type != 4 || !write_WEBP_buffer(image_buffer, image_width, image_height, row_stride, quality))
#endif
	{
		type = 1;
		write_JPEG_buffer(image_buffer, image_width, image_height, row_stride, quality);
	}
#ifdef KVM_AVIF
	if (is_auto) image_auto_avif(image_buffer, image_width, image_height, row_stride, quality, type, image_time() - started);
#else
	(void)is_auto;
	(void)started;
#endif
	return 0;
}

void jpeg_error_handler(j_common_ptr ptr)
{
	// Build the error string
	(*(ptr->err->format_message)) (ptr, jpegLastError);

	if (default_JPEG_error_handler != NULL) { default_JPEG_error_handler(jpegLastError); }
	exit(1);
}

void init_destination(j_compress_ptr cinfo)
{
	JOCTET * next_output_byte;
	if (jpeg_buffer != NULL) { free(jpeg_buffer); }
	if ((jpeg_buffer = malloc(MAX_BUFFER)) == NULL) { ILIBCRITICALEXIT(254); }
	jpeg_buffer_length = 0;
	next_output_byte = jpeg_buffer;
	cinfo->dest->next_output_byte = next_output_byte;
	cinfo->dest->free_in_buffer = MAX_BUFFER;
}

boolean empty_output_buffer(j_compress_ptr cinfo)
{
	JOCTET * next_output_byte;

	jpeg_buffer_length += MAX_BUFFER;
	if ((jpeg_buffer = (unsigned char *)realloc(jpeg_buffer, jpeg_buffer_length + MAX_BUFFER)) == NULL) { ILIBCRITICALEXIT(254); }
	next_output_byte = jpeg_buffer + jpeg_buffer_length;
	cinfo->dest->next_output_byte = next_output_byte;
	cinfo->dest->free_in_buffer = MAX_BUFFER;

#if MAX_TILE_SIZE > 0
	if ( jpeg_buffer_length > MAX_TILE_SIZE) return FALSE;
#endif
	return TRUE;
}

void term_destination (j_compress_ptr cinfo)
{
	int remaining_buff_length = MAX_BUFFER - cinfo->dest->free_in_buffer;

	jpeg_buffer_length += remaining_buff_length;

#if MAX_TILE_SIZE > 0
	if (jpeg_buffer_length > MAX_TILE_SIZE)
	{
		free(jpeg_buffer);
		jpeg_buffer = NULL;
	}
	else 
#endif
	{
		if ((jpeg_buffer = (unsigned char *)realloc(jpeg_buffer, jpeg_buffer_length)) == NULL) { ILIBCRITICALEXIT(254); }
	}
}

int write_JPEG_buffer(JSAMPLE *image_buffer, int image_width, int image_height, size_t row_stride, int quality)
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;
	JSAMPROW row_pointer[16];

	cinfo.err = jpeg_std_error(&jerr);
	if (default_JPEG_error_handler != NULL) { jerr.error_exit = jpeg_error_handler; }

	jpeg_create_compress(&cinfo);
	cinfo.dest = (struct jpeg_destination_mgr *) malloc(sizeof(struct jpeg_destination_mgr));
	cinfo.dest->init_destination = &init_destination;
	cinfo.dest->empty_output_buffer = &empty_output_buffer;
	cinfo.dest->term_destination = &term_destination;

	cinfo.image_width = image_width;
	cinfo.image_height = image_height;
	cinfo.input_components = 3;
	cinfo.in_color_space = JCS_RGB;
	jpeg_set_defaults(&cinfo);

	// 4:4:4, 1x1 (no subsampling)
	// The resolution of chrominance information (Cb & Cr) is preserved at the same rate as the luminance (Y) information
	cinfo.comp_info[0].v_samp_factor = 1;
	cinfo.comp_info[0].h_samp_factor = 1;
	cinfo.comp_info[1].v_samp_factor = 1;
	cinfo.comp_info[1].h_samp_factor = 1;
	cinfo.comp_info[2].v_samp_factor = 1;
	cinfo.comp_info[2].h_samp_factor = 1;

	jpeg_set_quality(&cinfo, quality, TRUE);
	jpeg_start_compress(&cinfo, TRUE);

	while (cinfo.next_scanline < cinfo.image_height)
	{
		JDIMENSION rows = cinfo.image_height - cinfo.next_scanline;
		if (rows > 16) { rows = 16; }
		for (JDIMENSION i = 0; i < rows; ++i) { row_pointer[i] = &image_buffer[(cinfo.next_scanline + i) * row_stride]; }
		(void)jpeg_write_scanlines(&cinfo, row_pointer, rows);
	}

	jpeg_finish_compress(&cinfo);

	free(cinfo.dest);
	cinfo.dest = NULL;
	jpeg_destroy_compress(&cinfo);

	return 0;
}
