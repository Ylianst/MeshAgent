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
#include <stdint.h>
#include <limits.h>
#include <setjmp.h>
#include <string.h>

#ifndef JPEGMAXBUF
#define JPEGMAXBUF 65500
#endif
#ifndef LINUX_JPEG_MALLOC
#define LINUX_JPEG_MALLOC malloc
#endif
#ifndef LINUX_JPEG_REALLOC
#define LINUX_JPEG_REALLOC realloc
#endif
/* Retain ordinary output capacity, not an unusually large jumbo high-water mark. */
#define JPEG_RETAIN_LIMIT (4u * 1024u * 1024u)

unsigned char *jpeg_buffer = NULL;
int jpeg_buffer_length = 0;
char jpegLastError[JMSG_LENGTH_MAX];
JPEG_error_handler default_JPEG_error_handler = NULL;

/* Like the existing exported output, this context belongs to one capture worker.
 * No pointer into it escapes to an asynchronous send: tiles own their packets. */
static struct {
    struct jpeg_compress_struct codec;
    struct jpeg_error_mgr errors;
    struct jpeg_destination_mgr destination;
    jmp_buf recovery;
    unsigned char *output;
    size_t capacity;
    int configured, quality;
    jpeg_pixel_format format;
} encoder;

static void reset_codec(void)
{
    if (encoder.codec.mem != NULL) { jpeg_destroy_compress(&encoder.codec); }
    memset(&encoder.codec, 0, sizeof(encoder.codec));
    encoder.configured = 0;
}

void jpeg_discard_output(void)
{
    /* The packed compatibility API transfers ownership instead of borrowing. */
    if (jpeg_buffer != NULL && jpeg_buffer != encoder.output) { free(jpeg_buffer); }
    jpeg_buffer = NULL;
    jpeg_buffer_length = 0;
    if (encoder.capacity > JPEG_RETAIN_LIMIT) {
        free(encoder.output); encoder.output = NULL; encoder.capacity = 0;
    }
}

void jpeg_encoder_cleanup(void)
{
    jpeg_discard_output();
    reset_codec();
    free(encoder.output); encoder.output = NULL; encoder.capacity = 0;
}

static void jpeg_error_handler(j_common_ptr ptr)
{
    (*ptr->err->format_message)(ptr, jpegLastError);
    longjmp(encoder.recovery, 1);
}

static void init_destination(j_compress_ptr cinfo)
{
    if (encoder.output == NULL) {
        encoder.capacity = MAX_BUFFER;
        encoder.output = LINUX_JPEG_MALLOC(encoder.capacity);
        if (encoder.output == NULL) { encoder.capacity = 0; ERREXIT(cinfo, JERR_OUT_OF_MEMORY); }
    }
    cinfo->dest->next_output_byte = encoder.output;
    cinfo->dest->free_in_buffer = encoder.capacity;
}

static boolean empty_output_buffer(j_compress_ptr cinfo)
{
    size_t used = encoder.capacity;
#if JPEGMAXBUF > 0
    if (used > JPEGMAXBUF) {
        jpeg_buffer_length = (int)used;
        longjmp(encoder.recovery, 2); /* Oversize is a tile-splitting request. */
    }
#endif
    if (used >= (size_t)INT_MAX - 16u) { ERREXIT(cinfo, JERR_OUT_OF_MEMORY); }
    size_t next = used > ((size_t)INT_MAX - 16u) / 2u ? (size_t)INT_MAX - 16u : used * 2u;
#if JPEGMAXBUF > 0
    if (next > (size_t)JPEGMAXBUF + 1u) { next = (size_t)JPEGMAXBUF + 1u; }
#endif
    unsigned char *grown = LINUX_JPEG_REALLOC(encoder.output, next);
    if (grown == NULL) { ERREXIT(cinfo, JERR_OUT_OF_MEMORY); }
    encoder.output = grown; encoder.capacity = next;
    cinfo->dest->next_output_byte = grown + used;
    cinfo->dest->free_in_buffer = next - used;
    return TRUE;
}

static void term_destination(j_compress_ptr cinfo)
{
    jpeg_buffer_length = (int)(encoder.capacity - cinfo->dest->free_in_buffer);
}

/* Packed callers (including macOS) keep the original caller-owned result and
 * per-call codec lifetime. Linux's strided capture API opts into reuse. */
int write_JPEG_buffer(JSAMPLE *image_buffer, int width, int height, int quality)
{
    int result = write_JPEG_buffer_strided(image_buffer, width, height, width > 0 ? (size_t)width * 3u : 0, quality);
    if (jpeg_buffer != NULL) { encoder.output = NULL; encoder.capacity = 0; }
    else { free(encoder.output); encoder.output = NULL; encoder.capacity = 0; }
    reset_codec();
    if (result < 0 && default_JPEG_error_handler != NULL) { default_JPEG_error_handler(jpegLastError); }
    return result;
}

int write_JPEG_buffer_strided(JSAMPLE *image_buffer, int width, int height, size_t stride, int quality)
{
    return write_JPEG_buffer_pixels(image_buffer, width, height, stride, quality, JPEG_RGB24);
}

int jpeg_rgb32_supported(jpeg_pixel_format format)
{
#ifdef JCS_EXTENSIONS
    return format >= JPEG_BGRX32 && format <= JPEG_XRGB32;
#else
    (void)format;
    return 0;
#endif
}

int write_JPEG_buffer_pixels(JSAMPLE *image_buffer, int width, int height, size_t stride,
    int quality, jpeg_pixel_format format)
{
    jpeg_discard_output();
    int components = format == JPEG_RGB24 ? 3 : 4;
    J_COLOR_SPACE color = JCS_RGB;
    if (format != JPEG_RGB24 && !jpeg_rgb32_supported(format)) {
        strcpy(jpegLastError, "Unsupported JPEG input format"); return -1;
    }
#ifdef JCS_EXTENSIONS
    switch (format) {
    case JPEG_BGRX32: color = JCS_EXT_BGRX; break;
    case JPEG_RGBX32: color = JCS_EXT_RGBX; break;
    case JPEG_XBGR32: color = JCS_EXT_XBGR; break;
    case JPEG_XRGB32: color = JCS_EXT_XRGB; break;
    default: break;
    }
#endif
    if (image_buffer == NULL || width <= 0 || height <= 0 ||
        width > JPEG_MAX_DIMENSION || height > JPEG_MAX_DIMENSION ||
        stride < (size_t)width * components || (height > 1 &&
        stride > (SIZE_MAX - (size_t)width * components) / (size_t)(height - 1))) {
        strcpy(jpegLastError, "Invalid JPEG image geometry");
        return -1;
    }
    /* All state modified across the error jump has static storage duration. */
    int failure = setjmp(encoder.recovery);
    if (failure != 0) {
        if (failure == 2) { jpeg_abort_compress(&encoder.codec); return 0; }
        jpeg_encoder_cleanup();
        return -1;
    }
    if (encoder.codec.mem == NULL) {
        encoder.codec.err = jpeg_std_error(&encoder.errors);
        encoder.errors.error_exit = jpeg_error_handler;
        jpeg_create_compress(&encoder.codec);
    }
    encoder.destination.init_destination = init_destination;
    encoder.destination.empty_output_buffer = empty_output_buffer;
    encoder.destination.term_destination = term_destination;
    encoder.codec.dest = &encoder.destination;
    encoder.codec.image_width = width; encoder.codec.image_height = height;
    int reconfigure = !encoder.configured || encoder.format != format;
    if (reconfigure) {
        encoder.codec.input_components = components; encoder.codec.in_color_space = color;
        jpeg_set_defaults(&encoder.codec);
        for (int i = 0; i < 3; ++i) {
            encoder.codec.comp_info[i].v_samp_factor = 1;
            encoder.codec.comp_info[i].h_samp_factor = 1;
        }
    }
    if (reconfigure || encoder.quality != quality) {
        jpeg_set_quality(&encoder.codec, quality, TRUE);
        encoder.quality = quality;
    }
    encoder.configured = 1;
    encoder.format = format;
    jpeg_start_compress(&encoder.codec, TRUE);
    while (encoder.codec.next_scanline < encoder.codec.image_height) {
        JSAMPROW row = image_buffer + (size_t)encoder.codec.next_scanline * stride;
        if (jpeg_write_scanlines(&encoder.codec, &row, 1) != 1) {
            ERREXIT(&encoder.codec, JERR_CANT_SUSPEND);
        }
    }
    jpeg_finish_compress(&encoder.codec);
#if JPEGMAXBUF > 0
    if (jpeg_buffer_length > JPEGMAXBUF) { return 0; }
#endif
    jpeg_buffer = encoder.output;
    jpegLastError[0] = 0;
    return 0;
}
