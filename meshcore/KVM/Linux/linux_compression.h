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

#ifndef LINUX_COMPRESSION_H_
#define LINUX_COMPRESSION_H_

#include <stdio.h>
#include <stdlib.h>
#ifdef __APPLE__
#include "lib-jpeg-turbo/includes/jpeglib.h"
#include "lib-jpeg-turbo/includes/jerror.h"
#else
#include <jpeglib.h>
#include <jerror.h>
#endif

#define MAX_BUFFER  22528 // 22 KiB should be fine.

typedef void(*JPEG_error_handler)(char *msg);

/** Legacy packed RGB24 entry point: publishes caller-owned jpeg_buffer storage.
 * The caller frees it. Unlike the reusable interfaces below, this detaches the
 * packet and destroys codec state to preserve the historical ownership contract.
 */
extern int write_JPEG_buffer (JSAMPLE * image_buffer, int image_width, int image_height, int quality);
/** Encode top-down RGB24 rows without repacking source padding; see pixels(). */
extern int write_JPEG_buffer_strided(JSAMPLE *image_buffer, int image_width, int image_height, size_t row_stride, int quality);
/* Byte order in private ordinary RAM, independent of DRM's native-endian names. */
typedef enum { JPEG_RGB24, JPEG_BGRX32, JPEG_RGBX32, JPEG_XBGR32, JPEG_XRGB32 } jpeg_pixel_format;
extern int jpeg_rgb32_supported(jpeg_pixel_format format);
/** Encode validated ordinary-RAM rows, reusing this capture worker's codec.
 * Non-reentrant: input and published globals belong to one capture worker.
 * @return -1 on error, 0 for completion OR an oversize tile-splitting request.
 * A usable image additionally requires non-NULL jpeg_buffer and a valid length;
 * an oversize request publishes no buffer but retains the reported size hint.
 * Output is borrowed until the next encode/discard/cleanup, not send-owned.
 */
extern int write_JPEG_buffer_pixels(JSAMPLE *image_buffer, int image_width, int image_height,
    size_t row_stride, int quality, jpeg_pixel_format format);
extern JPEG_error_handler default_JPEG_error_handler;

/* Strided output is borrowed until the next encode/discard/cleanup. Packet
 * callers must copy it before discarding; packed output remains caller-owned. */
extern void jpeg_discard_output(void);
extern void jpeg_encoder_cleanup(void);

#endif // LINUX_COMPRESSION_H_ 
