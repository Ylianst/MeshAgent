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
#include <stddef.h>
#ifdef __APPLE__
#include "lib-jpeg-turbo/includes/jpeglib.h"
#include "lib-jpeg-turbo/includes/jerror.h"
#else
#include <jpeglib.h>
#include <jerror.h>
#endif

#define MAX_BUFFER  22528 // The output buffer starts at 22 KiB and doubles when a JPEG needs more
#define JPEG_HEADER_ROOM 16

typedef void(*JPEG_error_handler)(char *msg);

extern int write_JPEG_buffer (JSAMPLE * image_buffer, int image_width, int image_height, int quality);
// Encodes a rectangle straight from the caller's pixels. stride is the byte distance between two rows, negative for a bottom-up frame, components the bytes per pixel.
// Returns the JPEG and sets *length. The JPEG lies in the encoder's one output buffer and holds until the next call.
// JPEG_HEADER_ROOM bytes in front of the JPEG are free for a packet header, so a packet needs no copy.
extern unsigned char *write_JPEG_rect(const unsigned char *pixels, ptrdiff_t stride, int image_width, int image_height, int components, J_COLOR_SPACE format, int quality, int *length);
extern void jpeg_output_free(void);
extern JPEG_error_handler default_JPEG_error_handler;

#endif // LINUX_COMPRESSION_H_ 
