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

#define TILE_JPEG_OPTIMIZE_MAX_AREA (128 * 128)

// Filled by write_JPEG_buffer() only, with a copy that the caller frees
unsigned char *jpeg_buffer = NULL;
int jpeg_buffer_length = 0;
char jpegLastError[JMSG_LENGTH_MAX];
JPEG_error_handler default_JPEG_error_handler = NULL;

// One output buffer for all rectangles. It only grows, and it has room for a packet header in front of the JPEG.
static unsigned char *jpegOut = NULL;
static size_t jpegOutSize = 0;
static int jpegOutLength = 0;

void jpeg_error_handler(j_common_ptr ptr)
{
	// Build the error string
	(*(ptr->err->format_message)) (ptr, jpegLastError);

	if (default_JPEG_error_handler != NULL) { default_JPEG_error_handler(jpegLastError); }
	exit(1);
}

void init_destination(j_compress_ptr cinfo)
{
	if (jpegOut == NULL)
	{
		jpegOutSize = JPEG_HEADER_ROOM + MAX_BUFFER;
		if ((jpegOut = (unsigned char *)malloc(jpegOutSize)) == NULL) { ILIBCRITICALEXIT(254); }
	}
	jpegOutLength = 0;
	cinfo->dest->next_output_byte = jpegOut + JPEG_HEADER_ROOM;
	cinfo->dest->free_in_buffer = jpegOutSize - JPEG_HEADER_ROOM;
}

boolean empty_output_buffer(j_compress_ptr cinfo)
{
	// libjpeg calls this with the whole buffer used, whatever free_in_buffer says
	size_t used = jpegOutSize;

	if ((jpegOut = (unsigned char *)realloc(jpegOut, jpegOutSize * 2)) == NULL) { ILIBCRITICALEXIT(254); }
	jpegOutSize *= 2;
	cinfo->dest->next_output_byte = jpegOut + used;
	cinfo->dest->free_in_buffer = jpegOutSize - used;

	return TRUE;
}

void term_destination (j_compress_ptr cinfo)
{
	jpegOutLength = (int)(jpegOutSize - JPEG_HEADER_ROOM - cinfo->dest->free_in_buffer);
}

void jpeg_output_free(void)
{
	free(jpegOut);
	jpegOut = NULL;
	jpegOutSize = 0;
	jpegOutLength = 0;
}

unsigned char *write_JPEG_rect(const unsigned char *pixels, size_t stride, int image_width, int image_height, int components, J_COLOR_SPACE format, int quality, int *length)
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;
	struct jpeg_destination_mgr dest;
	JSAMPROW row_pointer[1];

	cinfo.err = jpeg_std_error(&jerr);
	if (default_JPEG_error_handler != NULL) { jerr.error_exit = jpeg_error_handler; }

	jpeg_create_compress(&cinfo);
	dest.init_destination = &init_destination;
	dest.empty_output_buffer = &empty_output_buffer;
	dest.term_destination = &term_destination;
	cinfo.dest = &dest;

	cinfo.image_width = image_width;
	cinfo.image_height = image_height;
	cinfo.input_components = components;
	cinfo.in_color_space = format;
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
	// Huffman tables built for each rectangle up to 128x128, where the standard tables are a large share of a small JPEG. Larger rectangles gain less for the second pass over the data.
	if ((long)image_width * image_height <= TILE_JPEG_OPTIMIZE_MAX_AREA) { cinfo.optimize_coding = TRUE; }
	jpeg_start_compress(&cinfo, TRUE);

	// The rows are read where they lie in the caller's frame, so no copy of the rectangle is made
	while (cinfo.next_scanline < cinfo.image_height)
	{
		row_pointer[0] = (JSAMPROW)(pixels + (size_t)cinfo.next_scanline * stride);
		(void)jpeg_write_scanlines(&cinfo, row_pointer, 1);
	}

	jpeg_finish_compress(&cinfo);
	jpeg_destroy_compress(&cinfo);

	*length = jpegOutLength;
	return jpegOut + JPEG_HEADER_ROOM;
}

// The RGB24 entry point with the older contract, which macOS uses: the JPEG is a copy in jpeg_buffer that the caller frees
int write_JPEG_buffer(JSAMPLE * image_buffer, int image_width, int image_height, int quality)
{
	unsigned char *jpeg = write_JPEG_rect(image_buffer, (size_t)image_width * 3, image_width, image_height, 3, JCS_RGB, quality, &jpeg_buffer_length);

	if (jpeg_buffer != NULL) { free(jpeg_buffer); jpeg_buffer = NULL; }
	if ((jpeg_buffer = (unsigned char *)malloc(jpeg_buffer_length)) == NULL) { ILIBCRITICALEXIT(254); }
	memcpy(jpeg_buffer, jpeg, jpeg_buffer_length);
	return 0;
}
