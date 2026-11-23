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

#if defined(JPEGMAXBUF)
	#define MAX_TILE_SIZE JPEGMAXBUF
#else
	#define MAX_TILE_SIZE 65500
#endif
#define TILE_JPEG_OPTIMIZE_MAX_AREA (128 * 128)

unsigned char *jpeg_buffer = NULL;
int jpeg_buffer_length = 0;
char jpegLastError[JMSG_LENGTH_MAX];
JPEG_error_handler default_JPEG_error_handler = NULL;

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

int write_JPEG_rect(const unsigned char *pixels, size_t stride, int image_width, int image_height, int components, J_COLOR_SPACE format, int quality)
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;
	JSAMPROW row_pointer[1];

	cinfo.err = jpeg_std_error(&jerr);
	if (default_JPEG_error_handler != NULL) { jerr.error_exit = jpeg_error_handler; }

	jpeg_create_compress(&cinfo);
	cinfo.dest = (struct jpeg_destination_mgr *) malloc(sizeof(struct jpeg_destination_mgr));
	cinfo.dest->init_destination = &init_destination;
	cinfo.dest->empty_output_buffer = &empty_output_buffer;
	cinfo.dest->term_destination = &term_destination;

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
#if MAX_TILE_SIZE == 0
	// Huffman tables built for each rectangle up to 128x128, where the standard tables are a large share of a small JPEG. Larger rectangles gain less for the second pass over the data.
	// Not with a tile size limit, because optimized tables write all output in jpeg_finish_compress(), which cannot suspend, and a suspension there ends in exit().
	if ((long)image_width * image_height <= TILE_JPEG_OPTIMIZE_MAX_AREA) { cinfo.optimize_coding = TRUE; }
#endif
	jpeg_start_compress(&cinfo, TRUE);

	// The rows are read where they lie in the caller's frame, so no copy of the rectangle is made
	while (cinfo.next_scanline < cinfo.image_height)
	{
		row_pointer[0] = (JSAMPROW)(pixels + (size_t)cinfo.next_scanline * stride);
		(void)jpeg_write_scanlines(&cinfo, row_pointer, 1);
	}

	jpeg_finish_compress(&cinfo);

	free(cinfo.dest);
	cinfo.dest = NULL;
	jpeg_destroy_compress(&cinfo);

	return 0;
}

// The RGB24 entry point, for a rectangle that is already packed
int write_JPEG_buffer(JSAMPLE * image_buffer, int image_width, int image_height, int quality)
{
	return write_JPEG_rect(image_buffer, (size_t)image_width * 3, image_width, image_height, 3, JCS_RGB, quality);
}
