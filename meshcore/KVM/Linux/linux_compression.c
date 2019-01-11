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
	jpeg_buffer = malloc(MAX_BUFFER);
	jpeg_buffer_length = 0;
	next_output_byte = jpeg_buffer;
	cinfo->dest->next_output_byte = next_output_byte;
	cinfo->dest->free_in_buffer = MAX_BUFFER;
}

boolean empty_output_buffer(j_compress_ptr cinfo)
{
	JOCTET * next_output_byte;

	jpeg_buffer_length += MAX_BUFFER;
	jpeg_buffer = (unsigned char *) realloc(jpeg_buffer, jpeg_buffer_length + MAX_BUFFER);
	next_output_byte = jpeg_buffer + jpeg_buffer_length;
	cinfo->dest->next_output_byte = next_output_byte;
	cinfo->dest->free_in_buffer = MAX_BUFFER;

	if (jpeg_buffer_length > 65500) return FALSE;
	return TRUE;
}

void term_destination (j_compress_ptr cinfo)
{
	int remaining_buff_length = MAX_BUFFER - cinfo->dest->free_in_buffer;

	jpeg_buffer_length += remaining_buff_length;

	if (jpeg_buffer_length > 65500) {
		free(jpeg_buffer);
		jpeg_buffer = NULL;
	}
	else {
		jpeg_buffer = (unsigned char *) realloc(jpeg_buffer, jpeg_buffer_length);
	}
}

int write_JPEG_buffer (JSAMPLE * image_buffer, int image_width, int image_height, int quality)
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr jerr;
	JSAMPROW row_pointer[1];
	int row_stride;

	cinfo.err = jpeg_std_error(&jerr);
	if (default_JPEG_error_handler != NULL) { jerr.error_exit = jpeg_error_handler; }

	jpeg_create_compress(&cinfo);
	cinfo.dest = (struct jpeg_destination_mgr *) malloc (sizeof(struct jpeg_destination_mgr));
	cinfo.dest->init_destination = &init_destination;
	cinfo.dest->empty_output_buffer = &empty_output_buffer;
	cinfo.dest->term_destination = &term_destination;

	cinfo.image_width = image_width;
	cinfo.image_height = image_height;
	cinfo.input_components = 3;
	cinfo.in_color_space = JCS_RGB;
	jpeg_set_defaults(&cinfo);
	jpeg_set_quality(&cinfo, quality, TRUE);
	jpeg_start_compress(&cinfo, TRUE);
	row_stride = image_width * 3;

	while (cinfo.next_scanline < cinfo.image_height)
	{
		row_pointer[0] = & image_buffer[cinfo.next_scanline * row_stride];
		(void) jpeg_write_scanlines(&cinfo, row_pointer, 1);
	}

	jpeg_finish_compress(&cinfo);

	free(cinfo.dest);
	cinfo.dest = NULL;
	jpeg_destroy_compress(&cinfo);

	return 0;
}

