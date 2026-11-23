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

#ifndef LINUX_TILE_H_
#define LINUX_TILE_H_

#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "linux_compression.h"

enum TILE_FLAGS_ENUM {
	TILE_DONE = 0,			// Nothing to send, the tile is unchanged or was sent in this pass
	TILE_CHANGED			// The tile differs from the reference and was not sent yet
};

struct tileInfo_t {
	unsigned char stale;	// 1 when the reference frame does not hold this tile, so it counts as changed
	unsigned char flag;
};

// The frame of one pass, compared and encoded where it lies. width and height are the real size, not rounded up to whole tiles.
struct tileFrame_t {
	const unsigned char *pixels;
	size_t stride;			// Bytes from one row to the next
	int bytesPerPixel;
	int width;
	int height;
	J_COLOR_SPACE format;
};

extern void tile_info_alloc(void);
extern void tile_info_free(void);
extern void tile_request_refresh(void);
extern void tile_frame_from_rgb24(struct tileFrame_t *frame, const unsigned char *pixels, size_t stride, int width, int height);
extern int tile_frame_from_ximage(struct tileFrame_t *frame, XImage *image);
extern void tile_start_pass(const struct tileFrame_t *frame);
extern int adjust_screen_size(int pixles);
extern int getTileAt(int x, int y, void** buffer, long long *bufferSize, const struct tileFrame_t *frame, int row, int col);
extern int getScreenBuffer(char **desktop, long long *desktopsize, XImage *image);
extern void set_tile_compression(int type, int level);


#endif /* LINUX_TILE_H_ */
