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

#include "linux_tile.h"
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"

extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;
extern struct tileInfo_t **g_tileInfo;

int COMPRESSION_QUALITY = 50;

static unsigned char *refFrame = NULL;
static int refWidth = 0;
static int refHeight = 0;
static int refBytesPerPixel = 0;
static int tileRefreshPending = 1;

/******************************************************************************
 * EXTERNAL FUNCTIONS
 ******************************************************************************/

// Adjusts the screen size(width or height) to be exactly divisible by TILE_WIDTH
int adjust_screen_size(int pixles)
{
	int extra = pixles % TILE_WIDTH; //Assuming tile width and height will remain the same.

	if (extra != 0) { return pixles + TILE_WIDTH - extra; }

	return pixles;
}

void tile_info_free(void)
{
	free(g_tileInfo);
	g_tileInfo = NULL;
	free(refFrame);
	refFrame = NULL;
	refWidth = refHeight = refBytesPerPixel = 0;
}

// One block for the row pointers and the tiles. Every tile starts stale, so the next pass sends the whole screen.
void tile_info_alloc(void)
{
	int r, c;
	size_t rows = (size_t)TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *);
	struct tileInfo_t *tiles;

	free(g_tileInfo);
	if ((g_tileInfo = (struct tileInfo_t **)malloc(rows + (size_t)TILE_HEIGHT_COUNT * TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) { ILIBCRITICALEXIT(254); }
	tiles = (struct tileInfo_t *)((char *)g_tileInfo + rows);
	for (r = 0; r < TILE_HEIGHT_COUNT; r++)
	{
		g_tileInfo[r] = tiles + (size_t)r * TILE_WIDTH_COUNT;
		for (c = 0; c < TILE_WIDTH_COUNT; c++) { g_tileInfo[r][c].stale = 1; g_tileInfo[r][c].flag = TILE_DONE; }
	}
}

// Input is read in the frame loop thread, on X11 and on DRM, so a plain flag is enough
void tile_request_refresh(void)
{
	tileRefreshPending = 1;
}

void tile_frame_from_rgb24(struct tileFrame_t *frame, const unsigned char *pixels, ptrdiff_t stride, int width, int height)
{
	frame->pixels = pixels;
	frame->stride = stride;
	frame->bytesPerPixel = 3;
	frame->width = width;
	frame->height = height;
	frame->format = JCS_RGB;
	frame->changed = NULL;
}

// Describes a 32 bpp capture with 8 bit channels, so it is compared and encoded without the RGB24 copy of getScreenBuffer().
// Returns 0 for every other layout, and when jpeglib.h is not libjpeg-turbo's, which has no 4 byte pixel formats.
int tile_frame_from_ximage(struct tileFrame_t *frame, XImage *image)
{
#ifdef JCS_EXTENSIONS
	int lsb = (image->byte_order == LSBFirst);

	if (image->bits_per_pixel != 32 || image->green_mask != 0xFF00) { return 0; }
	if (image->red_mask == 0xFF0000 && image->blue_mask == 0xFF) { frame->format = lsb ? JCS_EXT_BGRX : JCS_EXT_XRGB; }
	else if (image->red_mask == 0xFF && image->blue_mask == 0xFF0000) { frame->format = lsb ? JCS_EXT_RGBX : JCS_EXT_XBGR; }
	else { return 0; }

	frame->pixels = (const unsigned char *)image->data;
	frame->stride = (ptrdiff_t)image->bytes_per_line;
	frame->bytesPerPixel = 4;
	frame->width = image->width;
	frame->height = image->height;
	frame->changed = NULL;
	return 1;
#else
	return 0;
#endif
}

// Marks the tiles that differ from the reference frame, and copies the parts that differ, so the reference holds the frame afterwards.
// Compared a pixel row at a time in memory order because tile by tile measured 6.2 against 1.05 ms per 1080p frame on a Cortex-A76.
// Exact, where the hash it replaces could miss a change.
void tile_start_pass(const struct tileFrame_t *frame)
{
	int all = tileRefreshPending;
	size_t bpp = (size_t)frame->bytesPerPixel;
	size_t refStride = (size_t)frame->width * bpp;
	size_t len = (size_t)TILE_WIDTH * bpp;
	size_t lastLen = refStride - (size_t)(TILE_WIDTH_COUNT - 1) * len;
	int row, col, r, rows;

	// A frame that does not match the tile grid sends nothing now, and the whole screen once it does
	if (frame->pixels == NULL || frame->width <= 0 || frame->height <= 0 ||
		(frame->width + TILE_WIDTH - 1) / TILE_WIDTH != TILE_WIDTH_COUNT || (frame->height + TILE_HEIGHT - 1) / TILE_HEIGHT != TILE_HEIGHT_COUNT)
	{
		tileRefreshPending = 1;
		return;
	}

	tileRefreshPending = 0;
#ifdef KVM_ALL_TILES
	all = 1;
#endif
	if (refFrame == NULL || refWidth != frame->width || refHeight != frame->height || refBytesPerPixel != frame->bytesPerPixel)
	{
		free(refFrame);
		refFrame = (unsigned char *)malloc(refStride * (size_t)frame->height);
		refWidth = frame->width;
		refHeight = frame->height;
		refBytesPerPixel = frame->bytesPerPixel;
		all = 1;
	}

	for (row = 0; row < TILE_HEIGHT_COUNT; row++)
	{
		struct tileInfo_t *tiles = g_tileInfo[row];
		const unsigned char *cur = frame->pixels + (ptrdiff_t)row * TILE_HEIGHT * frame->stride;
		const unsigned char *hint = (frame->changed != NULL) ? frame->changed + (size_t)row * TILE_WIDTH_COUNT : NULL;
		unsigned char *ref;
		int work = (hint == NULL);

		for (col = 0; col < TILE_WIDTH_COUNT; col++)
		{
			if (all) { tiles[col].stale = 1; }
			tiles[col].flag = tiles[col].stale ? TILE_CHANGED : TILE_DONE;
			if (tiles[col].stale || (hint != NULL && hint[col])) { work = 1; }
		}
		if (refFrame == NULL) { continue; } // Without a reference every tile stays stale and is sent, which costs data but loses nothing
		if (!work) { continue; } // The capture found no change in this tile row and no tile of it is stale

		ref = refFrame + (size_t)row * TILE_HEIGHT * refStride;
		rows = frame->height - row * TILE_HEIGHT;
		if (rows > TILE_HEIGHT) { rows = TILE_HEIGHT; }

		for (r = 0; r < rows; r++, cur += frame->stride, ref += refStride)
		{
			for (col = 0; col < TILE_WIDTH_COUNT; col++)
			{
				// The last tile of a row ends at the frame edge
				size_t n = (col == TILE_WIDTH_COUNT - 1) ? lastLen : len;
				if (!tiles[col].stale && ((hint != NULL && !hint[col]) || memcmp(cur + col * len, ref + col * len, n) == 0)) { continue; }
				memcpy(ref + col * len, cur + col * len, n);
				tiles[col].flag = TILE_CHANGED;
			}
		}
		for (col = 0; col < TILE_WIDTH_COUNT; col++) { tiles[col].stale = 0; }
	}
}

//Fetches the encoded jpeg tile at the given location. The neighboring changed tiles are coalesced to form a larger jpeg before returning.
// *buffer is the packet inside the encoder's buffer. It holds until the next call and the caller does not free it.
int getTileAt(int x, int y, void** buffer, long long *bufferSize, const struct tileFrame_t *frame, int row, int col)
{
	int rcol, r, c;
	int rightcol = col; //Used in coalescing. Indicates the rightmost column to be coalesced.
	int botrow = row; //Used in coalescing. Indicates the bottom most row to be coalesced.
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;
	unsigned char *tileJpeg;
	int tileJpegLength = 0;

	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;

	if (g_tileInfo[row][col].flag != TILE_CHANGED) { return 0; }

	// First go to the right most changed tile
	while (rightcol + 1 < TILE_WIDTH_COUNT && g_tileInfo[row][rightcol + 1].flag == TILE_CHANGED)
	{
		rightcol++;
		captureWidth += TILE_WIDTH;
	}

	// Now go to the bottom tiles, a row of them is added when all of its tiles in the range have changed
	while (botrow + 1 < TILE_HEIGHT_COUNT)
	{
		rcol = col;
		while (rcol <= rightcol && g_tileInfo[botrow + 1][rcol].flag == TILE_CHANGED) { rcol++; }
		if (rcol <= rightcol) { break; }
		botrow++;
		captureHeight += TILE_HEIGHT;
	}

	// The tile grid is rounded up to whole tiles, so a rectangle on the right or bottom edge ends at the frame edge
	if (x + captureWidth > frame->width) { captureWidth = frame->width - x; }
	if (y + captureHeight > frame->height) { captureHeight = frame->height - y; }

	// Encoded from the reference frame, which tile_start_pass() just brought up to date for every changed tile.
	// A DRM frame is the live scanout buffer and can change after the compare, and then the picture sent would differ from the reference.
	if (refFrame != NULL && refWidth == frame->width && refHeight == frame->height && refBytesPerPixel == frame->bytesPerPixel)
	{
		ptrdiff_t refStride = (ptrdiff_t)refWidth * refBytesPerPixel;
		tileJpeg = write_JPEG_rect(refFrame + (ptrdiff_t)y * refStride + (ptrdiff_t)x * refBytesPerPixel, refStride, captureWidth, captureHeight, refBytesPerPixel, frame->format, COMPRESSION_QUALITY, &tileJpegLength);
	}
	else
	{
		tileJpeg = write_JPEG_rect(frame->pixels + (ptrdiff_t)y * frame->stride + (ptrdiff_t)x * frame->bytesPerPixel, frame->stride, captureWidth, captureHeight, frame->bytesPerPixel, frame->format, COMPRESSION_QUALITY, &tileJpegLength);
	}

	// The packet header is written into the room in front of the JPEG, so the packet is sent from the encoder's buffer without a copy
	if (tileJpeg != NULL)
	{
		if (tileJpegLength > 65500)
		{
			*buffer = tileJpeg - 16;
			*bufferSize = tileJpegLength + 16;
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
			((unsigned int*)*buffer)[1] = (unsigned int)htonl(tileJpegLength + 8);					// Size of the Next Packet
			((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[5] = 0;														// RESERVED
			((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
		}
		else
		{
			*buffer = tileJpeg - 8;
			*bufferSize = tileJpegLength + 8;
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
			((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
		}
	}

	// The region is done for this pass either way, and a failed encode leaves it stale so the next pass sends it again
	for (r = row; r <= botrow; r++)
	{
		for (c = col; c <= rightcol; c++)
		{
			g_tileInfo[r][c].flag = TILE_DONE;
			if (*buffer == NULL) { g_tileInfo[r][c].stale = 1; }
		}
	}

	return 0;
}


// Shift and width of one colour channel, from its mask
static void tile_mask_layout(unsigned long mask, int *shift, int *bits)
{
	*shift = 0;
	*bits = 0;
	if (mask == 0) { return; }
	while ((mask & 1) == 0) { mask >>= 1; (*shift)++; }
	while ((mask & 1) != 0) { mask >>= 1; (*bits)++; }
}

static unsigned char tile_channel(unsigned long pixel, unsigned long mask, int shift, int bits)
{
	unsigned long v = (pixel & mask) >> shift;
	return (unsigned char)(bits >= 8 ? (v >> (bits - 8)) : (v << (8 - bits)));
}

// Get screen buffer from the XImage structure, as RGB24 with rows and height padded to whole tiles.
// The channels come from the image's masks and byte order and the rows from bytes_per_line. Before, the shifts were fixed and
// 16 and 24 bpp rows were read as packed, so a visual with other masks got wrong colours and a padded row a skewed picture.
int getScreenBuffer(char **desktop, long long *desktopsize, XImage *image)
{
	size_t stride = (size_t)adjust_screen_size(SCREEN_WIDTH) * 3;
	size_t rows = (size_t)adjust_screen_size(SCREEN_HEIGHT);
	long long size = (long long)(stride * rows);
	int bytes = image->bits_per_pixel >> 3;
	int width = image->width;
	int height = image->height;
	int rs, rb, gs, gb, bs, bb;
	int row, col, i;

	if (*desktopsize != size || *desktop == NULL) {
		if (*desktop != NULL) { free(*desktop); }
		*desktopsize = size;
		if ((*desktop = (char *) malloc ((size_t)size)) == NULL) ILIBCRITICALEXIT(254);
	}

	if (width > adjust_screen_size(SCREEN_WIDTH)) { width = adjust_screen_size(SCREEN_WIDTH); }
	if (height > (int)rows) { height = (int)rows; }
	if (bytes < 1 || bytes > 4) { memset(*desktop, 0, (size_t)size); return 0; }

	tile_mask_layout(image->red_mask, &rs, &rb);
	tile_mask_layout(image->green_mask, &gs, &gb);
	tile_mask_layout(image->blue_mask, &bs, &bb);

	for (row = 0; row < height; row++) {
		const unsigned char *src = (const unsigned char *)image->data + (size_t)row * image->bytes_per_line;
		unsigned char *output = (unsigned char *)*desktop + (size_t)row * stride;

		for (col = 0; col < width; col++) {
			unsigned long pixel = 0;
			if (image->byte_order == LSBFirst) { for (i = bytes - 1; i >= 0; i--) { pixel = (pixel << 8) | src[i]; } }
			else { for (i = 0; i < bytes; i++) { pixel = (pixel << 8) | src[i]; } }
			src += bytes;

			*output++ = tile_channel(pixel, image->red_mask, rs, rb);
			*output++ = tile_channel(pixel, image->green_mask, gs, gb);
			*output++ = tile_channel(pixel, image->blue_mask, bs, bb);
		}
		memset(output, 0, stride - (size_t)width * 3);
	}
	memset(*desktop + (size_t)height * stride, 0, (rows - (size_t)height) * stride);

	return 0;
}


// Set the compression quality
void set_tile_compression(int type, int level)
{
	if (level > 0 && level <= 100) {
		COMPRESSION_QUALITY = level;
	}
	else {
		COMPRESSION_QUALITY = 60;
	}
}
