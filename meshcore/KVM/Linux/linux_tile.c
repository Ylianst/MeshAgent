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

extern int SCREEN_NUM;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_DEPTH;
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;
extern struct tileInfo_t **g_tileInfo;

int COMPRESSION_QUALITY = 50;

#if 0
void dump32bit (const XImage * input)
{
    int row, col;
    static char head[256];

    static FILE *fp2 = NULL;
    char *ptr2, *output;
    long size;

    register unsigned int
	rm = input->red_mask,
	gm = input->green_mask,
	bm = input->blue_mask,
	rs = 16,
	gs = 8,
	bs = 0, *p32 = (unsigned int *) input->data;


    sprintf (head, "P6\n%d %d\n%d\n", input->width, input->height, 255);
    size = ((input->bytes_per_line * input->height) / 4) * 3;
    output = malloc (size);
    ptr2 = output;

    for (row = 0; row < input->height; row++) {
		for (col = 0; col < input->width; col++) {
			*output++ = ((*p32 & rm) >> rs);
			*output++ = ((*p32 & gm) >> gs);
			*output++ = ((*p32 & bm) >> bs);
			p32++;		     // ignore alpha values
		}
		//
		// eat padded bytes, for better speed we use shifting,
		// (bytes_per_line - bits_per_pixel / 8 * width ) / 4
		//
		p32 += (input->bytes_per_line - (input->bits_per_pixel >> 3)
			* input->width) >> 2;
    }

    fp2 = fopen ("/tmp/pic.rgb.pnm", "w");
    fwrite (head, strlen (head), 1, fp2);

    fwrite (ptr2, size, 1, fp2);
    fclose (fp2);
    free (ptr2);
}
#endif

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

void tile_frame_from_rgb24(struct tileFrame_t *frame, const unsigned char *pixels, size_t stride, int width, int height)
{
	frame->pixels = pixels;
	frame->stride = stride;
	frame->bytesPerPixel = 3;
	frame->width = width;
	frame->height = height;
	frame->format = JCS_RGB;
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
	frame->stride = (size_t)image->bytes_per_line;
	frame->bytesPerPixel = 4;
	frame->width = image->width;
	frame->height = image->height;
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
		const unsigned char *cur = frame->pixels + (size_t)row * TILE_HEIGHT * frame->stride;
		unsigned char *ref;

		for (col = 0; col < TILE_WIDTH_COUNT; col++)
		{
			if (all) { tiles[col].stale = 1; }
			tiles[col].flag = tiles[col].stale ? TILE_CHANGED : TILE_DONE;
		}
		if (refFrame == NULL) { continue; } // Without a reference every tile stays stale and is sent, which costs data but loses nothing

		ref = refFrame + (size_t)row * TILE_HEIGHT * refStride;
		rows = frame->height - row * TILE_HEIGHT;
		if (rows > TILE_HEIGHT) { rows = TILE_HEIGHT; }

		for (r = 0; r < rows; r++, cur += frame->stride, ref += refStride)
		{
			for (col = 0; col < TILE_WIDTH_COUNT; col++)
			{
				// The last tile of a row ends at the frame edge
				size_t n = (col == TILE_WIDTH_COUNT - 1) ? lastLen : len;
				if (!tiles[col].stale && memcmp(cur + col * len, ref + col * len, n) == 0) { continue; }
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

	tileJpeg = write_JPEG_rect(frame->pixels + (size_t)y * frame->stride + (size_t)x * frame->bytesPerPixel, frame->stride, captureWidth, captureHeight, frame->bytesPerPixel, frame->format, COMPRESSION_QUALITY, &tileJpegLength);

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


// Get screen buffer from the XImage structure
int getScreenBuffer(char **desktop, long long *desktopsize, XImage *image)
{
	long long size = adjust_screen_size(SCREEN_WIDTH) * adjust_screen_size(SCREEN_HEIGHT) * 3;
	int row, col, i, width_padding_size = 0, height_padding_size = 0;
	char *output;
	register unsigned char* tmpPtr2 = (unsigned char *)image->data;
	register unsigned short* tmpPtr3 = (unsigned short *)image->data;
	register unsigned int
		rm = image->red_mask,
		gm = image->green_mask,
		bm = image->blue_mask,
		rs = 16,
		gs = 8,
		bs = 0, *tmpPtr = (unsigned int *) image->data;
	int bpp = image->bits_per_pixel;

	if (*desktopsize != size) {
		if (*desktop != NULL) { free(*desktop); }
		*desktopsize = size;
		if ((*desktop = (char *) malloc (*desktopsize + 4)) == NULL) ILIBCRITICALEXIT(254);
	}

	if (bpp == 16) {
		rs = 11;
		gs = 5;
	}
	output = *desktop;

	for (row = 0; row < image->height; row++) {
		for (col = 0; col < image->width; col++) {
			if (bpp == 16) {
				*output++ = ((*tmpPtr3 >> rs) & 0x01f) << 3;
				*output++ = ((*tmpPtr3 >> gs) & 0x03f) << 2;
				*output++ = ((*tmpPtr3 >> bs) & 0x01f) << 3;
				tmpPtr3++;
			}
			else if (bpp == 24) {
				*output++ = *(tmpPtr2 + 2);
				*output++ = *(tmpPtr2 + 1);
				*output++ = *tmpPtr2;
				tmpPtr2 += 3;
			}
			else {
				*output++ = ((*tmpPtr & rm) >> rs);
				*output++ = ((*tmpPtr & gm) >> gs);
				*output++ = ((*tmpPtr & bm) >> bs);
				tmpPtr = (unsigned int *) (((char *)tmpPtr) + (image->bits_per_pixel >> 3));
				//tmpPtr++;		     // ignore alpha values
			}
		}
		//
		// eat padded bytes, for better speed we use shifting,
		// (bytes_per_line - bits_per_pixel / 8 * width ) / 4

		tmpPtr += (image->bytes_per_line - (image->bits_per_pixel >> 3)
			* image->width) >> 2;

		width_padding_size = (adjust_screen_size(SCREEN_WIDTH) - image->width) * 3;

		if (width_padding_size != 0) {
			for (i = 0; i < width_padding_size; i++) {
				*output++ = 0;
			}
		}
	}

	height_padding_size = adjust_screen_size(SCREEN_HEIGHT) - image->height;

	if (height_padding_size != 0) {
		for (row = 0; row < height_padding_size; row++) {
			for (col = 0; col < (image->width * 3) + width_padding_size; col++) {
				*output++ = 0;
			}
		}
	}

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

	//  TODO Make sure the all the types are handled. We ignore the type variable for now.
}
