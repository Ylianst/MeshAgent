/*
 *  mac_tile.c
 *  
 *
 *  Created by Ylian Saint-Hilaire on 8/18/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#include "mac_tile.h"
#include "../../meshinfo.h"
#include "../../meshdefines.h"
#include "../../../microstack/ILibParsers.h"

extern CGDirectDisplayID SCREEN_NUM;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_SCALE;
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
	
	
	printf("%x %x %x\n", rm, gm, bm);
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

// The last frame as it was compared, unpadded, in the frame's own pixel format
static unsigned char *refFrame = NULL;
static int refWidth = 0, refHeight = 0, refBytesPerPixel = 0;
static int tileRefreshPending = 1;
static int tileStalePending = 0; // 1 when an encode failed in the last pass, so its tiles are still to be sent

/******************************************************************************
 * EXTERNAL FUNCTIONS
 ******************************************************************************/

//Adjusts the screen size(width or height) to be exactly divisible by TILE_WIDTH
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

// Called by the input thread, which only sets a flag, so the table is touched by the capture thread alone
void tile_request_refresh(void)
{
	__atomic_store_n(&tileRefreshPending, 1, __ATOMIC_SEQ_CST);
}

// 1 when a pass has something to send without a new frame: a viewer's refresh, or tiles whose encode failed
int tile_pass_pending(void)
{
	return(tileStalePending || __atomic_load_n(&tileRefreshPending, __ATOMIC_SEQ_CST));
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

// Marks the tiles that differ from the reference frame, and copies the parts that differ, so the reference holds the frame afterwards.
// Compared a pixel row at a time in memory order because tile by tile measured 6.2 against 1.05 ms per 1080p frame on a Cortex-A76.
// Exact, where the hash it replaces could miss a change.
void tile_start_pass(const struct tileFrame_t *frame)
{
	int all = __atomic_exchange_n(&tileRefreshPending, 0, __ATOMIC_SEQ_CST);
	size_t bpp = (size_t)frame->bytesPerPixel;
	size_t refStride = (size_t)frame->width * bpp;
	size_t len = (size_t)TILE_WIDTH * bpp;
	size_t lastLen = refStride - (size_t)(TILE_WIDTH_COUNT - 1) * len;
	int row, col, r, rows;

	tileStalePending = 0;

	// A frame that does not match the tile grid sends nothing now, and the whole screen once it does
	if (frame->pixels == NULL || frame->width <= 0 || frame->height <= 0 ||
		(frame->width + TILE_WIDTH - 1) / TILE_WIDTH != TILE_WIDTH_COUNT || (frame->height + TILE_HEIGHT - 1) / TILE_HEIGHT != TILE_HEIGHT_COUNT)
	{
		for (row = 0; row < TILE_HEIGHT_COUNT; row++) { for (col = 0; col < TILE_WIDTH_COUNT; col++) { g_tileInfo[row][col].flag = TILE_DONE; } }
		tile_request_refresh();
		return;
	}

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

// Encodes the changed tile at the given location together with its changed neighbours.
// The packet points into the encoder's output buffer and holds until the next call, so the caller does not free it.
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
			if (*buffer == NULL) { g_tileInfo[r][c].stale = 1; tileStalePending = 1; }
		}
	}

	return 0;
}


// Get screen buffer from the CGImageRef structure
int getScreenBuffer(unsigned char **desktop, long long *desktopsize, CGImageRef image)
{	
	unsigned int row, col, bpp, len, width_padding_size, height_padding_size, i;
	unsigned char *output;
	int height = CGImageGetHeight(image);
	int width = CGImageGetWidth(image);
	int targetWidth = adjust_screen_size(SCREEN_WIDTH);
	int targetHeight = adjust_screen_size(SCREEN_HEIGHT);
	long long need;

	CGImageAlphaInfo alphaInfo = CGImageGetAlphaInfo(image);

	CFDataRef dataRef = CGDataProviderCopyData(CGImageGetDataProvider(image));
	if (dataRef == NULL) { return -1; }
	const unsigned char *sourceBytesPtr = CFDataGetBytePtr(dataRef);
	len = CFDataGetLength(dataRef);

	// The image can be larger than the screen size the caller read just before the capture, for example while a fast user switch changes the display mode.
	// The paddings below are unsigned, so a negative one became about 4 GB, and the zero fill ran past the buffer (SIGSEGV in __bzero on macOS 26.7, an image 3420 pixels wide).
	if (width > targetWidth || height > targetHeight) { CFRelease(dataRef); return -1; }

	// The buffer holds the padded screen at 3 bytes per pixel, which a small image's own data length need not cover
	need = (long long)targetWidth * targetHeight * 3;
	if (need < len) { need = len; }
	if (*desktopsize != need) {
		if (*desktop != NULL) { free(*desktop); }
		*desktopsize = need;
		*desktop = (unsigned char *) malloc (*desktopsize);
		if (*desktop == NULL) { *desktopsize = 0; CFRelease(dataRef); return -1; }
	}
	
	output = *desktop;
	bpp = CGImageGetBitsPerPixel(image);
	width_padding_size = (adjust_screen_size(SCREEN_WIDTH) - width) * 3;
	
	switch(bpp) {
		case 16:
		{
			const unsigned short *tmpPtr = (const unsigned short *)sourceBytesPtr;
			if(alphaInfo == kCGImageAlphaNoneSkipFirst ||
					alphaInfo == kCGImageAlphaPremultipliedFirst ||
					alphaInfo == kCGImageAlphaFirst) {
				for (row = 0; row < height; row++) {
					for (col = 0; col < width; col++) {
						*output++ = (*tmpPtr & 0x7C00) >> 7;
						*output++ = (*tmpPtr & 0x3E0) >> 2;
						*output++ = (*tmpPtr & 0x1F) << 3;
						tmpPtr++;
					}

					if (width_padding_size != 0) {
						for (i = 0; i < width_padding_size; i++) {
							*output++ = 0;
						}
					}
					tmpPtr += (CGImageGetBytesPerRow(image) - (bpp >> 3) * width) >> 2;
				}
			}
			else if (alphaInfo == kCGImageAlphaNone ||
					alphaInfo == kCGImageAlphaNoneSkipLast ||
					alphaInfo == kCGImageAlphaPremultipliedLast ||
					alphaInfo == kCGImageAlphaLast) {
				for (row = 0; row < height; row++) {
					for (col = 0; col < width; col++) {
						*output++ = (*tmpPtr & 0xF800) >> 8;
						*output++ = (*tmpPtr & 0x7C0) >> 3;
						*output++ = (*tmpPtr & 0x3E) << 2;
						tmpPtr++;
					}
					if (width_padding_size != 0) {
						for (i = 0; i < width_padding_size; i++) {
							*output++ = 0;
						}
					}
					tmpPtr += (CGImageGetBytesPerRow(image) - (bpp >> 3) * width) >> 2;
				}
			}
		}
		break;
		case 32:
		{
			const unsigned int *tmpPtr1 = (const unsigned int *)sourceBytesPtr;
			if(alphaInfo == kCGImageAlphaNoneSkipFirst ||
					alphaInfo == kCGImageAlphaPremultipliedFirst ||
					alphaInfo == kCGImageAlphaFirst) {
				for (row = 0; row < height; row++) {
					for (col = 0; col < width; col++) {
						*output++ = (*tmpPtr1 & 0x0ff0000) >> 16;
						*output++ = (*tmpPtr1 & 0x0ff00) >> 8;
						*output++ = (*tmpPtr1 & 0x0FF);
						tmpPtr1++;
					}
					if (width_padding_size > 0) {
						for (i = 0; i < width_padding_size; i++) {
							*output++ = 0;
						}
					}
					tmpPtr1 += (CGImageGetBytesPerRow(image) - (bpp >> 3) * width) >> 2;
				}
			}
			else if (alphaInfo == kCGImageAlphaNone ||
					alphaInfo == kCGImageAlphaNoneSkipLast ||
					alphaInfo == kCGImageAlphaPremultipliedLast ||
					alphaInfo == kCGImageAlphaLast) {
				for (row = 0; row < height; row++) {
					for (col = 0; col < width; col++) {
						*output++ = (*tmpPtr1 & 0xFF000000) >> 24;
						*output++ = (*tmpPtr1 & 0x0ff0000) >> 16;
						*output++ = (*tmpPtr1 & 0x0ff00) >> 8;
						tmpPtr1++;
					}
					if (width_padding_size != 0) {
						for (i = 0; i < width_padding_size; i++) {
							*output++ = 0;
						}
					}
					tmpPtr1 += (CGImageGetBytesPerRow(image) - (bpp >> 3) * width) >> 2;
				}
			}
		}
		break;
		default:
			fprintf(stderr, "This image depth is not supported.\n");
			return -1;
	}
	
	height_padding_size = adjust_screen_size(SCREEN_HEIGHT) - height;
	
	if (height_padding_size > 0) {
		for (row = 0; row < height_padding_size; row++) {
			for (col = 0; col < (width * 3) + width_padding_size; col++) {
				*output++ = 0;
			}
		}
	}
	
	CFRelease(dataRef);
	
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

