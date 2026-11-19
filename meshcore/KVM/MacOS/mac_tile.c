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
extern int COMPRESSION_RATIO;
extern struct tileInfo_t **g_tileInfo;
extern unsigned char *jpeg_buffer;
extern int jpeg_buffer_length;

int tilebuffersize = 0;
void* tilebuffer = NULL;
int COMPRESSION_QUALITY = 50;

#if defined(JPEGMAXBUF)
	#define MAX_TILE_SIZE JPEGMAXBUF
#else
	#define MAX_TILE_SIZE 65500
#endif


/******************************************************************************
 * INTERNAL FUNCTIONS
 ******************************************************************************/

//Extracts the required tile buffer from the desktop buffer
int get_tile_buffer(int x, int y, void **buffer, long long bufferSize, void *desktop, long long desktopsize, int tilewidth, int tileheight)
{
	char *target = *buffer;
	int height = 0;
	
	for (height = y; height < y + tileheight; height++) {
		memcpy_s(target, (size_t)bufferSize - (target - (char*)*buffer), (void *)(((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x))), (size_t)(tilewidth * 3));
		target = (char *) (target + (3 * tilewidth));
	}
	
	return 0;
}

//This function returns 0 and *buffer != NULL if everything was good. retval = jpegsize if the captured image was too large.
int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void* desktop, long long desktopsize, void ** buffer, long long *bufferSize)
{
	
	*buffer = NULL;
	*bufferSize = 0;
	
	// Make sure a tile buffer is available. Most of the time, this is skipped.
	if (tilebuffersize != captureWidth * captureHeight * 3)
	{
		if (tilebuffer != NULL) free(tilebuffer);
		tilebuffersize = captureWidth * captureHeight * 3;
		if ((tilebuffer = malloc(tilebuffersize)) == NULL) return 0;
	}
	
	//Get the final coalesced tile
	get_tile_buffer(x, y, &tilebuffer, tilebuffersize, desktop, desktopsize, captureWidth, captureHeight);
	
	write_JPEG_buffer(tilebuffer, captureWidth, captureHeight, COMPRESSION_QUALITY);

#if MAX_TILE_SIZE > 0
	if (jpeg_buffer_length > MAX_TILE_SIZE)
	{
		return jpeg_buffer_length;
	}
	else
#endif
	{
		return 0;
	}
}

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

static unsigned char *refFrame = NULL;
static size_t refFrameSize = 0;
static int tileRefreshPending = 1;

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
	refFrameSize = 0;
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

// Marks the tiles that differ from the reference frame, and copies the parts that differ, so the reference holds the frame afterwards.
// Compared a pixel row at a time in memory order because tile by tile measured 6.2 against 1.05 ms per 1080p frame on a Cortex-A76.
// Exact, where the hash it replaces could miss a change.
void tile_start_pass(const unsigned char *desktop, long long desktopsize)
{
	int all = __atomic_exchange_n(&tileRefreshPending, 0, __ATOMIC_SEQ_CST);
	size_t stride = (size_t)adjust_screen_size(SCREEN_WIDTH) * 3;
	size_t size = stride * (size_t)TILE_HEIGHT_COUNT * TILE_HEIGHT;
	size_t len = (size_t)TILE_WIDTH * 3;
	int row, col, r;

#ifdef KVM_ALL_TILES
	all = 1;
#endif
	if (refFrame == NULL || refFrameSize != size)
	{
		free(refFrame);
		refFrameSize = 0;
		if ((refFrame = (unsigned char *)malloc(size)) != NULL) { refFrameSize = size; }
		all = 1;
	}

	for (row = 0; row < TILE_HEIGHT_COUNT; row++)
	{
		struct tileInfo_t *tiles = g_tileInfo[row];
		const unsigned char *cur = desktop + (size_t)row * TILE_HEIGHT * stride;
		unsigned char *ref;

		// A frame buffer that does not hold whole tiles is not read: nothing is sent now, and the whole screen once it fits
		if (desktop == NULL || desktopsize < (long long)size)
		{
			for (col = 0; col < TILE_WIDTH_COUNT; col++) { tiles[col].stale = 1; tiles[col].flag = TILE_DONE; }
			continue;
		}

		for (col = 0; col < TILE_WIDTH_COUNT; col++)
		{
			if (all) { tiles[col].stale = 1; }
			tiles[col].flag = tiles[col].stale ? TILE_CHANGED : TILE_DONE;
		}
		if (refFrame == NULL) { continue; } // Without a reference every tile stays stale and is sent, which costs data but loses nothing

		ref = refFrame + (size_t)row * TILE_HEIGHT * stride;

		for (r = 0; r < TILE_HEIGHT; r++, cur += stride, ref += stride)
		{
			for (col = 0; col < TILE_WIDTH_COUNT; col++)
			{
				if (!tiles[col].stale && memcmp(cur + col * len, ref + col * len, len) == 0) { continue; }
				memcpy(ref + col * len, cur + col * len, len);
				tiles[col].flag = TILE_CHANGED;
			}
		}
		for (col = 0; col < TILE_WIDTH_COUNT; col++) { tiles[col].stale = 0; }
	}
}

//Fetches the encoded jpeg tile at the given location. The neighboring changed tiles are coalesced to form a larger jpeg before returning.
int getTileAt(int x, int y, void** buffer, long long *bufferSize, void *desktop, long long desktopsize, int row, int col)
{
	int rcol, r, c;
	int rightcol = col; //Used in coalescing. Indicates the rightmost column to be coalesced.
	int botrow = row; //Used in coalescing. Indicates the bottom most row to be coalesced.
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;
	
	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;
	
	if (g_tileInfo[row][col].flag != TILE_CHANGED) { return 0; }
	
	// First go to the right most changed tile
	while (rightcol + 1 < TILE_WIDTH_COUNT && g_tileInfo[row][rightcol + 1].flag == TILE_CHANGED)
	{
#if MAX_TILE_SIZE > 0
		if ((captureWidth + TILE_WIDTH) * TILE_HEIGHT * 3 / COMPRESSION_RATIO > MAX_TILE_SIZE) { break; }
#endif
		rightcol++;
		captureWidth += TILE_WIDTH;
	}
	
	// Now go to the bottom tiles, a row of them is added when all of its tiles in the range have changed
	while (botrow + 1 < TILE_HEIGHT_COUNT)
	{
#if MAX_TILE_SIZE > 0
		if ((captureHeight + TILE_HEIGHT) * captureWidth * 3 / COMPRESSION_RATIO > MAX_TILE_SIZE) { break; }
#endif
		rcol = col;
		while (rcol <= rightcol && g_tileInfo[botrow + 1][rcol].flag == TILE_CHANGED) { rcol++; }
		if (rcol <= rightcol) { break; }
		botrow++;
		captureHeight += TILE_HEIGHT;
	}
	
	int retval = 0;
	
#if MAX_TILE_SIZE == 0
	retval = calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, desktopsize, buffer, bufferSize);
#else
	int firstTime = 1;

	//This loop is used to adjust the COMPRESSION_RATIO. This loop runs only once most of the time.
	do {
		//retval here is 0 if everything was good. It is > 0 if it contains the size of the jpeg that was created and not sent.
		retval = calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, desktopsize, buffer, bufferSize);
		if (retval != 0) {
			if (firstTime) {
				// Re-adjust the compression ratio.
				COMPRESSION_RATIO = (int)(((double)COMPRESSION_RATIO / (double)retval) * (0.92 * MAX_TILE_SIZE)); //Magic number: 92% of MAX_TILE_SIZE
				if (COMPRESSION_RATIO <= 1) { COMPRESSION_RATIO = 2; }
				firstTime = 0;
			}

			if (botrow > row) { //First time, try reducing the height.
				botrow = row + ((botrow - row + 1) / 2);
				captureHeight = (botrow - row + 1) * TILE_HEIGHT;
			}
			else if (rightcol > col) { //If it is not possible, reduce the width
				rightcol = col + ((rightcol - col + 1) / 2);
				captureWidth = (rightcol - col + 1) * TILE_WIDTH;
			}
			else { //This never happens in any case.
				retval = 0;
				break;
			}

		}
	} while (retval != 0);
#endif

	if (jpeg_buffer != NULL) 
	{
		*bufferSize = jpeg_buffer_length + (jpeg_buffer_length > 65500 ? 16 : 8);
		*buffer = malloc (*bufferSize);

		if (jpeg_buffer_length > 65500)
		{
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
			((unsigned int*)*buffer)[1] = (unsigned int)htonl(jpeg_buffer_length + 8);				// Size of the Next Packet
			((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[5] = 0;														// RESERVED
			((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
			memcpy_s((char *)(*buffer) + 16, (*bufferSize - 16), jpeg_buffer, jpeg_buffer_length);
		}
		else
		{
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
			((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
			memcpy_s((char *)(*buffer) + 8, (*bufferSize - 8), jpeg_buffer, jpeg_buffer_length);
		}
		free(jpeg_buffer);
		jpeg_buffer = NULL;
		jpeg_buffer_length = 0;
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
	
	return retval;
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

