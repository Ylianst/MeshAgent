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

// Really fast CRC-like method. Used for the KVM.

int util_crc(int x, int y, long long bufferSize, void *desktop, long long desktopsize, int tilewidth, int tileheight)
{
    int hval = 0;
    int *bp = NULL;
    int *be = NULL;
    int height = 0;
	
    for (height = y; height < y + tileheight; height++) {
    	bp = (int *)(((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x)));
    	be = (int *)(((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x + tilewidth)));
    	while ((bp + 1) <= be)
		{
			//hval *= 0x01000193;
			hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
			hval ^= *bp++;
		}
		
    	/*if ((int)be - (int)bp >= 0) {
		 hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
		 hval ^= (*(int *)(((int)be) - 3));
		 }*/
    }
	
    return hval;
}

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

// Reset the tile info structure
int reset_tile_info(int old_height_count) {
	int row, col;
	
	if (g_tileInfo != NULL)
	{
		for (row = 0; row < old_height_count; row++) { free(g_tileInfo[row]); }
		free(g_tileInfo);
		g_tileInfo = NULL;
	}
	
	g_tileInfo = (struct tileInfo_t **) malloc(sizeof(struct tileInfo_t *) * TILE_HEIGHT_COUNT);
	for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
		g_tileInfo[row] = (struct tileInfo_t *) calloc (TILE_WIDTH_COUNT, sizeof(struct tileInfo_t));
		for (col = 0; col < TILE_WIDTH_COUNT; col++) { g_tileInfo[row][col].crc = 0xff; }
	}
	
	return 0;
}

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesced to form a larger jpeg before returning.
int getTileAt(int x, int y, void** buffer, long long *bufferSize, void *desktop, long long desktopsize, int row, int col)
{
	int CRC, rcol, i, r, c;
	int rightcol = col; //Used in coalescing. Indicates the rightmost column to be coalesced.
	int botrow = row; //Used in coalescing. Indicates the bottom most row to be coalesced.
	int r_x = x;
	int r_y = y;
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;
	
	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;
	
	if (g_tileInfo[row][col].flag == TILE_TODO) { //First check whether the tile-crc needs to be calculated or not.
		if ((CRC = util_crc(x, y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT)) == g_tileInfo[row][col].crc) return 0;
		g_tileInfo[row][col].crc = CRC; //Update the tile CRC in the global data structure.
	}
	
	g_tileInfo[row][col].flag = TILE_MARKED_NOT_SENT;
	
	//COALESCING SECTION
	
	// First got to the right most changed tile and record it
	while (rightcol + 1 < TILE_WIDTH_COUNT) {
		rightcol++;
		r_x = rightcol * TILE_WIDTH;
		
		CRC = g_tileInfo[row][rightcol].crc;
		
		if (g_tileInfo[row][rightcol].flag == TILE_TODO) {
			CRC = util_crc(r_x, y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT);
		}
		
		if (CRC != g_tileInfo[row][rightcol].crc || g_tileInfo[row][rightcol].flag == TILE_MARKED_NOT_SENT) { //If the tile has changed, increment the capturewidth.
			g_tileInfo[row][rightcol].crc = CRC;

#if MAX_TILE_SIZE > 0
			//Here we check whether the size of the coalesced bitmap is greater than the threshold (MAX_TILE_SIZE)
			if ((captureWidth + TILE_WIDTH) * TILE_HEIGHT * 3 / COMPRESSION_RATIO > MAX_TILE_SIZE)
			{
				g_tileInfo[row][rightcol].flag = TILE_MARKED_NOT_SENT;
				--rightcol;
				break;
			}
#endif

			g_tileInfo[row][rightcol].flag = TILE_MARKED_NOT_SENT;
			captureWidth += TILE_WIDTH;
		}
		else
		{
			g_tileInfo[row][rightcol].flag = TILE_DONT_SEND;
			--rightcol;
			break;
		}
	}
	
	//int TOLERANCE = (rightcol - col) / 3;
	
	// Now go to the bottom tiles, check if they have changed and record them
#if MAX_TILE_SIZE > 0
	while ((botrow + 1 < TILE_HEIGHT_COUNT) && ((captureHeight + TILE_HEIGHT) * captureWidth * 3 / COMPRESSION_RATIO <= MAX_TILE_SIZE))
#else
	while ((botrow + 1 < TILE_HEIGHT_COUNT))
#endif
	{
		botrow++;
		r_y = botrow * TILE_HEIGHT;
		int fail = 0;
		r_x = x;
		
		//int missCount = 0;
		
		for (rcol = col; rcol <= rightcol; rcol++) {
			
			CRC = g_tileInfo[botrow][rcol].crc;
			if (g_tileInfo[botrow][rcol].flag == TILE_TODO) {
				CRC = util_crc(r_x, r_y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT);
			}
			
			if (CRC != g_tileInfo[botrow][rcol].crc || g_tileInfo[botrow][rcol].flag == TILE_MARKED_NOT_SENT) {
				g_tileInfo[botrow][rcol].flag = TILE_MARKED_NOT_SENT;
				g_tileInfo[botrow][rcol].crc = CRC;
				r_x += TILE_WIDTH;
			}
			else {
				/*//Keep this part commented. Adding tolerance adds to the complexity of this code.
				 missCount++;
				 
				 if (missCount > TOLERANCE) {
				 fail = 1;
				 for (int i = col; i < rcol; i++) {
				 if (g_tileInfo[botrow][i].flag == TILE_SKIPPED) {
				 g_tileInfo[botrow][i].flag = TILE_DONT_SEND;
				 }
				 else {
				 g_tileInfo[botrow][i].flag = TILE_MARKED_NOT_SENT;
				 }
				 }
				 g_tileInfo[botrow][rcol].flag = TILE_DONT_SEND;
				 botrow--;
				 break;
				 }
				 else {
				 g_tileInfo[botrow][rcol].flag = TILE_SKIPPED;
				 g_tileInfo[botrow][rcol].crc = CRC;
				 r_x += TILE_WIDTH;
				 }*/
				fail = 1;
				for (i = col; i < rcol; i++) {
					g_tileInfo[botrow][i].flag = TILE_MARKED_NOT_SENT;
				}
				g_tileInfo[botrow][rcol].flag = TILE_DONT_SEND;
				botrow--;
				break;
			}
		}
		
		if (!fail) {
			captureHeight += TILE_HEIGHT;
		}
		else {
			break;
		}
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

	//Set the flags to TILE_SENT
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
		
		for (r = row; r <= botrow; r++) {
			for (c = col; c <= rightcol; c++) 
			{
				g_tileInfo[r][c].flag = TILE_SENT;
			}
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

	CGImageAlphaInfo alphaInfo = CGImageGetAlphaInfo(image);
	
	CFDataRef dataRef = CGDataProviderCopyData(CGImageGetDataProvider(image));
	const unsigned char *sourceBytesPtr = CFDataGetBytePtr(dataRef);
	len = CFDataGetLength(dataRef);
	
	if (*desktopsize != len) {
		if (*desktop != NULL) { free(*desktop); }
		*desktopsize = len;
		*desktop = (unsigned char *) malloc (*desktopsize);
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

