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
#include "linux_kvm_capture.h"
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"

#ifndef LINUX_TILE_MALLOC
#define LINUX_TILE_MALLOC malloc
#endif

#if defined(JPEGMAXBUF)
	#define MAX_TILE_SIZE JPEGMAXBUF
#else
	#define MAX_TILE_SIZE 65500
#endif

extern int SCREEN_NUM;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
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

/******************************************************************************
 * INTERNAL FUNCTIONS
 ******************************************************************************/

//Extracts the required tile buffer from the desktop buffer
int get_tile_buffer(int x, int y, void **buffer, long long bufferSize, void *desktop, long long desktopsize, int tilewidth, int tileheight)
{
	char *target = *buffer;
	int height = 0;

	for (height = y; height < y + tileheight; height++) {
		memcpy_s(target, (size_t)bufferSize, (const void *)(((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x))), (size_t)(tilewidth * 3));
		target = (char *) (target + (3 * tilewidth));
	}

	return 0;
}

//This function returns 0 and *buffer != NULL if everything was good. retval = jpegsize if the captured image was too large.
static int calc_opt_compr_send_pixels(int x, int y, int captureWidth, int captureHeight, void* desktop,
    long long desktopsize, void **buffer, long long *bufferSize, const linux_tile_rgb32_frame *rgb32)
{

	*buffer = NULL;
	*bufferSize = 0;

	if (!desktop || desktopsize < 0 || SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0 ||
		TILE_WIDTH <= 0 || SCREEN_WIDTH > INT32_MAX - TILE_WIDTH ||
		SCREEN_HEIGHT > INT32_MAX - TILE_WIDTH || x < 0 || y < 0 ||
		captureWidth <= 0 || captureHeight <= 0 ||
		(uint64_t)x + captureWidth > (uint64_t)adjust_screen_size(SCREEN_WIDTH) ||
		(uint64_t)y + captureHeight > (uint64_t)adjust_screen_size(SCREEN_HEIGHT))
	{ jpeg_discard_output(); return -1; }
	unsigned pixelSize = rgb32 ? 4u : 3u;
	uint64_t rowStride = rgb32 ? rgb32->stride : (uint64_t)adjust_screen_size(SCREEN_WIDTH) * 3u;
	if (rowStride > SIZE_MAX)
	{ jpeg_discard_output(); return -1; }
	size_t stride = (size_t)rowStride;
	uint64_t offset = (uint64_t)y * stride + (uint64_t)x * pixelSize;
	uint64_t end = offset + (uint64_t)(captureHeight - 1) * stride + (uint64_t)captureWidth * pixelSize;
	if (end > (uint64_t)desktopsize || end > SIZE_MAX)
	{ jpeg_discard_output(); return -1; }
	if (write_JPEG_buffer_pixels((JSAMPLE *)desktop + (size_t)offset,
		captureWidth, captureHeight, stride, COMPRESSION_QUALITY,
        rgb32 ? rgb32->format : JPEG_RGB24) != 0) { return -1; }

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

int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void *desktop,
    long long desktopsize, void **buffer, long long *bufferSize)
{
    return calc_opt_compr_send_pixels(x, y, captureWidth, captureHeight, desktop,
        desktopsize, buffer, bufferSize, NULL);
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
static uint32_t tile_tail(const unsigned char *row, size_t bytes)
{
	uint32_t tail = 0;
	size_t count = bytes < 3u ? bytes : 3u;
	memcpy(&tail, row + bytes - count, count);
	return tail;
}

int util_crc(int x, int y, long long bufferSize, void *desktop, long long desktopsize, int tilewidth, int tileheight)
{
    uint32_t hval = 0;
    char *bp = NULL;
    char *be = NULL;
    int height = 0;

    // Walked as bytes: the row stride is 3 bytes per pixel, so these 32 bit reads land on
    // arbitrary addresses and must not be issued through an int* (SIGBUS on MIPS/ARMv5).
    for (height = y; height < y + tileheight; height++) {
    	bp = ((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x));
    	be = ((char *)desktop) + (3 * ((height * adjust_screen_size(SCREEN_WIDTH)) + x + tilewidth));
    	while ((bp + 4) <= be)
		{
			// hval *= 0x01000193;
			hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
			hval ^= (int)ILibUnaligned_Read32(bp);
			bp += 4;
		}

        // The legacy four-byte read at be-3 included a neighbouring byte and
        // read past the final desktop allocation. Hash only this row's bytes.
        hval = (hval * 0x01000193u) ^ tile_tail((const unsigned char *)desktop +
            3u * ((size_t)height * adjust_screen_size(SCREEN_WIDTH) + x), (size_t)tilewidth * 3u);
    }

    return (int)hval;
}

static void set_tile_checksum(int row, int col, uint32_t checksum)
{
	struct tileInfo_t *tile = &g_tileInfo[row][col];
	// 0xff is reset_tile_info's refresh sentinel, never an unchanged proof.
	tile->flag = tile->crc == 0xff || (uint32_t)tile->crc != checksum ? TILE_MARKED_NOT_SENT : TILE_DONT_SEND;
	tile->crc = (int)checksum;
}

// Four independent FNV chains hide multiply latency without changing image
// quality, capture cadence or the checksum width. All word reads are unaligned
// safe, and the scalar remainder uses the same bounded row-tail operation.
int update_tile_checksums(void *desktop, long long desktopsize)
{
	if (!desktop || !g_tileInfo || SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0 ||
		SCREEN_WIDTH > 32768 || SCREEN_HEIGHT > 32768 || TILE_WIDTH <= 0 || TILE_WIDTH > 32768 ||
		TILE_HEIGHT != TILE_WIDTH) { return -1; }
	size_t stride = (size_t)adjust_screen_size(SCREEN_WIDTH) * 3u;
	size_t height = (size_t)adjust_screen_size(SCREEN_HEIGHT);
	uint64_t required = (uint64_t)stride * height;
	if (desktopsize < 0 || required > SIZE_MAX || required > (uint64_t)desktopsize ||
		TILE_WIDTH_COUNT != adjust_screen_size(SCREEN_WIDTH) / TILE_WIDTH ||
		TILE_HEIGHT_COUNT != (int)height / TILE_HEIGHT) { return -1; }
	size_t bytes = (size_t)TILE_WIDTH * 3u;
	for (int row = 0; row < TILE_HEIGHT_COUNT; ++row)
	{
		int col = 0;
		for (; col + 3 < TILE_WIDTH_COUNT; col += 4)
		{
			uint32_t a = 0, b = 0, c = 0, d = 0;
			for (int y = 0; y < TILE_HEIGHT; ++y)
			{
				const unsigned char *p = (const unsigned char *)desktop +
					((size_t)row * TILE_HEIGHT + y) * stride + (size_t)col * bytes;
				for (size_t x = 0; x + 4u <= bytes; x += 4u)
				{
					a = (a * 0x01000193u) ^ ILibUnaligned_Read32(p + x);
					b = (b * 0x01000193u) ^ ILibUnaligned_Read32(p + bytes + x);
					c = (c * 0x01000193u) ^ ILibUnaligned_Read32(p + 2u * bytes + x);
					d = (d * 0x01000193u) ^ ILibUnaligned_Read32(p + 3u * bytes + x);
				}
				a = (a * 0x01000193u) ^ tile_tail(p, bytes);
				b = (b * 0x01000193u) ^ tile_tail(p + bytes, bytes);
				c = (c * 0x01000193u) ^ tile_tail(p + 2u * bytes, bytes);
				d = (d * 0x01000193u) ^ tile_tail(p + 3u * bytes, bytes);
			}
			set_tile_checksum(row, col, a); set_tile_checksum(row, col + 1, b);
			set_tile_checksum(row, col + 2, c); set_tile_checksum(row, col + 3, d);
		}
		for (; col < TILE_WIDTH_COUNT; ++col)
		{
			set_tile_checksum(row, col, (uint32_t)util_crc(col * TILE_WIDTH, row * TILE_HEIGHT,
				0, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT));
		}
	}
	return 0;
}

static int rgb32_frame_valid(const linux_tile_rgb32_frame *f)
{
    if (!f || !f->pixels || !jpeg_rgb32_supported(f->format) ||
        SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0 || (unsigned)SCREEN_WIDTH > KVM_CAPTURE_MAX_DIMENSION ||
        (unsigned)SCREEN_HEIGHT > KVM_CAPTURE_MAX_DIMENSION || TILE_WIDTH != 32 || TILE_HEIGHT != 32 ||
        SCREEN_WIDTH % 32 || f->stride < (size_t)SCREEN_WIDTH * 4u ||
        TILE_WIDTH_COUNT != SCREEN_WIDTH / 32 || TILE_HEIGHT_COUNT != adjust_screen_size(SCREEN_HEIGHT) / 32)
        return 0;
    size_t rows = (size_t)adjust_screen_size(SCREEN_HEIGHT);
    return f->capacity <= KVM_CAPTURE_MAX_BUFFER_BYTES && f->stride <= SIZE_MAX / rows &&
        f->stride * rows <= f->capacity;
}

static void rgb32_channels(jpeg_pixel_format format, unsigned *r, unsigned *g, unsigned *b)
{
    switch (format) {
    case JPEG_BGRX32: *r=2; *g=1; *b=0; break;
    case JPEG_RGBX32: *r=0; *g=1; *b=2; break;
    case JPEG_XBGR32: *r=3; *g=2; *b=1; break;
    default: *r=1; *g=2; *b=3; break; /* validated JPEG_XRGB32 */
    }
}

/* Keep the exact RGB24 hash and coalescing decisions. A small stack row replaces
 * the full RGB image; the X/alpha channel and source pitch padding are excluded. */
static uint32_t rgb32_crc(const linux_tile_rgb32_frame *f, int x, int y)
{
    unsigned r,g,b; rgb32_channels(f->format,&r,&g,&b);
    unsigned char rgb[32*3]; uint32_t hash=0;
    for (int row=0; row<32; ++row) {
        kvm_capture_rgb32_row(rgb,f->pixels+(size_t)(y+row)*f->stride+(size_t)x*4,32,r,g,b);
        for (size_t i=0; i<sizeof(rgb); i+=4) hash=(hash*0x01000193u)^ILibUnaligned_Read32(rgb+i);
        hash=(hash*0x01000193u)^tile_tail(rgb,sizeof(rgb));
    }
    return hash;
}

int update_tile_checksums_rgb32(const linux_tile_rgb32_frame *f)
{
    if (!g_tileInfo || !rgb32_frame_valid(f)) return -1;
    unsigned red,green,blue; rgb32_channels(f->format,&red,&green,&blue);
    unsigned char rgb[4*32*3];
    for (int row=0; row<TILE_HEIGHT_COUNT; ++row) {
        int col=0;
        for (; col+3<TILE_WIDTH_COUNT; col+=4) {
            uint32_t a=0,b=0,c=0,d=0;
            for (int y=0; y<32; ++y) {
                const unsigned char *source=f->pixels+((size_t)row*32+y)*f->stride+(size_t)col*32*4;
                kvm_capture_rgb32_row(rgb,source,128,red,green,blue);
                for (size_t i=0; i<96; i+=4) {
                    a=(a*0x01000193u)^ILibUnaligned_Read32(rgb+i);
                    b=(b*0x01000193u)^ILibUnaligned_Read32(rgb+96+i);
                    c=(c*0x01000193u)^ILibUnaligned_Read32(rgb+192+i);
                    d=(d*0x01000193u)^ILibUnaligned_Read32(rgb+288+i);
                }
                a=(a*0x01000193u)^tile_tail(rgb,96);
                b=(b*0x01000193u)^tile_tail(rgb+96,96);
                c=(c*0x01000193u)^tile_tail(rgb+192,96);
                d=(d*0x01000193u)^tile_tail(rgb+288,96);
            }
            set_tile_checksum(row,col,a); set_tile_checksum(row,col+1,b);
            set_tile_checksum(row,col+2,c); set_tile_checksum(row,col+3,d);
        }
        for (; col<TILE_WIDTH_COUNT; ++col) set_tile_checksum(row,col,rgb32_crc(f,col*32,row*32));
    }
    return 0;
}

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

// Reset the tile info structure
int reset_tile_info(int old_height_count) {
	int row, col;

	if (g_tileInfo != NULL) {
		for (row = 0; row < old_height_count; row++) {
			free(g_tileInfo[row]);
		}
		free(g_tileInfo);
		g_tileInfo = NULL;
	}

	if ((g_tileInfo = (struct tileInfo_t **) malloc (sizeof(struct tileInfo_t *) * TILE_HEIGHT_COUNT)) == NULL) ILIBCRITICALEXIT(254);

	for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
		if ((g_tileInfo[row] = (struct tileInfo_t *)calloc(TILE_WIDTH_COUNT, sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254);
		for (col = 0; col < TILE_WIDTH_COUNT; col++) {
			g_tileInfo[row][col].crc = 0xff;
		}
	}

	return 0;
}

static int tile_encode_failed(void)
{
    jpeg_discard_output();
    for (int r = 0; r < TILE_HEIGHT_COUNT; ++r)
        for (int c = 0; c < TILE_WIDTH_COUNT; ++c) g_tileInfo[r][c].crc = 0xff;
    return -1;
}

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesced to form a larger jpeg before returning.
static int getTileAt_pixels(int x, int y, void** buffer, long long *bufferSize, void *desktop,
    long long desktopsize, int row, int col, const linux_tile_rgb32_frame *rgb32)
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
		if ((CRC = rgb32 ? (int)rgb32_crc(rgb32,x,y) : util_crc(x, y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT)) == g_tileInfo[row][col].crc) return 0;
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
			CRC = rgb32 ? (int)rgb32_crc(rgb32,r_x,y) : util_crc(r_x, y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT);
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
		else {
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
				CRC = rgb32 ? (int)rgb32_crc(rgb32,r_x,r_y) : util_crc(r_x, r_y, TILE_HEIGHT * TILE_WIDTH * 3, desktop, desktopsize, TILE_WIDTH, TILE_HEIGHT);
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
	retval = calc_opt_compr_send_pixels(x, y, captureWidth, captureHeight, desktop, desktopsize, buffer, bufferSize, rgb32);
#else
	int firstTime = 1;

	//This loop is used to adjust the COMPRESSION_RATIO. This loop runs only once most of the time.
	do {
		//retval here is 0 if everything was good. It is > 0 if it contains the size of the jpeg that was created and not sent.
		retval = calc_opt_compr_send_pixels(x, y, captureWidth, captureHeight, desktop, desktopsize, buffer, bufferSize, rgb32);
		if (retval < 0) { return tile_encode_failed(); }
		if (retval != 0) {
			if (firstTime) {
				// Re-adjust the compression ratio.
				COMPRESSION_RATIO = (int)(((double)COMPRESSION_RATIO/(double)retval) * (0.92 * MAX_TILE_SIZE)); //Magic number: 92% of MAX_TILE_SIZE
				if (COMPRESSION_RATIO <= 1) { COMPRESSION_RATIO = 2; }
				firstTime = 0;
			}

			if (botrow > row) { //First time, try reducing the height.
				botrow = row + ((botrow - row) / 2);
				captureHeight = (botrow - row + 1) * TILE_HEIGHT;
			}
			else if (rightcol > col){ //If it is not possible, reduce the width
				rightcol = col + ((rightcol - col) / 2);
				captureWidth = (rightcol - col + 1) * TILE_WIDTH;
			}
			else { // A configured limit can be smaller than one tile.
				return tile_encode_failed();
			}

		}
	} while (retval != 0);
#endif

	if (retval < 0) { return tile_encode_failed(); }

	//Set the flags to TILE_SENT
	if (jpeg_buffer != NULL && jpeg_buffer_length > 0)
	{
		*bufferSize = jpeg_buffer_length + (jpeg_buffer_length > 65500 ? 16 : 8);
		*buffer = LINUX_TILE_MALLOC((size_t)*bufferSize);
		if (*buffer == NULL) { *bufferSize = 0; return tile_encode_failed(); }

		if (jpeg_buffer_length > 65500)
		{
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
			((unsigned int*)*buffer)[1] = (unsigned int)htonl(jpeg_buffer_length + 8);				// Size of the Next Packet
			((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[5] = 0;														// RESERVED
			((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
			memcpy_s((char *)(*buffer) + 16, *bufferSize -16, jpeg_buffer, jpeg_buffer_length);
		}
		else
		{
			((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
			((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
			((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
			((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
			memcpy_s((char *)(*buffer) + 8, *bufferSize -8, jpeg_buffer, jpeg_buffer_length);
		}

		jpeg_discard_output();

		for (r = row; r <= botrow; r++) {
			for (c = col; c <= rightcol; c++) {
				g_tileInfo[r][c].flag = TILE_SENT;
			}
		}
	}

	return retval;
}

int getTileAt(int x, int y, void **buffer, long long *bufferSize, void *desktop,
    long long desktopsize, int row, int col)
{
    return getTileAt_pixels(x,y,buffer,bufferSize,desktop,desktopsize,row,col,NULL);
}

int getTileAt_rgb32(int x, int y, void **buffer, long long *bufferSize,
    const linux_tile_rgb32_frame *f, int row, int col)
{
    if (!buffer || !bufferSize) return -1;
    *buffer=NULL; *bufferSize=0;
    if (!g_tileInfo || !rgb32_frame_valid(f) || row<0 || col<0 ||
        row>=TILE_HEIGHT_COUNT || col>=TILE_WIDTH_COUNT || x!=col*32 || y!=row*32) return -1;
    return getTileAt_pixels(x,y,buffer,bufferSize,f->pixels,(long long)f->capacity,row,col,f);
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
