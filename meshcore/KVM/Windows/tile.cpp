/*   
Copyright 2006 - 2022 Intel Corporation

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

#if defined(_LINKVM)

#include <stdio.h>
#include "tile.h"
#include <gdiplus.h>
#include "meshcore/meshdefines.h"
#include <setjmp.h>
#include "lib-jpeg-turbo/includes/jpeglib.h"
#include "lib-jpeg-turbo/includes/jerror.h"
using namespace Gdiplus;

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

// #define KVMDEBUGENABLED 1

#ifdef KVMDEBUGENABLED
extern "C"
{
extern void KvmCriticalLog(const char* msg, const char* file, int line, int user1, int user2);
#define KVMDEBUG(m,u) { KvmCriticalLog(m, __FILE__, __LINE__, u, GetLastError()); printf("TVMMSG: %s (%d,%d).\r\n", m, (int)u, (int)GetLastError()); }
#define KVMDEBUG2(x) x
}
#else
#define KVMDEBUG(m, u)
#define KVMDEBUG2(x)
#endif

extern "C"
{
#include "microstack/ILibCrypto.h"
int TILE_WIDTH = 0;			// Set in initialize_gdiplus()
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;	// Set in tile_info_alloc() for the scaled screen
int TILE_HEIGHT_COUNT = 0;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_X;
extern int SCREEN_Y;
extern int SCALED_WIDTH;
extern int SCALED_HEIGHT;
extern int PIXEL_SIZE;
extern int SCALING_FACTOR;
extern int SCALING_FACTOR_NEW;
extern int FRAME_RATE_TIMER;
}

// Used with setting up a GDI+ session.
GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;
HDC hDesktopDC;
HDC hCaptureDC;
HBITMAP hCapturedBitmap;
//HDC hdc;
CLSID encoderClsid;
ULONG encCompression = 50; // Image compression
EncoderParameters encParam;
// The viewer's choice, set from the input thread, while encoderClsid is looked up on the KVM thread only, after GdiplusStartup.
// In console mode a compression command can arrive before GdiplusStartup, and GDI+ called that early crashed the agent.
volatile LONG tileEncoderType = 1; // The type numbers of set_tile_compression()
int encoderClsidType = 0;

LPVOID tilebuffer = NULL;
unsigned int tilebuffersize = 0;

// Used to obtain the GUID for the image encoder.
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	unsigned int num = 0, size = 0;
	ImageCodecInfo* pImageCodecInfo = NULL;

	GetImageEncodersSize(&num, &size);
	if (size == 0) return -1;

	if ((pImageCodecInfo = (ImageCodecInfo*)(malloc(size))) == NULL) return -1;
	GetImageEncoders(num, size, pImageCodecInfo);

	for (unsigned int j = 0; j < num; ++j)
	{
		if (wcsncmp(pImageCodecInfo[j].MimeType, format, size) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;
		}
	}

	free(pImageCodecInfo);
	return -1;
}

// Adjusts the screen size(width or height) to be exactly divisible by TILE_WIDTH
int adjust_screen_size(int pixles) 
{
	int extra = pixles % TILE_WIDTH; // Assuming tile width and height will remain the same.
	if (extra != 0) return pixles + TILE_WIDTH - extra;
	return pixles;
}

// Extracts the required tile buffer from the desktop buffer
int get_tile_buffer(int x, int y, void **buffer, void *desktop, int tilewidth, int tileheight) 
{
	void *target = *buffer;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		memcpy_s(target, tilebuffersize, (const void *)((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE) ), (size_t)(tilewidth * PIXEL_SIZE));
		target = (void *) ((unsigned char *)target + tilewidth * PIXEL_SIZE);
	}
	return 0;
}

#define TILE_HEADER_SIZE 8
#define TILE_JUMBO_HEADER_SIZE 16
#define TILE_JUMBO_LIMIT 65500
#define TILE_JPEG_START_SIZE 4096
#define TILE_JPEG_OPTIMIZE_MAX_AREA (128 * 128)

// libjpeg writes the JPEG straight into the tile packet, behind room for the 8-byte header.
// Static, because the error branch reads it after the longjmp(), and only the KVM thread encodes.
static struct
{
	struct jpeg_compress_struct cinfo;
	struct jpeg_error_mgr err;
	jmp_buf jump;
	struct jpeg_destination_mgr dest;
	unsigned char *packet;
	size_t capacity;
} tileJpeg;

// Replaces libjpeg's error_exit(), which calls exit() and would end the KVM slave
static void tile_jpeg_error_exit(j_common_ptr cinfo)
{
	UNREFERENCED_PARAMETER(cinfo);
	longjmp(tileJpeg.jump, 1);
}

static void tile_jpeg_output_message(j_common_ptr cinfo)
{
	UNREFERENCED_PARAMETER(cinfo);
}

static void tile_jpeg_dest_init(j_compress_ptr cinfo)
{
	UNREFERENCED_PARAMETER(cinfo);
	tileJpeg.dest.next_output_byte = tileJpeg.packet + TILE_HEADER_SIZE;
	tileJpeg.dest.free_in_buffer = tileJpeg.capacity - TILE_HEADER_SIZE;
}

// libjpeg calls this with the whole buffer used, whatever next_output_byte and free_in_buffer say at that moment.
// When realloc() fails the old packet stays valid, and the error branch of tile_jpeg_encode() frees it.
static boolean tile_jpeg_dest_grow(j_compress_ptr cinfo)
{
	size_t used = tileJpeg.capacity;
	unsigned char *grown = (unsigned char*)realloc(tileJpeg.packet, used * 2);
	if (grown == NULL) { ERREXIT1(cinfo, JERR_OUT_OF_MEMORY, 10); }
	tileJpeg.packet = grown;
	tileJpeg.capacity = used * 2;
	tileJpeg.dest.next_output_byte = grown + used;
	tileJpeg.dest.free_in_buffer = used;
	return TRUE;
}

static void tile_jpeg_dest_term(j_compress_ptr cinfo)
{
	UNREFERENCED_PARAMETER(cinfo);
}

// Encodes a rectangle straight from the bottom-up desktop buffer into a malloc'd tile packet, with the header still to be written.
// Returns NULL when libjpeg reported an error or memory ran out
static char* tile_jpeg_encode(int x, int y, int width, int height, void *desktop, unsigned long *jpegSize)
{
	size_t stride = (size_t)adjust_screen_size(SCALED_WIDTH) * PIXEL_SIZE;
	JSAMPROW top, row;
	unsigned char *packet, *grown;
	size_t size;

	// jpeg_create_compress() keeps cinfo.err, so the error and destination managers are set up once
	if (tileJpeg.dest.init_destination == NULL)
	{
		tileJpeg.cinfo.err = jpeg_std_error(&tileJpeg.err);
		tileJpeg.err.error_exit = tile_jpeg_error_exit;
		tileJpeg.err.output_message = tile_jpeg_output_message;
		tileJpeg.dest.init_destination = tile_jpeg_dest_init;
		tileJpeg.dest.empty_output_buffer = tile_jpeg_dest_grow;
		tileJpeg.dest.term_destination = tile_jpeg_dest_term;
	}

	tileJpeg.capacity = TILE_JPEG_START_SIZE;
	if ((tileJpeg.packet = (unsigned char*)malloc(tileJpeg.capacity)) == NULL) { return NULL; }
	if (setjmp(tileJpeg.jump))
	{
		jpeg_destroy_compress(&tileJpeg.cinfo);
		free(tileJpeg.packet);
		tileJpeg.packet = NULL;
		return NULL;
	}

	jpeg_create_compress(&tileJpeg.cinfo);
	tileJpeg.cinfo.dest = &tileJpeg.dest;
	tileJpeg.cinfo.image_width = width;
	tileJpeg.cinfo.image_height = height;
	tileJpeg.cinfo.input_components = PIXEL_SIZE;
	tileJpeg.cinfo.in_color_space = (PIXEL_SIZE == 4) ? JCS_EXT_BGRX : JCS_EXT_BGR;
	jpeg_set_defaults(&tileJpeg.cinfo);
	// 4:4:4 like Linux and macOS, not the 4:2:0 of the defaults and of the old GDI+ encoder.
	// 4:2:0 averages the colour over 2x2 pixels, and a text stroke is thinner than that, so coloured text turned dull and dark.
	for (int c = 0; c < 3; c++) { tileJpeg.cinfo.comp_info[c].h_samp_factor = 1; tileJpeg.cinfo.comp_info[c].v_samp_factor = 1; }
	// No 18-byte JFIF block in every tile. Without it, decoders still take 3 components with IDs 1 to 3 as YCbCr.
	tileJpeg.cinfo.write_JFIF_header = FALSE;
	// Huffman tables built for each rectangle up to 128x128, where the standard tables are a large share of a small JPEG.
	// Larger rectangles gain less for the second pass over the data.
	if ((long long)width * height <= TILE_JPEG_OPTIMIZE_MAX_AREA) { tileJpeg.cinfo.optimize_coding = TRUE; }
	jpeg_set_quality(&tileJpeg.cinfo, (int)encCompression, TRUE);
	jpeg_start_compress(&tileJpeg.cinfo, TRUE);

	// The top row of the rectangle is its last row in the buffer, so the rows are walked backwards
	top = (JSAMPROW)desktop + (size_t)(adjust_screen_size(SCALED_HEIGHT) - 1 - y) * stride + (size_t)x * PIXEL_SIZE;
	while (tileJpeg.cinfo.next_scanline < tileJpeg.cinfo.image_height)
	{
		row = top - tileJpeg.cinfo.next_scanline * stride;
		jpeg_write_scanlines(&tileJpeg.cinfo, &row, 1);
	}

	jpeg_finish_compress(&tileJpeg.cinfo);
	jpeg_destroy_compress(&tileJpeg.cinfo);

	packet = tileJpeg.packet;
	tileJpeg.packet = NULL;
	size = tileJpeg.capacity - tileJpeg.dest.free_in_buffer - TILE_HEADER_SIZE;
	if (size > TILE_JUMBO_LIMIT)
	{
		// The jumbo header is longer, so the JPEG moves up behind it
		if (tileJpeg.capacity < size + TILE_JUMBO_HEADER_SIZE)
		{
			if ((grown = (unsigned char*)realloc(packet, size + TILE_JUMBO_HEADER_SIZE)) == NULL) { free(packet); return NULL; }
			packet = grown;
		}
		memmove_s(packet + TILE_JUMBO_HEADER_SIZE, size, packet + TILE_HEADER_SIZE, size);
	}
	*jpegSize = (unsigned long)size;
	return (char*)packet;
}

// Writes the tile header in front of the encoded image, a jumbo header when it is over 65500 bytes
static void set_tile_header(char *Tile, DWORD jpegSize, int x, int y, void **buffer, long long *bufferSize)
{
	*buffer = (unsigned char*)Tile;
	*bufferSize = jpegSize + (jpegSize > 65500 ? 16 : 8);

	if (jpegSize > 65500)
	{
		((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
		((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
		((unsigned int*)*buffer)[1]   = (unsigned int)htonl(jpegSize + 8);						// Size of the Next Packet
		((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
		((unsigned short*)*buffer)[5] = 0;														// RESERVED
		((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
		((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
	}
	else
	{
		((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
		((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
		((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
		((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
	}
}

// This function always returns 0 since jumbo support, and *buffer != NULL if everything was good
int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void* desktop, void ** buffer, long long *bufferSize) 
{
	BITMAPINFO bmpInfo;
	LARGE_INTEGER Offset;
	BITMAPFILEHEADER bmpFileHeader;
	*buffer = NULL;
	*bufferSize = 0;

	KVMDEBUG("calc_opt_compr_send()", 0);

	// JPEG goes through libjpeg, which reads the desktop buffer in place, and GDI+ below stays for PNG, TIFF and 16-bit screens
	int encoderType = (int)tileEncoderType;
	if (encoderType == 1 && (PIXEL_SIZE == 4 || PIXEL_SIZE == 3))
	{
		unsigned long encodedSize = 0;
		char *packet = tile_jpeg_encode(x, y, captureWidth, captureHeight, desktop, &encodedSize);
		if (packet == NULL)
		{
			KVMDEBUG("tile_jpeg_encode() failed", 0);
			ILibCriticalLog(NULL, __FILE__, __LINE__, 252, 0);
			return 0;
		}
		set_tile_header(packet, (DWORD)encodedSize, x, y, buffer, bufferSize);
		return 0;
	}

	if (encoderClsidType != encoderType)
	{
		switch (encoderType)
		{
			case 2: { GetEncoderClsid(L"image/png", &encoderClsid); break; }
			case 3: { GetEncoderClsid(L"image/tiff", &encoderClsid); break; }
			default: { GetEncoderClsid(L"image/jpeg", &encoderClsid); break; }
		}
		encoderClsidType = encoderType;
	}

	// Get the bmpInfo structure
	bmpInfo = get_bmp_info(captureWidth, captureHeight);

	// Make sure a tile buffer is available. Most of the time, this is skipped.
	if (tilebuffersize != bmpInfo.bmiHeader.biSizeImage)
	{
		if (tilebuffer != NULL) free(tilebuffer);
		tilebuffersize = 0;
		if ((tilebuffer = malloc(bmpInfo.bmiHeader.biSizeImage)) == NULL) return 0;
		tilebuffersize = bmpInfo.bmiHeader.biSizeImage;
	}

	// Get the final coalesced tile
	get_tile_buffer(x, y, &tilebuffer, desktop, captureWidth, captureHeight);

	bmpFileHeader.bfReserved1 = 0;
	bmpFileHeader.bfReserved2 = 0;
	bmpFileHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpInfo.bmiHeader.biSizeImage;
	bmpFileHeader.bfType = 'MB';
	bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// Construct stream object.
	IStream* bmpStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&bmpStream) != S_OK)
	{
		KVMDEBUG("CreateStreamOnHGlobal() failed", 0);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Write entire contents of the source BMP into this stream.
	bmpStream->Write(&bmpFileHeader, sizeof(BITMAPFILEHEADER), NULL);
	bmpStream->Write(&bmpInfo, sizeof(BITMAPINFOHEADER), NULL);
	bmpStream->Write(tilebuffer, bmpInfo.bmiHeader.biSizeImage, NULL);

	// Move the stream pointer to the beginning of the stream.
	Offset.QuadPart = 0;
	if (bmpStream->Seek(Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		KVMDEBUG("bmpStream->Seek() failed", 0);
		bmpStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Construct GDI+ Image object from the BMP stream.
	Gdiplus::Image* DIBImage = Gdiplus::Image::FromStream(bmpStream);

	// Create stream to receive the encoded JPEG.
	IStream* jpegStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&jpegStream) != S_OK)
	{
		KVMDEBUG("CreateStreamOnHGlobal() failed", 0);
		delete DIBImage;
		bmpStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Save image stream into the stream object.
	Status SaveStatus = DIBImage->Save(jpegStream, &encoderClsid, &encParam);
	if (SaveStatus != S_OK)
	{
		KVMDEBUG("DIBImage->Save() failed", 0);
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Get the size of the output stream
	ULARGE_INTEGER Size;
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_END, &Size) != S_OK)
	{
		KVMDEBUG("jpegStream->Save() failed", 0);
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}       

	// Move the image stream's pointer to its beginning.
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		KVMDEBUG("jpegStream->Seek() failed", 0);
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}        

	// A JPEG over 65500 bytes goes out as a jumbo packet
	DWORD jpegSize = (DWORD)Size.QuadPart;

	// Save the image stream in memory.
	char* Tile = (char*)ILibMemory_Allocate(jpegSize > 65500 ? (jpegSize + 16):(jpegSize + 8), 0, NULL, NULL);
	if (jpegStream->Read(Tile + (jpegSize > 65500 ? 16 : 8), jpegSize, NULL) != S_OK)
	{
		KVMDEBUG("jpegStream->Read() failed", 0);
		delete DIBImage;
		free(Tile);
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Cleanup
	delete DIBImage;
	bmpStream->Release();
	jpegStream->Release();

	set_tile_header(Tile, jpegSize, x, y, buffer, bufferSize);
	return 0;
}

struct tileInfo_t {
	unsigned char stale;	// 1 when the reference frame does not hold this tile, so it counts as changed
	unsigned char flags;	// See TILE_FLAGS_ENUM
};

enum TILE_FLAGS_ENUM {
	TILE_DONE = 0,			// Nothing to send, the tile is unchanged or was sent in this pass
	TILE_CHANGED			// The tile differs from the reference and was not sent yet
};

static tileInfo_t **tileInfo = NULL;			// One block that holds the row pointers and behind them the tiles
static volatile LONG tileRefreshPending = 0;

// The tiles as they were when last found changed, in the layout of the desktop buffer
static unsigned char *refFrame = NULL;
static long long refFrameSize = 0;
static int refPixelSize = 0;

// Reallocates the reference when the frame size or pixel format changed, and returns 1 then because it holds no tile anymore
static int tile_check_reference(void)
{
	long long size = (long long)adjust_screen_size(SCALED_WIDTH) * adjust_screen_size(SCALED_HEIGHT) * PIXEL_SIZE;
	if (refFrame != NULL && refFrameSize == size && refPixelSize == PIXEL_SIZE) { return 0; }
	free(refFrame);
	refFrameSize = 0;
	if ((refFrame = (unsigned char *)malloc((size_t)size)) == NULL) { return 0; }
	refFrameSize = size;
	refPixelSize = PIXEL_SIZE;
	return 1;
}

extern "C"
{

void tile_info_free(void)
{
	free(tileInfo);
	tileInfo = NULL;
}

// Every tile starts stale, so the next pass sends the whole screen
void tile_info_alloc(void)
{
	tile_info_free();
	TILE_WIDTH_COUNT = (SCALED_WIDTH + TILE_WIDTH - 1) / TILE_WIDTH;
	TILE_HEIGHT_COUNT = (SCALED_HEIGHT + TILE_HEIGHT - 1) / TILE_HEIGHT;

	size_t rows = (size_t)TILE_HEIGHT_COUNT * sizeof(tileInfo_t *);
	if ((tileInfo = (tileInfo_t **)malloc(rows + (size_t)TILE_HEIGHT_COUNT * TILE_WIDTH_COUNT * sizeof(tileInfo_t))) == NULL) { ILIBCRITICALEXIT(254); }
	tileInfo_t *tiles = (tileInfo_t *)((char *)tileInfo + rows);
	for (int r = 0; r < TILE_HEIGHT_COUNT; r++)
	{
		tileInfo[r] = tiles + (size_t)r * TILE_WIDTH_COUNT;
		for (int c = 0; c < TILE_WIDTH_COUNT; c++) { tileInfo[r][c].stale = 1; tileInfo[r][c].flags = TILE_DONE; }
	}
}

// The input thread only sets a flag, so the table is touched by the capture thread alone
void tile_request_refresh(void)
{
	InterlockedExchange(&tileRefreshPending, 1);
}

// Called by the capture loop before it walks the tiles of a new frame. Marks the tiles that differ from the reference.
// The frame is compared in memory order, a pixel row at a time, because tile by tile is several times slower on some processors.
// Exact, a hash could miss a change. Only the parts that differ are copied, so the reference holds the frame afterwards.
void tile_start_pass(void *desktop)
{
	int all = (int)InterlockedExchange(&tileRefreshPending, 0);
#ifdef KVM_ALL_TILES
	all = 1;
#endif
	if (tile_check_reference()) { all = 1; }
	if (refFrame == NULL) { all = 1; } // Without a reference every tile counts as changed, which costs data but loses nothing

	size_t stride = (size_t)adjust_screen_size(SCALED_WIDTH) * PIXEL_SIZE;
	size_t len = (size_t)TILE_WIDTH * PIXEL_SIZE;
	for (int row = TILE_HEIGHT_COUNT - 1; row >= 0; row--) // The last tile row lies first in the bottom-up frame
	{
		size_t offset = (size_t)(adjust_screen_size(SCALED_HEIGHT) - (row + 1) * TILE_HEIGHT) * stride;
		unsigned char *cur = (unsigned char *)desktop + offset;
		tileInfo_t *tiles = tileInfo[row];

		for (int col = 0; col < TILE_WIDTH_COUNT; col++)
		{
			if (all) { tiles[col].stale = 1; }
			tiles[col].flags = tiles[col].stale ? TILE_CHANGED : TILE_DONE;
		}
		if (refFrame == NULL) { continue; }

		unsigned char *ref = refFrame + offset;
		for (int r = 0; r < TILE_HEIGHT; r++, cur += stride, ref += stride)
		{
			for (int col = 0; col < TILE_WIDTH_COUNT; col++)
			{
				if (!tiles[col].stale && memcmp(cur + col * len, ref + col * len, len) == 0) { continue; }
				memcpy(ref + col * len, cur + col * len, len);
				tiles[col].flags = TILE_CHANGED;
			}
		}
		for (int col = 0; col < TILE_WIDTH_COUNT; col++) { tiles[col].stale = 0; }
	}
}

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesed to form a larger jpeg before returning.
void get_tile_at(void** buffer, long long *bufferSize, void *desktop, int row, int col)
{
	int x = col * TILE_WIDTH;
	int y = row * TILE_HEIGHT;
	int rightcol = col;		// Used in coalescing. Indicates the right-most column to be coalesced.
	int botrow = row;		// Used in coalescing. Indicates the bottom-most row to be coalesced.
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;

	*buffer = NULL;			// If anything fails, this will be the indication.
	*bufferSize = 0;

	// Nothing to send when the tile is unchanged or was already sent in this pass
	if (tileInfo[row][col].flags != TILE_CHANGED) return;


	// COALESCING SECTION

	// First go to the right most changed tile
	while (rightcol + 1 < TILE_WIDTH_COUNT && tileInfo[row][rightcol + 1].flags == TILE_CHANGED)
	{
		rightcol++;
		captureWidth += TILE_WIDTH;
	}

	// Now go to the bottom tiles, a row of them is added when all of its tiles have changed
	while (botrow + 1 < TILE_HEIGHT_COUNT)
	{
		int rcol = col;
		while (rcol <= rightcol && tileInfo[botrow + 1][rcol].flags == TILE_CHANGED) { rcol++; }
		if (rcol <= rightcol) { break; }
		botrow++;
		captureHeight += TILE_HEIGHT;
	}

	// One encode for the whole region, whatever its size
	calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, buffer, bufferSize);

	// After an encode the tiles of the region are done for this pass, after a failed one they are stale so the next pass tries them again
	for (int r = row; r <= botrow; r++) {
		for (int c = col; c <= rightcol; c++) {
			if (*buffer != NULL) { tileInfo[r][c].flags = TILE_DONE; } else { tileInfo[r][c].stale = 1; }
		}
	}
}

// This function captures the entire desktop buffer to scan.
int get_desktop_buffer(void **buffer, long long *bufferSize, long* mouseMove)
{
	BITMAPINFO bmpInfo;

	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;

	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	if ((hDesktopDC = GetDC(NULL)) == NULL) { KVMDEBUG("GetDC(NULL) returned NULL", 0); return 1; } // We need to do this incase the current desktop changes.
	if (hCapturedBitmap) DeleteObject(hCapturedBitmap);	
	if ((hCapturedBitmap = CreateCompatibleBitmap(hDesktopDC, adjust_screen_size(SCALED_WIDTH), adjust_screen_size(SCALED_HEIGHT))) == NULL)
	{
		KVMDEBUG("CreateCompatibleBitmap() returned NULL", 0);
		return 1;
	}
	
	if (SelectObject(hCaptureDC, hCapturedBitmap) == NULL) { KVMDEBUG("SelectObject() failed", 0); return(1); }
	if (SCALING_FACTOR == 1024)
	{
		if (BitBlt(hCaptureDC, 0, 0, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, SRCCOPY) == FALSE)
		{
			KVMDEBUG("BitBlt() returned FALSE", 0);
			return 1; // If the copy fails, error out.
		}
		if (mouseMove[0] != 0)
		{
			CURSORINFO info = { 0 };
			ICONINFO ii = { 0 };
			info.cbSize = sizeof(info);
			if (GetCursorInfo(&info) && (info.flags & CURSOR_SHOWING) != 0 && GetIconInfo(info.hCursor, &ii))
			{
				// DrawIconEx() applies the cursor's masks and alpha to the captured pixels, as Windows does on the screen
				DrawIconEx(hCaptureDC, mouseMove[1] - (int)ii.xHotspot, mouseMove[2] - (int)ii.yHotspot, info.hCursor, 0, 0, 0, NULL, DI_NORMAL);
				// GetIconInfo returns copies of the cursor bitmaps that we own
				if (ii.hbmMask != NULL) { DeleteObject(ii.hbmMask); }
				if (ii.hbmColor != NULL) { DeleteObject(ii.hbmColor); }
			}
		}
	}
	else
	{
		if (SetStretchBltMode(hCaptureDC, HALFTONE) == 0) { KVMDEBUG("SetStretchBltMode() failed", 0); return(1); }
		if (StretchBlt(hCaptureDC, 0, 0, adjust_screen_size(SCALED_WIDTH), adjust_screen_size(SCALED_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), SRCCOPY) == FALSE)
		{
			KVMDEBUG("StretchBlt() returned FALSE", 0);
			return 1; // If the copy fails, error out.
		}
	}

	ZeroMemory(&bmpInfo, sizeof(BITMAPINFO));
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);

	// Populates some fields in the bmpInfo struct based on the properties of the bitmap.
	if (GetDIBits(hDesktopDC, hCapturedBitmap, 0, 0, NULL, &bmpInfo, DIB_RGB_COLORS) == 0)
	{
		KVMDEBUG("GetDIBits() failed", 0);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return(1);
	}

	// Screens below 24 bits are captured as 32-bit BGRX, so their tiles go through libjpeg instead of GDI+.
	// GetDIBits() converts the pixels, the screen itself keeps its depth.
	if (bmpInfo.bmiHeader.biBitCount < 24)
	{
		bmpInfo.bmiHeader.biBitCount = 32;
		bmpInfo.bmiHeader.biClrUsed = 0;
		bmpInfo.bmiHeader.biSizeImage = 0;
	}

	if (bmpInfo.bmiHeader.biSizeImage <= 0)
	{
		bmpInfo.bmiHeader.biSizeImage = bmpInfo.bmiHeader.biWidth * abs(bmpInfo.bmiHeader.biHeight) * (bmpInfo.bmiHeader.biBitCount + 7) / 8;
	}

	*bufferSize = bmpInfo.bmiHeader.biSizeImage;
	PIXEL_SIZE = bmpInfo.bmiHeader.biBitCount / 8;
	if ((*buffer = malloc((size_t)*bufferSize)) == NULL) { KVMDEBUG("malloc() failed", 0); return 1; }
	
	bmpInfo.bmiHeader.biCompression = BI_RGB;
	if (GetDIBits(hDesktopDC, hCapturedBitmap, 0, bmpInfo.bmiHeader.biHeight, *buffer, &bmpInfo, DIB_RGB_COLORS) == 0) { KVMDEBUG("GetDIBits() failed", 0); free(*buffer); return(1); }

	return 0;
}

// Creates a BITMAPINFO object with required width and height
BITMAPINFO get_bmp_info(int width, int height)
{
	BITMAPINFO bmpInfo;

	ZeroMemory(&bmpInfo, sizeof(BITMAPINFO));
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmpInfo.bmiHeader.biBitCount = (WORD)(PIXEL_SIZE * 8);
	bmpInfo.bmiHeader.biSize = 40;
	bmpInfo.bmiHeader.biHeight = height;
	bmpInfo.bmiHeader.biWidth = width;
	bmpInfo.bmiHeader.biSizeImage = height * width * PIXEL_SIZE;
	bmpInfo.bmiHeader.biPlanes = 1;

	return bmpInfo;
}

short initialize_gdiplus()
{
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	FRAME_RATE_TIMER = 50;
	SCALING_FACTOR = 1024;
	SCALING_FACTOR_NEW = 1024;

	SCALED_WIDTH = SCREEN_WIDTH = GetSystemMetrics(SM_CXSCREEN);
	SCALED_HEIGHT = SCREEN_HEIGHT = GetSystemMetrics(SM_CYSCREEN);

	if ((hDesktopDC = GetDC(NULL)) == NULL) { KVMDEBUG("GetDC() failed", 0); return 0; }
	if ((hCaptureDC = CreateCompatibleDC(hDesktopDC)) == NULL) { KVMDEBUG("CreateCompatibleDC() failed", 0); return 0; }
	if ((hCapturedBitmap = CreateCompatibleBitmap(hDesktopDC, SCALED_WIDTH, SCALED_HEIGHT)) == NULL) { KVMDEBUG("CreateCompatibleBitmap() failed", 0); return 0; }
	if (SelectObject(hCaptureDC, hCapturedBitmap) == NULL) { KVMDEBUG("SelectObject() failed", 0); }
	
	// Find encoder and setup encoder parameters
	encoderClsidType = 0; // Looked up by the first GDI+ encode, the viewer's type may already be set
	encParam.Count = 1;
	encParam.Parameter[0].Guid = EncoderQuality;
	encParam.Parameter[0].Type = EncoderParameterValueTypeLong;
	encParam.Parameter[0].NumberOfValues = 1;
	encParam.Parameter[0].Value = &encCompression;

	return 1;
}

void teardown_gdiplus()
{
	if (tilebuffer) free(tilebuffer);
	tilebuffersize = 0;
	tilebuffer = NULL;
	free(refFrame);
	refFrame = NULL;
	refFrameSize = 0;
	GdiplusShutdown(gdiplusToken);
	DeleteDC(hCaptureDC);
	DeleteObject(hCapturedBitmap);
	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	hDesktopDC = NULL;
}

void set_tile_compression(int type, int level)
{
	encCompression = level;
	if (encCompression < 1) { encCompression = 1; } // Guard against bad values.
	if (encCompression > 90) { encCompression = 90; }
	KVMDEBUG("set_tile_compression() type", type);
	KVMDEBUG("set_tile_compression() level", level);

	// Only the type is stored here, GDI+ may not be started yet and encoderClsid belongs to the KVM thread
	if (type >= 1 && type <= 3) { tileEncoderType = type; }
}

}

#endif
