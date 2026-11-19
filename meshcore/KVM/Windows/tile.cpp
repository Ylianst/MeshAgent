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
#include "dxgi_capture.h"
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
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_X;
extern int SCREEN_Y;
extern int SCALED_WIDTH;
extern int SCALED_HEIGHT;
extern int PIXEL_SIZE;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;
extern int COMPRESSION_RATIO;
extern int SCALING_FACTOR;
extern int SCALING_FACTOR_NEW;
extern int FRAME_RATE_TIMER;
extern tileInfo_t **tileInfo;
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
LPVOID tilebuffer = NULL;
unsigned int tilebuffersize = 0;

// The captured frame, kept across frames and freed in teardown_gdiplus()
void *captureBuffer = NULL;
long long captureBufferSize = 0;
int capturedWidth = 0;
int capturedHeight = 0;

// Set while captureBuffer holds the last DXGI frame, cleared when GDI writes into it
int captureHoldsDxgiFrame = 0;

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

int tile_crc(int x, int y, void *desktop, int tilewidth, int tileheight) 
{
	int crc = 0;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		crc = util_crc(((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE) ), (size_t)(tilewidth * PIXEL_SIZE), crc);
	}
	return crc;
}

// This function returns 0 and *buffer != NULL if everything was good. retval = jpegsize if the captured image was too large.
int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void* desktop, void ** buffer, long long *bufferSize) 
{
	BITMAPINFO bmpInfo;
	LARGE_INTEGER Offset;
	BITMAPFILEHEADER bmpFileHeader;
	*buffer = NULL;
	*bufferSize = 0;

	KVMDEBUG("calc_opt_compr_send()", 0);

	// Get the bmpInfo structure
	bmpInfo = get_bmp_info(captureWidth, captureHeight);

	// Make sure a tile buffer is available. Most of the time, this is skipped.
	if (tilebuffersize != bmpInfo.bmiHeader.biSizeImage)
	{
		if (tilebuffer != NULL) free(tilebuffer);
		tilebuffersize = bmpInfo.bmiHeader.biSizeImage;
		if ((tilebuffer = malloc(tilebuffersize)) == NULL) return 0;
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

	// Check if the tile is too large to send
	DWORD jpegSize = (DWORD)Size.QuadPart;

	//if (jpegSize > 65500)
	//{
	//	KVMDEBUG("jpegSize > 65500", jpegSize);
	//	delete DIBImage;
	//	*bufferSize = 0;
	//	// ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
	//	return jpegSize;
	//}

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

	*buffer = (unsigned char*)Tile;
	*bufferSize = jpegSize + (jpegSize > 65500 ? 16 : 8);

	// Place the header
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
	return 0;
}


extern "C"
{

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesed to form a larger jpeg before returning.
int get_tile_at(int x, int y, void** buffer, long long *bufferSize, void *desktop, int row, int col)
{	
	int CRC;
	int rightcol = col;		// Used in coalescing. Indicates the right-most column to be coalesced.
	int botrow = row;		// Used in coalescing. Indicates the bottom-most row to be coalesced.
	int r_x = x;
	int r_y = y;
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;

	*buffer = NULL;			// If anything fails, this will be the indication.
	*bufferSize = 0;

	if (tileInfo[row][col].flags == (char)TILE_TODO) // First check whether the tile-crc needs to be calcualted or not.
	{ 
		// Compute CRC on the contents of the bitmap; Proceed with image encoding only if the CRC is different.
		if ((CRC = tile_crc(x, y, desktop, TILE_WIDTH, TILE_HEIGHT)) == tileInfo[row][col].crc) return 0;
		tileInfo[row][col].crc = CRC; // Update the tile CRC in the global data structure.
	}

	tileInfo[row][col].flags = (char)TILE_MARKED_NOT_SENT;


	// COALESCING SECTION

	// First got to the right most changed tile and record it
	while (rightcol + 1 < TILE_WIDTH_COUNT)
	{
		rightcol++;
		r_x = rightcol * TILE_WIDTH;
		
		CRC = tileInfo[row][rightcol].crc;

		if (tileInfo[row][rightcol].flags == (char)TILE_TODO) {
			// Compute CRC on the contents of the bitmap.
			CRC = tile_crc(r_x, y, desktop, TILE_WIDTH, TILE_HEIGHT);
		}

		if (CRC != tileInfo[row][rightcol].crc || tileInfo[row][rightcol].flags == (char)TILE_MARKED_NOT_SENT) // If the tile has changed, increment the capturewidth.
		{
			tileInfo[row][rightcol].crc = CRC; 
			// Here we check whether the size of the coalesced bitmap is greater than the threshold (65500)
			//if ((captureWidth + TILE_WIDTH) * TILE_HEIGHT * PIXEL_SIZE / COMPRESSION_RATIO > 65500) { 
			//	tileInfo[row][rightcol].flags = (char)TILE_MARKED_NOT_SENT;
			//	--rightcol;
			//	break;
			//}

			tileInfo[row][rightcol].flags = (char)TILE_MARKED_NOT_SENT;
			captureWidth += TILE_WIDTH;
		} 
		else
		{
			tileInfo[row][rightcol].flags = (char)TILE_DONT_SEND;
			--rightcol;
			break;
		}
	}

	// int TOLERANCE = (rightcol - col) / 4;

	// Now go to the bottom tiles, check if they have changed and record them
	//while ((botrow + 1 < TILE_HEIGHT_COUNT) && ((captureHeight + TILE_HEIGHT) * captureWidth * PIXEL_SIZE / COMPRESSION_RATIO <= 65500))
	while ((botrow + 1 < TILE_HEIGHT_COUNT))
	{
		botrow++;
		r_y = botrow * TILE_HEIGHT;
		int fail = 0;
		r_x = x;

		// int missCount = 0;

		for (int rcol = col; rcol <= rightcol; rcol++) {

			CRC = tileInfo[botrow][rcol].crc;
			if (tileInfo[botrow][rcol].flags == (char)TILE_TODO)
			{
				// Compute CRC on the contents of the bitmap; Proceed with image encoding only if the CRC is different.
				CRC = tile_crc(r_x, r_y, desktop, TILE_WIDTH, TILE_HEIGHT);
			}

			if (CRC != tileInfo[botrow][rcol].crc || tileInfo[botrow][rcol].flags == (char)TILE_MARKED_NOT_SENT)
			{
				tileInfo[botrow][rcol].flags = (char)TILE_MARKED_NOT_SENT;
				tileInfo[botrow][rcol].crc = CRC;
				r_x += TILE_WIDTH;
			}
			else
			{
				/*// Keep this part commented. Adding tolerance adds to the complexity of this code.
				missCount++;

				if (missCount > TOLERANCE) {
					fail = 1;
					for (int i = col; i < rcol; i++) {
						if (tileInfo[botrow][i].flags == (char)TILE_SKIPPED) {
							tileInfo[botrow][i].flags = (char)TILE_DONT_SEND;
						} 
						else {
							tileInfo[botrow][i].flags = (char)TILE_MARKED_NOT_SENT;
						}
					}
					tileInfo[botrow][rcol].flags = (char)TILE_DONT_SEND;
					botrow--;
					break;
				}
				else {
					tileInfo[botrow][rcol].flags = (char)TILE_SKIPPED;
					tileInfo[botrow][rcol].crc = CRC;
					r_x += TILE_WIDTH;
				}*/
				fail = 1;
				for (int i = col; i < rcol; i++)
				{
					tileInfo[botrow][i].flags = (char)TILE_MARKED_NOT_SENT;
				}
				tileInfo[botrow][rcol].flags = (char)TILE_DONT_SEND;
				botrow--;
				break;
			}
		}

		if (!fail)
		{
			captureHeight += TILE_HEIGHT;
		}
		else
		{
			break;
		}
	}

	int retval = 0;
	int firstTime = 1;

	// This loop is used to adjust the COMPRESSION_RATIO. This loop runs only once most of the time.
	do {
		// retval here is 0 if everything was good. It is > 0 if it contains the size of the jpeg that was created and not sent.
		retval = calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, buffer, bufferSize);
		if (retval == 0 && *bufferSize == 0) break;
		if (retval != 0)
		{
			if (firstTime)
			{
				// Re-adjust the compression ratio.
				//COMPRESSION_RATIO = (int)(((double)COMPRESSION_RATIO/(double)retval) * 60000);//Magic number: 60000 ~= 65500
				//if (COMPRESSION_RATIO <= 1) COMPRESSION_RATIO = 2;
				firstTime = 0;
			}

			if (botrow > row) // First time, try reducing the height.
			{ 
				botrow = row + ((botrow - row + 1) / 2);
				captureHeight = (botrow - row + 1) * TILE_HEIGHT;
			}
			else if (rightcol > col) // If it is not possible, reduce the width
			{
				rightcol = col + ((rightcol - col + 1) / 2);
				captureWidth = (rightcol - col + 1) * TILE_WIDTH;
			} 
			else
			{   // This never happens, but just in case.
				retval = 0;
				break;
			}

		}
	} while (*buffer == NULL);

	// Set the flags to TILE_SENT
	if (*buffer != NULL) {
		for (int r = row; r <= botrow; r++) {
			for (int c = col; c <= rightcol; c++) {
				tileInfo[r][c].flags = (char)TILE_SENT;
			}
		}
	}

	return retval;
}

// The pixels under the cursor drawn into the last DXGI frame. A frame without changes leaves the buffer as it is,
// so they are put back before the next capture.
static unsigned char *cursorSave = NULL;
static size_t cursorSaveSize = 0;
static int cursorSaveX = 0, cursorSaveY = 0, cursorSaveW = 0, cursorSaveH = 0;
static HDC hCursorDC = NULL;
static HBITMAP hCursorBitmap = NULL;
static HGDIOBJ hCursorOldBitmap = NULL;
static unsigned char *cursorBits = NULL;
static int cursorDibW = 0, cursorDibH = 0;

// The capture buffer is a bottom-up DIB, so screen row y is buffer row (bufH - 1 - y)
static unsigned char *capture_row(int y, int bufW, int bufH)
{
	return (unsigned char *)captureBuffer + (size_t)(bufH - 1 - y) * bufW * 4;
}

static void dxgi_cursor_restore(int bufW, int bufH)
{
	for (int r = 0; r < cursorSaveH; r++)
	{
		memcpy(capture_row(cursorSaveY + r, bufW, bufH) + (size_t)cursorSaveX * 4, cursorSave + (size_t)r * cursorSaveW * 4, (size_t)cursorSaveW * 4);
	}
	cursorSaveW = cursorSaveH = 0;
}

// A top-down 32 bpp DIB section of the cursor's size, kept until the size changes
static int dxgi_cursor_dib(int cw, int ch)
{
	BITMAPINFO bi;

	if (hCursorBitmap != NULL && cursorDibW == cw && cursorDibH == ch) { return 0; }
	if (hCursorDC == NULL && (hCursorDC = CreateCompatibleDC(NULL)) == NULL) { return 1; }
	if (hCursorBitmap != NULL)
	{
		SelectObject(hCursorDC, hCursorOldBitmap);
		DeleteObject(hCursorBitmap);
		hCursorBitmap = NULL;
	}
	cursorDibW = cursorDibH = 0;
	ZeroMemory(&bi, sizeof(bi));
	bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bi.bmiHeader.biWidth = cw;
	bi.bmiHeader.biHeight = -ch;
	bi.bmiHeader.biPlanes = 1;
	bi.bmiHeader.biBitCount = 32;
	bi.bmiHeader.biCompression = BI_RGB;
	if ((hCursorBitmap = CreateDIBSection(hCursorDC, &bi, DIB_RGB_COLORS, (void **)&cursorBits, NULL, 0)) == NULL) { return 1; }
	hCursorOldBitmap = SelectObject(hCursorDC, hCursorBitmap);
	cursorDibW = cw;
	cursorDibH = ch;
	return 0;
}

// Draws the cursor at (x, y) into the DXGI frame. DrawIconEx() draws on a copy of the pixels under it, so masks, alpha
// and inverting cursors such as the text cursor come out as on the screen. The covered pixels are kept for the restore.
static void dxgi_cursor_draw(int x, int y, int bufW, int bufH)
{
	CURSORINFO info = { 0 };
	ICONINFO ii = { 0 };
	BITMAP bm;

	info.cbSize = sizeof(info);
	if (!GetCursorInfo(&info) || (info.flags & CURSOR_SHOWING) == 0 || !GetIconInfo(info.hCursor, &ii)) { return; }
	// (x, y) is the hotspot, the image starts that far up and left of it
	x -= (int)ii.xHotspot;
	y -= (int)ii.yHotspot;
	if (GetObject(ii.hbmMask, sizeof(bm), &bm) == sizeof(bm))
	{
		int cw = bm.bmWidth, ch = ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2);
		int x0 = x < 0 ? 0 : x, y0 = y < 0 ? 0 : y;
		int x1 = x + cw > SCREEN_WIDTH ? SCREEN_WIDTH : x + cw;
		int y1 = y + ch > SCREEN_HEIGHT ? SCREEN_HEIGHT : y + ch;
		size_t need = (size_t)(x1 > x0 ? x1 - x0 : 0) * (y1 > y0 ? y1 - y0 : 0) * 4;

		if (need > 0 && dxgi_cursor_dib(cw, ch) == 0)
		{
			if (need > cursorSaveSize)
			{
				unsigned char *grown = (unsigned char *)realloc(cursorSave, need);
				if (grown != NULL) { cursorSave = grown; cursorSaveSize = need; }
			}
			if (need <= cursorSaveSize)
			{
				cursorSaveX = x0;
				cursorSaveY = y0;
				cursorSaveW = x1 - x0;
				cursorSaveH = y1 - y0;
				for (int r = y0; r < y1; r++)
				{
					unsigned char *row = capture_row(r, bufW, bufH) + (size_t)x0 * 4;
					memcpy(cursorSave + (size_t)(r - y0) * cursorSaveW * 4, row, (size_t)cursorSaveW * 4);
					memcpy(cursorBits + ((size_t)(r - y) * cw + (x0 - x)) * 4, row, (size_t)cursorSaveW * 4);
				}
				DrawIconEx(hCursorDC, 0, 0, info.hCursor, cw, ch, 0, NULL, DI_NORMAL);
				GdiFlush();
				for (int r = y0; r < y1; r++)
				{
					memcpy(capture_row(r, bufW, bufH) + (size_t)x0 * 4, cursorBits + ((size_t)(r - y) * cw + (x0 - x)) * 4, (size_t)cursorSaveW * 4);
				}
			}
		}
	}
	// GetIconInfo returns copies of the cursor bitmaps that we own
	if (ii.hbmMask != NULL) { DeleteObject(ii.hbmMask); }
	if (ii.hbmColor != NULL) { DeleteObject(ii.hbmColor); }
}

static void dxgi_cursor_free(void)
{
	if (hCursorDC != NULL)
	{
		if (hCursorBitmap != NULL) { SelectObject(hCursorDC, hCursorOldBitmap); }
		DeleteDC(hCursorDC);
		hCursorDC = NULL;
	}
	if (hCursorBitmap != NULL) { DeleteObject(hCursorBitmap); hCursorBitmap = NULL; }
	cursorBits = NULL;
	cursorDibW = cursorDibH = 0;
	free(cursorSave);
	cursorSave = NULL;
	cursorSaveSize = 0;
	cursorSaveW = cursorSaveH = 0;
}

// This function captures the entire desktop buffer to scan.
int get_desktop_buffer(void **buffer, long long *bufferSize, long* mouseMove)
{
	BITMAPINFO bmpInfo;
	int w = adjust_screen_size(SCALED_WIDTH);
	int h = adjust_screen_size(SCALED_HEIGHT);

	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;

	// Scaled frames stay on GDI. DXGI frames carry no cursor, so dxgi_cursor_draw() adds it when it has to be drawn in.
	if (SCALING_FACTOR == 1024 && !dxgi_capture_unsupported())
	{
		long long size = (long long)w * h * 4;
		if (captureBufferSize != size)
		{
			free(captureBuffer);
			captureHoldsDxgiFrame = 0;
			cursorSaveW = cursorSaveH = 0;
			if ((captureBuffer = calloc(1, (size_t)size)) == NULL) { captureBufferSize = 0; return 1; }
			captureBufferSize = size;
		}
		dxgi_cursor_restore(w, h);
		if (dxgi_capture_frame(SCREEN_X, SCREEN_Y, SCREEN_WIDTH, SCREEN_HEIGHT, (unsigned char *)captureBuffer, w, h, captureHoldsDxgiFrame) == 0)
		{
			captureHoldsDxgiFrame = 1;
			if (mouseMove[0] != 0) { dxgi_cursor_draw(mouseMove[1], mouseMove[2], w, h); }
			PIXEL_SIZE = 4;
			*buffer = captureBuffer;
			*bufferSize = captureBufferSize;
			return 0;
		}
	}
	captureHoldsDxgiFrame = 0;
	cursorSaveW = cursorSaveH = 0;

	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	if ((hDesktopDC = GetDC(NULL)) == NULL) { KVMDEBUG("GetDC(NULL) returned NULL", 0); return 1; } // We need to do this incase the current desktop changes.

	// Recreated only when the size changes, it used to be a new bitmap every frame
	if (hCapturedBitmap == NULL || capturedWidth != w || capturedHeight != h)
	{
		if (hCapturedBitmap) DeleteObject(hCapturedBitmap);
		if ((hCapturedBitmap = CreateCompatibleBitmap(hDesktopDC, w, h)) == NULL)
		{
			KVMDEBUG("CreateCompatibleBitmap() returned NULL", 0);
			capturedWidth = capturedHeight = 0;
			return 1;
		}
		capturedWidth = w;
		capturedHeight = h;
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
			BITMAP bm;
			ICONINFO ii = { 0 };
			info.cbSize = sizeof(info);
			GetCursorInfo(&info);
			GetIconInfo(info.hCursor, &ii);
			if (GetObject(ii.hbmMask, sizeof(bm), &bm) == sizeof(bm))
			{
				HDC hdcScreen = GetDC(NULL);
				if (hdcScreen != NULL)
				{
					HDC hdcMem = CreateCompatibleDC(hdcScreen);
					HBITMAP hbmCanvas = CreateCompatibleBitmap(hdcScreen, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2));
					if(hdcMem!=NULL && hbmCanvas != NULL)
					{
						HGDIOBJ hbmold = SelectObject(hdcMem, hbmCanvas);

						DrawIconEx(hdcMem, 0, 0, info.hCursor, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), 0, NULL, DI_NORMAL);
						BitBlt(hCaptureDC, mouseMove[1], mouseMove[2], bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), hdcMem, 0, 0, SRCINVERT);

						SelectObject(hdcMem, hbmold);
					}
					if (hbmCanvas != NULL) { DeleteObject(hbmCanvas); }
					if (hdcMem != NULL) { DeleteDC(hdcMem); }
					if (hdcScreen != NULL) { ReleaseDC(NULL, hdcScreen); }
				}
			}
			// GetIconInfo returns copies of the cursor bitmaps that we own
			if (ii.hbmMask != NULL) { DeleteObject(ii.hbmMask); }
			if (ii.hbmColor != NULL) { DeleteObject(ii.hbmColor); }
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

	if (bmpInfo.bmiHeader.biSizeImage <= 0)
	{
		bmpInfo.bmiHeader.biSizeImage = bmpInfo.bmiHeader.biWidth * abs(bmpInfo.bmiHeader.biHeight) * (bmpInfo.bmiHeader.biBitCount + 7) / 8;
	}

	PIXEL_SIZE = bmpInfo.bmiHeader.biBitCount / 8;

	// Kept across frames, it used to be a malloc and free per frame
	if (captureBufferSize != (long long)bmpInfo.bmiHeader.biSizeImage)
	{
		free(captureBuffer);
		if ((captureBuffer = malloc((size_t)bmpInfo.bmiHeader.biSizeImage)) == NULL) { KVMDEBUG("malloc() failed", 0); captureBufferSize = 0; return 1; }
		captureBufferSize = bmpInfo.bmiHeader.biSizeImage;
	}

	bmpInfo.bmiHeader.biCompression = BI_RGB;
	if (GetDIBits(hDesktopDC, hCapturedBitmap, 0, bmpInfo.bmiHeader.biHeight, captureBuffer, &bmpInfo, DIB_RGB_COLORS) == 0) { KVMDEBUG("GetDIBits() failed", 0); return(1); }

	*buffer = captureBuffer;
	*bufferSize = captureBufferSize;
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
	COMPRESSION_RATIO = 100;
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
	GetEncoderClsid(L"image/jpeg", &encoderClsid);
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
	GdiplusShutdown(gdiplusToken);
	DeleteDC(hCaptureDC);
	DeleteObject(hCapturedBitmap);
	hCapturedBitmap = NULL;
	capturedWidth = capturedHeight = 0;
	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	hDesktopDC = NULL;
	dxgi_capture_release();
	dxgi_cursor_free();
	free(captureBuffer);
	captureBuffer = NULL;
	captureBufferSize = 0;
	captureHoldsDxgiFrame = 0;
}

void set_tile_compression(int type, int level)
{
	encCompression = level;
	if (encCompression < 1) { encCompression = 1; } // Guard against bad values.
	if (encCompression > 90) { encCompression = 90; }
	if (tilebuffer == NULL) { KVMDEBUG("set_tile_compression(), tilebuffer == NULL.", 0); return; }
	KVMDEBUG("set_tile_compression() type", type);
	KVMDEBUG("set_tile_compression() level", level);

	switch (type)
	{
		case 1: { GetEncoderClsid(L"image/jpeg", &encoderClsid); break; }
		case 2: { GetEncoderClsid(L"image/png", &encoderClsid); break; }
		case 3: { GetEncoderClsid(L"image/tiff", &encoderClsid); break; }
	}
}

}

#endif
