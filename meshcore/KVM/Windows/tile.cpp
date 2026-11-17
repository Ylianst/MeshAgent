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

// This function always returns 0 since jumbo support, and *buffer != NULL if everything was good
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

// The tiles as they were when last found changed, in the layout of the desktop buffer
static unsigned char *refFrame = NULL;
static long long refFrameSize = 0;
static int refPixelSize = 0;

// Reallocated when the frame size or pixel format changes, and then every tile counts as changed
static unsigned char *tile_reference(void)
{
	long long size = (long long)adjust_screen_size(SCALED_WIDTH) * adjust_screen_size(SCALED_HEIGHT) * PIXEL_SIZE;
	if (refFrame != NULL && refFrameSize == size && refPixelSize == PIXEL_SIZE) { return refFrame; }
	free(refFrame);
	refFrameSize = 0;
	if ((refFrame = (unsigned char *)malloc((size_t)size)) == NULL) { return NULL; }
	refFrameSize = size;
	refPixelSize = PIXEL_SIZE;
	tile_mark_all_stale();
	return refFrame;
}

// Returns 1 and updates the reference when the tile is stale or differs from it, 0 when it is unchanged.
// Exact, a hash could miss a change. Rows before the first difference are equal already, so only the rest is copied.
static int tile_changed(int x, int y, void *desktop, int row, int col)
{
	size_t stride = (size_t)adjust_screen_size(SCALED_WIDTH) * PIXEL_SIZE;
	size_t len = (size_t)TILE_WIDTH * PIXEL_SIZE;
	size_t offset = (size_t)(adjust_screen_size(SCALED_HEIGHT) - y - TILE_HEIGHT) * stride + (size_t)x * PIXEL_SIZE;
	unsigned char *cur = (unsigned char *)desktop + offset;
	unsigned char *ref = tile_reference();
	int r = 0;

	if (ref == NULL) { return 1; } // Without a reference every tile counts as changed, which costs data but loses nothing
	ref += offset;
	if (tileInfo[row][col].stale == 0)
	{
		while (r < TILE_HEIGHT && memcmp(cur + r * stride, ref + r * stride, len) == 0) { r++; }
		if (r == TILE_HEIGHT) { return 0; }
	}
	for (; r < TILE_HEIGHT; r++) { memcpy(ref + r * stride, cur + r * stride, len); }
	tileInfo[row][col].stale = 0;
	return 1;
}

// A tile is pending when it changed in this pass and has not been sent yet
static int tile_pending(int x, int y, void *desktop, int row, int col)
{
	if (tileInfo[row][col].flags == TILE_TODO) { return tile_changed(x, y, desktop, row, col); }
	return tileInfo[row][col].flags == TILE_CHANGED;
}

extern "C"
{

// Makes every tile count as changed on its next compare, so the next pass sends the whole screen
void tile_mark_all_stale(void)
{
	for (int r = 0; r < TILE_HEIGHT_COUNT; r++) { for (int c = 0; c < TILE_WIDTH_COUNT; c++) { tileInfo[r][c].stale = 1; } }
}

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesed to form a larger jpeg before returning.
int get_tile_at(int x, int y, void** buffer, long long *bufferSize, void *desktop, int row, int col)
{
	int rightcol = col;		// Used in coalescing. Indicates the right-most column to be coalesced.
	int botrow = row;		// Used in coalescing. Indicates the bottom-most row to be coalesced.
	int r_x = x;
	int r_y = y;
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;

	*buffer = NULL;			// If anything fails, this will be the indication.
	*bufferSize = 0;

	// Nothing to send when the tile is unchanged
	if (tileInfo[row][col].flags == TILE_TODO && !tile_changed(x, y, desktop, row, col)) return 0;

	tileInfo[row][col].flags = TILE_CHANGED;


	// COALESCING SECTION

	// First got to the right most changed tile and record it
	while (rightcol + 1 < TILE_WIDTH_COUNT)
	{
		rightcol++;
		r_x = rightcol * TILE_WIDTH;
		
		if (tile_pending(r_x, y, desktop, row, rightcol)) // If the tile has changed, increment the capturewidth
		{
			tileInfo[row][rightcol].flags = TILE_CHANGED;
			captureWidth += TILE_WIDTH;
		} 
		else
		{
			tileInfo[row][rightcol].flags = TILE_DONE;
			--rightcol;
			break;
		}
	}

	// Now go to the bottom tiles, check if they have changed and record them
	while ((botrow + 1 < TILE_HEIGHT_COUNT))
	{
		botrow++;
		r_y = botrow * TILE_HEIGHT;
		int fail = 0;
		r_x = x;

		for (int rcol = col; rcol <= rightcol; rcol++) {

			if (tile_pending(r_x, r_y, desktop, botrow, rcol))
			{
				tileInfo[botrow][rcol].flags = TILE_CHANGED;
				r_x += TILE_WIDTH;
			}
			else
			{
				fail = 1;
				for (int i = col; i < rcol; i++)
				{
					tileInfo[botrow][i].flags = TILE_CHANGED;
				}
				tileInfo[botrow][rcol].flags = TILE_DONE;
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

	// One encode for the whole region, whatever its size
	calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, buffer, bufferSize);

	// After an encode the tiles of the region are done for this pass, after a failed one they are stale so the next pass tries them again
	for (int r = row; r <= botrow; r++) {
		for (int c = col; c <= rightcol; c++) {
			if (*buffer != NULL) { tileInfo[r][c].flags = TILE_DONE; } else { tileInfo[r][c].stale = 1; }
		}
	}

	return 0;
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
