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
#include <limits.h>
#if defined(_M_IX86) || defined(_M_X64)
#include <intrin.h>
#include <nmmintrin.h>
#endif
#ifdef MESH_WINDOWS_TURBOJPEG
#include "windows_jpeg_encoder.h"
static WinJpegEncoder fastJpeg;
static bool useFastJpeg = true;
#endif
#include "tile.h"
#include <gdiplus.h>
#include "windows_desktop_duplication.h"
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
static HGDIOBJ hCaptureOriginalBitmap;
static void* capturePixels;
static int captureWidth, captureHeight, captureSourceWidth, captureSourceHeight;
static int captureSourceX, captureSourceY, captureScale;
static WCHAR captureDesktop[256];
static WinDesktopDuplication desktopDuplication;
static bool useCaptureDamage, lastWasDuplication;
static LONG captureRevision, processedCaptureRevision = -1;
struct CaptureCursorKey { HCURSOR cursor; DWORD flags; long rendered, x, y; };
static CaptureCursorKey lastCaptureCursor;
static bool captureCursorValid;

extern "C" void invalidate_desktop_capture(void) { InterlockedIncrement(&captureRevision); }

// Never reuse a snapshot when the worker's desktop differs from the current input desktop.
static bool capture_desktop_identity(WCHAR* name, DWORD capacity)
{
    DWORD needed = 0;
    if (!GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, name, capacity, &needed)) return false;
    HDESK input = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!input) return false;
    WCHAR inputName[256];
    BOOL read = GetUserObjectInformationW(input, UOI_NAME, inputName, sizeof(inputName), &needed);
    CloseDesktop(input);
    return read && wcscmp(name, inputName) == 0;
}

static bool capture_desktop_still_current(const WCHAR* expected)
{
    WCHAR current[256];
    return capture_desktop_identity(current, sizeof(current)) && wcscmp(expected, current) == 0;
}

static bool capture_tile_dirty(int row, int col)
{
    return tileInfo[row][col].pending || !useCaptureDamage || desktopDuplication.damage.rows != TILE_HEIGHT_COUNT ||
        desktopDuplication.damage.columns != TILE_WIDTH_COUNT || desktopDuplication.damage.Dirty(row, col);
}


// This worker owns the DIB exclusively; no compositor/shared memory is encoded.
static void reset_capture_buffer()
{
#ifdef MESH_WINDOWS_TURBOJPEG
    fastJpeg.Reset();
#endif
    if (hCaptureDC && hCaptureOriginalBitmap) SelectObject(hCaptureDC, hCaptureOriginalBitmap);
    if (hCapturedBitmap) DeleteObject(hCapturedBitmap);
    if (hCaptureDC) DeleteDC(hCaptureDC);
    hCapturedBitmap = NULL;
    hCaptureDC = NULL;
    hCaptureOriginalBitmap = NULL;
    capturePixels = NULL;
    captureWidth = captureHeight = 0;
    captureDesktop[0] = 0;
    desktopDuplication.Reset();
    useCaptureDamage = lastWasDuplication = captureCursorValid = false;
    processedCaptureRevision = -1;
}

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

// These checksums detect changed image tiles; they are never authentication hashes.
// CRC32C processes two pixels per instruction on x64. Keep FNV on other CPUs.
static bool checksum_crc_available()
{
#if defined(_M_X64)
    int cpu[4]; __cpuid(cpu, 1); return (cpu[2] & (1 << 20)) != 0;
#else
    return false;
#endif
}
static bool useChecksumCrc = checksum_crc_available();
#if defined(_M_X64)
static __forceinline unsigned int checksum_pair(unsigned int crc, const unsigned int* pixels)
{
    unsigned long long pair; memcpy(&pair, pixels, sizeof(pair));
    return (unsigned int)_mm_crc32_u64(crc, pair);
}
#endif

int tile_crc(int x, int y, void *desktop, int tilewidth, int tileheight) 
{
	int crc = 0;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		#if defined(_M_X64)
        if (useChecksumCrc && PIXEL_SIZE == 4)
        {
            const unsigned int* pixels = (const unsigned int*)desktop + (size_t)height * adjust_screen_size(SCALED_WIDTH) + x;
            int i = 0;
            for (; i + 1 < tilewidth; i += 2) crc = checksum_pair(crc, pixels + i);
            if (i < tilewidth) crc = _mm_crc32_u32(crc, pixels[i]);
        }
        else
#endif
        crc = util_crc(((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE) ), (size_t)(tilewidth * PIXEL_SIZE), crc);
	}
	return crc;
}

extern "C" void prepare_tile_checksums(void* desktop)
{
    if (PIXEL_SIZE != 4) return; // Scalar tile_crc remains the fallback.
    const int stride = adjust_screen_size(SCALED_WIDTH);
    const int paddedHeight = adjust_screen_size(SCALED_HEIGHT);
    for (int row = 0; row < TILE_HEIGHT_COUNT; ++row)
    {
        int col = 0;
        for (; col + 3 < TILE_WIDTH_COUNT; col += 4)
        {
            bool dirty[4] = { capture_tile_dirty(row, col), capture_tile_dirty(row, col + 1),
                capture_tile_dirty(row, col + 2), capture_tile_dirty(row, col + 3) };
            if (!(dirty[0] && dirty[1] && dirty[2] && dirty[3]))
            {
                // Keep the four-lane loop for dense damage. Sparse groups must not
                // hash their unchanged neighbors (or replace their retained CRCs).
                for (int i = 0; i < 4; ++i)
                {
                    tileInfo_t* tile = &tileInfo[row][col + i];
                    if (!dirty[i]) { tile->flags = (char)TILE_DONT_SEND; continue; }
                    int crc = tile_crc((col + i) * TILE_WIDTH, row * TILE_HEIGHT, desktop, TILE_WIDTH, TILE_HEIGHT);
                    tile->pending |= tile->crc != crc;
                    tile->flags = (char)(tile->pending ? TILE_MARKED_NOT_SENT : TILE_DONT_SEND);
                    tile->crc = crc;
                }
                continue;
            }
            unsigned int a = 0, b = 0, c = 0, d = 0;
            for (int y = paddedHeight - (row + 1) * TILE_HEIGHT; y < paddedHeight - row * TILE_HEIGHT; ++y)
            {
                const unsigned int* pixels = (const unsigned int*)desktop + (size_t)y * stride + col * TILE_WIDTH;
                #if defined(_M_X64)
                if (useChecksumCrc)
                {
                    int x = 0;
                    for (; x + 1 < TILE_WIDTH; x += 2)
                    {
                        a = checksum_pair(a, pixels+x);
                        b = checksum_pair(b, pixels+x+TILE_WIDTH);
                        c = checksum_pair(c, pixels+x+2*TILE_WIDTH);
                        d = checksum_pair(d, pixels+x+3*TILE_WIDTH);
                    }
                    if (x < TILE_WIDTH)
                    {
                        a = _mm_crc32_u32(a,pixels[x]); b = _mm_crc32_u32(b,pixels[x+TILE_WIDTH]);
                        c = _mm_crc32_u32(c,pixels[x+2*TILE_WIDTH]); d = _mm_crc32_u32(d,pixels[x+3*TILE_WIDTH]);
                    }
                    continue;
                }
#endif
                for (int x = 0; x < TILE_WIDTH; ++x)
                {
                    a = (a * 0x01000193u) ^ pixels[x];
                    b = (b * 0x01000193u) ^ pixels[x + TILE_WIDTH];
                    c = (c * 0x01000193u) ^ pixels[x + 2 * TILE_WIDTH];
                    d = (d * 0x01000193u) ^ pixels[x + 3 * TILE_WIDTH];
                }
            }
            unsigned int values[4] = { a, b, c, d };

            for (int i = 0; i < 4; ++i)
            {
                tileInfo_t* tile = &tileInfo[row][col + i];
                tile->pending |= tile->crc != (int)values[i];
                tile->flags = (char)(tile->pending ? TILE_MARKED_NOT_SENT : TILE_DONT_SEND);
                tile->crc = (int)values[i];
            }
        }
        for (; col < TILE_WIDTH_COUNT; ++col)
        {
            tileInfo_t* tile = &tileInfo[row][col];
            if (!capture_tile_dirty(row, col)) { tile->flags = (char)TILE_DONT_SEND; continue; }
            int crc = tile_crc(col * TILE_WIDTH, row * TILE_HEIGHT, desktop, TILE_WIDTH, TILE_HEIGHT);
            tile->pending |= tile->crc != crc;
            tile->flags = (char)(tile->pending ? TILE_MARKED_NOT_SENT : TILE_DONT_SEND);
            tile->crc = crc;
        }
    }
}

// Returns zero with an owned packet on success, negative on encoding failure.
int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void* desktop, void ** buffer, long long *bufferSize) 
{
	LARGE_INTEGER Offset;
	*buffer = NULL;
	*bufferSize = 0;

	KVMDEBUG("calc_opt_compr_send()", 0);

    if (PIXEL_SIZE != 4 || captureWidth <= 0 || captureHeight <= 0 ||
        captureWidth > INT_MAX / 4 || (size_t)captureWidth * 4 > UINT_MAX / (size_t)captureHeight) return -1;

    // Save is synchronous on the capture worker. Encode a bounded view of its
    // private DIB directly; no shared GPU surface or extra tile allocation is used.
    if (!desktop || SCALED_WIDTH <= 0 || SCALED_HEIGHT <= 0 ||
        SCALED_WIDTH > INT_MAX - 31 || SCALED_HEIGHT > INT_MAX - 31) return -1;
    const int desktopWidth = adjust_screen_size(SCALED_WIDTH);
    const int desktopHeight = adjust_screen_size(SCALED_HEIGHT);
    if (desktopWidth > INT_MAX / PIXEL_SIZE || x < 0 || y < 0 ||
        x > desktopWidth || y > desktopHeight || captureWidth > desktopWidth - x ||
        captureHeight > desktopHeight - y ||
        (size_t)desktopWidth * PIXEL_SIZE > SIZE_MAX / (size_t)desktopHeight) return -1;
    const int stride = desktopWidth * PIXEL_SIZE;
    char* Tile = NULL;
    DWORD jpegSize = 0;
#ifdef MESH_WINDOWS_TURBOJPEG
    void* encoded = NULL;
    unsigned long encodedSize = 0;
    if (useFastJpeg && fastJpeg.Encode((const unsigned char*)desktop +
        (size_t)(desktopHeight-y-1)*stride + (size_t)x*PIXEL_SIZE,
        captureWidth, captureHeight, stride, (int)encCompression, &encoded, &encodedSize))
    {
        Tile = (char*)encoded;
        jpegSize = encodedSize;
        if (jpegSize <= 65500) memmove(Tile+8, Tile+16, jpegSize);
    }
    else
#endif
    {
    Gdiplus::Bitmap DIBImage(captureWidth, captureHeight, -stride,
        PixelFormat32bppRGB, (BYTE*)desktop + (size_t)(desktopHeight - y - 1) * stride + (size_t)x * PIXEL_SIZE);
    if (DIBImage.GetLastStatus() != Ok) return -1;

	// Create stream to receive the encoded JPEG.
	IStream* jpegStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&jpegStream) != S_OK)
	{
		KVMDEBUG("CreateStreamOnHGlobal() failed", 0);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return -1;
	}

	// Save image stream into the stream object.
	Status SaveStatus = DIBImage.Save(jpegStream, &encoderClsid, &encParam);
	if (SaveStatus != S_OK)
	{
		KVMDEBUG("DIBImage.Save() failed", 0);
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return -1;
	}

	// Get the size of the output stream
	ULARGE_INTEGER Size;
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_END, &Size) != S_OK)
	{
		KVMDEBUG("jpegStream->Save() failed", 0);
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return -1;
	}       

	// Move the image stream's pointer to its beginning.
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		KVMDEBUG("jpegStream->Seek() failed", 0);
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return -1;
	}        

	// Check if the tile is too large to send
	if (Size.QuadPart == 0 || Size.QuadPart > INT_MAX - 16u) { jpegStream->Release(); return -1; }
	jpegSize = (DWORD)Size.QuadPart;

	//if (jpegSize > 65500)
	//{
	//	KVMDEBUG("jpegSize > 65500", jpegSize);
	//	//	*bufferSize = 0;
	//	// ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
	//	return jpegSize;
	//}

	// Save the image stream in memory.
	Tile = (char*)malloc(jpegSize > 65500 ? (jpegSize + 16):(jpegSize + 8));
	if (Tile == NULL) { jpegStream->Release(); return -1; }
	ULONG bytesRead = 0;
	if (jpegStream->Read(Tile + (jpegSize > 65500 ? 16 : 8), jpegSize, &bytesRead) != S_OK || bytesRead != jpegSize)
	{
		KVMDEBUG("jpegStream->Read() failed", 0);
		free(Tile);
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return -1;
	}

	// Cleanup
	jpegStream->Release();

    }

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
		if ((CRC = tile_crc(x, y, desktop, TILE_WIDTH, TILE_HEIGHT)) == tileInfo[row][col].crc && !tileInfo[row][col].pending) return 0;
		tileInfo[row][col].crc = CRC; // Update the tile CRC in the global data structure.
	}

	tileInfo[row][col].flags = (char)TILE_MARKED_NOT_SENT;
	tileInfo[row][col].pending = 1;


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

		if (CRC != tileInfo[row][rightcol].crc || tileInfo[row][rightcol].pending || tileInfo[row][rightcol].flags == (char)TILE_MARKED_NOT_SENT) // If the tile has changed, increment the capturewidth.
		{
			tileInfo[row][rightcol].pending = 1;
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

			if (CRC != tileInfo[botrow][rcol].crc || tileInfo[botrow][rcol].pending || tileInfo[botrow][rcol].flags == (char)TILE_MARKED_NOT_SENT)
			{
				tileInfo[botrow][rcol].pending = 1;
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
		if (retval < 0 || (retval == 0 && (*buffer == NULL || *bufferSize == 0)))
		{
			// Force a fresh private snapshot even when DXGI has no new damage.
			// Pending tile delivery survives checksum preparation on that frame.
			invalidate_desktop_capture();
			return -1;
		}
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
				tileInfo[r][c].pending = 0;
			}
		}
	}

	return retval;
}

// This function captures the entire desktop buffer to scan.
int get_desktop_buffer(void **buffer, long long *bufferSize, long* mouseMove)
{
	BITMAPINFO bmpInfo;

	*buffer = NULL; // If anything fails, this will be the indication.
	*bufferSize = 0;

	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	if ((hDesktopDC = GetDC(NULL)) == NULL) { reset_capture_buffer(); KVMDEBUG("GetDC(NULL) returned NULL", 0); return 1; } // We need to do this incase the current desktop changes.
    WCHAR desktopName[256];
    if (!capture_desktop_identity(desktopName, sizeof(desktopName))) { reset_capture_buffer(); return 1; }
    if (SCALED_WIDTH <= 0 || SCALED_HEIGHT <= 0 || SCALED_WIDTH > INT_MAX - TILE_WIDTH || SCALED_HEIGHT > INT_MAX - TILE_HEIGHT)
    { reset_capture_buffer(); return WIN_CAPTURE_FAILED; }
    const int width = adjust_screen_size(SCALED_WIDTH), height = adjust_screen_size(SCALED_HEIGHT);
    if (width <= 0 || height <= 0 || width > INT_MAX / 4 || (size_t)width * 4 > UINT_MAX / (size_t)height)
    { reset_capture_buffer(); return 1; }
    if (!capturePixels || width != captureWidth || height != captureHeight ||
        SCREEN_WIDTH != captureSourceWidth || SCREEN_HEIGHT != captureSourceHeight ||
        SCREEN_X != captureSourceX || SCREEN_Y != captureSourceY || SCALING_FACTOR != captureScale ||
        wcscmp(desktopName, captureDesktop) != 0)
    {
        reset_capture_buffer();
        PIXEL_SIZE = 4;
        bmpInfo = get_bmp_info(width, height);
        hCaptureDC = CreateCompatibleDC(hDesktopDC);
        if (!hCaptureDC) return 1;
        hCapturedBitmap = CreateDIBSection(hDesktopDC, &bmpInfo, DIB_RGB_COLORS, &capturePixels, NULL, 0);
        if (!hCapturedBitmap || !capturePixels) { reset_capture_buffer(); return 1; }
        hCaptureOriginalBitmap = SelectObject(hCaptureDC, hCapturedBitmap);
        if (!hCaptureOriginalBitmap || hCaptureOriginalBitmap == HGDI_ERROR)
        { hCaptureOriginalBitmap = NULL; reset_capture_buffer(); return 1; }
        ZeroMemory(capturePixels, bmpInfo.bmiHeader.biSizeImage);
        captureWidth = width;
        captureHeight = height;
        captureSourceWidth = SCREEN_WIDTH;
        captureSourceHeight = SCREEN_HEIGHT;
        captureSourceX = SCREEN_X;
        captureSourceY = SCREEN_Y;
        captureScale = SCALING_FACTOR;
        wcscpy_s(captureDesktop, _countof(captureDesktop), desktopName);
    }
    LONG revision = InterlockedCompareExchange(&captureRevision, 0, 0);
    CURSORINFO cursorInfo = {}; cursorInfo.cbSize = sizeof(cursorInfo);
    bool haveCursor = GetCursorInfo(&cursorInfo) != FALSE;
    CaptureCursorKey cursorKey = {};
    if (mouseMove[0])
    {
        cursorKey.cursor = cursorInfo.hCursor; cursorKey.flags = cursorInfo.flags;
        cursorKey.rendered = 1; cursorKey.x = mouseMove[1]; cursorKey.y = mouseMove[2];
    }
    bool cursorChanged = !captureCursorValid || !haveCursor ||
        cursorKey.cursor != lastCaptureCursor.cursor || cursorKey.flags != lastCaptureCursor.flags ||
        cursorKey.rendered != lastCaptureCursor.rendered || cursorKey.x != lastCaptureCursor.x || cursorKey.y != lastCaptureCursor.y;
    bool fromDuplication = false, drawDuplicationCursor = false;
    useCaptureDamage = false;
    // Exact unrotated outputs at native scale use DXGI. Other layouts retain GDI.
    if (SCALING_FACTOR == 1024 && wcscmp(desktopName, L"Default") == 0 && haveCursor &&
        (long long)SCREEN_X + SCREEN_WIDTH <= LONG_MAX && (long long)SCREEN_Y + SCREEN_HEIGHT <= LONG_MAX)
    {
        RECT selected = { SCREEN_X, SCREEN_Y, SCREEN_X + SCREEN_WIDTH, SCREEN_Y + SCREEN_HEIGHT };
        if (!GdiFlush()) { reset_capture_buffer(); return WIN_CAPTURE_FAILED; }
        WinDesktopDuplication::Result result = desktopDuplication.Capture((BYTE*)capturePixels,
            (size_t)width * height * 4, width * 4, height, selected, TILE_WIDTH, TILE_HEIGHT,
            revision != processedCaptureRevision || !lastWasDuplication, cursorChanged, mouseMove[0] != 0, drawDuplicationCursor);
        if (result == WinDesktopDuplication::Unchanged)
        {
            if (!capture_desktop_still_current(desktopName)) { reset_capture_buffer(); return WIN_CAPTURE_FAILED; }
            return WIN_CAPTURE_UNCHANGED; // Health, session checks and input still run in the main loop.
        }
        fromDuplication = result == WinDesktopDuplication::Frame;
        useCaptureDamage = fromDuplication;
    }
    else desktopDuplication.Reset(); // Includes secure desktops: discard all DXGI images first.
    if (!fromDuplication)
    {
	if (SCALING_FACTOR == 1024)
	{
		if (BitBlt(hCaptureDC, 0, 0, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, SRCCOPY) == FALSE)
		{
			KVMDEBUG("BitBlt() returned FALSE", 0);
			reset_capture_buffer(); return 1; // If the copy fails, error out.
		}

	}
	else
	{
		if (SetStretchBltMode(hCaptureDC, HALFTONE) == 0) { reset_capture_buffer(); KVMDEBUG("SetStretchBltMode() failed", 0); return(1); }
		if (StretchBlt(hCaptureDC, 0, 0, adjust_screen_size(SCALED_WIDTH), adjust_screen_size(SCALED_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), SRCCOPY) == FALSE)
		{
			KVMDEBUG("StretchBlt() returned FALSE", 0);
			reset_capture_buffer(); return 1; // If the copy fails, error out.
		}
	}

    }
    bool cursorRenderValid = true;
		if ((fromDuplication && drawDuplicationCursor) || (!fromDuplication && SCALING_FACTOR == 1024 && mouseMove[0] != 0))
		{
            cursorRenderValid = false;
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

						BOOL drew = DrawIconEx(hdcMem, 0, 0, info.hCursor, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), 0, NULL, DI_NORMAL);
						if (drew && BitBlt(hCaptureDC, mouseMove[1], mouseMove[2], bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), hdcMem, 0, 0, SRCINVERT)) cursorRenderValid = true;

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
    lastWasDuplication = fromDuplication;
    lastCaptureCursor = cursorKey; captureCursorValid = haveCursor && cursorRenderValid;

    // Flush GDI writes before reading DIB memory from the CPU.
    if (!GdiFlush()) { reset_capture_buffer(); return 1; }
    if (!capture_desktop_still_current(desktopName)) { reset_capture_buffer(); return WIN_CAPTURE_FAILED; }
    processedCaptureRevision = revision;
    PIXEL_SIZE = 4;
    *buffer = capturePixels; // Borrowed until next capture or teardown; never free().
    *bufferSize = (long long)captureWidth * captureHeight * 4;

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
	bmpInfo.bmiHeader.biSizeImage = (DWORD)((size_t)height * width * PIXEL_SIZE);
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
    reset_capture_buffer();
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

	#ifdef MESH_WINDOWS_TURBOJPEG
    // Invalid/unknown types retain the existing selected encoder.
    if (type >= 1 && type <= 3) useFastJpeg = type == 1;
#endif
    switch (type)
	{
		case 1: { GetEncoderClsid(L"image/jpeg", &encoderClsid); break; }
		case 2: { GetEncoderClsid(L"image/png", &encoderClsid); break; }
		case 3: { GetEncoderClsid(L"image/tiff", &encoderClsid); break; }
	}
}

}

#endif
