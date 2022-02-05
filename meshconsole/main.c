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

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#endif

#include "meshcore/agentcore.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "microscript/ILibDuktape_ScriptContainer.h"
#include "microstack/ILibCrypto.h"
#include "microscript/ILibDuktape_Commit.h"

MeshAgentHostContainer *agentHost = NULL;
#ifdef _OPENBSD
#include <stdlib.h>
char __agentExecPath[1024] = { 0 };
#endif


#ifdef WIN32
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	{
		if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
		return TRUE;
	}
	default:
		return FALSE;
	}
}
#endif


#if defined(_POSIX)
void BreakSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl c interrupts
	if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
}
#endif
#include <d3d11.h>
#include <dxgi.h>
#include <dxgi1_2.h>

#if defined(_LINKVM) && defined(__APPLE__)
extern void* kvm_server_mainloop(void *parm);
extern void senddebug(int val);
ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	ignore_result(write(STDOUT_FILENO, (void*)buffer, bufferLen));
	return ILibTransport_DoneState_COMPLETE;
}
#endif

typedef int(*GdipLoadImageFromStream_func)(IStream* stream, void **image);
typedef int(*GdiplusStartup_func)(ULONG_PTR *token, void *input, void *output);
typedef int(*GdipSaveImageToStream_func)(void *image, IStream* stream, void* clsidEncoder, void* encoderParams);
typedef int(*GetImageEncodersSize_func)(UINT *numEncoders, UINT *size);
typedef int(*GetImageEncoders_func)(UINT numEncoders, UINT size, void *encoders);

GetImageEncoders_func _GetImageEncoders = NULL;
GetImageEncodersSize_func _GetImageEncodersSize = NULL;
GdipLoadImageFromStream_func _GdipLoadImageFromStream = NULL;
GdiplusStartup_func _GdiplusStartup = NULL;
GdipSaveImageToStream_func _GdipSaveImageToStream = NULL;

typedef HRESULT(*D3D11CreateDevice_func)(void *pAdapter, int DriverType, HMODULE Software, UINT Flags, int *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion, void **ppDevice, UINT *pFeatureLevel, void **context);
typedef HRESULT(*GetParent_func)(void *self, void* iid, void **ppParent);
typedef ULONG(*Release_func)(void *self);
typedef UINT(*D3D11CalcSubresource_func)(UINT MipSlice, UINT ArraySlice, UINT MipLevels);

UINT defaultCompressionLevel = 50;
DWORD tilebuffersize = 0;
LPVOID tilebuffer = NULL;
int SCALED_WIDTH, SCREEN_WIDTH;
int SCALED_HEIGHT, SCREEN_HEIGHT;

extern 	void __jpeghelp2(void *x);
// Used to obtain the GUID for the image encoder.
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	unsigned int num = 0, size = 0;
	char* pImageCodecInfo = NULL;

	_GetImageEncodersSize(&num, &size);
	if (size == 0) return -1;

	if ((pImageCodecInfo = (char*)(malloc(size))) == NULL) return -1;
	_GetImageEncoders(num, size, (void*)pImageCodecInfo);

	for (unsigned int j = 0; j < num; ++j)
	{
		WCHAR *tmp = ((WCHAR**)(pImageCodecInfo + (104 * j) + 64))[0];
		if (wcsncmp(tmp, format, size) == 0)
		{
			*pClsid = ((CLSID*)(pImageCodecInfo + (104 * j)))[0];
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
	int extra = pixles % 32; // Assuming tile width and height will remain the same.
	if (extra != 0) return pixles + 32 - extra;
	return pixles;
}

// Creates a BITMAPINFO object with required width and height
BITMAPINFO _get_bmp_info(int width, int height, int PIXEL_SIZE)
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
// Extracts the required tile buffer from the desktop buffer
int _get_tile_buffer(int x, int y, int PIXEL_SIZE, void **buffer, void *desktop, int tilewidth, int tileheight)
{
	void *target = *buffer;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		memcpy_s(target, tilebuffersize, (const void *)((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE)), (size_t)(tilewidth * PIXEL_SIZE));
		target = (void *)((unsigned char *)target + tilewidth * PIXEL_SIZE);
	}
	return 0;
}

int _calc_opt_compr_send(int x, int y, int PIXEL_SIZE, int captureWidth, int captureHeight, void* desktop, void ** buffer, int64_t *bufferSize)
{
	BITMAPINFO bmpInfo;
	LARGE_INTEGER Offset;
	BITMAPFILEHEADER bmpFileHeader;
	*buffer = NULL;
	*bufferSize = 0;

	// Get the bmpInfo structure
	bmpInfo = _get_bmp_info(captureWidth, captureHeight, PIXEL_SIZE);

	// Make sure a tile buffer is available. Most of the time, this is skipped.
	if (tilebuffersize != bmpInfo.bmiHeader.biSizeImage)
	{
		if (tilebuffer != NULL) free(tilebuffer);
		tilebuffersize = bmpInfo.bmiHeader.biSizeImage;
		if ((tilebuffer = malloc(tilebuffersize)) == NULL) return 0;
	}

	// Get the final coalesced tile
	_get_tile_buffer(x, y, PIXEL_SIZE, &tilebuffer, desktop, captureWidth, captureHeight);

	bmpFileHeader.bfReserved1 = 0;
	bmpFileHeader.bfReserved2 = 0;
	bmpFileHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpInfo.bmiHeader.biSizeImage;
	bmpFileHeader.bfType = 'MB';
	bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// Construct stream object.
	IStream* bmpStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&bmpStream) != S_OK)
	{
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Write entire contents of the source BMP into this stream.
	bmpStream->lpVtbl->Write(bmpStream, &bmpFileHeader, sizeof(BITMAPFILEHEADER), NULL);
	bmpStream->lpVtbl->Write(bmpStream, &bmpInfo, sizeof(BITMAPINFOHEADER), NULL);
	bmpStream->lpVtbl->Write(bmpStream, tilebuffer, bmpInfo.bmiHeader.biSizeImage, NULL);

	// Move the stream pointer to the beginning of the stream.
	Offset.QuadPart = 0;
	if (bmpStream->lpVtbl->Seek(bmpStream, Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		bmpStream->lpVtbl->Release(bmpStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}
	
	// Construct GDI+ Image object from the BMP stream.
	void *DIBImage;
	_GdipLoadImageFromStream(bmpStream, &DIBImage);

	// Create stream to receive the encoded JPEG.
	IStream* jpegStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&jpegStream) != S_OK)
	{
		//delete DIBImage;
		bmpStream->lpVtbl->Release(bmpStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	CLSID encoderClsid;
	GetEncoderClsid(L"image/jpeg", &encoderClsid);

	char encparms[40];
	((uint32_t*)encparms)[0] = 1;											// EncoderParameters::Count
	util_hexToBuf("B5E45B1D4AFA2D459CDD5DB35105E7EB", 32, encparms + 8);	// EncoderParameter::Guid
	((uint32_t*)(24 + encparms))[0] = 1;										// EncoderParameter::NumberOfValues
	((uint32_t*)(28 + encparms))[0] = 4;									// EncoderParameter::Type
	((void**)(32 + encparms))[0] = (void*)&defaultCompressionLevel;			// EncoderParameter::Value


	// Save image stream into the stream object.
	int SaveStatus = _GdipSaveImageToStream(DIBImage, jpegStream, &encoderClsid, (void*)encparms);
	if (SaveStatus != S_OK)
	{
		//delete DIBImage;
		bmpStream->lpVtbl->Release(bmpStream);
		jpegStream->lpVtbl->Release(jpegStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Get the size of the output stream
	ULARGE_INTEGER Size;
	Offset.QuadPart = 0;
	if (jpegStream->lpVtbl->Seek(jpegStream, Offset, STREAM_SEEK_END, &Size) != S_OK)
	{
		//delete DIBImage;
		bmpStream->lpVtbl->Release(bmpStream);
		jpegStream->lpVtbl->Release(jpegStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Move the image stream's pointer to its beginning.
	Offset.QuadPart = 0;
	if (jpegStream->lpVtbl->Seek(jpegStream, Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		//delete DIBImage;
		bmpStream->lpVtbl->Release(bmpStream);
		jpegStream->lpVtbl->Release(jpegStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Check if the tile is too large to send
	DWORD jpegSize = (DWORD)Size.QuadPart;

	// Save the image stream in memory.
	char* Tile = (char*)ILibMemory_Allocate(jpegSize > 65500 ? (jpegSize + 16) : (jpegSize + 8), 0, NULL, NULL);
	if (jpegStream->lpVtbl->Read(jpegStream, Tile + (jpegSize > 65500 ? 16 : 8), jpegSize, NULL) != S_OK)
	{
		//delete DIBImage;
		free(Tile);
		bmpStream->lpVtbl->Release(bmpStream);
		jpegStream->lpVtbl->Release(jpegStream);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Cleanup
	//delete DIBImage;
	bmpStream->lpVtbl->Release(bmpStream);
	jpegStream->lpVtbl->Release(jpegStream);

	*buffer = (unsigned char*)Tile;
	*bufferSize = jpegSize + (jpegSize > 65500 ? 16 : 8);

	//// Place the header
	//if (jpegSize > 65500)
	//{
	//	((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
	//	((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	//	((unsigned int*)*buffer)[1] = (unsigned int)htonl(jpegSize + 8);						// Size of the Next Packet
	//	((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
	//	((unsigned short*)*buffer)[5] = 0;														// RESERVED
	//	((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
	//	((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
	//}
	//else
	//{
	//	((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
	//	((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
	//	((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
	//	((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
	//}
	//return 0;
}
extern void __jpeghelp(void *x);
#ifdef WIN32
#define wmain_free(argv) for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv);
int wmain(int argc, char **wargv)
#else
int main(int argc, char **argv)
#endif
{
#ifdef _OPENBSD
	realpath(argv[0], __agentExecPath);
#endif

	// Check if .JS file is integrated with executable
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;
	int retCode = 0;
	int capabilities = 0;
	
	CLSID encoderClsid;
	HRESULT hr;
	HMODULE GDIP = LoadLibraryExW(L"Gdiplus.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	void *gdiptoken = NULL;
	char gdipinput[24] = { 0 };
	((int*)gdipinput)[0] = 1;

	_GdipLoadImageFromStream = (GdipLoadImageFromStream_func)GetProcAddress(GDIP, "GdipLoadImageFromStream");
	_GdiplusStartup = (GdiplusStartup_func)GetProcAddress(GDIP, "GdiplusStartup");
	_GdipSaveImageToStream = (GdipSaveImageToStream_func)GetProcAddress(GDIP, "GdipSaveImageToStream");
	_GetImageEncodersSize = (GetImageEncodersSize_func)GetProcAddress(GDIP, "GdipGetImageEncodersSize");
	_GetImageEncoders = (GetImageEncoders_func)GetProcAddress(GDIP, "GdipGetImageEncoders");
	_GdiplusStartup(&gdiptoken, gdipinput, NULL);

	util_hexToBuf("B5E45B1D4AFA2D459CDD5DB35105E7EB", 32, ILibScratchPad);

	GUID G;
	util_hexToBuf("B5E45B1D4AFA2D459CDD5DB35105E7EB", 32, &G);

	char encparms[40];


	//EncoderParameters::Count = > 0
	//EncoderParameters::Parameter = > 8
	//EncoderParameter::Guid = > 0
	//EncoderParameter::NumberOfValues = > 16
	//EncoderParameter::Type = > 20
	//EncoderParameter::Value = > 24


	HMODULE D3D = LoadLibraryExW(L"D3D11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	D3D11CreateDevice_func func = (D3D11CreateDevice_func)GetProcAddress(D3D, "D3D11CreateDevice");
	D3D11CalcSubresource_func func2 = (D3D11CalcSubresource_func)GetProcAddress(D3D, "D3D11CalcSubresource");

	void *lDevice = NULL;
	int lFeatureLevel = 0;
	ID3D11DeviceContext *lImmediateContext = NULL;

	IID iid;
	hr = IIDFromString(L"{54ec77fa-1377-44e6-8c32-88fd5f44c84c}", &iid);

	// Create device
	UINT gNumDriverTypes = 1;
	for (UINT DriverTypeIndex = 0; DriverTypeIndex < gNumDriverTypes; ++DriverTypeIndex)
	{
		hr = func(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &lDevice, &lFeatureLevel, &lImmediateContext);

		if (SUCCEEDED(hr))
		{
			// Device creation success, no need to loop anymore
			break;
		}
		((ID3D11Device*)lDevice)->lpVtbl->Release(lDevice);
		((ID3D11DeviceContext*)lImmediateContext)->lpVtbl->Release(lImmediateContext);
	}

	// Get DXGI device
	IDXGIDevice *lDxgiDevice;
	hr = ((ID3D11Device*)lDevice)->lpVtbl->QueryInterface(lDevice, &iid, &lDxgiDevice);
	
	// Get DXGI adapter
	GetParent_func fnc = (GetParent_func)((void**)((void**)lDxgiDevice)[0])[6];		// GetParent
	IID adapteriid;
	void *adapter = NULL;
	IIDFromString(L"{2411e7e1-12ac-4ccf-bd14-9798e8534dc0}", &adapteriid);
	hr = fnc(lDxgiDevice, &adapteriid, &adapter);

	((Release_func)((void**)((void**)lDxgiDevice)[0])[2])(lDxgiDevice);				// Release
	UINT Output = 0;
	IDXGIOutput *lDxgiOutput = NULL;
	hr = ((IDXGIAdapter*)adapter)->lpVtbl->EnumOutputs(adapter, Output, &lDxgiOutput);	// Get output
	((IDXGIAdapter*)adapter)->lpVtbl->Release(adapter);

	DXGI_OUTPUT_DESC outdesc;
	hr = lDxgiOutput->lpVtbl->GetDesc(lDxgiOutput, &outdesc);

	IID output1IID;
	IDXGIOutput1 *output1 = NULL;
	IIDFromString(L"{00cddea8-939b-4b83-a340-a685226666cc}", &output1IID);
	hr = lDxgiOutput->lpVtbl->QueryInterface(lDxgiOutput, &output1IID, &output1);
	
	lDxgiOutput->lpVtbl->Release(lDxgiOutput);

	IDXGIOutputDuplication *lDeskDupl = NULL;

	// Create desktop duplication
	hr = output1->lpVtbl->DuplicateOutput(output1, lDevice, &lDeskDupl);
	lDxgiOutput->lpVtbl->Release(lDxgiOutput);

	// Create GUI drawing texture
	DXGI_OUTDUPL_DESC lOutputDuplDesc;
	lDeskDupl->lpVtbl->GetDesc(lDeskDupl, &lOutputDuplDesc);

	D3D11_TEXTURE2D_DESC desc;
	ID3D11Texture2D *lGDIImage = NULL;
	ID3D11Texture2D *lDestImage = NULL;
	ID3D11Texture2D *lAcquiredDesktopImage = NULL;

	desc.Width = lOutputDuplDesc.ModeDesc.Width;
	desc.Height = lOutputDuplDesc.ModeDesc.Height;
	desc.Format = lOutputDuplDesc.ModeDesc.Format;
	desc.ArraySize = 1;
	desc.BindFlags = D3D11_BIND_RENDER_TARGET;
	desc.MiscFlags = D3D11_RESOURCE_MISC_GDI_COMPATIBLE;
	desc.SampleDesc.Count = 1;
	desc.SampleDesc.Quality = 0;
	desc.MipLevels = 1;
	desc.CPUAccessFlags = 0;
	desc.Usage = D3D11_USAGE_DEFAULT;
	hr = ((ID3D11Device*)lDevice)->lpVtbl->CreateTexture2D(lDevice, &desc, NULL, &lGDIImage);


	// Create CPU access texture
	desc.Width = lOutputDuplDesc.ModeDesc.Width;
	desc.Height = lOutputDuplDesc.ModeDesc.Height;
	desc.Format = lOutputDuplDesc.ModeDesc.Format;
	desc.ArraySize = 1;
	desc.BindFlags = 0;
	desc.MiscFlags = 0;
	desc.SampleDesc.Count = 1;
	desc.SampleDesc.Quality = 0;
	desc.MipLevels = 1;
	desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ | D3D11_CPU_ACCESS_WRITE;
	desc.Usage = D3D11_USAGE_STAGING;
	hr = ((ID3D11Device*)lDevice)->lpVtbl->CreateTexture2D(lDevice, &desc, NULL, &lDestImage);

	IDXGIResource *lDesktopResource;
	DXGI_OUTDUPL_FRAME_INFO lFrameInfo;
	int lTryCount = 4;

	do
	{

		Sleep(100);

		// Get new frame
		hr = lDeskDupl->lpVtbl->AcquireNextFrame(
			lDeskDupl,
			250,
			&lFrameInfo,
			&lDesktopResource);

		if (SUCCEEDED(hr))
			break;

		if (hr == DXGI_ERROR_WAIT_TIMEOUT)
		{
			continue;
		}
		else if (FAILED(hr))
			break;

	} while (--lTryCount > 0);

	IID ID3D11Texture2D_IID;
	IIDFromString(L"{6f15aaf2-d208-4e89-9ab4-489535d34f9c}", &ID3D11Texture2D_IID);
	hr = lDesktopResource->lpVtbl->QueryInterface(lDesktopResource, &ID3D11Texture2D_IID, &lAcquiredDesktopImage);
	lDesktopResource->lpVtbl->Release(lDesktopResource);

	// Copy image into GDI drawing texture
	lImmediateContext->lpVtbl->CopyResource(lImmediateContext, lGDIImage, lAcquiredDesktopImage);


	// Draw cursor image into GDI drawing texture
	IID IDXGISurface1_IID;
	IIDFromString(L"{4AE63092-6327-4c1b-80AE-BFE12EA32B86}", &IDXGISurface1_IID);
	IDXGISurface1 *lIDXGISurface1 = NULL;
	hr = lGDIImage->lpVtbl->QueryInterface(lGDIImage, &IDXGISurface1_IID, &lIDXGISurface1);

	CURSORINFO lCursorInfo = { 0 };
	lCursorInfo.cbSize = sizeof(lCursorInfo);

	if (GetCursorInfo(&lCursorInfo) == TRUE)
	{
		if (lCursorInfo.flags == CURSOR_SHOWING)
		{
			POINT lCursorPosition = lCursorInfo.ptScreenPos;
			DWORD lCursorSize = lCursorInfo.cbSize;
			HDC  lHDC;

			lIDXGISurface1->lpVtbl->GetDC(lIDXGISurface1, FALSE, &lHDC);

			DrawIconEx(
				lHDC,
				lCursorPosition.x,
				lCursorPosition.y,
				lCursorInfo.hCursor,
				0,
				0,
				0,
				0,
				DI_NORMAL | DI_DEFAULTSIZE);

			lIDXGISurface1->lpVtbl->ReleaseDC(lIDXGISurface1, NULL);
		}
	}

	// Copy image into CPU access texture
	lImmediateContext->lpVtbl->CopyResource(lImmediateContext, lDestImage, lGDIImage);

	// Copy from CPU access texture to bitmap buffer
	D3D11_MAPPED_SUBRESOURCE resource;
	UINT subresource = 0;
	lImmediateContext->lpVtbl->Map(lImmediateContext, lDestImage, subresource, D3D11_MAP_READ_WRITE, 0, &resource);

	BITMAPINFO	lBmpInfo;
	ZeroMemory(&lBmpInfo, sizeof(BITMAPINFO));
	lBmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	lBmpInfo.bmiHeader.biBitCount = 32;
	lBmpInfo.bmiHeader.biCompression = BI_RGB;
	lBmpInfo.bmiHeader.biWidth = lOutputDuplDesc.ModeDesc.Width;
	lBmpInfo.bmiHeader.biHeight = lOutputDuplDesc.ModeDesc.Height;
	lBmpInfo.bmiHeader.biPlanes = 1;
	lBmpInfo.bmiHeader.biSizeImage = lOutputDuplDesc.ModeDesc.Width * lOutputDuplDesc.ModeDesc.Height * 4;
	
	BYTE* pBuf;
	ILibMemory_AllocateRaw(pBuf, lBmpInfo.bmiHeader.biSizeImage);
	UINT lBmpRowPitch = lOutputDuplDesc.ModeDesc.Width * 4;
	BYTE* sptr = (BYTE*)resource.pData;
	BYTE* dptr = pBuf + lBmpInfo.bmiHeader.biSizeImage - lBmpRowPitch;
	UINT lRowPitch = ((lBmpRowPitch < resource.RowPitch) ? lBmpRowPitch : resource.RowPitch);

	for (size_t h = 0; h < lOutputDuplDesc.ModeDesc.Height; ++h)
	{
		memcpy_s(dptr, lBmpRowPitch, sptr, lRowPitch);
		sptr += resource.RowPitch;
		dptr -= lBmpRowPitch;
	}

	char *desk = NULL;
	int64_t deskSize = 0;
	int vv = _calc_opt_compr_send(0, 0, 4, lOutputDuplDesc.ModeDesc.Width, lOutputDuplDesc.ModeDesc.Height, pBuf, &desk, &deskSize);



	// Save bitmap buffer into the file ScreenShot.bmp
	FILE* lfile = NULL;
	errno_t lerr = _wfopen_s(&lfile, L"C:\\TEST\\KVM.bmp", L"wb");

	if (lfile != NULL)
	{

		BITMAPFILEHEADER	bmpFileHeader;

		bmpFileHeader.bfReserved1 = 0;
		bmpFileHeader.bfReserved2 = 0;
		bmpFileHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + lBmpInfo.bmiHeader.biSizeImage;
		bmpFileHeader.bfType = 'MB';
		bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

		fwrite(&bmpFileHeader, sizeof(BITMAPFILEHEADER), 1, lfile);
		fwrite(&lBmpInfo.bmiHeader, sizeof(BITMAPINFOHEADER), 1, lfile);
		fwrite(pBuf, lBmpInfo.bmiHeader.biSizeImage, 1, lfile);

		fclose(lfile);
	}







#ifdef WIN32
	int argvi, argvsz;
	char **argv = (char**)ILibMemory_SmartAllocate(argc * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		argvsz = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, argv[argvi], argvsz, NULL, NULL);
	}
#endif

#if defined (_POSIX)
#ifndef _NOILIBSTACKDEBUG
char* crashMemory = ILib_POSIX_InstallCrashHandler(argv[0]);
#endif
#endif


	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integratedJavaScriptLen);

	if (integratedJavaScriptLen != 0 && integratedJavaScript != NULL && argc > 1)
	{
		int i;
		for (i = 1; i < argc; ++i)
		{
			if (strcmp(argv[i], "--no-embedded=1") == 0 || strcmp(argv[i], "--no-embedded=\"1\"") == 0)
			{
				free(integratedJavaScript);
				integratedJavaScript = NULL;
				integratedJavaScriptLen = 0;
				break;
			}
		}
	}

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	} 
	if (argc > 2 && strcmp(argv[1], "-b64exec") == 0)
	{
		integratedJavaScript = NULL;
		integratedJavaScriptLen = ILibBase64Decode((unsigned char *)argv[2], (const int)strnlen_s(argv[2], sizeof(ILibScratchPad2)), (unsigned char**)&integratedJavaScript);
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-name") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId').serviceName());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentFullHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcmp(argv[1], "-daemon") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('daemon').agent();", 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcasecmp(argv[1], "-licenses") == 0)
	{
		printf("========================================================================================\n");
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2022 Intel Corporation\n");
		printf("                        https://github.com/Ylianst/MeshAgent \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Licensed under the Apache License, Version 2.0 (the \"License\");\n");
		printf("   you may not use this file except in compliance with the License.\n");
		printf("   You may obtain a copy of the License at\n");
		printf("   \n");
		printf("   http://www.apache.org/licenses/LICENSE-2.0\n");
		printf("   \n");
		printf("   Unless required by applicable law or agreed to in writing, software\n");
		printf("   distributed under the License is distributed on an \"AS IS\" BASIS,\n");
		printf("   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
		printf("   See the License for the specific language governing permissions and\n");
		printf("   limitations under the License.\n\n");
		printf("========================================================================================\n");
		printf(" Duktape Javascript Engine: Copyright (c) 2013-2019 by Duktape authors (see AUTHORS.rst)\n");
		printf("                        https://github.com/svaarala/duktape \n");
		printf("                        http://opensource.org/licenses/MIT \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Permission is hereby granted, free of charge, to any person obtaining a copy\n");
		printf("   of this software and associated documentation files(the \"Software\"), to deal\n");
		printf("   in the Software without restriction, including without limitation the rights\n");
		printf("   to use, copy, modify, merge, publish, distribute, sublicense, and / or sell\n");
		printf("   copies of the Software, and to permit persons to whom the Software is\n");
		printf("   furnished to do so, subject to the following conditions :\n");
		printf("   \n");
		printf("   The above copyright notice and this permission notice shall be included in\n");
		printf("   all copies or substantial portions of the Software.\n");
		printf("   \n");
		printf("   THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n");
		printf("   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n");
		printf("   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE\n");
		printf("   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n");
		printf("   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n");
		printf("   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n");
		printf("   THE SOFTWARE.\n");
		printf("========================================================================================\n");
		printf("ZLIB Data Compression Library: Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler\n");
		printf("                               http://www.zlib.net \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   This software is provided 'as-is', without any express or implied\n");
		printf("   warranty.In no event will the authors be held liable for any damages\n");
		printf("   arising from the use of this software.\n");
		printf("\n");
		printf("   Permission is granted to anyone to use this software for any purpose,\n");
		printf("   including commercial applications, and to alter it and redistribute it\n");
		printf("   freely, subject to the following restrictions :\n");
		printf("\n");
		printf("   1. The origin of this software must not be misrepresented; you must not\n");
		printf("      claim that you wrote the original software.If you use this software\n");
		printf("      in a product, an acknowledgment in the product documentation would be\n");
		printf("      appreciated but is not required.\n");
		printf("   2. Altered source versions must be plainly marked as such, and must not be\n");
		printf("      misrepresented as being the original software.\n");
		printf("   3. This notice may not be removed or altered from any source distribution.\n");
		printf("\n");
		printf("   Jean - loup Gailly        Mark Adler\n");
		printf("   jloup@gzip.org            madler@alumni.caltech.edu\n");


#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
		if (SOURCE_COMMIT_HASH != NULL && SOURCE_COMMIT_DATE != NULL) 
		{ 
			printf("   Commit Hash: %s\n", SOURCE_COMMIT_HASH); 
			printf("   Commit Date: %s\n", SOURCE_COMMIT_DATE); 
		}
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif

		printf("Agent ARCHID: %d\n", MESH_AGENTID);
		char script[] = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(process.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require('win-authenticode-opus').locked(_tmp.url); if(_tmp!=null) { console.log('LOCKED to: ' + _tmp.dns); console.log(' => ' + _tmp.id); } } } process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-updaterversion") == 0)
	{
#ifdef WIN32
		DWORD dummy;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "1\n", 2, &dummy, NULL);
#else
		ignore_result(write(STDOUT_FILENO, "1\n", 2));
#endif
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
#if defined(_LINKVM) && defined(__APPLE__)
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		kvm_server_mainloop(NULL);
		return 0;
	}
	else if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		kvm_server_mainloop((void*)(uint64_t)getpid());
		return 0;
	}
#endif

	if (argc > 2 && strcasecmp(argv[1], "-faddr") == 0)
	{
#if !defined(WIN32)
		uint64_t addrOffset = 0;
		sscanf(argv[2] + 2, "%016"PRIx64, &addrOffset);
#elif defined(WIN64)
		uint64_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%016llx", &addrOffset);
#else
		uint32_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%x", &addrOffset);
#endif

		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), (uint64_t)addrOffset);
		printf("%s", ILibScratchPad);
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
#ifdef WIN32
		sscanf_s(argv[2], "%lld", &delta);
#else
		sscanf(argv[2], "%"PRIu64, &delta);
#endif
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}

	if (argc > 1 && strcasecmp(argv[1], "connect") == 0) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }

	if (integratedJavaScriptLen == 0)
	{
		if (argc >= 2 && strnlen_s(argv[1], 9) >= 8 && strncmp(argv[1], "-update:", 8) == 0)
		{
			ILibMemory_AllocateRaw(integratedJavaScript, 1024);
			if (argv[1][8] == '*')
			{
				// New Style
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, '%s');", argc > 2 ? argv[2] : "null");
			}
			else
			{
				// Legacy
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, ['%s']);", argc > 2 ? argv[2] : "");
			}
		}
	}
#ifdef WIN32
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C
	ILib_DumpEnabledContext winExceptionContext;
#elif defined(_POSIX)
	signal(SIGPIPE, SIG_IGN); // Set a SIGNAL on Linux to listen for Ctrl-C						  
	signal(SIGINT, BreakSink);// Shutdown on Ctrl + C
	{	
		struct sigaction act;
		act.sa_handler = SIG_IGN;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGPIPE, &act, NULL);
	}
#endif

#ifdef WIN32
	__try
	{
		agentHost = MeshAgent_Create(capabilities);
		agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
		agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
		while (MeshAgent_Start(agentHost, argc, argv) != 0);
		retCode = agentHost->exitCode;
		MeshAgent_Destroy(agentHost);
		agentHost = NULL;
	}
	__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winExceptionContext))
	{
		ILib_WindowsExceptionDebugEx(&winExceptionContext);
	}
	wmain_free(argv);
	_CrtDumpMemoryLeaks();
#else
	agentHost = MeshAgent_Create(capabilities);
	agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
	agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
	while (MeshAgent_Start(agentHost, argc, argv) != 0);
	retCode = agentHost->exitCode;
	MeshAgent_Destroy(agentHost);
	agentHost = NULL;
#ifndef _NOILIBSTACKDEBUG
	if (crashMemory != NULL) { free(crashMemory); }
#endif
#endif
	return retCode;
}
