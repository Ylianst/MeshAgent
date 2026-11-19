/*
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

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <string.h>
#include "dxgi_capture.h"

typedef HRESULT (WINAPI *CreateDXGIFactory1_t)(REFIID, void **);
typedef HRESULT (WINAPI *D3D11CreateDevice_t)(IDXGIAdapter *, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL *, UINT, UINT, ID3D11Device **, D3D_FEATURE_LEVEL *, ID3D11DeviceContext **);

static HMODULE dxgiLib = NULL;
static HMODULE d3d11Lib = NULL;
static ID3D11Device *dev = NULL;
static ID3D11DeviceContext *ctx = NULL;
static IDXGIOutputDuplication *dup = NULL;
static ID3D11Texture2D *staging = NULL;
static int dupX = 0;
static int dupY = 0;
static int dupW = 0;
static int dupH = 0;
static int hasFrame = 0;
static int unsupported = 0;
static int failed = 0;
static DWORD failedAt = 0;
static int startNext = 0;

#define DXGI_SAFE_RELEASE(p) if ((p) != NULL) { (p)->Release(); (p) = NULL; }

extern "C" void dxgi_capture_release(void)
{
	DXGI_SAFE_RELEASE(staging);
	DXGI_SAFE_RELEASE(dup);
	DXGI_SAFE_RELEASE(ctx);
	DXGI_SAFE_RELEASE(dev);
	hasFrame = 0;
}

extern "C" int dxgi_capture_unsupported(void)
{
	return unsupported;
}

static void dxgi_capture_failed(void)
{
	dxgi_capture_release();
	failed = 1;
	failedAt = GetTickCount();
}

static int dxgi_capture_init(int x, int y, int w, int h)
{
	CreateDXGIFactory1_t createFactory;
	D3D11CreateDevice_t createDevice;
	IDXGIFactory1 *factory = NULL;
	IDXGIAdapter1 *adapter = NULL;
	IDXGIOutput *output = NULL;
	IDXGIOutput1 *output1 = NULL;
	D3D11_TEXTURE2D_DESC td;
	HRESULT hr;
	UINT a, o;
	int found = 0;

	dxgi_capture_release();
	if (unsupported) { return 1; }

	// Loaded at runtime so the agent still starts on Windows 7, which has no Desktop Duplication
	if (dxgiLib == NULL) { dxgiLib = LoadLibraryExA("dxgi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (d3d11Lib == NULL) { d3d11Lib = LoadLibraryExA("d3d11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (dxgiLib == NULL || d3d11Lib == NULL) { unsupported = 1; return 1; }
	createFactory = (CreateDXGIFactory1_t)GetProcAddress(dxgiLib, "CreateDXGIFactory1");
	createDevice = (D3D11CreateDevice_t)GetProcAddress(d3d11Lib, "D3D11CreateDevice");
	if (createFactory == NULL || createDevice == NULL || FAILED(createFactory(__uuidof(IDXGIFactory1), (void **)&factory))) { unsupported = 1; return 1; }

	// Only an output that covers exactly the captured rectangle, so "all displays" across several monitors stays on BitBlt
	for (a = 0; !found && factory->EnumAdapters1(a, &adapter) != DXGI_ERROR_NOT_FOUND; a++)
	{
		for (o = 0; !found && adapter->EnumOutputs(o, &output) != DXGI_ERROR_NOT_FOUND; o++)
		{
			DXGI_OUTPUT_DESC d;
			output->GetDesc(&d);
			if (d.AttachedToDesktop && d.Rotation == DXGI_MODE_ROTATION_IDENTITY &&
				d.DesktopCoordinates.left == x && d.DesktopCoordinates.top == y &&
				d.DesktopCoordinates.right - d.DesktopCoordinates.left == w &&
				d.DesktopCoordinates.bottom - d.DesktopCoordinates.top == h)
			{
				found = 1;
				break;
			}
			DXGI_SAFE_RELEASE(output);
		}
		if (!found) { DXGI_SAFE_RELEASE(adapter); }
	}
	factory->Release();
	if (!found) { return 1; }

	if (FAILED(output->QueryInterface(__uuidof(IDXGIOutput1), (void **)&output1)))
	{
		// No IDXGIOutput1 means Windows 7 without the Platform Update, which never gets it, so stop trying
		unsupported = 1;
		output->Release();
		adapter->Release();
		return 1;
	}
	hr = createDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &dev, NULL, &ctx);
	if (SUCCEEDED(hr)) { hr = output1->DuplicateOutput(dev, &dup); }
	output1->Release();
	output->Release();
	adapter->Release();
	if (FAILED(hr))
	{
		// Windows 7 with the Platform Update has IDXGIOutput1 but answers E_NOTIMPL, which never changes
		if (hr == E_NOTIMPL) { unsupported = 1; }
		// E_ACCESSDENIED on the secure desktop and DXGI_ERROR_SESSION_DISCONNECTED are temporary, DXGI_ERROR_UNSUPPORTED is not
		if (hr == DXGI_ERROR_UNSUPPORTED) { unsupported = 1; }
		dxgi_capture_release();
		return 1;
	}

	memset(&td, 0, sizeof(td));
	td.Width = w;
	td.Height = h;
	td.MipLevels = 1;
	td.ArraySize = 1;
	td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	td.SampleDesc.Count = 1;
	td.Usage = D3D11_USAGE_STAGING;
	td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
	if (FAILED(dev->CreateTexture2D(&td, NULL, &staging))) { dxgi_capture_release(); return 1; }
	dupX = x;
	dupY = y;
	dupW = w;
	dupH = h;
	return 0;
}

// Copies the last frame from the staging texture into dest, returns 0 on success and -1 when Map() failed
static int dxgi_capture_copy(unsigned char *dest, int destWidth, int destHeight)
{
	D3D11_MAPPED_SUBRESOURCE map;
	int r;

	if (FAILED(ctx->Map(staging, 0, D3D11_MAP_READ, 0, &map))) { return -1; }
	// The tile code reads a bottom-up DIB with adjust_screen_size() rows, so screen row r goes to DIB row (destHeight - 1 - r)
	for (r = 0; r < dupH; r++)
	{
		memcpy(dest + (size_t)(destHeight - 1 - r) * destWidth * 4, (unsigned char *)map.pData + (size_t)r * map.RowPitch, (size_t)dupW * 4);
	}
	ctx->Unmap(staging, 0);
	return 0;
}

extern "C" int dxgi_capture_frame(int x, int y, int w, int h, unsigned char *dest, int destWidth, int destHeight, int destCurrent)
{
	DXGI_OUTDUPL_FRAME_INFO fi;
	IDXGIResource *res = NULL;
	ID3D11Texture2D *tex = NULL;
	HRESULT hr;
	int result;

	if (unsupported || w > destWidth || h > destHeight) { return 1; }
	if (dup != NULL && (x != dupX || y != dupY || w != dupW || h != dupH)) { dxgi_capture_release(); }
	if (dup == NULL)
	{
		// One attempt every 2 seconds, so the secure desktop or a disconnected session does not cost a failed init per frame
		if (failed && GetTickCount() - failedAt < 2000) { return 1; }
		// The start takes longer than a BitBlt frame and has no frame ready right after it, so GDI takes this frame
		// and the start follows on the next one. Otherwise the first picture of a session waits for the start.
		if (!startNext) { startNext = 1; return 1; }
		startNext = 0;
		if (dxgi_capture_init(x, y, w, h) != 0) { dxgi_capture_failed(); return 1; }
		failed = 0;
	}

	hr = dup->AcquireNextFrame(0, &fi, &res);
	if (hr == DXGI_ERROR_WAIT_TIMEOUT)
	{
		// Nothing changed, but right after an init there may be no frame yet, and then GDI captures this one
		if (!hasFrame) { return 1; }
		if (destCurrent) { return 0; }
		if (dxgi_capture_copy(dest, destWidth, destHeight) != 0) { dxgi_capture_failed(); return 1; }
		return 0;
	}
	if (FAILED(hr)) { dxgi_capture_failed(); return 1; } // DXGI_ERROR_ACCESS_LOST on a desktop switch, UAC prompt or mode change

	// A frame with LastPresentTime 0 only moved the pointer, the image is unchanged
	if (fi.LastPresentTime.QuadPart != 0)
	{
		result = -1;
		if (SUCCEEDED(res->QueryInterface(__uuidof(ID3D11Texture2D), (void **)&tex)))
		{
			ctx->CopyResource(staging, tex);
			tex->Release();
			hasFrame = 1;
			result = dxgi_capture_copy(dest, destWidth, destHeight);
		}
	}
	else if (!hasFrame) { result = 1; }
	else { result = destCurrent ? 0 : dxgi_capture_copy(dest, destWidth, destHeight); }
	res->Release();
	dup->ReleaseFrame();
	if (result < 0) { dxgi_capture_failed(); return 1; }
	return result;
}

#endif
