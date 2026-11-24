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

// The changed areas of the last frame, as move and dirty rectangles from DXGI, and -1 for the whole screen
static unsigned char *meta = NULL;
static UINT metaSize = 0;
static RECT *changed = NULL;
static int changedCount = 0;
static int changedCapacity = 0;

#define DXGI_SAFE_RELEASE(p) do { if ((p) != NULL) { (p)->Release(); (p) = NULL; } } while (0)

extern "C" void dxgi_capture_release(void)
{
	DXGI_SAFE_RELEASE(staging);
	DXGI_SAFE_RELEASE(dup);
	DXGI_SAFE_RELEASE(ctx);
	DXGI_SAFE_RELEASE(dev);
	hasFrame = 0;
	free(meta);
	meta = NULL;
	metaSize = 0;
	free(changed);
	changed = NULL;
	changedCount = changedCapacity = 0;
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

// Only an output that covers exactly the captured rectangle, so "all displays" across several monitors stays on BitBlt.
// Returns 1 with the adapter and output for the caller to release, 0 when no output matches.
static int dxgi_find_output(IDXGIFactory1 *factory, int x, int y, int w, int h, IDXGIAdapter1 **adapter, IDXGIOutput **output)
{
	UINT a, o;

	for (a = 0; factory->EnumAdapters1(a, adapter) != DXGI_ERROR_NOT_FOUND; a++)
	{
		for (o = 0; (*adapter)->EnumOutputs(o, output) != DXGI_ERROR_NOT_FOUND; o++)
		{
			DXGI_OUTPUT_DESC d;
			(*output)->GetDesc(&d);
			if (d.AttachedToDesktop && d.Rotation == DXGI_MODE_ROTATION_IDENTITY &&
				d.DesktopCoordinates.left == x && d.DesktopCoordinates.top == y &&
				d.DesktopCoordinates.right - d.DesktopCoordinates.left == w &&
				d.DesktopCoordinates.bottom - d.DesktopCoordinates.top == h)
			{
				return 1;
			}
			DXGI_SAFE_RELEASE(*output);
		}
		DXGI_SAFE_RELEASE(*adapter);
	}
	return 0;
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
	int found;

	dxgi_capture_release();
	if (unsupported) { return 1; }

	// Loaded at runtime so the agent still starts on Windows 7, which has no Desktop Duplication
	if (dxgiLib == NULL) { dxgiLib = LoadLibraryExA("dxgi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (d3d11Lib == NULL) { d3d11Lib = LoadLibraryExA("d3d11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (dxgiLib == NULL || d3d11Lib == NULL) { unsupported = 1; return 1; }
	createFactory = (CreateDXGIFactory1_t)GetProcAddress(dxgiLib, "CreateDXGIFactory1");
	createDevice = (D3D11CreateDevice_t)GetProcAddress(d3d11Lib, "D3D11CreateDevice");
	if (createFactory == NULL || createDevice == NULL || FAILED(createFactory(__uuidof(IDXGIFactory1), (void **)&factory))) { unsupported = 1; return 1; }

	found = dxgi_find_output(factory, x, y, w, h, &adapter, &output);
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

// Clamped to the output, empty rectangles are dropped, returns 1 when the list could not grow
static int dxgi_changed_add(const RECT *r)
{
	RECT c;
	c.left = r->left < 0 ? 0 : r->left;
	c.top = r->top < 0 ? 0 : r->top;
	c.right = r->right > dupW ? dupW : r->right;
	c.bottom = r->bottom > dupH ? dupH : r->bottom;
	if (c.right <= c.left || c.bottom <= c.top) { return 0; }
	if (changedCount == changedCapacity)
	{
		RECT *grown = (RECT *)realloc(changed, sizeof(RECT) * (changedCapacity + 64));
		if (grown == NULL) { return 1; }
		changed = grown;
		changedCapacity += 64;
	}
	changed[changedCount++] = c;
	return 0;
}

// Collects the dirty rectangles and the destinations of the move rectangles of the acquired frame.
// Returns 1 when they could not be read or cover more than half the screen, and then the caller takes the whole frame.
static int dxgi_read_changes(const DXGI_OUTDUPL_FRAME_INFO *fi)
{
	UINT used, i;
	long long area = 0;

	changedCount = 0;
	if (fi->TotalMetadataBufferSize == 0) { return 1; }
	if (metaSize < fi->TotalMetadataBufferSize)
	{
		unsigned char *grown = (unsigned char *)realloc(meta, fi->TotalMetadataBufferSize);
		if (grown == NULL) { return 1; }
		meta = grown;
		metaSize = fi->TotalMetadataBufferSize;
	}
	// Moves first, the dirty rectangles reuse the buffer afterwards
	if (FAILED(dup->GetFrameMoveRects(metaSize, (DXGI_OUTDUPL_MOVE_RECT *)meta, &used))) { return 1; }
	for (i = 0; i < used / sizeof(DXGI_OUTDUPL_MOVE_RECT); i++)
	{
		if (dxgi_changed_add(&((DXGI_OUTDUPL_MOVE_RECT *)meta)[i].DestinationRect)) { return 1; }
	}
	if (FAILED(dup->GetFrameDirtyRects(metaSize, (RECT *)meta, &used))) { return 1; }
	for (i = 0; i < used / sizeof(RECT); i++)
	{
		if (dxgi_changed_add(&((RECT *)meta)[i])) { return 1; }
	}
	// Scattered changes in one window come as their bounding box, and copying a large part rectangle by rectangle
	// costs more than one copy of the whole frame. Overlaps count twice, which only moves the switch a little earlier.
	for (i = 0; i < (UINT)changedCount; i++) { area += (long long)(changed[i].right - changed[i].left) * (changed[i].bottom - changed[i].top); }
	if (area * 2 > (long long)dupW * dupH) { return 1; }
	return 0;
}

// Copies the changed areas of the last frame, or all of it when changedCount is -1, from the staging texture into dest.
// Returns 0 on success and -1 when Map() failed.
static int dxgi_capture_copy(unsigned char *dest, int destWidth, int destHeight)
{
	D3D11_MAPPED_SUBRESOURCE map;
	int r, i;

	if (changedCount == 0) { return 0; }
	if (FAILED(ctx->Map(staging, 0, D3D11_MAP_READ, 0, &map))) { return -1; }
	// The tile code reads a bottom-up DIB with adjust_screen_size() rows, so screen row r goes to DIB row (destHeight - 1 - r)
	if (changedCount < 0)
	{
		for (r = 0; r < dupH; r++)
		{
			memcpy(dest + (size_t)(destHeight - 1 - r) * destWidth * 4, (unsigned char *)map.pData + (size_t)r * map.RowPitch, (size_t)dupW * 4);
		}
	}
	for (i = 0; i < changedCount; i++)
	{
		const RECT *c = &changed[i];
		for (r = c->top; r < c->bottom; r++)
		{
			memcpy(dest + ((size_t)(destHeight - 1 - r) * destWidth + c->left) * 4, (unsigned char *)map.pData + (size_t)r * map.RowPitch + (size_t)c->left * 4, (size_t)(c->right - c->left) * 4);
		}
	}
	ctx->Unmap(staging, 0);
	return 0;
}

extern "C" int dxgi_capture_frame(int x, int y, int w, int h, unsigned char *dest, int destWidth, int destHeight, int destCurrent, const RECT **rects, int *rectCount)
{
	DXGI_OUTDUPL_FRAME_INFO fi;
	IDXGIResource *res = NULL;
	ID3D11Texture2D *tex = NULL;
	HRESULT hr;
	int result;
	int fresh = 0;

	*rects = NULL;
	*rectCount = -1;
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
	// DXGI_ERROR_ACCESS_LOST on a desktop switch, UAC prompt or mode change
	if (FAILED(hr) && hr != DXGI_ERROR_WAIT_TIMEOUT) { dxgi_capture_failed(); return 1; }

	// A timeout means nothing changed, and a frame with LastPresentTime 0 only moved the pointer
	result = 0;
	if (SUCCEEDED(hr) && fi.LastPresentTime.QuadPart != 0)
	{
		if (FAILED(res->QueryInterface(__uuidof(ID3D11Texture2D), (void **)&tex))) { result = -1; }
		else
		{
			// The whole frame after a start, after GDI wrote dest and when the rectangles cannot be read
			if (!hasFrame || !destCurrent || dxgi_read_changes(&fi) != 0)
			{
				ctx->CopyResource(staging, tex);
				changedCount = -1;
			}
			for (int i = 0; i < changedCount; i++)
			{
				D3D11_BOX b = { (UINT)changed[i].left, (UINT)changed[i].top, 0, (UINT)changed[i].right, (UINT)changed[i].bottom, 1 };
				ctx->CopySubresourceRegion(staging, 0, b.left, b.top, 0, tex, 0, &b);
			}
			tex->Release();
			hasFrame = 1;
			fresh = 1;
		}
	}
	if (result == 0)
	{
		// Right after a start there may be no frame yet, and then GDI captures this one
		if (!hasFrame) { result = 1; }
		else
		{
			if (!fresh) { changedCount = destCurrent ? 0 : -1; }
			result = dxgi_capture_copy(dest, destWidth, destHeight);
		}
	}
	if (SUCCEEDED(hr))
	{
		res->Release();
		dup->ReleaseFrame();
	}
	if (result < 0) { dxgi_capture_failed(); return 1; }
	if (result == 0)
	{
		*rects = changed;
		*rectCount = changedCount;
	}
	return result;
}

#endif
