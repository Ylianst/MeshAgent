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

#define DXGI_MAX_OUTPUTS 8

// One duplication for every output in the captured rectangle, so "all displays" across several monitors works too
typedef struct dxgi_out
{
	ID3D11Device *dev;				// One device per adapter, and each of its outputs holds a reference
	ID3D11DeviceContext *ctx;
	IDXGIOutputDuplication *dup;
	ID3D11Texture2D *staging;
	unsigned char *upright;			// A rotated output's picture turned to the desktop's orientation, NULL when not rotated
	int ox;							// Position in the captured rectangle
	int oy;
	int w;
	int h;
	int tw;							// Size of the output's texture, which has the orientation of the panel
	int th;
	int rot;
	int hasFrame;
	int full;						// The whole output is copied in this frame
	int first;						// Start of this output's part of changed[]
} dxgi_out;

static HMODULE dxgiLib = NULL;
static HMODULE d3d11Lib = NULL;
static D3D11CreateDevice_t createDevice = NULL;
static dxgi_out outs[DXGI_MAX_OUTPUTS];
static int outCount = 0;
static int dupX = 0;
static int dupY = 0;
static int dupW = 0;
static int dupH = 0;
static int unsupported = 0;
static int failed = 0;
static DWORD failedAt = 0;
static DWORD failedWait = 0;
static int startNext = 0;

// The changed areas of the last frame, one output's part after the other. They are in the coordinates of the output's texture
// until the copy into dest, which leaves them in the coordinates of the captured rectangle.
static unsigned char *meta = NULL;
static UINT metaSize = 0;
static RECT *changed = NULL;
static int changedCount = 0;
static int changedCapacity = 0;

#define DXGI_RETRY_MS 2000
// An output in the captured rectangle is only partly inside it, in a mode that cannot be duplicated or has frames of an unexpected size.
// A display change ends the wait through dxgi_capture_release(), and the retry finds a change of colour depth alone.
#define DXGI_RETRY_NO_OUTPUT_MS 30000
#define DXGI_SAFE_RELEASE(p) do { if ((p) != NULL) { (p)->Release(); (p) = NULL; } } while (0)

static void dxgi_release_objects(void)
{
	for (int i = 0; i < outCount; i++)
	{
		DXGI_SAFE_RELEASE(outs[i].staging);
		DXGI_SAFE_RELEASE(outs[i].dup);
		DXGI_SAFE_RELEASE(outs[i].ctx);
		DXGI_SAFE_RELEASE(outs[i].dev);
		free(outs[i].upright);
		outs[i].upright = NULL;
	}
	outCount = 0;
	free(meta);
	meta = NULL;
	metaSize = 0;
	free(changed);
	changed = NULL;
	changedCount = changedCapacity = 0;
}

// Called on a display, resolution or desktop change and at the end of a session, so the next frame may try a start at once
extern "C" void dxgi_capture_release(void)
{
	dxgi_release_objects();
	failed = 0;
}

extern "C" int dxgi_capture_unsupported(void)
{
	return unsupported;
}

// One attempt per wait, so the secure desktop or a disconnected session does not cost a failed start per frame
static void dxgi_capture_failed(DWORD wait)
{
	dxgi_release_objects();
	failed = 1;
	failedAt = GetTickCount();
	failedWait = wait;
}

// Starts the duplication of one output, dc is its place on the desktop.
// Returns 0 when it runs, 2 when the output's desktop mode cannot be duplicated and 1 on every other failure.
// DuplicateOutput() needs a device on the adapter that drives the output, so adev and actx are the caller's device for this adapter.
static int dxgi_output_start(IDXGIAdapter1 *adapter, IDXGIOutput *output, ID3D11Device **adev, ID3D11DeviceContext **actx, const RECT *dc)
{
	dxgi_out *o = &outs[outCount];
	IDXGIOutput1 *output1 = NULL;
	DXGI_OUTDUPL_DESC dd;
	D3D11_TEXTURE2D_DESC td;
	HRESULT hr;

	// No IDXGIOutput1 means Windows 7 without the Platform Update, which never gets it, so stop trying
	if (FAILED(output->QueryInterface(__uuidof(IDXGIOutput1), (void **)&output1))) { unsupported = 1; return 1; }
	if (*adev == NULL && FAILED(createDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0, NULL, 0, D3D11_SDK_VERSION, adev, NULL, actx)))
	{
		output1->Release();
		return 1;
	}

	memset(o, 0, sizeof(*o));
	o->dev = *adev;
	o->dev->AddRef();
	o->ctx = *actx;
	o->ctx->AddRef();
	outCount++; // Counted from here on, so dxgi_release_objects() also frees an output that failed halfway
	hr = output1->DuplicateOutput(o->dev, &o->dup);
	output1->Release();
	if (FAILED(hr))
	{
		// Windows 7 with the Platform Update has IDXGIOutput1 but answers E_NOTIMPL, which never changes
		if (hr == E_NOTIMPL) { unsupported = 1; }
		// DXGI_ERROR_UNSUPPORTED is about the desktop mode, like 8 bit colour, so it gets the long wait and DXGI stays on.
		// E_ACCESSDENIED on the secure desktop and DXGI_ERROR_SESSION_DISCONNECTED are temporary.
		return hr == DXGI_ERROR_UNSUPPORTED ? 2 : 1;
	}

	o->ox = dc->left - dupX;
	o->oy = dc->top - dupY;
	o->w = dc->right - dc->left;
	o->h = dc->bottom - dc->top;
	// A rotated output is duplicated in the orientation of the panel, so its texture has the sides swapped at 90 and 270 degrees
	o->dup->GetDesc(&dd);
	o->rot = (dd.Rotation == DXGI_MODE_ROTATION_UNSPECIFIED) ? DXGI_MODE_ROTATION_IDENTITY : dd.Rotation;
	o->tw = (o->rot == DXGI_MODE_ROTATION_ROTATE90 || o->rot == DXGI_MODE_ROTATION_ROTATE270) ? o->h : o->w;
	o->th = (o->rot == DXGI_MODE_ROTATION_ROTATE90 || o->rot == DXGI_MODE_ROTATION_ROTATE270) ? o->w : o->h;
	if (o->rot != DXGI_MODE_ROTATION_IDENTITY && (o->upright = (unsigned char *)malloc((size_t)o->w * o->h * 4)) == NULL) { return 1; }
	memset(&td, 0, sizeof(td));
	td.Width = o->tw;
	td.Height = o->th;
	td.MipLevels = 1;
	td.ArraySize = 1;
	td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	td.SampleDesc.Count = 1;
	td.Usage = D3D11_USAGE_STAGING;
	td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
	return FAILED(o->dev->CreateTexture2D(&td, NULL, &o->staging)) ? 1 : 0;
}

// Starts a duplication for every output in the rectangle. An output that is only partly inside it leaves the whole rectangle on BitBlt.
// Returns 0 when all of them run, 2 for such an output, for a mode that cannot be duplicated or when there is none, and 1 for every other failure.
static int dxgi_capture_init(int x, int y, int w, int h)
{
	CreateDXGIFactory1_t createFactory;
	IDXGIFactory1 *factory = NULL;
	IDXGIAdapter1 *adapter = NULL;
	IDXGIOutput *output = NULL;
	UINT a, n;
	int result = 0;

	dxgi_release_objects();
	if (unsupported) { return 1; }

	// Loaded at runtime so the agent still starts on Windows 7, which has no Desktop Duplication
	if (dxgiLib == NULL) { dxgiLib = LoadLibraryExA("dxgi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (d3d11Lib == NULL) { d3d11Lib = LoadLibraryExA("d3d11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); }
	if (dxgiLib == NULL || d3d11Lib == NULL) { unsupported = 1; return 1; }
	createFactory = (CreateDXGIFactory1_t)GetProcAddress(dxgiLib, "CreateDXGIFactory1");
	createDevice = (D3D11CreateDevice_t)GetProcAddress(d3d11Lib, "D3D11CreateDevice");
	if (createFactory == NULL || createDevice == NULL || FAILED(createFactory(__uuidof(IDXGIFactory1), (void **)&factory))) { unsupported = 1; return 1; }

	dupX = x;
	dupY = y;
	dupW = w;
	dupH = h;
	for (a = 0; result == 0 && factory->EnumAdapters1(a, &adapter) != DXGI_ERROR_NOT_FOUND; a++)
	{
		ID3D11Device *adev = NULL;
		ID3D11DeviceContext *actx = NULL;
		for (n = 0; result == 0 && adapter->EnumOutputs(n, &output) != DXGI_ERROR_NOT_FOUND; n++)
		{
			DXGI_OUTPUT_DESC d;
			const RECT *dc = &d.DesktopCoordinates;
			output->GetDesc(&d);
			if (d.AttachedToDesktop && dc->right > x && dc->left < x + w && dc->bottom > y && dc->top < y + h)
			{
				if (dc->left < x || dc->top < y || dc->right > x + w || dc->bottom > y + h || outCount == DXGI_MAX_OUTPUTS) { result = 2; }
				else { result = dxgi_output_start(adapter, output, &adev, &actx, dc); }
			}
			output->Release();
		}
		DXGI_SAFE_RELEASE(actx);
		DXGI_SAFE_RELEASE(adev);
		adapter->Release();
	}
	factory->Release();
	if (result == 0 && outCount == 0) { result = 2; }
	if (result != 0) { dxgi_release_objects(); }
	return result;
}

// r is in the coordinates of the output's texture. Clamped to the texture, empty rectangles are dropped, returns 1 when the list could not grow.
static int dxgi_changed_add(const dxgi_out *o, const RECT *r)
{
	RECT c;
	c.left = r->left < 0 ? 0 : r->left;
	c.top = r->top < 0 ? 0 : r->top;
	c.right = r->right > o->tw ? o->tw : r->right;
	c.bottom = r->bottom > o->th ? o->th : r->bottom;
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

// Turns the rectangle c of a rotated output's texture into the upright copy, and sets c to its place there.
// Desktop Duplication delivers a rotated output as the panel has it, and the changed rectangles in that orientation too.
static void dxgi_turn_rect(const dxgi_out *o, const D3D11_MAPPED_SUBRESOURCE *map, RECT *c)
{
	const unsigned char *base = (const unsigned char *)map->pData;
	ptrdiff_t pitch = (ptrdiff_t)map->RowPitch;
	RECT d;
	int x, y;

	if (o->rot == DXGI_MODE_ROTATION_ROTATE90) { d.left = o->w - c->bottom; d.top = c->left; d.right = o->w - c->top; d.bottom = c->right; }
	else if (o->rot == DXGI_MODE_ROTATION_ROTATE180) { d.left = o->w - c->right; d.top = o->h - c->bottom; d.right = o->w - c->left; d.bottom = o->h - c->top; }
	else { d.left = c->top; d.top = o->h - c->right; d.right = c->bottom; d.bottom = o->h - c->left; }
	for (y = d.top; y < d.bottom; y++)
	{
		// The texture pixel that the first upright pixel of this row shows, and the step to the one of the next upright pixel
		const unsigned char *p;
		ptrdiff_t step;
		unsigned int *out = (unsigned int *)(o->upright + ((size_t)y * o->w + d.left) * 4);
		if (o->rot == DXGI_MODE_ROTATION_ROTATE90) { p = base + (ptrdiff_t)(o->w - 1 - d.left) * pitch + (ptrdiff_t)y * 4; step = -pitch; }
		else if (o->rot == DXGI_MODE_ROTATION_ROTATE180) { p = base + (ptrdiff_t)(o->h - 1 - y) * pitch + (ptrdiff_t)(o->w - 1 - d.left) * 4; step = -4; }
		else { p = base + (ptrdiff_t)d.left * pitch + (ptrdiff_t)(o->h - 1 - y) * 4; step = pitch; }
		for (x = d.left; x < d.right; x++, p += step) { *out++ = *(const unsigned int *)p; }
	}
	*c = d;
}

// Collects the dirty rectangles and the destinations of the move rectangles of the output's acquired frame.
// Returns 1 when they could not be read or cover more than half the output, and then the caller takes the whole output.
static int dxgi_read_changes(const dxgi_out *o, const DXGI_OUTDUPL_FRAME_INFO *fi)
{
	UINT used, i;
	long long area = 0;
	int c;

	if (fi->TotalMetadataBufferSize == 0) { return 1; }
	if (metaSize < fi->TotalMetadataBufferSize)
	{
		unsigned char *grown = (unsigned char *)realloc(meta, fi->TotalMetadataBufferSize);
		if (grown == NULL) { return 1; }
		meta = grown;
		metaSize = fi->TotalMetadataBufferSize;
	}
	// Moves first, the dirty rectangles reuse the buffer afterwards
	if (FAILED(o->dup->GetFrameMoveRects(metaSize, (DXGI_OUTDUPL_MOVE_RECT *)meta, &used))) { return 1; }
	for (i = 0; i < used / sizeof(DXGI_OUTDUPL_MOVE_RECT); i++)
	{
		if (dxgi_changed_add(o, &((DXGI_OUTDUPL_MOVE_RECT *)meta)[i].DestinationRect)) { return 1; }
	}
	if (FAILED(o->dup->GetFrameDirtyRects(metaSize, (RECT *)meta, &used))) { return 1; }
	for (i = 0; i < used / sizeof(RECT); i++)
	{
		if (dxgi_changed_add(o, &((RECT *)meta)[i])) { return 1; }
	}
	// Scattered changes in one window come as their bounding box, and copying a large part rectangle by rectangle
	// costs more than one copy of the whole output. Overlaps count twice, which only moves the switch a little earlier.
	for (c = o->first; c < changedCount; c++) { area += (long long)(changed[c].right - changed[c].left) * (changed[c].bottom - changed[c].top); }
	if (area * 2 > (long long)o->w * o->h) { return 1; }
	return 0;
}

// Acquires the output's next frame and copies what changed into dest, or all of it when dest does not hold the last frame.
// Returns 0 when dest holds the output's current picture, 1 when the output has no frame yet, -1 on failure
// and -2 when the frame has a size that the output's rotation does not explain.
static int dxgi_output_frame(dxgi_out *o, unsigned char *dest, int destWidth, int destHeight, int destCurrent)
{
	DXGI_OUTDUPL_FRAME_INFO fi;
	IDXGIResource *res = NULL;
	ID3D11Texture2D *tex = NULL;
	D3D11_MAPPED_SUBRESOURCE map;
	int result = 0;
	int i, r;
	HRESULT hr = o->dup->AcquireNextFrame(0, &fi, &res);

	// DXGI_ERROR_ACCESS_LOST on a desktop switch, UAC prompt or mode change
	if (FAILED(hr) && hr != DXGI_ERROR_WAIT_TIMEOUT) { return -1; }

	o->first = changedCount;
	o->full = !destCurrent;
	// A timeout means nothing changed, and a frame with LastPresentTime 0 only moved the pointer
	if (SUCCEEDED(hr) && fi.LastPresentTime.QuadPart != 0)
	{
		if (FAILED(res->QueryInterface(__uuidof(ID3D11Texture2D), (void **)&tex))) { result = -1; }
		else
		{
			D3D11_TEXTURE2D_DESC fd;
			tex->GetDesc(&fd);
			// The staging texture has the size that follows from the rotation. A frame of another size cannot be copied into it.
			if ((int)fd.Width != o->tw || (int)fd.Height != o->th) { result = -2; }
			// The whole output after a start, after GDI wrote dest and when the rectangles cannot be read
			else if (o->full || !o->hasFrame || dxgi_read_changes(o, &fi) != 0)
			{
				o->ctx->CopyResource(o->staging, tex);
				o->full = 1;
				changedCount = o->first;
			}
			for (i = o->first; result == 0 && i < changedCount; i++)
			{
				D3D11_BOX b = { (UINT)changed[i].left, (UINT)changed[i].top, 0, (UINT)changed[i].right, (UINT)changed[i].bottom, 1 };
				o->ctx->CopySubresourceRegion(o->staging, 0, b.left, b.top, 0, tex, 0, &b);
			}
			tex->Release();
			if (result == 0) { o->hasFrame = 1; }
		}
	}
	// Right after a start there may be no frame yet, and then GDI captures this one
	if (result == 0 && !o->hasFrame) { result = 1; }
	if (result == 0 && o->full)
	{
		// One rectangle for the whole output, so the caller checks this output's tiles only
		RECT all = { 0, 0, o->tw, o->th };
		changedCount = o->first;
		if (dxgi_changed_add(o, &all)) { result = -1; }
	}
	if (result == 0 && changedCount > o->first)
	{
		if (FAILED(o->ctx->Map(o->staging, 0, D3D11_MAP_READ, 0, &map))) { result = -1; }
		else
		{
			const unsigned char *src = (o->upright != NULL) ? o->upright : (const unsigned char *)map.pData;
			size_t pitch = (o->upright != NULL) ? (size_t)o->w * 4 : (size_t)map.RowPitch;
			// The tile code reads a bottom-up DIB with adjust_screen_size() rows, so screen row r goes to DIB row (destHeight - 1 - r)
			for (i = o->first; i < changedCount; i++)
			{
				RECT *c = &changed[i];
				if (o->upright != NULL) { dxgi_turn_rect(o, &map, c); }
				for (r = c->top; r < c->bottom; r++)
				{
					memcpy(dest + ((size_t)(destHeight - 1 - (r + o->oy)) * destWidth + c->left + o->ox) * 4, src + (size_t)r * pitch + (size_t)c->left * 4, (size_t)(c->right - c->left) * 4);
				}
				// The caller gets the rectangle in the coordinates of the captured rectangle
				OffsetRect(c, o->ox, o->oy);
			}
			o->ctx->Unmap(o->staging, 0);
		}
	}
	if (SUCCEEDED(hr))
	{
		res->Release();
		o->dup->ReleaseFrame();
	}
	return result;
}

extern "C" int dxgi_capture_frame(int x, int y, int w, int h, unsigned char *dest, int destWidth, int destHeight, int destCurrent, const RECT **rects, int *rectCount)
{
	int result = 0;
	int allFull = 1;
	int i;

	*rects = NULL;
	*rectCount = -1;
	if (unsupported || w > destWidth || h > destHeight) { return 1; }
	if (outCount > 0 && (x != dupX || y != dupY || w != dupW || h != dupH)) { dxgi_release_objects(); }
	if (outCount == 0)
	{
		if (failed && GetTickCount() - failedAt < failedWait) { return 1; }
		// The start takes longer than a BitBlt frame and has no frame ready right after it, so GDI takes this frame
		// and the start follows on the next one. Otherwise the first picture of a session waits for the start.
		if (!startNext) { startNext = 1; return 1; }
		startNext = 0;
		result = dxgi_capture_init(x, y, w, h);
		if (result != 0) { dxgi_capture_failed(result == 2 ? DXGI_RETRY_NO_OUTPUT_MS : DXGI_RETRY_MS); return 1; }
		failed = 0;
	}

	// Areas of the rectangle that no output covers are never written, so they keep the black they had
	changedCount = 0;
	for (i = 0; i < outCount && result == 0; i++)
	{
		result = dxgi_output_frame(&outs[i], dest, destWidth, destHeight, destCurrent);
		allFull &= outs[i].full;
	}
	if (result < 0) { dxgi_capture_failed(result == -2 ? DXGI_RETRY_NO_OUTPUT_MS : DXGI_RETRY_MS); return 1; }
	if (result == 0)
	{
		*rects = changed;
		*rectCount = allFull ? -1 : changedCount;
	}
	return result;
}

#endif
