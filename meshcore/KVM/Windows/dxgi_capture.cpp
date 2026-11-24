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

#if defined(_M_X64) || defined(__x86_64__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define DXGI_HALF_SSE2
#elif defined(_M_ARM64)
#include <arm64_neon.h>
#define DXGI_HALF_NEON
#elif defined(__aarch64__)
#include <arm_neon.h>
#define DXGI_HALF_NEON
#endif

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
	IDXGIResource *res;				// The acquired frame, held until its pixels are copied out
	D3D11_MAPPED_SUBRESOURCE map;
	const unsigned char *src;		// The output's picture in the desktop's orientation while mapped is set
	size_t pitch;
	int mapped;
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
	int first;						// Start and end of this output's part of changed[]
	int end;
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

// The scaling of the last frame: mapSrcW x mapSrcH screen pixels from the rectangle's corner fill mapDstW x mapDstH pixels of dest
static int mapSrcW = 0;
static int mapSrcH = 0;
static int mapDstW = 0;
static int mapDstH = 0;
static int scaled = 0;

// For every scaled column or row: the first screen pixel it shows, how many it shows, and the part of it each one fills.
// The parts are weights that add up to DXGI_TAP_ONE, with max entries for every column or row.
typedef struct dxgi_taps
{
	int *start;
	int *count;
	unsigned short *weight;
	int max;
	int src;						// The scaling the lists were made for
	int dst;
} dxgi_taps;
static dxgi_taps tapsX;
static dxgi_taps tapsY;
#define DXGI_TAP_ONE 4096

// The changed areas of the last frame, one output's part after the other. They are in the coordinates of the output's texture
// until the copy into dest, which leaves them in the coordinates of dest.
static unsigned char *meta = NULL;
static UINT metaSize = 0;
static RECT *changed = NULL;
static int changedCount = 0;
static int changedCapacity = 0;

#define DXGI_RETRY_MS 2000
// The longest wait for the first frame of an output in a scaled session, which starts with DXGI
#define DXGI_FIRST_FRAME_MS 200
// An output in the captured rectangle is only partly inside it, in a mode that cannot be duplicated or has frames of an unexpected size.
// A display change ends the wait through dxgi_capture_release(), and the retry finds a change of colour depth alone.
#define DXGI_RETRY_NO_OUTPUT_MS 30000
#define DXGI_SAFE_RELEASE(p) do { if ((p) != NULL) { (p)->Release(); (p) = NULL; } } while (0)

static void dxgi_taps_free(dxgi_taps *t)
{
	free(t->start);
	free(t->count);
	free(t->weight);
	memset(t, 0, sizeof(*t));
}

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
	dxgi_taps_free(&tapsX);
	dxgi_taps_free(&tapsY);
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

// Fills t for src screen pixels shown by dst scaled pixels. Returns 1 when the lists could not be allocated.
static int dxgi_taps_build(dxgi_taps *t, int src, int dst)
{
	int d, k;

	if (t->start != NULL && t->src == src && t->dst == dst) { return 0; }
	dxgi_taps_free(t);
	t->max = (src + dst - 1) / dst + 1;
	t->start = (int *)malloc(sizeof(int) * dst);
	t->count = (int *)malloc(sizeof(int) * dst);
	t->weight = (unsigned short *)malloc(sizeof(unsigned short) * dst * t->max);
	if (t->start == NULL || t->count == NULL || t->weight == NULL) { dxgi_taps_free(t); return 1; }
	for (d = 0; d < dst; d++)
	{
		// In units of 1 / dst of a screen pixel, scaled pixel d covers lo up to hi, and screen pixel j covers j * dst up to (j + 1) * dst
		long long lo = (long long)d * src, hi = lo + src;
		int first = (int)(lo / dst), last = (int)((hi - 1) / dst);
		unsigned short *w = t->weight + (size_t)d * t->max;
		int sum = 0, big = 0;
		for (k = 0; k <= last - first; k++)
		{
			long long a = (long long)(first + k) * dst, b = a + dst;
			long long part = (b < hi ? b : hi) - (a > lo ? a : lo);
			w[k] = (unsigned short)(part * DXGI_TAP_ONE / src);
			sum += w[k];
			if (w[k] > w[big]) { big = k; }
		}
		// The rounding goes to the screen pixel that fills the most, so the weights add up to exactly DXGI_TAP_ONE
		w[big] = (unsigned short)(w[big] + DXGI_TAP_ONE - sum);
		t->start[d] = first;
		t->count[d] = last - first + 1;
	}
	t->src = src;
	t->dst = dst;
	return 0;
}

// The pixel at (x, y) of the captured rectangle in the picture of the output that shows it, or NULL where no output is
static const unsigned char *dxgi_pixel(int x, int y)
{
	for (int i = 0; i < outCount; i++)
	{
		const dxgi_out *o = &outs[i];
		if (x >= o->ox && x < o->ox + o->w && y >= o->oy && y < o->oy + o->h) { return o->src + (size_t)(y - o->oy) * o->pitch + (size_t)(x - o->ox) * 4; }
	}
	return NULL;
}

// One scaled pixel whose screen pixels are not all in one output, at the edge of an output or of the screen.
// The screen pixels that exist share the whole weight, so an edge next to nothing does not turn dark.
static void dxgi_scale_edge(int dx, int dy, unsigned char *out)
{
	const unsigned short *wx = tapsX.weight + (size_t)dx * tapsX.max;
	const unsigned short *wy = tapsY.weight + (size_t)dy * tapsY.max;
	unsigned int b = 0, g = 0, r = 0, total = 0;
	int j, k;

	for (j = 0; j < tapsY.count[dy]; j++)
	{
		for (k = 0; k < tapsX.count[dx]; k++)
		{
			const unsigned char *p = dxgi_pixel(tapsX.start[dx] + k, tapsY.start[dy] + j);
			unsigned int w = (unsigned int)wx[k] * wy[j];
			if (p == NULL) { continue; }
			b += w * p[0];
			g += w * p[1];
			r += w * p[2];
			total += w;
		}
	}
	if (total == 0) { return; }
	out[0] = (unsigned char)(b / total);
	out[1] = (unsigned char)(g / total);
	out[2] = (unsigned char)(r / total);
	out[3] = 0xFF;
}

// Writes n pixels, each the average of a 2x2 block from the rows p and q, rounded down as the weighted average does
static void dxgi_half_row(const unsigned char *p, const unsigned char *q, unsigned char *out, int n)
{
	int k = 0;
#if defined(DXGI_HALF_SSE2)
	const __m128i zero = _mm_setzero_si128();
	const __m128i alpha = _mm_set1_epi32((int)0xFF000000);
	for (; k + 4 <= n; k += 4, p += 32, q += 32, out += 16)
	{
		__m128i a0 = _mm_loadu_si128((const __m128i *)p), a1 = _mm_loadu_si128((const __m128i *)(p + 16));
		__m128i b0 = _mm_loadu_si128((const __m128i *)q), b1 = _mm_loadu_si128((const __m128i *)(q + 16));
		// 16 bit sums of the two rows, two screen pixels in each register
		__m128i v0 = _mm_add_epi16(_mm_unpacklo_epi8(a0, zero), _mm_unpacklo_epi8(b0, zero));
		__m128i v1 = _mm_add_epi16(_mm_unpackhi_epi8(a0, zero), _mm_unpackhi_epi8(b0, zero));
		__m128i v2 = _mm_add_epi16(_mm_unpacklo_epi8(a1, zero), _mm_unpacklo_epi8(b1, zero));
		__m128i v3 = _mm_add_epi16(_mm_unpackhi_epi8(a1, zero), _mm_unpackhi_epi8(b1, zero));
		// The second pixel of each register is added to the first, which gives one scaled pixel in the low half
		v0 = _mm_add_epi16(v0, _mm_srli_si128(v0, 8));
		v1 = _mm_add_epi16(v1, _mm_srli_si128(v1, 8));
		v2 = _mm_add_epi16(v2, _mm_srli_si128(v2, 8));
		v3 = _mm_add_epi16(v3, _mm_srli_si128(v3, 8));
		v0 = _mm_srli_epi16(_mm_unpacklo_epi64(v0, v1), 2);
		v2 = _mm_srli_epi16(_mm_unpacklo_epi64(v2, v3), 2);
		_mm_storeu_si128((__m128i *)out, _mm_or_si128(_mm_packus_epi16(v0, v2), alpha));
	}
#elif defined(DXGI_HALF_NEON)
	for (; k + 8 <= n; k += 8, p += 64, q += 64, out += 32)
	{
		// One register for each colour of 16 screen pixels, added in pairs and then with the row below
		uint8x16x4_t a = vld4q_u8(p), b = vld4q_u8(q);
		uint8x8x4_t o;
		o.val[0] = vshrn_n_u16(vaddq_u16(vpaddlq_u8(a.val[0]), vpaddlq_u8(b.val[0])), 2);
		o.val[1] = vshrn_n_u16(vaddq_u16(vpaddlq_u8(a.val[1]), vpaddlq_u8(b.val[1])), 2);
		o.val[2] = vshrn_n_u16(vaddq_u16(vpaddlq_u8(a.val[2]), vpaddlq_u8(b.val[2])), 2);
		o.val[3] = vdup_n_u8(0xFF);
		vst4_u8(out, o);
	}
#endif
	for (; k < n; k++, p += 8, q += 8, out += 4)
	{
		out[0] = (unsigned char)((p[0] + p[4] + q[0] + q[4]) >> 2);
		out[1] = (unsigned char)((p[1] + p[5] + q[1] + q[5]) >> 2);
		out[2] = (unsigned char)((p[2] + p[6] + q[2] + q[6]) >> 2);
		out[3] = 0xFF;
	}
}

// Writes the scaled rectangle s of dest. A scaled pixel is the average of the screen pixels it shows, each counted by the part of it inside.
// The pixels whose screen pixels are all in the output o come straight from its picture, the others go through dxgi_scale_edge().
static void dxgi_scale_rect(const dxgi_out *o, unsigned char *dest, int destWidth, int destHeight, const RECT *s)
{
	int half = (mapSrcW == 2 * mapDstW && mapSrcH == 2 * mapDstH);
	int fl = s->left, fr = s->right, ft = s->top, fb = s->bottom;
	int dx, dy, j, k;

	while (fl < fr && tapsX.start[fl] < o->ox) { fl++; }
	while (fr > fl && tapsX.start[fr - 1] + tapsX.count[fr - 1] > o->ox + o->w) { fr--; }
	while (ft < fb && tapsY.start[ft] < o->oy) { ft++; }
	while (fb > ft && tapsY.start[fb - 1] + tapsY.count[fb - 1] > o->oy + o->h) { fb--; }
	for (dy = s->top; dy < s->bottom; dy++)
	{
		unsigned char *out = dest + ((size_t)(destHeight - 1 - dy) * destWidth + s->left) * 4;
		int from = (dy >= ft && dy < fb) ? fl : s->right;
		int to = (dy >= ft && dy < fb) ? fr : s->right;

		for (dx = s->left; dx < from; dx++, out += 4) { dxgi_scale_edge(dx, dy, out); }
		if (from < to)
		{
			// The first screen row of this scaled row, placed so that a column of the captured rectangle can be added to it
			const unsigned char *rows = o->src + (ptrdiff_t)(tapsY.start[dy] - o->oy) * (ptrdiff_t)o->pitch - (ptrdiff_t)o->ox * 4;
			const unsigned short *wy = tapsY.weight + (size_t)dy * tapsY.max;
			int ny = tapsY.count[dy];

			if (half)
			{
				// At exactly half size every weight is the same, which leaves a plain average of four pixels
				dxgi_half_row(rows + (ptrdiff_t)tapsX.start[from] * 4, rows + (ptrdiff_t)tapsX.start[from] * 4 + o->pitch, out, to - from);
				out += (size_t)(to - from) * 4;
			}
			else
			{
				for (dx = from; dx < to; dx++, out += 4)
				{
					const unsigned short *wx = tapsX.weight + (size_t)dx * tapsX.max;
					const unsigned char *col = rows + (ptrdiff_t)tapsX.start[dx] * 4;
					int nx = tapsX.count[dx];
					unsigned int b = 0, g = 0, r = 0;
					for (j = 0; j < ny; j++, col += o->pitch)
					{
						const unsigned char *p = col;
						unsigned int rb = 0, rg = 0, rr = 0;
						for (k = 0; k < nx; k++, p += 4) { rb += wx[k] * p[0]; rg += wx[k] * p[1]; rr += wx[k] * p[2]; }
						b += wy[j] * rb;
						g += wy[j] * rg;
						r += wy[j] * rr;
					}
					// Both weights add up to DXGI_TAP_ONE, so the sums are the colour times its square and fit 32 bits
					out[0] = (unsigned char)(b >> 24);
					out[1] = (unsigned char)(g >> 24);
					out[2] = (unsigned char)(r >> 24);
					out[3] = 0xFF;
				}
			}
		}
		for (dx = to; dx < s->right; dx++, out += 4) { dxgi_scale_edge(dx, dy, out); }
	}
}

// Acquires the output's next frame and copies what changed into its staging texture, or all of it when dest does not hold the last frame.
// Returns 0 when the staging texture holds the output's current picture, 1 when the output has no frame yet, -1 on failure
// and -2 when the frame has a size that the output's rotation does not explain.
static int dxgi_output_acquire(dxgi_out *o, int destCurrent)
{
	DXGI_OUTDUPL_FRAME_INFO fi;
	ID3D11Texture2D *tex = NULL;
	int i;
	// A scaled session has no GDI frame before the first DXGI frame, so that one is waited for
	HRESULT hr = o->dup->AcquireNextFrame((scaled && !o->hasFrame) ? DXGI_FIRST_FRAME_MS : 0, &fi, &o->res);

	// DXGI_ERROR_ACCESS_LOST on a desktop switch, UAC prompt or mode change
	if (FAILED(hr)) { o->res = NULL; }
	if (FAILED(hr) && hr != DXGI_ERROR_WAIT_TIMEOUT) { return -1; }

	o->first = o->end = changedCount;
	o->full = !destCurrent;
	// A timeout means nothing changed, and a frame with LastPresentTime 0 only moved the pointer
	if (SUCCEEDED(hr) && fi.LastPresentTime.QuadPart != 0)
	{
		D3D11_TEXTURE2D_DESC fd;
		if (FAILED(o->res->QueryInterface(__uuidof(ID3D11Texture2D), (void **)&tex))) { return -1; }
		tex->GetDesc(&fd);
		// The staging texture has the size that follows from the rotation. A frame of another size cannot be copied into it.
		if ((int)fd.Width != o->tw || (int)fd.Height != o->th) { tex->Release(); return -2; }
		// The whole output after a start, after GDI wrote dest and when the rectangles cannot be read
		if (o->full || !o->hasFrame || dxgi_read_changes(o, &fi) != 0)
		{
			o->ctx->CopyResource(o->staging, tex);
			o->full = 1;
			changedCount = o->first;
		}
		for (i = o->first; i < changedCount; i++)
		{
			D3D11_BOX b = { (UINT)changed[i].left, (UINT)changed[i].top, 0, (UINT)changed[i].right, (UINT)changed[i].bottom, 1 };
			o->ctx->CopySubresourceRegion(o->staging, 0, b.left, b.top, 0, tex, 0, &b);
		}
		tex->Release();
		o->hasFrame = 1;
	}
	// Right after a start there may be no frame yet, and then GDI captures this one
	if (!o->hasFrame) { return 1; }
	if (o->full)
	{
		// One rectangle for the whole output, so the caller checks this output's tiles only
		RECT all = { 0, 0, o->tw, o->th };
		changedCount = o->first;
		if (dxgi_changed_add(o, &all)) { return -1; }
	}
	o->end = changedCount;
	return 0;
}

// Maps the output's staging texture and sets its changed rectangles to the coordinates of the captured rectangle.
// A rotated output is turned into its upright copy on the way. Returns -1 when the texture could not be mapped.
static int dxgi_output_map(dxgi_out *o)
{
	int i;

	if (FAILED(o->ctx->Map(o->staging, 0, D3D11_MAP_READ, 0, &o->map))) { return -1; }
	o->mapped = 1;
	o->src = (o->upright != NULL) ? o->upright : (const unsigned char *)o->map.pData;
	o->pitch = (o->upright != NULL) ? (size_t)o->w * 4 : (size_t)o->map.RowPitch;
	for (i = o->first; i < o->end; i++)
	{
		if (o->upright != NULL) { dxgi_turn_rect(o, &o->map, &changed[i]); }
		OffsetRect(&changed[i], o->ox, o->oy);
	}
	return 0;
}

// Copies the output's changed rectangles into dest, scaled when the session is, and leaves them in the coordinates of dest
static void dxgi_output_copy(const dxgi_out *o, unsigned char *dest, int destWidth, int destHeight)
{
	int i, r;

	// The tile code reads a bottom-up DIB with adjust_screen_size() rows, so picture row r goes to DIB row (destHeight - 1 - r)
	for (i = o->first; i < o->end; i++)
	{
		RECT *c = &changed[i];
		if (!scaled)
		{
			for (r = c->top; r < c->bottom; r++)
			{
				memcpy(dest + ((size_t)(destHeight - 1 - r) * destWidth + c->left) * 4, o->src + (size_t)(r - o->oy) * o->pitch + (size_t)(c->left - o->ox) * 4, (size_t)(c->right - c->left) * 4);
			}
			continue;
		}
		// Every scaled pixel that shows a part of the rectangle, also the ones it shares with the output next to it
		RECT s;
		s.left = (LONG)((long long)c->left * mapDstW / mapSrcW);
		s.top = (LONG)((long long)c->top * mapDstH / mapSrcH);
		s.right = (LONG)(((long long)c->right * mapDstW + mapSrcW - 1) / mapSrcW);
		s.bottom = (LONG)(((long long)c->bottom * mapDstH + mapSrcH - 1) / mapSrcH);
		// The span can end a part of a scaled pixel before the screen does, and dest ends with the span
		if (s.right > mapDstW) { s.right = mapDstW; }
		if (s.bottom > mapDstH) { s.bottom = mapDstH; }
		*c = s;
		if (s.right > s.left && s.bottom > s.top) { dxgi_scale_rect(o, dest, destWidth, destHeight, &s); }
	}
}

// Unmaps the output's staging texture and gives its frame back
static void dxgi_output_done(dxgi_out *o)
{
	if (o->mapped) { o->ctx->Unmap(o->staging, 0); o->mapped = 0; }
	if (o->res != NULL)
	{
		o->res->Release();
		o->res = NULL;
		o->dup->ReleaseFrame();
	}
}

extern "C" int dxgi_capture_frame(int x, int y, int w, int h, int spanW, int spanH, unsigned char *dest, int destWidth, int destHeight, int destCurrent, const RECT **rects, int *rectCount)
{
	int result = 0;
	int allFull = 1;
	int i;

	*rects = NULL;
	*rectCount = -1;
	// A span smaller than dest would enlarge the picture, which stays on GDI
	if (unsupported || destWidth > spanW || destHeight > spanH) { return 1; }
	mapSrcW = spanW;
	mapSrcH = spanH;
	mapDstW = destWidth;
	mapDstH = destHeight;
	scaled = (spanW != destWidth || spanH != destHeight);
	// Unscaled rows are copied as they are, so the rectangle has to fit. A scaled copy is limited to dest instead.
	if (!scaled && (w > destWidth || h > destHeight)) { return 1; }
	if (outCount > 0 && (x != dupX || y != dupY || w != dupW || h != dupH)) { dxgi_release_objects(); }
	if (outCount == 0)
	{
		if (failed && GetTickCount() - failedAt < failedWait) { return 1; }
		// The start takes longer than a BitBlt frame and has no frame ready right after it, so GDI takes this frame
		// and the start follows on the next one. Otherwise the first picture of a session waits for the start.
		// A scaled session starts at once: its GDI frame has other pixels than a DXGI frame, so the picture would be sent twice.
		if (!scaled && !startNext) { startNext = 1; return 1; }
		startNext = 0;
		result = dxgi_capture_init(x, y, w, h);
		if (result != 0) { dxgi_capture_failed(result == 2 ? DXGI_RETRY_NO_OUTPUT_MS : DXGI_RETRY_MS); return 1; }
		failed = 0;
	}
	// After the start, which releases the lists of an earlier scaling
	if (scaled && (dxgi_taps_build(&tapsX, spanW, destWidth) != 0 || dxgi_taps_build(&tapsY, spanH, destHeight) != 0)) { return 1; }

	// Areas of the rectangle that no output covers are never written, so they keep the black they had
	changedCount = 0;
	for (i = 0; i < outCount; i++) { outs[i].first = outs[i].end = 0; }
	for (i = 0; i < outCount && result == 0; i++)
	{
		result = dxgi_output_acquire(&outs[i], destCurrent);
		allFull &= outs[i].full;
	}
	if (result == 0 && changedCount > 0)
	{
		// A scaled pixel at the edge of an output also shows pixels of the output next to it, so a scaled frame maps all of them
		for (i = 0; i < outCount && result == 0; i++) { if (scaled || outs[i].end > outs[i].first) { result = dxgi_output_map(&outs[i]); } }
		for (i = 0; i < outCount && result == 0; i++) { dxgi_output_copy(&outs[i], dest, destWidth, destHeight); }
	}
	for (i = 0; i < outCount; i++) { dxgi_output_done(&outs[i]); }
	if (result < 0) { dxgi_capture_failed(result == -2 ? DXGI_RETRY_NO_OUTPUT_MS : DXGI_RETRY_MS); return 1; }
	if (result == 0)
	{
		*rects = changed;
		*rectCount = allFull ? -1 : changedCount;
	}
	return result;
}

#endif
