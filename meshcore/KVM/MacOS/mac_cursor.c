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

// The captured picture has no pointer in it, and the viewer draws its own, so the viewer is told which shape macOS shows.
// AppKit has the only API for the system pointer, +[NSCursor currentSystemCursor]. It is loaded at run time and called through the
// Objective-C runtime, so only the KVM processes load it and the build needs no Objective-C and no extra framework.

#include "mac_cursor.h"
#include "mac_inputlock.h"
#include "../../meshdefines.h"
#include <CoreGraphics/CoreGraphics.h>
#include <objc/objc.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Positions in MeshCentral's mouseCursors list (agent-desktop-0.0.2.js), which is what message 88 carries
enum
{
	KVM_CURSOR_DEFAULT = 0, KVM_CURSOR_CROSSHAIR = 2, KVM_CURSOR_POINTER = 3, KVM_CURSOR_TEXT = 5,
	KVM_CURSOR_MOVE = 7, KVM_CURSOR_NESW = 8, KVM_CURSOR_NS = 9, KVM_CURSOR_NWSE = 10, KVM_CURSOR_EW = 11, KVM_CURSOR_ALIAS = 12,
	KVM_CURSOR_NOTALLOWED = 15, KVM_CURSOR_COLRESIZE = 16, KVM_CURSOR_ROWRESIZE = 17, KVM_CURSOR_COPY = 18, KVM_CURSOR_ZOOMIN = 19, KVM_CURSOR_ZOOMOUT = 20
};

typedef struct kvm_cursor_sig
{
	double hotX, hotY, width, height;
	uint64_t hash;
	int viewer;
} kvm_cursor_sig;

static id(*p_getClass)(const char *name);
static SEL(*p_sel)(const char *name);
static void *p_msgSend;
static void *(*p_poolPush)(void);
static void (*p_poolPop)(void *pool);
static id p_NSCursor, p_NSBitmapImageRep, p_NSGraphicsContext, p_deviceRGB;
static kvm_cursor_sig g_cursorKnown[64];
static int g_cursorKnownCount = 0;

#define KVM_MSG(ret, ...) ((ret (*)(id, SEL, ##__VA_ARGS__))p_msgSend)

// Hot spot, size and a hash of the pointer image drawn at its size, which told all shapes apart on macOS 26.7 (arrow, text, hand, resize)
static int kvm_cursor_signature(id cursor, kvm_cursor_sig *sig)
{
	id image, rep, ctx;
	CGPoint hot;
	CGSize size;
	unsigned char *data;
	long rowBytes, rows, i;

	if (cursor == NULL || (image = KVM_MSG(id)(cursor, p_sel("image"))) == NULL) { return(0); }
	hot = KVM_MSG(CGPoint)(cursor, p_sel("hotSpot"));
	size = KVM_MSG(CGSize)(image, p_sel("size"));
	if (size.width < 1 || size.height < 1 || size.width > 256 || size.height > 256) { return(0); }

	rep = KVM_MSG(id)(p_NSBitmapImageRep, p_sel("alloc"));
	rep = KVM_MSG(id, unsigned char**, long, long, long, long, BOOL, BOOL, id, long, long)(rep, p_sel("initWithBitmapDataPlanes:pixelsWide:pixelsHigh:bitsPerSample:samplesPerPixel:hasAlpha:isPlanar:colorSpaceName:bytesPerRow:bitsPerPixel:"),
		NULL, (long)size.width, (long)size.height, 8, 4, YES, NO, p_deviceRGB, 0, 32);
	if (rep == NULL) { return(0); }

	KVM_MSG(void)(p_NSGraphicsContext, p_sel("saveGraphicsState"));
	ctx = KVM_MSG(id, id)(p_NSGraphicsContext, p_sel("graphicsContextWithBitmapImageRep:"), rep);
	if (ctx == NULL)
	{
		// Nothing would be drawn, and every pointer would hash the same
		KVM_MSG(void)(p_NSGraphicsContext, p_sel("restoreGraphicsState"));
		KVM_MSG(void)(rep, p_sel("release"));
		return(0);
	}
	KVM_MSG(void, id)(p_NSGraphicsContext, p_sel("setCurrentContext:"), ctx);
	KVM_MSG(void, CGRect, CGRect, unsigned long, double)(image, p_sel("drawInRect:fromRect:operation:fraction:"), CGRectMake(0, 0, size.width, size.height), CGRectZero, 1, 1.0);
	KVM_MSG(void)(p_NSGraphicsContext, p_sel("restoreGraphicsState"));

	memset(sig, 0, sizeof(*sig));
	sig->hotX = hot.x; sig->hotY = hot.y; sig->width = size.width; sig->height = size.height;
	sig->hash = 1469598103934665603ULL;
	data = KVM_MSG(unsigned char*)(rep, p_sel("bitmapData"));
	rowBytes = KVM_MSG(long)(rep, p_sel("bytesPerRow"));
	rows = KVM_MSG(long)(rep, p_sel("pixelsHigh"));
	for (i = 0; data != NULL && i < rowBytes * rows; ++i) { sig->hash = (sig->hash ^ data[i]) * 1099511628211ULL; }
	KVM_MSG(void)(rep, p_sel("release"));
	return(data != NULL);
}

static void kvm_cursor_learn(id cursor, int viewer)
{
	kvm_cursor_sig sig;
	if (g_cursorKnownCount >= (int)(sizeof(g_cursorKnown) / sizeof(g_cursorKnown[0])) || !kvm_cursor_signature(cursor, &sig)) { return; }
	sig.viewer = viewer;
	g_cursorKnown[g_cursorKnownCount++] = sig;
}

static int kvm_cursor_init(void)
{
	static int state = 0;
	static const struct { const char *selector; int viewer; } standard[] =
	{
		{ "arrowCursor", KVM_CURSOR_DEFAULT }, { "IBeamCursor", KVM_CURSOR_TEXT }, { "IBeamCursorForVerticalLayout", KVM_CURSOR_TEXT },
		{ "pointingHandCursor", KVM_CURSOR_POINTER }, { "crosshairCursor", KVM_CURSOR_CROSSHAIR }, { "openHandCursor", KVM_CURSOR_MOVE },
		{ "closedHandCursor", KVM_CURSOR_MOVE }, { "resizeLeftRightCursor", KVM_CURSOR_COLRESIZE }, { "resizeUpDownCursor", KVM_CURSOR_ROWRESIZE },
		{ "resizeLeftCursor", KVM_CURSOR_EW }, { "resizeRightCursor", KVM_CURSOR_EW }, { "resizeUpCursor", KVM_CURSOR_NS },
		{ "resizeDownCursor", KVM_CURSOR_NS }, { "operationNotAllowedCursor", KVM_CURSOR_NOTALLOWED }, { "dragCopyCursor", KVM_CURSOR_COPY },
		{ "dragLinkCursor", KVM_CURSOR_ALIAS }, { "zoomInCursor", KVM_CURSOR_ZOOMIN }, { "zoomOutCursor", KVM_CURSOR_ZOOMOUT }
	};
	// Window edges through frameResizeCursorFromPosition:inDirections: (positions top 1, left 2, bottom 4, right 8, corners combined)
	static const struct { long position; int viewer; } frame[] =
	{
		{ 1, KVM_CURSOR_NS }, { 4, KVM_CURSOR_NS }, { 2, KVM_CURSOR_EW }, { 8, KVM_CURSOR_EW },
		{ 3, KVM_CURSOR_NWSE }, { 12, KVM_CURSOR_NWSE }, { 9, KVM_CURSOR_NESW }, { 6, KVM_CURSOR_NESW }
	};
	void *objc, *appkit, *pool;
	id *deviceRGB, app;
	SEL frameSel;
	size_t i;
	long direction;

	if (state != 0) { return(state > 0); }
	state = -1;
	if ((objc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY)) == NULL || (appkit = dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", RTLD_LAZY)) == NULL) { return(0); }
	p_getClass = (id(*)(const char*))dlsym(objc, "objc_getClass");
	p_sel = (SEL(*)(const char*))dlsym(objc, "sel_registerName");
	p_msgSend = dlsym(objc, "objc_msgSend");
	p_poolPush = (void*(*)(void))dlsym(objc, "objc_autoreleasePoolPush");
	p_poolPop = (void(*)(void*))dlsym(objc, "objc_autoreleasePoolPop");
	deviceRGB = (id*)dlsym(appkit, "NSDeviceRGBColorSpace");
	if (p_getClass == NULL || p_sel == NULL || p_msgSend == NULL || p_poolPush == NULL || p_poolPop == NULL || deviceRGB == NULL) { return(0); }
	p_NSCursor = p_getClass("NSCursor");
	p_NSBitmapImageRep = p_getClass("NSBitmapImageRep");
	p_NSGraphicsContext = p_getClass("NSGraphicsContext");
	p_deviceRGB = *deviceRGB;
	if (p_NSCursor == NULL || p_NSBitmapImageRep == NULL || p_NSGraphicsContext == NULL || p_getClass("NSApplication") == NULL) { return(0); }

	pool = p_poolPush();
	// arrowCursor and IBeamCursor are nil until the process has an NSApplication (measured on macOS 26.7), and policy 2, prohibited, keeps it out of the Dock
	app = KVM_MSG(id)(p_getClass("NSApplication"), p_sel("sharedApplication"));
	if (app != NULL) { KVM_MSG(BOOL, long)(app, p_sel("setActivationPolicy:"), 2); }

	for (i = 0; i < sizeof(standard) / sizeof(standard[0]); ++i) { kvm_cursor_learn(KVM_MSG(id)(p_NSCursor, p_sel(standard[i].selector)), standard[i].viewer); }
	// Directions inward 1, outward 2, both 3, the edge shows one or two arrows depending on whether the window can still shrink or grow
	frameSel = p_sel("frameResizeCursorFromPosition:inDirections:");
	for (i = 0; i < sizeof(frame) / sizeof(frame[0]); ++i)
	{
		for (direction = 1; direction <= 3; ++direction) { kvm_cursor_learn(KVM_MSG(id, long, long)(p_NSCursor, frameSel, frame[i].position, direction), frame[i].viewer); }
	}
	p_poolPop(pool);
	state = 1;
	return(1);
}

int kvm_cursor_current(void)
{
	kvm_cursor_sig sig;
	void *pool;
	int i, ok, ret = -1;

	if (!kvm_cursor_init()) { return(-1); }
	pool = p_poolPush();
	ok = kvm_cursor_signature(KVM_MSG(id)(p_NSCursor, p_sel("currentSystemCursor")), &sig);
	p_poolPop(pool);
	if (!ok) { return(-1); }

	for (i = 0; i < g_cursorKnownCount; ++i)
	{
		if (g_cursorKnown[i].hash == sig.hash && g_cursorKnown[i].width == sig.width && g_cursorKnown[i].height == sig.height &&
			g_cursorKnown[i].hotX == sig.hotX && g_cursorKnown[i].hotY == sig.hotY) { ret = g_cursorKnown[i].viewer; break; }
	}
	if (ret < 0)
	{
		// Applications draw their own text pointer, Terminal's is 9x18 with the hot spot in its middle, so a narrow pointer held by its middle counts as text
		ret = (sig.width * 2 <= sig.height && sig.hotX * 2 >= sig.width - 2 && sig.hotX * 2 <= sig.width + 2) ? KVM_CURSOR_TEXT : KVM_CURSOR_DEFAULT;
	}
	return(ret);
}

// Time between pointer reads, so a shape change can trail the picture that shows it by about this long
#define KVM_CURSOR_INTERVAL_MS 100
// For this long after a mouse event from the viewer the pointer is read on every pass, so its shape changes with the picture
#define KVM_CURSOR_ACTIVE_MS 1000

static int g_cursorSent = -1;
static uint64_t g_cursorMouseMs = 0;

static uint64_t kvm_cursor_now(void)
{
	return(clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000);
}

void kvm_cursor_reset(void)
{
	g_cursorSent = -1;
}

// Called on the input thread, read on the capture thread
void kvm_cursor_moved(void)
{
	__atomic_store_n(&g_cursorMouseMs, kvm_cursor_now(), __ATOMIC_RELAXED);
}

void kvm_cursor_check(ILibQueue queue)
{
	static uint64_t lastCheck = 0;
	uint64_t now = kvm_cursor_now();
	unsigned char *buffer;
	int cur;

	// The pointer belongs to the local user during the backoff, so its shape is not the viewer's business
	if (kvm_local_input_active()) { return; }
	// Compared as a sum, because a mouse event stored after now was read would make now minus it wrap around
	if (now >= __atomic_load_n(&g_cursorMouseMs, __ATOMIC_RELAXED) + KVM_CURSOR_ACTIVE_MS && now - lastCheck < KVM_CURSOR_INTERVAL_MS) { return; }
	lastCheck = now;
	if ((cur = kvm_cursor_current()) < 0 || cur == g_cursorSent) { return; }
	g_cursorSent = cur;

	buffer = (unsigned char*)ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);
	buffer[4] = (unsigned char)cur;
	ILibQueue_Lock(queue);
	ILibQueue_EnQueue(queue, buffer);
	ILibQueue_UnLock(queue);
}
