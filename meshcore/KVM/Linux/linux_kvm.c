/*   
Copyright 2010 - 2011 Intel Corporation

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

#include "linux_kvm.h"
#include "linux_kvm_wayland.h"
#include "linux_kvm_drm.h"
#include "linux_kvm_recovery.h"
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibAsyncServerSocket.h"
#include "microstack/ILibProcessPipe.h"
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include "linux_kvm_bridge_auth.h"
#include "linux_kvm_capture.h"
#if defined(__linux__)
#include "linux_kvm_capture_helper.h"
#include <sys/socket.h>
#endif

// The process-pipe implementation exposes this lifecycle operation internally but its public
// header does not currently declare it; agentcore.c uses the same declaration for viewer teardown.
extern void ILibProcessPipe_FreePipe(ILibProcessPipe_Pipe pipeObject);
#include <pwd.h>
#include <grp.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xrandr.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <dlfcn.h>

#if !defined(_FREEBSD)
	#include <sys/prctl.h>
#endif

#include "linux_events.h"
#include "linux_compression.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
extern uint32_t crc32c(uint32_t crc, const unsigned char* buf, uint32_t len);
extern char* g_ILibCrashDump_path;

typedef struct kvm_keydata
{
	int delay;
	uint8_t up;
	uint16_t data;
}kvm_keydata;

typedef enum KVM_MouseCursors
{
	KVM_MouseCursor_NOCHANGE = -1,
	KVM_MouseCursor_ARROW = 0,
	KVM_MouseCursor_APPSTARTING = 1,
	KVM_MouseCursor_CROSS = 2,
	KVM_MouseCursor_HAND = 3,
	KVM_MouseCursor_HELP = 4,
	KVM_MouseCursor_IBEAM = 5,
	KVM_MouseCursor_NO = 6,
	KVM_MouseCursor_SIZEALL = 7,
	KVM_MouseCursor_SIZENESW = 8,
	KVM_MouseCursor_SIZENS = 9,
	KVM_MouseCursor_SIZENWSE = 10,
	KVM_MouseCursor_SIZEWE = 11,
	KVM_MouseCursor_UPARROW = 12,
	KVM_MouseCursor_WAIT = 13,
	KVM_MouseCursor_NONE = 14,
	KVM_MouseCursor_NOTALLOWED = 15
}KVM_MouseCursors;

typedef struct _XkbStateNotifyEvent 
{
	int 			type;				/* XkbAnyEvent */
	unsigned long 	serial;				/* # of last req processed by server */
	int 			send_event;			/* is this from a SendEvent request? */
	void			*display;			/* Display the event was read from */
	uint64_t 		time;				/* milliseconds */
	int 			xkb_type;			/* XkbStateNotify */
	int 			device;				/* device ID */
	unsigned int 	changed;			/* mask of changed state components */
	int 			group;				/* keyboard group */
	int 			base_group;			/* base keyboard group */
	int 			latched_group;		/* latched keyboard group */
	int 			locked_group;		/* locked keyboard group */
	unsigned int	mods;				/* modifier state */
	unsigned int 	base_mods;			/* base modifier state */
	unsigned int	latched_mods;		/* latched modifiers */
	unsigned int	locked_mods;		/* locked modifiers */
	int 			compat_state;		/* compatibility state */
	unsigned char	grab_mods;			/* mods used for grabs */
	unsigned char	compat_grab_mods;	/* grab mods for non-XKB clients */
	unsigned char	lookup_mods;		/* mods sent to clients */
	unsigned char	compat_lookup_mods; /* mods sent to non-XKB clients */
	int 			ptr_buttons;		/* pointer button state */
	char			keycode;			/* keycode that caused the change */
	char 			event_type;			/* KeyPress or KeyRelease */
	char 			req_major;			/* Major opcode of request */
	char 			req_minor;			/* Minor opcode of request */
} XkbStateNotifyEvent;

int curcursor = KVM_MouseCursor_HELP;
int SLAVELOG = 0;

int SCREEN_NUM = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int KVM_OUTPUT_WIDTH = 0, KVM_OUTPUT_HEIGHT = 0;
int kvm_force_refresh = 1;
int kvm_registered_uid = -1;
int SCALING_FACTOR = 1024;		// Scaling factor, 1024 = 100%
int SCALING_FACTOR_NEW = 1024;	// Desired scaling factor, 1024 = 100%
int FRAME_RATE_TIMER = 0;
struct tileInfo_t **g_tileInfo = NULL;
pthread_t kvmthread = (pthread_t)NULL;
Display *eventdisplay = NULL;
int g_remotepause = 0;
int g_pause = 0;
uint32_t g_restartcount = 0;
int g_totalRestartCount = 0;
int g_shutdown = 0;
int change_display = 0;
pid_t g_slavekvm = 0;
int master2slave[2] = { -1, -1 };
int slave2master[2] = { -1, -1 };
static void *g_kvmChain = NULL;
char CURRENT_XDISPLAY[256];
int CURRENT_DISPLAY_ID = -1;

kvm_monitor_info g_monitors[KVM_MAX_MONITORS];
int g_monitor_count = 0;
int SCREEN_SEL = 0;         // 0 = all monitors, 1..N = specific physical monitor
int SCREEN_SEL_TARGET = 0;
int CAPTURE_X = 0;          // top-left of capture region (0 if all monitors)
int CAPTURE_Y = 0;
int VSCREEN_WIDTH = 0;      // full virtual desktop width (all monitors combined)
int VSCREEN_HEIGHT = 0;

FILE *logFile = NULL;
int g_enableEvents = 0;
extern int gRemoteMouseRenderDefault;

// In DRM mode the slave->master pipe is non-blocking and shared with the tile stream, so every
// sender must go through the draining writer in linux_kvm_drm.c: a raw write() could truncate a
// message on a full pipe (desyncing the stream) or, blocking, re-arm the master<->slave pipe
// deadlock that the draining writer exists to prevent.
static void kvm_slave_send(const void *buffer, size_t len)
{
	if (g_kvmBackendDRM != 0)
	{
		ignore_result(kvm_drm_slave_write(buffer, len));
	}
	else
	{
		ignore_result(write(slave2master[1], buffer, len));
	}
}

int remoteMouseX = 0, remoteMouseY = 0;

extern void* tilebuffer;
extern char **environ;
struct timespec inputtime;
uint32_t inputcounter = 0;
int SHIFT_STATE = 0;

typedef struct x11ext_struct
{
	void *xext_lib;
	Bool(*XShmDetach)(Display *d, XShmSegmentInfo *si);
	Bool(*XShmGetImage)(Display *dis, Drawable d, XImage *image, int x, int y, unsigned long plane_mask);
	Bool(*XShmAttach)(Display *d, XShmSegmentInfo *si);
	XImage*(*XShmCreateImage)(Display *display, Visual *visual, unsigned int depth, int format, char *data, XShmSegmentInfo *shminfo, unsigned int width, unsigned int height);
}x11ext_struct;
x11ext_struct *x11ext_exports = NULL;
extern x11tst_struct *x11tst_exports;
x11_struct *x11_exports = NULL;

typedef struct xfixes_struct
{
	void *xfixes_lib;
	Bool(*XFixesSelectCursorInput)(Display *d, Window w, int i);
	Bool(*XFixesQueryExtension)(Display *d, int *eventbase, int *errorbase);
	void*(*XFixesGetCursorImage)(Display *d);
	void*(*XFixesGetCursorImageAndName)(Display *d);
}xfixes_struct;
xfixes_struct *xfixes_exports = NULL;
xkb_struct *xkb_exports = NULL;

typedef struct xrandr_struct
{
	void *xrandr_lib;
	XRRScreenResources*(*XRRGetScreenResources)(Display *dpy, Window window);
	void(*XRRFreeScreenResources)(XRRScreenResources *resources);
	XRRCrtcInfo*(*XRRGetCrtcInfo)(Display *dpy, XRRScreenResources *resources, RRCrtc crtc);
	void(*XRRFreeCrtcInfo)(XRRCrtcInfo *crtcInfo);
} xrandr_struct;
xrandr_struct *xrandr_exports = NULL;

void kvm_keyboard_unmap_unicode_key(Display *display, int keycode)
{
	// Delete a keymapping that we created previously
	KeySym keysym_list[] = { 0 };
	x11_exports->XChangeKeyboardMapping(display, keycode, 1, keysym_list, 1);
	x11_exports->XSync(display, 0);
}
int kvm_keyboard_update_map_unicode_key(Display *display, uint16_t unicode, int keycode)
{
	char unicodestring[6];

	// Convert the unicode character to something xorg will understand
	if (sprintf_s(unicodestring, sizeof(unicodestring), "U%04X", unicode) < 0) { return(keycode); }

	// Map the unicode character to one of the unused keys above
	KeySym sym = x11_exports->XStringToKeysym(unicodestring);
	KeySym keysym_list[] = { sym, sym };
	x11_exports->XChangeKeyboardMapping(display, keycode, 2, keysym_list, 1);
	x11_exports->XSync(display, 0);
	return(keycode);
}
int kvm_keyboard_map_unicode_key(Display *display, uint16_t unicode, int *alreadyExists)
{
	KeySym *keysyms = NULL;
	int keysyms_per_keycode = 0;
	int keycode_low, keycode_high;
	int empty_keycode = 0;
	int i, j, keycodeIndex;
	char unicodestring[6];
	if (alreadyExists != NULL) { *alreadyExists = 0; }

	// Convert the unicode character to something xorg will understand
	if (sprintf_s(unicodestring, sizeof(unicodestring), "U%04X", unicode) < 0) { return(-1); }	
	KeySym sym = x11_exports->XStringToKeysym(unicodestring);
	//ILIBLOGMESSAGEX("UNICODE SYM: %X", sym);

	// Get the keycode range that is supported on this platform
	x11_exports->XDisplayKeycodes(display, &keycode_low, &keycode_high);						
	keysyms = x11_exports->XGetKeyboardMapping(display, keycode_low, keycode_high - keycode_low, &keysyms_per_keycode);

	if (alreadyExists != NULL)
	{
		int foundCode = x11_exports->XKeysymToKeycode(display, sym);
		if (foundCode != 0)
		{
			// Check to see if this mapping is the primary mapping
			keycodeIndex = (foundCode - keycode_low) * keysyms_per_keycode;
			if (keysyms[keycodeIndex] == sym && SHIFT_STATE == 0)
			{
				// We have a match!
				//ILIBLOGMESSAGEX("   Already mapped at: %d", foundCode);
				empty_keycode = foundCode;
				*alreadyExists = 1;
			}
			else
			{
				// No match!
				//ILIBLOGMESSAGEX("   Already mapped at: %d, but is not PRIMARY", foundCode);
				//ILIBLOGMESSAGEX("   keycode_low: %d , keycode_high: %d , per: %d", keycode_low, keycode_high, keysyms_per_keycode);
			}
		}
		return(empty_keycode);
	}


	if (empty_keycode == 0)
	{
		// Find an unmapped key
		for (i = keycode_low; i <= keycode_high; ++i)
		{
			int empty = 1;
			for (j = 0; j < keysyms_per_keycode; ++j)
			{
				keycodeIndex = (i - keycode_low) * keysyms_per_keycode + j;
				if (keysyms[keycodeIndex] != 0) 
				{
					empty = 0; 
					break;
				}
			}
			if (empty) 
			{
				empty_keycode = i; 
				break; 
			} // Found it!
		}


		// Map the unicode character to one of the unused keys above
		//ILIBLOGMESSAGEX("   MAPPING SYM: %x on: %d", sym, empty_keycode);

		KeySym keysym_list[] = { sym, sym };
		x11_exports->XChangeKeyboardMapping(display, empty_keycode, 2, keysym_list, 1);
		x11_exports->XSync(display, 0);

	}

	x11_exports->XFree(keysyms);
	return(empty_keycode);
}

void kvm_send_error(char *msg)
{
	int msgLen = strnlen_s(msg, 255);
	char buffer[512];

	// Otherwise this only reaches the MeshCentral viewer, so the error never shows in the agent's own log.
	if (msgLen > 0) { fprintf(stderr, "KVM error: %s\n", msg); fflush(stderr); }

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(msgLen + 4));	// Write the size
	memcpy_s(buffer + 4, msgLen, msg, msgLen);
	kvm_slave_send(buffer, msgLen + 4);
}

KVM_MouseCursors kvm_fetch_currentCursor(Display *cursordisplay)
{
	// Name was NULL, so as a last ditch effort, lets try to look at the XFixesCursorImage
	char *cursor_image = (char*)xfixes_exports->XFixesGetCursorImage(cursordisplay);
	KVM_MouseCursors ret = KVM_MouseCursor_HELP;

	unsigned short w = ((unsigned short*)(cursor_image + 4))[0];
	unsigned short h = ((unsigned short*)(cursor_image + 6))[0];
	char *pixels = cursor_image + (sizeof(void*) == 8 ? 24 : 16);
	char alpha[65535];
	int i;

	if (((size_t)(w*h) <= sizeof(alpha)) && ((size_t)(w*h) > 6))
	{
		for (i = 0; i < (w*h); ++i)
		{
			alpha[i] = pixels[(sizeof(void*)==8?(3 + (i * 8)):(3 + (i * 4)))];
		}
		switch (crc32c(0, (unsigned char*)alpha+6, (uint32_t)((w*h)-6)))
		{
			case 2788757291:			// Ubuntu 20
			case 1722092522:			// Ubuntu 9/10 (Top)
			case 2893151230:			// Ubuntu 9/10 (Bottom)
			case 3911022957:			// Ubuntu/Peppermint (Top)
			case 315617398:				// Ubuntu/Peppermint (Bottom)
			case 313635327:				// FreeBSD
			case 399455764:				// openSUSE
			case 3867633865:			// PuppyLinux (Top)
			case 2405141328:			// PuppyLinux (Bottom)
			case 2017738775:			// Raspian/CentOS (Top)
			case 1820008802:			// Raspian/CentOS (Bottom)
				ret = KVM_MouseCursor_SIZENS;
				break;

			case 2098355412:			// Ubuntu 20 (Left)
			case 1870927140:			// Ubuntu 20 (Right)
			case 3756583870:			// Ubuntu 9/10 (Left)
			case 2797106708:			// Ubuntu 9/10 (Right)
			case 1206496159:			// Ubuntu (Left)
			case 3947249005:			// Ubuntu (Right)
			case 2065486748:			// FreeBSD
			case 3817177836:			// openSUSE
			case 2760825997:			// PuppyLinux (Left)
			case 222646089:				// PuppyLinux (Right)
			case 1924105758:			// Raspian (Left)
			case 18444308:				// Raspian (Right)
				ret = KVM_MouseCursor_SIZEWE;
				break;

			case 1022545981:			// Ubuntu 20 (Bottom Left)
			case 587249781:				// Ubuntu 20 (Upper Right)
			case 465233379:				// Ubuntu 9/10 (Bottom Left)
			case 1129233427:			// Ubuntu 9/10  (Upper Right)
			case 305612954:				// Ubuntu (Bottom Left)
			case 1245488815:			// Ubuntu (Upper Right)
			case 169817074:				// FreeBSD + PuppyLinux (Bottom Left)
			case 482480649:				// FreeBSD + PuppyLinux (Upper Right)
			case 1405624986:			// openSUSE
			case 2989878302:			// Raspian (Bottom Left)
			case 21344493:				// Raspian (Upper Right)
				ret = KVM_MouseCursor_SIZENESW;
				break;

			
			case 1016474413:			// Ubuntu 20 (Upper Left)
			case 2912730571:			// Ubuntu 20 (Bottom Right)
			case 1292166613:			// Ubuntu 9/10 (Upper Left)
			case 4017655526:			// Ubuntu 9/10 (Bottom Right)
			case 799529566:				// Ubuntu (Upper Left)
			case 4056118275:			// Ubuntu (Bottom Right)
			case 2757619196:			// FreeBSD + PuppyLinux (Bottom Right)
			case 3302778157:			// FreeBSD + PuppyLinux (Upper Left)
			case 924333740:				// openSUSE
			case 2843753620:			// Raspian (Upper Left)
			case 4110212903:			// Raspian (Bottom Right)
				ret = KVM_MouseCursor_SIZENWSE;
				break;
			
			case 177740762:				// Deepin 20
			case 3606431443:			// Ubuntu 20
			case 3694153785:			// Ubuntu 9/10
			case 2280086639:			// Ubuntu
			case 920009133:				// FreeBSD + PuppyLinux
			case 2321998854:			// openSUSE
			case 926331252:				// Raspian
				ret = KVM_MouseCursor_SIZEALL;
				break;

			case 539866054:				// Deepin 20 (Normal)
			case 1802968862:			// Deepin 20 (Large)
			case 2550770000:			// Ubuntu 20
			case 3097204904:			// Ubuntu 9/10
			case 3546300886:			// Ubuntu
			case 1038978227:			// FreeBSD + PuppyLinux + openSUSE
			case 4237429080:			// Raspian
				ret = KVM_MouseCursor_ARROW;
				break;

			case 4197067144:			// Ubuntu 20
			case 2170379861:			// Ubuntu 9/10
			case 1176251007:			// Ubuntu
			case 3320936845:			// FreeBSD
			case 795881928:				// PuppyLinux
			case 134935791:				// Raspian
				ret = KVM_MouseCursor_IBEAM;
				break;

			case 3805997719:			// Deepin 20
			case 1393241229:			// Ubuntu 20
			case 990896914:				// Ubuntu 9/10
			case 3673902152:			// Ubuntu
			case 27109234:				// Raspian
			case (uint32_t)-1421461853:	// PuppyLinux
				ret = KVM_MouseCursor_HAND;
				break;

			case 3503643429:			// Deepin 20
			case 620546299:				// Ubuntu 20
			case 3463742778:			// Ubuntu
				ret = KVM_MouseCursor_WAIT;
				break;
			default:
				break;
		}
	}
		
	x11_exports->XFree(cursor_image);
	return(ret);
}
void kvm_send_resolution()
{
	char buffer[8];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(g_kvmBackendDRM && KVM_OUTPUT_WIDTH ? KVM_OUTPUT_WIDTH : SCREEN_WIDTH));		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(g_kvmBackendDRM && KVM_OUTPUT_HEIGHT ? KVM_OUTPUT_HEIGHT : SCREEN_HEIGHT));	// Y position

	kvm_slave_send(buffer, sizeof(buffer));
}

void kvm_send_display()
{
	char buffer[6];
	unsigned short sel = (g_monitor_count > 0) ? ((SCREEN_SEL == 0) ? (unsigned short)65535 : (unsigned short)SCREEN_SEL) : (unsigned short)CURRENT_DISPLAY_ID;
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SET_DISPLAY);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)6);					// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons(sel);									// Display selection

	kvm_slave_send(buffer, sizeof(buffer));
}

#define BUFSIZE 65535

int kvm_server_inputdata(char* block, int blocklen);

int lockfileCheckFn(const struct dirent *ent) {
	if (ent == NULL) {
		return 0;
	}

	if (!strncmp(ent->d_name, ".X", 2) && strcmp(ent->d_name, ".X11-unix") && strcmp(ent->d_name, ".XIM-unix")) {
		return 1;
	}

	return 0;
}

void kvm_apply_monitor_selection()
{
	if (SCREEN_SEL > 0 && (SCREEN_SEL - 1) < g_monitor_count)
	{
		int idx = SCREEN_SEL - 1;
		CAPTURE_X    = g_monitors[idx].x;
		CAPTURE_Y    = g_monitors[idx].y;
		SCREEN_WIDTH  = g_monitors[idx].width;
		SCREEN_HEIGHT = g_monitors[idx].height;
	}
	else
	{
		SCREEN_SEL   = 0;
		SCREEN_SEL_TARGET = 0;
		CAPTURE_X    = 0;
		CAPTURE_Y    = 0;
		SCREEN_WIDTH  = VSCREEN_WIDTH;
		SCREEN_HEIGHT = VSCREEN_HEIGHT;
	}
}

void kvm_update_monitor_layout(kvm_monitor_info *monitors, int monitorCount, int virtualWidth, int virtualHeight)
{
	int i;
	if (monitorCount < 0) { monitorCount = 0; }
	if (monitorCount > KVM_MAX_MONITORS) { monitorCount = KVM_MAX_MONITORS; }

	g_monitor_count = 0;
	for (i = 0; i < monitorCount; ++i)
	{
		if (monitors[i].width <= 0 || monitors[i].height <= 0) { continue; }
		g_monitors[g_monitor_count] = monitors[i];
		g_monitors[g_monitor_count].id = g_monitor_count + 1;
		g_monitor_count++;
	}

	VSCREEN_WIDTH = virtualWidth;
	VSCREEN_HEIGHT = virtualHeight;
	if (g_monitor_count == 0 && (VSCREEN_WIDTH <= 0 || VSCREEN_HEIGHT <= 0))
	{
		VSCREEN_WIDTH = SCREEN_WIDTH;
		VSCREEN_HEIGHT = SCREEN_HEIGHT;
	}

	kvm_apply_monitor_selection();
}

// Enumerate physical monitors via XRandR into g_monitors[] and update capture region.
// Falls back gracefully if XRandR is unavailable.
static void kvm_enumerate_monitors()
{
	g_monitor_count = 0;
	if (xrandr_exports != NULL && xrandr_exports->XRRGetScreenResources != NULL)
	{
		Window root = x11_exports->XRootWindow(eventdisplay, SCREEN_NUM);
		XRRScreenResources *res = xrandr_exports->XRRGetScreenResources(eventdisplay, root);
		if (res != NULL)
		{
			int mi;
			for (mi = 0; mi < res->ncrtc && g_monitor_count < KVM_MAX_MONITORS; mi++)
			{
				XRRCrtcInfo *ci = xrandr_exports->XRRGetCrtcInfo(eventdisplay, res, res->crtcs[mi]);
				if (ci != NULL)
				{
					if (ci->width > 0 && ci->height > 0)
					{
						g_monitors[g_monitor_count].id     = g_monitor_count + 1;
						g_monitors[g_monitor_count].x      = ci->x;
						g_monitors[g_monitor_count].y      = ci->y;
						g_monitors[g_monitor_count].width  = (int)ci->width;
						g_monitors[g_monitor_count].height = (int)ci->height;
						g_monitor_count++;
					}
					xrandr_exports->XRRFreeCrtcInfo(ci);
				}
			}
			xrandr_exports->XRRFreeScreenResources(res);
		}
	}
	kvm_apply_monitor_selection();
}

// Send MNG_KVM_DISPLAY_INFO: per-monitor geometry (ID, X, Y, W, H) matching Windows format.
void kvm_send_display_info()
{
	int i;
	int totalSize;
	char *buffer;
	if (g_monitor_count == 0) { return; }
	totalSize = 4 + (g_monitor_count * 10); // 4-byte header + 10 bytes (5 shorts) per monitor
	buffer = (char*)ILibMemory_SmartAllocate(totalSize);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_DISPLAY_INFO);
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)totalSize);
	for (i = 0; i < g_monitor_count; i++)
	{
		int base = 2 + (i * 5); // index into unsigned short array
		((unsigned short*)buffer)[base + 0] = (unsigned short)htons((unsigned short)g_monitors[i].id);
		((unsigned short*)buffer)[base + 1] = (unsigned short)htons((unsigned short)g_monitors[i].x);
		((unsigned short*)buffer)[base + 2] = (unsigned short)htons((unsigned short)g_monitors[i].y);
		((unsigned short*)buffer)[base + 3] = (unsigned short)htons((unsigned short)g_monitors[i].width);
		((unsigned short*)buffer)[base + 4] = (unsigned short)htons((unsigned short)g_monitors[i].height);
	}
	kvm_slave_send(buffer, ILibMemory_Size(buffer));
	ILibMemory_Free(buffer);
}

void getAvailableDisplays(unsigned short **array, int *len)
{
	int i;
	if (g_monitor_count > 0)
	{
		// XRandR mode: expose 65535 ("all") + 1-based physical monitor IDs
		*len = g_monitor_count + 1;
		if ((*array = (unsigned short *)malloc((*len) * sizeof(unsigned short))) == NULL) ILIBCRITICALEXIT(254);
		(*array)[0] = (unsigned short)65535; // "all monitors"
		for (i = 0; i < g_monitor_count; i++) { (*array)[i + 1] = (unsigned short)g_monitors[i].id; }
		return;
	}
	// Legacy: X11 logical screens (usually just one)
	*len = x11_exports->XScreenCount(eventdisplay);
	if ((*array = (unsigned short *)malloc((*len) * sizeof(unsigned short))) == NULL) ILIBCRITICALEXIT(254);
	for (i = 0; i < (*len); ++i)
	{
		(*array)[i] = (unsigned short)i;
	}
}

void kvm_send_display_list()
{
	unsigned short *displays = NULL;
	int len = 0;
	char* buffer;
	int totalSize = 0;
	int i;
	unsigned short currentSel;

	kvm_send_display_info(); // Send per-monitor geometry (MNG_KVM_DISPLAY_INFO) first

	getAvailableDisplays(&displays, &len);
	totalSize = 2 /*Type*/ + 2 /*length of packet*/ + 2 /*count*/ + (len * 2) /*IDs*/ + 2 /* Current display */;
	buffer = (char*)ILibMemory_SmartAllocate(totalSize);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)totalSize);			// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)len);					// Count
	for (i = 0; i < len; i++)
	{
		((unsigned short*)buffer)[i + 3] = (unsigned short)htons(displays[i]);
	}
	// Current selection: 65535 = all monitors, 1..N = specific monitor (matches Windows convention)
	if (g_monitor_count > 0)
		currentSel = (SCREEN_SEL == 0) ? (unsigned short)65535 : (unsigned short)SCREEN_SEL;
	else
		currentSel = (unsigned short)CURRENT_DISPLAY_ID;
	((unsigned short*)buffer)[i + 3] = (unsigned short)htons(currentSel);

	kvm_slave_send(buffer, ILibMemory_Size(buffer));
	free(displays);
}

char Location_X11LIB[NAME_MAX];
char Location_X11TST[NAME_MAX];
char Location_X11EXT[NAME_MAX];
char Location_X11FIXES[NAME_MAX];
char Location_X11KB[NAME_MAX];
char Location_X11RANDR[NAME_MAX];
void kvm_set_x11_locations(char *libx11, char *libx11tst, char *libx11ext, char *libxfixes, char *libx11kb)
{
	if (libx11 != NULL) { strcpy_s(Location_X11LIB, sizeof(Location_X11LIB), libx11); } else { strcpy_s(Location_X11LIB, sizeof(Location_X11LIB), "libX11.so"); }
	if (libx11tst != NULL) { strcpy_s(Location_X11TST, sizeof(Location_X11TST), libx11tst); } else { strcpy_s(Location_X11TST, sizeof(Location_X11TST), "libXtst.so"); }
	if (libx11ext != NULL) { strcpy_s(Location_X11EXT, sizeof(Location_X11EXT), libx11ext); } else { strcpy_s(Location_X11EXT, sizeof(Location_X11EXT), "libXext.so"); }
	if (libxfixes != NULL) { strcpy_s(Location_X11FIXES, sizeof(Location_X11FIXES), libxfixes); } else { strcpy_s(Location_X11FIXES, sizeof(Location_X11FIXES), "libXfixes.so"); }
	if (libx11kb != NULL) { strcpy_s(Location_X11KB, sizeof(Location_X11KB), libx11kb); } else { strcpy_s(Location_X11KB, sizeof(Location_X11KB), "libxkbfile.so"); }
	strcpy_s(Location_X11RANDR, sizeof(Location_X11RANDR), "libXrandr.so");
}

// Runtime installations need not contain the unversioned linker names from -dev packages.
// Keep discovered/custom paths first, and use the ABI soname when discovery is unavailable.
static void *kvm_x11_open_library(const char *configuredPath, const char *runtimeName)
{
	void *library = NULL;
	if (configuredPath != NULL && configuredPath[0] != 0)
	{
		library = dlopen(configuredPath, RTLD_NOW);
	}
	if (library == NULL) { library = dlopen(runtimeName, RTLD_NOW); }
	return library;
}

int kvm_init(int displayNo)
{
	if (logFile) { fprintf(logFile, "kvm_init(%d) called\n", displayNo); fflush(logFile); }
	int old_height_count = TILE_HEIGHT_COUNT;
	int dummy1, dummy2, dummy3;

	if (clock_gettime(CLOCK_MONOTONIC, &inputtime) != 0) { memset(&inputtime, 0, sizeof(inputtime)); }

	if (x11ext_exports == NULL)
	{
		x11ext_exports = ILibMemory_SmartAllocate(sizeof(x11ext_struct));
		x11ext_exports->xext_lib = kvm_x11_open_library(Location_X11EXT, "libXext.so.6");
		if (x11ext_exports->xext_lib)
		{
			((void**)x11ext_exports)[1] = (void*)dlsym(x11ext_exports->xext_lib, "XShmDetach");
			((void**)x11ext_exports)[2] = (void*)dlsym(x11ext_exports->xext_lib, "XShmGetImage");
			((void**)x11ext_exports)[3] = (void*)dlsym(x11ext_exports->xext_lib, "XShmAttach");
			((void**)x11ext_exports)[4] = (void*)dlsym(x11ext_exports->xext_lib, "XShmCreateImage");
		}
	}
	if (x11tst_exports == NULL)
	{
		x11tst_exports = ILibMemory_SmartAllocate(sizeof(x11tst_struct));
		x11tst_exports->x11tst_lib = kvm_x11_open_library(Location_X11TST, "libXtst.so.6");
		if (x11tst_exports->x11tst_lib)
		{
			((void**)x11tst_exports)[1] = (void*)dlsym(x11tst_exports->x11tst_lib, "XTestFakeMotionEvent");
			((void**)x11tst_exports)[2] = (void*)dlsym(x11tst_exports->x11tst_lib, "XTestFakeButtonEvent");
			((void**)x11tst_exports)[3] = (void*)dlsym(x11tst_exports->x11tst_lib, "XTestFakeKeyEvent");
		}
	}
	if (x11_exports == NULL)
	{
		x11_exports = ILibMemory_SmartAllocate(sizeof(x11_struct));
		x11_exports->x11_lib = kvm_x11_open_library(Location_X11LIB, "libX11.so.6");
		if (x11_exports->x11_lib)
		{
			((void**)x11_exports)[1] = (void*)dlsym(x11_exports->x11_lib, "XOpenDisplay");
			((void**)x11_exports)[2] = (void*)dlsym(x11_exports->x11_lib, "XCloseDisplay");
			((void**)x11_exports)[3] = (void*)dlsym(x11_exports->x11_lib, "XFlush");
			((void**)x11_exports)[4] = (void*)dlsym(x11_exports->x11_lib, "XKeysymToKeycode");
			((void**)x11_exports)[5] = (void*)dlsym(x11_exports->x11_lib, "XQueryExtension");

			((void**)x11_exports)[6] = (void*)dlsym(x11_exports->x11_lib, "XConnectionNumber");
			((void**)x11_exports)[7] = (void*)dlsym(x11_exports->x11_lib, "XGetAtomName");
			((void**)x11_exports)[8] = (void*)dlsym(x11_exports->x11_lib, "XNextEvent");
			((void**)x11_exports)[9] = (void*)dlsym(x11_exports->x11_lib, "XPending");
			((void**)x11_exports)[10] = (void*)dlsym(x11_exports->x11_lib, "XRootWindow");
			((void**)x11_exports)[11] = (void*)dlsym(x11_exports->x11_lib, "XSync");
			((void**)x11_exports)[12] = (void*)dlsym(x11_exports->x11_lib, "XFree");
			((void**)x11_exports)[13] = (void*)dlsym(x11_exports->x11_lib, "XSelectInput");
			((void**)x11_exports)[14] = (void*)dlsym(x11_exports->x11_lib, "XGetWindowAttributes");
			((void**)x11_exports)[15] = (void*)dlsym(x11_exports->x11_lib, "XChangeWindowAttributes");
			((void**)x11_exports)[16] = (void*)dlsym(x11_exports->x11_lib, "XQueryPointer");
			((void**)x11_exports)[17] = (void*)dlsym(x11_exports->x11_lib, "XDisplayKeycodes");
			((void**)x11_exports)[18] = (void*)dlsym(x11_exports->x11_lib, "XGetKeyboardMapping");
			((void**)x11_exports)[19] = (void*)dlsym(x11_exports->x11_lib, "XStringToKeysym");
			((void**)x11_exports)[20] = (void*)dlsym(x11_exports->x11_lib, "XChangeKeyboardMapping");
			((void**)x11_exports)[21] = (void*)dlsym(x11_exports->x11_lib, "XScreenCount");

			((void**)x11tst_exports)[4] = (void*)x11_exports->XFlush;
			((void**)x11tst_exports)[5] = (void*)x11_exports->XKeysymToKeycode;
		}
	}
	if (xfixes_exports == NULL)
	{
		xfixes_exports = ILibMemory_SmartAllocate(sizeof(xfixes_struct));
		xfixes_exports->xfixes_lib = kvm_x11_open_library(Location_X11FIXES, "libXfixes.so.3");
		if (xfixes_exports->xfixes_lib)
		{
			((void**)xfixes_exports)[1] = (void*)dlsym(xfixes_exports->xfixes_lib, "XFixesSelectCursorInput");
			((void**)xfixes_exports)[2] = (void*)dlsym(xfixes_exports->xfixes_lib, "XFixesQueryExtension");
			((void**)xfixes_exports)[3] = (void*)dlsym(xfixes_exports->xfixes_lib, "XFixesGetCursorImage");
			((void**)xfixes_exports)[4] = (void*)dlsym(xfixes_exports->xfixes_lib, "XFixesGetCursorImageAndName");
		}
	}
	if (xkb_exports == NULL)
	{
		xkb_exports = ILibMemory_SmartAllocate(sizeof(xkb_struct));
		xkb_exports->xkb_lib = kvm_x11_open_library(Location_X11KB, "libxkbfile.so.1");
		if (xkb_exports->xkb_lib)
		{
			((void**)xkb_exports)[1] = (void*)dlsym(xkb_exports->xkb_lib, "XkbGetState");
			((void**)xkb_exports)[2] = (void*)dlsym(xkb_exports->xkb_lib, "XkbLockModifiers");
			((void**)xkb_exports)[3] = (void*)dlsym(xkb_exports->xkb_lib, "XkbQueryExtension");
			((void**)xkb_exports)[4] = (void*)dlsym(xkb_exports->xkb_lib, "XkbSelectEvents");
		}
	}
	if (xrandr_exports == NULL)
	{
		xrandr_exports = ILibMemory_SmartAllocate(sizeof(xrandr_struct));
		// Try unversioned name first (needs libxrandr-dev), then fall back to versioned runtime lib
		xrandr_exports->xrandr_lib = dlopen(Location_X11RANDR, RTLD_NOW);
		if (xrandr_exports->xrandr_lib == NULL) { xrandr_exports->xrandr_lib = dlopen("libXrandr.so.2", RTLD_NOW); }
		if (xrandr_exports->xrandr_lib == NULL) { xrandr_exports->xrandr_lib = dlopen("libXrandr.so.2.2.0", RTLD_NOW); }
		if (xrandr_exports->xrandr_lib)
		{
			((void**)xrandr_exports)[1] = (void*)dlsym(xrandr_exports->xrandr_lib, "XRRGetScreenResources");
			((void**)xrandr_exports)[2] = (void*)dlsym(xrandr_exports->xrandr_lib, "XRRFreeScreenResources");
			((void**)xrandr_exports)[3] = (void*)dlsym(xrandr_exports->xrandr_lib, "XRRGetCrtcInfo");
			((void**)xrandr_exports)[4] = (void*)dlsym(xrandr_exports->xrandr_lib, "XRRFreeCrtcInfo");
		}
	}

	// Do not call through an unresolved runtime export: report the dependency failure to the viewer.
#define KVM_REQUIRE_X11_EXPORT(table, symbol) \
	if ((table)->symbol == NULL) { kvm_send_error("X11 runtime symbol unavailable: " #symbol); return -1; }
	KVM_REQUIRE_X11_EXPORT(x11_exports, XOpenDisplay);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XCloseDisplay);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XFlush);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XKeysymToKeycode);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XQueryExtension);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XConnectionNumber);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XGetAtomName);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XNextEvent);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XPending);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XRootWindow);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XSync);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XFree);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XSelectInput);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XGetWindowAttributes);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XChangeWindowAttributes);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XQueryPointer);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XDisplayKeycodes);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XGetKeyboardMapping);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XStringToKeysym);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XChangeKeyboardMapping);
	KVM_REQUIRE_X11_EXPORT(x11_exports, XScreenCount);
	KVM_REQUIRE_X11_EXPORT(x11ext_exports, XShmDetach);
	KVM_REQUIRE_X11_EXPORT(x11ext_exports, XShmGetImage);
	KVM_REQUIRE_X11_EXPORT(x11ext_exports, XShmAttach);
	KVM_REQUIRE_X11_EXPORT(x11ext_exports, XShmCreateImage);
	KVM_REQUIRE_X11_EXPORT(x11tst_exports, XTestFakeMotionEvent);
	KVM_REQUIRE_X11_EXPORT(x11tst_exports, XTestFakeButtonEvent);
	KVM_REQUIRE_X11_EXPORT(x11tst_exports, XTestFakeKeyEvent);
	KVM_REQUIRE_X11_EXPORT(xfixes_exports, XFixesSelectCursorInput);
	KVM_REQUIRE_X11_EXPORT(xfixes_exports, XFixesQueryExtension);
	KVM_REQUIRE_X11_EXPORT(xfixes_exports, XFixesGetCursorImage);
	KVM_REQUIRE_X11_EXPORT(xkb_exports, XkbGetState);
	KVM_REQUIRE_X11_EXPORT(xkb_exports, XkbLockModifiers);
	KVM_REQUIRE_X11_EXPORT(xkb_exports, XkbQueryExtension);
	KVM_REQUIRE_X11_EXPORT(xkb_exports, XkbSelectEvents);
#undef KVM_REQUIRE_X11_EXPORT

	sprintf_s(CURRENT_XDISPLAY, sizeof(CURRENT_XDISPLAY), ":%d", (int)displayNo);

	eventdisplay = x11_exports->XOpenDisplay(CURRENT_XDISPLAY);
	if (logFile) { fprintf(logFile, "XAUTHORITY is %s\n", getenv("XAUTHORITY")); fflush(logFile); }
	if (logFile) { fprintf(logFile, "DisplayString is %s\n", CURRENT_XDISPLAY); fflush(logFile); }

	if (eventdisplay == NULL)
	{
		char tmpBuff[1024];
		sprintf_s(tmpBuff, sizeof(tmpBuff), "XOpenDisplay(%s) failed, using XAUTHORITY: %s", CURRENT_XDISPLAY, getenv("XAUTHORITY"));
		if (logFile) { fprintf(logFile, "XOpenDisplay(%s) failed, using XAUTHORITY: %s\n", CURRENT_XDISPLAY, getenv("XAUTHORITY")); fflush(logFile); }
		kvm_send_error(tmpBuff);
		return(-1);
	}

	g_enableEvents = x11_exports->XQueryExtension(eventdisplay, "XTEST", &dummy1, &dummy2, &dummy3)? 1 : 0;
	if (!g_enableEvents) { printf("FATAL::::Fake motion is not supported.\n\n\n"); }

	CURRENT_DISPLAY_ID = SCREEN_NUM = DefaultScreen(eventdisplay);
	VSCREEN_WIDTH  = DisplayWidth(eventdisplay, SCREEN_NUM);
	VSCREEN_HEIGHT = DisplayHeight(eventdisplay, SCREEN_NUM);
	SCREEN_DEPTH   = DefaultDepth(eventdisplay, SCREEN_NUM);

	if (SCREEN_DEPTH < 15) {
		// fprintf(stderr, "kvm_init: We do not support display depth < 15.");
		return -1;
	}

	// Enumerate physical monitors and set SCREEN_WIDTH/HEIGHT/CAPTURE_X/Y
	kvm_enumerate_monitors();

	// Some magic numbers.
	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	COMPRESSION_RATIO = 50;
	FRAME_RATE_TIMER = 100;

	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH) { TILE_WIDTH_COUNT++; }
	if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }

	kvm_send_resolution();
	kvm_send_display();
	reset_tile_info(old_height_count);

	if (xkb_exports != NULL)
	{
		char buffer[5];
		int kberror_base = 0, major = 0, minor = 0, opcode = 0, kbevent_base = 0, kb_status = 0;

		XkbStateRec ptr;
		kb_status = xkb_exports->XkbQueryExtension(eventdisplay, &opcode, &kbevent_base, &kberror_base, &major, &minor);
		if (logFile) { fprintf(logFile, "XkbQueryExtension(): %d\n", kb_status); fflush(logFile); }
		xkb_exports->XkbGetState(eventdisplay, XkbUseCoreKbd, &ptr);
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
		buffer[4] = (((ptr.mods & 16) == 16) | (((ptr.mods & 32) == 32) << 1) | (((ptr.mods & 2) == 2) << 2));

		ignore_result(write(slave2master[1], buffer, sizeof(buffer)));
		if (logFile) { fprintf(logFile, "Keyboard Initial State: NUM[%d], SCROLL[%d], CAPS[%d]\n", (ptr.mods & 16) == 16, (ptr.mods & 32) == 32, (ptr.mods & 2) == 2); fflush(logFile); }
	}

	return 0;
}

void CheckDesktopSwitch(int checkres)
{
	UNREFERENCED_PARAMETER(checkres);
	if (g_kvmBackendDRM != 0) { return; }

	if (change_display)
	{
		if (logFile) { fprintf(logFile, "CheckDesktopSwitch: SCREEN_SEL_TARGET=%d CURRENT_DISPLAY_ID=%d\n", SCREEN_SEL_TARGET, CURRENT_DISPLAY_ID); fflush(logFile); }
		int old_height_count = TILE_HEIGHT_COUNT;
		change_display = 0;

		if (g_monitor_count > 0)
		{
			// XRandR mode: switch physical monitor selection
			SCREEN_SEL = SCREEN_SEL_TARGET;
			if (SCREEN_SEL > 0 && (SCREEN_SEL - 1) < g_monitor_count)
			{
				int idx = SCREEN_SEL - 1;
				CAPTURE_X    = g_monitors[idx].x;
				CAPTURE_Y    = g_monitors[idx].y;
				SCREEN_WIDTH  = g_monitors[idx].width;
				SCREEN_HEIGHT = g_monitors[idx].height;
			}
			else
			{
				SCREEN_SEL   = 0;
				CAPTURE_X    = 0;
				CAPTURE_Y    = 0;
				SCREEN_WIDTH  = VSCREEN_WIDTH;
				SCREEN_HEIGHT = VSCREEN_HEIGHT;
			}
		}
		else
		{
			// Legacy: switch X11 logical screen
			SCREEN_NUM    = CURRENT_DISPLAY_ID;
			SCREEN_HEIGHT = DisplayHeight(eventdisplay, CURRENT_DISPLAY_ID);
			SCREEN_WIDTH  = DisplayWidth(eventdisplay, CURRENT_DISPLAY_ID);
			SCREEN_DEPTH  = DefaultDepth(eventdisplay, CURRENT_DISPLAY_ID);
			CAPTURE_X     = 0;
			CAPTURE_Y     = 0;
		}

		TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
		TILE_WIDTH_COUNT  = SCREEN_WIDTH  / TILE_WIDTH;
		if (SCREEN_WIDTH  % TILE_WIDTH)  { TILE_WIDTH_COUNT++; }
		if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }

		kvm_send_resolution();
		kvm_send_display();
		kvm_send_display_list(); // re-send list with updated current selection so the UI highlights the right icon
		reset_tile_info(old_height_count);
	}
}

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;
	CheckDesktopSwitch(0);

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ntohs(ILibUnaligned_Read16(block));
	size = ntohs(ILibUnaligned_Read16(block + 2));
	if (size < 4) return 4;
	if (size > blocklen) return 0;

	switch (type)
	{
	case MNG_KVM_KEY_UNICODE: // Unicode Key
		if (size != 7) break;
		if (g_enableEvents && block[4] == 0)
		{
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4], eventdisplay);
		}
		break;
	case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			if (g_enableEvents)
			{
				if (logFile) { fprintf(logFile, "KeyAction(%u, %d)\n", ((unsigned char*)block)[5], block[4]); fflush(logFile); }
				KeyAction(((unsigned char*)block)[5], block[4], eventdisplay);
			}
			break;
		}
	case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (size == 10 || size == 12)
			{
				// Translate transmitted coordinates back to the selected source desktop.
				x = (int)ntohs(ILibUnaligned_Read16(block + 6));
                if (g_kvmBackendDRM && KVM_OUTPUT_WIDTH) x = (int)kvm_capture_source_coordinate(x, SCREEN_WIDTH, KVM_OUTPUT_WIDTH);
                if (g_kvmBackendDRM && x >= SCREEN_WIDTH) x = SCREEN_WIDTH-1;
                x += CAPTURE_X;
				y = (int)ntohs(ILibUnaligned_Read16(block + 8));
                if (g_kvmBackendDRM && KVM_OUTPUT_HEIGHT) y = (int)kvm_capture_source_coordinate(y, SCREEN_HEIGHT, KVM_OUTPUT_HEIGHT);
                if (g_kvmBackendDRM && y >= SCREEN_HEIGHT) y = SCREEN_HEIGHT-1;
                y += CAPTURE_Y;
				if (size == 12) w = ((short)ntohs(ILibUnaligned_Read16(block + 10)));
				if (logFile) { fprintf(logFile, "RemoteMouseMove: (%d, %d)\n", x, y); }
				// printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				if (g_enableEvents)
				{
					remoteMouseX = x, remoteMouseY = y;
					MouseAction(x, y, (int)(unsigned char)(block[5]), w, eventdisplay);
				}
			}
			break;
		}
	case MNG_KVM_COMPRESSION: // Compression
		{
			if (size >= 10) { int fr = ((int)ntohs(ILibUnaligned_Read16(block + 8))); if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr; }
			if (size >= 8) { int ns = ((int)ntohs(ILibUnaligned_Read16(block + 6))); if (ns >= 64 && ns <= 4096) SCALING_FACTOR_NEW = ns; }
			if (size >= 6) { set_tile_compression((int)block[4], (int)block[5]); }
			COMPRESSION_RATIO = 100;
            kvm_force_refresh = 1;
			break;
		}
	case MNG_KVM_REFRESH: // Refresh
		{
			int row, col;
			if (size != 4) break;
            kvm_force_refresh = 1;
			kvm_send_resolution();
			if (g_tileInfo == NULL) {
				if ((g_tileInfo = (struct tileInfo_t **) malloc(TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *))) == NULL) ILIBCRITICALEXIT(254);
				for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
					if ((g_tileInfo[row] = (struct tileInfo_t *) malloc(TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254);
				}
			}
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
				for (col = 0; col < TILE_WIDTH_COUNT; col++) {
					g_tileInfo[row][col].crc = 0xFF;
					g_tileInfo[row][col].flag = 0;
				}
			}
			break;
		}
	case MNG_KVM_PAUSE: // Pause
		{
			if (size != 5) break;
			g_remotepause = block[4];
            if (!g_remotepause) kvm_force_refresh = 1;
			break;
		}
	case MNG_KVM_FRAME_RATE_TIMER:
		{
			if (size != 6) break;
			int fr = ((int)ntohs(ILibUnaligned_Read16(block + 4)));
			if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr;
			break;
		}
	case MNG_KVM_GET_DISPLAYS:
		{
			if (size != 4) break;
			kvm_send_display_list();
			break;
		}
	case MNG_KVM_SET_DISPLAY:
		{
			if (size != 6) break;
			unsigned short newval = ntohs(ILibUnaligned_Read16(block + 4));
			if (g_monitor_count > 0)
			{
				// XRandR mode: 65535 = all monitors, 1..N = specific physical monitor
				int newsel = (newval == 65535) ? 0 : (int)newval;
				if (newsel == SCREEN_SEL_TARGET) { break; }
				SCREEN_SEL_TARGET = newsel;
				change_display = 1;
			}
			else
			{
				// Legacy X11 screen mode
				if ((int)newval == CURRENT_DISPLAY_ID) { break; }
				CURRENT_DISPLAY_ID = (int)newval;
				SCREEN_SEL_TARGET  = 0;
				change_display = 1;
			}
			break;
		}
	}
	return size;
}


int kvm_relay_feeddata(char* buf, int len)
{
	ssize_t written = 0;
	if (g_slavekvm <= 0 || master2slave[1] < 0 || buf == NULL || len <= 0) { return 0; }

	// Write the reply to the pipe.
	//fprintf(logFile, "Writing to slave in kvm_relay_feeddata\n");
	written = write(
		master2slave[1],			// handle to pipe
		buf,			// buffer to write from
		len);
	fsync(master2slave[1]);
	//fprintf(logFile, "Written %d bytes to slave in kvm_relay_feeddata\n", written);

	if (written == -1) return 0;
	if (len != (int)written) return written;
	return len;
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	g_pause = pause;
}

void kvm_server_jpegerror(char *msg)
{
	int msgLen = strnlen_s(msg, 255);
	char *buffer = (char*)ILibMemory_SmartAllocate(msgLen + 4);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(msgLen + 4));	// Write the size
	memcpy_s(buffer + 4, msgLen, msg, msgLen);

	kvm_slave_send(buffer, ILibMemory_Size(buffer));
}

#pragma pack(push, 1)
typedef struct bitmapdata
{
	int a;
	int r;
	int g;
	int b;
}bitmapdata;

typedef struct bitmapdata2
{
	unsigned char b;
	unsigned char g;
	unsigned char r;
	unsigned char a;
}bitmapdata2;
#pragma pack(pop)

void kvm_test_disaplymatrix(char *source, int width, int height)
{
	int i;
	int row = 0, column = 0;
	for (i = 0; i < (width*height); ++i)
	{
		printf("[%d, %d, %d, %d] ", ((bitmapdata*)source)[i].a, ((bitmapdata*)source)[i].r, ((bitmapdata*)source)[i].g, ((bitmapdata*)source)[i].b);
		if (++column == width)
		{
			column = 0;
			++row;
			printf("\n");
		}
	}
}

int kvm_createrect(char *sourcebitmap, int source_width, int source_height, int rx, int ry, int rw, int rh, char *buffer, int bufferSize)
{
	int i, len = rh * sizeof(bitmapdata*);
	if (bufferSize < len || buffer == NULL) { return(len); }
	memset(buffer, 0, len);

	bitmapdata **rows = (bitmapdata**)buffer;
	for (i = ry; (i - ry) < rh; ++i)
	{
		rows[i - ry] = (bitmapdata*)(sourcebitmap + (i*source_width * sizeof(bitmapdata)));
	}

	bitmapdata **rr = (bitmapdata**)buffer;
	for (i = 0; i < rh; ++i)
	{
		rr[i] = &(rr[i][rx]);
	}
	return(0);
}

int kvm_createrect3(unsigned long *sourcebitmap, int source_width, int source_height, int rx, int ry, int rw, int rh, char *buffer, int bufferSize)
{
	int i, len = (rw * rh * sizeof(bitmapdata2)) + (rh * sizeof(bitmapdata2*));
	if (bufferSize < len || buffer == NULL) { return(len); }
	memset(buffer, 0, len);
	
	bitmapdata2 **ret = (bitmapdata2**)buffer;
	bitmapdata2 *data = (bitmapdata2*)(buffer + (sizeof(bitmapdata2*) * rh));

	int row = 0, col = 0;

	for (i = 0; i < rh; ++i)
	{
		ret[i] = (bitmapdata2*)((char*)data + (i * rw * sizeof(bitmapdata2)));
	}

	for (i = 0; i < source_width*source_height; ++i, ++col)
	{
		if (col >= source_width) { col = 0; ++row; }
		if (row >= ry && row < (ry + rh) &&
			col >= rx && col < (rx + rw))
		{
			ret[row - rx][col - ry].a = (sourcebitmap[i] >> 24) & 0xFF;
			ret[row - rx][col - ry].r = (sourcebitmap[i] >> 16) & 0xFF;
			ret[row - rx][col - ry].g = (sourcebitmap[i] >> 8) & 0xFF;
			ret[row - rx][col - ry].b = (sourcebitmap[i] >> 0) & 0xFF;
		}
	}

	return(0);
}
int kvm_createrect2(char *sourcebitmap, int source_width, int source_height, int rx, int ry, int rw, int rh, char *buffer, int bufferSize)
{
	int i, len = rh * sizeof(bitmapdata2*);
	if (bufferSize < len || buffer == NULL) { return(len); }
	memset(buffer, 0, len);

	bitmapdata2 **rows = (bitmapdata2**)buffer;

	for (i = 0; i < rh; ++i)
	{
		rows[i] = (bitmapdata2*)(sourcebitmap + ((i + ry)*source_width * sizeof(bitmapdata2)) + (rx * sizeof(bitmapdata2)));
	}

	return(0);
}
void bitblt(char *sourcebitmap, int source_width, int source_height, int sx, int sy, int rw, int rh, char *destbitmap, int dest_width, int dest_height, int dx, int dy, int rmode)
{
	int x, y;
	char *srect, *drect;
	int srectLen = kvm_createrect3((unsigned long*)sourcebitmap, source_width, source_height, sx, sy, rw, rh, NULL, 0);
	int drectLen = kvm_createrect2(destbitmap, dest_width, dest_height, dx, dy, rw, rh, NULL, 0);

	srect = ILibMemory_SmartAllocate(srectLen);
	drect = ILibMemory_SmartAllocate(drectLen);

	kvm_createrect3((unsigned long*)sourcebitmap, source_width, source_height, sx, sy, rw, rh, srect, srectLen);
	kvm_createrect2(destbitmap, dest_width, dest_height, dx, dy, rw, rh, drect, drectLen);

	for (y = 0; y < rh; ++y)
	{
		for (x = 0; x < rw; ++x)
		{
			if (((bitmapdata2**)srect)[y][x].a > 128)
			{
				((bitmapdata2**)drect)[y][x].r = (255 - ((bitmapdata2**)srect)[y][x].r);
				((bitmapdata2**)drect)[y][x].g = (255 - ((bitmapdata2**)srect)[y][x].g);
				((bitmapdata2**)drect)[y][x].b = (255 - ((bitmapdata2**)srect)[y][x].b);
			}
		}
	}

	ILibMemory_Free(srect);
	ILibMemory_Free(drect);
}

void kvm_server_sighandler(int signum, siginfo_t *info, void *context)
{
	g_shutdown = 1;
}

void* kvm_server_mainloop_x11(void* parm)
{
	int sessionUid = (int)(intptr_t)parm;
	int maxsleep;
	Window rr, cr;
	int rx, ry, wx, wy, rs;
	unsigned int mr;
	char *cimage;

	int x, y, height, width, r, c;
	int sentHideCursor = 0;
	long long desktopsize = 0;
	long long tilesize = 0;

	void *desktop = NULL;
	XImage *image = NULL;
	eventdisplay = NULL;
	Display *imagedisplay = NULL, *cursordisplay = NULL;
	void *buf = NULL;
	int event_base = 0, error_base = 0, cursor_descriptor = -1;
	int kbevent_base = 0;
	ssize_t written;
	XShmSegmentInfo shminfo;
	default_JPEG_error_handler = kvm_server_jpegerror;

	struct timeval tv;
	fd_set readset;
	fd_set errorset;
	fd_set writeset;
	XEvent XE;

	unsigned short currentDisplayId = 0;

	if (sessionUid != 0)
	{
		// Full drop, not bare setuid: keeping gid 0 / root's supplementary groups would leave the
		// X11 slave more privileged than the session user, and continuing as root after a failed
		// setuid (EAGAIN under RLIMIT_NPROC) must not happen. The DRM path does the same in
		// kvm_drm_drop_to_session_uid_with_caps().
		struct passwd *pw = getpwuid((uid_t)sessionUid);
		if (pw == NULL ||
			initgroups(pw->pw_name, pw->pw_gid) != 0 ||
			setgid(pw->pw_gid) != 0 ||
			setuid((uid_t)sessionUid) != 0)
		{
			fprintf(stderr, "KVM: privilege drop to uid %d failed (errno=%d); aborting capture child\n", sessionUid, errno);
			kvm_send_error("KVM privilege drop failed");
			return (void *)-1;
		}
	}

	if (logFile) { fprintf(logFile, "Checking $DISPLAY\n"); fflush(logFile); }
	for (char **env = environ; *env; ++env)
	{
		int envLen = (int)strnlen_s(*env, INT_MAX);
		int i = ILibString_IndexOf(*env, envLen, "=", 1);
		if (i > 0)
		{
			if (i == 7 && strncmp("DISPLAY", *env, 7) == 0)
			{
				currentDisplayId = (unsigned short)atoi(*env + i + 2);
				if (logFile) { fprintf(logFile, "ENV[DISPLAY] = %s\n", *env + i + 2); fflush(logFile); }
				break;
			}
		}
	}

	// Init the kvm
	if (logFile) { fprintf(logFile, "Before kvm_init(%d).\n", currentDisplayId); fflush(logFile); }
	if (kvm_init(currentDisplayId) != 0) { return (void*)-1; }
	kvm_send_display_list();
	//fprintf(logFile, "After kvm_init.\n"); fflush(logFile);

	g_shutdown = 0;

	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = kvm_server_sighandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO;
	ignore_result(sigaction(SIGTERM, &action, NULL));

	//pthread_create(&kvmthread, NULL, kvm_mainloopinput, parm);
	//fprintf(logFile, "Created the kvmthread.\n"); fflush(logFile);

	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char pchRequest2[30000];
	ssize_t cbBytesRead = 0;

	while (!g_shutdown) 
	{
		for (r = 0; r < TILE_HEIGHT_COUNT; r++) 
		{
			for (c = 0; c < TILE_WIDTH_COUNT; c++) 
			{
				g_tileInfo[r][c].flag = TILE_TODO;
#ifdef KVM_ALL_TILES
				g_tileInfo[r][c].crc = 0xFF;
#endif
			}
		}
		//fprintf(logFile, "Before CheckDesktopSwitch.\n"); fflush(logFile);
		CheckDesktopSwitch(1);
		//fprintf(logFile, "After CheckDesktopSwitch.\n"); fflush(logFile);

		imagedisplay = x11_exports->XOpenDisplay(CURRENT_XDISPLAY);
		if (imagedisplay == NULL) { g_shutdown = 1; break; }

		if (DisplayWidth(imagedisplay, CURRENT_DISPLAY_ID) != VSCREEN_WIDTH ||
			DisplayHeight(imagedisplay, CURRENT_DISPLAY_ID) != VSCREEN_HEIGHT ||
			DefaultDepth(eventdisplay, CURRENT_DISPLAY_ID) != SCREEN_DEPTH)
		{
			int old = TILE_HEIGHT_COUNT;
			VSCREEN_WIDTH  = DisplayWidth(imagedisplay, CURRENT_DISPLAY_ID);
			VSCREEN_HEIGHT = DisplayHeight(imagedisplay, CURRENT_DISPLAY_ID);
			SCREEN_DEPTH   = DefaultDepth(imagedisplay, CURRENT_DISPLAY_ID);
			if (logFile) { fprintf(logFile, "SLAVE/KVM Virtual Screen Changed: %d x %d x %d bpp\n", VSCREEN_WIDTH, VSCREEN_HEIGHT, SCREEN_DEPTH); fflush(logFile); }

			// Re-enumerate physical monitors and update capture region
			kvm_enumerate_monitors();

			TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
			TILE_WIDTH_COUNT  = SCREEN_WIDTH  / TILE_WIDTH;
			if (SCREEN_WIDTH  % TILE_WIDTH)  { TILE_WIDTH_COUNT++; }
			if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }

			kvm_send_resolution();
			kvm_send_display_list();
			reset_tile_info(old);
		}


		FD_ZERO(&readset);
		FD_ZERO(&errorset);
		FD_ZERO(&writeset);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		FD_SET(master2slave[0], &readset);
		if (select(FD_SETSIZE, &readset, &writeset, &errorset, &tv) > 0 && FD_ISSET(master2slave[0], &readset))
		{

			//fprintf(logFile, "Reading from master in kvm_mainloopinput\n");
			cbBytesRead = read(master2slave[0], pchRequest2 + len, 30000 - len);
			//fprintf(logFile, "Read %d bytes from master in kvm_mainloopinput\n", cbBytesRead);
			if (cbBytesRead == -1 || cbBytesRead == 0 || g_shutdown)
			{
				g_shutdown = 1;
				break;
			}
			len += cbBytesRead;
			ptr2 = 0;
			while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, cbBytesRead - ptr)) != 0) { ptr += ptr2; }
			if (ptr == len) { len = 0; ptr = 0; }
		}

		if (cursordisplay == NULL)
		{
			if ((cursordisplay = x11_exports->XOpenDisplay(CURRENT_XDISPLAY)))
			{
				Window rootwin = x11_exports->XRootWindow(cursordisplay, CURRENT_DISPLAY_ID);
				if (xfixes_exports->XFixesQueryExtension(cursordisplay, &event_base, &error_base))
				{
					xfixes_exports->XFixesSelectCursorInput(cursordisplay, rootwin, 1); // Register for Cursor Change Notifications
					x11_exports->XSync(cursordisplay, 0);								// Sync with XServer
					cursor_descriptor = x11_exports->XConnectionNumber(cursordisplay);	// Get the FD to use in select
				}
				curcursor = kvm_fetch_currentCursor(cursordisplay);						// Cursor Type

				if (xkb_exports != NULL)
				{
					int kberror_base = 0, major = 0, minor = 0, opcode = 0;
					if (xkb_exports->XkbQueryExtension(cursordisplay, &opcode, &kbevent_base, &kberror_base, &major, &minor))
					{
						xkb_exports->XkbSelectEvents(cursordisplay, XkbUseCoreKbd, XkbStateNotifyMask, XkbStateNotifyMask);
					}
				}
			}
		}
		else if (cursor_descriptor > 0)
		{
			FD_ZERO(&readset);
			FD_ZERO(&errorset);
			FD_ZERO(&writeset);
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			FD_SET(cursor_descriptor, &readset);
			if (select(FD_SETSIZE, &readset, &writeset, &errorset, &tv) > 0 && FD_ISSET(cursor_descriptor, &readset))
			{
				// We have a waiting event
				while (x11_exports->XPending(cursordisplay))
				{					
					x11_exports->XNextEvent(cursordisplay, &XE);
					if (XE.type == (event_base + 1))
					{
						char buffer[8];
						char *name = NULL;

						if (sizeof(void*) == 8)
						{
							// 64bit
							if (((uint64_t*)((char*)&XE + 64))[0] != 0)
							{
								name = x11_exports->XGetAtomName(cursordisplay, ((Atom*)((char*)&XE + 64))[0]);
							}
						}
						else
						{
							// 32bit
							if (((uint32_t*)((char*)&XE + 32))[0] != 0)
							{
								name = x11_exports->XGetAtomName(cursordisplay, ((Atom*)((char*)&XE + 32))[0]);
							}
						}
					
						if (name != NULL)
						{
							if (strcmp(name, "bottom_left_corner") == 0 || strcmp(name, "sw-resize") == 0) { curcursor = KVM_MouseCursor_SIZENESW; }
							if (strcmp(name, "bottom_right_corner") == 0 || strcmp(name, "se-resize") == 0) { curcursor = KVM_MouseCursor_SIZENWSE; }
							if (strcmp(name, "bottom_side") == 0) { curcursor = KVM_MouseCursor_SIZENS; }
							if (strcmp(name, "fleur") == 0) { curcursor = KVM_MouseCursor_SIZEALL; }
							if (strcmp(name, "hand1") == 0 || strcmp(name, "pointer")==0) { curcursor = KVM_MouseCursor_HAND; }
							if (strcmp(name, "hand2") == 0) { curcursor = KVM_MouseCursor_HAND; }
							if (strcmp(name, "left_ptr") == 0) { curcursor = KVM_MouseCursor_ARROW; }
							if (strcmp(name, "left_side") == 0 || strcmp(name, "w-resize") == 0 || strcmp(name, "e-resize") == 0) { curcursor = KVM_MouseCursor_SIZEWE; }
							if (strcmp(name, "right_side") == 0) { curcursor = KVM_MouseCursor_SIZEWE; }
							if (strcmp(name, "top_left_corner") == 0 || strcmp(name, "nw-resize") == 0) { curcursor = KVM_MouseCursor_SIZENWSE; }
							if (strcmp(name, "top_right_corner") == 0 || strcmp(name, "ne-resize") == 0) { curcursor = KVM_MouseCursor_SIZENESW; }
							if (strcmp(name, "top_side") == 0) { curcursor = KVM_MouseCursor_SIZENS; }
							if (strcmp(name, "watch") == 0) { curcursor = KVM_MouseCursor_WAIT; }
							if (strcmp(name, "top_side") == 0 || strcmp(name, "n-resize") == 0 || strcmp(name, "s-resize") == 0) { curcursor = KVM_MouseCursor_SIZENS; }
							if (strcmp(name, "xterm") == 0 || strcmp(name, "ibeam") == 0 || strcmp(name, "text") == 0) { curcursor = KVM_MouseCursor_IBEAM; }
							x11_exports->XFree(name);
						}
						else
						{
							// Name was NULL, so as a last ditch effort, lets try to look at the XFixesCursorImage
							curcursor = kvm_fetch_currentCursor(cursordisplay);
						}

						if (sentHideCursor == 0)
						{
							((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
							((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
							buffer[4] = (char)curcursor;																// Cursor Type
							written = write(slave2master[1], buffer, 5);
							fsync(slave2master[1]);
						}
					}
					if (kbevent_base != 0 && XE.type == kbevent_base)
					{
						XkbStateNotifyEvent *e = (XkbStateNotifyEvent*)&XE;
						if (e->event_type == 3) // KEY_UP
						{
							if (logFile) { fprintf(logFile, "Keyboard Evented State: NUM[%d], SCROLL[%d], CAPS[%d]\n", (e->mods & 16) == 16, (e->mods & 32) == 32, (e->mods & 2) == 2); fflush(logFile); }
							char buffer[5];
							((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
							((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
							buffer[4] = (((e->mods & 16) == 16) | (((e->mods & 32) == 32) << 1) | (((e->mods & 2) == 2) << 2));

							ignore_result(write(slave2master[1], buffer, sizeof(buffer)));
						}
					}
				}
			}
		}

		image = x11ext_exports->XShmCreateImage(imagedisplay,
			DefaultVisual(imagedisplay, SCREEN_NUM), // Use a correct visual. Omitted for brevity     
			SCREEN_DEPTH,
			ZPixmap, NULL, &shminfo, SCREEN_WIDTH, SCREEN_HEIGHT);
		shminfo.shmid = shmget(IPC_PRIVATE,
			image->bytes_per_line * image->height,
			IPC_CREAT | 0777);
		shminfo.shmaddr = image->data = shmat(shminfo.shmid, 0, 0);
		shminfo.readOnly = False;
		x11ext_exports->XShmAttach(imagedisplay, &shminfo);
		
		x11ext_exports->XShmGetImage(imagedisplay,
			RootWindowOfScreen(ScreenOfDisplay(imagedisplay, CURRENT_DISPLAY_ID)),
			image,
			CAPTURE_X,
			CAPTURE_Y,
			AllPlanes);

		//image = XGetImage(imagedisplay,
		//		RootWindowOfScreen(DefaultScreenOfDisplay(imagedisplay))
		//		, 0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, AllPlanes, ZPixmap);


		if (image == NULL) {
			g_shutdown = 1;
		}
		else 
		{
			rs = x11_exports->XQueryPointer(imagedisplay, RootWindowOfScreen(ScreenOfDisplay(imagedisplay, CURRENT_DISPLAY_ID)),
				&rr, &cr, &rx, &ry, &wx, &wy, &mr);
			if (rs == 1 && cursordisplay != NULL)
			{
				if (gRemoteMouseRenderDefault != 0 || (remoteMouseX != rx && remoteMouseY != ry))
				{
					cimage = (char*)xfixes_exports->XFixesGetCursorImage(cursordisplay);
					unsigned short w = ((unsigned short*)(cimage + 4))[0];
					unsigned short h = ((unsigned short*)(cimage + 6))[0];
					unsigned short xhot = ((unsigned short*)(cimage + 8))[0];
					unsigned short yhot = ((unsigned short*)(cimage + 10))[0];
					// Translate absolute cursor pos to capture-region-relative coordinates
					int localRx = rx - CAPTURE_X;
					int localRy = ry - CAPTURE_Y;
					unsigned short mx = (localRx > (int)xhot) ? (unsigned short)(localRx - xhot) : 0;
					unsigned short my = (localRy > (int)yhot) ? (unsigned short)(localRy - yhot) : 0;
					char *pixels = cimage + (sizeof(void*) == 8 ? 24 : 16);

					if ((mx + w) > (unsigned short)SCREEN_WIDTH)  { mx = (unsigned short)(SCREEN_WIDTH  - w); }
					if ((my + h) > (unsigned short)SCREEN_HEIGHT) { my = (unsigned short)(SCREEN_HEIGHT - h); }

					// Only render cursor if it is within the current capture region
					if (localRx >= 0 && localRx < SCREEN_WIDTH && localRy >= 0 && localRy < SCREEN_HEIGHT)
					{
						bitblt(pixels, (int)w, (int)h, 0, 0, (int)w, (int)h, image->data, SCREEN_WIDTH, SCREEN_HEIGHT, mx, my, 1);
					}

					if (sentHideCursor == 0)
					{
						char tmpbuffer[8];
						sentHideCursor = 1;
						((unsigned short*)tmpbuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
						((unsigned short*)tmpbuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
						tmpbuffer[4] = (char)KVM_MouseCursor_NONE;														// Cursor Type
						written = write(slave2master[1], tmpbuffer, 5);
						fsync(slave2master[1]);
					}
					x11_exports->XFree(cimage);
				}
				else
				{
					if (sentHideCursor != 0)
					{
						char tmpbuffer[8];
						sentHideCursor = 1;
						((unsigned short*)tmpbuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
						((unsigned short*)tmpbuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
						tmpbuffer[4] = (char)curcursor;																	// Cursor Type
						written = write(slave2master[1], tmpbuffer, 5);
						fsync(slave2master[1]);
					}
					sentHideCursor = 0;
				}
			}
			getScreenBuffer((char **)&desktop, &desktopsize, image);
			(void)update_tile_checksums(desktop, desktopsize);

			for (y = 0; y < TILE_HEIGHT_COUNT; y++) {
				for (x = 0; x < TILE_WIDTH_COUNT; x++) {
					height = TILE_HEIGHT * y;
					width = TILE_WIDTH * x;

					if (g_shutdown) { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }

					if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND) {
						continue;
					}

					if (getTileAt(width, height, &buf, &tilesize, desktop, desktopsize, y, x) < 0)
                    { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }

					if (buf && !g_shutdown)
					{
						// Write the reply to the pipe.
						//fprintf(logFile, "Writing to master in kvm_server_mainloop\n");
						written = write(slave2master[1], buf, tilesize);
						fsync(slave2master[1]);
						//fprintf(logFile, "Wrote %d bytes to master in kvm_server_mainloop\n", written);
						free(buf);
						if (written == -1) { /*ILIBMESSAGE("KVMBREAK-K2\r\n");*/ g_shutdown = 1; height = SCREEN_HEIGHT; width = SCREEN_WIDTH; break; }
					}
				}
			}
		}
		
		x11ext_exports->XShmDetach(imagedisplay, &shminfo);
		XDestroyImage(image); image = NULL;
		shmdt(shminfo.shmaddr);
		shmctl(shminfo.shmid, IPC_RMID, 0);
		
		if (imagedisplay != NULL) 
		{
			x11_exports->XCloseDisplay(imagedisplay);
			imagedisplay = NULL;
		}

		// We can't go full speed here, we need to slow this down.
		height = FRAME_RATE_TIMER;
		while (!g_shutdown && height > 0)
		{
			if (height > 50)
			{
				height -= 50;
				maxsleep = 50000;
			}
			else 
			{
				maxsleep = height * 1000;
				height = 0;
			}

			usleep(maxsleep);
		}
	}

	if (desktop != NULL) { free(desktop); desktop = NULL; }
	close(slave2master[1]);
	close(master2slave[0]);
	slave2master[1] = 0;
	master2slave[0] = 0;

	//ILIBLOGMESSAGEX("UNMAPPING ALL");

	KeyActionUnicode_UNMAP_ALL(eventdisplay);
	x11_exports->XCloseDisplay(eventdisplay);
	eventdisplay  = NULL;

	if (cursordisplay != NULL)
	{
		x11_exports->XCloseDisplay(cursordisplay);
		cursordisplay = NULL;
	}

	if (g_tileInfo != NULL)
	{
		for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); }
		free(g_tileInfo);
		g_tileInfo = NULL;
	}
	jpeg_encoder_cleanup();
	if(tilebuffer != NULL) { free(tilebuffer); tilebuffer = NULL; }
	return (void*)0;
}

void* kvm_server_mainloop(void* parm)
{
	int sessionUid = (int)(intptr_t)parm;
	kvm_screenreader_mode_t screenreaderMode = kvm_screenreader_mode_for_uid(sessionUid);
	if (screenreaderMode == KVM_SCREENREADER_MODE_DRM)
	{
		if (logFile) { fprintf(logFile, "Using DRM KVM backend\n"); fflush(logFile); }
		return kvm_server_mainloop_drm(parm);
	}
	return kvm_server_mainloop_x11(parm);
}

void kvm_relay_readSink(ILibProcessPipe_Pipe sender, char *buffer, size_t bufferLen, size_t* bytesConsumed)
{
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)ILibMemory_Extra(sender))[0];
	void *reserved = ((void**)ILibMemory_Extra(sender))[1];
	unsigned short size;

	if (bufferLen > 4)
	{
		if (ntohs(ILibUnaligned_Read16(buffer)) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (8 + (int)ntohl(ILibUnaligned_Read32(buffer + 4))))
				{
					*bytesConsumed = 8 + (int)ntohl(ILibUnaligned_Read32(buffer + 4));
					writeHandler(buffer, *bytesConsumed, reserved);
					return;
				}
			}
		}
		else
		{
			size = ntohs(ILibUnaligned_Read16(buffer + 2));
			if (size <= bufferLen)
			{
				*bytesConsumed = size;
				writeHandler(buffer, size, reserved);
				return;
			}
		}
	}
	*bytesConsumed = 0;

}

#include "../../../microstack/ILibParsers.h"

// --- KVM capture auto-recovery (session handover) -----------------------------------------------
// When a capture child exits unexpectedly (logout / user-switch / crash) the child's pipe breaks and
// kvm_relay_brokenPipeSink() runs (a deliberate viewer teardown clears this handler to NULL first, so
// it never runs then). Instead of only telling the viewer the child died, we ask the agent to
// re-derive the CURRENT console session uid and re-fork. Rate-limited so a genuinely unrecoverable
// child cannot storm-fork.
#define KVM_AUTORECOVER_RESET_MS   30000	// a child that ran at least this long was healthy: reset the burst
#define KVM_FORK_RETRY_DELAY_MS     2000
#define KVM_FORK_RETRY_MAX          10

static uint64_t g_lastKvmForkMs = 0;		// monotonic ms when the current child was forked
static int g_kvmForkRetryCount = 0;
static int g_kvmForkRetryDispatch = 0;

// Implemented in agentcore.c: re-derive consoleUid()/X env and re-fork the capture child (reuses the
// same path as a live user-sessions 'changed' event).
extern void ILibDuktape_MeshAgent_RemoteDesktop_KvmAutoRecover(void *reservedPtrs);

static uint64_t kvm_relay_now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
	return (((uint64_t)ts.tv_sec) * 1000ULL) + (((uint64_t)ts.tv_nsec) / 1000000ULL);
}

typedef struct kvm_child_reaper
{
	void *chain;
	pid_t pid;
	uint64_t killDeadline;
} kvm_child_reaper;

static void kvm_relay_reap_shutdown(void *object)
{
	kvm_child_reaper *child = (kvm_child_reaper*)object;
	kill(child->pid, SIGKILL);
	while (waitpid(child->pid, NULL, 0) < 0 && errno == EINTR) {}
	free(child);
}

static void kvm_relay_reap(void *object)
{
	kvm_child_reaper *child = (kvm_child_reaper*)object;
	pid_t result = waitpid(child->pid, NULL, WNOHANG);
	if (result == 0 || (result < 0 && errno == EINTR))
	{
		// EOF can arrive before exit; a stuck capture must not block the agent chain.
		if (kvm_relay_now_ms() >= child->killDeadline)
		{
			kill(child->pid, SIGKILL);
			child->killDeadline = UINT64_MAX;
		}
		ILibLifeTime_AddEx(ILibGetBaseTimer(child->chain), child, 100, kvm_relay_reap, kvm_relay_reap_shutdown);
		return;
	}
	free(child);
}

#if defined(__linux__)
typedef struct kvm_capture_chain_link
{
    ILibChain_Link link;
    kvm_capture_broker *broker;
} kvm_capture_chain_link;
static kvm_capture_chain_link *g_captureLink;
static uint64_t g_captureGeneration;
typedef struct kvm_capture_reaper {void *chain;int pin;} kvm_capture_reaper;
static void kvm_capture_reap_shutdown(void *object)
{
    kvm_capture_reaper *child=object;
    kvm_capture_helper_reap(child->pin);close(child->pin);free(child);
}
static void kvm_capture_reap(void *object)
{
    kvm_capture_reaper *child=object;
    if(kvm_capture_helper_reap(child->pin)){close(child->pin);free(child);return;}
    ILibLifeTime_AddEx(ILibGetBaseTimer(child->chain),child,100,kvm_capture_reap,kvm_capture_reap_shutdown);
}
static void kvm_capture_link_stop(kvm_capture_chain_link *link)
{
    if (link == NULL || link->broker == NULL) return;
    int pin = kvm_capture_broker_free(link->broker);
    link->broker = NULL;
    if (pin >= 0)
    {
        kvm_capture_reaper *child = calloc(1, sizeof(*child));
        if (child == NULL) { ILIBCRITICALEXIT(254); }
        child->chain = g_kvmChain; child->pin = pin;
        if (child->chain == NULL || ILibIsChainBeingDestroyed(child->chain)) kvm_capture_reap_shutdown(child);
        else kvm_capture_reap(child);
    }
}
static void kvm_capture_link_pre(void *object, fd_set *readset, fd_set *writeset, fd_set *errorset, int *blocktime)
{
    kvm_capture_chain_link *link = object;
    if(!kvm_capture_broker_select(link->broker,readset,writeset,errorset)){kvm_capture_link_stop(link);return;}
    uint64_t deadline = kvm_capture_broker_deadline(link->broker), now = kvm_relay_now_ms();
    if (deadline)
    {
        uint64_t remaining = deadline > now ? deadline-now : 0;
        if (remaining < (uint64_t)*blocktime) *blocktime = (int)remaining;
    }
}
static void kvm_capture_link_post(void *object, int selected, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
    (void)selected; (void)writeset;
    kvm_capture_chain_link *link=object;int fds[6];
    int count=kvm_capture_broker_fds(link->broker,fds),ready=0;
    for(int i=0;i<count;++i) if(fds[i]<FD_SETSIZE&&(FD_ISSET(fds[i],readset)||FD_ISSET(fds[i],errorset)))ready=1;
    int writefd=kvm_capture_broker_write_fd(link->broker);
    if(writefd>=0&&writefd<FD_SETSIZE&&FD_ISSET(writefd,writeset))ready=1;
    uint64_t deadline=kvm_capture_broker_deadline(link->broker);
    if(ready||(deadline&&kvm_relay_now_ms()>=deadline))kvm_capture_broker_step(link->broker);
}
static void kvm_capture_link_destroy(void *object)
{
    kvm_capture_link_stop(object); g_captureLink = NULL;
}
static void kvm_capture_link_start(int fd, pid_t worker, uid_t uid, uint64_t generation)
{
    if (g_captureLink == NULL)
    {
        g_captureLink = (kvm_capture_chain_link*)ILibChain_Link_Allocate(sizeof(*g_captureLink), 0);
        if (g_captureLink == NULL) { close(fd); return; }
        g_captureLink->link.PreSelectHandler = kvm_capture_link_pre;
        g_captureLink->link.PostSelectHandler = kvm_capture_link_post;
        g_captureLink->link.DestroyHandler = kvm_capture_link_destroy;
        ILibChain_SafeAdd(g_kvmChain, g_captureLink);
    }
    g_captureLink->broker = kvm_capture_broker_new(fd, worker, uid, generation);
}
#endif

static void kvm_relay_stop_child(int signalNumber)
{
#if defined(__linux__)
    kvm_capture_link_stop(g_captureLink);
#endif
	if (master2slave[1] >= 0) { close(master2slave[1]); master2slave[1] = -1; }
	if (g_slavekvm > 0)
	{
		kvm_child_reaper *child = (kvm_child_reaper*)malloc(sizeof(kvm_child_reaper));
		if (child == NULL) { ILIBCRITICALEXIT(254); }
		child->chain = g_kvmChain;
		child->pid = g_slavekvm;
#if defined(__linux__)
        kvm_bridge_worker_record(g_slavekvm, 0, 1);
#endif
		child->killDeadline = kvm_relay_now_ms() + 1000;
		g_slavekvm = 0;
		if (signalNumber != 0) { kill(child->pid, signalNumber); }
		if (child->chain == NULL || ILibIsChainBeingDestroyed(child->chain)) { kvm_relay_reap_shutdown(child); }
		else { kvm_relay_reap(child); }
	}
}

// A short-failure burst progressively opens the circuit breaker, but never permanently disables
// access. A later healthy console therefore recovers without requiring someone to act locally.
static uint32_t kvm_relay_autorecover_delay_ms(void)
{
	uint64_t now = kvm_relay_now_ms();
	uint32_t delay = kvm_recovery_next_delay_ms(&g_restartcount, g_lastKvmForkMs, now, KVM_AUTORECOVER_RESET_MS);
	if (g_totalRestartCount < INT_MAX) { ++g_totalRestartCount; }
	return delay;
}

// Deferred off the broken-pipe callback (so we don't re-enter pipe teardown) to perform the recovery.
static void kvm_relay_autoRecoverSink(void *sender)
{
	if (!ILibMemory_CanaryOK(sender)) { return; }	// pipe freed (deliberate teardown) before the timer fired
	if (g_shutdown || g_slavekvm != 0) { return; }	// shutting down, or a child is already running again
	ILibDuktape_MeshAgent_RemoteDesktop_KvmAutoRecover(((void**)ILibMemory_Extra(sender))[1]);
}

static void kvm_relay_forkRetrySink(void *sender)
{
	void *reserved;
	if (!ILibMemory_CanaryOK(sender)) { return; }
	reserved = ((void**)ILibMemory_Extra(sender))[1];
	g_kvmForkRetryDispatch = 1;
	ILibDuktape_MeshAgent_RemoteDesktop_KvmAutoRecover(reserved);
	g_kvmForkRetryDispatch = 0;
}

void kvm_relay_brokenPipeSink_2(void *sender)
{
	if (!ILibMemory_CanaryOK(sender)) { return; } // pipe was freed before this 4s timer fired
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)ILibMemory_Extra(sender))[0];
	void *reserved = ((void**)ILibMemory_Extra(sender))[1];
	char msg[] = "KVM Child process has unexpectedly exited";
	char buffer[4096];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);		// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(sizeof(msg) + 3));// Write the size
	memcpy_s(buffer + 4, sizeof(msg) - 1, msg, sizeof(msg) - 1);

	writeHandler(buffer, sizeof(msg) + 3, reserved);
}
void kvm_relay_brokenPipeSink(ILibProcessPipe_Pipe sender)
{
	void *chain = ((void**)ILibMemory_Extra(sender))[2];
	uint32_t recoveryDelay;
	kvm_relay_stop_child(0);

	// The child exited without a deliberate teardown (teardown clears this handler first). Try to
	// auto-recover the session (logout / user-switch) rather than just reporting the child death.
	// Deliberate teardown clears this handler and its timer. Unexpected failures always retain a
	// bounded delayed probe; the increasing delay prevents a process storm without making the fifth
	// transient failure terminal for the rest of the viewer session.
	if (!g_shutdown)
	{
		recoveryDelay = kvm_relay_autorecover_delay_ms();
		fprintf(stderr, "MeshAgent: KVM capture worker exited; recovery attempt=%u in %u ms\n",
			(unsigned int)g_restartcount, (unsigned int)recoveryDelay);
		fflush(stderr);
		ILibLifeTime_AddEx(ILibGetBaseTimer(chain), sender, recoveryDelay, kvm_relay_autoRecoverSink, NULL);
		return;
	}

	ILibLifeTime_AddEx(ILibGetBaseTimer(chain), sender, 4000, kvm_relay_brokenPipeSink_2, NULL);
}

void* kvm_relay_restart(int paused, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid, char* authToken, char *dispid)
{
	ILibProcessPipe_Pipe slave_out;

	g_kvmChain = ((ILibChain_Link*)processPipeMgr)->ParentChain;
	if (paused != 0 || !g_kvmForkRetryDispatch) { g_kvmForkRetryCount = 0; }
	kvm_relay_stop_child(SIGKILL);

	if (pipe(slave2master) != 0) { return NULL; }
	if (pipe(master2slave) != 0)
	{
		close(slave2master[0]); close(slave2master[1]);
		slave2master[0] = slave2master[1] = -1;
		return NULL;
	}

	// Two Phase is ok here, because all our fork/vfork calls always happen on the same thread
	fcntl(slave2master[0], F_SETFD, FD_CLOEXEC);
	fcntl(slave2master[1], F_SETFD, FD_CLOEXEC);
	fcntl(master2slave[0], F_SETFD, FD_CLOEXEC);
	fcntl(master2slave[1], F_SETFD, FD_CLOEXEC);

	slave_out = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(processPipeMgr, slave2master[0], 3 * sizeof(void*));	
	if (slave_out == NULL)
	{
		close(slave2master[0]);
		close(slave2master[1]);
		close(master2slave[0]);
		close(master2slave[1]);
		slave2master[0] = slave2master[1] = -1;
		master2slave[0] = master2slave[1] = -1;
		return NULL;
	}
	((void**)ILibMemory_Extra(slave_out))[0] = writeHandler;
	((void**)ILibMemory_Extra(slave_out))[1] = reserved;
	((void**)ILibMemory_Extra(slave_out))[2] = ((ILibChain_Link*)processPipeMgr)->ParentChain;

	int registrationGate[2];
    if (pipe(registrationGate) != 0) { ILibProcessPipe_FreePipe(slave_out); return NULL; }
    int registrationUid = uid;
#if defined(__linux__)
    kvm_wayland_console_session registrationSession;
    int haveCaptureSession = kvm_wayland_active_console_session(&registrationSession);
    if (haveCaptureSession) registrationUid = registrationSession.uid;
    int capturePair[2] = {-1, -1};
    pid_t captureParent = getpid();
    uint64_t captureGeneration = ++g_captureGeneration;
    if (!captureGeneration) captureGeneration = ++g_captureGeneration;
    if (geteuid() == 0 && haveCaptureSession && registrationUid > 0 && !strcmp(registrationSession.type, "wayland"))
    {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, capturePair) != 0)
            capturePair[0] = capturePair[1] = -1;
    }
#endif
    g_slavekvm = fork();
	if (g_slavekvm < 0)
	{
#if defined(__linux__)
        if (capturePair[0] >= 0) close(capturePair[0]);
        if (capturePair[1] >= 0) close(capturePair[1]);
#endif
        close(registrationGate[0]); close(registrationGate[1]);
		close(slave2master[1]);
		close(master2slave[0]); close(master2slave[1]);
		slave2master[0] = slave2master[1] = master2slave[0] = master2slave[1] = -1;
		g_slavekvm = 0;
		if (paused == 0 && ++g_kvmForkRetryCount < KVM_FORK_RETRY_MAX)
		{
			ILibLifeTime_AddEx(ILibGetBaseTimer(g_kvmChain), slave_out, KVM_FORK_RETRY_DELAY_MS, kvm_relay_forkRetrySink, NULL);
			return slave_out;
		}
		g_kvmForkRetryCount = 0;
		ILibProcessPipe_FreePipe(slave_out);
		return NULL;
	}

	if (g_slavekvm == 0) //slave
    {
#if defined(__linux__)
        if (capturePair[0] >= 0) close(capturePair[0]);
        if (capturePair[1] >= 0) kvm_capture_worker_attach(capturePair[1], captureParent, captureGeneration);
#endif
        char registered;
        close(registrationGate[1]);
        ssize_t gateRead;
        do { gateRead = read(registrationGate[0], &registered, 1); } while (gateRead < 0 && errno == EINTR);
        close(registrationGate[0]);
        if (gateRead != 1) _exit(1);
		close(slave2master[0]);
		close(master2slave[1]);

		if (SLAVELOG != 0) { logFile = fopen("/tmp/slave", "w"); }

		if (g_ILibCrashDump_path != NULL)
		{
#if !defined(_FREEBSD)
			prctl(PR_SET_DUMPABLE, 1);
			if (logFile) { fprintf(logFile, "SLAVE/KVM DUMPABLE: %s\n", prctl(PR_GET_DUMPABLE, 0)?"YES":"NO"); fflush(logFile); }
#endif
		}
		else
		{
			if (logFile) { fprintf(logFile, "SLAVE/KVM CoreDumps DISABLED\n"); fflush(logFile); }
		}


		//fprintf(logFile, "Starting kvm_server_mainloop\n");
		if (authToken != NULL) { setenv("XAUTHORITY", authToken, 1); }
		if (dispid != NULL) { setenv("DISPLAY", dispid, 1); }

		kvm_registered_uid = registrationUid;
        kvm_server_mainloop((void*)(intptr_t)uid);
		_exit(0);
		return(NULL);
	}
	else
	{ //master
#if defined(__linux__)
        if (capturePair[1] >= 0) close(capturePair[1]);
        if (capturePair[0] >= 0) kvm_capture_link_start(capturePair[0], g_slavekvm, registrationUid, captureGeneration);
#endif
        close(registrationGate[0]);
#if defined(__linux__)
        kvm_bridge_worker_record(g_slavekvm, (uid_t)registrationUid, 0);
#endif
        ignore_result(write(registrationGate[1], "1", 1));
        close(registrationGate[1]);
		// A child is (re)running now: clear any stale shutdown flag left by kvm_cleanup() on a restart
		// path, and stamp the fork time so the auto-recovery burst gate can tell a healthy child (ran a
		// while) from a fork storm (dies immediately).
		g_shutdown = 0;
		g_kvmForkRetryCount = 0;
		g_lastKvmForkMs = kvm_relay_now_ms();
		close(slave2master[1]);
		close(master2slave[0]);
		slave2master[0] = slave2master[1] = master2slave[0] = -1;
		if (SLAVELOG != 0) { logFile = fopen("/tmp/master", "w"); }
		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "Child KVM (pid=%d)", g_slavekvm);

		// We will asyncronously read from the pipe, so we can just return
		ILibProcessPipe_Pipe_AddPipeReadHandler(slave_out, 65535, kvm_relay_readSink);
		ILibProcessPipe_Pipe_SetBrokenPipeHandler(slave_out, kvm_relay_brokenPipeSink);
		ILibProcessPipe_Pipe_ResetMetadata(slave_out, tmp);
		return(slave_out);
	}
}


// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
void* kvm_relay_setup(void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid, char *authToken, char *dispid)
{
	if (kvmthread != (pthread_t)NULL || g_slavekvm != 0) return 0;
	g_restartcount = 0;
	return kvm_relay_restart(1, processPipeMgr, writeHandler, reserved, uid, authToken, dispid);
}

// Force a KVM reset & refresh
void kvm_relay_reset()
{
	char buffer[4];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size
	kvm_relay_feeddata(buffer, 4);
}

// Clean up the KVM session.
void kvm_cleanup()
{
	g_shutdown = 1;
	kvm_relay_stop_child(SIGTERM);
	g_totalRestartCount = 0;
}
