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

#include "linux_events.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

#if defined(__linux__)

#include <linux/input.h>

struct libevdev;
struct libevdev_uinput;

typedef struct libevdev *(*kvm_libevdev_new_fn)(void);
typedef void (*kvm_libevdev_free_fn)(struct libevdev *dev);
typedef int (*kvm_libevdev_set_name_fn)(struct libevdev *dev, const char *name);
typedef int (*kvm_libevdev_enable_event_type_fn)(struct libevdev *dev, unsigned int type);
typedef int (*kvm_libevdev_enable_event_code_fn)(struct libevdev *dev, unsigned int type, unsigned int code, const void *data);
typedef int (*kvm_libevdev_uinput_create_from_device_fn)(const struct libevdev *dev, int uinput_fd, struct libevdev_uinput **uinput_dev);
typedef void (*kvm_libevdev_uinput_destroy_fn)(struct libevdev_uinput *uinput_dev);
typedef int (*kvm_libevdev_uinput_write_event_fn)(const struct libevdev_uinput *uinput_dev, unsigned int type, unsigned int code, int value);
typedef const char *(*kvm_libevdev_strerror_fn)(int errcode);

typedef struct kvm_evdev_exports
{
	void *library;
	kvm_libevdev_new_fn libevdev_new;
	kvm_libevdev_free_fn libevdev_free;
	kvm_libevdev_set_name_fn libevdev_set_name;
	kvm_libevdev_enable_event_type_fn libevdev_enable_event_type;
	kvm_libevdev_enable_event_code_fn libevdev_enable_event_code;
	kvm_libevdev_uinput_create_from_device_fn libevdev_uinput_create_from_device;
	kvm_libevdev_uinput_destroy_fn libevdev_uinput_destroy;
	kvm_libevdev_uinput_write_event_fn libevdev_uinput_write_event;
	kvm_libevdev_strerror_fn libevdev_strerror;
} kvm_evdev_exports;

typedef struct kvm_evdev_state
{
	struct libevdev *dev;
	struct libevdev_uinput *uinput;
	int active;
} kvm_evdev_state;

static kvm_evdev_exports g_kvm_evdev_exports = {0};
static kvm_evdev_state g_kvm_evdev_state = {0};

extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;

static const unsigned int g_kvm_evdev_alpha_keycodes[26] = {
	KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I, KEY_J, KEY_K, KEY_L, KEY_M,
	KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z
};
static const unsigned int g_kvm_evdev_digit_keycodes[10] = {
	KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9
};
static const unsigned int g_kvm_evdev_numpad_keycodes[10] = {
	KEY_KP0, KEY_KP1, KEY_KP2, KEY_KP3, KEY_KP4, KEY_KP5, KEY_KP6, KEY_KP7, KEY_KP8, KEY_KP9
};

#define KVM_LIBEVDEV_UINPUT_OPEN_MANAGED -2
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef KEY_BOOKMARKS
#define KEY_BOOKMARKS KEY_RESERVED
#endif
#ifndef KEY_HOMEPAGE
#define KEY_HOMEPAGE KEY_RESERVED
#endif
#ifndef KEY_MEDIA
#define KEY_MEDIA KEY_RESERVED
#endif
#ifndef KEY_PROG1
#define KEY_PROG1 KEY_RESERVED
#endif
#ifndef KEY_PROG2
#define KEY_PROG2 KEY_RESERVED
#endif
#ifndef KEY_BREAK
#define KEY_BREAK KEY_RESERVED
#endif
#ifndef KEY_OK
#define KEY_OK KEY_RESERVED
#endif
#ifndef KEY_KPCOMMA
#define KEY_KPCOMMA KEY_RESERVED
#endif
#ifndef KEY_PRINT
#define KEY_PRINT KEY_RESERVED
#endif

void kvm_events_evdev_shutdown();

static int kvm_events_evdev_load_exports()
{
	if (g_kvm_evdev_exports.library != NULL)
	{
		return 1;
	}

	g_kvm_evdev_exports.library = dlopen("libevdev.so.2", RTLD_NOW | RTLD_LOCAL);
	if (g_kvm_evdev_exports.library == NULL)
	{
		g_kvm_evdev_exports.library = dlopen("libevdev.so", RTLD_NOW | RTLD_LOCAL);
		if (g_kvm_evdev_exports.library == NULL)
		{
			return 0;
		}
	}

#define KVM_DLSYM_REQ(name)                                                                \
	g_kvm_evdev_exports.name = (kvm_##name##_fn)dlsym(g_kvm_evdev_exports.library, #name); \
	if (g_kvm_evdev_exports.name == NULL)                                                  \
	{                                                                                      \
		dlclose(g_kvm_evdev_exports.library);                                              \
		memset(&g_kvm_evdev_exports, 0, sizeof(g_kvm_evdev_exports));                      \
		return 0;                                                                          \
	}

	KVM_DLSYM_REQ(libevdev_new);
	KVM_DLSYM_REQ(libevdev_free);
	KVM_DLSYM_REQ(libevdev_set_name);
	KVM_DLSYM_REQ(libevdev_enable_event_type);
	KVM_DLSYM_REQ(libevdev_enable_event_code);
	KVM_DLSYM_REQ(libevdev_uinput_create_from_device);
	KVM_DLSYM_REQ(libevdev_uinput_destroy);
	KVM_DLSYM_REQ(libevdev_uinput_write_event);
	g_kvm_evdev_exports.libevdev_strerror = (kvm_libevdev_strerror_fn)dlsym(g_kvm_evdev_exports.library, "libevdev_strerror");

#undef KVM_DLSYM_REQ
	return 1;
}

static const char *kvm_events_evdev_error_string(int rc)
{
	int e = rc < 0 ? -rc : rc;
	const char *ret = NULL;

	if (g_kvm_evdev_exports.libevdev_strerror != NULL)
	{
		ret = g_kvm_evdev_exports.libevdev_strerror(e);
	}
	if (ret == NULL)
	{
		ret = strerror(e);
	}
	return ret == NULL ? "unknown error" : ret;
}

static int kvm_events_evdev_try_open_uinput()
{
	static const char *paths[] = { "/dev/uinput", "/dev/input/uinput", "/dev/misc/uinput" };
	size_t i = 0;
	int fd = -1;
	int lastErr = ENOENT;

	for (i = 0; i < (sizeof(paths) / sizeof(paths[0])); ++i)
	{
		fd = open(paths[i], O_RDWR | O_CLOEXEC);
		if (fd >= 0)
		{
			return fd;
		}
		lastErr = errno;
	}
	errno = lastErr;
	return -1;
}

static unsigned int kvm_events_evdev_vk_to_keycode(unsigned char vk)
{
	if (vk >= VK_0 && vk <= VK_9)
	{
		return g_kvm_evdev_digit_keycodes[vk - VK_0];
	}
	if (vk >= VK_A && vk <= VK_Z)
	{
		return g_kvm_evdev_alpha_keycodes[vk - VK_A];
	}
	if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9)
	{
		return g_kvm_evdev_numpad_keycodes[vk - VK_NUMPAD0];
	}
	if (vk >= VK_F1 && vk <= VK_F24)
	{
		return KEY_F1 + (vk - VK_F1);
	}

	switch (vk)
	{
	case VK_BACK:
		return KEY_BACKSPACE;
	case VK_TAB:
		return KEY_TAB;
	case VK_CLEAR:
		return KEY_CLEAR;
	case VK_RETURN:
		return KEY_ENTER;
	case VK_SHIFT:
		return KEY_LEFTSHIFT;
	case VK_CONTROL:
		return KEY_LEFTCTRL;
	case VK_MENU:
		return KEY_LEFTALT;
	case VK_PAUSE:
		return KEY_PAUSE;
	case VK_CAPITAL:
		return KEY_CAPSLOCK;
	case VK_ESCAPE:
		return KEY_ESC;
	case VK_SPACE:
		return KEY_SPACE;
	case VK_PRIOR:
		return KEY_PAGEUP;
	case VK_NEXT:
		return KEY_PAGEDOWN;
	case VK_END:
		return KEY_END;
	case VK_HOME:
		return KEY_HOME;
	case VK_LEFT:
		return KEY_LEFT;
	case VK_UP:
		return KEY_UP;
	case VK_RIGHT:
		return KEY_RIGHT;
	case VK_DOWN:
		return KEY_DOWN;
	case VK_SELECT:
		return KEY_SELECT;
	case VK_PRINT:
		return KEY_PRINT;
	case VK_EXECUTE:
		return KEY_OK;
	case VK_SNAPSHOT:
		return KEY_SYSRQ;
	case VK_INSERT:
		return KEY_INSERT;
	case VK_DELETE:
		return KEY_DELETE;
	case VK_HELP:
		return KEY_HELP;
	case VK_CANCEL:
		return KEY_BREAK;
	case VK_LWIN:
		return KEY_LEFTMETA;
	case VK_RWIN:
		return KEY_RIGHTMETA;
	case VK_APPS:
		return KEY_MENU;
	case VK_SLEEP:
		return KEY_SLEEP;
	case VK_MULTIPLY:
		return KEY_KPASTERISK;
	case VK_ADD:
		return KEY_KPPLUS;
	case VK_SEPARATOR:
		return KEY_KPCOMMA;
	case VK_SUBTRACT:
		return KEY_KPMINUS;
	case VK_DECIMAL:
		return KEY_KPDOT;
	case VK_DIVIDE:
		return KEY_KPSLASH;
	case VK_NUMLOCK:
		return KEY_NUMLOCK;
	case VK_SCROLL:
		return KEY_SCROLLLOCK;
	case VK_LSHIFT:
		return KEY_LEFTSHIFT;
	case VK_RSHIFT:
		return KEY_RIGHTSHIFT;
	case VK_LCONTROL:
		return KEY_LEFTCTRL;
	case VK_RCONTROL:
		return KEY_RIGHTCTRL;
	case VK_LMENU:
		return KEY_LEFTALT;
	case VK_RMENU:
		return KEY_RIGHTALT;
	case VK_BROWSER_BACK:
		return KEY_BACK;
	case VK_BROWSER_FORWARD:
		return KEY_FORWARD;
	case VK_BROWSER_REFRESH:
		return KEY_REFRESH;
	case VK_BROWSER_STOP:
		return KEY_STOP;
	case VK_BROWSER_SEARCH:
		return KEY_SEARCH;
	case VK_BROWSER_FAVORITES:
		return KEY_BOOKMARKS;
	case VK_BROWSER_HOME:
		return KEY_HOMEPAGE;
	case VK_VOLUME_MUTE:
		return KEY_MUTE;
	case VK_VOLUME_DOWN:
		return KEY_VOLUMEDOWN;
	case VK_VOLUME_UP:
		return KEY_VOLUMEUP;
	case VK_MEDIA_NEXT_TRACK:
		return KEY_NEXTSONG;
	case VK_MEDIA_PREV_TRACK:
		return KEY_PREVIOUSSONG;
	case VK_MEDIA_STOP:
		return KEY_STOPCD;
	case VK_MEDIA_PLAY_PAUSE:
		return KEY_PLAYPAUSE;
	case VK_MEDIA_LAUNCH_MAIL:
		return KEY_MAIL;
	case VK_MEDIA_LAUNCH_MEDIA_SELECT:
		return KEY_MEDIA;
	case VK_MEDIA_LAUNCH_APP1:
		return KEY_PROG1;
	case VK_MEDIA_LAUNCH_APP2:
		return KEY_PROG2;
	case VK_OEM_1:
		return KEY_SEMICOLON;
	case VK_OEM_PLUS:
		return KEY_EQUAL;
	case VK_OEM_COMMA:
		return KEY_COMMA;
	case VK_OEM_MINUS:
		return KEY_MINUS;
	case VK_OEM_PERIOD:
		return KEY_DOT;
	case VK_OEM_2:
		return KEY_SLASH;
	case VK_OEM_3:
		return KEY_GRAVE;
	case VK_OEM_4:
		return KEY_LEFTBRACE;
	case VK_OEM_5:
		return KEY_BACKSLASH;
	case VK_OEM_6:
		return KEY_RIGHTBRACE;
	case VK_OEM_7:
		return KEY_APOSTROPHE;
	default:
		return KEY_RESERVED;
	}
}

static int kvm_events_evdev_ascii_to_keycode(uint16_t unicode, unsigned int *keycode, int *needsShift)
{
	*needsShift = 0;
	*keycode = KEY_RESERVED;

	if (unicode >= 'a' && unicode <= 'z')
	{
		*keycode = g_kvm_evdev_alpha_keycodes[unicode - 'a'];
		return 1;
	}
	if (unicode >= 'A' && unicode <= 'Z')
	{
		*keycode = g_kvm_evdev_alpha_keycodes[unicode - 'A'];
		*needsShift = 1;
		return 1;
	}
	if (unicode >= '0' && unicode <= '9')
	{
		*keycode = g_kvm_evdev_digit_keycodes[unicode - '0'];
		return 1;
	}

	switch (unicode)
	{
	case ' ':
		*keycode = KEY_SPACE;
		return 1;
	case '\t':
		*keycode = KEY_TAB;
		return 1;
	case '\n':
	case '\r':
		*keycode = KEY_ENTER;
		return 1;
	case '\b':
		*keycode = KEY_BACKSPACE;
		return 1;
	case '-':
		*keycode = KEY_MINUS;
		return 1;
	case '_':
		*keycode = KEY_MINUS;
		*needsShift = 1;
		return 1;
	case '=':
		*keycode = KEY_EQUAL;
		return 1;
	case '+':
		*keycode = KEY_EQUAL;
		*needsShift = 1;
		return 1;
	case '[':
		*keycode = KEY_LEFTBRACE;
		return 1;
	case '{':
		*keycode = KEY_LEFTBRACE;
		*needsShift = 1;
		return 1;
	case ']':
		*keycode = KEY_RIGHTBRACE;
		return 1;
	case '}':
		*keycode = KEY_RIGHTBRACE;
		*needsShift = 1;
		return 1;
	case '\\':
		*keycode = KEY_BACKSLASH;
		return 1;
	case '|':
		*keycode = KEY_BACKSLASH;
		*needsShift = 1;
		return 1;
	case ';':
		*keycode = KEY_SEMICOLON;
		return 1;
	case ':':
		*keycode = KEY_SEMICOLON;
		*needsShift = 1;
		return 1;
	case '\'':
		*keycode = KEY_APOSTROPHE;
		return 1;
	case '"':
		*keycode = KEY_APOSTROPHE;
		*needsShift = 1;
		return 1;
	case ',':
		*keycode = KEY_COMMA;
		return 1;
	case '<':
		*keycode = KEY_COMMA;
		*needsShift = 1;
		return 1;
	case '.':
		*keycode = KEY_DOT;
		return 1;
	case '>':
		*keycode = KEY_DOT;
		*needsShift = 1;
		return 1;
	case '/':
		*keycode = KEY_SLASH;
		return 1;
	case '?':
		*keycode = KEY_SLASH;
		*needsShift = 1;
		return 1;
	case '`':
		*keycode = KEY_GRAVE;
		return 1;
	case '~':
		*keycode = KEY_GRAVE;
		*needsShift = 1;
		return 1;
	case '!':
		*keycode = KEY_1;
		*needsShift = 1;
		return 1;
	case '@':
		*keycode = KEY_2;
		*needsShift = 1;
		return 1;
	case '#':
		*keycode = KEY_3;
		*needsShift = 1;
		return 1;
	case '$':
		*keycode = KEY_4;
		*needsShift = 1;
		return 1;
	case '%':
		*keycode = KEY_5;
		*needsShift = 1;
		return 1;
	case '^':
		*keycode = KEY_6;
		*needsShift = 1;
		return 1;
	case '&':
		*keycode = KEY_7;
		*needsShift = 1;
		return 1;
	case '*':
		*keycode = KEY_8;
		*needsShift = 1;
		return 1;
	case '(':
		*keycode = KEY_9;
		*needsShift = 1;
		return 1;
	case ')':
		*keycode = KEY_0;
		*needsShift = 1;
		return 1;
	default:
		return 0;
	}
}

static int kvm_events_evdev_write(unsigned int type, unsigned int code, int value)
{
	int r = 0;
	if (g_kvm_evdev_state.active == 0 || g_kvm_evdev_state.uinput == NULL)
	{
		return -1;
	}

	r = g_kvm_evdev_exports.libevdev_uinput_write_event(g_kvm_evdev_state.uinput, type, code, value);
	if (r != 0)
	{
		kvm_events_evdev_shutdown();
	}
	return r;
}

static int kvm_events_evdev_sync()
{
	return kvm_events_evdev_write(EV_SYN, SYN_REPORT, 0);
}

static int kvm_events_evdev_scale_axis(int value, int maxPixels)
{
	if (maxPixels <= 1)
	{
		if (value < 0)
		{
			return 0;
		}
		if (value > 65535)
		{
			return 65535;
		}
		return value;
	}

	if (value < 0)
	{
		value = 0;
	}
	if (value >= maxPixels)
	{
		value = maxPixels - 1;
	}
	return (int)(((uint64_t)value * 65535ULL) / ((uint64_t)(maxPixels - 1)));
}

int kvm_events_evdev_init()
{
	struct input_absinfo absInfo;
	unsigned char vk = 0;
	int keyEnabled[KEY_MAX + 1];
	unsigned int keycode = KEY_RESERVED;
	int r = 0;
	int createRc = 0;
	int createManagedRc = 0;
	int uinputFd = -1;
	int uinputErrno = 0;

	if (g_kvm_evdev_state.active != 0)
	{
		return 1;
	}
	if (!kvm_events_evdev_load_exports())
	{
		printf("MeshAgent: Failed to load libevdev symbols\n");
		return 0;
	}

	if (g_kvm_evdev_state.dev != NULL || g_kvm_evdev_state.uinput != NULL)
	{
		kvm_events_evdev_shutdown();
	}
	memset(&g_kvm_evdev_state, 0, sizeof(g_kvm_evdev_state));

	g_kvm_evdev_state.dev = g_kvm_evdev_exports.libevdev_new();
	if (g_kvm_evdev_state.dev == NULL)
	{
		return 0;
	}

	ignore_result(g_kvm_evdev_exports.libevdev_set_name(g_kvm_evdev_state.dev, "MeshAgent Virtual Input"));

	r = g_kvm_evdev_exports.libevdev_enable_event_type(g_kvm_evdev_state.dev, EV_KEY);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_type(EV_KEY) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}
	r = g_kvm_evdev_exports.libevdev_enable_event_type(g_kvm_evdev_state.dev, EV_REL);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_type(EV_REL) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}
	r = g_kvm_evdev_exports.libevdev_enable_event_type(g_kvm_evdev_state.dev, EV_ABS);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_type(EV_ABS) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}

	memset(&absInfo, 0, sizeof(absInfo));
	absInfo.minimum = 0;
	absInfo.maximum = 65535;
	r = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_ABS, ABS_X, &absInfo);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_code(EV_ABS, ABS_X) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}
	r = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_ABS, ABS_Y, &absInfo);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_code(EV_ABS, ABS_Y) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}

	r = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_REL, REL_WHEEL, NULL);
	if (r != 0)
	{
		printf("MeshAgent: libevdev_enable_event_code(EV_REL, REL_WHEEL) failed: %d (%s)\n", r, kvm_events_evdev_error_string(r));
		goto error;
	}
	ignore_result(g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_REL, REL_HWHEEL, NULL));

	memset(keyEnabled, 0, sizeof(keyEnabled));
	keyEnabled[BTN_LEFT] = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, BTN_LEFT, NULL) == 0;
	keyEnabled[BTN_RIGHT] = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, BTN_RIGHT, NULL) == 0;
	keyEnabled[BTN_MIDDLE] = g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, BTN_MIDDLE, NULL) == 0;
	ignore_result(g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, BTN_SIDE, NULL));
	ignore_result(g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, BTN_EXTRA, NULL));

	for (vk = 0; vk < 0xFF; ++vk)
	{
		keycode = kvm_events_evdev_vk_to_keycode(vk);
		if (keycode != KEY_RESERVED && keycode <= KEY_MAX && !keyEnabled[keycode])
		{
			if (g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, keycode, NULL) == 0)
			{
				keyEnabled[keycode] = 1;
			}
		}
	}
	keycode = kvm_events_evdev_vk_to_keycode((unsigned char)0xFF);
	if (keycode != KEY_RESERVED && keycode <= KEY_MAX && !keyEnabled[keycode])
	{
		ignore_result(g_kvm_evdev_exports.libevdev_enable_event_code(g_kvm_evdev_state.dev, EV_KEY, keycode, NULL));
	}

	createManagedRc = g_kvm_evdev_exports.libevdev_uinput_create_from_device(g_kvm_evdev_state.dev, KVM_LIBEVDEV_UINPUT_OPEN_MANAGED, &g_kvm_evdev_state.uinput);
	createRc = createManagedRc;
	if (createRc != 0)
	{
		uinputFd = kvm_events_evdev_try_open_uinput();
		uinputErrno = errno;
		if (uinputFd >= 0)
		{
			createRc = g_kvm_evdev_exports.libevdev_uinput_create_from_device(g_kvm_evdev_state.dev, uinputFd, &g_kvm_evdev_state.uinput);
			if (createRc != 0)
			{
				close(uinputFd);
				uinputFd = -1;
			}
		}
		if (createRc != 0)
		{
			int rwAccess = access("/dev/uinput", R_OK | W_OK);
			printf("MeshAgent: libevdev_uinput_create_from_device failed (managed=%d:%s, fallback=%d:%s, /dev/uinput access=%d errno=%d:%s, open_errno=%d:%s, uid=%d euid=%d)\n",
				createManagedRc, kvm_events_evdev_error_string(createManagedRc),
				createRc, kvm_events_evdev_error_string(createRc),
				rwAccess, errno, strerror(errno),
				uinputErrno, strerror(uinputErrno),
				(int)getuid(), (int)geteuid());
			goto error;
		}
	}

	printf("MeshAgent: evdev virtual input device created successfully\n");
	usleep(50000);
	g_kvm_evdev_state.active = 1;
	return 1;

error:
	printf("MeshAgent: Failed to create evdev virtual input device\n");
	kvm_events_evdev_shutdown();
	return 0;
}

void kvm_events_evdev_shutdown()
{
	if (g_kvm_evdev_state.uinput != NULL)
	{
		g_kvm_evdev_exports.libevdev_uinput_destroy(g_kvm_evdev_state.uinput);
		g_kvm_evdev_state.uinput = NULL;
	}
	if (g_kvm_evdev_state.dev != NULL)
	{
		g_kvm_evdev_exports.libevdev_free(g_kvm_evdev_state.dev);
		g_kvm_evdev_state.dev = NULL;
	}
	g_kvm_evdev_state.active = 0;
}

int kvm_events_evdev_is_active()
{
	return g_kvm_evdev_state.active;
}

void kvm_events_evdev_mouse_action(double absX, double absY, int button, short wheel)
{
	int x = (int)absX;
	int y = (int)absY;
	unsigned int mouseCode = 0;
	int mouseValue = 0;

	if (!kvm_events_evdev_is_active())
	{
		return;
	}
	if (button == 0x88)
	{
		return;
	}

	if (kvm_events_evdev_write(EV_ABS, ABS_X, kvm_events_evdev_scale_axis(x, SCREEN_WIDTH)) != 0)
	{
		return;
	}
	if (kvm_events_evdev_write(EV_ABS, ABS_Y, kvm_events_evdev_scale_axis(y, SCREEN_HEIGHT)) != 0)
	{
		return;
	}

	if (button != 0)
	{
		switch (button)
		{
		case MOUSEEVENTF_LEFTDOWN:
			mouseCode = BTN_LEFT;
			mouseValue = 1;
			break;
		case MOUSEEVENTF_LEFTUP:
			mouseCode = BTN_LEFT;
			mouseValue = 0;
			break;
		case MOUSEEVENTF_RIGHTDOWN:
			mouseCode = BTN_RIGHT;
			mouseValue = 1;
			break;
		case MOUSEEVENTF_RIGHTUP:
			mouseCode = BTN_RIGHT;
			mouseValue = 0;
			break;
		case MOUSEEVENTF_MIDDLEDOWN:
			mouseCode = BTN_MIDDLE;
			mouseValue = 1;
			break;
		case MOUSEEVENTF_MIDDLEUP:
			mouseCode = BTN_MIDDLE;
			mouseValue = 0;
			break;
		default:
			mouseCode = 0;
			break;
		}
		if (mouseCode != 0)
		{
			if (kvm_events_evdev_write(EV_KEY, mouseCode, mouseValue) != 0)
			{
				return;
			}
		}
	}
	else if (wheel != 0)
	{
		if (kvm_events_evdev_write(EV_REL, REL_WHEEL, wheel > 0 ? 1 : -1) != 0)
		{
			return;
		}
	}

	ignore_result(kvm_events_evdev_sync());
}

void kvm_events_evdev_key_action(unsigned char vk, int up)
{
	unsigned int keycode = kvm_events_evdev_vk_to_keycode(vk);
	int value = up == 0 ? 1 : 0;

	if (!kvm_events_evdev_is_active())
	{
		return;
	}
	if (up == 4)
	{
		value = 1;
	}
	if (keycode == KEY_RESERVED)
	{
		return;
	}

	if (kvm_events_evdev_write(EV_KEY, keycode, value) != 0)
	{
		return;
	}
	ignore_result(kvm_events_evdev_sync());
}

void kvm_events_evdev_key_action_unicode(uint16_t unicode, int up)
{
	unsigned int keycode = KEY_RESERVED;
	int needsShift = 0;

	if (!kvm_events_evdev_is_active())
	{
		return;
	}
	if (up != 0)
	{
		return;
	}
	if (!kvm_events_evdev_ascii_to_keycode(unicode, &keycode, &needsShift))
	{
		return;
	}

	if (needsShift)
	{
		if (kvm_events_evdev_write(EV_KEY, KEY_LEFTSHIFT, 1) != 0)
		{
			return;
		}
	}
	if (kvm_events_evdev_write(EV_KEY, keycode, 1) != 0)
	{
		return;
	}
	if (kvm_events_evdev_write(EV_KEY, keycode, 0) != 0)
	{
		return;
	}
	if (needsShift)
	{
		if (kvm_events_evdev_write(EV_KEY, KEY_LEFTSHIFT, 0) != 0)
		{
			return;
		}
	}
	ignore_result(kvm_events_evdev_sync());
}

#else

int kvm_events_evdev_init()
{
	return 0;
}

void kvm_events_evdev_shutdown()
{
}

int kvm_events_evdev_is_active()
{
	return 0;
}

void kvm_events_evdev_mouse_action(double absX, double absY, int button, short wheel)
{
	UNREFERENCED_PARAMETER(absX);
	UNREFERENCED_PARAMETER(absY);
	UNREFERENCED_PARAMETER(button);
	UNREFERENCED_PARAMETER(wheel);
}

void kvm_events_evdev_key_action(unsigned char vk, int up)
{
	UNREFERENCED_PARAMETER(vk);
	UNREFERENCED_PARAMETER(up);
}

void kvm_events_evdev_key_action_unicode(uint16_t unicode, int up)
{
	UNREFERENCED_PARAMETER(unicode);
	UNREFERENCED_PARAMETER(up);
}

#endif
