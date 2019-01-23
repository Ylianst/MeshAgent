#include "mac_events.h"
#include <assert.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <string.h>
#include "../../../microstack/ILibParsers.h"
#include "../../meshdefines.h"

static const int g_keymapLen = 114; // Modify this when you change anything in g_keymap.
static int g_capsLock = 0;
static int g_lMouseDown = 0;
static int g_rMouseDown = 0;

static struct keymap_t g_keymap[] = {
	{ kVK_Space,		 VK_SPACE },
	{ kVK_CapsLock,		 VK_CAPITAL },
	{ kVK_ANSI_Q,        VK_Q },
	{ kVK_ANSI_W,        VK_W },
	{ kVK_ANSI_E,        VK_E },
	{ kVK_ANSI_R,        VK_R },
	{ kVK_ANSI_T,        VK_T },
	{ kVK_ANSI_Y,        VK_Y },
	{ kVK_ANSI_U,        VK_U },
	{ kVK_ANSI_I,        VK_I },
	{ kVK_ANSI_O,        VK_O },
	{ kVK_ANSI_P,        VK_P },
	{ kVK_ANSI_A,        VK_A },
	{ kVK_ANSI_S,        VK_S },
	{ kVK_ANSI_D,        VK_D },
	{ kVK_ANSI_F,        VK_F },
	{ kVK_ANSI_G,        VK_G },
	{ kVK_ANSI_H,        VK_H },
	{ kVK_ANSI_J,        VK_J },
	{ kVK_ANSI_K,        VK_K },
	{ kVK_ANSI_L,        VK_L },
	{ kVK_ANSI_Z,        VK_Z },
	{ kVK_ANSI_X,        VK_X },
	{ kVK_ANSI_C,        VK_C },
	{ kVK_ANSI_V,        VK_V },
	{ kVK_ANSI_B,        VK_B },
	{ kVK_ANSI_N,        VK_N },
	{ kVK_ANSI_M,        VK_M },
	{ kVK_ANSI_1,        VK_1 },
	{ kVK_ANSI_2,        VK_2 },
	{ kVK_ANSI_3,        VK_3 },
	{ kVK_ANSI_4,        VK_4 },
	{ kVK_ANSI_5,        VK_5 },
	{ kVK_ANSI_6,        VK_6 },
	{ kVK_ANSI_7,        VK_7 },
	{ kVK_ANSI_8,        VK_8 },
	{ kVK_ANSI_9,        VK_9 },
	{ kVK_ANSI_0,        VK_0 },
	{ kVK_Delete,        VK_BACK },
	{ kVK_Tab,           VK_TAB },
	{ kVK_ANSI_KeypadClear,            VK_CLEAR },
	{ kVK_Return,           VK_RETURN },
	{ kVK_Help,            VK_PAUSE },
	{ kVK_Escape,           VK_ESCAPE },
	{ kVK_ForwardDelete,           VK_DELETE },
	{ kVK_Home,             VK_HOME },
	{ kVK_LeftArrow,             VK_LEFT },
	{ kVK_UpArrow,               VK_UP },
	{ kVK_RightArrow,            VK_RIGHT },
	{ kVK_DownArrow,             VK_DOWN },
	{ kVK_PageUp,          VK_PRIOR },
	{ kVK_PageDown,        VK_NEXT },
	{ kVK_End,              VK_END },
	{ kVK_Help,           VK_SELECT },
	{ kVK_Help,            VK_SNAPSHOT },
	{ kVK_Help,          VK_EXECUTE },
	{ kVK_Help,           VK_INSERT },
	{ kVK_Help,             VK_HELP },
	{ kVK_Escape,            VK_CANCEL },
	{ kVK_F1,               VK_F1 },
	{ kVK_F2,               VK_F2 },
	{ kVK_F3,               VK_F3 },
	{ kVK_F4,               VK_F4 },
	{ kVK_F5,               VK_F5 },
	{ kVK_F6,               VK_F6 },
	{ kVK_F7,               VK_F7 },
	{ kVK_F8,               VK_F8 },
	{ kVK_F9,               VK_F9 },
	{ kVK_F10,              VK_F10 },
	{ kVK_F11,              VK_F11 },
	{ kVK_F12,              VK_F12 },
	{ kVK_F13,              VK_F13 },
	{ kVK_F14,              VK_F14 },
	{ kVK_F15,              VK_F15 },
	{ kVK_F16,              VK_F16 },
	{ kVK_F17,              VK_F17 },
	{ kVK_F18,              VK_F18 },
	{ kVK_F19,              VK_F19 },
	{ kVK_F20,              VK_F20 },
	{ kVK_Home,          VK_HOME },
	{ kVK_ANSI_KeypadMultiply,      VK_MULTIPLY },
	{ kVK_ANSI_Equal,           VK_ADD },
	{ kVK_ANSI_Comma,     VK_SEPARATOR },
	{ kVK_ANSI_Minus,      VK_SUBTRACT },
	{ kVK_ANSI_KeypadDecimal,       VK_DECIMAL },
	{ kVK_ANSI_KeypadDivide,        VK_DIVIDE },
	{ kVK_ANSI_Keypad0,             VK_NUMPAD0 },
	{ kVK_ANSI_Keypad1,             VK_NUMPAD1 },
	{ kVK_ANSI_Keypad2,             VK_NUMPAD2 },
	{ kVK_ANSI_Keypad3,             VK_NUMPAD3 },
	{ kVK_ANSI_Keypad4,             VK_NUMPAD4 },
	{ kVK_ANSI_Keypad5,             VK_NUMPAD5 },
	{ kVK_ANSI_Keypad6,             VK_NUMPAD6 },
	{ kVK_ANSI_Keypad7,             VK_NUMPAD7 },
	{ kVK_ANSI_Keypad8,             VK_NUMPAD8 },
	{ kVK_ANSI_Keypad9,             VK_NUMPAD9 },
	{ kVK_Shift,          VK_SHIFT },
	{ kVK_Control,        VK_CONTROL },
	{ kVK_Option,            VK_MENU },
	{ kVK_Command,          VK_RWIN },
	{ kVK_Command,          VK_LWIN },
	{ kVK_Option,             VK_APPS },
	{ kVK_JIS_Kana,       VK_KANA },
	{ kVK_ANSI_Semicolon,			   VK_OEM_1 },
	{ kVK_ANSI_Equal,		 	   VK_OEM_PLUS },
	{ kVK_ANSI_Comma,			   VK_OEM_COMMA },
	{ kVK_ANSI_Minus,		 	   VK_OEM_MINUS },
	{ kVK_ANSI_Period, 		   VK_OEM_PERIOD },
	{ kVK_ANSI_Slash, 	       VK_OEM_2  },
	{ kVK_ANSI_Grave, 		   VK_OEM_3 },
	{ kVK_ANSI_LeftBracket, 	   VK_OEM_4 },
	{ kVK_ANSI_Backslash,		   VK_OEM_5 },
	{ kVK_ANSI_RightBracket,	   VK_OEM_6 },
	{ kVK_ANSI_Quote,	   VK_OEM_7 }
};
extern int KVM_SEND(char *buffer, int bufferLen);

void kvm_server_sendmsg(char *msg)
{
	int msgLen = strnlen_s(msg, 255);
	char buffer[512];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(msgLen + 4));	// Write the size
	memcpy_s(buffer + 4, 512 - 4, msg, msgLen);

	KVM_SEND(buffer, msgLen + 4);
}

char* getCurrentSession() {
	SCDynamicStoreRef store;
    CFStringRef name;
    uid_t uid;
    char *buf;
    Boolean ok;
	
	buf = (char *)malloc (BUFSIZ);
    store = SCDynamicStoreCreate(NULL, CFSTR("GetConsoleUser"), NULL, NULL);
    assert(store != NULL);
    name = SCDynamicStoreCopyConsoleUser(store, &uid, NULL);
    CFRelease(store);
	
    if (name != NULL) {
        ok = CFStringGetCString(name, buf, BUFSIZ, kCFStringEncodingUTF8);
        assert(ok == true);
        CFRelease(name);
    } else {
        strcpy(buf, "<none>");
    }

	return buf;
}

void MouseAction(double absX, double absY, int button, short wheel)
{
	CGPoint curPos;
	CGEventRef e;
	CGEventType event;
	CGEventSourceRef source;

	curPos.x = absX;
	curPos.y = absY;

	source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
	
	
	if (g_lMouseDown || g_rMouseDown) {
		event = g_lMouseDown ? kCGEventLeftMouseDragged : kCGEventRightMouseDragged;
		e = CGEventCreateMouseEvent(source, event, curPos, 1);
		CGEventPost(kCGHIDEventTap, e);
		CGEventPost(kCGSessionEventTap, e);
		CFRelease(e);
	}
	else {
		CGWarpMouseCursorPosition (curPos);
	}
	
	if (button != 0) {

		switch (button) {
			case MOUSEEVENTF_LEFTDOWN:
				event = kCGEventLeftMouseDown;
				g_lMouseDown = 1;
				break;
			case MOUSEEVENTF_RIGHTDOWN:
				g_rMouseDown = 1;
				event = kCGEventRightMouseDown;
				break;
			case MOUSEEVENTF_LEFTUP:
				g_lMouseDown = 0;
				event = kCGEventLeftMouseUp;
				break;
			case MOUSEEVENTF_RIGHTUP:
				g_rMouseDown = 0;
				event = kCGEventRightMouseUp;
				break;
			default:
				break;
		}

		if (button == 0x88) 
		{
			// Double click, this is useful on MacOS.
			e = CGEventCreateMouseEvent(source, kCGEventLeftMouseDown, curPos, 1);
			CGEventSetIntegerValueField(e, kCGMouseEventClickState, 2);
			CGEventPost(kCGHIDEventTap, e);
			CGEventSetType(e, kCGEventLeftMouseUp);
			CGEventPost(kCGHIDEventTap, e);
		}
		else
		{
			e = CGEventCreateMouseEvent(source, event, curPos, 1);
			CGEventPost(kCGHIDEventTap, e);
		}
		CFRelease(e);
	}
	else if (wheel != 0)
	{
		e = CGEventCreateScrollWheelEvent(source, kCGScrollEventUnitPixel, 1, wheel);
		CGEventPost(kCGHIDEventTap, e);
		CFRelease(e);
	}
	if (source != NULL) CFRelease(source);
}

void KeyAction(unsigned char vk, int up) {
	int i;
	CGKeyCode keycode;
	CGEventSourceRef source;

	source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
	for (i = 0 ; i < g_keymapLen; i++) {
		if (g_keymap[i].vk == vk) {
			keycode = g_keymap[i].keycode;
			break;
		}
	}

	if (i == g_keymapLen) { return; }
	if (vk == VK_CAPITAL && up) { g_capsLock = g_capsLock ? 0 : 1; }

	/*
	if (!strcmp(getCurrentSession(), "<none>")) {
		// This call is deprecated in OSX 10.6
		CGPostKeyboardEvent(0, keycode, !up);
	}
	else
	{
	*/
		CGEventRef key = CGEventCreateKeyboardEvent(source, keycode, !up);
		if (g_capsLock) { CGEventSetFlags(key, kCGEventFlagMaskAlphaShift); }
		CGEventPost(kCGHIDEventTap, key);
		CFRelease(key);
	/*
	}
	*/
	if (source != NULL) CFRelease(source);
}
