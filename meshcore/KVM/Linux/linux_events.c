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
#include "microstack/ILibParsers.h"


static const int g_keymapLen = 96; // Modify this when you change anything in g_keymap.
extern int change_display;
x11tst_struct *x11tst_exports = NULL;
extern void kvm_keyboard_unmap_unicode_key(Display *display, int keycode);
extern int kvm_keyboard_map_unicode_key(Display *display, uint16_t unicode, int *alreadyExists);
extern int kvm_keyboard_update_map_unicode_key(Display *display, uint16_t unicode, int keycode);

#define g_keyboardMapCount 8
int g_keyboardMap[g_keyboardMapCount] = { 0 };
int g_keyboardMapIndex = 0;

static struct keymap_t g_keymap[] = {
	{ XK_BackSpace,        VK_BACK },
	{ XK_Tab,              VK_TAB },
	{ XK_Clear,            VK_CLEAR },
	{ XK_Return,           VK_RETURN },
	{ XK_Pause,            VK_PAUSE },
	{ XK_Escape,           VK_ESCAPE },
	{ XK_Delete,           VK_DELETE },
	{ XK_Home,             VK_HOME },
	{ XK_Left,             VK_LEFT },
	{ XK_Up,               VK_UP },
	{ XK_Right,            VK_RIGHT },
	{ XK_Down,             VK_DOWN },
	{ XK_Page_Up,          VK_PRIOR },
	{ XK_Page_Down,        VK_NEXT },
	{ XK_End,              VK_END },
	{ XK_Select,           VK_SELECT },
	{ XK_Print,            VK_SNAPSHOT },
	{ XK_Execute,          VK_EXECUTE },
	{ XK_Insert,           VK_INSERT },
	{ XK_Help,             VK_HELP },
	{ XK_Break,            VK_CANCEL },
	{ XK_F1,               VK_F1 },
	{ XK_F2,               VK_F2 },
	{ XK_F3,               VK_F3 },
	{ XK_F4,               VK_F4 },
	{ XK_F5,               VK_F5 },
	{ XK_F6,               VK_F6 },
	{ XK_F7,               VK_F7 },
	{ XK_F8,               VK_F8 },
	{ XK_F9,               VK_F9 },
	{ XK_F10,              VK_F10 },
	{ XK_F11,              VK_F11 },
	{ XK_F12,              VK_F12 },
	{ XK_F13,              VK_F13 },
	{ XK_F14,              VK_F14 },
	{ XK_F15,              VK_F15 },
	{ XK_F16,              VK_F16 },
	{ XK_F17,              VK_F17 },
	{ XK_F18,              VK_F18 },
	{ XK_F19,              VK_F19 },
	{ XK_F20,              VK_F20 },
	{ XK_F21,              VK_F21 },
	{ XK_F22,              VK_F22 },
	{ XK_F23,              VK_F23 },
	{ XK_F24,              VK_F24 },
	{ XK_KP_Tab,           VK_TAB },
	{ XK_KP_Enter,         VK_RETURN },
	{ XK_KP_F1,            VK_F1 },
	{ XK_KP_F2,            VK_F2 },
	{ XK_KP_F3,            VK_F3 },
	{ XK_KP_F4,            VK_F4 },
	{ XK_KP_Home,          VK_HOME },
	{ XK_KP_End,           VK_END },
	{ XK_KP_Page_Up,       VK_PRIOR },
	{ XK_KP_Page_Down,     VK_NEXT },
	{ XK_KP_Begin,         VK_CLEAR },
	{ XK_KP_Insert,        VK_INSERT },
	{ XK_KP_Delete,        VK_DELETE },
	{ XK_KP_Multiply,      VK_MULTIPLY },
	{ XK_KP_Add,           VK_ADD },
	{ XK_KP_Separator,     VK_SEPARATOR },
	{ XK_KP_Subtract,      VK_SUBTRACT },
	{ XK_KP_Decimal,       VK_DECIMAL },
	{ XK_KP_Divide,        VK_DIVIDE },
	{ XK_KP_0,             VK_NUMPAD0 },
	{ XK_KP_1,             VK_NUMPAD1 },
	{ XK_KP_2,             VK_NUMPAD2 },
	{ XK_KP_3,             VK_NUMPAD3 },
	{ XK_KP_4,             VK_NUMPAD4 },
	{ XK_KP_5,             VK_NUMPAD5 },
	{ XK_KP_6,             VK_NUMPAD6 },
	{ XK_KP_7,             VK_NUMPAD7 },
	{ XK_KP_8,             VK_NUMPAD8 },
	{ XK_KP_9,             VK_NUMPAD9 },
	{ XK_Shift_L,          VK_SHIFT },
	{ XK_Shift_R,          VK_SHIFT },
	{ XK_Control_L,        VK_CONTROL },
	{ XK_Control_R,        VK_CONTROL },
	{ XK_Alt_L,            VK_MENU },
	{ XK_Alt_R,            VK_MENU },
	{ XK_Super_L,          VK_LWIN },
	{ XK_Super_R,          VK_RWIN },
	{ XK_Menu,             VK_APPS },
	{ XK_Kanji,            VK_KANJI },
	{ XK_Kana_Shift,       VK_KANA },
	{ XK_colon,			   VK_OEM_1 },
	{ XK_plus,		 	   VK_OEM_PLUS },
	{ XK_comma,			   VK_OEM_COMMA },
	{ XK_minus,		 	   VK_OEM_MINUS },
	{ XK_period, 		   VK_OEM_PERIOD },
	{ XK_slash, 	       VK_OEM_2  },
	{ XK_grave, 		   VK_OEM_3 },
	{ XK_bracketleft, 	   VK_OEM_4 },
	{ XK_backslash,		   VK_OEM_5 },
	{ XK_bracketright,	   VK_OEM_6 },
	{ XK_apostrophe,	   VK_OEM_7 }
};

void MouseAction(double absX, double absY, int button, short wheel, Display *display)
{
	if (change_display) {
		return;
	}
	
	if (button == 0x88) {
		// Double click, do nothing on Linux.
		return;
	}

	if (!x11tst_exports->XTestFakeMotionEvent(display, -1, absX, absY, CurrentTime )) { return; }

	if (button != 0) {
		int mouseDown = 1;

		switch (button) {
			case MOUSEEVENTF_LEFTDOWN:
				button = 1;
				break;
			case MOUSEEVENTF_RIGHTDOWN:
				button = 3;
				break;
			case MOUSEEVENTF_MIDDLEDOWN:
				button = 2;
				break;
			case MOUSEEVENTF_LEFTUP:
				button = 1;
				mouseDown = 0;
				break;
			case MOUSEEVENTF_RIGHTUP:
				button = 3;
				mouseDown = 0;
				break;
			case MOUSEEVENTF_MIDDLEUP:
				button = 2;
				mouseDown = 0;
				break;
			default:
				break;
		}

		if (!x11tst_exports->XTestFakeButtonEvent(display, button, mouseDown, CurrentTime)) { return; }
	}
	else if (wheel != 0) {
		if (wheel > 0) {
			button = Button4;
		}
		else {
			button = Button5;
		}

		if (!x11tst_exports->XTestFakeButtonEvent(display, button, True, CurrentTime)) { return; }
		x11tst_exports->XFlush(display);

		if (!x11tst_exports->XTestFakeButtonEvent(display, button, False, CurrentTime)) { return; }
	}

	x11tst_exports->XFlush(display);
}


void KeyAction(unsigned char vk, int up, Display *display) 
{
	int i = 0;
	unsigned int keysym = 0;
	unsigned int keycode = 0;

	if (change_display)
	{
		return;
	}

	for (i = 0; i < g_keymapLen; i++) 
	{
		if (g_keymap[i].vk == vk) 
		{
			keysym = g_keymap[i].keysym;
			break;
		}
	}
	if (keysym == 0) 
	{
		keycode = x11tst_exports->XKeysymToKeycode(display, vk);
	}
	else 
	{
		keycode = x11tst_exports->XKeysymToKeycode(display, keysym);
	}

	//printf("%x %x %d %d\n", keysym, vk, keycode, up);
	if (keycode != 0) 
	{
		//ILIBLOGMESSAGEX("VK: %u [%d]", vk, up);

		if (!x11tst_exports->XTestFakeKeyEvent(display, keycode, !up, 0)) { return; }
		x11tst_exports->XFlush(display);
	}
}
void KeyActionUnicode_UNMAP_ALL(Display *display)
{
	int i;
	for (i = 0; i < g_keyboardMapCount; ++i)
	{
		if (g_keyboardMap[i] != 0) 
		{
			kvm_keyboard_unmap_unicode_key(display, g_keyboardMap[i]);
			g_keyboardMap[i] = 0; 
		}
	}
	g_keyboardMapIndex = 0;
}
void KeyActionUnicode(uint16_t unicode, int up, Display *display)
{
	if (change_display) { return; }
	int i;

	if (up == 0)
	{
		int exists = 0;
		int mapping = 0;

		// Check if a primary mapping already exists
		mapping = kvm_keyboard_map_unicode_key(display, unicode, &exists);
		if (mapping == 0)
		{
			if (g_keyboardMap[g_keyboardMapIndex] != 0)
			{
				mapping = g_keyboardMap[g_keyboardMapIndex] = kvm_keyboard_update_map_unicode_key(display, unicode, g_keyboardMap[g_keyboardMapIndex]);	// Create a key mapping on an unmapped key
			}
			else
			{
				mapping = g_keyboardMap[g_keyboardMapIndex] = kvm_keyboard_map_unicode_key(display, unicode, NULL);	// Create a key mapping on an unmapped key
			}
		}
		if (mapping > 0)
		{
			x11tst_exports->XTestFakeKeyEvent(display, mapping, 1, 0);
			x11tst_exports->XTestFakeKeyEvent(display, mapping, 0, 15);
			x11tst_exports->XFlush(display);
			
			if (exists == 0)
			{
				if (++g_keyboardMapIndex >= g_keyboardMapCount)
				{
					g_keyboardMapIndex = 0;
				}
			}
		}
	}
}