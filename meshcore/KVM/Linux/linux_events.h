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

#ifndef LINUX_EVENTS_H_
#define LINUX_EVENTS_H_

#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

typedef struct x11tst_struct
{
	void *x11tst_lib;
	int(*XTestFakeMotionEvent)(Display *d, int screen_number, int x, int y, unsigned long delay);
	int(*XTestFakeButtonEvent)(Display *d, unsigned int button, Bool is_press, unsigned long delay);
	int(*XTestFakeKeyEvent)(Display *d, unsigned int key_code, Bool is_press, unsigned long delay);

	int(*XFlush)(Display *d);
	KeyCode(*XKeysymToKeycode)(Display *d, KeySym keysym);
}x11tst_struct;
x11tst_struct *x11tst_exports;

enum MOUSE_EVENTS {
	MOUSEEVENTF_LEFTDOWN = 		0x0002,
	MOUSEEVENTF_RIGHTDOWN = 	0x0008,
	MOUSEEVENTF_MIDDLEDOWN = 	0x0020,
	MOUSEEVENTF_LEFTUP = 		0x0004,
	MOUSEEVENTF_RIGHTUP	=		0x0010,
	MOUSEEVENTF_MIDDLEUP = 		0x0040
};

// VK_LBUTTON (01) Left mouse button
#define VK_LBUTTON		0x01
// VK_RBUTTON (02) Right mouse button
#define VK_RBUTTON		0x02
// VK_CANCEL (03) Control-break processing
#define VK_CANCEL		0x03
// VK_MBUTTON (04) Middle mouse button (three-button mouse)
#define VK_MBUTTON		0x04
// VK_XBUTTON1 (05)
#define VK_XBUTTON1		0x05
// VK_XBUTTON2 (06)
#define VK_XBUTTON2		0x06
 // VK_BACK (08) BACKSPACE key
#define VK_BACK		0x08
 // VK_TAB (09) TAB key
#define VK_TAB		0x09
 // VK_CLEAR (0C) CLEAR key
#define VK_CLEAR		0x0C
 // VK_RETURN (0D)
#define VK_RETURN		0x0D
 // VK_SHIFT (10) SHIFT key
#define VK_SHIFT		0x10
 // VK_CONTROL (11) CTRL key
#define VK_CONTROL		0x11
 // VK_MENU (12) ALT key
#define VK_MENU		0x12
 // VK_PAUSE (13) PAUSE key
#define VK_PAUSE		0x13
 // VK_CAPITAL (14) CAPS LOCK key
#define VK_CAPITAL		0x14
 // VK_KANA (15) Input Method Editor (IME) Kana mode
#define VK_KANA		0x15
 // VK_HANGUEL (15) IME Hanguel mode (maintained for compatibility; use VK_HANGUL)
 // VK_HANGUL (15) IME Hangul mode
#define VK_HANGUL		0x15
 // VK_JUNJA (17) IME Junja mode
#define VK_JUNJA		0x17
 // VK_FINAL (18) IME final mode
#define VK_FINAL		0x18
 // VK_HANJA (19) IME Hanja mode
#define VK_HANJA		0x19
 // VK_KANJI (19) IME Kanji mode
#define VK_KANJI		0x19
 // VK_ESCAPE (1B) ESC key
#define VK_ESCAPE		0x1B
 // VK_CONVERT (1C) IME convert
#define VK_CONVERT		0x1C
 // VK_NONCONVERT (1D) IME nonconvert
#define VK_NONCONVERT		0x1D
 // VK_ACCEPT (1E) IME accept
#define VK_ACCEPT		0x1E
 // VK_MODECHANGE (1F) IME mode change request
#define VK_MODECHANGE		0x1F
 // VK_SPACE (20) SPACEBAR
#define VK_SPACE		0x20
 // VK_PRIOR (21) PAGE UP key
#define VK_PRIOR		0x21
 // VK_NEXT (22) PAGE DOWN key
#define VK_NEXT		0x22
 // VK_END (23) END key
#define VK_END		0x23
 // VK_HOME (24) HOME key
#define VK_HOME		0x24
 // VK_LEFT (25) LEFT ARROW key
#define VK_LEFT		0x25
 // VK_UP (26) UP ARROW key
#define VK_UP		0x26
 // VK_RIGHT (27) RIGHT ARROW key
#define VK_RIGHT		0x27
 // VK_DOWN (28) DOWN ARROW key
#define VK_DOWN		0x28
 // VK_SELECT (29) SELECT key
#define VK_SELECT		0x29
 // VK_PRINT (2A) PRINT key
#define VK_PRINT		0x2A
 // VK_EXECUTE (2B) EXECUTE key
#define VK_EXECUTE		0x2B
 // VK_SNAPSHOT (2C) PRINT SCREEN key
#define VK_SNAPSHOT		0x2C
 // VK_INSERT (2D) INS key
#define VK_INSERT		0x2D
 // VK_DELETE (2E) DEL key
#define VK_DELETE		0x2E
 // VK_HELP (2F) HELP key
#define VK_HELP		0x2F
 // (30) 0 key
#define VK_0		0x30
 // (31) 1 key
#define VK_1		0x31
 // (32) 2 key
#define VK_2		0x32
 // (33) 3 key
#define VK_3		0x33
 // (34) 4 key
#define VK_4		0x34
 // (35) 5 key;
#define VK_5		0x35
 // (36) 6 key
#define VK_6		0x36
 // (37) 7 key
#define VK_7		0x37
 // (38) 8 key
#define VK_8		0x38
 // (39) 9 key
#define VK_9		0x39
 // (41) A key
#define VK_A		0x41
 // (42) B key
#define VK_B		0x42
 // (43) C key
#define VK_C		0x43
 // (44) D key
#define VK_D		0x44
 // (45) E key
#define VK_E		0x45
 // (46) F key
#define VK_F		0x46
 // (47) G key
#define VK_G		0x47
 // (48) H key
#define VK_H		0x48
 // (49) I key
#define VK_I		0x49
 // (4A) J key
#define VK_J		0x4A
 // (4B) K key
#define VK_K		0x4B
 // (4C) L key
#define VK_L		0x4C
 // (4D) M key
#define VK_M		0x4D
 // (4E) N key
#define VK_N		0x4E
 // (4F) O key
#define VK_O		0x4F
 // (50) P key
#define VK_P		0x50
 // (51) Q key
#define VK_Q		0x51
 // (52) R key
#define VK_R		0x52
 // (53) S key
#define VK_S		0x53
 // (54) T key
#define VK_T		0x54
 // (55) U key
#define VK_U		0x55
 // (56) V key
#define VK_V		0x56
 // (57) W key
#define VK_W		0x57
 // (58) X key
#define VK_X		0x58
 // (59) Y key
#define VK_Y		0x59
 // (5A) Z key
#define VK_Z		0x5A
 // VK_LWIN (5B) Left Windows key (Microsoft Natural keyboard)
#define VK_LWIN		0x5B
 // VK_RWIN (5C) Right Windows key (Natural keyboard)
#define VK_RWIN		0x5C
 // VK_APPS (5D) Applications key (Natural keyboard)
#define VK_APPS		0x5D
 // VK_SLEEP (5F) Computer Sleep key
#define VK_SLEEP		0x5F
 // VK_NUMPAD0 (60) Numeric keypad 0 key
#define VK_NUMPAD0		0x60
 // VK_NUMPAD1 (61) Numeric keypad 1 key
#define VK_NUMPAD1		0x61
 // VK_NUMPAD2 (62) Numeric keypad 2 key
#define VK_NUMPAD2		0x62
 // VK_NUMPAD3 (63) Numeric keypad 3 key
#define VK_NUMPAD3		0x63
 // VK_NUMPAD4 (64) Numeric keypad 4 key
#define VK_NUMPAD4		0x64
 // VK_NUMPAD5 (65) Numeric keypad 5 key
#define VK_NUMPAD5		0x65
 // VK_NUMPAD6 (66) Numeric keypad 6 key
#define VK_NUMPAD6		0x66
 // VK_NUMPAD7 (67) Numeric keypad 7 key
#define VK_NUMPAD7		0x67
 // VK_NUMPAD8 (68) Numeric keypad 8 key
#define VK_NUMPAD8		0x68
 // VK_NUMPAD9 (69) Numeric keypad 9 key
#define VK_NUMPAD9		0x69
 // VK_MULTIPLY (6A) Multiply key
#define VK_MULTIPLY		0x6A
 // VK_ADD (6B) Add key
#define VK_ADD		0x6B
 // VK_SEPARATOR (6C) Separator key
#define VK_SEPARATOR		0x6C
 // VK_SUBTRACT (6D) Subtract key
#define VK_SUBTRACT		0x6D
 // VK_DECIMAL (6E) Decimal key
#define VK_DECIMAL		0x6E
 // VK_DIVIDE (6F) Divide key
#define VK_DIVIDE		0x6F
 // VK_F1 (70) F1 key
#define VK_F1		0x70
 // VK_F2 (71) F2 key
#define VK_F2		0x71
 // VK_F3 (72) F3 key
#define VK_F3		0x72
 // VK_F4 (73) F4 key
#define VK_F4		0x73
 // VK_F5 (74) F5 key
#define VK_F5		0x74
 // VK_F6 (75) F6 key
#define VK_F6		0x75
 // VK_F7 (76) F7 key
#define VK_F7		0x76
 // VK_F8 (77) F8 key
#define VK_F8		0x77
 // VK_F9 (78) F9 key
#define VK_F9		0x78
 // VK_F10 (79) F10 key
#define VK_F10		0x79
 // VK_F11 (7A) F11 key
#define VK_F11		0x7A
 // VK_F12 (7B) F12 key
#define VK_F12		0x7B
 // VK_F13 (7C) F13 key
#define VK_F13		0x7C
 // VK_F14 (7D) F14 key
#define VK_F14		0x7D
 // VK_F15 (7E) F15 key
#define VK_F15		0x7E
 // VK_F16 (7F) F16 key
#define VK_F16		0x7F
 // VK_F17 (80H) F17 key
#define VK_F17		0x80
 // VK_F18 (81H) F18 key
#define VK_F18		0x81
 // VK_F19 (82H) F19 key
#define VK_F19		0x82
 // VK_F20 (83H) F20 key
#define VK_F20		0x83
 // VK_F21 (84H) F21 key
#define VK_F21		0x84
 // VK_F22 (85H) F22 key
#define VK_F22		0x85
 // VK_F23 (86H) F23 key
#define VK_F23		0x86
 // VK_F24 (87H) F24 key
#define VK_F24		0x87
 // VK_NUMLOCK (90) NUM LOCK key
#define VK_NUMLOCK		0x90
 // VK_SCROLL (91) SCROLL LOCK key
#define VK_SCROLL		0x91
 // VK_LSHIFT (A0) Left SHIFT key
#define VK_LSHIFT		0xA0
 // VK_RSHIFT (A1) Right SHIFT key
#define VK_RSHIFT		0xA1
 // VK_LCONTROL (A2) Left CONTROL key
#define VK_LCONTROL		0xA2
 // VK_RCONTROL (A3) Right CONTROL key
#define VK_RCONTROL		0xA3
 // VK_LMENU (A4) Left MENU key
#define VK_LMENU		0xA4
 // VK_RMENU (A5) Right MENU key
#define VK_RMENU		0xA5
 // VK_BROWSER_BACK (A6) Windows 2000/XP: Browser Back key
#define VK_BROWSER_BACK		0xA6
 // VK_BROWSER_FORWARD (A7) Windows 2000/XP: Browser Forward key
#define VK_BROWSER_FORWARD		0xA7
 // VK_BROWSER_REFRESH (A8) Windows 2000/XP: Browser Refresh key
#define VK_BROWSER_REFRESH		0xA8
 // VK_BROWSER_STOP (A9) Windows 2000/XP: Browser Stop key
#define VK_BROWSER_STOP		0xA9
 // VK_BROWSER_SEARCH (AA) Windows 2000/XP: Browser Search key
#define VK_BROWSER_SEARCH		0xAA
 // VK_BROWSER_FAVORITES (AB) Windows 2000/XP: Browser Favorites key
#define VK_BROWSER_FAVORITES		0xAB
 // VK_BROWSER_HOME (AC) Windows 2000/XP: Browser Start and Home key
#define VK_BROWSER_HOME		0xAC
 // VK_VOLUME_MUTE (AD) Windows 2000/XP: Volume Mute key
#define VK_VOLUME_MUTE		0xAD
 // VK_VOLUME_DOWN (AE) Windows 2000/XP: Volume Down key
#define VK_VOLUME_DOWN		0xAE
 // VK_VOLUME_UP (AF) Windows 2000/XP: Volume Up key
#define VK_VOLUME_UP		0xAF
 // VK_MEDIA_NEXT_TRACK (B0) Windows 2000/XP: Next Track key
#define VK_MEDIA_NEXT_TRACK		0xB0
 // VK_MEDIA_PREV_TRACK (B1) Windows 2000/XP: Previous Track key
#define VK_MEDIA_PREV_TRACK		0xB1
 // VK_MEDIA_STOP (B2) Windows 2000/XP: Stop Media key
#define VK_MEDIA_STOP		0xB2
 // VK_MEDIA_PLAY_PAUSE (B3) Windows 2000/XP: Play/Pause Media key
#define VK_MEDIA_PLAY_PAUSE		0xB3
 // VK_LAUNCH_MAIL (B4) Windows 2000/XP: Start Mail key
#define VK_MEDIA_LAUNCH_MAIL		0xB4
 // VK_LAUNCH_MEDIA_SELECT (B5) Windows 2000/XP: Select Media key
#define VK_MEDIA_LAUNCH_MEDIA_SELECT		0xB5
 // VK_LAUNCH_APP1 (B6) Windows 2000/XP: Start Application 1 key
#define VK_MEDIA_LAUNCH_APP1		0xB6
 // VK_LAUNCH_APP2 (B7) Windows 2000/XP: Start Application 2 key
#define VK_MEDIA_LAUNCH_APP2		0xB7
 // VK_OEM_1 (BA) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the ';:' key
#define VK_OEM_1		0xBA
 // VK_OEM_PLUS (BB) Windows 2000/XP: For any country/region, the '+' key
#define VK_OEM_PLUS		0xBB
 // VK_OEM_COMMA (BC) Windows 2000/XP: For any country/region, the ',' key
#define VK_OEM_COMMA		0xBC
 // VK_OEM_MINUS (BD) Windows 2000/XP: For any country/region, the '-' key
#define VK_OEM_MINUS		0xBD
 // VK_OEM_PERIOD (BE) Windows 2000/XP: For any country/region, the '.' key
#define VK_OEM_PERIOD		0xBE
 // VK_OEM_2 (BF) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the '/?' key
#define VK_OEM_2		0xBF
 // VK_OEM_3 (C0) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the '`~' key
#define VK_OEM_3		0xC0
 // VK_OEM_4 (DB) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the '[{' key
#define VK_OEM_4		0xDB
 // VK_OEM_5 (DC) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the '\|' key
#define VK_OEM_5		0xDC
 // VK_OEM_6 (DD) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the ']}' key
#define VK_OEM_6		0xDD
 // VK_OEM_7 (DE) Used for miscellaneous characters; it can vary by keyboard. Windows 2000/XP: For the US standard keyboard, the 'single-quote/double-quote' key
#define VK_OEM_7		0xDE
 // VK_OEM_8 (DF) Used for miscellaneous characters; it can vary by keyboard.
#define VK_OEM_8		0xDF
 // VK_OEM_102 (E2) Windows 2000/XP: Either the angle bracket key or the backslash key on the RT 102-key keyboard
#define VK_OEM_102		0xE2
 // VK_PROCESSKEY (E5) Windows 95/98/Me, Windows NT 4.0, Windows 2000/XP: IME PROCESS key
#define VK_PROCESSKEY		0xE5
 // VK_PACKET (E7) Windows 2000/XP: Used to pass Unicode characters as if they were keystrokes. The VK_PACKET key is the low word of a 32-bit Virtual Key value used for non-keyboard input methods. For more information, see Remark in KEYBDINPUT,SendInput, WM_KEYDOWN, and WM_KEYUP
#define VK_PACKET		0xE7
 // VK_ATTN (F6) Attn key
#define VK_ATTN		0xF6
 // VK_CRSEL (F7) CrSel key
#define VK_CRSEL		0xF7
 // VK_EXSEL (F8) ExSel key
#define VK_EXSEL		0xF8
 // VK_EREOF (F9) Erase EOF key
#define VK_EREOF		0xF9
 // VK_PLAY (FA) Play key
#define VK_PLAY		0xFA
 // VK_ZOOM (FB) Zoom key
#define VK_ZOOM		0xFB
 // VK_NONAME (FC) Reserved for future use
#define VK_NONAME		0xFC
 // VK_PA1 (FD) PA1 key
#define VK_PA1		0xFD
 // VK_OEM_CLEAR (FE) Clear key
#define VK_OEM_CLEAR		0xFE
#define VK_UNKNOWN		0

struct keymap_t {
  unsigned int keysym;
  unsigned char vk;
};

extern void MouseAction(double absX, double absY, int button, short wheel, Display *display);
extern void KeyAction(unsigned char vk, int up, Display *display);

#endif /* LINUX_EVENTS_H_ */
