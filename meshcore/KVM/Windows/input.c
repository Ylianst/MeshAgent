/*
Copyright 2006 - 2018 Intel Corporation

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

#include <Windows.h>
#include <Winuser.h>
#include <stdio.h>
#include "input.h"

#include "microstack/ILibCrypto.h"

extern void ILibAppendStringToDiskEx(char *FileName, char *data, int dataLen);

int CUR_CURRENT = 0;
int CUR_APPSTARTING;
int CUR_ARROW;
int CUR_CROSS;
int CUR_HAND;
int CUR_HELP;
int CUR_IBEAM;
int CUR_NO;
int CUR_SIZEALL;
int CUR_SIZENESW;
int CUR_SIZENS;
int CUR_SIZENWSE;
int CUR_SIZEWE;
int CUR_UPARROW;
int CUR_WAIT;


/*
#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
*/

/*
MOUSEEVENTF_LEFTDOWN		0x0002
MOUSEEVENTF_RIGHTDOWN		0x0008
MOUSEEVENTF_MIDDLEDOWN		0x0020
MOUSEEVENTF_LEFTUP			0x0004
MOUSEEVENTF_RIGHTUP			0x0010
MOUSEEVENTF_MIDDLEUP		0x0040
MOUSEEVENTF_DOUBLECLK		0x0088
*/

int KVM_GetCursorHash(HCURSOR hc, char *buffer, size_t bufferLen)
{
	int crc = 0;
	BITMAP bm;
	ICONINFO ii;
	
	GetIconInfo(hc, &ii);
	
	if (GetObject(ii.hbmMask, sizeof(bm), &bm) == sizeof(bm))
	{
		//printf("CX: %ul, CY:%ul, Color: %ul, Showing: %d\n", bm.bmWidth, bm.bmHeight, ii.hbmColor, info.flags);
		HDC hdcScreen = GetDC(NULL);
		HDC hdcMem = CreateCompatibleDC(hdcScreen);
		HBITMAP hbmCanvas = CreateCompatibleBitmap(hdcScreen, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2));
		HGDIOBJ hbmold = SelectObject(hdcMem, hbmCanvas);
		BITMAPINFO bmpInfo;
		char *tmpBuffer;

		ZeroMemory(&bmpInfo, sizeof(bmpInfo));
		bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmpInfo.bmiHeader.biCompression = BI_RGB;

		DrawIconEx(hdcMem, 0, 0, hc, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), 0, NULL, DI_NORMAL);
		GetDIBits(hdcScreen, hbmCanvas, 0, 0, NULL, &bmpInfo, DIB_RGB_COLORS);
		tmpBuffer = (char*)malloc(bmpInfo.bmiHeader.biSizeImage);
		bmpInfo.bmiHeader.biCompression = BI_RGB;

		GetDIBits(hdcScreen, hbmCanvas, 0, (UINT)(ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2)), tmpBuffer, &bmpInfo, DIB_RGB_COLORS);

		crc = util_crc((unsigned char*)tmpBuffer, bmpInfo.bmiHeader.biSizeImage, 0);

		SelectObject(hdcMem, hbmold);
		ReleaseDC(NULL, hdcMem);
		ReleaseDC(NULL, hdcScreen);
	}

	return(crc);
}

void KVM_InitMouseCursors()
{
	CUR_ARROW = KVM_GetCursorHash(LoadCursorA(NULL, IDC_ARROW), NULL, 0);					
	CUR_APPSTARTING = KVM_GetCursorHash(LoadCursorA(NULL, IDC_APPSTARTING), NULL, 0);		
	CUR_CROSS = KVM_GetCursorHash(LoadCursorA(NULL, IDC_CROSS), NULL, 0);					
	CUR_HAND = KVM_GetCursorHash(LoadCursorA(NULL, IDC_HAND), NULL, 0);						
	CUR_HELP = KVM_GetCursorHash(LoadCursorA(NULL, IDC_HELP), NULL, 0);						
	CUR_IBEAM = KVM_GetCursorHash(LoadCursorA(NULL, IDC_IBEAM), NULL, 0);					
	CUR_NO = KVM_GetCursorHash(LoadCursorA(NULL, IDC_NO), NULL, 0);							
	CUR_SIZEALL = KVM_GetCursorHash(LoadCursorA(NULL, IDC_SIZEALL), NULL, 0);				
	CUR_SIZENESW = KVM_GetCursorHash(LoadCursorA(NULL, IDC_SIZENESW), NULL, 0);				
	CUR_SIZENS = KVM_GetCursorHash(LoadCursorA(NULL, IDC_SIZENS), NULL, 0);					
	CUR_SIZENWSE = KVM_GetCursorHash(LoadCursorA(NULL, IDC_SIZENWSE), NULL, 0);				
	CUR_SIZEWE = KVM_GetCursorHash(LoadCursorA(NULL, IDC_SIZEWE), NULL, 0);					
	CUR_UPARROW = KVM_GetCursorHash(LoadCursorA(NULL, IDC_UPARROW), NULL, 0);				
	CUR_WAIT = KVM_GetCursorHash(LoadCursorA(NULL, IDC_WAIT), NULL, 0);						
}

KVM_MouseCursors MouseAction(double absX, double absY, int button, short wheel)
{
	INPUT mouse;
	KVM_MouseCursors ret = KVM_MouseCursor_NOCHANGE;

	if (button == 0x88) 
	{
		// Double click indication, no nothing on windows.
		return(ret);
	}

	mouse.type = INPUT_MOUSE;
	mouse.mi.dx = (long)absX;
	mouse.mi.dy = (long)absY;
	mouse.mi.mouseData = wheel;
	mouse.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE | button;
	if (wheel) mouse.mi.dwFlags |= MOUSEEVENTF_WHEEL;
	mouse.mi.time = 0;
	mouse.mi.dwExtraInfo = 0;
	SendInput(1, &mouse, sizeof(INPUT));

	CURSORINFO info = { 0 };
	info.cbSize = sizeof(info);
	GetCursorInfo(&info);
	int i = KVM_GetCursorHash(info.hCursor, NULL, 0);

	if (i != CUR_CURRENT)
	{
		CUR_CURRENT = i;
		if (CUR_CURRENT == CUR_APPSTARTING)
		{
			ret = KVM_MouseCursor_APPSTARTING;
		}
		else if (CUR_CURRENT == CUR_ARROW)
		{
			ret = KVM_MouseCursor_ARROW;
		}
		else if (CUR_CURRENT == CUR_CROSS)
		{
			ret = KVM_MouseCursor_CROSS;
		}
		else if (CUR_CURRENT == CUR_HAND)
		{
			ret = KVM_MouseCursor_HAND;
		}
		else if (CUR_CURRENT == CUR_HELP)
		{
			ret = KVM_MouseCursor_HELP;
		}
		else if (CUR_CURRENT == CUR_IBEAM)
		{
			ret = KVM_MouseCursor_IBEAM;
		}
		else if (CUR_CURRENT == CUR_NO)
		{
			ret = KVM_MouseCursor_NO;
		}
		else if (CUR_CURRENT == CUR_SIZEALL)
		{
			ret = KVM_MouseCursor_SIZEALL;
		}
		else if (CUR_CURRENT == CUR_SIZENESW)
		{
			ret = KVM_MouseCursor_SIZENESW;
		}
		else if (CUR_CURRENT == CUR_SIZENS)
		{
			ret = KVM_MouseCursor_SIZENS;
		}
		else if (CUR_CURRENT == CUR_SIZENWSE)
		{
			ret = KVM_MouseCursor_SIZENWSE;
		}
		else if (CUR_CURRENT == CUR_SIZEWE)
		{
			ret = KVM_MouseCursor_SIZEWE;
		}
		else if (CUR_CURRENT == CUR_UPARROW)
		{
			ret = KVM_MouseCursor_UPARROW;
		}
		else if (CUR_CURRENT == CUR_WAIT)
		{
			ret = KVM_MouseCursor_WAIT;
		}
	}
	return(ret);
}


// Handling keyboard Input
// MSDN References:
// Keyboard input structure: http://msdn.microsoft.com/en-us/library/ms646271%28v=VS.85%29.aspx
// Virtual key-codes: http://msdn.microsoft.com/en-us/library/dd375731%28v=VS.85%29.aspx

void KeyAction(unsigned char keycode, int up)
{
	HWND windowHandle = GetForegroundWindow();
	INPUT key;
	if (windowHandle == NULL) return;
	SetForegroundWindow(windowHandle);
	key.type = INPUT_KEYBOARD;
	key.ki.wVk = keycode;
	key.ki.dwFlags = 0;
	if (up == 1) key.ki.dwFlags = KEYEVENTF_KEYUP;									// 1 = UP
	else if (up == 3) key.ki.dwFlags = KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP;		// 3 = EXUP
	else if (up == 4) key.ki.dwFlags = KEYEVENTF_EXTENDEDKEY;						// 4 = EXDOWN
	key.ki.time = 0;
	key.ki.wScan = (WORD)MapVirtualKey((UINT)keycode, MAPVK_VK_TO_VSC);				// This is required to make RDP client work.
	key.ki.dwExtraInfo = 0;
	SendInput(1, &key, sizeof(INPUT));
}

// Windows 8 Touch Related Support

#define MAX_TOUCH_COUNT 256
#define TOUCH_FEEDBACK_DEFAULT 0x1 
#define TOUCH_FEEDBACK_INDIRECT 0x2
#define TOUCH_FEEDBACK_NONE 0x3

#if WINVER < 0x0602 // If compiled on anything below Windows8 
typedef enum _POINTER_BUTTON_CHANGE_TYPE {		// This is a guess as what these values are, check for real values for this enum
	POINTER_CHANGE_NONE               = 0x00000000,
	POINTER_CHANGE_FIRSTBUTTON_DOWN   = 0x00000001,
	POINTER_CHANGE_FIRSTBUTTON_UP     = 0x00000002,
	POINTER_CHANGE_SECONDBUTTON_DOWN  = 0x00000004,
	POINTER_CHANGE_SECONDBUTTON_UP    = 0x00000010,
	POINTER_CHANGE_THIRDBUTTON_DOWN   = 0x00000020,
	POINTER_CHANGE_THIRDBUTTON_UP     = 0x00000040,
	POINTER_CHANGE_FOURTHBUTTON_DOWN  = 0x00000100,
	POINTER_CHANGE_FOURTHBUTTON_UP    = 0x00000200,
	POINTER_CHANGE_FIFTHBUTTON_DOWN   = 0x00000400,
	POINTER_CHANGE_FIFTHBUTTON_UP     = 0x00001000
} POINTER_BUTTON_CHANGE_TYPE;

typedef enum tagPOINTER_FLAGS {
	POINTER_FLAG_NONE = 0x00000000,
	POINTER_FLAG_NEW = 0x00000001,
	POINTER_FLAG_INRANGE = 0x00000002,
	POINTER_FLAG_INCONTACT = 0x00000004,
	POINTER_FLAG_FIRSTBUTTON = 0x00000010,
	POINTER_FLAG_SECONDBUTTON = 0x00000020,
	POINTER_FLAG_THIRDBUTTON = 0x00000040,
	POINTER_FLAG_FOURTHBUTTON = 0x00000080,
	POINTER_FLAG_FIFTHBUTTON = 0x00000100,
	POINTER_FLAG_PRIMARY = 0x00002000,
	POINTER_FLAG_CONFIDENCE = 0x000004000,
	POINTER_FLAG_CANCELED = 0x000008000,
	POINTER_FLAG_DOWN = 0x00010000,
	POINTER_FLAG_UPDATE = 0x00020000,
	POINTER_FLAG_UP = 0x00040000,
	POINTER_FLAG_WHEEL = 0x00080000,
	POINTER_FLAG_HWHEEL = 0x00100000,
	POINTER_FLAG_CAPTURECHANGED = 0x00200000
} POINTER_FLAGS;

typedef enum tagPOINTER_INPUT_TYPE { 
	PT_POINTER  = 0x00000001,
	PT_TOUCH    = 0x00000002,
	PT_PEN      = 0x00000003,
	PT_MOUSE    = 0x00000004
} POINTER_INPUT_TYPE;

typedef enum tagTOUCH_MASK { 
	TOUCH_MASK_NONE = 0x00000000,
	TOUCH_MASK_CONTACTAREA = 0x00000001,
	TOUCH_MASK_ORIENTATION = 0x00000002,
	TOUCH_MASK_PRESSURE = 0x00000004,
} TOUCH_MASK;

typedef struct tagPOINTER_INFO {
	POINTER_INPUT_TYPE         pointerType;
	UINT32                     pointerId;
	UINT32                     frameId;
	POINTER_FLAGS              pointerFlags;
	HANDLE                     sourceDevice;
	HWND                       hwndTarget;
	POINT                      ptPixelLocation;
	POINT                      ptHimetricLocation;
	POINT                      ptPixelLocationRaw;
	POINT                      ptHimetricLocationRaw;
	DWORD                      dwTime;
	UINT32                     historyCount;
	INT32                      inputData;
	DWORD                      dwKeyStates;
	UINT64                     PerformanceCount;
	POINTER_BUTTON_CHANGE_TYPE ButtonChangeType;
} POINTER_INFO;

typedef struct tagPOINTER_TOUCH_INFO {
	POINTER_INFO pointerInfo;
	int		     touchFlags;
	int		     touchMask;
	RECT         rcContact;
	RECT         rcContactRaw;
	UINT32       orientation;
	UINT32       pressure;
} POINTER_TOUCH_INFO;
#endif

typedef BOOL(WINAPI *_InitializeTouchInjection)(UINT32 maxCount, DWORD dwMode);
typedef BOOL(WINAPI *_InjectTouchInput)(UINT32 count, const POINTER_TOUCH_INFO *contacts);
_InjectTouchInput g_TouchInjectionCall = NULL;
HMODULE g_TouchLoadLibrary = NULL;
int g_TouchLoadLibraryState = 0;

int TouchInit()
{
	_InitializeTouchInjection init = NULL;
	if (g_TouchLoadLibraryState > 0) return g_TouchLoadLibraryState;
	g_TouchLoadLibrary = LoadLibrary(TEXT("User32.dll"));
	if (g_TouchLoadLibrary == NULL) { g_TouchLoadLibraryState = 2; return 2; }
	init = (_InitializeTouchInjection)GetProcAddress(g_TouchLoadLibrary, "InitializeTouchInjection");
	g_TouchInjectionCall = (_InjectTouchInput)GetProcAddress(g_TouchLoadLibrary, "InjectTouchInput");
	if (init == NULL || g_TouchInjectionCall == NULL || !init(MAX_TOUCH_COUNT, TOUCH_FEEDBACK_DEFAULT)) { FreeLibrary(g_TouchLoadLibrary); g_TouchLoadLibraryState = 2; return 2; }
	g_TouchLoadLibraryState = 1;
	return 1;
}

void TouchUnInit()
{
	if (g_TouchLoadLibraryState != 1) return;
	FreeLibrary(g_TouchLoadLibrary);
	g_TouchLoadLibrary = NULL;
	g_TouchInjectionCall = NULL;
	g_TouchLoadLibraryState = 0;

}

void MakeTouchObject(POINTER_TOUCH_INFO* contact, unsigned char id, POINTER_FLAGS flags, int x, int y)
{
	memset(contact, 0, sizeof(POINTER_TOUCH_INFO));
	contact->pointerInfo.pointerType = PT_TOUCH;	// we're sending touch input
	contact->pointerInfo.pointerId = id;			// contact id
	contact->pointerInfo.ptPixelLocation.x = x;
	contact->pointerInfo.ptPixelLocation.y = y;
	contact->pointerInfo.pointerFlags = flags;
	contact->touchFlags = 0;
	contact->touchMask = TOUCH_MASK_CONTACTAREA | TOUCH_MASK_ORIENTATION | TOUCH_MASK_PRESSURE;
	contact->orientation = 90;
	contact->pressure = 32000;

	// Contact area
	contact->rcContact.top = contact->pointerInfo.ptPixelLocation.y - 2;
	contact->rcContact.bottom = contact->pointerInfo.ptPixelLocation.y + 2;
	contact->rcContact.left = contact->pointerInfo.ptPixelLocation.x  - 2;
	contact->rcContact.right = contact->pointerInfo.ptPixelLocation.x  + 2;
}

int TouchAction1(unsigned char id, unsigned int flags, unsigned short x, unsigned short y)
{
	POINTER_TOUCH_INFO contact;

	if (g_TouchLoadLibraryState != 1) return 0;
	MakeTouchObject(&contact, id, (POINTER_FLAGS)flags, x, y);
	if (!g_TouchInjectionCall(1, &contact)) { printf("TOUCH1ERROR: id=%d, flags=%d, x=%d, y=%d, err=%ld\r\n", id, flags, x, y, GetLastError()); return 1; }

	//printf("TOUCH: id=%d, flags=%d, x=%d, y=%d\r\n", id, flags, x, y);
	return 0;
}

int TouchAction2(char* data, int datalen, int scaling)
{
	int i, records = datalen / 9;
	POINTER_TOUCH_INFO contact[16];

	if (g_TouchLoadLibraryState != 1) return 0;

	if (records > 16) records = 16;
	for (i = 0; i < records; i++) {
		int flags = (int)ntohl(((unsigned int*)(data + (9 * i) + 1))[0]);
		int x = (int)(ntohs(((unsigned short*)(data + (9 * i) + 5))[0]));
		int y = (int)(ntohs(((unsigned short*)(data + (9 * i) + 7))[0]));
		x = (x * 1024) / scaling;
		y = (y * 1024) / scaling;
		MakeTouchObject(&contact[i], data[i * 9], (POINTER_FLAGS)flags, x, y);
		//printf("TOUCH2: flags=%d, x=%d, y=%d\r\n", flags, x, y);
	}
	if (!g_TouchInjectionCall(records, contact)) { printf("TOUCH2ERROR: records=%d, err=%ld\r\n", records, GetLastError()); return 1; }

	return 0;
}

#endif
