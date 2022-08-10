/*
Copyright 2006 - 2022 Intel Corporation

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
#include "meshcore/meshdefines.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

extern ILibQueue gPendingPackets;
extern int gRemoteMouseRenderDefault;
extern int gRemoteMouseMoved;
uint64_t gMouseInputTime = 0;
int gCurrentCursor = KVM_MouseCursor_HELP;

HWINEVENTHOOK CUR_HOOK = NULL;
WNDCLASSEXA CUR_WNDCLASS;
HWND CUR_HWND = NULL;
HANDLE CUR_APCTHREAD = NULL;
HANDLE CUR_WORKTHREAD = NULL;

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

int KVM_CursorHashToMSG(int hashcode)
{
	int ret = KVM_MouseCursor_ARROW;
	if (hashcode == CUR_APPSTARTING)
	{
		ret = KVM_MouseCursor_APPSTARTING;
	}
	else if (hashcode == CUR_ARROW)
	{
		ret = KVM_MouseCursor_ARROW;
	}
	else if (hashcode == CUR_CROSS)
	{
		ret = KVM_MouseCursor_CROSS;
	}
	else if (hashcode == CUR_HAND)
	{
		ret = KVM_MouseCursor_HAND;
	}
	else if (hashcode == CUR_HELP)
	{
		ret = KVM_MouseCursor_HELP;
	}
	else if (hashcode == CUR_IBEAM)
	{
		ret = KVM_MouseCursor_IBEAM;
	}
	else if (hashcode == CUR_NO)
	{
		ret = KVM_MouseCursor_NO;
	}
	else if (hashcode == CUR_SIZEALL)
	{
		ret = KVM_MouseCursor_SIZEALL;
	}
	else if (hashcode == CUR_SIZENESW)
	{
		ret = KVM_MouseCursor_SIZENESW;
	}
	else if (hashcode == CUR_SIZENS)
	{
		ret = KVM_MouseCursor_SIZENS;
	}
	else if (hashcode == CUR_SIZENWSE)
	{
		ret = KVM_MouseCursor_SIZENWSE;
	}
	else if (hashcode == CUR_SIZEWE)
	{
		ret = KVM_MouseCursor_SIZEWE;
	}
	else if (hashcode == CUR_UPARROW)
	{
		ret = KVM_MouseCursor_UPARROW;
	}
	else if (hashcode == CUR_WAIT)
	{
		ret = KVM_MouseCursor_WAIT;
	}
	else if (hashcode == -495298424)
	{
		ret = KVM_MouseCursor_COL_RESIZE;
	}
	return(ret);
}

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
		if (hdcScreen != NULL)
		{
			HDC hdcMem = CreateCompatibleDC(hdcScreen);
			HBITMAP hbmCanvas = CreateCompatibleBitmap(hdcScreen, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2));
			if (hdcMem != NULL && hbmCanvas != NULL)
			{
				HGDIOBJ hbmold = SelectObject(hdcMem, hbmCanvas);
				BITMAPINFO bmpInfo;
				char *tmpBuffer;

				ZeroMemory(&bmpInfo, sizeof(bmpInfo));
				bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
				bmpInfo.bmiHeader.biCompression = BI_RGB;

				DrawIconEx(hdcMem, 0, 0, hc, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), 0, NULL, DI_NORMAL);
				GetDIBits(hdcScreen, hbmCanvas, 0, 0, NULL, &bmpInfo, DIB_RGB_COLORS);
				if ((tmpBuffer = (char*)malloc(bmpInfo.bmiHeader.biSizeImage)) == NULL) { ILIBCRITICALEXIT(254); }

				bmpInfo.bmiHeader.biCompression = BI_RGB;
				GetDIBits(hdcScreen, hbmCanvas, 0, (UINT)(ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2)), tmpBuffer, &bmpInfo, DIB_RGB_COLORS);
				crc = util_crc((unsigned char*)tmpBuffer, bmpInfo.bmiHeader.biSizeImage, 0);

				free(tmpBuffer);
				SelectObject(hdcMem, hbmold);
			}
			if (hbmCanvas != NULL) { DeleteObject(hbmCanvas); }
			if (hdcMem != NULL) { ReleaseDC(NULL, hdcMem); }
			if (hdcScreen != NULL) { ReleaseDC(NULL, hdcScreen); }
		}
	}

	return(crc);
}

void __stdcall KVM_APCSink(ULONG_PTR user)
{
	if (ntohs(((unsigned short*)user)[0]) == MNG_KVM_MOUSE_MOVE) { gRemoteMouseMoved = 0; }
	ILibQueue_EnQueue(gPendingPackets, (char*)user);
}
void CALLBACK KVMWinEventProc(
	HWINEVENTHOOK hook,
	DWORD event,
	HWND hwnd,
	LONG idObject,
	LONG idChild,
	DWORD idEventThread,
	DWORD time)
{
	char *buffer;
	CURSORINFO info = { 0 };

	if (hwnd == NULL && idObject == OBJID_CURSOR && CUR_APCTHREAD != NULL)
	{
		switch (event)
		{
			case EVENT_OBJECT_LOCATIONCHANGE:
				if (gRemoteMouseRenderDefault != 0 || ((uint64_t)ILibGetUptime() - gMouseInputTime) > 500)
				{
					info.cbSize = sizeof(info);
					GetCursorInfo(&info);

					buffer = (char*)ILibMemory_SmartAllocate(12);
					((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_MOVE);	// Write the type
					((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)12);					// Write the size
					((long*)buffer)[1] = info.ptScreenPos.x;
					((long*)buffer)[2] = info.ptScreenPos.y;
					QueueUserAPC((PAPCFUNC)KVM_APCSink, CUR_APCTHREAD, (ULONG_PTR)buffer);
				}
				break;
			case EVENT_OBJECT_NAMECHANGE:
			case EVENT_OBJECT_HIDE:
				// Mouse Cursor has changed
				info.cbSize = sizeof(info);
				GetCursorInfo(&info);
				gCurrentCursor = KVM_CursorHashToMSG(KVM_GetCursorHash(info.hCursor, NULL, 0));

				//printf(" MOUSE CURSOR => %d, %d\n", gCurrentCursor, KVM_GetCursorHash(info.hCursor, NULL, 0));

				buffer = (char*)ILibMemory_SmartAllocate(5);
				((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
				((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
				buffer[4] = (char)gCurrentCursor;															// Cursor Type
				QueueUserAPC((PAPCFUNC)KVM_APCSink, CUR_APCTHREAD, (ULONG_PTR)buffer);
				break;
			default:
				//printf("Unknown: %ul\n", event);
				break;
		}
	}
}

void KVM_StopMessagePump()
{
	if (CUR_HWND != NULL) 
	{
		PostMessageA(CUR_HWND, WM_QUIT, 0, 0);
		if (WaitForSingleObjectEx(CUR_WORKTHREAD, 5000, TRUE) == 0) { CloseHandle(CUR_WORKTHREAD); CUR_WORKTHREAD = NULL; }
		if (CUR_APCTHREAD != NULL) { CloseHandle(CUR_APCTHREAD); CUR_APCTHREAD = NULL; }
	}
}

void KVM_UnInitMouseCursors()
{
	if (CUR_HOOK != NULL)
	{
		UnhookWinEvent(CUR_HOOK);
		CUR_HOOK = NULL;

		KVM_StopMessagePump();
	}
}

LRESULT CALLBACK KVMWindowProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	if (uMsg == WM_CREATE)
	{
		CUR_HOOK = SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_NAMECHANGE, NULL, KVMWinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
	}
	return(DefWindowProcA(hwnd, uMsg, wParam, lParam));
}

void KVM_PumpMessage()
{
	MSG m;
	while (GetMessageA(&m, CUR_HWND, 0, 0) > 0)
	{
		TranslateMessage(&m);
		DispatchMessageA(&m);
	}
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION)
	{
		switch (wParam)
		{
			case WM_KEYUP:
			case WM_SYSKEYUP:
				{
					PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
					switch (p->vkCode)
					{
						case 0x90: // NUM_LOCK
						case 0x91: // SCROLL LOCK
						case 0x14: // CAPS LOCK
						{
							unsigned char *buffer = (char*)ILibMemory_SmartAllocate(5);
							((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
							((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
							buffer[4] = (unsigned char)((GetKeyState(0x90) & 0x1) | ((GetKeyState(0x91) & 0x1) << 1) | ((GetKeyState(0x14) & 0x1) << 2));
							QueueUserAPC((PAPCFUNC)KVM_APCSink, CUR_APCTHREAD, (ULONG_PTR)buffer);
							break;
						}
					}
				}
				break;
		}
	}
	return(CallNextHookEx(NULL, nCode, wParam, lParam));
}

DWORD WINAPI KVM_InitMessagePumpEx(LPVOID parm)
{
	ATOM a;
	//printf("MessagePump ThreadID: %u\n", GetCurrentThreadId());
	memset(&CUR_WNDCLASS, 0, sizeof(CUR_WNDCLASS));
	CUR_WNDCLASS.hInstance = GetModuleHandleA(NULL);
	CUR_WNDCLASS.lpszClassName = "MainWWW2Class";
	CUR_WNDCLASS.cbSize = sizeof(CUR_WNDCLASS);
	CUR_WNDCLASS.lpfnWndProc = KVMWindowProc;

	if ((a=RegisterClassExA(&CUR_WNDCLASS)) != 0)
	{
		HHOOK hhkLowLevelKybd = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, 0, 0);

		CUR_HWND = CreateWindowExA(0x00000088, "MainWWW2Class", "TestTitle", 0x00800000, 0, 0, 100, 100, 0, 0, 0, 0);
		KVM_PumpMessage();
		DestroyWindow(CUR_HWND);
		CUR_HWND = NULL;

		UnhookWindowsHookEx(hhkLowLevelKybd);
		UnregisterClassA((LPCSTR)a, GetModuleHandleA(NULL));
	}
	return(0);
}
void KVM_InitMessagePump()
{
	CUR_APCTHREAD = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
	CUR_WORKTHREAD = CreateThread(NULL, 0, KVM_InitMessagePumpEx, NULL, 0, 0);
}

void KVM_InitMouseCursors(void *pendingPackets)
{
	CURSORINFO info = { 0 };
	char *buffer;

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
	
	info.cbSize = sizeof(info);
	GetCursorInfo(&info);
	gCurrentCursor = KVM_CursorHashToMSG(KVM_GetCursorHash(info.hCursor, NULL, 0));

	buffer = (char*)ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
	buffer[4] = (char)gCurrentCursor;															// Cursor Type
	ILibQueue_EnQueue(pendingPackets, buffer);

	buffer = (char*)ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
	buffer[4] = (char)((GetKeyState(0x90) & 0x1) | ((GetKeyState(0x91) & 0x1) << 1) | ((GetKeyState(0x14) & 0x1) << 2));
	ILibQueue_EnQueue(pendingPackets, buffer);

	KVM_InitMessagePump();
}

void MouseAction(double absX, double absY, int button, short wheel)
{
	INPUT mouse;
	if (button == 0x88) return; // Double click indication, no nothing on windows.
	mouse.type = INPUT_MOUSE;
	mouse.mi.dx = (long)absX;
	mouse.mi.dy = (long)absY;
	mouse.mi.mouseData = wheel;
	mouse.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE | button;
	if (wheel) mouse.mi.dwFlags |= MOUSEEVENTF_WHEEL;
	mouse.mi.time = 0;
	mouse.mi.dwExtraInfo = 0;
	gMouseInputTime = (uint64_t)ILibGetUptime();
	SendInput(1, &mouse, sizeof(INPUT));
}

void KeyAction(unsigned char keycode, int up)
{
	INPUT key;
	HWND windowHandle = GetForegroundWindow();
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
	key.ki.dwExtraInfo = GetMessageExtraInfo();
	SendInput(1, &key, sizeof(INPUT));
	//printf("KEY keycode: %d, up: %d, scan: %d\r\n", keycode, up, key.ki.wScan);
}

void KeyActionUnicode(WORD unicode, int up)
{
	INPUT key;
	HWND windowHandle = GetForegroundWindow();
	if (windowHandle == NULL) return;
	SetForegroundWindow(windowHandle);
	key.type = INPUT_KEYBOARD;
	key.ki.wVk = 0;
	key.ki.dwFlags = KEYEVENTF_UNICODE;
	if (up == 1) key.ki.dwFlags |= KEYEVENTF_KEYUP;	 // 1 = UP
	key.ki.time = 0;
	key.ki.wScan = unicode;
	key.ki.dwExtraInfo = GetMessageExtraInfo();
	SendInput(1, &key, sizeof(INPUT));
	//printf("KEY unicode: %d, up: %d\r\n", unicode, up);
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
	// These functions only exist on Windows 8 and above, so it's ok that the SYSTEM32 flag requires Win 7 SP2
	_InitializeTouchInjection init = NULL;
	if (g_TouchLoadLibraryState > 0) return g_TouchLoadLibraryState;
	g_TouchLoadLibrary = LoadLibraryExA((LPCSTR)"User32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); 
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
	if (!g_TouchInjectionCall(1, &contact)) { printf("TOUCH1ERROR: id=%u, flags=%u, x=%u, y=%u, err=%ld\r\n", id, flags, x, y, GetLastError()); return 1; }

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
