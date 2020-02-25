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

typedef enum KVM_MouseCursors
{
	KVM_MouseCursor_NOCHANGE	= -1,
	KVM_MouseCursor_ARROW		= 0, 
	KVM_MouseCursor_APPSTARTING = 1,
	KVM_MouseCursor_CROSS 		= 2,
	KVM_MouseCursor_HAND		= 3,
	KVM_MouseCursor_HELP		= 4,
	KVM_MouseCursor_IBEAM 		= 5,
	KVM_MouseCursor_NO 			= 6,
	KVM_MouseCursor_SIZEALL 	= 7,
	KVM_MouseCursor_SIZENESW 	= 8,
	KVM_MouseCursor_SIZENS		= 9,
	KVM_MouseCursor_SIZENWSE	= 10,
	KVM_MouseCursor_SIZEWE 		= 11,
	KVM_MouseCursor_UPARROW		= 12,
	KVM_MouseCursor_WAIT		= 13
}KVM_MouseCursors;

void KVM_InitMouseCursors();
void KVM_UnInitMouseCursors();
void MouseAction(double absX, double absY, int button, short wheel);
void KeyAction(unsigned char keycode, int up);
int TouchInit();
void TouchUnInit();
int TouchAction1(unsigned char id, unsigned int flags, unsigned short x, unsigned short y);
int TouchAction2(char* data, int datalen, int scaling);

#endif
