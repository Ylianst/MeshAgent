// Exercise production keyboard dispatch with OS calls substituted; no live input.
#define WIN32_LEAN_AND_MEAN
#define _LINKVM
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
static int testModifiers,lockCalls,sentCount,failSend;
static INPUT sent[32];
static UINT WINAPI testSendInput(UINT count,LPINPUT inputs,int size){if(failSend)return 0;for(UINT i=0;i<count;++i)sent[sentCount++]=inputs[i];return count;}
static SHORT WINAPI testGetAsyncKeyState(int key){return (testModifiers & (key==VK_CONTROL?1:key==VK_MENU?2:key==VK_SHIFT?4:0))?(SHORT)0x8000:0;}
static HWND WINAPI testGetForegroundWindow(void){return (HWND)1;}
static BOOL WINAPI testSetForegroundWindow(HWND h){return TRUE;}
static BOOL WINAPI testLockWorkStation(void){++lockCalls;return TRUE;}
#define SendInput testSendInput
#define GetAsyncKeyState testGetAsyncKeyState
#define GetForegroundWindow testGetForegroundWindow
#define SetForegroundWindow testSetForegroundWindow
#define LockWorkStation testLockWorkStation
#include "meshcore/KVM/Windows/input.c"
static int checks;
#define REQUIRE(x) do{++checks;if(!(x)){fprintf(stderr,"input test failed line %d\n",__LINE__);return 1;}}while(0)
static void reset_test(void){remoteWindowsKeys=0;suppressLockKeyUp=0;testModifiers=0;lockCalls=sentCount=failSend=0;}
int main(void){
 reset_test();KeyAction('L',0);REQUIRE(lockCalls==0&&sentCount==1);
 reset_test();KeyAction(VK_LWIN,0);KeyAction('L',0);REQUIRE(lockCalls==1&&sentCount==2&&remoteWindowsKeys==0);REQUIRE(sent[1].ki.wVk==VK_LWIN&&(sent[1].ki.dwFlags&KEYEVENTF_KEYUP));KeyAction('L',0);REQUIRE(sentCount==2&&lockCalls==1);KeyAction('L',1);REQUIRE(sentCount==2);KeyAction(VK_LWIN,1);REQUIRE(remoteWindowsKeys==0);
 reset_test();KeyAction(VK_RWIN,4);KeyAction('L',4);REQUIRE(lockCalls==1&&sent[1].ki.wVk==VK_RWIN);
 reset_test();KeyAction(VK_LWIN,0);KeyAction(VK_RWIN,4);KeyAction('L',0);REQUIRE(lockCalls==1&&sentCount==4);REQUIRE(sent[2].ki.wVk==VK_LWIN&&sent[3].ki.wVk==VK_RWIN);
 for(int mask=1;mask<=4;mask*=2){reset_test();KeyAction(VK_LWIN,0);testModifiers=mask;KeyAction('L',0);REQUIRE(lockCalls==0&&sentCount==2);}
 reset_test();failSend=1;KeyAction(VK_LWIN,0);REQUIRE(remoteWindowsKeys==0);failSend=0;KeyAction('L',0);REQUIRE(lockCalls==0);
 reset_test();KeyAction(VK_LWIN,0);failSend=1;KeyAction('L',0);REQUIRE(lockCalls==0);failSend=0;KeyAction(VK_LWIN,1);REQUIRE(remoteWindowsKeys==0);
 reset_test();KeyAction(VK_LWIN,0);KeyAction(VK_LWIN,1);KeyAction('L',0);REQUIRE(lockCalls==0);
 reset_test();KeyActionUnicode(0x03a9,0);KeyActionUnicode(0x03a9,1);REQUIRE(sentCount==2&&sent[0].ki.wScan==0x03a9&&(sent[1].ki.dwFlags&KEYEVENTF_KEYUP));
 // Enter identities and Unicode-to-Enter ordering must preserve the native wire path.
 reset_test();KeyAction(VK_RETURN,0);KeyAction(VK_RETURN,1);
 REQUIRE(sentCount==2&&sent[0].ki.wVk==VK_RETURN&&sent[1].ki.wVk==VK_RETURN);
 REQUIRE(sent[0].ki.wScan==MapVirtualKey(VK_RETURN,MAPVK_VK_TO_VSC)&&sent[0].ki.wScan!=0);
 REQUIRE(sent[0].ki.dwFlags==0&&sent[1].ki.dwFlags==KEYEVENTF_KEYUP);
 reset_test();KeyAction(VK_RETURN,4);KeyAction(VK_RETURN,3);
 REQUIRE(sentCount==2&&sent[0].ki.wVk==VK_RETURN&&sent[1].ki.wVk==VK_RETURN);
 REQUIRE(sent[0].ki.dwFlags==KEYEVENTF_EXTENDEDKEY&&sent[1].ki.dwFlags==(KEYEVENTF_EXTENDEDKEY|KEYEVENTF_KEYUP));
 reset_test();KeyActionUnicode(0x03a9,0);KeyActionUnicode(0x03a9,1);KeyAction(VK_RETURN,0);KeyAction(VK_RETURN,1);
 REQUIRE(sentCount==4&&(sent[0].ki.dwFlags&KEYEVENTF_UNICODE)&&sent[2].ki.wVk==VK_RETURN&&sent[3].ki.wVk==VK_RETURN);
 printf("PASS: %d Windows input assertions\n",checks);return 0;
}
ILibQueue gPendingPackets;
int gRemoteMouseRenderDefault,gRemoteMouseMoved;
void* ILibMemory_Init(void* p,size_t a,size_t b,ILibMemory_Types t){abort();return NULL;}
long long ILibGetUptime(void){return 0;}
void ILibQueue_EnQueue(ILibQueue q,void* p){abort();}
char* ILibCriticalLog(const char* m,const char* f,int l,int u1,int u2){abort();return NULL;}
int __fastcall util_crc(unsigned char* p,int len,int seed){abort();return 0;}
