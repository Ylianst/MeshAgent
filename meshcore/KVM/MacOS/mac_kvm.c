/*
Copyright 2010 - 2018 Intel Corporation

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

#include "mac_kvm.h"
#include "../../meshdefines.h"
#include "../../meshinfo.h"
#include "../../../microstack/ILibParsers.h"
#include "../../../microstack/ILibAsyncSocket.h"
#include "../../../microstack/ILibAsyncServerSocket.h"
#include "../../../microstack/ILibProcessPipe.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDLib.h>
#include <IOKit/hidsystem/IOHIDParameter.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>


int KVM_Listener_FD = -1;
#define KVM_Listener_Path "/usr/local/mesh_services/meshagent/kvm"
#if defined(_TLSLOG)
#define TLSLOG1 printf
#else
#define TLSLOG1(...) ;
#endif


int KVM_AGENT_FD = -1;
int KVM_SEND(char *buffer, int bufferLen)
{
	int retVal = -1;
	retVal = write(KVM_AGENT_FD == -1 ? STDOUT_FILENO : KVM_AGENT_FD, buffer, bufferLen);
	if (KVM_AGENT_FD == -1) { fsync(STDOUT_FILENO); }
	else
	{
		if (retVal < 0)
		{
			char tmp[255];
			int tmpLen = sprintf_s(tmp, sizeof(tmp), "Write Error: %d on %d\n", errno, KVM_AGENT_FD);
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}
	}
	return(retVal);
}



CGDirectDisplayID SCREEN_NUM = 0;
int SH_HANDLE = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_SCALE = 1;
int SCREEN_SCALE_SET = 0;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int FRAME_RATE_TIMER = 0;
struct tileInfo_t **g_tileInfo = NULL;
int g_remotepause = 0;
int g_pause = 0;
int g_shutdown = 0;
int g_resetipc = 0;
int kvm_clientProcessId = 0;
int g_restartcount = 0;
int g_totalRestartCount = 0;
int restartKvm = 0;
extern void* tilebuffer;
pid_t g_slavekvm = 0;
pthread_t kvmthread = (pthread_t)NULL;
ILibProcessPipe_Process gChildProcess;
ILibQueue g_messageQ;

//int logenabled = 1;
//FILE *logfile = NULL;
//#define MASTERLOGFILE "/dev/null"
//#define SLAVELOGFILE "/dev/null"
//#define LOGFILE "/dev/null"


#define KvmDebugLog(...)
//#define KvmDebugLog(...) printf(__VA_ARGS__); if (logfile != NULL) fprintf(logfile, __VA_ARGS__);
//#define KvmDebugLog(x) if (logenabled) printf(x);
//#define KvmDebugLog(x) if (logenabled) fprintf(logfile, "Writing from slave in kvm_send_resolution\n");

void senddebug(int val)
{
	char *buffer = (char*)ILibMemory_SmartAllocate(8);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_DEBUG);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);			// Write the size
	((int*)buffer)[1] = val;

	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}



void kvm_send_resolution() 
{
	char *buffer = ILibMemory_SmartAllocate(8);
	
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);	// Y position


	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}

#define BUFSIZE 65535

int set_kbd_state(int input_state)
{
	int ret = 0;
	kern_return_t kr;
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// Set CAPSLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDCapsLockState, (input_state & 4) == 4);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// Set NUMLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDNumLockState, (input_state & 1) == 1);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}
int get_kbd_state()
{
	int ret = 0;
	kern_return_t kr;
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}


int kvm_init()
{
	ILibCriticalLogFilename = "KVMSlave.log";
	int old_height_count = TILE_HEIGHT_COUNT;
	
	SCREEN_NUM = CGMainDisplayID();
	
	if (SCREEN_WIDTH > 0)
	{
		CGDisplayModeRef mode = CGDisplayCopyDisplayMode(SCREEN_NUM);
		SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
		CGDisplayModeRelease(mode);
	}

	SCREEN_HEIGHT = CGDisplayPixelsHigh(SCREEN_NUM) * SCREEN_SCALE;
	SCREEN_WIDTH = CGDisplayPixelsWide(SCREEN_NUM) * SCREEN_SCALE;
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
	reset_tile_info(old_height_count);
	
	unsigned char *buffer = ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
	buffer[4] = (unsigned char)get_kbd_state();

	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
	return 0;
}

// void CheckDesktopSwitch(int checkres) { return; }

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;
	//CheckDesktopSwitch(0);
	
	//senddebug(100+blocklen);

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);

	if (size > blocklen) return 0;

	switch (type)
	{
		case MNG_KVM_KEY_UNICODE: // Unicode Key
			if (size != 7) break;
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			break;
		case MNG_KVM_KEY: // Key
		{
			if (size != 6 || KVM_AGENT_FD != -1) { break; }
			KeyAction(block[5], block[4]);
			break;
		}
		case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (KVM_AGENT_FD != -1) { break; }
			if (size == 10 || size == 12)
			{
				x = ((int)ntohs(((unsigned short*)(block))[3])) / SCREEN_SCALE;
				y = ((int)ntohs(((unsigned short*)(block))[4])) / SCREEN_SCALE;
				
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				
				//printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				MouseAction(x, y, (int)(unsigned char)(block[5]), w);
			}
			break;
		}
		case MNG_KVM_COMPRESSION: // Compression
		{
			if (size != 6) break;
			set_tile_compression((int)block[4], (int)block[5]);
			COMPRESSION_RATIO = 100;
			break;
		}
		case MNG_KVM_REFRESH: // Refresh
		{
			kvm_send_resolution();

			int row, col;
			if (size != 4) break;
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
			break;
		}
		case MNG_KVM_FRAME_RATE_TIMER:
		{
			//int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			//if (fr > 20 && fr < 2000) FRAME_RATE_TIMER = fr;
			break;
		}
	}

	return size;
}


int kvm_relay_feeddata(char* buf, int len)
{
	ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
	return(len);
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	g_pause = pause;
}


void* kvm_mainloopinput(void* param)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char* pchRequest2[30000];
	int cbBytesRead = 0;

	char tmp[255];
	int tmpLen;

	if (KVM_AGENT_FD == -1)
	{
		int flags;
		flags = fcntl(STDIN_FILENO, F_GETFL, 0);
		if (fcntl(STDIN_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { senddebug(-999); }
	}

	while (!g_shutdown)
	{
		if (KVM_AGENT_FD != -1)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "About to read from IPC Socket\n");
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}

		KvmDebugLog("Reading from master in kvm_mainloopinput\n");
		cbBytesRead = read(KVM_AGENT_FD == -1 ? STDIN_FILENO: KVM_AGENT_FD, pchRequest2 + len, 30000 - len);
		KvmDebugLog("Read %d bytes from master in kvm_mainloopinput\n", cbBytesRead);

		if (KVM_AGENT_FD != -1)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "Read %d bytes from IPC-xx-Socket\n", cbBytesRead);
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}

		if (cbBytesRead == -1 || cbBytesRead == 0) 
		{ 
			/*ILIBMESSAGE("KVMBREAK-K1\r\n"); g_shutdown = 1; printf("shutdown\n");*/ 
			if (KVM_AGENT_FD == -1)
			{
				g_shutdown = 1;
			}
			else
			{
				g_resetipc = 1;
			}
			break; 
		}
		len += cbBytesRead;
		ptr2 = 0;
		
		if (KVM_AGENT_FD != -1)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "enter while\n");
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}
		while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, cbBytesRead - ptr)) != 0) { ptr += ptr2; }

		if (KVM_AGENT_FD != -1)
		{
			tmpLen = sprintf_s(tmp, sizeof(tmp), "exited while\n");
			write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);
		}

		if (ptr == len) { len = 0; ptr = 0; }
		// TODO: else move the reminder.
	}

	return 0;
}
void ExitSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGTERM, SIG_IGN);	
	
	if (KVM_Listener_FD > 0) 
	{
		write(STDOUT_FILENO, "EXITING\n", 8);
		fsync(STDOUT_FILENO);
		close(KVM_Listener_FD); 
	}
	g_shutdown = 1;
}
void* kvm_server_mainloop(void* param)
{
	int x, y, height, width, r, c = 0;
	long long desktopsize = 0;
	long long tilesize = 0;
	void *desktop = NULL;
	void *buf = NULL;
	int screen_height, screen_width, screen_num;
	int written = 0;
	struct sockaddr_un serveraddr;

	if (param == NULL)
	{
		// This is doing I/O via StdIn/StdOut

		int flags;
		flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
		if (fcntl(STDOUT_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) {}
	}
	else
	{
		// this is doing I/O via a Unix Domain Socket
		if ((KVM_Listener_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "ERROR CREATING DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			written = write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		int flags;
		flags = fcntl(KVM_Listener_FD, F_GETFL, 0);
		if (fcntl(KVM_Listener_FD, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { }

		written = write(STDOUT_FILENO, "Set FCNTL2\n", 11);
		fsync(STDOUT_FILENO);

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sun_family = AF_UNIX;
		strcpy(serveraddr.sun_path, KVM_Listener_Path);
		remove(KVM_Listener_Path);
		if (bind(KVM_Listener_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "BIND ERROR on DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			written = write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		if (listen(KVM_Listener_FD, 1) < 0)
		{
			written = write(STDOUT_FILENO, "LISTEN ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		written = write(STDOUT_FILENO, "LISTENING ON DOMAIN SOCKET\n", 27);
		fsync(STDOUT_FILENO);

		signal(SIGTERM, ExitSink);

		if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
		{
			written = write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}
		else
		{
			char tmp[255];
			int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
			written = write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);

		}
	}
	// Init the kvm
	g_messageQ = ILibQueue_Create();
	if (kvm_init() != 0) { return (void*)-1; }


	g_shutdown = 0;
	pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);


	if (KVM_AGENT_FD != -1)
	{
		written = write(STDOUT_FILENO, "Starting Loop []\n", 14);
		fsync(STDOUT_FILENO);

		char stmp[255];
		int stmpLen = sprintf_s(stmp, sizeof(stmp), "TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);
		written = write(STDOUT_FILENO, stmp, stmpLen);
		fsync(STDOUT_FILENO);
	}

	while (!g_shutdown) 
	{
		if (g_resetipc != 0)
		{
			g_resetipc = 0;
			close(KVM_AGENT_FD);

			SCREEN_HEIGHT = SCREEN_WIDTH = 0;

			char stmp[255];
			int stmpLen = sprintf_s(stmp, sizeof(stmp), "Waiting for NEXT DomainSocket, TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);
			written = write(STDOUT_FILENO, stmp, stmpLen);
			fsync(STDOUT_FILENO);

			if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
			{
				g_shutdown = 1;
				written = write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
				fsync(STDOUT_FILENO);
				break;
			}
			else
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
				pthread_create(&kvmthread, NULL, kvm_mainloopinput, param);
			}
		}
		
		// Check if there are pending messages to be sent
		ILibQueue_Lock(g_messageQ);
		while (ILibQueue_IsEmpty(g_messageQ) == 0)
		{
			if ((buf = (char*)ILibQueue_DeQueue(g_messageQ)) != NULL)
			{
				KVM_SEND(buf, (int)ILibMemory_Size(buf));
				ILibMemory_Free(buf);
			}
		}
		ILibQueue_UnLock(g_messageQ);


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

		screen_num = CGMainDisplayID();

		if (screen_num == 0) { g_shutdown = 1; senddebug(-2); break; }
		
		if (SCREEN_SCALE_SET == 0)
		{
			CGDisplayModeRef mode = CGDisplayCopyDisplayMode(screen_num);
			if (SCREEN_WIDTH > 0 && SCREEN_SCALE < (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH)
			{
				SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
				SCREEN_SCALE_SET = 1;
			}			 
			CGDisplayModeRelease(mode);
		}
		
		screen_height = CGDisplayPixelsHigh(screen_num) * SCREEN_SCALE;
		screen_width = CGDisplayPixelsWide(screen_num) * SCREEN_SCALE;
		
		if ((SCREEN_HEIGHT != screen_height || (SCREEN_WIDTH != screen_width) || SCREEN_NUM != screen_num)) 
		{
			kvm_init();
			continue;
		}

		//senddebug(screen_num);
		CGImageRef image = CGDisplayCreateImage(screen_num);
		//senddebug(99);
		if (image == NULL) 
		{
			g_shutdown = 1;
			senddebug(0);
		}
		else {
			//senddebug(100);
			getScreenBuffer((unsigned char **)&desktop, &desktopsize, image);

			if (KVM_AGENT_FD != -1)
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "...Enter for loop\n");
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
			}

			for (y = 0; y < TILE_HEIGHT_COUNT; y++) 
			{
				for (x = 0; x < TILE_WIDTH_COUNT; x++) {
					height = TILE_HEIGHT * y;
					width = TILE_WIDTH * x;
					if (!g_shutdown && (g_pause)) { usleep(100000); g_pause = 0; } //HACK: Change this
					
					if (g_shutdown) { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }
					
					if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND) {
						continue;
					}
					
					getTileAt(width, height, &buf, &tilesize, desktop, desktopsize, y, x);
					
					if (buf && !g_shutdown)
					{	
						// Write the reply to the pipe.
						//KvmDebugLog("Writing to master in kvm_server_mainloop\n");

						written = KVM_SEND(buf, tilesize);

						//KvmDebugLog("Wrote %d bytes to master in kvm_server_mainloop\n", written);
						if (written == -1) 
						{ 
							/*ILIBMESSAGE("KVMBREAK-K2\r\n");*/ 
							if(KVM_AGENT_FD == -1)
							{
								// This is a User Session, so if the connection fails, we exit out... We can be spawned again later
								g_shutdown = 1; height = SCREEN_HEIGHT; width = SCREEN_WIDTH; break;
							}
						}
						//else
						//{
						//	char tmp[255];
						//	int tmpLen = sprintf_s(tmp, sizeof(tmp), "KVM_SEND => tilesize: %d\n", tilesize);
						//	written = write(STDOUT_FILENO, tmp, tmpLen);
						//	fsync(STDOUT_FILENO);
						//}
						free(buf);

					}
				}
			}

			if (KVM_AGENT_FD != -1)
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "...exit for loop\n");
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
			}

		}
		CGImageRelease(image);
	}
	
	pthread_join(kvmthread, NULL);
	kvmthread = (pthread_t)NULL;

	if (g_tileInfo != NULL) { for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); } }
	g_tileInfo = NULL;
	if(tilebuffer != NULL) {
		free(tilebuffer);
		tilebuffer = NULL;
	}

	if (KVM_AGENT_FD != -1)
	{
		written = write(STDOUT_FILENO, "Exiting...\n", 11);
		fsync(STDOUT_FILENO);
	}
	ILibQueue_Destroy(g_messageQ);
	return (void*)0;
}

void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	//ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	//void *reserved = ((void**)user)[1];
	//void *pipeMgr = ((void**)user)[2];
	//char *exePath = (char*)((void**)user)[3];
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(exitCode);
	UNREFERENCED_PARAMETER(user);
}
void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	unsigned short size = 0;
	UNREFERENCED_PARAMETER(sender);
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	void *reserved = ((void**)user)[1];

	if (bufferLen > 4)
	{
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					TLSLOG1("<< KVM/WRITE: %d bytes\n", *bytesConsumed);
					writeHandler(buffer, *bytesConsumed, reserved);

					//printf("JUMBO PACKET: %d\n", *bytesConsumed);
					return;
				}
			}
		}
		else
		{
			size = ntohs(((unsigned short*)(buffer))[1]);
			if (size <= bufferLen)
			{
				*bytesConsumed = size;
				writeHandler(buffer, size, reserved);
				//printf("Normal PACKET: %d\n", *bytesConsumed);
				return;
			}
		}
	}
	*bytesConsumed = 0;
}
void kvm_relay_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	//KVMDebugLog *log = (KVMDebugLog*)buffer;

	//UNREFERENCED_PARAMETER(sender);
	//UNREFERENCED_PARAMETER(user);

	//if (bufferLen < sizeof(KVMDebugLog) || bufferLen < log->length) { *bytesConsumed = 0;  return; }
	//*bytesConsumed = log->length;
	////ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), (ILibRemoteLogging_Modules)log->logType, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	//ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	*bytesConsumed = bufferLen;
}


// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid)
{
	char * parms0[] = { "meshagent_osx64", "-kvm0", NULL };
	void **user = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, NULL, NULL);
	user[0] = writeHandler;
	user[1] = reserved;
	user[2] = processPipeMgr;
	user[3] = exePath;

	if (uid != 0)
	{
		// Spawn child kvm process into a specific user session
		gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx3(processPipeMgr, exePath, parms0, ILibProcessPipe_SpawnTypes_DEFAULT, (void*)(uint64_t)uid, 0);
		g_slavekvm = ILibProcessPipe_Process_GetPID(gChildProcess);
		
		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "Child KVM (pid: %d)", g_slavekvm);
		ILibProcessPipe_Process_ResetMetadata(gChildProcess, tmp);
		
		ILibProcessPipe_Process_AddHandlers(gChildProcess, 65535, &kvm_relay_ExitHandler, &kvm_relay_StdOutHandler, &kvm_relay_StdErrHandler, NULL, user);

		// Run the relay
		g_shutdown = 0;
		return(ILibProcessPipe_Process_GetStdOut(gChildProcess));
	}
	else
	{
		// No users are logged in. This is a special case for MacOS
		//int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		//if (!fd < 0)
		//{
		//	struct sockaddr_un serveraddr;
		//	memset(&serveraddr, 0, sizeof(serveraddr));
		//	serveraddr.sun_family = AF_UNIX;
		//	strcpy(serveraddr.sun_path, KVM_Listener_Path);
		//	if (!connect(fd, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
		//	{
		//		return((void*)(uint64_t)fd);
		//	}
		//}
		return((void*)KVM_Listener_Path);
	}
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
	KvmDebugLog("kvm_cleanup\n");
	g_shutdown = 1;
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
}
