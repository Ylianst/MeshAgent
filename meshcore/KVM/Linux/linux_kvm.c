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
#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibAsyncServerSocket.h"
#include "microstack/ILibProcessPipe.h"
#include <sys/wait.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <X11/extensions/XShm.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#ifdef _DAEMON
#define _GNU_SOURCE
#endif

int SCREEN_NUM = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int FRAME_RATE_TIMER = 0;
struct tileInfo_t **g_tileInfo = NULL;
pthread_t kvmthread = (pthread_t)NULL;
Display *eventdisplay = NULL;
int g_remotepause = 0;
int g_pause = 0;
int g_restartcount = 0;
int g_totalRestartCount = 0;
int g_shutdown = 0;
int change_display = 0;
unsigned short current_display = 0;
pid_t g_slavekvm = 0;
int master2slave[2];
int slave2master[2];
FILE *logFile = NULL;
int g_enableEvents = 0;

extern void* tilebuffer;

void kvm_send_resolution()
{
	char buffer[8];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);	// Y position

	// Write the reply to the pipe.
	//fprintf(logFile, "Writing from slave in kvm_send_resolution\n");
	if (write(slave2master[1], buffer, 8)) {}
	fsync(slave2master[1]);
	//fprintf(logFile, "Written %d bytes to master in kvm_send_resolution\n", written);
}

void kvm_send_display()
{
	char buffer[5];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SET_DISPLAY);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);				// Write the size
	buffer[4] = current_display;		// Display number

	// Write the reply to the pipe.
	//fprintf(logFile, "Writing from slave in kvm_send_display\n");
	if (write(slave2master[1], buffer, 5)) {}
	fsync(slave2master[1]);
	//fprintf(logFile, "Written %d bytes to master in kvm_send_display\n", written);
}

#define BUFSIZE 65535
#ifdef _DAEMON
int kvm_relay_restart(int paused);

void* kvm_mainrelay(void* param)
{
	int ptr = 0;
	int endPointer = 0;
	unsigned short size;
	char* pchRequest;
	ssize_t cbBytesRead = 0;
	enum ILibAsyncSocket_SendStatus r;

	if ((pchRequest = (char*)malloc(BUFSIZE)) == NULL) ILIBCRITICALEXIT(254);

	g_restartcount = 0;
	while (!g_shutdown)
	{
		//fprintf(logFile, "Reading from slave in kvm_mainrelay\n");
		cbBytesRead = read(slave2master[0], pchRequest + endPointer, BUFSIZE - endPointer);
		//fprintf(logFile, "Read %d bytes from slave in kvm_mainrelay\n", cbBytesRead);
		if (g_shutdown == 0 && (cbBytesRead == -1 || cbBytesRead == 0)) { g_shutdown = 3; }
		if (g_shutdown) { /*ILIBMESSAGE("KVMBREAK-R1\r\n");*/ break; }
		endPointer += cbBytesRead;

		// See how much we can safely send
		while (endPointer - ptr > 4)
		{
			//type = ntohs(((unsigned short*)(pchRequest + ptr))[0]);
			size = ntohs(((unsigned short*)(pchRequest + ptr))[1]);
			if (ptr + size > endPointer) break;
			ptr += size;
		}

		if (ptr > 0)
		{
			// Send any complete data
			r = GuardPost_ILibKVMSendTo(pchRequest, ptr, ILibAsyncSocket_MemoryOwnership_USER);
			if (r == ILibAsyncSocket_SEND_ON_CLOSED_SOCKET_ERROR) { /*ILIBMESSAGE("KVMBREAK-R2\r\n");*/ break; }
			else if (r == ILibAsyncSocket_NOT_ALL_DATA_SENT_YET)
			{
				g_pause = 1;
				while (g_pause && !g_shutdown) { if (GuardPost_ILibKVMGetPendingBytesToSend() == 0) { g_pause = 0; } usleep(5000); }
			}

			// Move remaining data to the front of the buffer
			if (endPointer - ptr > 0) memcpy(pchRequest, pchRequest + ptr, endPointer - ptr);
			endPointer -= ptr;
			ptr = 0;

		}

		if (g_shutdown || ((BUFSIZE - endPointer) == 0)) break;
	}

	if (g_slavekvm != 0)
	{
		int r;
		kill(g_slavekvm, SIGKILL);
		waitpid(g_slavekvm, &r, 0);
		g_slavekvm = 0;
	}

	close(slave2master[0]);
	close(master2slave[1]);
	kvmthread = (pthread_t)NULL;
	free(pchRequest);
	if (g_shutdown == 3 && g_restartcount < 4 && g_totalRestartCount < 256)
	{
		g_restartcount++;
		g_totalRestartCount++;
		usleep(500000);
		// fprintf(logFile, "Restarting again!\n");
		if (kvm_relay_restart(0) == 0) GuardPost_ILibKVMDisconnect();
	}
	else
	{
		if (g_shutdown == 2) GuardPost_ILibKVMDisconnect();
	}
	return 0;
}
#endif

int kvm_server_inputdata(char* block, int blocklen);
void* kvm_mainloopinput(void* parm)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char* pchRequest2[30000];
	ssize_t cbBytesRead = 0;

	while (!g_shutdown)
	{
		//fprintf(logFile, "Reading from master in kvm_mainloopinput\n");
		cbBytesRead = read(master2slave[0], pchRequest2 + len, 30000 - len);
		//fprintf(logFile, "Read %d bytes from master in kvm_mainloopinput\n", cbBytesRead);
		if (cbBytesRead == -1 || cbBytesRead == 0 || g_shutdown) { /*ILIBMESSAGE("KVMBREAK-K1\r\n");*/ g_shutdown = 1; break; }
		len += cbBytesRead;
		ptr2 = 0;
		while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, cbBytesRead - ptr)) != 0) { ptr += ptr2; }
		if (ptr == len) { len = 0; ptr = 0; }
		// TODO: else move the reminder.
	}

	return 0;
}


int lockfileCheckFn(const struct dirent *ent) {
	if (ent == NULL) {
		return 0;
	}

	if (!strncmp(ent->d_name, ".X", 2) && strcmp(ent->d_name, ".X11-unix") && strcmp(ent->d_name, ".XIM-unix")) {
		return 1;
	}

	return 0;
}

void getAvailableDisplays(unsigned short **array, int *len) {
	DIR *dir = NULL;
	struct dirent **ent = NULL;
	int i;
	*array = NULL;
	*len = 0;

	dir = opendir("/tmp/");
	if (dir != NULL) {
		*len = scandir("/tmp/", &ent, lockfileCheckFn, alphasort);

		if ((*array = (unsigned short *)malloc(*len)) == NULL) ILIBCRITICALEXIT(254);

		for (i = 0; i < *len; i++) {
			int dispNo = 0;

			sscanf(ent[i]->d_name, ".X%d-lock", &dispNo);
			(*array)[i] = (unsigned short)dispNo;
		}
	}
}

int getNextDisplay() {
	DIR *dir = NULL;
	struct dirent **ent = NULL;
	int i, dispNo;

	dir = opendir("/tmp/");
	if (dir != NULL) {
		int numDisplays = scandir("/tmp/", &ent, lockfileCheckFn, alphasort);
		if (numDisplays == 0) { return -1; }

		for (i = 0; i < numDisplays; i++) {

			sscanf(ent[i]->d_name, ".X%d-lock", &dispNo);

			if (dispNo == (int)current_display) {
				break;
			}
		}

		if (i == numDisplays) {
			i = 0;
		}
		else {
			i = (i + 1) % numDisplays;
		}

		sscanf(ent[i]->d_name, ".X%d-lock", &dispNo);
		current_display = (unsigned short) dispNo;
		closedir(dir);
	}
	else {
		current_display = 0;
	}

	return 0;
}

int setDisplay(unsigned short display_no) {
	char cmd[BUFSIZ] = "";
	char authFile[BUFSIZ] = "";
	FILE *pfile = NULL;
	int dispNo;

	sprintf(cmd, "ps aux 2>/dev/null | grep '/X.* :[0-9][0-9]* .*-auth' | egrep -v 'startx|xinit' | sed -e 's,^.*/X.* :\\([0-9][0-9]*\\) .* -auth \\([^ ][^ ]*\\).*$,\\1\\,\\2,' | grep '%d,'", display_no);
	pfile = popen(cmd, "r");

	if (pfile == NULL) {
		return -1;
	}

	if (fscanf(pfile, "%d,%510s", &dispNo, authFile) != 2) {
		fclose(pfile);
		return -1;
	}

	fclose(pfile);

	return setenv("XAUTHORITY", authFile, 1);
}

void kvm_send_display_list()
{
	unsigned short *displays = NULL;
	int len = 0;
	char* buffer;
	int totalSize = 0;
	int i;

	getAvailableDisplays(&displays, &len);
	totalSize = 2 /*Type*/ + 2 /*length of packet*/ + 2 /*length of data*/ + (len * 2) /*Data*/ + 2 /* Current display */;
	if ((buffer = (char*)malloc(totalSize)) == NULL) ILIBCRITICALEXIT(254);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)totalSize);			// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)len);					// Length
	for (i = 0; i < len; i++) {
		((unsigned short*)buffer)[i + 3] = (unsigned short)htons(displays[i]);
	}
	((unsigned short*)buffer)[i + 3] = (unsigned short)htons((unsigned short)current_display);	// Current display

	// Write the reply to the pipe.
	//fprintf(logFile, "Writing from slave in kvm_send_displays\n");
	if (write(slave2master[1], buffer, totalSize)) {}
	fsync(slave2master[1]);
	//fprintf(logFile, "Written %d bytes to master in kvm_send_displays\n", written);

	if (displays != NULL) free(displays);
}

int kvm_init(int displayNo)
{
	//fprintf(logFile, "kvm_init called\n"); fflush(logFile);
	int old_height_count = TILE_HEIGHT_COUNT;
	int count = 0;
	int dummy1, dummy2, dummy3;
	char displayString[256] = "";

	sprintf(displayString, ":%d", (int)displayNo);

	while (setDisplay(displayNo) != 0 && count++ < 10);

	if (count == 10) { return -1; }
	count = 0;

	eventdisplay = XOpenDisplay(displayString);
	//fprintf(logFile, "XAUTHORITY is %s", getenv("XAUTHORITY")); fflush(logFile);

	if (eventdisplay != NULL) { current_display = (unsigned short)displayNo; }

	while (eventdisplay == NULL && count++ < 100) {
		if (getNextDisplay() == -1) { return -1; }
		sprintf(displayString, ":%d", (int)current_display);
		if (setDisplay(current_display) != 0) { continue; }
		eventdisplay = XOpenDisplay(displayString);
	}

	if (count == 100 && eventdisplay == NULL) { return -1; }

	g_enableEvents = XQueryExtension(eventdisplay, "XTEST", &dummy1, &dummy2, &dummy3)? 1 : 0;
	if (!g_enableEvents) { printf("FATAL::::Fake motion is not supported.\n\n\n"); }

	SCREEN_NUM = DefaultScreen(eventdisplay);
	SCREEN_HEIGHT = DisplayHeight(eventdisplay, SCREEN_NUM);
	SCREEN_WIDTH = DisplayWidth(eventdisplay, SCREEN_NUM);
	SCREEN_DEPTH = DefaultDepth(eventdisplay, SCREEN_NUM);

	if (SCREEN_DEPTH < 15) {
		// fprintf(stderr, "kvm_init: We do not support display depth < 15.");
		return -1;
	}

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

	return 0;
}

void CheckDesktopSwitch(int checkres)
{
	if (change_display) {
		kvm_init(current_display);
		change_display = 0;
		return;
	}
}

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;
	CheckDesktopSwitch(0);

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);
	if (size > blocklen) return 0;

	switch (type)
	{
	case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			if (g_enableEvents) KeyAction(block[5], block[4], eventdisplay);
			break;
		}
	case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (size == 10 || size == 12)
			{
				x = ((int)ntohs(((unsigned short*)(block))[3]));
				y = ((int)ntohs(((unsigned short*)(block))[4]));
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				// printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				if (g_enableEvents) MouseAction(x, y, block[5], w, eventdisplay);
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
	case MNG_KVM_GET_DISPLAYS:
		{
			kvm_send_display_list();
			break;
		}
	case MNG_KVM_SET_DISPLAY:
		{
			if (ntohs(((unsigned short*)(block))[2]) == current_display) { break; } // Don't do anything
			current_display = ntohs(((unsigned short*)(block))[2]);
			change_display = 1;
			break;
		}
	case MNG_KVM_FRAME_RATE_TIMER:
		{
			int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			if (fr > 20 && fr < 2000) FRAME_RATE_TIMER = fr;
			break;
		}
	}
	return size;
}


int kvm_relay_feeddata(char* buf, int len)
{
	ssize_t written = 0;

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

void* kvm_server_mainloop(void* parm)
{
	int x, y, height, width, r, c, count = 0;
	long long desktopsize = 0;
	long long tilesize = 0;
	long long prev_timestamp = 0;
	long long cur_timestamp = 0;
	long long time_diff = 50;
	struct timeb tp;
	void *desktop = NULL;
	XImage *image = NULL;
	eventdisplay = NULL;
	Display *imagedisplay = NULL;
	void *buf = NULL;
	char displayString[256] = "";
	int screen_height, screen_width, screen_depth, screen_num;
	ssize_t written;
	XShmSegmentInfo shminfo;

	// Init the kvm
	//fprintf(logFile, "Before kvm_init.\n"); fflush(logFile);
	if (kvm_init(0) != 0) { return (void*)-1; }
	kvm_send_display_list();
	//fprintf(logFile, "After kvm_init.\n"); fflush(logFile);

	g_shutdown = 0;
	pthread_create(&kvmthread, NULL, kvm_mainloopinput, parm);
	//fprintf(logFile, "Created the kvmthread.\n"); fflush(logFile);

	while (!g_shutdown) {

		//printf("KVM/Loop");
		ftime(&tp);
		cur_timestamp = tp.time * 1000 + tp.millitm;
		if (prev_timestamp != 0)
		{
			time_diff = (FRAME_RATE_TIMER - (cur_timestamp - prev_timestamp));
			if (time_diff < 20) { time_diff = 20; }
		}
		usleep(time_diff * 1000);
		prev_timestamp = cur_timestamp;
		//printf("...\n");

		for (r = 0; r < TILE_HEIGHT_COUNT; r++) {
			for (c = 0; c < TILE_WIDTH_COUNT; c++) {
				g_tileInfo[r][c].flag = TILE_TODO;
			}
		}
		//fprintf(logFile, "Before CheckDesktopSwitch.\n"); fflush(logFile);
		CheckDesktopSwitch(1);
		//fprintf(logFile, "After CheckDesktopSwitch.\n"); fflush(logFile);

		setDisplay(current_display);

		sprintf(displayString, ":%d", (int)current_display);
		imagedisplay = XOpenDisplay(displayString);

		count = 0;

		if (imagedisplay == NULL && count++ < 100) {
			change_display = 1;
			if (getNextDisplay() == -1) { return (void*)-1; }
			//fprintf(logFile, "Before kvm_init1.\n"); fflush(logFile);
			kvm_init(current_display);
			//fprintf(logFile, "After kvm_init1.\n"); fflush(logFile);
			change_display = 0;
			if (image != NULL) { XDestroyImage(image); image = NULL; }
			continue;
		}

		if (count == 100 && imagedisplay == NULL) { g_shutdown = 1; break; }

		screen_num = DefaultScreen(imagedisplay);
		screen_height = DisplayHeight(imagedisplay, screen_num);
		screen_width = DisplayWidth(imagedisplay, screen_num);
		screen_depth = DefaultDepth(imagedisplay, screen_num);

		if (screen_depth <= 15) {
			//fprintf(logFile, "We do not support display depth %d < 15.\n", screen_depth); fflush(logFile);
			//fprintf(stderr, "We do not support display depth <= 15.");
			break;
		}

		if ((SCREEN_HEIGHT != screen_height || SCREEN_WIDTH != screen_width || SCREEN_DEPTH != screen_depth || SCREEN_NUM != screen_num)) 
		{
			kvm_init(current_display);
			if (image != NULL) { XDestroyImage(image); image = NULL; }
			continue;
		}


		image = XShmCreateImage(imagedisplay,
			DefaultVisual(imagedisplay, screen_num), // Use a correct visual. Omitted for brevity     
			screen_depth,
			ZPixmap, NULL, &shminfo, screen_width, screen_height);
		shminfo.shmid = shmget(IPC_PRIVATE,
			image->bytes_per_line * image->height,
			IPC_CREAT | 0777);
		shminfo.shmaddr = image->data = shmat(shminfo.shmid, 0, 0);
		shminfo.readOnly = False;
		XShmAttach(imagedisplay, &shminfo);
		XShmGetImage(imagedisplay,
			RootWindowOfScreen(DefaultScreenOfDisplay(imagedisplay)),
			image,
			0,
			0,
			AllPlanes);

		//image = XGetImage(imagedisplay,
		//		RootWindowOfScreen(DefaultScreenOfDisplay(imagedisplay))
		//		, 0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, AllPlanes, ZPixmap);


		if (image == NULL) {
			g_shutdown = 1;
		}
		else {
			getScreenBuffer((char **)&desktop, &desktopsize, image);
			for (y = 0; y < TILE_HEIGHT_COUNT; y++) {
				for (x = 0; x < TILE_WIDTH_COUNT; x++) {
					height = TILE_HEIGHT * y;
					width = TILE_WIDTH * x;

					if (g_shutdown) { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }

					if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND) {
						continue;
					}

					getTileAt(width, height, &buf, &tilesize, desktop, desktopsize, y, x);

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

		XShmDetach(imagedisplay, &shminfo);
		XDestroyImage(image); image = NULL;
		shmdt(shminfo.shmaddr);
		shmctl(shminfo.shmid, IPC_RMID, 0);
		
		if (imagedisplay != NULL) 
		{
			XCloseDisplay(imagedisplay);
			imagedisplay = NULL;
		}
	}

	close(slave2master[1]);
	close(master2slave[0]);
	slave2master[1] = 0;
	master2slave[0] = 0;

	XCloseDisplay(eventdisplay);
	eventdisplay  = NULL;
	pthread_join(kvmthread, NULL);
	kvmthread = (pthread_t)NULL;
	if (g_tileInfo != NULL)
	{
		for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); }
		free(g_tileInfo);
		g_tileInfo = NULL;
	}
	if(tilebuffer != NULL) { free(tilebuffer); tilebuffer = NULL; }
	return (void*)0;
}

void kvm_relay_readSink(ILibProcessPipe_Pipe sender, char *buffer, int bufferLen, int* bytesConsumed)
{
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0];
	void *reserved = ((void**)ILibMemory_GetExtraMemory(sender, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[1];
	unsigned short size;

	if (bufferLen > 4)
	{
		size = ntohs(((unsigned short*)(buffer))[1]);
		if (size <= bufferLen)
		{
			//printf("KVM Data: %u bytes\n", size);
			*bytesConsumed = size;
			writeHandler(buffer, size, reserved);
			return;
		}
	}
	*bytesConsumed = 0;
}
void* kvm_relay_restart(int paused, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int r;
	int count = 0;
	ILibProcessPipe_Pipe slave_out;

	if (g_slavekvm != 0) 
	{
		kill(g_slavekvm, SIGKILL);
		waitpid(g_slavekvm, &r, 0);
		g_slavekvm = 0;
	}

	r = pipe(slave2master);
	r = pipe(master2slave);

	slave_out = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(processPipeMgr, slave2master[0], 2 * sizeof(void*));	
	((void**)ILibMemory_GetExtraMemory(slave_out, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[0] = writeHandler;
	((void**)ILibMemory_GetExtraMemory(slave_out, ILibMemory_ILibProcessPipe_Pipe_CONTAINERSIZE))[1] = reserved;

	UNREFERENCED_PARAMETER(r);

	do
	{
		g_slavekvm = fork();
		if (g_slavekvm == -1 && paused == 0) sleep(2); // If we can't launch the child process, retry in a little while.
	}
	while (g_slavekvm == -1 && paused == 0 && ++count < 10);
	if (g_slavekvm == -1) return(NULL);

	if (g_slavekvm == 0) //slave
	{
		close(slave2master[0]);
		close(master2slave[1]);

		logFile = fopen("/tmp/slave", "w");

		//fprintf(logFile, "Starting kvm_server_mainloop\n");
		kvm_server_mainloop((void*)0);
		return(NULL);
	}
	else { //master
		close(slave2master[1]);
		close(master2slave[0]);
		logFile = fopen("/tmp/master", "w");

		// We will asyncronously read from the pipe, so we can just return
		ILibProcessPipe_Pipe_AddPipeReadHandler(slave_out, 65535, kvm_relay_readSink);
		return(slave_out);
	}
}


// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
void* kvm_relay_setup(void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	if (kvmthread != (pthread_t)NULL || g_slavekvm != 0) return 0;
	g_restartcount = 0;
	return kvm_relay_restart(1, processPipeMgr, writeHandler, reserved);
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
	int code;
	g_shutdown = 1;

	if (master2slave[1] != 0 && g_slavekvm != 0) 
	{ 
		kill(g_slavekvm, SIGKILL); 
		waitpid(g_slavekvm, &code, 0);
		g_slavekvm = 0; 
	}
	g_totalRestartCount = 0;
}
