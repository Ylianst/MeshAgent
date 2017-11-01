/*
Copyright 2006 - 2017 Intel Corporation

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

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#endif

#include "meshcore/agentcore.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

MeshAgentHostContainer *agentHost = NULL;

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <conio.h>
#include <ctype.h>
#include <tchar.h>
#endif

#ifdef _POSIX
#include <ctype.h>
#include <string.h>
#include <termios.h>
char _getch() {
               char cbuf = 0;
               struct termios old = { 0 };
               fflush(stdout);
               if (tcgetattr(0, &old) < 0) perror("Failed to get termios setting");
               old.c_lflag &= ~ICANON;   
               old.c_lflag &= ~ECHO;     
               old.c_cc[VMIN] = 1;         
               old.c_cc[VTIME] = 0;         
               if (tcsetattr(0, TCSANOW, &old) < 0) perror("Setting ICANON failed");
               if (read(0, &cbuf, 1) < 0) perror("read()");
               old.c_lflag |= ICANON;    
               old.c_lflag |= ECHO;      
               if (tcsetattr(0, TCSADRAIN, &old) < 0) perror("Faield to revert termios setting");
               return cbuf;
}
#endif
#define USERNAME_MAXLEN 32
#define PASSWORD_MAXLEN 32
#define DEFSETTINGS_MAXLEN 96



/*
G* Get password from console
*/
char * getpass_noecho(char* buffer, char *prompt) {
               char ch;
               int len = 0;

               printf("%s", prompt);
               while (len<PASSWORD_MAXLEN - 1) {
                              ch = _getch();
                              if (ch == '\r' || ch == '\n') break;
                              buffer[len++] = ch;
               }
               return buffer;
}


#ifdef WIN32
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	{
		if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
		return TRUE;
	}
	default:
		return FALSE;
	}
}
#endif


#if defined(_POSIX)
void BreakSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl c interrupts
	if (agentHost != NULL) { MeshAgent_Stop(agentHost); }
}
#endif


int main(int argc, char **argv)
{
	// Check if .JS file is integrated with executable
	FILE *tmpFile;
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;

	char *username = NULL;
	char *password = NULL;
	char *defsettings_str = NULL;
	int defsettings_strlen = 0;

#ifdef WIN32
	if (ILibString_EndsWith(argv[0], -1, ".exe", 4) == 0)
	{
		sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s.exe", argv[0]);
		tmpFile = fopen(ILibScratchPad, "rb");
	}
	else
	{
		tmpFile = fopen(argv[0], "rb");
	}
#else
	tmpFile = fopen(argv[0], "rb");
#endif
	
	if (tmpFile != NULL)
	{
		fseek(tmpFile, 0, SEEK_END);
		fseek(tmpFile, ftell(tmpFile) - 4, SEEK_SET);
		ignore_result(fread(ILibScratchPad, 1, 4, tmpFile));
		fseek(tmpFile, 0, SEEK_END);
		if (ftell(tmpFile) == ntohl(((int*)ILibScratchPad)[0]))
		{
			fseek(tmpFile, ftell(tmpFile) - 8, SEEK_SET);
			ignore_result(fread(ILibScratchPad, 1, 4, tmpFile));
			integratedJavaScriptLen = ntohl(((int*)ILibScratchPad)[0]);
			integratedJavaScript = ILibMemory_Allocate(1+integratedJavaScriptLen, 0, NULL, NULL);
			fseek(tmpFile, 0, SEEK_END);
			fseek(tmpFile, ftell(tmpFile) - 8 - integratedJavaScriptLen, SEEK_SET);
			ignore_result(fread(integratedJavaScript, 1, integratedJavaScriptLen, tmpFile));
			integratedJavaScript[integratedJavaScriptLen] = 0;
		}
		fclose(tmpFile);
	}

	int retCode = 0;
	if (argc > 2 && memcmp(argv[1], "-faddr", 6) == 0)
	{
		uint64_t addrOffset;
		util_hexToBuf(argv[2] + 2, strnlen_s(argv[2], 130) - 2, (char*)&addrOffset);
		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), addrOffset);
		printf("%s", ILibScratchPad);
		return(0);
	}
	// get user and password
	if (argc > 2 && memcmp(argv[1], "-username",9) == 0)
	{
		// it must be followed with username, -password and optionally password
		if (argc >=4 && memcmp(argv[3], "-password",9) == 0) 
		{
			username = ILibMemory_Allocate(1+USERNAME_MAXLEN, 0, NULL, NULL);
			memcpy_s((void *)username, USERNAME_MAXLEN, argv[2], USERNAME_MAXLEN);
			if (argc > 4)
			{
				// after password is assumed to be the password string
				password = ILibMemory_Allocate(1+PASSWORD_MAXLEN, 0, NULL, NULL);
				memcpy_s((void *)password, PASSWORD_MAXLEN, argv[4], PASSWORD_MAXLEN);

			} else {
				password = ILibMemory_Allocate(1+PASSWORD_MAXLEN, 0, NULL, NULL);
				password = getpass_noecho(password, "Password: ");
			}
		} else {
			fprintf(stderr, "Options -username must be followed by username, option -password and optionally the password.\n");
		}
		defsettings_str = ILibMemory_Allocate(DEFSETTINGS_MAXLEN, 0, NULL, NULL);
		snprintf(defsettings_str, DEFSETTINGS_MAXLEN,"var defsettings = {\n\tusername: '%s',\n\tpassword: '%s'\n};\n", username, password);
		fprintf(stdout,"\n%s\n",defsettings_str);
		defsettings_strlen = strlen(defsettings_str);
		// prepend the defsettings_str to integratedJavaScript
		if (integratedJavaScriptLen >0) 
		{	
			int tmplen = defsettings_strlen + integratedJavaScriptLen + 1;
			char * tmpbuf = ILibMemory_Allocate(tmplen, 0, NULL, NULL);
			snprintf(tmpbuf, tmplen, "%s%s", defsettings_str, integratedJavaScript);
			tmpbuf[tmplen - 1] = 0;
			free(defsettings_str);	
			free(integratedJavaScript);
			integratedJavaScript = tmpbuf;
			integratedJavaScriptLen = strlen(tmpbuf);
		} else {
			free(defsettings_str);	
		}
	}

	if (integratedJavaScriptLen == 0)
	{
		if (argc >= 2 && strnlen_s(argv[1], 9) >= 8 && strncmp(argv[1], "-update:", 8) == 0)
		{
			/*
			// If in OSX, attempt to clean up the KVM slave process.
			#if defined(__APPLE__) && defined(_DAEMON) && defined(_LINKVM)
			installOsx(0);
			#endif
			*/

			// -update:"C:\Users\Public\Downloads\MeshManageability\Debug\MeshConsol2.exe"
			MeshAgent_PerformSelfUpdate(argv[0], argv[1] + 8, argc, argv);
			return 0;
		}
	}
#ifdef WIN32
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C
	CONTEXT winExceptionContext;
#elif defined(_POSIX)
	signal(SIGPIPE, SIG_IGN); // Set a SIGNAL on Linux to listen for Ctrl-C						  
	signal(SIGINT, BreakSink);// Shutdown on Ctrl + C
	{	
		struct sigaction act;
		act.sa_handler = SIG_IGN;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGPIPE, &act, NULL);
	}
#ifndef _NOILIBSTACKDEBUG
	char* crashMemory = ILib_POSIX_InstallCrashHandler(argv[0]);
#endif
#endif

#ifdef WIN32
	__try
	{
		agentHost = MeshAgent_Create();
		agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
		agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
		while (MeshAgent_Start(agentHost, argc, argv) != 0);
		retCode = agentHost->exitCode;
		MeshAgent_Destroy(agentHost);
	}
	__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winExceptionContext))
	{
		ILib_WindowsExceptionDebug(&winExceptionContext);
	}
	_CrtDumpMemoryLeaks();
#else
	agentHost = MeshAgent_Create();
	agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
	agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
	while (MeshAgent_Start(agentHost, argc, argv) != 0);
	retCode = agentHost->exitCode;
	MeshAgent_Destroy(agentHost);
#ifndef _NOILIBSTACKDEBUG
	if (crashMemory != NULL) { free(crashMemory); }
#endif
#endif
	return retCode;
}
