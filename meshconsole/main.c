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
