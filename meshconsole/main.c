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

#include "microscript/ILibDuktape_ScriptContainer.h"
#include "microstack/ILibCrypto.h"

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

#if defined(WIN32) && defined(MeshLibInterface)
extern void ILibDuktape_ScriptContainer_GetEmbeddedJS_Raw(char *exePath, char **script, int *scriptLen);
typedef void(__stdcall *ExternalDispatch)(void *data);
__declspec(dllexport)  ExternalDispatch ExternalDispatchSink = NULL;
__declspec(dllexport) int mainEx(int argc, char **argv, ExternalDispatch ptr)
{
	int retCode = 0;
	char *js = NULL;
	int jsLen = 0;

	ExternalDispatchSink = ptr;
	ILibDuktape_ScriptContainer_GetEmbeddedJS_Raw(argv[0], &js, &jsLen);

	agentHost = MeshAgent_Create(0);
	agentHost->exePath = (char*)ILibMemory_AllocateA(strnlen_s(argv[0], _MAX_PATH) + 1);
	memcpy_s(agentHost->exePath, ILibMemory_AllocateA_Size(agentHost->exePath), argv[0], ILibMemory_AllocateA_Size(agentHost->exePath) - 1);
	
	agentHost->meshCoreCtx_embeddedScript = js;
	agentHost->meshCoreCtx_embeddedScriptLen = jsLen;
	while (MeshAgent_Start(agentHost, argc, argv) != 0);
	retCode = agentHost->exitCode;
	MeshAgent_Destroy(agentHost);
	agentHost = NULL;
	return(retCode);
}
#endif

#if defined(_LINKVM) && defined(__APPLE__)
extern void* kvm_server_mainloop(void *parm);
extern void senddebug(int val);
ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	ignore_result(write(STDOUT_FILENO, (void*)buffer, bufferLen));
	return ILibTransport_DoneState_COMPLETE;
}
#endif

int main(int argc, char **argv)
{
	// Check if .JS file is integrated with executable
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;
	int retCode = 0;
	int capabilities = 0;

#if defined (_POSIX)
#ifndef _NOILIBSTACKDEBUG
char* crashMemory = ILib_POSIX_InstallCrashHandler(argv[0]);
#endif
#endif


	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integratedJavaScriptLen);

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], -1);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, (int)sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
		return(0);
	}

#if defined(_LINKVM) && defined(__APPLE__)
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		kvm_server_mainloop(NULL);
		return 0;
	}
	else if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		kvm_server_mainloop((void*)(uint64_t)getpid());
		return 0;
	}
#endif

	if (argc > 2 && strcasecmp(argv[1], "-faddr") == 0)
	{
#if !defined(WIN32)
		uint64_t addrOffset = 0;
		sscanf(argv[2] + 2, "%016"PRIx64, &addrOffset);
#elif defined(WIN64)
		uint64_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%016llx", &addrOffset);
#else
		uint32_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%x", &addrOffset);
#endif

		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), (uint64_t)addrOffset);
		printf("%s", ILibScratchPad);
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
#ifdef WIN32
		sscanf_s(argv[2], "%lld", &delta);
#else
		sscanf(argv[2], "%"PRIu64, &delta);
#endif
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
		return(0);
	}

	if (argc > 1 && strcasecmp(argv[1], "connect") == 0) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }

	if (integratedJavaScriptLen == 0)
	{
		if (argc >= 2 && strnlen_s(argv[1], 9) >= 8 && strncmp(argv[1], "-update:", 8) == 0)
		{
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
#endif

#ifdef WIN32
	__try
	{
		agentHost = MeshAgent_Create(capabilities);
		agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
		agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
		while (MeshAgent_Start(agentHost, argc, argv) != 0);
		retCode = agentHost->exitCode;
		MeshAgent_Destroy(agentHost);
		agentHost = NULL;
	}
	__except (ILib_WindowsExceptionFilter(GetExceptionCode(), GetExceptionInformation(), &winExceptionContext))
	{
		ILib_WindowsExceptionDebug(&winExceptionContext);
	}
	_CrtDumpMemoryLeaks();
#else
	agentHost = MeshAgent_Create(capabilities);
	agentHost->meshCoreCtx_embeddedScript = integratedJavaScript;
	agentHost->meshCoreCtx_embeddedScriptLen = integratedJavaScriptLen;
	while (MeshAgent_Start(agentHost, argc, argv) != 0);
	retCode = agentHost->exitCode;
	MeshAgent_Destroy(agentHost);
	agentHost = NULL;
#ifndef _NOILIBSTACKDEBUG
	if (crashMemory != NULL) { free(crashMemory); }
#endif
#endif
	return retCode;
}
