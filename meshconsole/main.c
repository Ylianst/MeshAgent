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
#include "microscript/ILibDuktape_Commit.h"

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

#if defined(_LINKVM) && defined(__APPLE__)
extern void* kvm_server_mainloop(void *parm);
extern void senddebug(int val);
ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	ignore_result(write(STDOUT_FILENO, (void*)buffer, bufferLen));
	return ILibTransport_DoneState_COMPLETE;
}
#endif

#ifdef WIN32
#define wmain_free(argv) for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv);
int wmain(int argc, char **wargv)
#else
int main(int argc, char **argv)
#endif
{
	// Check if .JS file is integrated with executable
	char *integratedJavaScript = NULL;
	int integratedJavaScriptLen = 0;
	int retCode = 0;
	int capabilities = 0;

#ifdef WIN32
	int argvi, argvsz;
	char **argv = (char**)ILibMemory_SmartAllocate(argc * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		argvsz = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)wargv[argvi], -1, argv[argvi], argvsz, NULL, NULL);
	}
#endif

#if defined (_POSIX)
#ifndef _NOILIBSTACKDEBUG
char* crashMemory = ILib_POSIX_InstallCrashHandler(argv[0]);
#endif
#endif


	ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integratedJavaScriptLen);

	if (integratedJavaScriptLen != 0 && integratedJavaScript != NULL && argc > 1)
	{
		int i;
		for (i = 1; i < argc; ++i)
		{
			if (strcmp(argv[i], "--no-embedded=1") == 0 || strcmp(argv[i], "--no-embedded=\"1\"") == 0)
			{
				free(integratedJavaScript);
				integratedJavaScript = NULL;
				integratedJavaScriptLen = 0;
				break;
			}
		}
	}

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	} 
	if (argc > 2 && strcmp(argv[1], "-b64exec") == 0)
	{
		integratedJavaScript = NULL;
		integratedJavaScriptLen = ILibBase64Decode((unsigned char *)argv[2], (const int)strnlen_s(argv[2], sizeof(ILibScratchPad2)), (unsigned char**)&integratedJavaScript);
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-name") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(require('_agentNodeId').serviceName());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}

	if (argc > 1 && strcmp(argv[1], "-daemon") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('daemon').agent();", 0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcasecmp(argv[1], "-licenses") == 0)
	{
		printf("========================================================================================\n");
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2020 Intel Corporation\n");
		printf("                        https://github.com/Ylianst/MeshAgent \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Licensed under the Apache License, Version 2.0 (the \"License\");\n");
		printf("   you may not use this file except in compliance with the License.\n");
		printf("   You may obtain a copy of the License at\n");
		printf("   \n");
		printf("   http://www.apache.org/licenses/LICENSE-2.0\n");
		printf("   \n");
		printf("   Unless required by applicable law or agreed to in writing, software\n");
		printf("   distributed under the License is distributed on an \"AS IS\" BASIS,\n");
		printf("   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
		printf("   See the License for the specific language governing permissions and\n");
		printf("   limitations under the License.\n\n");
		printf("========================================================================================\n");
		printf(" Duktape Javascript Engine: Copyright (c) 2013-2019 by Duktape authors (see AUTHORS.rst)\n");
		printf("                        https://github.com/svaarala/duktape \n");
		printf("                        http://opensource.org/licenses/MIT \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Permission is hereby granted, free of charge, to any person obtaining a copy\n");
		printf("   of this software and associated documentation files(the \"Software\"), to deal\n");
		printf("   in the Software without restriction, including without limitation the rights\n");
		printf("   to use, copy, modify, merge, publish, distribute, sublicense, and / or sell\n");
		printf("   copies of the Software, and to permit persons to whom the Software is\n");
		printf("   furnished to do so, subject to the following conditions :\n");
		printf("   \n");
		printf("   The above copyright notice and this permission notice shall be included in\n");
		printf("   all copies or substantial portions of the Software.\n");
		printf("   \n");
		printf("   THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n");
		printf("   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n");
		printf("   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE\n");
		printf("   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n");
		printf("   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n");
		printf("   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n");
		printf("   THE SOFTWARE.\n");
		printf("========================================================================================\n");
		printf("ZLIB Data Compression Library: Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler\n");
		printf("                               http://www.zlib.net \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   This software is provided 'as-is', without any express or implied\n");
		printf("   warranty.In no event will the authors be held liable for any damages\n");
		printf("   arising from the use of this software.\n");
		printf("\n");
		printf("   Permission is granted to anyone to use this software for any purpose,\n");
		printf("   including commercial applications, and to alter it and redistribute it\n");
		printf("   freely, subject to the following restrictions :\n");
		printf("\n");
		printf("   1. The origin of this software must not be misrepresented; you must not\n");
		printf("      claim that you wrote the original software.If you use this software\n");
		printf("      in a product, an acknowledgment in the product documentation would be\n");
		printf("      appreciated but is not required.\n");
		printf("   2. Altered source versions must be plainly marked as such, and must not be\n");
		printf("      misrepresented as being the original software.\n");
		printf("   3. This notice may not be removed or altered from any source distribution.\n");
		printf("\n");
		printf("   Jean - loup Gailly        Mark Adler\n");
		printf("   jloup@gzip.org            madler@alumni.caltech.edu\n");


#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
		if (SOURCE_COMMIT_HASH != NULL && SOURCE_COMMIT_DATE != NULL) 
		{ 
			printf("   Commit Hash: %s\n", SOURCE_COMMIT_HASH); 
			printf("   Commit Date: %s\n", SOURCE_COMMIT_DATE);
		}
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	if (argc > 1 && strcasecmp(argv[1], "-updaterversion") == 0)
	{
#ifdef WIN32
		DWORD dummy;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "1\n", 2, &dummy, NULL);
#else
		ignore_result(write(STDOUT_FILENO, "1\n", 2));
#endif
#ifdef WIN32
		wmain_free(argv);
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
#ifdef WIN32
		wmain_free(argv);
#endif
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
#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}

	if (argc > 1 && strcasecmp(argv[1], "connect") == 0) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }

	if (integratedJavaScriptLen == 0)
	{
		if (argc >= 2 && strnlen_s(argv[1], 9) >= 8 && strncmp(argv[1], "-update:", 8) == 0)
		{
			ILibMemory_AllocateRaw(integratedJavaScript, 1024);
			if (argv[1][8] == '*')
			{
				// New Style
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, '%s');", argc > 2 ? argv[2] : "null");
			}
			else
			{
				// Legacy
				integratedJavaScriptLen = sprintf_s(integratedJavaScript, 1024, "require('agent-installer').update(false, ['%s']);", argc > 2 ? argv[2] : "");
			}
		}
	}
#ifdef WIN32
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C
	ILib_DumpEnabledContext winExceptionContext;
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
	__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winExceptionContext))
	{
		ILib_WindowsExceptionDebugEx(&winExceptionContext);
	}
	wmain_free(argv);
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
