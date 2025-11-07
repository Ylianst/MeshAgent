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

#if defined(__APPLE__) && defined(_LINKVM)
#include <dirent.h>
#include <limits.h>
#include <libgen.h>
#include <string.h>
#endif

MeshAgentHostContainer *agentHost = NULL;
#ifdef _OPENBSD
#include <stdlib.h>
char __agentExecPath[1024] = { 0 };
#endif


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
extern void* kvm_server_mainloop(void *parm, char *companyName, char *meshServiceName);
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
#ifdef _OPENBSD
	realpath(argv[0], __agentExecPath);
#endif

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

	if (argc > 1 && strcmp(argv[1], "-export") == 0 && integratedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').expand({embedded: true});process.exit();",0);
		integratedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
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
	if (argc > 1 && strcasecmp(argv[1], "-agentHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentFullHash") == 0 && integratedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();";
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
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2022 Intel Corporation\n");
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

		printf("Agent ARCHID: %d\n", MESH_AGENTID);
		char script[] = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(process.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require('win-authenticode-opus').locked(_tmp.url); if(_tmp!=null) { console.log('LOCKED to: ' + _tmp.dns); console.log(' => ' + _tmp.id); } } } process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integratedJavaScriptLen = (int)sizeof(script) - 1;
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
	// -kvm0 DISABLED: macOS now uses REVERSED ARCHITECTURE with -kvm1
	//
	// Historical context:
	// - -kvm0: Original process-spawning architecture (stdin/stdout I/O)
	// - -kvm1: Apple-required architecture using QueueDirectories + domain sockets
	//
	// The -kvm1 REVERSED ARCHITECTURE was required to work within Apple's
	// LaunchAgent/LaunchDaemon framework and bootstrap namespace restrictions.
	// -kvm0 is kept commented here for function/feature comparison purposes.
	//
	// See commit 8772b02 (Oct 29, 2025) for removal of -kvm0 spawning code.
	/*
	if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)
	{
		kvm_server_mainloop(NULL);
		return 0;
	}
	else
	*/
	if (argc > 1 && strcasecmp(argv[1], "-kvm1") == 0)
	{
		// Read companyName and meshServiceName from database for dynamic path generation
		char *companyName = NULL;
		char *meshServiceName = NULL;
		void *masterDb = NULL;
		char dbPath[PATH_MAX];
		char exePath[PATH_MAX];
		int msnlen;

		// Get executable directory using dirname() which requires a modifiable string
		strncpy(exePath, argv[0], sizeof(exePath) - 1);
		exePath[sizeof(exePath) - 1] = '\0';
		char *exedir = dirname(exePath);

		if (exedir != NULL)
		{
			snprintf(dbPath, sizeof(dbPath), "%s/meshagent.db", exedir);

			// Open database
			masterDb = ILibSimpleDataStore_Create(dbPath);
			if (masterDb != NULL)
			{
				// Read meshServiceName
				if ((msnlen = ILibSimpleDataStore_Get(masterDb, "meshServiceName", NULL, 0)) != 0)
				{
					meshServiceName = (char*)malloc(msnlen + 1);
					ILibSimpleDataStore_Get(masterDb, "meshServiceName", meshServiceName, msnlen);
					meshServiceName[msnlen] = '\0';
				}
				else
				{
					meshServiceName = strdup("meshagent");
				}

				// Read companyName
				if ((msnlen = ILibSimpleDataStore_Get(masterDb, "companyName", NULL, 0)) != 0)
				{
					companyName = (char*)malloc(msnlen + 1);
					ILibSimpleDataStore_Get(masterDb, "companyName", companyName, msnlen);
					companyName[msnlen] = '\0';
				}

				ILibSimpleDataStore_Close(masterDb);
			}
			else
			{
				// Fallback if database can't be opened
				meshServiceName = strdup("meshagent");
			}
		}
		else
		{
			// Fallback if exedir can't be determined
			meshServiceName = strdup("meshagent");
		}

		kvm_server_mainloop((void*)(uint64_t)getpid(), companyName, meshServiceName);

		// Cleanup
		if (companyName != NULL) free(companyName);
		if (meshServiceName != NULL) free(meshServiceName);

		return 0;
	}
#endif

#if defined(__APPLE__) && defined(_LINKVM)
	// TODO: Clean up stale KVM session files from previous crash/unclean shutdown
	// Now that paths are dynamic based on companyName.meshServiceName, we need to either:
	// 1. Read companyName/meshServiceName early to build correct paths for cleanup
	// 2. Use glob patterns to clean up all matching files (/tmp/*-kvm.sock, /var/run/*/session-active)
	// 3. Move cleanup to after database is loaded in MeshAgent_Start
	// For now, skipping cleanup - each serviceId has its own paths and won't conflict
	/*
	unlink("/tmp/meshagent-kvm.sock");
	unlink("/var/run/meshagent/session-active");

	// Clear all contents from /var/run/meshagent but keep the directory itself
	// This avoids QueueDirectories weirdness while cleaning up stale files
	DIR *dir = opendir("/var/run/meshagent");
	if (dir != NULL)
	{
		struct dirent *entry;
		char filepath[PATH_MAX];
		
		while ((entry = readdir(dir)) != NULL)
		{
			// Skip . and .. entries
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;
				
			snprintf(filepath, sizeof(filepath), "/var/run/meshagent/%s", entry->d_name);
			
			if (entry->d_type == DT_DIR)
			{
				// Recursively remove subdirectory - this shouldn't happen but handle it
				char rm_cmd[PATH_MAX + 20];
				snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf \"%s\"", filepath);
				system(rm_cmd);
			}
			else
			{
				// Remove regular file
				unlink(filepath);
			}
		}
		closedir(dir);
	}
	// Errors are ignored - files might not exist and that's fine
	*/
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

	// Note: KVM socket is now created on-demand when session starts (not at startup)
	// QueueDirectories triggers -kvm1 only when /var/run/meshagent/ contains session file

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

extern void* gILibChain;
void _fdsnap()
{
	char val[] = "require('ChainViewer').getSnapshot().then(function(c) { console.log(c); console.log(require('ChainViewer').getTimerInfo()); });";
	duk_eval_string_noresult(agentHost->meshCoreCtx, val);
}
void _fdsnap2()
{
	char val[] = "console.setDestination(console.Destinations.LOGFILE);require('ChainViewer').getSnapshot().then(function(c) { console.log(c); console.log(require('ChainViewer').getTimerInfo()); });";
	duk_eval_string_noresult(agentHost->meshCoreCtx, val);
}
void _timerinfo()
{
	char *s = ILibChain_GetMetadataForTimers(gILibChain);
	printf("%s\n", s);
	ILibMemory_Free(s);
}