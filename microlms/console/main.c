/*   
Copyright 2006 - 2013 Intel Corporation

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

#if defined(WIN32) || defined (_WIN32_WCE)
#ifndef MICROSTACK_NO_STDAFX
#include "stdafx.h"
#endif
#endif

#if defined(WIN32)
#define _CRTDBG_MAP_ALLOC
#ifdef _DEBUG
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif
#endif

#if defined(WINSOCK2)
	#include <winsock2.h>
	#include <ws2tcpip.h>
#elif defined(WINSOCK1)
	#include <winsock.h>
	#include <wininet.h>
#endif

#include <signal.h>
#include "../../microstack/ILibParsers.h"
#include "../lms/ILibLMS.h"

#if defined(WIN32) & !defined(_CONSOLE)
#include "resource.h"
#endif

#if defined(WIN32) && defined (_DEBUG)
#include <crtdbg.h>
#endif

// The following macros set and clear, respectively, given bits
// of the C runtime library debug flag, as specified by a bitmask.
#ifdef   _DEBUG
#define  SET_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \
	_CrtSetDbgFlag(~(a) & _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#else
#define  SET_CRT_DEBUG_FIELD(a)   ((void) 0)
#define  CLEAR_CRT_DEBUG_FIELD(a) ((void) 0)
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
// This routine place comments at the head of a section of debug output
void OutputHeading( const char * explanation )
{
	_RPT1( _CRT_WARN, "\n\n%s:\n**************************************************************************\n", explanation );
}
#endif
#endif

void *Chain = NULL;
struct ILibLMS_StateModule *MicroLMS = NULL;

extern void ctrl_SendSubscriptionEvent(char *data, int datalen);
void BreakSink(int s)
{
	UNREFERENCED_PARAMETER( s );
	signal(SIGINT, SIG_IGN);	// To ignore any more ctrl-c interrupts
	ILibStopChain(Chain);
}

#if defined(_POSIX) || defined (_CONSOLE)
int main(int argc, char **argv)
#else
DWORD WINAPI GPMain(LPVOID lpParameter)
#endif
{
// Shutdown on Ctrl + C
signal(SIGINT, BreakSink);

#ifdef _POSIX
	signal(SIGPIPE, SIG_IGN);
#ifdef _DEBUG
	//mtrace();
#endif
#endif

#ifdef MEMORY_CHECK
#ifdef WIN32
	//SET_CRT_DEBUG_FIELD( _CRTDBG_DELAY_FREE_MEM_DF );
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF);
#endif
#endif

	Chain = ILibCreateChain();
	MicroLMS = ILibLMS_Create(Chain, NULL);
	if (MicroLMS != NULL)
	{
		printf("Starting MicroLMS.\r\n");
		ILibStartChain(Chain);
		printf("Stopping MicroLMS.\r\n");
	}
	else
	{
		printf("Unable to launch MicroLMS. Check that Intel ME is present, MEI driver installed and run this executable as administrator.\r\n");
	}

#ifdef MEMORY_CHECK
#ifdef WIN32
	OutputHeading("Generating the final memory leak report\r\n");
	_CrtCheckMemory();
	_CrtDumpMemoryLeaks();
#endif
#endif

#ifdef _POSIX
#ifdef _DEBUG
    //muntrace();
#endif
#endif

#ifdef _POSIX
	exit(EXIT_SUCCESS);
#else
	return 0;
#endif
}

