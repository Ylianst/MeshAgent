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

#ifndef __ILIBDUKTAPE_SCRIPTCONTAINER__
#define __ILIBDUKTAPE_SCRIPTCONTAINER__

#include "microscript/duktape.h"
#include "ILibDuktape_Helpers.h"
#include "../microstack/ILibProcessPipe.h"
#include "../microstack/ILibSimpleDataStore.h"

#ifdef __DOXY__
/*!
\brief Process Encapsulation for a JavaScript engine. To use, must <b>require('ScriptContainer')</b>
*/
class MasterScriptContainer
{
public:
	/*!
	\brief Event emitted when the parent container has sent an out of band data object. <B>Note: </b>Only exposed if the currently executing code is running in a process isolated container
	\param obj The object that was received
	*/
	void data;
	/*!
	\brief Sends out of band data to the parent container. <B>Note: </b>Only exposed if the currently executing code is running in a process isolated container
	\param obj The object to send to the parent container
	*/
	void send(obj);

	/*!
	\brief Creates a ChildScriptContainer that is process isolated from the parent.
	*
	ChildScriptContainer Create(executionTimeout, permissions[, userType]);
	\param executionTimeout <int> Specifies the number of seconds that execution must complete, before the process is terminated. <b>0</b> means no limit.
	\param permissions <ContainerPermissions> ContainerPermissions specifying what permissions the child container will have. Default is all.
	\param userType <ContainerUserTypes> Optional ContainerUserTypes specifying the type of process isolation.
	\return ChildScriptContainer result
	*/
	ChildScriptContainer Create(executionTimeout, permissions[, userType]);

	/*! 
	\brief Enumeration describing the permissions executing java script will have
	*/
	enum ContainerPermissions
	{
		DEFAULT, //!< All Access
		NO_AGENT,//!< MeshAgent object will not be accessible
		NO_MARSHAL,//!< _GenericMarshal class will not be accessible
		NO_PROCESS_SPAWNING, //!< ILibProcessPipe class will not be accessible
		NO_FILE_SYSTEM_ACCESS,//!< fs class will not be accessible
		NO_NETWORK_ACCESS//!< Networking classes will not be accessible
	};

	/*!
	\brief Abstraction for a process isolated Java Script Engine.
	*/
	class ChildScriptContainer
	{
	public:
		/*!
		\brief Event emitted when the child process has exited
		\param code <int> The code that the child process exited with
		*/
		void exit;
		/*!
		\brief Event emitted when an exception has occured
		\param err Error object representing the exception that occured
		*/
		void error;
		/*!
		\brief Event emitted when the child container has sent an out of band data object
		\param obj The object that was received
		*/
		void data;

		/*!
		\brief Signals the child process to terminate
		*/
		void exit();
		/*!
		\brief Executes the supplied javascript in the context of the child container
		\param script <String | Buffer> The JavaScript to execute
		\param callback Optional callback that will get dispatched with the return value of the specified script. <b>Undefined</b> will be passed if there was no return value.
		*/
		void ExecuteString(script[, callback]);
		/*!
		\brief Sends out of band data to the child container
		\param obj The object to send to the child container
		*/
		void send(obj);
		/*!
		\brief Supplies JavaScript modules to the ChildScriptContainer
		\param name \<String\> The name to associate with the supplied module
		\param module <String | Buffer> The module to send to the ChildScriptContainer.
		*/
		void addModule(name, module);
	};

};
#endif

typedef enum SCRIPT_ENGINE_SECURITY_FLAGS
{
	SCRIPT_ENGINE_NO_DEBUGGER = 0x20000000,
	SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS = 0x10000000,
	SCRIPT_ENGINE_NO_GENERIC_MARSHAL_ACCESS = 0x08000000,
	SCRIPT_ENGINE_NO_PROCESS_SPAWNING = 0x04000000,
	SCRIPT_ENGINE_NO_FILE_SYSTEM_ACCESS = 0x00000001,
	SCRIPT_ENGINE_NO_NETWORK_ACCESS = 0x00000002,
}SCRIPT_ENGINE_SECURITY_FLAGS;

typedef struct SCRIPT_ENGINE_SETTINGS
{
	void *chain;
	SCRIPT_ENGINE_SECURITY_FLAGS securityFlags;
	unsigned int executionTimeout;
	ILibSimpleDataStore db;
	ILibDuktape_HelperEvent exitHandler;
	void *exitUserObject;

	ILibDuktape_NativeUncaughtExceptionHandler nExeptionHandler;
	void* nExceptionUserObject;

	char *exePath;
	ILibProcessPipe_Manager pipeManager;

	char *argList[];
}SCRIPT_ENGINE_SETTINGS;


void ILibDuktape_ScriptContainer_CheckEmbedded(char **script, int *scriptLen);
void ILibDuktape_ScriptContainer_CheckEmbeddedEx(char *exePath, char **script, int *scriptLen);

void ILibDuktape_ScriptContainer_InitMaster(void *chain, char *exePath, ILibProcessPipe_Manager manager);
int ILibDuktape_ScriptContainer_StartSlave(void *chain, ILibProcessPipe_Manager manager);

duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngine_minimal();
duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx3(duk_context *ctx, SCRIPT_ENGINE_SECURITY_FLAGS securityFlags, unsigned int executionTimeout, void *chain, char **argList, ILibSimpleDataStore *db, char *exePath, ILibProcessPipe_Manager pipeManager, ILibDuktape_HelperEvent exitHandler, void *exitUser);
duk_context *ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx2(SCRIPT_ENGINE_SETTINGS *settings);
#define ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(securityFlags, executionTimeout, chain, argList, db, exePath, pipeManager, exitHandler, exitUser) ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx3(ILibDuktape_ScriptContainer_InitializeJavaScriptEngine_minimal(), (securityFlags), (executionTimeout), (chain), (argList), (db), (exePath), (pipeManager), (exitHandler), (exitUser))
#define ILibDuktape_ScriptContainer_InitializeJavaScriptEngine(securityFlags, executionTimeout, chain, pp_argList, db, exitHandler, exitUser) ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx((securityFlags), (executionTimeout), (chain), (pp_argList), (db), NULL, NULL, (exitHandler), (exitUser))
int ILibDuktape_ScriptContainer_DebuggingOK(duk_context *ctx);

SCRIPT_ENGINE_SETTINGS *ILibDuktape_ScriptContainer_GetSettings(duk_context *ctx);
int ILibDuktape_ScriptContainer_CompileJavaScript_FromFile(duk_context *ctx, char *path, int pathLen);
int ILibDuktape_ScriptContainer_CompileJavaScriptEx(duk_context *ctx, char *payload, int payloadLen, char *filename, int filenameLen);
#define ILibDuktape_ScriptContainer_CompileJavaScript(ctx, payload, payloadLen) ILibDuktape_ScriptContainer_CompileJavaScriptEx(ctx, payload, payloadLen, NULL, 0)
int ILibDuktape_ScriptContainer_ExecuteByteCode(duk_context *ctx);

#endif
