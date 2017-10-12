#ifndef __DUKTAPE_PROCESSPIPE__
#define __DUKTAPE_PROCESSPIPE__

#include "duktape.h"

#ifdef __DOXY__
/*!
\brief An object that is used to spawn child processes to perform various tasks. <b>Note:</b> To use, must <b>require('ILibProcessPipe')</b>
*/
class ILibProcessPipe
{
public:
	/*!
	\brief Spawns a child process
	*
	ILibProcessPipe_Process CreateProcess(target[, spawnType][, ...args]);
	\param target \<String\> The target module to execute
	\param spawnType <ILibProcessPipe_SpawnTypes> The optional process type to spawn
	\param args \<String\> optional paramaters to pass to target on the command line. The first one is argv0, the second is argv1, etc.
	\returns \<ILibProcessPipe_Process\> stream attached to child process. NULL if the process could not be spawned.
	*/
	ILibProcessPipe_Process CreateProcess(target[, spawnType][, ...args]);

	/*!
	\brief Specifies the type of child process to spawn
	*/
	enum class ILibProcessPipe_SpawnTypes
	{
		DEFAULT, /*!< Same as parent*/
		USER, /*!< Currently logged on user*/
		WINLOGON, /*!< Windows Logon Screen*/
		TERM	/*!< Terminal*/
	};
	/*!
	\implements DuplexStream
	\brief Stream abstraction for a child process of ILibProcessPipe.
	*
	The underyling ReadableStream is attached to the child process's <b>stdIn</b>. \n
	The underlying WritableStream is attached tot he child process's <b>stdOut</b>.
	*/
	class ILibProcessPipe_Process 
	{
	public:
		/*!
		\brief The Child's Process ID
		*/
		int pid;
		/*!
		\brief The ReadableStream that is attached to the child process's <b>StdErr</b>
		*/
		ReadableStream error;


		/*!
		\brief The 'data' event is emitted data is available from the child process's <b>StdOut</b>.
		\param chunk A chunk of data. Can be a Buffer or a string.
		*/
		void data;
		/*!
		\brief The 'end' event is emitted when the child process has exited.
		*/
		void end;
	};
};
#endif


void ILibDuktape_ProcessPipe_Init(duk_context *ctx, void *chain);


#endif
