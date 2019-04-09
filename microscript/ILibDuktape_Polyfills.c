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

#include "duktape.h"
#include "ILibDuktape_Helpers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_DuplexStream.h"
#include "ILibDuktape_EventEmitter.h"
#include "ILibDuktape_Debugger.h"
#include "../microstack/ILibParsers.h"
#include "../microstack/ILibCrypto.h"
#include "../microstack/ILibRemoteLogging.h"


#define ILibDuktape_Timer_Ptrs					"\xFF_DuktapeTimer_PTRS"
#define ILibDuktape_Queue_Ptr					"\xFF_Queue"
#define ILibDuktape_Stream_Buffer				"\xFF_BUFFER"
#define ILibDuktape_Stream_ReadablePtr			"\xFF_ReadablePtr"
#define ILibDuktape_Stream_WritablePtr			"\xFF_WritablePtr"
#define ILibDuktape_Console_Destination			"\xFF_Console_Destination"
#define ILibDuktape_Console_LOG_Destination		"\xFF_Console_Destination"
#define ILibDuktape_Console_WARN_Destination	"\xFF_Console_WARN_Destination"
#define ILibDuktape_Console_ERROR_Destination	"\xFF_Console_ERROR_Destination"
#define ILibDuktape_Console_INFO_Level			"\xFF_Console_INFO_Level"
#define ILibDuktape_Console_SessionID			"\xFF_Console_SessionID"

#define ILibDuktape_DescriptorEvents_ChainLink	"\xFF_DescriptorEvents_ChainLink"
#define ILibDuktape_DescriptorEvents_Table		"\xFF_DescriptorEvents_Table"
#define ILibDuktape_DescriptorEvents_FD			"\xFF_DescriptorEvents_FD"
#define ILibDuktape_DescriptorEvents_Options	"\xFF_DescriptorEvents_Options"

typedef enum ILibDuktape_Console_DestinationFlags
{
	ILibDuktape_Console_DestinationFlags_DISABLED		= 0,
	ILibDuktape_Console_DestinationFlags_StdOut			= 1,
	ILibDuktape_Console_DestinationFlags_ServerConsole	= 2,
	ILibDuktape_Console_DestinationFlags_WebLog			= 4,
	ILibDuktape_Console_DestinationFlags_LogFile		= 8
}ILibDuktape_Console_DestinationFlags;

int g_displayStreamPipeMessages = 0;
int g_displayFinalizerMessages = 0;
extern int GenerateSHA384FileHash(char *filePath, char *fileHash);

duk_ret_t ILibDuktape_Pollyfills_Buffer_slice(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer;
	char *out;
	duk_size_t bufferLen;
	int offset = 0;
	duk_push_this(ctx);

	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	if (nargs >= 1)
	{
		offset = duk_require_int(ctx, 0);
		bufferLen -= offset;
	}
	if (nargs == 2)
	{
		bufferLen = (duk_size_t)duk_require_int(ctx, 1) - offset;
	}
	duk_push_fixed_buffer(ctx, bufferLen);
	out = Duktape_GetBuffer(ctx, -1, NULL);
	memcpy_s(out, bufferLen, buffer + offset, bufferLen);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_toString(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *buffer, *tmpBuffer;
	duk_size_t bufferLen = 0;
	char *cType;

	duk_push_this(ctx);									// [buffer]
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (nargs == 0)
	{
		if (bufferLen == 0 || buffer == NULL)
		{
			duk_push_null(ctx);
		}
		else
		{
			// Just convert to a string
			duk_push_lstring(ctx, buffer, strnlen_s(buffer, bufferLen));			// [buffer][string]
		}
	}
	else
	{
		cType = (char*)duk_require_string(ctx, 0);
		if (strcmp(cType, "base64") == 0)
		{
			duk_push_fixed_buffer(ctx, ILibBase64EncodeLength((int)bufferLen));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			ILibBase64Encode((unsigned char*)buffer, (int)bufferLen, (unsigned char**)&tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 2));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else if (strcmp(cType, "hex:") == 0)
		{
			duk_push_fixed_buffer(ctx, 1 + (bufferLen * 3));
			tmpBuffer = Duktape_GetBuffer(ctx, -1, NULL);
			util_tohex2(buffer, (int)bufferLen, tmpBuffer);
			duk_push_string(ctx, tmpBuffer);
		}
		else
		{
			return(ILibDuktape_Error(ctx, "Unrecognized parameter"));
		}
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_from(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	char *str;
	duk_size_t strlength;
	char *encoding;
	char *buffer;
	int bufferLen;

	if (nargs == 1)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if(!(nargs == 2 && duk_is_string(ctx, 0) && duk_is_string(ctx, 1)))
	{
		return(ILibDuktape_Error(ctx, "usage not supported yet"));
	}

	str = (char*)duk_get_lstring(ctx, 0, &strlength);
	encoding = (char*)duk_require_string(ctx, 1);

	if (strcmp(encoding, "base64") == 0)
	{
		// Base64		
		buffer = duk_push_fixed_buffer(ctx, ILibBase64DecodeLength((int)strlength));
		bufferLen = ILibBase64Decode((unsigned char*)str, (int)strlength, (unsigned char**)&buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else if (strcmp(encoding, "hex") == 0)
	{		
		if (ILibString_StartsWith(str, (int)strlength, "0x", 2) != 0)
		{
			str += 2;
			strlength -= 2;
		}
		buffer = duk_push_fixed_buffer(ctx, strlength / 2);
		bufferLen = util_hexToBuf(str, (int)strlength, buffer);
		duk_push_buffer_object(ctx, -1, 0, bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "unsupported encoding"));
	}
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_Buffer_readInt32BE(duk_context *ctx)
{
	int offset = duk_require_int(ctx, 0);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	duk_push_int(ctx, ntohl(((int*)(buffer + offset))[0]));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Buffer_alloc(duk_context *ctx)
{
	int sz = duk_require_int(ctx, 0);
	int fill = 0;

	if (duk_is_number(ctx, 1)) { fill = duk_require_int(ctx, 1); }

	duk_push_fixed_buffer(ctx, sz);
	char *buffer = Duktape_GetBuffer(ctx, -1, NULL);
	memset(buffer, fill, sz);
	duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}

void ILibDuktape_Polyfills_Buffer(duk_context *ctx)
{
	char extras[] =
		"Object.defineProperty(Buffer.prototype, \"swap32\",\
	{\
		value: function swap32()\
		{\
			var a = this.readUInt16BE(0);\
			var b = this.readUInt16BE(2);\
			this.writeUInt16LE(a, 2);\
			this.writeUInt16LE(b, 0);\
			return(this);\
		}\
	});";

	duk_eval_string(ctx, extras); duk_pop(ctx);

	// Polyfill Buffer.from()
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_from, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "from");											// [g][Buffer]
	duk_pop(ctx);																	// [g]

	// Polyfill Buffer.alloc() for Node Buffers)
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_alloc, DUK_VARARGS);		// [g][Buffer][func]
	duk_put_prop_string(ctx, -2, "alloc");											// [g][Buffer]
	duk_pop(ctx);																	// [g]


	// Polyfill Buffer.toString() for Node Buffers
	duk_get_prop_string(ctx, -1, "Buffer");											// [g][Buffer]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Buffer][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_toString, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "toString");										// [g][Buffer][prototype]
	duk_pop_2(ctx);																	// [g]
}
duk_ret_t ILibDuktape_Polyfills_String_startsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if (ILibString_StartsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_endsWith(duk_context *ctx)
{
	duk_size_t tokenLen;
	char *token = Duktape_GetBuffer(ctx, 0, &tokenLen);
	char *buffer;
	duk_size_t bufferLen;

	duk_push_this(ctx);
	buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);
	
	if (ILibString_EndsWith(buffer, (int)bufferLen, token, (int)tokenLen) != 0)
	{
		duk_push_true(ctx);
	}
	else
	{
		duk_push_false(ctx);
	}

	return 1;
}
duk_ret_t ILibDuktape_Polyfills_String_padStart(duk_context *ctx)
{
	int totalLen = (int)duk_require_int(ctx, 0);

	duk_size_t padcharLen;
	duk_size_t bufferLen;

	char *padchars;
	if (duk_get_top(ctx) > 1)
	{
		padchars = (char*)duk_get_lstring(ctx, 1, &padcharLen);
	}
	else
	{
		padchars = " ";
		padcharLen = 1;
	}

	duk_push_this(ctx);
	char *buffer = Duktape_GetBuffer(ctx, -1, &bufferLen);

	if ((int)bufferLen > totalLen)
	{
		duk_push_lstring(ctx, buffer, bufferLen);
		return(1);
	}
	else
	{
		duk_size_t needs = totalLen - bufferLen;

		duk_push_array(ctx);											// [array]
		while(needs > 0)
		{
			if (needs > padcharLen)
			{
				duk_push_string(ctx, padchars);							// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs -= padcharLen;
			}
			else
			{
				duk_push_lstring(ctx, padchars, needs);					// [array][pad]
				duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));	// [array]
				needs = 0;
			}
		}
		duk_push_lstring(ctx, buffer, bufferLen);						// [array][pad]
		duk_put_prop_index(ctx, -2, (duk_uarridx_t)duk_get_length(ctx, -2));			// [array]
		duk_get_prop_string(ctx, -1, "join");							// [array][join]
		duk_swap_top(ctx, -2);											// [join][this]
		duk_push_string(ctx, "");										// [join][this]['']
		duk_call_method(ctx, 1);										// [result]
		return(1);
	}
}
void ILibDuktape_Polyfills_String(duk_context *ctx)
{
	// Polyfill 'String.startsWith'
	duk_get_prop_string(ctx, -1, "String");											// [string]
	duk_get_prop_string(ctx, -1, "prototype");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_startsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "startsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_endsWith, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "endsWith");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_padStart, DUK_VARARGS);				// [string][proto][func]
	duk_put_prop_string(ctx, -2, "padStart");
	duk_pop_2(ctx);
}
duk_ret_t ILibDuktape_Polyfills_Console_log(duk_context *ctx)
{
	int numargs = duk_get_top(ctx);
	int i, x;
	int len = 0;
	duk_size_t strLen;
	char *str;
	char *PREFIX = NULL;
	char *DESTINATION = NULL;
	duk_push_current_function(ctx);
	ILibDuktape_LogTypes logType = (ILibDuktape_LogTypes)Duktape_GetIntPropertyValue(ctx, -1, "logType", ILibDuktape_LogType_Normal);
	switch (logType)
	{
		case ILibDuktape_LogType_Warn:
			PREFIX = (char*)"WARNING: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_WARN_Destination;
			break;
		case ILibDuktape_LogType_Error:
			PREFIX = (char*)"ERROR: "; // LENGTH MUST BE <= 9
			DESTINATION = ILibDuktape_Console_ERROR_Destination;
			break;
		case ILibDuktape_LogType_Info1:
		case ILibDuktape_LogType_Info2:
		case ILibDuktape_LogType_Info3:
			duk_push_this(ctx);
			i = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_Console_INFO_Level, 0);
			duk_pop(ctx);
			PREFIX = NULL;
			if (i >= (((int)logType + 1) - (int)ILibDuktape_LogType_Info1))
			{
				DESTINATION = ILibDuktape_Console_LOG_Destination;
			}
			else
			{
				return(0);
			}
			break;
		default:
			PREFIX = NULL;
			DESTINATION = ILibDuktape_Console_LOG_Destination;
			break;
	}
	duk_pop(ctx);

	// Calculate total length of string
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			len += (i == 0 ? 0 : 2);
			duk_get_lstring(ctx, i, &strLen);
			len += (int)strLen;
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				len += (i == 0 ? 1 : 3);
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					len += 2;
					len += (propNum++ == 0 ? 1 : 2);
					duk_to_lstring(ctx, -2, &strLen); len += (int)strLen;
					duk_to_lstring(ctx, -1, &strLen); len += (int)strLen;
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				len += 2;
			}
			else
			{
				len += (i == 0 ? 0 : 2);
				duk_get_lstring(ctx, -1, &strLen); len += (int)strLen;
			}
		}
	}
	len += 2; // NULL Terminator and final carriage return
	strLen = len;

	str = ILibMemory_AllocateA(strLen + ((PREFIX != NULL) ? strnlen_s(PREFIX, 9) : 0));
	x = (int)(ILibMemory_AllocateA_Size(str) - strLen);
	if (x != 0)
	{
		strLen += sprintf_s(str, strLen, PREFIX);
	}
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				x += sprintf_s(str+x, strLen - x, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					x += sprintf_s(str + x, strLen - x, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				x += sprintf_s(str + x, strLen - x, " }");
			}
			else
			{
				x += sprintf_s(str + x, strLen - x, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	x += sprintf_s(str + x, strLen - x, "\n");

	duk_push_this(ctx);		// [console]
	int dest = Duktape_GetIntPropertyValue(ctx, -1, DESTINATION, ILibDuktape_Console_DestinationFlags_StdOut);

	if ((dest & ILibDuktape_Console_DestinationFlags_StdOut) == ILibDuktape_Console_DestinationFlags_StdOut)
	{
#ifdef WIN32
		DWORD writeLen;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (void*)str, x, &writeLen, NULL);
#else
		ignore_result(write(STDOUT_FILENO, str, x));
#endif
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_WebLog) == ILibDuktape_Console_DestinationFlags_WebLog)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(Duktape_GetChain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "%s", str);
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		if (duk_peval_string(ctx, "require('MeshAgent');") == 0)
		{
			duk_get_prop_string(ctx, -1, "SendCommand");	// [console][agent][SendCommand]
			duk_swap_top(ctx, -2);							// [console][SendCommand][this]
			duk_push_object(ctx);							// [console][SendCommand][this][options]
			duk_push_string(ctx, "msg"); duk_put_prop_string(ctx, -2, "action");
			duk_push_string(ctx, "console"); duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, str); duk_put_prop_string(ctx, -2, "value");
			if (duk_has_prop_string(ctx, -4, ILibDuktape_Console_SessionID))
			{
				duk_get_prop_string(ctx, -4, ILibDuktape_Console_SessionID);
				duk_put_prop_string(ctx, -2, "sessionid");
			}
			duk_call_method(ctx, 1);
		}
	}
	if ((dest & ILibDuktape_Console_DestinationFlags_LogFile) == ILibDuktape_Console_DestinationFlags_LogFile)
	{
		duk_size_t pathLen;
		char *path;
		char *tmp = ILibMemory_AllocateA(x + 32);
		int tmpx = ILibGetLocalTime(tmp + 1, (int)ILibMemory_AllocateA_Size(tmp) - 1) + 1;
		tmp[0] = '[';
		tmp[tmpx] = ']';
		tmp[tmpx + 1] = ':';
		tmp[tmpx + 2] = ' ';
		memcpy_s(tmp + tmpx + 3, ILibMemory_AllocateA_Size(tmp) - tmpx - 3, str, x);
		duk_eval_string(ctx, "require('fs');");
		duk_get_prop_string(ctx, -1, "writeFileSync");						// [fs][writeFileSync]
		duk_swap_top(ctx, -2);												// [writeFileSync][this]
		duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));			// [writeFileSync][this][process]
		duk_get_prop_string(ctx, -1, "execPath");							// [writeFileSync][this][process][execPath]
		path = (char*)duk_get_lstring(ctx, -1, &pathLen);
		if (path != NULL)
		{
			if (ILibString_EndsWithEx(path, (int)pathLen, ".exe", 4, 0))
			{
				duk_get_prop_string(ctx, -1, "substring");						// [writeFileSync][this][process][execPath][substring]
				duk_swap_top(ctx, -2);											// [writeFileSync][this][process][substring][this]
				duk_push_int(ctx, 0);											// [writeFileSync][this][process][substring][this][0]
				duk_push_int(ctx, (int)(pathLen - 4));							// [writeFileSync][this][process][substring][this][0][len]
				duk_call_method(ctx, 2);										// [writeFileSync][this][process][path]
			}
			duk_get_prop_string(ctx, -1, "concat");								// [writeFileSync][this][process][path][concat]
			duk_swap_top(ctx, -2);												// [writeFileSync][this][process][concat][this]
			duk_push_string(ctx, ".jlog");										// [writeFileSync][this][process][concat][this][.jlog]
			duk_call_method(ctx, 1);											// [writeFileSync][this][process][logPath]
			duk_remove(ctx, -2);												// [writeFileSync][this][logPath]
			duk_push_string(ctx, tmp);											// [writeFileSync][this][logPath][log]
			duk_push_object(ctx);												// [writeFileSync][this][logPath][log][options]
			duk_push_string(ctx, "a"); duk_put_prop_string(ctx, -2, "flags");
			duk_call_method(ctx, 3);
		}
	}
	return 0;
}
duk_ret_t ILibDuktape_Polyfills_Console_enableWebLog(duk_context *ctx)
{
#ifdef _REMOTELOGGING
	void *chain = Duktape_GetChain(ctx);
	int port = duk_require_int(ctx, 0);
	duk_size_t pLen;
	if (duk_peval_string(ctx, "process.argv0") != 0) { return(ILibDuktape_Error(ctx, "console.enableWebLog(): Couldn't fetch argv0")); }
	char *p = (char*)duk_get_lstring(ctx, -1, &pLen);
	if (ILibString_EndsWith(p, (int)pLen, ".js", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 3);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 3, ".wlg");
	}
	else if (ILibString_EndsWith(p, (int)pLen, ".exe", 3) != 0)
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), p, pLen - 4);
		sprintf_s(ILibScratchPad2 + (pLen - 3), sizeof(ILibScratchPad2) - 4, ".wlg");
	}
	else
	{
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s.wlg", p);
	}
	ILibStartDefaultLoggerEx(chain, (unsigned short)port, ILibScratchPad2);
#endif
	return (0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayStreamPipeMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayStreamPipe_setter(duk_context *ctx)
{
	g_displayStreamPipeMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_getter(duk_context *ctx)
{
	duk_push_int(ctx, g_displayFinalizerMessages);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_displayFinalizer_setter(duk_context *ctx)
{
	g_displayFinalizerMessages = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_logRefCount(duk_context *ctx)
{
	printf("Reference Count => %s[%p]:%d\n", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "UNKNOWN"), duk_require_heapptr(ctx, 0), ILibDuktape_GetReferenceCount(ctx, 0) - 1);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setDestination(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int dest = duk_require_int(ctx, 0);

	duk_push_this(ctx);						// console
	if ((dest & ILibDuktape_Console_DestinationFlags_ServerConsole) == ILibDuktape_Console_DestinationFlags_ServerConsole)
	{
		// Mesh Server Console
		if (duk_peval_string(ctx, "require('MeshAgent');") != 0) { return(ILibDuktape_Error(ctx, "Unable to set destination to Mesh Console ")); }
		duk_pop(ctx);
		if (nargs > 1)
		{
			duk_dup(ctx, 1);
			duk_put_prop_string(ctx, -2, ILibDuktape_Console_SessionID);
		}
		else
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_Console_SessionID);
		}
	}
	duk_dup(ctx, 0);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_Destination);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoLevel(duk_context *ctx)
{
	int val = duk_require_int(ctx, 0);
	if (val < 0) { return(ILibDuktape_Error(ctx, "Invalid Info Level: %d", val)); }

	duk_push_this(ctx);
	duk_push_int(ctx, val);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	return(0);
}
void ILibDuktape_Polyfills_Console(duk_context *ctx)
{
	// Polyfill console.log()
#ifdef WIN32
	SetConsoleOutputCP(CP_UTF8);
#endif

	if (duk_has_prop_string(ctx, -1, "console"))
	{
		duk_get_prop_string(ctx, -1, "console");									// [g][console]
	}
	else
	{
		duk_push_object(ctx);														// [g][console]
		duk_dup(ctx, -1);															// [g][console][console]
		duk_put_prop_string(ctx, -3, "console");									// [g][console]
	}

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Normal, "log", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Warn, "warn", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Error, "error", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info1, "info1", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info2, "info2", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "logType", (int)ILibDuktape_LogType_Info3, "info3", ILibDuktape_Polyfills_Console_log, DUK_VARARGS);


	ILibDuktape_CreateInstanceMethod(ctx, "enableWebLog", ILibDuktape_Polyfills_Console_enableWebLog, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayStreamPipeMessages", ILibDuktape_Polyfills_Console_displayStreamPipe_getter, ILibDuktape_Polyfills_Console_displayStreamPipe_setter);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "displayFinalizerMessages", ILibDuktape_Polyfills_Console_displayFinalizer_getter, ILibDuktape_Polyfills_Console_displayFinalizer_setter);
	ILibDuktape_CreateInstanceMethod(ctx, "logReferenceCount", ILibDuktape_Polyfills_Console_logRefCount, 1);
	
	ILibDuktape_CreateInstanceMethod(ctx, "setDestination", ILibDuktape_Polyfills_Console_setDestination, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoLevel", ILibDuktape_Polyfills_Console_setInfoLevel, 1);

	duk_push_object(ctx);
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_DISABLED); duk_put_prop_string(ctx, -2, "DISABLED");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut); duk_put_prop_string(ctx, -2, "STDOUT");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_ServerConsole); duk_put_prop_string(ctx, -2, "SERVERCONSOLE");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_WebLog); duk_put_prop_string(ctx, -2, "WEBLOG");
	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_LogFile); duk_put_prop_string(ctx, -2, "LOGFILE");
	ILibDuktape_CreateReadonlyProperty(ctx, "Destinations");

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_ERROR_Destination);

	duk_push_int(ctx, ILibDuktape_Console_DestinationFlags_StdOut | ILibDuktape_Console_DestinationFlags_LogFile);
	duk_put_prop_string(ctx, -2, ILibDuktape_Console_WARN_Destination);

	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_Console_INFO_Level);

	duk_pop(ctx);																	// [g]
}
duk_ret_t ILibDuktape_ntohl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohl(((unsigned int*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_ntohs(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < 2 + offset) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohs(((unsigned short*)(buffer + offset))[0]));
	return 1;
}
duk_ret_t ILibDuktape_htonl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned int*)(buffer + offset))[0] = htonl(val);
	return 0;
}
duk_ret_t ILibDuktape_htons(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (2 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	((unsigned short*)(buffer + offset))[0] = htons(val);
	return 0;
}
void ILibDuktape_Polyfills_byte_ordering(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethod(ctx, "ntohl", ILibDuktape_ntohl, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "ntohs", ILibDuktape_ntohs, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "htonl", ILibDuktape_htonl, 3);
	ILibDuktape_CreateInstanceMethod(ctx, "htons", ILibDuktape_htons, 3);
}

typedef enum ILibDuktape_Timer_Type
{
	ILibDuktape_Timer_Type_TIMEOUT = 0,
	ILibDuktape_Timer_Type_INTERVAL = 1,
	ILibDuktape_Timer_Type_IMMEDIATE = 2
}ILibDuktape_Timer_Type;
typedef struct ILibDuktape_Timer
{
	duk_context *ctx;
	void *object;
	void *callback;
	void *args;
	int timeout;
	ILibDuktape_Timer_Type timerType;
}ILibDuktape_Timer;

duk_ret_t ILibDuktape_Polyfills_timer_finalizer(duk_context *ctx)
{
	// Make sure we remove any timers just in case, so we don't leak resources
	ILibDuktape_Timer *ptrs;
	if (duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs))
	{
		duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
		if (duk_has_prop_string(ctx, 0, "\xFF_callback"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_callback");
		}
		if (duk_has_prop_string(ctx, 0, "\xFF_argArray"))
		{
			duk_del_prop_string(ctx, 0, "\xFF_argArray");
		}
		ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

		ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	}
	return 0;
}
void ILibDuktape_Polyfills_timer_elapsed(void *obj)
{
	ILibDuktape_Timer *ptrs = (ILibDuktape_Timer*)obj;
	int argCount, i;
	duk_context *ctx = ptrs->ctx;
	char *funcName;

	if (!ILibMemory_CanaryOK(ptrs)) { return; }
	if (duk_check_stack(ctx, 3) == 0) { return; }

	duk_push_heapptr(ctx, ptrs->callback);				// [func]
	funcName = Duktape_GetStringPropertyValue(ctx, -1, "name", "unknown_method");
	duk_push_heapptr(ctx, ptrs->object);				// [func][this]
	duk_push_heapptr(ctx, ptrs->args);					// [func][this][argArray]

	if (ptrs->timerType == ILibDuktape_Timer_Type_INTERVAL)
	{
		ILibLifeTime_AddEx(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL);
	}
	else
	{
		if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
		{
			duk_push_heap_stash(ctx);
			duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
			duk_pop(ctx);
		}

		duk_del_prop_string(ctx, -2, "\xFF_callback");
		duk_del_prop_string(ctx, -2, "\xFF_argArray");
		duk_del_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);
	}

	argCount = (int)duk_get_length(ctx, -1);
	for (i = 0; i < argCount; ++i)
	{
		duk_get_prop_index(ctx, -1, i);					// [func][this][argArray][arg]
		duk_swap_top(ctx, -2);							// [func][this][arg][argArray]
	}
	duk_pop(ctx);										// [func][this][...arg...]
	if (duk_pcall_method(ctx, argCount) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "timers.onElapsed() callback handler on '%s()' ", funcName); }
	duk_pop(ctx);										// ...
}
duk_ret_t ILibDuktape_Polyfills_timer_set(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	void *chain = Duktape_GetChain(ctx);
	int argx;

	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	duk_push_object(ctx);																	//[retVal]
	switch (timerType)
	{
	case ILibDuktape_Timer_Type_IMMEDIATE:
		ILibDuktape_WriteID(ctx, "Timers.immediate");										
		// We're only saving a reference for immediates
		duk_push_heap_stash(ctx);															//[retVal][stash]
		duk_dup(ctx, -2);																	//[retVal][stash][immediate]
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		//[retVal][stash]
		duk_pop(ctx);																		//[retVal]
		break;
	case ILibDuktape_Timer_Type_INTERVAL:
		ILibDuktape_WriteID(ctx, "Timers.interval");
		break;
	case ILibDuktape_Timer_Type_TIMEOUT:
		ILibDuktape_WriteID(ctx, "Timers.timeout");
		break;
	}
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Polyfills_timer_finalizer);
	
	ptrs = (ILibDuktape_Timer*)Duktape_PushBuffer(ctx, sizeof(ILibDuktape_Timer));	//[retVal][ptrs]
	duk_put_prop_string(ctx, -2, ILibDuktape_Timer_Ptrs);							//[retVal]

	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
	ptrs->timerType = timerType;
	ptrs->timeout = timerType == ILibDuktape_Timer_Type_IMMEDIATE ? 0 : (int)duk_require_int(ctx, 1);
	ptrs->callback = duk_require_heapptr(ctx, 0);

	duk_push_array(ctx);																			//[retVal][argArray]
	for (argx = ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2; argx < nargs; ++argx)
	{
		duk_dup(ctx, argx);																			//[retVal][argArray][arg]
		duk_put_prop_index(ctx, -2, argx - (ILibDuktape_Timer_Type_IMMEDIATE == timerType ? 1 : 2));//[retVal][argArray]
	}
	ptrs->args = duk_get_heapptr(ctx, -1);															//[retVal]
	duk_put_prop_string(ctx, -2, "\xFF_argArray");

	duk_dup(ctx, 0);																				//[retVal][callback]
	duk_put_prop_string(ctx, -2, "\xFF_callback");													//[retVal]

	ILibLifeTime_AddEx(ILibGetBaseTimer(chain), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL);
	return 1;
}
duk_ret_t ILibDuktape_Polyfills_timer_clear(duk_context *ctx)
{
	ILibDuktape_Timer *ptrs;
	ILibDuktape_Timer_Type timerType;
	
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "type");
	timerType = (ILibDuktape_Timer_Type)duk_get_int(ctx, -1);

	if(!duk_has_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs)) 
	{
		switch (timerType)
		{
			case ILibDuktape_Timer_Type_TIMEOUT:
				return(ILibDuktape_Error(ctx, "timers.clearTimeout(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_INTERVAL:
				return(ILibDuktape_Error(ctx, "timers.clearInterval(): Invalid Parameter"));
			case ILibDuktape_Timer_Type_IMMEDIATE:
				return(ILibDuktape_Error(ctx, "timers.clearImmediate(): Invalid Parameter"));
		}
	}

	duk_get_prop_string(ctx, 0, ILibDuktape_Timer_Ptrs);
	ptrs = (ILibDuktape_Timer*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->timerType == ILibDuktape_Timer_Type_IMMEDIATE)
	{
		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
		duk_pop(ctx);
	}

	ILibLifeTime_Remove(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs);
	return 0;
}
void ILibDuktape_Polyfills_timer(duk_context *ctx)
{
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "setTimeout", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "setInterval", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "setImmediate", ILibDuktape_Polyfills_timer_set, DUK_VARARGS);

	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_TIMEOUT, "clearTimeout", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_INTERVAL, "clearInterval", ILibDuktape_Polyfills_timer_clear, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "type", ILibDuktape_Timer_Type_IMMEDIATE, "clearImmediate", ILibDuktape_Polyfills_timer_clear, 1);
}
duk_ret_t ILibDuktape_Polyfills_getJSModule(duk_context *ctx)
{
	if (ILibDuktape_ModSearch_GetJSModule(ctx, (char*)duk_require_string(ctx, 0)) == 0)
	{
		return(ILibDuktape_Error(ctx, "getJSModule(): (%s) not found", (char*)duk_require_string(ctx, 0)));
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_addModule(duk_context *ctx)
{
	duk_size_t moduleLen;
	char *module = (char*)Duktape_GetBuffer(ctx, 1, &moduleLen);
	char *moduleName = (char*)duk_require_string(ctx, 0);

	if (ILibDuktape_ModSearch_AddModule(ctx, moduleName, module, (int)moduleLen) != 0)
	{
		return(ILibDuktape_Error(ctx, "Cannot add module: %s", moduleName));
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addModuleObject(duk_context *ctx)
{
	void *module = duk_require_heapptr(ctx, 1);
	char *moduleName = (char*)duk_require_string(ctx, 0);

	ILibDuktape_ModSearch_AddModuleObject(ctx, moduleName, module);
	return(0);
}
duk_ret_t ILibDuktape_Queue_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, ILibDuktape_Queue_Ptr);
	ILibQueue_Destroy((ILibQueue)duk_get_pointer(ctx, -1));
	return(0);
}
duk_ret_t ILibDuktape_Queue_EnQueue(duk_context *ctx)
{
	ILibQueue Q;
	int i;
	int nargs = duk_get_top(ctx);
	duk_push_this(ctx);																// [queue]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);							// [queue][ptr]
	Q = (ILibQueue)duk_get_pointer(ctx, -1);
	duk_pop(ctx);																	// [queue]

	ILibDuktape_Push_ObjectStash(ctx);												// [queue][stash]
	duk_push_array(ctx);															// [queue][stash][array]
	for (i = 0; i < nargs; ++i)
	{
		duk_dup(ctx, i);															// [queue][stash][array][arg]
		duk_put_prop_index(ctx, -2, i);												// [queue][stash][array]
	}
	ILibQueue_EnQueue(Q, duk_get_heapptr(ctx, -1));
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));	// [queue][stash]
	return(0);
}
duk_ret_t ILibDuktape_Queue_DeQueue(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_get_prop_string(ctx, -1, "peek");
	int peek = duk_get_int(ctx, -1);

	duk_push_this(ctx);										// [Q]
	duk_get_prop_string(ctx, -1, ILibDuktape_Queue_Ptr);	// [Q][ptr]
	ILibQueue Q = (ILibQueue)duk_get_pointer(ctx, -1);
	void *h = peek == 0 ? ILibQueue_DeQueue(Q) : ILibQueue_PeekQueue(Q);
	if (h == NULL) { return(ILibDuktape_Error(ctx, "Queue is empty")); }
	duk_pop(ctx);											// [Q]
	ILibDuktape_Push_ObjectStash(ctx);						// [Q][stash]
	duk_push_heapptr(ctx, h);								// [Q][stash][array]
	int length = (int)duk_get_length(ctx, -1);
	int i;
	for (i = 0; i < length; ++i)
	{
		duk_get_prop_index(ctx, -i - 1, i);				   // [Q][stash][array][args]
	}
	if (peek == 0) { duk_del_prop_string(ctx, -length - 2, Duktape_GetStashKey(h)); }
	return(length);
}
duk_ret_t ILibDuktape_Queue_isEmpty(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_boolean(ctx, ILibQueue_IsEmpty((ILibQueue)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Queue_Ptr)));
	return(1);
}
duk_ret_t ILibDuktape_Queue_new(duk_context *ctx)
{
	duk_push_object(ctx);									// [queue]
	duk_push_pointer(ctx, ILibQueue_Create());				// [queue][ptr]
	duk_put_prop_string(ctx, -2, ILibDuktape_Queue_Ptr);	// [queue]

	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_Queue_Finalizer);
	ILibDuktape_CreateInstanceMethod(ctx, "enQueue", ILibDuktape_Queue_EnQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 0, "deQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "peek", 1, "peekQueue", ILibDuktape_Queue_DeQueue, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "isEmpty", ILibDuktape_Queue_isEmpty, 0);

	return(1);
}
void ILibDuktape_Queue_Push(duk_context *ctx, void* chain)
{
	duk_push_c_function(ctx, ILibDuktape_Queue_new, 0);
}

typedef struct ILibDuktape_DynamicBuffer_data
{
	int start;
	int end;
	int unshiftBytes;
	char *buffer;
	int bufferLen;
}ILibDuktape_DynamicBuffer_data;

typedef struct ILibDuktape_DynamicBuffer_ContextSwitchData
{
	void *chain;
	void *heapptr;
	ILibDuktape_DuplexStream *stream;
	ILibDuktape_DynamicBuffer_data *data;
	int bufferLen;
	char buffer[];
}ILibDuktape_DynamicBuffer_ContextSwitchData;

ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user);
void ILibDuktape_DynamicBuffer_WriteSink_ChainThread(void *chain, void *user)
{
	ILibDuktape_DynamicBuffer_ContextSwitchData *data = (ILibDuktape_DynamicBuffer_ContextSwitchData*)user;
	if(ILibMemory_CanaryOK(data->stream))
	{
		ILibDuktape_DynamicBuffer_WriteSink(data->stream, data->buffer, data->bufferLen, data->data);
		ILibDuktape_DuplexStream_Ready(data->stream);
	}
	free(user);
}
ILibTransport_DoneState ILibDuktape_DynamicBuffer_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	if (ILibIsRunningOnChainThread(stream->readableStream->chain) == 0)
	{
		ILibDuktape_DynamicBuffer_ContextSwitchData *tmp = (ILibDuktape_DynamicBuffer_ContextSwitchData*)ILibMemory_Allocate(sizeof(ILibDuktape_DynamicBuffer_ContextSwitchData) + bufferLen, 0, NULL, NULL);
		tmp->chain = stream->readableStream->chain;
		tmp->heapptr = stream->ParentObject;
		tmp->stream = stream;
		tmp->data = data;
		tmp->bufferLen = bufferLen;
		memcpy_s(tmp->buffer, bufferLen, buffer, bufferLen);
		ILibChain_RunOnMicrostackThread(tmp->chain, ILibDuktape_DynamicBuffer_WriteSink_ChainThread, tmp);
		return(ILibTransport_DoneState_INCOMPLETE);
	}


	if ((data->bufferLen - data->start - data->end) < bufferLen)
	{
		if (data->end > 0)
		{
			// Move the buffer first
			memmove_s(data->buffer, data->bufferLen, data->buffer + data->start, data->end);
			data->start = 0;
		}
		if ((data->bufferLen - data->end) < bufferLen)
		{
			// Need to resize buffer first
			int tmpSize = data->bufferLen;
			while ((tmpSize - data->end) < bufferLen)
			{
				tmpSize += 4096;
			}
			if ((data->buffer = (char*)realloc(data->buffer, tmpSize)) == NULL) { ILIBCRITICALEXIT(254); }
			data->bufferLen = tmpSize;
		}
	}


	memcpy_s(data->buffer + data->start + data->end, data->bufferLen - data->start - data->end, buffer, bufferLen);
	data->end += bufferLen;

	int unshifted = 0;
	do
	{
		duk_push_heapptr(stream->readableStream->ctx, stream->ParentObject);		// [ds]
		duk_get_prop_string(stream->readableStream->ctx, -1, "emit");				// [ds][emit]
		duk_swap_top(stream->readableStream->ctx, -2);								// [emit][this]
		duk_push_string(stream->readableStream->ctx, "readable");					// [emit][this][readable]
		if (duk_pcall_method(stream->readableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->readableStream->ctx, "DynamicBuffer.WriteSink => readable(): "); }
		duk_pop(stream->readableStream->ctx);										// ...

		ILibDuktape_DuplexStream_WriteData(stream, data->buffer + data->start, data->end);
		if (data->unshiftBytes == 0)
		{
			// All the data was consumed
			data->start = data->end = 0;
		}
		else
		{
			unshifted = (data->end - data->unshiftBytes);
			if (unshifted > 0)
			{
				data->start += unshifted;
				data->end = data->unshiftBytes;
				data->unshiftBytes = 0;
			}
		}
	} while (unshifted != 0);

	return(ILibTransport_DoneState_COMPLETE);
}
void ILibDuktape_DynamicBuffer_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_DuplexStream_WriteEnd(stream);
}
duk_ret_t ILibDuktape_DynamicBuffer_Finalizer(duk_context *ctx)
{
	duk_get_prop_string(ctx, 0, "\xFF_buffer");
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	free(data->buffer);
	return(0);
}

int ILibDuktape_DynamicBuffer_unshift(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	ILibDuktape_DynamicBuffer_data *data = (ILibDuktape_DynamicBuffer_data*)user;
	data->unshiftBytes = unshiftBytes;
	return(unshiftBytes);
}
duk_ret_t ILibDuktape_DynamicBuffer_read(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	duk_push_this(ctx);															// [DynamicBuffer]
	duk_get_prop_string(ctx, -1, "\xFF_buffer");								// [DynamicBuffer][buffer]
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_push_external_buffer(ctx);												// [DynamicBuffer][buffer][extBuffer]
	duk_config_buffer(ctx, -1, data->buffer + data->start, data->bufferLen - (data->start + data->end));
	duk_push_buffer_object(ctx, -1, 0, data->bufferLen - (data->start + data->end), DUK_BUFOBJ_NODEJS_BUFFER);
	return(1);
}
duk_ret_t ILibDuktape_DynamicBuffer_new(duk_context *ctx)
{
	ILibDuktape_DynamicBuffer_data *data;
	int initSize = 4096;
	if (duk_get_top(ctx) != 0)
	{
		initSize = duk_require_int(ctx, 0);
	}

	duk_push_object(ctx);					// [stream]
	duk_push_fixed_buffer(ctx, sizeof(ILibDuktape_DynamicBuffer_data));
	data = (ILibDuktape_DynamicBuffer_data*)Duktape_GetBuffer(ctx, -1, NULL);
	memset(data, 0, sizeof(ILibDuktape_DynamicBuffer_data));
	duk_put_prop_string(ctx, -2, "\xFF_buffer");

	data->bufferLen = initSize;
	data->buffer = (char*)malloc(initSize);

	ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_DynamicBuffer_WriteSink, ILibDuktape_DynamicBuffer_EndSink, NULL, NULL, ILibDuktape_DynamicBuffer_unshift, data);
	ILibDuktape_EventEmitter_CreateEventEx(ILibDuktape_EventEmitter_GetEmitter(ctx, -1), "readable");
	ILibDuktape_CreateInstanceMethod(ctx, "read", ILibDuktape_DynamicBuffer_read, DUK_VARARGS);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DynamicBuffer_Finalizer);

	return(1);
}

void ILibDuktape_DynamicBuffer_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_DynamicBuffer_new, DUK_VARARGS);
}

duk_ret_t ILibDuktape_Polyfills_debugCrash(duk_context *ctx)
{
	void *p = NULL;
	((int*)p)[0] = 55;
	return(0);
}


void ILibDuktape_Stream_PauseSink(struct ILibDuktape_readableStream *sender, void *user)
{
}
void ILibDuktape_Stream_ResumeSink(struct ILibDuktape_readableStream *sender, void *user)
{
	int skip = 0;
	duk_size_t bufferLen;

	duk_push_heapptr(sender->ctx, sender->object);			// [stream]
	void *func = Duktape_GetHeapptrProperty(sender->ctx, -1, "_read");
	duk_pop(sender->ctx);									// ...

	while (func != NULL && sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);									// [this]
		if (!skip && duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
		{
			duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);			// [this][buffer]
			if ((bufferLen = duk_get_length(sender->ctx, -1)) > 0)
			{
				// Buffer is not empty, so we need to 'PUSH' it
				duk_get_prop_string(sender->ctx, -2, "push");							// [this][buffer][push]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this]
				duk_dup(sender->ctx, -3);												// [this][buffer][push][this][buffer]
				duk_remove(sender->ctx, -4);											// [this][push][this][buffer]
				duk_call_method(sender->ctx, 1);										// [this][boolean]
				sender->paused = !duk_get_boolean(sender->ctx, -1);
				duk_pop(sender->ctx);													// [this]

				if (duk_has_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer))
				{
					duk_get_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);	// [this][buffer]
					if (duk_get_length(sender->ctx, -1) == bufferLen)
					{
						// All the data was unshifted
						skip = !sender->paused;					
					}
					duk_pop(sender->ctx);												// [this]
				}
				duk_pop(sender->ctx);													// ...
			}
			else
			{
				// Buffer is empty
				duk_pop(sender->ctx);													// [this]
				duk_del_prop_string(sender->ctx, -1, ILibDuktape_Stream_Buffer);
				duk_pop(sender->ctx);													// ...
			}
		}
		else
		{
			// We need to 'read' more data
			duk_push_heapptr(sender->ctx, func);										// [this][read]
			duk_swap_top(sender->ctx, -2);												// [read][this]
			if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtException(sender->ctx); duk_pop(sender->ctx); break; }
			//																			// [buffer]
			duk_push_heapptr(sender->ctx, sender->object);								// [buffer][this]
			duk_swap_top(sender->ctx, -2);												// [this][buffer]
			if (duk_has_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer))
			{
				duk_push_global_object(sender->ctx);									// [this][buffer][g]
				duk_get_prop_string(sender->ctx, -1, "Buffer");							// [this][buffer][g][Buffer]
				duk_remove(sender->ctx, -2);											// [this][buffer][Buffer]
				duk_get_prop_string(sender->ctx, -1, "concat");							// [this][buffer][Buffer][concat]
				duk_swap_top(sender->ctx, -2);											// [this][buffer][concat][this]
				duk_push_array(sender->ctx);											// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_get_prop_string(sender->ctx, -7, ILibDuktape_Stream_Buffer);		// [this][buffer][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][buffer][concat][this][Array]
				duk_get_prop_string(sender->ctx, -1, "push");							// [this][buffer][concat][this][Array][push]
				duk_dup(sender->ctx, -2);												// [this][buffer][concat][this][Array][push][this]
				duk_dup(sender->ctx, -6);												// [this][buffer][concat][this][Array][push][this][buffer]
				duk_remove(sender->ctx, -7);											// [this][concat][this][Array][push][this][buffer]
				duk_call_method(sender->ctx, 1); duk_pop(sender->ctx);					// [this][concat][this][Array]
				duk_call_method(sender->ctx, 1);										// [this][buffer]
			}
			duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);			// [this]
			duk_pop(sender->ctx);														// ...
			skip = 0;
		}
	}
}
int ILibDuktape_Stream_UnshiftSink(struct ILibDuktape_readableStream *sender, int unshiftBytes, void *user)
{
	duk_push_fixed_buffer(sender->ctx, unshiftBytes);									// [buffer]
	memcpy_s(Duktape_GetBuffer(sender->ctx, -1, NULL), unshiftBytes, sender->unshiftReserved, unshiftBytes);
	duk_push_heapptr(sender->ctx, sender->object);										// [buffer][stream]
	duk_push_buffer_object(sender->ctx, -2, 0, unshiftBytes, DUK_BUFOBJ_NODEJS_BUFFER);	// [buffer][stream][buffer]
	duk_put_prop_string(sender->ctx, -2, ILibDuktape_Stream_Buffer);					// [buffer][stream]
	duk_pop_2(sender->ctx);																// ...

	return(unshiftBytes);
}
duk_ret_t ILibDuktape_Stream_Push(duk_context *ctx)
{
	duk_push_this(ctx);																					// [stream]
	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	duk_push_boolean(ctx, !ILibDuktape_readableStream_WriteDataEx(RS, 0, buffer, (int)bufferLen));		// [stream][buffer][retVal]
	return(1);
}
duk_ret_t ILibDuktape_Stream_EndSink(duk_context *ctx)
{
	duk_push_this(ctx);												// [stream]
	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_readableStream_WriteEnd(RS);
	return(0);
}
duk_idx_t ILibDuktape_Stream_newReadable(duk_context *ctx)
{
	ILibDuktape_readableStream *RS;
	duk_push_object(ctx);							// [Readable]
	ILibDuktape_WriteID(ctx, "stream.readable");
	RS = ILibDuktape_ReadableStream_InitEx(ctx, ILibDuktape_Stream_PauseSink, ILibDuktape_Stream_ResumeSink, ILibDuktape_Stream_UnshiftSink, NULL);
	RS->paused = 1;

	duk_push_pointer(ctx, RS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_Writable_WriteSink_Flush(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibTransport_DoneState *retVal = (ILibTransport_DoneState*)Duktape_GetPointerProperty(ctx, -1, "retval");
	if (retVal != NULL)
	{
		*retVal = ILibTransport_DoneState_COMPLETE;
	}
	else
	{
		ILibDuktape_WritableStream *WS = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_WritablePtr);
		ILibDuktape_WritableStream_Ready(WS);
	}
	return(0);
}
ILibTransport_DoneState ILibDuktape_Stream_Writable_WriteSink(struct ILibDuktape_WritableStream *stream, char *buffer, int bufferLen, void *user)
{
	void *h;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_INCOMPLETE;

	duk_push_this(stream->ctx);																		// [writable]
	duk_get_prop_string(stream->ctx, -1, "_write");													// [writable][_write]
	duk_swap_top(stream->ctx, -2);																	// [_write][this]
	if (stream->Reserved == 0)
	{
		duk_push_external_buffer(stream->ctx);														// [_write][this][extBuffer]
		duk_insert(stream->ctx, -3);																// [extBuffer][_write][this]
		duk_config_buffer(stream->ctx, -3, buffer, (duk_size_t)bufferLen);
		duk_push_buffer_object(stream->ctx, -3, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [extBuffer][_write][this][buffer]
	}
	else
	{
		duk_push_lstring(stream->ctx, buffer, (duk_size_t)bufferLen);								// [_write][this][string]
	}
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_WriteSink_Flush, DUK_VARARGS);		// [_write][this][string/buffer][callback]
	h = duk_get_heapptr(stream->ctx, -1);
	duk_push_heap_stash(stream->ctx);																// [_write][this][string/buffer][callback][stash]
	duk_dup(stream->ctx, -2);																		// [_write][this][string/buffer][callback][stash][callback]
	duk_put_prop_string(stream->ctx, -2, Duktape_GetStashKey(h));									// [_write][this][string/buffer][callback][stash]
	duk_pop(stream->ctx);																			// [_write][this][string/buffer][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(stream->ctx, &retVal);															// [_write][this][string/buffer][callback][retval]
	duk_put_prop_string(stream->ctx, -2, "retval");													// [_write][this][string/buffer][callback]
	if (duk_pcall_method(stream->ctx, 2) != 0)
	{
		ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable.write(): "); retVal = ILibTransport_DoneState_ERROR;
	}
	else
	{
		retVal = duk_to_boolean(stream->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
	}
	duk_pop(stream->ctx);																			// ...

	duk_push_heapptr(stream->ctx, h);																// [callback]
	duk_del_prop_string(stream->ctx, -1, "retval");
	duk_pop(stream->ctx);																			// ...
	
	duk_push_heap_stash(stream->ctx);
	duk_del_prop_string(stream->ctx, -1, Duktape_GetStashKey(h));
	duk_pop(stream->ctx);

	return(retVal);
}
duk_ret_t ILibDuktape_Stream_Writable_EndSink_finish(duk_context *ctx)
{
	duk_push_current_function(ctx);
	ILibDuktape_WritableStream *ws = (ILibDuktape_WritableStream*)Duktape_GetPointerProperty(ctx, -1, "ptr");
	if (ILibMemory_CanaryOK(ws))
	{
		ILibDuktape_WritableStream_Finish(ws);
	}
	return(0);
}
void ILibDuktape_Stream_Writable_EndSink(struct ILibDuktape_WritableStream *stream, void *user)
{
	duk_push_this(stream->ctx);															// [writable]
	duk_get_prop_string(stream->ctx, -1, "_final");										// [writable][_final]
	duk_swap_top(stream->ctx, -2);														// [_final][this]
	duk_push_c_function(stream->ctx, ILibDuktape_Stream_Writable_EndSink_finish, 0);	// [_final][this][callback]
	duk_push_pointer(stream->ctx, stream); duk_put_prop_string(stream->ctx, -2, "ptr");
	if (duk_pcall_method(stream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->ctx, "stream.writable._final(): "); }
	duk_pop(stream->ctx);								// ...
}
duk_ret_t ILibDuktape_Stream_newWritable(duk_context *ctx)
{
	ILibDuktape_WritableStream *WS;
	duk_push_object(ctx);						// [Writable]
	ILibDuktape_WriteID(ctx, "stream.writable");
	WS = ILibDuktape_WritableStream_Init(ctx, ILibDuktape_Stream_Writable_WriteSink, ILibDuktape_Stream_Writable_EndSink, NULL);
	WS->JSCreated = 1;

	duk_push_pointer(ctx, WS);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
	}
	return(1);
}
void ILibDuktape_Stream_Duplex_PauseSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_PauseSink(stream->readableStream, user);
}
void ILibDuktape_Stream_Duplex_ResumeSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_ResumeSink(stream->readableStream, user);
}
int ILibDuktape_Stream_Duplex_UnshiftSink(ILibDuktape_DuplexStream *stream, int unshiftBytes, void *user)
{
	return(ILibDuktape_Stream_UnshiftSink(stream->readableStream, unshiftBytes, user));
}
ILibTransport_DoneState ILibDuktape_Stream_Duplex_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
	return(ILibDuktape_Stream_Writable_WriteSink(stream->writableStream, buffer, bufferLen, user));
}
void ILibDuktape_Stream_Duplex_EndSink(ILibDuktape_DuplexStream *stream, void *user)
{
	ILibDuktape_Stream_Writable_EndSink(stream->writableStream, user);
}
duk_ret_t ILibDuktape_Stream_newDuplex(duk_context *ctx)
{
	ILibDuktape_DuplexStream *DS;
	duk_push_object(ctx);						// [Duplex]
	ILibDuktape_WriteID(ctx, "stream.Duplex");
	DS = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_Stream_Duplex_WriteSink, ILibDuktape_Stream_Duplex_EndSink, ILibDuktape_Stream_Duplex_PauseSink, ILibDuktape_Stream_Duplex_ResumeSink, ILibDuktape_Stream_Duplex_UnshiftSink, NULL);
	DS->writableStream->JSCreated = 1;

	duk_push_pointer(ctx, DS->writableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_WritablePtr);

	duk_push_pointer(ctx, DS->readableStream);
	duk_put_prop_string(ctx, -2, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_CreateInstanceMethod(ctx, "push", ILibDuktape_Stream_Push, DUK_VARARGS);
	ILibDuktape_EventEmitter_AddOnceEx3(ctx, -1, "end", ILibDuktape_Stream_EndSink);

	if (duk_is_object(ctx, 0))
	{
		void *h = Duktape_GetHeapptrProperty(ctx, 0, "write");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_write"); }
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
		h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
	}
	return(1);
}
void ILibDuktape_Stream_Init(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);					// [stream
	ILibDuktape_WriteID(ctx, "stream");
	ILibDuktape_CreateInstanceMethod(ctx, "Readable", ILibDuktape_Stream_newReadable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Writable", ILibDuktape_Stream_newWritable, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Duplex", ILibDuktape_Stream_newDuplex, DUK_VARARGS);
}
void ILibDuktape_Polyfills_debugGC2(duk_context *ctx, void ** args, int argsLen)
{
	if (g_displayFinalizerMessages) { printf("=> GC();\n"); }
	duk_gc(ctx, 0);
	duk_gc(ctx, 0);
}
duk_ret_t ILibDuktape_Polyfills_debugGC(duk_context *ctx)
{
	ILibDuktape_Immediate(ctx, (void*[]) { NULL }, 0, ILibDuktape_Polyfills_debugGC2);
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_debug(duk_context *ctx)
{
#ifdef WIN32
	if (IsDebuggerPresent()) { __debugbreak(); }
#elif defined(_POSIX)
	raise(SIGTRAP);
#endif
	return(0);
}
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_PKCS7_getSignedDataBlock(duk_context *ctx)
{
	char *hash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	char *pkeyHash = ILibMemory_AllocateA(UTIL_SHA256_HASHSIZE);
	unsigned int size, r;
	BIO *out = NULL;
	PKCS7 *message = NULL;
	char* data2 = NULL;
	STACK_OF(X509) *st = NULL;

	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);

	message = d2i_PKCS7(NULL, (const unsigned char**)&buffer, (long)bufferLen);
	if (message == NULL) { return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	// Lets rebuild the original message and check the size
	size = i2d_PKCS7(message, NULL);
	if (size < (unsigned int)bufferLen) { PKCS7_free(message); return(ILibDuktape_Error(ctx, "PKCS7 Error")); }

	out = BIO_new(BIO_s_mem());

	// Check the PKCS7 signature, but not the certificate chain.
	r = PKCS7_verify(message, NULL, NULL, NULL, out, PKCS7_NOVERIFY);
	if (r == 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Verify Error")); }

	// If data block contains less than 32 bytes, fail.
	size = (unsigned int)BIO_get_mem_data(out, &data2);
	if (size <= ILibMemory_AllocateA_Size(hash)) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Size Mismatch Error")); }


	duk_push_object(ctx);												// [val]
	duk_push_fixed_buffer(ctx, size);									// [val][fbuffer]
	duk_dup(ctx, -1);													// [val][fbuffer][dup]
	duk_put_prop_string(ctx, -3, "\xFF_fixedbuffer");					// [val][fbuffer]
	duk_swap_top(ctx, -2);												// [fbuffer][val]
	duk_push_buffer_object(ctx, -2, 0, size, DUK_BUFOBJ_NODEJS_BUFFER); // [fbuffer][val][buffer]
	ILibDuktape_CreateReadonlyProperty(ctx, "data");					// [fbuffer][val]
	memcpy_s(Duktape_GetBuffer(ctx, -2, NULL), size, data2, size);


	// Get the certificate signer
	st = PKCS7_get0_signers(message, NULL, PKCS7_NOVERIFY);
	
	// Get a full certificate hash of the signer
	X509_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)hash, NULL);
	X509_pubkey_digest(sk_X509_value(st, 0), EVP_sha256(), (unsigned char*)pkeyHash, NULL); 

	sk_X509_free(st);
	
	// Check certificate hash with first 32 bytes of data.
	if (memcmp(hash, Duktape_GetBuffer(ctx, -2, NULL), ILibMemory_AllocateA_Size(hash)) != 0) { PKCS7_free(message); BIO_free(out); return(ILibDuktape_Error(ctx, "PKCS7 Certificate Hash Mismatch Error")); }
	char *tmp = ILibMemory_AllocateA(1 + (ILibMemory_AllocateA_Size(hash) * 2));
	util_tohex(hash, (int)ILibMemory_AllocateA_Size(hash), tmp);
	duk_push_object(ctx);												// [fbuffer][val][cert]
	ILibDuktape_WriteID(ctx, "certificate");
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][fingerprint]
	ILibDuktape_CreateReadonlyProperty(ctx, "fingerprint");				// [fbuffer][val][cert]
	util_tohex(pkeyHash, (int)ILibMemory_AllocateA_Size(pkeyHash), tmp);
	duk_push_string(ctx, tmp);											// [fbuffer][val][cert][publickeyhash]
	ILibDuktape_CreateReadonlyProperty(ctx, "publicKeyHash");			// [fbuffer][val][cert]

	ILibDuktape_CreateReadonlyProperty(ctx, "signingCertificate");		// [fbuffer][val]

	// Approved, cleanup and return.
	BIO_free(out);
	PKCS7_free(message);

	return(1);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlockFinalizer(duk_context *ctx)
{
	char *buffer = Duktape_GetPointerProperty(ctx, 0, "\xFF_signature");
	if (buffer != NULL) { free(buffer); }
	return(0);
}
duk_ret_t ILibDuktape_PKCS7_signDataBlock(duk_context *ctx)
{
	duk_get_prop_string(ctx, 1, "secureContext");
	duk_get_prop_string(ctx, -1, "\xFF_SecureContext2CertBuffer");
	struct util_cert *cert = (struct util_cert*)Duktape_GetBuffer(ctx, -1, NULL);
	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	BIO *in = NULL;
	PKCS7 *message = NULL;
	char *signature = NULL;
	int signatureLength = 0;

	// Sign the block
	in = BIO_new_mem_buf(buffer, (int)bufferLen);
	message = PKCS7_sign(cert->x509, cert->pkey, NULL, in, PKCS7_BINARY);
	if (message != NULL)
	{
		signatureLength = i2d_PKCS7(message, (unsigned char**)&signature);
		PKCS7_free(message);
	}
	if (in != NULL) BIO_free(in);
	if (signatureLength <= 0) { return(ILibDuktape_Error(ctx, "PKCS7_signDataBlockError: ")); }

	duk_push_external_buffer(ctx);
	duk_config_buffer(ctx, -1, signature, signatureLength);
	duk_push_buffer_object(ctx, -1, 0, signatureLength, DUK_BUFOBJ_NODEJS_BUFFER);
	duk_push_pointer(ctx, signature);
	duk_put_prop_string(ctx, -2, "\xFF_signature");
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_PKCS7_signDataBlockFinalizer);

	return(1);
}
void ILibDuktape_PKCS7_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);
	ILibDuktape_CreateInstanceMethod(ctx, "getSignedDataBlock", ILibDuktape_PKCS7_getSignedDataBlock, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "signDataBlock", ILibDuktape_PKCS7_signDataBlock, DUK_VARARGS);
}

extern uint32_t crc32c(uint32_t crc, const unsigned char* buf, uint32_t len);
duk_ret_t ILibDuktape_Polyfills_crc32c(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	duk_push_int(ctx, crc32c(0, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_Object_hashCode(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_push_string(ctx, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_peek(duk_context *ctx)
{
	duk_push_this(ctx);				// [Array]
	duk_get_prop_index(ctx, -1, (duk_uarridx_t)duk_get_length(ctx, -1) - 1);
	return(1);
}
void ILibDuktape_Polyfills_object(duk_context *ctx)
{
	// Polyfill Object._hashCode() 
	duk_get_prop_string(ctx, -1, "Object");											// [g][Object]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_hashCode, 0);				// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "_hashCode");							// [g][Object][prototype]
	duk_pop_2(ctx);																	// [g]

	duk_get_prop_string(ctx, -1, "Array");											// [g][Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Array][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Array_peek, 0);					// [g][Array][prototype][peek]
	ILibDuktape_CreateReadonlyProperty(ctx, "peek");								// [g][Array][prototype]
	duk_pop_2(ctx);																	// [g]
}


#ifndef MICROSTACK_NOTLS
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b);
duk_ret_t ILibDuktape_bignum_toString(duk_context *ctx)
{
	duk_push_this(ctx);
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	if (b != NULL)
	{
		char *numstr = BN_bn2dec(b);
		duk_push_string(ctx, numstr);
		OPENSSL_free(numstr);
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid BIGNUM"));
	}
}
duk_ret_t ILibDuktape_bignum_add(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_add(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_sub(duk_context* ctx)
{
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");

	BN_sub(ret, r1, r2);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mul(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_mul(ret, r1, r2, bx);
	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_div(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(ret, NULL, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}
duk_ret_t ILibDuktape_bignum_mod(duk_context* ctx)
{
	BN_CTX *bx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BIGNUM *r1, *r2;

	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BN_div(NULL, ret, r1, r2, bx);

	BN_CTX_free(bx);
	ILibDuktape_bignum_addBigNumMethods(ctx, ret);
	return(1);
}

duk_ret_t ILibDuktape_bignum_finalizer(duk_context *ctx)
{
	BIGNUM *b = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	if (b != NULL)
	{
		BN_free(b);
	}
	return(0);
}
void ILibDuktape_bignum_addBigNumMethods(duk_context *ctx, BIGNUM *b)
{
	duk_push_object(ctx);
	duk_push_pointer(ctx, b); duk_put_prop_string(ctx, -2, "\xFF_BIGNUM");
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "toString", ILibDuktape_bignum_toString, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "add", ILibDuktape_bignum_add, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "sub", ILibDuktape_bignum_sub, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mul", ILibDuktape_bignum_mul, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "div", ILibDuktape_bignum_div, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "mod", ILibDuktape_bignum_mod, 1);
	duk_push_c_function(ctx, ILibDuktape_bignum_finalizer, 1); duk_set_finalizer(ctx, -2);
	duk_eval_string(ctx, "(function toNumber(){return(parseInt(this.toString()));})"); duk_put_prop_string(ctx, -2, "toNumber");
}
duk_ret_t ILibDuktape_bignum_fromBuffer(duk_context *ctx)
{
	char *endian = duk_get_top(ctx) > 1 ? Duktape_GetStringPropertyValue(ctx, 1, "endian", "big") : "big";
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	BIGNUM *b;

	if (strcmp(endian, "big") == 0)
	{
		b = BN_bin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else if (strcmp(endian, "little") == 0)
	{
		b = BN_lebin2bn((unsigned char*)buffer, (int)len, NULL);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
	}

	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}

duk_ret_t ILibDuktape_bignum_func(duk_context *ctx)
{	
	BIGNUM *b = NULL;
	BN_dec2bn(&b, duk_require_string(ctx, 0));
	ILibDuktape_bignum_addBigNumMethods(ctx, b);
	return(1);
}
void ILibDuktape_bignum_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_bignum_func, DUK_VARARGS);
	duk_push_c_function(ctx, ILibDuktape_bignum_fromBuffer, DUK_VARARGS); duk_put_prop_string(ctx, -2, "fromBuffer");
}
void ILibDuktape_dataGenerator_onPause(struct ILibDuktape_readableStream *sender, void *user)
{

}
void ILibDuktape_dataGenerator_onResume(struct ILibDuktape_readableStream *sender, void *user)
{
	SHA256_CTX shctx;

	char *buffer = (char*)user;
	size_t bufferLen = ILibMemory_Size(buffer);
	int val;

	while (sender->paused == 0)
	{
		duk_push_heapptr(sender->ctx, sender->object);
		val = Duktape_GetIntPropertyValue(sender->ctx, -1, "\xFF_counter", 0);
		duk_push_int(sender->ctx, (val + 1) < 255 ? (val+1) : 0); duk_put_prop_string(sender->ctx, -2, "\xFF_counter");
		duk_pop(sender->ctx);

		//util_random((int)(bufferLen - UTIL_SHA256_HASHSIZE), buffer + UTIL_SHA256_HASHSIZE);
		memset(buffer + UTIL_SHA256_HASHSIZE, val, bufferLen - UTIL_SHA256_HASHSIZE);


		SHA256_Init(&shctx);
		SHA256_Update(&shctx, buffer + UTIL_SHA256_HASHSIZE, bufferLen - UTIL_SHA256_HASHSIZE);
		SHA256_Final((unsigned char*)buffer, &shctx);
		ILibDuktape_readableStream_WriteData(sender, buffer, (int)bufferLen);
	}
}
duk_ret_t ILibDuktape_dataGenerator_const(duk_context *ctx)
{
	int bufSize = (int)duk_require_int(ctx, 0);
	void *buffer;

	if (bufSize <= UTIL_SHA256_HASHSIZE)
	{
		return(ILibDuktape_Error(ctx, "Value too small. Must be > %d", UTIL_SHA256_HASHSIZE));
	}

	duk_push_object(ctx);
	duk_push_int(ctx, 0); duk_put_prop_string(ctx, -2, "\xFF_counter");
	buffer = Duktape_PushBuffer(ctx, bufSize);
	duk_put_prop_string(ctx, -2, "\xFF_buffer");
	ILibDuktape_ReadableStream_Init(ctx, ILibDuktape_dataGenerator_onPause, ILibDuktape_dataGenerator_onResume, buffer)->paused = 1;
	return(1);
}
void ILibDuktape_dataGenerator_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_dataGenerator_const, DUK_VARARGS);
}
#endif

void ILibDuktape_Polyfills_JS_Init(duk_context *ctx)
{
	// The following can be overriden by calling addModule() or by having a .js file in the module path

	// http-digest. Refer to /modules/http-digest.js for a human readable version
	duk_peval_string_noresult(ctx, "addModule('http-digest', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQoNCnZhciB3cml0YWJsZSA9IHJlcXVpcmUoJ3N0cmVhbScpLldyaXRhYmxlOw0KdmFyIG1kNSA9IHJlcXVpcmUoJ01ENVN0cmVhbScpLmNyZWF0ZSgpOw0KDQpmdW5jdGlvbiBjaGVja0V2ZW50Rm9yd2FyZGluZyhkaWdlc3RSZXF1ZXN0LCBldmVudE5hbWUpDQp7DQogICAgaWYgKGRpZ2VzdFJlcXVlc3QubGlzdGVuZXJDb3VudChldmVudE5hbWUpID4gMCkNCiAgICB7DQogICAgICAgIHZhciBlRm9yd2FyZCA9IGZ1bmN0aW9uIF9lRm9yd2FyZCgpDQogICAgICAgIHsNCiAgICAgICAgICAgIHZhciBwID0gW2VGb3J3YXJkLl9ldmVudE5hbWVdOw0KICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyArK2kpIHsgcC5wdXNoKGFyZ3VtZW50c1tpXSk7IH0NCiAgICAgICAgICAgIF9lRm9yd2FyZC5fZGlnZXN0UmVxdWVzdC5lbWl0LmFwcGx5KF9lRm9yd2FyZC5fZGlnZXN0UmVxdWVzdCwgcCk7DQogICAgICAgIH07DQogICAgICAgIGVGb3J3YXJkLl9ldmVudE5hbWUgPSBldmVudE5hbWU7DQogICAgICAgIGVGb3J3YXJkLl9kaWdlc3RSZXF1ZXN0ID0gZGlnZXN0UmVxdWVzdDsNCiAgICAgICAgZGlnZXN0UmVxdWVzdC5fcmVxdWVzdC5vbihldmVudE5hbWUsIGVGb3J3YXJkKTsNCiAgICB9DQp9DQoNCmZ1bmN0aW9uIGdlbmVyYXRlQXV0aEhlYWRlcnMoaW1zZywgb3B0aW9ucywgZGlnZXN0KQ0Kew0KICAgIHZhciBhdXRoOw0KDQogICAgaWYgKGltc2cgIT0gbnVsbCkNCiAgICB7DQogICAgICAgIGF1dGggPSB7IHJlYWxtOiBudWxsLCBub25jZTogbnVsbCwgb3BhcXVlOiBudWxsLCBxb3A6IG51bGwgfTsNCiAgICAgICAgdmFyIHd3dyA9IGltc2cuaGVhZGVyc1snV1dXLUF1dGhlbnRpY2F0ZSddOw0KICAgICAgICB2YXIgdG9rZW5zID0gd3d3LnNwbGl0KCcsJyk7DQoNCiAgICAgICAgdmFyIHBhaXJzOw0KICAgICAgICBmb3IgKHZhciBpIGluIHRva2VucykNCiAgICAgICAgew0KICAgICAgICAgICAgcGFpcnMgPSB0b2tlbnNbaV0uc3BsaXQoJz0nKTsNCiAgICAgICAgICAgIGlmIChwYWlycy5sZW5ndGggPT0gMikNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBzd2l0Y2ggKHBhaXJzWzBdLnRvTG93ZXJDYXNlKCkudHJpbSgpKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnZGlnZXN0IHJlYWxtJzoNCiAgICAgICAgICAgICAgICAgICAgICAgIGF1dGgucmVhbG0gPSBwYWlyc1sxXTsNCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChhdXRoLnJlYWxtWzBdID09ICciJykgeyBhdXRoLnJlYWxtID0gYXV0aC5yZWFsbS5zdWJzdHJpbmcoMSwgYXV0aC5yZWFsbS5sZW5ndGggLSAxKTsgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgIGNhc2UgJ25vbmNlJzoNCiAgICAgICAgICAgICAgICAgICAgICAgIGF1dGgubm9uY2UgPSBwYWlyc1sxXTsNCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChhdXRoLm5vbmNlWzBdID09ICciJykgeyBhdXRoLm5vbmNlID0gYXV0aC5ub25jZS5zdWJzdHJpbmcoMSwgYXV0aC5ub25jZS5sZW5ndGggLSAxKTsgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgIGNhc2UgJ29wYXF1ZSc6DQogICAgICAgICAgICAgICAgICAgICAgICBhdXRoLm9wYXF1ZSA9IHBhaXJzWzFdOw0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGF1dGgub3BhcXVlWzBdID09ICciJykgeyBhdXRoLm9wYXF1ZSA9IGF1dGgub3BhcXVlLnN1YnN0cmluZygxLCBhdXRoLm9wYXF1ZS5sZW5ndGggLSAxKTsgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgIGNhc2UgJ3FvcCc6DQogICAgICAgICAgICAgICAgICAgICAgICBhdXRoLnFvcCA9IHBhaXJzWzFdOw0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGF1dGgucW9wWzBdID09ICciJykgeyBhdXRoLnFvcCA9IGF1dGgucW9wLnN1YnN0cmluZygxLCBhdXRoLnFvcC5sZW5ndGggLSAxKTsgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGRpZ2VzdC5fYXV0aCA9IGF1dGg7DQogICAgfQ0KICAgIGVsc2UNCiAgICB7DQogICAgICAgIGlmICghKGF1dGggPSBkaWdlc3QuX2F1dGgpKSB7IHJldHVybjsgfQ0KICAgIH0NCg0KICAgIHZhciBzdGVwMSA9IGRpZ2VzdC5fb3B0aW9ucy51c2VybmFtZSArICc6JyArIGF1dGgucmVhbG0gKyAnOicgKyBkaWdlc3QuX29wdGlvbnMucGFzc3dvcmQ7DQogICAgYXV0aC5zdGVwMSA9IG1kNS5zeW5jSGFzaChzdGVwMSkudG9TdHJpbmcoJ2hleCcpLnRvTG93ZXJDYXNlKCk7DQoNCiAgICB2YXIgc3RlcDIgPSBvcHRpb25zLm1ldGhvZCArICc6JyArIG9wdGlvbnMucGF0aDsNCiAgICBhdXRoLnN0ZXAyID0gbWQ1LnN5bmNIYXNoKHN0ZXAyKS50b1N0cmluZygnaGV4JykudG9Mb3dlckNhc2UoKTsNCg0KDQogICAgaWYgKGF1dGgucW9wID09IG51bGwpDQogICAgew0KICAgICAgICB2YXIgc3RlcDMgPSBhdXRoLnN0ZXAxICsgJzonICsgYXV0aC5ub25jZSArICc6JyArIGF1dGguc3RlcDI7DQogICAgICAgIGF1dGguc3RlcDMgPSBtZDUuc3luY0hhc2goc3RlcDMpLnRvU3RyaW5nKCdoZXgnKS50b0xvd2VyQ2FzZSgpOw0KICAgIH0NCiAgICBlbHNlDQogICAgew0KICAgICAgICBkaWdlc3QuX05DICs9IDE7DQogICAgICAgIHZhciBzdGVwMyA9IGF1dGguc3RlcDEgKyAnOicgKyBhdXRoLm5vbmNlICsgJzonICsgZGlnZXN0Ll9OQy50b1N0cmluZygxNikudG9Mb3dlckNhc2UoKS5wYWRTdGFydCg4LCAnMCcpICsgJzonICsgZGlnZXN0Ll9DTk9OQ0UgKyAnOicgKyBhdXRoLnFvcCArICc6JyArIGF1dGguc3RlcDI7DQogICAgICAgIGF1dGguc3RlcDMgPSBtZDUuc3luY0hhc2goc3RlcDMpLnRvU3RyaW5nKCdoZXgnKS50b0xvd2VyQ2FzZSgpOw0KICAgIH0NCg0KICAgIHZhciByZXQgPSAnRGlnZXN0IHVzZXJuYW1lPSInICsgZGlnZXN0Ll9vcHRpb25zLnVzZXJuYW1lICsgJyIscmVhbG09IicgKyBhdXRoLnJlYWxtICsgJyIsbm9uY2U9IicgKyBhdXRoLm5vbmNlICsgJyIsdXJpPSInICsgb3B0aW9ucy5wYXRoICsgJyInOw0KICAgIGlmIChhdXRoLm9wYXF1ZSAhPSBudWxsKSB7IHJldCArPSAoJyxvcGFxdWU9IicgKyBhdXRoLm9wYXF1ZSArICciJyk7IH0NCiAgICByZXQgKz0gKCcscmVzcG9uc2U9IicgKyBhdXRoLnN0ZXAzICsgJyInKTsNCg0KICAgIGlmIChhdXRoLnFvcCAhPSBudWxsKQ0KICAgIHsNCiAgICAgICAgcmV0ICs9ICgnLHFvcD0iJyArIGF1dGgucW9wICsgJyIsbmM9IicgKyBkaWdlc3QuX05DLnRvU3RyaW5nKDE2KS50b0xvd2VyQ2FzZSgpLnBhZFN0YXJ0KDgsICcwJykgKyAnIixjbm9uY2U9IicgKyBkaWdlc3QuX0NOT05DRSArICciJyk7DQogICAgfQ0KDQoNCiAgICBpZiAoIW9wdGlvbnMuaGVhZGVycykgeyBvcHRpb25zLmhlYWRlcnMgPSB7fTsgfQ0KICAgIG9wdGlvbnMuaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gcmV0Ow0KICAgIHJldHVybiAocmV0KTsNCn0NCg0KZnVuY3Rpb24gaHR0cF9kaWdlc3QoKQ0Kew0KICAgIHRoaXMuX09iamVjdElEID0gImh0dHAtZGlnZXN0IjsNCiAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uKCkNCiAgICB7DQogICAgICAgIGlmKGFyZ3VtZW50cy5sZW5ndGggPT0gMSAmJiB0eXBlb2YoYXJndW1lbnRzWzBdID09ICdvYmplY3QnKSkNCiAgICAgICAgew0KICAgICAgICAgICAgcmV0dXJuIChuZXcgaHR0cF9kaWdlc3RfaW5zdGFuY2UoYXJndW1lbnRzWzBdKSk7DQogICAgICAgIH0NCiAgICAgICAgaWYoYXJndW1lbnRzLmxlbmd0aCA9PSAyICYmIHR5cGVvZihhcmd1bWVudHNbMF0pID09ICdzdHJpbmcnICYmIHR5cGVvZihhcmd1bWVudHNbMV0pID09ICdzdHJpbmcnKQ0KICAgICAgICB7DQogICAgICAgICAgICByZXR1cm4gKG5ldyBodHRwX2RpZ2VzdF9pbnN0YW5jZSh7dXNlcm5hbWU6IGFyZ3VtZW50c1swXSwgcGFzc3dvcmQ6IGFyZ3VtZW50c1sxXX0pKTsNCiAgICAgICAgfQ0KICAgICAgICB0aHJvdyAoJ0ludmFsaWQgUGFyYW1ldGVycycpOw0KICAgIH0NCn0NCg0KZnVuY3Rpb24gaHR0cF9kaWdlc3RfaW5zdGFuY2Uob3B0aW9ucykNCnsNCiAgICB0aGlzLl9PYmplY3RJRCA9ICdodHRwLWRpZ2VzdC5pbnN0YW5jZSc7DQogICAgdGhpcy5fb3B0aW9ucyA9IG9wdGlvbnM7DQogICAgdGhpcy5odHRwID0gbnVsbDsNCiAgICB0aGlzLl9OQyA9IDA7DQogICAgdGhpcy5fQ05PTkNFID0gcmVxdWlyZSgnaHR0cCcpLmdlbmVyYXRlTm9uY2UoMTYpOw0KDQogICAgdGhpcy5nZXQgPSBmdW5jdGlvbih1cmkpDQogICAgew0KICAgICAgICByZXR1cm4gKHRoaXMucmVxdWVzdCh1cmkpKTsNCiAgICB9DQogICAgdGhpcy5yZXF1ZXN0ID0gZnVuY3Rpb24gKHBhcjEpDQogICAgew0KICAgICAgICB2YXIgY2FsbGVuZCA9IGZhbHNlOw0KICAgICAgICB2YXIgcmV0ID0gbmV3IHdyaXRhYmxlKA0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHdyaXRlOiBmdW5jdGlvbiAoY2h1bmssIGZsdXNoKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX2VuZGVkKSB7IHRocm93ICgnU3RyZWFtIGFscmVhZHkgZW5kZWQnKTsgfQ0KICAgICAgICAgICAgICAgICAgICBpZighdGhpcy5fYnVmZmVyZWQpIA0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9idWZmZXJlZCA9IEJ1ZmZlci5hbGxvYyhjaHVuay5sZW5ndGgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgY2h1bmsuY29weSh0aGlzLl9idWZmZXJlZCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9idWZmZXJlZCA9IEJ1ZmZlci5jb25jYXQoW3RoaXMuX2J1ZmZlcmVkLCBjaHVua10sIHRoaXMuX2J1ZmZlcmVkLmxlbmd0aCArIGNodW5rLmxlbmd0aCk7DQogICAgICAgICAgICAgICAgICAgIH0NCg0KICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5fcmVxdWVzdCkgeyB0aGlzLl9yZXF1ZXN0LndyaXRlKGNodW5rKTsgfQ0KICAgICAgICAgICAgICAgICAgICBpZiAoZmx1c2ggIT0gbnVsbCkgeyBmbHVzaCgpOyB9DQogICAgICAgICAgICAgICAgICAgIHJldHVybiAodHJ1ZSk7DQogICAgICAgICAgICAgICAgfSwNCiAgICAgICAgICAgICAgICBmaW5hbDogZnVuY3Rpb24gKGZsdXNoKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX2VuZGVkKSB7IHRocm93ICgnU3RyZWFtIGFscmVhZHkgZW5kZWQnKTsgfQ0KICAgICAgICAgICAgICAgICAgICB0aGlzLl9lbmRlZCA9IHRydWU7DQogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLl9yZXF1ZXN0KSB7IHRoaXMuX3JlcXVlc3QuZW5kKCk7IH0NCiAgICAgICAgICAgICAgICAgICAgaWYgKGZsdXNoICE9IG51bGwpIHsgZmx1c2goKTsgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIH0pOw0KICAgICAgICByZXQuX2J1ZmZlcmVkID0gbnVsbDsNCiAgICAgICAgcmV0Ll9lbmRlZCA9IGZhbHNlOw0KICAgICAgICBzd2l0Y2ggKHR5cGVvZiAocGFyMSkpDQogICAgICAgIHsNCiAgICAgICAgICAgIGRlZmF1bHQ6DQogICAgICAgICAgICAgICAgdGhyb3cgKCdJbnZhbGlkIFBhcmFtZXRlcicpOw0KICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgY2FzZSAnc3RyaW5nJzoNCiAgICAgICAgICAgICAgICByZXQub3B0aW9ucyA9IHRoaXMuaHR0cC5wYXJzZVVyaShwYXIxKTsNCiAgICAgICAgICAgICAgICBjYWxsZW5kID0gdHJ1ZTsNCiAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgIGNhc2UgJ29iamVjdCc6DQogICAgICAgICAgICAgICAgcmV0Lm9wdGlvbnMgPSBwYXIxOw0KICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICB9DQogICAgICAgIHJlcXVpcmUoJ2V2ZW50cycpLkV2ZW50RW1pdHRlci5jYWxsKHJldCwgdHJ1ZSkNCiAgICAgICAgICAgIC5jcmVhdGVFdmVudCgncmVzcG9uc2UnKQ0KICAgICAgICAgICAgLmNyZWF0ZUV2ZW50KCdlcnJvcicpDQogICAgICAgICAgICAuY3JlYXRlRXZlbnQoJ3VwZ3JhZGUnKQ0KICAgICAgICAgICAgLmNyZWF0ZUV2ZW50KCdjb250aW51ZScpDQogICAgICAgICAgICAuY3JlYXRlRXZlbnQoJ3RpbWVvdXQnKTsNCiAgICAgICAgcmV0Ll9kaWdlc3QgPSB0aGlzOw0KDQogICAgICAgIGlmIChhcmd1bWVudHMubGVuZ3RoID4gMSAmJiB0eXBlb2YgKGFyZ3VtZW50c1sxXSkgPT0gJ2Z1bmN0aW9uJykNCiAgICAgICAgew0KICAgICAgICAgICAgcmV0Lm9uY2UoJ3Jlc3BvbnNlJywgYXJndW1lbnRzWzFdKTsNCiAgICAgICAgfQ0KDQogICAgICAgIC8vDQogICAgICAgIC8vIENoZWNrIGlmIHdlIGNhbiBhZGQgQXV0aEhlYWRlcnMgbm93DQogICAgICAgIC8vDQogICAgICAgIGdlbmVyYXRlQXV0aEhlYWRlcnMobnVsbCwgcmV0Lm9wdGlvbnMsIHRoaXMpOw0KDQogICAgICAgIC8vIFdoZW4gc29tZWJvZHkgaG9va3MgdXAgZXZlbnRzIHRvIGRpZ2VzdC5jbGllbnRSZXF1ZXN0LCB3ZSBuZWVkIHRvIGhvb2sgdGhlIHJlYWwgZXZlbnQgb24gaHR0cC5jbGllbnRSZXF1ZXN0DQogICAgICAgIHJldC5fcmVxdWVzdCA9IHRoaXMuaHR0cC5yZXF1ZXN0KHJldC5vcHRpb25zKTsNCiAgICAgICAgcmV0Ll9yZXF1ZXN0LmRpZ1JlcXVlc3QgPSByZXQ7DQogICAgICAgIHJldC5vbignbmV3TGlzdGVuZXInLCBmdW5jdGlvbiAoZXZOYW1lLCBjYWxsYmFjaykNCiAgICAgICAgew0KICAgICAgICAgICAgaWYgKGV2TmFtZSAhPSAndXBncmFkZScgJiYgZXZOYW1lICE9ICdlcnJvcicgJiYgZXZOYW1lICE9ICdjb250aW51ZScgJiYgZXZOYW1lICE9ICd0aW1lb3V0JyAmJiBldk5hbWUgIT0gJ2RyYWluJykgeyByZXR1cm47IH0NCiAgICAgICAgICAgIGlmICh0aGlzLl9yZXF1ZXN0Lmxpc3RlbmVyQ291bnQoZXZOYW1lKSA9PSAwKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHZhciBldlNpbmsgPSBmdW5jdGlvbiBfZXZTaW5rKCkNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHZhciBwYXJtcyA9IFtfZXZTaW5rLmV2ZW50TmFtZV07DQogICAgICAgICAgICAgICAgICAgIGZvcih2YXIgaT0wO2k8YXJndW1lbnRzLmxlbmd0aDsrK2kpIHtwYXJtcy5wdXNoKGFyZ3VtZW50c1tpXSk7fQ0KICAgICAgICAgICAgICAgICAgICB0aGlzLmRpZ1JlcXVlc3QuZW1pdC5hcHBseSh0aGlzLmRpZ1JlcXVlc3QsIHBhcm1zKTsNCiAgICAgICAgICAgICAgICB9Ow0KICAgICAgICAgICAgICAgIGV2U2luay5ldmVudE5hbWUgPSBldk5hbWU7DQogICAgICAgICAgICAgICAgdGhpcy5fcmVxdWVzdC5vbihldk5hbWUsIGV2U2luayk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KDQogICAgICAgIHJldC5fcmVxdWVzdC5vbmNlKCdyZXNwb25zZScsIGZ1bmN0aW9uIChpbXNnKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAoaW1zZy5zdGF0dXNDb2RlID09IDQwMSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB2YXIgY2FsbGVuZCA9IHRoaXMuZGlnUmVxdWVzdC5fcmVxdWVzdC5fY2FsbGVuZDsNCiAgICAgICAgICAgICAgICB2YXIgYXV0aCA9IGdlbmVyYXRlQXV0aEhlYWRlcnMoaW1zZywgdGhpcy5kaWdSZXF1ZXN0Lm9wdGlvbnMsIHRoaXMuZGlnUmVxdWVzdC5fZGlnZXN0KTsNCg0KICAgICAgICAgICAgICAgIHRoaXMuZGlnUmVxdWVzdC5fcmVxdWVzdCA9IHRoaXMuZGlnUmVxdWVzdC5fZGlnZXN0Lmh0dHAucmVxdWVzdCh0aGlzLmRpZ1JlcXVlc3Qub3B0aW9ucyk7DQogICAgICAgICAgICAgICAgdGhpcy5kaWdSZXF1ZXN0Ll9yZXF1ZXN0LmRpZ1JlcXVlc3QgPSB0aGlzLmRpZ1JlcXVlc3Q7DQogICAgICAgICAgICAgICAgdGhpcy5kaWdSZXF1ZXN0Ll9yZXF1ZXN0Lm9uY2UoJ3Jlc3BvbnNlJywgZnVuY3Rpb24gKGltc2cpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICBzd2l0Y2goaW1zZy5zdGF0dXNDb2RlKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDQwMToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRpZ1JlcXVlc3QuZW1pdCgnZXJyb3InLCAnRGlnZXN0IGZhaWxlZCB0b28gbWFueSB0aW1lcycpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRpZ1JlcXVlc3QuZW1pdCgncmVzcG9uc2UnLCBpbXNnKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgICAgIGNoZWNrRXZlbnRGb3J3YXJkaW5nKHRoaXMuZGlnUmVxdWVzdCwgJ3VwZ3JhZGUnKTsNCiAgICAgICAgICAgICAgICBjaGVja0V2ZW50Rm9yd2FyZGluZyh0aGlzLmRpZ1JlcXVlc3QsICdlcnJvcicpOw0KICAgICAgICAgICAgICAgIGNoZWNrRXZlbnRGb3J3YXJkaW5nKHRoaXMuZGlnUmVxdWVzdCwgJ2NvbnRpbnVlJyk7DQogICAgICAgICAgICAgICAgY2hlY2tFdmVudEZvcndhcmRpbmcodGhpcy5kaWdSZXF1ZXN0LCAndGltZW91dCcpOw0KICAgICAgICAgICAgICAgIGNoZWNrRXZlbnRGb3J3YXJkaW5nKHRoaXMuZGlnUmVxdWVzdCwgJ2RyYWluJyk7DQogICAgICAgICAgICAgICAgaWYgKGNhbGxlbmQpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLmRpZ1JlcXVlc3QuX3JlcXVlc3QuZW5kKCk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLmRpZ1JlcXVlc3QuX2J1ZmZlcmVkKSB7IHRoaXMuZGlnUmVxdWVzdC5fcmVxdWVzdC53cml0ZSh0aGlzLmRpZ1JlcXVlc3QuX2J1ZmZlcmVkKTsgfQ0KICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5kaWdSZXF1ZXN0Ll9lbmRlZCkgeyB0aGlzLmRpZ1JlcXVlc3QuX3JlcXVlc3QuZW5kKCk7IH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBlbHNlDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5kaWdSZXF1ZXN0LmVtaXQoJ3Jlc3BvbnNlJywgaW1zZyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgICAgICBpZiAoY2FsbGVuZCkNCiAgICAgICAgew0KICAgICAgICAgICAgcmV0Ll9yZXF1ZXN0Ll9jYWxsZW5kID0gdHJ1ZTsgcmV0Ll9yZXF1ZXN0LmVuZCgpOw0KICAgICAgICB9DQogICAgICAgIGVsc2UNCiAgICAgICAgew0KICAgICAgICAgICAgaWYgKHJldC5fYnVmZmVyZWQpIHsgcmV0Ll9yZXF1ZXN0LndyaXRlKHJldC5fYnVmZmVyZWQpOyB9DQogICAgICAgICAgICBpZiAocmV0Ll9lbmRlZCkgeyByZXQuX3JlcXVlc3QuZW5kKCk7IH0NCiAgICAgICAgfQ0KICAgICAgICByZXR1cm4gKHJldCk7DQogICAgfTsNCn0NCg0KDQptb2R1bGUuZXhwb3J0cyA9IG5ldyBodHRwX2RpZ2VzdCgpOw0KDQo=', 'base64').toString());");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	char *_clipboard = ILibMemory_Allocate(41006, 0, NULL, NULL);
	memcpy_s(_clipboard + 0, 23432, "LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcHJvbWlzZSA9IHJlcXVpcmUoJ3Byb21pc2UnKTsNCg0KdmFyIEFueVByb3BlcnR5VHlwZSA9IDA7DQp2YXIgQ3VycmVudFRpbWUgPSAwOw0KdmFyIE5vbmUgPSAwOw0KdmFyIFByb3BNb2RlUmVwbGFjZSA9IDA7DQp2YXIgU2VsZWN0aW9uQ2xlYXIgPSAyOTsNCnZhciBTZWxlY3Rpb25Ob3RpZnkgPSAzMTsNCnZhciBTZWxlY3Rpb25SZXF1ZXN0ID0gMzA7DQp2YXIgWEFfUFJJTUFSWSA9IDE7DQoNCmZ1bmN0aW9uIG5hdGl2ZUFkZE1vZHVsZShuYW1lKQ0Kew0KICAgIHZhciB2YWx1ZSA9IGdldEpTTW9kdWxlKG5hbWUpOw0KICAgIHZhciByZXQgPSAiZHVrX3BldmFsX3N0cmluZ19ub3Jlc3VsdChjdHgsIFwiYWRkTW9kdWxlKCciICsgbmFtZSArICInLCBCdWZmZXIuZnJvbSgnIiArIEJ1ZmZlci5mcm9tKHZhbHVlKS50b1N0cmluZygnYmFzZTY0JykgKyAiJywgJ2Jhc2U2NCcpLnRvU3RyaW5nKCkpO1wiKTsiOw0KICAgIGlmIChyZXQubGVuZ3RoID4gMTYzMDApDQogICAgew0KICAgICAgICAvLyBNUyBWaXN1YWwgU3R1ZGlvIGhhcyBhIG1heHNpemUgbGltaXRhdGlvbg0KICAgICAgICB2YXIgdG1wID0gQnVmZmVyLmZyb20odmFsdWUpLnRvU3RyaW5nKCdiYXNlNjQnKTsNCiAgICAgICAgcmV0ID0gJ2NoYXIgKl8nICsgbmFtZS5zcGxpdCgnLScpLmpvaW4oJycpICsgJyA9IElMaWJNZW1vcnlfQWxsb2NhdGUoJyArICh0bXAubGVuZ3RoICsgdmFsdWUubGVuZ3RoICsgMikgKyAnLCAwLCBOVUxMLCBOVUxMKTtcbic7DQogICAgICAgIHZhciBpID0gMDsNCiAgICAgICAgd2hpbGUgKGkgPCB0bXAubGVuZ3RoKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgY2h1bmsgPSB0bXAuc3Vic3RyaW5nKGksIGkrMTYwMDApOw0KICAgICAgICAgICAgcmV0ICs9ICgnbWVtY3B5X3MoXycgKyBuYW1lLnNwbGl0KCctJykuam9pbignJykgKyAnICsgJyArIGkgKyAnLCAnICsgKHRtcC5sZW5ndGggLSBpKSArICcsICInICsgY2h1bmsgKyAnIiwgJyArIGNodW5rLmxlbmd0aCArICcpO1xuJyk7DQogICAgICAgICAgICBpICs9IGNodW5rLmxlbmd0aDsNCiAgICAgICAgfQ0KICAgICAgICByZXQgKz0gKCdJTGliQmFzZTY0RGVjb2RlRXgoKHVuc2lnbmVkIGNoYXIqKV8nICsgbmFtZS5zcGxpdCgnLScpLmpvaW4oJycpICsgJywgJyArIHRtcC5sZW5ndGggKyAnLCAodW5zaWduZWQgY2hhciopXycgKyBuYW1lLnNwbGl0KCctJykuam9pbignJykgKyAnICsgJyArIHRtcC5sZW5ndGggKyAnKTtcbicpOw0KICAgICAgICByZXQgKz0gKCdkdWtfcHVzaF9nbG9iYWxfb2JqZWN0KGN0eCk7ZHVrX2dldF9wcm9wX3N0cmluZyhjdHgsIC0xLCAiYWRkTW9kdWxlIik7ZHVrX3N3YXBfdG9wKGN0eCwgLTIpO2R1a19wdXNoX3N0cmluZyhjdHgsICInICsgbmFtZSArICciKTtkdWtfcHVzaF9zdHJpbmcoY3R4LCBfJyArIG5hbWUuc3BsaXQoJy0nKS5qb2luKCcnKSArICcgKyAnICsgdG1wLmxlbmd0aCArICcpO1xuJyk7DQogICAgICAgIHJldCArPSAoJ2R1a19wY2FsbF9tZXRob2QoY3R4LCAyKTsgZHVrX3BvcChjdHgpO1xuJyk7DQogICAgICAgIHJldCArPSAoJ2ZyZWUoXycgKyBuYW1lLnNwbGl0KCctJykuam9pbignJykgKyAnKTtcbicpOw0KICAgIH0NCiAgICBtb2R1bGUuZXhwb3J0cyhyZXQpOw0KfQ0KZnVuY3Rpb24gZGlzcGF0Y2hSZWFkKHNpZCkNCnsNCiAgICB2YXIgaWQgPSAwOw0KDQogICAgaWYoc2lkPT1udWxsKQ0KICAgIHsNCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIGFjdGl2ZSA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5DdXJyZW50KCkuQWN0aXZlOw0KICAgICAgICAgICAgaWYgKGFjdGl2ZS5sZW5ndGggPiAwKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGlkID0gcGFyc2VJbnQoYWN0aXZlWzBdLlNlc3Npb25JZCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICBpZCA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5jb25zb2xlVWlkKCk7DQogICAgICAgIH0NCiAgICB9DQogICAgZWxzZQ0KICAgIHsNCiAgICAgICAgaWQgPSBzaWQ7DQogICAgfQ0KDQogICAgaWYoaWQgPT0gMCkNCiAgICB7DQogICAgICAgIHJldHVybiAobW9kdWxlLmV4cG9ydHMucmVhZCgpKTsNCiAgICB9DQogICAgZWxzZQ0KICAgIHsNCiAgICAgICAgdmFyIGNoaWxkUHJvcGVydGllcyA9IHsgc2Vzc2lvbklkOiBpZCB9Ow0KICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQ0KICAgICAgICB7DQogICAgICAgICAgICB4aW5mbyA9IHJlcXVpcmUoJ21vbml0b3ItaW5mbycpLmdldFhJbmZvKGlkKTsNCiAgICAgICAgICAgIGNoaWxkUHJvcGVydGllcy5lbnYgPSB7IFhBVVRIT1JJVFk6IHhpbmZvLnhhdXRob3JpdHksIERJU1BMQVk6IHhpbmZvLmRpc3BsYXkgfTsNCiAgICAgICAgfQ0KDQogICAgICAgIHZhciByZXQgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOw0KICAgICAgICByZXQuc3VjY2VzcyA9IGZhbHNlOw0KICAgICAgICByZXQubWFzdGVyID0gcmVxdWlyZSgnU2NyaXB0Q29udGFpbmVyJykuQ3JlYXRlKGNoaWxkUHJvcGVydGllcyk7DQogICAgICAgIHJldC5tYXN0ZXIucHJvbWlzZSA9IHJldDsNCiAgICAgICAgcmV0Lm1hc3Rlci5vbignZGF0YScsIGZ1bmN0aW9uIChkKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLnByb21pc2Uuc3VjY2VzcyA9IHRydWU7DQogICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlcyhkKTsNCiAgICAgICAgICAgIHRoaXMuZXhpdCgpOw0KICAgICAgICB9KTsNCiAgICAgICAgcmV0Lm1hc3Rlci5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAoIXRoaXMucHJvbWlzZS5zdWNjZXNzKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKCdFcnJvciByZWFkaW5nIGNsaXBib2FyZCcpOw0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZGVsZXRlIHRoaXMucHJvbWlzZS5tYXN0ZXI7DQogICAgICAgIH0pOw0KICAgICAgICByZXQubWFzdGVyLkV4ZWN1dGVTdHJpbmcoInZhciBwYXJlbnQgPSByZXF1aXJlKCdTY3JpcHRDb250YWluZXInKTsgcmVxdWlyZSgnY2xpcGJvYXJkJykucmVhZCgpLnRoZW4oZnVuY3Rpb24odil7cGFyZW50LnNlbmQodik7fSwgZnVuY3Rpb24oZSl7Y29uc29sZS5lcnJvcihlKTtwcm9jZXNzLmV4aXQoKTt9KTsiKTsNCiAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgIH0NCn0NCg0KZnVuY3Rpb24gZGlzcGF0Y2hXcml0ZShkYXRhLCBzaWQpDQp7DQogICAgdmFyIGlkID0gMDsNCg0KICAgIGlmKHNpZCA9PSBudWxsKQ0KICAgIHsNCiAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgYWN0aXZlID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLkN1cnJlbnQoKS5BY3RpdmU7DQogICAgICAgICAgICBpZihhY3RpdmUubGVuZ3RoPjApDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgaWQgPSBwYXJzZUludChhY3RpdmVbMF0uU2Vzc2lvbklkKTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KICAgICAgICBlbHNlDQogICAgICAgIHsNCiAgICAgICAgICAgIGlkID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmNvbnNvbGVVaWQoKTsNCiAgICAgICAgfQ0KICAgIH0NCiAgICBlbHNlDQogICAgew0KICAgICAgICBpZCA9IHNpZDsNCiAgICB9DQoNCiAgICBpZihpZCA9PSAwKQ0KICAgIHsNCiAgICAgICAgbW9kdWxlLmV4cG9ydHMoZGF0YSk7DQogICAgfQ0KICAgIGVsc2UNCiAgICB7DQogICAgICAgIHZhciBjaGlsZFByb3BlcnRpZXMgPSB7IHNlc3Npb25JZDogaWQgfTsNCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JykNCiAgICAgICAgew0KICAgICAgICAgICAgeGluZm8gPSByZXF1aXJlKCdtb25pdG9yLWluZm8nKS5nZXRYSW5mbyhpZCk7DQogICAgICAgICAgICBjaGlsZFByb3BlcnRpZXMuZW52ID0geyBYQVVUSE9SSVRZOiB4aW5mby54YXV0aG9yaXR5LCBESVNQTEFZOiB4aW5mby5kaXNwbGF5IH07DQogICAgICAgIH0NCg0KICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInIHx8ICF0aGlzLm1hc3RlcikNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5tYXN0ZXIgPSByZXF1aXJlKCdTY3JpcHRDb250YWluZXInKS5DcmVhdGUoY2hpbGRQcm9wZXJ0aWVzKTsNCiAgICAgICAgICAgIHRoaXMubWFzdGVyLnBhcmVudCA9IHRoaXM7DQogICAgICAgICAgICB0aGlzLm1hc3Rlci5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKSB7IGlmICh0aGlzLnBhcmVudC5tYXN0ZXIpIHsgZGVsZXRlIHRoaXMucGFyZW50Lm1hc3RlcjsgfSB9KTsNCiAgICAgICAgICAgIHRoaXMubWFzdGVyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGQpIHsgY29uc29sZS5sb2coZCk7IH0pOw0KICAgICAgICAgICAgdGhpcy5tYXN0ZXIuRXhlY3V0ZVN0cmluZygidmFyIHBhcmVudCA9IHJlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpOyBwYXJlbnQub24oJ2RhdGEnLCBmdW5jdGlvbihkKXt0cnl7cmVxdWlyZSgnY2xpcGJvYXJkJykoZCk7fWNhdGNoKGUpe3JlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpLnNlbmQoZSk7fWlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJyl7cHJvY2Vzcy5leGl0KCk7fX0pOyIpOw0KICAgICAgICB9DQogICAgICAgIHRoaXMubWFzdGVyLnNlbmQoZGF0YSk7DQoNCiAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnICYmIHRoaXMubWFzdGVyKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZih0aGlzLm1hc3Rlci50aW1lb3V0KQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGNsZWFyVGltZW91dCh0aGlzLm1hc3Rlci50aW1lb3V0KTsNCiAgICAgICAgICAgICAgICB0aGlzLm1hc3Rlci50aW1lb3V0ID0gbnVsbDsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIHRoaXMubWFzdGVyLnRpbWVvdXQgPSBzZXRUaW1lb3V0KGZ1bmN0aW9uIChzZWxmKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHNlbGYubWFzdGVyLmV4aXQoKTsNCiAgICAgICAgICAgICAgICBzZWxmLm1hc3RlciA9IG51bGw7DQogICAgICAgICAgICB9LCA2MDAwMCwgdGhpcyk7DQogICAgICAgIH0NCg0KICAgIH0NCn0NCg0KZnVuY3Rpb24gbGluX3JlYWR0ZXh0KCkNCnsNCiAgICB2YXIgcmV0ID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsNCiAgICB0cnkNCiAgICB7DQogICAgICAgIHJlcXVpcmUoJ21vbml0b3ItaW5mbycpDQogICAgfQ0KICAgIGNhdGNoKGV4YykNCiAgICB7DQogICAgICAgIHJldC5fcmVqKGV4Yyk7DQogICAgICAgIHJldHVybiAocmV0KTsNCiAgICB9DQoNCiAgICB2YXIgWDExID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuX1gxMTsNCiAgICBpZiAoIVgxMSkNCiAgICB7DQogICAgICAgIHJldC5fcmVqKCdYMTEgcmVxdWlyZWQgZm9yIENsaXBib2FyZCBNYW5pcHVsYXRpb24nKTsNCiAgICB9DQogICAgZWxzZQ0KICAgIHsNCiAgICAgICAgdmFyIEdNID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuX2dtOw0KDQoNCiAgICAgICAgcmV0Ll9nZXRJbmZvUHJvbWlzZSA9IHJlcXVpcmUoJ21vbml0b3ItaW5mbycpLmdldEluZm8oKTsNCiAgICAgICAgcmV0Ll9nZXRJbmZvUHJvbWlzZS5fbWFzdGVyUHJvbWlzZSA9IHJldDsNCiAgICAgICAgcmV0Ll9nZXRJbmZvUHJvbWlzZS50aGVuKGZ1bmN0aW9uIChtb24pDQogICAgICAgIHsNCiAgICAgICAgICAgIGlmIChtb24ubGVuZ3RoID4gMCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB2YXIgd2hpdGUgPSBYMTEuWFdoaXRlUGl4ZWwobW9uWzBdLmRpc3BsYXksIG1vblswXS5zY3JlZW5JZCkuVmFsOw0KDQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5DTElQSUQgPSBYMTEuWEludGVybkF0b20obW9uWzBdLmRpc3BsYXksIEdNLkNyZWF0ZVZhcmlhYmxlKCdDTElQQk9BUkQnKSwgMCk7DQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5GTVRJRCA9IFgxMS5YSW50ZXJuQXRvbShtb25bMF0uZGlzcGxheSwgR00uQ3JlYXRlVmFyaWFibGUoJ1VURjhfU1RSSU5HJyksIDApOw0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuUFJPUElEID0gWDExLlhJbnRlcm5BdG9tKG1vblswXS5kaXNwbGF5LCBHTS5DcmVhdGVWYXJpYWJsZSgnWFNFTF9EQVRBJyksIDApOw0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuSU5DUklEID0gWDExLlhJbnRlcm5BdG9tKG1vblswXS5kaXNwbGF5LCBHTS5DcmVhdGVWYXJpYWJsZSgnSU5DUicpLCAwKTsNCiAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLlJPT1RXSU4gPSBYMTEuWFJvb3RXaW5kb3cobW9uWzBdLmRpc3BsYXksIG1vblswXS5zY3JlZW5JZCk7DQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5GQUtFV0lOID0gWDExLlhDcmVhdGVTaW1wbGVXaW5kb3cobW9uWzBdLmRpc3BsYXksIHRoaXMuX21hc3RlclByb21pc2UuUk9PVFdJTiwgMCwgMCwgbW9uWzBdLnJpZ2h0LCA1LCAwLCB3aGl0ZSwgd2hpdGUpOw0KDQogICAgICAgICAgICAgICAgWDExLlhTeW5jKG1vblswXS5kaXNwbGF5LCAwKTsNCiAgICAgICAgICAgICAgICBYMTEuWENvbnZlcnRTZWxlY3Rpb24obW9uWzBdLmRpc3BsYXksIHRoaXMuX21hc3RlclByb21pc2UuQ0xJUElELCB0aGlzLl9tYXN0ZXJQcm9taXNlLkZNVElELCB0aGlzLl9tYXN0ZXJQcm9taXNlLlBST1BJRCwgdGhpcy5fbWFzdGVyUHJvbWlzZS5GQUtFV0lOLCBDdXJyZW50VGltZSk7DQogICAgICAgICAgICAgICAgWDExLlhTeW5jKG1vblswXS5kaXNwbGF5LCAwKTsNCg0KDQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5EZXNjcmlwdG9yRXZlbnQgPSByZXF1aXJlKCdEZXNjcmlwdG9yRXZlbnRzJykuYWRkRGVzY3JpcHRvcihYMTEuWENvbm5lY3Rpb25OdW1iZXIobW9uWzBdLmRpc3BsYXkpLlZhbCwgeyByZWFkc2V0OiB0cnVlIH0pOw0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuRGVzY3JpcHRvckV2ZW50Ll9tYXN0ZXJQcm9taXNlID0gdGhpcy5fbWFzdGVyUHJvbWlzZTsNCiAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLkRlc2NyaXB0b3JFdmVudC5fZGlzcGxheSA9IG1vblswXS5kaXNwbGF5Ow0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuRGVzY3JpcHRvckV2ZW50Lm9uKCdyZWFkc2V0JywgZnVuY3Rpb24gKGZkKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdmFyIFhFID0gR00uQ3JlYXRlVmFyaWFibGUoMTAyNCk7DQogICAgICAgICAgICAgICAgICAgIHdoaWxlIChYMTEuWFBlbmRpbmcodGhpcy5fZGlzcGxheSkuVmFsKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBYMTEuWE5leHRFdmVudFN5bmModGhpcy5fZGlzcGxheSwgWEUpOw0KICAgICAgICAgICAgICAgICAgICAgICAgaWYoWEUuRGVyZWYoMCwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSA9PSBTZWxlY3Rpb25Ob3RpZnkpDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGlkID0gR00uQ3JlYXRlUG9pbnRlcigpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiaXRzID0gR00uQ3JlYXRlUG9pbnRlcigpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzeiA9IEdNLkNyZWF0ZVBvaW50ZXIoKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdGFpbCA9IEdNLkNyZWF0ZVBvaW50ZXIoKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVzdWx0ID0gR00uQ3JlYXRlUG9pbnRlcigpOw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgWDExLlhHZXRXaW5kb3dQcm9wZXJ0eSh0aGlzLl9kaXNwbGF5LCB0aGlzLl9tYXN0ZXJQcm9taXNlLkZBS0VXSU4sIHRoaXMuX21hc3RlclByb21pc2UuUFJPUElELCAwLCA2NTUzNSwgMCwgQW55UHJvcGVydHlUeXBlLCBpZCwgYml0cywgc3osIHRhaWwsIHJlc3VsdCk7DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLl9yZXMocmVzdWx0LkRlcmVmKCkuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBYMTEuWEZyZWUocmVzdWx0LkRlcmVmKCkpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIFgxMS5YRGVzdHJveVdpbmRvdyh0aGlzLl9kaXNwbGF5LCB0aGlzLl9tYXN0ZXJQcm9taXNlLkZBS0VXSU4pOw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZW1vdmVEZXNjcmlwdG9yKGZkKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9LCBjb25zb2xlLmVycm9yKTsNCiAgICB9DQogICAgcmV0dXJuIChyZXQpOw0KfQ0KZnVuY3Rpb24gbGluX2NvcHl0ZXh0KHR4dCkNCnsNCiAgICB2YXIgWDExID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuX1gxMTsNCiAgICBpZiAoIVgxMSkNCiAgICB7DQogICAgICAgIHRocm93KCdYMTEgcmVxdWlyZWQgZm9yIENsaXBib2FyZCBNYW5pcHVsYXRpb24nKTsNCiAgICB9DQogICAgZWxzZQ0KICAgIHsNCiAgICAgICAgdmFyIEdNID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuX2dtOw0KICAgICAgICB2YXIgcmV0ID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsNCiAgICAgICAgcmV0Ll90eHQgPSB0eHQ7DQogICAgICAgIHJldC5fZ2V0SW5mb1Byb21pc2UgPSByZXF1aXJlKCdtb25pdG9yLWluZm8nKS5nZXRJbmZvKCk7DQogICAgICAgIHJldC5fZ2V0SW5mb1Byb21pc2UuX21hc3RlclByb21pc2UgPSByZXQ7DQogICAgICAgIHJldC5fZ2V0SW5mb1Byb21pc2UudGhlbihmdW5jdGlvbiAobW9uKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZiAobW9uLmxlbmd0aCA+IDApDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHdoaXRlID0gWDExLlhXaGl0ZVBpeGVsKG1vblswXS5kaXNwbGF5LCBtb25bMF0uc2NyZWVuSWQpLlZhbDsNCiAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLkNMSVBJRCA9IFgxMS5YSW50ZXJuQXRvbShtb25bMF0uZGlzcGxheSwgR00uQ3JlYXRlVmFyaWFibGUoJ0NMSVBCT0FSRCcpLCAwKTsNCiAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLkZNVElEID0gWDExLlhJbnRlcm5BdG9tKG1vblswXS5kaXNwbGF5LCBHTS5DcmVhdGVWYXJpYWJsZSgnVVRGOF9TVFJJTkcnKSwgMCk7DQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5ST09UV0lOID0gWDExLlhSb290V2luZG93KG1vblswXS5kaXNwbGF5LCBtb25bMF0uc2NyZWVuSWQpOw0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuRkFLRVdJTiA9IFgxMS5YQ3JlYXRlU2ltcGxlV2luZG93KG1vblswXS5kaXNwbGF5LCB0aGlzLl9tYXN0ZXJQcm9taXNlLlJPT1RXSU4sIDAsIDAsIG1vblswXS5yaWdodCwgNSwgMCwgd2hpdGUsIHdoaXRlKTsNCg0KICAgICAgICAgICAgICAgIFgxMS5YU2V0U2VsZWN0aW9uT3duZXIobW9uWzBdLmRpc3BsYXksIFhBX1BSSU1BUlksIHRoaXMuX21hc3RlclByb21pc2UuRkFLRVdJTiwgQ3VycmVudFRpbWUpOw0KICAgICAgICAgICAgICAgIFgxMS5YU2V0U2VsZWN0aW9uT3duZXIobW9uWzBdLmRpc3BsYXksIHRoaXMuX21hc3RlclByb21pc2UuQ0xJUElELCB0aGlzLl9tYXN0ZXJQcm9taXNlLkZBS0VXSU4sIEN1cnJlbnRUaW1lKTsNCiAgICAgICAgICAgICAgICBYMTEuWFN5bmMobW9uWzBdLmRpc3BsYXksIDApOw0KDQogICAgICAgICAgICAgICAgdGhpcy5fbWFzdGVyUHJvbWlzZS5EZXNjcmlwdG9yRXZlbnQgPSByZXF1aXJlKCdEZXNjcmlwdG9yRXZlbnRzJykuYWRkRGVzY3JpcHRvcihYMTEuWENvbm5lY3Rpb25OdW1iZXIobW9uWzBdLmRpc3BsYXkpLlZhbCwgeyByZWFkc2V0OiB0cnVlIH0pOw0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuRGVzY3JpcHRvckV2ZW50Ll9tYXN0ZXJQcm9taXNlID0gdGhpcy5fbWFzdGVyUHJvbWlzZTsNCiAgICAgICAgICAgICAgICB0aGlzLl9tYXN0ZXJQcm9taXNlLkRlc2NyaXB0b3JFdmVudC5fZGlzcGxheSA9IG1vblswXS5kaXNwbGF5Ow0KICAgICAgICAgICAgICAgIHRoaXMuX21hc3RlclByb21pc2UuRGVzY3JpcHRvckV2ZW50Lm9uKCdyZWFkc2V0JywgZnVuY3Rpb24gKGZkKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdmFyIFhFID0gR00uQ3JlYXRlVmFyaWFibGUoMTAyNCk7DQogICAgICAgICAgICAgICAgICAgIHdoaWxlIChYMTEuWFBlbmRpbmcodGhpcy5fZGlzcGxheSkuVmFsKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBYMTEuWE5leHRFdmVudFN5bmModGhpcy5fZGlzcGxheSwgWEUpOw0KICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoIChYRS5EZXJlZigwLCA0KS50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKQ0KICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgU2VsZWN0aW9uQ2xlYXI6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuaW5mbzEoJ1NvbWVib2R5IGVsc2Ugb3ducyBjbGlwYm9hcmQnKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBTZWxlY3Rpb25SZXF1ZXN0Og0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmluZm8xKCdTb21lYm9keSB3YW50cyB1cyB0byBzZW5kIHRoZW0gZGF0YScpOw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldiA9IEdNLkNyZWF0ZVZhcmlhYmxlKEdNLlBvaW50ZXJTaXplID09IDggPyA3MiA6IDM2KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNyX3JlcXVlc3RvciA9IEdNLlBvaW50ZXJTaXplID09IDggPyBYRS5EZXJlZig0MCwgOCkgOiBYRS5EZXJlZigyMCwgNCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBz", 16000);
	memcpy_s(_clipboard + 16000, 7432, "cl9zZWxlY3Rpb24gPSBHTS5Qb2ludGVyU2l6ZSA9PSA4ID8gWEUuRGVyZWYoNDgsIDgpIDogWEUuRGVyZWYoMjQsIDQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3JfcHJvcGVydHkgPSBHTS5Qb2ludGVyU2l6ZSA9PSA4ID8gWEUuRGVyZWYoNjQsIDgpIDogWEUuRGVyZWYoMzIsIDQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3JfdGFyZ2V0ID0gR00uUG9pbnRlclNpemUgPT0gOCA/IFhFLkRlcmVmKDU2LCA4KSA6IFhFLkRlcmVmKDI4LCA0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNyX3RpbWUgPSBHTS5Qb2ludGVyU2l6ZSA9PSA4ID8gWEUuRGVyZWYoNzIsIDgpIDogWEUuRGVyZWYoMzYsIDQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3JfZGlzcGxheSA9IEdNLlBvaW50ZXJTaXplID09IDggPyBYRS5EZXJlZigyNCwgOCkgOiBYRS5EZXJlZigxMiwgNCk7DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXYuRGVyZWYoMCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKFNlbGVjdGlvbk5vdGlmeSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldl9yZXF1ZXN0b3IgPSBHTS5Qb2ludGVyU2l6ZSA9PSA4ID8gZXYuRGVyZWYoMzIsIDgpIDogZXYuRGVyZWYoMTYsIDQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXZfc2VsZWN0aW9uID0gR00uUG9pbnRlclNpemUgPT0gOCA/IGV2LkRlcmVmKDQwLCA4KSA6IGV2LkRlcmVmKDIwLCA0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2X3RhcmdldCA9IEdNLlBvaW50ZXJTaXplID09IDggPyBldi5EZXJlZig0OCwgOCkgOiBldi5EZXJlZigyNCwgNCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldl90aW1lID0gR00uUG9pbnRlclNpemUgPT0gOCA/IGV2LkRlcmVmKDY0LCA4KSA6IGV2LkRlcmVmKDMyLCA0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2X3Byb3BlcnR5ID0gR00uUG9pbnRlclNpemUgPT0gOCA/IGV2LkRlcmVmKDU2LCA4KSA6IGV2LkRlcmVmKDI4LCA0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNsaXB0ZXh0ID0gR00uQ3JlYXRlVmFyaWFibGUodGhpcy5fbWFzdGVyUHJvbWlzZS5fdHh0KTsNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcl9yZXF1ZXN0b3IuRGVyZWYoKS5wb2ludGVyQnVmZmVyKCkuY29weShldl9yZXF1ZXN0b3IudG9CdWZmZXIoKSk7IGNvbnNvbGUuaW5mbzEoJ1JFUVVFU1RPUjogJyArIHNyX3JlcXVlc3Rvci5EZXJlZigpLnBvaW50ZXJCdWZmZXIoKS50b1N0cmluZygnaGV4JykpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcl9zZWxlY3Rpb24uRGVyZWYoKS5wb2ludGVyQnVmZmVyKCkuY29weShldl9zZWxlY3Rpb24udG9CdWZmZXIoKSk7IGNvbnNvbGUuaW5mbzEoJ1NFTEVDVElPTjogJyArIHNyX3NlbGVjdGlvbi5EZXJlZigpLnBvaW50ZXJCdWZmZXIoKS50b1N0cmluZygnaGV4JykpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcl90YXJnZXQuRGVyZWYoKS5wb2ludGVyQnVmZmVyKCkuY29weShldl90YXJnZXQudG9CdWZmZXIoKSk7IGNvbnNvbGUuaW5mbzEoJ1RBUkdFVDogJyArIHNyX3RhcmdldC5EZXJlZigpLnBvaW50ZXJCdWZmZXIoKS50b1N0cmluZygnaGV4JykpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcl90aW1lLkRlcmVmKCkucG9pbnRlckJ1ZmZlcigpLmNvcHkoZXZfdGltZS50b0J1ZmZlcigpKTsgY29uc29sZS5pbmZvMSgnVElNRTogJyArIHNyX3RpbWUuRGVyZWYoKS5wb2ludGVyQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpKTsNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3JfdGFyZ2V0LkRlcmVmKCkuVmFsID09IHRoaXMuX21hc3RlclByb21pc2UuRk1USUQuVmFsKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmluZm8xKCdVVEY4IFJlcXVlc3QgZm9yOiAnICsgY2xpcHRleHQuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuaW5mbzEoc3JfZGlzcGxheS5WYWwsIHNyX3JlcXVlc3Rvci5EZXJlZigpLlZhbCwgc3JfcHJvcGVydHkuRGVyZWYoKS5WYWwsIHNyX3RhcmdldC5EZXJlZigpLlZhbCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBYMTEuWENoYW5nZVByb3BlcnR5KHNyX2Rpc3BsYXkuRGVyZWYoKSwgc3JfcmVxdWVzdG9yLkRlcmVmKCksIHNyX3Byb3BlcnR5LkRlcmVmKCksIHNyX3RhcmdldC5EZXJlZigpLCA4LCBQcm9wTW9kZVJlcGxhY2UsIGNsaXB0ZXh0LCBjbGlwdGV4dC5fc2l6ZSAtIDEpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgWDExLlhTeW5jKHNyX2Rpc3BsYXkuRGVyZWYoKSwgMCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcl9wcm9wZXJ0eS5EZXJlZigpLnBvaW50ZXJCdWZmZXIoKS5jb3B5KGV2X3Byb3BlcnR5LnRvQnVmZmVyKCkpOyANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuaW5mbzEoJ1Vua25vd24gRm9ybWF0IFJlcXVlc3QnKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV2X3Byb3BlcnR5LnBvaW50ZXJCdWZmZXIoKS53cml0ZVVJbnQzMkxFKE5vbmUpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgWDExLlhTZW5kRXZlbnQoc3JfZGlzcGxheS5EZXJlZigpLCBzcl9yZXF1ZXN0b3IuRGVyZWYoKSwgMSwgMCwgZXYpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9LCBjb25zb2xlLmxvZyk7DQogICAgfQ0KfQ0KDQpmdW5jdGlvbiB3aW5fcmVhZHRleHQoKQ0Kew0KICAgIHZhciByZXQgPSAnJzsNCiAgICB2YXIgQ0ZfVEVYVCA9IDE7DQogICAgdmFyIEdNID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7DQogICAgdmFyIHVzZXIzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCd1c2VyMzIuZGxsJyk7DQogICAgdmFyIGtlcm5lbDMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ2tlcm5lbDMyLmRsbCcpOw0KICAgIGtlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2xvYmFsQWxsb2MnKTsNCiAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dsb2JhbExvY2snKTsNCiAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dsb2JhbFVubG9jaycpOw0KICAgIHVzZXIzMi5DcmVhdGVNZXRob2QoJ09wZW5DbGlwYm9hcmQnKTsNCiAgICB1c2VyMzIuQ3JlYXRlTWV0aG9kKCdDbG9zZUNsaXBib2FyZCcpOw0KICAgIHVzZXIzMi5DcmVhdGVNZXRob2QoJ0dldENsaXBib2FyZERhdGEnKTsNCg0KICAgIHVzZXIzMi5PcGVuQ2xpcGJvYXJkKDApOw0KICAgIHZhciBoID0gdXNlcjMyLkdldENsaXBib2FyZERhdGEoQ0ZfVEVYVCk7DQogICAgaWYoaC5WYWwhPTApDQogICAgew0KICAgICAgICB2YXIgaGJ1ZmZlciA9IGtlcm5lbDMyLkdsb2JhbExvY2soaCk7DQogICAgICAgIHJldCA9IGhidWZmZXIuU3RyaW5nOw0KICAgICAgICBrZXJuZWwzMi5HbG9iYWxVbmxvY2soaCk7DQogICAgfQ0KICAgIHVzZXIzMi5DbG9zZUNsaXBib2FyZCgpOw0KDQogICAgdmFyIHAgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOw0KICAgIHAuX3JlcyhyZXQpOw0KICAgIHJldHVybiAocCk7DQp9DQoNCmZ1bmN0aW9uIHdpbl9jb3B5dGV4dCh0eHQpDQp7DQogICAgdmFyIEdNRU1fTU9WRUFCTEUgPSAweDAwMDI7DQogICAgdmFyIENGX1RFWFQgPSAxOw0KDQogICAgdmFyIEdNID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7DQogICAgdmFyIHVzZXIzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCd1c2VyMzIuZGxsJyk7DQogICAgdmFyIGtlcm5lbDMyID0gR00uQ3JlYXRlTmF0aXZlUHJveHkoJ2tlcm5lbDMyLmRsbCcpOw0KICAgIGtlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2xvYmFsQWxsb2MnKTsNCiAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dsb2JhbExvY2snKTsNCiAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dsb2JhbFVubG9jaycpOw0KICAgIHVzZXIzMi5DcmVhdGVNZXRob2QoJ09wZW5DbGlwYm9hcmQnKTsNCiAgICB1c2VyMzIuQ3JlYXRlTWV0aG9kKCdFbXB0eUNsaXBib2FyZCcpOw0KICAgIHVzZXIzMi5DcmVhdGVNZXRob2QoJ0Nsb3NlQ2xpcGJvYXJkJyk7DQogICAgdXNlcjMyLkNyZWF0ZU1ldGhvZCgnU2V0Q2xpcGJvYXJkRGF0YScpOw0KDQogICAgdmFyIGggPSBrZXJuZWwzMi5HbG9iYWxBbGxvYyhHTUVNX01PVkVBQkxFLCB0eHQubGVuZ3RoICsgMik7DQogICAgaC5hdXRvRnJlZShmYWxzZSk7DQogICAgdmFyIGhidWZmZXIgPSBrZXJuZWwzMi5HbG9iYWxMb2NrKGgpOw0KICAgIGhidWZmZXIuYXV0b0ZyZWUoZmFsc2UpOw0KICAgIHZhciB0bXAgPSBCdWZmZXIuYWxsb2ModHh0Lmxlbmd0aCArIDEpOw0KICAgIEJ1ZmZlci5mcm9tKHR4dCkuY29weSh0bXApOw0KICAgIHRtcC5jb3B5KGhidWZmZXIuRGVyZWYoMCwgdHh0Lmxlbmd0aCArIDEpLnRvQnVmZmVyKCkpOw0KICAgIGtlcm5lbDMyLkdsb2JhbFVubG9jayhoKTsNCg0KICAgIHVzZXIzMi5PcGVuQ2xpcGJvYXJkKDApOw0KICAgIHVzZXIzMi5FbXB0eUNsaXBib2FyZCgpOw0KICAgIHVzZXIzMi5TZXRDbGlwYm9hcmREYXRhKENGX1RFWFQsIGgpOw0KICAgIHVzZXIzMi5DbG9zZUNsaXBib2FyZCgpOw0KfQ0KDQpzd2l0Y2gocHJvY2Vzcy5wbGF0Zm9ybSkNCnsNCiAgICBjYXNlICd3aW4zMic6DQogICAgICAgIG1vZHVsZS5leHBvcnRzID0gd2luX2NvcHl0ZXh0Ow0KICAgICAgICBtb2R1bGUuZXhwb3J0cy5yZWFkID0gd2luX3JlYWR0ZXh0Ow0KICAgICAgICBicmVhazsNCiAgICBjYXNlICdsaW51eCc6DQogICAgICAgIG1vZHVsZS5leHBvcnRzID0gbGluX2NvcHl0ZXh0Ow0KICAgICAgICBtb2R1bGUuZXhwb3J0cy5yZWFkID0gbGluX3JlYWR0ZXh0Ow0KICAgICAgICBicmVhazsNCiAgICBjYXNlICdkYXJ3aW4nOg0KICAgICAgICBicmVhazsNCn0NCm1vZHVsZS5leHBvcnRzLm5hdGl2ZUFkZE1vZHVsZSA9IG5hdGl2ZUFkZE1vZHVsZTsNCm1vZHVsZS5leHBvcnRzLmRpc3BhdGNoV3JpdGUgPSBkaXNwYXRjaFdyaXRlOw0KbW9kdWxlLmV4cG9ydHMuZGlzcGF0Y2hSZWFkID0gZGlzcGF0Y2hSZWFkO/==", 7432);
	ILibBase64DecodeEx((unsigned char*)_clipboard, 23432, (unsigned char*)_clipboard + 23432);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "clipboard"); duk_push_string(ctx, _clipboard + 23432);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_clipboard);

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addModule('promise', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcmVmVGFibGUgPSB7fTsNCg0KZnVuY3Rpb24gZXZlbnRfc3dpdGNoZXJfaGVscGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAnZXZlbnRfc3dpdGNoZXInOw0KICAgIHRoaXMuZnVuYyA9IGZ1bmN0aW9uIGZ1bmMoKQ0KICAgIHsNCiAgICAgICAgdmFyIGFyZ3MgPSBbXTsNCiAgICAgICAgZm9yKHZhciBpIGluIGFyZ3VtZW50cykNCiAgICAgICAgew0KICAgICAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1tpXSk7DQogICAgICAgIH0NCiAgICAgICAgcmV0dXJuIChmdW5jLnRhcmdldC5hcHBseShmdW5jLmRlc2lyZWQsIGFyZ3MpKTsNCiAgICB9Ow0KICAgIHRoaXMuZnVuYy5kZXNpcmVkID0gZGVzaXJlZF9jYWxsZWU7DQogICAgdGhpcy5mdW5jLnRhcmdldCA9IHRhcmdldDsNCiAgICB0aGlzLmZ1bmMuc2VsZiA9IHRoaXM7DQp9DQpmdW5jdGlvbiBldmVudF9zd2l0Y2hlcihkZXNpcmVkX2NhbGxlZSwgdGFyZ2V0KQ0Kew0KICAgIHJldHVybiAobmV3IGV2ZW50X3N3aXRjaGVyX2hlbHBlcihkZXNpcmVkX2NhbGxlZSwgdGFyZ2V0KSk7DQp9DQoNCmZ1bmN0aW9uIFByb21pc2UocHJvbWlzZUZ1bmMpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAncHJvbWlzZSc7DQogICAgdGhpcy5wcm9taXNlID0gdGhpczsNCiAgICB0aGlzLl9pbnRlcm5hbCA9IHsgX09iamVjdElEOiAncHJvbWlzZS5pbnRlcm5hbCcsIHByb21pc2U6IHRoaXMsIGZ1bmM6IHByb21pc2VGdW5jLCBjb21wbGV0ZWQ6IGZhbHNlLCBlcnJvcnM6IGZhbHNlLCBjb21wbGV0ZWRBcmdzOiBbXSB9Ow0KICAgIHJlcXVpcmUoJ2V2ZW50cycpLkV2ZW50RW1pdHRlci5jYWxsKHRoaXMuX2ludGVybmFsKTsNCiAgICB0aGlzLl9pbnRlcm5hbC5vbignbmV3TGlzdGVuZXInLCBmdW5jdGlvbiAoZXZlbnROYW1lLCBldmVudENhbGxiYWNrKQ0KICAgIHsNCiAgICAgICAgLy9jb25zb2xlLmxvZygnbmV3TGlzdGVuZXInLCBldmVudE5hbWUsICdlcnJvcnMvJyArIHRoaXMuZXJyb3JzICsgJyBjb21wbGV0ZWQvJyArIHRoaXMuY29tcGxldGVkKTsNCiAgICAgICAgdmFyIHIgPSBudWxsOw0KDQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3Jlc29sdmVkJyAmJiAhdGhpcy5lcnJvcnMgJiYgdGhpcy5jb21wbGV0ZWQpDQogICAgICAgIHsNCiAgICAgICAgICAgIHIgPSBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIHRoaXMuY29tcGxldGVkQXJncyk7DQogICAgICAgICAgICBpZihyIT1udWxsKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnLCByKTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZWplY3RlZCcgJiYgdGhpcy5lcnJvcnMgJiYgdGhpcy5jb21wbGV0ZWQpDQogICAgICAgIHsNCiAgICAgICAgICAgIGV2ZW50Q2FsbGJhY2suYXBwbHkodGhpcywgdGhpcy5jb21wbGV0ZWRBcmdzKTsNCiAgICAgICAgfQ0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdzZXR0bGVkJyAmJiB0aGlzLmNvbXBsZXRlZCkNCiAgICAgICAgew0KICAgICAgICAgICAgZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCBbXSk7DQogICAgICAgIH0NCiAgICB9KTsNCiAgICB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlciA9IGZ1bmN0aW9uIF9yZXNvbHZlcigpDQogICAgew0KICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuZXJyb3JzID0gZmFsc2U7DQogICAgICAgIF9yZXNvbHZlci5fc2VsZi5jb21wbGV0ZWQgPSB0cnVlOw0KICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuY29tcGxldGVkQXJncyA9IFtdOw0KICAgICAgICB2YXIgYXJncyA9IFsncmVzb2x2ZWQnXTsNCiAgICAgICAgaWYgKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSAmJiB0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykgIT0gbnVsbCkNCiAgICAgICAgew0KICAgICAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZEFyZ3MucHVzaCh0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykpOw0KICAgICAgICAgICAgYXJncy5wdXNoKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICBmb3IgKHZhciBhIGluIGFyZ3VtZW50cykNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuY29tcGxldGVkQXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmVtaXQuYXBwbHkoX3Jlc29sdmVyLl9zZWxmLCBhcmdzKTsNCiAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmVtaXQoJ3NldHRsZWQnKTsNCiAgICB9Ow0KICAgIHRoaXMuX2ludGVybmFsLnJlamVjdG9yID0gZnVuY3Rpb24gX3JlamVjdG9yKCkNCiAgICB7DQogICAgICAgIF9yZWplY3Rvci5fc2VsZi5lcnJvcnMgPSB0cnVlOw0KICAgICAgICBfcmVqZWN0b3IuX3NlbGYuY29tcGxldGVkID0gdHJ1ZTsNCiAgICAgICAgX3JlamVjdG9yLl9zZWxmLmNvbXBsZXRlZEFyZ3MgPSBbXTsNCiAgICAgICAgdmFyIGFyZ3MgPSBbJ3JlamVjdGVkJ107DQogICAgICAgIGZvciAodmFyIGEgaW4gYXJndW1lbnRzKQ0KICAgICAgICB7DQogICAgICAgICAgICBfcmVqZWN0b3IuX3NlbGYuY29tcGxldGVkQXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2FdKTsNCiAgICAgICAgfQ0KDQogICAgICAgIF9yZWplY3Rvci5fc2VsZi5lbWl0LmFwcGx5KF9yZWplY3Rvci5fc2VsZiwgYXJncyk7DQogICAgICAgIF9yZWplY3Rvci5fc2VsZi5lbWl0KCdzZXR0bGVkJyk7DQogICAgfTsNCiAgICB0aGlzLmNhdGNoID0gZnVuY3Rpb24oZnVuYykNCiAgICB7DQogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3JlamVjdGVkJywgZXZlbnRfc3dpdGNoZXIodGhpcywgZnVuYykuZnVuYyk7DQogICAgfQ0KICAgIHRoaXMuZmluYWxseSA9IGZ1bmN0aW9uIChmdW5jKQ0KICAgIHsNCiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgnc2V0dGxlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIGZ1bmMpLmZ1bmMpOw0KICAgIH07DQogICAgdGhpcy50aGVuID0gZnVuY3Rpb24gKHJlc29sdmVkLCByZWplY3RlZCkNCiAgICB7DQogICAgICAgIGlmIChyZXNvbHZlZCkgeyB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIHJlc29sdmVkKS5mdW5jKTsgfQ0KICAgICAgICBpZiAocmVqZWN0ZWQpIHsgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCByZWplY3RlZCkuZnVuYyk7IH0NCg0KICAgICAgICB2YXIgcmV0VmFsID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHIsIGopIHsgfSk7DQogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3Jlc29sdmVkJywgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlcik7DQogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3JlamVjdGVkJywgcmV0VmFsLl9pbnRlcm5hbC5yZWplY3Rvcik7DQogICAgICAgIHJldFZhbC5wYXJlbnRQcm9taXNlID0gdGhpczsNCiAgICAgICAgcmV0dXJuIChyZXRWYWwpOw0KICAgIH07DQoNCiAgICB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlci5fc2VsZiA9IHRoaXMuX2ludGVybmFsOw0KICAgIHRoaXMuX2ludGVybmFsLnJlamVjdG9yLl9zZWxmID0gdGhpcy5faW50ZXJuYWw7Ow0KDQogICAgdHJ5DQogICAgew0KICAgICAgICBwcm9taXNlRnVuYy5jYWxsKHRoaXMsIHRoaXMuX2ludGVybmFsLnJlc29sdmVyLCB0aGlzLl9pbnRlcm5hbC5yZWplY3Rvcik7DQogICAgfQ0KICAgIGNhdGNoKGUpDQogICAgew0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lcnJvcnMgPSB0cnVlOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWQgPSB0cnVlOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWRBcmdzID0gW2VdOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lbWl0KCdyZWplY3RlZCcsIGUpOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lbWl0KCdzZXR0bGVkJyk7DQogICAgfQ0KDQogICAgaWYoIXRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCkNCiAgICB7DQogICAgICAgIC8vIFNhdmUgcmVmZXJlbmNlIG9mIHRoaXMgb2JqZWN0DQogICAgICAgIHJlZlRhYmxlW3RoaXMuX2ludGVybmFsLl9oYXNoQ29kZSgpXSA9IHRoaXMuX2ludGVybmFsOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZnVuY3Rpb24gKCkgeyByZWZUYWJsZVt0aGlzLl9oYXNoQ29kZSgpXSA9IG51bGw7IH0pOw0KICAgIH0NCn0NCg0KUHJvbWlzZS5yZXNvbHZlID0gZnVuY3Rpb24gcmVzb2x2ZSgpDQp7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpDQogICAgew0KICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2ldKTsNCiAgICB9DQogICAgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlci5hcHBseShyZXRWYWwuX2ludGVybmFsLCBhcmdzKTsNCiAgICByZXR1cm4gKHJldFZhbCk7DQp9Ow0KUHJvbWlzZS5yZWplY3QgPSBmdW5jdGlvbiByZWplY3QoKSB7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpIHsNCiAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1tpXSk7DQogICAgfQ0KICAgIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IuYXBwbHkocmV0VmFsLl9pbnRlcm5hbCwgYXJncyk7DQogICAgcmV0dXJuIChyZXRWYWwpOw0KfTsNClByb21pc2UuYWxsID0gZnVuY3Rpb24gYWxsKHByb21pc2VMaXN0KQ0Kew0KICAgIHZhciByZXQgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopDQogICAgew0KICAgICAgICB0aGlzLl9fcmVqZWN0b3IgPSByZWo7DQogICAgICAgIHRoaXMuX19yZXNvbHZlciA9IHJlczsNCiAgICAgICAgdGhpcy5fX3Byb21pc2VMaXN0ID0gcHJvbWlzZUxpc3Q7DQogICAgICAgIHRoaXMuX19kb25lID0gZmFsc2U7DQogICAgICAgIHRoaXMuX19jb3VudCA9IDA7DQogICAgfSk7DQoNCiAgICBmb3IgKHZhciBpIGluIHByb21pc2VMaXN0KQ0KICAgIHsNCiAgICAgICAgcHJvbWlzZUxpc3RbaV0udGhlbihmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBTdWNjZXNzDQogICAgICAgICAgICBpZigrK3JldC5fX2NvdW50ID09IHJldC5fX3Byb21pc2VMaXN0Lmxlbmd0aCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXQuX19kb25lID0gdHJ1ZTsNCiAgICAgICAgICAgICAgICByZXQuX19yZXNvbHZlcihyZXQuX19wcm9taXNlTGlzdCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0sIGZ1bmN0aW9uIChhcmcpDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vIEZhaWx1cmUNCiAgICAgICAgICAgIGlmKCFyZXQuX19kb25lKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJldC5fX2RvbmUgPSB0cnVlOw0KICAgICAgICAgICAgICAgIHJldC5fX3JlamVjdG9yKGFyZyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgIH0NCiAgICBpZiAocHJvbWlzZUxpc3QubGVuZ3RoID09IDApDQogICAgew0KICAgICAgICByZXQuX19yZXNvbHZlcihwcm9taXNlTGlzdCk7DQogICAgfQ0KICAgIHJldHVybiAocmV0KTsNCn07DQoNCm1vZHVsZS5leHBvcnRzID0gUHJvbWlzZTsNCm1vZHVsZS5leHBvcnRzLmV2ZW50X3N3aXRjaGVyID0gZXZlbnRfc3dpdGNoZXI7', 'base64').toString());");

#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addModule('win-registry', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBLRVlfUVVFUllfVkFMVUUgPSAweDAwMDE7CnZhciBLRVlfRU5VTUVSQVRFX1NVQl9LRVlTID0gMHgwMDA4Owp2YXIgS0VZX1dSSVRFID0gMHgyMDAwNjsKCnZhciBLRVlfREFUQV9UWVBFUyA9CiAgICB7CiAgICAgICAgUkVHX05PTkU6IDAsCiAgICAgICAgUkVHX1NaOiAxLAogICAgICAgIFJFR19FWFBBTkRfU1o6IDIsCiAgICAgICAgUkVHX0JJTkFSWTogMywKICAgICAgICBSRUdfRFdPUkQ6IDQsCiAgICAgICAgUkVHX0RXT1JEX0JJR19FTkRJQU46IDUsCiAgICAgICAgUkVHX0xJTks6IDYsCiAgICAgICAgUkVHX01VTFRJX1NaOiA3LAogICAgICAgIFJFR19SRVNPVVJDRV9MSVNUOiA4LAogICAgICAgIFJFR19GVUxMX1JFU09VUkNFX0RFU0NSSVBUT1I6IDksCiAgICAgICAgUkVHX1JFU09VUkNFX1JFUVVJUkVNRU5UU19MSVNUOiAxMCwKICAgICAgICBSRUdfUVdPUkQ6IDExCiAgICB9OwoKZnVuY3Rpb24gd2luZG93c19yZWdpc3RyeSgpCnsKICAgIHRoaXMuX09iamVjdElkID0gJ3dpbi1yZWdpc3RyeSc7CiAgICB0aGlzLl9tYXJzaGFsID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICB0aGlzLl9BZHZBcGkgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdBZHZhcGkzMi5kbGwnKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0NyZWF0ZUtleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnRW51bUtleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnRW51bVZhbHVlQScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnT3BlbktleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnUXVlcnlJbmZvS2V5QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnUXVlcnlWYWx1ZUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnQ2xvc2VLZXknKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0RlbGV0ZUtleUEnKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0RlbGV0ZVZhbHVlQScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnU2V0VmFsdWVFeEEnKTsKICAgIHRoaXMuSEtFWSA9IHsgUm9vdDogQnVmZmVyLmZyb20oJzgwMDAwMDAwJywgJ2hleCcpLnN3YXAzMigpLCBDdXJyZW50VXNlcjogQnVmZmVyLmZyb20oJzgwMDAwMDAxJywgJ2hleCcpLnN3YXAzMigpLCBMb2NhbE1hY2hpbmU6IEJ1ZmZlci5mcm9tKCc4MDAwMDAwMicsICdoZXgnKS5zd2FwMzIoKSwgVXNlcnM6IEJ1ZmZlci5mcm9tKCc4MDAwMDAwMycsICdoZXgnKS5zd2FwMzIoKSB9OwoKICAgIHRoaXMuUXVlcnlLZXkgPSBmdW5jdGlvbiBRdWVyeUtleShoa2V5LCBwYXRoLCBrZXkpCiAgICB7CiAgICAgICAgdmFyIGVycjsKICAgICAgICB2YXIgaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgIHZhciBsZW4gPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgIHZhciB2YWxUeXBlID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsKICAgICAgICB2YXIgSEsgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSk7CiAgICAgICAgdmFyIHJldFZhbCA9IG51bGw7CiAgICAgICAgaWYgKGtleSkgeyBrZXkgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSk7IH0KICAgICAgICBpZiAoIXBhdGgpIHsgcGF0aCA9ICcnOyB9CgoKICAgICAgICBpZiAoKGVyciA9IHRoaXMuX0FkdkFwaS5SZWdPcGVuS2V5RXhBKEhLLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKHBhdGgpLCAwLCBLRVlfUVVFUllfVkFMVUUgfCBLRVlfRU5VTUVSQVRFX1NVQl9LRVlTLCBoKS5WYWwpICE9IDApCiAgICAgICAgewogICAgICAgICAgICB0aHJvdyAoJ09wZW5pbmcgUmVnaXN0cnkgS2V5OiAnICsgcGF0aCArICcgPT4gUmV0dXJuZWQgRXJyb3I6ICcgKyBlcnIpOwogICAgICAgIH0KICAKICAgICAgICBpZiAoKHBhdGggPT0gJycgJiYgIWtleSkgfHwgIWtleSkKICAgICAgICB7DQogICAgICAgICAgICB2YXIgcmVzdWx0ID0geyBzdWJrZXlzOiBbXSwgdmFsdWVzOiBbXSB9Ow0KDQogICAgICAgICAgICAvLyBFbnVtZXJhdGUgIGtleXMNCiAgICAgICAgICAgIHZhciBhY2hDbGFzcyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoMTAyNCk7DQogICAgICAgICAgICB2YXIgYWNoS2V5ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSgxMDI0KTsNCiAgICAgICAgICAgIHZhciBhY2hWYWx1ZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoMzI3NjgpOw0KICAgICAgICAgICAgdmFyIGFjaFZhbHVlU2l6ZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbmFtZVNpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOyANCiAgICAgICAgICAgIHZhciBhY2hDbGFzc1NpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOyBhY2hDbGFzc1NpemUudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEwMjQpOw0KICAgICAgICAgICAgdmFyIG51bVN1YktleXMgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOw0KICAgICAgICAgICAgdmFyIG51bVZhbHVlcyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFN1YmtleVNpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOw0KICAgICAgICAgICAgdmFyIGxvbmdlc3RDbGFzc1N0cmluZyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFZhbHVlTmFtZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFZhbHVlRGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgc2VjdXJpdHlEZXNjcmlwdG9yID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsNCiAgICAgICAgICAgIHZhciBsYXN0V3JpdGVUaW1lID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg4KTsNCg0KICAgICAgICAgICAgcmV0VmFsID0gdGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5SW5mb0tleUEoaC5EZXJlZigpLCBhY2hDbGFzcywgYWNoQ2xhc3NTaXplLCAwLA0KICAgICAgICAgICAgICAgIG51bVN1YktleXMsIGxvbmdlc3RTdWJrZXlTaXplLCBsb25nZXN0Q2xhc3NTdHJpbmcsIG51bVZhbHVlcywNCiAgICAgICAgICAgICAgICBsb25nZXN0VmFsdWVOYW1lLCBsb25nZXN0VmFsdWVEYXRhLCBzZWN1cml0eURlc2NyaXB0b3IsIGxhc3RXcml0ZVRpbWUpOw0KICAgICAgICAgICAgaWYgKHJldFZhbC5WYWwgIT0gMCkgeyB0aHJvdyAoJ1JlZ1F1ZXJ5SW5mb0tleUEoKSByZXR1cm5lZCBlcnJvcjogJyArIHJldFZhbC5WYWwpOyB9DQogICAgICAgICAgICBmb3IodmFyIGkgPSAwOyBpIDwgbnVtU3ViS2V5cy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpOyArK2kpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgbmFtZVNpemUudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEwMjQpOw0KICAgICAgICAgICAgICAgIHJldFZhbCA9IHRoaXMuX0FkdkFwaS5SZWdFbnVtS2V5RXhBKGguRGVyZWYoKSwgaSwgYWNoS2V5LCBuYW1lU2l6ZSwgMCwgMCwgMCwgbGFzdFdyaXRlVGltZSk7DQogICAgICAgICAgICAgICAgaWYocmV0VmFsLlZhbCA9PSAwKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnN1YmtleXMucHVzaChhY2hLZXkuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IG51bVZhbHVlcy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpIDsgKytpKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGFjaFZhbHVlU2l6ZS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzI3NjgpOw0KICAgICAgICAgICAgICAgIGlmKHRoaXMuX0FkdkFwaS5SZWdFbnVtVmFsdWVBKGguRGVyZWYoKSwgaSwgYWNoVmFsdWUsIGFjaFZhbHVlU2l6ZSwgMCwgMCwgMCwgMCkuVmFsID09IDApDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXN1bHQudmFsdWVzLnB1c2goYWNoVmFsdWUuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICByZXR1cm4gKHJlc3VsdCk7DQogICAgICAgIH0KCiAgICAgICAgaWYodGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5VmFsdWVFeEEoaC5EZXJlZigpLCBrZXksIDAsIDAsIDAsIGxlbikuVmFsID09IDApCiAgICAgICAgewogICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUobGVuLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpOwogICAgICAgICAgICBpZiAodGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5VmFsdWVFeEEoaC5EZXJlZigpLCBrZXksIDAsIHZhbFR5cGUsIGRhdGEsIGxlbikuVmFsID09IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHN3aXRjaCh2YWxUeXBlLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBLRVlfREFUQV9UWVBFUy5SRUdfRFdPUkQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbCA9IGRhdGEudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKTsKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBLRVlfREFUQV9UWVBFUy5SRUdfRFdPUkRfQklHX0VORElBTjoKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsID0gZGF0YS50b0J1ZmZlcigpLnJlYWRVSW50MzJCRSgpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBjYXNlIEtFWV9EQVRBX1RZUEVTLlJFR19TWjoKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsID0gZGF0YS5TdHJpbmc7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgS0VZX0RBVEFfVFlQRVMuUkVHX0JJTkFSWToKICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwgPSBkYXRhLnRvQnVmZmVyKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5fZGF0YSA9IGRhdGE7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuX0FkdkFwaS5SZWdDbG9zZUtleShoLkRlcmVmKCkpOwogICAgICAgICAgICB0aHJvdyAoJ05vdCBGb3VuZCcpOwogICAgICAgIH0KICAgICAgICB0aGlzLl9BZHZBcGkuUmVnQ2xvc2VLZXkoaC5EZXJlZigpKTsKICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICB9OwogICAgdGhpcy5Xcml0ZUtleSA9IGZ1bmN0aW9uIFdyaXRlS2V5KGhrZXksIHBhdGgsIGtleSwgdmFsdWUpCiAgICB7CiAgICAgICAgdmFyIHJlc3VsdDsKICAgICAgICB2YXIgaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwoKICAgICAgICBpZiAodGhpcy5fQWR2QXBpLlJlZ0NyZWF0ZUtleUV4QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCksIDAsIDAsIDAsIEtFWV9XUklURSwgMCwgaCwgMCkuVmFsICE9IDApCiAgICAgICAgewogICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIE9wZW5pbmcgUmVnaXN0cnkgS2V5OiAnICsgcGF0aCk7CiAgICAgICAgfQoKICAgICAgICB2YXIgZGF0YTsKICAgICAgICB2YXIgZGF0YVR5cGU7CgogICAgICAgIHN3aXRjaCh0eXBlb2YodmFsdWUpKQogICAgICAgIHsKICAgICAgICAgICAgY2FzZSAnYm9vbGVhbic6CiAgICAgICAgICAgICAgICBkYXRhVHlwZSA9IEtFWV9EQVRBX1RZUEVTLlJFR19EV09SRDsKICAgICAgICAgICAgICAgIGRhdGEgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgICAgICAgICAgZGF0YS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUodmFsdWUgPyAxIDogMCk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnbnVtYmVyJzoKICAgICAgICAgICAgICAgIGRhdGFUeXBlID0gS0VZX0RBVEFfVFlQRVMuUkVHX0RXT1JEOwogICAgICAgICAgICAgICAgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7CiAgICAgICAgICAgICAgICBkYXRhLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSh2YWx1ZSk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnc3RyaW5nJzoKICAgICAgICAgICAgICAgIGRhdGFUeXBlID0gS0VZX0RBVEFfVFlQRVMuUkVHX1NaOwogICAgICAgICAgICAgICAgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUodmFsdWUpOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICBkYXRhVHlwZSA9IEtFWV9EQVRBX1RZUEVTLlJFR19CSU5BUlk7CiAgICAgICAgICAgICAgICBkYXRhID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSh2YWx1ZS5sZW5ndGgpOwogICAgICAgICAgICAgICAgdmFsdWUuY29weShkYXRhLnRvQnVmZmVyKCkpOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQoKICAgICAgICBpZih0aGlzLl9BZHZBcGkuUmVnU2V0VmFsdWVFeEEoaC5EZXJlZigpLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSksIDAsIGRhdGFUeXBlLCBkYXRhLCBkYXRhLl9zaXplKS5WYWwgIT0gMCkKICAgICAgICB7ICAgICAgICAgICAKICAgICAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICAgICAgICAgIHRocm93ICgnRXJyb3Igd3JpdGluZyByZWcga2V5OiAnICsga2V5KTsKICAgICAgICB9CiAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICB9OwogICAgdGhpcy5EZWxldGVLZXkgPSBmdW5jdGlvbiBEZWxldGVLZXkoaGtleSwgcGF0aCwga2V5KQogICAgewogICAgICAgIGlmKCFrZXkpCiAgICAgICAgewogICAgICAgICAgICBpZih0aGlzLl9BZHZBcGkuUmVnRGVsZXRlS2V5QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCkpLlZhbCAhPSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIERlbGV0aW5nIEtleTogJyArIHBhdGgpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHZhciBoID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciByZXN1bHQ7CiAgICAgICAgICAgIGlmICh0aGlzLl9BZHZBcGkuUmVnT3BlbktleUV4QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCksIDAsIEtFWV9RVUVSWV9WQUxVRSB8IEtFWV9XUklURSwgaCkuVmFsICE9IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRocm93ICgnRXJyb3IgT3BlbmluZyBSZWdpc3RyeSBLZXk6ICcgKyBwYXRoKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoKHJlc3VsdCA9IHRoaXMuX0FkdkFwaS5SZWdEZWxldGVWYWx1ZUEoaC5EZXJlZigpLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSkpLlZhbCkgIT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yWycgKyByZXN1bHQgKyAnXSBEZWxldGluZyBLZXk6ICcgKyBwYXRoICsgJy4nICsga2V5KTsKICAgICAgICAgICAgfQogICAgICAgICAgICB0aGlzLl9BZHZBcGkuUmVnQ2xvc2VLZXkoaC5EZXJlZigpKTsKICAgICAgICB9CiAgICB9Owp9Cgptb2R1bGUuZXhwb3J0cyA9IG5ldyB3aW5kb3dzX3JlZ2lzdHJ5KCk7Cgo=', 'base64').toString());");
	
	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addModule('PE_Parser', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCi8vIFJldHVybiBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIGV4ZWN1dGFibGUKZnVuY3Rpb24gcGFyc2UoZXhlUGF0aCkKewogICAgdmFyIHJldFZhbCA9IHt9OwogICAgdmFyIGZzID0gcmVxdWlyZSgnZnMnKTsKICAgIHZhciBmZCA9IGZzLm9wZW5TeW5jKGV4ZVBhdGgsICdyYicpOwogICAgdmFyIGJ5dGVzUmVhZDsKICAgIHZhciBkb3NIZWFkZXIgPSBCdWZmZXIuYWxsb2MoNjQpOwogICAgdmFyIG50SGVhZGVyID0gQnVmZmVyLmFsbG9jKDI0KTsKICAgIHZhciBvcHRIZWFkZXI7CgogICAgLy8gUmVhZCB0aGUgRE9TIGhlYWRlcgogICAgYnl0ZXNSZWFkID0gZnMucmVhZFN5bmMoZmQsIGRvc0hlYWRlciwgMCwgNjQsIDApOwogICAgaWYgKGRvc0hlYWRlci5yZWFkVUludDE2TEUoMCkudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkgIT0gJzVBNEQnKQogICAgewogICAgICAgIHRocm93ICgndW5yZWNvZ25pemVkIGJpbmFyeSBmb3JtYXQnKTsKICAgIH0KCiAgICAvLyBSZWFkIHRoZSBOVCBoZWFkZXIKICAgIGJ5dGVzUmVhZCA9IGZzLnJlYWRTeW5jKGZkLCBudEhlYWRlciwgMCwgbnRIZWFkZXIubGVuZ3RoLCBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSk7CiAgICBpZiAobnRIZWFkZXIuc2xpY2UoMCwgNCkudG9TdHJpbmcoJ2hleCcpICE9ICc1MDQ1MDAwMCcpCiAgICB7CiAgICAgICAgdGhyb3cgKCdub3QgYSBQRSBmaWxlJyk7CiAgICB9CiAgICBzd2l0Y2ggKG50SGVhZGVyLnJlYWRVSW50MTZMRSg0KS50b1N0cmluZygxNikpCiAgICB7CiAgICAgICAgY2FzZSAnMTRjJzogLy8gMzIgYml0CiAgICAgICAgICAgIHJldFZhbC5mb3JtYXQgPSAneDg2JzsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAnODY2NCc6IC8vIDY0IGJpdAogICAgICAgICAgICByZXRWYWwuZm9ybWF0ID0gJ3g2NCc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGRlZmF1bHQ6IC8vIFVua25vd24KICAgICAgICAgICAgcmV0VmFsLmZvcm1hdCA9IHVuZGVmaW5lZDsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CgogICAgcmV0VmFsLm9wdGlvbmFsSGVhZGVyU2l6ZSA9IG50SGVhZGVyLnJlYWRVSW50MTZMRSgyMCk7CiAgICByZXRWYWwub3B0aW9uYWxIZWFkZXJTaXplQWRkcmVzcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjA7CgogICAgLy8gUmVhZCB0aGUgb3B0aW9uYWwgaGVhZGVyCiAgICBvcHRIZWFkZXIgPSBCdWZmZXIuYWxsb2MobnRIZWFkZXIucmVhZFVJbnQxNkxFKDIwKSk7CiAgICBieXRlc1JlYWQgPSBmcy5yZWFkU3luYyhmZCwgb3B0SGVhZGVyLCAwLCBvcHRIZWFkZXIubGVuZ3RoLCBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSArIDI0KTsKICAgIHZhciBudW1SVkEgPSB1bmRlZmluZWQ7CgogICAgcmV0VmFsLkNoZWNrU3VtUG9zID0gZG9zSGVhZGVyLnJlYWRVSW50MzJMRSg2MCkgKyAyNCArIDY0OwogICAgcmV0VmFsLlNpemVPZkNvZGUgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDQpOwogICAgcmV0VmFsLlNpemVPZkluaXRpYWxpemVkRGF0YSA9IG9wdEhlYWRlci5yZWFkVUludDMyTEUoOCk7CiAgICByZXRWYWwuU2l6ZU9mVW5Jbml0aWFsaXplZERhdGEgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDEyKTsKCiAgICBzd2l0Y2ggKG9wdEhlYWRlci5yZWFkVUludDE2TEUoMCkudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkpCiAgICB7CiAgICAgICAgY2FzZSAnMTBCJzogLy8gMzIgYml0IGJpbmFyeQogICAgICAgICAgICBudW1SVkEgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDkyKTsKICAgICAgICAgICAgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzID0gb3B0SGVhZGVyLnJlYWRVSW50MzJMRSgxMjgpOwogICAgICAgICAgICByZXRWYWwuQ2VydGlmaWNhdGVUYWJsZVNpemUgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDEzMik7CiAgICAgICAgICAgIHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlU2l6ZVBvcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjQgKyAxMzI7CiAgICAgICAgICAgIHJldFZhbC5ydmFTdGFydEFkZHJlc3MgPSBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSArIDI0ICsgOTY7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgJzIwQic6IC8vIDY0IGJpdCBiaW5hcnkKICAgICAgICAgICAgbnVtUlZBID0gb3B0SGVhZGVyLnJlYWRVSW50MzJMRSgxMDgpOwogICAgICAgICAgICByZXRWYWwuQ2VydGlmaWNhdGVUYWJsZUFkZHJlc3MgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDE0NCk7CiAgICAgICAgICAgIHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlU2l6ZSA9IG9wdEhlYWRlci5yZWFkVUludDMyTEUoMTQ4KTsKICAgICAgICAgICAgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVTaXplUG9zID0gZG9zSGVhZGVyLnJlYWRVSW50MzJMRSg2MCkgKyAyNCArIDE0ODsKICAgICAgICAgICAgcmV0VmFsLnJ2YVN0YXJ0QWRkcmVzcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjQgKyAxMTI7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgIHRocm93ICgnVW5rbm93biBWYWx1ZSBmb3VuZCBmb3IgT3B0aW9uYWwgTWFnaWM6ICcgKyBudEhlYWRlci5yZWFkVUludDE2TEUoMjQpLnRvU3RyaW5nKDE2KS50b1VwcGVyQ2FzZSgpKTsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CiAgICByZXRWYWwucnZhQ291bnQgPSBudW1SVkE7CgogICAgaWYgKHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlQWRkcmVzcykKICAgIHsKICAgICAgICAvLyBSZWFkIHRoZSBhdXRoZW50aWNvZGUgY2VydGlmaWNhdGUsIG9ubHkgb25lIGNlcnQgKG9ubHkgdGhlIGZpcnN0IGVudHJ5KQogICAgICAgIHZhciBoZHIgPSBCdWZmZXIuYWxsb2MoOCk7CiAgICAgICAgZnMucmVhZFN5bmMoZmQsIGhkciwgMCwgaGRyLmxlbmd0aCwgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzKTsKICAgICAgICByZXRWYWwuY2VydGlmaWNhdGUgPSBCdWZmZXIuYWxsb2MoaGRyLnJlYWRVSW50MzJMRSgwKSk7CiAgICAgICAgZnMucmVhZFN5bmMoZmQsIHJldFZhbC5jZXJ0aWZpY2F0ZSwgMCwgcmV0VmFsLmNlcnRpZmljYXRlLmxlbmd0aCwgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzICsgaGRyLmxlbmd0aCk7CiAgICAgICAgcmV0VmFsLmNlcnRpZmljYXRlID0gcmV0VmFsLmNlcnRpZmljYXRlLnRvU3RyaW5nKCdiYXNlNjQnKTsKICAgICAgICByZXRWYWwuY2VydGlmaWNhdGVEd0xlbmd0aCA9IGhkci5yZWFkVUludDMyTEUoMCk7CiAgICB9CiAgICBmcy5jbG9zZVN5bmMoZmQpOwogICAgcmV0dXJuIChyZXRWYWwpOwp9Cgptb2R1bGUuZXhwb3J0cyA9IHBhcnNlOwoKCv==', 'base64').toString());");

	// Windows Message Pump, refer to modules/win-message-pump.js
	duk_peval_string_noresult(ctx, "addModule('win-message-pump', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgV0hfQ0FMTFdORFBST0MgPSA0Ow0KdmFyIFdNX1FVSVQgPSAgMHgwMDEyOw0KDQp2YXIgR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsNCg0KZnVuY3Rpb24gV2luZG93c01lc3NhZ2VQdW1wKG9wdGlvbnMpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAnd2luLW1lc3NhZ2UtcHVtcCc7DQogICAgdGhpcy5fb3B0aW9ucyA9IG9wdGlvbnM7DQogICAgdmFyIGVtaXR0ZXJVdGlscyA9IHJlcXVpcmUoJ2V2ZW50cycpLmluaGVyaXRzKHRoaXMpOw0KICAgIGVtaXR0ZXJVdGlscy5jcmVhdGVFdmVudCgnaHduZCcpOw0KICAgIGVtaXR0ZXJVdGlscy5jcmVhdGVFdmVudCgnZXJyb3InKTsNCiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ21lc3NhZ2UnKTsNCiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ2V4aXQnKTsNCg0KICAgIHRoaXMuX21zZyA9IEdNLkNyZWF0ZVZhcmlhYmxlKEdNLlBvaW50ZXJTaXplID09IDQgPyAyOCA6IDQ4KTsNCiAgICB0aGlzLl9rZXJuZWwzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdLZXJuZWwzMi5kbGwnKTsNCiAgICB0aGlzLl9rZXJuZWwzMi5tcCA9IHRoaXM7DQogICAgdGhpcy5fa2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdHZXRMYXN0RXJyb3InKTsNCiAgICB0aGlzLl9rZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldE1vZHVsZUhhbmRsZUEnKTsNCg0KICAgIHRoaXMuX3VzZXIzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdVc2VyMzIuZGxsJyk7DQogICAgdGhpcy5fdXNlcjMyLm1wID0gdGhpczsNCiAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKCdHZXRNZXNzYWdlQScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ0NyZWF0ZVdpbmRvd0V4QScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ1RyYW5zbGF0ZU1lc3NhZ2UnKTsNCiAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKCdEaXNwYXRjaE1lc3NhZ2VBJyk7DQogICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnUmVnaXN0ZXJDbGFzc0V4QScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ0RlZldpbmRvd1Byb2NBJyk7DQogICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnUG9zdE1lc3NhZ2VBJyk7DQoNCg0KICAgIHRoaXMud25kY2xhc3MgPSBHTS5DcmVhdGVWYXJpYWJsZShHTS5Qb2ludGVyU2l6ZSA9PSA0ID8gNDggOiA4MCk7DQogICAgdGhpcy53bmRjbGFzcy5tcCA9IHRoaXM7DQogICAgdGhpcy53bmRjbGFzcy5oaW5zdGFuY2UgPSB0aGlzLl9rZXJuZWwzMi5HZXRNb2R1bGVIYW5kbGVBKDApOw0KICAgIHRoaXMud25kY2xhc3MuY25hbWUgPSBHTS5DcmVhdGVWYXJpYWJsZSgnTWFpbldXV0NsYXNzJyk7DQogICAgdGhpcy53bmRjbGFzcy53bmRwcm9jID0gR00uR2V0R2VuZXJpY0dsb2JhbENhbGxiYWNrKDQpOw0KICAgIHRoaXMud25kY2xhc3Mud25kcHJvYy5tcCA9IHRoaXM7DQogICAgdGhpcy53bmRjbGFzcy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUodGhpcy53bmRjbGFzcy5fc2l6ZSk7DQogICAgdGhpcy53bmRjbGFzcy5jbmFtZS5wb2ludGVyQnVmZmVyKCkuY29weSh0aGlzLnduZGNsYXNzLkRlcmVmKEdNLlBvaW50ZXJTaXplID09IDQgPyA0MCA6IDY0LCBHTS5Qb2ludGVyU2l6ZSkudG9CdWZmZXIoKSk7DQogICAgdGhpcy53bmRjbGFzcy53bmRwcm9jLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHRoaXMud25kY2xhc3MuRGVyZWYoOCwgR00uUG9pbnRlclNpemUpLnRvQnVmZmVyKCkpOw0KICAgIHRoaXMud25kY2xhc3MuaGluc3RhbmNlLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHRoaXMud25kY2xhc3MuRGVyZWYoR00uUG9pbnRlclNpemUgPT0gNCA/IDIwIDogMjQsIEdNLlBvaW50ZXJTaXplKS50b0J1ZmZlcigpKTsNCiAgICB0aGlzLnduZGNsYXNzLnduZHByb2Mub24oJ0dsb2JhbENhbGxiYWNrJywgZnVuY3Rpb24gb25XbmRQcm9jKHhod25kLCB4bXNnLCB3cGFyYW0sIGxwYXJhbSkNCiAgICB7DQogICAgICAgIGlmICh0aGlzLm1wLl9od25kICE9IG51bGwgJiYgdGhpcy5tcC5faHduZC5WYWwgPT0geGh3bmQuVmFsKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBUaGlzIGlzIGZvciB1cw0KICAgICAgICAgICAgdGhpcy5tcC5lbWl0KCdtZXNzYWdlJywgeyBtZXNzYWdlOiB4bXNnLlZhbCwgd3BhcmFtOiB3cGFyYW0uVmFsLCBscGFyYW06IGxwYXJhbS5WYWwsIGxwYXJhbV9oZXg6IGxwYXJhbS5wb2ludGVyQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpIH0pOw0KICAgICAgICAgICAgcmV0dXJuICh0aGlzLm1wLl91c2VyMzIuRGVmV2luZG93UHJvY0EoeGh3bmQsIHhtc2csIHdwYXJhbSwgbHBhcmFtKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZSBpZih0aGlzLm1wLl9od25kID09IG51bGwgJiYgdGhpcy5DYWxsaW5nVGhyZWFkKCkgPT0gdGhpcy5tcC5fdXNlcjMyLlJlZ2lzdGVyQ2xhc3NFeEEuYXN5bmMudGhyZWFkSWQoKSkNCiAgICAgICAgew0KICAgICAgICAgICAgLy8gVGhpcyBtZXNzYWdlIHdhcyBnZW5lcmF0ZWQgZnJvbSBvdXIgQ3JlYXRlV2luZG93RXhBIG1ldGhvZA0KICAgICAgICAgICAgcmV0dXJuICh0aGlzLm1wLl91c2VyMzIuRGVmV2luZG93UHJvY0EoeGh3bmQsIHhtc2csIHdwYXJhbSwgbHBhcmFtKSk7DQogICAgICAgIH0NCiAgICB9KTsNCg0KICAgIHRoaXMuX3VzZXIzMi5SZWdpc3RlckNsYXNzRXhBLmFzeW5jKHRoaXMud25kY2xhc3MpLnRoZW4oZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIHRoaXMubmF0aXZlUHJveHkuQ3JlYXRlV2luZG93RXhBLmFzeW5jKHRoaXMubmF0aXZlUHJveHkuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgMHgwMDAwMDA4OCwgdGhpcy5uYXRpdmVQcm94eS5tcC53bmRjbGFzcy5jbmFtZSwgMCwgMHgwMDgwMDAwMCwgMCwgMCwgMTAwLCAxMDAsIDAsIDAsIDAsIDApDQogICAgICAgICAgICAudGhlbihmdW5jdGlvbihoKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGlmIChoLlZhbCA9PSAwKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgLy8gRXJyb3IgY3JlYXRpbmcgaGlkZGVuIHdpbmRvdw0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5Lm1wLmVtaXQoJ2Vycm9yJywgJ0Vycm9yIGNyZWF0aW5nIGhpZGRlbiB3aW5kb3cnKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5faHduZCA9IGg7DQogICAgICAgICAgICAgICAgICAgIHRoaXMubmF0aXZlUHJveHkubXAuZW1pdCgnaHduZCcsIGgpOw0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5Lm1wLl9zdGFydFB1bXAoKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9KTsNCiAgICB9KTsNCiAgICB0aGlzLl9zdGFydFB1bXAgPSBmdW5jdGlvbiBfc3RhcnRQdW1wKCkNCiAgICB7DQogICAgICAgIHRoaXMuX3VzZXIzMi5HZXRNZXNzYWdlQS5hc3luYyh0aGlzLl91c2VyMzIuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgdGhpcy5fbXNnLCB0aGlzLl9od25kLCAwLCAwKS50aGVuKGZ1bmN0aW9uIChyKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZihyLlZhbCA+IDApDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5UcmFuc2xhdGVNZXNzYWdlLmFzeW5jKHRoaXMubmF0aXZlUHJveHkuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgdGhpcy5uYXRpdmVQcm94eS5tcC5fbXNnKS50aGVuKGZ1bmN0aW9uICgpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5LkRpc3BhdGNoTWVzc2FnZUEuYXN5bmModGhpcy5uYXRpdmVQcm94eS5SZWdpc3RlckNsYXNzRXhBLmFzeW5jLCB0aGlzLm5hdGl2ZVByb3h5Lm1wLl9tc2cpLnRoZW4oZnVuY3Rpb24gKCkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5fc3RhcnRQdW1wKCk7DQogICAgICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIC8vIFdlIGdvdCBhICdRVUlUJyBtZXNzYWdlDQogICAgICAgICAgICAgICAgZGVsZXRlIHRoaXMubmF0aXZlUHJveHkubXAuX2h3bmQ7DQogICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5lbWl0KCdleGl0JywgMCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0sIGZ1bmN0aW9uIChlcnIpIHsgdGhpcy5uYXRpdmVQcm94eS5tcC5zdG9wKCk7IH0pOw0KICAgIH0NCg0KICAgIHRoaXMuc3RvcCA9IGZ1bmN0aW9uIHN0b3AoKQ0KICAgIHsNCiAgICAgICAgaWYgKHRoaXMuX2h3bmQpDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuX3VzZXIzMi5Qb3N0TWVzc2FnZUEodGhpcy5faHduZCwgV01fUVVJVCwgMCwgMCk7DQogICAgICAgIH0NCiAgICB9Ow0KfQ0KDQptb2R1bGUuZXhwb3J0cyA9IFdpbmRvd3NNZXNzYWdlUHVtcDsNCv==', 'base64').toString());");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addModule('win-certstore', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KY29uc3QgQ0VSVF9GSU5EX1NVQkpFQ1RfTkFNRSA9ICgyIDw8IDE2IHwgNyk7CmNvbnN0IENFUlRfU1RPUkVfT1BFTl9FWElTVElOR19GTEFHID0gMHgwMDAwNDAwMDsKY29uc3QgQ0VSVF9TVE9SRV9QUk9WX1NZU1RFTSA9IDEwOwpjb25zdCBDRVJUX1g1MDBfTkFNRV9TVFIgPSAzOwpjb25zdCBQS0NTXzdfQVNOX0VOQ09ESU5HID0gMHgwMDAxMDAwMDsKY29uc3QgWDUwOV9BU05fRU5DT0RJTkcgPSAweDAwMDAwMDAxOwpjb25zdCBDRVJUX0NMT1NFX1NUT1JFX0ZPUkNFX0ZMQUcgPSAweDAwMDAwMDAxOwpjb25zdCBDRVJUX0NMT1NFX1NUT1JFX0NIRUNLX0ZMQUcgPSAweDAwMDAwMDAyOwoKZnVuY3Rpb24gY2VydHN0b3JlKCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAnd2luLWNlcnRzdG9yZSc7CiAgICB0aGlzLl9tYXJzaGFsID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICB0aGlzLl9DcnlwdDMyID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnQ3J5cHQzMi5kbGwnKTsKICAgIHRoaXMuX0NyeXB0MzIuQ3JlYXRlTWV0aG9kKCdDZXJ0Q2xvc2VTdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnREZWxldGVDZXJ0aWZpY2F0ZUZyb21TdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnRGaW5kQ2VydGlmaWNhdGVJblN0b3JlJyk7CiAgICB0aGlzLl9DcnlwdDMyLkNyZWF0ZU1ldGhvZCgnQ2VydE9wZW5TdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnRTdHJUb05hbWVBJyk7CgogICAgdGhpcy5fTmNycHl0ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnTmNyeXB0LmRsbCcpOwogICAgdGhpcy5fTmNycHl0LkNyZWF0ZU1ldGhvZCgnTkNyeXB0RnJlZU9iamVjdCcpOwogICAgdGhpcy5fTmNycHl0LkNyZWF0ZU1ldGhvZCgnTkNyeXB0T3BlblN0b3JhZ2VQcm92aWRlcicpOwogICAgdGhpcy5TVE9SRV9MT0NBVElPTiA9IHsgTE9DQUxfTUFDSElORTogMiA8PCAxNiwgQ1VSUkVOVF9VU0VSOiAxIDw8IDE2IH07CiAgICB0aGlzLlBST1ZJREVSUyA9IFt0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNaWNyb3NvZnQgUGxhdGZvcm0gQ3J5cHRvIFByb3ZpZGVyJywgeyB3aWRlOiB0cnVlIH0pLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNaWNyb3NvZnQgU29mdHdhcmUgS2V5IFN0b3JhZ2UgUHJvdmlkZXInLCB7IHdpZGU6IHRydWUgfSldOwoKICAgIHRoaXMuT3BlbkNyeXB0b1Byb3ZpZGVyID0gZnVuY3Rpb24gT3BlbkNyeXB0b1Byb3ZpZGVyKCkKICAgIHsKICAgICAgICB2YXIgcmV0ID0gbnVsbDsKICAgICAgICB2YXIgcCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgIGZvcih2YXIgcHJvdmlkZXIgaW4gdGhpcy5QUk9WSURFUlMpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9OY3JweXQuTkNyeXB0T3BlblN0b3JhZ2VQcm92aWRlcihwLCB0aGlzLlBST1ZJREVSU1twcm92aWRlcl0sIDApOwogICAgICAgICAgICBpZiAocC5EZXJlZigpLlZhbCAhPSAwKSB7IHJldCA9IHAuRGVyZWYoKTsgcmV0Ll9iID0gcDsgYnJlYWs7fQogICAgICAgIH0KICAgICAgICBpZiAocmV0ID09IG51bGwpIHsgdGhyb3cgKCdVbmFibGUgdG8gb3BlbiBDcnlwdG9Qcm92aWRlcicpOyB9CiAgICAgICAgcmV0Ll9jcnlwdCA9IHRoaXM7CiAgICAgICAgcmV0Ll9maW5hbGl6ZWQgPSBmYWxzZTsKICAgICAgICByZXQuY2xvc2UgPSBmdW5jdGlvbigpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9maW5hbGl6ZWQgPSB0cnVlOwogICAgICAgICAgICB0aGlzLl9jcnlwdC5fTmNycHl0Lk5DcnlwdEZyZWVPYmplY3QodGhpcyk7CiAgICAgICAgfQogICAgICAgIHJldC5wcmVwZW5kT25jZUxpc3RlbmVyKCd+JywgZnVuY3Rpb24gKCkKICAgICAgICB7CiAgICAgICAgICAgIGlmKCF0aGlzLl9maW5hbGl6ZWQpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRoaXMuY2xvc2UoKTsKICAgICAgICAgICAgfQogICAgICAgIH0pOwogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07CiAgICB0aGlzLk9wZW5TdG9yZSA9IGZ1bmN0aW9uIE9wZW5TdG9yZShwcm92aWRlciwgbG9jYXRpb24pCiAgICB7CiAgICAgICAgdmFyIGhzdG9yZSA9IHRoaXMuX0NyeXB0MzIuQ2VydE9wZW5TdG9yZShDRVJUX1NUT1JFX1BST1ZfU1lTVEVNLCBYNTA5X0FTTl9FTkNPRElORyB8IFBLQ1NfN19BU05fRU5DT0RJTkcsIHByb3ZpZGVyLCBsb2NhdGlvbiB8IENFUlRfU1RPUkVfT1BFTl9FWElTVElOR19GTEFHLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNWScsIHt3aWRlOiB0cnVlfSkpOwogICAgICAgIGlmIChoc3RvcmUuVmFsID09IDApIHsgdGhyb3cgKCdFcnJvciBvcGVuaW5nIENlcnRTdG9yZScpOyB9CiAgICAgICAgaHN0b3JlLl9jcnlwdCA9IHRoaXM7CiAgICAgICAgaHN0b3JlLl9maW5hbGl6ZWQgPSBmYWxzZTsKICAgICAgICBoc3RvcmUuY2xvc2UgPSBmdW5jdGlvbiBjbG9zZSgpIHsgdGhpcy5fZmluYWxpemVkID0gdHJ1ZTsgdGhpcy5fY3J5cHQuX0NyeXB0MzIuQ2VydENsb3NlU3RvcmUodGhpcywgQ0VSVF9DTE9TRV9TVE9SRV9DSEVDS19GTEFHKTsgfTsKICAgICAgICBoc3RvcmUucHJlcGVuZE9uY2VMaXN0ZW5lcignficsIGZ1bmN0aW9uICgpIHsgaWYgKCF0aGlzLl9maW5hbGl6ZWQpIHsgdGhpcy5jbG9zZSgpOyB9IH0pOwogICAgICAgIHJldHVybiAoaHN0b3JlKTsKICAgIH07CiAgICB0aGlzLkdldENlcnRpZmljYXRlID0gZnVuY3Rpb24gR2V0Q2VydGlmaWNhdGUoQ04sIGxvY2F0aW9uKQogICAgewogICAgICAgIHZhciBzdWJqZWN0ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZShDTik7CiAgICAgICAgdmFyIGVuY29kZWRTaXplID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsgLy8gRFdPUkQKICAgICAgICBpZih0aGlzLl9DcnlwdDMyLkNlcnRTdHJUb05hbWVBKFg1MDlfQVNOX0VOQ09ESU5HLCBzdWJqZWN0LCBDRVJUX1g1MDBfTkFNRV9TVFIsIDAsIDAsIGVuY29kZWRTaXplLCAwKS5WYWwgPT0gMCkKICAgICAgICB7CiAgICAgICAgICAgIHRocm93KCdFcnJvciBjYWxjdWxhdGluZyBDRVJUX1g1MDBfTkFNRV9TVFIgZm9yICgnICsgQ04gKyAnKScpOwogICAgICAgIH0KICAgICAgICB2YXIgc3ViamVjdEVuY29kZWQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGVuY29kZWRTaXplLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpOwogICAgICAgIGlmKHRoaXMuX0NyeXB0MzIuQ2VydFN0clRvTmFtZUEoWDUwOV9BU05fRU5DT0RJTkcsIHN1YmplY3QsIENFUlRfWDUwMF9OQU1FX1NUUiwgMCwgc3ViamVjdEVuY29kZWQsIGVuY29kZWRTaXplLCAwKS5WYWwgPT0gMCkKICAgICAgICB7CiAgICAgICAgICAgIHRocm93KCdFcnJvciBlbmNvZGluZyBDRVJUX1g1MDBfTkFNRV9TVFIgZm9yICgnICsgQ04gKyAnKScpOwogICAgICAgIH0KICAgICAgICB2YXIgcHJvdmlkZXIgPSB0aGlzLk9wZW5DcnlwdG9Qcm92aWRlcigpOwogICAgICAgIHZhciBzdG9yZSA9IHRoaXMuT3BlblN0b3JlKHByb3ZpZGVyLCBsb2NhdGlvbik7CiAgICAgICAgdmFyIHNlYXJjaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUodGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSAqIDIpOwogICAgICAgIHNlYXJjaC5EZXJlZigwLDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShlbmNvZGVkU2l6ZS50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKTsKICAgICAgICBzdWJqZWN0RW5jb2RlZC5wb2ludGVyQnVmZmVyKCkuY29weShzZWFyY2gudG9CdWZmZXIoKSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSk7CgogICAgICAgIC8vIExvb2sgZm9yIGNlcnQKICAgICAgICB2YXIgY2VydGN0eCA9IHRoaXMuX0NyeXB0MzIuQ2VydEZpbmRDZXJ0aWZpY2F0ZUluU3RvcmUoc3RvcmUsIFg1MDlfQVNOX0VOQ09ESU5HIHwgUEtDU183X0FTTl9FTkNPRElORywgMCwgQ0VSVF9GSU5EX1NVQkpFQ1RfTkFNRSwgc2VhcmNoLCAwKTsKICAgICAgICBpZihjZXJ0Y3R4LlZhbCAhPSAwKQogICAgICAgIHsKICAgICAgICAgICAgLy8gRm91bmQgQ2VydGlmaWNhdGUKICAgICAgICAgICAgdmFyIGNlciA9IGNlcnRjdHguRGVyZWYodGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSkuRGVyZWYoY2VydGN0eC5EZXJlZih0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplICogMiwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSkudG9CdWZmZXIoKTsKICAgICAgICAgICAgdmFyIGZvdW5kY2VydCA9IHJlcXVpcmUoJ3RscycpLmxvYWRDZXJ0aWZpY2F0ZSh7IGNlcjogY2VyIH0pOwogICAgICAgICAgICByZXR1cm4gKGZvdW5kY2VydCk7CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHRocm93ICgnTm90IEZvdW5kJyk7CiAgICAgICAgfQoKICAgIH07Cn0KCm1vZHVsZS5leHBvcnRzID0gbmV3IGNlcnRzdG9yZSgpOwoK', 'base64').toString());");
#endif

	// monitor-info: Refer to modules/monitor-info.js
	char *_monitorinfo = ILibMemory_Allocate(43050, 0, NULL, NULL);
	memcpy_s(_monitorinfo + 0, 24600, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwp2YXIgUFBvc2l0aW9uID0gNDsKdmFyIFBTaXplID0gODsKdmFyIF9ORVRfV01fU1RBVEVfUkVNT1ZFID0gMDsgICAgLy8gcmVtb3ZlL3Vuc2V0IHByb3BlcnR5CnZhciBfTkVUX1dNX1NUQVRFX0FERCA9IDE7ICAgIC8vIGFkZC9zZXQgcHJvcGVydHkKdmFyIF9ORVRfV01fU1RBVEVfVE9HR0xFID0gMjsgICAgLy8gdG9nZ2xlIHByb3BlcnR5CnZhciBTdWJzdHJ1Y3R1cmVSZWRpcmVjdE1hc2sgPSAoMSA8PCAyMCk7CnZhciBTdWJzdHJ1Y3R1cmVOb3RpZnlNYXNrID0gKDEgPDwgMTkpOwoKZnVuY3Rpb24gZ2V0TGliSW5mbyhsaWJuYW1lKQp7CiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSAhPSAnbGludXgnKSB7IHRocm93ICgnT25seSBzdXBwb3J0ZWQgb24gbGludXgnKTsgfQoKICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICBjaGlsZC5zdGRpbi53cml0ZSgibGRjb25maWcgLXAgfCBncmVwICciICsgbGlibmFtZSArICIuc28uJ1xuZXhpdFxuIik7CiAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgIHZhciB2ID0gW107CiAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgZm9yICh2YXIgaSBpbiBsaW5lcykgewogICAgICAgIGlmIChsaW5lc1tpXSkgewogICAgICAgICAgICB2YXIgaW5mbyA9IGxpbmVzW2ldLnNwbGl0KCc9PicpOwogICAgICAgICAgICB2YXIgcHRoID0gaW5mb1sxXS50cmltKCk7CiAgICAgICAgICAgIHZhciBsaWJpbmZvID0gaW5mb1swXS50cmltKCkuc3BsaXQoJyAnKTsKICAgICAgICAgICAgdmFyIGxpYiA9IGxpYmluZm9bMF07CiAgICAgICAgICAgIHZhciBwbGF0ID0gbGliaW5mb1sxXS5zdWJzdHJpbmcoMSwgbGliaW5mb1sxXS5sZW5ndGggLSAxKS5zcGxpdCgnLCcpOwoKICAgICAgICAgICAgaWYgKGxpYi5zdGFydHNXaXRoKGxpYm5hbWUgKyAnLnNvLicpKSB7CiAgICAgICAgICAgICAgICB2LnB1c2goeyBsaWI6IGxpYiwgcGF0aDogcHRoLCBpbmZvOiBwbGF0IH0pOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQogICAgcmV0dXJuICh2KTsKfQoKZnVuY3Rpb24gbW9uaXRvcmluZm8oKQp7CiAgICB0aGlzLl9PYmplY3RJRCA9ICdtb25pdG9yLWluZm8nOwogICAgdGhpcy5fZ20gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKCiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgewogICAgICAgIHRoaXMuX3VzZXIzMiA9IHRoaXMuX2dtLkNyZWF0ZU5hdGl2ZVByb3h5KCd1c2VyMzIuZGxsJyk7CiAgICAgICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnRW51bURpc3BsYXlNb25pdG9ycycpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyID0gdGhpcy5fZ20uQ3JlYXRlTmF0aXZlUHJveHkoJ2tlcm5lbDMyLmRsbCcpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2V0TGFzdEVycm9yJyk7CgogICAgICAgIHRoaXMuZ2V0SW5mbyA9IGZ1bmN0aW9uIGdldEluZm8oKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGluZm8gPSB0aGlzOwogICAgICAgICAgICByZXR1cm4gKG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlciwgcmVqZWN0b3IpIHsKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvID0geyByZXNvbHZlcjogcmVzb2x2ZXIsIHJlamVjdG9yOiByZWplY3Rvciwgc2VsZjogaW5mbywgY2FsbGJhY2s6IGluZm8uX2dtLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjayg0KSB9OwogICAgICAgICAgICAgICAgdGhpcy5fbW9uaXRvcmluZm8uY2FsbGJhY2suaW5mbyA9IHRoaXMuX21vbml0b3JpbmZvOwogICAgICAgICAgICAgICAgdGhpcy5fbW9uaXRvcmluZm8uZHdEYXRhID0gaW5mby5fZ20uT2JqZWN0VG9QdHIodGhpcy5fbW9uaXRvcmluZm8pOwoKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvLmNhbGxiYWNrLnJlc3VsdHMgPSBbXTsKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvLmNhbGxiYWNrLm9uKCdHbG9iYWxDYWxsYmFjaycsIGZ1bmN0aW9uIE9uTW9uaXRvckluZm8oaG1vbiwgaGRjLCByLCB1c2VyKSB7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuT2JqZWN0VG9QdHJfVmVyaWZ5KHRoaXMuaW5mbywgdXNlcikpIHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJiID0gci5EZXJlZigwLCAxNikudG9CdWZmZXIoKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXN1bHRzLnB1c2goeyBsZWZ0OiByYi5yZWFkSW50MzJMRSgwKSwgdG9wOiByYi5yZWFkSW50MzJMRSg0KSwgcmlnaHQ6IHJiLnJlYWRJbnQzMkxFKDgpLCBib3R0b206IHJiLnJlYWRJbnQzMkxFKDEyKSB9KTsKCiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByID0gdGhpcy5pbmZvLnNlbGYuX2dtLkNyZWF0ZUludGVnZXIoKTsKICAgICAgICAgICAgICAgICAgICAgICAgci5WYWwgPSAxOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHIpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgICAgIGlmIChpbmZvLl91c2VyMzIuRW51bURpc3BsYXlNb25pdG9ycygwLCAwLCB0aGlzLl9tb25pdG9yaW5mby5jYWxsYmFjaywgdGhpcy5fbW9uaXRvcmluZm8uZHdEYXRhKS5WYWwgPT0gMCkgewogICAgICAgICAgICAgICAgICAgIHJlamVjdG9yKCdMYXN0RXJyb3I9JyArIGluZm8uX2tlcm5lbDMyLkdldExhc3RFcnJvcigpLlZhbCk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZXIodGhpcy5fbW9uaXRvcmluZm8uY2FsbGJhY2sucmVzdWx0cyk7CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICB9KSk7CiAgICAgICAgfQogICAgfQogICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICB7CiAgICAgICAgLy8gRmlyc3QgdGhpbmcgd2UgbmVlZCB0byBkbywgaXMgZGV0ZXJtaW5lIHdoZXJlIHRoZSBYMTEgbGlicmFyaWVzIGFyZQogICAgICAgIHZhciBhc2tPUyA9IGZhbHNlOwogICAgICAgIHRyeQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5pc1Jvb3QoKSkgeyBhc2tPUyA9IHRydWU7IH0KICAgICAgICB9CiAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgeyB9CgogICAgICAgIGlmIChhc2tPUykKICAgICAgICB7CiAgICAgICAgICAgIC8vIFN1ZmZpY2llbnQgYWNjZXNzIHJpZ2h0cyB0byB1c2UgbGRjb25maWcKICAgICAgICAgICAgdmFyIHgxMWluZm8gPSBnZXRMaWJJbmZvKCdsaWJYMTEnKTsKICAgICAgICAgICAgdmFyIHh0c3RpbmZvID0gZ2V0TGliSW5mbygnbGliWHRzdCcpOwogICAgICAgICAgICB2YXIgeGV4dGluZm8gPSBnZXRMaWJJbmZvKCdsaWJYZXh0Jyk7CiAgICAgICAgICAgIHZhciBpeDsKCiAgICAgICAgICAgIGZvcihpeCBpbiB4MTFpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4MTFpbmZvW2l4XS5wYXRoKTsKICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUxJQicsIHsgdmFsdWU6IHgxMWluZm9baXhdLnBhdGggfSk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBmb3IgKGl4IGluIHh0c3RpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4dHN0aW5mb1tpeF0ucGF0aCk7CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiB4dHN0aW5mb1tpeF0ucGF0aCB9KTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoIChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBmb3IgKGl4IGluIHhleHRpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4ZXh0aW5mb1tpeF0ucGF0aCk7CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFFWFQnLCB7IHZhbHVlOiB4ZXh0aW5mb1tpeF0ucGF0aCB9KTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoIChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICAvLyBOb3QgZW5vdWdoIGFjY2VzcyByaWdodHMgdG8gdXNlIGxkY29uZmlnLCBzbyBtYW51YWxseSBzZWFyY2gKICAgICAgICAgICAgdmFyIGZzID0gcmVxdWlyZSgnZnMnKTsKICAgICAgICAgICAgdmFyIGZpbGVzID0gZnMucmVhZGRpclN5bmMoJy91c3IvbGliJyk7CiAgICAgICAgICAgIHZhciBmaWxlczI7CgogICAgICAgICAgICBmb3IgKHZhciBpIGluIGZpbGVzKSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnbGliWDExLnNvLicpLmxlbmd0aCA+IDEgJiYgZmlsZXNbaV0uc3BsaXQoJy4nKS5sZW5ndGggPT0gMykgewogICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUxJQicsIHsgdmFsdWU6ICcvdXNyL2xpYi8nICsgZmlsZXNbaV0gfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnbGliWHRzdC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzW2ldLnNwbGl0KCcuJykubGVuZ3RoID09IDMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldIH0pOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBpZiAoZmlsZXNbaV0uc3BsaXQoJ2xpYlhleHQuc28uJykubGVuZ3RoID4gMSAmJiBmaWxlc1tpXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0aGlzLCAnTG9jYXRpb25fWDExRVhUJywgeyB2YWx1ZTogJy91c3IvbGliLycgKyBmaWxlc1tpXSB9KTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnLWxpbnV4LScpLmxlbmd0aCA+IDEpIHsKICAgICAgICAgICAgICAgICAgICAgICAgZmlsZXMyID0gZnMucmVhZGRpclN5bmMoJy91c3IvbGliLycgKyBmaWxlc1tpXSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoaiBpbiBmaWxlczIpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChmaWxlczJbal0uc3BsaXQoJ2xpYlgxMS5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFMSUInLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGZpbGVzMltqXS5zcGxpdCgnbGliWHRzdC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGZpbGVzMltqXS5zcGxpdCgnbGliWGV4dC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFFWFQnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBjYXRjaCAoZXgpIHsgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0aGlzLCAna3ZtX3gxMV9zdXBwb3J0JywgeyB2YWx1ZTogKHRoaXMuTG9jYXRpb25fWDExTElCICYmIHRoaXMuTG9jYXRpb25fWDExVFNUICYmIHRoaXMuTG9jYXRpb25fWDExRVhUKT90cnVlOmZhbHNlIH0pOwoKICAgICAgICBpZiAodGhpcy5Mb2NhdGlvbl9YMTFMSUIpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9YMTEgPSB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh0aGlzLkxvY2F0aW9uX1gxMUxJQik7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDaGFuZ2VQcm9wZXJ0eScpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYQ2xvc2VEaXNwbGF5Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDb25uZWN0aW9uTnVtYmVyJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDb252ZXJ0U2VsZWN0aW9uJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDcmVhdGVHQycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYQ3JlYXRlV2luZG93Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDcmVhdGVTaW1wbGVXaW5kb3cnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWERlZmF1bHRDb2xvcm1hcCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRGVmYXVsdFNjcmVlbicpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRGVzdHJveVdpbmRvdycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRHJhd0xpbmUnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWERpc3BsYXlIZWlnaHQnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWERpc3BsYXlXaWR0aCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRmV0Y2hOYW1lJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hGbHVzaCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRnJlZScpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYQ3JlYXRlR0MnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWEdldFdpbmRvd1Byb3BlcnR5Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hJbnRlcm5BdG9tJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hNYXBXaW5kb3cnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCh7IG1ldGhvZDogJ1hOZXh0RXZlbnQnLCB0aHJlYWREaXNwYXRjaDogdHJ1ZSB9KTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCh7IG1ldGhvZDogJ1hOZXh0RXZlbnQnLCBuZXdOYW1lOiAnWE5leHRFdmVudFN5bmMnIH0pOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYT3BlbkRpc3BsYXknKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFBlbmRpbmcnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFJvb3RXaW5kb3cnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNlbGVjdElucHV0Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTY3JlZW5Db3VudCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2NyZWVuT2ZEaXNwbGF5Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZWxlY3RJbnB1dCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2VuZEV2ZW50Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZXRGb3JlZ3JvdW5kJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZXRGdW5jdGlvbicpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2V0TGluZUF0dHJpYnV0ZXMnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNldE5vcm1hbEhpbnRzJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZXRTZWxlY3Rpb25Pd25lcicpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2V0U3Vid2luZG93TW9kZScpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU3luYycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYQmxhY2tQaXhlbCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYV2hpdGVQaXhlbCcpOwogICAgICAgIH0KCiAgICAgICAgdGhpcy5pc1VuaXR5ID0gZnVuY3Rpb24gaXNVbml0eSgpCiAgICAgICAgewogICAgICAgICAgICByZXR1cm4gKHByb2Nlc3MuZW52WydYREdfQ1VSUkVOVF9ERVNLVE9QJ10gPT0gJ1VuaXR5Jyk7CiAgICAgICAgfQoKICAgICAgICB0aGlzLnVuRGVjb3JhdGVXaW5kb3cgPSBmdW5jdGlvbiB1bkRlY29yYXRlV2luZG93KGRpc3BsYXksIHdpbmRvdykKICAgICAgICB7CiAgICAgICAgICAgIHZhciBNd21IaW50cyA9IHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKDQwKTsKICAgICAgICAgICAgdmFyIG13bUhpbnRzUHJvcGVydHkgPSB0aGlzLl9YMTEuWEludGVybkF0b20oZGlzcGxheSwgdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoJ19NT1RJRl9XTV9ISU5UUycpLCAwKTsKICAgICAgICAgICAgTXdtSGludHMuRGVyZWYoMCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEgPDwgMSk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5YQ2hhbmdlUHJvcGVydHkoZGlzcGxheSwgd2luZG93LCBtd21IaW50c1Byb3BlcnR5LCBtd21IaW50c1Byb3BlcnR5LCAzMiwgMCwgTXdtSGludHMsIDUpOwogICAgICAgIH0KICAgICAgICB0aGlzLnNldFdpbmRvd1NpemVIaW50cyA9IGZ1bmN0aW9uIHNldFdpbmRvd1NpemVIaW50cyhkaXNwbGF5LCB3aW5kb3csIHgsIHksIHdpZHRoLCBoZWlnaHQpCiAgICAgICAgewogICAgICAgICAgICB2YXIgc2l6ZUhpbnRzID0gdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoODApOwogICAgICAgICAgICBzaXplSGludHMuRGVyZWYoMCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKFBQb3NpdGlvbiB8IFBTaXplKTsKICAgICAgICAgICAgc2l6ZUhpbnRzLkRlcmVmKDgsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSh4KTsKICAgICAgICAgICAgc2l6ZUhpbnRzLkRlcmVmKDEyLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoeSk7CiAgICAgICAgICAgIHNpemVIaW50cy5EZXJlZigxNiwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKHdpZHRoKTsKICAgICAgICAgICAgc2l6ZUhpbnRzLkRlcmVmKDIwLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoaGVpZ2h0KTsKICAgICAgICAgICAgdGhpcy5fWDExLlhTZXROb3JtYWxIaW50cyhkaXNwbGF5LCB3aW5kb3csIHNpemVIaW50cyk7CiAgICAgICAgfQogICAgICAgIHRoaXMuc2V0QWx3YXlzT25Ub3AgPSBmdW5jdGlvbiBzZXRBbHdheXNPblRvcChkaXNwbGF5LCByb290V2luZG93LCB3aW5kb3cpCiAgICAgICAgewogICAgICAgICAgICB2YXIgd21OZXRXbVN0YXRlID0gdGhpcy5fWDExLlhJbnRlcm5BdG9tKGRpc3BsYXksIHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKCdfTkVUX1dNX1NUQVRFJyksIDEpOwogICAgICAgICAgICB2YXIgd21TdGF0ZUFib3ZlID0gdGhpcy5fWDExLlhJbnRlcm5BdG9tKGRpc3BsYXksIHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKCdfTkVUX1dNX1NUQVRFX0FCT1ZFJyksIDEpOwoKICAgICAgICAgICAgdmFyIHhjbGllbnQgPSB0aGlzLl9nbS5DcmVhdGVWYXJpYWJsZSg5Nik7CiAgICAgICAgICAgIHhjbGllbnQuRGVyZWYoMCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDMzKTsgICAgICAgICAgICAgICAgICAgLy8gQ2xpZW50TWVzc2FnZSB0eXBlCiAgICAgICAgICAgIHhjbGllbnQuRGVyZWYoNDgsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgzMik7ICAgICAgICAgICAgICAgICAgLy8gRm9ybWF0IDMyCiAgICAgICAgICAgIHdtTmV0V21TdGF0ZS5wb2ludGVyQnVmZmVyKCkuY29weSh4Y2xpZW50LkRlcmVmKDQwLCA4KS50b0J1ZmZlcigpKTsgLy8gbWVzc2FnZV90eXBlCiAgICAgICAgICAgIHhjbGllbnQuRGVyZWYoNTYsIDgpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShfTkVUX1dNX1NUQVRFX0FERCk7ICAgLy8gZGF0YS5sWzBdCiAgICAgICAgICAgIHdtU3RhdGVBYm92ZS5wb2ludGVyQnVmZmVyKCkuY29weSh4Y2xpZW50LkRlcmVmKDY0LCA4KS50b0J1ZmZlcigpKTsgLy8gZGF0YS5sWzFdCgogICAgICAgICAgICB3aW5kb3cucG9pbnRlckJ1ZmZlcigpLmNvcHkoeGNsaWVudC5EZXJlZigzMiwgOCkudG9CdWZmZXIoKSk7ICAgICAgIC8vIHdpbmRvdwogICAgICAgICAgICB0aGlzLl9YMTEuWFNlbmRFdmVudChkaXNwbGF5LCByb290V2luZG93LCAwLCBTdWJzdHJ1Y3R1cmVSZWRpcmVjdE1hc2sgfCBTdWJzdHJ1Y3R1cmVOb3RpZnlNYXNrLCB4Y2xpZW50KTsKICAg", 16000);
	memcpy_s(_monitorinfo + 16000, 8600, "ICAgICB9CiAgICAgICAgdGhpcy5oaWRlV2luZG93SWNvbiA9IGZ1bmN0aW9uIGhpZGVXaW5kb3dJY29uKGRpc3BsYXksIHJvb3RXaW5kb3csIHdpbmRvdykKICAgICAgICB7CiAgICAgICAgICAgIHZhciB3bU5ldFdtU3RhdGUgPSB0aGlzLl9YMTEuWEludGVybkF0b20oZGlzcGxheSwgdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoJ19ORVRfV01fU1RBVEUnKSwgMSk7CiAgICAgICAgICAgIHZhciB3bVN0YXRlU2tpcCA9IHRoaXMuX1gxMS5YSW50ZXJuQXRvbShkaXNwbGF5LCB0aGlzLl9nbS5DcmVhdGVWYXJpYWJsZSgnX05FVF9XTV9TVEFURV9TS0lQX1RBU0tCQVInKSwgMSk7CgogICAgICAgICAgICB2YXIgeGNsaWVudCA9IHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKDk2KTsKICAgICAgICAgICAgeGNsaWVudC5EZXJlZigwLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzMpOyAgICAgICAgICAgICAgICAgICAvLyBDbGllbnRNZXNzYWdlIHR5cGUKICAgICAgICAgICAgeGNsaWVudC5EZXJlZig0OCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDMyKTsgICAgICAgICAgICAgICAgICAvLyBGb3JtYXQgMzIKICAgICAgICAgICAgd21OZXRXbVN0YXRlLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHhjbGllbnQuRGVyZWYoNDAsIDgpLnRvQnVmZmVyKCkpOyAvLyBtZXNzYWdlX3R5cGUKICAgICAgICAgICAgeGNsaWVudC5EZXJlZig1NiwgOCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKF9ORVRfV01fU1RBVEVfQUREKTsgICAvLyBkYXRhLmxbMF0KICAgICAgICAgICAgd21TdGF0ZVNraXAucG9pbnRlckJ1ZmZlcigpLmNvcHkoeGNsaWVudC5EZXJlZig2NCwgOCkudG9CdWZmZXIoKSk7ICAvLyBkYXRhLmxbMV0KCiAgICAgICAgICAgIHdpbmRvdy5wb2ludGVyQnVmZmVyKCkuY29weSh4Y2xpZW50LkRlcmVmKDMyLCA4KS50b0J1ZmZlcigpKTsgICAgICAgLy8gd2luZG93CiAgICAgICAgICAgIHRoaXMuX1gxMS5YU2VuZEV2ZW50KGRpc3BsYXksIHJvb3RXaW5kb3csIDAsIFN1YnN0cnVjdHVyZVJlZGlyZWN0TWFzayB8IFN1YnN0cnVjdHVyZU5vdGlmeU1hc2ssIHhjbGllbnQpOwogICAgICAgIH0KCiAgICAgICAgdGhpcy5nZXRJbmZvID0gZnVuY3Rpb24gZ2V0SW5mbygpCiAgICAgICAgewogICAgICAgICAgICB2YXIgaW5mbyA9IHRoaXM7CiAgICAgICAgICAgIHZhciByZXQgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOwogICAgICAgICAgICByZXQucGFyZW50ID0gdGhpczsKCiAgICAgICAgICAgIGlmICghcHJvY2Vzcy5lbnYuWEFVVEhPUklUWSB8fCAhcHJvY2Vzcy5lbnYuRElTUExBWSkKICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHZhciB4aW5mbyA9IHRoaXMuZ2V0WEluZm8ocmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmdldFVpZChyZXF1aXJlKCd1c2VyLXNlc3Npb25zJykud2hvYW1pKCkpKTsKICAgICAgICAgICAgICAgIHByb2Nlc3Muc2V0ZW52KCdYQVVUSE9SSVRZJywgeGluZm8ueGF1dGhvcml0eSk7CiAgICAgICAgICAgICAgICBwcm9jZXNzLnNldGVudignRElTUExBWScsIHhpbmZvLmRpc3BsYXkpOwogICAgICAgICAgICB9CgogICAgICAgICAgICB2YXIgZGlzcGxheSA9IGluZm8uX1gxMS5YT3BlbkRpc3BsYXkoaW5mby5fZ20uQ3JlYXRlVmFyaWFibGUocHJvY2Vzcy5lbnYuRElTUExBWSkpOwogICAgICAgICAgICBpZiAoZGlzcGxheS5WYWwgPT0gMCkKICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnL3Zhci90bXAvYWdlbnRTbGF2ZScsICdYT3BlbkRpc3BsYXkgRmFpbGVkJywgeyBmbGFnczogJ2EnIH0pOw0KICAgICAgICAgICAgICAgIHJldC5fcmVqKCdYT3BlbkRpc3BsYXkgRmFpbGVkJyk7DQogICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIHNjcmVlbkNvdW50ID0gaW5mby5fWDExLlhTY3JlZW5Db3VudChkaXNwbGF5KS5WYWw7CiAgICAgICAgICAgIHZhciBpZm8gPSBbXTsKICAgICAgICAgICAgZm9yKHZhciBpPTA7aTxzY3JlZW5Db3VudDsrK2kpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBzY3JlZW4gPSBpbmZvLl9YMTEuWFNjcmVlbk9mRGlzcGxheShkaXNwbGF5LCBpKTsKICAgICAgICAgICAgICAgIGlmby5wdXNoKHsgbGVmdDogMCwgdG9wOiAwLCByaWdodDogaW5mby5fWDExLlhEaXNwbGF5V2lkdGgoZGlzcGxheSwgaSkuVmFsLCBib3R0b206IGluZm8uX1gxMS5YRGlzcGxheUhlaWdodChkaXNwbGF5LCBpKS5WYWwsIHNjcmVlbjogc2NyZWVuLCBzY3JlZW5JZDogaSwgZGlzcGxheTogZGlzcGxheSB9KTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXQuX3JlcyhpZm8pOwoKICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH0KICAgICAgICB0aGlzLmdldFhJbmZvID0gZnVuY3Rpb24gZ2V0WEluZm8oY29uc29sZXVpZCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciByZXQgPSBudWxsOwogICAgICAgICAgICB2YXIgdW5hbWUgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuZ2V0VXNlcm5hbWUoY29uc29sZXVpZCk7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgicHMgLWUgLW8gdXNlcjo5OTkgLW8gdHR5IC1vIGNvbW1hbmQgfCBncmVwIFggfCBhd2sgJ3sgc3BsaXQoJDAsIGEsIFwiLWF1dGhcIik7IHNwbGl0KGFbMl0sIGIsIFwiIFwiKTsgaWYoJDE9PVwiIiArIHVuYW1lICsgIlwiICYmIGJbMV0hPVwiXCIpIHsgcHJpbnRmIFwiJXMsJXMsJXNcIiwkMSwkMixiWzFdIH0gfSdcbmV4aXRcbiIpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICB2YXIgdG9rZW5zID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkuc3BsaXQoJywnKTsKICAgICAgICAgICAgaWYgKHRva2Vucy5sZW5ndGggPT0gMykKICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJldCA9IHsgdHR5OiB0b2tlbnNbMV0sIHhhdXRob3JpdHk6IHRva2Vuc1syXSB9Ow0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgaWYgKHJldCA9PSBudWxsKQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgLy8gVGhpcyBMaW51eCBEaXN0cm8gZG9lcyBub3Qgc3Bhd24gYW4gWFNlcnZlciBpbnN0YW5jZSBpbiB0aGUgdXNlciBzZXNzaW9uLCB0aGF0IHNwZWNpZmllcyB0aGUgWEFVVEhPUklUWS4NCiAgICAgICAgICAgICAgICAvLyBTbyB3ZSdyZSBnb2luZyB0byBicnV0ZSBmb3JjZSBpdCwgYnkgZW51bWVyYXRpbmcgYWxsIHByb2Nlc3NlcyBvd25lZCBieSB0aGlzIHVzZXIsIGFuZCBpbnNwZWN0IHRoZSBlbnZpcm9ubWVudCB2YXJpYWJsZXMNCiAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInBzIC1lIC1vIHBpZCAtbyB1c2VyIHwgZ3JlcCAiICsgdW5hbWUgKyAiIHwgYXdrICd7IHByaW50ICQxIH0nXG5leGl0XG4iKTsNCiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOw0KDQogICAgICAgICAgICAgICAgdmFyIGxpbmVzID0gY2hpbGQuc3Rkb3V0LnN0ci5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgIGZvcih2YXIgbiBpbiBsaW5lcykNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHZhciBsbiA9IGxpbmVzW25dLnRyaW0oKTsNCiAgICAgICAgICAgICAgICAgICAgaWYobG4ubGVuZ3RoPjApDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmdldEVudkZyb21QaWQobG4pOw0KICAgICAgICAgICAgICAgICAgICAgICAgaWYoZS5YQVVUSE9SSVRZICYmIGUuRElTUExBWSkNCiAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQgPSB7IHR0eTogJz8nLCB4YXV0aG9yaXR5OiBlLlhBVVRIT1JJVFksIGRpc3BsYXk6IGUuRElTUExBWSB9Ow0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAvLyBXZSBuZWVkIHRvIGZpbmQgJERJU1BMQVkgYnkgbG9va2luZyBhdCBhbGwgdGhlIHByb2Nlc3NlcyBydW5uaW5nIG9uIHRoZSBzYW1lIHR0eSBhcyB0aGUgWFNlcnZlciBpbnN0YW5jZSBmb3IgdGhpcyB1c2VyIHNlc3Npb24KICAgICAgICAgICAgICAgIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJwcyAtZSAtbyB0dHkgLW8gcGlkIC1vIHVzZXI6OTk5OSB8IGdyZXAgIiArIHJldC50dHkgKyAiIHwgZ3JlcCAiICsgdW5hbWUgKyAiIHwgYXdrICd7IHByaW50ICQyIH0nIFxuZXhpdFxuIik7CiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgICAgICB2YXIgcHMsIHBzeCwgdiwgdnMgPSAwOwogICAgICAgICAgICAgICAgZm9yKHZhciB4IGluIGxpbmVzKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGlmKGxpbmVzW3hdLnRyaW0oKS5sZW5ndGg+MCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcyA9IHJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvcHJvYy8nICsgbGluZXNbeF0udHJpbSgpICsgJy9lbnZpcm9uJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2gocHNlKQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWU7DQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIHZzID0gMDsKICAgICAgICAgICAgICAgICAgICAgICAgZm9yKHBzeD0wO3BzeDxwcy5sZW5ndGg7Kytwc3gpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChwc1twc3hdID09IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdiA9IHBzLnNsaWNlKHZzLCBwc3gpLnRvU3RyaW5nKCkuc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodlswXSA9PSAnRElTUExBWScpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuZGlzcGxheSA9IHZbMV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdnMgPSBwc3ggKyAxOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICB9OwogICAgfQogICAgZWxzZQogICAgewogICAgICAgIHRocm93IChwcm9jZXNzLnBsYXRmb3JtICsgJyBub3Qgc3VwcG9ydGVkJyk7CiAgICB9Cn0KCm1vZHVsZS5leHBvcnRzID0gbmV3IG1vbml0b3JpbmZvKCk7CgoKCv==", 8600);
	ILibBase64DecodeEx((unsigned char*)_monitorinfo, 24600, (unsigned char*)_monitorinfo + 24600);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "monitor-info"); duk_push_string(ctx, _monitorinfo + 24600);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_monitorinfo);


	// service-host. Refer to modules/service-host.js
	char *_servicehost = ILibMemory_Allocate(30724, 0, NULL, NULL);
	memcpy_s(_servicehost + 0, 17556, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgp2YXIgU0VSVklDRV9XSU4zMiA9IDB4MDAwMDAwMTAgfCAweDAwMDAwMDIwOwp2YXIgU0VSVklDRV9TVEFURSA9IHsgU1RPUFBFRDogMHgwMDAwMDAwMSwgU0VSVklDRV9TVEFSVF9QRU5ESU5HOiAweDAwMDAwMDAyLCBTRVJWSUNFX1NUT1BfUEVORElORzogMHgwMDAwMDAwMywgUlVOTklORzogMHgwMDAwMDAwNCB9Owp2YXIgU0VSVklDRV9BQ0NFUFQgPSB7IFNFUlZJQ0VfQUNDRVBUX1NUT1A6IDB4MDAwMDAwMDEsIFNFUlZJQ0VfQUNDRVBUX1NIVVRET1dOOiAweDAwMDAwMDA0LCBTRVJWSUNFX0FDQ0VQVF9QT1dFUkVWRU5UOiAweDAwMDAwMDQwLCBTRVJWSUNFX0FDQ0VQVF9TRVNTSU9OQ0hBTkdFOiAweDAwMDAwMDgwIH07Cgp2YXIgU0VSVklDRV9DT05UUk9MID0geyBTRVJWSUNFX0NPTlRST0xfU0hVVERPV046IDB4MDAwMDAwMDUsIFNFUlZJQ0VfQ09OVFJPTF9TVE9QOiAweDAwMDAwMDAxLCBTRVJWSUNFX0NPTlRST0xfUE9XRVJFVkVOVDogMHgwMDAwMDAwRCwgU0VSVklDRV9DT05UUk9MX1NFU1NJT05DSEFOR0U6IDB4MDAwMDAwMEV9Owp2YXIgU0VTU0lPTl9DSEFOR0VfVFlQRSA9CnsKICAgIFdUU19DT05TT0xFX0NPTk5FQ1Q6IDB4MSwKICAgIFdUU19DT05TT0xFX0RJU0NPTk5FQ1Q6IDB4MiwKICAgIFdUU19SRU1PVEVfQ09OTkVDVDogMHgzLAogICAgV1RTX1JFTU9URV9ESVNDT05ORUNUOiAweDQsCiAgICBXVFNfU0VTU0lPTl9MT0dPTjogMHg1LAogICAgV1RTX1NFU1NJT05fTE9HT0ZGOiAweDYsCiAgICBXVFNfU0VTU0lPTl9MT0NLOiAweDcsCiAgICBXVFNfU0VTU0lPTl9VTkxPQ0s6IDB4OCwKICAgIFdUU19TRVNTSU9OX1JFTU9URV9DT05UUk9MOiAweDksCiAgICBXVFNfU0VTU0lPTl9DUkVBVEU6IDB4YSwKICAgIFdUU19TRVNTSU9OX1RFUk1JTkFURTogMHhiCn07CgoKdmFyIE5PX0VSUk9SID0gMDsKCnZhciBzZXJ2aWNlTWFuYWdlciA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpOwoKZnVuY3Rpb24gc2VydmljZUhvc3Qoc2VydmljZU5hbWUpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3NlcnZpY2UtaG9zdCc7CiAgICB2YXIgZW1pdHRlclV0aWxzID0gcmVxdWlyZSgnZXZlbnRzJykuaW5oZXJpdHModGhpcyk7CiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ3NlcnZpY2VTdGFydCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdzZXJ2aWNlU3RvcCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdub3JtYWxTdGFydCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdzZXNzaW9uJyk7CiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ3Bvd2VyU3RhdGVDaGFuZ2UnKTsKCiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgewogICAgICAgIHRoaXMuR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKICAgICAgICB0aGlzLkFkdmFwaSA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0FkdmFwaTMyLmRsbCcpOwogICAgICAgIHRoaXMuQWR2YXBpLkNyZWF0ZU1ldGhvZCh7IG1ldGhvZDogJ1N0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQScsIHRocmVhZERpc3BhdGNoOiAxIH0pOwogICAgICAgIHRoaXMuQWR2YXBpLkNyZWF0ZU1ldGhvZCgnUmVnaXN0ZXJTZXJ2aWNlQ3RybEhhbmRsZXJFeEEnKTsKICAgICAgICB0aGlzLkFkdmFwaS5DcmVhdGVNZXRob2QoJ1NldFNlcnZpY2VTdGF0dXMnKTsKICAgICAgICB0aGlzLktlcm5lbDMyID0gdGhpcy5HTS5DcmVhdGVOYXRpdmVQcm94eSgnS2VybmVsMzIuZGxsJyk7CiAgICAgICAgdGhpcy5LZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldExhc3RFcnJvcicpOwoKICAgICAgICB0aGlzLk9sZTMyID0gdGhpcy5HTS5DcmVhdGVOYXRpdmVQcm94eSgnT2xlMzIuZGxsJyk7CiAgICAgICAgdGhpcy5PbGUzMi5DcmVhdGVNZXRob2QoJ0NvSW5pdGlhbGl6ZUV4Jyk7CiAgICAgICAgdGhpcy5PbGUzMi5DcmVhdGVNZXRob2QoJ0NvVW5pbml0aWFsaXplJyk7CgogICAgICAgIHRoaXMuX1NlcnZpY2VOYW1lID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSh0eXBlb2YgKHNlcnZpY2VOYW1lKSA9PSAnc3RyaW5nJyA/IHNlcnZpY2VOYW1lIDogc2VydmljZU5hbWUubmFtZSk7CiAgICAgICAgdGhpcy5fU2VydmljZU1haW4gPSB0aGlzLkdNLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjaygyKTsKICAgICAgICB0aGlzLl9TZXJ2aWNlTWFpbi5QYXJlbnQgPSB0aGlzOwogICAgICAgIHRoaXMuX1NlcnZpY2VNYWluLkdNID0gdGhpcy5HTTsKICAgICAgICB0aGlzLl9TZXJ2aWNlTWFpbi5vbignR2xvYmFsQ2FsbGJhY2snLCBmdW5jdGlvbiBvbkdsb2JhbENhbGxiYWNrKGFyZ2MsIGFyZ3YpCiAgICAgICAgewogICAgICAgICAgICAvL1RvRG86IENoZWNrIHRvIG1ha2Ugc3VyZSB0aGlzIGlzIGZvciB1cwoKICAgICAgICAgICAgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKDI4KTsKICAgICAgICAgICAgLy90eXBlZGVmIHN0cnVjdCBfU0VSVklDRV9TVEFUVVMgewogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3U2VydmljZVR5cGU7CiAgICAgICAgICAgIC8vICAgIERXT1JEICAgZHdDdXJyZW50U3RhdGU7CiAgICAgICAgICAgIC8vICAgIERXT1JEICAgZHdDb250cm9sc0FjY2VwdGVkOwogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3V2luMzJFeGl0Q29kZTsKICAgICAgICAgICAgLy8gICAgRFdPUkQgICBkd1NlcnZpY2VTcGVjaWZpY0V4aXRDb2RlOwogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3Q2hlY2tQb2ludDsKICAgICAgICAgICAgLy8gICAgRFdPUkQgICBkd1dhaXRIaW50OwogICAgICAgICAgICAvL30gU0VSVklDRV9TVEFUVVMsICpMUFNFUlZJQ0VfU1RBVFVTOwoKICAgICAgICAgICAgLy8gSW5pdGlhbGlzZSBzZXJ2aWNlIHN0YXR1cwogICAgICAgICAgICB0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1cy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoU0VSVklDRV9XSU4zMik7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX1NUQVRFLlNFUlZJQ0VfU1RPUFBFRCwgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzSGFuZGxlID0gdGhpcy5QYXJlbnQuQWR2YXBpLlJlZ2lzdGVyU2VydmljZUN0cmxIYW5kbGVyRXhBKHRoaXMuUGFyZW50Ll9TZXJ2aWNlTmFtZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VDb250cm9sSGFuZGxlciwgdGhpcy5QYXJlbnQuR00uU3Rhc2hPYmplY3QodGhpcy5QYXJlbnQuX1NlcnZpY2VDb250cm9sSGFuZGxlcikpOwogICAgICAgICAgICBpZih0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZS5WYWwgPT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KDEpOwogICAgICAgICAgICB9CgogICAgICAgICAgICAvLyBTZXJ2aWNlIGlzIHN0YXJ0aW5nCiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX1NUQVRFLlNFUlZJQ0VfU1RBUlRfUEVORElORywgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50LkFkdmFwaS5TZXRTZXJ2aWNlU3RhdHVzKHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzSGFuZGxlLCB0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1cyk7CgogICAgICAgICAgICAvLyBTZXJ2aWNlIHJ1bm5pbmcKICAgICAgICAgICAgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKFNFUlZJQ0VfU1RBVEUuUlVOTklORywgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX0FDQ0VQVC5TRVJWSUNFX0FDQ0VQVF9TVE9QIHwgU0VSVklDRV9BQ0NFUFQuU0VSVklDRV9BQ0NFUFRfUE9XRVJFVkVOVCB8IFNFUlZJQ0VfQUNDRVBULlNFUlZJQ0VfQUNDRVBUX1NFU1NJT05DSEFOR0UsIDgpOwogICAgICAgICAgICB0aGlzLlBhcmVudC5BZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMpOwoKICAgICAgICAgICAgdGhpcy5QYXJlbnQuT2xlMzIuQ29Jbml0aWFsaXplRXgoMCwgMik7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Lm9uKCd+JywgZnVuY3Rpb24gT25TZXJ2aWNlSG9zdEZpbmFsaXplcigpCiAgICAgICAgICAgIHsgICAgICAgICAgICAKICAgICAgICAgICAgICAgIHZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwogICAgICAgICAgICAgICAgdmFyIEFkdmFwaSA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdBZHZhcGkzMi5kbGwnKTsKICAgICAgICAgICAgICAgIEFkdmFwaS5DcmVhdGVNZXRob2QoJ1NldFNlcnZpY2VTdGF0dXMnKTsKCiAgICAgICAgICAgICAgICBLZXJuZWwzMiA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0tlcm5lbDMyLmRsbCcpOwogICAgICAgICAgICAgICAgS2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdHZXRMYXN0RXJyb3InKTsKCiAgICAgICAgICAgICAgICB2YXIgc3RhdHVzID0gR00uQ3JlYXRlVmFyaWFibGUoMjgpOwoKICAgICAgICAgICAgICAgIC8vIFNlcnZpY2Ugd2FzIHN0b3BwZWQKICAgICAgICAgICAgICAgIHN0YXR1cy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoU0VSVklDRV9XSU4zMik7CiAgICAgICAgICAgICAgICBzdGF0dXMudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDB4MDAwMDAwMDEsIDQpOwogICAgICAgICAgICAgICAgc3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgwLCA4KTsKCiAgICAgICAgICAgICAgICBBZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLl9TZXJ2aWNlU3RhdHVzSGFuZGxlLCBzdGF0dXMpOwoKICAgICAgICAgICAgICAgIHRoaXMuT2xlMzIuQ29VbmluaXRpYWxpemUoKTsKICAgICAgICAgICAgfSk7CgogICAgICAgICAgICB0aGlzLlBhcmVudC5lbWl0KCdzZXJ2aWNlU3RhcnQnKTsKICAgICAgICB9KTsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIgPSB0aGlzLkdNLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjayg0KTsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIuUGFyZW50ID0gdGhpczsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIuR00gPSB0aGlzLkdNOwogICAgICAgIHRoaXMuX1NlcnZpY2VDb250cm9sSGFuZGxlci5vbignR2xvYmFsQ2FsbGJhY2snLCBmdW5jdGlvbiBvblNlcnZpY2VDb250cm9sSGFuZGxlcihjb2RlLCBldmVudFR5cGUsIGV2ZW50RGF0YSwgY29udGV4dCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBqID0gdGhpcy5QYXJlbnQuR00uVW5zdGFzaE9iamVjdChjb250ZXh0KTsKICAgICAgICAgICAgaWYgKGogIT0gbnVsbCAmJiBqID09IHRoaXMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHN3aXRjaCAoY29kZS5WYWwpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBTRVJWSUNFX0NPTlRST0wuU0VSVklDRV9DT05UUk9MX1NIVVRET1dOOgogICAgICAgICAgICAgICAgICAgIGNhc2UgU0VSVklDRV9DT05UUk9MLlNFUlZJQ0VfQ09OVFJPTF9TVE9QOgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLlBhcmVudC5lbWl0KCdzZXJ2aWNlU3RvcCcpOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgY2FzZSBTRVJWSUNFX0NPTlRST0wuU0VSVklDRV9DT05UUk9MX1NFU1NJT05DSEFOR0U6CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uSWQgPSBldmVudERhdGEuRGVyZWYoNCwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKTsKICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGV2ZW50VHlwZS5WYWwpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgU0VTU0lPTl9DSEFOR0VfVFlQRS5XVFNfU0VTU0lPTl9MT0dPTjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgU0VTU0lPTl9DSEFOR0VfVFlQRS5XVFNfU0VTU0lPTl9MT0dPRkY6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICB0aGlzLlBhcmVudC5BZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMpOwogICAgICAgICAgICB9CiAgICAgICAgfSk7CiAgICB9CgogICAgaWYgKHNlcnZpY2VOYW1lKSB7IHRoaXMuX1NlcnZpY2VPcHRpb25zID0gdHlwZW9mIChzZXJ2aWNlTmFtZSkgPT0gJ29iamVjdCcgPyBzZXJ2aWNlTmFtZSA6IHsgbmFtZTogc2VydmljZU5hbWUgfTsgfQogICAgZWxzZQogICAgewogICAgICAgIHRocm93ICgnTXVzdCBzcGVjaWZ5IGVpdGhlciBTZXJ2aWNlTmFtZSBvciBPcHRpb25zJyk7CiAgICB9CiAgICBpZiAoIXRoaXMuX1NlcnZpY2VPcHRpb25zLnNlcnZpY2VQYXRoKQogICAgewogICAgICAgIHRoaXMuX1NlcnZpY2VPcHRpb25zLnNlcnZpY2VQYXRoID0gcHJvY2Vzcy5leGVjUGF0aDsKICAgIH0KICAgIAogICAgdGhpcy5ydW4gPSBmdW5jdGlvbiBydW4oKQogICAgewogICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtICE9ICd3aW4zMicpCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIFNJR1RFUk1fSGFuZGxlciA9IGZ1bmN0aW9uIF9TSUdURVJNX0hhbmRsZXIoKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIF9TSUdURVJNX0hhbmRsZXIucGFyZW50LmVtaXQoJ3NlcnZpY2VTdG9wJyk7DQogICAgICAgICAgICB9Ow0KICAgICAgICAgICAgU0lHVEVSTV9IYW5kbGVyLnBhcmVudCA9IHRoaXM7DQogICAgICAgICAgICBwcm9jZXNzLm9uKCdTSUdURVJNJywgU0lHVEVSTV9IYW5kbGVyKTsNCiAgICAgICAgfQoKICAgICAgICBmb3IodmFyIGkgPSAwOyBpPHByb2Nlc3MuYXJndi5sZW5ndGg7ICsraSkKICAgICAgICB7CiAgICAgICAgICAgIHN3aXRjaChwcm9jZXNzLmFyZ3ZbaV0pCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGNhc2UgJy1pbnN0YWxsJzoKICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3N2Y01hbmFnZXIpIHsgdGhpcy5fc3ZjTWFuYWdlciA9IG5ldyBzZXJ2aWNlTWFuYWdlcigpOyB9CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmluc3RhbGxTZXJ2aWNlKHRoaXMuX1NlcnZpY2VPcHRpb25zKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGUpOwogICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIGluc3RhbGxlZCcpOwogICAgICAgICAgICAgICAgICAgIHByb2Nlc3MuZXhpdCgpOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnLXVuaW5zdGFsbCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl9zdmNNYW5hZ2VyKSB7IHRoaXMuX3N2Y01hbmFnZXIgPSBuZXcgc2VydmljZU1hbmFnZXIoKTsgfQogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fc3ZjTWFuYWdlci51bmluc3RhbGxTZXJ2aWNlKHRoaXMuX1NlcnZpY2VPcHRpb25zKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGUpOwogICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIHVuaW5zdGFsbGVkJyk7CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdzdGFydCc6CiAgICAgICAgICAgICAgICBjYXNlICctZCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gIT0gJ3dpbjMyJykgeyBicmVhazsgfQogICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fc3ZjTWFuYWdlcikgeyB0aGlzLl9zdmNNYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7IH0KICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmdldFNlcnZpY2UodGhpcy5fU2VydmljZU9wdGlvbnMubmFtZSkuc3RhcnQoKTsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyh0aGlzLl9TZXJ2aWNlT3B0aW9ucy5uYW1lICsgJyBzdGFydGluZy4uLicpOwogICAgICAgICAgICAgICAgICAgIHByb2Nlc3MuZXhpdCgpOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnc3RvcCc6CiAgICAgICAgICAgICAgICBjYXNlICctcyc6CiAgICAgICAgICAgICAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gIT0gJ3dpbjMyJykgeyBicmVhazsgfQogICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fc3ZjTWFuYWdlcikgeyB0aGlzLl9zdmNNYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7IH0KICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmdldFNlcnZpY2UodGhpcy5fU2VydmljZU9wdGlvbnMubmFtZSkuc3RvcCgpOwogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIHN0b3BwaW5nLi4uJyk7CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CgogICAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHNlcnZpY2VUYWJsZSA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUoNCAqIHRoaXMuR00uUG9pbnRlclNpemUpOwogICAgICAgICAgICB0aGlzLl9TZXJ2aWNlTmFtZS5wb2ludGVyQnVmZmVyKCkuY29weShzZXJ2aWNlVGFibGUudG9CdWZmZXIoKSk7CiAgICAgICAgICAgIHRoaXMuX1NlcnZpY2VNYWluLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHNlcnZpY2VUYWJsZS50b0J1ZmZlcigpLCB0aGlzLkdNLlBvaW50ZXJTaXplKTsKICAgICAgICAgICAgdGhpcy5fc3NjZCA9IHRoaXMuQWR2YXBpLlN0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQShzZXJ2aWNlVGFibGUpOwogICAgICAgICAgICB0aGlzLl9zc2NkLnBhcmVudCA9IHRoaXM7CiAgICAgICAgICAgIHRoaXMuX3NzY2Qub24oJ2RvbmUnLCBmdW5jdGlvbiBPblN0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQShyZXRWYWwpIHsKICAgICAgICAgICAgICAgIGlmIChyZXRWYWwuVmFsID09IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW1pdCgnbm9ybWFsU3RhcnQnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgZWxzZSBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIG1vZHVsZU5hbWUgPSB0aGlzLl9TZXJ2aWNlT3B0aW9ucyA/IHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgOiBwcm9jZXNzLmV4ZWNQYXRoLnN1YnN0cmluZygxICsgcHJvY2Vzcy5leGVjUGF0aC5sYXN0SW5kZXhPZignLycpKTsKICAgICAgICAgICAgdmFyIHBsYXRmb3JtVHlwZSA9IHJlcXVpcmUoJ3Byb2Nlc3MtbWFuYWdlcicpLmdldFByb2Nlc3NJbmZvKDEpLk5hbWU7CgogICAgICAgICAgICBpZiAocGxhdGZvcm1UeXBlICE9ICdzeXN0ZW1kJyAmJiBwbGF0Zm9ybVR5cGUgIT0gJ2luaXQnKQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5lbWl0KCdub3JtYWxTdGFydCcpOyAvLyBVbmtub3duIFBsYXRmb3JtIFR5cGUsIHNvIHdlJ3JlIHByb2JhYmx5IG5vdCBhIHNlcnZpY2UNCiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQuc3Rkb3V0LnJlc3VsdCA9ICcnOw0KICAgICAgICAgICAgICAgIHRoaXMuX2NoZWNrcGlkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnJlc3VsdCArPSBjaHVuay50b1N0cmluZygpOyB9KTsNCiAgICAgICAgICAgICAgICBzd2l0Y2gocGxhdGZvcm1UeXBlKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnaW5pdCc6DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9jaGVja3BpZC5zdGRpbi53cml0ZSgnc2VydmljZSAnICsgbW9kdWxlTmFtZSArICIgc3RhdHVzIHwgYXdrICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7DQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnc3lzdGVtZCc6DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9jaGVja3BpZC5zdGRpbi53cml0ZSgnc3lzdGVtY3RsIHN0YXR1cyAnICsgbW9kdWxlTmFtZSArICIgfCBncmVwICdNYWluIFBJRDonIHwgYXdrICd7cHJpbnQgJDN9J1xuZXhpdFxuIik7DQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQud2FpdEV4aXQoKTsNCg0KICAgICAgICAgICAgICAgIGlmKHRoaXMuX2NoZWNrcGlkLnN0ZG91dC5yZXN1bHQgIT0gJycgJiYgcGFyc2VJbnQodGhpcy5fY2hlY2twaWQuc3Rkb3V0LnJlc3VsdCkgPT0gcHJvY2Vzcy5waWQpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ3NlcnZpY2VT", 16000);
	memcpy_s(_servicehost + 16000, 1556, "dGFydCcpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ25vcm1hbFN0YXJ0Jyk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpCiAgICAgICAgewogICAgICAgICAgICAvLyBGaXJzdCBsZXQncyBmZXRjaCBhbGwgdGhlIFBJRHMgb2YgcnVubmluZyBzZXJ2aWNlcwogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCBsaXN0XG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciB0b2tlbnMsIGk7CiAgICAgICAgICAgIHZhciBwID0ge307CiAgICAgICAgICAgIGZvciAoaSA9IDE7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJ1x0Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdICYmIHRva2Vuc1swXSAhPSAnLScpIHsgcFt0b2tlbnNbMF1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmKHBbcHJvY2Vzcy5waWQudG9TdHJpbmcoKV0pCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIFdlIGFyZSBhIHNlcnZpY2UhCiAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ3NlcnZpY2VTdGFydCcpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5lbWl0KCdub3JtYWxTdGFydCcpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfTsKfQoKbW9kdWxlLmV4cG9ydHMgPSBzZXJ2aWNlSG9zdDs=", 1556);
	ILibBase64DecodeEx((unsigned char*)_servicehost, 17556, (unsigned char*)_servicehost + 17556);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "service-host"); duk_push_string(ctx, _servicehost + 17556);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_servicehost);


	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addModule('process-manager', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgp2YXIgR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKCi8vIFVzZWQgb24gV2luZG93cyBhbmQgTGludXggdG8gZ2V0IGluZm9ybWF0aW9uIGFib3V0IHJ1bm5pbmcgcHJvY2Vzc2VzCmZ1bmN0aW9uIHByb2Nlc3NNYW5hZ2VyKCkgewogICAgdGhpcy5fT2JqZWN0SUQgPSAncHJvY2Vzcy1tYW5hZ2VyJzsgLy8gVXNlZCBmb3IgZGVidWdnaW5nLCBhbGxvd3MgeW91IHRvIGdldCB0aGUgb2JqZWN0IHR5cGUgYXQgcnVudGltZS4KICAgIAogICAgLy8gU2V0dXAgdGhlIHBsYXRmb3JtIHNwZWNpZmljIGNhbGxzLgogICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQogICAgewogICAgICAgIGNhc2UgJ3dpbjMyJzoKICAgICAgICAgICAgdGhpcy5fa2VybmVsMzIgPSBHTS5DcmVhdGVOYXRpdmVQcm94eSgna2VybmVsMzIuZGxsJyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2V0TGFzdEVycm9yJyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnQ3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90Jyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnUHJvY2VzczMyRmlyc3QnKTsKICAgICAgICAgICAgdGhpcy5fa2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdQcm9jZXNzMzJOZXh0Jyk7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgJ2xpbnV4JzoKICAgICAgICBjYXNlICdkYXJ3aW4nOgogICAgICAgICAgICB0aGlzLl9jaGlsZFByb2Nlc3MgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJyk7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgIHRocm93IChwcm9jZXNzLnBsYXRmb3JtICsgJyBub3Qgc3VwcG9ydGVkJyk7CiAgICAgICAgICAgIGJyZWFrOwogICAgfQogICAgdGhpcy5lbnVtZXJhdGVQcm9jZXNzZXMgPSBmdW5jdGlvbiBlbnVtZXJhdGVQcm9jZXNzZXMoKQogICAgewogICAgICAgIHZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwogICAgICAgIHZhciByZXQgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOwogICAgICAgIHRoaXMuZ2V0UHJvY2Vzc2VzKGZ1bmN0aW9uIChwcywgcHJvbSkgeyBwcm9tLl9yZXMocHMpOyB9LCByZXQpOwogICAgICAgIHJldHVybiAocmV0KTsKICAgIH0KICAgIC8vIFJldHVybiBhIG9iamVjdCBvZjogcGlkIC0+IHByb2Nlc3MgaW5mb3JtYXRpb24uCiAgICB0aGlzLmdldFByb2Nlc3NlcyA9IGZ1bmN0aW9uIGdldFByb2Nlc3NlcyhjYWxsYmFjaykKICAgIHsKICAgICAgICBzd2l0Y2gocHJvY2Vzcy5wbGF0Zm9ybSkKICAgICAgICB7CiAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0VudW1lcmF0aW5nIHByb2Nlc3NlcyBvbiAnICsgcHJvY2Vzcy5wbGF0Zm9ybSArICcgbm90IHN1cHBvcnRlZCcpOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGNhc2UgJ3dpbjMyJzogLy8gV2luZG93cyBwcm9jZXNzZXMKICAgICAgICAgICAgICAgIHZhciByZXRWYWwgPSB7fTsKICAgICAgICAgICAgICAgIHZhciBoID0gdGhpcy5fa2VybmVsMzIuQ3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90KDIsIDApOwogICAgICAgICAgICAgICAgdmFyIGluZm8gPSBHTS5DcmVhdGVWYXJpYWJsZSgzMDQpOwogICAgICAgICAgICAgICAgaW5mby50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzA0LCAwKTsKICAgICAgICAgICAgICAgIHZhciBuZXh0UHJvY2VzcyA9IHRoaXMuX2tlcm5lbDMyLlByb2Nlc3MzMkZpcnN0KGgsIGluZm8pOwogICAgICAgICAgICAgICAgd2hpbGUgKG5leHRQcm9jZXNzLlZhbCkgCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsW2luZm8uRGVyZWYoOCwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoMCldID0geyBwaWQ6IGluZm8uRGVyZWYoOCwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoMCksIGNtZDogaW5mby5EZXJlZihHTS5Qb2ludGVyU2l6ZSA9PSA0ID8gMzYgOiA0NCwgMjYwKS5TdHJpbmcgfTsKICAgICAgICAgICAgICAgICAgICBuZXh0UHJvY2VzcyA9IHRoaXMuX2tlcm5lbDMyLlByb2Nlc3MzMk5leHQoaCwgaW5mbyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBpZiAoY2FsbGJhY2spIHsgY2FsbGJhY2suYXBwbHkodGhpcywgW3JldFZhbF0pOyB9CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnbGludXgnOiAvLyBMaW51eCBwcm9jZXNzZXMKICAgICAgICAgICAgICAgIGlmICghdGhpcy5fcHNwKSB7IHRoaXMuX3BzcCA9IHt9OyB9CiAgICAgICAgICAgICAgICB2YXIgcCA9IHRoaXMuX2NoaWxkUHJvY2Vzcy5leGVjRmlsZSgiL2Jpbi9wcyIsIFsicHMiLCAiLXV4YSJdLCB7IHR5cGU6IHRoaXMuX2NoaWxkUHJvY2Vzcy5TcGF3blR5cGVzLlRFUk0gfSk7CiAgICAgICAgICAgICAgICB0aGlzLl9wc3BbcC5waWRdID0gcDsKICAgICAgICAgICAgICAgIHAuUGFyZW50ID0gdGhpczsKICAgICAgICAgICAgICAgIHAucHMgPSAnJzsKICAgICAgICAgICAgICAgIHAuY2FsbGJhY2sgPSBjYWxsYmFjazsKICAgICAgICAgICAgICAgIHAuYXJncyA9IFtdOwogICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyArK2kpIHsgcC5hcmdzLnB1c2goYXJndW1lbnRzW2ldKTsgfQogICAgICAgICAgICAgICAgcC5vbignZXhpdCcsIGZ1bmN0aW9uIG9uR2V0UHJvY2Vzc2VzKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBkZWxldGUgdGhpcy5QYXJlbnQuX3BzcFt0aGlzLnBpZF07IAogICAgICAgICAgICAgICAgICAgIHZhciByZXRWYWwgPSB7fSwgbGluZXMgPSB0aGlzLnBzLnNwbGl0KCdceDBEXHgwQScpLCBrZXkgPSB7fSwga2V5aSA9IDA7CiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBsaW5lcykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSBsaW5lc1tpXS5zcGxpdCgnICcpOwogICAgICAgICAgICAgICAgICAgICAgICB2YXIgdG9rZW5MaXN0ID0gW107CiAgICAgICAgICAgICAgICAgICAgICAgIGZvcih2YXIgeCBpbiB0b2tlbnMpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpID09IDAgJiYgdG9rZW5zW3hdKSB7IGtleVt0b2tlbnNbeF1dID0ga2V5aSsrOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaSA+IDAgJiYgdG9rZW5zW3hdKSB7IHRva2VuTGlzdC5wdXNoKHRva2Vuc1t4XSk7fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpID4gMCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRva2VuTGlzdFtrZXkuUElEXSkgeyByZXRWYWxbdG9rZW5MaXN0W2tleS5QSURdXSA9IHsgcGlkOiBrZXkuUElELCB1c2VyOiB0b2tlbkxpc3Rba2V5LlVTRVJdLCBjbWQ6IHRva2VuTGlzdFtrZXkuQ09NTUFORF0gfTsgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLmNhbGxiYWNrKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5hcmdzLnVuc2hpZnQocmV0VmFsKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5jYWxsYmFjay5hcHBseSh0aGlzLnBhcmVudCwgdGhpcy5hcmdzKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIHAuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMucGFyZW50LnBzICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGNhc2UgJ2Rhcndpbic6CiAgICAgICAgICAgICAgICB2YXIgcHJvbWlzZSA9IHJlcXVpcmUoJ3Byb21pc2UnKTsKICAgICAgICAgICAgICAgIHZhciBwID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsKICAgICAgICAgICAgICAgIHAucG0gPSB0aGlzOwogICAgICAgICAgICAgICAgcC5jYWxsYmFjayA9IGNhbGxiYWNrOwogICAgICAgICAgICAgICAgcC5hcmdzID0gW107CiAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMTsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7ICsraSkgeyBwLmFyZ3MucHVzaChhcmd1bWVudHNbaV0pOyB9CiAgICAgICAgICAgICAgICBwLmNoaWxkID0gdGhpcy5fY2hpbGRQcm9jZXNzLmV4ZWNGaWxlKCIvYmluL3BzIiwgWyJwcyIsICIteGEiXSk7CiAgICAgICAgICAgICAgICBwLmNoaWxkLnByb21pc2UgPSBwOwogICAgICAgICAgICAgICAgcC5jaGlsZC5zdGRvdXQucHMgPSAnJzsKICAgICAgICAgICAgICAgIHAuY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMucHMgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBwLmNoaWxkLm9uKCdleGl0JywgZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgbGluZXMgPSB0aGlzLnN0ZG91dC5wcy5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgICAgICB2YXIgcGlkWCA9IGxpbmVzWzBdLnNwbGl0KCdQSUQnKVswXS5sZW5ndGggKyAzOwogICAgICAgICAgICAgICAgICAgIHZhciBjbWRYID0gbGluZXNbMF0uc3BsaXQoJ0NNRCcpWzBdLmxlbmd0aDsKICAgICAgICAgICAgICAgICAgICB2YXIgcmV0ID0ge307CiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChsaW5lc1tpXS5sZW5ndGggPiAwKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRbbGluZXNbaV0uc3Vic3RyaW5nKDAsIHBpZFgpLnRyaW0oKV0gPSB7IHBpZDogbGluZXNbaV0uc3Vic3RyaW5nKDAsIHBpZFgpLnRyaW0oKSwgY21kOiBsaW5lc1tpXS5zdWJzdHJpbmcoY21kWCkgfTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlcyhyZXQpOwogICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICBwLnRoZW4oZnVuY3Rpb24gKHBzKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRoaXMuYXJncy51bnNoaWZ0KHBzKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLmNhbGxiYWNrLmFwcGx5KHRoaXMucG0sIHRoaXMuYXJncyk7CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgIH07CgogICAgLy8gR2V0IGluZm9ybWF0aW9uIGFib3V0IGEgc3BlY2lmaWMgcHJvY2VzcyBvbiBMaW51eAogICAgdGhpcy5nZXRQcm9jZXNzSW5mbyA9IGZ1bmN0aW9uIGdldFByb2Nlc3NJbmZvKHBpZCkKICAgIHsKICAgICAgICBzd2l0Y2gocHJvY2Vzcy5wbGF0Zm9ybSkKICAgICAgICB7CiAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICB0aHJvdyAoJ2dldFByb2Nlc3NJbmZvKCkgbm90IHN1cHBvcnRlZCBmb3IgJyArIHByb2Nlc3MucGxhdGZvcm0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGNhc2UgJ2xpbnV4JzoKICAgICAgICAgICAgICAgIHZhciBzdGF0dXMgPSByZXF1aXJlKCdmcycpLnJlYWRGaWxlU3luYygnL3Byb2MvJyArIHBpZCArICcvc3RhdHVzJyk7CiAgICAgICAgICAgICAgICB2YXIgaW5mbyA9IHt9OwogICAgICAgICAgICAgICAgdmFyIGxpbmVzID0gc3RhdHVzLnRvU3RyaW5nKCkuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgICAgICBmb3IodmFyIGkgaW4gbGluZXMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIHRva2VucyA9IGxpbmVzW2ldLnNwbGl0KCc6Jyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2Vucy5sZW5ndGggPiAxKSB7IHRva2Vuc1sxXSA9IHRva2Vuc1sxXS50cmltKCk7IH0KICAgICAgICAgICAgICAgICAgICBpbmZvW3Rva2Vuc1swXV0gPSB0b2tlbnNbMV07CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICByZXR1cm4gKGluZm8pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgfTsKfQoKbW9kdWxlLmV4cG9ydHMgPSBuZXcgcHJvY2Vzc01hbmFnZXIoKTs=', 'base64').toString());");
#if defined(_POSIX) && !defined(__APPLE__)
	duk_peval_string_noresult(ctx, "addModule('linux-dbus', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnRyeSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShBcnJheS5wcm90b3R5cGUsICJwZWVrIiwgeyB2YWx1ZTogZnVuY3Rpb24gKCkgeyByZXR1cm4gKHRoaXMubGVuZ3RoID4gMCA/IHRoaXNbdGhpcy5sZW5ndGggLSAxXSA6IHVuZGVmaW5lZCk7IH0gfSk7IH0gY2F0Y2ggKGUpIHsgfQoKCgpmdW5jdGlvbiBkYnVzKGFkZHJlc3MsIHVpZCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAnbGludXgtZGJ1cyc7CiAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbCh0aGlzLCB0cnVlKQogICAgICAgIC5jcmVhdGVFdmVudCgnc2lnbmFsJyk7CiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgInVpZCIsIHsgdmFsdWU6IHVpZCB9KTsKICAgIHRoaXMuX2NoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCIvYmluL3NoIiwgWyJzaCJdLCB7IHR5cGU6IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5TcGF3blR5cGVzLlRFUk0sIHVpZDogdWlkID09IG51bGwgPyAtMSA6IHVpZCB9KTsKICAgIHRoaXMuX2NoaWxkLnN0ZGluLndyaXRlKCdkYnVzLW1vbml0b3IgLS1zZXNzaW9uICJ0eXBlPVwnc2lnbmFsXCcsIGludGVyZmFjZT1cJycgKyBhZGRyZXNzICsgJ1wnIiB8ICggd2hpbGUgcmVhZCBYOyBkbyBlY2hvICIkWCI7IGRvbmUgKVxuJyk7CiAgICB0aGlzLl9jaGlsZC5zdGRvdXQuZGJ1cyA9IHRoaXM7CiAgICB0aGlzLl9jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspCiAgICB7CiAgICAgICAgLy8gUGFyc2UgREJVUyBEYXRhCiAgICAgICAgaWYgKCF0aGlzLnJlYWR5KSB7IHRoaXMucmVhZHkgPSB0cnVlOyByZXR1cm47IH0KCiAgICAgICAgdmFyIGxpbmVzID0gW107CiAgICAgICAgdmFyIHRva2VucyA9IGNodW5rLnRvU3RyaW5nKCkuc3BsaXQoJ1xyXG4nKTsKICAgICAgICBmb3IgKHZhciBpIGluIHRva2VucykKICAgICAgICB7CiAgICAgICAgICAgIGlmICh0b2tlbnNbaV0gPT0gJycpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIEVuZCBvZiByZWNvcmQKICAgICAgICAgICAgICAgIHRoaXMuZGJ1cy5wcmVQYXJzZVJlY29yZHMobGluZXMpOwogICAgICAgICAgICAgICAgbGluZXMgPSBbXTsKICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGxpbmVzLnB1c2godG9rZW5zW2ldKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0pOwogICAgdGhpcy5wcmVQYXJzZVJlY29yZHMgPSBmdW5jdGlvbiAobGluZXMpCiAgICB7CiAgICAgICAgdmFyIHJlY29yZCA9IFtdOwogICAgICAgIGZvciAodmFyIGkgaW4gbGluZXMpCiAgICAgICAgewogICAgICAgICAgICBpZihsaW5lc1tpXS5zdGFydHNXaXRoKCdzaWduYWwgJykpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmKHJlY29yZC5sZW5ndGg+MCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcnNlUmVjb3JkcyhyZWNvcmQpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmVjb3JkID0gW107CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmVjb3JkLnB1c2gobGluZXNbaV0pOwogICAgICAgIH0KICAgICAgICBpZiAocmVjb3JkLmxlbmd0aCA+IDApCiAgICAgICAgewogICAgICAgICAgICB0aGlzLnBhcnNlUmVjb3JkcyhyZWNvcmQpOwogICAgICAgIH0KICAgIH0KICAgIHRoaXMucGFyc2VSZWNvcmRzID0gZnVuY3Rpb24gKGxpbmVzKQogICAgewogICAgICAgIGlmIChsaW5lc1swXS5zdGFydHNXaXRoKCdzaWduYWwgJykpCiAgICAgICAgewogICAgICAgICAgICB2YXIgc2lnbmFsID0ge307CiAgICAgICAgICAgIHZhciBzaWd0b2tlbnMgPSBsaW5lc1swXS5zcGxpdCgnICcpOwogICAgICAgICAgICBzaWd0b2tlbnMuc2hpZnQoKTsKCiAgICAgICAgICAgIGZvciAodmFyIGkgaW4gc2lndG9rZW5zKSB7CiAgICAgICAgICAgICAgICB2YXIgc2lnaXRlbXMgPSBzaWd0b2tlbnNbaV0uc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgIGlmIChzaWdpdGVtcy5sZW5ndGggPT0gMikgewogICAgICAgICAgICAgICAgICAgIHNpZ25hbFtzaWdpdGVtc1swXV0gPSBzaWdpdGVtc1sxXTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgbGluZXMuc2hpZnQoKTsKICAgICAgICAgICAgc2lnbmFsLmRhdGEgPSBsaW5lczsKCiAgICAgICAgICAgIHRoaXMucGFyc2VTaWduYWwoc2lnbmFsKTsKICAgICAgICB9CiAgICB9CiAgICB0aGlzLnBhcnNlU2lnbmFsID0gZnVuY3Rpb24oc2lnbmFsKQogICAgewogICAgICAgIHZhciBkYXRhID0gc2lnbmFsLmRhdGE7CiAgICAgICAgc2lnbmFsLmRhdGEgPSBbXTsKCiAgICAgICAgZm9yKHZhciBpPTA7IGk8ZGF0YS5sZW5ndGg7ICsraSkKICAgICAgICB7CiAgICAgICAgICAgIGlmIChkYXRhW2ldLnN0YXJ0c1dpdGgoJ2FycmF5ICcpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBzaWduYWwuZGF0YS5wdXNoKFtdKTsKICAgICAgICAgICAgICAgIGZvcihpPWkrMTsgaTxkYXRhLmxlbmd0aDsgKytpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRoaXMucGFyc2VTaWduYWwyKGRhdGFbaV0sIHNpZ25hbC5kYXRhLnBlZWsoKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aGlzLnBhcnNlU2lnbmFsMihkYXRhW2ldLCBzaWduYWwuZGF0YSk7CiAgICAgICAgICAgIH0KICAgICAgICB9CgogICAgICAgIHRoaXMuZW1pdCgnc2lnbmFsJywgc2lnbmFsKTsKICAgIH0KICAgIHRoaXMucGFyc2VTaWduYWwyID0gZnVuY3Rpb24gKGlucHV0U3RyLCBvdXRBcnJheSkKICAgIHsKICAgICAgICBpZihpbnB1dFN0ci5zdGFydHNXaXRoKCdzdHJpbmcgJykpCiAgICAgICAgewogICAgICAgICAgICBvdXRBcnJheS5wdXNoKEpTT04ucGFyc2UoaW5wdXRTdHIuc2xpY2UoNykpKTsKICAgICAgICB9CiAgICAgICAgZWxzZSBpZihpbnB1dFN0ci5zdGFydHNXaXRoKCdib29sZWFuICcpKQogICAgICAgIHsKICAgICAgICAgICAgb3V0QXJyYXkucHVzaChKU09OLnBhcnNlKGlucHV0U3RyLnNsaWNlKDgpKSk7CiAgICAgICAgfQogICAgfQp9Cgptb2R1bGUuZXhwb3J0cyA9IGRidXM7Cv==', 'base64').toString());");
#endif

	char *_servicemanager = ILibMemory_Allocate(143628, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 82072, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgpmdW5jdGlvbiBleHRyYWN0RmlsZU5hbWUoZmlsZVBhdGgpCnsKICAgIGlmICh0eXBlb2YgKGZpbGVQYXRoKSA9PSAnc3RyaW5nJykKICAgIHsKICAgICAgICB2YXIgdG9rZW5zID0gZmlsZVBhdGguc3BsaXQoJ1xcJykuam9pbignLycpLnNwbGl0KCcvJyk7CiAgICAgICAgdmFyIG5hbWU7CgogICAgICAgIHdoaWxlICgobmFtZSA9IHRva2Vucy5wb3AoKSkgPT0gJycpOwogICAgICAgIHJldHVybiAobmFtZSk7CiAgICB9CiAgICBlbHNlCiAgICB7CiAgICAgICAgcmV0dXJuKGZpbGVQYXRoLm5ld05hbWUpCiAgICB9Cn0KZnVuY3Rpb24gZXh0cmFjdEZpbGVTb3VyY2UoZmlsZVBhdGgpCnsKICAgIHJldHVybiAodHlwZW9mIChmaWxlUGF0aCkgPT0gJ3N0cmluZycgPyBmaWxlUGF0aCA6IGZpbGVQYXRoLnNvdXJjZSk7Cn0KCmZ1bmN0aW9uIHBhcnNlU2VydmljZVN0YXR1cyh0b2tlbikKewogICAgdmFyIGogPSB7fTsKICAgIHZhciBzZXJ2aWNlVHlwZSA9IHRva2VuLkRlcmVmKDAsIDQpLkludFZhbDsKICAgIGouaXNGaWxlU3lzdGVtRHJpdmVyID0gKChzZXJ2aWNlVHlwZSAmIDB4MDAwMDAwMDIpID09IDB4MDAwMDAwMDIpOwogICAgai5pc0tlcm5lbERyaXZlciA9ICgoc2VydmljZVR5cGUgJiAweDAwMDAwMDAxKSA9PSAweDAwMDAwMDAxKTsKICAgIGouaXNTaGFyZWRQcm9jZXNzID0gKChzZXJ2aWNlVHlwZSAmIDB4MDAwMDAwMjApID09IDB4MDAwMDAwMjApOwogICAgai5pc093blByb2Nlc3MgPSAoKHNlcnZpY2VUeXBlICYgMHgwMDAwMDAxMCkgPT0gMHgwMDAwMDAxMCk7CiAgICBqLmlzSW50ZXJhY3RpdmUgPSAoKHNlcnZpY2VUeXBlICYgMHgwMDAwMDEwMCkgPT0gMHgwMDAwMDEwMCk7CiAgICBzd2l0Y2ggKHRva2VuLkRlcmVmKCgxICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpCiAgICB7CiAgICAgICAgY2FzZSAweDAwMDAwMDA1OgogICAgICAgICAgICBqLnN0YXRlID0gJ0NPTlRJTlVFX1BFTkRJTkcnOwogICAgICAgICAgICBicmVhazsKICAgICAgICBjYXNlIDB4MDAwMDAwMDY6CiAgICAgICAgICAgIGouc3RhdGUgPSAnUEFVU0VfUEVORElORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwNzoKICAgICAgICAgICAgai5zdGF0ZSA9ICdQQVVTRUQnOwogICAgICAgICAgICBicmVhazsKICAgICAgICBjYXNlIDB4MDAwMDAwMDQ6CiAgICAgICAgICAgIGouc3RhdGUgPSAnUlVOTklORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwMjoKICAgICAgICAgICAgai5zdGF0ZSA9ICdTVEFSVF9QRU5ESU5HJzsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAweDAwMDAwMDAzOgogICAgICAgICAgICBqLnN0YXRlID0gJ1NUT1BfUEVORElORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwMToKICAgICAgICAgICAgai5zdGF0ZSA9ICdTVE9QUEVEJzsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CiAgICB2YXIgY29udHJvbHNBY2NlcHRlZCA9IHRva2VuLkRlcmVmKCgyICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCk7CiAgICBqLmNvbnRyb2xzQWNjZXB0ZWQgPSBbXTsKICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAwMTApID09IDB4MDAwMDAwMTApCiAgICB7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5EQUREJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5EUkVNT1ZFJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5ERU5BQkxFJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5ERElTQUJMRScpOwogICAgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAwOCkgPT0gMHgwMDAwMDAwOCkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX1BBUkFNQ0hBTkdFJyk7IH0KICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAwMDIpID09IDB4MDAwMDAwMDIpIHsgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9QQVVTRScpOyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX0NPTlRJTlVFJyk7IH0KICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAxMDApID09IDB4MDAwMDAxMDApIHsgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9QUkVTSFVURE9XTicpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDA0KSA9PSAweDAwMDAwMDA0KSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfU0hVVERPV04nKTsgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAwMSkgPT0gMHgwMDAwMDAwMSkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX1NUT1AnKTsgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAyMCkgPT0gMHgwMDAwMDAyMCkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX0hBUkRXQVJFUFJPRklMRUNIQU5HRScpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDQwKSA9PSAweDAwMDAwMDQwKSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfUE9XRVJFVkVOVCcpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDgwKSA9PSAweDAwMDAwMDgwKSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfU0VTU0lPTkNIQU5HRScpOyB9CiAgICBqLnBpZCA9IHRva2VuLkRlcmVmKCg3ICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCk7CiAgICByZXR1cm4gKGopOwp9CgpmdW5jdGlvbiBzZXJ2aWNlTWFuYWdlcigpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3NlcnZpY2UtbWFuYWdlcic7CiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKSAKICAgIHsKICAgICAgICB0aGlzLkdNID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICAgICAgdGhpcy5wcm94eSA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0FkdmFwaTMyLmRsbCcpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdPcGVuU0NNYW5hZ2VyQScpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdFbnVtU2VydmljZXNTdGF0dXNFeEEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnT3BlblNlcnZpY2VBJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ1F1ZXJ5U2VydmljZVN0YXR1c0V4Jyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ1F1ZXJ5U2VydmljZUNvbmZpZ0EnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnUXVlcnlTZXJ2aWNlQ29uZmlnMkEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ29udHJvbFNlcnZpY2UnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnU3RhcnRTZXJ2aWNlQScpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdDbG9zZVNlcnZpY2VIYW5kbGUnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ3JlYXRlU2VydmljZUEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ2hhbmdlU2VydmljZUNvbmZpZzJBJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0RlbGV0ZVNlcnZpY2UnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQWxsb2NhdGVBbmRJbml0aWFsaXplU2lkJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0NoZWNrVG9rZW5NZW1iZXJzaGlwJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0ZyZWVTaWQnKTsKCiAgICAgICAgdGhpcy5wcm94eTIgPSB0aGlzLkdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdLZXJuZWwzMi5kbGwnKTsKICAgICAgICB0aGlzLnByb3h5Mi5DcmVhdGVNZXRob2QoJ0dldExhc3RFcnJvcicpOwoKICAgICAgICB0aGlzLmlzQWRtaW4gPSBmdW5jdGlvbiBpc0FkbWluKCkgewogICAgICAgICAgICB2YXIgTlRBdXRob3JpdHkgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKDYpOwogICAgICAgICAgICBOVEF1dGhvcml0eS50b0J1ZmZlcigpLndyaXRlSW50OCg1LCA1KTsKICAgICAgICAgICAgdmFyIEFkbWluaXN0cmF0b3JzR3JvdXAgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGFkbWluID0gZmFsc2U7CgogICAgICAgICAgICBpZiAodGhpcy5wcm94eS5BbGxvY2F0ZUFuZEluaXRpYWxpemVTaWQoTlRBdXRob3JpdHksIDIsIDMyLCA1NDQsIDAsIDAsIDAsIDAsIDAsIDAsIEFkbWluaXN0cmF0b3JzR3JvdXApLlZhbCAhPSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgbWVtYmVyID0gdGhpcy5HTS5DcmVhdGVJbnRlZ2VyKCk7CiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGVja1Rva2VuTWVtYmVyc2hpcCgwLCBBZG1pbmlzdHJhdG9yc0dyb3VwLkRlcmVmKCksIG1lbWJlcikuVmFsICE9IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYgKG1lbWJlci50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpICE9IDApIHsgYWRtaW4gPSB0cnVlOyB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB0aGlzLnByb3h5LkZyZWVTaWQoQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gYWRtaW47CiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFByb2dyYW1Gb2xkZXIgPSBmdW5jdGlvbiBnZXRQcm9ncmFtRm9sZGVyKCkKICAgICAgICB7CiAgICAgICAgICAgIGlmIChyZXF1aXJlKCdvcycpLmFyY2goKSA9PSAneDY0JykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gNjQgYml0IFdpbmRvd3MKICAgICAgICAgICAgICAgIGlmICh0aGlzLkdNLlBvaW50ZXJTaXplID09IDQpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHByb2Nlc3MuZW52WydQcm9ncmFtRmlsZXMoeDg2KSddOyAgICAvLyAzMiBCaXQgQXBwCiAgICAgICAgICAgICAgICB9IAogICAgICAgICAgICAgICAgcmV0dXJuIHByb2Nlc3MuZW52WydQcm9ncmFtRmlsZXMnXTsgICAgICAgICAgICAgLy8gNjQgYml0IEFwcAogICAgICAgICAgICB9CgogICAgICAgICAgICAvLyAzMiBiaXQgV2luZG93cwogICAgICAgICAgICByZXR1cm4gcHJvY2Vzcy5lbnZbJ1Byb2dyYW1GaWxlcyddOyAgICAgICAgICAgICAgICAgCiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFNlcnZpY2VGb2xkZXIgPSBmdW5jdGlvbiBnZXRTZXJ2aWNlRm9sZGVyKCkgeyByZXR1cm4gdGhpcy5nZXRQcm9ncmFtRm9sZGVyKCkgKyAnXFxtZXNoJzsgfTsKCiAgICAgICAgdGhpcy5lbnVtZXJhdGVTZXJ2aWNlID0gZnVuY3Rpb24gKCkgewogICAgICAgICAgICB2YXIgbWFjaGluZU5hbWUgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGRiTmFtZSA9IHRoaXMuR00uQ3JlYXRlUG9pbnRlcigpOwogICAgICAgICAgICB2YXIgaGFuZGxlID0gdGhpcy5wcm94eS5PcGVuU0NNYW5hZ2VyQSgweDAwLCAweDAwLCAweDAwMDEgfCAweDAwMDQpOwoKICAgICAgICAgICAgdmFyIGJ5dGVzTmVlZGVkID0gdGhpcy5HTS5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciBzZXJ2aWNlc1JldHVybmVkID0gdGhpcy5HTS5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciByZXN1bWVIYW5kbGUgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgLy92YXIgc2VydmljZXMgPSB0aGlzLnByb3h5LkNyZWF0ZVZhcmlhYmxlKDI2MjE0NCk7CiAgICAgICAgICAgIHZhciBzdWNjZXNzID0gdGhpcy5wcm94eS5FbnVtU2VydmljZXNTdGF0dXNFeEEoaGFuZGxlLCAwLCAweDAwMDAwMDMwLCAweDAwMDAwMDAzLCAweDAwLCAweDAwLCBieXRlc05lZWRlZCwgc2VydmljZXNSZXR1cm5lZCwgcmVzdW1lSGFuZGxlLCAweDAwKTsKICAgICAgICAgICAgaWYgKGJ5dGVzTmVlZGVkLkludFZhbCA8PSAwKSB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ2Vycm9yIGVudW1lcmF0aW5nIHNlcnZpY2VzJyk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdmFyIHN6ID0gYnl0ZXNOZWVkZWQuSW50VmFsOwogICAgICAgICAgICB2YXIgc2VydmljZXMgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKHN6KTsKICAgICAgICAgICAgdGhpcy5wcm94eS5FbnVtU2VydmljZXNTdGF0dXNFeEEoaGFuZGxlLCAwLCAweDAwMDAwMDMwLCAweDAwMDAwMDAzLCBzZXJ2aWNlcywgc3osIGJ5dGVzTmVlZGVkLCBzZXJ2aWNlc1JldHVybmVkLCByZXN1bWVIYW5kbGUsIDB4MDApOwogICAgICAgICAgICBjb25zb2xlLmxvZygic2VydmljZXNSZXR1cm5lZCIsIHNlcnZpY2VzUmV0dXJuZWQuSW50VmFsKTsKCiAgICAgICAgICAgIHZhciBwdHJTaXplID0gZGJOYW1lLl9zaXplOwogICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gMzYgKyAoMiAqIHB0clNpemUpOwogICAgICAgICAgICBibG9ja1NpemUgKz0gKChwdHJTaXplIC0gKGJsb2NrU2l6ZSAlIHB0clNpemUpKSAlIHB0clNpemUpOwogICAgICAgICAgICB2YXIgcmV0VmFsID0gW107CiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2VydmljZXNSZXR1cm5lZC5JbnRWYWw7ICsraSkgewogICAgICAgICAgICAgICAgdmFyIHRva2VuID0gc2VydmljZXMuRGVyZWYoaSAqIGJsb2NrU2l6ZSwgYmxvY2tTaXplKTsKICAgICAgICAgICAgICAgIHZhciBqID0ge307CiAgICAgICAgICAgICAgICBqLm5hbWUgPSB0b2tlbi5EZXJlZigwLCBwdHJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouZGlzcGxheU5hbWUgPSB0b2tlbi5EZXJlZihwdHJTaXplLCBwdHJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouc3RhdHVzID0gcGFyc2VTZXJ2aWNlU3RhdHVzKHRva2VuLkRlcmVmKDIgKiBwdHJTaXplLCAzNikpOwogICAgICAgICAgICAgICAgcmV0VmFsLnB1c2goaik7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaGFuZGxlKTsKICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgIH0KICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiAobmFtZSkgewogICAgICAgICAgICB2YXIgc2VydmljZU5hbWUgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKG5hbWUpOwogICAgICAgICAgICB2YXIgcHRyID0gdGhpcy5HTS5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciBieXRlc05lZWRlZCA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUocHRyLl9zaXplKTsKICAgICAgICAgICAgdmFyIGhhbmRsZSA9IHRoaXMucHJveHkuT3BlblNDTWFuYWdlckEoMHgwMCwgMHgwMCwgMHgwMDAxIHwgMHgwMDA0IHwgMHgwMDIwIHwgMHgwMDEwKTsKICAgICAgICAgICAgaWYgKGhhbmRsZS5WYWwgPT0gMCkgeyB0aHJvdyAoJ2NvdWxkIG5vdCBvcGVuIFNlcnZpY2VNYW5hZ2VyJyk7IH0KICAgICAgICAgICAgdmFyIGggPSB0aGlzLnByb3h5Lk9wZW5TZXJ2aWNlQShoYW5kbGUsIHNlcnZpY2VOYW1lLCAweDAwMDEgfCAweDAwMDQgfCAweDAwMjAgfCAweDAwMTAgfCAweDAwMDEwMDAwKTsKICAgICAgICAgICAgaWYgKGguVmFsICE9IDApIHsKICAgICAgICAgICAgICAgIHZhciBzdWNjZXNzID0gdGhpcy5wcm94eS5RdWVyeVNlcnZpY2VTdGF0dXNFeChoLCAwLCAwLCAwLCBieXRlc05lZWRlZCk7CiAgICAgICAgICAgICAgICB2YXIgc3RhdHVzID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZShieXRlc05lZWRlZC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKTsKICAgICAgICAgICAgICAgIHN1Y2Nlc3MgPSB0aGlzLnByb3h5LlF1ZXJ5U2VydmljZVN0YXR1c0V4KGgsIDAsIHN0YXR1cywgc3RhdHVzLl9zaXplLCBieXRlc05lZWRlZCk7CiAgICAgICAgICAgICAgICBpZiAoc3VjY2VzcyAhPSAwKSB7CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsID0ge307CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLnN0YXR1cyA9IHBhcnNlU2VydmljZVN0YXR1cyhzdGF0dXMpOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5fc2NtID0gaGFuZGxlOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5fc2VydmljZSA9IGg7CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9HTSA9IHRoaXMuR007CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9wcm94eSA9IHRoaXMucHJveHk7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZXZlbnRzJykuaW5oZXJpdHMocmV0VmFsKTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwub24oJ34nLCBmdW5jdGlvbiAoKSB7IHRoaXMuX3Byb3h5LkNsb3NlU2VydmljZUhhbmRsZSh0aGlzKTsgdGhpcy5fcHJveHkuQ2xvc2VTZXJ2aWNlSGFuZGxlKHRoaXMuX3NjbSk7IH0pOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5uYW1lID0gbmFtZTsKCiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmFwcExvY2F0aW9uID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZWcgPSByZXF1aXJlKCd3aW4tcmVnaXN0cnknKTsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGltYWdlUGF0aCA9IHJlZy5RdWVyeUtleShyZWcuSEtFWS5Mb2NhbE1hY2hpbmUsICdTWVNURU1cXEN1cnJlbnRDb250cm9sU2V0XFxTZXJ2aWNlc1xcJyArIHRoaXMubmFtZSwgJ0ltYWdlUGF0aCcpLnRvU3RyaW5nKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXQgPSBpbWFnZVBhdGguc3BsaXQoJy5leGUnKVswXSArICcuZXhlJzsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJldC5zdGFydHNXaXRoKCciJykpIHsgcmV0ID0gcmV0LnN1YnN0cmluZygxKTsgfQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwuYXBwV29ya2luZ0RpcmVjdG9yeSA9IGZ1bmN0aW9uICgpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgdG9rZW5zID0gdGhpcy5hcHBMb2NhdGlvbigpLnNwbGl0KCdcXCcpOwogICAgICAgICAgICAgICAgICAgICAgICB0b2tlbnMucG9wKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAodG9rZW5zLmpvaW4oJ1xcJykpOwogICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmlzUnVubmluZyA9IGZ1bmN0aW9uICgpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgYnl0ZXNOZWVkZWQgPSB0aGlzLl9HTS5DcmVhdGVWYXJpYWJsZSh0aGlzLl9HTS5Qb2ludGVyU2l6ZSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3Byb3h5LlF1ZXJ5U2VydmljZVN0YXR1c0V4KHRoaXMuX3NlcnZpY2UsIDAsIDAsIDAsIGJ5dGVzTmVlZGVkKTsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHN0ID0gdGhpcy5fR00uQ3JlYXRlVmFyaWFibGUoYnl0ZXNOZWVkZWQudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmKHRoaXMuX3Byb3h5LlF1ZXJ5U2VydmljZVN0YXR1c0V4KHRoaXMuX3NlcnZpY2UsIDAsIHN0LCBzdC5fc2l6ZSwgYnl0ZXNOZWVkZWQpLlZhbCAhPSAwKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3RhdGUgPSBwYXJzZVNlcnZpY2VTdGF0dXMoc3QpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChzdGF0ZS5zdGF0ZSA9PSAnUlVOTklORycpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoZmFsc2UpOwogICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLnN0b3AgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnN0YXR1cy5zdGF0ZSA9PSAnUlVOTklORycpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBuZXdzdGF0ZSA9IHRoaXMuX0dNLkNyZWF0ZVZhcmlhYmxlKDM2KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzdWNjZXNzID0gdGhpcy5fcHJveHkuQ29udHJvbFNlcnZpY2UodGhpcy5fc2VydmljZSwgMHgwMDAwMDAwMSwgbmV3c3RhdGUpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHN1Y2Nlc3MgPT0gMCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICh0aGlzLm5hbWUgKyAnLnN0b3AoKSBmYWlsZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnY2Fubm90IGNhbGwgJyArIHRoaXMubmFtZSArICcuc3RvcCgpLCB3aGVuIGN1cnJlbnQgc3RhdGUgaXM6ICcgKyB0aGlzLnN0YXR1cy5zdGF0ZSk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLnN0YXJ0ID0gZnVuY3Rpb24gKCkgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zdGF0dXMuc3RhdGUgPT0gJ1NUT1BQRUQnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3VjY2VzcyA9IHRoaXMuX3Byb3h5LlN0YXJ0U2VydmljZUEodGhpcy5fc2VydmljZSwgMCwgMCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3VjY2VzcyA9PSAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHRoaXMubmFtZSArICcuc3RhcnQoKSBmYWlsZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnY2Fubm90IGNhbGwgJyArIHRoaXMubmFtZSArICcuc3RhcnQoKSwgd2hlbiBjdXJyZW50IHN0YXRlIGlzOiAnICsgdGhpcy5zdGF0dXMuc3RhdGUpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICB2YXIgcXVlcnlfc2VydmljZV9jb25maWdhX0RXT1JEID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSg0KTsK", 16000);
	memcpy_s(_servicemanager + 16000, 66072, "ICAgICAgICAgICAgICAgICAgICB0aGlzLnByb3h5LlF1ZXJ5U2VydmljZUNvbmZpZ0EoaCwgMCwgMCwgcXVlcnlfc2VydmljZV9jb25maWdhX0RXT1JEKTsKICAgICAgICAgICAgICAgICAgICBpZiAocXVlcnlfc2VydmljZV9jb25maWdhX0RXT1JELnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkgPiAwKQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBxdWVyeV9zZXJ2aWNlX2NvbmZpZ2EgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKHF1ZXJ5X3NlcnZpY2VfY29uZmlnYV9EV09SRC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYodGhpcy5wcm94eS5RdWVyeVNlcnZpY2VDb25maWdBKGgsIHF1ZXJ5X3NlcnZpY2VfY29uZmlnYSwgcXVlcnlfc2VydmljZV9jb25maWdhLl9zaXplLCBxdWVyeV9zZXJ2aWNlX2NvbmZpZ2FfRFdPUkQpLlZhbCAhPSAwKQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbCA9IHF1ZXJ5X3NlcnZpY2VfY29uZmlnYS5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDQgPyAyOCA6IDQ4LCB0aGlzLkdNLlBvaW50ZXJTaXplKS5EZXJlZigpLlN0cmluZzsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0VmFsLCAndXNlcicsIHsgdmFsdWU6IHZhbCB9KTsNCiAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgfQoKCiAgICAgICAgICAgICAgICAgICAgdmFyIGZhaWx1cmVhY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSg4MTkyKTsKICAgICAgICAgICAgICAgICAgICB2YXIgYm5lZWRlZCA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUoNCk7ICAgICAgICAKICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5RdWVyeVNlcnZpY2VDb25maWcyQShoLCAyLCBmYWlsdXJlYWN0aW9ucywgODE5MiwgYm5lZWRlZCkuVmFsICE9IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgY0FjdGlvbnMgPSBmYWlsdXJlYWN0aW9ucy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSh0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAyNCA6IDEyKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zID0ge307CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5mYWlsdXJlQWN0aW9ucy5yZXNldFBlcmlvZCA9IGZhaWx1cmVhY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKDApOwogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucyA9IFtdOwogICAgICAgICAgICAgICAgICAgICAgICBmb3IodmFyIGFjdCA9IDAgOyBhY3QgPCBjQWN0aW9uczsgKythY3QpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhY3Rpb24gPSBmYWlsdXJlYWN0aW9ucy5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAzMiA6IDE2LCB0aGlzLkdNLlBvaW50ZXJTaXplKS5EZXJlZigpLkRlcmVmKGFjdCo4LDgpLnRvQnVmZmVyKCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYWN0aW9uLnJlYWRVSW50MzJMRSgpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zLmFjdGlvbnMucHVzaCh7IHR5cGU6ICdOT05FJyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAxOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wdXNoKHsgdHlwZTogJ1NFUlZJQ0VfUkVTVEFSVCcgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zLmFjdGlvbnMucHVzaCh7IHR5cGU6ICdSRUJPT1QnIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wdXNoKHsgdHlwZTogJ09USEVSJyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wZWVrKCkuZGVsYXkgPSBhY3Rpb24ucmVhZFVJbnQzMkxFKDQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UgewoKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaGFuZGxlKTsKICAgICAgICAgICAgdGhyb3cgKCdjb3VsZCBub3QgZmluZCBzZXJ2aWNlOiAnICsgbmFtZSk7CiAgICAgICAgfQogICAgfQogICAgZWxzZQogICAgewogICAgICAgIHRoaXMuaXNBZG1pbiA9IGZ1bmN0aW9uIGlzQWRtaW4oKSAKICAgICAgICB7CiAgICAgICAgICAgIHJldHVybiAocmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmlzUm9vdCgpKTsKICAgICAgICB9CiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiAobmFtZSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdmFyIHJldCA9IHsgbmFtZTogbmFtZSB9OwogICAgICAgICAgICAgICAgaWYoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgbmFtZSArICcucGxpc3QnKSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAvLyBCZWZvcmUgd2UgdGhyb3cgaW4gdGhlIHRvd2VsLCBsZXQncyBlbnVtZXJhdGUgYWxsIHRoZSBwbGlzdCBmaWxlcywgYW5kIHNlZSBpZiBvbmUgaGFzIGEgbWF0Y2hpbmcgbGFiZWwKICAgICAgICAgICAgICAgICAgICB2YXIgZmlsZXMgPSByZXF1aXJlKCdmcycpLnJlYWRkaXJTeW5jKCcvTGlicmFyeS9MYXVuY2hEYWVtb25zJyk7CiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgZmlsZSBpbiBmaWxlcykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvIiArIGZpbGVzW2ZpbGVdICsgIiB8IHRyICdcbicgJ1wuJyB8IGF3ayAneyBzcGxpdCgkMCwgYSwgXCI8a2V5PkxhYmVsPC9rZXk+XCIpOyBzcGxpdChhWzJdLCBiLCBcIjwvc3RyaW5nPlwiKTsgc3BsaXQoYlsxXSwgYywgXCI8c3RyaW5nPlwiKTsgcHJpbnQgY1syXTsgfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICBpZihjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSA9PSBuYW1lKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQubmFtZSA9IGZpbGVzW2ZpbGVdLmVuZHNXaXRoKCcucGxpc3QnKSA/IGZpbGVzW2ZpbGVdLnN1YnN0cmluZygwLCBmaWxlc1tmaWxlXS5sZW5ndGggLSA2KSA6IGZpbGVzW2ZpbGVdOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldCwgJ2FsaWFzJywgeyB2YWx1ZTogbmFtZSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChyZXQubmFtZSA9PSBuYW1lKSB7IHRocm93ICgnIExhdW5jaERhZW1vbiAoJyArIG5hbWUgKyAnKSBOT1QgRk9VTkQnKTsgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmV0LmxhYmVsID0gZnVuY3Rpb24gbGFiZWwoKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvIiArIHRoaXMubmFtZSArICIucGxpc3QgfCB0ciAnXG4nICdcLicgfCBhd2sgJ3sgc3BsaXQoJDAsIGEsIFwiPGtleT5MYWJlbDwva2V5PlwiKTsgc3BsaXQoYVsyXSwgYiwgXCI8L3N0cmluZz5cIik7IHNwbGl0KGJbMV0sIGMsIFwiPHN0cmluZz5cIik7IHByaW50IGNbMl07IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgaWYgKCFyZXQuYWxpYXMpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldCwgJ2FsaWFzJywgeyB2YWx1ZTogcmV0LmxhYmVsKCkgfSk7IH0KICAgICAgICAgICAgICAgIHJldC5sYWJlbCA9IG51bGw7CiAgICAgICAgICAgICAgICByZXQuZ2V0UElEID0gZnVuY3Rpb24gZ2V0UElEKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImxhdW5jaGN0bCBsaXN0IHwgZ3JlcCAnIiArIHRoaXMuYWxpYXMgKyAiJyB8IGF3ayAneyBpZigkMz09XCIiICsgdGhpcy5hbGlhcyArICJcIil7cHJpbnQgJDE7fX0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOyAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKSk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0LmlzUnVubmluZyA9IGZ1bmN0aW9uIGlzUnVubmluZygpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICh0aGlzLmdldFBJRCgpID4gMCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0LmlzTWUgPSBmdW5jdGlvbiBpc01lKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHRoaXMuZ2V0UElEKCkgPT0gcHJvY2Vzcy5waWQpOwogICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgIHJldC5hcHBXb3JraW5nRGlyZWN0b3J5ID0gZnVuY3Rpb24gYXBwV29ya2luZ0RpcmVjdG9yeSgpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8iICsgdGhpcy5uYW1lICsgIi5wbGlzdCB8IHRyICdcbicgJ1wuJyB8IGF3ayAneyBzcGxpdCgkMCwgYSwgXCI8a2V5PldvcmtpbmdEaXJlY3Rvcnk8L2tleT5cIik7IHNwbGl0KGFbMl0sIGIsIFwiPC9zdHJpbmc+XCIpOyBzcGxpdChiWzFdLCBjLCBcIjxzdHJpbmc+XCIpOyBwcmludCBjWzJdOyB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCk7CgogICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci5lbmRzV2l0aCgnLycpID8gY2hpbGQuc3Rkb3V0LnN0ci5zdWJzdHJpbmcoMCwgY2hpbGQuc3Rkb3V0LnN0ci5sZW5ndGggLSAxKSA6IGNoaWxkLnN0ZG91dC5zdHIpOwogICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgIHJldC5hcHBMb2NhdGlvbiA9IGZ1bmN0aW9uIGFwcExvY2F0aW9uKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvTGlicmFyeS9MYXVuY2hEYWVtb25zLyIgKyB0aGlzLm5hbWUgKyAiLnBsaXN0IHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7IHNwbGl0KCQwLCBhLCBcIjxrZXk+UHJvZ3JhbUFyZ3VtZW50czwva2V5PlwiKTsgc3BsaXQoYVsyXSwgYiwgXCI8L3N0cmluZz5cIik7IHNwbGl0KGJbMV0sIGMsIFwiPHN0cmluZz5cIik7IHByaW50IGNbMl07IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgIHJldC5zdGFydCA9IGZ1bmN0aW9uIHN0YXJ0KCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnbGF1bmNoY3RsIHN0YXJ0ICcgKyB0aGlzLmFsaWFzICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICByZXQuc3RvcCA9IGZ1bmN0aW9uIHN0b3AoKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgc3RvcCAnICsgdGhpcy5hbGlhcyArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0LnJlc3RhcnQgPSBmdW5jdGlvbiByZXN0YXJ0KCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3AoKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLnN0YXJ0KCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICB9OwogICAgICAgIH0KICAgICAgICBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiAobmFtZSwgcGxhdGZvcm0pCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmICghcGxhdGZvcm0pIHsgcGxhdGZvcm0gPSB0aGlzLmdldFNlcnZpY2VUeXBlKCk7IH0KICAgICAgICAgICAgICAgIHZhciByZXQgPSB7IG5hbWU6IG5hbWUgfTsKICAgICAgICAgICAgICAgIHN3aXRjaChwbGF0Zm9ybSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjYXNlICdpbml0JzoKICAgICAgICAgICAgICAgICAgICBjYXNlICd1cHN0YXJ0JzoKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpKSB7IHBsYXRmb3JtID0gJ2luaXQnOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpKSB7IHBsYXRmb3JtID0gJ3Vwc3RhcnQnOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgocGxhdGZvcm0gPT0gJ2luaXQnICYmIHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgKHBsYXRmb3JtID09ICd1cHN0YXJ0JyAmJiByZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpKSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcFdvcmtpbmdEaXJlY3RvcnkgPSBmdW5jdGlvbiBhcHBXb3JraW5nRGlyZWN0b3J5KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGFwcFdvcmtpbmdEaXJlY3RvcnkucGxhdGZvcm0gPT0gJ2luaXQnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL2luaXQuZC8iICsgdGhpcy5uYW1lICsgIiB8IGdyZXAgJ1NDUklQVD0nIHwgYXdrIC1GPSAneyBsZW49c3BsaXQoJDIsIGEsIFwiL1wiKTsgcHJpbnQgc3Vic3RyKCQyLDAsbGVuZ3RoKCQyKS1sZW5ndGgoYVtsZW5dKSk7IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL2luaXQvIiArIHRoaXMubmFtZSArICIuY29uZiB8IGdyZXAgJ2NoZGlyICcgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuYXBwV29ya2luZ0RpcmVjdG9yeS5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gYXBwTG9jYXRpb24oKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihhcHBMb2NhdGlvbi5wbGF0Zm9ybSA9PSAnaW5pdCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9ldGMvaW5pdC5kLyIgKyB0aGlzLm5hbWUgKyAiIHwgZ3JlcCAnU0NSSVBUPScgfCBhd2sgLUY9ICd7cHJpbnQgJDJ9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL2V0Yy9pbml0LyIgKyB0aGlzLm5hbWUgKyAiLmNvbmYgfCBncmVwICdleGVjICcgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuYXBwTG9jYXRpb24ucGxhdGZvcm0gPSBwbGF0Zm9ybTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5pc01lID0gZnVuY3Rpb24gaXNNZSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAg", 16000);
	memcpy_s(_servicemanager + 32000, 50072, "ICAgICAgICAgICAgICAgICAgIGlmIChpc01lLnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJpbml0Y3RsIHN0YXR1cyAiICsgdGhpcy5uYW1lICsgIiB8IGF3ayAne3ByaW50ICQyfScgfCBhd2sgLUYsICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJzZXJ2aWNlICIgKyB0aGlzLm5hbWUgKyAiIHN0YXR1cyB8IGF3ayAne3ByaW50ICQyfScgfCBhd2sgLUYsICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChwYXJzZUludChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSkgPT0gcHJvY2Vzcy5waWQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5pc01lLnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuaXNSdW5uaW5nID0gZnVuY3Rpb24gaXNSdW5uaW5nKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGlzUnVubmluZy5wbGF0Zm9ybSA9PSAndXBzdGFydCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiaW5pdGN0bCBzdGF0dXMgIiArIHRoaXMubmFtZSArICIgfCBhd2sgJ3twcmludCAkMn0nIHwgYXdrIC1GLCAne3ByaW50ICQxfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgic2VydmljZSAiICsgdGhpcy5uYW1lICsgIiBzdGF0dXMgfCBhd2sgJ3twcmludCAkMn0nIHwgYXdrIC1GLCAne3ByaW50ICQxfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgPT0gJ3N0YXJ0L3J1bm5pbmcnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuaXNSdW5uaW5nLnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuc3RhcnQgPSBmdW5jdGlvbiBzdGFydCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHN0YXJ0LnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdpbml0Y3RsIHN0YXJ0ICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3NlcnZpY2UgJyArIHRoaXMubmFtZSArICcgc3RhcnRcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGFydC5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AgPSBmdW5jdGlvbiBzdG9wKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3RvcC5wbGF0Zm9ybSA9PSAndXBzdGFydCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnaW5pdGN0bCBzdG9wICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3NlcnZpY2UgJyArIHRoaXMubmFtZSArICcgc3RvcFxuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AucGxhdGZvcm0gPSBwbGF0Zm9ybTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5yZXN0YXJ0ID0gZnVuY3Rpb24gcmVzdGFydCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3RhcnQucGxhdGZvcm0gPT0gJ3Vwc3RhcnQnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2luaXRjdGwgcmVzdGFydCAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyB0aGlzLm5hbWUgKyAnIHJlc3RhcnRcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5yZXN0YXJ0LnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuc3RhdHVzID0gZnVuY3Rpb24gc3RhdHVzKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5fc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuX3N0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3RhdHVzLnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdpbml0Y3RsIHN0YXR1cyAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyB0aGlzLm5hbWUgKyAnIHN0YXR1c1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuX3N0cik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0YXR1cy5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHBsYXRmb3JtICsgJyBTZXJ2aWNlICgnICsgbmFtZSArICcpIE5PVCBGT1VORCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgJ3N5c3RlbWQnOgogICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJykgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vJyArIG5hbWUgKyAnLnNlcnZpY2UnKSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcFdvcmtpbmdEaXJlY3RvcnkgPSBmdW5jdGlvbiBhcHBXb3JraW5nRGlyZWN0b3J5KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgdGhpcy5uYW1lICsgJy5zZXJ2aWNlJykpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvbGliL3N5c3RlbWQvc3lzdGVtLyIgKyB0aGlzLm5hbWUgKyAiLnNlcnZpY2UgfCBncmVwICdXb3JraW5nRGlyZWN0b3J5PScgfCBhd2sgLUY9ICd7IHByaW50ICQyIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC91c3IvbGliL3N5c3RlbWQvc3lzdGVtLyIgKyB0aGlzLm5hbWUgKyAiLnNlcnZpY2UgfCBncmVwICdXb3JraW5nRGlyZWN0b3J5PScgfCBhd2sgLUY9ICd7IHByaW50ICQyIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgdGhpcy5uYW1lICsgJy5zZXJ2aWNlJykpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9saWIvc3lzdGVtZC9zeXN0ZW0vIiArIHRoaXMubmFtZSArICIuc2VydmljZSB8IGdyZXAgJ0V4ZWNTdGFydD0nIHwgYXdrIC1GPSAneyBzcGxpdCgkMiwgYSwgXCIgXCIpOyBwcmludCBhWzFdIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vIiArIHRoaXMubmFtZSArICIuc2VydmljZSB8IGdyZXAgJ0V4ZWNTdGFydD0nIHwgYXdrIC1GPSAneyBzcGxpdCgkMiwgYSwgXCIgXCIpOyBwcmludCBhWzFdIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmlzTWUgPSBmdW5jdGlvbiBpc01lKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInN5c3RlbWN0bCBzdGF0dXMgIiArIHRoaXMubmFtZSArICIgfCBncmVwICdNYWluIFBJRDonIHwgYXdrICd7cHJpbnQgJDN9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKSA9PSBwcm9jZXNzLnBpZCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmlzUnVubmluZyA9IGZ1bmN0aW9uIGlzUnVubmluZygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJzeXN0ZW1jdGwgc3RhdHVzICIgKyB0aGlzLm5hbWUgKyAiIHwgZ3JlcCAnQWN0aXZlOicgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgPT0gJ2FjdGl2ZScpOyAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGFydCA9IGZ1bmN0aW9uIHN0YXJ0KCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzeXN0ZW1jdGwgc3RhcnQgJyArIHRoaXMubmFtZSArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AgPSBmdW5jdGlvbiBzdG9wKCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzeXN0ZW1jdGwgc3RvcCAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQucmVzdGFydCA9IGZ1bmN0aW9uIHJlc3RhcnQoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCByZXN0YXJ0ICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGF0dXMgPSBmdW5jdGlvbiBzdGF0dXMoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuX3N0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLl9zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCBzdGF0dXMgJyArIHRoaXMubmFtZSArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuX3N0cik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHBsYXRmb3JtICsgJyBTZXJ2aWNlICgnICsgbmFtZSArICcpIE5PVCBGT1VORCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnVW5rbm93biBTZXJ2aWNlIFBsYXRmb3JtOiAnICsgcGxhdGZvcm0pOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfTsKICAgICAgICB9CiAgICB9CiAgICB0aGlzLmluc3RhbGxTZXJ2aWNlID0gZnVuY3Rpb24gaW5zdGFsbFNlcnZpY2Uob3B0aW9ucykKICAgIHsKICAgICAgICBpZiAoIW9wdGlvbnMudGFyZ2V0KSB7IG9wdGlvbnMudGFyZ2V0ID0gb3B0aW9ucy5uYW1lOyB9CiAgICAgICAgaWYgKCFvcHRpb25zLmRpc3BsYXlOYW1lKSB7IG9wdGlvbnMuZGlzcGxheU5hbWUgPSBvcHRpb25zLm5hbWU7IH0KCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykKICAgICAgICB7CiAgICAgICAgICAgIGlmICghdGhpcy5pc0FkbWluKCkpIHsgdGhyb3cgKCdJbnN0YWxsaW5nIGFz", 16000);
	memcpy_s(_servicemanager + 48000, 34072, "IFNlcnZpY2UsIHJlcXVpcmVzIGFkbWluJyk7IH0KCiAgICAgICAgICAgIC8vIEJlZm9yZSB3ZSBzdGFydCwgd2UgbmVlZCB0byBjb3B5IHRoZSBiaW5hcnkgdG8gdGhlIHJpZ2h0IHBsYWNlCiAgICAgICAgICAgIHZhciBmb2xkZXIgPSB0aGlzLmdldFNlcnZpY2VGb2xkZXIoKTsKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoZm9sZGVyKSkgeyByZXF1aXJlKCdmcycpLm1rZGlyU3luYyhmb2xkZXIpOyB9CiAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUpOyB9CgogICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCBmb2xkZXIgKyAnXFwnICsgb3B0aW9ucy5uYW1lICsgJ1xcJyArIG9wdGlvbnMudGFyZ2V0ICsgJy5leGUnKTsKICAgICAgICAgICAgb3B0aW9ucy5zZXJ2aWNlUGF0aCA9IGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUgKyAnXFwnICsgb3B0aW9ucy50YXJnZXQgKyAnLmV4ZSc7CgogICAgICAgICAgICB2YXIgc2VydmljZVBhdGggPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKCciJyArIG9wdGlvbnMuc2VydmljZVBhdGggKyAnIicpOwogICAgICAgICAgICB2YXIgaGFuZGxlID0gdGhpcy5wcm94eS5PcGVuU0NNYW5hZ2VyQSgweDAwLCAweDAwLCAweDAwMDIpOwogICAgICAgICAgICBpZiAoaGFuZGxlLlZhbCA9PSAwKSB7IHRocm93ICgnZXJyb3Igb3BlbmluZyBTQ01hbmFnZXInKTsgfQogICAgICAgICAgICB2YXIgc2VydmljZU5hbWUgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKG9wdGlvbnMubmFtZSk7CiAgICAgICAgICAgIHZhciBkaXNwbGF5TmFtZSA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUob3B0aW9ucy5kaXNwbGF5TmFtZSk7CiAgICAgICAgICAgIHZhciBhbGxBY2Nlc3MgPSAweDAwMEYwMUZGOwogICAgICAgICAgICB2YXIgc2VydmljZVR5cGU7CiAgICAgICAgICAgIAoKICAgICAgICAgICAgc3dpdGNoIChvcHRpb25zLnN0YXJ0VHlwZSkgewogICAgICAgICAgICAgICAgY2FzZSAnQVVUT19TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgc2VydmljZVR5cGUgPSAweDAyOyAvLyBBdXRvbWF0aWMKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgJ0RFTUFORF9TVEFSVCc6CiAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgIHNlcnZpY2VUeXBlID0gMHgwMzsgLy8gTWFudWFsCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdESVNBQkxFRCc6CiAgICAgICAgICAgICAgICAgICAgc2VydmljZVR5cGUgPSAweDA0OyAvLyBEaXNhYmxlZAogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CgogICAgICAgICAgICB2YXIgaCA9IHRoaXMucHJveHkuQ3JlYXRlU2VydmljZUEoaGFuZGxlLCBzZXJ2aWNlTmFtZSwgZGlzcGxheU5hbWUsIGFsbEFjY2VzcywgMHgxMCB8IDB4MTAwLCBzZXJ2aWNlVHlwZSwgMCwgc2VydmljZVBhdGgsIDAsIDAsIDAsIDAsIDApOwogICAgICAgICAgICBpZiAoaC5WYWwgPT0gMCkgeyB0aGlzLnByb3h5LkNsb3NlU2VydmljZUhhbmRsZShoYW5kbGUpOyB0aHJvdyAoJ0Vycm9yIENyZWF0aW5nIFNlcnZpY2U6ICcgKyB0aGlzLnByb3h5Mi5HZXRMYXN0RXJyb3IoKS5WYWwpOyB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLmRlc2NyaXB0aW9uKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgZHNjID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZShvcHRpb25zLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgICAgIHZhciBzZXJ2aWNlRGVzY3JpcHRpb24gPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKHRoaXMuR00uUG9pbnRlclNpemUpOwogICAgICAgICAgICAgICAgZHNjLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHNlcnZpY2VEZXNjcmlwdGlvbi5EZXJlZigwLCB0aGlzLkdNLlBvaW50ZXJTaXplKS50b0J1ZmZlcigpKTsKCiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGFuZ2VTZXJ2aWNlQ29uZmlnMkEoaCwgMSwgc2VydmljZURlc2NyaXB0aW9uKS5WYWwgPT0gMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygndW5hYmxlIHRvIHNldCBkZXNjcmlwdGlvbi4uLicpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID09IG51bGwgfHwgb3B0aW9ucy5mYWlsdXJlUmVzdGFydCA+IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBkZWxheSA9IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPT0gbnVsbCA/IDUwMDAgOiBvcHRpb25zLmZhaWx1cmVSZXN0YXJ0OyAgICAgICAgICAgICAvLyBEZWxheSBpbiBtaWxsaXNlY29uZHMKICAgICAgICAgICAgICAgIHZhciBhY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSgzICogOCk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyAzKnNpemVvZihTQ19BQ1RJT04pCiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgxKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzBdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoNCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKGRlbGF5KTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzBdLmRlbGF5CiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDgsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgxKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzFdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoMTIsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShkZWxheSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzFdLmRlbGF5CiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDE2LCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzJdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoMjAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShkZWxheSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzJdLmRlbGF5CgogICAgICAgICAgICAgICAgdmFyIGZhaWx1cmVBY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSg0MCk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNpemVvZihTRVJWSUNFX0ZBSUxVUkVfQUNUSU9OUykKICAgICAgICAgICAgICAgIGZhaWx1cmVBY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSg3MjAwKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBkd1Jlc2V0UGVyaW9kOiAyIEhvdXJzCiAgICAgICAgICAgICAgICBmYWlsdXJlQWN0aW9ucy5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAyNCA6IDEyLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMyk7Ly8gY0FjdGlvbnM6IDMKICAgICAgICAgICAgICAgIGFjdGlvbnMucG9pbnRlckJ1ZmZlcigpLmNvcHkoZmFpbHVyZUFjdGlvbnMuRGVyZWYodGhpcy5HTS5Qb2ludGVyU2l6ZSA9PSA4ID8gMzIgOiAxNiwgdGhpcy5HTS5Qb2ludGVyU2l6ZSkudG9CdWZmZXIoKSk7CiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGFuZ2VTZXJ2aWNlQ29uZmlnMkEoaCwgMiwgZmFpbHVyZUFjdGlvbnMpLlZhbCA9PSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdVbmFibGUgdG8gc2V0IEZhaWx1cmVBY3Rpb25zLi4uJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaCk7CiAgICAgICAgICAgIHRoaXMucHJveHkuQ2xvc2VTZXJ2aWNlSGFuZGxlKGhhbmRsZSk7CgogICAgICAgICAgICBpZiAob3B0aW9ucy5maWxlcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgZm9yKHZhciBpIGluIG9wdGlvbnMuZmlsZXMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2NvcHlpbmcgJyArIGV4dHJhY3RGaWxlU291cmNlKG9wdGlvbnMuZmlsZXNbaV0pKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhleHRyYWN0RmlsZVNvdXJjZShvcHRpb25zLmZpbGVzW2ldKSwgZm9sZGVyICsgJ1xcJyArIG9wdGlvbnMubmFtZSArICdcXCcgKyBleHRyYWN0RmlsZU5hbWUob3B0aW9ucy5maWxlc1tpXSkpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLnBhcmFtZXRlcnMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciByZWcgPSByZXF1aXJlKCd3aW4tcmVnaXN0cnknKTsKICAgICAgICAgICAgICAgIHZhciBpbWFnZVBhdGggPSByZWcuUXVlcnlLZXkocmVnLkhLRVkuTG9jYWxNYWNoaW5lLCAnU1lTVEVNXFxDdXJyZW50Q29udHJvbFNldFxcU2VydmljZXNcXCcgKyBvcHRpb25zLm5hbWUsICdJbWFnZVBhdGgnKTsKICAgICAgICAgICAgICAgIGltYWdlUGF0aCArPSAoJyAnICsgb3B0aW9ucy5wYXJhbWV0ZXJzLmpvaW4oJyAnKSk7CiAgICAgICAgICAgICAgICByZWcuV3JpdGVLZXkocmVnLkhLRVkuTG9jYWxNYWNoaW5lLCAnU1lTVEVNXFxDdXJyZW50Q29udHJvbFNldFxcU2VydmljZXNcXCcgKyBvcHRpb25zLm5hbWUsICdJbWFnZVBhdGgnLCBpbWFnZVBhdGgpOwogICAgICAgICAgICB9CgogICAgICAgICAgICByZXR1cm4gKHRoaXMuZ2V0U2VydmljZShvcHRpb25zLm5hbWUpKTsKICAgICAgICB9CiAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKCF0aGlzLmlzQWRtaW4oKSkgeyBjb25zb2xlLmxvZygnSW5zdGFsbGluZyBhIFNlcnZpY2UgcmVxdWlyZXMgcm9vdCcpOyB0aHJvdyAoJ0luc3RhbGxpbmcgYXMgU2VydmljZSwgcmVxdWlyZXMgcm9vdCcpOyB9CiAgICAgICAgICAgIHZhciBwYXJhbWV0ZXJzID0gb3B0aW9ucy5wYXJhbWV0ZXJzID8gb3B0aW9ucy5wYXJhbWV0ZXJzLmpvaW4oJyAnKSA6ICcnOwogICAgICAgICAgICB2YXIgY29uZjsKICAgICAgICAgICAgaWYgKCFvcHRpb25zLnNlcnZpY2VQbGF0Zm9ybSkgeyBvcHRpb25zLnNlcnZpY2VQbGF0Zm9ybSA9IHRoaXMuZ2V0U2VydmljZVR5cGUoKTsgfQogICAgICAgICAgIAogICAgICAgICAgICBzd2l0Y2ggKG9wdGlvbnMuc2VydmljZVBsYXRmb3JtKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBjYXNlICdpbml0JzoKICAgICAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSkpIHsgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lKTsgfQoKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCAnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCk7CiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2NvcHlpbmcgJyArIG9wdGlvbnMuc2VydmljZVBhdGgpOwoKICAgICAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpLm1vZGU7CiAgICAgICAgICAgICAgICAgICAgbSB8PSAocmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYVVNSIHwgcmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYR1JQKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNobW9kU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCwgbSk7CgogICAgICAgICAgICAgICAgICAgIC8vIFRoZSBmb2xsb3dpbmcgaXMgdGhlIGluaXQuZCBzY3JpcHQgSSB3cm90ZS4gUmF0aGVyIHRoYW4gaGF2aW5nIHRvIGRlYWwgd2l0aCBlc2NhcGluZyB0aGUgdGhpbmcsIEkganVzdCBCYXNlNjQgZW5jb2RlZCBpdCB0byBwcmV2ZW50IGlzc3Vlcy4KICAgICAgICAgICAgICAgICAgICBjb25mID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSgnL2V0Yy9pbml0LmQvJyArIG9wdGlvbnMubmFtZSwgeyBmbGFnczogJ3diJyB9KTsKICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKEJ1ZmZlci5mcm9tKCdJeUV2WW1sdUwzTm9DZ29LVTBOU1NWQlVQUzkxYzNJdmJHOWpZV3d2YldWemFGOXpaWEoyYVdObGN5OVlXRmhZV0M5WldWbFpXUXBTVlU1QlV6MXliMjkwQ2dwUVNVUkdTVXhGUFM5MllYSXZjblZ1TDFoWVdGaFlMbkJwWkFwTVQwZEdTVXhGUFM5MllYSXZiRzluTDFoWVdGaFlMbXh2WndvS2MzUmhjblFvS1NCN0NpQWdhV1lnV3lBdFppQWlKRkJKUkVaSlRFVWlJRjBnSmlZZ2EybHNiQ0F0TUNBa0tHTmhkQ0FpSkZCSlJFWkpURVVpS1NBeVBpOWtaWFl2Ym5Wc2JEc2dkR2hsYmdvZ0lDQWdaV05vYnlBblUyVnlkbWxqWlNCaGJISmxZV1I1SUhKMWJtNXBibWNuSUQ0bU1nb2dJQ0FnY21WMGRYSnVJREVLSUNCbWFRb2dJR1ZqYUc4Z0oxTjBZWEowYVc1bklITmxjblpwWTJYaWdLWW5JRDRtTWdvZ0lHeHZZMkZzSUVOTlJEMGlKRk5EVWtsUVZDQjdlMUJCVWsxVGZYMGdKajRnWENJa1RFOUhSa2xNUlZ3aUlDWWdaV05vYnlCY0pDRWlDaUFnYkc5allXd2dRMDFFVUVGVVNEMGtLR1ZqYUc4Z0pGTkRVa2xRVkNCOElHRjNheUFuZXlCc1pXNDljM0JzYVhRb0pEQXNJR0VzSUNJdklpazdJSEJ5YVc1MElITjFZbk4wY2lna01Dd2dNQ3dnYkdWdVozUm9LQ1F3S1Mxc1pXNW5kR2dvWVZ0c1pXNWRLU2s3SUgwbktRb2dJR05rSUNSRFRVUlFRVlJJQ2lBZ2MzVWdMV01nSWlSRFRVUWlJQ1JTVlU1QlV5QStJQ0lrVUVsRVJrbE1SU0lLSUNCbFkyaHZJQ2RUWlhKMmFXTmxJSE4wWVhKMFpXUW5JRDRtTWdwOUNncHpkRzl3S0NrZ2V3b2dJR2xtSUZzZ0lTQXRaaUFpSkZCSlJFWkpURVVpSUYwN0lIUm9aVzRLSUNBZ0lHVmphRzhnSjFObGNuWnBZMlVnYm05MElISjFibTVwYm1jbklENG1NZ29nSUNBZ2NtVjBkWEp1SURFS0lDQmxiSE5sQ2dsd2FXUTlKQ2dnWTJGMElDSWtVRWxFUmtsTVJTSWdLUW9KYVdZZ2EybHNiQ0F0TUNBa2NHbGtJREkrTDJSbGRpOXVkV3hzT3lCMGFHVnVDaUFnSUNBZ0lHVmphRzhnSjFOMGIzQndhVzVuSUhObGNuWnBZMlhpZ0tZbklENG1NZ29nSUNBZ0lDQnJhV3hzSUMweE5pQWtjR2xrQ2lBZ0lDQWdJR1ZqYUc4Z0oxTmxjblpwWTJVZ2MzUnZjSEJsWkNjZ1BpWXlDZ2xsYkhObENna2dJR1ZqYUc4Z0oxTmxjblpwWTJVZ2JtOTBJSEoxYm01cGJtY25DZ2xtYVFvSmNtMGdMV1lnSkNKUVNVUkdTVXhGSWdvZ0lHWnBDbjBLY21WemRHRnlkQ2dwZXdvSmMzUnZjQW9KYzNSaGNuUUtmUXB6ZEdGMGRYTW9LWHNLQ1dsbUlGc2dMV1lnSWlSUVNVUkdTVXhGSWlCZENnbDBhR1Z1Q2drSmNHbGtQU1FvSUdOaGRDQWlKRkJKUkVaSlRFVWlJQ2tLQ1FscFppQnJhV3hzSUMwd0lDUndhV1FnTWo0dlpHVjJMMjUxYkd3N0lIUm9aVzRLQ1FrSlpXTm9ieUFpV0ZoWVdGZ2djM1JoY25RdmNuVnVibWx1Wnl3Z2NISnZZMlZ6Y3lBa2NHbGtJZ29KQ1dWc2MyVUtDUWtKWldOb2J5QW5XRmhZV0ZnZ2MzUnZjQzkzWVdsMGFXNW5Kd29KQ1dacENnbGxiSE5sQ2drSlpXTm9ieUFuV0ZoWVdGZ2djM1J2Y0M5M1lXbDBhVzVuSndvSlpta0tDbjBLQ2dwallYTmxJQ0lrTVNJZ2FXNEtDWE4wWVhKMEtRb0pDWE4wWVhKMENna0pPenNLQ1hOMGIzQXBDZ2tKYzNSdmNBb0pDVHM3Q2dseVpYTjBZWEowS1FvSkNYTjBiM0FLQ1FsemRHRnlkQW9KQ1RzN0NnbHpkR0YwZFhNcENna0pjM1JoZEhWekNna0pPenNLQ1NvcENna0paV05vYnlBaVZYTmhaMlU2SUhObGNuWnBZMlVnV0ZoWVdGZ2dlM04wWVhKMGZITjBiM0I4Y21WemRHRnlkSHh6ZEdGMGRYTjlJZ29KQ1RzN0NtVnpZV01LWlhocGRDQXdDZ289JywgJ2Jhc2U2NCcpLnRvU3RyaW5nKCkuc3BsaXQoJ1hYWFhYJykuam9pbihvcHRpb25zLm5hbWUpLnNwbGl0KCdZWVlZWScpLmpvaW4ob3B0aW9ucy50YXJnZXQpLnJlcGxhY2UoJ3t7UEFSTVN9fScsIHBhcmFtZXRlcnMpKTsKICAgICAgICAgICAgICAgICAgICBjb25mLmVuZCgpOwoKICAgICAgICAgICAgICAgICAgICBtID0gcmVxdWlyZSgnZnMnKS5zdGF0U3luYygnL2V0Yy9pbml0LmQvJyArIG9wdGlvbnMubmFtZSkubW9kZTsKICAgICAgICAgICAgICAgICAgICBtIHw9IChyZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhHUlApOwogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY2htb2RTeW5jKCcvZXRjL2luaXQuZC8nICsgb3B0aW9ucy5uYW1lLCBtKTsKICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKG9wdGlvbnMuc3RhcnRUeXBlKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnQk9PVF9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1NZU1RFTV9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0FVVE9fU1RBUlQnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCd1cGRhdGUtcmMuZCAnICsgb3B0aW9ucy5uYW1lICsgJyBkZWZhdWx0c1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICd1cHN0YXJ0JzoKICAgICAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSkpIHsgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lKTsgfQoKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCAnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCk7CiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2NvcHlpbmcgJyArIG9wdGlvbnMuc2VydmljZVBhdGgpOwoKICAgICAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpLm1vZGU7CiAgICAgICAgICAgICAgICAgICAgbSB8PSAocmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYVVNSIHwgcmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYR1JQKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNobW9kU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCwgbSk7CgogICAgICAgICAgICAgICAgICAgIGNvbmYgPSByZXF1aXJlKCdmcycpLmNyZWF0ZVdyaXRlU3RyZWFtKCcvZXRjL2luaXQvJyArIG9wdGlvbnMubmFtZSArICcuY29uZicsIHsgZmxhZ3M6ICd3YicgfSk7CiAgICAgICAgICAgICAgICAgICAgc3dpdGNoIChvcHRpb25zLnN0YXJ0VHlwZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0JPT1RfU1RBUlQnOgogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdTWVNURU1fU1RBUlQnOgogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdBVVRPX1NUQVJUJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ3N0YXJ0IG9uIHJ1bmxldmVsIFsyMzQ1XVxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdzdG9wIG9uIHJ1bmxldmVsIFswMTZdXG5cbicpOwogICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID09IG51bGwgfHwgb3B0aW9ucy5mYWlsdXJlUmVzdGFydCA+IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdyZXNwYXduXG5cbicpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdjaGRpciAvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICdcbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ2V4ZWMgL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCArICcgJyArIHBhcmFtZXRlcnMgKyAnXG5cbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYuZW5kKCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdzeXN0ZW1kJzoKICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmljZURlc2NyaXB0aW9uID0gb3B0aW9ucy5kZXNjcmlwdGlvbiA/IG9wdGlvbnMuZGVzY3JpcHRpb24gOiAnTWVzaENlbnRyYWwgQWdlbnQnOwoKICAgICAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSkpIHsgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lKTsgfQoKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnY29weWluZyAnICsgb3B0aW9u", 16000);
	memcpy_s(_servicemanager + 64000, 18072, "cy5zZXJ2aWNlUGF0aCk7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jb3B5RmlsZVN5bmMob3B0aW9ucy5zZXJ2aWNlUGF0aCwgJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpOwoKICAgICAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpLm1vZGU7CiAgICAgICAgICAgICAgICAgICAgbSB8PSAocmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYVVNSIHwgcmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYR1JQKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNobW9kU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCwgbSk7CgogICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9saWIvc3lzdGVtZC9zeXN0ZW0nKSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYgPSByZXF1aXJlKCdmcycpLmNyZWF0ZVdyaXRlU3RyZWFtKCcvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBvcHRpb25zLm5hbWUgKyAnLnNlcnZpY2UnLCB7IGZsYWdzOiAnd2InIH0pOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbGliL3N5c3RlbWQvc3lzdGVtJykpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjb25mID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSgnL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vJyArIG9wdGlvbnMubmFtZSArICcuc2VydmljZScsIHsgZmxhZ3M6ICd3YicgfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgndW5rbm93biBsb2NhdGlvbiBmb3Igc3lzdGVtZCBjb25maWd1cmF0aW9uIGZpbGVzJyk7CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdbVW5pdF1cbkRlc2NyaXB0aW9uPScgKyBzZXJ2aWNlRGVzY3JpcHRpb24gKyAnXG4nKTsKICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdbU2VydmljZV1cbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1dvcmtpbmdEaXJlY3Rvcnk9L3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnXG4nKTsKICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdFeGVjU3RhcnQ9L3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCArICcgJyArIHBhcmFtZXRlcnMgKyAnXG4nKTsKICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdTdGFuZGFyZE91dHB1dD1udWxsXG4nKTsKICAgICAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy5mYWlsdXJlUmVzdGFydCA9PSBudWxsIHx8IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPiAwKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnUmVzdGFydD1vbi1mYWlsdXJlXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPT0gbnVsbCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnUmVzdGFydFNlYz0zXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1Jlc3RhcnRTZWM9JyArIChvcHRpb25zLmZhaWx1cmVSZXN0YXJ0IC8gMTAwMCkgKyAnXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKG9wdGlvbnMuc3RhcnRUeXBlKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnQk9PVF9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1NZU1RFTV9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0FVVE9fU1RBUlQnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnW0luc3RhbGxdXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1dhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ0FsaWFzPScgKyBvcHRpb25zLm5hbWUgKyAnLnNlcnZpY2VcbicpOyBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZSA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSwgeyB0eXBlOiByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuU3Bhd25UeXBlcy5URVJNIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLl9tb2R1bGVOYW1lID0gb3B0aW9ucy5uYW1lOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnc3lzdGVtY3RsIGVuYWJsZSAnICsgb3B0aW9ucy5uYW1lICsgJy5zZXJ2aWNlXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBjb25mLmVuZCgpOwoKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGRlZmF1bHQ6IC8vIHVua25vd24gcGxhdGZvcm0gc2VydmljZSB0eXBlCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykKICAgICAgICB7CiAgICAgICAgICAgIGlmICghdGhpcy5pc0FkbWluKCkpIHsgdGhyb3cgKCdJbnN0YWxsaW5nIGFzIFNlcnZpY2UsIHJlcXVpcmVzIHJvb3QnKTsgfQoKICAgICAgICAgICAgLy8gTWFjIE9TCiAgICAgICAgICAgIHZhciBzdGRvdXRwYXRoID0gKG9wdGlvbnMuc3Rkb3V0ID8gKCc8a2V5PlN0YW5kYXJkT3V0UGF0aDwva2V5PlxuPHN0cmluZz4nICsgb3B0aW9ucy5zdGRvdXQgKyAnPC9zdHJpbmc+JykgOiAnJyk7CiAgICAgICAgICAgIHZhciBhdXRvU3RhcnQgPSAob3B0aW9ucy5zdGFydFR5cGUgPT0gJ0FVVE9fU1RBUlQnID8gJzx0cnVlLz4nIDogJzxmYWxzZS8+Jyk7CiAgICAgICAgICAgIHZhciBwYXJhbXMgPSAgJyAgICAgPGtleT5Qcm9ncmFtQXJndW1lbnRzPC9rZXk+XG4nOwogICAgICAgICAgICBwYXJhbXMgKz0gJyAgICAgPGFycmF5PlxuJzsKICAgICAgICAgICAgcGFyYW1zICs9ICgnICAgICAgICAgPHN0cmluZz4vdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0ICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgIGlmKG9wdGlvbnMucGFyYW1ldGVycykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgZm9yKHZhciBpdG0gaW4gb3B0aW9ucy5wYXJhbWV0ZXJzKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHBhcmFtcyArPSAoJyAgICAgICAgIDxzdHJpbmc+JyArIG9wdGlvbnMucGFyYW1ldGVyc1tpdG1dICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gICAgICAgIAogICAgICAgICAgICBwYXJhbXMgKz0gJyAgICAgPC9hcnJheT5cbic7CiAgICAgICAgICAgIAogICAgICAgICAgICB2YXIgcGxpc3QgPSAnPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICc8IURPQ1RZUEUgcGxpc3QgUFVCTElDICItLy9BcHBsZSBDb21wdXRlci8vRFREIFBMSVNUIDEuMC8vRU4iICJodHRwOi8vd3d3LmFwcGxlLmNvbS9EVERzL1Byb3BlcnR5TGlzdC0xLjAuZHRkIj5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICc8cGxpc3QgdmVyc2lvbj0iMS4wIj5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICcgIDxkaWN0PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+TGFiZWw8L2tleT5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICgnICAgICA8c3RyaW5nPicgKyBvcHRpb25zLm5hbWUgKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgcGxpc3QgKz0gKHBhcmFtcyArICdcbicpOwogICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5Xb3JraW5nRGlyZWN0b3J5PC9rZXk+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAoJyAgICAgPHN0cmluZz4vdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICc8L3N0cmluZz5cbicpOwogICAgICAgICAgICBwbGlzdCArPSAoc3Rkb3V0cGF0aCArICdcbicpOwogICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5SdW5BdExvYWQ8L2tleT5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9IChhdXRvU3RhcnQgKyAnXG4nKTsKICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+S2VlcEFsaXZlPC9rZXk+XG4nOwogICAgICAgICAgICBpZihvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID09IG51bGwgfHwgb3B0aW9ucy5mYWlsdXJlUmVzdGFydCA+IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8dHJ1ZS8+XG4nOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxmYWxzZS8+XG4nOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgIT0gbnVsbCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+VGhyb3R0bGVJbnRlcnZhbDwva2V5PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8aW50ZWdlcj4nICsgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgLyAxMDAwKSArICc8L2ludGVnZXI+XG4nOwogICAgICAgICAgICB9CgogICAgICAgICAgICBwbGlzdCArPSAnICA8L2RpY3Q+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAnPC9wbGlzdD4nOwoKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgb3B0aW9ucy5uYW1lICsgJy5wbGlzdCcpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSk7IH0KICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLmJpbmFyeSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQsIG9wdGlvbnMuYmluYXJ5KTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCAnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIG9wdGlvbnMubmFtZSArICcucGxpc3QnLCBwbGlzdCk7CiAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpLm1vZGU7CiAgICAgICAgICAgICAgICBtIHw9IChyZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhHUlApOwogICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jaG1vZFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQsIG0pOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCdTZXJ2aWNlOiAnICsgb3B0aW9ucy5uYW1lICsgJyBhbHJlYWR5IGV4aXN0cycpOwogICAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBpZiAob3B0aW9ucy5maWxlcykgewogICAgICAgICAgICBmb3IgKHZhciBpIGluIG9wdGlvbnMuZmlsZXMpIHsKICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdjb3B5aW5nICcgKyBleHRyYWN0RmlsZVNvdXJjZShvcHRpb25zLmZpbGVzW2ldKSk7CiAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhleHRyYWN0RmlsZVNvdXJjZShvcHRpb25zLmZpbGVzW2ldKSwgJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgZXh0cmFjdEZpbGVOYW1lKG9wdGlvbnMuZmlsZXNbaV0pKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KICAgIHRoaXMudW5pbnN0YWxsU2VydmljZSA9IGZ1bmN0aW9uIHVuaW5zdGFsbFNlcnZpY2UobmFtZSkKICAgIHsKICAgICAgICBpZiAoIXRoaXMuaXNBZG1pbigpKSB7IHRocm93ICgnVW5pbnN0YWxsaW5nIGEgc2VydmljZSwgcmVxdWlyZXMgYWRtaW4nKTsgfQoKICAgICAgICBpZiAodHlwZW9mIChuYW1lKSA9PSAnb2JqZWN0JykgeyBuYW1lID0gbmFtZS5uYW1lOyB9CiAgICAgICAgdmFyIHNlcnZpY2UgPSB0aGlzLmdldFNlcnZpY2UobmFtZSk7CiAgICAgICAgdmFyIHNlcnZpY2VQYXRoID0gc2VydmljZS5hcHBMb2NhdGlvbigpOwoKICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHNlcnZpY2Uuc3RhdHVzLnN0YXRlID09IHVuZGVmaW5lZCB8fCBzZXJ2aWNlLnN0YXR1cy5zdGF0ZSA9PSAnU1RPUFBFRCcpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYyhzZXJ2aWNlUGF0aCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaCAoZSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmICh0aGlzLnByb3h5LkRlbGV0ZVNlcnZpY2Uoc2VydmljZS5fc2VydmljZSkgPT0gMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aHJvdyAoJ1VuaW5zdGFsbCBTZXJ2aWNlIGZvcjogJyArIG5hbWUgKyAnLCBmYWlsZWQgd2l0aCBlcnJvcjogJyArIHRoaXMucHJveHkyLkdldExhc3RFcnJvcigpKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRocm93ICgnQ2Fubm90IHVuaW5zdGFsbCBzZXJ2aWNlOiAnICsgbmFtZSArICcsIGJlY2F1c2UgaXQgaXM6ICcgKyBzZXJ2aWNlLnN0YXR1cy5zdGF0ZSk7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICAgICAgewogICAgICAgICAgICBzd2l0Y2ggKHRoaXMuZ2V0U2VydmljZVR5cGUoKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgY2FzZSAnaW5pdCc6CiAgICAgICAgICAgICAgICBjYXNlICd1cHN0YXJ0JzoKICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvZXRjL2luaXQuZC8nICsgbmFtZSkpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAvLyBpbml0LmQgc2VydmljZQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ3NlcnZpY2UgJyArIG5hbWUgKyAnIHN0b3BcbicpOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ3VwZGF0ZS1yYy5kIC1mICcgKyBuYW1lICsgJyByZW1vdmVcbicpOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKHNlcnZpY2VQYXRoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG5hbWUgKyAnIHVuaW5zdGFsbGVkJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG5hbWUgKyAnIGNvdWxkIG5vdCBiZSB1bmluc3RhbGxlZCcsIGUpCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LycgKyBuYW1lICsgJy5jb25mJykpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAvLyB1cHN0YXJ0IHNlcnZpY2UKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyBuYW1lICsgJyBzdG9wXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdleGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKHNlcnZpY2VQYXRoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG5hbWUgKyAnIHVuaW5zdGFsbGVkJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG5hbWUgKyAnIGNvdWxkIG5vdCBiZSB1bmluc3RhbGxlZCcsIGUpCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdzeXN0ZW1kJzoKICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10sIHsgdHlwZTogcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLlNwYXduVHlwZXMuVEVSTSB9KTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnc3lzdGVtY3RsIHN0b3AgJyArIG5hbWUgKyAnLnNlcnZpY2VcbicpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnc3lzdGVtY3RsIGRpc2FibGUgJyArIG5hbWUgKyAnLnNlcnZpY2VcbicpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoc2VydmljZVBhdGgpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJykpIHsgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKCcvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJyk7IH0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vJyArIG5hbWUgKyAnLnNlcnZpY2UnKSkgeyByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoJy91c3IvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJyk7IH0KICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobmFtZSArICcgdW5pbnN0YWxsZWQnKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhuYW1lICsgJyBjb3VsZCBub3QgYmUgdW5pbnN0YWxsZWQnLCBlKQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGRlZmF1bHQ6IC8vIHVua25vd24gcGxhdGZvcm0gc2VydmljZSB0eXBlCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgbmFtZSArICcucGxpc3QnKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdmFyIGNo", 16000);
	memcpy_s(_servicemanager + 80000, 2072, "aWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgc3RvcCAnICsgbmFtZSArICdcbicpOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCB1bmxvYWQgL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgbmFtZSArICcucGxpc3RcbicpOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoc2VydmljZVBhdGgpOwogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgbmFtZSArICcucGxpc3QnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoKGUpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhyb3cgKCdFcnJvciB1bmluc3RhbGxpbmcgc2VydmljZTogJyArIG5hbWUgKyAnID0+ICcgKyBlKTsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnJtZGlyU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBuYW1lKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoKGUpCiAgICAgICAgICAgICAgICB7fQogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCdTZXJ2aWNlOiAnICsgbmFtZSArICcgZG9lcyBub3QgZXhpc3QnKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KICAgIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JykKICAgIHsKICAgICAgICB0aGlzLmdldFNlcnZpY2VUeXBlID0gZnVuY3Rpb24gZ2V0U2VydmljZVR5cGUoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHBsYXRmb3JtID0gcmVxdWlyZSgncHJvY2Vzcy1tYW5hZ2VyJykuZ2V0UHJvY2Vzc0luZm8oMSkuTmFtZTsKICAgICAgICAgICAgaWYgKHBsYXRmb3JtID09ICdpbml0JykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgaWYocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvZXRjL2luaXQnKSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBwbGF0Zm9ybSA9ICd1cHN0YXJ0JzsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gKHBsYXRmb3JtKTsKICAgICAgICB9OwogICAgfQp9Cgptb2R1bGUuZXhwb3J0cyA9IHNlcnZpY2VNYW5hZ2VyOwptb2R1bGUuZXhwb3J0cy5tYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7", 2072);
	ILibBase64DecodeEx((unsigned char*)_servicemanager, 82072, (unsigned char*)_servicemanager + 82072);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "service-manager"); duk_push_string(ctx, _servicemanager + 82072);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_servicemanager);

	char *_usersessions = ILibMemory_Allocate(76714, 0, NULL, NULL);
	memcpy_s(_usersessions + 0, 43836, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBOT1RJRllfRk9SX1RISVNfU0VTU0lPTiA9IDA7CnZhciBOT1RJRllfRk9SX0FMTF9TRVNTSU9OUyA9IDE7CnZhciBXTV9XVFNTRVNTSU9OX0NIQU5HRSA9IDB4MDJCMTsKdmFyIFdNX1BPV0VSQlJPQURDQVNUID0gMHgyMTg7CnZhciBQQlRfUE9XRVJTRVRUSU5HQ0hBTkdFID0gMHg4MDEzOwp2YXIgUEJUX0FQTVNVU1BFTkQgPSAweDQ7CnZhciBQQlRfQVBNUkVTVU1FU1VTUEVORCA9IDB4NzsKdmFyIFBCVF9BUE1SRVNVTUVBVVRPTUFUSUMgPSAweDEyOwp2YXIgUEJUX0FQTVBPV0VSU1RBVFVTQ0hBTkdFID0gMHhBOwoKdmFyIFdUU19DT05TT0xFX0NPTk5FQ1QgICAgICAgICA9ICgweDEpOwp2YXIgV1RTX0NPTlNPTEVfRElTQ09OTkVDVCAgICAgID0gKDB4Mik7CnZhciBXVFNfUkVNT1RFX0NPTk5FQ1QgICAgICAgICAgPSAoMHgzKTsKdmFyIFdUU19SRU1PVEVfRElTQ09OTkVDVCAgICAgICA9ICgweDQpOwp2YXIgV1RTX1NFU1NJT05fTE9HT04gICAgICAgICAgID0gKDB4NSk7CnZhciBXVFNfU0VTU0lPTl9MT0dPRkYgICAgICAgICAgPSAoMHg2KTsKdmFyIFdUU19TRVNTSU9OX0xPQ0sgICAgICAgICAgICA9ICgweDcpOwp2YXIgV1RTX1NFU1NJT05fVU5MT0NLICAgICAgICAgID0gKDB4OCk7CnZhciBXVFNfU0VTU0lPTl9SRU1PVEVfQ09OVFJPTCAgPSAoMHg5KTsKdmFyIFdUU19TRVNTSU9OX0NSRUFURSAgICAgICAgICA9ICgweEEpOwp2YXIgV1RTX1NFU1NJT05fVEVSTUlOQVRFICAgICAgID0gKDB4Qik7Cgp2YXIgR1VJRF9BQ0RDX1BPV0VSX1NPVVJDRTsKdmFyIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORzsKdmFyIEdVSURfQ09OU09MRV9ESVNQTEFZX1NUQVRFOwoKZnVuY3Rpb24gY29sdW1uUGFyc2UoZGF0YSwgZGVsaW1pdGVyKQp7DQogICAgdmFyIHRva2VucyA9IGRhdGEuc3BsaXQoZGVsaW1pdGVyKTsNCiAgICB2YXIgcmV0ID0gW107DQogICAgZm9yKHZhciBpIGluIHRva2VucykNCiAgICB7DQogICAgICAgIGlmICh0b2tlbnNbaV0ubGVuZ3RoID4gMCkgeyByZXQucHVzaCh0b2tlbnNbaV0pOyB9DQogICAgfQ0KICAgIHJldHVybiAocmV0KTsNCn0KCgpmdW5jdGlvbiBVc2VyU2Vzc2lvbnMoKQp7CiAgICB0aGlzLl9PYmplY3RJRCA9ICd1c2VyLXNlc3Npb25zJzsKICAgIHJlcXVpcmUoJ2V2ZW50cycpLkV2ZW50RW1pdHRlci5jYWxsKHRoaXMsIHRydWUpCiAgICAgICAgLmNyZWF0ZUV2ZW50KCdjaGFuZ2VkJykKICAgICAgICAuY3JlYXRlRXZlbnQoJ2xvY2tlZCcpCiAgICAgICAgLmNyZWF0ZUV2ZW50KCd1bmxvY2tlZCcpOwoKICAgIHRoaXMuZW51bWVyYXRlVXNlcnMgPSBmdW5jdGlvbiBlbnVtZXJhdGVVc2VycygpCiAgICB7CiAgICAgICAgdmFyIHByb21pc2UgPSByZXF1aXJlKCdwcm9taXNlJyk7CiAgICAgICAgdmFyIHAgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9fcmVzb2x2ZXIgPSByZXM7CiAgICAgICAgICAgIHRoaXMuX19yZWplY3RvciA9IHJlajsKICAgICAgICB9KTsKICAgICAgICBwLl9faGFuZGxlciA9IGZ1bmN0aW9uIF9faGFuZGxlcih1c2VycykKICAgICAgICB7CiAgICAgICAgICAgIHAuX19yZXNvbHZlcih1c2Vycyk7CiAgICAgICAgfTsKICAgICAgICB0cnkKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuQ3VycmVudChwLl9faGFuZGxlcik7CiAgICAgICAgfQogICAgICAgIGNhdGNoKGUpCiAgICAgICAgewogICAgICAgICAgICBwLl9fcmVqZWN0b3IoZSk7CiAgICAgICAgfQogICAgICAgIHAucGFyZW50ID0gdGhpczsKICAgICAgICByZXR1cm4gKHApOwogICAgfQoKICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICd3aW4zMicpCiAgICB7CiAgICAgICAgdGhpcy5fc2VydmljZUhvb2tlZCA9IGZhbHNlOwogICAgICAgIHRoaXMuX21hcnNoYWwgPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKICAgICAgICB0aGlzLl9rZXJuZWwzMiA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoJ0tlcm5lbDMyLmRsbCcpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2V0TGFzdEVycm9yJyk7CiAgICAgICAgCiAgICAgICAgdHJ5CiAgICAgICAgewogICAgICAgICAgICB0aGlzLl93dHMgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdXdHNhcGkzMi5kbGwnKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTRW51bWVyYXRlU2Vzc2lvbnNBJyk7CiAgICAgICAgICAgIHRoaXMuX3d0cy5DcmVhdGVNZXRob2QoJ1dUU1F1ZXJ5U2Vzc2lvbkluZm9ybWF0aW9uQScpOwogICAgICAgICAgICB0aGlzLl93dHMuQ3JlYXRlTWV0aG9kKCdXVFNSZWdpc3RlclNlc3Npb25Ob3RpZmljYXRpb24nKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTVW5SZWdpc3RlclNlc3Npb25Ob3RpZmljYXRpb24nKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTRnJlZU1lbW9yeScpOwogICAgICAgIH0KICAgICAgICBjYXRjaChleGMpCiAgICAgICAgewogICAgICAgIH0KCiAgICAgICAgdGhpcy5fYWR2YXBpID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnQWR2YXBpMzIuZGxsJyk7CiAgICAgICAgdGhpcy5fYWR2YXBpLkNyZWF0ZU1ldGhvZCgnQWxsb2NhdGVBbmRJbml0aWFsaXplU2lkJyk7CiAgICAgICAgdGhpcy5fYWR2YXBpLkNyZWF0ZU1ldGhvZCgnQ2hlY2tUb2tlbk1lbWJlcnNoaXAnKTsKICAgICAgICB0aGlzLl9hZHZhcGkuQ3JlYXRlTWV0aG9kKCdGcmVlU2lkJyk7CgogICAgICAgIHRoaXMuX3VzZXIzMiA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKICAgICAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKHsgbWV0aG9kOiAnUmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24nLCB0aHJlYWREaXNwYXRjaDogMX0pOwogICAgICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ1VucmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24nKTsKICAgICAgICB0aGlzLl9ycGNydCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoJ1JwY3J0NC5kbGwnKTsKICAgICAgICB0aGlzLl9ycGNydC5DcmVhdGVNZXRob2QoJ1V1aWRGcm9tU3RyaW5nQScpOwogICAgICAgIHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRCA9IGZ1bmN0aW9uIFN0cmluZ1RvVVVJRChndWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHJldFZhbCA9IFN0cmluZ1RvVVVJRC51cy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSgxNik7CiAgICAgICAgICAgIGlmKFN0cmluZ1RvVVVJRC51cy5fcnBjcnQuVXVpZEZyb21TdHJpbmdBKFN0cmluZ1RvVVVJRC51cy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZShndWlkKSwgcmV0VmFsKS5WYWwgPT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCdDb3VsZCBub3QgY29udmVydCBzdHJpbmcgdG8gVVVJRCcpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRC51cyA9IHRoaXM7CgogICAgICAgIEdVSURfQUNEQ19QT1dFUl9TT1VSQ0UgPSB0aGlzLl9ycGNydC5TdHJpbmdUb1VVSUQoJzVkM2U5YTU5LWU5RDUtNGIwMC1hNmJkLWZmMzRmZjUxNjU0OCcpOwogICAgICAgIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORyA9IHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRCgnYTdhZDgwNDEtYjQ1YS00Y2FlLTg3YTMtZWVjYmI0NjhhOWUxJyk7CiAgICAgICAgR1VJRF9DT05TT0xFX0RJU1BMQVlfU1RBVEUgPSB0aGlzLl9ycGNydC5TdHJpbmdUb1VVSUQoJzZmZTY5NTU2LTcwNGEtNDdhMC04ZjI0LWMyOGQ5MzZmZGE0NycpOwoKICAgICAgICB0aGlzLlNlc3Npb25TdGF0ZXMgPSBbJ0FjdGl2ZScsICdDb25uZWN0ZWQnLCAnQ29ubmVjdFF1ZXJ5JywgJ1NoYWRvdycsICdEaXNjb25uZWN0ZWQnLCAnSWRsZScsICdMaXN0ZW5pbmcnLCAnUmVzZXQnLCAnRG93bicsICdJbml0J107CiAgICAgICAgdGhpcy5JbmZvQ2xhc3MgPQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAnV1RTSW5pdGlhbFByb2dyYW0nOiAwLAogICAgICAgICAgICAgICAgJ1dUU0FwcGxpY2F0aW9uTmFtZSc6IDEsCiAgICAgICAgICAgICAgICAnV1RTV29ya2luZ0RpcmVjdG9yeSc6IDIsCiAgICAgICAgICAgICAgICAnV1RTT0VNSWQnOiAzLAogICAgICAgICAgICAgICAgJ1dUU1Nlc3Npb25JZCc6IDQsCiAgICAgICAgICAgICAgICAnV1RTVXNlck5hbWUnOiA1LAogICAgICAgICAgICAgICAgJ1dUU1dpblN0YXRpb25OYW1lJzogNiwKICAgICAgICAgICAgICAgICdXVFNEb21haW5OYW1lJzogNywKICAgICAgICAgICAgICAgICdXVFNDb25uZWN0U3RhdGUnOiA4LAogICAgICAgICAgICAgICAgJ1dUU0NsaWVudEJ1aWxkTnVtYmVyJzogOSwKICAgICAgICAgICAgICAgICdXVFNDbGllbnROYW1lJzogMTAsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50RGlyZWN0b3J5JzogMTEsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50UHJvZHVjdElkJzogMTIsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50SGFyZHdhcmVJZCc6IDEzLAogICAgICAgICAgICAgICAgJ1dUU0NsaWVudEFkZHJlc3MnOiAxNCwKICAgICAgICAgICAgICAgICdXVFNDbGllbnREaXNwbGF5JzogMTUsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50UHJvdG9jb2xUeXBlJzogMTYsCiAgICAgICAgICAgICAgICAnV1RTSWRsZVRpbWUnOiAxNywKICAgICAgICAgICAgICAgICdXVFNMb2dvblRpbWUnOiAxOCwKICAgICAgICAgICAgICAgICdXVFNJbmNvbWluZ0J5dGVzJzogMTksCiAgICAgICAgICAgICAgICAnV1RTT3V0Z29pbmdCeXRlcyc6IDIwLAogICAgICAgICAgICAgICAgJ1dUU0luY29taW5nRnJhbWVzJzogMjEsCiAgICAgICAgICAgICAgICAnV1RTT3V0Z29pbmdGcmFtZXMnOiAyMiwKICAgICAgICAgICAgICAgICdXVFNDbGllbnRJbmZvJzogMjMsCiAgICAgICAgICAgICAgICAnV1RTU2Vzc2lvbkluZm8nOiAyNCwKICAgICAgICAgICAgICAgICdXVFNTZXNzaW9uSW5mb0V4JzogMjUsCiAgICAgICAgICAgICAgICAnV1RTQ29uZmlnSW5mbyc6IDI2LAogICAgICAgICAgICAgICAgJ1dUU1ZhbGlkYXRpb25JbmZvJzogMjcsCiAgICAgICAgICAgICAgICAnV1RTU2Vzc2lvbkFkZHJlc3NWNCc6IDI4LAogICAgICAgICAgICAgICAgJ1dUU0lzUmVtb3RlU2Vzc2lvbic6IDI5CiAgICAgICAgICAgIH07CgogICAgICAgIHRoaXMuaXNSb290ID0gZnVuY3Rpb24gaXNSb290KCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBOVEF1dGhvcml0eSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNik7CiAgICAgICAgICAgIE5UQXV0aG9yaXR5LnRvQnVmZmVyKCkud3JpdGVJbnQ4KDUsIDUpOwoKICAgICAgICAgICAgdmFyIEFkbWluaXN0cmF0b3JzR3JvdXAgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGFkbWluID0gZmFsc2U7CgogICAgICAgICAgICBpZiAodGhpcy5fYWR2YXBpLkFsbG9jYXRlQW5kSW5pdGlhbGl6ZVNpZChOVEF1dGhvcml0eSwgMiwgMzIsIDU0NCwgMCwgMCwgMCwgMCwgMCwgMCwgQWRtaW5pc3RyYXRvcnNHcm91cCkuVmFsICE9IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBtZW1iZXIgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZUludGVnZXIoKTsKICAgICAgICAgICAgICAgIGlmICh0aGlzLl9hZHZhcGkuQ2hlY2tUb2tlbk1lbWJlcnNoaXAoMCwgQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpLCBtZW1iZXIpLlZhbCAhPSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGlmIChtZW1iZXIudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSAhPSAwKSB7IGFkbWluID0gdHJ1ZTsgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgdGhpcy5fYWR2YXBpLkZyZWVTaWQoQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gYWRtaW47CiAgICAgICAgfQoKICAgICAgICB0aGlzLmdldFNlc3Npb25BdHRyaWJ1dGUgPSBmdW5jdGlvbiBnZXRTZXNzaW9uQXR0cmlidXRlKHNlc3Npb25JZCwgYXR0cikKICAgICAgICB7CiAgICAgICAgICAgIHZhciBidWZmZXIgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGJ5dGVzUmV0dXJuZWQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwoKICAgICAgICAgICAgaWYgKHRoaXMuX3d0cy5XVFNRdWVyeVNlc3Npb25JbmZvcm1hdGlvbkEoMCwgc2Vzc2lvbklkLCBhdHRyLCBidWZmZXIsIGJ5dGVzUmV0dXJuZWQpLlZhbCA9PSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIGNhbGxpbmcgV1RTUXVlcnlTZXNzaW9uSW5mb3JtYXRpb246ICcgKyB0aGlzLl9rZXJuZWwzMi5HZXRMYXN0RXJyb3IuVmFsKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIHJldFZhbCA9IGJ1ZmZlci5EZXJlZigpLlN0cmluZzsKCiAgICAgICAgICAgIHRoaXMuX3d0cy5XVFNGcmVlTWVtb3J5KGJ1ZmZlci5EZXJlZigpKTsKICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgIH07CgogICAgICAgIHRoaXMuQ3VycmVudCA9IGZ1bmN0aW9uIEN1cnJlbnQoY2IpCiAgICAgICAgewogICAgICAgICAgICB2YXIgcmV0VmFsID0ge307CiAgICAgICAgICAgIHZhciBwaW5mbyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgICAgICB2YXIgY291bnQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgICAgICBpZiAodGhpcy5fd3RzLldUU0VudW1lcmF0ZVNlc3Npb25zQSgwLCAwLCAxLCBwaW5mbywgY291bnQpLlZhbCA9PSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIGNhbGxpbmcgV1RTRW51bWVyYXRlU2Vzc2lvbnNBOiAnICsgdGhpcy5fa2VybmVsMzIuR2V0TGFzdEVycm9yKCkuVmFsKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBjb3VudC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpIDsgKytpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgaW5mbyA9IHBpbmZvLkRlcmVmKCkuRGVyZWYoaSAqICh0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyAxMiA6IDI0KSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSA9PSA0ID8gMTIgOiAyNCk7CiAgICAgICAgICAgICAgICB2YXIgaiA9IHsgU2Vzc2lvbklkOiBpbmZvLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkgfTsKICAgICAgICAgICAgICAgIGouU3RhdGlvbk5hbWUgPSBpbmZvLkRlcmVmKHRoaXMuX21hcnNoYWwuUG9pbnRlclNpemUgPT0gNCA/IDQgOiA4LCB0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouU3RhdGUgPSB0aGlzLlNlc3Npb25TdGF0ZXNbaW5mby5EZXJlZih0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyA4IDogMTYsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCldOwogICAgICAgICAgICAgICAgaWYgKGouU3RhdGUgPT0gJ0FjdGl2ZScpIHsKICAgICAgICAgICAgICAgICAgICBqLlVzZXJuYW1lID0gdGhpcy5nZXRTZXNzaW9uQXR0cmlidXRlKGouU2Vzc2lvbklkLCB0aGlzLkluZm9DbGFzcy5XVFNVc2VyTmFtZSk7CiAgICAgICAgICAgICAgICAgICAgai5Eb21haW4gPSB0aGlzLmdldFNlc3Npb25BdHRyaWJ1dGUoai5TZXNzaW9uSWQsIHRoaXMuSW5mb0NsYXNzLldUU0RvbWFpbk5hbWUpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmV0VmFsW2ouU2Vzc2lvbklkXSA9IGo7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHRoaXMuX3d0cy5XVFNGcmVlTWVtb3J5KHBpbmZvLkRlcmVmKCkpOwoKICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldFZhbCwgJ0FjdGl2ZScsIHsgdmFsdWU6IHNob3dBY3RpdmVPbmx5KHJldFZhbCkgfSk7CiAgICAgICAgICAgIGlmIChjYikgeyBjYihyZXRWYWwpOyB9CiAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICB9OwoKCiAgICAgICAgLy8gV2UgbmVlZCB0byBzcGluIHVwIGEgbWVzc2FnZSBwdW1wLCBhbmQgZmV0Y2ggYSB3aW5kb3cgaGFuZGxlCiAgICAgICAgdmFyIG1lc3NhZ2VfcHVtcCA9IHJlcXVpcmUoJ3dpbi1tZXNzYWdlLXB1bXAnKTsKICAgICAgICB0aGlzLl9tZXNzYWdlcHVtcCA9IG5ldyBtZXNzYWdlX3B1bXAoeyBmaWx0ZXI6IFdNX1dUU1NFU1NJT05fQ0hBTkdFIH0pOyB0aGlzLl9tZXNzYWdlcHVtcC5wYXJlbnQgPSB0aGlzOyAgICAgCiAgICAgICAgdGhpcy5fbWVzc2FnZXB1bXAub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgeyB0aGlzLnBhcmVudC5fd3RzLldUU1VuUmVnaXN0ZXJTZXNzaW9uTm90aWZpY2F0aW9uKHRoaXMucGFyZW50Lmh3bmQpOyB9KTsKICAgICAgICB0aGlzLl9tZXNzYWdlcHVtcC5vbignaHduZCcsIGZ1bmN0aW9uIChoKQogICAgICAgIHsKICAgICAgICAgICAgdGhpcy5wYXJlbnQuaHduZCA9IGg7CgogICAgICAgICAgICAvLyBXZSBuZWVkIHRvIHlpZWxkLCBhbmQgZG8gdGhpcyBpbiB0aGUgbmV4dCBldmVudCBsb29wIHBhc3MsIGJlY3Vhc2Ugd2UgZG9uJ3Qgd2FudCB0byBjYWxsICdSZWdpc3RlclBvd2VyU2V0dGluZ05vdGlmaWNhdGlvbicKICAgICAgICAgICAgLy8gZnJvbSB0aGUgbWVzc2FnZXB1bXAgJ3RocmVhZCcsIGJlY2F1c2Ugd2UgYXJlIGFjdHVhbGx5IG9uIHRoZSBtaWNyb3N0YWNrIHRocmVhZCwgc3VjaCB0aGF0IHRoZSBtZXNzYWdlIHB1bXAgdGhyZWFkLCBpcyBob2xkaW5nCiAgICAgICAgICAgIC8vIG9uIGEgc2VtYXBob3JlIGZvciB1cyB0byByZXR1cm4uIElmIHdlIGNhbGwgbm93LCB3ZSBtYXkgZGVhZGxvY2sgb24gV2luZG93cyA3LCBiZWN1YXNlIGl0IHdpbGwgdHJ5IHRvIG5vdGlmeSBpbW1lZGlhdGVseQogICAgICAgICAgICB0aGlzLmltbWVkaWF0ZSA9IHNldEltbWVkaWF0ZShmdW5jdGlvbiAoc2VsZikKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gTm93IHRoYXQgd2UgaGF2ZSBhIHdpbmRvdyBoYW5kbGUsIHdlIGNhbiByZWdpc3RlciBpdCB0byByZWNlaXZlIFdpbmRvd3MgTWVzc2FnZXMKICAgICAgICAgICAgICAgIGlmIChzZWxmLnBhcmVudC5fd3RzKSB7IHNlbGYucGFyZW50Ll93dHMuV1RTUmVnaXN0ZXJTZXNzaW9uTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIE5PVElGWV9GT1JfQUxMX1NFU1NJT05TKTsgfQogICAgICAgICAgICAgICAgc2VsZi5wYXJlbnQuX3VzZXIzMi5BQ0RDX0ggPSBzZWxmLnBhcmVudC5fdXNlcjMyLlJlZ2lzdGVyUG93ZXJTZXR0aW5nTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIEdVSURfQUNEQ19QT1dFUl9TT1VSQ0UsIDApOwogICAgICAgICAgICAgICAgc2VsZi5wYXJlbnQuX3VzZXIzMi5CQVRUX0ggPSBzZWxmLnBhcmVudC5fdXNlcjMyLlJlZ2lzdGVyUG93ZXJTZXR0aW5nTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORywgMCk7CiAgICAgICAgICAgICAgICBzZWxmLnBhcmVudC5fdXNlcjMyLkRJU1BfSCA9IHNlbGYucGFyZW50Ll91c2VyMzIuUmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24oc2VsZi5wYXJlbnQuaHduZCwgR1VJRF9DT05TT0xFX0RJU1BMQVlfU1RBVEUsIDApOwogICAgICAgICAgICAgICAgLy9jb25zb2xlLmxvZyhzZWxmLnBhcmVudC5fdXNlcjMyLkFDRENfSC5WYWwsIHNlbGYucGFyZW50Ll91c2VyMzIuQkFUVF9ILlZhbCwgc2VsZi5wYXJlbnQuX3VzZXIzMi5ESVNQX0guVmFsKTsKICAgICAgICAgICAgfSwgdGhpcyk7CiAgICAgICAgfSk7CiAgICAgICAgdGhpcy5fbWVzc2FnZXB1bXAub24oJ21lc3NhZ2UnLCBmdW5jdGlvbiAobXNnKQogICAgICAgIHsKICAgICAgICAgICAgc3dpdGNoKG1zZy5tZXNzYWdlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBjYXNlIFdNX1dUU1NFU1NJT05fQ0hBTkdFOgogICAgICAgICAgICAgICAgICAgIHN3aXRjaChtc2cud3BhcmFtKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBXVFNfU0VTU0lPTl9MT0NLOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW51bWVyYXRlVXNlcnMoKS50aGVuKGZ1bmN0aW9uICh1c2VycykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodXNlcnNbbXNnLmxwYXJhbV0pIHsgdGhpcy5wYXJlbnQuZW1pdCgnbG9ja2VkJywgdXNlcnNbbXNnLmxwYXJhbV0pOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX1VOTE9DSzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmVudW1lcmF0ZVVzZXJzKCkudGhlbihmdW5jdGlvbiAodXNlcnMpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHVzZXJzW21zZy5scGFyYW1dKSB7IHRoaXMucGFyZW50LmVtaXQoJ3VubG9ja2VkJywgdXNlcnNbbXNnLmxwYXJhbV0pOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX0xPR09OOgogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX0xPR09GRjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgV01fUE9XRVJCUk9BRENBU1Q6CiAgICAgICAgICAgICAgICAgICAgc3dpdGNoKG1zZy53cGFyYW0pCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ1dNX1BPV0VSQlJPQURDQVNUIFtVTktOT1dOIHdwYXJhbV06ICcgKyBtc2cud3BhcmFtKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNl", 16000);
	memcpy_s(_usersessions + 16000, 27836, "IFBCVF9BUE1TVVNQRU5EOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1NMRUVQJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBQQlRfQVBNUkVTVU1FQVVUT01BVElDOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1JFU1VNRV9OT05fSU5URVJBQ1RJVkUnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFBCVF9BUE1SRVNVTUVTVVNQRU5EOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1JFU1VNRV9JTlRFUkFDVElWRScpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgUEJUX0FQTVBPV0VSU1RBVFVTQ0hBTkdFOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFBCVF9QT1dFUlNFVFRJTkdDSEFOR0U6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbHBhcmFtID0gdGhpcy5wYXJlbnQuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcihCdWZmZXIuZnJvbShtc2cubHBhcmFtX2hleCwgJ2hleCcpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBkYXRhID0gbHBhcmFtLkRlcmVmKDIwLCBscGFyYW0uRGVyZWYoMTYsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKDApKS50b0J1ZmZlcigpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGxwYXJhbS5EZXJlZigwLCAxNikudG9CdWZmZXIoKS50b1N0cmluZygnaGV4JykpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBHVUlEX0FDRENfUE9XRVJfU09VUkNFLkRlcmVmKDAsIDE2KS50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGRhdGEucmVhZFVJbnQzMkxFKDApKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2FjZGMnLCAnQUMnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnYWNkYycsICdCQVRURVJZJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDI6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2FjZGMnLCAnSE9UJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBHVUlEX0JBVFRFUllfUEVSQ0VOVEFHRV9SRU1BSU5JTkcuRGVyZWYoMCwgMTYpLnRvQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnYmF0dGVyeUxldmVsJywgZGF0YS5yZWFkVUludDMyTEUoMCkpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEdVSURfQ09OU09MRV9ESVNQTEFZX1NUQVRFLkRlcmVmKDAsIDE2KS50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGRhdGEucmVhZFVJbnQzMkxFKDApKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2Rpc3BsYXknLCAnT0ZGJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDE6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2Rpc3BsYXknLCAnT04nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnZGlzcGxheScsICdESU1NRUQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgIH0KICAgIGVsc2UgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgewogICAgICAgIHZhciBkYnVzID0gcmVxdWlyZSgnbGludXgtZGJ1cycpOwogICAgICAgIGlmIChyZXF1aXJlKCdmcycpLndhdGNoKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLl9saW51eFdhdGNoZXIgPSByZXF1aXJlKCdmcycpLndhdGNoKCcvdmFyL3J1bi91dG1wJyk7CiAgICAgICAgICAgIHRoaXMuX2xpbnV4V2F0Y2hlci51c2VyX3Nlc3Npb24gPSB0aGlzOwogICAgICAgICAgICB0aGlzLl9saW51eFdhdGNoZXIub24oJ2NoYW5nZScsIGZ1bmN0aW9uIChhLCBiKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMudXNlcl9zZXNzaW9uLmVtaXQoJ2NoYW5nZWQnKTsNCiAgICAgICAgICAgIH0pOw0KICAgICAgICB9CiAgICAgICAgdGhpcy5fdXNlcnMgPSBmdW5jdGlvbiBfdXNlcnMoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdhd2sgLUY6IFwnKCQzID49IDApIHtwcmludGYgIiVzOiVzXFxuIiwgJDEsICQzfVwnIC9ldGMvcGFzc3dkXG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciByZXQgPSB7fSwgdG9rZW5zOwogICAgICAgICAgICBmb3IgKHZhciBsbiBpbiBsaW5lcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbbG5dLnNwbGl0KCc6Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHJldFt0b2tlbnNbMF1dID0gdG9rZW5zWzFdOyB9ICAgICAgICAgICAKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgfQogICAgICAgIHRoaXMuX3VpZHMgPSBmdW5jdGlvbiBfdWlkcygpIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdhd2sgLUY6IFwnKCQzID49IDApIHtwcmludGYgIiVzOiVzXFxuIiwgJDEsICQzfVwnIC9ldGMvcGFzc3dkXG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciByZXQgPSB7fSwgdG9rZW5zOwogICAgICAgICAgICBmb3IgKHZhciBsbiBpbiBsaW5lcykgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbbG5dLnNwbGl0KCc6Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHJldFt0b2tlbnNbMV1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH0KICAgICAgICB0aGlzLkN1cnJlbnQgPSBmdW5jdGlvbiBDdXJyZW50KGNiKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHJldFZhbCA9IHt9OwogICAgICAgICAgICByZXRWYWwuX09iamVjdElEID0gJ1VzZXJTZXNzaW9uJwogICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0VmFsLCAnX2NhbGxiYWNrJywgeyB2YWx1ZTogY2IgfSk7CiAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXRWYWwsICdfY2hpbGQnLCB7IHZhbHVlOiByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy91c3IvYmluL2xhc3QnLCBbJ2xhc3QnLCAnLWYnLCAnL3Zhci9ydW4vdXRtcCddKSB9KTsKCiAgICAgICAgICAgIHJldFZhbC5fY2hpbGQuUGFyZW50ID0gcmV0VmFsOwogICAgICAgICAgICByZXRWYWwuX2NoaWxkLl90eHQgPSAnJzsKICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgbGluZXMgPSB0aGlzLl90eHQuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbnMgPSBbXTsKICAgICAgICAgICAgICAgIHZhciB1c2VycyA9IHt9OwoKICAgICAgICAgICAgICAgIGZvcih2YXIgaSBpbiBsaW5lcykKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBpZiAobGluZXNbaV0pCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgdG9rZW5zID0gZ2V0VG9rZW5zKGxpbmVzW2ldKTsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHMgPSB7IFVzZXJuYW1lOiB0b2tlbnNbMF0sIFNlc3Npb25JZDogdG9rZW5zWzFdIH0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRva2Vuc1szXS5pbmNsdWRlcygnc3RpbGwgbG9nZ2VkIGluJykpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMuU3RhdGUgPSAnQWN0aXZlJzsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMuTGFzdEFjdGl2ZSA9IHRva2Vuc1szXTsKICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbnMucHVzaChzKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBzZXNzaW9ucy5wb3AoKTsKCgogICAgICAgICAgICAgICAgdmFyIHVzZXJuYW1lcyA9IHt9OwogICAgICAgICAgICAgICAgdmFyIHByb21pc2VzID0gW107CgogICAgICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBzZXNzaW9ucykKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBpZiAoc2Vzc2lvbnNbaV0uVXNlcm5hbWUgIT0gJ3JlYm9vdCcpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB1c2Vyc1tzZXNzaW9uc1tpXS5TZXNzaW9uSWRdID0gc2Vzc2lvbnNbaV07CiAgICAgICAgICAgICAgICAgICAgICAgIGlmKHVzZXJuYW1lc1tzZXNzaW9uc1tpXS5Vc2VybmFtZV0gPT0gbnVsbCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWVzW3Nlc3Npb25zW2ldLlVzZXJuYW1lXSA9IC0xOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ3Byb21pc2UnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoKGUpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHVzZXJzLCAnQWN0aXZlJywgeyB2YWx1ZTogc2hvd0FjdGl2ZU9ubHkodXNlcnMpIH0pOwogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLlBhcmVudC5fY2FsbGJhY2spIHsgdGhpcy5QYXJlbnQuX2NhbGxiYWNrLmNhbGwodGhpcy5QYXJlbnQsIHVzZXJzKTsgfQogICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICB2YXIgcHJvbWlzZSA9IHJlcXVpcmUoJ3Byb21pc2UnKTsKICAgICAgICAgICAgICAgIGZvciAodmFyIG4gaW4gdXNlcm5hbWVzKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBwID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fX3VzZXJuYW1lID0gbjsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fX3Jlc29sdmVyID0gcmVzOyB0aGlzLl9fcmVqZWN0b3IgPSByZWo7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX19jaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vaWQnLCBbJ2lkJywgJy11Jywgbl0pOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9fY2hpbGQucHJvbWlzZSA9IHRoaXM7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX19jaGlsZC5zdGRvdXQuX3R4dCA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9fY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuX3R4dCArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fX2NoaWxkLm9uKCdleGl0JywgZnVuY3Rpb24gKGNvZGUpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcnNlSW50KHRoaXMuc3Rkb3V0Ll90eHQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX19yZWplY3RvcignaW52YWxpZCB1aWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGlkID0gcGFyc2VJbnQodGhpcy5zdGRvdXQuX3R4dCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX19yZXNvbHZlcihpZCk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIHByb21pc2VzLnB1c2gocCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBwcm9taXNlLmFsbChwcm9taXNlcykudGhlbihmdW5jdGlvbiAocGxpc3QpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgLy8gRG9uZQogICAgICAgICAgICAgICAgICAgIHZhciB0YWJsZSA9IHt9OwogICAgICAgICAgICAgICAgICAgIGZvcih2YXIgaSBpbiBwbGlzdCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlW3BsaXN0W2ldLl9fdXNlcm5hbWVdID0gcGxpc3RbaV0uX2ludGVybmFsLmNvbXBsZXRlZEFyZ3NbMF07CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGZvcih2YXIgaSBpbiB1c2VycykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHVzZXJzW2ldLnVpZCA9IHRhYmxlW3VzZXJzW2ldLlVzZXJuYW1lXTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHVzZXJzLCAnQWN0aXZlJywgeyB2YWx1ZTogc2hvd0FjdGl2ZU9ubHkodXNlcnMpIH0pOwogICAgICAgICAgICAgICAgICAgIGlmIChyZXRWYWwuX2NhbGxiYWNrKSB7IHJldFZhbC5fY2FsbGJhY2suY2FsbChyZXRWYWwsIHVzZXJzKTsgfQogICAgICAgICAgICAgICAgfSwgZnVuY3Rpb24gKHJlYXNvbikKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAvLyBGYWlsZWQKICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodXNlcnMsICdBY3RpdmUnLCB7IHZhbHVlOiBzaG93QWN0aXZlT25seSh1c2VycykgfSk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHJldFZhbC5fY2FsbGJhY2spIHsgcmV0VmFsLl9jYWxsYmFjay5jYWxsKHJldFZhbCwgdXNlcnMpOyB9CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHJldFZhbC5fY2hpbGQuc3Rkb3V0LlBhcmVudCA9IHJldFZhbC5fY2hpbGQ7CiAgICAgICAgICAgIHJldFZhbC5fY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuUGFyZW50Ll90eHQgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CgogICAgICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICAgICAgfQogICAgICAgIHRoaXMuX3JlY2hlY2tMb2dnZWRJblVzZXJzID0gZnVuY3Rpb24gX3JlY2hlY2tMb2dnZWRJblVzZXJzKCkKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuZW51bWVyYXRlVXNlcnMoKS50aGVuKGZ1bmN0aW9uICh1KQogICAgICAgICAgICB7CgogICAgICAgICAgICAgICAgaWYgKHUuQWN0aXZlLmxlbmd0aCA+IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgLy8gVGhlcmUgaXMgYWxyZWFkeSBhIHVzZXIgbG9nZ2VkIGluLCBzbyB3ZSBjYW4gbW9uaXRvciBEQlVTIGZvciBsb2NrL3VubG9jawogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnBhcmVudC5fbGludXhfbG9ja193YXRjaGVyICE9IG51bGwgJiYgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlci51aWQgIT0gdS5BY3RpdmVbMF0udWlkKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIHRoaXMucGFyZW50Ll9saW51eF9sb2NrX3dhdGNoZXI7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50Ll9saW51eF9sb2NrX3dhdGNoZXIgPSBuZXcgZGJ1cyhwcm9jZXNzLmVudlsnWERHX0NVUlJFTlRfREVTS1RPUCddID09ICdVbml0eScgPyAnY29tLnVidW50dS5VcHN0YXJ0MF82JyA6ICdvcmcuZ25vbWUuU2NyZWVuU2F2ZXInLCB1LkFjdGl2ZVswXS51aWQpOwogICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50Ll9saW51eF9sb2NrX3dhdGNoZXIudXNlcl9zZXNzaW9uID0gdGhpcy5wYXJlbnQ7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlci5vbignc2lnbmFsJywgZnVuY3Rpb24gKHMpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgcCA9IHRoaXMudXNlcl9zZXNzaW9uLmVudW1lcmF0ZVVzZXJzKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHAuc2lnbmFsRGF0YSA9IHMuZGF0YVswXTsKICAgICAgICAgICAgICAgICAgICAgICAgcC50aGVuKGZ1bmN0aW9uICh1KQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKHRoaXMuc2lnbmFsRGF0YSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIHRydWU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnZGVza3RvcC1sb2NrJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW1pdCgnbG9ja2VkJywgdS5BY3RpdmVbMF0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIGZhbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ2Rlc2t0b3AtdW5sb2NrJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW1pdCgndW5sb2NrZWQnLCB1LkFjdGl2ZVswXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UgaWYgKHRoaXMucGFyZW50Ll9saW51eF9sb2NrX3dhdGNoZXIgIT0gbnVsbCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBkZWxldGUgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlcjsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSk7CgogICAgICAgIH07CiAgICAgICAgdGhpcy5nZXRVaWRDb25maWcgPSBmdW5jdGlvbiBnZXRVaWRDb25maWcoKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgcmV0ID0ge307DQogICAgICAgICAgICB2YXIgY2ZnID0gcmVxdWlyZSgnZnMnKS5yZWFkRmlsZVN5bmMoJy9ldGMvbG9naW4uZGVmcycpLnRvU3RyaW5nKCkuc3BsaXQoJ1xuJyk7DQogICAgICAgICAgICB2YXIgdG9rZW5zOw0KICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBjZmcpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdG9rZW5zID0gY29sdW1uUGFyc2UoY2ZnW2ldLCAnXHQnKTsgLy9jb25zb2xlLmxvZyh0b2tlbnMpOw0KICAgICAgICAgICAgICAgIGlmICh0b2tlbnNbMF0gPT0gJ1VJRF9NSU4nKSB7IHJldC5NSU4gPSBwYXJzZUludCh0b2tlbnNbMV0pOyB9DQogICAgICAgICAgICAgICAgaWYgKHRva2Vuc1swXSA9PSAnVUlEX01BWCcpIHsgcmV0Lk1BWCA9IHBhcnNlSW50KHRva2Vuc1sxXSk7IH0NCiAgICAgICAgICAgICAgICBp", 16000);
	memcpy_s(_usersessions + 32000, 11836, "ZiAocmV0Lk1JTiAhPSBudWxsICYmIHJldC5NQVggIT0gbnVsbCkgeyBicmVhazsgfQ0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICB9OwogICAgICAgIHRoaXMuZ2V0VWlkID0gZnVuY3Rpb24gZ2V0VWlkKHVzZXJuYW1lKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOw0KICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOw0KICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOw0KICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL3Bhc3N3ZCB8IGF3ayAtRjogJygkMT09XCIiICsgdXNlcm5hbWUgKyAiXCIpe3ByaW50ICQzfSdcbmV4aXRcbiIpOw0KICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsNCg0KICAgICAgICAgICAgdmFyIHJldCA9IHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIpOyAgICAgICAgICAgIA0KICAgICAgICAgICAgaWYgKHJldCA+PSAwKSB7IHJldHVybiAocmV0KTsgfQ0KICAgICAgICAgICAgdGhyb3cgKCd1c2VybmFtZTogJyArIHVzZXJuYW1lICsgJyBOT1QgRk9VTkQnKTsNCiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFVzZXJuYW1lID0gZnVuY3Rpb24gZ2V0VXNlcm5hbWUodWlkKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOw0KICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOw0KICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOw0KICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL3Bhc3N3ZCB8IGF3ayAtRjogJygkMz09IiArIHVpZCArICIpe3ByaW50ICQxfSdcbmV4aXRcbiIpOw0KICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsNCiAgICAgICAgICAgIGlmIChjaGlsZC5zdGRvdXQuc3RyLmxlbmd0aCA+IDApIHsgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7IH0NCiAgICAgICAgICAgIHRocm93ICgndWlkOiAnICsgdWlkICsgJyBOT1QgRk9VTkQnKTsNCiAgICAgICAgfTsKICAgICAgICB0aGlzLndob2FtaSA9IGZ1bmN0aW9uIHdob2FtaSgpDQogICAgICAgIHsNCiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7DQogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7DQogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7DQogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hvYW1pXG5leGl0XG4iKTsNCiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7DQogICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsNCiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldEVudkZyb21QaWQgPSBmdW5jdGlvbiBnZXRFbnZGcm9tUGlkKHBpZCkKICAgICAgICB7DQogICAgICAgICAgICB2YXIgcmV0ID0ge307DQogICAgICAgICAgICB2YXIgcHMsIHBzeCwgdiwgdnMgPSAwOw0KICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHBzID0gcmVxdWlyZSgnZnMnKS5yZWFkRmlsZVN5bmMoJy9wcm9jLycgKyBwaWQgKyAnL2Vudmlyb24nKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjYXRjaChwc2UpCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7DQogICAgICAgICAgICB9DQoNCiAgICAgICAgICAgIGZvciAocHN4ID0gMDsgcHN4IDwgcHMubGVuZ3RoOyArK3BzeCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBpZiAocHNbcHN4XSA9PSAwKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdiA9IHBzLnNsaWNlKHZzLCBwc3gpLnRvU3RyaW5nKCkuc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgICAgICByZXRbdlswXV0gPSB2WzFdOwogICAgICAgICAgICAgICAgICAgIHZzID0gcHN4ICsgMTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICByZXR1cm4gKHJldCk7DQogICAgICAgIH07CgogICAgICAgIHRoaXMub24oJ2NoYW5nZWQnLCB0aGlzLl9yZWNoZWNrTG9nZ2VkSW5Vc2Vycyk7IC8vIEZvciBsaW51eCBMb2NrL1VubG9jayBtb25pdG9yaW5nLCB3ZSBuZWVkIHRvIHdhdGNoIGZvciBMb2dPbi9Mb2dPZmYsIGFuZCBrZWVwIHRyYWNrIG9mIHRoZSBVSUQuCgogICAgICAgIAogICAgICAgIC8vIEZpcnN0IHN0ZXAsIGlzIHRvIHNlZSBpZiB0aGVyZSBpcyBhIHVzZXIgbG9nZ2VkIGluOgogICAgICAgIHRoaXMuX3JlY2hlY2tMb2dnZWRJblVzZXJzKCk7CiAgICB9CiAgICBlbHNlIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpCiAgICB7CiAgICAgICAgdGhpcy5fdXNlcnMgPSBmdW5jdGlvbiAoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvdXNyL2Jpbi9kc2NsJywgWydkc2NsJywgJy4nLCAnbGlzdCcsICcvVXNlcnMnLCAnVW5pcXVlSUQnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnZXhpdFxuJyk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICB2YXIgdG9rZW5zLCBpOwogICAgICAgICAgICB2YXIgdXNlcnMgPSB7fTsKCiAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJyAnKTsKICAgICAgICAgICAgICAgIGlmICh0b2tlbnNbMF0pIHsgdXNlcnNbdG9rZW5zWzBdXSA9IHRva2Vuc1t0b2tlbnMubGVuZ3RoIC0gMV07IH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgcmV0dXJuICh1c2Vycyk7CiAgICAgICAgfQogICAgICAgIHRoaXMuX3VpZHMgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vZHNjbCcsIFsnZHNjbCcsICcuJywgJ2xpc3QnLCAnL1VzZXJzJywgJ1VuaXF1ZUlEJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAgICAgdmFyIGxpbmVzID0gY2hpbGQuc3Rkb3V0LnN0ci5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgdmFyIHRva2VucywgaTsKICAgICAgICAgICAgdmFyIHVzZXJzID0ge307CgogICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyArK2kpIHsKICAgICAgICAgICAgICAgIHRva2VucyA9IGxpbmVzW2ldLnNwbGl0KCcgJyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHVzZXJzW3Rva2Vuc1t0b2tlbnMubGVuZ3RoIC0gMV1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHJldHVybiAodXNlcnMpOwogICAgICAgIH0KICAgICAgICB0aGlzLl9pZFRhYmxlID0gZnVuY3Rpb24oKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHRhYmxlID0ge307CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vaWQnLCBbJ2lkJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJylbMF0uc3BsaXQoJyAnKTsKICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkgewogICAgICAgICAgICAgICAgdmFyIHR5cGVzID0gbGluZXNbaV0uc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSB0eXBlc1sxXS5zcGxpdCgnLCcpOwogICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dID0ge307CgogICAgICAgICAgICAgICAgZm9yICh2YXIgaiBpbiB0b2tlbnMpIHsKICAgICAgICAgICAgICAgICAgICB2YXIgaWRhcnIgPSB0b2tlbnNbal0uc3BsaXQoJygnKTsKICAgICAgICAgICAgICAgICAgICB2YXIgaWQgPSBpZGFyclswXTsKICAgICAgICAgICAgICAgICAgICB2YXIgbmFtZSA9IGlkYXJyWzFdLnN1YnN0cmluZygwLCBpZGFyclsxXS5sZW5ndGggLSAxKS50cmltKCk7CiAgICAgICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dW25hbWVdID0gaWQ7CiAgICAgICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dW2lkXSA9IG5hbWU7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuICh0YWJsZSk7CiAgICAgICAgfQogICAgICAgIHRoaXMuQ3VycmVudCA9IGZ1bmN0aW9uIChjYikKICAgICAgICB7CiAgICAgICAgICAgIHZhciB1c2VycyA9IHt9OwogICAgICAgICAgICB2YXIgdGFibGUgPSB0aGlzLl9pZFRhYmxlKCk7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vbGFzdCcsIFsnbGFzdCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aCAmJiBsaW5lc1tpXS5sZW5ndGggPiAwOyArK2kpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmICghdXNlcnNbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0pCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB1c2Vyc1tsaW5lc1tpXS5zcGxpdCgnICcpWzBdXSA9IHsgVXNlcm5hbWU6IGxpbmVzW2ldLnNwbGl0KCcgJylbMF0sIFN0YXRlOiBsaW5lc1tpXS5zcGxpdCgnc3RpbGwgbG9nZ2VkIGluJykubGVuZ3RoID4gMSA/ICdBY3RpdmUnIDogJ0luYWN0aXZlJywgdWlkOiB0YWJsZS51aWRbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0gfTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7fQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGlmKHVzZXJzW2xpbmVzW2ldLnNwbGl0KCcgJylbMF1dLlN0YXRlICE9ICdBY3RpdmUnICYmIGxpbmVzW2ldLnNwbGl0KCdzdGlsbCBsb2dnZWQgaW4nKS5sZW5ndGggPiAxKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdXNlcnNbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0uU3RhdGUgPSAnQWN0aXZlJzsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh1c2VycywgJ0FjdGl2ZScsIHsgdmFsdWU6IHNob3dBY3RpdmVPbmx5KHVzZXJzKSB9KTsKICAgICAgICAgICAgaWYgKGNiKSB7IGNiLmNhbGwodGhpcywgdXNlcnMpOyB9CiAgICAgICAgfQogICAgfQoKICAgIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JyB8fCBwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKQogICAgewogICAgICAgIHRoaXMuU2VsZiA9IGZ1bmN0aW9uIFNlbGYoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvdXNyL2Jpbi9pZCcsIFsnaWQnLCAnLXUnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIpKTsKICAgICAgICB9CiAgICAgICAgdGhpcy5pc1Jvb3QgPSBmdW5jdGlvbiBpc1Jvb3QoKQogICAgICAgIHsKICAgICAgICAgICAgcmV0dXJuICh0aGlzLlNlbGYoKSA9PSAwKTsKICAgICAgICB9CiAgICAgICAgdGhpcy5jb25zb2xlVWlkID0gZnVuY3Rpb24gY29uc29sZVVpZCgpCiAgICAgICAgewogICAgICAgICAgICB2YXIgY2hlY2tzdHIgPSBwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nID8gJ2NvbnNvbGUnIDogKChwcm9jZXNzLmVudlsnRElTUExBWSddKT9wcm9jZXNzLmVudlsnRElTUExBWSddOic6MCcpCiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnd2hvXG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciB0b2tlbnMsIGksIGo7CiAgICAgICAgICAgIGZvciAoaSBpbiBsaW5lcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJyAnKTsKICAgICAgICAgICAgICAgIGZvciAoaiA9IDE7IGogPCB0b2tlbnMubGVuZ3RoOyArK2opCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2Vuc1tqXS5sZW5ndGggPiAwKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChwYXJzZUludCh0aGlzLl91c2VycygpW3Rva2Vuc1swXV0pKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgCiAgICAgICAgICAgIHRocm93ICgnbm9ib2R5IGxvZ2dlZCBpbnRvIGNvbnNvbGUnKTsKICAgICAgICB9CiAgICB9CgoKfQpmdW5jdGlvbiBzaG93QWN0aXZlT25seShzb3VyY2UpCnsKICAgIHZhciByZXRWYWwgPSBbXTsKICAgIHZhciB1bmlxdWUgPSB7fTsKICAgIHZhciB1c2VybmFtZXMgPSBbXTsKICAgIHZhciB0bXA7CgogICAgZm9yICh2YXIgaSBpbiBzb3VyY2UpCiAgICB7CiAgICAgICAgaWYgKHNvdXJjZVtpXS5TdGF0ZSA9PSAnQWN0aXZlJykKICAgICAgICB7CiAgICAgICAgICAgIHJldFZhbC5wdXNoKHNvdXJjZVtpXSk7CiAgICAgICAgICAgIHRtcCA9IChzb3VyY2VbaV0uRG9tYWluID8gKHNvdXJjZVtpXS5Eb21haW4gKyAnXFwnKSA6ICcnKSArIHNvdXJjZVtpXS5Vc2VybmFtZTsKICAgICAgICAgICAgaWYgKCF1bmlxdWVbdG1wXSkgeyB1bmlxdWVbdG1wXSA9IHRtcDt9CiAgICAgICAgfQogICAgfQoKICAgIGZvciAodmFyIGkgaW4gdW5pcXVlKQogICAgewogICAgICAgIHVzZXJuYW1lcy5wdXNoKGkpOwogICAgfQoKICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXRWYWwsICd1c2VybmFtZXMnLCB7IHZhbHVlOiB1c2VybmFtZXMgfSk7CiAgICByZXR1cm4gKHJldFZhbCk7Cn0KZnVuY3Rpb24gZ2V0VG9rZW5zKHN0cikKewogICAgdmFyIGNvbHVtbnMgPSBbXTsKICAgIHZhciBpOwoKICAgIGNvbHVtbnMucHVzaChzdHIuc3Vic3RyaW5nKDAsIChpPXN0ci5pbmRleE9mKCcgJykpKSk7CiAgICB3aGlsZSAoc3RyWysraV0gPT0gJyAnKTsKICAgIGNvbHVtbnMucHVzaChzdHIuc3Vic3RyaW5nKGksIChpPXN0ci5zdWJzdHJpbmcoaSkuaW5kZXhPZignICcpICsgaSkpKTsKICAgIHdoaWxlIChzdHJbKytpXSA9PSAnICcpOwogICAgY29sdW1ucy5wdXNoKHN0ci5zdWJzdHJpbmcoaSwgKGk9c3RyLnN1YnN0cmluZyhpKS5pbmRleE9mKCcgJykgKyBpKSkpOwogICAgd2hpbGUgKHN0clsrK2ldID09ICcgJyk7CiAgICB2YXIgc3RhdHVzID0gc3RyLnN1YnN0cmluZyhpKS50cmltKCk7CiAgICBjb2x1bW5zLnB1c2goc3RhdHVzKTsKCiAgICByZXR1cm4gKGNvbHVtbnMpOwp9Cgptb2R1bGUuZXhwb3J0cyA9IG5ldyBVc2VyU2Vzc2lvbnMoKTs=", 11836);
	ILibBase64DecodeEx((unsigned char*)_usersessions, 43836, (unsigned char*)_usersessions + 43836);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "user-sessions"); duk_push_string(ctx, _usersessions + 43836);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_usersessions);


	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addModule('_agentNodeId', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCmZ1bmN0aW9uIF9tZXNoTm9kZUlkKCkNCnsNCiAgICB2YXIgcmV0ID0gJyc7DQogICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQ0KICAgIHsNCiAgICAgICAgY2FzZSAnbGludXgnOg0KICAgICAgICBjYXNlICdkYXJ3aW4nOg0KICAgICAgICAgICAgdHJ5DQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIGRiID0gcmVxdWlyZSgnU2ltcGxlRGF0YVN0b3JlJykuQ3JlYXRlKHByb2Nlc3MuZXhlY1BhdGggKyAnLmRiJywgeyByZWFkT25seTogdHJ1ZSB9KTsNCiAgICAgICAgICAgICAgICByZXQgPSByZXF1aXJlKCd0bHMnKS5sb2FkQ2VydGlmaWNhdGUoeyBwZng6IGRiLkdldEJ1ZmZlcignU2VsZk5vZGVDZXJ0JyksIHBhc3NwaHJhc2U6ICdoaWRkZW4nIH0pLmdldEtleUhhc2goKS50b1N0cmluZygnaGV4Jyk7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaChlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgYnJlYWs7DQogICAgICAgIGNhc2UgJ3dpbjMyJzoNCiAgICAgICAgICAgIC8vIEZpcnN0IENoZWNrIGlmIHRoZSBkYiBDb250YWlucyB0aGUgTm9kZUlEDQogICAgICAgICAgICB0cnkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB2YXIgZGIgPSByZXF1aXJlKCdTaW1wbGVEYXRhU3RvcmUnKS5DcmVhdGUocHJvY2Vzcy5leGVjUGF0aC5yZXBsYWNlKCcuZXhlJywgJy5kYicpLCB7IHJlYWRPbmx5OiB0cnVlIH0pOw0KICAgICAgICAgICAgICAgIHZhciB2ID0gZGIuR2V0QnVmZmVyKCdTZWxmTm9kZUNlcnQnKTsNCiAgICAgICAgICAgICAgICBpZiAodikNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHRyeQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICByZXQgPSByZXF1aXJlKCd0bHMnKS5sb2FkQ2VydGlmaWNhdGUoeyBwZng6IHYsIHBhc3NwaHJhc2U6ICdoaWRkZW4nIH0pLmdldEtleUhhc2goKS50b1N0cmluZygnaGV4Jyk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgdiA9IG51bGw7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgaWYgKHYgPT0gbnVsbCAmJiAodiA9IGRiLkdldEJ1ZmZlcignTm9kZUlEJykpICE9IE5VTEwpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXQgPSB2LnRvU3RyaW5nKCdoZXgnKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaCAoZSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICBkZWZhdWx0Og0KICAgICAgICAgICAgYnJlYWs7DQogICAgfQ0KICAgIHJldHVybiAocmV0KTsNCn0NCg0KbW9kdWxlLmV4cG9ydHMgPSBfbWVzaE5vZGVJZDsNCg0K', 'base64').toString());");

	// Task Scheduler, refer to modules/task-scheduler.js
	char *_taskscheduler = ILibMemory_Allocate(44751, 0, NULL, NULL);
	memcpy_s(_taskscheduler + 0, 25572, "LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcHJvbWlzZSA9IHJlcXVpcmUoJ3Byb21pc2UnKTsNCnZhciBzZXJ2aWNlbWFuYWdlciA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpOw0KdmFyIG1nciA9IG5ldyBzZXJ2aWNlbWFuYWdlcigpOw0KDQovL2F0dGFjaERlYnVnZ2VyKHsgd2VicG9ydDogOTk5NSwgd2FpdDogMSB9KS50aGVuKGNvbnNvbGUubG9nKTsNCg0KZnVuY3Rpb24gdGFzaygpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAndGFzay1zY2hlZHVsZXInOw0KDQogICAgdGhpcy5jcmVhdGUgPSBmdW5jdGlvbiBjcmVhdGUob3B0aW9ucykNCiAgICB7DQogICAgICAgIHZhciByZXQgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOw0KICAgICAgICBpZihvcHRpb25zLm5hbWUgJiYgb3B0aW9ucy5zZXJ2aWNlKQ0KICAgICAgICB7DQogICAgICAgICAgICBzd2l0Y2gocHJvY2Vzcy5wbGF0Zm9ybSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBjYXNlICd3aW4zMic6DQogICAgICAgICAgICAgICAgICAgIHZhciBwYXJtcyA9IFsnc2NodGFza3MnLCAnL0NyZWF0ZScsICcvUlUgU1lTVEVNJ107DQogICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGZ0eXBlIGluIG9wdGlvbnMpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChmdHlwZS50b1VwcGVyQ2FzZSgpKQ0KICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01JTlVURSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnSE9VUkxZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdEQUlMWSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnV0VFS0xZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdNT05USExZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL1NDICcgKyBmdHlwZS50b1VwcGVyQ2FzZSgpKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL01PICcgKyBvcHRpb25zW2Z0eXBlXSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0RBWSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9EICcgKyBvcHRpb25zW2Z0eXBlXSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01PTlRIJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL00gJyArIG9wdGlvbnNbZnR5cGVdKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnVElNRSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9TVCAnICsgb3B0aW9uc1tmdHlwZV0pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdOQU1FJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL1ROICInICsgb3B0aW9uc1tmdHlwZV0uc3BsaXQoJy8nKS5qb2luKCdcXCcpICsgJyInKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnU0VSVklDRSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9UUiAibmV0IHN0YXJ0ICcgKyBvcHRpb25zW2Z0eXBlXSArICciJyk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHBhcm1zLmpvaW4oJyAnKSk7DQogICAgICAgICAgICAgICAgICAgIHJldC5jaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZShwcm9jZXNzLmVudlsnd2luZGlyJ10gKyAnXFxzeXN0ZW0zMlxcc2NodGFza3MuZXhlJywgcGFybXMpOw0KICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOw0KICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOw0KICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOw0KICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQucHJvbWlzZSA9IHJldDsNCiAgICAgICAgICAgICAgICAgICAgcmV0LmNoaWxkLm9uKCdleGl0JywgZnVuY3Rpb24gKGNvZGUpIHsgaWYgKGNvZGUgPT0gMCkgeyB0aGlzLnByb21pc2UuX3JlcygpOyB9IGVsc2UgeyB0aGlzLnByb21pc2UuX3Jlaihjb2RlKTsgfX0pOyANCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgY2FzZSAnbGludXgnOg0KICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvZXRjL2Nyb24uZC8nICsgb3B0aW9ucy5uYW1lLnNwbGl0KCcvJykuam9pbignXycpLnNwbGl0KCcuJykuam9pbignJykpKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaignVGFzayBbJyArIG9wdGlvbnMubmFtZSArICddIEFscmVhZHkgZXhpc3RzJyk7DQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgdmFyIG1pbnV0ZSA9ICcqJzsNCiAgICAgICAgICAgICAgICAgICAgdmFyIGhvdXIgPSAnKic7DQogICAgICAgICAgICAgICAgICAgIHZhciBkYXkgPSAnKic7DQogICAgICAgICAgICAgICAgICAgIHZhciBtb250aCA9ICcqJzsNCiAgICAgICAgICAgICAgICAgICAgdmFyIHdlZWtkYXkgPSAnKic7DQogICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGZ0eXBlIGluIG9wdGlvbnMpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChmdHlwZS50b1VwcGVyQ2FzZSgpKQ0KICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01JTlVURSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghb3B0aW9ucy5USU1FICYmICFvcHRpb25zLnRpbWUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1pbnV0ZSA9ICcqLycgKyBvcHRpb25zW2Z0eXBlXTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdIT1VSTFknOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIW9wdGlvbnMuVElNRSAmJiAhb3B0aW9ucy50aW1lKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBob3VyID0gJyovJyArIG9wdGlvbnNbZnR5cGVdOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0RBSUxZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF5ID0gJyovJyArIG9wdGlvbnNbZnR5cGVdOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdXRUVLTFknOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAob3B0aW9uc1tmdHlwZV0gPT0gMSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoIW9wdGlvbnMuREFZICYmICFvcHRpb25zLmRheSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3ZWVrZGF5ID0gMDsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKCdPbmx5IE9uY2UvV2Vla2x5IHN1cHBvcnRlZCBvbiBMaW51eCcpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0RBWSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLndlZWtseSB8fCBvcHRpb25zLldFRUtMWSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2Vla2RheSA9IG9wdGlvbnNbZnR5cGVdOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF5ID0gb3B0aW9uc1tmdHlwZV07DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnVElNRSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhvdXIgPSBvcHRpb25zW2Z0eXBlXS5zcGxpdCgnOicpWzBdOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtaW51dGUgPSBvcHRpb25zW2Z0eXBlXS5zcGxpdCgnOicpWzFdOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdNT05USExZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9udGggPSAnKi8nICsgb3B0aW9uc1tmdHlwZV07DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICB9DQoNCiAgICAgICAgICAgICAgICAgICAgdmFyIGFjdGlvbiA9ICdTSEVMTD0vYmluL3NoXG5QQVRIPS91c3IvbG9jYWwvc2JpbjovdXNyL2xvY2FsL2Jpbjovc2JpbjovYmluOi91c3Ivc2JpbjovdXNyL2JpblxuXG4nOw0KICAgICAgICAgICAgICAgICAgICBhY3Rpb24gKz0gKG1pbnV0ZSArICcgJyArIGhvdXIgKyAnICcgKyBkYXkgKyAnICcgKyBtb250aCArICcgJyArIHdlZWtkYXkgKyAnICAgcm9vdCAgICcpOw0KICAgICAgICAgICAgICAgICAgICBzd2l0Y2gocmVxdWlyZSgnc2VydmljZS1tYW5hZ2VyJykubWFuYWdlci5nZXRTZXJ2aWNlVHlwZSgpKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdpbml0JzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJ3aGVyZWlzIHNlcnZpY2UgfCBhd2sgJ3twcmludCAkMn0nXG5cZXhpdFxuIik7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9uICs9IChjaGlsZC5zdGRvdXQuc3RyICsgJyAnICsgb3B0aW9ucy5zZXJ2aWNlICsgJyByZXN0YXJ0ID4vZGV2L251bGwgMj4mMSBcbicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAndXBzdGFydCc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hlcmVpcyBpbml0Y3RsIHwgYXdrICd7cHJpbnQgJDJ9J1xuXGV4aXRcbiIpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGlvbiArPSAoY2hpbGQuc3Rkb3V0LnN0ciArICcgJyArIG9wdGlvbnMuc2VydmljZSArICcgcmVzdGFydCA+L2Rldi9udWxsIDI+JjEgXG4nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ3N5c3RlbWQnOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoIndoZXJlaXMgc3lzdGVtY3RsIHwgYXdrICd7cHJpbnQgJDJ9J1xuXGV4aXRcbiIpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGlvbiArPSAoY2hpbGQuc3Rkb3V0LnN0ciArICcgcmVzdGFydCAnICsgb3B0aW9ucy5zZXJ2aWNlICsgJyA+L2Rldi9udWxsIDI+JjEgXG4nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooJ1Vua25vd24gU2VydmljZSBQbGF0Zm9ybTogJyArIHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0U2VydmljZVR5cGUoKSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgIHRyeQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JUlVTUiB8IHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JV1VTUiB8IHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JUk9USDsNCiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnL2V0Yy9jcm9uLmQvJyArIG9wdGlvbnMubmFtZS5zcGxpdCgnLycpLmpvaW4oJ18nKS5zcGxpdCgnLicpLmpvaW4oJycpLCBhY3Rpb24sIHsgZmxhZ3M6ICd3YicsIG1vZGU6IG0gfSk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooZSk7DQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZXMoKTsNCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgY2FzZSAnZGFyd2luJzoNCiAgICAgICAgICAgICAgICAgICAgdmFyIHRhc2tuYW1lID0gb3B0aW9ucy5uYW1lLnNwbGl0KCcvJykuam9pbignXycpLnNwbGl0KCcuJykuam9pbignJyk7DQogICAgICAgICAgICAgICAgICAgIHZhciBwbGlzdCA9ICc8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJVVEYtOCI/PlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJzwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlIENvbXB1dGVyLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJzxwbGlzdCB2ZXJzaW9uPSIxLjAiPlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgPGRpY3Q+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5MYWJlbDwva2V5PlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gKCcgICAgIDxzdHJpbmc+JyArIHRhc2tuYW1lICsgJzwvc3RyaW5nPlxuJyk7DQogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8a2V5PlByb2dyYW1Bcmd1bWVudHM8L2tleT5cbic7DQogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8YXJyYXk+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgICA8c3RyaW5nPi9iaW4vbGF1bmNoY3RsPC9zdHJpbmc+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgICA8c3RyaW5nPnN0YXJ0PC9zdHJpbmc+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAoJyAgICAgICA8c3RyaW5nPicgKyBvcHRpb25zLnNlcnZpY2UgKyAnPC9zdHJpbmc+XG4nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDwvYXJyYXk+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5SdW5BdExvYWQ8L2tleT5cbic7DQogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8ZmFsc2UvPlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJ3t7e0lOVEVSVkFMfX19JzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgPC9kaWN0PlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJzwvcGxpc3Q+JzsNCg0KICAgICAgICAgICAgICAgICAgICB2YXIgaW50ZXJ2YWwgPSBudWxsOw0KICAgICAgICAgICAgICAgICAgICB2YXIgcGVyaW9kaWMgPSAnJzsNCg0KICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBmdHlwZSBpbiBvcHRpb25zKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKGZ0eXBlLnRvVXBwZXJDYXNlKCkpDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnTUlOVVRFJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGludGVydmFsICE9IG51bGwgfHwgcGVyaW9kaWMgIT0gJycpIHsgcmV0Ll9yZWooJ0ludmFsaWQgT3B0aW9ucycpOyByZXR1cm4gKHJldCk7IH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW50ZXJ2YWwgPSAnICAgICAgPGludGVnZXI+JyArIChwYXJzZUludChvcHRpb25zW2Z0eXBlXSkgKiA2MCkgKyAnPC9pbnRlZ2VyPlxuJzsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnSE9VUkxZJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGludGVydmFsICE9IG51bGwgfHwgcGVyaW9kaWMgIT0gJycpIHsgcmV0Ll9yZWooJ0ludmFsaWQgT3B0aW9ucycpOyByZXR1cm4gKHJldCk7IH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW50ZXJ2YWwgPSAnICAgICAgPGludGVnZXI+JyArIChwYXJzZUludChvcHRpb25zW2Z0eXBlXSkgKiA2MCAqIDYwKSArICc8L2ludGVnZXI+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdEQUlMWSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCAhPSBudWxsIHx8IHBlcmlvZGljICE9ICcnKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpO30NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW50ZXJ2YWwgPSAnICAgICAgPGludGVnZXI+JyArIChwYXJzZUludChvcHRpb25zW2Z0eXBlXSkgKiAyNCAqIDYwICogNjApICsgJzwvaW50ZWdlcj5cbic7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1dFRUtM", 16000);
	memcpy_s(_taskscheduler + 16000, 9572, "WSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCAhPSBudWxsKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpOyB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghb3B0aW9ucy5EQVkgJiYgIW9wdGlvbnMuZGF5KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnRlcnZhbCA9ICcgICAgICA8aW50ZWdlcj4nICsgKHBhcnNlSW50KG9wdGlvbnNbZnR5cGVdKSAqIDYwKSArICc8L2ludGVnZXI+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYocGFyc2VJbnQob3B0aW9uc1tmdHlwZV0pICE9IDEpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMsIE9ubHkgT25jZSBXZWVrbHkgU3VwcG9ydGVkIHdoZW4gREFZIHNwZWNpZmllZCcpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01PTlRITFknOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaW50ZXJ2YWwgIT0gbnVsbCB8fCBwZXJpb2RpYyAhPSAnJykgeyByZXQuX3JlaignSW52YWxpZCBPcHRpb25zJyk7IHJldHVybiAocmV0KTt9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGludGVydmFsID0gJyAgICAgIDxpbnRlZ2VyPicgKyAocGFyc2VJbnQob3B0aW9uc1tmdHlwZV0pICogMzAgKiAyNCAqIDYwICogNjApICsgJzwvaW50ZWdlcj5cbic7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0RBWSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCAhPSBudWxsKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpO30NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHBhcnNlSW50KG9wdGlvbnMud2Vla2x5KSA9PSAxIHx8IHBhcnNlSW50KG9wdGlvbnMuV0VFS0xZKSA9PSAxKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAnICAgICAgICAgPGtleT5XZWVrZGF5PC9rZXk+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMgKz0gKCcgICAgICAgICA8aW50ZWdlcj4nICsgb3B0aW9uc1tmdHlwZV0gKyAnPC9pbnRlZ2VyPlxuJyk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAnICAgICAgICAgPGtleT5EYXk8L2tleT5cbic7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAoJyAgICAgICAgIDxpbnRlZ2VyPicgKyBvcHRpb25zW2Z0eXBlXSArICc8L2ludGVnZXI+XG4nKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdNT05USCc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCAhPSBudWxsKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpO30NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMgKz0gJyAgICAgICAgIDxrZXk+TW9udGg8L2tleT5cbic7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlcmlvZGljICs9ICgnICAgICAgICAgPGludGVnZXI+JyArIG9wdGlvbnNbZnR5cGVdICsgJzwvaW50ZWdlcj5cbicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdUSU1FJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGludGVydmFsICE9IG51bGwpIHsgcmV0Ll9yZWooJ0ludmFsaWQgT3B0aW9ucycpOyByZXR1cm4gKHJldCk7fQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAnICAgICAgICAgPGtleT5Ib3VyPC9rZXk+XG4nOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAoJyAgICAgICAgIDxpbnRlZ2VyPicgKyBvcHRpb25zW2Z0eXBlXS5zcGxpdCgnOicpWzBdICsgJzwvaW50ZWdlcj5cbicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYyArPSAnICAgICAgICAgPGtleT5NaW51dGU8L2tleT5cbic7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlcmlvZGljICs9ICgnICAgICAgICAgPGludGVnZXI+JyArIG9wdGlvbnNbZnR5cGVdLnNwbGl0KCc6JylbMV0gKyAnPC9pbnRlZ2VyPlxuJyk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgPSBwbGlzdC5yZXBsYWNlKCd7e3tJTlRFUlZBTH19fScsICcgICAgICA8a2V5PlN0YXJ0SW50ZXJ2YWw8L2tleT5cbicgKyBpbnRlcnZhbCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgaWYgKHBlcmlvZGljKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCA9IHBsaXN0LnJlcGxhY2UoJ3t7e0lOVEVSVkFMfX19JywgJyAgICAgIDxrZXk+U3RhcnRDYWxlbmRhckludGVydmFsPC9rZXk+XG4gICAgICA8ZGljdD5cbicgKyBwZXJpb2RpYyArICcgICAgICA8L2RpY3Q+XG4nKTsNCiAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIHRhc2tuYW1lICsgJy5wbGlzdCcsIHBsaXN0KTsNCg0KICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOw0KICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7DQogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgbG9hZCAvTGlicmFyeS9MYXVuY2hEYWVtb25zLycgKyB0YXNrbmFtZSArICcucGxpc3RcbmV4aXRcbicpOw0KICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOw0KICAgICAgICAgICAgICAgICAgICByZXQuX3JlcygpOw0KICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICBkZWZhdWx0Og0KICAgICAgICAgICAgICAgICAgICByZXQuX3JlaignTm90IGltcGxlbWVudGVkIG9uICcgKyBwcm9jZXNzLnBsYXRmb3JtKTsNCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICByZXQuX3JlaignSW52YWxpZCBQYXJhbWV0ZXJzLCBtdXN0IGF0IGxlYXN0IHNwZWNpZnkgbmFtZSBhbmQgc2VydmljZScpOw0KICAgICAgICB9DQogICAgICAgIHJldHVybiAocmV0KTsNCiAgICB9Ow0KICAgIHRoaXMuaW5mbyA9IGZ1bmN0aW9uIGluZm8obmFtZSkNCiAgICB7DQogICAgICAgIHZhciByZXQgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOw0KICAgICAgICBzd2l0Y2ggKHByb2Nlc3MucGxhdGZvcm0pDQogICAgICAgIHsNCiAgICAgICAgICAgIGRlZmF1bHQ6DQogICAgICAgICAgICAgICAgcmV0Ll9yZWooJ05vdCBpbXBsZW1lbnRlZCBvbiAnICsgcHJvY2Vzcy5wbGF0Zm9ybSk7DQogICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgIH0NCiAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgIH07DQogICAgdGhpcy5kZWxldGUgPSBmdW5jdGlvbiBfZGVsZXRlKG5hbWUpDQogICAgew0KICAgICAgICB2YXIgcmV0ID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsNCiAgICAgICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQ0KICAgICAgICB7DQogICAgICAgICAgICBjYXNlICd3aW4zMic6DQogICAgICAgICAgICAgICAgcmV0LmNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKHByb2Nlc3MuZW52Wyd3aW5kaXInXSArICdcXHN5c3RlbTMyXFxzY2h0YXNrcy5leGUnLCBbJ3NjaHRhc2tzJywgJy9EZWxldGUnLCAnL1ROICInICsgbmFtZS5zcGxpdCgnLycpLmpvaW4oJ1xcJykgKyAnIicsICcvRiddKTsNCiAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOw0KICAgICAgICAgICAgICAgIHJldC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7DQogICAgICAgICAgICAgICAgcmV0LmNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsNCiAgICAgICAgICAgICAgICByZXQuY2hpbGQucHJvbWlzZSA9IHJldDsNCiAgICAgICAgICAgICAgICByZXQuY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgeyBpZiAoY29kZSA9PSAwKSB7IHRoaXMucHJvbWlzZS5fcmVzKCk7IH0gZWxzZSB7IHRoaXMucHJvbWlzZS5fcmVqKGNvZGUpOyB9IH0pOw0KICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgY2FzZSAnbGludXgnOg0KICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvY3Jvbi5kLycgKyBuYW1lLnNwbGl0KCcvJykuam9pbignXycpLnNwbGl0KCcuJykuam9pbignJykpKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdHJ5DQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYygnL2V0Yy9jcm9uLmQvJyArIG5hbWUuc3BsaXQoJy8nKS5qb2luKCdfJykuc3BsaXQoJy4nKS5qb2luKCcnKSk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooZSk7DQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZXMoKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooJ1Rhc2sgWycgKyBuYW1lICsgJ10gZG9lcyBub3QgZXhpc3QnKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICBjYXNlICdkYXJ3aW4nOg0KICAgICAgICAgICAgICAgIHZhciB0YXNrbmFtZSA9IG5hbWUuc3BsaXQoJy8nKS5qb2luKCdfJykuc3BsaXQoJy4nKS5qb2luKCcnKTsNCiAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvTGlicmFyeS9MYXVuY2hEYWVtb25zLycgKyB0YXNrbmFtZSArICcucGxpc3QnKSkNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7DQogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsNCiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCB1bmxvYWQgL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0XG5leGl0XG4nKTsNCiAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsNCiAgICAgICAgICAgICAgICAgICAgdHJ5DQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0Jyk7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKGUpOw0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgIHJldC5fcmVzKCk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKCdUYXNrIFsnICsgbmFtZSArICddIGRvZXMgbm90IGV4aXN0Jyk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIGJyZWFrOw0KICAgICAgICAgICAgZGVmYXVsdDoNCiAgICAgICAgICAgICAgICByZXQuX3JlaignTm90IGltcGxlbWVudGVkIG9uICcgKyBwcm9jZXNzLnBsYXRmb3JtKTsNCiAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgfQ0KICAgICAgICByZXR1cm4gKHJldCk7DQogICAgfTsNCn0NCg0KDQptb2R1bGUuZXhwb3J0cyA9IG5ldyB0YXNrKCk7DQoNCv==", 9572);
	ILibBase64DecodeEx((unsigned char*)_taskscheduler, 25572, (unsigned char*)_taskscheduler + 25572);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "task-scheduler"); duk_push_string(ctx, _taskscheduler + 25572);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_taskscheduler);

	// wget: Refer to modules/wget.js for a human readable version. This is the only module that won't update, if you just past the .js file, because the module loader caches results, and the following does a require('wget') in the property definition
	duk_peval_string_noresult(ctx, "addModule('wget', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQoNCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOw0KdmFyIGh0dHAgPSByZXF1aXJlKCdodHRwJyk7DQp2YXIgd3JpdGFibGUgPSByZXF1aXJlKCdzdHJlYW0nKS5Xcml0YWJsZTsNCg0KDQpmdW5jdGlvbiB3Z2V0KHJlbW90ZVVyaSwgbG9jYWxGaWxlUGF0aCwgd2dldG9wdGlvbnMpDQp7DQogICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7DQogICAgdmFyIGFnZW50Q29ubmVjdGVkID0gZmFsc2U7DQogICAgcmVxdWlyZSgnZXZlbnRzJykuRXZlbnRFbWl0dGVyLmNhbGwocmV0LCB0cnVlKQ0KICAgICAgICAuY3JlYXRlRXZlbnQoJ2J5dGVzJykNCiAgICAgICAgLmNyZWF0ZUV2ZW50KCdhYm9ydCcpDQogICAgICAgIC5hZGRNZXRob2QoJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLl9yZXF1ZXN0LmFib3J0KCk7IH0pOw0KDQogICAgdHJ5DQogICAgew0KICAgICAgICBhZ2VudENvbm5lY3RlZCA9IHJlcXVpcmUoJ01lc2hBZ2VudCcpLmlzQ29udHJvbENoYW5uZWxDb25uZWN0ZWQ7DQogICAgfQ0KICAgIGNhdGNoIChlKQ0KICAgIHsNCiAgICB9DQoNCiAgICAvLyBXZSBvbmx5IG5lZWQgdG8gY2hlY2sgcHJveHkgc2V0dGluZ3MgaWYgdGhlIGFnZW50IGlzIG5vdCBjb25uZWN0ZWQsIGJlY2F1c2Ugd2hlbiB0aGUgYWdlbnQNCiAgICAvLyBjb25uZWN0cywgaXQgYXV0b21hdGljYWxseSBjb25maWd1cmVzIHRoZSBwcm94eSBmb3IgSmF2YVNjcmlwdC4NCiAgICBpZiAoIWFnZW50Q29ubmVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHJlZyA9IHJlcXVpcmUoJ3dpbi1yZWdpc3RyeScpOw0KICAgICAgICAgICAgaWYgKHJlZy5RdWVyeUtleShyZWcuSEtFWS5DdXJyZW50VXNlciwgJ1NvZnR3YXJlXFxNaWNyb3NvZnRcXFdpbmRvd3NcXEN1cnJlbnRWZXJzaW9uXFxJbnRlcm5ldCBTZXR0aW5ncycsICdQcm94eUVuYWJsZScpID09IDEpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHByb3h5VXJpID0gcmVnLlF1ZXJ5S2V5KHJlZy5IS0VZLkN1cnJlbnRVc2VyLCAnU29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXEludGVybmV0IFNldHRpbmdzJywgJ1Byb3h5U2VydmVyJyk7DQogICAgICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSByZXF1aXJlKCdodHRwJykucGFyc2VVcmkoJ2h0dHA6Ly8nICsgcHJveHlVcmkpOw0KDQogICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ3Byb3h5ID0+ICcgKyBwcm94eVVyaSk7DQogICAgICAgICAgICAgICAgcmVxdWlyZSgnZ2xvYmFsLXR1bm5lbCcpLmluaXRpYWxpemUob3B0aW9ucyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQoNCiAgICB2YXIgcmVxT3B0aW9ucyA9IHJlcXVpcmUoJ2h0dHAnKS5wYXJzZVVyaShyZW1vdGVVcmkpOw0KICAgIGlmICh3Z2V0b3B0aW9ucykNCiAgICB7DQogICAgICAgIGZvciAodmFyIGlucHV0T3B0aW9uIGluIHdnZXRvcHRpb25zKSB7DQogICAgICAgICAgICByZXFPcHRpb25zW2lucHV0T3B0aW9uXSA9IHdnZXRvcHRpb25zW2lucHV0T3B0aW9uXTsNCiAgICAgICAgfQ0KICAgIH0NCiAgICByZXQuX3RvdGFsQnl0ZXMgPSAwOw0KICAgIHJldC5fcmVxdWVzdCA9IGh0dHAuZ2V0KHJlcU9wdGlvbnMpOw0KICAgIHJldC5fbG9jYWxGaWxlUGF0aCA9IGxvY2FsRmlsZVBhdGg7DQogICAgcmV0Ll9yZXF1ZXN0LnByb21pc2UgPSByZXQ7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdlcnJvcicsIGZ1bmN0aW9uIChlKSB7IHRoaXMucHJvbWlzZS5fcmVqKGUpOyB9KTsNCiAgICByZXQuX3JlcXVlc3Qub24oJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLnByb21pc2UuZW1pdCgnYWJvcnQnKTsgfSk7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdyZXNwb25zZScsIGZ1bmN0aW9uIChpbXNnKQ0KICAgIHsNCiAgICAgICAgaWYoaW1zZy5zdGF0dXNDb2RlICE9IDIwMCkNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWooJ1NlcnZlciByZXNwb25zZWQgd2l0aCBTdGF0dXMgQ29kZTogJyArIGltc2cuc3RhdHVzQ29kZSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICB0cnkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9maWxlID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSh0aGlzLnByb21pc2UuX2xvY2FsRmlsZVBhdGgsIHsgZmxhZ3M6ICd3YicgfSk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhID0gcmVxdWlyZSgnU0hBMzg0U3RyZWFtJykuY3JlYXRlKCk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhLnByb21pc2UgPSB0aGlzLnByb21pc2U7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaChlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKGUpOw0KICAgICAgICAgICAgICAgIHJldHVybjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIHRoaXMuX3NoYS5vbignaGFzaCcsIGZ1bmN0aW9uIChoKSB7IHRoaXMucHJvbWlzZS5fcmVzKGgudG9TdHJpbmcoJ2hleCcpKTsgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvciA9IG5ldyB3cml0YWJsZSgNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHdyaXRlOiBmdW5jdGlvbihjaHVuaywgY2FsbGJhY2spDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fdG90YWxCeXRlcyArPSBjaHVuay5sZW5ndGg7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuZW1pdCgnYnl0ZXMnLCB0aGlzLnByb21pc2UuX3RvdGFsQnl0ZXMpOw0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICh0cnVlKTsNCiAgICAgICAgICAgICAgICAgICAgfSwNCiAgICAgICAgICAgICAgICAgICAgZmluYWw6IGZ1bmN0aW9uKGNhbGxiYWNrKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjaygpOw0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvci5wcm9taXNlID0gdGhpcy5wcm9taXNlOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2ZpbGUpOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2FjY3VtdWxhdG9yKTsNCiAgICAgICAgICAgIGltc2cucGlwZSh0aGlzLl9zaGEpOw0KICAgICAgICB9DQogICAgfSk7DQogICAgcmV0LnByb2dyZXNzID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gKHRoaXMuX3RvdGFsQnl0ZXMpOyB9Ow0KICAgIHJldHVybiAocmV0KTsNCn0NCg0KbW9kdWxlLmV4cG9ydHMgPSB3Z2V0Ow0KDQoNCv==', 'base64').toString());");
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {value: require('wget')});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {value: require('os').arch()});");
}

void ILibDuktape_ChainViewer_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[0];
	void *hptr = ((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[1];
	
	ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "PostSelect");	// [emit][this][name]
	duk_push_int(ctx, slct);										// [emit][this][name][select]

	char *m = ILibChain_GetMetaDataFromDescriptorSet(Duktape_GetChain(ctx), readset, writeset, errorset);
	duk_push_string(ctx, m);
	if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ChainViewer.emit('PostSelect'): Error "); }
	duk_pop(ctx);
}

extern void ILibPrependToChain(void *Chain, void *object);
void ILibDuktape_ChainViewer_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);			// [viewer]

	ILibTransport *t = (ILibTransport*)ILibChain_Link_Allocate(sizeof(ILibTransport), 2*sizeof(void*));
	t->ChainLink.MetaData = "ILibDuktape_ChainViewer";
	t->ChainLink.PostSelectHandler = ILibDuktape_ChainViewer_PostSelect;
	((void**)t->ChainLink.ExtraMemoryPtr)[0] = ctx;
	((void**)t->ChainLink.ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "PostSelect");
	ILibPrependToChain(chain, (void*)t);
}

duk_ret_t ILibDuktape_httpHeaders(duk_context *ctx)
{
	ILibHTTPPacket *packet = NULL;
	packetheader_field_node *node;
	int headersOnly = duk_get_top(ctx) > 1 ? (duk_require_boolean(ctx, 1) ? 1 : 0) : 0;

	duk_size_t bufferLen;
	char *buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);

	packet = ILibParsePacketHeader(buffer, 0, (int)bufferLen);
	if (packet == NULL) { return(ILibDuktape_Error(ctx, "http-headers(): Error parsing data")); }

	if (headersOnly == 0)
	{
		duk_push_object(ctx);
		if (packet->Directive != NULL)
		{
			duk_push_lstring(ctx, packet->Directive, packet->DirectiveLength);
			duk_put_prop_string(ctx, -2, "method");
			duk_push_lstring(ctx, packet->DirectiveObj, packet->DirectiveObjLength);
			duk_put_prop_string(ctx, -2, "url");
		}
		else
		{
			duk_push_int(ctx, packet->StatusCode);
			duk_put_prop_string(ctx, -2, "statusCode");
			duk_push_lstring(ctx, packet->StatusData, packet->StatusDataLength);
			duk_put_prop_string(ctx, -2, "statusMessage");
		}
		if (packet->VersionLength == 3)
		{
			duk_push_object(ctx);
			duk_push_lstring(ctx, packet->Version, 1);
			duk_put_prop_string(ctx, -2, "major");
			duk_push_lstring(ctx, packet->Version + 2, 1);
			duk_put_prop_string(ctx, -2, "minor");
			duk_put_prop_string(ctx, -2, "version");
		}
	}

	duk_push_object(ctx);		// headers
	node = packet->FirstField;
	while (node != NULL)
	{
		duk_push_lstring(ctx, node->Field, node->FieldLength);			// [str]
		duk_get_prop_string(ctx, -1, "toLowerCase");					// [str][toLower]
		duk_swap_top(ctx, -2);											// [toLower][this]
		duk_call_method(ctx, 0);										// [result]
		duk_push_lstring(ctx, node->FieldData, node->FieldDataLength);
		duk_put_prop(ctx, -3);
		node = node->NextField;
	}
	if (headersOnly == 0)
	{
		duk_put_prop_string(ctx, -2, "headers");
	}
	ILibDestructPacket(packet);
	return(1);
}
void ILibDuktape_httpHeaders_PUSH(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_httpHeaders, DUK_VARARGS);
}
void ILibDuktape_DescriptorEvents_PreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_heapptr(ctx, h);												// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][table][enum]
	while (duk_next(ctx, -1, 1))											// [obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);									
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [obj][table][enum][FD][emitter][options]
		if (Duktape_GetBooleanProperty(ctx, -1, "readset", 0)) { FD_SET(fd, readset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)) { FD_SET(fd, writeset); }
		if (Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)) { FD_SET(fd, errorset); }
		duk_pop_3(ctx);														// [obj][table][enum]
	}

	duk_set_top(ctx, i);
}
void ILibDuktape_DescriptorEvents_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL) { return; }

	int i = duk_get_top(ctx);
	int fd;

	duk_push_array(ctx);												// [array]
	duk_push_heapptr(ctx, h);											// [array][obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [array][obj][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [array][obj][table][enum]
	while (duk_next(ctx, -1, 1))										// [array][obj][table][enum][FD][emitter]
	{
		fd = (int)duk_to_int(ctx, -2);
		if (FD_ISSET(fd, readset) || FD_ISSET(fd, writeset) || FD_ISSET(fd, errorset))
		{
			duk_put_prop_index(ctx, -6, (duk_uarridx_t)duk_get_length(ctx, -6));		// [array][obj][table][enum][FD]
			duk_pop(ctx);												// [array][obj][table][enum]
		}
		else
		{
			duk_pop_2(ctx);												// [array][obj][table][enum]

		}
	}
	duk_pop_3(ctx);																						// [array]

	while (duk_get_length(ctx, -1) > 0)
	{
		duk_get_prop_string(ctx, -1, "pop");															// [array][pop]
		duk_dup(ctx, -2);																				// [array][pop][this]
		if (duk_pcall_method(ctx, 0) == 0)																// [array][emitter]
		{
			if ((fd = Duktape_GetIntPropertyValue(ctx, -1, ILibDuktape_DescriptorEvents_FD, -1)) != -1)
			{
				if (FD_ISSET(fd, readset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "readset");		// [array][emitter][emit][this][readset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][readset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, writeset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "writeset");		// [array][emitter][emit][this][writeset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][writeset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
				if (FD_ISSET(fd, errorset))
				{
					ILibDuktape_EventEmitter_SetupEmit(ctx, duk_get_heapptr(ctx, -1), "errorset");		// [array][emitter][emit][this][errorset]
					duk_push_int(ctx, fd);																// [array][emitter][emit][this][errorset][fd]
					duk_pcall_method(ctx, 2); duk_pop(ctx);												// [array][emitter]
				}
			}
		}
		duk_pop(ctx);																					// [array]
	}
	duk_set_top(ctx, i);
}
duk_ret_t ILibDuktape_DescriptorEvents_Remove(duk_context *ctx)
{
	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	duk_del_prop(ctx, -2);												// [obj][table]
	return(0);
}
duk_ret_t ILibDuktape_DescriptorEvents_Add(duk_context *ctx)
{
	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_push_object(ctx);												// [obj][table][value]
	duk_dup(ctx, 0);													// [obj][table][value][key]
	duk_dup(ctx, -2);													// [obj][table][value][key][value]
	ILibDuktape_EventEmitter *e = ILibDuktape_EventEmitter_Create(ctx);	
	ILibDuktape_EventEmitter_CreateEventEx(e, "readset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "writeset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "errorset");
	duk_dup(ctx, 0);													// [obj][table][value][key][value][FD]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_FD);		// [obj][table][value][key][value]
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);

	duk_put_prop(ctx, -4);												// [obj][table][value]

	return(1);
}
duk_ret_t ILibDuktape_DescriptorEvents_Finalizer(duk_context *ctx)
{
	ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, 0, ILibDuktape_DescriptorEvents_ChainLink);
	void *chain = Duktape_GetChain(ctx);

	link->PreSelectHandler = NULL;
	link->PostSelectHandler = NULL;
	((void**)link->ExtraMemoryPtr)[0] = NULL;
	((void**)link->ExtraMemoryPtr)[1] = NULL;
	
	if (ILibIsChainBeingDestroyed(chain) == 0)
	{
		ILibChain_SafeRemove(chain, link);
	}

	return(0);
}
void ILibDuktape_DescriptorEvents_Push(duk_context *ctx, void *chain)
{
	ILibChain_Link *link = (ILibChain_Link*)ILibChain_Link_Allocate(sizeof(ILibChain_Link), 2 * sizeof(void*));
	link->MetaData = "ILibDuktape_DescriptorEvents";
	link->PreSelectHandler = ILibDuktape_DescriptorEvents_PreSelect;
	link->PostSelectHandler = ILibDuktape_DescriptorEvents_PostSelect;

	duk_push_object(ctx);
	duk_push_pointer(ctx, link); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_ChainLink);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Table);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DescriptorEvents_Finalizer);

	((void**)link->ExtraMemoryPtr)[0] = ctx;
	((void**)link->ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_CreateInstanceMethod(ctx, "addDescriptor", ILibDuktape_DescriptorEvents_Add, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeDescriptor", ILibDuktape_DescriptorEvents_Remove, 1);


	ILibAddToChain(chain, link);
}
duk_ret_t ILibDuktape_Polyfills_filehash(duk_context *ctx)
{
	char *hash = duk_push_fixed_buffer(ctx, UTIL_SHA384_HASHSIZE);
	duk_push_buffer_object(ctx, -1, 0, UTIL_SHA384_HASHSIZE, DUK_BUFOBJ_NODEJS_BUFFER);
	if (GenerateSHA384FileHash((char*)duk_require_string(ctx, 0), hash) == 0)
	{
		return(1);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Error generating FileHash "));
	}
}
void ILibDuktape_Polyfills_Init(duk_context *ctx)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "queue", ILibDuktape_Queue_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DynamicBuffer", ILibDuktape_DynamicBuffer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "stream", ILibDuktape_Stream_Init);
	ILibDuktape_ModSearch_AddHandler(ctx, "http-headers", ILibDuktape_httpHeaders_PUSH);

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "pkcs7", ILibDuktape_PKCS7_Push);
#endif

#ifndef MICROSTACK_NOTLS
	ILibDuktape_ModSearch_AddHandler(ctx, "bignum", ILibDuktape_bignum_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "dataGenerator", ILibDuktape_dataGenerator_Push);
#endif
	ILibDuktape_ModSearch_AddHandler(ctx, "ChainViewer", ILibDuktape_ChainViewer_Push);
	ILibDuktape_ModSearch_AddHandler(ctx, "DescriptorEvents", ILibDuktape_DescriptorEvents_Push);

	// Global Polyfills
	duk_push_global_object(ctx);													// [g]

	ILibDuktape_Polyfills_String(ctx);
	ILibDuktape_Polyfills_Buffer(ctx);
	ILibDuktape_Polyfills_Console(ctx);
	ILibDuktape_Polyfills_byte_ordering(ctx);
	ILibDuktape_Polyfills_timer(ctx);
	ILibDuktape_Polyfills_object(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModule", ILibDuktape_Polyfills_getJSModule, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugCrash", ILibDuktape_Polyfills_debugCrash, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugGC", ILibDuktape_Polyfills_debugGC, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_Polyfills_debug, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getSHA384FileHash", ILibDuktape_Polyfills_filehash, 1);
#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateInstanceMethod(ctx, "crc32c", ILibDuktape_Polyfills_crc32c, DUK_VARARGS);
#endif
	duk_pop(ctx);																	// ...

	ILibDuktape_Debugger_Init(ctx, 9091);
}

#ifdef __DOXY__
/*!
\brief String 
*/
class String
{
public:
	/*!
	\brief Finds a String within another String
	\param str \<String\> Substring to search for
	\return <Integer> Index of where the string was found. -1 if not found
	*/
	Integer indexOf(str);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param length <Integer> Number of characters to extract
	\return \<String\> extracted String
	*/
	String substr(startIndex, length);
	/*!
	\brief Extracts a String from a String.
	\param startIndex <Integer> Starting index to extract
	\param endIndex <Integer> Ending index to extract
	\return \<String\> extracted String
	*/
	String splice(startIndex, endIndex);
	/*!
	\brief Split String into substrings
	\param str \<String\> Delimiter to split on
	\return Array of Tokens
	*/
	Array<String> split(str);
	/*!
	\brief Determines if a String starts with the given substring
	\param str \<String\> substring 
	\return <boolean> True, if this String starts with the given substring
	*/
	boolean startsWith(str);
};
/*!
\brief Instances of the Buffer class are similar to arrays of integers but correspond to fixed-sized, raw memory allocations.
*/
class Buffer
{
public:
	/*!
	\brief Create a new Buffer instance of the specified number of bytes
	\param size <integer> 
	\return \<Buffer\> new Buffer instance
	*/
	Buffer(size);

	/*!
	\brief Returns the amount of memory allocated in  bytes
	*/
	integer length;
	/*!
	\brief Creates a new Buffer instance from an encoded String
	\param str \<String\> encoded String
	\param encoding \<String\> Encoding. Can be either 'base64' or 'hex'
	\return \<Buffer\> new Buffer instance
	*/
	static Buffer from(str, encoding);
	/*!
	\brief Decodes Buffer to a String
	\param encoding \<String\> Optional. Can be either 'base64' or 'hex'. If not specified, will just encode as an ANSI string
	\param start <integer> Optional. Starting offset. <b>Default:</b> 0
	\param end <integer> Optional. Ending offset (not inclusive) <b>Default:</b> buffer length
	\return \<String\> Encoded String
	*/
	String toString([encoding[, start[, end]]]);
	/*!
	\brief Returns a new Buffer that references the same memory as the original, but offset and cropped by the start and end indices.
	\param start <integer> Where the new Buffer will start. <b>Default:</b> 0
	\param end <integer> Where the new Buffer will end. (Not inclusive) <b>Default:</b> buffer length
	\return \<Buffer\> 
	*/
	Buffer slice([start[, end]]);
};
/*!
\brief Console
*/
class Console
{
public:
	/*!
	\brief Serializes the input parameters to the Console Display
	\param args <any>
	*/
	void log(...args);
};
/*!
\brief Global Timer Methods
*/
class Timers
{
public:
	/*!
	\brief Schedules the "immediate" execution of the callback after I/O events' callbacks. 
	\param callback <func> Function to call at the end of the event loop
	\param args <any> Optional arguments to pass when the callback is called
	\return Immediate for use with clearImmediate().
	*/
	Immediate setImmediate(callback[, ...args]);
	/*!
	\brief Schedules execution of a one-time callback after delay milliseconds. 
	\param callback <func> Function to call when the timeout elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearTimeout().
	*/
	Timeout setTimeout(callback, delay[, ...args]);
	/*!
	\brief Schedules repeated execution of callback every delay milliseconds.
	\param callback <func> Function to call when the timer elapses
	\param args <any> Optional arguments to pass when the callback is called
	\return Timeout for use with clearInterval().
	*/
	Timeout setInterval(callback, delay[, ...args]);

	/*!
	\brief Cancels a Timeout returned by setTimeout()
	\param timeout Timeout
	*/
	void clearTimeout(timeout);
	/*!
	\brief Cancels a Timeout returned by setInterval()
	\param interval Timeout
	*/
	void clearInterval(interval);
	/*!
	\brief Cancels an Immediate returned by setImmediate()
	\param immediate Immediate
	*/
	void clearImmediate(immediate);

	/*!
	\brief Scheduled Timer
	*/
	class Timeout
	{
	public:
	};
	/*!
	\implements Timeout
	\brief Scheduled Immediate
	*/
	class Immediate
	{
	public:
	};
};

/*!
\brief Global methods for byte ordering manipulation
*/
class BytesOrdering
{
public:
	/*!
	\brief Converts 2 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohs(buffer, offset);
	/*!
	\brief Converts 4 bytes from network order to host order
	\param buffer \<Buffer\> bytes to convert
	\param offset <integer> offset to start
	\return <integer> host order value
	*/
	static integer ntohl(buffer, offset);
	/*!
	\brief Writes 2 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htons(buffer, offset, val);
	/*!
	\brief Writes 4 bytes in network order
	\param buffer \<Buffer\> Buffer to write to
	\param offset <integer> offset to start writing
	\param val <integer> host order value to write
	*/
	static void htonl(buffer, offset, val);
};
#endif
