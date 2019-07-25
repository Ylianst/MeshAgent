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
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "console");	// [g][console]
	duk_get_prop_string(ctx, -1, "log");									// [g][console][log]
	duk_swap_top(ctx, -2);													// [g][log][this]
	duk_push_sprintf(ctx, "Reference Count => %s[%p]:%d\n", Duktape_GetStringPropertyValue(ctx, 0, ILibDuktape_OBJID, "UNKNOWN"), duk_require_heapptr(ctx, 0), ILibDuktape_GetReferenceCount(ctx, 0) - 1);
	duk_call_method(ctx, 1);
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
duk_ret_t ILibDuktape_bignum_cmp(duk_context *ctx)
{
	BIGNUM *r1, *r2;
	duk_push_this(ctx);
	r1 = (BIGNUM*)Duktape_GetPointerProperty(ctx, -1, "\xFF_BIGNUM");
	r2 = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	duk_push_int(ctx, BN_cmp(r2, r1));
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
	ILibDuktape_CreateInstanceMethod(ctx, "cmp", ILibDuktape_bignum_cmp, 1);

	duk_push_c_function(ctx, ILibDuktape_bignum_finalizer, 1); duk_set_finalizer(ctx, -2);
	duk_eval_string(ctx, "(function toNumber(){return(parseInt(this.toString()));})"); duk_put_prop_string(ctx, -2, "toNumber");
}
duk_ret_t ILibDuktape_bignum_random(duk_context *ctx)
{
	BIGNUM *r = (BIGNUM*)Duktape_GetPointerProperty(ctx, 0, "\xFF_BIGNUM");
	BIGNUM *rnd = BN_new();

	if (BN_rand_range(rnd, r) == 0) { return(ILibDuktape_Error(ctx, "Error Generating Random Number")); }
	ILibDuktape_bignum_addBigNumMethods(ctx, rnd);
	return(1);
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
	duk_push_c_function(ctx, ILibDuktape_bignum_random, DUK_VARARGS); duk_put_prop_string(ctx, -2, "random");
	
	char randRange[] = "exports.randomRange = function randomRange(low, high)\
						{\
							var result = exports.random(high.sub(low)).add(low);\
							return(result);\
						};";
	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, randRange, sizeof(randRange) - 1);
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
	duk_peval_string_noresult(ctx, "addModule('promise', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciByZWZUYWJsZSA9IHt9OwoKZnVuY3Rpb24gZXZlbnRfc3dpdGNoZXJfaGVscGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ2V2ZW50X3N3aXRjaGVyJzsKICAgIHRoaXMuZnVuYyA9IGZ1bmN0aW9uIGZ1bmMoKQogICAgewogICAgICAgIHZhciBhcmdzID0gW107CiAgICAgICAgZm9yKHZhciBpIGluIGFyZ3VtZW50cykKICAgICAgICB7CiAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbaV0pOwogICAgICAgIH0KICAgICAgICByZXR1cm4gKGZ1bmMudGFyZ2V0LmFwcGx5KGZ1bmMuZGVzaXJlZCwgYXJncykpOwogICAgfTsKICAgIHRoaXMuZnVuYy5kZXNpcmVkID0gZGVzaXJlZF9jYWxsZWU7CiAgICB0aGlzLmZ1bmMudGFyZ2V0ID0gdGFyZ2V0OwogICAgdGhpcy5mdW5jLnNlbGYgPSB0aGlzOwp9CmZ1bmN0aW9uIGV2ZW50X3N3aXRjaGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpCnsKICAgIHJldHVybiAobmV3IGV2ZW50X3N3aXRjaGVyX2hlbHBlcihkZXNpcmVkX2NhbGxlZSwgdGFyZ2V0KSk7Cn0KCmZ1bmN0aW9uIFByb21pc2UocHJvbWlzZUZ1bmMpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3Byb21pc2UnOwogICAgdGhpcy5wcm9taXNlID0gdGhpczsKICAgIHRoaXMuX2ludGVybmFsID0geyBfT2JqZWN0SUQ6ICdwcm9taXNlLmludGVybmFsJywgcHJvbWlzZTogdGhpcywgZnVuYzogcHJvbWlzZUZ1bmMsIGNvbXBsZXRlZDogZmFsc2UsIGVycm9yczogZmFsc2UsIGNvbXBsZXRlZEFyZ3M6IFtdIH07CiAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbCh0aGlzLl9pbnRlcm5hbCk7CiAgICB0aGlzLl9pbnRlcm5hbC5vbignbmV3TGlzdGVuZXInLCBmdW5jdGlvbiAoZXZlbnROYW1lLCBldmVudENhbGxiYWNrKQogICAgewogICAgICAgIC8vY29uc29sZS5sb2coJ25ld0xpc3RlbmVyJywgZXZlbnROYW1lLCAnZXJyb3JzLycgKyB0aGlzLmVycm9ycyArICcgY29tcGxldGVkLycgKyB0aGlzLmNvbXBsZXRlZCk7CiAgICAgICAgdmFyIHIgPSBudWxsOwoKICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZXNvbHZlZCcgJiYgIXRoaXMuZXJyb3JzICYmIHRoaXMuY29tcGxldGVkKQogICAgICAgIHsKICAgICAgICAgICAgciA9IGV2ZW50Q2FsbGJhY2suYXBwbHkodGhpcywgdGhpcy5jb21wbGV0ZWRBcmdzKTsKICAgICAgICAgICAgaWYociE9bnVsbCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5lbWl0X3JldHVyblZhbHVlKCdyZXNvbHZlZCcsIHIpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3JlamVjdGVkJyAmJiB0aGlzLmVycm9ycyAmJiB0aGlzLmNvbXBsZXRlZCkKICAgICAgICB7CiAgICAgICAgICAgIGV2ZW50Q2FsbGJhY2suYXBwbHkodGhpcywgdGhpcy5jb21wbGV0ZWRBcmdzKTsKICAgICAgICB9CiAgICAgICAgaWYgKGV2ZW50TmFtZSA9PSAnc2V0dGxlZCcgJiYgdGhpcy5jb21wbGV0ZWQpCiAgICAgICAgewogICAgICAgICAgICBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIFtdKTsKICAgICAgICB9CiAgICB9KTsKICAgIHRoaXMuX2ludGVybmFsLnJlc29sdmVyID0gZnVuY3Rpb24gX3Jlc29sdmVyKCkKICAgIHsKICAgICAgICBpZiAoX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZCkgeyByZXR1cm47IH0KICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuZXJyb3JzID0gZmFsc2U7CiAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZCA9IHRydWU7CiAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZEFyZ3MgPSBbXTsKICAgICAgICB2YXIgYXJncyA9IFsncmVzb2x2ZWQnXTsKICAgICAgICBpZiAodGhpcy5lbWl0X3JldHVyblZhbHVlICYmIHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSAhPSBudWxsKQogICAgICAgIHsKICAgICAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZEFyZ3MucHVzaCh0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykpOwogICAgICAgICAgICBhcmdzLnB1c2godGhpcy5lbWl0X3JldHVyblZhbHVlKCdyZXNvbHZlZCcpKTsKICAgICAgICB9CiAgICAgICAgZWxzZQogICAgICAgIHsKICAgICAgICAgICAgZm9yICh2YXIgYSBpbiBhcmd1bWVudHMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIF9yZXNvbHZlci5fc2VsZi5jb21wbGV0ZWRBcmdzLnB1c2goYXJndW1lbnRzW2FdKTsKICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbYV0pOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIF9yZXNvbHZlci5fc2VsZi5lbWl0LmFwcGx5KF9yZXNvbHZlci5fc2VsZiwgYXJncyk7CiAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmVtaXQoJ3NldHRsZWQnKTsKICAgIH07CiAgICB0aGlzLl9pbnRlcm5hbC5yZWplY3RvciA9IGZ1bmN0aW9uIF9yZWplY3RvcigpCiAgICB7CiAgICAgICAgaWYgKF9yZWplY3Rvci5fc2VsZi5jb21wbGV0ZWQpIHsgcmV0dXJuOyB9CiAgICAgICAgX3JlamVjdG9yLl9zZWxmLmVycm9ycyA9IHRydWU7CiAgICAgICAgX3JlamVjdG9yLl9zZWxmLmNvbXBsZXRlZCA9IHRydWU7CiAgICAgICAgX3JlamVjdG9yLl9zZWxmLmNvbXBsZXRlZEFyZ3MgPSBbXTsKICAgICAgICB2YXIgYXJncyA9IFsncmVqZWN0ZWQnXTsKICAgICAgICBmb3IgKHZhciBhIGluIGFyZ3VtZW50cykKICAgICAgICB7CiAgICAgICAgICAgIF9yZWplY3Rvci5fc2VsZi5jb21wbGV0ZWRBcmdzLnB1c2goYXJndW1lbnRzW2FdKTsKICAgICAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1thXSk7CiAgICAgICAgfQoKICAgICAgICBfcmVqZWN0b3IuX3NlbGYuZW1pdC5hcHBseShfcmVqZWN0b3IuX3NlbGYsIGFyZ3MpOwogICAgICAgIF9yZWplY3Rvci5fc2VsZi5lbWl0KCdzZXR0bGVkJyk7CiAgICB9OwogICAgdGhpcy5jYXRjaCA9IGZ1bmN0aW9uKGZ1bmMpCiAgICB7CiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCBmdW5jKS5mdW5jKTsKICAgIH0KICAgIHRoaXMuZmluYWxseSA9IGZ1bmN0aW9uIChmdW5jKQogICAgewogICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3NldHRsZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCBmdW5jKS5mdW5jKTsKICAgIH07CiAgICB0aGlzLnRoZW4gPSBmdW5jdGlvbiAocmVzb2x2ZWQsIHJlamVjdGVkKQogICAgewogICAgICAgIGlmIChyZXNvbHZlZCkgeyB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZXNvbHZlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIHJlc29sdmVkKS5mdW5jKTsgfQogICAgICAgIGlmIChyZWplY3RlZCkgeyB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZWplY3RlZCcsIGV2ZW50X3N3aXRjaGVyKHRoaXMsIHJlamVjdGVkKS5mdW5jKTsgfQoKICAgICAgICB2YXIgcmV0VmFsID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHIsIGopIHsgfSk7CiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyKTsKICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZWplY3RlZCcsIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IpOwogICAgICAgIHJldFZhbC5wYXJlbnRQcm9taXNlID0gdGhpczsKICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICB9OwoKICAgIHRoaXMuX2ludGVybmFsLnJlc29sdmVyLl9zZWxmID0gdGhpcy5faW50ZXJuYWw7CiAgICB0aGlzLl9pbnRlcm5hbC5yZWplY3Rvci5fc2VsZiA9IHRoaXMuX2ludGVybmFsOzsKCiAgICB0cnkKICAgIHsKICAgICAgICBwcm9taXNlRnVuYy5jYWxsKHRoaXMsIHRoaXMuX2ludGVybmFsLnJlc29sdmVyLCB0aGlzLl9pbnRlcm5hbC5yZWplY3Rvcik7CiAgICB9CiAgICBjYXRjaChlKQogICAgewogICAgICAgIHRoaXMuX2ludGVybmFsLmVycm9ycyA9IHRydWU7CiAgICAgICAgdGhpcy5faW50ZXJuYWwuY29tcGxldGVkID0gdHJ1ZTsKICAgICAgICB0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWRBcmdzID0gW2VdOwogICAgICAgIHRoaXMuX2ludGVybmFsLmVtaXQoJ3JlamVjdGVkJywgZSk7CiAgICAgICAgdGhpcy5faW50ZXJuYWwuZW1pdCgnc2V0dGxlZCcpOwogICAgfQoKICAgIGlmKCF0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWQpCiAgICB7CiAgICAgICAgLy8gU2F2ZSByZWZlcmVuY2Ugb2YgdGhpcyBvYmplY3QKICAgICAgICByZWZUYWJsZVt0aGlzLl9pbnRlcm5hbC5faGFzaENvZGUoKV0gPSB0aGlzLl9pbnRlcm5hbDsKICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZnVuY3Rpb24gKCkgeyByZWZUYWJsZVt0aGlzLl9oYXNoQ29kZSgpXSA9IG51bGw7IH0pOwogICAgfQp9CgpQcm9taXNlLnJlc29sdmUgPSBmdW5jdGlvbiByZXNvbHZlKCkKewogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOwogICAgdmFyIGFyZ3MgPSBbXTsKICAgIGZvciAodmFyIGkgaW4gYXJndW1lbnRzKQogICAgewogICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbaV0pOwogICAgfQogICAgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlci5hcHBseShyZXRWYWwuX2ludGVybmFsLCBhcmdzKTsKICAgIHJldHVybiAocmV0VmFsKTsKfTsKUHJvbWlzZS5yZWplY3QgPSBmdW5jdGlvbiByZWplY3QoKSB7CiAgICB2YXIgcmV0VmFsID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHIsIGopIHsgfSk7CiAgICB2YXIgYXJncyA9IFtdOwogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpIHsKICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2ldKTsKICAgIH0KICAgIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IuYXBwbHkocmV0VmFsLl9pbnRlcm5hbCwgYXJncyk7CiAgICByZXR1cm4gKHJldFZhbCk7Cn07ClByb21pc2UuYWxsID0gZnVuY3Rpb24gYWxsKHByb21pc2VMaXN0KQp7CiAgICB2YXIgcmV0ID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKQogICAgewogICAgICAgIHRoaXMuX19yZWplY3RvciA9IHJlajsKICAgICAgICB0aGlzLl9fcmVzb2x2ZXIgPSByZXM7CiAgICAgICAgdGhpcy5fX3Byb21pc2VMaXN0ID0gcHJvbWlzZUxpc3Q7CiAgICAgICAgdGhpcy5fX2RvbmUgPSBmYWxzZTsKICAgICAgICB0aGlzLl9fY291bnQgPSAwOwogICAgfSk7CgogICAgZm9yICh2YXIgaSBpbiBwcm9taXNlTGlzdCkKICAgIHsKICAgICAgICBwcm9taXNlTGlzdFtpXS50aGVuKGZ1bmN0aW9uICgpCiAgICAgICAgewogICAgICAgICAgICAvLyBTdWNjZXNzCiAgICAgICAgICAgIGlmKCsrcmV0Ll9fY291bnQgPT0gcmV0Ll9fcHJvbWlzZUxpc3QubGVuZ3RoKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICByZXQuX19kb25lID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHJldC5fX3Jlc29sdmVyKHJldC5fX3Byb21pc2VMaXN0KTsKICAgICAgICAgICAgfQogICAgICAgIH0sIGZ1bmN0aW9uIChhcmcpCiAgICAgICAgewogICAgICAgICAgICAvLyBGYWlsdXJlCiAgICAgICAgICAgIGlmKCFyZXQuX19kb25lKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICByZXQuX19kb25lID0gdHJ1ZTsKICAgICAgICAgICAgICAgIHJldC5fX3JlamVjdG9yKGFyZyk7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgIH0KICAgIGlmIChwcm9taXNlTGlzdC5sZW5ndGggPT0gMCkKICAgIHsKICAgICAgICByZXQuX19yZXNvbHZlcihwcm9taXNlTGlzdCk7CiAgICB9CiAgICByZXR1cm4gKHJldCk7Cn07Cgptb2R1bGUuZXhwb3J0cyA9IFByb21pc2U7Cm1vZHVsZS5leHBvcnRzLmV2ZW50X3N3aXRjaGVyID0gZXZlbnRfc3dpdGNoZXI7', 'base64').toString());");

#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addModule('win-registry', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBLRVlfUVVFUllfVkFMVUUgPSAweDAwMDE7CnZhciBLRVlfRU5VTUVSQVRFX1NVQl9LRVlTID0gMHgwMDA4Owp2YXIgS0VZX1dSSVRFID0gMHgyMDAwNjsKCnZhciBLRVlfREFUQV9UWVBFUyA9CiAgICB7CiAgICAgICAgUkVHX05PTkU6IDAsCiAgICAgICAgUkVHX1NaOiAxLAogICAgICAgIFJFR19FWFBBTkRfU1o6IDIsCiAgICAgICAgUkVHX0JJTkFSWTogMywKICAgICAgICBSRUdfRFdPUkQ6IDQsCiAgICAgICAgUkVHX0RXT1JEX0JJR19FTkRJQU46IDUsCiAgICAgICAgUkVHX0xJTks6IDYsCiAgICAgICAgUkVHX01VTFRJX1NaOiA3LAogICAgICAgIFJFR19SRVNPVVJDRV9MSVNUOiA4LAogICAgICAgIFJFR19GVUxMX1JFU09VUkNFX0RFU0NSSVBUT1I6IDksCiAgICAgICAgUkVHX1JFU09VUkNFX1JFUVVJUkVNRU5UU19MSVNUOiAxMCwKICAgICAgICBSRUdfUVdPUkQ6IDExCiAgICB9OwoKZnVuY3Rpb24gd2luZG93c19yZWdpc3RyeSgpCnsKICAgIHRoaXMuX09iamVjdElkID0gJ3dpbi1yZWdpc3RyeSc7CiAgICB0aGlzLl9tYXJzaGFsID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICB0aGlzLl9BZHZBcGkgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdBZHZhcGkzMi5kbGwnKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0NyZWF0ZUtleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnRW51bUtleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnRW51bVZhbHVlQScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnT3BlbktleUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnUXVlcnlJbmZvS2V5QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnUXVlcnlWYWx1ZUV4QScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnQ2xvc2VLZXknKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0RlbGV0ZUtleUEnKTsKICAgIHRoaXMuX0FkdkFwaS5DcmVhdGVNZXRob2QoJ1JlZ0RlbGV0ZVZhbHVlQScpOwogICAgdGhpcy5fQWR2QXBpLkNyZWF0ZU1ldGhvZCgnUmVnU2V0VmFsdWVFeEEnKTsKICAgIHRoaXMuSEtFWSA9IHsgUm9vdDogQnVmZmVyLmZyb20oJzgwMDAwMDAwJywgJ2hleCcpLnN3YXAzMigpLCBDdXJyZW50VXNlcjogQnVmZmVyLmZyb20oJzgwMDAwMDAxJywgJ2hleCcpLnN3YXAzMigpLCBMb2NhbE1hY2hpbmU6IEJ1ZmZlci5mcm9tKCc4MDAwMDAwMicsICdoZXgnKS5zd2FwMzIoKSwgVXNlcnM6IEJ1ZmZlci5mcm9tKCc4MDAwMDAwMycsICdoZXgnKS5zd2FwMzIoKSB9OwoKICAgIHRoaXMuUXVlcnlLZXkgPSBmdW5jdGlvbiBRdWVyeUtleShoa2V5LCBwYXRoLCBrZXkpCiAgICB7CiAgICAgICAgdmFyIGVycjsKICAgICAgICB2YXIgaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgIHZhciBsZW4gPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgIHZhciB2YWxUeXBlID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsKICAgICAgICB2YXIgSEsgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSk7CiAgICAgICAgdmFyIHJldFZhbCA9IG51bGw7CiAgICAgICAgaWYgKGtleSkgeyBrZXkgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSk7IH0KICAgICAgICBpZiAoIXBhdGgpIHsgcGF0aCA9ICcnOyB9CgoKICAgICAgICBpZiAoKGVyciA9IHRoaXMuX0FkdkFwaS5SZWdPcGVuS2V5RXhBKEhLLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKHBhdGgpLCAwLCBLRVlfUVVFUllfVkFMVUUgfCBLRVlfRU5VTUVSQVRFX1NVQl9LRVlTLCBoKS5WYWwpICE9IDApCiAgICAgICAgewogICAgICAgICAgICB0aHJvdyAoJ09wZW5pbmcgUmVnaXN0cnkgS2V5OiAnICsgcGF0aCArICcgPT4gUmV0dXJuZWQgRXJyb3I6ICcgKyBlcnIpOwogICAgICAgIH0KICAKICAgICAgICBpZiAoKHBhdGggPT0gJycgJiYgIWtleSkgfHwgIWtleSkKICAgICAgICB7DQogICAgICAgICAgICB2YXIgcmVzdWx0ID0geyBzdWJrZXlzOiBbXSwgdmFsdWVzOiBbXSB9Ow0KDQogICAgICAgICAgICAvLyBFbnVtZXJhdGUgIGtleXMNCiAgICAgICAgICAgIHZhciBhY2hDbGFzcyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoMTAyNCk7DQogICAgICAgICAgICB2YXIgYWNoS2V5ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSgxMDI0KTsNCiAgICAgICAgICAgIHZhciBhY2hWYWx1ZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoMzI3NjgpOw0KICAgICAgICAgICAgdmFyIGFjaFZhbHVlU2l6ZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbmFtZVNpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOyANCiAgICAgICAgICAgIHZhciBhY2hDbGFzc1NpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOyBhY2hDbGFzc1NpemUudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEwMjQpOw0KICAgICAgICAgICAgdmFyIG51bVN1YktleXMgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOw0KICAgICAgICAgICAgdmFyIG51bVZhbHVlcyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFN1YmtleVNpemUgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOw0KICAgICAgICAgICAgdmFyIGxvbmdlc3RDbGFzc1N0cmluZyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFZhbHVlTmFtZSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgbG9uZ2VzdFZhbHVlRGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7DQogICAgICAgICAgICB2YXIgc2VjdXJpdHlEZXNjcmlwdG9yID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsNCiAgICAgICAgICAgIHZhciBsYXN0V3JpdGVUaW1lID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg4KTsNCg0KICAgICAgICAgICAgcmV0VmFsID0gdGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5SW5mb0tleUEoaC5EZXJlZigpLCBhY2hDbGFzcywgYWNoQ2xhc3NTaXplLCAwLA0KICAgICAgICAgICAgICAgIG51bVN1YktleXMsIGxvbmdlc3RTdWJrZXlTaXplLCBsb25nZXN0Q2xhc3NTdHJpbmcsIG51bVZhbHVlcywNCiAgICAgICAgICAgICAgICBsb25nZXN0VmFsdWVOYW1lLCBsb25nZXN0VmFsdWVEYXRhLCBzZWN1cml0eURlc2NyaXB0b3IsIGxhc3RXcml0ZVRpbWUpOw0KICAgICAgICAgICAgaWYgKHJldFZhbC5WYWwgIT0gMCkgeyB0aHJvdyAoJ1JlZ1F1ZXJ5SW5mb0tleUEoKSByZXR1cm5lZCBlcnJvcjogJyArIHJldFZhbC5WYWwpOyB9DQogICAgICAgICAgICBmb3IodmFyIGkgPSAwOyBpIDwgbnVtU3ViS2V5cy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpOyArK2kpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgbmFtZVNpemUudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEwMjQpOw0KICAgICAgICAgICAgICAgIHJldFZhbCA9IHRoaXMuX0FkdkFwaS5SZWdFbnVtS2V5RXhBKGguRGVyZWYoKSwgaSwgYWNoS2V5LCBuYW1lU2l6ZSwgMCwgMCwgMCwgbGFzdFdyaXRlVGltZSk7DQogICAgICAgICAgICAgICAgaWYocmV0VmFsLlZhbCA9PSAwKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnN1YmtleXMucHVzaChhY2hLZXkuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IG51bVZhbHVlcy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpIDsgKytpKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGFjaFZhbHVlU2l6ZS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzI3NjgpOw0KICAgICAgICAgICAgICAgIGlmKHRoaXMuX0FkdkFwaS5SZWdFbnVtVmFsdWVBKGguRGVyZWYoKSwgaSwgYWNoVmFsdWUsIGFjaFZhbHVlU2l6ZSwgMCwgMCwgMCwgMCkuVmFsID09IDApDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXN1bHQudmFsdWVzLnB1c2goYWNoVmFsdWUuU3RyaW5nKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICByZXR1cm4gKHJlc3VsdCk7DQogICAgICAgIH0KCiAgICAgICAgaWYodGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5VmFsdWVFeEEoaC5EZXJlZigpLCBrZXksIDAsIDAsIDAsIGxlbikuVmFsID09IDApCiAgICAgICAgewogICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUobGVuLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpOwogICAgICAgICAgICBpZiAodGhpcy5fQWR2QXBpLlJlZ1F1ZXJ5VmFsdWVFeEEoaC5EZXJlZigpLCBrZXksIDAsIHZhbFR5cGUsIGRhdGEsIGxlbikuVmFsID09IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHN3aXRjaCh2YWxUeXBlLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBLRVlfREFUQV9UWVBFUy5SRUdfRFdPUkQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbCA9IGRhdGEudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKTsKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBLRVlfREFUQV9UWVBFUy5SRUdfRFdPUkRfQklHX0VORElBTjoKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsID0gZGF0YS50b0J1ZmZlcigpLnJlYWRVSW50MzJCRSgpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBjYXNlIEtFWV9EQVRBX1RZUEVTLlJFR19TWjoKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsID0gZGF0YS5TdHJpbmc7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgS0VZX0RBVEFfVFlQRVMuUkVHX0JJTkFSWToKICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwgPSBkYXRhLnRvQnVmZmVyKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5fZGF0YSA9IGRhdGE7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuX0FkdkFwaS5SZWdDbG9zZUtleShoLkRlcmVmKCkpOwogICAgICAgICAgICB0aHJvdyAoJ05vdCBGb3VuZCcpOwogICAgICAgIH0KICAgICAgICB0aGlzLl9BZHZBcGkuUmVnQ2xvc2VLZXkoaC5EZXJlZigpKTsKICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICB9OwogICAgdGhpcy5Xcml0ZUtleSA9IGZ1bmN0aW9uIFdyaXRlS2V5KGhrZXksIHBhdGgsIGtleSwgdmFsdWUpCiAgICB7CiAgICAgICAgdmFyIHJlc3VsdDsKICAgICAgICB2YXIgaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwoKICAgICAgICBpZiAodGhpcy5fQWR2QXBpLlJlZ0NyZWF0ZUtleUV4QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCksIDAsIDAsIDAsIEtFWV9XUklURSwgMCwgaCwgMCkuVmFsICE9IDApCiAgICAgICAgewogICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIE9wZW5pbmcgUmVnaXN0cnkgS2V5OiAnICsgcGF0aCk7CiAgICAgICAgfQoKICAgICAgICB2YXIgZGF0YTsKICAgICAgICB2YXIgZGF0YVR5cGU7CgogICAgICAgIHN3aXRjaCh0eXBlb2YodmFsdWUpKQogICAgICAgIHsKICAgICAgICAgICAgY2FzZSAnYm9vbGVhbic6CiAgICAgICAgICAgICAgICBkYXRhVHlwZSA9IEtFWV9EQVRBX1RZUEVTLlJFR19EV09SRDsKICAgICAgICAgICAgICAgIGRhdGEgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgICAgICAgICAgZGF0YS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUodmFsdWUgPyAxIDogMCk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnbnVtYmVyJzoKICAgICAgICAgICAgICAgIGRhdGFUeXBlID0gS0VZX0RBVEFfVFlQRVMuUkVHX0RXT1JEOwogICAgICAgICAgICAgICAgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNCk7CiAgICAgICAgICAgICAgICBkYXRhLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSh2YWx1ZSk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnc3RyaW5nJzoKICAgICAgICAgICAgICAgIGRhdGFUeXBlID0gS0VZX0RBVEFfVFlQRVMuUkVHX1NaOwogICAgICAgICAgICAgICAgZGF0YSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUodmFsdWUpOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICBkYXRhVHlwZSA9IEtFWV9EQVRBX1RZUEVTLlJFR19CSU5BUlk7CiAgICAgICAgICAgICAgICBkYXRhID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSh2YWx1ZS5sZW5ndGgpOwogICAgICAgICAgICAgICAgdmFsdWUuY29weShkYXRhLnRvQnVmZmVyKCkpOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQoKICAgICAgICBpZih0aGlzLl9BZHZBcGkuUmVnU2V0VmFsdWVFeEEoaC5EZXJlZigpLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSksIDAsIGRhdGFUeXBlLCBkYXRhLCBkYXRhLl9zaXplKS5WYWwgIT0gMCkKICAgICAgICB7ICAgICAgICAgICAKICAgICAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICAgICAgICAgIHRocm93ICgnRXJyb3Igd3JpdGluZyByZWcga2V5OiAnICsga2V5KTsKICAgICAgICB9CiAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICB9OwogICAgdGhpcy5EZWxldGVLZXkgPSBmdW5jdGlvbiBEZWxldGVLZXkoaGtleSwgcGF0aCwga2V5KQogICAgewogICAgICAgIGlmKCFrZXkpCiAgICAgICAgewogICAgICAgICAgICBpZih0aGlzLl9BZHZBcGkuUmVnRGVsZXRlS2V5QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCkpLlZhbCAhPSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIERlbGV0aW5nIEtleTogJyArIHBhdGgpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHZhciBoID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciByZXN1bHQ7CiAgICAgICAgICAgIGlmICh0aGlzLl9BZHZBcGkuUmVnT3BlbktleUV4QSh0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoaGtleSksIHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUocGF0aCksIDAsIEtFWV9RVUVSWV9WQUxVRSB8IEtFWV9XUklURSwgaCkuVmFsICE9IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRocm93ICgnRXJyb3IgT3BlbmluZyBSZWdpc3RyeSBLZXk6ICcgKyBwYXRoKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoKHJlc3VsdCA9IHRoaXMuX0FkdkFwaS5SZWdEZWxldGVWYWx1ZUEoaC5EZXJlZigpLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGtleSkpLlZhbCkgIT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5fQWR2QXBpLlJlZ0Nsb3NlS2V5KGguRGVyZWYoKSk7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yWycgKyByZXN1bHQgKyAnXSBEZWxldGluZyBLZXk6ICcgKyBwYXRoICsgJy4nICsga2V5KTsKICAgICAgICAgICAgfQogICAgICAgICAgICB0aGlzLl9BZHZBcGkuUmVnQ2xvc2VLZXkoaC5EZXJlZigpKTsKICAgICAgICB9CiAgICB9Owp9Cgptb2R1bGUuZXhwb3J0cyA9IG5ldyB3aW5kb3dzX3JlZ2lzdHJ5KCk7Cgo=', 'base64').toString());");
	
	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addModule('PE_Parser', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCi8vIFJldHVybiBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIGV4ZWN1dGFibGUKZnVuY3Rpb24gcGFyc2UoZXhlUGF0aCkKewogICAgdmFyIHJldFZhbCA9IHt9OwogICAgdmFyIGZzID0gcmVxdWlyZSgnZnMnKTsKICAgIHZhciBmZCA9IGZzLm9wZW5TeW5jKGV4ZVBhdGgsICdyYicpOwogICAgdmFyIGJ5dGVzUmVhZDsKICAgIHZhciBkb3NIZWFkZXIgPSBCdWZmZXIuYWxsb2MoNjQpOwogICAgdmFyIG50SGVhZGVyID0gQnVmZmVyLmFsbG9jKDI0KTsKICAgIHZhciBvcHRIZWFkZXI7CgogICAgLy8gUmVhZCB0aGUgRE9TIGhlYWRlcgogICAgYnl0ZXNSZWFkID0gZnMucmVhZFN5bmMoZmQsIGRvc0hlYWRlciwgMCwgNjQsIDApOwogICAgaWYgKGRvc0hlYWRlci5yZWFkVUludDE2TEUoMCkudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkgIT0gJzVBNEQnKQogICAgewogICAgICAgIHRocm93ICgndW5yZWNvZ25pemVkIGJpbmFyeSBmb3JtYXQnKTsKICAgIH0KCiAgICAvLyBSZWFkIHRoZSBOVCBoZWFkZXIKICAgIGJ5dGVzUmVhZCA9IGZzLnJlYWRTeW5jKGZkLCBudEhlYWRlciwgMCwgbnRIZWFkZXIubGVuZ3RoLCBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSk7CiAgICBpZiAobnRIZWFkZXIuc2xpY2UoMCwgNCkudG9TdHJpbmcoJ2hleCcpICE9ICc1MDQ1MDAwMCcpCiAgICB7CiAgICAgICAgdGhyb3cgKCdub3QgYSBQRSBmaWxlJyk7CiAgICB9CiAgICBzd2l0Y2ggKG50SGVhZGVyLnJlYWRVSW50MTZMRSg0KS50b1N0cmluZygxNikpCiAgICB7CiAgICAgICAgY2FzZSAnMTRjJzogLy8gMzIgYml0CiAgICAgICAgICAgIHJldFZhbC5mb3JtYXQgPSAneDg2JzsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAnODY2NCc6IC8vIDY0IGJpdAogICAgICAgICAgICByZXRWYWwuZm9ybWF0ID0gJ3g2NCc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGRlZmF1bHQ6IC8vIFVua25vd24KICAgICAgICAgICAgcmV0VmFsLmZvcm1hdCA9IHVuZGVmaW5lZDsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CgogICAgcmV0VmFsLm9wdGlvbmFsSGVhZGVyU2l6ZSA9IG50SGVhZGVyLnJlYWRVSW50MTZMRSgyMCk7CiAgICByZXRWYWwub3B0aW9uYWxIZWFkZXJTaXplQWRkcmVzcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjA7CgogICAgLy8gUmVhZCB0aGUgb3B0aW9uYWwgaGVhZGVyCiAgICBvcHRIZWFkZXIgPSBCdWZmZXIuYWxsb2MobnRIZWFkZXIucmVhZFVJbnQxNkxFKDIwKSk7CiAgICBieXRlc1JlYWQgPSBmcy5yZWFkU3luYyhmZCwgb3B0SGVhZGVyLCAwLCBvcHRIZWFkZXIubGVuZ3RoLCBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSArIDI0KTsKICAgIHZhciBudW1SVkEgPSB1bmRlZmluZWQ7CgogICAgcmV0VmFsLkNoZWNrU3VtUG9zID0gZG9zSGVhZGVyLnJlYWRVSW50MzJMRSg2MCkgKyAyNCArIDY0OwogICAgcmV0VmFsLlNpemVPZkNvZGUgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDQpOwogICAgcmV0VmFsLlNpemVPZkluaXRpYWxpemVkRGF0YSA9IG9wdEhlYWRlci5yZWFkVUludDMyTEUoOCk7CiAgICByZXRWYWwuU2l6ZU9mVW5Jbml0aWFsaXplZERhdGEgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDEyKTsKCiAgICBzd2l0Y2ggKG9wdEhlYWRlci5yZWFkVUludDE2TEUoMCkudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkpCiAgICB7CiAgICAgICAgY2FzZSAnMTBCJzogLy8gMzIgYml0IGJpbmFyeQogICAgICAgICAgICBudW1SVkEgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDkyKTsKICAgICAgICAgICAgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzID0gb3B0SGVhZGVyLnJlYWRVSW50MzJMRSgxMjgpOwogICAgICAgICAgICByZXRWYWwuQ2VydGlmaWNhdGVUYWJsZVNpemUgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDEzMik7CiAgICAgICAgICAgIHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlU2l6ZVBvcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjQgKyAxMzI7CiAgICAgICAgICAgIHJldFZhbC5ydmFTdGFydEFkZHJlc3MgPSBkb3NIZWFkZXIucmVhZFVJbnQzMkxFKDYwKSArIDI0ICsgOTY7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgJzIwQic6IC8vIDY0IGJpdCBiaW5hcnkKICAgICAgICAgICAgbnVtUlZBID0gb3B0SGVhZGVyLnJlYWRVSW50MzJMRSgxMDgpOwogICAgICAgICAgICByZXRWYWwuQ2VydGlmaWNhdGVUYWJsZUFkZHJlc3MgPSBvcHRIZWFkZXIucmVhZFVJbnQzMkxFKDE0NCk7CiAgICAgICAgICAgIHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlU2l6ZSA9IG9wdEhlYWRlci5yZWFkVUludDMyTEUoMTQ4KTsKICAgICAgICAgICAgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVTaXplUG9zID0gZG9zSGVhZGVyLnJlYWRVSW50MzJMRSg2MCkgKyAyNCArIDE0ODsKICAgICAgICAgICAgcmV0VmFsLnJ2YVN0YXJ0QWRkcmVzcyA9IGRvc0hlYWRlci5yZWFkVUludDMyTEUoNjApICsgMjQgKyAxMTI7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgIHRocm93ICgnVW5rbm93biBWYWx1ZSBmb3VuZCBmb3IgT3B0aW9uYWwgTWFnaWM6ICcgKyBudEhlYWRlci5yZWFkVUludDE2TEUoMjQpLnRvU3RyaW5nKDE2KS50b1VwcGVyQ2FzZSgpKTsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CiAgICByZXRWYWwucnZhQ291bnQgPSBudW1SVkE7CgogICAgaWYgKHJldFZhbC5DZXJ0aWZpY2F0ZVRhYmxlQWRkcmVzcykKICAgIHsKICAgICAgICAvLyBSZWFkIHRoZSBhdXRoZW50aWNvZGUgY2VydGlmaWNhdGUsIG9ubHkgb25lIGNlcnQgKG9ubHkgdGhlIGZpcnN0IGVudHJ5KQogICAgICAgIHZhciBoZHIgPSBCdWZmZXIuYWxsb2MoOCk7CiAgICAgICAgZnMucmVhZFN5bmMoZmQsIGhkciwgMCwgaGRyLmxlbmd0aCwgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzKTsKICAgICAgICByZXRWYWwuY2VydGlmaWNhdGUgPSBCdWZmZXIuYWxsb2MoaGRyLnJlYWRVSW50MzJMRSgwKSk7CiAgICAgICAgZnMucmVhZFN5bmMoZmQsIHJldFZhbC5jZXJ0aWZpY2F0ZSwgMCwgcmV0VmFsLmNlcnRpZmljYXRlLmxlbmd0aCwgcmV0VmFsLkNlcnRpZmljYXRlVGFibGVBZGRyZXNzICsgaGRyLmxlbmd0aCk7CiAgICAgICAgcmV0VmFsLmNlcnRpZmljYXRlID0gcmV0VmFsLmNlcnRpZmljYXRlLnRvU3RyaW5nKCdiYXNlNjQnKTsKICAgICAgICByZXRWYWwuY2VydGlmaWNhdGVEd0xlbmd0aCA9IGhkci5yZWFkVUludDMyTEUoMCk7CiAgICB9CiAgICBmcy5jbG9zZVN5bmMoZmQpOwogICAgcmV0dXJuIChyZXRWYWwpOwp9Cgptb2R1bGUuZXhwb3J0cyA9IHBhcnNlOwoKCv==', 'base64').toString());");

	// Windows Message Pump, refer to modules/win-message-pump.js
	duk_peval_string_noresult(ctx, "addModule('win-message-pump', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgV0hfQ0FMTFdORFBST0MgPSA0Ow0KdmFyIFdNX1FVSVQgPSAgMHgwMDEyOw0KDQp2YXIgR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsNCg0KZnVuY3Rpb24gV2luZG93c01lc3NhZ2VQdW1wKG9wdGlvbnMpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAnd2luLW1lc3NhZ2UtcHVtcCc7DQogICAgdGhpcy5fb3B0aW9ucyA9IG9wdGlvbnM7DQogICAgdmFyIGVtaXR0ZXJVdGlscyA9IHJlcXVpcmUoJ2V2ZW50cycpLmluaGVyaXRzKHRoaXMpOw0KICAgIGVtaXR0ZXJVdGlscy5jcmVhdGVFdmVudCgnaHduZCcpOw0KICAgIGVtaXR0ZXJVdGlscy5jcmVhdGVFdmVudCgnZXJyb3InKTsNCiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ21lc3NhZ2UnKTsNCiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ2V4aXQnKTsNCg0KICAgIHRoaXMuX21zZyA9IEdNLkNyZWF0ZVZhcmlhYmxlKEdNLlBvaW50ZXJTaXplID09IDQgPyAyOCA6IDQ4KTsNCiAgICB0aGlzLl9rZXJuZWwzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdLZXJuZWwzMi5kbGwnKTsNCiAgICB0aGlzLl9rZXJuZWwzMi5tcCA9IHRoaXM7DQogICAgdGhpcy5fa2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdHZXRMYXN0RXJyb3InKTsNCiAgICB0aGlzLl9rZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldE1vZHVsZUhhbmRsZUEnKTsNCg0KICAgIHRoaXMuX3VzZXIzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdVc2VyMzIuZGxsJyk7DQogICAgdGhpcy5fdXNlcjMyLm1wID0gdGhpczsNCiAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKCdHZXRNZXNzYWdlQScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ0NyZWF0ZVdpbmRvd0V4QScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ1RyYW5zbGF0ZU1lc3NhZ2UnKTsNCiAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKCdEaXNwYXRjaE1lc3NhZ2VBJyk7DQogICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnUmVnaXN0ZXJDbGFzc0V4QScpOw0KICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ0RlZldpbmRvd1Byb2NBJyk7DQogICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnUG9zdE1lc3NhZ2VBJyk7DQoNCg0KICAgIHRoaXMud25kY2xhc3MgPSBHTS5DcmVhdGVWYXJpYWJsZShHTS5Qb2ludGVyU2l6ZSA9PSA0ID8gNDggOiA4MCk7DQogICAgdGhpcy53bmRjbGFzcy5tcCA9IHRoaXM7DQogICAgdGhpcy53bmRjbGFzcy5oaW5zdGFuY2UgPSB0aGlzLl9rZXJuZWwzMi5HZXRNb2R1bGVIYW5kbGVBKDApOw0KICAgIHRoaXMud25kY2xhc3MuY25hbWUgPSBHTS5DcmVhdGVWYXJpYWJsZSgnTWFpbldXV0NsYXNzJyk7DQogICAgdGhpcy53bmRjbGFzcy53bmRwcm9jID0gR00uR2V0R2VuZXJpY0dsb2JhbENhbGxiYWNrKDQpOw0KICAgIHRoaXMud25kY2xhc3Mud25kcHJvYy5tcCA9IHRoaXM7DQogICAgdGhpcy53bmRjbGFzcy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUodGhpcy53bmRjbGFzcy5fc2l6ZSk7DQogICAgdGhpcy53bmRjbGFzcy5jbmFtZS5wb2ludGVyQnVmZmVyKCkuY29weSh0aGlzLnduZGNsYXNzLkRlcmVmKEdNLlBvaW50ZXJTaXplID09IDQgPyA0MCA6IDY0LCBHTS5Qb2ludGVyU2l6ZSkudG9CdWZmZXIoKSk7DQogICAgdGhpcy53bmRjbGFzcy53bmRwcm9jLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHRoaXMud25kY2xhc3MuRGVyZWYoOCwgR00uUG9pbnRlclNpemUpLnRvQnVmZmVyKCkpOw0KICAgIHRoaXMud25kY2xhc3MuaGluc3RhbmNlLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHRoaXMud25kY2xhc3MuRGVyZWYoR00uUG9pbnRlclNpemUgPT0gNCA/IDIwIDogMjQsIEdNLlBvaW50ZXJTaXplKS50b0J1ZmZlcigpKTsNCiAgICB0aGlzLnduZGNsYXNzLnduZHByb2Mub24oJ0dsb2JhbENhbGxiYWNrJywgZnVuY3Rpb24gb25XbmRQcm9jKHhod25kLCB4bXNnLCB3cGFyYW0sIGxwYXJhbSkNCiAgICB7DQogICAgICAgIGlmICh0aGlzLm1wLl9od25kICE9IG51bGwgJiYgdGhpcy5tcC5faHduZC5WYWwgPT0geGh3bmQuVmFsKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBUaGlzIGlzIGZvciB1cw0KICAgICAgICAgICAgdGhpcy5tcC5lbWl0KCdtZXNzYWdlJywgeyBtZXNzYWdlOiB4bXNnLlZhbCwgd3BhcmFtOiB3cGFyYW0uVmFsLCBscGFyYW06IGxwYXJhbS5WYWwsIGxwYXJhbV9oZXg6IGxwYXJhbS5wb2ludGVyQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpIH0pOw0KICAgICAgICAgICAgcmV0dXJuICh0aGlzLm1wLl91c2VyMzIuRGVmV2luZG93UHJvY0EoeGh3bmQsIHhtc2csIHdwYXJhbSwgbHBhcmFtKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZSBpZih0aGlzLm1wLl9od25kID09IG51bGwgJiYgdGhpcy5DYWxsaW5nVGhyZWFkKCkgPT0gdGhpcy5tcC5fdXNlcjMyLlJlZ2lzdGVyQ2xhc3NFeEEuYXN5bmMudGhyZWFkSWQoKSkNCiAgICAgICAgew0KICAgICAgICAgICAgLy8gVGhpcyBtZXNzYWdlIHdhcyBnZW5lcmF0ZWQgZnJvbSBvdXIgQ3JlYXRlV2luZG93RXhBIG1ldGhvZA0KICAgICAgICAgICAgcmV0dXJuICh0aGlzLm1wLl91c2VyMzIuRGVmV2luZG93UHJvY0EoeGh3bmQsIHhtc2csIHdwYXJhbSwgbHBhcmFtKSk7DQogICAgICAgIH0NCiAgICB9KTsNCg0KICAgIHRoaXMuX3VzZXIzMi5SZWdpc3RlckNsYXNzRXhBLmFzeW5jKHRoaXMud25kY2xhc3MpLnRoZW4oZnVuY3Rpb24gKCkNCiAgICB7DQogICAgICAgIHRoaXMubmF0aXZlUHJveHkuQ3JlYXRlV2luZG93RXhBLmFzeW5jKHRoaXMubmF0aXZlUHJveHkuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgMHgwMDAwMDA4OCwgdGhpcy5uYXRpdmVQcm94eS5tcC53bmRjbGFzcy5jbmFtZSwgMCwgMHgwMDgwMDAwMCwgMCwgMCwgMTAwLCAxMDAsIDAsIDAsIDAsIDApDQogICAgICAgICAgICAudGhlbihmdW5jdGlvbihoKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGlmIChoLlZhbCA9PSAwKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgLy8gRXJyb3IgY3JlYXRpbmcgaGlkZGVuIHdpbmRvdw0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5Lm1wLmVtaXQoJ2Vycm9yJywgJ0Vycm9yIGNyZWF0aW5nIGhpZGRlbiB3aW5kb3cnKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5faHduZCA9IGg7DQogICAgICAgICAgICAgICAgICAgIHRoaXMubmF0aXZlUHJveHkubXAuZW1pdCgnaHduZCcsIGgpOw0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5Lm1wLl9zdGFydFB1bXAoKTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9KTsNCiAgICB9KTsNCiAgICB0aGlzLl9zdGFydFB1bXAgPSBmdW5jdGlvbiBfc3RhcnRQdW1wKCkNCiAgICB7DQogICAgICAgIHRoaXMuX3VzZXIzMi5HZXRNZXNzYWdlQS5hc3luYyh0aGlzLl91c2VyMzIuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgdGhpcy5fbXNnLCB0aGlzLl9od25kLCAwLCAwKS50aGVuKGZ1bmN0aW9uIChyKQ0KICAgICAgICB7DQogICAgICAgICAgICBpZihyLlZhbCA+IDApDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5UcmFuc2xhdGVNZXNzYWdlLmFzeW5jKHRoaXMubmF0aXZlUHJveHkuUmVnaXN0ZXJDbGFzc0V4QS5hc3luYywgdGhpcy5uYXRpdmVQcm94eS5tcC5fbXNnKS50aGVuKGZ1bmN0aW9uICgpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLm5hdGl2ZVByb3h5LkRpc3BhdGNoTWVzc2FnZUEuYXN5bmModGhpcy5uYXRpdmVQcm94eS5SZWdpc3RlckNsYXNzRXhBLmFzeW5jLCB0aGlzLm5hdGl2ZVByb3h5Lm1wLl9tc2cpLnRoZW4oZnVuY3Rpb24gKCkNCiAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5fc3RhcnRQdW1wKCk7DQogICAgICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgICAgIH0pOw0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgZWxzZQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIC8vIFdlIGdvdCBhICdRVUlUJyBtZXNzYWdlDQogICAgICAgICAgICAgICAgZGVsZXRlIHRoaXMubmF0aXZlUHJveHkubXAuX2h3bmQ7DQogICAgICAgICAgICAgICAgdGhpcy5uYXRpdmVQcm94eS5tcC5lbWl0KCdleGl0JywgMCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0sIGZ1bmN0aW9uIChlcnIpIHsgdGhpcy5uYXRpdmVQcm94eS5tcC5zdG9wKCk7IH0pOw0KICAgIH0NCg0KICAgIHRoaXMuc3RvcCA9IGZ1bmN0aW9uIHN0b3AoKQ0KICAgIHsNCiAgICAgICAgaWYgKHRoaXMuX2h3bmQpDQogICAgICAgIHsNCiAgICAgICAgICAgIHRoaXMuX3VzZXIzMi5Qb3N0TWVzc2FnZUEodGhpcy5faHduZCwgV01fUVVJVCwgMCwgMCk7DQogICAgICAgIH0NCiAgICB9Ow0KfQ0KDQptb2R1bGUuZXhwb3J0cyA9IFdpbmRvd3NNZXNzYWdlUHVtcDsNCv==', 'base64').toString());");
	duk_peval_string_noresult(ctx, "addModule('win-console', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBUcmF5SWNvbkZsYWdzID0KICAgIHsKICAgICAgICBOSUZfTUVTU0FHRTogMHgwMDAwMDAwMSwKICAgICAgICBOSUZfSUNPTjogMHgwMDAwMDAwMiwKICAgICAgICBOSUZfVElQOiAweDAwMDAwMDA0LAogICAgICAgIE5JRl9TVEFURTogMHgwMDAwMDAwOCwKICAgICAgICBOSUZfSU5GTzogMHgwMDAwMDAxMCwKICAgICAgICBOSUZfR1VJRDogMHgwMDAwMDAyMCwKICAgICAgICBOSUZfUkVBTFRJTUU6IDB4MDAwMDAwNDAsCiAgICAgICAgTklGX1NIT1dUSVA6IDB4MDAwMDAwODAsCgogICAgICAgIE5JTV9BREQ6IDB4MDAwMDAwMDAsCiAgICAgICAgTklNX01PRElGWTogMHgwMDAwMDAwMSwKICAgICAgICBOSU1fREVMRVRFOiAweDAwMDAwMDAyLAogICAgICAgIE5JTV9TRVRGT0NVUzogMHgwMDAwMDAwMywKICAgICAgICBOSU1fU0VUVkVSU0lPTjogMHgwMDAwMDAwNAogICAgfTsKdmFyIE5PVElGWUlDT05fVkVSU0lPTl80ID0gNDsKdmFyIE1lc3NhZ2VUeXBlcyA9IHsgV01fQVBQOiAweDgwMDAsIFdNX1VTRVI6IDB4MDQwMCB9OwpmdW5jdGlvbiBXaW5kb3dzQ29uc29sZSgpCnsKICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICd3aW4zMicpCiAgICB7CiAgICAgICAgdGhpcy5fT2JqZWN0SUQgPSAnd2luLWNvbnNvbGUnOwogICAgICAgIHRoaXMuX01hcnNoYWwgPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKICAgICAgICB0aGlzLl9rZXJuZWwzMiA9IHRoaXMuX01hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoImtlcm5lbDMyLmRsbCIpOwogICAgICAgIHRoaXMuX3VzZXIzMiA9IHRoaXMuX01hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoInVzZXIzMi5kbGwiKTsKICAgICAgICB0aGlzLl9rZXJuZWwzMi5DcmVhdGVNZXRob2QoIkdldENvbnNvbGVXaW5kb3ciKTsKICAgICAgICB0aGlzLl9rZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldEN1cnJlbnRUaHJlYWQnKTsKICAgICAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKCJTaG93V2luZG93Iik7CiAgICAgICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgiTG9hZEltYWdlQSIpOwogICAgICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoeyBtZXRob2Q6ICdHZXRNZXNzYWdlQScsIHRocmVhZERpc3BhdGNoOiAxIH0pOwogICAgICAgIHRoaXMuX3NoZWxsMzIgPSB0aGlzLl9NYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdTaGVsbDMyLmRsbCcpOwogICAgICAgIHRoaXMuX3NoZWxsMzIuQ3JlYXRlTWV0aG9kKCdTaGVsbF9Ob3RpZnlJY29uQScpOwoKICAgICAgICB0aGlzLl9oYW5kbGUgPSB0aGlzLl9rZXJuZWwzMi5HZXRDb25zb2xlV2luZG93KCk7CiAgICAgICAgdGhpcy5taW5pbWl6ZSA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgdGhpcy5fdXNlcjMyLlNob3dXaW5kb3codGhpcy5faGFuZGxlLCA2KTsKICAgICAgICB9OwogICAgICAgIHRoaXMucmVzdG9yZSA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgdGhpcy5fdXNlcjMyLlNob3dXaW5kb3codGhpcy5faGFuZGxlLCA5KTsKICAgICAgICB9OwogICAgICAgIHRoaXMuaGlkZSA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgdGhpcy5fdXNlcjMyLlNob3dXaW5kb3codGhpcy5faGFuZGxlLCAwKTsKICAgICAgICB9OwogICAgICAgIHRoaXMuc2hvdyA9IGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgdGhpcy5fdXNlcjMyLlNob3dXaW5kb3codGhpcy5faGFuZGxlLCA1KTsKICAgICAgICB9OwoKCiAgICAgICAgdGhpcy5fbG9hZGljb24gPSBmdW5jdGlvbiAoaW1hZ2VQYXRoKSB7CiAgICAgICAgICAgIHZhciBoID0gdGhpcy5fdXNlcjMyLkxvYWRJbWFnZUEoMCwgdGhpcy5fTWFyc2hhbC5DcmVhdGVWYXJpYWJsZShpbWFnZVBhdGgpLCAxLCAwLCAwLCAweDAwMDAwMDEwIHwgMHgwMDAwODAwMCB8IDB4MDAwMDAwNDApOyAvLyBMUl9MT0FERlJPTUZJTEUgfCBMUl9TSEFSRUQgfCBMUl9ERUZBVUxUU0laRQogICAgICAgICAgICByZXR1cm4gKGgpOwogICAgICAgIH07CgogICAgICAgIHRoaXMuU2V0VHJheUljb24gPSBmdW5jdGlvbiBTZXRUcmF5SWNvbihvcHRpb25zKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9NYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKHRoaXMuX01hcnNoYWwuUG9pbnRlclNpemUgPT0gNCA/IDUwOCA6IDUyOCk7CiAgICAgICAgICAgIC8vY29uc29sZS5sb2coJ3N0cnVjdCBzaXplID0gJyArIGRhdGEuX3NpemUpOwogICAgICAgICAgICAvL2NvbnNvbGUubG9nKCdUcnlJY29uLCBXTV9NRVNTQUdFIGZpbHRlciA9ICcgKyBvcHRpb25zLmZpbHRlcik7CiAgICAgICAgICAgIGRhdGEudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKGRhdGEuX3NpemUsIDApOwoKICAgICAgICAgICAgdmFyIHRyYXlUeXBlID0gVHJheUljb25GbGFncy5OSUZfVElQIHwgVHJheUljb25GbGFncy5OSUZfTUVTU0FHRQogICAgICAgICAgICBvcHRpb25zLmZpbHRlciA9IE1lc3NhZ2VUeXBlcy5XTV9BUFAgKyAxOwogICAgICAgICAgICBkYXRhLkRlcmVmKHRoaXMuX01hcnNoYWwuUG9pbnRlclNpemUgPT0gNCA/IDE2IDogMjQsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShvcHRpb25zLmZpbHRlcik7CgogICAgICAgICAgICBpZiAoIW9wdGlvbnMubm9CYWxsb29uKSB7IHRyYXlUeXBlIHw9IFRyYXlJY29uRmxhZ3MuTklGX0lORk87IH0KCiAgICAgICAgICAgIGlmIChvcHRpb25zLmljb24pCiAgICAgICAgICAgIHsgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICB0cmF5VHlwZSB8PSBUcmF5SWNvbkZsYWdzLk5JRl9JQ09OOwogICAgICAgICAgICAgICAgdmFyIGhJY29uID0gZGF0YS5EZXJlZih0aGlzLl9NYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyAyMCA6IDMyLCB0aGlzLl9NYXJzaGFsLlBvaW50ZXJTaXplKTsKICAgICAgICAgICAgICAgIG9wdGlvbnMuaWNvbi5wb2ludGVyQnVmZmVyKCkuY29weShoSWNvbi50b0J1ZmZlcigpKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgZGF0YS5EZXJlZih0aGlzLl9NYXJzaGFsLlBvaW50ZXJTaXplICogMiwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDEpOwogICAgICAgICAgICBkYXRhLkRlcmVmKHRoaXMuX01hcnNoYWwuUG9pbnRlclNpemUgPT0gNCA/IDEyIDogMjAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSh0cmF5VHlwZSk7CiAgICAgICAgICAgIGRhdGEuRGVyZWYodGhpcy5fTWFyc2hhbC5Qb2ludGVyU2l6ZSA9PSA0ID8gNDE2IDogNDMyLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoTk9USUZZSUNPTl9WRVJTSU9OXzQpOwoKICAgICAgICAgICAgdmFyIHN6VGlwID0gZGF0YS5EZXJlZih0aGlzLl9NYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyAyNCA6IDQwLCAxMjgpOwogICAgICAgICAgICB2YXIgc3pJbmZvID0gZGF0YS5EZXJlZih0aGlzLl9NYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyAxNjAgOiAxNzYsIDI1Nik7CiAgICAgICAgICAgIHZhciBzekluZm9UaXRsZSA9IGRhdGEuRGVyZWYodGhpcy5fTWFyc2hhbC5Qb2ludGVyU2l6ZSA9PSA0ID8gNDIwIDogNDM2LCA2NCk7CgogICAgICAgICAgICBpZiAob3B0aW9ucy5zelRpcCkgeyBCdWZmZXIuZnJvbShvcHRpb25zLnN6VGlwKS5jb3B5KHN6VGlwLnRvQnVmZmVyKCkpOyB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLnN6SW5mbykgeyBCdWZmZXIuZnJvbShvcHRpb25zLnN6SW5mbykuY29weShzekluZm8udG9CdWZmZXIoKSk7IH0KICAgICAgICAgICAgaWYgKG9wdGlvbnMuc3pJbmZvVGl0bGUpIHsgQnVmZmVyLmZyb20ob3B0aW9ucy5zekluZm9UaXRsZSkuY29weShzekluZm9UaXRsZS50b0J1ZmZlcigpKTsgfQoKCiAgICAgICAgICAgIHZhciBNZXNzYWdlUHVtcCA9IHJlcXVpcmUoJ3dpbi1tZXNzYWdlLXB1bXAnKTsKICAgICAgICAgICAgcmV0VmFsID0geyBfT2JqZWN0SUQ6ICdXaW5kb3dzQ29uc29sZS5UcmF5SWNvbicsIE1lc3NhZ2VQdW1wOiBuZXcgTWVzc2FnZVB1bXAob3B0aW9ucykgfTsKICAgICAgICAgICAgdmFyIHJldFZhbEV2ZW50cyA9IHJlcXVpcmUoJ2V2ZW50cycpLmluaGVyaXRzKHJldFZhbCk7CiAgICAgICAgICAgIHJldFZhbEV2ZW50cy5jcmVhdGVFdmVudCgnVG9hc3RDbGlja2VkJyk7CiAgICAgICAgICAgIHJldFZhbEV2ZW50cy5jcmVhdGVFdmVudCgnSWNvbkhvdmVyJyk7CiAgICAgICAgICAgIHJldFZhbEV2ZW50cy5jcmVhdGVFdmVudCgnVG9hc3REaXNtaXNzZWQnKTsKICAgICAgICAgICAgcmV0VmFsLk9wdGlvbnMgPSBvcHRpb25zOwogICAgICAgICAgICByZXRWYWwuTWVzc2FnZVB1bXAuVHJheUljb24gPSByZXRWYWw7CiAgICAgICAgICAgIHJldFZhbC5NZXNzYWdlUHVtcC5Ob3RpZnlEYXRhID0gZGF0YTsKICAgICAgICAgICAgcmV0VmFsLk1lc3NhZ2VQdW1wLldpbmRvd3NDb25zb2xlID0gdGhpczsKICAgICAgICAgICAgcmV0VmFsLk1lc3NhZ2VQdW1wLm9uKCdleGl0JywgZnVuY3Rpb24gb25FeGl0KGNvZGUpIHsgY29uc29sZS5sb2coJ1B1bXAgRXhpdGVkJyk7IGlmICh0aGlzLlRyYXlJY29uKSB7IHRoaXMuVHJheUljb24ucmVtb3ZlKCk7IH0gfSk7CiAgICAgICAgICAgIHJldFZhbC5NZXNzYWdlUHVtcC5vbignaHduZCcsIGZ1bmN0aW9uIG9uSHduZChoKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAvL2NvbnNvbGUubG9nKCdHb3QgSFdORCcpOwogICAgICAgICAgICAgICAgb3B0aW9ucy5od25kID0gaDsKICAgICAgICAgICAgICAgIGgucG9pbnRlckJ1ZmZlcigpLmNvcHkodGhpcy5Ob3RpZnlEYXRhLkRlcmVmKHRoaXMuV2luZG93c0NvbnNvbGUuX01hcnNoYWwuUG9pbnRlclNpemUsIHRoaXMuV2luZG93c0NvbnNvbGUuX01hcnNoYWwuUG9pbnRlclNpemUpLnRvQnVmZmVyKCkpOwoKICAgICAgICAgICAgICAgIGlmKHRoaXMuV2luZG93c0NvbnNvbGUuX3NoZWxsMzIuU2hlbGxfTm90aWZ5SWNvbkEoVHJheUljb25GbGFncy5OSU1fQURELCB0aGlzLk5vdGlmeURhdGEpLlZhbCA9PSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIC8vIFNvbWV0aGluZyB3ZW50IHdyb25nCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pOwogICAgICAgICAgICByZXRWYWwuTWVzc2FnZVB1bXAub24oJ21lc3NhZ2UnLCBmdW5jdGlvbiBvbldpbmRvd3NNZXNzYWdlKG1zZykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgaWYobXNnLm1lc3NhZ2UgPT0gdGhpcy5UcmF5SWNvbi5PcHRpb25zLmZpbHRlcikKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgaGFuZGxlZCA9IGZhbHNlOwogICAgICAgICAgICAgICAgICAgIGlmIChtc2cud3BhcmFtID09IDEgJiYgbXNnLmxwYXJhbSA9PSAxMDI5KQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5UcmF5SWNvbi5lbWl0KCdUb2FzdENsaWNrZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlZCA9IHRydWU7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChtc2cud3BhcmFtID09IDEgJiYgbXNnLmxwYXJhbSA9PSA1MTIpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLlRyYXlJY29uLmVtaXQoJ0ljb25Ib3ZlcicpOwogICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVkID0gdHJ1ZTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuVHJheUljb24uT3B0aW9ucy5iYWxsb29uT25seSAmJiBtc2cud3BhcmFtID09IDEgJiYgKG1zZy5scGFyYW0gPT0gMTAyOCB8fCBtc2cubHBhcmFtID09IDEwMjkpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5UcmF5SWNvbi5lbWl0KCdUb2FzdERpc21pc3NlZCcpOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLlRyYXlJY29uLnJlbW92ZSgpOwogICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVkID0gdHJ1ZTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pOwogICAgICAgICAgICByZXRWYWwucmVtb3ZlID0gZnVuY3Rpb24gcmVtb3ZlKCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5NZXNzYWdlUHVtcC5XaW5kb3dzQ29uc29sZS5fc2hlbGwzMi5TaGVsbF9Ob3RpZnlJY29uQShUcmF5SWNvbkZsYWdzLk5JTV9ERUxFVEUsIHRoaXMuTWVzc2FnZVB1bXAuTm90aWZ5RGF0YSk7CiAgICAgICAgICAgICAgICB0aGlzLk1lc3NhZ2VQdW1wLnN0b3AoKTsKICAgICAgICAgICAgICAgIGRlbGV0ZSB0aGlzLk1lc3NhZ2VQdW1wLlRyYXlJY29uOwogICAgICAgICAgICAgICAgZGVsZXRlIHRoaXMuTWVzc2FnZVB1bXA7CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICAgICAgCiAgICAgICAgfTsKICAgIH0KfQoKbW9kdWxlLmV4cG9ydHMgPSBuZXcgV2luZG93c0NvbnNvbGUoKTs=', 'base64').toString());");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addModule('win-certstore', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KY29uc3QgQ0VSVF9GSU5EX1NVQkpFQ1RfTkFNRSA9ICgyIDw8IDE2IHwgNyk7CmNvbnN0IENFUlRfU1RPUkVfT1BFTl9FWElTVElOR19GTEFHID0gMHgwMDAwNDAwMDsKY29uc3QgQ0VSVF9TVE9SRV9QUk9WX1NZU1RFTSA9IDEwOwpjb25zdCBDRVJUX1g1MDBfTkFNRV9TVFIgPSAzOwpjb25zdCBQS0NTXzdfQVNOX0VOQ09ESU5HID0gMHgwMDAxMDAwMDsKY29uc3QgWDUwOV9BU05fRU5DT0RJTkcgPSAweDAwMDAwMDAxOwpjb25zdCBDRVJUX0NMT1NFX1NUT1JFX0ZPUkNFX0ZMQUcgPSAweDAwMDAwMDAxOwpjb25zdCBDRVJUX0NMT1NFX1NUT1JFX0NIRUNLX0ZMQUcgPSAweDAwMDAwMDAyOwoKZnVuY3Rpb24gY2VydHN0b3JlKCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAnd2luLWNlcnRzdG9yZSc7CiAgICB0aGlzLl9tYXJzaGFsID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICB0aGlzLl9DcnlwdDMyID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnQ3J5cHQzMi5kbGwnKTsKICAgIHRoaXMuX0NyeXB0MzIuQ3JlYXRlTWV0aG9kKCdDZXJ0Q2xvc2VTdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnREZWxldGVDZXJ0aWZpY2F0ZUZyb21TdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnRGaW5kQ2VydGlmaWNhdGVJblN0b3JlJyk7CiAgICB0aGlzLl9DcnlwdDMyLkNyZWF0ZU1ldGhvZCgnQ2VydE9wZW5TdG9yZScpOwogICAgdGhpcy5fQ3J5cHQzMi5DcmVhdGVNZXRob2QoJ0NlcnRTdHJUb05hbWVBJyk7CgogICAgdGhpcy5fTmNycHl0ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnTmNyeXB0LmRsbCcpOwogICAgdGhpcy5fTmNycHl0LkNyZWF0ZU1ldGhvZCgnTkNyeXB0RnJlZU9iamVjdCcpOwogICAgdGhpcy5fTmNycHl0LkNyZWF0ZU1ldGhvZCgnTkNyeXB0T3BlblN0b3JhZ2VQcm92aWRlcicpOwogICAgdGhpcy5TVE9SRV9MT0NBVElPTiA9IHsgTE9DQUxfTUFDSElORTogMiA8PCAxNiwgQ1VSUkVOVF9VU0VSOiAxIDw8IDE2IH07CiAgICB0aGlzLlBST1ZJREVSUyA9IFt0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNaWNyb3NvZnQgUGxhdGZvcm0gQ3J5cHRvIFByb3ZpZGVyJywgeyB3aWRlOiB0cnVlIH0pLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNaWNyb3NvZnQgU29mdHdhcmUgS2V5IFN0b3JhZ2UgUHJvdmlkZXInLCB7IHdpZGU6IHRydWUgfSldOwoKICAgIHRoaXMuT3BlbkNyeXB0b1Byb3ZpZGVyID0gZnVuY3Rpb24gT3BlbkNyeXB0b1Byb3ZpZGVyKCkKICAgIHsKICAgICAgICB2YXIgcmV0ID0gbnVsbDsKICAgICAgICB2YXIgcCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgIGZvcih2YXIgcHJvdmlkZXIgaW4gdGhpcy5QUk9WSURFUlMpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9OY3JweXQuTkNyeXB0T3BlblN0b3JhZ2VQcm92aWRlcihwLCB0aGlzLlBST1ZJREVSU1twcm92aWRlcl0sIDApOwogICAgICAgICAgICBpZiAocC5EZXJlZigpLlZhbCAhPSAwKSB7IHJldCA9IHAuRGVyZWYoKTsgcmV0Ll9iID0gcDsgYnJlYWs7fQogICAgICAgIH0KICAgICAgICBpZiAocmV0ID09IG51bGwpIHsgdGhyb3cgKCdVbmFibGUgdG8gb3BlbiBDcnlwdG9Qcm92aWRlcicpOyB9CiAgICAgICAgcmV0Ll9jcnlwdCA9IHRoaXM7CiAgICAgICAgcmV0Ll9maW5hbGl6ZWQgPSBmYWxzZTsKICAgICAgICByZXQuY2xvc2UgPSBmdW5jdGlvbigpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9maW5hbGl6ZWQgPSB0cnVlOwogICAgICAgICAgICB0aGlzLl9jcnlwdC5fTmNycHl0Lk5DcnlwdEZyZWVPYmplY3QodGhpcyk7CiAgICAgICAgfQogICAgICAgIHJldC5wcmVwZW5kT25jZUxpc3RlbmVyKCd+JywgZnVuY3Rpb24gKCkKICAgICAgICB7CiAgICAgICAgICAgIGlmKCF0aGlzLl9maW5hbGl6ZWQpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRoaXMuY2xvc2UoKTsKICAgICAgICAgICAgfQogICAgICAgIH0pOwogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07CiAgICB0aGlzLk9wZW5TdG9yZSA9IGZ1bmN0aW9uIE9wZW5TdG9yZShwcm92aWRlciwgbG9jYXRpb24pCiAgICB7CiAgICAgICAgdmFyIGhzdG9yZSA9IHRoaXMuX0NyeXB0MzIuQ2VydE9wZW5TdG9yZShDRVJUX1NUT1JFX1BST1ZfU1lTVEVNLCBYNTA5X0FTTl9FTkNPRElORyB8IFBLQ1NfN19BU05fRU5DT0RJTkcsIHByb3ZpZGVyLCBsb2NhdGlvbiB8IENFUlRfU1RPUkVfT1BFTl9FWElTVElOR19GTEFHLCB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKCdNWScsIHt3aWRlOiB0cnVlfSkpOwogICAgICAgIGlmIChoc3RvcmUuVmFsID09IDApIHsgdGhyb3cgKCdFcnJvciBvcGVuaW5nIENlcnRTdG9yZScpOyB9CiAgICAgICAgaHN0b3JlLl9jcnlwdCA9IHRoaXM7CiAgICAgICAgaHN0b3JlLl9maW5hbGl6ZWQgPSBmYWxzZTsKICAgICAgICBoc3RvcmUuY2xvc2UgPSBmdW5jdGlvbiBjbG9zZSgpIHsgdGhpcy5fZmluYWxpemVkID0gdHJ1ZTsgdGhpcy5fY3J5cHQuX0NyeXB0MzIuQ2VydENsb3NlU3RvcmUodGhpcywgQ0VSVF9DTE9TRV9TVE9SRV9DSEVDS19GTEFHKTsgfTsKICAgICAgICBoc3RvcmUucHJlcGVuZE9uY2VMaXN0ZW5lcignficsIGZ1bmN0aW9uICgpIHsgaWYgKCF0aGlzLl9maW5hbGl6ZWQpIHsgdGhpcy5jbG9zZSgpOyB9IH0pOwogICAgICAgIHJldHVybiAoaHN0b3JlKTsKICAgIH07CiAgICB0aGlzLkdldENlcnRpZmljYXRlID0gZnVuY3Rpb24gR2V0Q2VydGlmaWNhdGUoQ04sIGxvY2F0aW9uKQogICAgewogICAgICAgIHZhciBzdWJqZWN0ID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZShDTik7CiAgICAgICAgdmFyIGVuY29kZWRTaXplID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSg0KTsgLy8gRFdPUkQKICAgICAgICBpZih0aGlzLl9DcnlwdDMyLkNlcnRTdHJUb05hbWVBKFg1MDlfQVNOX0VOQ09ESU5HLCBzdWJqZWN0LCBDRVJUX1g1MDBfTkFNRV9TVFIsIDAsIDAsIGVuY29kZWRTaXplLCAwKS5WYWwgPT0gMCkKICAgICAgICB7CiAgICAgICAgICAgIHRocm93KCdFcnJvciBjYWxjdWxhdGluZyBDRVJUX1g1MDBfTkFNRV9TVFIgZm9yICgnICsgQ04gKyAnKScpOwogICAgICAgIH0KICAgICAgICB2YXIgc3ViamVjdEVuY29kZWQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKGVuY29kZWRTaXplLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpOwogICAgICAgIGlmKHRoaXMuX0NyeXB0MzIuQ2VydFN0clRvTmFtZUEoWDUwOV9BU05fRU5DT0RJTkcsIHN1YmplY3QsIENFUlRfWDUwMF9OQU1FX1NUUiwgMCwgc3ViamVjdEVuY29kZWQsIGVuY29kZWRTaXplLCAwKS5WYWwgPT0gMCkKICAgICAgICB7CiAgICAgICAgICAgIHRocm93KCdFcnJvciBlbmNvZGluZyBDRVJUX1g1MDBfTkFNRV9TVFIgZm9yICgnICsgQ04gKyAnKScpOwogICAgICAgIH0KICAgICAgICB2YXIgcHJvdmlkZXIgPSB0aGlzLk9wZW5DcnlwdG9Qcm92aWRlcigpOwogICAgICAgIHZhciBzdG9yZSA9IHRoaXMuT3BlblN0b3JlKHByb3ZpZGVyLCBsb2NhdGlvbik7CiAgICAgICAgdmFyIHNlYXJjaCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUodGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSAqIDIpOwogICAgICAgIHNlYXJjaC5EZXJlZigwLDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShlbmNvZGVkU2l6ZS50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKTsKICAgICAgICBzdWJqZWN0RW5jb2RlZC5wb2ludGVyQnVmZmVyKCkuY29weShzZWFyY2gudG9CdWZmZXIoKSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSk7CgogICAgICAgIC8vIExvb2sgZm9yIGNlcnQKICAgICAgICB2YXIgY2VydGN0eCA9IHRoaXMuX0NyeXB0MzIuQ2VydEZpbmRDZXJ0aWZpY2F0ZUluU3RvcmUoc3RvcmUsIFg1MDlfQVNOX0VOQ09ESU5HIHwgUEtDU183X0FTTl9FTkNPRElORywgMCwgQ0VSVF9GSU5EX1NVQkpFQ1RfTkFNRSwgc2VhcmNoLCAwKTsKICAgICAgICBpZihjZXJ0Y3R4LlZhbCAhPSAwKQogICAgICAgIHsKICAgICAgICAgICAgLy8gRm91bmQgQ2VydGlmaWNhdGUKICAgICAgICAgICAgdmFyIGNlciA9IGNlcnRjdHguRGVyZWYodGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSkuRGVyZWYoY2VydGN0eC5EZXJlZih0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplICogMiwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSkudG9CdWZmZXIoKTsKICAgICAgICAgICAgdmFyIGZvdW5kY2VydCA9IHJlcXVpcmUoJ3RscycpLmxvYWRDZXJ0aWZpY2F0ZSh7IGNlcjogY2VyIH0pOwogICAgICAgICAgICByZXR1cm4gKGZvdW5kY2VydCk7CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHRocm93ICgnTm90IEZvdW5kJyk7CiAgICAgICAgfQoKICAgIH07Cn0KCm1vZHVsZS5leHBvcnRzID0gbmV3IGNlcnRzdG9yZSgpOwoK', 'base64').toString());");
#endif

#ifdef _FREEBSD
	// Helper to locate installed libraries. Currently only supports FreeBSD
	duk_peval_string_noresult(ctx, "addModule('lib-finder', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQpmdW5jdGlvbiBmaW5kKG5hbWUpDQp7DQoJc3dpdGNoKHByb2Nlc3MucGxhdGZvcm0pDQoJew0KCQljYXNlICdmcmVlYnNkJzoNCgkJCXZhciByZXQgPSBbXTsNCgkJCXZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7DQoJCQljaGlsZC5zdGRvdXQuc3RyID0gJyc7DQoJCQljaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOw0KCQkJY2hpbGQuc3RkaW4ud3JpdGUoInBrZyBpbmZvICIgKyBuYW1lICsgIiB8IHRyICdcXG4nICdcXHwnIHwgYXdrICcgeyBhPXNwbGl0KCQwLCB0LCBcIlNoYXJlZCBMaWJzIHByb3ZpZGVkOlwiKTsgaWYoYT09MikgeyBzcGxpdCh0WzJdLCBsaWIsIFwiOlwiKTsgcHJpbnQgbGliWzFdOyB9IH0nIHwgdHIgJ1xcfCcgJ1xcbicgfCBhd2sgJ3sgaWYoc3BsaXQoJDEsIHJlcywgXCIuc29cIik+MSkgeyBwcmludCAkMTsgfSB9J1xuZXhpdFxuIik7DQoJCQljaGlsZC53YWl0RXhpdCgpOw0KCQkJdmFyIHJlcyA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpLnNwbGl0KCdcbicpOw0KCQkJZm9yKHZhciBpIGluIHJlcykNCgkJCXsNCgkJCQlpZighcmVzW2ldLnN0YXJ0c1dpdGgobmFtZSArICcuc28nKSkgeyBjb250aW51ZTsgfQ0KCQkJCXZhciB2ID0ge25hbWU6IHJlc1tpXX07DQoJCQkJY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOw0KCQkJCWNoaWxkLnN0ZG91dC5zdHIgPSAnJzsNCgkJCQljaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOw0KCQkJCWNoaWxkLnN0ZGluLndyaXRlKCdwa2cgaW5mbyAtbCAnICsgbmFtZSArICcgfCBncmVwICcgKyB2Lm5hbWUgKyAnIHwgYXdrIFwneyBhPXNwbGl0KCQxLCB0b2ssICIvIik7IGlmKHRva1thXT09IicgKyB2Lm5hbWUgKyAnIikgeyBwcmludCAkMTsgfSB9XCdcbmV4aXRcbicpOw0KCQkJCWNoaWxkLndhaXRFeGl0KCk7DQoJCQkJdi5sb2NhdGlvbiA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOw0KCQkJCXJldC5wdXNoKHYpOw0KCQkJfQ0KCQkJcmV0dXJuKHJldCk7DQoJCWJyZWFrOw0KCX0NCn0NCg0KbW9kdWxlLmV4cG9ydHMgPSBmaW5kOw0K', 'base64').toString());");
#endif

	// monitor-info: Refer to modules/monitor-info.js
	char *_monitorinfo = ILibMemory_Allocate(46347, 0, NULL, NULL);
	memcpy_s(_monitorinfo + 0, 26484, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwp2YXIgUFBvc2l0aW9uID0gNDsKdmFyIFBTaXplID0gODsKdmFyIF9ORVRfV01fU1RBVEVfUkVNT1ZFID0gMDsgICAgLy8gcmVtb3ZlL3Vuc2V0IHByb3BlcnR5CnZhciBfTkVUX1dNX1NUQVRFX0FERCA9IDE7ICAgIC8vIGFkZC9zZXQgcHJvcGVydHkKdmFyIF9ORVRfV01fU1RBVEVfVE9HR0xFID0gMjsgICAgLy8gdG9nZ2xlIHByb3BlcnR5CnZhciBTdWJzdHJ1Y3R1cmVSZWRpcmVjdE1hc2sgPSAoMSA8PCAyMCk7CnZhciBTdWJzdHJ1Y3R1cmVOb3RpZnlNYXNrID0gKDEgPDwgMTkpOwoKZnVuY3Rpb24gZ2V0TGliSW5mbyhsaWJuYW1lKQp7CiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSAhPSAnbGludXgnKSB7IHRocm93ICgnT25seSBzdXBwb3J0ZWQgb24gbGludXgnKTsgfQoKICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICBjaGlsZC5zdGRpbi53cml0ZSgibGRjb25maWcgLXAgfCBncmVwICciICsgbGlibmFtZSArICIuc28uJ1xuZXhpdFxuIik7CiAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgIHZhciB2ID0gW107CiAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgZm9yICh2YXIgaSBpbiBsaW5lcykgewogICAgICAgIGlmIChsaW5lc1tpXSkgewogICAgICAgICAgICB2YXIgaW5mbyA9IGxpbmVzW2ldLnNwbGl0KCc9PicpOwogICAgICAgICAgICB2YXIgcHRoID0gaW5mb1sxXS50cmltKCk7CiAgICAgICAgICAgIHZhciBsaWJpbmZvID0gaW5mb1swXS50cmltKCkuc3BsaXQoJyAnKTsKICAgICAgICAgICAgdmFyIGxpYiA9IGxpYmluZm9bMF07CiAgICAgICAgICAgIHZhciBwbGF0ID0gbGliaW5mb1sxXS5zdWJzdHJpbmcoMSwgbGliaW5mb1sxXS5sZW5ndGggLSAxKS5zcGxpdCgnLCcpOwoKICAgICAgICAgICAgaWYgKGxpYi5zdGFydHNXaXRoKGxpYm5hbWUgKyAnLnNvLicpKSB7CiAgICAgICAgICAgICAgICB2LnB1c2goeyBsaWI6IGxpYiwgcGF0aDogcHRoLCBpbmZvOiBwbGF0IH0pOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQogICAgcmV0dXJuICh2KTsKfQoKZnVuY3Rpb24gbW9uaXRvcmluZm8oKQp7CiAgICB0aGlzLl9PYmplY3RJRCA9ICdtb25pdG9yLWluZm8nOwogICAgdGhpcy5fZ20gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKCiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgewogICAgICAgIHRoaXMuX3VzZXIzMiA9IHRoaXMuX2dtLkNyZWF0ZU5hdGl2ZVByb3h5KCd1c2VyMzIuZGxsJyk7CiAgICAgICAgdGhpcy5fdXNlcjMyLkNyZWF0ZU1ldGhvZCgnRW51bURpc3BsYXlNb25pdG9ycycpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyID0gdGhpcy5fZ20uQ3JlYXRlTmF0aXZlUHJveHkoJ2tlcm5lbDMyLmRsbCcpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2V0TGFzdEVycm9yJyk7CgogICAgICAgIHRoaXMuZ2V0SW5mbyA9IGZ1bmN0aW9uIGdldEluZm8oKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGluZm8gPSB0aGlzOwogICAgICAgICAgICByZXR1cm4gKG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlciwgcmVqZWN0b3IpIHsKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvID0geyByZXNvbHZlcjogcmVzb2x2ZXIsIHJlamVjdG9yOiByZWplY3Rvciwgc2VsZjogaW5mbywgY2FsbGJhY2s6IGluZm8uX2dtLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjayg0KSB9OwogICAgICAgICAgICAgICAgdGhpcy5fbW9uaXRvcmluZm8uY2FsbGJhY2suaW5mbyA9IHRoaXMuX21vbml0b3JpbmZvOwogICAgICAgICAgICAgICAgdGhpcy5fbW9uaXRvcmluZm8uZHdEYXRhID0gaW5mby5fZ20uT2JqZWN0VG9QdHIodGhpcy5fbW9uaXRvcmluZm8pOwoKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvLmNhbGxiYWNrLnJlc3VsdHMgPSBbXTsKICAgICAgICAgICAgICAgIHRoaXMuX21vbml0b3JpbmZvLmNhbGxiYWNrLm9uKCdHbG9iYWxDYWxsYmFjaycsIGZ1bmN0aW9uIE9uTW9uaXRvckluZm8oaG1vbiwgaGRjLCByLCB1c2VyKSB7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuT2JqZWN0VG9QdHJfVmVyaWZ5KHRoaXMuaW5mbywgdXNlcikpIHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJiID0gci5EZXJlZigwLCAxNikudG9CdWZmZXIoKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXN1bHRzLnB1c2goeyBsZWZ0OiByYi5yZWFkSW50MzJMRSgwKSwgdG9wOiByYi5yZWFkSW50MzJMRSg0KSwgcmlnaHQ6IHJiLnJlYWRJbnQzMkxFKDgpLCBib3R0b206IHJiLnJlYWRJbnQzMkxFKDEyKSB9KTsKCiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByID0gdGhpcy5pbmZvLnNlbGYuX2dtLkNyZWF0ZUludGVnZXIoKTsKICAgICAgICAgICAgICAgICAgICAgICAgci5WYWwgPSAxOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHIpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgICAgIGlmIChpbmZvLl91c2VyMzIuRW51bURpc3BsYXlNb25pdG9ycygwLCAwLCB0aGlzLl9tb25pdG9yaW5mby5jYWxsYmFjaywgdGhpcy5fbW9uaXRvcmluZm8uZHdEYXRhKS5WYWwgPT0gMCkgewogICAgICAgICAgICAgICAgICAgIHJlamVjdG9yKCdMYXN0RXJyb3I9JyArIGluZm8uX2tlcm5lbDMyLkdldExhc3RFcnJvcigpLlZhbCk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZXIodGhpcy5fbW9uaXRvcmluZm8uY2FsbGJhY2sucmVzdWx0cyk7CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICB9KSk7CiAgICAgICAgfQogICAgfQogICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICB7CiAgICAgICAgLy8gRmlyc3QgdGhpbmcgd2UgbmVlZCB0byBkbywgaXMgZGV0ZXJtaW5lIHdoZXJlIHRoZSBYMTEgbGlicmFyaWVzIGFyZQogICAgICAgIHZhciBhc2tPUyA9IGZhbHNlOwogICAgICAgIHRyeQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5pc1Jvb3QoKSkgeyBhc2tPUyA9IHRydWU7IH0KICAgICAgICB9CiAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgeyB9CgogICAgICAgIGlmIChhc2tPUykKICAgICAgICB7CiAgICAgICAgICAgIC8vIFN1ZmZpY2llbnQgYWNjZXNzIHJpZ2h0cyB0byB1c2UgbGRjb25maWcKICAgICAgICAgICAgdmFyIHgxMWluZm8gPSBnZXRMaWJJbmZvKCdsaWJYMTEnKTsKICAgICAgICAgICAgdmFyIHh0c3RpbmZvID0gZ2V0TGliSW5mbygnbGliWHRzdCcpOwogICAgICAgICAgICB2YXIgeGV4dGluZm8gPSBnZXRMaWJJbmZvKCdsaWJYZXh0Jyk7CiAgICAgICAgICAgIHZhciBpeDsKCiAgICAgICAgICAgIGZvcihpeCBpbiB4MTFpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4MTFpbmZvW2l4XS5wYXRoKTsKICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUxJQicsIHsgdmFsdWU6IHgxMWluZm9baXhdLnBhdGggfSk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBmb3IgKGl4IGluIHh0c3RpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4dHN0aW5mb1tpeF0ucGF0aCk7CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiB4dHN0aW5mb1tpeF0ucGF0aCB9KTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoIChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBmb3IgKGl4IGluIHhleHRpbmZvKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9nbS5DcmVhdGVOYXRpdmVQcm94eSh4ZXh0aW5mb1tpeF0ucGF0aCk7CiAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFFWFQnLCB7IHZhbHVlOiB4ZXh0aW5mb1tpeF0ucGF0aCB9KTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoIChleCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICAvLyBOb3QgZW5vdWdoIGFjY2VzcyByaWdodHMgdG8gdXNlIGxkY29uZmlnLCBzbyBtYW51YWxseSBzZWFyY2gKICAgICAgICAgICAgdmFyIGZzID0gcmVxdWlyZSgnZnMnKTsKICAgICAgICAgICAgdmFyIGZpbGVzID0gZnMucmVhZGRpclN5bmMoJy91c3IvbGliJyk7CiAgICAgICAgICAgIHZhciBmaWxlczI7CgogICAgICAgICAgICBmb3IgKHZhciBpIGluIGZpbGVzKSB7CiAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnbGliWDExLnNvLicpLmxlbmd0aCA+IDEgJiYgZmlsZXNbaV0uc3BsaXQoJy4nKS5sZW5ndGggPT0gMykgewogICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUxJQicsIHsgdmFsdWU6ICcvdXNyL2xpYi8nICsgZmlsZXNbaV0gfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnbGliWHRzdC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzW2ldLnNwbGl0KCcuJykubGVuZ3RoID09IDMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldIH0pOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBpZiAoZmlsZXNbaV0uc3BsaXQoJ2xpYlhleHQuc28uJykubGVuZ3RoID4gMSAmJiBmaWxlc1tpXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0aGlzLCAnTG9jYXRpb25fWDExRVhUJywgeyB2YWx1ZTogJy91c3IvbGliLycgKyBmaWxlc1tpXSB9KTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGlmIChmaWxlc1tpXS5zcGxpdCgnLWxpbnV4LScpLmxlbmd0aCA+IDEpIHsKICAgICAgICAgICAgICAgICAgICAgICAgZmlsZXMyID0gZnMucmVhZGRpclN5bmMoJy91c3IvbGliLycgKyBmaWxlc1tpXSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoaiBpbiBmaWxlczIpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChmaWxlczJbal0uc3BsaXQoJ2xpYlgxMS5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFMSUInLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGZpbGVzMltqXS5zcGxpdCgnbGliWHRzdC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGZpbGVzMltqXS5zcGxpdCgnbGliWGV4dC5zby4nKS5sZW5ndGggPiAxICYmIGZpbGVzMltqXS5zcGxpdCgnLicpLmxlbmd0aCA9PSAzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFFWFQnLCB7IHZhbHVlOiAnL3Vzci9saWIvJyArIGZpbGVzW2ldICsgJy8nICsgZmlsZXMyW2pdIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfSBjYXRjaCAoZXgpIHsgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQogICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcpCiAgICB7CglPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUxJQicsIHsgdmFsdWU6IHJlcXVpcmUoJ2xpYi1maW5kZXInKSgnbGliWDExJylbMF0/cmVxdWlyZSgnbGliLWZpbmRlcicpKCdsaWJYMTEnKVswXS5sb2NhdGlvbjogdW5kZWZpbmVkIH0pOwoJT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdMb2NhdGlvbl9YMTFUU1QnLCB7IHZhbHVlOiByZXF1aXJlKCdsaWItZmluZGVyJykoJ2xpYlh0c3QnKVswXT9yZXF1aXJlKCdsaWItZmluZGVyJykoJ2xpYlh0c3QnKVswXS5sb2NhdGlvbjp1bmRlZmluZWQgfSk7CglPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgJ0xvY2F0aW9uX1gxMUVYVCcsIHsgdmFsdWU6IHJlcXVpcmUoJ2xpYi1maW5kZXInKSgnbGliWGV4dCcpWzBdP3JlcXVpcmUoJ2xpYi1maW5kZXInKSgnbGliWGV4dCcpWzBdLmxvY2F0aW9uOnVuZGVmaW5lZCB9KTsKICAgIH0KCiAgICBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcgfHwgcHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcpCiAgICB7CiAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICdrdm1feDExX3N1cHBvcnQnLCB7IHZhbHVlOiAodGhpcy5Mb2NhdGlvbl9YMTFMSUIgJiYgdGhpcy5Mb2NhdGlvbl9YMTFUU1QgJiYgdGhpcy5Mb2NhdGlvbl9YMTFFWFQpP3RydWU6ZmFsc2UgfSk7CgogICAgICAgIGlmICh0aGlzLkxvY2F0aW9uX1gxMUxJQikKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuX1gxMSA9IHRoaXMuX2dtLkNyZWF0ZU5hdGl2ZVByb3h5KHRoaXMuTG9jYXRpb25fWDExTElCKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWENoYW5nZVByb3BlcnR5Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDbG9zZURpc3BsYXknKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWENvbm5lY3Rpb25OdW1iZXInKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWENvbnZlcnRTZWxlY3Rpb24nKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWENyZWF0ZUdDJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDcmVhdGVXaW5kb3cnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWENyZWF0ZVNpbXBsZVdpbmRvdycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRGVmYXVsdENvbG9ybWFwJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hEZWZhdWx0U2NyZWVuJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hEZXN0cm95V2luZG93Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hEcmF3TGluZScpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRGlzcGxheUhlaWdodCcpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYRGlzcGxheVdpZHRoJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hGZXRjaE5hbWUnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWEZsdXNoJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hGcmVlJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hDcmVhdGVHQycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYR2V0V2luZG93UHJvcGVydHknKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWEludGVybkF0b20nKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWE1hcFdpbmRvdycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKHsgbWV0aG9kOiAnWE5leHRFdmVudCcsIHRocmVhZERpc3BhdGNoOiB0cnVlIH0pOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKHsgbWV0aG9kOiAnWE5leHRFdmVudCcsIG5ld05hbWU6ICdYTmV4dEV2ZW50U3luYycgfSk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hPcGVuRGlzcGxheScpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYUGVuZGluZycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYUm9vdFdpbmRvdycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2VsZWN0SW5wdXQnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNjcmVlbkNvdW50Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTY3JlZW5PZkRpc3BsYXknKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNlbGVjdElucHV0Jyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZW5kRXZlbnQnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNldEZvcmVncm91bmQnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNldEZ1bmN0aW9uJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZXRMaW5lQXR0cmlidXRlcycpOwogICAgICAgICAgICB0aGlzLl9YMTEuQ3JlYXRlTWV0aG9kKCdYU2V0Tm9ybWFsSGludHMnKTsKICAgICAgICAgICAgdGhpcy5fWDExLkNyZWF0ZU1ldGhvZCgnWFNldFNlbGVjdGlvbk93bmVyJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTZXRTdWJ3aW5kb3dNb2RlJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hTeW5jJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hCbGFja1BpeGVsJyk7CiAgICAgICAgICAgIHRoaXMuX1gxMS5DcmVhdGVNZXRob2QoJ1hXaGl0ZVBpeGVsJyk7CiAgICAgICAgfQoKICAgICAgICB0aGlzLmlzVW5pdHkgPSBmdW5jdGlvbiBpc1VuaXR5KCkKICAgICAgICB7CiAgICAgICAgICAgIHJldHVybiAocHJvY2Vzcy5lbnZbJ1hER19DVVJSRU5UX0RFU0tUT1AnXSA9PSAnVW5pdHknKTsKICAgICAgICB9CgogICAgICAgIHRoaXMudW5EZWNvcmF0ZVdpbmRvdyA9IGZ1bmN0aW9uIHVuRGVjb3JhdGVXaW5kb3coZGlzcGxheSwgd2luZG93KQogICAgICAgIHsKICAgICAgICAgICAgdmFyIE13bUhpbnRzID0gdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoNDApOwogICAgICAgICAgICB2YXIgbXdtSGludHNQcm9wZXJ0eSA9IHRoaXMuX1gxMS5YSW50ZXJuQXRvbShkaXNwbGF5LCB0aGlzLl9nbS5DcmVhdGVWYXJpYWJsZSgnX01PVElGX1dNX0hJTlRTJyksIDApOwogICAgICAgICAgICBNd21IaW50cy5EZXJlZigwLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMSA8PCAxKTsKICAgICAgICAgICAgdGhpcy5fWDExLlhDaGFuZ2VQcm9wZXJ0eShkaXNwbGF5LCB3aW5kb3csIG13bUhpbnRzUHJvcGVydHksIG13bUhpbnRzUHJvcGVydHksIDMyLCAwLCBNd21IaW50cywgNSk7CiAgICAgICAgfQogICAgICAgIHRoaXMuc2V0V2luZG93U2l6ZUhpbnRzID0gZnVuY3Rpb24gc2V0V2luZG93U2l6ZUhpbnRzKGRpc3BsYXksIHdpbmRvdywgeCwgeSwgd2lkdGgsIGhlaWdodCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBzaXplSGludHMgPSB0aGlzLl9nbS5DcmVhdGVWYXJpYWJsZSg4MCk7CiAgICAgICAgICAgIHNpemVIaW50cy5EZXJlZigwLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoUFBvc2l0aW9uIHwgUFNpemUpOwogICAgICAgICAgICBzaXplSGludHMuRGVyZWYoOCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKHgpOwogICAgICAgICAgICBzaXplSGludHMuRGVyZWYoMTIsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSh5KTsKICAgICAgICAgICAgc2l6ZUhpbnRzLkRlcmVmKDE2LCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUod2lkdGgpOwogICAgICAgICAgICBzaXplSGludHMuRGVyZWYoMjAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShoZWlnaHQpOwogICAgICAgICAgICB0aGlzLl9YMTEuWFNldE5vcm1hbEhpbnRzKGRpc3BsYXksIHdpbmRvdywgc2l6ZUhpbnRzKTsKICAgICAgICB9CiAgICAgICAgdGhpcy5zZXRBbHdheXNPblRvcCA9IGZ1bmN0aW9uIHNldEFsd2F5c09uVG9wKGRpc3BsYXksIHJvb3RXaW5kb3csIHdpbmRvdykKICAgICAgICB7CiAgICAgICAgICAgIHZhciB3bU5ldFdtU3RhdGUgPSB0aGlzLl9YMTEuWEludGVybkF0b20oZGlzcGxheSwgdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoJ19ORVRfV01fU1RBVEUnKSwgMSk7CiAgICAgICAgICAgIHZhciB3bVN0YXRlQWJvdmUgPSB0aGlzLl9YMTEuWEludGVybkF0b20oZGlzcGxheSwgdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoJ19ORVRfV01fU1RBVEVfQUJPVkUnKSwgMSk7CgogICAgICAgICAgICB2YXIgeGNsaWVudCA9IHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKDk2KTsKICAgICAgICAgICAgeGNsaWVudC5EZXJlZigwLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzMpOyAgICAgICAgICAgICAgICAgICAvLyBDbGllbnRNZXNzYWdlIHR5cGUK", 16000);
	memcpy_s(_monitorinfo + 16000, 10484, "ICAgICAgICAgICAgeGNsaWVudC5EZXJlZig0OCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDMyKTsgICAgICAgICAgICAgICAgICAvLyBGb3JtYXQgMzIKICAgICAgICAgICAgd21OZXRXbVN0YXRlLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHhjbGllbnQuRGVyZWYoNDAsIDgpLnRvQnVmZmVyKCkpOyAvLyBtZXNzYWdlX3R5cGUKICAgICAgICAgICAgeGNsaWVudC5EZXJlZig1NiwgOCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKF9ORVRfV01fU1RBVEVfQUREKTsgICAvLyBkYXRhLmxbMF0KICAgICAgICAgICAgd21TdGF0ZUFib3ZlLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHhjbGllbnQuRGVyZWYoNjQsIDgpLnRvQnVmZmVyKCkpOyAvLyBkYXRhLmxbMV0KCiAgICAgICAgICAgIHdpbmRvdy5wb2ludGVyQnVmZmVyKCkuY29weSh4Y2xpZW50LkRlcmVmKDMyLCA4KS50b0J1ZmZlcigpKTsgICAgICAgLy8gd2luZG93CiAgICAgICAgICAgIHRoaXMuX1gxMS5YU2VuZEV2ZW50KGRpc3BsYXksIHJvb3RXaW5kb3csIDAsIFN1YnN0cnVjdHVyZVJlZGlyZWN0TWFzayB8IFN1YnN0cnVjdHVyZU5vdGlmeU1hc2ssIHhjbGllbnQpOwogICAgICAgIH0KICAgICAgICB0aGlzLmhpZGVXaW5kb3dJY29uID0gZnVuY3Rpb24gaGlkZVdpbmRvd0ljb24oZGlzcGxheSwgcm9vdFdpbmRvdywgd2luZG93KQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHdtTmV0V21TdGF0ZSA9IHRoaXMuX1gxMS5YSW50ZXJuQXRvbShkaXNwbGF5LCB0aGlzLl9nbS5DcmVhdGVWYXJpYWJsZSgnX05FVF9XTV9TVEFURScpLCAxKTsKICAgICAgICAgICAgdmFyIHdtU3RhdGVTa2lwID0gdGhpcy5fWDExLlhJbnRlcm5BdG9tKGRpc3BsYXksIHRoaXMuX2dtLkNyZWF0ZVZhcmlhYmxlKCdfTkVUX1dNX1NUQVRFX1NLSVBfVEFTS0JBUicpLCAxKTsKCiAgICAgICAgICAgIHZhciB4Y2xpZW50ID0gdGhpcy5fZ20uQ3JlYXRlVmFyaWFibGUoOTYpOwogICAgICAgICAgICB4Y2xpZW50LkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgzMyk7ICAgICAgICAgICAgICAgICAgIC8vIENsaWVudE1lc3NhZ2UgdHlwZQogICAgICAgICAgICB4Y2xpZW50LkRlcmVmKDQ4LCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMzIpOyAgICAgICAgICAgICAgICAgIC8vIEZvcm1hdCAzMgogICAgICAgICAgICB3bU5ldFdtU3RhdGUucG9pbnRlckJ1ZmZlcigpLmNvcHkoeGNsaWVudC5EZXJlZig0MCwgOCkudG9CdWZmZXIoKSk7IC8vIG1lc3NhZ2VfdHlwZQogICAgICAgICAgICB4Y2xpZW50LkRlcmVmKDU2LCA4KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoX05FVF9XTV9TVEFURV9BREQpOyAgIC8vIGRhdGEubFswXQogICAgICAgICAgICB3bVN0YXRlU2tpcC5wb2ludGVyQnVmZmVyKCkuY29weSh4Y2xpZW50LkRlcmVmKDY0LCA4KS50b0J1ZmZlcigpKTsgIC8vIGRhdGEubFsxXQoKICAgICAgICAgICAgd2luZG93LnBvaW50ZXJCdWZmZXIoKS5jb3B5KHhjbGllbnQuRGVyZWYoMzIsIDgpLnRvQnVmZmVyKCkpOyAgICAgICAvLyB3aW5kb3cKICAgICAgICAgICAgdGhpcy5fWDExLlhTZW5kRXZlbnQoZGlzcGxheSwgcm9vdFdpbmRvdywgMCwgU3Vic3RydWN0dXJlUmVkaXJlY3RNYXNrIHwgU3Vic3RydWN0dXJlTm90aWZ5TWFzaywgeGNsaWVudCk7CiAgICAgICAgfQoKICAgICAgICB0aGlzLmdldEluZm8gPSBmdW5jdGlvbiBnZXRJbmZvKCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBpbmZvID0gdGhpczsKICAgICAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgICAgIHJldC5wYXJlbnQgPSB0aGlzOwoKICAgICAgICAgICAgaWYgKCFwcm9jZXNzLmVudi5YQVVUSE9SSVRZIHx8ICFwcm9jZXNzLmVudi5ESVNQTEFZKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgeGluZm8gPSB0aGlzLmdldFhJbmZvKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRVaWQocmVxdWlyZSgndXNlci1zZXNzaW9ucycpLndob2FtaSgpKSk7CiAgICAgICAgICAgICAgICBwcm9jZXNzLnNldGVudignWEFVVEhPUklUWScsIHhpbmZvLnhhdXRob3JpdHkpOwogICAgICAgICAgICAgICAgcHJvY2Vzcy5zZXRlbnYoJ0RJU1BMQVknLCB4aW5mby5kaXNwbGF5KTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIGRpc3BsYXkgPSBpbmZvLl9YMTEuWE9wZW5EaXNwbGF5KGluZm8uX2dtLkNyZWF0ZVZhcmlhYmxlKHByb2Nlc3MuZW52LkRJU1BMQVkpKTsKICAgICAgICAgICAgaWYgKGRpc3BsYXkuVmFsID09IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnL3Zhci90bXAvYWdlbnRTbGF2ZScsICdYT3BlbkRpc3BsYXkgRmFpbGVkJywgeyBmbGFnczogJ2EnIH0pOwogICAgICAgICAgICAgICAgcmV0Ll9yZWooJ1hPcGVuRGlzcGxheSBGYWlsZWQnKTsKICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIHNjcmVlbkNvdW50ID0gaW5mby5fWDExLlhTY3JlZW5Db3VudChkaXNwbGF5KS5WYWw7CiAgICAgICAgICAgIHZhciBpZm8gPSBbXTsKICAgICAgICAgICAgZm9yKHZhciBpPTA7aTxzY3JlZW5Db3VudDsrK2kpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBzY3JlZW4gPSBpbmZvLl9YMTEuWFNjcmVlbk9mRGlzcGxheShkaXNwbGF5LCBpKTsKICAgICAgICAgICAgICAgIGlmby5wdXNoKHsgbGVmdDogMCwgdG9wOiAwLCByaWdodDogaW5mby5fWDExLlhEaXNwbGF5V2lkdGgoZGlzcGxheSwgaSkuVmFsLCBib3R0b206IGluZm8uX1gxMS5YRGlzcGxheUhlaWdodChkaXNwbGF5LCBpKS5WYWwsIHNjcmVlbjogc2NyZWVuLCBzY3JlZW5JZDogaSwgZGlzcGxheTogZGlzcGxheSB9KTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXQuX3JlcyhpZm8pOwoKICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH0KICAgICAgICB0aGlzLmdldFhJbmZvID0gZnVuY3Rpb24gZ2V0WEluZm8oY29uc29sZXVpZCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciByZXQgPSBudWxsOwogICAgICAgICAgICB2YXIgdW5hbWUgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuZ2V0VXNlcm5hbWUoY29uc29sZXVpZCk7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgicHMgIiArIChwcm9jZXNzLnBsYXRmb3JtID09ICdmcmVlYnNkJz8iLWF4ICI6IiIpICsgIi1lIC1vIHVzZXIiICsgKHByb2Nlc3MucGxhdGZvcm09PSdsaW51eCc/Ijo5OTkiOiIiKSArICIgLW8gdHR5IC1vIGNvbW1hbmQgfCBncmVwIFggfCBhd2sgJ3sgc3BsaXQoJDAsIGEsIFwiLWF1dGhcIik7IHNwbGl0KGFbMl0sIGIsIFwiIFwiKTsgaWYoJDE9PVwiIiArIHVuYW1lICsgIlwiICYmIGJbMV0hPVwiXCIpIHsgcHJpbnRmIFwiJXMsJXMsJXNcIiwkMSwkMixiWzFdIH0gfSdcbmV4aXRcbiIpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICB2YXIgdG9rZW5zID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkuc3BsaXQoJywnKTsKICAgICAgICAgICAgaWYgKHRva2Vucy5sZW5ndGggPT0gMykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0ID0geyB0dHk6IHRva2Vuc1sxXSwgeGF1dGhvcml0eTogdG9rZW5zWzJdIH07CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmIChyZXQgPT0gbnVsbCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gVGhpcyBMaW51eCBEaXN0cm8gZG9lcyBub3Qgc3Bhd24gYW4gWFNlcnZlciBpbnN0YW5jZSBpbiB0aGUgdXNlciBzZXNzaW9uLCB0aGF0IHNwZWNpZmllcyB0aGUgWEFVVEhPUklUWS4KICAgICAgICAgICAgICAgIC8vIFNvIHdlJ3JlIGdvaW5nIHRvIGJydXRlIGZvcmNlIGl0LCBieSBlbnVtZXJhdGluZyBhbGwgcHJvY2Vzc2VzIG93bmVkIGJ5IHRoaXMgdXNlciwgYW5kIGluc3BlY3QgdGhlIGVudmlyb25tZW50IHZhcmlhYmxlcwogICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJwcyAiICsgKHByb2Nlc3MucGxhdGZvcm09PSdmcmVlYnNkJz8iLWF4ICI6IiIpICsgIi1lIC1vIHBpZCAtbyB1c2VyIHwgZ3JlcCAiICsgdW5hbWUgKyAiIHwgYXdrICd7IHByaW50ICQxIH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICAgICAgdmFyIGxpbmVzID0gY2hpbGQuc3Rkb3V0LnN0ci5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgIGZvcih2YXIgbiBpbiBsaW5lcykKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgbG4gPSBsaW5lc1tuXS50cmltKCk7CiAgICAgICAgICAgICAgICAgICAgaWYobG4ubGVuZ3RoPjApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgZSA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRFbnZGcm9tUGlkKGxuKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYoZS5YQVVUSE9SSVRZICYmIGUuRElTUExBWSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0ID0geyB0dHk6ICc/JywgeGF1dGhvcml0eTogZS5YQVVUSE9SSVRZLCBkaXNwbGF5OiBlLkRJU1BMQVkgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmKHJldCA9PSBudWxsKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIC8vIFdlIGNvdWxkbid0IGZpbmQgWEFVVEhPUklUWSBhbmQgRElTUExBWSwgc28gYXMgYSBsYXN0IGRpdGNoIGVmZm9ydCwgbGV0cyBqdXN0IGxvb2sgZm9yIERJU1BMQVkKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBuIGluIGxpbmVzKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxuID0gbGluZXNbbl0udHJpbSgpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAobG4ubGVuZ3RoID4gMCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGUgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuZ2V0RW52RnJvbVBpZChsbik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZS5ESVNQTEFZKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldCA9IHsgdHR5OiAnPycsIGRpc3BsYXk6IGUuRElTUExBWSB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIFdlIG5lZWQgdG8gZmluZCAkRElTUExBWSBieSBsb29raW5nIGF0IGFsbCB0aGUgcHJvY2Vzc2VzIHJ1bm5pbmcgb24gdGhlIHNhbWUgdHR5IGFzIHRoZSBYU2VydmVyIGluc3RhbmNlIGZvciB0aGlzIHVzZXIgc2Vzc2lvbgogICAgICAgICAgICAgICAgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInBzIC1lIC1vIHR0eSAtbyBwaWQgLW8gdXNlcjo5OTk5IHwgZ3JlcCAiICsgcmV0LnR0eSArICIgfCBncmVwICIgKyB1bmFtZSArICIgfCBhd2sgJ3sgcHJpbnQgJDIgfScgXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICAgICAgdmFyIGxpbmVzID0gY2hpbGQuc3Rkb3V0LnN0ci5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgIHZhciBwcywgcHN4LCB2LCB2cyA9IDA7CiAgICAgICAgICAgICAgICBmb3IodmFyIHggaW4gbGluZXMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYobGluZXNbeF0udHJpbSgpLmxlbmd0aD4wKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBzID0gcmVxdWlyZSgnZnMnKS5yZWFkRmlsZVN5bmMoJy9wcm9jLycgKyBsaW5lc1t4XS50cmltKCkgKyAnL2Vudmlyb24nKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBjYXRjaChwc2UpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIHZzID0gMDsKICAgICAgICAgICAgICAgICAgICAgICAgZm9yKHBzeD0wO3BzeDxwcy5sZW5ndGg7Kytwc3gpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChwc1twc3hdID09IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdiA9IHBzLnNsaWNlKHZzLCBwc3gpLnRvU3RyaW5nKCkuc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodlswXSA9PSAnRElTUExBWScpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuZGlzcGxheSA9IHZbMV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdnMgPSBwc3ggKyAxOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICB9OwogICAgfQogICAgZWxzZQogICAgewogICAgICAgIHRocm93IChwcm9jZXNzLnBsYXRmb3JtICsgJyBub3Qgc3VwcG9ydGVkJyk7CiAgICB9Cn0KCm1vZHVsZS5leHBvcnRzID0gbmV3IG1vbml0b3JpbmZvKCk7CgoKCv==", 10484);
	ILibBase64DecodeEx((unsigned char*)_monitorinfo, 26484, (unsigned char*)_monitorinfo + 26484);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "monitor-info"); duk_push_string(ctx, _monitorinfo + 26484);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_monitorinfo);


	// service-host. Refer to modules/service-host.js
	char *_servicehost = ILibMemory_Allocate(30948, 0, NULL, NULL);
	memcpy_s(_servicehost + 0, 17684, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgp2YXIgU0VSVklDRV9XSU4zMiA9IDB4MDAwMDAwMTAgfCAweDAwMDAwMDIwOwp2YXIgU0VSVklDRV9TVEFURSA9IHsgU1RPUFBFRDogMHgwMDAwMDAwMSwgU0VSVklDRV9TVEFSVF9QRU5ESU5HOiAweDAwMDAwMDAyLCBTRVJWSUNFX1NUT1BfUEVORElORzogMHgwMDAwMDAwMywgUlVOTklORzogMHgwMDAwMDAwNCB9Owp2YXIgU0VSVklDRV9BQ0NFUFQgPSB7IFNFUlZJQ0VfQUNDRVBUX1NUT1A6IDB4MDAwMDAwMDEsIFNFUlZJQ0VfQUNDRVBUX1NIVVRET1dOOiAweDAwMDAwMDA0LCBTRVJWSUNFX0FDQ0VQVF9QT1dFUkVWRU5UOiAweDAwMDAwMDQwLCBTRVJWSUNFX0FDQ0VQVF9TRVNTSU9OQ0hBTkdFOiAweDAwMDAwMDgwIH07Cgp2YXIgU0VSVklDRV9DT05UUk9MID0geyBTRVJWSUNFX0NPTlRST0xfU0hVVERPV046IDB4MDAwMDAwMDUsIFNFUlZJQ0VfQ09OVFJPTF9TVE9QOiAweDAwMDAwMDAxLCBTRVJWSUNFX0NPTlRST0xfUE9XRVJFVkVOVDogMHgwMDAwMDAwRCwgU0VSVklDRV9DT05UUk9MX1NFU1NJT05DSEFOR0U6IDB4MDAwMDAwMEV9Owp2YXIgU0VTU0lPTl9DSEFOR0VfVFlQRSA9CnsKICAgIFdUU19DT05TT0xFX0NPTk5FQ1Q6IDB4MSwKICAgIFdUU19DT05TT0xFX0RJU0NPTk5FQ1Q6IDB4MiwKICAgIFdUU19SRU1PVEVfQ09OTkVDVDogMHgzLAogICAgV1RTX1JFTU9URV9ESVNDT05ORUNUOiAweDQsCiAgICBXVFNfU0VTU0lPTl9MT0dPTjogMHg1LAogICAgV1RTX1NFU1NJT05fTE9HT0ZGOiAweDYsCiAgICBXVFNfU0VTU0lPTl9MT0NLOiAweDcsCiAgICBXVFNfU0VTU0lPTl9VTkxPQ0s6IDB4OCwKICAgIFdUU19TRVNTSU9OX1JFTU9URV9DT05UUk9MOiAweDksCiAgICBXVFNfU0VTU0lPTl9DUkVBVEU6IDB4YSwKICAgIFdUU19TRVNTSU9OX1RFUk1JTkFURTogMHhiCn07CgoKdmFyIE5PX0VSUk9SID0gMDsKCnZhciBzZXJ2aWNlTWFuYWdlciA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpOwoKZnVuY3Rpb24gc2VydmljZUhvc3Qoc2VydmljZU5hbWUpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3NlcnZpY2UtaG9zdCc7CiAgICB2YXIgZW1pdHRlclV0aWxzID0gcmVxdWlyZSgnZXZlbnRzJykuaW5oZXJpdHModGhpcyk7CiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ3NlcnZpY2VTdGFydCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdzZXJ2aWNlU3RvcCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdub3JtYWxTdGFydCcpOwogICAgZW1pdHRlclV0aWxzLmNyZWF0ZUV2ZW50KCdzZXNzaW9uJyk7CiAgICBlbWl0dGVyVXRpbHMuY3JlYXRlRXZlbnQoJ3Bvd2VyU3RhdGVDaGFuZ2UnKTsKCiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgewogICAgICAgIHRoaXMuR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKICAgICAgICB0aGlzLkFkdmFwaSA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0FkdmFwaTMyLmRsbCcpOwogICAgICAgIHRoaXMuQWR2YXBpLkNyZWF0ZU1ldGhvZCh7IG1ldGhvZDogJ1N0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQScsIHRocmVhZERpc3BhdGNoOiAxIH0pOwogICAgICAgIHRoaXMuQWR2YXBpLkNyZWF0ZU1ldGhvZCgnUmVnaXN0ZXJTZXJ2aWNlQ3RybEhhbmRsZXJFeEEnKTsKICAgICAgICB0aGlzLkFkdmFwaS5DcmVhdGVNZXRob2QoJ1NldFNlcnZpY2VTdGF0dXMnKTsKICAgICAgICB0aGlzLktlcm5lbDMyID0gdGhpcy5HTS5DcmVhdGVOYXRpdmVQcm94eSgnS2VybmVsMzIuZGxsJyk7CiAgICAgICAgdGhpcy5LZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldExhc3RFcnJvcicpOwoKICAgICAgICB0aGlzLk9sZTMyID0gdGhpcy5HTS5DcmVhdGVOYXRpdmVQcm94eSgnT2xlMzIuZGxsJyk7CiAgICAgICAgdGhpcy5PbGUzMi5DcmVhdGVNZXRob2QoJ0NvSW5pdGlhbGl6ZUV4Jyk7CiAgICAgICAgdGhpcy5PbGUzMi5DcmVhdGVNZXRob2QoJ0NvVW5pbml0aWFsaXplJyk7CgogICAgICAgIHRoaXMuX1NlcnZpY2VOYW1lID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSh0eXBlb2YgKHNlcnZpY2VOYW1lKSA9PSAnc3RyaW5nJyA/IHNlcnZpY2VOYW1lIDogc2VydmljZU5hbWUubmFtZSk7CiAgICAgICAgdGhpcy5fU2VydmljZU1haW4gPSB0aGlzLkdNLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjaygyKTsKICAgICAgICB0aGlzLl9TZXJ2aWNlTWFpbi5QYXJlbnQgPSB0aGlzOwogICAgICAgIHRoaXMuX1NlcnZpY2VNYWluLkdNID0gdGhpcy5HTTsKICAgICAgICB0aGlzLl9TZXJ2aWNlTWFpbi5vbignR2xvYmFsQ2FsbGJhY2snLCBmdW5jdGlvbiBvbkdsb2JhbENhbGxiYWNrKGFyZ2MsIGFyZ3YpCiAgICAgICAgewogICAgICAgICAgICAvL1RvRG86IENoZWNrIHRvIG1ha2Ugc3VyZSB0aGlzIGlzIGZvciB1cwoKICAgICAgICAgICAgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKDI4KTsKICAgICAgICAgICAgLy90eXBlZGVmIHN0cnVjdCBfU0VSVklDRV9TVEFUVVMgewogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3U2VydmljZVR5cGU7CiAgICAgICAgICAgIC8vICAgIERXT1JEICAgZHdDdXJyZW50U3RhdGU7CiAgICAgICAgICAgIC8vICAgIERXT1JEICAgZHdDb250cm9sc0FjY2VwdGVkOwogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3V2luMzJFeGl0Q29kZTsKICAgICAgICAgICAgLy8gICAgRFdPUkQgICBkd1NlcnZpY2VTcGVjaWZpY0V4aXRDb2RlOwogICAgICAgICAgICAvLyAgICBEV09SRCAgIGR3Q2hlY2tQb2ludDsKICAgICAgICAgICAgLy8gICAgRFdPUkQgICBkd1dhaXRIaW50OwogICAgICAgICAgICAvL30gU0VSVklDRV9TVEFUVVMsICpMUFNFUlZJQ0VfU1RBVFVTOwoKICAgICAgICAgICAgLy8gSW5pdGlhbGlzZSBzZXJ2aWNlIHN0YXR1cwogICAgICAgICAgICB0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1cy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoU0VSVklDRV9XSU4zMik7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX1NUQVRFLlNFUlZJQ0VfU1RPUFBFRCwgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzSGFuZGxlID0gdGhpcy5QYXJlbnQuQWR2YXBpLlJlZ2lzdGVyU2VydmljZUN0cmxIYW5kbGVyRXhBKHRoaXMuUGFyZW50Ll9TZXJ2aWNlTmFtZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VDb250cm9sSGFuZGxlciwgdGhpcy5QYXJlbnQuR00uU3Rhc2hPYmplY3QodGhpcy5QYXJlbnQuX1NlcnZpY2VDb250cm9sSGFuZGxlcikpOwogICAgICAgICAgICBpZih0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZS5WYWwgPT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KDEpOwogICAgICAgICAgICB9CgogICAgICAgICAgICAvLyBTZXJ2aWNlIGlzIHN0YXJ0aW5nCiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX1NUQVRFLlNFUlZJQ0VfU1RBUlRfUEVORElORywgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50LkFkdmFwaS5TZXRTZXJ2aWNlU3RhdHVzKHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzSGFuZGxlLCB0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1cyk7CgogICAgICAgICAgICAvLyBTZXJ2aWNlIHJ1bm5pbmcKICAgICAgICAgICAgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKFNFUlZJQ0VfU1RBVEUuUlVOTklORywgNCk7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Ll9TZXJ2aWNlU3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShTRVJWSUNFX0FDQ0VQVC5TRVJWSUNFX0FDQ0VQVF9TVE9QIHwgU0VSVklDRV9BQ0NFUFQuU0VSVklDRV9BQ0NFUFRfUE9XRVJFVkVOVCB8IFNFUlZJQ0VfQUNDRVBULlNFUlZJQ0VfQUNDRVBUX1NFU1NJT05DSEFOR0UsIDgpOwogICAgICAgICAgICB0aGlzLlBhcmVudC5BZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMpOwoKICAgICAgICAgICAgdGhpcy5QYXJlbnQuT2xlMzIuQ29Jbml0aWFsaXplRXgoMCwgMik7CiAgICAgICAgICAgIHRoaXMuUGFyZW50Lm9uKCd+JywgZnVuY3Rpb24gT25TZXJ2aWNlSG9zdEZpbmFsaXplcigpCiAgICAgICAgICAgIHsgICAgICAgICAgICAKICAgICAgICAgICAgICAgIHZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwogICAgICAgICAgICAgICAgdmFyIEFkdmFwaSA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdBZHZhcGkzMi5kbGwnKTsKICAgICAgICAgICAgICAgIEFkdmFwaS5DcmVhdGVNZXRob2QoJ1NldFNlcnZpY2VTdGF0dXMnKTsKCiAgICAgICAgICAgICAgICBLZXJuZWwzMiA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0tlcm5lbDMyLmRsbCcpOwogICAgICAgICAgICAgICAgS2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdHZXRMYXN0RXJyb3InKTsKCiAgICAgICAgICAgICAgICB2YXIgc3RhdHVzID0gR00uQ3JlYXRlVmFyaWFibGUoMjgpOwoKICAgICAgICAgICAgICAgIC8vIFNlcnZpY2Ugd2FzIHN0b3BwZWQKICAgICAgICAgICAgICAgIHN0YXR1cy50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoU0VSVklDRV9XSU4zMik7CiAgICAgICAgICAgICAgICBzdGF0dXMudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKDB4MDAwMDAwMDEsIDQpOwogICAgICAgICAgICAgICAgc3RhdHVzLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgwLCA4KTsKCiAgICAgICAgICAgICAgICBBZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLl9TZXJ2aWNlU3RhdHVzSGFuZGxlLCBzdGF0dXMpOwoKICAgICAgICAgICAgICAgIHRoaXMuT2xlMzIuQ29VbmluaXRpYWxpemUoKTsKICAgICAgICAgICAgfSk7CgogICAgICAgICAgICB0aGlzLlBhcmVudC5lbWl0KCdzZXJ2aWNlU3RhcnQnKTsKICAgICAgICB9KTsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIgPSB0aGlzLkdNLkdldEdlbmVyaWNHbG9iYWxDYWxsYmFjayg0KTsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIuUGFyZW50ID0gdGhpczsKICAgICAgICB0aGlzLl9TZXJ2aWNlQ29udHJvbEhhbmRsZXIuR00gPSB0aGlzLkdNOwogICAgICAgIHRoaXMuX1NlcnZpY2VDb250cm9sSGFuZGxlci5vbignR2xvYmFsQ2FsbGJhY2snLCBmdW5jdGlvbiBvblNlcnZpY2VDb250cm9sSGFuZGxlcihjb2RlLCBldmVudFR5cGUsIGV2ZW50RGF0YSwgY29udGV4dCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBqID0gdGhpcy5QYXJlbnQuR00uVW5zdGFzaE9iamVjdChjb250ZXh0KTsKICAgICAgICAgICAgaWYgKGogIT0gbnVsbCAmJiBqID09IHRoaXMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHN3aXRjaCAoY29kZS5WYWwpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY2FzZSBTRVJWSUNFX0NPTlRST0wuU0VSVklDRV9DT05UUk9MX1NIVVRET1dOOgogICAgICAgICAgICAgICAgICAgIGNhc2UgU0VSVklDRV9DT05UUk9MLlNFUlZJQ0VfQ09OVFJPTF9TVE9QOgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLlBhcmVudC5lbWl0KCdzZXJ2aWNlU3RvcCcpOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICAgICAgY2FzZSBTRVJWSUNFX0NPTlRST0wuU0VSVklDRV9DT05UUk9MX1NFU1NJT05DSEFOR0U6CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uSWQgPSBldmVudERhdGEuRGVyZWYoNCwgNCkudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKTsKICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGV2ZW50VHlwZS5WYWwpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgU0VTU0lPTl9DSEFOR0VfVFlQRS5XVFNfU0VTU0lPTl9MT0dPTjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgU0VTU0lPTl9DSEFOR0VfVFlQRS5XVFNfU0VTU0lPTl9MT0dPRkY6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICB0aGlzLlBhcmVudC5BZHZhcGkuU2V0U2VydmljZVN0YXR1cyh0aGlzLlBhcmVudC5fU2VydmljZVN0YXR1c0hhbmRsZSwgdGhpcy5QYXJlbnQuX1NlcnZpY2VTdGF0dXMpOwogICAgICAgICAgICB9CiAgICAgICAgfSk7CiAgICB9CgogICAgaWYgKHNlcnZpY2VOYW1lKSB7IHRoaXMuX1NlcnZpY2VPcHRpb25zID0gdHlwZW9mIChzZXJ2aWNlTmFtZSkgPT0gJ29iamVjdCcgPyBzZXJ2aWNlTmFtZSA6IHsgbmFtZTogc2VydmljZU5hbWUgfTsgfQogICAgZWxzZQogICAgewogICAgICAgIHRocm93ICgnTXVzdCBzcGVjaWZ5IGVpdGhlciBTZXJ2aWNlTmFtZSBvciBPcHRpb25zJyk7CiAgICB9CiAgICBpZiAoIXRoaXMuX1NlcnZpY2VPcHRpb25zLnNlcnZpY2VQYXRoKQogICAgewogICAgICAgIHRoaXMuX1NlcnZpY2VPcHRpb25zLnNlcnZpY2VQYXRoID0gcHJvY2Vzcy5leGVjUGF0aDsKICAgIH0KICAgIAogICAgdGhpcy5ydW4gPSBmdW5jdGlvbiBydW4oKQogICAgewogICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtICE9ICd3aW4zMicpCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIFNJR1RFUk1fSGFuZGxlciA9IGZ1bmN0aW9uIF9TSUdURVJNX0hhbmRsZXIoKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIF9TSUdURVJNX0hhbmRsZXIucGFyZW50LmVtaXQoJ3NlcnZpY2VTdG9wJyk7DQogICAgICAgICAgICB9Ow0KICAgICAgICAgICAgU0lHVEVSTV9IYW5kbGVyLnBhcmVudCA9IHRoaXM7DQogICAgICAgICAgICBwcm9jZXNzLm9uKCdTSUdURVJNJywgU0lHVEVSTV9IYW5kbGVyKTsNCiAgICAgICAgfQoKICAgICAgICBmb3IodmFyIGkgPSAwOyBpPHByb2Nlc3MuYXJndi5sZW5ndGg7ICsraSkKICAgICAgICB7CiAgICAgICAgICAgIHN3aXRjaChwcm9jZXNzLmFyZ3ZbaV0pCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGNhc2UgJy1pbnN0YWxsJzoKICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3N2Y01hbmFnZXIpIHsgdGhpcy5fc3ZjTWFuYWdlciA9IG5ldyBzZXJ2aWNlTWFuYWdlcigpOyB9CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmluc3RhbGxTZXJ2aWNlKHRoaXMuX1NlcnZpY2VPcHRpb25zKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGUpOwogICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIGluc3RhbGxlZCcpOwogICAgICAgICAgICAgICAgICAgIHByb2Nlc3MuZXhpdCgpOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnLXVuaW5zdGFsbCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl9zdmNNYW5hZ2VyKSB7IHRoaXMuX3N2Y01hbmFnZXIgPSBuZXcgc2VydmljZU1hbmFnZXIoKTsgfQogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fc3ZjTWFuYWdlci51bmluc3RhbGxTZXJ2aWNlKHRoaXMuX1NlcnZpY2VPcHRpb25zKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGUpOwogICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoKTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIHVuaW5zdGFsbGVkJyk7CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdzdGFydCc6CiAgICAgICAgICAgICAgICBjYXNlICctZCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gIT0gJ3dpbjMyJykgeyBicmVhazsgfQogICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fc3ZjTWFuYWdlcikgeyB0aGlzLl9zdmNNYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7IH0KICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmdldFNlcnZpY2UodGhpcy5fU2VydmljZU9wdGlvbnMubmFtZSkuc3RhcnQoKTsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyh0aGlzLl9TZXJ2aWNlT3B0aW9ucy5uYW1lICsgJyBzdGFydGluZy4uLicpOwogICAgICAgICAgICAgICAgICAgIHByb2Nlc3MuZXhpdCgpOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnc3RvcCc6CiAgICAgICAgICAgICAgICBjYXNlICctcyc6CiAgICAgICAgICAgICAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gIT0gJ3dpbjMyJykgeyBicmVhazsgfQogICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fc3ZjTWFuYWdlcikgeyB0aGlzLl9zdmNNYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7IH0KICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdmNNYW5hZ2VyLmdldFNlcnZpY2UodGhpcy5fU2VydmljZU9wdGlvbnMubmFtZSkuc3RvcCgpOwogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgKyAnIHN0b3BwaW5nLi4uJyk7CiAgICAgICAgICAgICAgICAgICAgcHJvY2Vzcy5leGl0KCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CgogICAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHNlcnZpY2VUYWJsZSA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUoNCAqIHRoaXMuR00uUG9pbnRlclNpemUpOwogICAgICAgICAgICB0aGlzLl9TZXJ2aWNlTmFtZS5wb2ludGVyQnVmZmVyKCkuY29weShzZXJ2aWNlVGFibGUudG9CdWZmZXIoKSk7CiAgICAgICAgICAgIHRoaXMuX1NlcnZpY2VNYWluLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHNlcnZpY2VUYWJsZS50b0J1ZmZlcigpLCB0aGlzLkdNLlBvaW50ZXJTaXplKTsKICAgICAgICAgICAgdGhpcy5fc3NjZCA9IHRoaXMuQWR2YXBpLlN0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQShzZXJ2aWNlVGFibGUpOwogICAgICAgICAgICB0aGlzLl9zc2NkLnBhcmVudCA9IHRoaXM7CiAgICAgICAgICAgIHRoaXMuX3NzY2Qub24oJ2RvbmUnLCBmdW5jdGlvbiBPblN0YXJ0U2VydmljZUN0cmxEaXNwYXRjaGVyQShyZXRWYWwpIHsKICAgICAgICAgICAgICAgIGlmIChyZXRWYWwuVmFsID09IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW1pdCgnbm9ybWFsU3RhcnQnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgZWxzZSBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIG1vZHVsZU5hbWUgPSB0aGlzLl9TZXJ2aWNlT3B0aW9ucyA/IHRoaXMuX1NlcnZpY2VPcHRpb25zLm5hbWUgOiBwcm9jZXNzLmV4ZWNQYXRoLnN1YnN0cmluZygxICsgcHJvY2Vzcy5leGVjUGF0aC5sYXN0SW5kZXhPZignLycpKTsKICAgICAgICAgICAgdmFyIHBsYXRmb3JtVHlwZSA9IHJlcXVpcmUoJ3Byb2Nlc3MtbWFuYWdlcicpLmdldFByb2Nlc3NJbmZvKDEpLk5hbWU7CgogICAgICAgICAgICBpZiAocGxhdGZvcm1UeXBlICE9ICdzeXN0ZW1kJyAmJiBwbGF0Zm9ybVR5cGUgIT0gJ2luaXQnKQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5lbWl0KCdub3JtYWxTdGFydCcpOyAvLyBVbmtub3duIFBsYXRmb3JtIFR5cGUsIHNvIHdlJ3JlIHByb2JhYmx5IG5vdCBhIHNlcnZpY2UNCiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQuc3Rkb3V0LnJlc3VsdCA9ICcnOw0KICAgICAgICAgICAgICAgIHRoaXMuX2NoZWNrcGlkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnJlc3VsdCArPSBjaHVuay50b1N0cmluZygpOyB9KTsNCiAgICAgICAgICAgICAgICBzd2l0Y2gocGxhdGZvcm1UeXBlKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnaW5pdCc6DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9jaGVja3BpZC5zdGRpbi53cml0ZSgnc2VydmljZSAnICsgbW9kdWxlTmFtZSArICIgc3RhdHVzIHwgYXdrICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7DQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnc3lzdGVtZCc6DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9jaGVja3BpZC5zdGRpbi53cml0ZSgnc3lzdGVtY3RsIHN0YXR1cyAnICsgbW9kdWxlTmFtZSArICIgfCBncmVwICdNYWluIFBJRDonIHwgYXdrICd7cHJpbnQgJDN9J1xuZXhpdFxuIik7DQogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgdGhpcy5fY2hlY2twaWQud2FpdEV4aXQoKTsNCg0KICAgICAgICAgICAgICAgIGlmKHRoaXMuX2NoZWNrcGlkLnN0ZG91dC5yZXN1bHQgIT0gJycgJiYgcGFyc2VJbnQodGhpcy5fY2hlY2twaWQuc3Rkb3V0LnJlc3VsdCkgPT0gcHJvY2Vzcy5waWQpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ3NlcnZpY2VT", 16000);
	memcpy_s(_servicehost + 16000, 1684, "dGFydCcpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ25vcm1hbFN0YXJ0Jyk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpCiAgICAgICAgewogICAgICAgICAgICAvLyBGaXJzdCBsZXQncyBmZXRjaCBhbGwgdGhlIFBJRHMgb2YgcnVubmluZyBzZXJ2aWNlcwogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCBsaXN0XG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciB0b2tlbnMsIGk7CiAgICAgICAgICAgIHZhciBwID0ge307CiAgICAgICAgICAgIGZvciAoaSA9IDE7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJ1x0Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdICYmIHRva2Vuc1swXSAhPSAnLScpIHsgcFt0b2tlbnNbMF1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmKHBbcHJvY2Vzcy5waWQudG9TdHJpbmcoKV0pCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIFdlIGFyZSBhIHNlcnZpY2UhCiAgICAgICAgICAgICAgICB0aGlzLmVtaXQoJ3NlcnZpY2VTdGFydCcpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhpcy5lbWl0KCdub3JtYWxTdGFydCcpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfTsKfQoKbW9kdWxlLmV4cG9ydHMgPSBzZXJ2aWNlSG9zdDsKbW9kdWxlLmV4cG9ydHMuY3JlYXRlID0gZnVuY3Rpb24gY3JlYXRlKG9wdGlvbnMpDQp7DQogICAgcmV0dXJuIChuZXcgc2VydmljZUhvc3Qob3B0aW9ucykpOw0KfTs=", 1684);
	ILibBase64DecodeEx((unsigned char*)_servicehost, 17684, (unsigned char*)_servicehost + 17684);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "service-host"); duk_push_string(ctx, _servicehost + 17684);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_servicehost);


	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addModule('process-manager', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgp2YXIgR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTsKCi8vIFVzZWQgb24gV2luZG93cyBhbmQgTGludXggdG8gZ2V0IGluZm9ybWF0aW9uIGFib3V0IHJ1bm5pbmcgcHJvY2Vzc2VzCmZ1bmN0aW9uIHByb2Nlc3NNYW5hZ2VyKCkgewogICAgdGhpcy5fT2JqZWN0SUQgPSAncHJvY2Vzcy1tYW5hZ2VyJzsgLy8gVXNlZCBmb3IgZGVidWdnaW5nLCBhbGxvd3MgeW91IHRvIGdldCB0aGUgb2JqZWN0IHR5cGUgYXQgcnVudGltZS4KICAgIAogICAgLy8gU2V0dXAgdGhlIHBsYXRmb3JtIHNwZWNpZmljIGNhbGxzLgogICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQogICAgewogICAgICAgIGNhc2UgJ3dpbjMyJzoKICAgICAgICAgICAgdGhpcy5fa2VybmVsMzIgPSBHTS5DcmVhdGVOYXRpdmVQcm94eSgna2VybmVsMzIuZGxsJyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnR2V0TGFzdEVycm9yJyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnQ3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90Jyk7CiAgICAgICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnUHJvY2VzczMyRmlyc3QnKTsKICAgICAgICAgICAgdGhpcy5fa2VybmVsMzIuQ3JlYXRlTWV0aG9kKCdQcm9jZXNzMzJOZXh0Jyk7CiAgICAgICAgICAgIGJyZWFrOwoJY2FzZSAnZnJlZWJzZCc6CiAgICAgICAgY2FzZSAnbGludXgnOgogICAgICAgIGNhc2UgJ2Rhcndpbic6CiAgICAgICAgICAgIHRoaXMuX2NoaWxkUHJvY2VzcyA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKTsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgdGhyb3cgKHByb2Nlc3MucGxhdGZvcm0gKyAnIG5vdCBzdXBwb3J0ZWQnKTsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CiAgICB0aGlzLmVudW1lcmF0ZVByb2Nlc3NlcyA9IGZ1bmN0aW9uIGVudW1lcmF0ZVByb2Nlc3NlcygpCiAgICB7CiAgICAgICAgdmFyIHByb21pc2UgPSByZXF1aXJlKCdwcm9taXNlJyk7CiAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgdGhpcy5nZXRQcm9jZXNzZXMoZnVuY3Rpb24gKHBzLCBwcm9tKSB7IHByb20uX3Jlcyhwcyk7IH0sIHJldCk7CiAgICAgICAgcmV0dXJuIChyZXQpOwogICAgfQogICAgLy8gUmV0dXJuIGEgb2JqZWN0IG9mOiBwaWQgLT4gcHJvY2VzcyBpbmZvcm1hdGlvbi4KICAgIHRoaXMuZ2V0UHJvY2Vzc2VzID0gZnVuY3Rpb24gZ2V0UHJvY2Vzc2VzKGNhbGxiYWNrKQogICAgewogICAgICAgIHN3aXRjaChwcm9jZXNzLnBsYXRmb3JtKQogICAgICAgIHsKICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgIHRocm93ICgnRW51bWVyYXRpbmcgcHJvY2Vzc2VzIG9uICcgKyBwcm9jZXNzLnBsYXRmb3JtICsgJyBub3Qgc3VwcG9ydGVkJyk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnd2luMzInOiAvLyBXaW5kb3dzIHByb2Nlc3NlcwogICAgICAgICAgICAgICAgdmFyIHJldFZhbCA9IHt9OwogICAgICAgICAgICAgICAgdmFyIGggPSB0aGlzLl9rZXJuZWwzMi5DcmVhdGVUb29saGVscDMyU25hcHNob3QoMiwgMCk7CiAgICAgICAgICAgICAgICB2YXIgaW5mbyA9IEdNLkNyZWF0ZVZhcmlhYmxlKDMwNCk7CiAgICAgICAgICAgICAgICBpbmZvLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgzMDQsIDApOwogICAgICAgICAgICAgICAgdmFyIG5leHRQcm9jZXNzID0gdGhpcy5fa2VybmVsMzIuUHJvY2VzczMyRmlyc3QoaCwgaW5mbyk7CiAgICAgICAgICAgICAgICB3aGlsZSAobmV4dFByb2Nlc3MuVmFsKSAKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXRWYWxbaW5mby5EZXJlZig4LCA0KS50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgwKV0gPSB7IHBpZDogaW5mby5EZXJlZig4LCA0KS50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgwKSwgY21kOiBpbmZvLkRlcmVmKEdNLlBvaW50ZXJTaXplID09IDQgPyAzNiA6IDQ0LCAyNjApLlN0cmluZyB9OwogICAgICAgICAgICAgICAgICAgIG5leHRQcm9jZXNzID0gdGhpcy5fa2VybmVsMzIuUHJvY2VzczMyTmV4dChoLCBpbmZvKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGlmIChjYWxsYmFjaykgeyBjYWxsYmFjay5hcHBseSh0aGlzLCBbcmV0VmFsXSk7IH0KICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICBjYXNlICdsaW51eCc6IC8vIExpbnV4IHByb2Nlc3NlcwogICAgICAgICAgICAgICAgaWYgKCF0aGlzLl9wc3ApIHsgdGhpcy5fcHNwID0ge307IH0KICAgICAgICAgICAgICAgIHZhciBwID0gdGhpcy5fY2hpbGRQcm9jZXNzLmV4ZWNGaWxlKCIvYmluL3BzIiwgWyJwcyIsICItdXhhIl0sIHsgdHlwZTogdGhpcy5fY2hpbGRQcm9jZXNzLlNwYXduVHlwZXMuVEVSTSB9KTsKICAgICAgICAgICAgICAgIHRoaXMuX3BzcFtwLnBpZF0gPSBwOwogICAgICAgICAgICAgICAgcC5QYXJlbnQgPSB0aGlzOwogICAgICAgICAgICAgICAgcC5wcyA9ICcnOwogICAgICAgICAgICAgICAgcC5jYWxsYmFjayA9IGNhbGxiYWNrOwogICAgICAgICAgICAgICAgcC5hcmdzID0gW107CiAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMTsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7ICsraSkgeyBwLmFyZ3MucHVzaChhcmd1bWVudHNbaV0pOyB9CiAgICAgICAgICAgICAgICBwLm9uKCdleGl0JywgZnVuY3Rpb24gb25HZXRQcm9jZXNzZXMoKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGRlbGV0ZSB0aGlzLlBhcmVudC5fcHNwW3RoaXMucGlkXTsgCiAgICAgICAgICAgICAgICAgICAgdmFyIHJldFZhbCA9IHt9LCBsaW5lcyA9IHRoaXMucHMuc3BsaXQoJ1x4MERceDBBJyksIGtleSA9IHt9LCBrZXlpID0gMDsKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpIGluIGxpbmVzKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHRva2VucyA9IGxpbmVzW2ldLnNwbGl0KCcgJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0b2tlbkxpc3QgPSBbXTsKICAgICAgICAgICAgICAgICAgICAgICAgZm9yKHZhciB4IGluIHRva2VucykKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGkgPT0gMCAmJiB0b2tlbnNbeF0pIHsga2V5W3Rva2Vuc1t4XV0gPSBrZXlpKys7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpID4gMCAmJiB0b2tlbnNbeF0pIHsgdG9rZW5MaXN0LnB1c2godG9rZW5zW3hdKTt9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGkgPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodG9rZW5MaXN0W2tleS5QSURdKSB7IHJldFZhbFt0b2tlbkxpc3Rba2V5LlBJRF1dID0geyBwaWQ6IGtleS5QSUQsIHVzZXI6IHRva2VuTGlzdFtrZXkuVVNFUl0sIGNtZDogdG9rZW5MaXN0W2tleS5DT01NQU5EXSB9OyB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuY2FsbGJhY2spCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmFyZ3MudW5zaGlmdChyZXRWYWwpOwogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmNhbGxiYWNrLmFwcGx5KHRoaXMucGFyZW50LCB0aGlzLmFyZ3MpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgcC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5wYXJlbnQucHMgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnZGFyd2luJzoKICAgICAgICAgICAgICAgIHZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwogICAgICAgICAgICAgICAgdmFyIHAgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOwogICAgICAgICAgICAgICAgcC5wbSA9IHRoaXM7CiAgICAgICAgICAgICAgICBwLmNhbGxiYWNrID0gY2FsbGJhY2s7CiAgICAgICAgICAgICAgICBwLmFyZ3MgPSBbXTsKICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAxOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgKytpKSB7IHAuYXJncy5wdXNoKGFyZ3VtZW50c1tpXSk7IH0KICAgICAgICAgICAgICAgIHAuY2hpbGQgPSB0aGlzLl9jaGlsZFByb2Nlc3MuZXhlY0ZpbGUoIi9iaW4vcHMiLCBbInBzIiwgIi14YSJdKTsKICAgICAgICAgICAgICAgIHAuY2hpbGQucHJvbWlzZSA9IHA7CiAgICAgICAgICAgICAgICBwLmNoaWxkLnN0ZG91dC5wcyA9ICcnOwogICAgICAgICAgICAgICAgcC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5wcyArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgIHAuY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBsaW5lcyA9IHRoaXMuc3Rkb3V0LnBzLnNwbGl0KCdcbicpOwogICAgICAgICAgICAgICAgICAgIHZhciBwaWRYID0gbGluZXNbMF0uc3BsaXQoJ1BJRCcpWzBdLmxlbmd0aCArIDM7CiAgICAgICAgICAgICAgICAgICAgdmFyIGNtZFggPSBsaW5lc1swXS5zcGxpdCgnQ01EJylbMF0ubGVuZ3RoOwogICAgICAgICAgICAgICAgICAgIHZhciByZXQgPSB7fTsKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMTsgaSA8IGxpbmVzLmxlbmd0aDsgKytpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGxpbmVzW2ldLmxlbmd0aCA+IDApCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldFtsaW5lc1tpXS5zdWJzdHJpbmcoMCwgcGlkWCkudHJpbSgpXSA9IHsgcGlkOiBsaW5lc1tpXS5zdWJzdHJpbmcoMCwgcGlkWCkudHJpbSgpLCBjbWQ6IGxpbmVzW2ldLnN1YnN0cmluZyhjbWRYKSB9OwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVzKHJldCk7CiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIHAudGhlbihmdW5jdGlvbiAocHMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5hcmdzLnVuc2hpZnQocHMpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuY2FsbGJhY2suYXBwbHkodGhpcy5wbSwgdGhpcy5hcmdzKTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgYnJlYWs7CgkgICAgY2FzZSAnZnJlZWJzZCc6CiAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkZXJyLnN0ciA9ICcnOwoJCWNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjKSB7dGhpcy5zdHIgKz0gYy50b1N0cmluZygpO30pOwoJCWNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjKSB7IHRoaXMuc3RyICs9IGMudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgicHMgLXhhIHwgYXdrICd7IHByaW50ZiBcIiVzXCIsICQxOyAkMT1cIlwiOyAkMj1cIlwiOyAkMz1cIlwiOyAkND1cIlwiOyBwcmludGYgXCIlc1xcblwiLCAkMDsgfScgfCBhd2sgJ3sgcHJpbnRmIFwiJXNcIiwgJDE7ICQxPVwiXCI7IHByaW50ZiBcIiVzXFxuXCIsICQwOyB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoJCQoJCXZhciB0bXA7CgkJdmFyIHJldCA9IFtdOwoJCXZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpLnNwbGl0KCdcbicpOwoJCWZvcih2YXIgaSBpbiBsaW5lcykKCQl7CgkJCXRtcCA9IHtwaWQ6IGxpbmVzW2ldLnNwbGl0KCcgJykuc2hpZnQoKX07CgkJCXRtcFsnY21kJ10gPSBsaW5lc1tpXS5zdWJzdHJpbmcodG1wLnBpZC5sZW5ndGggKyAxKTsKCQkJdG1wWydwaWQnXSA9IHBhcnNlSW50KHRtcFsncGlkJ10pOwoJCQlpZighaXNOYU4odG1wWydwaWQnXSkpCgkJCXsKCQkJCXJldC5wdXNoKHRtcCk7CgkJCX0KCQl9CgkJaWYoY2FsbGJhY2spIHsgY2FsbGJhY2suYXBwbHkodGhpcywgW3JldF0pOyB9CgkJYnJlYWs7CiAgICAgICAgfQogICAgfTsKCiAgICAvLyBHZXQgaW5mb3JtYXRpb24gYWJvdXQgYSBzcGVjaWZpYyBwcm9jZXNzIG9uIExpbnV4CiAgICB0aGlzLmdldFByb2Nlc3NJbmZvID0gZnVuY3Rpb24gZ2V0UHJvY2Vzc0luZm8ocGlkKQogICAgewogICAgICAgIHN3aXRjaChwcm9jZXNzLnBsYXRmb3JtKQogICAgICAgIHsKICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgIHRocm93ICgnZ2V0UHJvY2Vzc0luZm8oKSBub3Qgc3VwcG9ydGVkIGZvciAnICsgcHJvY2Vzcy5wbGF0Zm9ybSk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgY2FzZSAnbGludXgnOgogICAgICAgICAgICAgICAgdmFyIHN0YXR1cyA9IHJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvcHJvYy8nICsgcGlkICsgJy9zdGF0dXMnKTsKICAgICAgICAgICAgICAgIHZhciBpbmZvID0ge307CiAgICAgICAgICAgICAgICB2YXIgbGluZXMgPSBzdGF0dXMudG9TdHJpbmcoKS5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgIGZvcih2YXIgaSBpbiBsaW5lcykKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJzonKTsKICAgICAgICAgICAgICAgICAgICBpZiAodG9rZW5zLmxlbmd0aCA+IDEpIHsgdG9rZW5zWzFdID0gdG9rZW5zWzFdLnRyaW0oKTsgfQogICAgICAgICAgICAgICAgICAgIGluZm9bdG9rZW5zWzBdXSA9IHRva2Vuc1sxXTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIHJldHVybiAoaW5mbyk7CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICB9CiAgICB9Owp9Cgptb2R1bGUuZXhwb3J0cyA9IG5ldyBwcm9jZXNzTWFuYWdlcigpOwo=', 'base64').toString());"); 
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addModule('linux-dbus', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnRyeSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShBcnJheS5wcm90b3R5cGUsICJwZWVrIiwgeyB2YWx1ZTogZnVuY3Rpb24gKCkgeyByZXR1cm4gKHRoaXMubGVuZ3RoID4gMCA/IHRoaXNbdGhpcy5sZW5ndGggLSAxXSA6IHVuZGVmaW5lZCk7IH0gfSk7IH0gY2F0Y2ggKGUpIHsgfQoKCgpmdW5jdGlvbiBkYnVzKGFkZHJlc3MsIHVpZCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAnbGludXgtZGJ1cyc7CiAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbCh0aGlzLCB0cnVlKQogICAgICAgIC5jcmVhdGVFdmVudCgnc2lnbmFsJyk7CiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgInVpZCIsIHsgdmFsdWU6IHVpZCB9KTsKICAgIHRoaXMuX2NoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCIvYmluL3NoIiwgWyJzaCJdLCB7IHR5cGU6IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5TcGF3blR5cGVzLlRFUk0sIHVpZDogdWlkID09IG51bGwgPyAtMSA6IHVpZCB9KTsKICAgIHRoaXMuX2NoaWxkLnN0ZGluLndyaXRlKCdkYnVzLW1vbml0b3IgLS1zZXNzaW9uICJ0eXBlPVwnc2lnbmFsXCcsIGludGVyZmFjZT1cJycgKyBhZGRyZXNzICsgJ1wnIiB8ICggd2hpbGUgcmVhZCBYOyBkbyBlY2hvICIkWCI7IGRvbmUgKVxuJyk7CiAgICB0aGlzLl9jaGlsZC5zdGRvdXQuZGJ1cyA9IHRoaXM7CiAgICB0aGlzLl9jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspCiAgICB7CiAgICAgICAgLy8gUGFyc2UgREJVUyBEYXRhCiAgICAgICAgaWYgKCF0aGlzLnJlYWR5KSB7IHRoaXMucmVhZHkgPSB0cnVlOyByZXR1cm47IH0KCiAgICAgICAgdmFyIGxpbmVzID0gW107CiAgICAgICAgdmFyIHRva2VucyA9IGNodW5rLnRvU3RyaW5nKCkuc3BsaXQoJ1xyXG4nKTsKICAgICAgICBmb3IgKHZhciBpIGluIHRva2VucykKICAgICAgICB7CiAgICAgICAgICAgIGlmICh0b2tlbnNbaV0gPT0gJycpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIEVuZCBvZiByZWNvcmQKICAgICAgICAgICAgICAgIHRoaXMuZGJ1cy5wcmVQYXJzZVJlY29yZHMobGluZXMpOwogICAgICAgICAgICAgICAgbGluZXMgPSBbXTsKICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGxpbmVzLnB1c2godG9rZW5zW2ldKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0pOwogICAgdGhpcy5wcmVQYXJzZVJlY29yZHMgPSBmdW5jdGlvbiAobGluZXMpCiAgICB7CiAgICAgICAgdmFyIHJlY29yZCA9IFtdOwogICAgICAgIGZvciAodmFyIGkgaW4gbGluZXMpCiAgICAgICAgewogICAgICAgICAgICBpZihsaW5lc1tpXS5zdGFydHNXaXRoKCdzaWduYWwgJykpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmKHJlY29yZC5sZW5ndGg+MCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcnNlUmVjb3JkcyhyZWNvcmQpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmVjb3JkID0gW107CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmVjb3JkLnB1c2gobGluZXNbaV0pOwogICAgICAgIH0KICAgICAgICBpZiAocmVjb3JkLmxlbmd0aCA+IDApCiAgICAgICAgewogICAgICAgICAgICB0aGlzLnBhcnNlUmVjb3JkcyhyZWNvcmQpOwogICAgICAgIH0KICAgIH0KICAgIHRoaXMucGFyc2VSZWNvcmRzID0gZnVuY3Rpb24gKGxpbmVzKQogICAgewogICAgICAgIGlmIChsaW5lc1swXS5zdGFydHNXaXRoKCdzaWduYWwgJykpCiAgICAgICAgewogICAgICAgICAgICB2YXIgc2lnbmFsID0ge307CiAgICAgICAgICAgIHZhciBzaWd0b2tlbnMgPSBsaW5lc1swXS5zcGxpdCgnICcpOwogICAgICAgICAgICBzaWd0b2tlbnMuc2hpZnQoKTsKCiAgICAgICAgICAgIGZvciAodmFyIGkgaW4gc2lndG9rZW5zKSB7CiAgICAgICAgICAgICAgICB2YXIgc2lnaXRlbXMgPSBzaWd0b2tlbnNbaV0uc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgIGlmIChzaWdpdGVtcy5sZW5ndGggPT0gMikgewogICAgICAgICAgICAgICAgICAgIHNpZ25hbFtzaWdpdGVtc1swXV0gPSBzaWdpdGVtc1sxXTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgbGluZXMuc2hpZnQoKTsKICAgICAgICAgICAgc2lnbmFsLmRhdGEgPSBsaW5lczsKCiAgICAgICAgICAgIHRoaXMucGFyc2VTaWduYWwoc2lnbmFsKTsKICAgICAgICB9CiAgICB9CiAgICB0aGlzLnBhcnNlU2lnbmFsID0gZnVuY3Rpb24oc2lnbmFsKQogICAgewogICAgICAgIHZhciBkYXRhID0gc2lnbmFsLmRhdGE7CiAgICAgICAgc2lnbmFsLmRhdGEgPSBbXTsKCiAgICAgICAgZm9yKHZhciBpPTA7IGk8ZGF0YS5sZW5ndGg7ICsraSkKICAgICAgICB7CiAgICAgICAgICAgIGlmIChkYXRhW2ldLnN0YXJ0c1dpdGgoJ2FycmF5ICcpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBzaWduYWwuZGF0YS5wdXNoKFtdKTsKICAgICAgICAgICAgICAgIGZvcihpPWkrMTsgaTxkYXRhLmxlbmd0aDsgKytpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRoaXMucGFyc2VTaWduYWwyKGRhdGFbaV0sIHNpZ25hbC5kYXRhLnBlZWsoKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aGlzLnBhcnNlU2lnbmFsMihkYXRhW2ldLCBzaWduYWwuZGF0YSk7CiAgICAgICAgICAgIH0KICAgICAgICB9CgogICAgICAgIHRoaXMuZW1pdCgnc2lnbmFsJywgc2lnbmFsKTsKICAgIH0KICAgIHRoaXMucGFyc2VTaWduYWwyID0gZnVuY3Rpb24gKGlucHV0U3RyLCBvdXRBcnJheSkKICAgIHsKICAgICAgICBpZihpbnB1dFN0ci5zdGFydHNXaXRoKCdzdHJpbmcgJykpCiAgICAgICAgewogICAgICAgICAgICBvdXRBcnJheS5wdXNoKEpTT04ucGFyc2UoaW5wdXRTdHIuc2xpY2UoNykpKTsKICAgICAgICB9CiAgICAgICAgZWxzZSBpZihpbnB1dFN0ci5zdGFydHNXaXRoKCdib29sZWFuICcpKQogICAgICAgIHsKICAgICAgICAgICAgb3V0QXJyYXkucHVzaChKU09OLnBhcnNlKGlucHV0U3RyLnNsaWNlKDgpKSk7CiAgICAgICAgfQogICAgfQp9Cgptb2R1bGUuZXhwb3J0cyA9IGRidXM7Cv==', 'base64').toString());");
#endif

	char *_servicemanager = ILibMemory_Allocate(205072, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 117184, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgpmdW5jdGlvbiBleHRyYWN0RmlsZU5hbWUoZmlsZVBhdGgpCnsKICAgIGlmICh0eXBlb2YgKGZpbGVQYXRoKSA9PSAnc3RyaW5nJykKICAgIHsKICAgICAgICB2YXIgdG9rZW5zID0gZmlsZVBhdGguc3BsaXQoJ1xcJykuam9pbignLycpLnNwbGl0KCcvJyk7CiAgICAgICAgdmFyIG5hbWU7CgogICAgICAgIHdoaWxlICgobmFtZSA9IHRva2Vucy5wb3AoKSkgPT0gJycpOwogICAgICAgIHJldHVybiAobmFtZSk7CiAgICB9CiAgICBlbHNlCiAgICB7CiAgICAgICAgcmV0dXJuKGZpbGVQYXRoLm5ld05hbWUpCiAgICB9Cn0KZnVuY3Rpb24gZXh0cmFjdEZpbGVTb3VyY2UoZmlsZVBhdGgpCnsKICAgIHJldHVybiAodHlwZW9mIChmaWxlUGF0aCkgPT0gJ3N0cmluZycgPyBmaWxlUGF0aCA6IGZpbGVQYXRoLnNvdXJjZSk7Cn0KCmZ1bmN0aW9uIHBhcnNlU2VydmljZVN0YXR1cyh0b2tlbikKewogICAgdmFyIGogPSB7fTsKICAgIHZhciBzZXJ2aWNlVHlwZSA9IHRva2VuLkRlcmVmKDAsIDQpLkludFZhbDsKICAgIGouaXNGaWxlU3lzdGVtRHJpdmVyID0gKChzZXJ2aWNlVHlwZSAmIDB4MDAwMDAwMDIpID09IDB4MDAwMDAwMDIpOwogICAgai5pc0tlcm5lbERyaXZlciA9ICgoc2VydmljZVR5cGUgJiAweDAwMDAwMDAxKSA9PSAweDAwMDAwMDAxKTsKICAgIGouaXNTaGFyZWRQcm9jZXNzID0gKChzZXJ2aWNlVHlwZSAmIDB4MDAwMDAwMjApID09IDB4MDAwMDAwMjApOwogICAgai5pc093blByb2Nlc3MgPSAoKHNlcnZpY2VUeXBlICYgMHgwMDAwMDAxMCkgPT0gMHgwMDAwMDAxMCk7CiAgICBqLmlzSW50ZXJhY3RpdmUgPSAoKHNlcnZpY2VUeXBlICYgMHgwMDAwMDEwMCkgPT0gMHgwMDAwMDEwMCk7CiAgICBzd2l0Y2ggKHRva2VuLkRlcmVmKCgxICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpCiAgICB7CiAgICAgICAgY2FzZSAweDAwMDAwMDA1OgogICAgICAgICAgICBqLnN0YXRlID0gJ0NPTlRJTlVFX1BFTkRJTkcnOwogICAgICAgICAgICBicmVhazsKICAgICAgICBjYXNlIDB4MDAwMDAwMDY6CiAgICAgICAgICAgIGouc3RhdGUgPSAnUEFVU0VfUEVORElORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwNzoKICAgICAgICAgICAgai5zdGF0ZSA9ICdQQVVTRUQnOwogICAgICAgICAgICBicmVhazsKICAgICAgICBjYXNlIDB4MDAwMDAwMDQ6CiAgICAgICAgICAgIGouc3RhdGUgPSAnUlVOTklORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwMjoKICAgICAgICAgICAgai5zdGF0ZSA9ICdTVEFSVF9QRU5ESU5HJzsKICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAweDAwMDAwMDAzOgogICAgICAgICAgICBqLnN0YXRlID0gJ1NUT1BfUEVORElORyc7CiAgICAgICAgICAgIGJyZWFrOwogICAgICAgIGNhc2UgMHgwMDAwMDAwMToKICAgICAgICAgICAgai5zdGF0ZSA9ICdTVE9QUEVEJzsKICAgICAgICAgICAgYnJlYWs7CiAgICB9CiAgICB2YXIgY29udHJvbHNBY2NlcHRlZCA9IHRva2VuLkRlcmVmKCgyICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCk7CiAgICBqLmNvbnRyb2xzQWNjZXB0ZWQgPSBbXTsKICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAwMTApID09IDB4MDAwMDAwMTApCiAgICB7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5EQUREJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5EUkVNT1ZFJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5ERU5BQkxFJyk7CiAgICAgICAgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9ORVRCSU5ERElTQUJMRScpOwogICAgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAwOCkgPT0gMHgwMDAwMDAwOCkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX1BBUkFNQ0hBTkdFJyk7IH0KICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAwMDIpID09IDB4MDAwMDAwMDIpIHsgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9QQVVTRScpOyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX0NPTlRJTlVFJyk7IH0KICAgIGlmICgoY29udHJvbHNBY2NlcHRlZCAmIDB4MDAwMDAxMDApID09IDB4MDAwMDAxMDApIHsgai5jb250cm9sc0FjY2VwdGVkLnB1c2goJ1NFUlZJQ0VfQ09OVFJPTF9QUkVTSFVURE9XTicpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDA0KSA9PSAweDAwMDAwMDA0KSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfU0hVVERPV04nKTsgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAwMSkgPT0gMHgwMDAwMDAwMSkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX1NUT1AnKTsgfQogICAgaWYgKChjb250cm9sc0FjY2VwdGVkICYgMHgwMDAwMDAyMCkgPT0gMHgwMDAwMDAyMCkgeyBqLmNvbnRyb2xzQWNjZXB0ZWQucHVzaCgnU0VSVklDRV9DT05UUk9MX0hBUkRXQVJFUFJPRklMRUNIQU5HRScpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDQwKSA9PSAweDAwMDAwMDQwKSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfUE9XRVJFVkVOVCcpOyB9CiAgICBpZiAoKGNvbnRyb2xzQWNjZXB0ZWQgJiAweDAwMDAwMDgwKSA9PSAweDAwMDAwMDgwKSB7IGouY29udHJvbHNBY2NlcHRlZC5wdXNoKCdTRVJWSUNFX0NPTlRST0xfU0VTU0lPTkNIQU5HRScpOyB9CiAgICBqLnBpZCA9IHRva2VuLkRlcmVmKCg3ICogNCksIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCk7CiAgICByZXR1cm4gKGopOwp9CgppZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykKewogICAgZnVuY3Rpb24gZ2V0T1NWZXJzaW9uKCkKICAgIHsKICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInN3X3ZlcnMgfCBncmVwIFByb2R1Y3RWZXJzaW9uIHwgYXdrICd7IHByaW50ICQyIH0nXG5leGl0XG4iKTsKICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAvL2NoaWxkLnN0ZG91dC5zdHIgPSAnMTAuOSc7CgogICAgICAgIHZhciByZXQgPSB7IHJhdzogY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkuc3BsaXQoJy4nKSwgdG9TdHJpbmc6IGZ1bmN0aW9uICgpIHsgcmV0dXJuICh0aGlzLnJhdy5qb2luKCcuJykpOyB9IH07CiAgICAgICAgcmV0LmNvbXBhcmVUbyA9IGZ1bmN0aW9uIGNvbXBhcmVUbyh2YWwpCiAgICAgICAgewogICAgICAgICAgICB2YXIgcmF3ID0gKHR5cGVvZiAodmFsKSA9PSAnc3RyaW5nJykgPyB2YWwuc3BsaXQoJy4nKSA6IHZhbC5yYXc7IGlmICghcmF3KSB7IHRocm93ICgnSW52YWxpZCBwYXJhbWV0ZXInKTsgfQogICAgICAgICAgICB2YXIgc2VsZiA9IHRoaXMucmF3LmpvaW4oJy4nKS5zcGxpdCgnLicpOwoKICAgICAgICAgICAgdmFyIHIgPSBudWxsLCBzID0gbnVsbDsKICAgICAgICAgICAgd2hpbGUgKHNlbGYubGVuZ3RoID4gMCAmJiByYXcubGVuZ3RoID4gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcyA9IHBhcnNlSW50KHNlbGYuc2hpZnQoKSk7IHIgPSBwYXJzZUludChyYXcuc2hpZnQoKSk7CiAgICAgICAgICAgICAgICBpZiAocyA8IHIpIHsgcmV0dXJuICgtMSk7IH0KICAgICAgICAgICAgICAgIGlmIChzID4gcikgeyByZXR1cm4gKDEpOyB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgaWYgKHNlbGYubGVuZ3RoID09IHJhdy5sZW5ndGgpIHsgcmV0dXJuICgwKTsgfQogICAgICAgICAgICBpZiAoc2VsZi5sZW5ndGggPCByYXcubGVuZ3RoKSB7IHJldHVybiAoLTEpOyB9IGVsc2UgeyByZXR1cm4gKDEpOyB9ICAgIAogICAgICAgIH0KICAgICAgICByZXR1cm4gKHJldCk7CiAgICB9OwoKCiAgICBmdW5jdGlvbiBmZXRjaFBsaXN0KGZvbGRlciwgbmFtZSwgdXNlcmlkKQogICAgewogICAgICAgIGlmIChmb2xkZXIuZW5kc1dpdGgoJy8nKSkgeyBmb2xkZXIgPSBmb2xkZXIuc3Vic3RyaW5nKDAsIGZvbGRlci5sZW5ndGggLSAxKTsgfQogICAgICAgIHZhciByZXQgPSB7IG5hbWU6IG5hbWUsIGNsb3NlOiBmdW5jdGlvbiAoKSB7IH0sIF91aWQ6IHVzZXJpZCB9OwogICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKGZvbGRlciArICcvJyArIG5hbWUgKyAnLnBsaXN0JykpCiAgICAgICAgewogICAgICAgICAgICAvLyBCZWZvcmUgd2UgdGhyb3cgaW4gdGhlIHRvd2VsLCBsZXQncyBlbnVtZXJhdGUgYWxsIHRoZSBwbGlzdCBmaWxlcywgYW5kIHNlZSBpZiBvbmUgaGFzIGEgbWF0Y2hpbmcgbGFiZWwKICAgICAgICAgICAgdmFyIGZpbGVzID0gcmVxdWlyZSgnZnMnKS5yZWFkZGlyU3luYyhmb2xkZXIpOwogICAgICAgICAgICBmb3IgKHZhciBmaWxlIGluIGZpbGVzKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAiICsgZm9sZGVyICsgJy8nICsgZmlsZXNbZmlsZV0gKyAiIHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7IHNwbGl0KCQwLCBhLCBcIjxrZXk+TGFiZWw8L2tleT5cIik7IHNwbGl0KGFbMl0sIGIsIFwiPC9zdHJpbmc+XCIpOyBzcGxpdChiWzFdLCBjLCBcIjxzdHJpbmc+XCIpOyBwcmludCBjWzJdOyB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgaWYgKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpID09IG5hbWUpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0Lm5hbWUgPSBmaWxlc1tmaWxlXS5lbmRzV2l0aCgnLnBsaXN0JykgPyBmaWxlc1tmaWxlXS5zdWJzdHJpbmcoMCwgZmlsZXNbZmlsZV0ubGVuZ3RoIC0gNikgOiBmaWxlc1tmaWxlXTsKICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0LCAnYWxpYXMnLCB7IHZhbHVlOiBuYW1lIH0pOwogICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXQsICdwbGlzdCcsIHsgdmFsdWU6IGZvbGRlciArICcvJyArIGZpbGVzW2ZpbGVdIH0pOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChyZXQubmFtZSA9PSBuYW1lKSB7IHRocm93ICgnICcgKyAoZm9sZGVyLnNwbGl0KCdMYXVuY2hEYWVtb24nKS5sZW5ndGg+MSA/ICdMYXVuY2hEYWVtb24nIDogJ0xhdW5jaEFnZW50JykgKyAnICgnICsgbmFtZSArICcpIE5PVCBGT1VORCcpOyB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXQsICdwbGlzdCcsIHsgdmFsdWU6IGZvbGRlciArICcvJyArIG5hbWUgKyAnLnBsaXN0JyB9KTsKICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldCwgJ2FsaWFzJywgewogICAgICAgICAgICAgICAgdmFsdWU6IChmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgIiArIHJldC5wbGlzdCArICIgfCB0ciAnXG4nICdcLicgfCBhd2sgJ3sgc3BsaXQoJDAsIGEsIFwiPGtleT5MYWJlbDwva2V5PlwiKTsgc3BsaXQoYVsyXSwgYiwgXCI8L3N0cmluZz5cIik7IHNwbGl0KGJbMV0sIGMsIFwiPHN0cmluZz5cIik7IHByaW50IGNbMl07IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgICAgICAgICAgfSkoKQogICAgICAgICAgICB9KTsKICAgICAgICB9CiAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldCwgJ2RhZW1vbicsIHsgdmFsdWU6IHJldC5wbGlzdC5zcGxpdCgnL0xhdW5jaERhZW1vbnMvJykubGVuZ3RoID4gMSA/IHRydWUgOiBmYWxzZSB9KTsKCiAgICAgICAgcmV0LmFwcFdvcmtpbmdEaXJlY3RvcnkgPSBmdW5jdGlvbiBhcHBXb3JraW5nRGlyZWN0b3J5KCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0ICIgKyB0aGlzLnBsaXN0ICsgIiB8IHRyICdcbicgJ1wuJyB8IGF3ayAneyBzcGxpdCgkMCwgYSwgXCI8a2V5PldvcmtpbmdEaXJlY3Rvcnk8L2tleT5cIik7IHNwbGl0KGFbMl0sIGIsIFwiPC9zdHJpbmc+XCIpOyBzcGxpdChiWzFdLCBjLCBcIjxzdHJpbmc+XCIpOyBwcmludCBjWzJdOyB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSBjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKTsKCiAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci5lbmRzV2l0aCgnLycpID8gY2hpbGQuc3Rkb3V0LnN0ci5zdWJzdHJpbmcoMCwgY2hpbGQuc3Rkb3V0LnN0ci5sZW5ndGggLSAxKSA6IGNoaWxkLnN0ZG91dC5zdHIpOwogICAgICAgIH07CiAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gYXBwTG9jYXRpb24oKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgIiArIHRoaXMucGxpc3QgKyAiIHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7IHNwbGl0KCQwLCBhLCBcIjxrZXk+UHJvZ3JhbUFyZ3VtZW50czwva2V5PlwiKTsgc3BsaXQoYVsyXSwgYiwgXCI8L3N0cmluZz5cIik7IHNwbGl0KGJbMV0sIGMsIFwiPHN0cmluZz5cIik7IHByaW50IGNbMl07IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgfTsKICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0LCAnX3J1bkF0TG9hZCcsIHsKICAgICAgICAgICAgdmFsdWU6IChmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAvLyBXZSBuZWVkIHRvIHNlZSBpZiB0aGlzIGlzIGFuIEF1dG8tU3RhcnRpbmcgc2VydmljZSwgaW4gb3JkZXIgdG8gZmlndXJlIG91dCBob3cgdG8gaW1wbGVtZW50ICdzdGFydCcKICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0ICIgKyByZXQucGxpc3QgKyAiIHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7IHNwbGl0KCQwLCBhLCBcIjxrZXk+UnVuQXRMb2FkPC9rZXk+XCIpOyBzcGxpdChhWzJdLCBiLCBcIi8+XCIpOyBzcGxpdChiWzFdLCBjLCBcIjxcIik7IHByaW50IGNbMl07IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpLnRvVXBwZXJDYXNlKCkgPT0gIlRSVUUiKTsKICAgICAgICAgICAgfSkoKQogICAgICAgIH0pOwogICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXQsICJfa2VlcEFsaXZlIiwgewogICAgICAgICAgICB2YWx1ZTogKGZ1bmN0aW9uICgpIHsKICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0ICIgKyByZXQucGxpc3QgKyAiIHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7c3BsaXQoJDAsIGEsIFwiPGtleT5LZWVwQWxpdmU8L2tleT5cIik7IHNwbGl0KGFbMl0sIGIsIFwiPFwiKTsgc3BsaXQoYlsyXSwgYywgXCI+XCIpOyAiKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCIgaWYoY1sxXT09XCJkaWN0XCIpeyBzcGxpdChhWzJdLCBkLCBcIjwvZGljdD5cIik7IGlmKHNwbGl0KGRbMV0sIHRydXZhbCwgXCI8dHJ1ZS8+XCIpPjEpIHsgc3BsaXQodHJ1dmFsWzFdLCBrbjEsIFwiPGtleT5cIik7IHNwbGl0KGtuMVsyXSwga24yLCBcIjwva2V5PlwiKTsgcHJpbnQga24yWzFdOyB9IH0iKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCIgZWxzZSB7IHNwbGl0KGNbMV0sIGthLCBcIi9cIik7IGlmKGthWzFdPT1cInRydWVcIikge3ByaW50IFwiQUxXQVlTXCI7fSB9IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsKICAgICAgICAgICAgfSkoKQogICAgICAgIH0pOwogICAgICAgIHJldC5nZXRQSUQgPSBmdW5jdGlvbiBnZXRQSUQodWlkLCBhc1N0cmluZykKICAgICAgICB7CiAgICAgICAgICAgIHZhciBvcHRpb25zID0gdW5kZWZpbmVkOwogICAgICAgICAgICB2YXIgY29tbWFuZDsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQoKICAgICAgICAgICAgaWYgKGdldE9TVmVyc2lvbigpLmNvbXBhcmVUbygnMTAuMTAnKSA8IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGNvbW1hbmQgPSAibGF1bmNoY3RsIGxpc3QgfCBncmVwICciICsgdGhpcy5hbGlhcyArICInIHwgYXdrICd7IGlmKCQzPT1cIiIgKyB0aGlzLmFsaWFzICsgIlwiKXtwcmludCAkMTt9fSdcbmV4aXRcbiI7CiAgICAgICAgICAgICAgICBvcHRpb25zID0geyB1aWQ6IHVpZCB9OwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgaWYgKHVpZCA9PSBudWxsKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSAnbGF1bmNoY3RsIHByaW50IHN5c3RlbSB8IGdyZXAgIicgKyB0aGlzLmFsaWFzICsgJyIgfCBhd2sgXCd7IGlmKHNwbGl0KCQwLCB0bXAsICIgIik9PTMpIHsgaWYoJDM9PSInICsgdGhpcy5hbGlhcyArICciKSB7IHByaW50ICQxOyB9IH19XCdcbmV4aXRcbic7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9ICdsYXVuY2hjdGwgcHJpbnQgZ3VpLycgKyB1aWQgKyAnIHwgZ3JlcCAiJyArIHRoaXMuYWxpYXMgKyAnIiB8IGF3ayBcJ3sgaWYoc3BsaXQoJDAsIHRtcCwgIiAiKT09MykgeyBpZigkMz09IicgKyB0aGlzLmFsaWFzICsgJyIpIHsgcHJpbnQgJDE7IH0gfX1cJ1xuZXhpdFxuJzsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddLCBvcHRpb25zKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKGNvbW1hbmQpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAgICAgaWYgKGFzU3RyaW5nID09IG51bGwgfHwgYXNTdHJpbmcgIT0gdHJ1ZSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0dXJuIChwYXJzZUludChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSkpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgICAgIH0KICAgICAgICB9OwogICAgICAgIHJldC5pc0xvYWRlZCA9IGZ1bmN0aW9uIGlzTG9hZGVkKHVpZCkKICAgICAgICB7CiAgICAgICAgICAgIGlmICh0aGlzLl91aWQgIT0gbnVsbCkgeyB1aWQgPSB0aGlzLl91aWQ7IH0KICAgICAgICAgICAgcmV0dXJuICh0aGlzLmdldFBJRCh1aWQsIHRydWUpICE9ICcnKTsKICAgICAgICB9OwogICAgICAgIHJldC5pc1J1bm5pbmcgPSBmdW5jdGlvbiBpc1J1bm5pbmcodWlkKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQogICAgICAgICAgICByZXR1", 16000);
	memcpy_s(_servicemanager + 16000, 101184, "cm4gKHRoaXMuZ2V0UElEKHVpZCkgPiAwKTsKICAgICAgICB9OwogICAgICAgIHJldC5pc01lID0gZnVuY3Rpb24gaXNNZSh1aWQpCiAgICAgICAgewogICAgICAgICAgICBpZiAodGhpcy5fdWlkICE9IG51bGwpIHsgdWlkID0gdGhpcy5fdWlkOyB9CiAgICAgICAgICAgIHJldHVybiAodGhpcy5nZXRQSUQodWlkKSA9PSBwcm9jZXNzLnBpZCk7CiAgICAgICAgfTsKICAgICAgICByZXQubG9hZCA9IGZ1bmN0aW9uIGxvYWQodWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHNlbGYgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuU2VsZigpOwogICAgICAgICAgICB2YXIgdmVyID0gZ2V0T1NWZXJzaW9uKCk7CiAgICAgICAgICAgIHZhciBvcHRpb25zID0gdW5kZWZpbmVkOwogICAgICAgICAgICB2YXIgY29tbWFuZCA9ICdsb2FkJzsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQoKICAgICAgICAgICAgaWYgKHRoaXMuZGFlbW9uKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZih1aWQhPW51bGwgfHwgdWlkIT0wKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRocm93ICgnTGF1bmNoRGFlbW9uIG11c3QgcnVuIGFzIHJvb3QnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmICh1aWQgPT0gbnVsbCkgeyB1aWQgPSBzZWxmOyB9CiAgICAgICAgICAgICAgICBpZih2ZXIuY29tcGFyZVRvKCcxMC4xMCcpIDwgMCAmJiB1aWQgIT0gc2VsZiAmJiBzZWxmICE9IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhyb3cgKCdPbiB0aGlzIHZlcnNpb24gb2YgTWFjT1MsIG11c3QgYmUgcm9vdCB0byBsb2FkIHRoaXMgc2VydmljZSBpbnRvIHRoZSBzcGVjaWZpZWQgdXNlciBzcGFjZScpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZSBpZiAodmVyLmNvbXBhcmVUbygnMTAuMTAnKSA8IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgb3B0aW9ucyA9IHsgdWlkOiB1aWQgfTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gJ2Jvb3RzdHJhcCBndWkvJyArIHVpZDsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddLCBvcHRpb25zKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5zdHIgPSAnJzsgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnbGF1bmNoY3RsICcgKyBjb21tYW5kICsgJyAnICsgdGhpcy5wbGlzdCArICdcblxleGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICB9OwogICAgICAgIHJldC51bmxvYWQgPSBmdW5jdGlvbiB1bmxvYWQodWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gbnVsbDsKICAgICAgICAgICAgdmFyIHYgPSBnZXRPU1ZlcnNpb24oKTsKICAgICAgICAgICAgdmFyIHNlbGYgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuU2VsZigpOwogICAgICAgICAgICB2YXIgb3B0aW9ucyA9IHVuZGVmaW5lZDsKICAgICAgICAgICAgdmFyIHVzZUJvb3RvdXQgPSBmYWxzZTsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQoKICAgICAgICAgICAgaWYodWlkIT1udWxsKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAodi5jb21wYXJlVG8oJzEwLjEwJykgPD0gMCAmJiBzZWxmID09IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgLy8gV2UgbXVzdCBzd2l0Y2ggdG8gdXNlciBjb250ZXh0IHRvIHVubG9hZCB0aGUgc2VydmljZQogICAgICAgICAgICAgICAgICAgIG9wdGlvbnMgPSB7IHVpZDogdWlkIH07CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYodi5jb21wYXJlVG8oJzEwLjEwJykgPiAwKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYoc2VsZiA9PSAwIHx8IHNlbGYgPT0gdWlkKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB1c2UgYm9vdG91dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlQm9vdG91dCA9IHRydWU7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBpbnN1ZmZpY2llbnQgYWNjZXNzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyAoJ05lZWRzIGVsZXZhdGVkIHByaXZpbGVnZXMnKQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZWxmID09IHVpZCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8ganVzdCB1bmxvYWQsIGJlY3Vhc2Ugd2UgYXJlIGFscmVhZHkgaW4gdGhlIHJpZ2h0IGNvbnRleHQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVzZUJvb3RvdXQgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIGluc3VmZmljaWVudCBhY2Nlc3MKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnTmVlZHMgZWxldmF0ZWQgcHJpdmlsZWdlcycpCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZihzZWxmID09IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYodi5jb21wYXJlVG8oJzEwLjEwJykgPiAwKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gdXNlIGJvb3RvdXQKICAgICAgICAgICAgICAgICAgICAgICAgdXNlQm9vdG91dCA9IHRydWU7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIC8vIGp1c3QgdW5sb2FkCiAgICAgICAgICAgICAgICAgICAgICAgIHVzZUJvb3RvdXQgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgLy8gSW5zdWZmaWNpZW50IGFjY2VzcwogICAgICAgICAgICAgICAgICAgIHRocm93ICgnTmVlZHMgZWxldmF0ZWQgcHJpdmlsZWdlcycpCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddLCBvcHRpb25zKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRlcnIuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBpZiAodXNlQm9vdG91dCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCBib290b3V0IGd1aS8nICsgdWlkICsgJyAnICsgdGhpcy5wbGlzdCArICdcbmV4aXRcbicpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCB1bmxvYWQgJyArIHRoaXMucGxpc3QgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgIH07CiAgICAgICAgcmV0LnN0YXJ0ID0gZnVuY3Rpb24gc3RhcnQodWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSB1bmRlZmluZWQ7CiAgICAgICAgICAgIHZhciBzZWxmID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLlNlbGYoKTsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQogICAgICAgICAgICBpZiAoIXRoaXMuZGFlbW9uICYmIHVpZCA9PSBudWxsKSB7IHVpZCA9IHNlbGY7IH0KICAgICAgICAgICAgaWYgKCF0aGlzLmRhZW1vbiAmJiB1aWQgPiAwICYmIHNlbGYgPT0gMCkgeyBvcHRpb25zID0geyB1aWQ6IHVpZCB9OyB9CiAgICAgICAgICAgIGlmICghdGhpcy5kYWVtb24gJiYgdWlkID4gMCAmJiBzZWxmICE9IDAgJiYgdWlkICE9IHNlbGYpIHsgdGhyb3cgKCdDYW5ub3Qgc3RhcnQgTGF1bmNoQWdlbnQgaW50byBhbm90aGVyIHVzZXIgZG9tYWluIHdoaWxlIG5vdCByb290Jyk7IH0KICAgICAgICAgICAgaWYgKHRoaXMuZGFlbW9uICYmIHNlbGYgIT0gMCkgeyB0aHJvdyAoJ0Nhbm5vdCBzdGFydCBMYXVuY2hEYWVtb24gd2hpbGUgbm90IHJvb3QnKTsgfQoKICAgICAgICAgICAgdGhpcy5sb2FkKHVpZCk7CgogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10sIG9wdGlvbnMpOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgc3RhcnQgJyArIHRoaXMuYWxpYXMgKyAnXG5cZXhpdFxuJyk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgfTsKICAgICAgICByZXQuc3RvcCA9IGZ1bmN0aW9uIHN0b3AodWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSB1bmRlZmluZWQ7CiAgICAgICAgICAgIHZhciBzZWxmID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLlNlbGYoKTsKICAgICAgICAgICAgaWYgKHRoaXMuX3VpZCAhPSBudWxsKSB7IHVpZCA9IHRoaXMuX3VpZDsgfQogICAgICAgICAgICBpZiAoIXRoaXMuZGFlbW9uICYmIHVpZCA9PSBudWxsKSB7IHVpZCA9IHNlbGY7IH0KICAgICAgICAgICAgaWYgKCF0aGlzLmRhZW1vbiAmJiB1aWQgPiAwICYmIHNlbGYgPT0gMCkgeyBvcHRpb25zID0geyB1aWQ6IHVpZCB9OyB9CiAgICAgICAgICAgIGlmICghdGhpcy5kYWVtb24gJiYgdWlkID4gMCAmJiBzZWxmICE9IDAgJiYgdWlkICE9IHNlbGYpIHsgdGhyb3cgKCdDYW5ub3Qgc3RvcCBMYXVuY2hBZ2VudCBpbiBhbm90aGVyIHVzZXIgZG9tYWluIHdoaWxlIG5vdCByb290Jyk7IH0KICAgICAgICAgICAgaWYgKHRoaXMuZGFlbW9uICYmIHNlbGYgIT0gMCkgeyB0aHJvdyAoJ0Nhbm5vdCBzdG9wIExhdW5jaERhZW1vbiB3aGlsZSBub3Qgcm9vdCcpOyB9CgogICAgICAgICAgICBpZiAoISh0aGlzLl9rZWVwQWxpdmUgPT0gJ0NyYXNoZWQnIHx8IHRoaXMuX2tlZXBBbGl2ZSA9PSAnJykpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIFdlIG11c3QgdW5sb2FkIHRoZSBzZXJ2aWNlLCByYXRoZXIgdGhhbiBzdG9wcGluZyBpdCwgYmVjYXVzZSBvdGhlcndpc2UgaXQnbGwgbGlrZWx5IHJlc3RhcnQKICAgICAgICAgICAgICAgIHRoaXMudW5sb2FkKHVpZCk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10sIG9wdGlvbnMpOwogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRlcnIuc3RyID0gJyc7IGNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgc3RvcCAnICsgdGhpcy5hbGlhcyArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgfQogICAgICAgIH07CiAgICAgICAgcmV0LnJlc3RhcnQgPSBmdW5jdGlvbiByZXN0YXJ0KHVpZCkKICAgICAgICB7CiAgICAgICAgICAgIGlmICh0aGlzLl91aWQgIT0gbnVsbCkgeyB1aWQgPSB0aGlzLl91aWQ7IH0KICAgICAgICAgICAgaWYgKGdldE9TVmVyc2lvbigpLmNvbXBhcmVUbygnMTAuMTAnKSA8IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmICghdGhpcy5kYWVtb24gJiYgdWlkID09IG51bGwpIHsgdWlkID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLlNlbGYoKTsgfQogICAgICAgICAgICAgICAgdmFyIGNvbW1hbmQgPSAnbGF1bmNoY3RsIHVubG9hZCAnICsgdGhpcy5wbGlzdCArICdcbmxhdW5jaGN0bCBsb2FkICcgKyB0aGlzLnBsaXN0ICsgJ1xubGF1bmNoY3RsIHN0YXJ0ICcgKyB0aGlzLmFsaWFzICsgJ1xuZXhpdFxuJzsKICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSwgeyBkZXRhY2hlZDogdHJ1ZSwgdWlkOiB1aWQgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7IGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5zdHIgPSAnJzsgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoY29tbWFuZCk7CiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdmFyIGNvbW1hbmQgPSB0aGlzLmRhZW1vbiA/ICgnc3lzdGVtLycgKyB0aGlzLmFsaWFzKSA6ICgnZ3VpLycgKyAodWlkICE9IG51bGwgPyB1aWQgOiByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuU2VsZigpKSArICcvJyArIHRoaXMuYWxpYXMpOwogICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgY2hpbGQuc3RkZXJyLnN0ciA9ICcnOyBjaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnbGF1bmNoY3RsIGtpY2tzdGFydCAtayAnICsgY29tbWFuZCArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgfQogICAgICAgIH07CiAgICAgICAgcmV0dXJuIChyZXQpOwogICAgfTsKfQoKCgpmdW5jdGlvbiBzZXJ2aWNlTWFuYWdlcigpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3NlcnZpY2UtbWFuYWdlcic7CiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKSAKICAgIHsKICAgICAgICB0aGlzLkdNID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICAgICAgdGhpcy5wcm94eSA9IHRoaXMuR00uQ3JlYXRlTmF0aXZlUHJveHkoJ0FkdmFwaTMyLmRsbCcpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdPcGVuU0NNYW5hZ2VyQScpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdFbnVtU2VydmljZXNTdGF0dXNFeEEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnT3BlblNlcnZpY2VBJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ1F1ZXJ5U2VydmljZVN0YXR1c0V4Jyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ1F1ZXJ5U2VydmljZUNvbmZpZ0EnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnUXVlcnlTZXJ2aWNlQ29uZmlnMkEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ29udHJvbFNlcnZpY2UnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnU3RhcnRTZXJ2aWNlQScpOwogICAgICAgIHRoaXMucHJveHkuQ3JlYXRlTWV0aG9kKCdDbG9zZVNlcnZpY2VIYW5kbGUnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ3JlYXRlU2VydmljZUEnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQ2hhbmdlU2VydmljZUNvbmZpZzJBJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0RlbGV0ZVNlcnZpY2UnKTsKICAgICAgICB0aGlzLnByb3h5LkNyZWF0ZU1ldGhvZCgnQWxsb2NhdGVBbmRJbml0aWFsaXplU2lkJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0NoZWNrVG9rZW5NZW1iZXJzaGlwJyk7CiAgICAgICAgdGhpcy5wcm94eS5DcmVhdGVNZXRob2QoJ0ZyZWVTaWQnKTsKCiAgICAgICAgdGhpcy5wcm94eTIgPSB0aGlzLkdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdLZXJuZWwzMi5kbGwnKTsKICAgICAgICB0aGlzLnByb3h5Mi5DcmVhdGVNZXRob2QoJ0dldExhc3RFcnJvcicpOwoKICAgICAgICB0aGlzLmlzQWRtaW4gPSBmdW5jdGlvbiBpc0FkbWluKCkgewogICAgICAgICAgICB2YXIgTlRBdXRob3JpdHkgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKDYpOwogICAgICAgICAgICBOVEF1dGhvcml0eS50b0J1ZmZlcigpLndyaXRlSW50OCg1LCA1KTsKICAgICAgICAgICAgdmFyIEFkbWluaXN0cmF0b3JzR3JvdXAgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGFkbWluID0gZmFsc2U7CgogICAgICAgICAgICBpZiAodGhpcy5wcm94eS5BbGxvY2F0ZUFuZEluaXRpYWxpemVTaWQoTlRBdXRob3JpdHksIDIsIDMyLCA1NDQsIDAsIDAsIDAsIDAsIDAsIDAsIEFkbWluaXN0cmF0b3JzR3JvdXApLlZhbCAhPSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgbWVtYmVyID0gdGhpcy5HTS5DcmVhdGVJbnRlZ2VyKCk7CiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGVja1Rva2VuTWVtYmVyc2hpcCgwLCBBZG1pbmlzdHJhdG9yc0dyb3VwLkRlcmVmKCksIG1lbWJlcikuVmFsICE9IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYgKG1lbWJlci50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpICE9IDApIHsgYWRtaW4gPSB0cnVlOyB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB0aGlzLnByb3h5LkZyZWVTaWQoQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gYWRtaW47CiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFByb2dyYW1Gb2xkZXIgPSBmdW5jdGlvbiBnZXRQcm9ncmFtRm9sZGVyKCkKICAgICAgICB7CiAgICAgICAgICAgIGlmIChyZXF1aXJlKCdvcycpLmFyY2goKSA9PSAneDY0JykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gNjQgYml0IFdpbmRvd3MKICAgICAgICAgICAgICAgIGlmICh0aGlzLkdNLlBvaW50ZXJTaXplID09IDQpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHByb2Nlc3MuZW52WydQcm9ncmFtRmlsZXMoeDg2KSddOyAgICAvLyAzMiBCaXQgQXBwCiAgICAgICAgICAgICAgICB9IAogICAgICAgICAgICAgICAgcmV0dXJuIHByb2Nlc3MuZW52WydQcm9ncmFtRmlsZXMnXTsgICAgICAgICAgICAgLy8gNjQgYml0IEFwcAogICAgICAgICAgICB9CgogICAgICAgICAgICAvLyAzMiBiaXQgV2luZG93cwogICAgICAgICAgICByZXR1cm4gcHJvY2Vzcy5lbnZbJ1Byb2dyYW1GaWxlcyddOyAgICAgICAgICAgICAgICAgCiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFNlcnZpY2VGb2xkZXIgPSBmdW5jdGlvbiBnZXRTZXJ2aWNlRm9sZGVyKCkgeyByZXR1cm4gdGhpcy5nZXRQcm9ncmFtRm9sZGVyKCkgKyAnXFxtZXNoJzsgfTsKCiAgICAgICAgdGhpcy5lbnVtZXJhdGVTZXJ2aWNlID0gZnVuY3Rpb24gKCkgewogICAgICAgICAgICB2YXIgbWFjaGluZU5hbWUgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGRiTmFtZSA9IHRoaXMuR00uQ3JlYXRlUG9pbnRlcigpOwogICAgICAgICAgICB2YXIgaGFuZGxlID0gdGhpcy5wcm94eS5PcGVuU0NNYW5hZ2VyQSgweDAwLCAweDAwLCAweDAwMDEgfCAweDAwMDQpOwoKICAgICAgICAgICAgdmFyIGJ5dGVzTmVlZGVkID0gdGhpcy5HTS5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciBzZXJ2aWNlc1JldHVybmVkID0gdGhpcy5HTS5DcmVhdGVQb2ludGVyKCk7CiAgICAgICAgICAgIHZhciByZXN1bWVIYW5kbGUgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgLy92YXIgc2VydmljZXMgPSB0aGlzLnByb3h5LkNyZWF0ZVZhcmlhYmxlKDI2MjE0NCk7CiAgICAgICAgICAgIHZhciBzdWNjZXNzID0gdGhpcy5wcm94eS5FbnVtU2VydmljZXNTdGF0dXNFeEEoaGFuZGxlLCAwLCAweDAwMDAwMDMwLCAweDAwMDAwMDAzLCAweDAwLCAweDAwLCBieXRlc05lZWRlZCwgc2VydmljZXNSZXR1cm5lZCwgcmVzdW1lSGFuZGxlLCAweDAwKTsKICAgICAgICAgICAgaWYgKGJ5dGVzTmVlZGVkLkludFZhbCA8PSAwKSB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ2Vycm9yIGVudW1lcmF0aW5nIHNlcnZpY2VzJyk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdmFyIHN6ID0gYnl0ZXNOZWVkZWQuSW50VmFsOwogICAgICAgICAgICB2YXIgc2VydmljZXMgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKHN6KTsKICAgICAgICAgICAgdGhpcy5wcm94eS5FbnVtU2VydmljZXNTdGF0dXNFeEEoaGFuZGxlLCAwLCAweDAwMDAwMDMwLCAweDAwMDAwMDAzLCBzZXJ2aWNlcywgc3osIGJ5dGVzTmVlZGVkLCBzZXJ2aWNlc1JldHVybmVkLCByZXN1bWVIYW5kbGUsIDB4MDApOwogICAgICAgICAgICBjb25zb2xlLmxvZygic2VydmljZXNSZXR1cm5lZCIsIHNlcnZpY2VzUmV0dXJuZWQuSW50VmFsKTsKCiAgICAgICAgICAgIHZhciBwdHJTaXplID0gZGJOYW1lLl9zaXplOwogICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gMzYgKyAoMiAqIHB0clNpemUpOwogICAgICAgICAgICBibG9ja1NpemUgKz0g", 16000);
	memcpy_s(_servicemanager + 32000, 85184, "KChwdHJTaXplIC0gKGJsb2NrU2l6ZSAlIHB0clNpemUpKSAlIHB0clNpemUpOwogICAgICAgICAgICB2YXIgcmV0VmFsID0gW107CiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2VydmljZXNSZXR1cm5lZC5JbnRWYWw7ICsraSkgewogICAgICAgICAgICAgICAgdmFyIHRva2VuID0gc2VydmljZXMuRGVyZWYoaSAqIGJsb2NrU2l6ZSwgYmxvY2tTaXplKTsKICAgICAgICAgICAgICAgIHZhciBqID0ge307CiAgICAgICAgICAgICAgICBqLm5hbWUgPSB0b2tlbi5EZXJlZigwLCBwdHJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouZGlzcGxheU5hbWUgPSB0b2tlbi5EZXJlZihwdHJTaXplLCBwdHJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouc3RhdHVzID0gcGFyc2VTZXJ2aWNlU3RhdHVzKHRva2VuLkRlcmVmKDIgKiBwdHJTaXplLCAzNikpOwogICAgICAgICAgICAgICAgcmV0VmFsLnB1c2goaik7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaGFuZGxlKTsKICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgIH0KICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiAobmFtZSkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBzZXJ2aWNlTmFtZSA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUobmFtZSk7CiAgICAgICAgICAgIHZhciBwdHIgPSB0aGlzLkdNLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGJ5dGVzTmVlZGVkID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZShwdHIuX3NpemUpOwogICAgICAgICAgICB2YXIgaGFuZGxlID0gdGhpcy5wcm94eS5PcGVuU0NNYW5hZ2VyQSgweDAwLCAweDAwLCAweDAwMDEgfCAweDAwMDQgfCAweDAwMjAgfCAweDAwMTApOwogICAgICAgICAgICBpZiAoaGFuZGxlLlZhbCA9PSAwKSB7IHRocm93ICgnY291bGQgbm90IG9wZW4gU2VydmljZU1hbmFnZXInKTsgfQogICAgICAgICAgICB2YXIgaCA9IHRoaXMucHJveHkuT3BlblNlcnZpY2VBKGhhbmRsZSwgc2VydmljZU5hbWUsIDB4MDAwMSB8IDB4MDAwNCB8IDB4MDAyMCB8IDB4MDAxMCB8IDB4MDAwMTAwMDApOwogICAgICAgICAgICBpZiAoaC5WYWwgIT0gMCkgewogICAgICAgICAgICAgICAgdmFyIHN1Y2Nlc3MgPSB0aGlzLnByb3h5LlF1ZXJ5U2VydmljZVN0YXR1c0V4KGgsIDAsIDAsIDAsIGJ5dGVzTmVlZGVkKTsKICAgICAgICAgICAgICAgIHZhciBzdGF0dXMgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKGJ5dGVzTmVlZGVkLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpOwogICAgICAgICAgICAgICAgc3VjY2VzcyA9IHRoaXMucHJveHkuUXVlcnlTZXJ2aWNlU3RhdHVzRXgoaCwgMCwgc3RhdHVzLCBzdGF0dXMuX3NpemUsIGJ5dGVzTmVlZGVkKTsKICAgICAgICAgICAgICAgIGlmIChzdWNjZXNzICE9IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIHJldFZhbCA9IHsgX09iamVjdElEOiAnc2VydmljZS1tYW5hZ2VyLnNlcnZpY2UnIH0KICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbChyZXRWYWwpOwoKICAgICAgICAgICAgICAgICAgICByZXRWYWwuY2xvc2UgPSBmdW5jdGlvbiAoKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYodGhpcy5fc2VydmljZSAmJiB0aGlzLl9zY20pCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3Byb3h5LkNsb3NlU2VydmljZUhhbmRsZSh0aGlzLl9zZXJ2aWNlKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3Byb3h5LkNsb3NlU2VydmljZUhhbmRsZSh0aGlzLl9zY20pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2VydmljZSA9IHRoaXMuX3NjbSA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9OwoKICAgICAgICAgICAgICAgICAgICByZXRWYWwub24oJ34nLCByZXRWYWwuY2xvc2UpOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5zdGF0dXMgPSBwYXJzZVNlcnZpY2VTdGF0dXMoc3RhdHVzKTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwuX3NjbSA9IGhhbmRsZTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwuX3NlcnZpY2UgPSBoOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5fR00gPSB0aGlzLkdNOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5fcHJveHkgPSB0aGlzLnByb3h5OwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5uYW1lID0gbmFtZTsKCiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmFwcExvY2F0aW9uID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZWcgPSByZXF1aXJlKCd3aW4tcmVnaXN0cnknKTsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGltYWdlUGF0aCA9IHJlZy5RdWVyeUtleShyZWcuSEtFWS5Mb2NhbE1hY2hpbmUsICdTWVNURU1cXEN1cnJlbnRDb250cm9sU2V0XFxTZXJ2aWNlc1xcJyArIHRoaXMubmFtZSwgJ0ltYWdlUGF0aCcpLnRvU3RyaW5nKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXQgPSBpbWFnZVBhdGguc3BsaXQoJy5leGUnKVswXSArICcuZXhlJzsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJldC5zdGFydHNXaXRoKCciJykpIHsgcmV0ID0gcmV0LnN1YnN0cmluZygxKTsgfQogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgICAgICAgICAgfTsKCgogICAgICAgICAgICAgICAgICAgIHJldFZhbC5hcHBXb3JraW5nRGlyZWN0b3J5ID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSB0aGlzLmFwcExvY2F0aW9uKCkuc3BsaXQoJ1xcJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRva2Vucy5wb3AoKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICh0b2tlbnMuam9pbignXFwnKSk7CiAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwuaXNSdW5uaW5nID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBieXRlc05lZWRlZCA9IHRoaXMuX0dNLkNyZWF0ZVZhcmlhYmxlKHRoaXMuX0dNLlBvaW50ZXJTaXplKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fcHJveHkuUXVlcnlTZXJ2aWNlU3RhdHVzRXgodGhpcy5fc2VydmljZSwgMCwgMCwgMCwgYnl0ZXNOZWVkZWQpOwogICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3QgPSB0aGlzLl9HTS5DcmVhdGVWYXJpYWJsZShieXRlc05lZWRlZC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYodGhpcy5fcHJveHkuUXVlcnlTZXJ2aWNlU3RhdHVzRXgodGhpcy5fc2VydmljZSwgMCwgc3QsIHN0Ll9zaXplLCBieXRlc05lZWRlZCkuVmFsICE9IDApCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzdGF0ZSA9IHBhcnNlU2VydmljZVN0YXR1cyhzdCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHN0YXRlLnN0YXRlID09ICdSVU5OSU5HJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChmYWxzZSk7CiAgICAgICAgICAgICAgICAgICAgfTsKCiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLnN0b3AgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnN0YXR1cy5zdGF0ZSA9PSAnUlVOTklORycpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBuZXdzdGF0ZSA9IHRoaXMuX0dNLkNyZWF0ZVZhcmlhYmxlKDM2KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzdWNjZXNzID0gdGhpcy5fcHJveHkuQ29udHJvbFNlcnZpY2UodGhpcy5fc2VydmljZSwgMHgwMDAwMDAwMSwgbmV3c3RhdGUpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHN1Y2Nlc3MgPT0gMCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICh0aGlzLm5hbWUgKyAnLnN0b3AoKSBmYWlsZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnY2Fubm90IGNhbGwgJyArIHRoaXMubmFtZSArICcuc3RvcCgpLCB3aGVuIGN1cnJlbnQgc3RhdGUgaXM6ICcgKyB0aGlzLnN0YXR1cy5zdGF0ZSk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLnN0YXJ0ID0gZnVuY3Rpb24gKCkgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zdGF0dXMuc3RhdGUgPT0gJ1NUT1BQRUQnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3VjY2VzcyA9IHRoaXMuX3Byb3h5LlN0YXJ0U2VydmljZUEodGhpcy5fc2VydmljZSwgMCwgMCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3VjY2VzcyA9PSAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHRoaXMubmFtZSArICcuc3RhcnQoKSBmYWlsZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnY2Fubm90IGNhbGwgJyArIHRoaXMubmFtZSArICcuc3RhcnQoKSwgd2hlbiBjdXJyZW50IHN0YXRlIGlzOiAnICsgdGhpcy5zdGF0dXMuc3RhdGUpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHZhciBxdWVyeV9zZXJ2aWNlX2NvbmZpZ2FfRFdPUkQgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgICAgICAgICAgICAgIHRoaXMucHJveHkuUXVlcnlTZXJ2aWNlQ29uZmlnQShoLCAwLCAwLCBxdWVyeV9zZXJ2aWNlX2NvbmZpZ2FfRFdPUkQpOwogICAgICAgICAgICAgICAgICAgIGlmIChxdWVyeV9zZXJ2aWNlX2NvbmZpZ2FfRFdPUkQudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSA+IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgcXVlcnlfc2VydmljZV9jb25maWdhID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZShxdWVyeV9zZXJ2aWNlX2NvbmZpZ2FfRFdPUkQudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmKHRoaXMucHJveHkuUXVlcnlTZXJ2aWNlQ29uZmlnQShoLCBxdWVyeV9zZXJ2aWNlX2NvbmZpZ2EsIHF1ZXJ5X3NlcnZpY2VfY29uZmlnYS5fc2l6ZSwgcXVlcnlfc2VydmljZV9jb25maWdhX0RXT1JEKS5WYWwgIT0gMCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbCA9IHF1ZXJ5X3NlcnZpY2VfY29uZmlnYS5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDQgPyAyOCA6IDQ4LCB0aGlzLkdNLlBvaW50ZXJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXRWYWwsICd1c2VyJywgeyB2YWx1ZTogdmFsIH0pOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKCiAgICAgICAgICAgICAgICAgICAgdmFyIGZhaWx1cmVhY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSg4MTkyKTsKICAgICAgICAgICAgICAgICAgICB2YXIgYm5lZWRlZCA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUoNCk7ICAgICAgICAKICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5RdWVyeVNlcnZpY2VDb25maWcyQShoLCAyLCBmYWlsdXJlYWN0aW9ucywgODE5MiwgYm5lZWRlZCkuVmFsICE9IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgY0FjdGlvbnMgPSBmYWlsdXJlYWN0aW9ucy50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSh0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAyNCA6IDEyKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zID0ge307CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5mYWlsdXJlQWN0aW9ucy5yZXNldFBlcmlvZCA9IGZhaWx1cmVhY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKDApOwogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucyA9IFtdOwogICAgICAgICAgICAgICAgICAgICAgICBmb3IodmFyIGFjdCA9IDAgOyBhY3QgPCBjQWN0aW9uczsgKythY3QpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhY3Rpb24gPSBmYWlsdXJlYWN0aW9ucy5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAzMiA6IDE2LCB0aGlzLkdNLlBvaW50ZXJTaXplKS5EZXJlZigpLkRlcmVmKGFjdCo4LDgpLnRvQnVmZmVyKCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYWN0aW9uLnJlYWRVSW50MzJMRSgpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zLmFjdGlvbnMucHVzaCh7IHR5cGU6ICdOT05FJyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAxOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wdXNoKHsgdHlwZTogJ1NFUlZJQ0VfUkVTVEFSVCcgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLmZhaWx1cmVBY3Rpb25zLmFjdGlvbnMucHVzaCh7IHR5cGU6ICdSRUJPT1QnIH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wdXNoKHsgdHlwZTogJ09USEVSJyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuZmFpbHVyZUFjdGlvbnMuYWN0aW9ucy5wZWVrKCkuZGVsYXkgPSBhY3Rpb24ucmVhZFVJbnQzMkxFKDQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UgewoKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaGFuZGxlKTsKICAgICAgICAgICAgdGhyb3cgKCdjb3VsZCBub3QgZmluZCBzZXJ2aWNlOiAnICsgbmFtZSk7CiAgICAgICAgfQogICAgfQogICAgZWxzZQogICAgewogICAgICAgIC8vIExpbnV4LCBNYWNPUywgRnJlZUJTRAoKICAgICAgICB0aGlzLmlzQWRtaW4gPSBmdW5jdGlvbiBpc0FkbWluKCkgCiAgICAgICAgewogICAgICAgICAgICByZXR1cm4gKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5pc1Jvb3QoKSk7CiAgICAgICAgfQoKICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiBnZXRTZXJ2aWNlKG5hbWUpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciByZXQgPSB7IG5hbWU6IG5hbWV9OwogICAgICAgICAgICAgICAgaWYocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvZXRjL3JjLmQvJyArIG5hbWUpKSAKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0LCAncmMnLCB7IHZhbHVlOiAnL2V0Yy9yYy5kLycgKyBuYW1lIH0pOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZSBpZihyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvZXRjL3JjLmQvJyArIG5hbWUpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyZXQsICdyYycsIHsgdmFsdWU6ICcvdXNyL2xvY2FsL2V0Yy9yYy5kLycgKyBuYW1lIH0pOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRocm93ICgnU2VydmljZTogJyArIG5hbWUgKyAnIG5vdCBmb3VuZCcpOwogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIHJldC5hcHBXb3JraW5nRGlyZWN0b3J5ID0gZnVuY3Rpb24gYXBwV29ya2luZ0RpcmVjdG9yeSgpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIHJldDsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGMpIHsgdGhpcy5zdHIgKz0gYy50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0ICIgKyB0aGlzLnJjICsgIiB8IGdyZXAgIiArIHRoaXMubmFtZSArICJfY2hkaXI9IHwgYXdrIC1GPSAneyBwcmludCAkMiB9JyB8IGF3ayAtRlxcXCIgJ3sgcHJpbnQgJDIgfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICAgICAgICAgIHJldCA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOwogICAgICAgICAgICAgICAgICAgIGlmKHJldCA9PSAnJykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldCA9IHRoaXMucmMuc3BsaXQoJy8nKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnBvcCgpOwogICAgICAgICAgICAgICAgICAgICAgICByZXQgPSByZXQuam9pbignLycpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gYXBwTG9jYXRpb24oKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CgkJICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgIiArIHRoaXMucmMgKyAiIHwgZ3JlcCBjb21tYW5kPSB8IGF3ayAtRj0gJ3sgcHJpbnQgJDIgfScgfCBhd2sgLUZcXFwiICd7IHByaW50ICQyIH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoJCSAgICAgICAgICAgIHZhciB0bXAgPSBjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKS5zcGxpdCgnJHtuYW1lfScpLmpvaW4odGhpcy5uYW1lKTsKCQkgICAgICAgICAgICBpZih0bXA9PScvdXNyL3NiaW4vZGFlbW9uJykKCQkgICAgICAgICAgICB7CgkJCSAgICAgICAgICAgIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKCQkJICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOwoJCQkgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnY2F0ICcgKyB0aGlzLnJjICsgJyB8IGdyZXAgY29tbWFuZF9hcmdzPSB8IGF3ayAtRiItZiAiIFwneyAkMT0iIjsgc3BsaXQoJDAsIHJlcywgIlxcIiIpOyBzcGxpdChyZXNbMV0sIHQsICIgIik7IHByaW50IHRbMV07IH1cJ1xuZXhpdFxuJyk7CgkJCSAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgkJCSAgICAgICAgICAgIHJldHVybihjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAJCSAgICAgICAgfQoJCSAgICAgICAgICAgIGVsc2UKCQkgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybih0bXApOwoJCSAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICByZXQuaXNSdW5uaW5nID0gZnVuY3Rpb24gaXNSdW5uaW5nKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGMpIHsgdGhpcy5zdHIgKz0gYy50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgic2VydmljZSAiICsgdGhpcy5uYW1lICsgIiBvbmVzdGF0dXMgfCBhd2sgJ3sgcHJpbnQgJDMgfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSA9PSAncnVubmluZycpOwogICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgIHJldC5pc01lID0gZnVuY3Rpb24gaXNNZSgpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7IGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjKSB7IHRoaXMuc3RyICs9IGMudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInNlcnZpY2UgIiArIHRoaXMubmFtZSArICIgb25lc3RhdHVzIHwgYXdrICd7IHNwbGl0KCQ2LCByZXMsIFwiLlwiKTsgcHJpbnQgcmVzWzFdOyB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKSA9PSBwcm9jZXNzLnBpZCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0LnN0b3AgPSBmdW5jdGlvbiBzdG9wKCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNo", 16000);
	memcpy_s(_servicemanager + 48000, 69184, "aWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGMpIHsgdGhpcy5zdHIgKz0gYy50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgic2VydmljZSAiICsgdGhpcy5uYW1lICsgIiBvbmVzdG9wXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgIHJldC5zdGFydCA9IGZ1bmN0aW9uIHN0YXJ0KCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGMpIHsgdGhpcy5zdHIgKz0gYy50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgic2VydmljZSAiICsgdGhpcy5uYW1lICsgIiBvbmVzdGFydFxuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICByZXQucmVzdGFydCA9IGZ1bmN0aW9uIHJlc3RhcnQoKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJzZXJ2aWNlICIgKyB0aGlzLm5hbWUgKyAiIG9uZXJlc3RhcnRcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICB9OwogICAgICAgIH0KCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLmdldFNlcnZpY2UgPSBmdW5jdGlvbiBnZXRTZXJ2aWNlKG5hbWUpIHsgcmV0dXJuIChmZXRjaFBsaXN0KCcvTGlicmFyeS9MYXVuY2hEYWVtb25zJywgbmFtZSkpOyB9OwogICAgICAgICAgICB0aGlzLmdldExhdW5jaEFnZW50ID0gZnVuY3Rpb24gZ2V0TGF1bmNoQWdlbnQobmFtZSwgdXNlcmlkKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAodXNlcmlkID09IG51bGwpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChmZXRjaFBsaXN0KCcvTGlicmFyeS9MYXVuY2hBZ2VudHMnLCBuYW1lKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChmZXRjaFBsaXN0KHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRIb21lRm9sZGVyKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRVc2VybmFtZSh1c2VyaWQpKSArICcvTGlicmFyeS9MYXVuY2hBZ2VudHMnLCBuYW1lLCB1c2VyaWQpKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfTsKICAgICAgICB9CiAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgICAgIHsKICAgICAgICAgICAgdGhpcy5nZXRTZXJ2aWNlID0gZnVuY3Rpb24gKG5hbWUsIHBsYXRmb3JtKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAoIXBsYXRmb3JtKSB7IHBsYXRmb3JtID0gdGhpcy5nZXRTZXJ2aWNlVHlwZSgpOyB9CiAgICAgICAgICAgICAgICB2YXIgcmV0ID0geyBuYW1lOiBuYW1lLCBjbG9zZTogZnVuY3Rpb24gKCkgeyB9fTsKICAgICAgICAgICAgICAgIHN3aXRjaChwbGF0Zm9ybSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjYXNlICdpbml0JzoKICAgICAgICAgICAgICAgICAgICBjYXNlICd1cHN0YXJ0JzoKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpKSB7IHBsYXRmb3JtID0gJ2luaXQnOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpKSB7IHBsYXRmb3JtID0gJ3Vwc3RhcnQnOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgocGxhdGZvcm0gPT0gJ2luaXQnICYmIHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpKSB8fAogICAgICAgICAgICAgICAgICAgICAgICAgICAgKHBsYXRmb3JtID09ICd1cHN0YXJ0JyAmJiByZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpKSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcFdvcmtpbmdEaXJlY3RvcnkgPSBmdW5jdGlvbiBhcHBXb3JraW5nRGlyZWN0b3J5KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGFwcFdvcmtpbmdEaXJlY3RvcnkucGxhdGZvcm0gPT0gJ2luaXQnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL2luaXQuZC8iICsgdGhpcy5uYW1lICsgIiB8IGdyZXAgJ1NDUklQVD0nIHwgYXdrIC1GPSAneyBsZW49c3BsaXQoJDIsIGEsIFwiL1wiKTsgcHJpbnQgc3Vic3RyKCQyLDAsbGVuZ3RoKCQyKS1sZW5ndGgoYVtsZW5dKSk7IH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL2luaXQvIiArIHRoaXMubmFtZSArICIuY29uZiB8IGdyZXAgJ2NoZGlyICcgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuYXBwV29ya2luZ0RpcmVjdG9yeS5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gYXBwTG9jYXRpb24oKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihhcHBMb2NhdGlvbi5wbGF0Zm9ybSA9PSAnaW5pdCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9ldGMvaW5pdC5kLyIgKyB0aGlzLm5hbWUgKyAiIHwgZ3JlcCAnU0NSSVBUPScgfCBhd2sgLUY9ICd7cHJpbnQgJDJ9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL2V0Yy9pbml0LyIgKyB0aGlzLm5hbWUgKyAiLmNvbmYgfCBncmVwICdleGVjICcgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuYXBwTG9jYXRpb24ucGxhdGZvcm0gPSBwbGF0Zm9ybTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5pc01lID0gZnVuY3Rpb24gaXNNZSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpc01lLnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJpbml0Y3RsIHN0YXR1cyAiICsgdGhpcy5uYW1lICsgIiB8IGF3ayAne3ByaW50ICQyfScgfCBhd2sgLUYsICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJzZXJ2aWNlICIgKyB0aGlzLm5hbWUgKyAiIHN0YXR1cyB8IGF3ayAne3ByaW50ICQyfScgfCBhd2sgLUYsICd7cHJpbnQgJDR9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChwYXJzZUludChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSkgPT0gcHJvY2Vzcy5waWQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5pc01lLnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuaXNSdW5uaW5nID0gZnVuY3Rpb24gaXNSdW5uaW5nKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGlzUnVubmluZy5wbGF0Zm9ybSA9PSAndXBzdGFydCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiaW5pdGN0bCBzdGF0dXMgIiArIHRoaXMubmFtZSArICIgfCBhd2sgJ3twcmludCAkMn0nIHwgYXdrIC1GLCAne3ByaW50ICQxfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgic2VydmljZSAiICsgdGhpcy5uYW1lICsgIiBzdGF0dXMgfCBhd2sgJ3twcmludCAkMn0nIHwgYXdrIC1GLCAne3ByaW50ICQxfSdcbmV4aXRcbiIpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgPT0gJ3N0YXJ0L3J1bm5pbmcnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuaXNSdW5uaW5nLnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuc3RhcnQgPSBmdW5jdGlvbiBzdGFydCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHN0YXJ0LnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdpbml0Y3RsIHN0YXJ0ICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3NlcnZpY2UgJyArIHRoaXMubmFtZSArICcgc3RhcnRcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGFydC5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AgPSBmdW5jdGlvbiBzdG9wKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3RvcC5wbGF0Zm9ybSA9PSAndXBzdGFydCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnaW5pdGN0bCBzdG9wICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3NlcnZpY2UgJyArIHRoaXMubmFtZSArICcgc3RvcFxuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AucGxhdGZvcm0gPSBwbGF0Zm9ybTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5yZXN0YXJ0ID0gZnVuY3Rpb24gcmVzdGFydCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3RhcnQucGxhdGZvcm0gPT0gJ3Vwc3RhcnQnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2luaXRjdGwgcmVzdGFydCAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyB0aGlzLm5hbWUgKyAnIHJlc3RhcnRcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5yZXN0YXJ0LnBsYXRmb3JtID0gcGxhdGZvcm07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuc3RhdHVzID0gZnVuY3Rpb24gc3RhdHVzKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5fc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuX3N0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc3RhdHVzLnBsYXRmb3JtID09ICd1cHN0YXJ0JykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdpbml0Y3RsIHN0YXR1cyAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyB0aGlzLm5hbWUgKyAnIHN0YXR1c1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuX3N0cik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0YXR1cy5wbGF0Zm9ybSA9IHBsYXRmb3JtOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHBsYXRmb3JtICsgJyBTZXJ2aWNlICgnICsgbmFtZSArICcpIE5PVCBGT1VORCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgJ3N5c3RlbWQnOgogICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJykgfHwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vJyArIG5hbWUgKyAnLnNlcnZpY2UnKSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcFdvcmtpbmdEaXJlY3RvcnkgPSBmdW5jdGlvbiBhcHBXb3JraW5nRGlyZWN0b3J5KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgdGhpcy5uYW1lICsgJy5zZXJ2aWNlJykpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvbGliL3N5c3RlbWQvc3lzdGVtLyIgKyB0aGlzLm5hbWUgKyAiLnNlcnZpY2UgfCBncmVwICdXb3JraW5nRGlyZWN0b3J5PScgfCBhd2sgLUY9ICd7IHByaW50ICQyIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC91c3IvbGliL3N5c3RlbWQvc3lzdGVtLyIgKyB0aGlzLm5hbWUgKyAiLnNlcnZpY2UgfCBncmVwICdXb3JraW5nRGlyZWN0b3J5PScgfCBhd2sgLUY9ICd7IHByaW50ICQyIH0nXG5cZXhpdFxuIik7CiAg", 16000);
	memcpy_s(_servicemanager + 64000, 53184, "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmFwcExvY2F0aW9uID0gZnVuY3Rpb24gKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgdGhpcy5uYW1lICsgJy5zZXJ2aWNlJykpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiY2F0IC9saWIvc3lzdGVtZC9zeXN0ZW0vIiArIHRoaXMubmFtZSArICIuc2VydmljZSB8IGdyZXAgJ0V4ZWNTdGFydD0nIHwgYXdrIC1GPSAneyBzcGxpdCgkMiwgYSwgXCIgXCIpOyBwcmludCBhWzFdIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vIiArIHRoaXMubmFtZSArICIuc2VydmljZSB8IGdyZXAgJ0V4ZWNTdGFydD0nIHwgYXdrIC1GPSAneyBzcGxpdCgkMiwgYSwgXCIgXCIpOyBwcmludCBhWzFdIH0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmlzTWUgPSBmdW5jdGlvbiBpc01lKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoInN5c3RlbWN0bCBzdGF0dXMgIiArIHRoaXMubmFtZSArICIgfCBncmVwICdNYWluIFBJRDonIHwgYXdrICd7cHJpbnQgJDN9J1xuZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKSA9PSBwcm9jZXNzLnBpZCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LmlzUnVubmluZyA9IGZ1bmN0aW9uIGlzUnVubmluZygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJzeXN0ZW1jdGwgc3RhdHVzICIgKyB0aGlzLm5hbWUgKyAiIHwgZ3JlcCAnQWN0aXZlOicgfCBhd2sgJ3twcmludCAkMn0nXG5leGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgPT0gJ2FjdGl2ZScpOyAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGFydCA9IGZ1bmN0aW9uIHN0YXJ0KCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzeXN0ZW1jdGwgc3RhcnQgJyArIHRoaXMubmFtZSArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0LnN0b3AgPSBmdW5jdGlvbiBzdG9wKCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdzeXN0ZW1jdGwgc3RvcCAnICsgdGhpcy5uYW1lICsgJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQucmVzdGFydCA9IGZ1bmN0aW9uIHJlc3RhcnQoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCByZXN0YXJ0ICcgKyB0aGlzLm5hbWUgKyAnXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldC5zdGF0dXMgPSBmdW5jdGlvbiBzdGF0dXMoKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuX3N0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLl9zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCBzdGF0dXMgJyArIHRoaXMubmFtZSArICdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChjaGlsZC5zdGRvdXQuX3N0cik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKHBsYXRmb3JtICsgJyBTZXJ2aWNlICgnICsgbmFtZSArICcpIE5PVCBGT1VORCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93ICgnVW5rbm93biBTZXJ2aWNlIFBsYXRmb3JtOiAnICsgcGxhdGZvcm0pOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfTsKICAgICAgICB9CiAgICB9CiAgICB0aGlzLmluc3RhbGxTZXJ2aWNlID0gZnVuY3Rpb24gaW5zdGFsbFNlcnZpY2Uob3B0aW9ucykKICAgIHsKICAgICAgICBpZiAoIW9wdGlvbnMudGFyZ2V0KSB7IG9wdGlvbnMudGFyZ2V0ID0gb3B0aW9ucy5uYW1lOyB9CiAgICAgICAgaWYgKCFvcHRpb25zLmRpc3BsYXlOYW1lKSB7IG9wdGlvbnMuZGlzcGxheU5hbWUgPSBvcHRpb25zLm5hbWU7IH0KCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykKICAgICAgICB7CiAgICAgICAgICAgIGlmICghdGhpcy5pc0FkbWluKCkpIHsgdGhyb3cgKCdJbnN0YWxsaW5nIGFzIFNlcnZpY2UsIHJlcXVpcmVzIGFkbWluJyk7IH0KCiAgICAgICAgICAgIC8vIEJlZm9yZSB3ZSBzdGFydCwgd2UgbmVlZCB0byBjb3B5IHRoZSBiaW5hcnkgdG8gdGhlIHJpZ2h0IHBsYWNlCiAgICAgICAgICAgIHZhciBmb2xkZXIgPSB0aGlzLmdldFNlcnZpY2VGb2xkZXIoKTsKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoZm9sZGVyKSkgeyByZXF1aXJlKCdmcycpLm1rZGlyU3luYyhmb2xkZXIpOyB9CiAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUpOyB9CgogICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCBmb2xkZXIgKyAnXFwnICsgb3B0aW9ucy5uYW1lICsgJ1xcJyArIG9wdGlvbnMudGFyZ2V0ICsgJy5leGUnKTsKICAgICAgICAgICAgb3B0aW9ucy5zZXJ2aWNlUGF0aCA9IGZvbGRlciArICdcXCcgKyBvcHRpb25zLm5hbWUgKyAnXFwnICsgb3B0aW9ucy50YXJnZXQgKyAnLmV4ZSc7CgogICAgICAgICAgICB2YXIgc2VydmljZVBhdGggPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKCciJyArIG9wdGlvbnMuc2VydmljZVBhdGggKyAnIicpOwogICAgICAgICAgICB2YXIgaGFuZGxlID0gdGhpcy5wcm94eS5PcGVuU0NNYW5hZ2VyQSgweDAwLCAweDAwLCAweDAwMDIpOwogICAgICAgICAgICBpZiAoaGFuZGxlLlZhbCA9PSAwKSB7IHRocm93ICgnZXJyb3Igb3BlbmluZyBTQ01hbmFnZXInKTsgfQogICAgICAgICAgICB2YXIgc2VydmljZU5hbWUgPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKG9wdGlvbnMubmFtZSk7CiAgICAgICAgICAgIHZhciBkaXNwbGF5TmFtZSA9IHRoaXMuR00uQ3JlYXRlVmFyaWFibGUob3B0aW9ucy5kaXNwbGF5TmFtZSk7CiAgICAgICAgICAgIHZhciBhbGxBY2Nlc3MgPSAweDAwMEYwMUZGOwogICAgICAgICAgICB2YXIgc2VydmljZVR5cGU7CiAgICAgICAgICAgIAoKICAgICAgICAgICAgc3dpdGNoIChvcHRpb25zLnN0YXJ0VHlwZSkgewogICAgICAgICAgICAgICAgY2FzZSAnQVVUT19TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgc2VydmljZVR5cGUgPSAweDAyOyAvLyBBdXRvbWF0aWMKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgJ0RFTUFORF9TVEFSVCc6CiAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgIHNlcnZpY2VUeXBlID0gMHgwMzsgLy8gTWFudWFsCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBjYXNlICdESVNBQkxFRCc6CiAgICAgICAgICAgICAgICAgICAgc2VydmljZVR5cGUgPSAweDA0OyAvLyBEaXNhYmxlZAogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CgogICAgICAgICAgICB2YXIgaCA9IHRoaXMucHJveHkuQ3JlYXRlU2VydmljZUEoaGFuZGxlLCBzZXJ2aWNlTmFtZSwgZGlzcGxheU5hbWUsIGFsbEFjY2VzcywgMHgxMCB8IDB4MTAwLCBzZXJ2aWNlVHlwZSwgMCwgc2VydmljZVBhdGgsIDAsIDAsIDAsIDAsIDApOwogICAgICAgICAgICBpZiAoaC5WYWwgPT0gMCkgeyB0aGlzLnByb3h5LkNsb3NlU2VydmljZUhhbmRsZShoYW5kbGUpOyB0aHJvdyAoJ0Vycm9yIENyZWF0aW5nIFNlcnZpY2U6ICcgKyB0aGlzLnByb3h5Mi5HZXRMYXN0RXJyb3IoKS5WYWwpOyB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLmRlc2NyaXB0aW9uKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgZHNjID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZShvcHRpb25zLmRlc2NyaXB0aW9uKTsKICAgICAgICAgICAgICAgIHZhciBzZXJ2aWNlRGVzY3JpcHRpb24gPSB0aGlzLkdNLkNyZWF0ZVZhcmlhYmxlKHRoaXMuR00uUG9pbnRlclNpemUpOwogICAgICAgICAgICAgICAgZHNjLnBvaW50ZXJCdWZmZXIoKS5jb3B5KHNlcnZpY2VEZXNjcmlwdGlvbi5EZXJlZigwLCB0aGlzLkdNLlBvaW50ZXJTaXplKS50b0J1ZmZlcigpKTsKCiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGFuZ2VTZXJ2aWNlQ29uZmlnMkEoaCwgMSwgc2VydmljZURlc2NyaXB0aW9uKS5WYWwgPT0gMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygndW5hYmxlIHRvIHNldCBkZXNjcmlwdGlvbi4uLicpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID09IG51bGwgfHwgb3B0aW9ucy5mYWlsdXJlUmVzdGFydCA+IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBkZWxheSA9IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPT0gbnVsbCA/IDUwMDAgOiBvcHRpb25zLmZhaWx1cmVSZXN0YXJ0OyAgICAgICAgICAgICAvLyBEZWxheSBpbiBtaWxsaXNlY29uZHMKICAgICAgICAgICAgICAgIHZhciBhY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSgzICogOCk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyAzKnNpemVvZihTQ19BQ1RJT04pCiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgxKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzBdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoNCwgNCkudG9CdWZmZXIoKS53cml0ZVVJbnQzMkxFKGRlbGF5KTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzBdLmRlbGF5CiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDgsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSgxKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzFdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoMTIsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShkZWxheSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzFdLmRlbGF5CiAgICAgICAgICAgICAgICBhY3Rpb25zLkRlcmVmKDE2LCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzJdLnR5cGUKICAgICAgICAgICAgICAgIGFjdGlvbnMuRGVyZWYoMjAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRShkZWxheSk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gU0NfQUNUSU9OWzJdLmRlbGF5CgogICAgICAgICAgICAgICAgdmFyIGZhaWx1cmVBY3Rpb25zID0gdGhpcy5HTS5DcmVhdGVWYXJpYWJsZSg0MCk7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNpemVvZihTRVJWSUNFX0ZBSUxVUkVfQUNUSU9OUykKICAgICAgICAgICAgICAgIGZhaWx1cmVBY3Rpb25zLkRlcmVmKDAsIDQpLnRvQnVmZmVyKCkud3JpdGVVSW50MzJMRSg3MjAwKTsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBkd1Jlc2V0UGVyaW9kOiAyIEhvdXJzCiAgICAgICAgICAgICAgICBmYWlsdXJlQWN0aW9ucy5EZXJlZih0aGlzLkdNLlBvaW50ZXJTaXplID09IDggPyAyNCA6IDEyLCA0KS50b0J1ZmZlcigpLndyaXRlVUludDMyTEUoMyk7Ly8gY0FjdGlvbnM6IDMKICAgICAgICAgICAgICAgIGFjdGlvbnMucG9pbnRlckJ1ZmZlcigpLmNvcHkoZmFpbHVyZUFjdGlvbnMuRGVyZWYodGhpcy5HTS5Qb2ludGVyU2l6ZSA9PSA4ID8gMzIgOiAxNiwgdGhpcy5HTS5Qb2ludGVyU2l6ZSkudG9CdWZmZXIoKSk7CiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5DaGFuZ2VTZXJ2aWNlQ29uZmlnMkEoaCwgMiwgZmFpbHVyZUFjdGlvbnMpLlZhbCA9PSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdVbmFibGUgdG8gc2V0IEZhaWx1cmVBY3Rpb25zLi4uJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdGhpcy5wcm94eS5DbG9zZVNlcnZpY2VIYW5kbGUoaCk7CiAgICAgICAgICAgIHRoaXMucHJveHkuQ2xvc2VTZXJ2aWNlSGFuZGxlKGhhbmRsZSk7CgogICAgICAgICAgICBpZiAob3B0aW9ucy5maWxlcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgZm9yKHZhciBpIGluIG9wdGlvbnMuZmlsZXMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMuZmlsZXNbaV0uX2J1ZmZlcikKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCd3cml0aW5nICcgKyBleHRyYWN0RmlsZU5hbWUob3B0aW9ucy5maWxlc1tpXSkpOwogICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoZm9sZGVyICsgJ1xcJyArIG9wdGlvbnMubmFtZSArICdcXCcgKyBleHRyYWN0RmlsZU5hbWUob3B0aW9ucy5maWxlc1tpXSksIG9wdGlvbnMuZmlsZXNbaV0uX2J1ZmZlcik7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdjb3B5aW5nICcgKyBleHRyYWN0RmlsZVNvdXJjZShvcHRpb25zLmZpbGVzW2ldKSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY29weUZpbGVTeW5jKGV4dHJhY3RGaWxlU291cmNlKG9wdGlvbnMuZmlsZXNbaV0pLCBmb2xkZXIgKyAnXFwnICsgb3B0aW9ucy5uYW1lICsgJ1xcJyArIGV4dHJhY3RGaWxlTmFtZShvcHRpb25zLmZpbGVzW2ldKSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChvcHRpb25zLnBhcmFtZXRlcnMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciByZWcgPSByZXF1aXJlKCd3aW4tcmVnaXN0cnknKTsKICAgICAgICAgICAgICAgIHZhciBpbWFnZVBhdGggPSByZWcuUXVlcnlLZXkocmVnLkhLRVkuTG9jYWxNYWNoaW5lLCAnU1lTVEVNXFxDdXJyZW50Q29udHJvbFNldFxcU2VydmljZXNcXCcgKyBvcHRpb25zLm5hbWUsICdJbWFnZVBhdGgnKTsKICAgICAgICAgICAgICAgIGltYWdlUGF0aCArPSAoJyAnICsgb3B0aW9ucy5wYXJhbWV0ZXJzLmpvaW4oJyAnKSk7CiAgICAgICAgICAgICAgICByZWcuV3JpdGVLZXkocmVnLkhLRVkuTG9jYWxNYWNoaW5lLCAnU1lTVEVNXFxDdXJyZW50Q29udHJvbFNldFxcU2VydmljZXNcXCcgKyBvcHRpb25zLm5hbWUsICdJbWFnZVBhdGgnLCBpbWFnZVBhdGgpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICdmcmVlYnNkJykKICAgICAgICB7CiAgICAgICAgICAgIGlmICghdGhpcy5pc0FkbWluKCkpIHsgY29uc29sZS5sb2coJ0luc3RhbGxpbmcgYSBTZXJ2aWNlIHJlcXVpcmVzIHJvb3QnKTsgdGhyb3cgKCdJbnN0YWxsaW5nIGFzIFNlcnZpY2UsIHJlcXVpcmVzIHJvb3QnKTsgfQogICAgICAgICAgICB2YXIgcGFyYW1ldGVycyA9IG9wdGlvbnMucGFyYW1ldGVycyA/IG9wdGlvbnMucGFyYW1ldGVycy5qb2luKCcgJykgOiAnJzsKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSk7IH0KICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jb3B5RmlsZVN5bmMob3B0aW9ucy5zZXJ2aWNlUGF0aCwgJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpOwoKICAgICAgICAgICAgdmFyIHJjID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSgnL3Vzci9sb2NhbC9ldGMvcmMuZC8nICsgb3B0aW9ucy5uYW1lLCB7IGZsYWdzOiAnd2InIH0pOwogICAgICAgICAgICByYy53cml0ZSgnIyEvYmluL3NoXG4nKTsKICAgICAgICAgICAgcmMud3JpdGUoJyMgUFJPVklERTogJyArIG9wdGlvbnMubmFtZSArICdcbicpOwogICAgICAgICAgICByYy53cml0ZSgnIyBSRVFVSVJFOiBGSUxFU1lTVEVNUyBORVRXT1JLSU5HXG4nKTsKICAgICAgICAgICAgcmMud3JpdGUoJyMgS0VZV09SRDogc2h1dGRvd25cbicpOwogICAgICAgICAgICByYy53cml0ZSgnLiAvZXRjL3JjLnN1YnJcblxuJyk7CiAgICAgICAgICAgIHJjLndyaXRlKCduYW1lPSInICsgb3B0aW9ucy5uYW1lICsgJyJcbicpOwogICAgICAgICAgICByYy53cml0ZSgnZGVzYz0iJyArIChvcHRpb25zLmRlc2NyaXB0aW9uID8gb3B0aW9ucy5kZXNjcmlwdGlvbiA6ICdNZXNoQ2VudHJhbCBBZ2VudCcpICsgJyJcbicpOwogICAgICAgICAgICByYy53cml0ZSgncmN2YXI9JHtuYW1lfV9lbmFibGVcbicpOwogICAgICAgICAgICByYy53cml0ZSgncGlkZmlsZT0iL3Zhci9ydW4vJyArIG9wdGlvbnMubmFtZSArICcucGlk", 16000);
	memcpy_s(_servicemanager + 80000, 37184, "IlxuJyk7CiAgICAgICAgICAgIHJjLndyaXRlKCdjb21tYW5kPSIvdXNyL3NiaW4vZGFlbW9uIlxuJyk7CiAgICAgICAgICAgIHJjLndyaXRlKCdjb21tYW5kX2FyZ3M9Ii1QICR7cGlkZmlsZX0gJyArICgob3B0aW9ucy5mYWlsdXJlUmVzdGFydCA9PSBudWxsIHx8IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPiAwKT8nLXInOicnKSArICcgLWYgL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCArICcgJyArIHBhcmFtZXRlcnMgKyAnIlxuJyk7CiAgICAgICAgICAgIHJjLndyaXRlKCdjb21tYW5kX2NoZGlyPSIvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICciXG5cbicpOwogICAgICAgICAgICByYy53cml0ZSgnbG9hZF9yY19jb25maWcgJG5hbWVcbicpOwogICAgICAgICAgICByYy53cml0ZSgnOiAkeycgKyBvcHRpb25zLm5hbWUgKyAnX2VuYWJsZT0iJyArICgob3B0aW9ucy5zdGFydFR5cGUgPT0gJ0FVVE9fU1RBUlQnIHx8IG9wdGlvbnMuc3RhcnRUeXBlID09ICdCT09UX1NUQVJUJyk/J1lFUyc6J05PJykgKyAnIn1cbicpOwogICAgICAgICAgICByYy53cml0ZSgncnVuX3JjX2NvbW1hbmQgIiQxIlxuJyk7CiAgICAgICAgICAgIHJjLmVuZCgpOwogICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvZXRjL3JjLmQvJyArIG9wdGlvbnMubmFtZSkubW9kZTsKICAgICAgICAgICAgbSB8PSAocmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYVVNSIHwgcmVxdWlyZSgnZnMnKS5DSE1PRF9NT0RFUy5TX0lYR1JQKTsKICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jaG1vZFN5bmMoJy91c3IvbG9jYWwvZXRjL3JjLmQvJyArIG9wdGlvbnMubmFtZSwgbSk7CiAgICAgICAgfQogICAgICAgIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JykKICAgICAgICB7CiAgICAgICAgICAgIGlmICghdGhpcy5pc0FkbWluKCkpIHsgY29uc29sZS5sb2coJ0luc3RhbGxpbmcgYSBTZXJ2aWNlIHJlcXVpcmVzIHJvb3QnKTsgdGhyb3cgKCdJbnN0YWxsaW5nIGFzIFNlcnZpY2UsIHJlcXVpcmVzIHJvb3QnKTsgfQogICAgICAgICAgICB2YXIgcGFyYW1ldGVycyA9IG9wdGlvbnMucGFyYW1ldGVycyA/IG9wdGlvbnMucGFyYW1ldGVycy5qb2luKCcgJykgOiAnJzsKICAgICAgICAgICAgdmFyIGNvbmY7CiAgICAgICAgICAgIGlmICghb3B0aW9ucy5zZXJ2aWNlUGxhdGZvcm0pIHsgb3B0aW9ucy5zZXJ2aWNlUGxhdGZvcm0gPSB0aGlzLmdldFNlcnZpY2VUeXBlKCk7IH0KICAgICAgICAgICAKICAgICAgICAgICAgc3dpdGNoIChvcHRpb25zLnNlcnZpY2VQbGF0Zm9ybSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgY2FzZSAnaW5pdCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nKSkgeyByZXF1aXJlKCdmcycpLm1rZGlyU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzJyk7IH0KICAgICAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSk7IH0KCiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jb3B5RmlsZVN5bmMob3B0aW9ucy5zZXJ2aWNlUGF0aCwgJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpOwogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdjb3B5aW5nICcgKyBvcHRpb25zLnNlcnZpY2VQYXRoKTsKCiAgICAgICAgICAgICAgICAgICAgdmFyIG0gPSByZXF1aXJlKCdmcycpLnN0YXRTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0KS5tb2RlOwogICAgICAgICAgICAgICAgICAgIG0gfD0gKHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JWFVTUiB8IHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JWEdSUCk7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jaG1vZFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQsIG0pOwoKICAgICAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy5mYWlsdXJlUmVzdGFydCA9PSBudWxsIHx8IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPiAwKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAvLyBDcmFzaCBSZXN0YXJ0IGlzIGVuYWJsZWQsIGJ1dCBpdCBpc24ndCBpbmhlcmVudGx5IHN1cHBvcnRlZCBieSBJTklULCBzbyB3ZSBtdXN0IGZha2UgaXQgd2l0aCBKUw0KICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHRtcF9wYXJhbWV0ZXJzID0gcGFyYW1ldGVycy5zcGxpdCgnIicpLmpvaW4oJ1xcIicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW1ldGVycyA9ICItZXhlYyBcXFwidmFyIGNoaWxkOyBwcm9jZXNzLm9uKCdTSUdURVJNJywgZnVuY3Rpb24gKCkgeyBjaGlsZC5yZW1vdmVBbGxMaXN0ZW5lcnMoJ2V4aXQnKTsgY2hpbGQua2lsbCgpOyBwcm9jZXNzLmV4aXQoKTsgfSk7IGZ1bmN0aW9uIHN0YXJ0KCkgeyBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZShwcm9jZXNzLmV4ZWNQYXRoLCBbcHJvY2Vzcy5hcmd2MCwgXFxcIiIgKyB0bXBfcGFyYW1ldGVycyArICJcXFwiXSk7IGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjKSB7IH0pOyBjaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB9KTsgY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoc3RhdHVzKSB7IHN0YXJ0KCk7IH0pOyB9IHN0YXJ0KCk7XFxcIiI7DQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gVGhlIGZvbGxvd2luZyBpcyB0aGUgaW5pdC5kIHNjcmlwdCBJIHdyb3RlLiBSYXRoZXIgdGhhbiBoYXZpbmcgdG8gZGVhbCB3aXRoIGVzY2FwaW5nIHRoZSB0aGluZywgSSBqdXN0IEJhc2U2NCBlbmNvZGVkIGl0IHRvIHByZXZlbnQgaXNzdWVzLgogICAgICAgICAgICAgICAgICAgIGNvbmYgPSByZXF1aXJlKCdmcycpLmNyZWF0ZVdyaXRlU3RyZWFtKCcvZXRjL2luaXQuZC8nICsgb3B0aW9ucy5uYW1lLCB7IGZsYWdzOiAnd2InIH0pOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoQnVmZmVyLmZyb20oJ0l5RXZZbWx1TDNOb0Nnb0tVME5TU1ZCVVBTOTFjM0l2Ykc5allXd3ZiV1Z6YUY5elpYSjJhV05sY3k5WVdGaFlXQzlaV1ZsWldRcFNWVTVCVXoxeWIyOTBDZ3BRU1VSR1NVeEZQUzkyWVhJdmNuVnVMMWhZV0ZoWUxuQnBaQXBNVDBkR1NVeEZQUzkyWVhJdmJHOW5MMWhZV0ZoWUxteHZad29LYzNSaGNuUW9LU0I3Q2lBZ2FXWWdXeUF0WmlBaUpGQkpSRVpKVEVVaUlGMGdKaVlnYTJsc2JDQXRNQ0FrS0dOaGRDQWlKRkJKUkVaSlRFVWlLU0F5UGk5a1pYWXZiblZzYkRzZ2RHaGxiZ29nSUNBZ1pXTm9ieUFuVTJWeWRtbGpaU0JoYkhKbFlXUjVJSEoxYm01cGJtY25JRDRtTWdvZ0lDQWdjbVYwZFhKdUlERUtJQ0JtYVFvZ0lHVmphRzhnSjFOMFlYSjBhVzVuSUhObGNuWnBZMlhpZ0tZbklENG1NZ29nSUd4dlkyRnNJRU5OUkQwaUpGTkRVa2xRVkNCN2UxQkJVazFUZlgwZ0pqNGdYQ0lrVEU5SFJrbE1SVndpSUNZZ1pXTm9ieUJjSkNFaUNpQWdiRzlqWVd3Z1EwMUVVRUZVU0Qwa0tHVmphRzhnSkZORFVrbFFWQ0I4SUdGM2F5QW5leUJzWlc0OWMzQnNhWFFvSkRBc0lHRXNJQ0l2SWlrN0lIQnlhVzUwSUhOMVluTjBjaWdrTUN3Z01Dd2diR1Z1WjNSb0tDUXdLUzFzWlc1bmRHZ29ZVnRzWlc1ZEtTazdJSDBuS1FvZ0lHTmtJQ1JEVFVSUVFWUklDaUFnYzNVZ0xXTWdJaVJEVFVRaUlDUlNWVTVCVXlBK0lDSWtVRWxFUmtsTVJTSUtJQ0JsWTJodklDZFRaWEoyYVdObElITjBZWEowWldRbklENG1NZ3A5Q2dwemRHOXdLQ2tnZXdvZ0lHbG1JRnNnSVNBdFppQWlKRkJKUkVaSlRFVWlJRjA3SUhSb1pXNEtJQ0FnSUdWamFHOGdKMU5sY25acFkyVWdibTkwSUhKMWJtNXBibWNuSUQ0bU1nb2dJQ0FnY21WMGRYSnVJREVLSUNCbGJITmxDZ2x3YVdROUpDZ2dZMkYwSUNJa1VFbEVSa2xNUlNJZ0tRb0phV1lnYTJsc2JDQXRNQ0FrY0dsa0lESStMMlJsZGk5dWRXeHNPeUIwYUdWdUNpQWdJQ0FnSUdWamFHOGdKMU4wYjNCd2FXNW5JSE5sY25acFkyWGlnS1luSUQ0bU1nb2dJQ0FnSUNCcmFXeHNJQzB4TlNBa2NHbGtDaUFnSUNBZ0lHVmphRzhnSjFObGNuWnBZMlVnYzNSdmNIQmxaQ2NnUGlZeUNnbGxiSE5sQ2drZ0lHVmphRzhnSjFObGNuWnBZMlVnYm05MElISjFibTVwYm1jbkNnbG1hUW9KY20wZ0xXWWdKQ0pRU1VSR1NVeEZJZ29nSUdacENuMEtjbVZ6ZEdGeWRDZ3Bld29KYzNSdmNBb0pjM1JoY25RS2ZRcHpkR0YwZFhNb0tYc0tDV2xtSUZzZ0xXWWdJaVJRU1VSR1NVeEZJaUJkQ2dsMGFHVnVDZ2tKY0dsa1BTUW9JR05oZENBaUpGQkpSRVpKVEVVaUlDa0tDUWxwWmlCcmFXeHNJQzB3SUNSd2FXUWdNajR2WkdWMkwyNTFiR3c3SUhSb1pXNEtDUWtKWldOb2J5QWlXRmhZV0ZnZ2MzUmhjblF2Y25WdWJtbHVaeXdnY0hKdlkyVnpjeUFrY0dsa0lnb0pDV1ZzYzJVS0NRa0paV05vYnlBbldGaFlXRmdnYzNSdmNDOTNZV2wwYVc1bkp3b0pDV1pwQ2dsbGJITmxDZ2tKWldOb2J5QW5XRmhZV0ZnZ2MzUnZjQzkzWVdsMGFXNW5Kd29KWm1rS0NuMEtDZ3BqWVhObElDSWtNU0lnYVc0S0NYTjBZWEowS1FvSkNYTjBZWEowQ2drSk96c0tDWE4wYjNBcENna0pjM1J2Y0FvSkNUczdDZ2x5WlhOMFlYSjBLUW9KQ1hOMGIzQUtDUWx6ZEdGeWRBb0pDVHM3Q2dsemRHRjBkWE1wQ2drSmMzUmhkSFZ6Q2drSk96c0tDU29wQ2drSlpXTm9ieUFpVlhOaFoyVTZJSE5sY25acFkyVWdXRmhZV0ZnZ2UzTjBZWEowZkhOMGIzQjhjbVZ6ZEdGeWRIeHpkR0YwZFhOOUlnb0pDVHM3Q21WellXTUtaWGhwZENBd0Nnbz0nLCAnYmFzZTY0JykudG9TdHJpbmcoKS5zcGxpdCgnWFhYWFgnKS5qb2luKG9wdGlvbnMubmFtZSkuc3BsaXQoJ1lZWVlZJykuam9pbihvcHRpb25zLnRhcmdldCkucmVwbGFjZSgne3tQQVJNU319JywgcGFyYW1ldGVycykpOwogICAgICAgICAgICAgICAgICAgIGNvbmYuZW5kKCk7CgogICAgICAgICAgICAgICAgICAgIG0gPSByZXF1aXJlKCdmcycpLnN0YXRTeW5jKCcvZXRjL2luaXQuZC8nICsgb3B0aW9ucy5uYW1lKS5tb2RlOwogICAgICAgICAgICAgICAgICAgIG0gfD0gKHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JWFVTUiB8IHJlcXVpcmUoJ2ZzJykuQ0hNT0RfTU9ERVMuU19JWEdSUCk7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jaG1vZFN5bmMoJy9ldGMvaW5pdC5kLycgKyBvcHRpb25zLm5hbWUsIG0pOwogICAgICAgICAgICAgICAgICAgIHN3aXRjaCAob3B0aW9ucy5zdGFydFR5cGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdCT09UX1NUQVJUJzoKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnU1lTVEVNX1NUQVJUJzoKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnQVVUT19TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3VwZGF0ZS1yYy5kICcgKyBvcHRpb25zLm5hbWUgKyAnIGRlZmF1bHRzXG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgJ3Vwc3RhcnQnOgogICAgICAgICAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJykpIHsgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcycpOyB9CiAgICAgICAgICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lKSkgeyByZXF1aXJlKCdmcycpLm1rZGlyU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpOyB9CgogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY29weUZpbGVTeW5jKG9wdGlvbnMuc2VydmljZVBhdGgsICcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0KTsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnY29weWluZyAnICsgb3B0aW9ucy5zZXJ2aWNlUGF0aCk7CgogICAgICAgICAgICAgICAgICAgIHZhciBtID0gcmVxdWlyZSgnZnMnKS5zdGF0U3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCkubW9kZTsKICAgICAgICAgICAgICAgICAgICBtIHw9IChyZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhHUlApOwogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY2htb2RTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0LCBtKTsKCiAgICAgICAgICAgICAgICAgICAgY29uZiA9IHJlcXVpcmUoJ2ZzJykuY3JlYXRlV3JpdGVTdHJlYW0oJy9ldGMvaW5pdC8nICsgb3B0aW9ucy5uYW1lICsgJy5jb25mJywgeyBmbGFnczogJ3diJyB9KTsKICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKG9wdGlvbnMuc3RhcnRUeXBlKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnQk9PVF9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1NZU1RFTV9TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0FVVE9fU1RBUlQnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnc3RhcnQgb24gcnVubGV2ZWwgWzIzNDVdXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ3N0b3Agb24gcnVubGV2ZWwgWzAxNl1cblxuJyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPT0gbnVsbCB8fCBvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID4gMCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ3Jlc3Bhd25cblxuJyk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ2NoZGlyIC91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJ1xuJyk7CiAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnZXhlYyAvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0ICsgJyAnICsgcGFyYW1ldGVycyArICdcblxuJyk7CiAgICAgICAgICAgICAgICAgICAgY29uZi5lbmQoKTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgJ3N5c3RlbWQnOgogICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2aWNlRGVzY3JpcHRpb24gPSBvcHRpb25zLmRlc2NyaXB0aW9uID8gb3B0aW9ucy5kZXNjcmlwdGlvbiA6ICdNZXNoQ2VudHJhbCBBZ2VudCc7CgogICAgICAgICAgICAgICAgICAgIGlmICghcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJykpIHsgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcycpOyB9CiAgICAgICAgICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lKSkgeyByZXF1aXJlKCdmcycpLm1rZGlyU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpOyB9CgogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdjb3B5aW5nICcgKyBvcHRpb25zLnNlcnZpY2VQYXRoKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCAnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCk7CgogICAgICAgICAgICAgICAgICAgIHZhciBtID0gcmVxdWlyZSgnZnMnKS5zdGF0U3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCkubW9kZTsKICAgICAgICAgICAgICAgICAgICBtIHw9IChyZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhHUlApOwogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY2htb2RTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0LCBtKTsKCiAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbScpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uZiA9IHJlcXVpcmUoJ2ZzJykuY3JlYXRlV3JpdGVTdHJlYW0oJy9saWIvc3lzdGVtZC9zeXN0ZW0vJyArIG9wdGlvbnMubmFtZSArICcuc2VydmljZScsIHsgZmxhZ3M6ICd3YicgfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0nKSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbmYgPSByZXF1aXJlKCdmcycpLmNyZWF0ZVdyaXRlU3RyZWFtKCcvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgb3B0aW9ucy5uYW1lICsgJy5zZXJ2aWNlJywgeyBmbGFnczogJ3diJyB9KTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdGhyb3cgKCd1bmtub3duIGxvY2F0aW9uIGZvciBzeXN0ZW1kIGNvbmZpZ3VyYXRpb24gZmlsZXMnKTsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1tVbml0XVxuRGVzY3JpcHRpb249JyArIHNlcnZpY2VEZXNjcmlwdGlvbiArICdcbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1tTZXJ2aWNlXVxuJyk7CiAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnV29ya2luZ0RpcmVjdG9yeT0vdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICdcbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ0V4ZWNTdGFydD0vdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIG9wdGlvbnMudGFyZ2V0ICsgJyAnICsgcGFyYW1ldGVycyArICdcbicpOwogICAgICAgICAgICAgICAgICAgIGNvbmYud3JpdGUoJ1N0YW5kYXJkT3V0cHV0PW51bGxcbicpOwogICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID09IG51bGwgfHwgb3B0aW9ucy5mYWlsdXJlUmVzdGFydCA+IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdSZXN0YXJ0PW9uLWZhaWx1cmVcbicpOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy5mYWlsdXJlUmVzdGFydCA9PSBudWxsKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdSZXN0YXJ0U2VjPTNcbicpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnUmVzdGFydFNlYz0nICsgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgLyAxMDAwKSArICdcbicpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHN3aXRjaCAob3B0aW9ucy5zdGFydFR5cGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdCT09UX1NUQVJUJzoKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnU1lTVEVNX1NUQVJUJzoKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnQVVUT19TVEFSVCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25mLndyaXRlKCdbSW5zdGFsbF1cbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZi53cml0ZSgnQWxpYXM9JyArIG9wdGlvbnMubmFtZSArICcuc2VydmljZVxuJyk7IGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddLCB7IHR5cGU6IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5TcGF3blR5cGVzLlRFUk0gfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuX21vZHVsZU5hbWUgPSBvcHRpb25zLm5hbWU7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdzeXN0ZW1jdGwgZW5hYmxlICcgKyBvcHRpb25zLm5hbWUgKyAnLnNlcnZpY2VcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdleGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNvbmYuZW5kKCk7CgogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgZGVmYXVsdDogLy8gdW5rbm93biBwbGF0Zm9ybSBzZXJ2aWNlIHR5cGUKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnVW5rbm93biBTZXJ2aWNlIFBsYXRmb3JtIFR5cGU6ICcgKyBvcHRpb25zLnNlcnZpY2VQbGF0Zm9ybSk7CiAgICAgICAgICAgICAgICAgICAgdGhyb3cgKCdVbmtub3duIFNlcnZpY2UgUGxhdGZvcm0g", 16000);
	memcpy_s(_servicemanager + 96000, 21184, "VHlwZTogJyArIG9wdGlvbnMuc2VydmljZVBsYXRmb3JtKTsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKCF0aGlzLmlzQWRtaW4oKSkgeyB0aHJvdyAoJ0luc3RhbGxpbmcgYXMgU2VydmljZSwgcmVxdWlyZXMgcm9vdCcpOyB9CgogICAgICAgICAgICAvLyBNYWMgT1MKICAgICAgICAgICAgdmFyIHN0ZG91dHBhdGggPSAob3B0aW9ucy5zdGRvdXQgPyAoJzxrZXk+U3RhbmRhcmRPdXRQYXRoPC9rZXk+XG48c3RyaW5nPicgKyBvcHRpb25zLnN0ZG91dCArICc8L3N0cmluZz4nKSA6ICcnKTsKICAgICAgICAgICAgdmFyIGF1dG9TdGFydCA9IChvcHRpb25zLnN0YXJ0VHlwZSA9PSAnQVVUT19TVEFSVCcgPyAnPHRydWUvPicgOiAnPGZhbHNlLz4nKTsKICAgICAgICAgICAgdmFyIHBhcmFtcyA9ICAnICAgICA8a2V5PlByb2dyYW1Bcmd1bWVudHM8L2tleT5cbic7CiAgICAgICAgICAgIHBhcmFtcyArPSAnICAgICA8YXJyYXk+XG4nOwogICAgICAgICAgICBwYXJhbXMgKz0gKCcgICAgICAgICA8c3RyaW5nPi91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQgKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgaWYob3B0aW9ucy5wYXJhbWV0ZXJzKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBmb3IodmFyIGl0bSBpbiBvcHRpb25zLnBhcmFtZXRlcnMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcGFyYW1zICs9ICgnICAgICAgICAgPHN0cmluZz4nICsgb3B0aW9ucy5wYXJhbWV0ZXJzW2l0bV0gKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSAgICAgICAgCiAgICAgICAgICAgIHBhcmFtcyArPSAnICAgICA8L2FycmF5PlxuJzsKICAgICAgICAgICAgCiAgICAgICAgICAgIHZhciBwbGlzdCA9ICc8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJVVEYtOCI/PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gJzwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlIENvbXB1dGVyLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gJzxwbGlzdCB2ZXJzaW9uPSIxLjAiPlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gJyAgPGRpY3Q+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5MYWJlbDwva2V5PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gKCcgICAgIDxzdHJpbmc+JyArIG9wdGlvbnMubmFtZSArICc8L3N0cmluZz5cbicpOwogICAgICAgICAgICBwbGlzdCArPSAocGFyYW1zICsgJ1xuJyk7CiAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8a2V5PldvcmtpbmdEaXJlY3Rvcnk8L2tleT5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICgnICAgICA8c3RyaW5nPi91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgIHBsaXN0ICs9IChzdGRvdXRwYXRoICsgJ1xuJyk7CiAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8a2V5PlJ1bkF0TG9hZDwva2V5PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gKGF1dG9TdGFydCArICdcbicpOwogICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5LZWVwQWxpdmU8L2tleT5cbic7CiAgICAgICAgICAgIGlmKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPT0gbnVsbCB8fCBvcHRpb25zLmZhaWx1cmVSZXN0YXJ0ID4gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxkaWN0PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICAgICA8a2V5PkNyYXNoZWQ8L2tleT5cbic7CiAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgICAgPHRydWUvPlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8L2RpY3Q+XG4nOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxmYWxzZS8+XG4nOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgIT0gbnVsbCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+VGhyb3R0bGVJbnRlcnZhbDwva2V5PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8aW50ZWdlcj4nICsgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgLyAxMDAwKSArICc8L2ludGVnZXI+XG4nOwogICAgICAgICAgICB9CgogICAgICAgICAgICBwbGlzdCArPSAnICA8L2RpY3Q+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAnPC9wbGlzdD4nOwoKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcycpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMnKTsgfQogICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgb3B0aW9ucy5uYW1lICsgJy5wbGlzdCcpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAoIXJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUpKSB7IHJlcXVpcmUoJ2ZzJykubWtkaXJTeW5jKCcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSk7IH0KICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLmJpbmFyeSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQsIG9wdGlvbnMuYmluYXJ5KTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNvcHlGaWxlU3luYyhvcHRpb25zLnNlcnZpY2VQYXRoLCAnL3Vzci9sb2NhbC9tZXNoX3NlcnZpY2VzLycgKyBvcHRpb25zLm5hbWUgKyAnLycgKyBvcHRpb25zLnRhcmdldCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIG9wdGlvbnMubmFtZSArICcucGxpc3QnLCBwbGlzdCk7CiAgICAgICAgICAgICAgICB2YXIgbSA9IHJlcXVpcmUoJ2ZzJykuc3RhdFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQpLm1vZGU7CiAgICAgICAgICAgICAgICBtIHw9IChyZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVhHUlApOwogICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jaG1vZFN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgb3B0aW9ucy50YXJnZXQsIG0pOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCdTZXJ2aWNlOiAnICsgb3B0aW9ucy5uYW1lICsgJyBhbHJlYWR5IGV4aXN0cycpOwogICAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBpZiAob3B0aW9ucy5maWxlcykKICAgICAgICB7CiAgICAgICAgICAgIGZvciAodmFyIGkgaW4gb3B0aW9ucy5maWxlcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMuZmlsZXNbaV0uX2J1ZmZlcikKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnd3JpdGluZyAnICsgZXh0cmFjdEZpbGVOYW1lKG9wdGlvbnMuZmlsZXNbaV0pKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgb3B0aW9ucy5uYW1lICsgJy8nICsgZXh0cmFjdEZpbGVOYW1lKG9wdGlvbnMuZmlsZXNbaV0pLCBvcHRpb25zLmZpbGVzW2ldLl9idWZmZXIpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdjb3B5aW5nICcgKyBleHRyYWN0RmlsZVNvdXJjZShvcHRpb25zLmZpbGVzW2ldKSk7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5jb3B5RmlsZVN5bmMoZXh0cmFjdEZpbGVTb3VyY2Uob3B0aW9ucy5maWxlc1tpXSksICcvdXNyL2xvY2FsL21lc2hfc2VydmljZXMvJyArIG9wdGlvbnMubmFtZSArICcvJyArIGV4dHJhY3RGaWxlTmFtZShvcHRpb25zLmZpbGVzW2ldKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9CiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykKICAgIHsKICAgICAgICB0aGlzLmluc3RhbGxMYXVuY2hBZ2VudCA9IGZ1bmN0aW9uIGluc3RhbGxMYXVuY2hBZ2VudChvcHRpb25zKQogICAgICAgIHsKICAgICAgICAgICAgaWYgKCEob3B0aW9ucy51aWQgfHwgb3B0aW9ucy51c2VyKSAmJiAhdGhpcy5pc0FkbWluKCkpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRocm93ICgnSW5zdGFsbGluZyBhIEdsb2JhbCBBZ2VudC9EYWVtb24sIHJlcXVpcmVzIGFkbWluJyk7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHZhciBzZXJ2aWNlUGF0aFRva2VucyA9IG9wdGlvbnMuc2VydmljZVBhdGguc3BsaXQoJy8nKTsKICAgICAgICAgICAgc2VydmljZVBhdGhUb2tlbnMucG9wKCk7CiAgICAgICAgICAgIGlmIChzZXJ2aWNlUGF0aFRva2Vucy5wZWVrKCkgPT0gJy4nKSB7IHNlcnZpY2VQYXRoVG9rZW5zLnBvcCgpOyB9CiAgICAgICAgICAgIG9wdGlvbnMud29ya2luZ0RpcmVjdG9yeSA9IHNlcnZpY2VQYXRoVG9rZW5zLmpvaW4oJy8nKTsKCiAgICAgICAgICAgIHZhciBhdXRvU3RhcnQgPSAob3B0aW9ucy5zdGFydFR5cGUgPT0gJ0FVVE9fU1RBUlQnID8gJzx0cnVlLz4nIDogJzxmYWxzZS8+Jyk7CiAgICAgICAgICAgIHZhciBzdGRvdXRwYXRoID0gKG9wdGlvbnMuc3Rkb3V0ID8gKCc8a2V5PlN0YW5kYXJkT3V0UGF0aDwva2V5PlxuPHN0cmluZz4nICsgb3B0aW9ucy5zdGRvdXQgKyAnPC9zdHJpbmc+JykgOiAnJyk7CiAgICAgICAgICAgIHZhciBwYXJhbXMgPSAgICAgICAgICcgICAgIDxrZXk+UHJvZ3JhbUFyZ3VtZW50czwva2V5PlxuJzsKICAgICAgICAgICAgcGFyYW1zICs9ICAgICAgICAgICAgJyAgICAgPGFycmF5PlxuJzsKICAgICAgICAgICAgcGFyYW1zICs9ICAgICAgICAgICAoJyAgICAgICAgIDxzdHJpbmc+JyArIG9wdGlvbnMuc2VydmljZVBhdGggKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgaWYgKG9wdGlvbnMucGFyYW1ldGVycykgewogICAgICAgICAgICAgICAgZm9yICh2YXIgaXRtIGluIG9wdGlvbnMucGFyYW1ldGVycykKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBwYXJhbXMgKz0gICAoJyAgICAgICAgIDxzdHJpbmc+JyArIG9wdGlvbnMucGFyYW1ldGVyc1tpdG1dICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcGFyYW1zICs9ICAgICAgICAgICAgJyAgICAgPC9hcnJheT5cbic7CgogICAgICAgICAgICB2YXIgcGxpc3QgPSAnPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICc8IURPQ1RZUEUgcGxpc3QgUFVCTElDICItLy9BcHBsZSBDb21wdXRlci8vRFREIFBMSVNUIDEuMC8vRU4iICJodHRwOi8vd3d3LmFwcGxlLmNvbS9EVERzL1Byb3BlcnR5TGlzdC0xLjAuZHRkIj5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICc8cGxpc3QgdmVyc2lvbj0iMS4wIj5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICcgIDxkaWN0PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+TGFiZWw8L2tleT5cbic7CiAgICAgICAgICAgIHBsaXN0ICs9ICgnICAgICA8c3RyaW5nPicgKyBvcHRpb25zLm5hbWUgKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgcGxpc3QgKz0gKHBhcmFtcyArICdcbicpOwogICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5Xb3JraW5nRGlyZWN0b3J5PC9rZXk+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAoJyAgICAgPHN0cmluZz4nICsgb3B0aW9ucy53b3JraW5nRGlyZWN0b3J5ICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgIHBsaXN0ICs9IChzdGRvdXRwYXRoICsgJ1xuJyk7CiAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8a2V5PlJ1bkF0TG9hZDwva2V5PlxuJzsKICAgICAgICAgICAgcGxpc3QgKz0gKGF1dG9TdGFydCArICdcbicpOwogICAgICAgICAgICBpZiAob3B0aW9ucy5zZXNzaW9uVHlwZXMgJiYgb3B0aW9ucy5zZXNzaW9uVHlwZXMubGVuZ3RoID4gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+TGltaXRMb2FkVG9TZXNzaW9uVHlwZTwva2V5PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8YXJyYXk+XG4nOwogICAgICAgICAgICAgICAgZm9yICh2YXIgc3R5cGUgaW4gb3B0aW9ucy5zZXNzaW9uVHlwZXMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gKCcgICAgICAgICAgPHN0cmluZz4nICsgb3B0aW9ucy5zZXNzaW9uVHlwZXNbc3R5cGVdICsgJzwvc3RyaW5nPlxuJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPC9hcnJheT5cbic7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+S2VlcEFsaXZlPC9rZXk+XG4nOwogICAgICAgICAgICBpZiAob3B0aW9ucy5mYWlsdXJlUmVzdGFydCA9PSBudWxsIHx8IG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgPiAwKSB7CiAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGRpY3Q+XG4nOwogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgICAgIDxrZXk+Q3Jhc2hlZDwva2V5PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICAgICA8dHJ1ZS8+XG4nOwogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDwvZGljdD5cbic7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGZhbHNlLz5cbic7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgaWYgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgIT0gbnVsbCkgewogICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+VGhyb3R0bGVJbnRlcnZhbDwva2V5PlxuJzsKICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8aW50ZWdlcj4nICsgKG9wdGlvbnMuZmFpbHVyZVJlc3RhcnQgLyAxMDAwKSArICc8L2ludGVnZXI+XG4nOwogICAgICAgICAgICB9CgogICAgICAgICAgICBwbGlzdCArPSAnICA8L2RpY3Q+XG4nOwogICAgICAgICAgICBwbGlzdCArPSAnPC9wbGlzdD4nOwoKICAgICAgICAgICAgaWYgKG9wdGlvbnMudWlkKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBvcHRpb25zLnVzZXIgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuZ2V0VXNlcm5hbWUob3B0aW9ucy51aWQpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIAogICAgICAgICAgICB2YXIgZm9sZGVyID0gb3B0aW9ucy51c2VyID8gKHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRIb21lRm9sZGVyKG9wdGlvbnMudXNlcikgKyAnL0xpYnJhcnkvTGF1bmNoQWdlbnRzLycpIDogJy9MaWJyYXJ5L0xhdW5jaEFnZW50cy8nOwogICAgICAgICAgICBvcHRpb25zLmdpZCA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRHcm91cElEKG9wdGlvbnMudWlkKTsKICAgICAgICAgICAgaWYgKCFyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoZm9sZGVyKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5ta2RpclN5bmMoZm9sZGVyKTsKICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykuY2hvd25TeW5jKGZvbGRlciwgb3B0aW9ucy51aWQsIG9wdGlvbnMuZ2lkKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXF1aXJlKCdmcycpLndyaXRlRmlsZVN5bmMoZm9sZGVyICsgb3B0aW9ucy5uYW1lICsgJy5wbGlzdCcsIHBsaXN0KTsKICAgICAgICAgICAgaWYob3B0aW9ucy51c2VyKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLmNob3duU3luYyhmb2xkZXIgKyBvcHRpb25zLm5hbWUgKyAnLnBsaXN0Jywgb3B0aW9ucy51aWQsIG9wdGlvbnMuZ2lkKTsKICAgICAgICAgICAgfQogICAgICAgIH07CiAgICB9CiAgICB0aGlzLnVuaW5zdGFsbFNlcnZpY2UgPSBmdW5jdGlvbiB1bmluc3RhbGxTZXJ2aWNlKG5hbWUpCiAgICB7CiAgICAgICAgaWYgKCF0aGlzLmlzQWRtaW4oKSkgeyB0aHJvdyAoJ1VuaW5zdGFsbGluZyBhIHNlcnZpY2UsIHJlcXVpcmVzIGFkbWluJyk7IH0KCiAgICAgICAgaWYgKHR5cGVvZiAobmFtZSkgPT0gJ29iamVjdCcpIHsgbmFtZSA9IG5hbWUubmFtZTsgfQogICAgICAgIHZhciBzZXJ2aWNlID0gdGhpcy5nZXRTZXJ2aWNlKG5hbWUpOwogICAgICAgIHZhciBzZXJ2aWNlUGF0aCA9IHNlcnZpY2UuYXBwTG9jYXRpb24oKTsKCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykKICAgICAgICB7CiAgICAgICAgICAgIGlmIChzZXJ2aWNlLnN0YXR1cy5zdGF0ZSA9PSB1bmRlZmluZWQgfHwgc2VydmljZS5zdGF0dXMuc3RhdGUgPT0gJ1NUT1BQRUQnKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoc2VydmljZVBhdGgpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBpZiAodGhpcy5wcm94eS5EZWxldGVTZXJ2aWNlKHNlcnZpY2UuX3NlcnZpY2UpID09IDApCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdGhyb3cgKCdVbmluc3RhbGwgU2VydmljZSBmb3I6ICcgKyBuYW1lICsgJywgZmFpbGVkIHdpdGggZXJyb3I6ICcgKyB0aGlzLnByb3h5Mi5HZXRMYXN0RXJyb3IoKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Nhbm5vdCB1bmluc3RhbGwgc2VydmljZTogJyArIG5hbWUgKyAnLCBiZWNhdXNlIGl0IGlzOiAnICsgc2VydmljZS5zdGF0dXMuc3RhdGUpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHNlcnZpY2UuY2xvc2UoKTsKICAgICAgICAgICAgc2VydmljZSA9IG51bGw7CiAgICAgICAgfQogICAgICAgIGVsc2UgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnKQogICAgICAgIHsKICAgICAgICAgICAgc3dpdGNoICh0aGlzLmdldFNlcnZpY2VUeXBlKCkpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGNhc2UgJ2luaXQnOgogICAgICAgICAgICAgICAgY2FzZSAndXBzdGFydCc6CiAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2V0Yy9pbml0LmQvJyArIG5hbWUpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gaW5pdC5kIHNlcnZpY2UKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdzZXJ2aWNlICcgKyBuYW1lICsgJyBzdG9wXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCd1cGRhdGUtcmMuZCAtZiAnICsgbmFtZSArICcgcmVtb3ZlXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZGluLndyaXRlKCdleGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoJy9ldGMvaW5pdC5kLycgKyBuYW1lKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYyhzZXJ2aWNlUGF0aCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhuYW1lICsgJyB1bmluc3RhbGxlZCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhuYW1lICsgJyBjb3VsZCBub3QgYmUgdW5pbnN0YWxsZWQnLCBlKQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvaW5pdC8nICsgbmFtZSArICcuY29uZicpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gdXBzdGFydCBzZXJ2aWNlCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZSA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnc2VydmljZSAnICsgbmFtZSArICcgc3RvcFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS5zdGRpbi53cml0ZSgnZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKCcvZXRjL2luaXQvJyArIG5hbWUgKyAnLmNvbmYnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYyhzZXJ2aWNlUGF0aCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhuYW1lICsgJyB1bmluc3RhbGxlZCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhuYW1lICsgJyBjb3VsZCBub3QgYmUgdW5pbnN0YWxsZWQnLCBlKQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnc3lzdGVtZCc6CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddLCB7IHR5cGU6IHJlcXVpcmUoJ2NoaWxkX3Byb2Nl", 16000);
	memcpy_s(_servicemanager + 112000, 5184, "c3MnKS5TcGF3blR5cGVzLlRFUk0gfSk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fdXBkYXRlLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCBzdG9wICcgKyBuYW1lICsgJy5zZXJ2aWNlXG4nKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ3N5c3RlbWN0bCBkaXNhYmxlICcgKyBuYW1lICsgJy5zZXJ2aWNlXG4nKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl91cGRhdGUuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3VwZGF0ZS53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKHNlcnZpY2VQYXRoKTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgbmFtZSArICcuc2VydmljZScpKSB7IHJlcXVpcmUoJ2ZzJykudW5saW5rU3luYygnL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgbmFtZSArICcuc2VydmljZScpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbGliL3N5c3RlbWQvc3lzdGVtLycgKyBuYW1lICsgJy5zZXJ2aWNlJykpIHsgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKCcvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS8nICsgbmFtZSArICcuc2VydmljZScpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG5hbWUgKyAnIHVuaW5zdGFsbGVkJyk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobmFtZSArICcgY291bGQgbm90IGJlIHVuaW5zdGFsbGVkJywgZSkKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBkZWZhdWx0OiAvLyB1bmtub3duIHBsYXRmb3JtIHNlcnZpY2UgdHlwZQogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykKICAgICAgICB7CiAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIG5hbWUgKyAnLnBsaXN0JykpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnbGF1bmNoY3RsIHN0b3AgJyArIG5hbWUgKyAnXG4nKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdsYXVuY2hjdGwgdW5sb2FkIC9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIG5hbWUgKyAnLnBsaXN0XG4nKTsKICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdleGl0XG4nKTsKICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKHNlcnZpY2VQYXRoKTsKICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoJy9MaWJyYXJ5L0xhdW5jaERhZW1vbnMvJyArIG5hbWUgKyAnLnBsaXN0Jyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaChlKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRocm93ICgnRXJyb3IgdW5pbnN0YWxsaW5nIHNlcnZpY2U6ICcgKyBuYW1lICsgJyA9PiAnICsgZSk7CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5ybWRpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgbmFtZSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaChlKQogICAgICAgICAgICAgICAge30KICAgICAgICAgICAgfQogICAgICAgICAgICBlbHNlCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRocm93ICgnU2VydmljZTogJyArIG5hbWUgKyAnIGRvZXMgbm90IGV4aXN0Jyk7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdmcmVlYnNkJykKICAgICAgICB7CiAgICAgICAgICAgIHNlcnZpY2Uuc3RvcCgpOwogICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmMoc2VydmljZS5hcHBMb2NhdGlvbigpKTsKICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKHNlcnZpY2UucmMpOwogICAgICAgICAgICB0cnkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS5ybWRpclN5bmMoJy91c3IvbG9jYWwvbWVzaF9zZXJ2aWNlcy8nICsgbmFtZSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgIHsgfQogICAgICAgIH0KICAgIH0KICAgIGlmKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JykKICAgIHsKICAgICAgICB0aGlzLmdldFNlcnZpY2VUeXBlID0gZnVuY3Rpb24gZ2V0U2VydmljZVR5cGUoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHBsYXRmb3JtID0gcmVxdWlyZSgncHJvY2Vzcy1tYW5hZ2VyJykuZ2V0UHJvY2Vzc0luZm8oMSkuTmFtZTsKICAgICAgICAgICAgaWYgKHBsYXRmb3JtID09ICJidXN5Ym94IikKICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7DQogICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOyBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoYykgeyB0aGlzLnN0ciArPSBjLnRvU3RyaW5nKCk7IH0pOw0KICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJwcyAtYXggLW8gcGlkIC1vIGNvbW1hbmQgfCBhd2sgJ3sgaWYoJDE9PVwiMVwiKSB7ICQxPVwiXCI7IHNwbGl0KCQwLCByZXMsIFwiIFwiKTsgcHJpbnQgcmVzWzJdOyB9fSdcbmV4aXRcbiIpOw0KICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7DQogICAgICAgICAgICAgICAgcGxhdGZvcm0gPSBjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKTsNCiAgICAgICAgICAgIH0KICAgICAgICAgICAgaWYgKHBsYXRmb3JtID09ICdpbml0JykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgaWYocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvZXRjL2luaXQnKSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBwbGF0Zm9ybSA9ICd1cHN0YXJ0JzsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gKHBsYXRmb3JtKTsKICAgICAgICB9OwogICAgfQp9Cgptb2R1bGUuZXhwb3J0cyA9IHNlcnZpY2VNYW5hZ2VyOwptb2R1bGUuZXhwb3J0cy5tYW5hZ2VyID0gbmV3IHNlcnZpY2VNYW5hZ2VyKCk7CgppZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykKewogICAgbW9kdWxlLmV4cG9ydHMuZ2V0T1NWZXJzaW9uID0gZ2V0T1NWZXJzaW9uOwp9Cv==", 5184);
	ILibBase64DecodeEx((unsigned char*)_servicemanager, 117184, (unsigned char*)_servicemanager + 117184);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "service-manager"); duk_push_string(ctx, _servicemanager + 117184);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_servicemanager);

	char *_usersessions = ILibMemory_Allocate(89020, 0, NULL, NULL);
	memcpy_s(_usersessions + 0, 50868, "LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBOT1RJRllfRk9SX1RISVNfU0VTU0lPTiA9IDA7CnZhciBOT1RJRllfRk9SX0FMTF9TRVNTSU9OUyA9IDE7CnZhciBXTV9XVFNTRVNTSU9OX0NIQU5HRSA9IDB4MDJCMTsKdmFyIFdNX1BPV0VSQlJPQURDQVNUID0gMHgyMTg7CnZhciBQQlRfUE9XRVJTRVRUSU5HQ0hBTkdFID0gMHg4MDEzOwp2YXIgUEJUX0FQTVNVU1BFTkQgPSAweDQ7CnZhciBQQlRfQVBNUkVTVU1FU1VTUEVORCA9IDB4NzsKdmFyIFBCVF9BUE1SRVNVTUVBVVRPTUFUSUMgPSAweDEyOwp2YXIgUEJUX0FQTVBPV0VSU1RBVFVTQ0hBTkdFID0gMHhBOwoKdmFyIFdUU19DT05TT0xFX0NPTk5FQ1QgICAgICAgICA9ICgweDEpOwp2YXIgV1RTX0NPTlNPTEVfRElTQ09OTkVDVCAgICAgID0gKDB4Mik7CnZhciBXVFNfUkVNT1RFX0NPTk5FQ1QgICAgICAgICAgPSAoMHgzKTsKdmFyIFdUU19SRU1PVEVfRElTQ09OTkVDVCAgICAgICA9ICgweDQpOwp2YXIgV1RTX1NFU1NJT05fTE9HT04gICAgICAgICAgID0gKDB4NSk7CnZhciBXVFNfU0VTU0lPTl9MT0dPRkYgICAgICAgICAgPSAoMHg2KTsKdmFyIFdUU19TRVNTSU9OX0xPQ0sgICAgICAgICAgICA9ICgweDcpOwp2YXIgV1RTX1NFU1NJT05fVU5MT0NLICAgICAgICAgID0gKDB4OCk7CnZhciBXVFNfU0VTU0lPTl9SRU1PVEVfQ09OVFJPTCAgPSAoMHg5KTsKdmFyIFdUU19TRVNTSU9OX0NSRUFURSAgICAgICAgICA9ICgweEEpOwp2YXIgV1RTX1NFU1NJT05fVEVSTUlOQVRFICAgICAgID0gKDB4Qik7Cgp2YXIgR1VJRF9BQ0RDX1BPV0VSX1NPVVJDRTsKdmFyIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORzsKdmFyIEdVSURfQ09OU09MRV9ESVNQTEFZX1NUQVRFOwoKZnVuY3Rpb24gY29sdW1uUGFyc2UoZGF0YSwgZGVsaW1pdGVyKQp7CiAgICB2YXIgdG9rZW5zID0gZGF0YS5zcGxpdChkZWxpbWl0ZXIpOwogICAgdmFyIHJldCA9IFtdOwogICAgZm9yKHZhciBpIGluIHRva2VucykKICAgIHsKICAgICAgICBpZiAodG9rZW5zW2ldLmxlbmd0aCA+IDApIHsgcmV0LnB1c2godG9rZW5zW2ldKTsgfQogICAgfQogICAgcmV0dXJuIChyZXQpOwp9CgoKZnVuY3Rpb24gVXNlclNlc3Npb25zKCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAndXNlci1zZXNzaW9ucyc7CiAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbCh0aGlzLCB0cnVlKQogICAgICAgIC5jcmVhdGVFdmVudCgnY2hhbmdlZCcpCiAgICAgICAgLmNyZWF0ZUV2ZW50KCdsb2NrZWQnKQogICAgICAgIC5jcmVhdGVFdmVudCgndW5sb2NrZWQnKTsKCiAgICB0aGlzLmVudW1lcmF0ZVVzZXJzID0gZnVuY3Rpb24gZW51bWVyYXRlVXNlcnMoKQogICAgewogICAgICAgIHZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwogICAgICAgIHZhciBwID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKQogICAgICAgIHsKICAgICAgICAgICAgdGhpcy5fX3Jlc29sdmVyID0gcmVzOwogICAgICAgICAgICB0aGlzLl9fcmVqZWN0b3IgPSByZWo7CiAgICAgICAgfSk7CiAgICAgICAgcC5fX2hhbmRsZXIgPSBmdW5jdGlvbiBfX2hhbmRsZXIodXNlcnMpCiAgICAgICAgewogICAgICAgICAgICBwLl9fcmVzb2x2ZXIodXNlcnMpOwogICAgICAgIH07CiAgICAgICAgdHJ5CiAgICAgICAgewogICAgICAgICAgICB0aGlzLkN1cnJlbnQocC5fX2hhbmRsZXIpOwogICAgICAgIH0KICAgICAgICBjYXRjaChlKQogICAgICAgIHsKICAgICAgICAgICAgcC5fX3JlamVjdG9yKGUpOwogICAgICAgIH0KICAgICAgICBwLnBhcmVudCA9IHRoaXM7CiAgICAgICAgcmV0dXJuIChwKTsKICAgIH0KCiAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKQogICAgewogICAgICAgIHRoaXMuX3NlcnZpY2VIb29rZWQgPSBmYWxzZTsKICAgICAgICB0aGlzLl9tYXJzaGFsID0gcmVxdWlyZSgnX0dlbmVyaWNNYXJzaGFsJyk7CiAgICAgICAgdGhpcy5fa2VybmVsMzIgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdLZXJuZWwzMi5kbGwnKTsKICAgICAgICB0aGlzLl9rZXJuZWwzMi5DcmVhdGVNZXRob2QoJ0dldExhc3RFcnJvcicpOwogICAgICAgIHRoaXMuX2tlcm5lbDMyLkNyZWF0ZU1ldGhvZCgnV1RTR2V0QWN0aXZlQ29uc29sZVNlc3Npb25JZCcpCiAgICAgICAgCiAgICAgICAgdHJ5CiAgICAgICAgewogICAgICAgICAgICB0aGlzLl93dHMgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZU5hdGl2ZVByb3h5KCdXdHNhcGkzMi5kbGwnKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTRW51bWVyYXRlU2Vzc2lvbnNBJyk7CiAgICAgICAgICAgIHRoaXMuX3d0cy5DcmVhdGVNZXRob2QoJ1dUU1F1ZXJ5U2Vzc2lvbkluZm9ybWF0aW9uQScpOwogICAgICAgICAgICB0aGlzLl93dHMuQ3JlYXRlTWV0aG9kKCdXVFNSZWdpc3RlclNlc3Npb25Ob3RpZmljYXRpb24nKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTVW5SZWdpc3RlclNlc3Npb25Ob3RpZmljYXRpb24nKTsKICAgICAgICAgICAgdGhpcy5fd3RzLkNyZWF0ZU1ldGhvZCgnV1RTRnJlZU1lbW9yeScpOwogICAgICAgIH0KICAgICAgICBjYXRjaChleGMpCiAgICAgICAgewogICAgICAgIH0KCiAgICAgICAgdGhpcy5fYWR2YXBpID0gdGhpcy5fbWFyc2hhbC5DcmVhdGVOYXRpdmVQcm94eSgnQWR2YXBpMzIuZGxsJyk7CiAgICAgICAgdGhpcy5fYWR2YXBpLkNyZWF0ZU1ldGhvZCgnQWxsb2NhdGVBbmRJbml0aWFsaXplU2lkJyk7CiAgICAgICAgdGhpcy5fYWR2YXBpLkNyZWF0ZU1ldGhvZCgnQ2hlY2tUb2tlbk1lbWJlcnNoaXAnKTsKICAgICAgICB0aGlzLl9hZHZhcGkuQ3JlYXRlTWV0aG9kKCdGcmVlU2lkJyk7CgogICAgICAgIHRoaXMuX3VzZXIzMiA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoJ3VzZXIzMi5kbGwnKTsKICAgICAgICB0aGlzLl91c2VyMzIuQ3JlYXRlTWV0aG9kKHsgbWV0aG9kOiAnUmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24nLCB0aHJlYWREaXNwYXRjaDogMX0pOwogICAgICAgIHRoaXMuX3VzZXIzMi5DcmVhdGVNZXRob2QoJ1VucmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24nKTsKICAgICAgICB0aGlzLl9ycGNydCA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlTmF0aXZlUHJveHkoJ1JwY3J0NC5kbGwnKTsKICAgICAgICB0aGlzLl9ycGNydC5DcmVhdGVNZXRob2QoJ1V1aWRGcm9tU3RyaW5nQScpOwogICAgICAgIHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRCA9IGZ1bmN0aW9uIFN0cmluZ1RvVVVJRChndWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHJldFZhbCA9IFN0cmluZ1RvVVVJRC51cy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZSgxNik7CiAgICAgICAgICAgIGlmKFN0cmluZ1RvVVVJRC51cy5fcnBjcnQuVXVpZEZyb21TdHJpbmdBKFN0cmluZ1RvVVVJRC51cy5fbWFyc2hhbC5DcmVhdGVWYXJpYWJsZShndWlkKSwgcmV0VmFsKS5WYWwgPT0gMCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCdDb3VsZCBub3QgY29udmVydCBzdHJpbmcgdG8gVVVJRCcpOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRC51cyA9IHRoaXM7CgogICAgICAgIEdVSURfQUNEQ19QT1dFUl9TT1VSQ0UgPSB0aGlzLl9ycGNydC5TdHJpbmdUb1VVSUQoJzVkM2U5YTU5LWU5RDUtNGIwMC1hNmJkLWZmMzRmZjUxNjU0OCcpOwogICAgICAgIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORyA9IHRoaXMuX3JwY3J0LlN0cmluZ1RvVVVJRCgnYTdhZDgwNDEtYjQ1YS00Y2FlLTg3YTMtZWVjYmI0NjhhOWUxJyk7CiAgICAgICAgR1VJRF9DT05TT0xFX0RJU1BMQVlfU1RBVEUgPSB0aGlzLl9ycGNydC5TdHJpbmdUb1VVSUQoJzZmZTY5NTU2LTcwNGEtNDdhMC04ZjI0LWMyOGQ5MzZmZGE0NycpOwoKICAgICAgICB0aGlzLlNlc3Npb25TdGF0ZXMgPSBbJ0FjdGl2ZScsICdDb25uZWN0ZWQnLCAnQ29ubmVjdFF1ZXJ5JywgJ1NoYWRvdycsICdEaXNjb25uZWN0ZWQnLCAnSWRsZScsICdMaXN0ZW5pbmcnLCAnUmVzZXQnLCAnRG93bicsICdJbml0J107CiAgICAgICAgdGhpcy5JbmZvQ2xhc3MgPQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAnV1RTSW5pdGlhbFByb2dyYW0nOiAwLAogICAgICAgICAgICAgICAgJ1dUU0FwcGxpY2F0aW9uTmFtZSc6IDEsCiAgICAgICAgICAgICAgICAnV1RTV29ya2luZ0RpcmVjdG9yeSc6IDIsCiAgICAgICAgICAgICAgICAnV1RTT0VNSWQnOiAzLAogICAgICAgICAgICAgICAgJ1dUU1Nlc3Npb25JZCc6IDQsCiAgICAgICAgICAgICAgICAnV1RTVXNlck5hbWUnOiA1LAogICAgICAgICAgICAgICAgJ1dUU1dpblN0YXRpb25OYW1lJzogNiwKICAgICAgICAgICAgICAgICdXVFNEb21haW5OYW1lJzogNywKICAgICAgICAgICAgICAgICdXVFNDb25uZWN0U3RhdGUnOiA4LAogICAgICAgICAgICAgICAgJ1dUU0NsaWVudEJ1aWxkTnVtYmVyJzogOSwKICAgICAgICAgICAgICAgICdXVFNDbGllbnROYW1lJzogMTAsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50RGlyZWN0b3J5JzogMTEsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50UHJvZHVjdElkJzogMTIsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50SGFyZHdhcmVJZCc6IDEzLAogICAgICAgICAgICAgICAgJ1dUU0NsaWVudEFkZHJlc3MnOiAxNCwKICAgICAgICAgICAgICAgICdXVFNDbGllbnREaXNwbGF5JzogMTUsCiAgICAgICAgICAgICAgICAnV1RTQ2xpZW50UHJvdG9jb2xUeXBlJzogMTYsCiAgICAgICAgICAgICAgICAnV1RTSWRsZVRpbWUnOiAxNywKICAgICAgICAgICAgICAgICdXVFNMb2dvblRpbWUnOiAxOCwKICAgICAgICAgICAgICAgICdXVFNJbmNvbWluZ0J5dGVzJzogMTksCiAgICAgICAgICAgICAgICAnV1RTT3V0Z29pbmdCeXRlcyc6IDIwLAogICAgICAgICAgICAgICAgJ1dUU0luY29taW5nRnJhbWVzJzogMjEsCiAgICAgICAgICAgICAgICAnV1RTT3V0Z29pbmdGcmFtZXMnOiAyMiwKICAgICAgICAgICAgICAgICdXVFNDbGllbnRJbmZvJzogMjMsCiAgICAgICAgICAgICAgICAnV1RTU2Vzc2lvbkluZm8nOiAyNCwKICAgICAgICAgICAgICAgICdXVFNTZXNzaW9uSW5mb0V4JzogMjUsCiAgICAgICAgICAgICAgICAnV1RTQ29uZmlnSW5mbyc6IDI2LAogICAgICAgICAgICAgICAgJ1dUU1ZhbGlkYXRpb25JbmZvJzogMjcsCiAgICAgICAgICAgICAgICAnV1RTU2Vzc2lvbkFkZHJlc3NWNCc6IDI4LAogICAgICAgICAgICAgICAgJ1dUU0lzUmVtb3RlU2Vzc2lvbic6IDI5CiAgICAgICAgICAgIH07CgogICAgICAgIHRoaXMuaXNSb290ID0gZnVuY3Rpb24gaXNSb290KCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBOVEF1dGhvcml0eSA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlVmFyaWFibGUoNik7CiAgICAgICAgICAgIE5UQXV0aG9yaXR5LnRvQnVmZmVyKCkud3JpdGVJbnQ4KDUsIDUpOwoKICAgICAgICAgICAgdmFyIEFkbWluaXN0cmF0b3JzR3JvdXAgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGFkbWluID0gZmFsc2U7CgogICAgICAgICAgICBpZiAodGhpcy5fYWR2YXBpLkFsbG9jYXRlQW5kSW5pdGlhbGl6ZVNpZChOVEF1dGhvcml0eSwgMiwgMzIsIDU0NCwgMCwgMCwgMCwgMCwgMCwgMCwgQWRtaW5pc3RyYXRvcnNHcm91cCkuVmFsICE9IDApCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBtZW1iZXIgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZUludGVnZXIoKTsKICAgICAgICAgICAgICAgIGlmICh0aGlzLl9hZHZhcGkuQ2hlY2tUb2tlbk1lbWJlcnNoaXAoMCwgQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpLCBtZW1iZXIpLlZhbCAhPSAwKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGlmIChtZW1iZXIudG9CdWZmZXIoKS5yZWFkVUludDMyTEUoKSAhPSAwKSB7IGFkbWluID0gdHJ1ZTsgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgdGhpcy5fYWR2YXBpLkZyZWVTaWQoQWRtaW5pc3RyYXRvcnNHcm91cC5EZXJlZigpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gYWRtaW47CiAgICAgICAgfQoKICAgICAgICB0aGlzLmdldFNlc3Npb25BdHRyaWJ1dGUgPSBmdW5jdGlvbiBnZXRTZXNzaW9uQXR0cmlidXRlKHNlc3Npb25JZCwgYXR0cikKICAgICAgICB7CiAgICAgICAgICAgIHZhciBidWZmZXIgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVBvaW50ZXIoKTsKICAgICAgICAgICAgdmFyIGJ5dGVzUmV0dXJuZWQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwoKICAgICAgICAgICAgaWYgKHRoaXMuX3d0cy5XVFNRdWVyeVNlc3Npb25JbmZvcm1hdGlvbkEoMCwgc2Vzc2lvbklkLCBhdHRyLCBidWZmZXIsIGJ5dGVzUmV0dXJuZWQpLlZhbCA9PSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIGNhbGxpbmcgV1RTUXVlcnlTZXNzaW9uSW5mb3JtYXRpb246ICcgKyB0aGlzLl9rZXJuZWwzMi5HZXRMYXN0RXJyb3IuVmFsKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgdmFyIHJldFZhbCA9IGJ1ZmZlci5EZXJlZigpLlN0cmluZzsKCiAgICAgICAgICAgIHRoaXMuX3d0cy5XVFNGcmVlTWVtb3J5KGJ1ZmZlci5EZXJlZigpKTsKICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgIH07CiAgICAgICAgdGhpcy5jb25zb2xlVWlkID0gZnVuY3Rpb24gY29uc29sZVVpZCgpCiAgICAgICAgewogICAgICAgICAgICB2YXIgaWQgPSB0aGlzLl9rZXJuZWwzMi5XVFNHZXRBY3RpdmVDb25zb2xlU2Vzc2lvbklkKCkuVmFsOwogICAgICAgICAgICBpZihpZD09MHhGRkZGRkZGRikge3Rocm93KCdOb2JvZHkgbG9nZ2VkIGluJyk7fQogICAgICAgICAgICByZXR1cm4gKGlkKTsKICAgICAgICB9OwogICAgICAgIHRoaXMuQ3VycmVudCA9IGZ1bmN0aW9uIEN1cnJlbnQoY2IpCiAgICAgICAgewogICAgICAgICAgICB2YXIgcmV0VmFsID0ge307CiAgICAgICAgICAgIHZhciBwaW5mbyA9IHRoaXMuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcigpOwogICAgICAgICAgICB2YXIgY291bnQgPSB0aGlzLl9tYXJzaGFsLkNyZWF0ZVZhcmlhYmxlKDQpOwogICAgICAgICAgICBpZiAodGhpcy5fd3RzLldUU0VudW1lcmF0ZVNlc3Npb25zQSgwLCAwLCAxLCBwaW5mbywgY291bnQpLlZhbCA9PSAwKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aHJvdyAoJ0Vycm9yIGNhbGxpbmcgV1RTRW51bWVyYXRlU2Vzc2lvbnNBOiAnICsgdGhpcy5fa2VybmVsMzIuR2V0TGFzdEVycm9yKCkuVmFsKTsKICAgICAgICAgICAgfQoKICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBjb3VudC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpIDsgKytpKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgaW5mbyA9IHBpbmZvLkRlcmVmKCkuRGVyZWYoaSAqICh0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyAxMiA6IDI0KSwgdGhpcy5fbWFyc2hhbC5Qb2ludGVyU2l6ZSA9PSA0ID8gMTIgOiAyNCk7CiAgICAgICAgICAgICAgICB2YXIgaiA9IHsgU2Vzc2lvbklkOiBpbmZvLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkgfTsKICAgICAgICAgICAgICAgIGouU3RhdGlvbk5hbWUgPSBpbmZvLkRlcmVmKHRoaXMuX21hcnNoYWwuUG9pbnRlclNpemUgPT0gNCA/IDQgOiA4LCB0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplKS5EZXJlZigpLlN0cmluZzsKICAgICAgICAgICAgICAgIGouU3RhdGUgPSB0aGlzLlNlc3Npb25TdGF0ZXNbaW5mby5EZXJlZih0aGlzLl9tYXJzaGFsLlBvaW50ZXJTaXplID09IDQgPyA4IDogMTYsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCldOwogICAgICAgICAgICAgICAgaWYgKGouU3RhdGUgPT0gJ0FjdGl2ZScpIHsKICAgICAgICAgICAgICAgICAgICBqLlVzZXJuYW1lID0gdGhpcy5nZXRTZXNzaW9uQXR0cmlidXRlKGouU2Vzc2lvbklkLCB0aGlzLkluZm9DbGFzcy5XVFNVc2VyTmFtZSk7CiAgICAgICAgICAgICAgICAgICAgai5Eb21haW4gPSB0aGlzLmdldFNlc3Npb25BdHRyaWJ1dGUoai5TZXNzaW9uSWQsIHRoaXMuSW5mb0NsYXNzLldUU0RvbWFpbk5hbWUpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcmV0VmFsW2ouU2Vzc2lvbklkXSA9IGo7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHRoaXMuX3d0cy5XVFNGcmVlTWVtb3J5KHBpbmZvLkRlcmVmKCkpOwoKICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldFZhbCwgJ0FjdGl2ZScsIHsgdmFsdWU6IHNob3dBY3RpdmVPbmx5KHJldFZhbCkgfSk7CiAgICAgICAgICAgIGlmIChjYikgeyBjYihyZXRWYWwpOyB9CiAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICB9OwoKCiAgICAgICAgLy8gV2UgbmVlZCB0byBzcGluIHVwIGEgbWVzc2FnZSBwdW1wLCBhbmQgZmV0Y2ggYSB3aW5kb3cgaGFuZGxlCiAgICAgICAgdmFyIG1lc3NhZ2VfcHVtcCA9IHJlcXVpcmUoJ3dpbi1tZXNzYWdlLXB1bXAnKTsKICAgICAgICB0aGlzLl9tZXNzYWdlcHVtcCA9IG5ldyBtZXNzYWdlX3B1bXAoeyBmaWx0ZXI6IFdNX1dUU1NFU1NJT05fQ0hBTkdFIH0pOyB0aGlzLl9tZXNzYWdlcHVtcC5wYXJlbnQgPSB0aGlzOyAgICAgCiAgICAgICAgdGhpcy5fbWVzc2FnZXB1bXAub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgeyB0aGlzLnBhcmVudC5fd3RzLldUU1VuUmVnaXN0ZXJTZXNzaW9uTm90aWZpY2F0aW9uKHRoaXMucGFyZW50Lmh3bmQpOyB9KTsKICAgICAgICB0aGlzLl9tZXNzYWdlcHVtcC5vbignaHduZCcsIGZ1bmN0aW9uIChoKQogICAgICAgIHsKICAgICAgICAgICAgdGhpcy5wYXJlbnQuaHduZCA9IGg7CgogICAgICAgICAgICAvLyBXZSBuZWVkIHRvIHlpZWxkLCBhbmQgZG8gdGhpcyBpbiB0aGUgbmV4dCBldmVudCBsb29wIHBhc3MsIGJlY3Vhc2Ugd2UgZG9uJ3Qgd2FudCB0byBjYWxsICdSZWdpc3RlclBvd2VyU2V0dGluZ05vdGlmaWNhdGlvbicKICAgICAgICAgICAgLy8gZnJvbSB0aGUgbWVzc2FnZXB1bXAgJ3RocmVhZCcsIGJlY2F1c2Ugd2UgYXJlIGFjdHVhbGx5IG9uIHRoZSBtaWNyb3N0YWNrIHRocmVhZCwgc3VjaCB0aGF0IHRoZSBtZXNzYWdlIHB1bXAgdGhyZWFkLCBpcyBob2xkaW5nCiAgICAgICAgICAgIC8vIG9uIGEgc2VtYXBob3JlIGZvciB1cyB0byByZXR1cm4uIElmIHdlIGNhbGwgbm93LCB3ZSBtYXkgZGVhZGxvY2sgb24gV2luZG93cyA3LCBiZWN1YXNlIGl0IHdpbGwgdHJ5IHRvIG5vdGlmeSBpbW1lZGlhdGVseQogICAgICAgICAgICB0aGlzLmltbWVkaWF0ZSA9IHNldEltbWVkaWF0ZShmdW5jdGlvbiAoc2VsZikKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gTm93IHRoYXQgd2UgaGF2ZSBhIHdpbmRvdyBoYW5kbGUsIHdlIGNhbiByZWdpc3RlciBpdCB0byByZWNlaXZlIFdpbmRvd3MgTWVzc2FnZXMKICAgICAgICAgICAgICAgIGlmIChzZWxmLnBhcmVudC5fd3RzKSB7IHNlbGYucGFyZW50Ll93dHMuV1RTUmVnaXN0ZXJTZXNzaW9uTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIE5PVElGWV9GT1JfQUxMX1NFU1NJT05TKTsgfQogICAgICAgICAgICAgICAgc2VsZi5wYXJlbnQuX3VzZXIzMi5BQ0RDX0ggPSBzZWxmLnBhcmVudC5fdXNlcjMyLlJlZ2lzdGVyUG93ZXJTZXR0aW5nTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIEdVSURfQUNEQ19QT1dFUl9TT1VSQ0UsIDApOwogICAgICAgICAgICAgICAgc2VsZi5wYXJlbnQuX3VzZXIzMi5CQVRUX0ggPSBzZWxmLnBhcmVudC5fdXNlcjMyLlJlZ2lzdGVyUG93ZXJTZXR0aW5nTm90aWZpY2F0aW9uKHNlbGYucGFyZW50Lmh3bmQsIEdVSURfQkFUVEVSWV9QRVJDRU5UQUdFX1JFTUFJTklORywgMCk7CiAgICAgICAgICAgICAgICBzZWxmLnBhcmVudC5fdXNlcjMyLkRJU1BfSCA9IHNlbGYucGFyZW50Ll91c2VyMzIuUmVnaXN0ZXJQb3dlclNldHRpbmdOb3RpZmljYXRpb24oc2VsZi5wYXJlbnQuaHduZCwgR1VJRF9DT05TT0xFX0RJU1BMQVlfU1RBVEUsIDApOwogICAgICAgICAgICAgICAgLy9jb25zb2xlLmxvZyhzZWxmLnBhcmVudC5fdXNlcjMyLkFDRENfSC5WYWwsIHNlbGYucGFyZW50Ll91c2VyMzIuQkFUVF9ILlZhbCwgc2VsZi5wYXJlbnQuX3VzZXIzMi5ESVNQX0guVmFsKTsKICAgICAgICAgICAgfSwgdGhpcyk7CiAgICAgICAgfSk7CiAgICAgICAgdGhpcy5fbWVzc2FnZXB1bXAub24oJ21lc3NhZ2UnLCBmdW5jdGlvbiAobXNnKQogICAgICAgIHsKICAgICAgICAgICAgc3dpdGNoKG1zZy5tZXNzYWdlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBjYXNlIFdNX1dUU1NFU1NJT05fQ0hBTkdFOgogICAgICAgICAgICAgICAgICAgIHN3aXRjaChtc2cud3BhcmFtKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBXVFNfU0VTU0lPTl9MT0NLOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuZW51bWVyYXRlVXNlcnMoKS50aGVuKGZ1bmN0aW9uICh1c2VycykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodXNlcnNbbXNnLmxwYXJhbV0pIHsgdGhpcy5wYXJlbnQuZW1pdCgnbG9ja2VkJywgdXNlcnNbbXNnLmxwYXJhbV0pOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX1VOTE9DSzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmVudW1lcmF0ZVVzZXJzKCkudGhlbihmdW5jdGlvbiAodXNlcnMpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHVzZXJzW21zZy5scGFyYW1dKSB7IHRoaXMucGFyZW50LmVtaXQoJ3VubG9ja2VkJywgdXNlcnNbbXNnLmxwYXJhbV0pOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX0xPR09OOgogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFdUU19TRVNTSU9OX0xPR09GRjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAg", 16000);
	memcpy_s(_usersessions + 16000, 34868, "ICAgICAgICAgIGNhc2UgV01fUE9XRVJCUk9BRENBU1Q6CiAgICAgICAgICAgICAgICAgICAgc3dpdGNoKG1zZy53cGFyYW0pCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ1dNX1BPV0VSQlJPQURDQVNUIFtVTktOT1dOIHdwYXJhbV06ICcgKyBtc2cud3BhcmFtKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFBCVF9BUE1TVVNQRU5EOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1NMRUVQJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBQQlRfQVBNUkVTVU1FQVVUT01BVElDOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1JFU1VNRV9OT05fSU5URVJBQ1RJVkUnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFBCVF9BUE1SRVNVTUVTVVNQRU5EOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ3N4JywgJ1JFU1VNRV9JTlRFUkFDVElWRScpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgUEJUX0FQTVBPV0VSU1RBVFVTQ0hBTkdFOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlIFBCVF9QT1dFUlNFVFRJTkdDSEFOR0U6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbHBhcmFtID0gdGhpcy5wYXJlbnQuX21hcnNoYWwuQ3JlYXRlUG9pbnRlcihCdWZmZXIuZnJvbShtc2cubHBhcmFtX2hleCwgJ2hleCcpKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBkYXRhID0gbHBhcmFtLkRlcmVmKDIwLCBscGFyYW0uRGVyZWYoMTYsIDQpLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKDApKS50b0J1ZmZlcigpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGxwYXJhbS5EZXJlZigwLCAxNikudG9CdWZmZXIoKS50b1N0cmluZygnaGV4JykpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBHVUlEX0FDRENfUE9XRVJfU09VUkNFLkRlcmVmKDAsIDE2KS50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGRhdGEucmVhZFVJbnQzMkxFKDApKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2FjZGMnLCAnQUMnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnYWNkYycsICdCQVRURVJZJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDI6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2FjZGMnLCAnSE9UJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBHVUlEX0JBVFRFUllfUEVSQ0VOVEFHRV9SRU1BSU5JTkcuRGVyZWYoMCwgMTYpLnRvQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnYmF0dGVyeUxldmVsJywgZGF0YS5yZWFkVUludDMyTEUoMCkpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEdVSURfQ09OU09MRV9ESVNQTEFZX1NUQVRFLkRlcmVmKDAsIDE2KS50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGRhdGEucmVhZFVJbnQzMkxFKDApKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2Rpc3BsYXknLCAnT0ZGJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIDE6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgncG93ZXItbW9uaXRvcicpLmVtaXQoJ2Rpc3BsYXknLCAnT04nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwb3dlci1tb25pdG9yJykuZW1pdCgnZGlzcGxheScsICdESU1NRUQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgIH0KICAgIGVsc2UgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnbGludXgnIHx8IHByb2Nlc3MucGxhdGZvcm0gPT0gJ2ZyZWVic2QnKQogICAgewogICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICAgICAgewogICAgICAgICAgICB2YXIgZGJ1cyA9IHJlcXVpcmUoJ2xpbnV4LWRidXMnKTsKICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykud2F0Y2gpIHsKICAgICAgICAgICAgICAgIHRoaXMuX2xpbnV4V2F0Y2hlciA9IHJlcXVpcmUoJ2ZzJykud2F0Y2goJy92YXIvcnVuL3V0bXAnKTsKICAgICAgICAgICAgICAgIHRoaXMuX2xpbnV4V2F0Y2hlci51c2VyX3Nlc3Npb24gPSB0aGlzOwogICAgICAgICAgICAgICAgdGhpcy5fbGludXhXYXRjaGVyLm9uKCdjaGFuZ2UnLCBmdW5jdGlvbiAoYSwgYikgewogICAgICAgICAgICAgICAgICAgIHRoaXMudXNlcl9zZXNzaW9uLmVtaXQoJ2NoYW5nZWQnKTsKICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHRoaXMuQ3VycmVudCA9IGZ1bmN0aW9uIEN1cnJlbnQoY2IpIHsKICAgICAgICAgICAgICAgIHZhciByZXRWYWwgPSB7fTsKICAgICAgICAgICAgICAgIHJldFZhbC5fT2JqZWN0SUQgPSAnVXNlclNlc3Npb24nCiAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0VmFsLCAnX2NhbGxiYWNrJywgeyB2YWx1ZTogY2IgfSk7CiAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkocmV0VmFsLCAnX2NoaWxkJywgeyB2YWx1ZTogcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvdXNyL2Jpbi9sYXN0JywgWydsYXN0JywgJy1mJywgJy92YXIvcnVuL3V0bXAnXSkgfSk7CgogICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5QYXJlbnQgPSByZXRWYWw7CiAgICAgICAgICAgICAgICByZXRWYWwuX2NoaWxkLl90eHQgPSAnJzsKICAgICAgICAgICAgICAgIHJldFZhbC5fY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgewogICAgICAgICAgICAgICAgICAgIHZhciBsaW5lcyA9IHRoaXMuX3R4dC5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbnMgPSBbXTsKICAgICAgICAgICAgICAgICAgICB2YXIgdXNlcnMgPSB7fTsKCiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBsaW5lcykgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAobGluZXNbaV0pIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSBnZXRUb2tlbnMobGluZXNbaV0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHMgPSB7IFVzZXJuYW1lOiB0b2tlbnNbMF0sIFNlc3Npb25JZDogdG9rZW5zWzFdIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0b2tlbnNbM10uaW5jbHVkZXMoJ3N0aWxsIGxvZ2dlZCBpbicpKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcy5TdGF0ZSA9ICdBY3RpdmUnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcy5MYXN0QWN0aXZlID0gdG9rZW5zWzNdOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlc3Npb25zLnB1c2gocyk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbnMucG9wKCk7CgoKICAgICAgICAgICAgICAgICAgICB2YXIgdXNlcm5hbWVzID0ge307CiAgICAgICAgICAgICAgICAgICAgdmFyIHByb21pc2VzID0gW107CgogICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGkgaW4gc2Vzc2lvbnMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNlc3Npb25zW2ldLlVzZXJuYW1lICE9ICdyZWJvb3QnKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1c2Vyc1tzZXNzaW9uc1tpXS5TZXNzaW9uSWRdID0gc2Vzc2lvbnNbaV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodXNlcm5hbWVzW3Nlc3Npb25zW2ldLlVzZXJuYW1lXSA9PSBudWxsKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWVzW3Nlc3Npb25zW2ldLlVzZXJuYW1lXSA9IC0xOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdwcm9taXNlJyk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh1c2VycywgJ0FjdGl2ZScsIHsgdmFsdWU6IHNob3dBY3RpdmVPbmx5KHVzZXJzKSB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuUGFyZW50Ll9jYWxsYmFjaykgeyB0aGlzLlBhcmVudC5fY2FsbGJhY2suY2FsbCh0aGlzLlBhcmVudCwgdXNlcnMpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIHZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwogICAgICAgICAgICAgICAgICAgIGZvciAodmFyIG4gaW4gdXNlcm5hbWVzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBwID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9fdXNlcm5hbWUgPSBuOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fX3Jlc29sdmVyID0gcmVzOyB0aGlzLl9fcmVqZWN0b3IgPSByZWo7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9fY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy91c3IvYmluL2lkJywgWydpZCcsICctdScsIG5dKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX19jaGlsZC5wcm9taXNlID0gdGhpczsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX19jaGlsZC5zdGRvdXQuX3R4dCA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fX2NoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLl90eHQgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9fY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcnNlSW50KHRoaXMuc3Rkb3V0Ll90eHQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX19yZWplY3RvcignaW52YWxpZCB1aWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGlkID0gcGFyc2VJbnQodGhpcy5zdGRvdXQuX3R4dCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9fcmVzb2x2ZXIoaWQpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgICAgICBwcm9taXNlcy5wdXNoKHApOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBwcm9taXNlLmFsbChwcm9taXNlcykudGhlbihmdW5jdGlvbiAocGxpc3QpIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gRG9uZQogICAgICAgICAgICAgICAgICAgICAgICB2YXIgdGFibGUgPSB7fTsKICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBwbGlzdCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVbcGxpc3RbaV0uX191c2VybmFtZV0gPSBwbGlzdFtpXS5faW50ZXJuYWwuY29tcGxldGVkQXJnc1swXTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpIGluIHVzZXJzKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1c2Vyc1tpXS51aWQgPSB0YWJsZVt1c2Vyc1tpXS5Vc2VybmFtZV07CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHVzZXJzLCAnQWN0aXZlJywgeyB2YWx1ZTogc2hvd0FjdGl2ZU9ubHkodXNlcnMpIH0pOwogICAgICAgICAgICAgICAgICAgICAgICBpZiAocmV0VmFsLl9jYWxsYmFjaykgeyByZXRWYWwuX2NhbGxiYWNrLmNhbGwocmV0VmFsLCB1c2Vycyk7IH0KICAgICAgICAgICAgICAgICAgICB9LCBmdW5jdGlvbiAocmVhc29uKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIC8vIEZhaWxlZAogICAgICAgICAgICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodXNlcnMsICdBY3RpdmUnLCB7IHZhbHVlOiBzaG93QWN0aXZlT25seSh1c2VycykgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXRWYWwuX2NhbGxiYWNrKSB7IHJldFZhbC5fY2FsbGJhY2suY2FsbChyZXRWYWwsIHVzZXJzKTsgfQogICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgfSk7CiAgICAgICAgICAgICAgICByZXRWYWwuX2NoaWxkLnN0ZG91dC5QYXJlbnQgPSByZXRWYWwuX2NoaWxkOwogICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5QYXJlbnQuX3R4dCArPSBjaHVuay50b1N0cmluZygpOyB9KTsKCiAgICAgICAgICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgdGhpcy5fcmVjaGVja0xvZ2dlZEluVXNlcnMgPSBmdW5jdGlvbiBfcmVjaGVja0xvZ2dlZEluVXNlcnMoKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aGlzLmVudW1lcmF0ZVVzZXJzKCkudGhlbihmdW5jdGlvbiAodSkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBpZiAodS5BY3RpdmUubGVuZ3RoID4gMCkgewogICAgICAgICAgICAgICAgICAgICAgICAvLyBUaGVyZSBpcyBhbHJlYWR5IGEgdXNlciBsb2dnZWQgaW4sIHNvIHdlIGNhbiBtb25pdG9yIERCVVMgZm9yIGxvY2svdW5sb2NrCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnBhcmVudC5fbGludXhfbG9ja193YXRjaGVyICE9IG51bGwgJiYgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlci51aWQgIT0gdS5BY3RpdmVbMF0udWlkKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxldGUgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlcjsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcmVudC5fbGludXhfbG9ja193YXRjaGVyID0gbmV3IGRidXMocHJvY2Vzcy5lbnZbJ1hER19DVVJSRU5UX0RFU0tUT1AnXSA9PSAnVW5pdHknID8gJ2NvbS51YnVudHUuVXBzdGFydDBfNicgOiAnb3JnLmdub21lLlNjcmVlblNhdmVyJywgdS5BY3RpdmVbMF0udWlkKTsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlci51c2VyX3Nlc3Npb24gPSB0aGlzLnBhcmVudDsKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlci5vbignc2lnbmFsJywgZnVuY3Rpb24gKHMpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBwID0gdGhpcy51c2VyX3Nlc3Npb24uZW51bWVyYXRlVXNlcnMoKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHAuc2lnbmFsRGF0YSA9IHMuZGF0YVswXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHAudGhlbihmdW5jdGlvbiAodSkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaCAodGhpcy5zaWduYWxEYXRhKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgdHJ1ZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnZGVza3RvcC1sb2NrJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmVtaXQoJ2xvY2tlZCcsIHUuQWN0aXZlWzBdKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIGZhbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdkZXNrdG9wLXVubG9jayc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcmVudC5lbWl0KCd1bmxvY2tlZCcsIHUuQWN0aXZlWzBdKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAodGhpcy5wYXJlbnQuX2xpbnV4X2xvY2tfd2F0Y2hlciAhPSBudWxsKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSB0aGlzLnBhcmVudC5fbGludXhfbG9ja193YXRjaGVyOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0pOwoKICAgICAgICAgICAgfTsKICAgICAgICAgICAgdGhpcy5nZXRVaWRDb25maWcgPSBmdW5jdGlvbiBnZXRVaWRDb25maWcoKSB7CiAgICAgICAgICAgICAgICB2YXIgcmV0ID0ge307CiAgICAgICAgICAgICAgICB2YXIgY2ZnID0gcmVxdWlyZSgnZnMnKS5yZWFkRmlsZVN5bmMoJy9ldGMvbG9naW4uZGVmcycpLnRvU3RyaW5nKCkuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgICAgICB2YXIgdG9rZW5zOwogICAgICAgICAgICAgICAgZm9yICh2YXIgaSBpbiBjZmcpIHsKICAgICAgICAgICAgICAgICAgICB0b2tlbnMgPSBjb2x1bW5QYXJzZShjZmdbaV0sICdcdCcpOyAvL2NvbnNvbGUubG9nKHRva2Vucyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2Vuc1swXSA9PSAnVUlEX01JTicpIHsgcmV0Lk1JTiA9IHBhcnNlSW50KHRva2Vuc1sxXSk7IH0KICAgICAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdID09ICdVSURfTUFYJykgeyByZXQuTUFYID0gcGFyc2VJbnQodG9rZW5zWzFdKTsgfQogICAgICAgICAgICAgICAgICAgIGlmIChyZXQuTUlOICE9IG51bGwgJiYgcmV0Lk1BWCAhPSBudWxsKSB7IGJyZWFrOyB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIHRoaXMub24oJ2NoYW5nZWQnLCB0aGlzLl9yZWNoZWNrTG9nZ2VkSW5Vc2Vycyk7IC8vIEZvciBsaW51eCBMb2NrL1VubG9jayBtb25pdG9yaW5nLCB3ZSBuZWVkIHRvIHdhdGNoIGZvciBMb2dPbi9Mb2dPZmYsIGFuZCBrZWVwIHRyYWNrIG9mIHRoZSBVSUQuCgogICAgICAgICAgICAvLyBGaXJzdCBzdGVwLCBpcyB0byBzZWUgaWYgdGhlcmUgaXMgYSB1c2VyIGxvZ2dlZCBpbjoKICAgICAgICAgICAgdGhpcy5fcmVjaGVja0xvZ2dlZEluVXNlcnMoKTsKICAgICAgICB9CiAgICAgICAgdGhpcy5fdXNlcnMgPSBmdW5jdGlvbiBfdXNlcnMoKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdhd2sgLUY6IFwnKCQzID49IDApIHtwcmludGYgIiVzOiVzXFxuIiwgJDEsICQzfVwnIC9ldGMvcGFzc3dkXG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciByZXQgPSB7fSwgdG9rZW5zOwogICAgICAgICAgICBmb3IgKHZhciBsbiBpbiBsaW5lcykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbbG5dLnNwbGl0KCc6Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHJl", 16000);
	memcpy_s(_usersessions + 32000, 18868, "dFt0b2tlbnNbMF1dID0gdG9rZW5zWzFdOyB9ICAgICAgICAgICAKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgfQogICAgICAgIHRoaXMuX3VpZHMgPSBmdW5jdGlvbiBfdWlkcygpIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdhd2sgLUY6IFwnKCQzID49IDApIHtwcmludGYgIiVzOiVzXFxuIiwgJDEsICQzfVwnIC9ldGMvcGFzc3dkXG5leGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJyk7CiAgICAgICAgICAgIHZhciByZXQgPSB7fSwgdG9rZW5zOwogICAgICAgICAgICBmb3IgKHZhciBsbiBpbiBsaW5lcykgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbbG5dLnNwbGl0KCc6Jyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHJldFt0b2tlbnNbMV1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH0KICAgICAgICB0aGlzLmNvbnNvbGVVaWQgPSBmdW5jdGlvbiBjb25zb2xlVWlkKCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRlcnIuc3RyID0gJyc7IGNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ3dob1xuZXhpdFxuJyk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICBpZiAoY2hpbGQuc3RkZXJyLnN0ciAhPSAnJykgeyByZXR1cm4gKDApOyB9CgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICB2YXIgdG9rZW5zLCBpLCBqOwogICAgICAgICAgICBmb3IgKGkgaW4gbGluZXMpIHsKICAgICAgICAgICAgICAgIHRva2VucyA9IGxpbmVzW2ldLnNwbGl0KCcgJyk7CiAgICAgICAgICAgICAgICBmb3IgKGogPSAxOyBqIDwgdG9rZW5zLmxlbmd0aDsgKytqKSB7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2Vuc1tqXS5sZW5ndGggPiAwKSB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocGFyc2VJbnQodGhpcy5fdXNlcnMoKVt0b2tlbnNbMF1dKSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIHRocm93ICgnbm9ib2R5IGxvZ2dlZCBpbnRvIGNvbnNvbGUnKTsKICAgICAgICB9CiAgICAgICAgCiAgICAgICAgdGhpcy5nZXRVaWQgPSBmdW5jdGlvbiBnZXRVaWQodXNlcm5hbWUpCiAgICAgICAgewogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImNhdCAvZXRjL3Bhc3N3ZCB8IGF3ayAtRjogJygkMT09XCIiICsgdXNlcm5hbWUgKyAiXCIpe3ByaW50ICQzfSdcbmV4aXRcbiIpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAgICAgdmFyIHJldCA9IHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIpOyAgICAgICAgICAgIAogICAgICAgICAgICBpZiAocmV0ID49IDApIHsgcmV0dXJuIChyZXQpOyB9CiAgICAgICAgICAgIHRocm93ICgndXNlcm5hbWU6ICcgKyB1c2VybmFtZSArICcgTk9UIEZPVU5EJyk7CiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldFVzZXJuYW1lID0gZnVuY3Rpb24gZ2V0VXNlcm5hbWUodWlkKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJjYXQgL2V0Yy9wYXNzd2QgfCBhd2sgLUY6ICcoJDM9PSIgKyB1aWQgKyAiKXtwcmludCAkMX0nXG5leGl0XG4iKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgaWYgKGNoaWxkLnN0ZG91dC5zdHIubGVuZ3RoID4gMCkgeyByZXR1cm4gKGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKTsgfQogICAgICAgICAgICB0aHJvdyAoJ3VpZDogJyArIHVpZCArICcgTk9UIEZPVU5EJyk7CiAgICAgICAgfTsKICAgICAgICB0aGlzLndob2FtaSA9IGZ1bmN0aW9uIHdob2FtaSgpCiAgICAgICAgewogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoIndob2FtaVxuZXhpdFxuIik7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgIH07CiAgICAgICAgdGhpcy5nZXRFbnZGcm9tUGlkID0gZnVuY3Rpb24gZ2V0RW52RnJvbVBpZChwaWQpCiAgICAgICAgewogICAgICAgICAgICB2YXIgcmV0ID0ge307CiAgICAgICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBwcywgcHN4LCB2LCB2cyA9IDA7CiAgICAgICAgICAgICAgICB0cnkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBwcyA9IHJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvcHJvYy8nICsgcGlkICsgJy9lbnZpcm9uJyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaCAocHNlKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBmb3IgKHBzeCA9IDA7IHBzeCA8IHBzLmxlbmd0aDsgKytwc3gpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaWYgKHBzW3BzeF0gPT0gMCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHYgPSBwcy5zbGljZSh2cywgcHN4KS50b1N0cmluZygpLnNwbGl0KCc9Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFt2WzBdXSA9IHZbMV07CiAgICAgICAgICAgICAgICAgICAgICAgIHZzID0gcHN4ICsgMTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZSBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7IGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjKSB7IHRoaXMuc3RyICs9IGMudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgicHJvY3N0YXQgLWUgIiArIHBpZCArICIgfCBncmVwICIgKyBwaWQgKyAiIHwgYXdrICd7ICQxPVwiXCI7ICQyPVwiXCI7IHByaW50ICQwIH0nIHwgdHIgXCJcXCBcIiBcIlxcblwiXG5leGl0XG4iKTsgCiAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoJCQogICAgICAgICAgICAgICAgdmFyIGVudjsKICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSBjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKS5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgICAgIGZvcih2YXIgaSBpbiB0b2tlbnMpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgZW52ID0gdG9rZW5zW2ldLnNwbGl0KCc9Jyk7CiAgICAgICAgICAgICAgICAgICAgcmV0W2VudlswXV0gPSBlbnZbMV07CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH07CiAgICAgICAgdGhpcy5maW5kRW52ID0gZnVuY3Rpb24gZmluZEVudih1aWQsIGVudikKICAgICAgICB7CiAgICAgICAgICAgIHZhciB1bmFtZSA9IHRoaXMuZ2V0VXNlcm5hbWUodWlkKTsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJwcyAiICsgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2ZyZWVic2QnID8gIi1heCAiOiIiKSArICItZSAtbyBwaWQgLW8gdXNlciB8IGdyZXAgIiArIHVuYW1lICsgIiB8IGF3ayAneyBwcmludCAkMSB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICBmb3IgKHZhciBuIGluIGxpbmVzKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgbG4gPSBsaW5lc1tuXS50cmltKCk7CiAgICAgICAgICAgICAgICBpZiAobG4ubGVuZ3RoID4gMCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICB2YXIgZSA9IHRoaXMuZ2V0RW52RnJvbVBpZChsbik7CiAgICAgICAgICAgICAgICAgICAgaWYgKGVbZW52XSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoZVtlbnZdKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIChudWxsKTsKICAgICAgICB9OwogICAgfQogICAgZWxzZSBpZihwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKQogICAgewogICAgICAgIHRoaXMuZ2V0VWlkID0gZnVuY3Rpb24gZ2V0VWlkKHVzZXJuYW1lKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJpZCAiICsgdXNlcm5hbWUgKyAiIHwgYXdrICd7IHNwbGl0KCQxLCB0b2tlbiwgXCI9XCIpOyBzcGxpdCh0b2tlblsyXSwgdWlkLCBcIihcIik7IHByaW50IHVpZFsxXTsgfSdcbmV4aXRcbiIpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICByZXR1cm4gKHBhcnNlSW50KGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpKSk7CiAgICAgICAgfTsKICAgICAgICB0aGlzLmdldEdyb3VwSUQgPSBmdW5jdGlvbiBnZXRHcm91cElEKHVpZCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgiaWQgIiArIHVpZCArICIgfCBhd2sgJ3sgc3BsaXQoJDIsIGdpZCwgXCI9XCIpOyBpZihnaWRbMV09PVwiZ2lkXCIpIHsgc3BsaXQoZ2lkWzJdLCBnaWRudW0sIFwiKFwiKTsgcHJpbnQgZ2lkbnVtWzFdOyAgfSB9J1xuZXhpdFxuIik7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgIHJldHVybiAocGFyc2VJbnQoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpKTsKICAgICAgICB9CiAgICAgICAgdGhpcy5nZXRVc2VybmFtZSA9IGZ1bmN0aW9uIGdldFVzZXJuYW1lKHVpZCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoImRzY2wgLiBsaXN0IC9Vc2VycyBVbmlxdWVJRCB8IGdyZXAgIiArIHVpZCArICIgfCBhd2sgJ3sgaWYoJDI9PSIgKyB1aWQgKyAiKXsgcHJpbnQgJDEgfX0nXG5leGl0XG4iKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAgaWYoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgIT0gJycpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCd1aWQ6ICcgKyB1aWQgKyAnIG5vdCBmb3VuZCcpOwogICAgICAgICAgICB9CiAgICAgICAgfTsKICAgICAgICB0aGlzLmNvbnNvbGVVaWQgPSBmdW5jdGlvbiBjb25zb2xlVWlkKCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hvIHwgdHIgJ1xuJyAnXC4nIHwgYXdrICd7IHByaW50ICQxIH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciByZXQgPSBjaGlsZC5zdGRvdXQuc3RyLnRyaW0oKTsKICAgICAgICAgICAgaWYgKHJldCAhPSAnJykKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0dXJuICh0aGlzLmdldFVpZChyZXQpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICB0aHJvdyAoJ25vYm9keSBsb2dnZWQgaW50byBjb25zb2xlJyk7ICAgICAKICAgICAgICB9CiAgICAgICAgdGhpcy5nZXRIb21lRm9sZGVyID0gZnVuY3Rpb24gZ2V0SG9tZUZvbGRlcih1c2VyKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJkc2NsIC4gLXJlYWQgL1VzZXJzLyIgKyB1c2VyICsgIiB8IGdyZXAgTkZTSG9tZURpcmVjdG9yeSB8IGF3ayAtRjogJ3sgcHJpbnQgJDIgfSdcbmV4aXRcbiIpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICBpZiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkgIT0gJycpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ci50cmltKCkpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdGhyb3cgKCd1c2VyOiAnICsgdXNlciArICcgbm90IGZvdW5kJyk7CiAgICAgICAgICAgIH0KICAgICAgICB9OwogICAgICAgIHRoaXMuX3VzZXJzID0gZnVuY3Rpb24gKCkKICAgICAgICB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vZHNjbCcsIFsnZHNjbCcsICcuJywgJ2xpc3QnLCAnL1VzZXJzJywgJ1VuaXF1ZUlEJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCdleGl0XG4nKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICB2YXIgdG9rZW5zLCBpOwogICAgICAgICAgICB2YXIgdXNlcnMgPSB7fTsKCiAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkgewogICAgICAgICAgICAgICAgdG9rZW5zID0gbGluZXNbaV0uc3BsaXQoJyAnKTsKICAgICAgICAgICAgICAgIGlmICh0b2tlbnNbMF0pIHsgdXNlcnNbdG9rZW5zWzBdXSA9IHRva2Vuc1t0b2tlbnMubGVuZ3RoIC0gMV07IH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgcmV0dXJuICh1c2Vycyk7CiAgICAgICAgfQogICAgICAgIHRoaXMuX3VpZHMgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vZHNjbCcsIFsnZHNjbCcsICcuJywgJ2xpc3QnLCAnL1VzZXJzJywgJ1VuaXF1ZUlEJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKICAgICAgICAgICAgdmFyIGxpbmVzID0gY2hpbGQuc3Rkb3V0LnN0ci5zcGxpdCgnXG4nKTsKICAgICAgICAgICAgdmFyIHRva2VucywgaTsKICAgICAgICAgICAgdmFyIHVzZXJzID0ge307CgogICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyArK2kpIHsKICAgICAgICAgICAgICAgIHRva2VucyA9IGxpbmVzW2ldLnNwbGl0KCcgJyk7CiAgICAgICAgICAgICAgICBpZiAodG9rZW5zWzBdKSB7IHVzZXJzW3Rva2Vuc1t0b2tlbnMubGVuZ3RoIC0gMV1dID0gdG9rZW5zWzBdOyB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHJldHVybiAodXNlcnMpOwogICAgICAgIH0KICAgICAgICB0aGlzLl9pZFRhYmxlID0gZnVuY3Rpb24oKQogICAgICAgIHsKICAgICAgICAgICAgdmFyIHRhYmxlID0ge307CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vaWQnLCBbJ2lkJ10pOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgIHZhciBsaW5lcyA9IGNoaWxkLnN0ZG91dC5zdHIuc3BsaXQoJ1xuJylbMF0uc3BsaXQoJyAnKTsKICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7ICsraSkgewogICAgICAgICAgICAgICAgdmFyIHR5cGVzID0gbGluZXNbaV0uc3BsaXQoJz0nKTsKICAgICAgICAgICAgICAgIHZhciB0b2tlbnMgPSB0eXBlc1sxXS5zcGxpdCgnLCcpOwogICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dID0ge307CgogICAgICAgICAgICAgICAgZm9yICh2YXIgaiBpbiB0b2tlbnMpIHsKICAgICAgICAgICAgICAgICAgICB2YXIgaWRhcnIgPSB0b2tlbnNbal0uc3BsaXQoJygnKTsKICAgICAgICAgICAgICAgICAgICB2YXIgaWQgPSBpZGFyclswXTsKICAgICAgICAgICAgICAgICAgICB2YXIgbmFtZSA9IGlkYXJyWzFdLnN1YnN0cmluZygwLCBpZGFyclsxXS5sZW5ndGggLSAxKS50cmltKCk7CiAgICAgICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dW25hbWVdID0gaWQ7CiAgICAgICAgICAgICAgICAgICAgdGFibGVbdHlwZXNbMF1dW2lkXSA9IG5hbWU7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuICh0YWJsZSk7CiAgICAgICAgfQogICAgICAgIHRoaXMuQ3VycmVudCA9IGZ1bmN0aW9uIChjYikKICAgICAgICB7CiAgICAgICAgICAgIHZhciB1c2VycyA9IHt9OwogICAgICAgICAgICB2YXIgdGFibGUgPSB0aGlzLl9pZFRhYmxlKCk7CiAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL3Vzci9iaW4vbGFzdCcsIFsnbGFzdCddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CgogICAgICAgICAgICB2YXIgbGluZXMgPSBjaGlsZC5zdGRvdXQuc3RyLnNwbGl0KCdcbicpOwogICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aCAmJiBsaW5lc1tpXS5sZW5ndGggPiAwOyArK2kpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmICghdXNlcnNbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0pCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB1c2Vyc1tsaW5lc1tpXS5zcGxpdCgnICcpWzBdXSA9IHsgVXNlcm5hbWU6IGxpbmVzW2ldLnNwbGl0KCcgJylbMF0sIFN0YXRlOiBsaW5lc1tpXS5zcGxpdCgnc3RpbGwgbG9nZ2VkIGluJykubGVuZ3RoID4gMSA/ICdBY3RpdmUnIDogJ0luYWN0aXZlJywgdWlk", 16000);
	memcpy_s(_usersessions + 48000, 2868, "OiB0YWJsZS51aWRbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0gfTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7fQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGlmKHVzZXJzW2xpbmVzW2ldLnNwbGl0KCcgJylbMF1dLlN0YXRlICE9ICdBY3RpdmUnICYmIGxpbmVzW2ldLnNwbGl0KCdzdGlsbCBsb2dnZWQgaW4nKS5sZW5ndGggPiAxKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdXNlcnNbbGluZXNbaV0uc3BsaXQoJyAnKVswXV0uU3RhdGUgPSAnQWN0aXZlJzsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh1c2VycywgJ0FjdGl2ZScsIHsgdmFsdWU6IHNob3dBY3RpdmVPbmx5KHVzZXJzKSB9KTsKICAgICAgICAgICAgaWYgKGNiKSB7IGNiLmNhbGwodGhpcywgdXNlcnMpOyB9CiAgICAgICAgfQogICAgfQoKICAgIGlmKHByb2Nlc3MucGxhdGZvcm0gIT0gJ3dpbjMyJykgLy8gTGludXgsIE1hY09TLCBGcmVlQlNECiAgICB7CiAgICAgICAgdGhpcy5TZWxmID0gZnVuY3Rpb24gU2VsZigpCiAgICAgICAgewogICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy91c3IvYmluL2lkJywgWydpZCcsICctdSddKTsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgIHJldHVybiAocGFyc2VJbnQoY2hpbGQuc3Rkb3V0LnN0cikpOwogICAgICAgIH0KICAgICAgICB0aGlzLmlzUm9vdCA9IGZ1bmN0aW9uIGlzUm9vdCgpCiAgICAgICAgewogICAgICAgICAgICByZXR1cm4gKHRoaXMuU2VsZigpID09IDApOwogICAgICAgIH0KICAgIH0KCgp9CmZ1bmN0aW9uIHNob3dBY3RpdmVPbmx5KHNvdXJjZSkKewogICAgdmFyIHJldFZhbCA9IFtdOwogICAgdmFyIHVuaXF1ZSA9IHt9OwogICAgdmFyIHVzZXJuYW1lcyA9IFtdOwogICAgdmFyIHRtcDsKCiAgICBmb3IgKHZhciBpIGluIHNvdXJjZSkKICAgIHsKICAgICAgICBpZiAoc291cmNlW2ldLlN0YXRlID09ICdBY3RpdmUnKQogICAgICAgIHsKICAgICAgICAgICAgcmV0VmFsLnB1c2goc291cmNlW2ldKTsKICAgICAgICAgICAgdG1wID0gKHNvdXJjZVtpXS5Eb21haW4gPyAoc291cmNlW2ldLkRvbWFpbiArICdcXCcpIDogJycpICsgc291cmNlW2ldLlVzZXJuYW1lOwogICAgICAgICAgICBpZiAoIXVuaXF1ZVt0bXBdKSB7IHVuaXF1ZVt0bXBdID0gdG1wO30KICAgICAgICB9CiAgICB9CgogICAgZm9yICh2YXIgaSBpbiB1bmlxdWUpCiAgICB7CiAgICAgICAgdXNlcm5hbWVzLnB1c2goaSk7CiAgICB9CgogICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHJldFZhbCwgJ3VzZXJuYW1lcycsIHsgdmFsdWU6IHVzZXJuYW1lcyB9KTsKICAgIHJldHVybiAocmV0VmFsKTsKfQpmdW5jdGlvbiBnZXRUb2tlbnMoc3RyKQp7CiAgICB2YXIgY29sdW1ucyA9IFtdOwogICAgdmFyIGk7CgogICAgY29sdW1ucy5wdXNoKHN0ci5zdWJzdHJpbmcoMCwgKGk9c3RyLmluZGV4T2YoJyAnKSkpKTsKICAgIHdoaWxlIChzdHJbKytpXSA9PSAnICcpOwogICAgY29sdW1ucy5wdXNoKHN0ci5zdWJzdHJpbmcoaSwgKGk9c3RyLnN1YnN0cmluZyhpKS5pbmRleE9mKCcgJykgKyBpKSkpOwogICAgd2hpbGUgKHN0clsrK2ldID09ICcgJyk7CiAgICBjb2x1bW5zLnB1c2goc3RyLnN1YnN0cmluZyhpLCAoaT1zdHIuc3Vic3RyaW5nKGkpLmluZGV4T2YoJyAnKSArIGkpKSk7CiAgICB3aGlsZSAoc3RyWysraV0gPT0gJyAnKTsKICAgIHZhciBzdGF0dXMgPSBzdHIuc3Vic3RyaW5nKGkpLnRyaW0oKTsKICAgIGNvbHVtbnMucHVzaChzdGF0dXMpOwoKICAgIHJldHVybiAoY29sdW1ucyk7Cn0KCm1vZHVsZS5leHBvcnRzID0gbmV3IFVzZXJTZXNzaW9ucygpOwo=", 2868);
	ILibBase64DecodeEx((unsigned char*)_usersessions, 50868, (unsigned char*)_usersessions + 50868);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "user-sessions"); duk_push_string(ctx, _usersessions + 50868);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_usersessions);

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addModule('_agentNodeId', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCmZ1bmN0aW9uIF9tZXNoTm9kZUlkKCkKewogICAgdmFyIHJldCA9ICcnOwogICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQogICAgewogICAgICAgIGNhc2UgJ2xpbnV4JzoKICAgICAgICBjYXNlICdkYXJ3aW4nOgogICAgICAgICAgICB0cnkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdmFyIGRiID0gcmVxdWlyZSgnU2ltcGxlRGF0YVN0b3JlJykuQ3JlYXRlKHByb2Nlc3MuZXhlY1BhdGggKyAnLmRiJywgeyByZWFkT25seTogdHJ1ZSB9KTsKICAgICAgICAgICAgICAgIHJldCA9IHJlcXVpcmUoJ3RscycpLmxvYWRDZXJ0aWZpY2F0ZSh7IHBmeDogZGIuR2V0QnVmZmVyKCdTZWxmTm9kZUNlcnQnKSwgcGFzc3BocmFzZTogJ2hpZGRlbicgfSkuZ2V0S2V5SGFzaCgpLnRvU3RyaW5nKCdoZXgnKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjYXRjaChlKQogICAgICAgICAgICB7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAnd2luMzInOgogICAgICAgICAgICAvLyBGaXJzdCBDaGVjayBpZiB0aGUgZGIgQ29udGFpbnMgdGhlIE5vZGVJRAogICAgICAgICAgICB0cnkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdmFyIGRiID0gcmVxdWlyZSgnU2ltcGxlRGF0YVN0b3JlJykuQ3JlYXRlKHByb2Nlc3MuZXhlY1BhdGgucmVwbGFjZSgnLmV4ZScsICcuZGInKSwgeyByZWFkT25seTogdHJ1ZSB9KTsKICAgICAgICAgICAgICAgIHZhciB2ID0gZGIuR2V0QnVmZmVyKCdTZWxmTm9kZUNlcnQnKTsKICAgICAgICAgICAgICAgIGlmICh2KQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0ID0gcmVxdWlyZSgndGxzJykubG9hZENlcnRpZmljYXRlKHsgcGZ4OiB2LCBwYXNzcGhyYXNlOiAnaGlkZGVuJyB9KS5nZXRLZXlIYXNoKCkudG9TdHJpbmcoJ2hleCcpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBjYXRjaChlKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdiA9IG51bGw7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgaWYgKHYgPT0gbnVsbCAmJiAodiA9IGRiLkdldEJ1ZmZlcignTm9kZUlEJykpICE9IG51bGwpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0ID0gdi50b1N0cmluZygnaGV4Jyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgfQogICAgICAgICAgICBicmVhazsKICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICBicmVhazsKICAgIH0KICAgIHJldHVybiAocmV0KTsKfQoKbW9kdWxlLmV4cG9ydHMgPSBfbWVzaE5vZGVJZDsKCv==', 'base64').toString());");
	
	// Task Scheduler, refer to modules/task-scheduler.js
	char *_taskscheduler = ILibMemory_Allocate(48679, 0, NULL, NULL);
	memcpy_s(_taskscheduler + 0, 27816, "LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwp2YXIgc2VydmljZW1hbmFnZXIgPSByZXF1aXJlKCdzZXJ2aWNlLW1hbmFnZXInKTsKdmFyIG1nciA9IG5ldyBzZXJ2aWNlbWFuYWdlcigpOwoKLy9hdHRhY2hEZWJ1Z2dlcih7IHdlYnBvcnQ6IDk5OTUsIHdhaXQ6IDEgfSkudGhlbihjb25zb2xlLmxvZyk7CgpmdW5jdGlvbiB0YXNrKCkKewogICAgdGhpcy5fT2JqZWN0SUQgPSAndGFzay1zY2hlZHVsZXInOwoKICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gY3JlYXRlKG9wdGlvbnMpCiAgICB7CiAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgaWYob3B0aW9ucy5uYW1lICYmIG9wdGlvbnMuc2VydmljZSkKICAgICAgICB7CiAgICAgICAgICAgIHN3aXRjaChwcm9jZXNzLnBsYXRmb3JtKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBjYXNlICd3aW4zMic6CiAgICAgICAgICAgICAgICAgICAgdmFyIHBhcm1zID0gWydzY2h0YXNrcycsICcvQ3JlYXRlJywgJy9SVSBTWVNURU0nXTsKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBmdHlwZSBpbiBvcHRpb25zKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGZ0eXBlLnRvVXBwZXJDYXNlKCkpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01JTlVURSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdIT1VSTFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnREFJTFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnV0VFS0xZJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01PTlRITFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9TQyAnICsgZnR5cGUudG9VcHBlckNhc2UoKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL01PICcgKyBvcHRpb25zW2Z0eXBlXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdEQVknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9EICcgKyBvcHRpb25zW2Z0eXBlXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdNT05USCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL00gJyArIG9wdGlvbnNbZnR5cGVdKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1RJTUUnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9TVCAnICsgb3B0aW9uc1tmdHlwZV0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnTkFNRSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFybXMucHVzaCgnL1ROICInICsgb3B0aW9uc1tmdHlwZV0uc3BsaXQoJy8nKS5qb2luKCdcXCcpICsgJyInKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1NFUlZJQ0UnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goJy9UUiAibmV0IHN0YXJ0ICcgKyBvcHRpb25zW2Z0eXBlXSArICciJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cocGFybXMuam9pbignICcpKTsKICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUocHJvY2Vzcy5lbnZbJ3dpbmRpciddICsgJ1xcc3lzdGVtMzJcXHNjaHRhc2tzLmV4ZScsIHBhcm1zKTsKICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgIHJldC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgcmV0LmNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQucHJvbWlzZSA9IHJldDsKICAgICAgICAgICAgICAgICAgICByZXQuY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgeyBpZiAoY29kZSA9PSAwKSB7IHRoaXMucHJvbWlzZS5fcmVzKCk7IH0gZWxzZSB7IHRoaXMucHJvbWlzZS5fcmVqKGNvZGUpOyB9fSk7IAogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnbGludXgnOgogICAgICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvY3Jvbi5kLycgKyBvcHRpb25zLm5hbWUuc3BsaXQoJy8nKS5qb2luKCdfJykuc3BsaXQoJy4nKS5qb2luKCcnKSkpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaignVGFzayBbJyArIG9wdGlvbnMubmFtZSArICddIEFscmVhZHkgZXhpc3RzJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgdmFyIG1pbnV0ZSA9ICcqJzsKICAgICAgICAgICAgICAgICAgICB2YXIgaG91ciA9ICcqJzsKICAgICAgICAgICAgICAgICAgICB2YXIgZGF5ID0gJyonOwogICAgICAgICAgICAgICAgICAgIHZhciBtb250aCA9ICcqJzsKICAgICAgICAgICAgICAgICAgICB2YXIgd2Vla2RheSA9ICcqJzsKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBmdHlwZSBpbiBvcHRpb25zKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGZ0eXBlLnRvVXBwZXJDYXNlKCkpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01JTlVURSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFvcHRpb25zLlRJTUUgJiYgIW9wdGlvbnMudGltZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1pbnV0ZSA9ICcqLycgKyBvcHRpb25zW2Z0eXBlXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdIT1VSTFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghb3B0aW9ucy5USU1FICYmICFvcHRpb25zLnRpbWUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBob3VyID0gJyovJyArIG9wdGlvbnNbZnR5cGVdOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0RBSUxZJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXkgPSAnKi8nICsgb3B0aW9uc1tmdHlwZV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdXRUVLTFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zW2Z0eXBlXSA9PSAxKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoIW9wdGlvbnMuREFZICYmICFvcHRpb25zLmRheSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2Vla2RheSA9IDA7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooJ09ubHkgT25jZS9XZWVrbHkgc3VwcG9ydGVkIG9uIExpbnV4Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdEQVknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLndlZWtseSB8fCBvcHRpb25zLldFRUtMWSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdlZWtkYXkgPSBvcHRpb25zW2Z0eXBlXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF5ID0gb3B0aW9uc1tmdHlwZV07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnVElNRSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaG91ciA9IG9wdGlvbnNbZnR5cGVdLnNwbGl0KCc6JylbMF07CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWludXRlID0gb3B0aW9uc1tmdHlwZV0uc3BsaXQoJzonKVsxXTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ01PTlRITFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vbnRoID0gJyovJyArIG9wdGlvbnNbZnR5cGVdOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICB2YXIgYWN0aW9uID0gJ1NIRUxMPS9iaW4vc2hcblBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi9zYmluOi9iaW46L3Vzci9zYmluOi91c3IvYmluXG5cbic7CiAgICAgICAgICAgICAgICAgICAgYWN0aW9uICs9IChtaW51dGUgKyAnICcgKyBob3VyICsgJyAnICsgZGF5ICsgJyAnICsgbW9udGggKyAnICcgKyB3ZWVrZGF5ICsgJyAgIHJvb3QgICAnKTsKICAgICAgICAgICAgICAgICAgICBzd2l0Y2gocmVxdWlyZSgnc2VydmljZS1tYW5hZ2VyJykubWFuYWdlci5nZXRTZXJ2aWNlVHlwZSgpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnaW5pdCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoIndoZXJlaXMgc2VydmljZSB8IGF3ayAne3ByaW50ICQyfSdcblxleGl0XG4iKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3Rpb24gKz0gKGNoaWxkLnN0ZG91dC5zdHIgKyAnICcgKyBvcHRpb25zLnNlcnZpY2UgKyAnIHN0YXJ0ID4vZGV2L251bGwgMj4mMSBcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ3Vwc3RhcnQnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJ3aGVyZWlzIGluaXRjdGwgfCBhd2sgJ3twcmludCAkMn0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9uICs9IChjaGlsZC5zdGRvdXQuc3RyICsgJyBzdGFydCAnICsgb3B0aW9ucy5zZXJ2aWNlICsgJyA+L2Rldi9udWxsIDI+JjEgXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdzeXN0ZW1kJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hlcmVpcyBzeXN0ZW1jdGwgfCBhd2sgJ3twcmludCAkMn0nXG5cZXhpdFxuIik7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9uICs9IChjaGlsZC5zdGRvdXQuc3RyICsgJyBzdGFydCAnICsgb3B0aW9ucy5zZXJ2aWNlICsgJyA+L2Rldi9udWxsIDI+JjEgXG4nKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooJ1Vua25vd24gU2VydmljZSBQbGF0Zm9ybTogJyArIHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0U2VydmljZVR5cGUoKSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG0gPSByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVJVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVdVU1IgfCByZXF1aXJlKCdmcycpLkNITU9EX01PREVTLlNfSVJPVEg7CiAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnL2V0Yy9jcm9uLmQvJyArIG9wdGlvbnMubmFtZS5zcGxpdCgnLycpLmpvaW4oJ18nKS5zcGxpdCgnLicpLmpvaW4oJycpLCBhY3Rpb24sIHsgZmxhZ3M6ICd3YicsIG1vZGU6IG0gfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGNhdGNoKGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaihlKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICByZXQuX3JlcygpOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnZGFyd2luJzoKICAgICAgICAgICAgICAgICAgICB2YXIgdGFza25hbWUgPSBvcHRpb25zLm5hbWUuc3BsaXQoJy8nKS5qb2luKCdfJykuc3BsaXQoJy4nKS5qb2luKCcnKTsKICAgICAgICAgICAgICAgICAgICB2YXIgcGxpc3QgPSAnPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz5cbic7CiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJzwhRE9DVFlQRSBwbGlzdCBQVUJMSUMgIi0vL0FwcGxlIENvbXB1dGVyLy9EVEQgUExJU1QgMS4wLy9FTiIgImh0dHA6Ly93d3cuYXBwbGUuY29tL0RURHMvUHJvcGVydHlMaXN0LTEuMC5kdGQiPlxuJzsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnPHBsaXN0IHZlcnNpb249IjEuMCI+XG4nOwogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgIDxkaWN0PlxuJzsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5MYWJlbDwva2V5PlxuJzsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAoJyAgICAgPHN0cmluZz4nICsgdGFza25hbWUgKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPGtleT5Qcm9ncmFtQXJndW1lbnRzPC9rZXk+XG4nOwogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8YXJyYXk+XG4nOwogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICAgIDxzdHJpbmc+L2Jpbi9sYXVuY2hjdGw8L3N0cmluZz5cbic7CiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgICAgPHN0cmluZz5zdGFydDwvc3RyaW5nPlxuJzsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAoJyAgICAgICA8c3RyaW5nPicgKyBvcHRpb25zLnNlcnZpY2UgKyAnPC9zdHJpbmc+XG4nKTsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAnICAgICAgPC9hcnJheT5cbic7CiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJyAgICAgIDxrZXk+UnVuQXRMb2FkPC9rZXk+XG4nOwogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgICAgICA8ZmFsc2UvPlxuJzsKICAgICAgICAgICAgICAgICAgICAgICBwbGlzdCArPSAne3t7SU5URVJWQUx9fX0nOwogICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ICs9ICcgIDwvZGljdD5cbic7CiAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgKz0gJzwvcGxpc3Q+JzsKCiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3ZjID0gcmVxdWlyZSgnc2VydmljZS1tYW5hZ2VyJykubWFuYWdlci5nZXRTZXJ2aWNlKG9wdGlvbnMuc2VydmljZSk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghc3ZjLmlzTG9hZGVkKCkpIHsgc3ZjLmxvYWQoKTsgfQogICAgICAgICAgICAgICAgICAgICAgICBzdmMgPSBudWxsOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBjYXRjaChzZSkKICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaihzZSk7IHJldHVybiAocmV0KTsNCiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICB2YXIgaW50ZXJ2YWwgPSBudWxsOwogICAgICAgICAgICAgICAgICAgIHZhciBwZXJpb2RpYyA9IFtdOwoKICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBmdHlwZSBpbiBvcHRpb25zKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2ggKGZ0eXBlLnRvVXBwZXJDYXNlKCkpDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnREFJTFknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBkYWlseVZhbCA9IHBhcnNlSW50KG9wdGlvbnNbZnR5cGVdKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGRhaWx5VmFsIDwgMSB8fCBkYWlseVZhbCA+IDMxKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaignSW52YWxpZCBPcHRpb25zJyk7IHJldHVybiAocmV0KTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGFpbHlWYWwgPiAxKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VycmVudERheSA9IChuZXcgRGF0ZSgpKS5nZXREYXRlKCk7ICAvLyAwIC0gMzENCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhY3R1YWxEYXkgPSBjdXJyZW50RGF5Ow0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZG8NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50RGF5ICs9IGRhaWx5VmFsOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChjdXJyZW50RGF5ID4gMzEpIGN1cnJlbnREYXkgPSBjdXJyZW50RGF5ICUgMzE7DQogICAgICAgICAgICAgICAgICAg", 16000);
	memcpy_s(_taskscheduler + 16000, 11816, "ICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMucHVzaCgoJyAgICAgICAgIDxrZXk+RGF5PC9rZXk+XG4gICAgICAgICA8aW50ZWdlcj4nICsgY3VycmVudERheSArICc8L2ludGVnZXI+XG4nKSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9IHdoaWxlICghKGN1cnJlbnREYXkgPCBhY3R1YWxEYXkgJiYgKGN1cnJlbnREYXkgKyBkYWlseVZhbCkgPiBhY3R1YWxEYXkpKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYy5wdXNoKCcnKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnV0VFS0xZJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocGFyc2VJbnQob3B0aW9uc1tmdHlwZV0pICE9IDEpIHsgcmV0Ll9yZWooJ09ubHkgb25jZSB3ZWVrbHkgaXMgc3VwcG9ydGVkJyk7IHJldHVybiAocmV0KTsgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChvcHRpb25zLkRBWSA8IDAgfHwgb3B0aW9ucy5EQVkgPiA2IHx8IG9wdGlvbnMuZGF5IDwgMCB8fCBvcHRpb25zLmRheSA+IDYpIHsgcmV0Ll9yZWooJ0RBWSBvdXQgb2YgcmFuZ2UnKTsgcmV0dXJuIChyZXQpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMuREFZID09IG51bGwgJiYgb3B0aW9ucy5kYXkgPT0gbnVsbCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMucHVzaCgoJyAgICAgICAgIDxrZXk+RGF5PC9rZXk+XG4gICAgICAgICA8aW50ZWdlcj4nICsgKG5ldyBEYXRlKCkpLmdldERheSgpICsgJzwvaW50ZWdlcj5cbicpKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJpb2RpYy5wdXNoKCcnKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnTU9OVEhMWSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMubW9udGggPT0gbnVsbCAmJiBvcHRpb25zLk1PTlRIID09IG51bGwpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtb250aGx5VmFsID0gcGFyc2VJbnQob3B0aW9uc1tmdHlwZV0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VycmVudE1vbnRoID0gKG5ldyBEYXRlKCkpLmdldE1vbnRoKCk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhY3R1YWxNb250aD0gY3VycmVudE1vbnRoOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkbw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRNb250aCArPSBtb250aGx5VmFsOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChjdXJyZW50TW9udGggPiAxMikgY3VycmVudE1vbnRoID0gY3VycmVudE1vbnRoICUgMTI7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMucHVzaCgoJyAgICAgICAgIDxrZXk+TW9udGg8L2tleT5cbiAgICAgICAgIDxpbnRlZ2VyPicgKyBjdXJyZW50TW9udGggKyAnPC9pbnRlZ2VyPlxuJykpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSB3aGlsZSAoIShjdXJyZW50TW9udGggPCBhY3R1YWxNb250aCAmJiAoY3VycmVudE1vbnRoICsgbW9udGhseVZhbCkgPiBhY3R1YWxNb250aCkpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWMucHVzaCgnJyk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgZnR5cGUgaW4gb3B0aW9ucykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaCAoZnR5cGUudG9VcHBlckNhc2UoKSkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSAnTUlOVVRFJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaW50ZXJ2YWwgIT0gbnVsbCB8fCBwZXJpb2RpYy5sZW5ndGggPiAwKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW50ZXJ2YWwgPSAnICAgICAgPGludGVnZXI+JyArIChwYXJzZUludChvcHRpb25zW2Z0eXBlXSkgKiA2MCkgKyAnPC9pbnRlZ2VyPlxuJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ0hPVVJMWSc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGludGVydmFsICE9IG51bGwgfHwgcGVyaW9kaWMubGVuZ3RoID4gMCkgeyByZXQuX3JlaignSW52YWxpZCBPcHRpb25zJyk7IHJldHVybiAocmV0KTsgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGludGVydmFsID0gJyAgICAgIDxpbnRlZ2VyPicgKyAocGFyc2VJbnQob3B0aW9uc1tmdHlwZV0pICogNjAgKiA2MCkgKyAnPC9pbnRlZ2VyPlxuJzsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdEQVknOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGQgaW4gcGVyaW9kaWMpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWNbZF0gKz0gKCcgICAgICAgICA8a2V5PkRheTwva2V5PlxuICAgICAgICAgPGludGVnZXI+JyArIG9wdGlvbnNbZnR5cGVdICsgJzwvaW50ZWdlcj5cbicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlICdNT05USCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgbSBpbiBwZXJpb2RpYykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWNbbV0gKz0gKCcgICAgICAgICA8a2V5Pk1vbnRoPC9rZXk+XG4gICAgICAgICA8aW50ZWdlcj4nICsgb3B0aW9uc1tmdHlwZV0gKyAnPC9pbnRlZ2VyPlxuJyk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgJ1RJTUUnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCAhPSBudWxsKSB7IHJldC5fcmVqKCdJbnZhbGlkIE9wdGlvbnMnKTsgcmV0dXJuIChyZXQpOyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgdCBpbiBwZXJpb2RpYykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyaW9kaWNbdF0gKz0gKCcgICAgICAgICA8a2V5PkhvdXI8L2tleT5cbiAgICAgICAgIDxpbnRlZ2VyPicgKyBvcHRpb25zW2Z0eXBlXS5zcGxpdCgnOicpWzBdICsgJzwvaW50ZWdlcj5cbicgKyAnICAgICAgICAgPGtleT5NaW51dGU8L2tleT5cbiAgICAgICAgIDxpbnRlZ2VyPicgKyBvcHRpb25zW2Z0eXBlXS5zcGxpdCgnOicpWzFdICsgJzwvaW50ZWdlcj5cbicpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgaWYgKGludGVydmFsKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcGxpc3QgPSBwbGlzdC5yZXBsYWNlKCd7e3tJTlRFUlZBTH19fScsICcgICAgICA8a2V5PlN0YXJ0SW50ZXJ2YWw8L2tleT5cbicgKyBpbnRlcnZhbCk7CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICBpZiAocGVyaW9kaWMubGVuZ3RoID4gMCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHBsaXN0ID0gcGxpc3QucmVwbGFjZSgne3t7SU5URVJWQUx9fX0nLCAnICAgICAgPGtleT5TdGFydENhbGVuZGFySW50ZXJ2YWw8L2tleT5cbiAgICAgIDxhcnJheT48ZGljdD5cbicgKyBwZXJpb2RpYy5qb2luKCcgICAgICA8L2RpY3Q+XG4gICAgICA8ZGljdD5cbicpICsgJyAgICAgIDwvZGljdD48L2FycmF5PlxuJyk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0JywgcGxpc3QpOwoKICAgICAgICAgICAgICAgICAgICB2YXIgY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgnbGF1bmNoY3RsIGxvYWQgL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0XG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwoKCgogICAgICAgICAgICAgICAgICAgIHJldC5fcmVzKCk7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKCdOb3QgaW1wbGVtZW50ZWQgb24gJyArIHByb2Nlc3MucGxhdGZvcm0pOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIHJldC5fcmVqKCdJbnZhbGlkIFBhcmFtZXRlcnMsIG11c3QgYXQgbGVhc3Qgc3BlY2lmeSBuYW1lIGFuZCBzZXJ2aWNlJyk7CiAgICAgICAgfQogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07CiAgICB0aGlzLmluZm8gPSBmdW5jdGlvbiBpbmZvKG5hbWUpCiAgICB7CiAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQogICAgICAgIHsKICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgIHJldC5fcmVqKCdOb3QgaW1wbGVtZW50ZWQgb24gJyArIHByb2Nlc3MucGxhdGZvcm0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07CiAgICB0aGlzLmRlbGV0ZSA9IGZ1bmN0aW9uIF9kZWxldGUobmFtZSkKICAgIHsKICAgICAgICB2YXIgcmV0ID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsKICAgICAgICBzd2l0Y2ggKHByb2Nlc3MucGxhdGZvcm0pCiAgICAgICAgewogICAgICAgICAgICBjYXNlICd3aW4zMic6CiAgICAgICAgICAgICAgICByZXQuY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUocHJvY2Vzcy5lbnZbJ3dpbmRpciddICsgJ1xcc3lzdGVtMzJcXHNjaHRhc2tzLmV4ZScsIFsnc2NodGFza3MnLCAnL0RlbGV0ZScsICcvVE4gIicgKyBuYW1lLnNwbGl0KCcvJykuam9pbignXFwnKSArICciJywgJy9GJ10pOwogICAgICAgICAgICAgICAgcmV0LmNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgICAgIHJldC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICByZXQuY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgcmV0LmNoaWxkLnByb21pc2UgPSByZXQ7CiAgICAgICAgICAgICAgICByZXQuY2hpbGQub24oJ2V4aXQnLCBmdW5jdGlvbiAoY29kZSkgeyBpZiAoY29kZSA9PSAwKSB7IHRoaXMucHJvbWlzZS5fcmVzKCk7IH0gZWxzZSB7IHRoaXMucHJvbWlzZS5fcmVqKGNvZGUpOyB9IH0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIGNhc2UgJ2xpbnV4JzoKICAgICAgICAgICAgICAgIGlmIChyZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy9ldGMvY3Jvbi5kLycgKyBuYW1lLnNwbGl0KCcvJykuam9pbignXycpLnNwbGl0KCcuJykuam9pbignJykpKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKCcvZXRjL2Nyb24uZC8nICsgbmFtZS5zcGxpdCgnLycpLmpvaW4oJ18nKS5zcGxpdCgnLicpLmpvaW4oJycpKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2goZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKGUpOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHJldC5fcmVzKCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgcmV0Ll9yZWooJ1Rhc2sgWycgKyBuYW1lICsgJ10gZG9lcyBub3QgZXhpc3QnKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICBjYXNlICdkYXJ3aW4nOgogICAgICAgICAgICAgICAgdmFyIHRhc2tuYW1lID0gbmFtZS5zcGxpdCgnLycpLmpvaW4oJ18nKS5zcGxpdCgnLicpLmpvaW4oJycpOwogICAgICAgICAgICAgICAgaWYgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYygnL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0JykpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgY2hpbGQuc3RkaW4ud3JpdGUoJ2xhdW5jaGN0bCB1bmxvYWQgL0xpYnJhcnkvTGF1bmNoRGFlbW9ucy8nICsgdGFza25hbWUgKyAnLnBsaXN0XG5leGl0XG4nKTsKICAgICAgICAgICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKCcvTGlicmFyeS9MYXVuY2hEYWVtb25zLycgKyB0YXNrbmFtZSArICcucGxpc3QnKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXQuX3JlaihlKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICByZXQuX3JlcygpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZWxzZQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHJldC5fcmVqKCdUYXNrIFsnICsgbmFtZSArICddIGRvZXMgbm90IGV4aXN0Jyk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgIHJldC5fcmVqKCdOb3QgaW1wbGVtZW50ZWQgb24gJyArIHByb2Nlc3MucGxhdGZvcm0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07Cn0KCgptb2R1bGUuZXhwb3J0cyA9IG5ldyB0YXNrKCk7Cgo=", 11816);
	ILibBase64DecodeEx((unsigned char*)_taskscheduler, 27816, (unsigned char*)_taskscheduler + 27816);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "task-scheduler"); duk_push_string(ctx, _taskscheduler + 27816);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_taskscheduler);

	// message-box, refer to modules/message-box.js
	char *_messagebox = ILibMemory_Allocate(48315, 0, NULL, NULL);
	memcpy_s(_messagebox + 0, 27608, "LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgpjb25zdCBNQl9PSyA9IDB4MDAwMDAwMDA7CmNvbnN0IE1CX09LQ0FOQ0VMICAgICAgICAgICAgICAgID0gMHgwMDAwMDAwMTsKY29uc3QgTUJfQUJPUlRSRVRSWUlHTk9SRSAgICAgICAgPSAweDAwMDAwMDAyOwpjb25zdCBNQl9ZRVNOT0NBTkNFTCAgICAgICAgICAgICA9IDB4MDAwMDAwMDM7CmNvbnN0IE1CX1lFU05PICAgICAgICAgICAgICAgICAgID0gMHgwMDAwMDAwNDsKY29uc3QgTUJfUkVUUllDQU5DRUwgICAgICAgICAgICAgPSAweDAwMDAwMDA1OwoKY29uc3QgTUJfREVGQlVUVE9OMSAgICAgICAgICAgICAgPSAweDAwMDAwMDAwOwpjb25zdCBNQl9ERUZCVVRUT04yICAgICAgICAgICAgICA9IDB4MDAwMDAxMDA7CmNvbnN0IE1CX0RFRkJVVFRPTjMgICAgICAgICAgICAgID0gMHgwMDAwMDIwMDsKY29uc3QgTUJfSUNPTkhBTkQgICAgICAgICAgICAgICAgPSAweDAwMDAwMDEwOwpjb25zdCBNQl9JQ09OUVVFU1RJT04gICAgICAgICAgICA9IDB4MDAwMDAwMjA7CmNvbnN0IE1CX0lDT05FWENMQU1BVElPTiAgICAgICAgID0gMHgwMDAwMDAzMDsKY29uc3QgTUJfSUNPTkFTVEVSSVNLICAgICAgICAgICAgPSAweDAwMDAwMDQwOwoKY29uc3QgSURPSyAgICAgPSAxOwpjb25zdCBJRENBTkNFTCA9IDI7CmNvbnN0IElEQUJPUlQgID0gMzsKY29uc3QgSURSRVRSWSAgPSA0Owpjb25zdCBJRElHTk9SRSA9IDU7CmNvbnN0IElEWUVTICAgID0gNjsKY29uc3QgSUROTyAgICAgPSA3OwoKdmFyIHByb21pc2UgPSByZXF1aXJlKCdwcm9taXNlJyk7CnZhciBjaGlsZFNjcmlwdCA9ICJcCiAgICAgICAgcmVxdWlyZSgnU2NyaXB0Q29udGFpbmVyJykub24oJ2RhdGEnLCBmdW5jdGlvbiAoailcCiAgICAgICAge1wKICAgICAgICAgICAgc3dpdGNoKGouY29tbWFuZClcCiAgICAgICAgICAgIHtcCiAgICAgICAgICAgICAgICBjYXNlICdtZXNzYWdlQm94JzpcCiAgICAgICAgICAgICAgICAgICAgaWYocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnd2luMzInKVwKICAgICAgICAgICAgICAgICAgICB7XAogICAgICAgICAgICAgICAgICAgICAgICB2YXIgR00gPSByZXF1aXJlKCdfR2VuZXJpY01hcnNoYWwnKTtcCiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB1c2VyMzIgPSBHTS5DcmVhdGVOYXRpdmVQcm94eSgndXNlcjMyLmRsbCcpO1wKICAgICAgICAgICAgICAgICAgICAgICAgdXNlcjMyLkNyZWF0ZU1ldGhvZCgnTWVzc2FnZUJveEEnKTtcCiAgICAgICAgICAgICAgICAgICAgICAgIHVzZXIzMi5NZXNzYWdlQm94QS5hc3luYygwLCBHTS5DcmVhdGVWYXJpYWJsZShqLmNhcHRpb24pLCBHTS5DcmVhdGVWYXJpYWJsZShqLnRpdGxlKSwgIiArIChNQl9ZRVNOTyB8IE1CX0RFRkJVVFRPTjIgfCBNQl9JQ09ORVhDTEFNQVRJT04pLnRvU3RyaW5nKCkgKyAiKS50aGVuKFwKICAgICAgICAgICAgICAgICAgICAgICAgZnVuY3Rpb24ocilcCiAgICAgICAgICAgICAgICAgICAgICAgIHtcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihyLlZhbCA9PSAiICsgSURZRVMudG9TdHJpbmcoKSArICIpXAogICAgICAgICAgICAgICAgICAgICAgICAgICAge1wKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlKCdTY3JpcHRDb250YWluZXInKS5zZW5kKCIgKyBJRFlFUy50b1N0cmluZygpICsgIik7XAogICAgICAgICAgICAgICAgICAgICAgICAgICAgfVwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpLnNlbmQoIiArIElETk8udG9TdHJpbmcoKSArICIpO1wKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzLmV4aXQoKTtcCiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1wKICAgICAgICAgICAgICAgICAgICB9XAogICAgICAgICAgICAgICAgICAgIGJyZWFrO1wKICAgICAgICAgICAgfVwKICAgICAgICB9KTtcCiAgICAiOwoKZnVuY3Rpb24gbWVzc2FnZUJveCgpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ21lc3NhZ2UtYm94JzsKICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gY3JlYXRlKHRpdGxlLCBjYXB0aW9uLCB0aW1lb3V0KQogICAgewogICAgICAgIHZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwogICAgICAgIHZhciBrZXJuZWwzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdrZXJuZWwzMi5kbGwnKTsKICAgICAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ1Byb2Nlc3NJZFRvU2Vzc2lvbklkJyk7CiAgICAgICAgdmFyIHBzaWQgPSBHTS5DcmVhdGVWYXJpYWJsZSg0KTsKICAgICAgICBpZiAoa2VybmVsMzIuUHJvY2Vzc0lkVG9TZXNzaW9uSWQocHJvY2Vzcy5waWQsIHBzaWQpLlZhbCA9PSAwKQogICAgICAgIHsKICAgICAgICAgICAgcmV0Ll9yZWooJ0ludGVybmFsIEVycm9yJyk7CiAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICB9CgogICAgICAgIGlmICh0aW1lb3V0ID09IG51bGwpIHsgdGltZW91dCA9IDEwOyB9CiAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgdmFyIG9wdGlvbnMgPSB7IGV4ZWN1dGlvblRpbWVvdXQ6IHRpbWVvdXQgfTsKCiAgICAgICAgdHJ5CiAgICAgICAgewogICAgICAgICAgICBvcHRpb25zLnNlc3Npb25JZCA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5jb25zb2xlVWlkKCk7CiAgICAgICAgICAgIGlmIChvcHRpb25zLnNlc3Npb25JZCA9PSBwc2lkLnRvQnVmZmVyKCkucmVhZFVJbnQzMkxFKCkpIHsgZGVsZXRlIG9wdGlvbnMuc2Vzc2lvbklkOyB9CiAgICAgICAgfQogICAgICAgIGNhdGNoKGVlKQogICAgICAgIHsKICAgICAgICAgICAgcmV0Ll9yZWooJ05vIGxvZ2dlZCBvbiB1c2VycycpOwogICAgICAgICAgICByZXR1cm4gKHJldCk7CiAgICAgICAgfQogICAgICAgIHJldC5fdGl0bGUgPSB0aXRsZTsKICAgICAgICByZXQuX2NhcHRpb24gPSBjYXB0aW9uOwogICAgICAgIHJldC5fY29udGFpbmVyID0gcmVxdWlyZSgnU2NyaXB0Q29udGFpbmVyJykuQ3JlYXRlKG9wdGlvbnMpOwogICAgICAgIHJldC5fY29udGFpbmVyLnByb21pc2UgPSByZXQ7CiAgICAgICAgcmV0Ll9jb250YWluZXIub24oJ2RhdGEnLCBmdW5jdGlvbiAoaikKICAgICAgICB7CiAgICAgICAgICAgIGlmKGogPT0gSURZRVMpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVzKCk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaignRGVuaWVkJyk7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgICAgICByZXQuX2NvbnRhaW5lci5vbignZXhpdCcsIGZ1bmN0aW9uICgpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaignVGltZW91dCcpOwogICAgICAgIH0pOwogICAgICAgIHJldC5fY29udGFpbmVyLkV4ZWN1dGVTdHJpbmcoY2hpbGRTY3JpcHQpOwogICAgICAgIHJldC5fY29udGFpbmVyLnNlbmQoeyBjb21tYW5kOiAnbWVzc2FnZUJveCcsIGNhcHRpb246IGNhcHRpb24sIHRpdGxlOiB0aXRsZSB9KTsKICAgICAgICByZXR1cm4gKHJldCk7CiAgICB9Owp9CgoKZnVuY3Rpb24gbGludXhfbWVzc2FnZUJveCgpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ21lc3NhZ2UtYm94JzsKICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gY3JlYXRlKHRpdGxlLCBjYXB0aW9uLCB0aW1lb3V0KQogICAgewogICAgICAgIGlmICh0aW1lb3V0ID09IG51bGwpIHsgdGltZW91dCA9IDEwOyB9CiAgICAgICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7CiAgICAgICAgdmFyIHplbml0eSA9ICcnLCBrZGlhbG9nID0gJyc7CiAgICAgICAgdmFyIHVpZDsgICAgCiAgICAgICAgdmFyIHhpbmZvOwoKICAgICAgICB0cnkKICAgICAgICB7CiAgICAgICAgICAgIHVpZCA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5jb25zb2xlVWlkKCk7CiAgICAgICAgICAgIHhpbmZvID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuZ2V0WEluZm8odWlkKTsKICAgICAgICB9CiAgICAgICAgY2F0Y2goZSkKICAgICAgICB7CiAgICAgICAgICAgIHVpZCA9IDA7CiAgICAgICAgICAgIHhpbmZvID0gcmVxdWlyZSgnbW9uaXRvci1pbmZvJykuZ2V0WEluZm8oMCk7CiAgICAgICAgfQoKICAgICAgICBpZiAoeGluZm8gPT0gbnVsbCkKICAgICAgICB7CiAgICAgICAgICAgIHJldC5fcmVqKCdUaGlzIHN5c3RlbSBjYW5ub3QgZGlzcGxheSBhIHVzZXIgZGlhbG9nIGJveCB3aGVuIGEgdXNlciBpcyBub3QgbG9nZ2VkIGluJyk7CiAgICAgICAgICAgIHJldHVybiAocmV0KTsKICAgICAgICB9CgogICAgICAgIHZhciBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgY2hpbGQuc3Rkb3V0LnN0ciA9ICcnOwogICAgICAgIGNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hlcmVpcyB6ZW5pdHkgfCBhd2sgJ3sgcHJpbnQgJDIgfSdcbmV4aXRcbiIpOwogICAgICAgIGNoaWxkLndhaXRFeGl0KCk7CiAgICAgICAgemVuaXR5ID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCk7CiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2ZyZWVic2QnICYmIHplbml0eSA9PSAnJyAmJiByZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvYmluL3plbml0eScpKSB7IHplbml0eSA9ICcvdXNyL2xvY2FsL2Jpbi96ZW5pdHknOyB9CiAgICAgICAgaWYgKHplbml0eSAhPSAnJykKICAgICAgICB7CiAgICAgICAgICAgIC8vIEdOT01FL1pFTklUWQogICAgICAgICAgICByZXQuY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoemVuaXR5LCBbJ3plbml0eScsICctLXF1ZXN0aW9uJywgJy0tdGl0bGU9JyArIHRpdGxlLCAnLS10ZXh0PScgKyBjYXB0aW9uLCAnLS10aW1lb3V0PScgKyB0aW1lb3V0XSwgeyB1aWQ6IHVpZCwgZW52OiB7IFhBVVRIT1JJVFk6IHhpbmZvLnhhdXRob3JpdHksIERJU1BMQVk6IHhpbmZvLmRpc3BsYXkgfSB9KTsKICAgICAgICAgICAgcmV0LmNoaWxkLnByb21pc2UgPSByZXQ7CiAgICAgICAgICAgIHJldC5jaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgIHJldC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgIHJldC5jaGlsZC5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBzd2l0Y2ggKGNvZGUpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgY2FzZSAwOgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlcygpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBjYXNlIDE6CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKCdkZW5pZWQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWooJ3RpbWVvdXQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pOwogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICBjaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgIGNoaWxkLnN0ZG91dC5zdHIgPSAnJzsKICAgICAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hlcmVpcyBrZGlhbG9nIHwgYXdrICd7IHByaW50ICQyIH0nXG5leGl0XG4iKTsKICAgICAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICAgICAga2RpYWxvZyA9IGNoaWxkLnN0ZG91dC5zdHIudHJpbSgpOwogICAgICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcgJiYga2RpYWxvZyA9PSAnJyAmJiByZXF1aXJlKCdmcycpLmV4aXN0c1N5bmMoJy91c3IvbG9jYWwvYmluL2tkaWFsb2cnKSkgeyBrZGlhbG9nID0gJy91c3IvbG9jYWwvYmluL2tkaWFsb2cnOyB9CiAgICAgICAgICAgIGlmIChrZGlhbG9nID09ICcnKSB7IHJldC5fcmVqKCdQbGF0Zm9ybSBub3Qgc3VwcG9ydGVkICh6ZW5pdHkgb3Iga2RpYWxvZyBub3QgZm91bmQpJyk7IHJldHVybiAocmV0KTsgfQogICAgICAgICAgICBpZiAocHJvY2Vzcy5wbGF0Zm9ybSAhPSAnZnJlZWJzZCcgJiYgcHJvY2Vzcy5lbnZbJ0RJU1BMQVknXSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgcmV0LmNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKGtkaWFsb2csIFsna2RpYWxvZycsICctLXRpdGxlJywgdGl0bGUsICctLXllc25vJywgY2FwdGlvbl0pOwogICAgICAgICAgICAgICAgcmV0LmNoaWxkLnByb21pc2UgPSByZXQ7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICB2YXIgeGRnID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmZpbmRFbnYodWlkLCAnWERHX1JVTlRJTUVfRElSJyk7IGlmICh4ZGcgPT0gbnVsbCkgeyB4ZGcgPSAnJzsgfQogICAgICAgICAgICAgICAgaWYgKCF4aW5mbyB8fCAheGluZm8uZGlzcGxheSB8fCAheGluZm8ueGF1dGhvcml0eSkgeyByZXQuX3JlaignSW50ZXJhbCBFcnJvciwgY291bGQgbm90IGRldGVybWluZSBYMTEvWERHIGVudicpOyByZXR1cm4gKHJldCk7IH0KICAgICAgICAgICAgICAgIHJldC5jaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZShrZGlhbG9nLCBbJ2tkaWFsb2cnLCAnLS10aXRsZScsIHRpdGxlLCAnLS15ZXNubycsIGNhcHRpb25dLCB7IHVpZDogdWlkLCBlbnY6IHsgRElTUExBWTogeGluZm8uZGlzcGxheSwgWEFVVEhPUklUWTogeGluZm8ueGF1dGhvcml0eSwgWERHX1JVTlRJTUVfRElSOiB4ZGcgfSB9KTsKICAgICAgICAgICAgICAgIHJldC5jaGlsZC5wcm9taXNlID0gcmV0OwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJldC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgIHJldC5jaGlsZC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgIHJldC5jaGlsZC5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBzd2l0Y2ggKGNvZGUpIHsKICAgICAgICAgICAgICAgICAgICBjYXNlIDA6CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVzKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgMToKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWooJ2RlbmllZCcpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaigndGltZW91dCcpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSk7CiAgICAgICAgfQogICAgICAgIHJldHVybiAocmV0KTsKICAgIH07Cn0KCmlmIChwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKQp7CiAgICBmdW5jdGlvbiB0cmFuc2xhdGVPYmplY3Qob2JqKQogICAgewogICAgICAgIHZhciBqID0gSlNPTi5zdHJpbmdpZnkob2JqKTsKICAgICAgICB2YXIgYiA9IEJ1ZmZlci5hbGxvYyhqLmxlbmd0aCArIDQpOwogICAgICAgIGIud3JpdGVVSW50MzJMRShqLmxlbmd0aCArIDQpOwogICAgICAgIEJ1ZmZlci5mcm9tKGopLmNvcHkoYiwgNCk7CiAgICAgICAgcmV0dXJuIChiKTsKICAgIH0KfQoKZnVuY3Rpb24gbWFjb3NfbWVzc2FnZUJveCgpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ21lc3NhZ2UtYm94JzsKICAgIHRoaXMuX2luaXRJUENCYXNlID0gZnVuY3Rpb24gX2luaXRJUENCYXNlKCkKICAgIHsKICAgICAgICB2YXIgcmV0ID0gbmV3IHByb21pc2UoZnVuY3Rpb24gKHJlcywgcmVqKSB7IHRoaXMuX3JlcyA9IHJlczsgdGhpcy5fcmVqID0gcmVqOyB9KTsKCiAgICAgICAgdHJ5CiAgICAgICAgewogICAgICAgICAgICByZXQudWlkID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmNvbnNvbGVVaWQoKTsKICAgICAgICB9CiAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgewogICAgICAgICAgICByZXQuX3JlaihlKTsKICAgICAgICAgICAgcmV0dXJuIChyZXQpOwogICAgICAgIH0KCiAgICAgICAgcmV0LnBhdGggPSAnL3Zhci90bXAvJyArIHByb2Nlc3MuZXhlY1BhdGguc3BsaXQoJy8nKS5wb3AoKSArICdfZXYnOwogICAgICAgIHZhciBuOwoKICAgICAgICB0cnkKICAgICAgICB7CiAgICAgICAgICAgIG4gPSByZXF1aXJlKCd0bHMnKS5nZW5lcmF0ZVJhbmRvbUludGVnZXIoJzEnLCAnOTk5OTknKTsKICAgICAgICB9CiAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgewogICAgICAgICAgICBuID0gMDsKICAgICAgICB9CiAgICAgICAgd2hpbGUgKHJlcXVpcmUoJ2ZzJykuZXhpc3RzU3luYyhyZXQucGF0aCArIG4pKQogICAgICAgIHsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIG4gPSByZXF1aXJlKCd0bHMnKS5nZW5lcmF0ZVJhbmRvbUludGVnZXIoJzEnLCAnOTk5OTknKTsKICAgICAgICAgICAgfQogICAgICAgICAgICBjYXRjaCAoZSkgewogICAgICAgICAgICAgICAgKytuOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIHJldC5wYXRoID0gcmV0LnBhdGggKyBuOwogICAgICAgIHJldC50bXBTZXJ2aWNlTmFtZSA9ICdtZXNoTm90aWZpY2F0aW9uU2VydmVyJyArIG47CiAgICAgICAgcmV0dXJuIChyZXQpOwogICAgfTsKICAgIAogICAgdGhpcy5jcmVhdGUgPSBmdW5jdGlvbiBjcmVhdGUodGl0bGUsIGNhcHRpb24sIHRpbWVvdXQpCiAgICB7CiAgICAgICAgLy8gU3RhcnQgTG9jYWwgU2VydmVyCiAgICAgICAgdmFyIHJldCA9IHRoaXMuX2luaXRJUENCYXNlKCk7CiAgICAgICAgcmV0LnRpdGxlID0gdGl0bGU7IHJldC5jYXB0aW9uID0gY2FwdGlvbjsgcmV0LnRpbWVvdXQgPSB0aW1lb3V0OwogICAgICAgIHJldC5zZXJ2ZXIgPSB0aGlzLnN0YXJ0TWVzc2FnZVNlcnZlcihyZXQpOwogICAgICAgIHJldC5zZXJ2ZXIucmV0ID0gcmV0OwogICAgICAgIHJldC5zZXJ2ZXIub24oJ2Nvbm5lY3Rpb24nLCBmdW5jdGlvbiAoYykKICAgICAgICB7CiAgICAgICAgICAgIHRoaXMuX2Nvbm5lY3Rpb24gPSBjOwogICAgICAgICAgICBjLnByb21pc2UgPSB0aGlzLnJldDsKICAgICAgICAgICAgYy5vbignZGF0YScsIGZ1bmN0aW9uIChidWZmZXIpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIGlmIChidWZmZXIubGVuIDwgNCB8fCBidWZmZXIucmVhZFVJbnQzMkxFKDApID4gYnVmZmVyLmxlbikgeyB0aGlzLnVuc2hpZnQoYnVmZmVyKTsgfQogICAgICAgICAgICAgICAgdmFyIHAgPSBKU09OLnBhcnNlKGJ1ZmZlci5zbGljZSg0LCBidWZmZXIucmVhZFVJbnQzMkxFKDApKS50b1N0cmluZygpKTsKICAgICAgICAgICAgICAgIHN3aXRjaCAocC5jb21tYW5kKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGNhc2UgJ0VSUk9SJzoKICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWoocC5yZWFzb24pOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgICAgICBjYXNlICdESUFMT0cnOgogICAgICAgICAgICAgICAgICAgICAgICBpZiAocC50aW1lb3V0KQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaignVElNRU9VVCcpOwogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHAuYnV0dG9uID09ICdZZXMnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVzKHAuYnV0dG9uKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaignZGVuaWVkJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0pOwogICAgICAgICAgICBjLndyaXRlKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdESUFMT0cnLCB0aXRsZTogdGhpcy5yZXQudGl0bGUsIGNhcHRpb246IHRoaXMucmV0LmNhcHRpb24sIGljb246ICdjYXV0aW9uJywgYnV0dG9uczogWyciWWVzIicsICciTm8iJ10sIGJ1dHRvbkRlZmF1bHQ6IDIsIHRpbWVvdXQ6IHRoaXMucmV0LnRpbWVvdXQgfSkpOwogICAgICAgIH0pOwoKICAgICAgICByZXR1cm4gKHJldCk7CiAgICB9OwogICAgdGhpcy5sb2NrID0gZnVuY3Rpb24gbG9jaygpCiAgICB7CiAgICAgICAgLy8gU3RhcnQgTG9jYWwgU2VydmVyCiAgICAgICAgdmFyIHJldCA9IHRoaXMuX2luaXRJUENCYXNlKCk7CiAgICAgICAgcmV0LnNlcnZlciA9IHRoaXMuc3RhcnRNZXNzYWdlU2VydmVyKHJldCk7CiAgICAgICAgcmV0LnNlcnZlci5yZXQgPSByZXQ7CiAgICAgICAgcmV0LnNlcnZlci5vbignY29ubmVjdGlvbicsIGZ1bmN0aW9uIChjKQ0KICAgICAgICB7DQogICAgICAgICAgICB0aGlzLl9jb25uZWN0aW9uID0gYzsKICAgICAgICAgICAgYy5wcm9taXNlID0gdGhpcy5yZXQ7CiAgICAgICAgICAgIGMub24oJ2RhdGEnLCBmdW5jdGlvbiAoYnVmZmVyKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGlm", 16000);
	memcpy_s(_messagebox + 16000, 11608, "IChidWZmZXIubGVuIDwgNCB8fCBidWZmZXIucmVhZFVJbnQzMkxFKDApID4gYnVmZmVyLmxlbikgeyB0aGlzLnVuc2hpZnQoYnVmZmVyKTsgfQogICAgICAgICAgICAgICAgdmFyIHAgPSBKU09OLnBhcnNlKGJ1ZmZlci5zbGljZSg0LCBidWZmZXIucmVhZFVJbnQzMkxFKDApKS50b1N0cmluZygpKTsKICAgICAgICAgICAgICAgIHN3aXRjaCAocC5jb21tYW5kKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgY2FzZSAnRVJST1InOgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlaihwLnJlYXNvbik7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgICAgIGNhc2UgJ0xPQ0snOgogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuX3JlcygpOwogICAgICAgICAgICAgICAgICAgICAgICBicmVhazsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgYy53cml0ZSh0cmFuc2xhdGVPYmplY3QoeyBjb21tYW5kOiAnTE9DSycgfSkpOw0KICAgICAgICB9KTsKCiAgICAgICAgcmV0dXJuIChyZXQpOw0KICAgIH07CiAgICB0aGlzLm5vdGlmeSA9IGZ1bmN0aW9uIG5vdGlmeSh0aXRsZSwgY2FwdGlvbikKICAgIHsKICAgICAgICAvLyBTdGFydCBMb2NhbCBTZXJ2ZXIKICAgICAgICB2YXIgcmV0ID0gdGhpcy5faW5pdElQQ0Jhc2UoKTsKICAgICAgICByZXQudGl0bGUgPSB0aXRsZTsgcmV0LmNhcHRpb24gPSBjYXB0aW9uOyAKICAgICAgICByZXQuc2VydmVyID0gdGhpcy5zdGFydE1lc3NhZ2VTZXJ2ZXIocmV0KTsKICAgICAgICByZXQuc2VydmVyLnJldCA9IHJldDsKICAgICAgICByZXQuc2VydmVyLm9uKCdjb25uZWN0aW9uJywgZnVuY3Rpb24gKGMpCiAgICAgICAgewogICAgICAgICAgICB0aGlzLl9jb25uZWN0aW9uID0gYzsKICAgICAgICAgICAgYy5wcm9taXNlID0gdGhpcy5yZXQ7CiAgICAgICAgICAgIGMub24oJ2RhdGEnLCBmdW5jdGlvbiAoYnVmZmVyKQogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICBpZiAoYnVmZmVyLmxlbiA8IDQgfHwgYnVmZmVyLnJlYWRVSW50MzJMRSgwKSA+IGJ1ZmZlci5sZW4pIHsgdGhpcy51bnNoaWZ0KGJ1ZmZlcik7IH0KICAgICAgICAgICAgICAgIHZhciBwID0gSlNPTi5wYXJzZShidWZmZXIuc2xpY2UoNCwgYnVmZmVyLnJlYWRVSW50MzJMRSgwKSkudG9TdHJpbmcoKSk7CiAgICAgICAgICAgICAgICBzd2l0Y2ggKHAuY29tbWFuZCkKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjYXNlICdFUlJPUic6CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKHAucmVhc29uKTsKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICAgICAgY2FzZSAnTk9USUZZJzoKCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVzKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgYy53cml0ZSh0cmFuc2xhdGVPYmplY3QoeyBjb21tYW5kOiAnTk9USUZZJywgdGl0bGU6IHRoaXMucmV0LnRpdGxlLCBjYXB0aW9uOiB0aGlzLnJldC5jYXB0aW9uIH0pKTsKICAgICAgICB9KTsKCiAgICAgICAgcmV0dXJuIChyZXQpOwogICAgfTsKICAgIHRoaXMuc3RhcnRDbGllbnQgPSBmdW5jdGlvbiBzdGFydENsaWVudChvcHRpb25zKQogICAgewogICAgICAgIC8vIENyZWF0ZSB0aGUgQ2xpZW50CiAgICAgICAgY29uc29sZS5sb2coJ1N0YXJ0aW5nIENsaWVudC4uLicpOwoKICAgICAgICBvcHRpb25zLm9zdmVyc2lvbiA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLmdldE9TVmVyc2lvbigpOwogICAgICAgIG9wdGlvbnMudWlkID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmNvbnNvbGVVaWQoKTsKICAgICAgICB0aGlzLmNsaWVudCA9IHJlcXVpcmUoJ25ldCcpLmNyZWF0ZUNvbm5lY3Rpb24ob3B0aW9ucyk7CiAgICAgICAgdGhpcy5jbGllbnQuX29wdGlvbnMgPSBvcHRpb25zOwogICAgICAgIHRoaXMuY2xpZW50Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGJ1ZmZlcikKICAgICAgICB7CiAgICAgICAgICAgIGlmIChidWZmZXIubGVuIDwgNCB8fCBidWZmZXIucmVhZFVJbnQzMkxFKDApID4gYnVmZmVyLmxlbikgeyB0aGlzLnVuc2hpZnQoYnVmZmVyKTsgfQogICAgICAgICAgICB2YXIgcCA9IEpTT04ucGFyc2UoYnVmZmVyLnNsaWNlKDQsIGJ1ZmZlci5yZWFkVUludDMyTEUoMCkpLnRvU3RyaW5nKCkpOwogICAgICAgICAgICBzd2l0Y2ggKHAuY29tbWFuZCkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgY2FzZSAnTE9DSyc6CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2hlbGwgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUoJy9iaW4vc2gnLCBbJ3NoJ10pOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsLnN0ZG91dC5zdHIgPSAnJzsgdGhpcy5fc2hlbGwuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsLnN0ZGVyci5zdHIgPSAnJzsgdGhpcy5fc2hlbGwuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsLnN0ZGluLndyaXRlKCcvU3lzdGVtL0xpYnJhcnkvQ29yZVNlcnZpY2VzL01lbnVcXCBFeHRyYXMvVXNlci5tZW51L0NvbnRlbnRzL1Jlc291cmNlcy9DR1Nlc3Npb24gLXN1c3BlbmRcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX3NoZWxsLnN0ZGVyci5zdHIgIT0gJycpDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdFUlJPUicsIHJlYXNvbjogdGhpcy5fc2hlbGwuc3RkZXJyLnN0ciB9KSk7DQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdMT0NLJywgc3RhdHVzOiAwIH0pKTsNCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICAgICAgY2FzZSAnTk9USUZZJzoKICAgICAgICAgICAgICAgICAgICB0aGlzLl9zaGVsbCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSgnL2Jpbi9zaCcsIFsnc2gnXSk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2hlbGwuc3Rkb3V0LnN0ciA9ICcnOyB0aGlzLl9zaGVsbC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2hlbGwuc3RkZXJyLnN0ciA9ICcnOyB0aGlzLl9zaGVsbC5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgdGhpcy5zdHIgKz0gY2h1bmsudG9TdHJpbmcoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2hlbGwuc3RkaW4ud3JpdGUoJ29zYXNjcmlwdCAtZSBcJ3RlbGwgY3VycmVudCBhcHBsaWNhdGlvbiB0byBkaXNwbGF5IG5vdGlmaWNhdGlvbiAiJyArIHAuY2FwdGlvbiArICciIHdpdGggdGl0bGUgIicgKyBwLnRpdGxlICsgJyJcJ1xuZXhpdFxuJyk7CiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc2hlbGwud2FpdEV4aXQoKTsKICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5fc2hlbGwuc3RkZXJyLnN0ciAhPSAnJykKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdFUlJPUicsIHJlYXNvbjogdGhpcy5fc2hlbGwuc3RkZXJyLnN0ciB9KSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdOT1RJRlknLCBzdGF0dXM6IDAgfSkpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgJ0RJQUxPRyc6CiAgICAgICAgICAgICAgICAgICAgdmFyIHRpbWVvdXQgPSBwLnRpbWVvdXQgPyAoJyBnaXZpbmcgdXAgYWZ0ZXIgJyArIHAudGltZW91dCkgOiAnJzsKICAgICAgICAgICAgICAgICAgICB2YXIgaWNvbiA9IHAuaWNvbiA/ICgnd2l0aCBpY29uICcgKyBwLmljb24pIDogJyc7CiAgICAgICAgICAgICAgICAgICAgdmFyIGJ1dHRvbnMgPSBwLmJ1dHRvbnMgPyAoJ2J1dHRvbnMgeycgKyBwLmJ1dHRvbnMudG9TdHJpbmcoKSArICd9JykgOiAnJzsKICAgICAgICAgICAgICAgICAgICBpZiAocC5idXR0b25EZWZhdWx0ICE9IG51bGwpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBidXR0b25zICs9ICgnIGRlZmF1bHQgYnV0dG9uICcgKyBwLmJ1dHRvbkRlZmF1bHQpCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9zaGVsbC5zdGRvdXQuc3RyID0gJyc7IHRoaXMuX3NoZWxsLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9zaGVsbC5zdGRlcnIuc3RyID0gJyc7IHRoaXMuX3NoZWxsLnN0ZGVyci5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB0aGlzLnN0ciArPSBjaHVuay50b1N0cmluZygpOyB9KTsKICAgICAgICAgICAgICAgICAgICB0aGlzLl9zaGVsbC5zdGRpbi53cml0ZSgnb3Nhc2NyaXB0IC1lIFwndGVsbCBjdXJyZW50IGFwcGxpY2F0aW9uIHRvIGRpc3BsYXkgZGlhbG9nICInICsgcC5jYXB0aW9uICsgJyIgd2l0aCB0aXRsZSAiJyArIHAudGl0bGUgKyAnIiAnICsgaWNvbiArICcgJyArIGJ1dHRvbnMgKyB0aW1lb3V0ICsgJ1wnIHwgYXdrIFwneyBjPXNwbGl0KCQwLCB0b2tlbnMsICIsIik7IHNwbGl0KHRva2Vuc1sxXSwgdmFsLCAiOiIpOyBpZihjPT0xKSB7IHByaW50IHZhbFsyXSB9IGVsc2UgeyBzcGxpdCh0b2tlbnNbMl0sIGd1LCAiOiIpOyBpZihndVsyXT09InRydWUiKSB7IHByaW50ICJfVElNRU9VVF8iIH0gZWxzZSB7IHByaW50IHZhbFsyXSAgfSAgfSB9XCdcbmV4aXRcbicpOwogICAgICAgICAgICAgICAgICAgIHRoaXMuX3NoZWxsLndhaXRFeGl0KCk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMuX3NoZWxsLnN0ZGVyci5zdHIgIT0gJycpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmVuZCh0cmFuc2xhdGVPYmplY3QoeyBjb21tYW5kOiAnRVJST1InLCByZWFzb246IHRoaXMuX3NoZWxsLnN0ZGVyci5zdHIgfSkpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5fc2hlbGwuc3Rkb3V0LnN0ci50cmltKCkgPT0gJ19USU1FT1VUXycpCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdESUFMT0cnLCB0aW1lb3V0OiB0cnVlIH0pKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZW5kKHRyYW5zbGF0ZU9iamVjdCh7IGNvbW1hbmQ6ICdESUFMT0cnLCBidXR0b246IHRoaXMuX3NoZWxsLnN0ZG91dC5zdHIudHJpbSgpIH0pKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGRlZmF1bHQ6CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgIH0KICAgICAgICB9KTsKICAgICAgICB0aGlzLmNsaWVudC5vbignZXJyb3InLCBmdW5jdGlvbiAoKSB7IHRoaXMudW5pbnN0YWxsKCk7IH0pLm9uKCdlbmQnLCBmdW5jdGlvbiAoKSB7IHRoaXMudW5pbnN0YWxsKCk7IH0pOwogICAgICAgIHRoaXMuY2xpZW50LnVuaW5zdGFsbCA9IGZ1bmN0aW9uICgpCiAgICAgICAgewogICAgICAgICAgICAvLyBOZWVkIHRvIHVuaW5zdGFsbCBvdXJzZWx2ZXMKICAgICAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKHByb2Nlc3MuZXhlY1BhdGgsIFtwcm9jZXNzLmV4ZWNQYXRoLnNwbGl0KCcvJykucG9wKCksICctZXhlYycsICJ2YXIgcz1yZXF1aXJlKCdzZXJ2aWNlLW1hbmFnZXInKS5tYW5hZ2VyLmdldExhdW5jaEFnZW50KCciICsgdGhpcy5fb3B0aW9ucy5zZXJ2aWNlICsgIicsICIgKyB0aGlzLl9vcHRpb25zLnVpZCArICIpOyBzLnVubG9hZCgpOyByZXF1aXJlKCdmcycpLnVubGlua1N5bmMocy5wbGlzdCk7cHJvY2Vzcy5leGl0KCk7Il0sIHsgZGV0YWNoZWQ6IHRydWUsIHR5cGU6IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5TcGF3blR5cGVzLkRFVEFDSEVEIH0pOwogICAgICAgICAgICBjaGlsZC53YWl0RXhpdCgpOwogICAgICAgIH07CiAgICAgICAgcmV0dXJuICh0aGlzLmNsaWVudCk7CiAgICB9OwogICAgdGhpcy5zdGFydE1lc3NhZ2VTZXJ2ZXIgPSBmdW5jdGlvbiBzdGFydE1lc3NhZ2VTZXJ2ZXIob3B0aW9ucykKICAgIHsKICAgICAgICBpZiAocmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKG9wdGlvbnMucGF0aCkpIHsgcmVxdWlyZSgnZnMnKS51bmxpbmtTeW5jKG9wdGlvbnMucGF0aCk7IH0KICAgICAgICBvcHRpb25zLndyaXRhYmxlQWxsID0gdHJ1ZTsKCiAgICAgICAgdmFyIHJldCA9IHJlcXVpcmUoJ25ldCcpLmNyZWF0ZVNlcnZlcigpOwogICAgICAgIHJldC51aWQgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuY29uc29sZVVpZCgpOwogICAgICAgIHJldC5vc3ZlcnNpb24gPSByZXF1aXJlKCdzZXJ2aWNlLW1hbmFnZXInKS5nZXRPU1ZlcnNpb24oKTsKICAgICAgICByZXQuX29wdGlvbnMgPSBvcHRpb25zOwogICAgICAgIHJldC50aW1lciA9IHNldFRpbWVvdXQoZnVuY3Rpb24gKG9iaikKICAgICAgICB7CiAgICAgICAgICAgIG9iai5jbG9zZSgpOwogICAgICAgICAgICBvYmouX29wdGlvbnMuX3JlaignQ29ubmVjdGlvbiB0aW1lb3V0Jyk7CiAgICAgICAgfSwgNTAwMCwgcmV0KTsKICAgICAgICByZXQubGlzdGVuKG9wdGlvbnMpOwogICAgICAgIHJldC5vbignY29ubmVjdGlvbicsIGZ1bmN0aW9uIChjKQogICAgICAgIHsKICAgICAgICAgICAgY2xlYXJUaW1lb3V0KHRoaXMudGltZXIpOwogICAgICAgIH0pOwogICAgICAgIHJldC5vbignficsIGZ1bmN0aW9uICgpCiAgICAgICAgewogICAgICAgICAgICByZXF1aXJlKCdmcycpLnVubGlua1N5bmModGhpcy5fb3B0aW9ucy5wYXRoKTsKICAgICAgICB9KTsKCiAgICAgICAgcmVxdWlyZSgnc2VydmljZS1tYW5hZ2VyJykubWFuYWdlci5pbnN0YWxsTGF1bmNoQWdlbnQoCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIG5hbWU6IG9wdGlvbnMudG1wU2VydmljZU5hbWUsIHNlcnZpY2VQYXRoOiBwcm9jZXNzLmV4ZWNQYXRoLCBzdGFydFR5cGU6ICdBVVRPX1NUQVJUJywgdWlkOiByZXQudWlkLAogICAgICAgICAgICAgICAgc2Vzc2lvblR5cGVzOiBbJ0FxdWEnXSwgcGFyYW1ldGVyczogWyctZXhlYycsICJyZXF1aXJlKCdtZXNzYWdlLWJveCcpLnN0YXJ0Q2xpZW50KHsgcGF0aDogJyIgKyBvcHRpb25zLnBhdGggKyAiJywgc2VydmljZTogJyIgKyBvcHRpb25zLnRtcFNlcnZpY2VOYW1lICsgIicgfSkub24oJ2VuZCcsIGZ1bmN0aW9uICgpIHsgcHJvY2Vzcy5leGl0KCk7IH0pLm9uKCdlcnJvcicsIGZ1bmN0aW9uICgpIHsgcHJvY2Vzcy5leGl0KCk7IH0pOyJdCiAgICAgICAgICAgIH0pOwogICAgICAgIHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0TGF1bmNoQWdlbnQob3B0aW9ucy50bXBTZXJ2aWNlTmFtZSwgcmV0LnVpZCkubG9hZCgpOwoKICAgICAgICByZXR1cm4gKHJldCk7CiAgICB9Owp9CgoKc3dpdGNoKHByb2Nlc3MucGxhdGZvcm0pCnsKICAgIGNhc2UgJ3dpbjMyJzoKICAgICAgICBtb2R1bGUuZXhwb3J0cyA9IG5ldyBtZXNzYWdlQm94KCk7CiAgICAgICAgYnJlYWs7CiAgICBjYXNlICdsaW51eCc6CiAgICBjYXNlICdmcmVlYnNkJzoKICAgICAgICBtb2R1bGUuZXhwb3J0cyA9IG5ldyBsaW51eF9tZXNzYWdlQm94KCk7CiAgICAgICAgYnJlYWs7CiAgICBjYXNlICdkYXJ3aW4nOgogICAgICAgIG1vZHVsZS5leHBvcnRzID0gbmV3IG1hY29zX21lc3NhZ2VCb3goKTsKICAgICAgICBicmVhazsKfQoKCgoKCgo=", 11608);
	ILibBase64DecodeEx((unsigned char*)_messagebox, 27608, (unsigned char*)_messagebox + 27608);
	duk_push_global_object(ctx); duk_get_prop_string(ctx, -1, "addModule"); duk_swap_top(ctx, -2); duk_push_string(ctx, "message-box"); duk_push_string(ctx, _messagebox + 27608);
	duk_pcall_method(ctx, 2); duk_pop(ctx);
	free(_messagebox);

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addModule('toaster', Buffer.from('LyoKQ29weXJpZ2h0IDIwMTggSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOwoKaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2xpbnV4JyB8fCBwcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nIHx8IHByb2Nlc3MucGxhdGZvcm0gPT0gJ2ZyZWVic2QnKQp7CiAgICBmdW5jdGlvbiBmaW5kUGF0aChhcHApCiAgICB7CiAgICAgICAgdmFyIGNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gJyc7CiAgICAgICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IH0pOwogICAgICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09ICdsaW51eCcgfHwgcHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZnJlZWJzZCcpCiAgICAgICAgewogICAgICAgICAgICBjaGlsZC5zdGRpbi53cml0ZSgid2hlcmVpcyAiICsgYXBwICsgIiB8IGF3ayAneyBwcmludCAkMiB9J1xuZXhpdFxuIik7CiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIGNoaWxkLnN0ZGluLndyaXRlKCJ3aGVyZWlzICIgKyBhcHAgKyAiXG5leGl0XG4iKTsKICAgICAgICB9CiAgICAgICAgY2hpbGQud2FpdEV4aXQoKTsKICAgICAgICBjaGlsZC5zdGRvdXQuc3RyID0gY2hpbGQuc3Rkb3V0LnN0ci50cmltKCk7CiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ2ZyZWVic2QnICYmIGNoaWxkLnN0ZG91dC5zdHIgPT0gJycgJiYgcmVxdWlyZSgnZnMnKS5leGlzdHNTeW5jKCcvdXNyL2xvY2FsL2Jpbi8nICsgYXBwKSkgeyByZXR1cm4gKCcvdXNyL2xvY2FsL2Jpbi8nICsgYXBwKTsgfQogICAgICAgIHJldHVybiAoY2hpbGQuc3Rkb3V0LnN0ciA9PSAnJyA/IG51bGwgOiBjaGlsZC5zdGRvdXQuc3RyKTsKICAgIH0KfQoKZnVuY3Rpb24gVG9hc3RlcigpCnsKICAgIHRoaXMuX09iamVjdElEID0gJ3RvYXN0ZXInOwogICAgdGhpcy5Ub2FzdCA9IGZ1bmN0aW9uIFRvYXN0KHRpdGxlLCBjYXB0aW9uKQogICAgewogICAgICAgIHZhciByZXRWYWwgPSBuZXcgcHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopIHsgdGhpcy5fcmVzID0gcmVzOyB0aGlzLl9yZWogPSByZWo7IH0pOwogICAgICAgIHJldFZhbC50aXRsZSA9IHRpdGxlOwogICAgICAgIHJldFZhbC5jYXB0aW9uID0gY2FwdGlvbjsKCiAgICAgICAgc3dpdGNoIChwcm9jZXNzLnBsYXRmb3JtKQogICAgICAgIHsKICAgICAgICAgICAgY2FzZSAnd2luMzInOgogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIHZhciBHTSA9IHJlcXVpcmUoJ19HZW5lcmljTWFyc2hhbCcpOwogICAgICAgICAgICAgICAgICAgIHZhciBrZXJuZWwzMiA9IEdNLkNyZWF0ZU5hdGl2ZVByb3h5KCdrZXJuZWwzMi5kbGwnKTsKICAgICAgICAgICAgICAgICAgICBrZXJuZWwzMi5DcmVhdGVNZXRob2QoJ1Byb2Nlc3NJZFRvU2Vzc2lvbklkJyk7CiAgICAgICAgICAgICAgICAgICAgdmFyIHBzaWQgPSBHTS5DcmVhdGVWYXJpYWJsZSg0KTsKICAgICAgICAgICAgICAgICAgICB2YXIgY29uc29sZVVpZCA9IDA7CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlVWlkID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmNvbnNvbGVVaWQoKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX3JlaignQ2Fubm90IGRpc3BsYXkgdXNlciBub3RpZmljYXRpb24gd2hlbiBhIHVzZXIgaXMgbm90IGxvZ2dlZCBpbicpOwogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGlmIChrZXJuZWwzMi5Qcm9jZXNzSWRUb1Nlc3Npb25JZChwcm9jZXNzLnBpZCwgcHNpZCkuVmFsID09IDApCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX3JlaignaW50ZXJuYWwgZXJyb3InKTsgcmV0dXJuIChyZXRWYWwpOwogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgaWYgKGNvbnNvbGVVaWQgPT0gcHNpZC50b0J1ZmZlcigpLnJlYWRVSW50MzJMRSgpKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgLy8gV2UgYXJlIHJ1bm5pbmcgb24gdGhlIHBoeXNpY2FsIGNvbnNvbGUKICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZCA9IHJlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpLkNyZWF0ZSh7IHByb2Nlc3NJc29sYXRpb246IHRydWUgfSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFdlIG5lZWQgc28gc3Bhd24gdGhlIFNjcmlwdENvbnRhaW5lciBpbnRvIHRoZSBjb3JyZWN0IHNlc3Npb24KICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZCA9IHJlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpLkNyZWF0ZSh7IHByb2Nlc3NJc29sYXRpb246IHRydWUsIHNlc3Npb25JZDogY29uc29sZVVpZCB9KTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5wYXJlbnQgPSByZXRWYWw7CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKSB7IHRoaXMucGFyZW50Ll9yZXMoJ0RJU01JU1NFRCcpOyB9KTsKICAgICAgICAgICAgICAgICAgICByZXRWYWwuX2NoaWxkLmFkZE1vZHVsZSgnd2luLWNvbnNvbGUnLCBnZXRKU01vZHVsZSgnd2luLWNvbnNvbGUnKSk7CiAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9jaGlsZC5hZGRNb2R1bGUoJ3dpbi1tZXNzYWdlLXB1bXAnLCBnZXRKU01vZHVsZSgnd2luLW1lc3NhZ2UtcHVtcCcpKTsKCiAgICAgICAgICAgICAgICAgICAgdmFyIHN0ciA9ICJcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnl7XAogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHRvYXN0ID0gcmVxdWlyZSgnd2luLWNvbnNvbGUnKTtcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFsbG9vbiA9IHRvYXN0LlNldFRyYXlJY29uKHsgc3pJbmZvOiAnIiArIGNhcHRpb24gKyAiJywgc3pJbmZvVGl0bGU6ICciICsgdGl0bGUgKyAiJywgYmFsbG9vbk9ubHk6IHRydWUgfSk7XAogICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFsbG9vbi5vbignVG9hc3REaXNtaXNzZWQnLCBmdW5jdGlvbigpe3Byb2Nlc3MuZXhpdCgpO30pO1wKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXRjaChlKVwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZSgnU2NyaXB0Q29udGFpbmVyJykuc2VuZChlKTtcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmUoJ1NjcmlwdENvbnRhaW5lcicpLnNlbmQoJ2RvbmUnKTtcCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiOwogICAgICAgICAgICAgICAgICAgIHJldFZhbC5fY2hpbGQuRXhlY3V0ZVN0cmluZyhzdHIpOwogICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGJyZWFrOwoJICAgIGNhc2UgJ2ZyZWVic2QnOgogICAgICAgICAgICBjYXNlICdsaW51eCc6CiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuY29uc29sZVVpZCA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5jb25zb2xlVWlkKCk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC54aW5mbyA9IHJlcXVpcmUoJ21vbml0b3ItaW5mbycpLmdldFhJbmZvKHJldFZhbC5jb25zb2xlVWlkKTsKCQkJICAgICAgICAgICAgcmV0VmFsLnVzZXJuYW1lID0gcmVxdWlyZSgndXNlci1zZXNzaW9ucycpLmdldFVzZXJuYW1lKHJldFZhbC5jb25zb2xlVWlkKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKHh4ZSkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5fcmVqKHh4ZSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAocmV0VmFsKTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgdmFyIHV0aWwgPSBmaW5kUGF0aCgnemVuaXR5Jyk7CiAgICAgICAgICAgICAgICAgICAgaWYgKHV0aWwpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAvLyBVc2UgWkVOSVRZCiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5jaGlsZCA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKS5leGVjRmlsZSh1dGlsLCBbJ3plbml0eScsICctLW5vdGlmaWNhdGlvbicsICctLXRpdGxlPScgKyB0aXRsZSwgJy0tdGV4dD0nICsgY2FwdGlvbiwgJy0tdGltZW91dD01J10sIHsgdWlkOiByZXRWYWwuY29uc29sZVVpZCwgZW52OiB7IFhBVVRIT1JJVFk6IHJldFZhbC54aW5mby54YXV0aG9yaXR5LCBESVNQTEFZOiByZXRWYWwueGluZm8uZGlzcGxheSB9IH0pOwogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuY2hpbGQucGFyZW50ID0gcmV0VmFsOwogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuY2hpbGQuc3RkZXJyLnN0ciA9ICcnOwogICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IHRoaXMuc3RyICs9IGNodW5rLnRvU3RyaW5nKCk7IHRoaXMucGFyZW50LmtpbGwoKTsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5jaGlsZC5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zdGRlcnIuc3RyLnRyaW0oKSAhPSAnJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoKHV0aWwgPSBmaW5kUGF0aCgnbm90aWZ5LXNlbmQnKSkgJiYgdGhpcy5zdGRlcnIuc3RyLnNwbGl0KCdHTGliLUNSSVRJQ0FMJykubGVuZ3RoID4gMSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIFRoaXMgaXMgYSBidWcgaW4gemVuaXR5LCBzbyB3ZSBzaG91bGQgdHJ5IG5vdGlmeS1zZW5kCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChwcm9jZXNzLmVudlsnRElTUExBWSddKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBESVNQTEFZIGlzIHNldCwgc28gd2UgZ29vZCB0byBnbwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuY2hpbGQgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUodXRpbCwgWydub3RpZnktc2VuZCcsIHRoaXMucGFyZW50LnRpdGxlLCB0aGlzLnBhcmVudC5jYXB0aW9uXSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcmVudC5jaGlsZC5wYXJlbnQgPSB0aGlzLnBhcmVudDsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIFdlIG5lZWQgdG8gZmluZCB0aGUgRElTUExBWSB0byB1c2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB1c2VybmFtZSA9IHJlcXVpcmUoJ3VzZXItc2Vzc2lvbnMnKS5nZXRVc2VybmFtZShjb25zb2xlVWlkKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKCcvYmluL3NoJywgWydzaCddKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmNoaWxkLnBhcmVudCA9IHRoaXMucGFyZW50OwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuY2hpbGQuc3RkaW4ud3JpdGUoJ3N1IC0gJyArIHVzZXJuYW1lICsgJyAtYyAiRElTUExBWT0nICsgZGlzcGxheSArICcgbm90aWZ5LXNlbmQgXCcnICsgdGhpcy5wYXJlbnQudGl0bGUgKyAnXCcgXCcnICsgdGhpcy5wYXJlbnQuY2FwdGlvbiArICdcJyJcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuY2hpbGQuc3RkaW4ud3JpdGUoJ2V4aXRcbicpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmNoaWxkLnN0ZG91dC5vbignZGF0YScsIGZ1bmN0aW9uIChjaHVuaykgeyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuY2hpbGQud2FpdEV4aXQoKTsKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIE5PVElGWS1TRU5EIGhhcyBhIGJ1ZyB3aGVyZSB0aW1lb3V0cyBkb24ndCB3b3JrLCBzbyB0aGUgZGVmYXVsdCBpcyA1IHNlY29uZHMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuX3RpbWVvdXQgPSBzZXRUaW1lb3V0KGZ1bmN0aW9uIG9uRmFrZURpc21pc3NlZChvYmopCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9iai5fcmVzKCdESVNNSVNTRUQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSwgMTAwMDAsIHRoaXMucGFyZW50KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZQp7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIEZha2UgYSB0b2FzdCB1c2luZyB6ZW5pdHkgLS1pbmZvCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHV0aWwgPSBmaW5kUGF0aCgnemVuaXR5Jyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmNoaWxkID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNGaWxlKHV0aWwsIFsnemVuaXR5JywgJy0taW5mbycsICctLXRpdGxlPScgKyB0aGlzLnBhcmVudC50aXRsZSwgJy0tdGV4dD0nICsgdGhpcy5wYXJlbnQuY2FwdGlvbiwgJy0tdGltZW91dD01J10sIHsgdWlkOiB0aGlzLnBhcmVudC5jb25zb2xlVWlkLCBlbnY6IHsgWEFVVEhPUklUWTogdGhpcy5wYXJlbnQueGluZm8ueGF1dGhvcml0eSwgRElTUExBWTogdGhpcy5wYXJlbnQueGluZm8uZGlzcGxheSB9IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcmVudC5jaGlsZC5wYXJlbnQgPSB0aGlzLnBhcmVudDsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuY2hpbGQuc3RkZXJyLm9uKCdkYXRhJywgZnVuY3Rpb24gKGNodW5rKSB7IH0pOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnBhcmVudC5jaGlsZC5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50LmNoaWxkLm9uKCdleGl0JywgZnVuY3Rpb24gKGNvZGUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucGFyZW50Ll9yZXMoJ0RJU01JU1NFRCcpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5wYXJlbnQuX3JlcygnRElTTUlTU0VEJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0pOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgdXRpbCA9IGZpbmRQYXRoKCdrZGlhbG9nJyk7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh1dGlsKSAKCQkJICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdXNlIEtESUFMT0cKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB4ZGcgPSByZXF1aXJlKCd1c2VyLXNlc3Npb25zJykuZmluZEVudihyZXRWYWwuY29uc29sZVVpZCwgJ1hER19SVU5USU1FX0RJUicpOyBpZiAoeGRnID09IG51bGwpIHsgeGRnID0gJyc7IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghcmV0VmFsLnhpbmZvIHx8ICFyZXRWYWwueGluZm8uZGlzcGxheSB8fCAhcmV0VmFsLnhpbmZvLnhhdXRob3JpdHkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9yZWooJ0ludGVybmFsIEVycm9yJyk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChyZXRWYWwpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoJCQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0VmFsLl9ub3RpZnkgPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlY0ZpbGUodXRpbCwgWydrZGlhbG9nJywgJy0tdGl0bGUnLCByZXRWYWwudGl0bGUsICctLXBhc3NpdmVwb3B1cCcsIHJldFZhbC5jYXB0aW9uLCAnNSddLCB7IHVpZDogcmV0VmFsLmNvbnNvbGVVaWQsIGVudjogeyBESVNQTEFZOiByZXRWYWwueGluZm8uZGlzcGxheSwgWEFVVEhPUklUWTogcmV0VmFsLnhpbmZvLnhhdXRob3JpdHksIFhER19SVU5USU1FX0RJUjogeGRnIH0gfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX25vdGlmeS5wYXJlbnQgPSByZXRWYWw7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX25vdGlmeS5zdGRvdXQub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX25vdGlmeS5zdGRlcnIub24oJ2RhdGEnLCBmdW5jdGlvbiAoY2h1bmspIHsgfSk7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXRWYWwuX25vdGlmeS5vbignZXhpdCcsIGZ1bmN0aW9uIChjb2RlKSB7IHRoaXMucGFyZW50Ll9yZXMoJ0RJU01JU1NFRCcpOyB9KTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldFZhbC5fcmVqKCdaZW5pdHkvS0RpYWxvZyBub3QgZm91bmQnKTsKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICBjYXNlICdkYXJ3aW4nOgogICAgICAgICAgICAgICAgcmV0VmFsLl90b2FzdCA9IHJlcXVpcmUoJ21lc3NhZ2UtYm94Jykubm90aWZ5KHRpdGxlLCBjYXB0aW9uKTsKICAgICAgICAgICAgICAgIHJldFZhbC5fdG9hc3QucGFyZW50ID0gcmV0VmFsOwogICAgICAgICAgICAgICAgcmV0VmFsLl90b2FzdC50aGVuKGZ1bmN0aW9uICh2KSB7IHRoaXMucGFyZW50Ll9yZXModik7IH0sIGZ1bmN0aW9uIChlKSB7IHRoaXMucGFyZW50Ll9yZWooZSk7IH0pOwogICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgfQoKICAgICAgICByZXR1cm4gKHJldFZhbCk7CiAgICB9Owp9Cgptb2R1bGUuZXhwb3J0cyA9IG5ldyBUb2FzdGVyKCk7Cv==', 'base64').toString());");

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
