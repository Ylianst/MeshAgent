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
#define ILibDuktape_DescriptorEvents_HTable		"\xFF_DescriptorEvents_HTable"
#define ILibDuktape_DescriptorEvents_CURRENT	"\xFF_DescriptorEvents_CURRENT"
#define ILibDuktape_DescriptorEvents_FD			"\xFF_DescriptorEvents_FD"
#define ILibDuktape_DescriptorEvents_Options	"\xFF_DescriptorEvents_Options"
#define ILibDuktape_DescriptorEvents_WaitHandle "\xFF_DescriptorEvents_WindowsWaitHandle"
#define ILibDuktape_ChainViewer_PromiseList		"\xFF_ChainViewer_PromiseList"
#define CP_ISO8859_1							28591

#define ILibDuktape_AddCompressedModule(ctx, name, b64str) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_pcall_method(ctx, 2);duk_pop(ctx);



typedef enum ILibDuktape_Console_DestinationFlags
{
	ILibDuktape_Console_DestinationFlags_DISABLED		= 0,
	ILibDuktape_Console_DestinationFlags_StdOut			= 1,
	ILibDuktape_Console_DestinationFlags_ServerConsole	= 2,
	ILibDuktape_Console_DestinationFlags_WebLog			= 4,
	ILibDuktape_Console_DestinationFlags_LogFile		= 8
}ILibDuktape_Console_DestinationFlags;

#ifdef WIN32
typedef struct ILibDuktape_DescriptorEvents_WindowsWaitHandle
{
	HANDLE waitHandle;
	HANDLE eventThread;
	void *chain;
	duk_context *ctx;
	void *object;
}ILibDuktape_DescriptorEvents_WindowsWaitHandle;
#endif

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
duk_ret_t ILibDuktape_Polyfills_Buffer_randomFill(duk_context *ctx)
{
	int start, length;
	char *buffer;
	duk_size_t bufferLen;

	start = (int)(duk_get_top(ctx) == 0 ? 0 : duk_require_int(ctx, 0));
	length = (int)(duk_get_top(ctx) == 2 ? duk_require_int(ctx, 1) : -1);

	duk_push_this(ctx);
	buffer = (char*)Duktape_GetBuffer(ctx, -1, &bufferLen);
	if ((duk_size_t)length > bufferLen || length < 0)
	{
		length = (int)(bufferLen - start);
	}

	util_random(length, buffer + start);
	return(0);
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
#ifdef WIN32
		else if (strcmp(cType, "utf16") == 0)
		{
			int sz = (MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, NULL, 0) * 2);
			WCHAR* b = duk_push_fixed_buffer(ctx, sz);
			duk_push_buffer_object(ctx, -1, 0, sz, DUK_BUFOBJ_NODEJS_BUFFER);
			MultiByteToWideChar(CP_UTF8, 0, buffer, (int)bufferLen, b, sz / 2);
		}
#endif
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
	else if (strcmp(encoding, "utf8") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);
		buffer = duk_push_fixed_buffer(ctx, strlength);
		memcpy_s(buffer, strlength, str, strlength);
		duk_push_buffer_object(ctx, -1, 0, strlength, DUK_BUFOBJ_NODEJS_BUFFER);
		return(1);
	}
	else if (strcmp(encoding, "binary") == 0)
	{
		str = (char*)duk_get_lstring(ctx, 0, &strlength);

#ifdef WIN32
		int r = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, NULL, 0);
		buffer = duk_push_fixed_buffer(ctx, 2 + (2 * r));
		strlength = (duk_size_t)MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, (int)strlength, (LPWSTR)buffer, r + 1);
		r = (int)WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, NULL, 0, NULL, FALSE);
		duk_push_fixed_buffer(ctx, r);
		WideCharToMultiByte(CP_ISO8859_1, 0, (LPCWCH)buffer, (int)strlength, (LPSTR)Duktape_GetBuffer(ctx, -1, NULL), r, NULL, FALSE);
		duk_push_buffer_object(ctx, -1, 0, r, DUK_BUFOBJ_NODEJS_BUFFER);
#else
		duk_eval_string(ctx, "Buffer.fromBinary");	// [func]
		duk_dup(ctx, 0);
		duk_call(ctx, 1);
#endif
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

#ifdef _POSIX
	char fromBinary[] =
		"Object.defineProperty(Buffer, \"fromBinary\",\
		{\
			get: function()\
			{\
				return((function fromBinary(str)\
						{\
							var child = require('child_process').execFile('/usr/bin/iconv', ['iconv', '-c','-f', 'UTF-8', '-t', 'CP819']);\
							child.stdout.buf = Buffer.alloc(0);\
							child.stdout.on('data', function(c) { this.buf = Buffer.concat([this.buf, c]); });\
							child.stdin.write(str);\
							child.stderr.on('data', function(c) { });\
							child.stdin.end();\
							child.waitExit();\
							return(child.stdout.buf);\
						}));\
			}\
		});";
	duk_eval_string_noresult(ctx, fromBinary);

#endif

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
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Buffer_randomFill, DUK_VARARGS);	// [g][Buffer][prototype][func]
	duk_put_prop_string(ctx, -2, "randomFill");										// [g][Buffer][prototype]
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
duk_ret_t ILibDuktape_Polyfills_Array_includes(duk_context *ctx)
{
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	for (i = 0; i < count; ++i)
	{
		duk_get_prop_index(ctx, -1, (duk_uarridx_t)i);		// [array][val1]
		duk_dup(ctx, 0);									// [array][val1][val2]
		if (duk_equals(ctx, -2, -1))
		{
			duk_push_true(ctx);
			return(1);
		}
		else
		{
			duk_pop_2(ctx);									// [array]
		}
	}
	duk_push_false(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Array_partialIncludes(duk_context *ctx)
{
	duk_size_t inLen;
	char *inStr = (char*)duk_get_lstring(ctx, 0, &inLen);
	duk_push_this(ctx);										// [array]
	uint32_t count = (uint32_t)duk_get_length(ctx, -1);
	uint32_t i;
	duk_size_t tmpLen;
	char *tmp;
	for (i = 0; i < count; ++i)
	{
		tmp = Duktape_GetStringPropertyIndexValueEx(ctx, -1, i, "", &tmpLen);
		if (inLen > 0 && inLen <= tmpLen && strncmp(inStr, tmp, inLen) == 0)
		{
			duk_push_int(ctx, i);
			return(1);
		}
	}
	duk_push_int(ctx, -1);
	return(1);
}
void ILibDuktape_Polyfills_Array(duk_context *ctx)
{
	// Polyfill 'Array.includes'
	duk_get_prop_string(ctx, -1, "Array");											// [Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [Array][proto]
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "includes", ILibDuktape_Polyfills_Array_includes, 1);
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "partialIncludes", ILibDuktape_Polyfills_Array_partialIncludes, 1);
	duk_pop_2(ctx);																	// ...
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
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_padStart, DUK_VARARGS);	// [string][proto][func]
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

	str = Duktape_PushBuffer(ctx, strLen + ((PREFIX != NULL) ? strnlen_s(PREFIX, 9) : 0));
	x = (int)(ILibMemory_Size(str) - strLen);
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
			duk_pcall_method(ctx, 3);
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
duk_ret_t ILibDuktape_Polyfills_Console_rawLog(duk_context *ctx)
{
	char *val = (char*)duk_require_string(ctx, 0);
	ILIBLOGMESSAGEX("%s", val);
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
	ILibDuktape_CreateInstanceMethod(ctx, "rawLog", ILibDuktape_Polyfills_Console_rawLog, 1);

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
duk_ret_t ILibDuktape_Polyfills_addCompressedModule_dataSink(duk_context *ctx)
{
	duk_push_this(ctx);								// [stream]
	if (!duk_has_prop_string(ctx, -1, "_buffer"))
	{
		duk_push_array(ctx);						// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	else
	{
		duk_push_array(ctx);						// [stream][array]
		duk_get_prop_string(ctx, -2, "_buffer");	// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_dup(ctx, 0);							// [stream][array][buffer]
		duk_array_push(ctx, -2);					// [stream][array]
		duk_buffer_concat(ctx);						// [stream][buffer]
		duk_put_prop_string(ctx, -2, "_buffer");	// [stream]
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_addCompressedModule(duk_context *ctx)
{
	duk_eval_string(ctx, "require('compressed-stream').createDecompressor();");
	void *decoder = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_Polyfills_addCompressedModule_dataSink);

	duk_dup(ctx, -1);						// [stream]
	duk_get_prop_string(ctx, -1, "end");	// [stream][end]
	duk_swap_top(ctx, -2);					// [end][this]
	duk_dup(ctx, 1);						// [end][this][buffer]
	if (duk_pcall_method(ctx, 1) == 0)
	{
		duk_push_heapptr(ctx, decoder);				// [stream]
		duk_get_prop_string(ctx, -1, "_buffer");	// [stream][buffer]
		duk_get_prop_string(ctx, -1, "toString");	// [stream][buffer][toString]
		duk_swap_top(ctx, -2);						// [stream][toString][this]
		duk_call_method(ctx, 0);					// [stream][decodedString]
		duk_push_global_object(ctx);				// [stream][decodedString][global]
		duk_get_prop_string(ctx, -1, "addModule");	// [stream][decodedString][global][addModule]
		duk_swap_top(ctx, -2);						// [stream][decodedString][addModule][this]
		duk_dup(ctx, 0);							// [stream][decodedString][addModule][this][name]
		duk_dup(ctx, -4);							// [stream][decodedString][addModule][this][name][string]
		duk_pcall_method(ctx, 2);
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
		Duktape_RunOnEventLoop(tmp->chain, duk_ctx_nonce(stream->readableStream->ctx), stream->readableStream->ctx, ILibDuktape_DynamicBuffer_WriteSink_ChainThread, NULL, tmp);
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
			if (duk_is_null_or_undefined(sender->ctx, -1))
			{
				duk_pop(sender->ctx);
				break;
			}
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
	if (buffer != NULL)
	{
		duk_push_boolean(ctx, !ILibDuktape_readableStream_WriteDataEx(RS, 0, buffer, (int)bufferLen));		// [stream][buffer][retVal]
	}
	else
	{
		ILibDuktape_readableStream_WriteEnd(RS);
		duk_push_false(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Stream_EndSink(duk_context *ctx)
{
	duk_push_this(ctx);												// [stream]
	ILibDuktape_readableStream *RS = (ILibDuktape_readableStream*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_Stream_ReadablePtr);
	ILibDuktape_readableStream_WriteEnd(RS);
	return(0);
}
duk_ret_t ILibDuktape_Stream_readonlyError(duk_context *ctx)
{
	duk_push_current_function(ctx);
	duk_size_t len;
	char *propName = Duktape_GetStringPropertyValueEx(ctx, -1, "propName", "<unknown>", &len);
	duk_push_lstring(ctx, propName, len);
	duk_get_prop_string(ctx, -1, "concat");					// [string][concat]
	duk_swap_top(ctx, -2);									// [concat][this]
	duk_push_string(ctx, " is readonly");					// [concat][this][str]
	duk_call_method(ctx, 1);								// [str]
	duk_throw(ctx);
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
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
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
	int bufmode = Duktape_GetIntPropertyValue(stream->ctx, -1, "bufferMode", 0);
	duk_get_prop_string(stream->ctx, -1, "_write");													// [writable][_write]
	duk_swap_top(stream->ctx, -2);																	// [_write][this]
	if(duk_stream_flags_isBuffer(stream->Reserved))
	{
		if (bufmode == 0)
		{
			// Legacy Mode. We use an external buffer, so a memcpy does not occur. JS must copy memory if it needs to save it
			duk_push_external_buffer(stream->ctx);													// [_write][this][extBuffer]
			duk_config_buffer(stream->ctx, -1, buffer, (duk_size_t)bufferLen);
		}
		else
		{
			// Compliant Mode. We copy the buffer into a buffer that will be wholly owned by the recipient
			char *cb = (char*)duk_push_fixed_buffer(stream->ctx, (duk_size_t)bufferLen);			// [_write][this][extBuffer]
			memcpy_s(cb, (size_t)bufferLen, buffer, (size_t)bufferLen);
		}
		duk_push_buffer_object(stream->ctx, -1, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [_write][this][extBuffer][buffer]
		duk_remove(stream->ctx, -2);																// [_write][this][buffer]	
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
		if (retVal != ILibTransport_DoneState_COMPLETE)
		{
			retVal = duk_to_boolean(stream->ctx, -1) ? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
		}
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
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_write", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "final");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_final"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_final", ILibDuktape_Stream_readonlyError);
		}
		h = Duktape_GetHeapptrProperty(ctx, 0, "read");
		if (h != NULL) { duk_push_heapptr(ctx, h); duk_put_prop_string(ctx, -2, "_read"); }
		else
		{
			ILibDuktape_CreateEventWithSetterEx(ctx, "_read", ILibDuktape_Stream_readonlyError);
		}
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
	if (duk_ctx_is_alive((duk_context*)args[1]) && duk_ctx_is_valid((uintptr_t)args[2], ctx) && duk_ctx_shutting_down(ctx)==0)
	{
		if (g_displayFinalizerMessages) { printf("=> GC();\n"); }
		duk_gc(ctx, 0);
	}
}
duk_ret_t ILibDuktape_Polyfills_debugGC(duk_context *ctx)
{
	ILibDuktape_Immediate(ctx, (void*[]) { Duktape_GetChain(ctx), ctx, (void*)duk_ctx_nonce(ctx), NULL }, 3, ILibDuktape_Polyfills_debugGC2);
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
extern uint32_t crc32(uint32_t crc, const unsigned char* buf, uint32_t len);
duk_ret_t ILibDuktape_Polyfills_crc32c(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32c(pre, (unsigned char*)buffer, (uint32_t)len));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_crc32(duk_context *ctx)
{
	duk_size_t len;
	char *buffer = Duktape_GetBuffer(ctx, 0, &len);
	uint32_t pre = duk_is_number(ctx, 1) ? duk_require_uint(ctx, 1) : 0;
	duk_push_uint(ctx, crc32(pre, (unsigned char*)buffer, (uint32_t)len));
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
duk_ret_t ILibDuktape_Polyfills_Object_keys(duk_context *ctx)
{
	duk_push_this(ctx);														// [obj]
	duk_push_array(ctx);													// [obj][keys]
	duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);						// [obj][keys][enum]
	while (duk_next(ctx, -1, 0))											// [obj][keys][enum][key]
	{
		duk_array_push(ctx, -3);											// [obj][keys][enum]
	}
	duk_pop(ctx);															// [obj][keys]
	return(1);
}
void ILibDuktape_Polyfills_object(duk_context *ctx)
{
	// Polyfill Object._hashCode() 
	duk_get_prop_string(ctx, -1, "Object");											// [g][Object]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_hashCode, 0);				// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "_hashCode");							// [g][Object][prototype]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_Object_keys, 0);					// [g][Object][prototype][func]
	ILibDuktape_CreateReadonlyProperty(ctx, "keys");								// [g][Object][prototype]
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

	// CRC32-STREAM, refer to /modules/crc32-stream.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVNFu2jAUfY+Uf7jiBaiygNgbVTWxtNOiVVARuqpPk3FugrdgZ7bTFCH+fdchtKTdpPnF2Pfk3HOOrxhd+F6kyp0W+cbCZDwZQywtFhApXSrNrFDS93zvVnCUBlOoZIoa7AZhVjJOW1sJ4DtqQ2iYhGMYOECvLfWGl763UxVs2Q6kslAZJAZhIBMFAj5zLC0ICVxty0IwyRFqYTdNl5Yj9L3HlkGtLSMwI3hJp+wcBsw6tUBrY205HY3qug5ZozRUOh8VR5wZ3cbRzTy5+UBq3Rf3skBjQOPvSmiyud4BK0kMZ2uSWLAalAaWa6SaVU5srYUVMg/AqMzWTKPvpcJYLdaV7eR0kkZ+zwGUFJPQmyUQJz34PEviJPC9h3j1dXG/gofZcjmbr+KbBBZLiBbz63gVL+Z0+gKz+SN8i+fXASClRF3wudROPUkULkFMKa4EsdM+U0c5pkQuMsHJlMwrliPk6gm1JC9Qot4K417RkLjU9wqxFbYZAvPeETW5GLnwnpiGB4qjyerqFOKgT2aRbfvD8FS8dGjfyyrJHSdwqlsc0DxEy+jjhA99b398PUep0RKbxPqFfHAsurV//emWew2cwgvzgG8q+SuArKjMZtjFvvnULTeN4Q9eaY3SNT2eG1ERfCKdnNSdODvgIUyP5b9XL9/3aiQN3lYOQfecCcmKc0P/6eQf7K/Hw6lG8Z5bHp9ft86v4OVpKAWrKyS3GSsMtuDF+idyG6ZIcvFOKxoguxsQRQD9J1ZU2A9gDznacydDuiJIpaX7n+ikBYeOvgZCu7s6uMnZqrQqMKSBV9oa0rdvZ2ja7nAg6B/4IHJ3', 'base64'));");

	// http-digest. Refer to /modules/http-digest.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'));");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'));");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'));");

#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'));");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('eJytV0tz2kgQvlPFf+j1RSjL8rJCEVM+EOxUqPWCC4FTOQ7SCKYsZrSjkTGbyn/fHkkIiad2KzogNNPzdffXL6n5oVoZimAr2XKloNNq92DEFfVhKGQgJFFM8GqlWnliDuUhdSHiLpWgVhQGAXHwlu7U4YXKEKWh02hBTQvcpFs3Zr9a2YoI1mQLXCiIQooILASP+RTou0MDBYyDI9aBzwh3KGyYWsVaUoxGtfI9RRALRVCYoHiAT15eDIjS1gJeK6WCu2Zzs9k0SGxpQ8hl00/kwubTaPg4th//QGv1iTn3aRiCpH9HTKKbiy2QAI1xyAJN9MkGhASylBT3lNDGbiRTjC/rEApPbYik1YrLQiXZIlIFnnamob95AWSKcLgZ2DCyb+DzwB7Z9Wrl22j2dTKfwbfBdDoYz0aPNkymMJyMH0az0WSMT19gMP4Of47GD3WgyBJqoe+B1NajiUwzSF2ky6a0oN4TiTlhQB3mMQed4suILCksxRuVHH2BgMo1C3UUQzTOrVZ8tmYqToLw2CNU8qGpyWs2YUpVJDnygmrW8QEgCxGpJM70nTqR0lRWK17EnXg/IDKkNdx6JmplVis/kri9EYlhUC/Eh3v48bO/X/VCXEkjVDO80DDzmy5uemFDBJTbW+7sgOtgyEVBcrFVNJxS4ubWXBF+xRX07x4+R55HZYP4vnBqXSt/lKvTUp2ClAhSsf4uF2OCiBuT9zCxYRVvJ3uZOYn9Ev/F9ntufW9WHVp16Fp42yliHtSy7fjUHAu33X16rLXMhhI2Jhpf1tpd/TAPMLJDgnSb8Ns9GB8H1oNhJkAp7fpSKyk2UDMiLqkjlpz9oyuBcSK3kMQ1I/LnKdfGs9Ke7ZiMHds9NHzKlzpkx47ddtCxbsvMu58dC3VV1xDIynlurOi7kbrbsj628Lrgsm5LBJ4f45aU91LfQuxGziqnsEC3VaT7WIeDxIPRthzjTtN120FO1X5bX0nCNxKSkS7jvdc1+kWZBWp97R/C9rpdK8HtWmVwUfoKrks9EvkqxpzzVy42/DKobgwe49S9AJzlS3oYawR7APETQm3MNAQ6zW8ny/mzZweuGzfA+wuZA7/jeDtZkTu8QvJmRXxY62eN3Fl5Ke0z1Djvs6cSia/NL/aiaD19GRzQX+BpuKLOqx2tn8V1Ziz86VpFnjWzE28oXB2bva2F45Z56syI42wkvu4fD0SR88d7J4/PeWmAdsfM3N6V6bHo9bZ4tmpbn/NVm3bDYp5nkThj46eO2T9ZQUMqlR7FRNGZHo77ND7rba8kVFpR53Buy5qkccrmD6KeBpVvxFZEqrJlqsE+dUu1v84uPkn3+1/xabfKsno9QJb1awJk/ZdAlw6Q1ft1AWq3D6N9bpAUpXYTNx0tgPoj/XaKbSx+R53suvFfZMmcOzBQ15mea12s6MvTqOj9ENXrUZakStZR9FvG5VQ47hv5yUIi/OWKObqHOnsEbP3cx28Xnqxiy9KP+oTHZKgAz8itucfU/X7lHo2iQo4cjhqUj4cM3rPxcsWXHFoqmbP5ULnGLeRGy7xkzjFgbN3xckljMSv2nl21/ISa/YviAvMFX4sugzxsnmJVCHbC82Jeoe+OL0KaOp+bcfobKc0ovRq/Fa2FG/m0gR9xQipde/GHUZyD1cq/OIedMw==', 'base64'));");

	// Windows Message Pump, refer to modules/win-message-pump.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'));");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzVV21v2zYQ/m7A/+HmD5XcqkqXFQPmIBi8xG2NJHYXpQ2COAho6SyzkUmXovyywP99R73Y8lvbtWix8oNFkce755473dEHT6uVEzmeKx4ONRy++PUPaAuNEZxINZaKaS5FtVKtnHMfRYwBJCJABXqI0Bwznx75jgPvUcUkDYfuC7CNQC3fqtWPqpW5TGDE5iCkhiRG0sBjGPAIAWc+jjVwAb4cjSPOhI8w5XqYWsl1uNXKTa5B9jUjYUbiY3oblMWAaYMWaAy1HjcODqbTqctSpK5U4UGUycUH5+2TVsdrPSe05sQ7EWEcg8KPCVfkZn8ObExgfNYniBGbglTAQoW0p6UBO1VccxE6EMuBnjKF1UrAY614P9FrPBXQyN+yADHFBNSaHrS9GvzV9NqeU61ct6/edN9dwXXz8rLZuWq3POhewkm3c9q+anc79PYKmp0bOGt3Th1AYoms4GysDHqCyA2DGBBdHuKa+YHM4MRj9PmA++SUCBMWIoRygkqQLzBGNeKxiWJM4IJqJeIjrtMkiLc9IiNPDwx5g0T4RgZC1Gc4j+16tfKYRWHCFJGq4RgeF0fZkj/kUUALOde2lS7cj5X0yQmr7uIM/VeUGXa+5KKY3FpTLgKurDt4BrVez5vHGke/HfZ6fT/AgGtzqubArZW/Ww5YByiSkZk8+olSKPTCuquXUbixDmSi6aEIkGUdrS9LYVsB04xULF20/To8ptmbnnp2DL6rpUdhFaFdP4LFlgFUarcmo2hDfMq4bs24ts3yisGIC4wJ4SZol8yO7LobU9C1bfVUT1iFwvSMGw/5wGjbeC2Um6SwjQVuUjqVqWc7efwKBFo+UMgJQipzy+8Km7A0WIg+4JzksgMlg2WRCYsSXAl9kFykmnJ/StKUO7ek8I6E00P51iJ70G6iiEl6mkOLrVS06ewqGQvxNHrLXE31bx6Pl8edzPB6Sv/AHCYk6ynswArVz5TOZXoDjFDjVoB+MLUZipTIHRT/ZNyW2EVhupbHBnghA/RQTahg23H27LARlj+JnGXi77nC0DSoOZF8Td0tjc8+gTdnrRv3XPosuqDmSkWBCPRuvKvWRa93kvF4IoVWMvJQ01I2p8gQqr6UtNRBPZXqodezKGYlcA6IJIqMumzN2kweHn+Ra1nrCcuptO7D0Uouq1mPlJcDlkS6AZaQAi0oehbJ024mRQrcvxNU84ye8DtSYZIEfKb9IdgfHzDNgvVSRpDcHDQcH+/njG4eX5wT5OxWD9iXBqfLD/nHJ0p9vRmkPNmz9f612Pw26KKkmdI2ffvs+1aeeJhQbZiKZekpFtLao9JfU4dSJL8cm6T/M52XikTDevG/urKkmny6DcoI3UiGdllT/eizJYoPYJUo969RoOL+BVPxkEVE8Fu6CGhUHv8HTTa/hCdPVtGQJgRMUYzraarPfn9prQI4kkFCmOgqLJWmi8pWBu8sio3dy87q2O4Pp7Fn3Snyq1FMnO1y1dheypM1owmjGD/j14ZvZuT3mUYxcfI7TCN/Oqum21hNna/l5Wu4CXNAYQ7oW7gq+Mreuv0P6GtTCanAvFWS/sjoub3OnQM1U0+MpprzKRob5ca7vrshvFYtPyNnRnr33d+Qym3lexXT7tg4ZopPNnuf3n7KV+7yiOl/uGk+k/ru/T1+muEz+tN52NgvYEbRxiyv+ap1f9E9bd13WlfX3cuzvZCK0VfIHj4hU7Ty/wrgmwwvdi8XVia7dO84k7f82Q7W9zC+9KPTvbxonu90YsNQ6TWt24t/ATXtbrU=', 'base64'));");

	// win-dispatcher a helper to run JavaScript as a particular user. Refer to modules/win-dispatcher.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('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', 'base64'));");

	// win-firewall is a helper to Modify Windows Firewall Filters. Refer to modules/win-firewall.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'));"); 
#endif

#ifdef _FREEBSD
	// Helper to locate installed libraries. Currently only supports FreeBSD
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJytVVFv2zYQfrYA/YebUIBSq8px3pbAA7w0xYwGDhCnCwrbGGiJtonIpEZSdoIk/30fJc1w0m4vmx9M83j33Xd3H+n++zC40NWjkeuNo9OTwc80Vk6UdKFNpQ13UqswCIMrmQtlRUG1KoQhtxE0qniOpTtJ6XdhLLzpNDuh2DtE3VGUnIfBo65pyx9JaUe1FUCQllayFCQeclE5kopyva1KyVUuaC/dpsnSYWRh8K1D0EvH4czhXmG3OnYj7jxbwmfjXHXW7+/3+4w3TDNt1v2y9bP9q/HF5WR6+RFsfcRXVQpryYg/a2lQ5vKReAUyOV+CYsn3pA3xtRE4c9qT3RvppFqnZPXK7bkRYVBI64xc1u5Vn/6mhnqPHdAprigaTWk8jejX0XQ8TcPgbnz72/XXW7ob3dyMJrfjyyld39DF9eTT+HZ8PcHuM40m3+jLePIpJYEuIYt4qIxnD4rSd1AUaNdUiFfpV7qlYyuRy5XMUZRa13wtaK13wijUQpUwW2n9FC3IFWFQyq10jQjs9xUhyfu+b96qVrn3wTxVESu+FUkYPIVBz2KM+SaujM7BL6tK7kBji9OeP+7lHMTYCl1d2oKdeVNvxw3G4GhIs8X5wZJvZFnA1g0oZo3hjw6ZJZl4EPlnyClm/aVUfbthKc0YlkXSojQBmXWFrh0WAzDGfnCkVcwK7jjiD3XFeUJPjWSbyA9DyjOnp5ilWsfJOb28zSFV5vUh4qi6X0MtK00RfSDfGiwRPRNg2HyumP9+ZjDw/T0xZOFDixG6+N1JSi6leTTdcK/IK7m0hHp3shDF2RyXiuQq5sPhqefWxrjZ6SKlUi59XOtTgaPzptlgAaL0wg7Jn1lHoUv+5AG75IMUrbYeJrMaQL8MfJYW7N2gBZor8SDdXEWvqt9z6S5hj5Pzo3latPvtBDL0bxsnWZsScKwLgUZiHyb9PUNs0lgbxfR64PgTbDO5AAY3zt7hEsRdZxnYssRTzbXC9awFqLZxHnAHFk/e9YxaiJc2Ye+/y+vf9PX/CewHCmMHhX0sIaCDyPxY8V5VjW2XHVn9sOfsSGkYttP3KUX9TlXYzfhiOIxex0bfaWB+EAF7zfCtCnq7rNR585L8sxI6V9z+rKrtJt51lnaCMNdGxVha89IIfu9/4fjFP0NbXdSlwKjwx+W84PxzBIe/ALtaHGg=', 'base64'));"); 
#endif

	// monitor-info: Refer to modules/monitor-info.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'));");

	// service-host. Refer to modules/service-host.js
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'));");


	// power-monitor, refer to modules/power-monitor.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'));");

	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'));"); 
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(27821, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 27820, "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", 16000);
	memcpy_s(_servicemanager + 16000, 11820, "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", 11820);
	ILibDuktape_AddCompressedModule(ctx, "service-manager", _servicemanager);
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'));");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('eJy9Vd9v0zAQfo+U/+HYA0lGSWE80WoPXTcgGmrRMkB7Qm5ySay5drCd/tDU/51z06G1K6MIhF8qn8/3ffd957R77HtDVS81LysLJ69ev4VEWhQwVLpWmlmupO/53keeoTSYQyNz1GArhEHNMvrZnHTgC2pD2XASv4LQJRxtjo6ivu8tVQNTtgSpLDQGqQI3UHCBgIsMawtcQqamteBMZghzbqs1yqZG7Hs3mwpqYhklM0qvaVc8TANmHVugVVlb97rd+XweszXTWOmyK9o80/2YDC9G6cVLYutufJYCjQGN3xuuqc3JElhNZDI2IYqCzUFpYKVGOrPKkZ1rbrksO2BUYedMo+/l3FjNJ43d0umeGvX7MIGUYhKOBikk6RGcDdIk7fje1+T6w/jzNXwdXF0NRtfJRQrjKxiOR+fJdTIe0e4dDEY3cJmMzjuApBKh4KLWjj1R5E5BzEmuFHELvlAtHVNjxgueUVOybFiJUKoZakm9QI16yo1z0RC53PcEn3K7HgLzuCMCOe468YpGZi4Hvk3RVCOVY5KHke/dtU7MmCZhLZxCEPTbkCF/swrCWquMmMe1YJYITqP2eHPRrYwR90Bw2SyC3m44Z3rO5cO4W1YvtwN329t7TvmEKG0cD4PUSYfnzLLUKo1BFA81Mos/OeICs0+MxvIFBHE+CTpwR7dZPpZi2SPQBmEV9R9Dta3/xLHCUG2hWD5EbZ0TDuQO6mLRI0rxe7RnTVGgJkooCqemSwyiDtTMmLrS1HoPgornOcqAMOMS7SUuPzBThVFsVUozJsswqHAR7BJabW8JO6tCjJ7Ua+fOhJq+7e9aQT68Odl1otuFd1wbC8MKs1vg7Vsl3YdKukds1vv1wJz/Vw9jjTRyGV1xIbJy7Wh0qKUOeUbAT9m15xr1H86ix/E9ve3V4Df5bv3JsM3+yUTdr9X+8P4JO6ATp69shDgcbk9orTictpXg+fP1bse2dvyCKIJnbd7hDrVqzw5QaPX7Zwh/+Q5zLFgjbO/XWZsCxLrREkL6dVRX7hM+VXkjkB4D/elbQ009+JT3XcIP9UUm2g==', 'base64'));");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJyNVUtv2zgQvgfwf+CNFOoyRpOTvdmim+aQxa7TR3qqF4ZCjWx6ZVIlqSZG4P++Q+phSs7G1cUwOY9vvvk4Mzr7mRpSGr2VFsgVMfCjkgYYbY5oMhsFE6UzkFlssUxXoNwcz28zmrDWUJbiU+rWaIkhBFjLyyJ1uTZbcnVF6KNUF+8oeU8YXeDHF4tSlrBYUPKmzfGG0LcfP9x+uqYJmRLWhhGPGUv85XlziQlHZ3mlhJNakR8VmN0HD4nph00yOnsenRH8PCYDDvEoeGwrZZ0bM2DHaLBJyDNxa2n5Ek9CnXbWHWzCwWZG9j6rD4sh+RIT4cUzEdtsSmhAQMeYsahgSvzlPrIWhURwMYMKHE24MJA6uNZKQYDEnkmJBE47Jns56yg87pg7vsYoVNQREdCh2KS2bKjxX6jQm2epS3u2Yl2pf5ODZeTU8lqAmvVPZd44crxbIfjfyGXHbKXsWuauiTzzgCujkNTjGAzdsbg6FBKUfbtV7uLdXzdskiTkdxLnOBV/73UyhO7L7RLYQgpgl2NfECrsMpkdO5TprtCpfwGqKoqBgTO7/sGALP8dAvz59W7Oy9SgDj0M7vRXZ6RasWSYeMCMSJ1YEwbJyWSBj0YkQcCM3ioUJj6vL2BLrVA7X0CA/AkZHWb1X8Pdq3B+perz8yEUyxomsK+2Ktz7/t8pfRHPqSi/whx7ep24/9OhVwQK+bTmWiGhB5phN+OQ+xhi9+xAZS+90BfQvdBSUWg76N++HovtX69cP6P+qPIcDM/RnQX52aA4me9YP66fnXE8H+Chyg8h0qLQIpS4abmIzNGUPxrpoHuvrZVncUwmsfGGC13uGPqM+28uQAph/GV7E89B1KYf3aHt+94esC41jh3mP45BqwvghV4x+tmPaKyb/A12TcK28A4OOOcdjatCP6QFX/qLyjrcW8SCu5db0JVjrw3TXq5vKn0ogDjtj10qXJQ0Tue/dsct4Uk61hU8JheTyeTQ0WjHteMdkeAOcWtQ/Z12DM7LOay2eoJ5Bdebjn6f392T67v5/Ob6/ubjP7Qn215NEW1NfsiwQlx+2F6fNaqp7VIMOgMrjCydNpYmh77W+KNMRxV5tEOSvGP9rk/atSrZ6qzCDPBUauNs2N1BL9P6B/f1f80shHM=', 'base64'));");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'));");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'));");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	duk_peval_string_noresult(ctx, "addCompressedModule('notifybar-desktop', Buffer.from('eJztG2tz2zbyu2f8HxB/qKhGpmU7zeXkujeyrSSas2VP5MTuuB4NTUIWG4rggVAkNdF/v10ApPiW5KSvmXLayCSxD+wLwO5y7/vtrVMWzLn7OBLkoLn/b9L1BfXIKeMB45Zwmb+9tb117trUD6lDJr5DOREjStqBZcOPftMgHygPYTQ5MJvEwAE7+tVO/Wh7a84mZGzNic8EmYQUMLghGboeJXRm00AQ1yc2Gweea/k2JVNXjCQVjcPc3vpZY2APwoLBFgwP4G6YHEYsgdwSuEZCBK29vel0alqSU5Pxxz1PjQv3zrunnV6/swvcIsR736NhSDj938TlMM2HObECYMa2HoBFz5oSxon1yCm8EwyZnXJXuP5jg4RsKKYWp9tbjhsK7j5MREpOEWsw3+QAkJTlk512n3T7O+Sk3e/2G9tbN93rt5fvr8lN+927du+62+mTy3fk9LJ31r3uXvbg7jVp934m/+32zhqEgpSACp0FHLkHFl2UIHVAXH1KU+SHTLETBtR2h64Nk/IfJ9YjJY/sE+U+zIUElI/dELUYAnPO9pbnjl0hjSDMzwiIfL+HwvtkcRII0P5vlBxHMjRqgzfUp9y1LywejiyvVjevmAvGxfsw8EiBnQK3vrgA7pGTY3J4eIQYt7eGE99GumAJvsOm4QAMxx3OHyw+AF3aHw3hCg+sToSuU9/e+qyU7g6NmDxYGd8FVcvpAPFHKq44s+HB5RT46lljagTqgRkAEhNRkeNj0qwrZBonXpyKCfeJkWcmnIeCjlPcoLkj0EL9UC+kGyD0mG15Cl8S06JSJAVcxDJBMQM5EO7nxVHkHfgwtLkb4POTyXBIuTnkbGzsxPKLse86NPwoWFCrG7Ud8pxIKvC7A0JlvlGzPRbSWoNE/Bn1z5FcB3TmCqN+tKgf7YCAWR/M3380ag9WSF++qNVjfmKq9BPYA6qrg390wPzAYEwQiQeaFTA3PqH1pRxNm1NLUDk44iT52nKcCypGzMmzSeQDo04+y2Bk2iPXc8yPLlCqH5FFkjehXiaNWz4Y6HkCu3RG7dcQzmKTwgdXlhg1yF32kRmCkwK7v/wCgAELjHqD1HYfXr7AAcChUsx9AzmbB7RF9htk4jotqVjFWYovExQkQRiHyVqOJSxgtUCBOcAA4pYv5LxE7mUoHDYRUsWIMik6w0axFXACMJTzzWBwMNpJejBzaKwaxaZJx65Y6lGOyCpKOhX84sPFijiS9LSUt+hwdDUZB0cpH4opJUYkjQJo7I7Vq90A3tUSk0X/I4PLh1+pLbpnrQL1mDeKRZibZKpFtD8PEFfYInf3+Dd4qRvCy5jqmPkuqH7X9YdMxbku/AWGvUiZcARpxoQzev/TPHA5OhEh8cI1y0DZu8Bq8wh+flQGoSRietR/FKMj8vy5W09DZhDhlQC8c+9NTsew7rU97xwWZVyoQm2Fkc4qYDXfmYGL9G0CBri/u0+MzgSXWDOwuPrG0gfG+YUIhcGGwzBWW/QQ1HnjOhhuwBz0X2pgA9+9pbjBky/VnzEDGTnDzmZcrpC9PRsWU+ZR02MQxi+U5YExw3Lgwv81mKkkfodPjLEUtNxa7hJ549GhqOPA+5ycI74BRRlgHkJNJgZ5YEKwcQQDPpUFicQEEBcYiYceY9yISX9PmuZhswAoppOG0o8RrHn4QxZOyb+C1A/NOvCaeBuzp99mEIbC4ogvlghIMmcNsZkEat92nDfnAu/AS4XIVvHLEhgNF4o5bKBbycCow1lfvjFv+oMP3X735LxDvlSOOrl8d9Z5t2LQafsKt8MrRvV/7l90eu8b5ZzPWkqmDTJvxTbTICja1lLKDSJNUT/hypOmqKdWwu9GVA1KeFsUxjESxFHXlE+LeVrkHy8yqi0IMkvUOi4Gk3Bk+HSalI6h7aGeNaoSFJR+NOqptSI9cBMsuMKPpr6TWuFH64bst+3eGZjNMRllA+5GUyncZuSYSNHPc1S6IuWolq9NJZMtncDGq1UlpuK1S4qzRAFLLMkNWOkymSWaXfwkqY01p7dVSeVhJJUbJm3lxjh8XG1T7pDgQHMcnTmPyf7h4foqSi+BOzcXg97pVbvbu95ZU6YFDPwL1gHETG4oga0ukadkzIrgoRwo3MBp//Lm6rJ/Cr7wptt7gzmIs26/jeEUDAOH4cFcBfC1p4KcJF2sQAgV0HihJww96zGU3lA+Lpy6wh4RQ2cJSgitIIaXDQdH8qJkiUpeEVcoaQ/OD9Z4wK2peUY5HRoHLxrkBZ5H1ckXTAz2sM77ri8OD847sHP+QpqzZrN5cIRK6cMa3r+5GvQuLy4/dFaTjhScI/uqiOqSaLS31YHaVNpU6/yXL6vp4vUkws+LCcsVrk5+Oi5+LdfBCk1G1wqNRhcI+swN4ZTBpio5iAEP9q7UtjBf6Aqwbs8jj4zAoRTTfg9s4jthlAC0J1weZfVhaD2aaxoHpvpobB3SssrCbvIq8P3stcwNVV3rS7CtxUcj6aGofG+O2UZ8ertrzdzwK4Szf1AonEg2hYYy/0bCegCr/bgClYwPr742PhzmZlkSH8g3jQ/7L78mQBTsVoqup5H+J0RU28c/IWIZP5t/3RBRgqLo2FWxYdXvVmQeE7nHWXH1Ip11/APS8etm45GdsesnU5vZagq8fu868TkCISZYPiG7+4lHIfWGVVj68N5Y0hV8nst4KaylGPRmPMmLVo9twZbTmM3SSbRFRAujsGTvGWxdMXxOVlZ/EmqMCzToUj2GcSlAergT9ykK24rmUlUGWm75OWMCa4lkSkk4YhPPQWngPh8QT2W5U5Yg4GjApJ+iIGoh0cawRInzwqn8KDX43XdyXs+W88pwoLk4pyIkI8Y+EjjVAJxMAkf82JYPMlB8IGmYf0g8C84o+axTlOkG4i3JQTZ/8dQ8c3StyDfHwzbKO5cIJsdz1vrUsTw6k2NVyPIfKeY5VJjT95WH9IHk5qD4SJ59KNPFGivIOZ5R9Cw7qYIJoZbEyEI1RVAmOkIB+aVXb+J/ySuyRrlDsASGjd9V7KskjjOaYaEkOad8AeVWVlCA8XLNWb9TUXBvZU1QlgLhnwah/qeWmg6gCRgXHf8T1n1Wc71pybACU1xDxGerh69fVaxGsmaZsQLJN6g7llLQTp12Ue3nG2dZNGS6Ql2yk1mDqdhul7JIVYNiXJktUEUoMuOFPmsBpT4styqx3yaRFce8deVZlkauyl0WTC25nUsIZHnzNZEEo+IzCVy+KIsRZ1Ojdtun/BPlpAuIXctzf5PdOKTDOePJdW+R5izR8JHTxBMW3jUW3W/SahGp+28RWZ/cf5EGLujBSA/YLGI+pRcjDffN+jFKXGmRbc3I76vjg9F6jRO3+ZYJ3e6xcdNEI0oPaNAp4x9h52tjcfPz4u/dUlHWdqDIneCuPhFfi9oP1m4U+KeY/3XF/PzBajpyBa1Yawa3+/vm7Q2OunJn1FMydOBc6lnzhqICUYpSv+vUzQ+Wt6ICpx1I1ZILFlU8sJb7k+LmHYxRNbpKbgoK9HqkLrnHcBifl7BO1ynI0qw5rXx9u3oup9JJ+thgSwvntIKSPuCrboNmI9E4sC/vpX71T34HVMVZH55Q2c66EUPxm0ZVy66a9geLu9gJbRS1MuQ6CqrZnYjhqz4VNxdXnAWUC5eGfxbjUvCp//IGVDYZ8FPdb+L+Rt+6EN+fPIsSoyi7WVfcI9fRltqFU/pTrHXdKWwkNZmApk5brjLfQPUZCheX193Xg9fn7Td98+LmYvD6fe90cHp+2e+sKzfJ49Sah5f+NWwXf3e5FcT68cChHhVUQw4sXAhXRSj8cIP7bRia4Xl9L6mBwM46553rju45qKGPFC0XyCZyFVZ3/Gfwv8jqQKIoL6QUCmLD6KhDjWA2855ubpJR7XybkL+wgqesFikTWZ/aaw9X6ySljVfEs/gsI/efSfVmXuGGFraiy6fGihWU+T6VXt+bjB9A2yk+0cbwDIZ1R/DAltwUr24Uqube1I5TaEdfh1mdTDbqiVuBcaBFEe0J9e3XIcXDnBZp6jw3dNbLFN92NnLw/eZBzsfxgm2NR8kKA7mivoMFKZUWTxrGE3LGhRR6dCakXPpz307TacBUy7JqmK+57ej6Zq68mekNOD5Of9X0tK4qW6K4nge4549pr/dtFbLwivyH/PCStMhBYfPPkt+KailOO8mHNncZg8uhVpSiq6KJyusnAsqwNAGfQ1cccvA0fKYUnDGrlXjFynbH7PjYF22PWrxStHj9scXqOCfxp31vEIFnIliUb8Gwl8mRjnUXLfmpqnwpd0xFHYhxObkEEC8JOL5rxuEWU0GnqlPkJsr9FKoyM41louhuGt7j0gDrVxnYMuNi5LYzi0wjj6pjT+msOmAvsut8alI6w3ayupE7BYarRzyx0zhbvzSZ6ToNt8Yz5XoxDylh3W/YHl2GplzkRaAFyS8jOyayzDUae4tcjkQN5Mlv3so/UBtbNgsHuiv4gc2KekQyaf2/wFeTEcMnbBa3lqc/8kuMSB1h9HdyMFMsI0uGjFqUyJWn4bsahG5b7Rpr9yU4TV3LTn/BmB6QinIx67L8lY7xZJE07uqRVUpV/c7Lz4s9SwwZHy+VKfsU8XvBw4NaoltxzJyJR3XJASNTydfPR2UgpvoSuBBSvUqAJhcgxZDn+pNZxJB6NOSUPoROJZe5/qZKIo7FgblKhFlfKMCne6z+D/KnKBc=', 'base64'));");

	// proxy-helper, refer to modules/proxy-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'));");

#ifdef _POSIX
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVFFP2zAQfo+U/3CqkJLQLim8jS4PXQERDbWIliFE0eQm19YitTPbIakY/33ntAU6eJzz4Pju8913d18SHbrOQBZrxRdLA8fdo6+QCIM5DKQqpGKGS+E6rnPJUxQaMyhFhgrMEqFfsJS2racDP1FpQsNx2AXfAlpbVyvouc5alrBiaxDSQKmRInANc54jYJ1iYYALSOWqyDkTKULFzbLJso0Rus7dNoKcGUZgRvCCTvP3MGDGsgVaS2OKkyiqqipkDdNQqkWUb3A6ukwGZ8Px2Rdia2/ciBy1BoW/S66ozNkaWEFkUjYjijmrQCpgC4XkM9KSrRQ3XCw6oOXcVEyh62RcG8Vnpdnr044a1fseQJ1iAlr9MSTjFnzvj5Nxx3Vuk8nF6GYCt/3r6/5wkpyNYXQNg9HwNJkkoyGdzqE/vIMfyfC0A0hdoixYF8qyJ4rcdhAzatcYcS/9XG7o6AJTPucpFSUWJVsgLOQTKkG1QIFqxbWdoiZymevkfMVNIwL9sSJKchjZ5s1LkVoMUJfTxytmln7gOs+bOfA5+IWSKREMi5wZ4rGCOAYv56KsvWCD2oLtemKKAvE8g3g3D99rDL+2cbwgxBrTc1KP70UzLiK99Dpw79H2YMW2C9XcCrUh4oo2RRE9r7dvlsL3MmYYBXitw08DeG4k2txqx5CGRo5pdmLhBz14+TSJLM1nSaz5/yXhIrTKo8IxXUo4uOpPLuAPsOoRpt4zrFHH3R6wWJMOjH/Q7cCsA60T+gatAvw6PurV32LWa7drm57P/dl9/RDHrUhTI1vWZmMcUX56CiJjrIGOU28qsOZmKryPzCrGzRk5fet6czbDZ0oj/VT8fxsVUqkrPwisGrrB26V3WrBrJx6NBsWT79mKqY87M9nuN7YHaIN30tSxx/Bl80rbi+W2klmZIymI/m9G07ReVdtQd52/UQCQ8A==', 'base64'));"); 
#endif

	// wget: Refer to modules/wget.js for a human readable version. 
	duk_peval_string_noresult(ctx, "addModule('wget', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQoNCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOw0KdmFyIGh0dHAgPSByZXF1aXJlKCdodHRwJyk7DQp2YXIgd3JpdGFibGUgPSByZXF1aXJlKCdzdHJlYW0nKS5Xcml0YWJsZTsNCg0KDQpmdW5jdGlvbiB3Z2V0KHJlbW90ZVVyaSwgbG9jYWxGaWxlUGF0aCwgd2dldG9wdGlvbnMpDQp7DQogICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7DQogICAgdmFyIGFnZW50Q29ubmVjdGVkID0gZmFsc2U7DQogICAgcmVxdWlyZSgnZXZlbnRzJykuRXZlbnRFbWl0dGVyLmNhbGwocmV0LCB0cnVlKQ0KICAgICAgICAuY3JlYXRlRXZlbnQoJ2J5dGVzJykNCiAgICAgICAgLmNyZWF0ZUV2ZW50KCdhYm9ydCcpDQogICAgICAgIC5hZGRNZXRob2QoJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLl9yZXF1ZXN0LmFib3J0KCk7IH0pOw0KDQogICAgdHJ5DQogICAgew0KICAgICAgICBhZ2VudENvbm5lY3RlZCA9IHJlcXVpcmUoJ01lc2hBZ2VudCcpLmlzQ29udHJvbENoYW5uZWxDb25uZWN0ZWQ7DQogICAgfQ0KICAgIGNhdGNoIChlKQ0KICAgIHsNCiAgICB9DQoNCiAgICAvLyBXZSBvbmx5IG5lZWQgdG8gY2hlY2sgcHJveHkgc2V0dGluZ3MgaWYgdGhlIGFnZW50IGlzIG5vdCBjb25uZWN0ZWQsIGJlY2F1c2Ugd2hlbiB0aGUgYWdlbnQNCiAgICAvLyBjb25uZWN0cywgaXQgYXV0b21hdGljYWxseSBjb25maWd1cmVzIHRoZSBwcm94eSBmb3IgSmF2YVNjcmlwdC4NCiAgICBpZiAoIWFnZW50Q29ubmVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHJlZyA9IHJlcXVpcmUoJ3dpbi1yZWdpc3RyeScpOw0KICAgICAgICAgICAgaWYgKHJlZy5RdWVyeUtleShyZWcuSEtFWS5DdXJyZW50VXNlciwgJ1NvZnR3YXJlXFxNaWNyb3NvZnRcXFdpbmRvd3NcXEN1cnJlbnRWZXJzaW9uXFxJbnRlcm5ldCBTZXR0aW5ncycsICdQcm94eUVuYWJsZScpID09IDEpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHByb3h5VXJpID0gcmVnLlF1ZXJ5S2V5KHJlZy5IS0VZLkN1cnJlbnRVc2VyLCAnU29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXEludGVybmV0IFNldHRpbmdzJywgJ1Byb3h5U2VydmVyJyk7DQogICAgICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSByZXF1aXJlKCdodHRwJykucGFyc2VVcmkoJ2h0dHA6Ly8nICsgcHJveHlVcmkpOw0KDQogICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ3Byb3h5ID0+ICcgKyBwcm94eVVyaSk7DQogICAgICAgICAgICAgICAgcmVxdWlyZSgnZ2xvYmFsLXR1bm5lbCcpLmluaXRpYWxpemUob3B0aW9ucyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQoNCiAgICB2YXIgcmVxT3B0aW9ucyA9IHJlcXVpcmUoJ2h0dHAnKS5wYXJzZVVyaShyZW1vdGVVcmkpOw0KICAgIGlmICh3Z2V0b3B0aW9ucykNCiAgICB7DQogICAgICAgIGZvciAodmFyIGlucHV0T3B0aW9uIGluIHdnZXRvcHRpb25zKSB7DQogICAgICAgICAgICByZXFPcHRpb25zW2lucHV0T3B0aW9uXSA9IHdnZXRvcHRpb25zW2lucHV0T3B0aW9uXTsNCiAgICAgICAgfQ0KICAgIH0NCiAgICByZXQuX3RvdGFsQnl0ZXMgPSAwOw0KICAgIHJldC5fcmVxdWVzdCA9IGh0dHAuZ2V0KHJlcU9wdGlvbnMpOw0KICAgIHJldC5fbG9jYWxGaWxlUGF0aCA9IGxvY2FsRmlsZVBhdGg7DQogICAgcmV0Ll9yZXF1ZXN0LnByb21pc2UgPSByZXQ7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdlcnJvcicsIGZ1bmN0aW9uIChlKSB7IHRoaXMucHJvbWlzZS5fcmVqKGUpOyB9KTsNCiAgICByZXQuX3JlcXVlc3Qub24oJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLnByb21pc2UuZW1pdCgnYWJvcnQnKTsgfSk7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdyZXNwb25zZScsIGZ1bmN0aW9uIChpbXNnKQ0KICAgIHsNCiAgICAgICAgaWYoaW1zZy5zdGF0dXNDb2RlICE9IDIwMCkNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWooJ1NlcnZlciByZXNwb25zZWQgd2l0aCBTdGF0dXMgQ29kZTogJyArIGltc2cuc3RhdHVzQ29kZSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICB0cnkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9maWxlID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSh0aGlzLnByb21pc2UuX2xvY2FsRmlsZVBhdGgsIHsgZmxhZ3M6ICd3YicgfSk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhID0gcmVxdWlyZSgnU0hBMzg0U3RyZWFtJykuY3JlYXRlKCk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhLnByb21pc2UgPSB0aGlzLnByb21pc2U7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaChlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKGUpOw0KICAgICAgICAgICAgICAgIHJldHVybjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIHRoaXMuX3NoYS5vbignaGFzaCcsIGZ1bmN0aW9uIChoKSB7IHRoaXMucHJvbWlzZS5fcmVzKGgudG9TdHJpbmcoJ2hleCcpKTsgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvciA9IG5ldyB3cml0YWJsZSgNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHdyaXRlOiBmdW5jdGlvbihjaHVuaywgY2FsbGJhY2spDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fdG90YWxCeXRlcyArPSBjaHVuay5sZW5ndGg7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuZW1pdCgnYnl0ZXMnLCB0aGlzLnByb21pc2UuX3RvdGFsQnl0ZXMpOw0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICh0cnVlKTsNCiAgICAgICAgICAgICAgICAgICAgfSwNCiAgICAgICAgICAgICAgICAgICAgZmluYWw6IGZ1bmN0aW9uKGNhbGxiYWNrKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjaygpOw0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvci5wcm9taXNlID0gdGhpcy5wcm9taXNlOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2ZpbGUpOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2FjY3VtdWxhdG9yKTsNCiAgICAgICAgICAgIGltc2cucGlwZSh0aGlzLl9zaGEpOw0KICAgICAgICB9DQogICAgfSk7DQogICAgcmV0LnByb2dyZXNzID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gKHRoaXMuX3RvdGFsQnl0ZXMpOyB9Ow0KICAgIHJldHVybiAocmV0KTsNCn0NCg0KbW9kdWxlLmV4cG9ydHMgPSB3Z2V0Ow0KDQoNCv==', 'base64').toString());");
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");

	// default_route: Refer to modules/default_route.js 
	duk_peval_string_noresult(ctx, "addCompressedModule('default_route', Buffer.from('eJztVttu4zYQfTfgf5gawUpKHDl2sgs0rltkc6vQxFnESRaLpghoaWQTK5NakoqcJvn3DmV5fY3bvvWhfLBM8nDmzBlyyMZ2tXIs0yfFB0MDrb3mjxAIgwkcS5VKxQyXolqpVi54iEJjBJmIUIEZIhylLKRPOVOHO1Sa0NDy98C1gFo5VfPa1cqTzGDEnkBIA5lGssA1xDxBwHGIqQEuIJSjNOFMhAg5N8PCS2nDr1a+lBZk3zACM4Kn1IvnYcCMZQvUhsakh41Gnuc+K5j6Ug0ayQSnGxfB8Wm3d7pLbO2KW5Gg1qDwW8YVhdl/ApYSmZD1iWLCcpAK2EAhzRlpyeaKGy4GddAyNjlTWK1EXBvF+5lZ0GlKjeKdB5BSTEDtqAdBrwYfj3pBr16tfA5ufr26vYHPR9fXR92b4LQHV9dwfNU9CW6Cqy71zuCo+wV+C7ondUBSibzgOFWWPVHkVkGMSK4e4oL7WE7o6BRDHvOQghKDjA0QBvIRlaBYIEU14tpmURO5qFpJ+IibYhPo1YjIyXbDihdnIrQYypqIZK4fIoxZlphrSZG6XrXyPEnJI1OksIEOiCxJ2rPB80saK7V3nYdzFKh4eMmUHrLE8Upk8IlQ55f+sUJmsEu0HvGTkuMn1wnSYZKylPtRMo8voZdohjJynXM0QXomFWUrurGJLaAzGpr/ifMu7pjiFuYeeO35CDTFRjiyv2LR3asXZurQnK7hsTtZ4t+xBDodaLZa3mSq1GVq2RSbbR0Ba9I38mMWx6hcz6fZ6JYO6n7r4tT1pp5s28yu8LDCcC3LPW82OcdzyhUF7WTU5Kiw6Z+gwthGf+C9TbS9akfJfGl0sUfb1rU43tlr859Kr+2dHe4t4pYoFlLIfIneAeyAy2Eb3n/w6vanvbqKx+DSyn8W0LJQG9jY1mjAyeRoQHE21qMsgx/sOXl5scfFHyEFHcLPMKO1/2EzrzWUNtAqxCrO5TNVNoMqZiEezrlr/o27Okw4Hv4LivC6RnzbXleHl4bmuuXf8kNBZEpQ/tDY1L4uFKeEi2y8qTSFQ55E84WoGHhIlQypujqej2MMz+jKcp1Gn4uGHjp1+N2hzx/TjVSs8LWhSql8KVwnYoYR6jsJN/RI5NcVPNGhjyLvjtNeHH7bjL1Di1U7HQhJ6R7lQAzomK1xwIVvbyzizlPKEkUPL0D3WQqlItRl+Ve4d55tLYCtZqdTK6dq8O4dbB0UA481sK5T8mRg6z25gtd7517gmJt74Sz6zRk3pzTx/eRPE7Qct0/MR5Pj5DjwS3E/wOHidnxjzWzvNSdhL2a9r6P/c+4INJrucdgl8XdjUtVWl7fSX+a2e/afzKymp2E4dMsM+WnCDN0Ro1laQ0avHYeeIvst53BWKUYyyugioLeSVMbeW+seK3MlqU/l6mt73mRRQDaaXC0xGw3G9Jyk/Tk1ORmMmCJmG90s7+k1Tgqp/gL2YXjV', 'base64'));");

	// agent-instaler: Refer to modules/agent-installer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('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', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'));");

	// zip-reader, refer to modules/zip-reader.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('eJzVG2tT40byO1X8h9m9qljOGmEMIQk+kiMYLlRY2MLsbaU2W1uyNMICWdJJowChuN9+3TN6jEajh5fkQ7y12NbMdPf0u3vG219vbhyH0WPs3SwZmYwnY3IWMOqT4zCOwthiXhhsbmxunHs2DRLqkDRwaEzYkpKjyLLhLRsZkf/QOIHZZGKOiYETXmdDr4fTzY3HMCUr65EEISNpQgGClxDX8ymhDzaNGPECYoeryPeswKbk3mNLjiWDYW5u/JpBCBfMgskWTI/gmytPIxZDagm8loxFB9vb9/f3psUpNcP4ZtsX85Lt87Pjk4v5yRZQiyveBz5NEhLT/6ZeDNtcPBIrAmJsawEk+tY9CWNi3cQUxliIxN7HHvOCmxFJQpfdWzHd3HC8hMXeImUVPuWkwX7lCcApKyCvj+bkbP6a/HQ0P5uPNjc+nF3/fPn+mnw4uro6urg+O5mTyytyfHkxO7s+u7yAb6fk6OJX8svZxWxEKHAJsNCHKEbqgUQPOUgdYNec0gp6NxTkJBG1PdezYVPBTWrdUHIT/k7jAPZCIhqvvASlmABxzuaG7608xpUgqe8IkHy9vbnxuxWTk8vj2RU5JDtj/Df5Zn8qnounu7v7u99P9r7LHp6f4sP9b3cne99+M5ki+/FxFIeAnMJQJgVjkD0aDLOVThr59EGeAfyk1mowNGd8iANz08BGkgkI3b47DX2g+53FloZDEzbc3HgSCuK5xAAENnDOjHyLAYNW5PCQDO69YHcyGIpZ2WR84XLAjW9mAmxmxmAbMN+GXmAMfvuNU4nznsUb9RPaBwauzIBsqzBw0yy8A25XF7XQTX4kCJIcEAlcCW1hcRYLoGay9Fxm5LPul2CPRjbk0+AGbPAHslPnBAfy5pAY/QkhbxScOVIhCuNVIVI3AX7QBzCVZP4Y2AYiGw7LyRId+KquW905Xlwuk3A8F4x9llSEPrDYstkFvBuRohtmRAMHzCJnBWxtPCRPJDKTMI1tatp+mFDgHjz5DAaIn2LK0jiYyvILADZwvAQXhVHBcq7VQiciE0kW6grcWou1iGP691FrG/xJ6FPTC9xwxxicCCEAb2BDsBtup9kKFj/WsGntWsFgMXtp0Ppua8KTh0CKt0ZFazJ5FrDFB5gpHA8XWwbwhrI5f2igNHIgMDVMWZQy2WtxVbVhLqMfIIzQbB3uYwQK5vrWTQKsuF8MyHMNkBlYKzRhSeblWOlEo9pYCKLgux6MSGEARp1FqEEYnnNg+WaBYpu8OiSVsZybsS3WIHEt1lqFi+weHF8dk2OUKHEt8D/OQOZ/TQaSjLk2SvYrwy7UQWJftovIi6hRcAXHnytR4w8viqhzubilNsDE+F/6BY7isxg7mwGXBzB7C8CCKprywsFUXsChoNfF92wE47GB5n/7gOlEjkjhmVh/OssXf7x9+GS6jsSMBWC/qyq/IMF0qOsF9F0cQlhnj5w9IzLAnCsBDZCQgOYe1DVCIz0kF6QBxHz8NK0Pecoz2KLh8c2VXBhWpygIMnGbUZosDWnVR++T0CwFw7NOU4gB7zrXP5SFgsp8WO4aFZhjqIkgByqTgzM/IYhCz2TQhSeQEUjuQYuGMxD8ITkkNUyVUEmMVzgPIxFbxuE9MQaYVLshJGhgO6WXkiQ2lZ8hCIRgYr6NiSOSx4Nbo+AVh30RQn1QrH2ls1juoO6zjM3oFDpm01RWQnuZBnfgp3zQhGF9vgaEhs53VpJsXy/jVMQVDjOP5m/g0eKRgS2o1OcvSU3g7+4kpyl/3rQOshkhQdTiy1801LfsoECcrc7VgVsEJ6AJrUBN+uDuwI8vznijDVdJKZ+LAk99v2XBc/NQmVR8AalVIvj7+lQ0PG4mrFt+It2bWczqKb3+G9FQ+zyqPwP/b/myVa1pTj3VqYsVfPeoHG2bb1e4P188IB2owsG64pS+jMsY/mUmJ94faphroUg19mZyeHlWCETSrqJUG5OvvqpKrOI+6ivzWmzY7MteqgGFN2zSvR4wSj7lWkL+Ln6JrrAYcmLLCxoDTQsRDY81iqkkRpqQbC5S16Xx29DBXHRHM0HWDV2SJ+bkiuVawB3djNy0Gie0CAbHRcwda0YiK1WKNrkWqAir1iaoVGB56kOdraKFJAqyGc3HIHt9Ih9+OrueH5CtnW+qPJXw8i1lqRu+TZUh9A9zL7iTs8HioUHjeCQSkSt4BB+5kPqlYhNjgHB4clOAKDMb8vHk6kqkPoAFn3+CxL9AbSbUd83PfOo5dZmqMo0TydZhia59Ec/rDLEnM8HuqzGWtjvUVKIN+8bX9jaZhQElH8reK/e+vCvJ+ywLP7Tv6gsLJ1TuQUl4W7CqXIfEcnZ5cUJwA9g1vcZWdgxqE9drV4lySJrfhjElaFwtoQCMRxsFNZ5A750adgAUFOjJdcip794raNgV2AxNkN8lAKFUCktHSnncxItqGwTllwmHFyWugy0QoTEHOQr+bUREoDtQEUPk2xt/v09+FG/1cV3UrjC90NoenK+6gSZj5+rPPQ5Tp4CKWv7PvGdQcwvK2Iu8w05ud0jT+7OA7U7OT4zxEFX//PRK3aqi4v+mAY0tn7xL4yhMKDn1raw9p0Dd2Qeo+7UMQgEn1YvkLWXL0GkG9l0XsFNIhC6wC3aeKUQTpEknXbz32A2nTpIqqsxJch0GcRbxBdtbhypQLomdvWGlLtdQJ9keC7NEE2k0GrA3m0TXgqFSEKvRs2aybfsHG+7tl3JLbyJQmL5+be4P/nRuNOADQ/DQThsB8N2HrptAtvGG7I6b1bJZ0XRFRxM+nduquSTdUq1nCgMIz1mu2hCYde1cOagSyZOXNjCHimiqXclZAMt+ErywfCDWQCF1mO057omITZF/SdFIkkAHCLL1Q9HFgnQVacSGbj2u1VPp/vGrsq/dMeQ7pQ7VCEZBi4eKyCrirR9PVBqelU5k1h4/8n05ypRP+ZGDOEnRnwN0nyRptIL3KEvIwHDbT+G7MTjAUyHsXJajeFSRIbHvIfXJzn/E4FQOvn1TfRV9wqyYJR88tuRHUS9AX35R291lZxy7ntkhhFGaECjZCCbciq6tyDgSboTJtHhwyx/cTqsyxu1Iu4H8UOyl9/lgbcMyb9IFXkkIbjAtl55nLYUtsjOcqrWOOPLJbF1xIdIRpoxHmZWVmWqJyY9EygMDflLRdvDLyiPVor3BF330Pim1mqQ60omRck7QZU2fS8MRrfxkUkne6sMopFWjZa0EtZXz5cbtQv7ueoGXLKmStnNA/PyZf4IPqc8S1WmJpnXtzLPctr62lUEKLj8RPJI4IBL9/EC7qrTVdZTeGUOzODKtHpIYurnqYU8zPFOYHU7oNx+PQR2oYSohzu5dcM+Oro+y44RMcCo/y54ZRAGUKm99dha30pI8bABq22LGR/uTikOpSeqV4HoIiqERacXVU8acx2CaPbMIhcMngYPXuuw0jmnASN6f0Sk0+gCFgiKlKPbUtPAPnUEb+bA25jYE12yxPsZmg5qD9r8waOD+uHHmjOBflAkZ51Q3zHlTd+9NLnBtL4oZ03lLDawZb6+D9aeoOjhm1p8rF2jzSqwvyRXv6GCWWNE9xIDMRA91njlubXk3qeSwavJJyEsK7Do0KDO3didoN3LxSZyiWdNQgXZA/eKqvRlWlmu3UNUF6b28w3ZYk0kHrHMrYeRt6OCVSH7RkVx7Kz1Avsud8doAZxZrA9hFoehQnHrUd9btU2gqla4aparaQyxJSodEwfDge+97AvCEm9KFlbPUNVk4FwlnraPyBdSCNBQKJ0Ai/Hcn3QG3VUV5m3RurSI/p3xSkj5Y0odBjf7n7pCh9UlZPS652ywGVabKLlIZetmNkmbCms401haTUvhqS14NATILJcbwLLZyd0ektdo0u7hA9aqWh9XqicrtPITJL5LmELQJiLiapTnHql78UiaUd1EriOnvkO8g8hP8cLLyGMMcDXjIiahcX8IM63/V/CrPEoprqc/1y21cXJHFluWdtr8oC+HMf4xoiLUOIuT1qSg2NbdQedHeeAeYA2gvBcVlQu5u5OtQulJHd0FM7ZnRoHZhM2EWK6kxk2pTSxxsOrVVIdSoxaqRqmXggpgFQjcvP1/NLi/Of+1z21aiEIFmZYiWlidSHMeAG3OTLD2e0cSOvYiF8WBUmKwgsDTTceG7CkUFsLZTcUX4fa3sLDeJJ7lPmV1tyEJaeZ+hvcekC/hDNPTj2RVqK9JWNEpv8TpYDI7jJI5h2/W72jKRbcldHmin9WXUbV0EblCzCHKZ9lUT3arsEnDlZHVvf0T29vE6eBnApXjbddhwDE4HE9IZ6KcNqvGYpcAHNTOqR87sxz/Nmcle10EMPHnrBd4qXb3glAmelLmG7sJoW+L8fo3EuQ8l66SpfdjTO4GejHtA455y7ex38uWQO9LgPhzAn6bFAajoEct+R5U0Q9ztIyNIrntB5Hzd7TyYhCeVkwmLNUPbq/Oyn4sD5UMnp95e0HV8yoSPHNaHG1blL9Hnw78tx+fVQ56DJn1sgSDXqy0w9tpgiGRSvxL43LLShYpWihPak0t1r9zRNRSHbctjW08hCFS/6lnRDyVSFa0uJQpUIgBe/nGLj0WwaUx/KkEzMTAn1PwiQq1uxL2vUE0O+JO10gNxj0bpt3iV0JUdExySyXhKPPJPUkkbpuTNG689bzAEEpVx1exji3jDoZpbQArLf+q4dnF5iukomeNJFIaak+NZ3l9C9+BJd7ZcSMAJFS1QLMa1V4oU6FtNrz6LCQT85I78Q3gqwZqu2K0Fc5GuFqCOQHdTJpHgr175L38dL7GbEdb9rBbhdcgASdCNthnTTj1UalHx02EdCi1oYdUT9U5FJ5ZmviXLMPUdssBfOBferhGziHx1hLprHNxES+/XVMI37LBS1zfQwu8vyGjgk44d8i+Z8pfu/LXic3KolQsNpTfSjdV4kJVLLV2msbLPrP7aIjCE2ysRDksSoLjIC01O+yp0UpA2fYjCmHfdn7IbPfwK4/P0//nGAP4=', 'base64'));");

	// zip-writer, refer to modules/zip-writer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'));");


#ifndef _NOHECI
	duk_peval_string_noresult(ctx, "addCompressedModule('heci', Buffer.from('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', 'base64'));"); 
#endif

#ifdef __APPLE__
	duk_peval_string_noresult(ctx, "addCompressedModule('mac-powerutil', Buffer.from('eJztVk1v00AQvVvyfxjlYgdSp+qRiENog7BAiVQXEKIIbdaTeMHeNbvjuhHqf2fWcdMUAhISHxLCF9uzzzNv3r5ZefwgDE5NvbFqXRCcHJ8cQ6oJSzg1tjZWkDI6DMLghZKoHebQ6BwtUIEwrYXkW78ygldoHaPhJDmG2AMG/dJgOAmDjWmgEhvQhqBxyBmUg5UqEfBaYk2gNEhT1aUSWiK0ioquSp8jCYM3fQazJMFgwfCa31b7MBDk2QJfBVH9aDxu2zYRHdPE2PW43OLc+EV6OptnsyNm6794qUt0Dix+apTlNpcbEDWTkWLJFEvRgrEg1hZ5jYwn21pFSq9H4MyKWmExDHLlyKplQ/d0uqXG/e4DWCmhYTDNIM0G8GSapdkoDF6nF88WLy/g9fT8fDq/SGcZLM7hdDE/Sy/SxZzfnsJ0/gaep/OzESCrxFXwuraePVNUXkHMWa4M8V75ldnScTVKtVKSm9LrRqwR1uYKreZeoEZbKed30TG5PAxKVSnqTOC+7YiLPBh78VaNlh4DtWnRNqTKeBgGn7f74Dc6eb9YfkBJ6Rk8hqgS8miHjCa3G9YBXYlYM2iXsgv4dB7Sp/TXlbAgC1Xmk7uYY9fIAuLaGsl6JHUpiNuuhneQvQz+koKViXJhW6WjR/fXunVfgen0voijLvC+LxANE7xG+ZRdHEfjpdJjV0QjeBvx7d1w8p10iaPcNMQ369WIJvfDRsdMiAQn2okQy6LRH4fwuReJv3z4GLpgQiZjT+l1PJzAzQ+LorWHivrw7yuqdOInhQUyTjhpFY/6EcJlxIdMeTtjXb1BtnGEFcyuUJMb+DHrNv8yutR4rehSR9+v1ApFMwbFhyBLi+LjV/EcV6Ip6cCeU2FNC3HUO687sfxYYcW8toPbHV637jrI6uuSN9vHmz2r88iSsLRv9j70U3b/7/bDRf+y213RcIethiPLDmr/tHl3Tvpt9t01uH9Y97H/5/U/5eDibzj4zku/2sI3/o+jMnlTIvuB/3LJscYa2/3/l8kX1l4yWQ==', 'base64'));"); 
#endif
}

void ILibDuktape_ChainViewer_PostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	duk_context *ctx = (duk_context*)((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[0];
	void *hptr = ((void**)((ILibTransport*)object)->ChainLink.ExtraMemoryPtr)[1];
	int top = duk_get_top(ctx);
	char *m;
	duk_push_heapptr(ctx, hptr);										// [this]
	if (ILibDuktape_EventEmitter_HasListenersEx(ctx, -1, "PostSelect"))
	{
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "PostSelect");	// [this][emit][this][name]
		duk_push_int(ctx, slct);										// [this][emit][this][name][select]
		m = ILibChain_GetMetaDataFromDescriptorSet(Duktape_GetChain(ctx), readset, writeset, errorset);
		duk_push_string(ctx, m);										// [this][emit][this][name][select][string]
		if (duk_pcall_method(ctx, 3) != 0) { ILibDuktape_Process_UncaughtExceptionEx(ctx, "ChainViewer.emit('PostSelect'): Error "); }
		duk_pop(ctx);													// [this]
	}

	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);	// [this][list]
	while (duk_get_length(ctx, -1) > 0)
	{
		m = ILibChain_GetMetaDataFromDescriptorSetEx(duk_ctx_chain(ctx), readset, writeset, errorset);
		duk_array_shift(ctx, -1);										// [this][list][promise]
		duk_get_prop_string(ctx, -1, "_RES");							// [this][list][promise][RES]
		duk_swap_top(ctx, -2);											// [this][list][RES][this]
		duk_push_string(ctx, m);										// [this][list][RES][this][str]
		duk_pcall_method(ctx, 1); duk_pop(ctx);							// [this][list]
		ILibMemory_Free(m);
	}

	duk_set_top(ctx, top);
}

extern void ILibPrependToChain(void *Chain, void *object);

duk_ret_t ILibDuktape_ChainViewer_getSnapshot_promise(duk_context *ctx)
{
	duk_push_this(ctx);										// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getSnapshot(duk_context *ctx)
{
	duk_push_this(ctx);															// [viewer]
	duk_get_prop_string(ctx, -1, ILibDuktape_ChainViewer_PromiseList);			// [viewer][list]
	duk_eval_string(ctx, "require('promise')");									// [viewer][list][promise]
	duk_push_c_function(ctx, ILibDuktape_ChainViewer_getSnapshot_promise, 2);	// [viewer][list][promise][func]
	duk_new(ctx, 1);															// [viewer][list][promise]
	duk_dup(ctx, -1);															// [viewer][list][promise][promise]
	duk_put_prop_index(ctx, -3, (duk_uarridx_t)duk_get_length(ctx, -3));						// [viewer][list][promise]
	ILibForceUnBlockChain(duk_ctx_chain(ctx));
	return(1);
}
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
	ILibDuktape_CreateInstanceMethod(ctx, "getSnapshot", ILibDuktape_ChainViewer_getSnapshot, 0);
	duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_ChainViewer_PromiseList);
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
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		duk_push_this(ctx);													// [obj]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [obj][table]
		ILibChain_RemoveWaitHandle(duk_ctx_chain(ctx), h);
		duk_push_sprintf(ctx, "%p", h);	duk_del_prop(ctx, -2);				// [obj][table]
		if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
		}
		return(0);
	}
#endif
	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (!duk_is_null_or_undefined(ctx, 1) && duk_is_object(ctx, 1))
	{
		duk_get_prop(ctx, -2);											// [obj][table][value]
		if (duk_is_null_or_undefined(ctx, -1)) { return(0); }
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (duk_has_prop_string(ctx, 1, "readset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (duk_has_prop_string(ctx, 1, "writeset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (duk_has_prop_string(ctx, 1, "errorset")) { duk_push_false(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		if(	Duktape_GetBooleanProperty(ctx, -1, "readset", 0)	== 0 && 
			Duktape_GetBooleanProperty(ctx, -1, "writeset", 0)	== 0 &&
			Duktape_GetBooleanProperty(ctx, -1, "errorset", 0)	== 0)
		{
			// No FD_SET watchers, so we can remove the entire object
			duk_pop_2(ctx);												// [obj][table]
			duk_dup(ctx, 0);											// [obj][table][key]
			duk_del_prop(ctx, -2);										// [obj][table]
		}
	}
	else
	{
		// Remove All FD_SET watchers for this FD
		duk_del_prop(ctx, -2);											// [obj][table]
	}
	return(0);
}
#ifdef WIN32
char *DescriptorEvents_Status[] = { "NONE", "INVALID_HANDLE", "TIMEOUT", "REMOVED", "EXITING", "ERROR" }; 
BOOL ILibDuktape_DescriptorEvents_WaitHandleSink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	BOOL ret = FALSE;
	duk_context *ctx = (duk_context*)((void**)user)[0];

	int top = duk_get_top(ctx);
	duk_push_heapptr(ctx, ((void**)user)[1]);								// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
	duk_push_sprintf(ctx, "%p", h);											// [events][table][key]
	duk_get_prop(ctx, -2);													// [events][table][val]
	if (!duk_is_null_or_undefined(ctx, -1))
	{
		void *hptr = duk_get_heapptr(ctx, -1);
		if (status != ILibWaitHandle_ErrorStatus_NONE) { duk_push_sprintf(ctx, "%p", h); duk_del_prop(ctx, -3); }
		duk_push_pointer(ctx, h); duk_put_prop_string(ctx, -3, ILibDuktape_DescriptorEvents_CURRENT);
		ILibDuktape_EventEmitter_SetupEmit(ctx, hptr, "signaled");			// [events][table][val][emit][this][signaled]
		duk_push_string(ctx, DescriptorEvents_Status[(int)status]);			// [events][table][val][emit][this][signaled][status]
		if (duk_pcall_method(ctx, 2) == 0)									// [events][table][val][undef]
		{
			ILibDuktape_EventEmitter_GetEmitReturn(ctx, hptr, "signaled");	// [events][table][val][undef][ret]
			if (duk_is_boolean(ctx, -1) && duk_get_boolean(ctx, -1) != 0)
			{
				ret = TRUE;
			}
		}	
		else
		{
			ILibDuktape_Process_UncaughtExceptionEx(ctx, "DescriptorEvents.signaled() threw an exception that will result in descriptor getting removed: ");
		}
		duk_set_top(ctx, top);
		duk_push_heapptr(ctx, ((void**)user)[1]);							// [events]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);	// [events][table]

		if (ret == FALSE && Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
		{
			//
			// We need to unhook the events to the descriptor event object, before we remove it from the table
			//
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_get_prop(ctx, -2);											// [events][table][descriptorevent]
			duk_get_prop_string(ctx, -1, "removeAllListeners");				// [events][table][descriptorevent][remove]
			duk_swap_top(ctx, -2);											// [events][table][remove][this]
			duk_push_string(ctx, "signaled");								// [events][table][remove][this][signaled]
			duk_pcall_method(ctx, 1); duk_pop(ctx);							// [events][table]
			duk_push_sprintf(ctx, "%p", h);									// [events][table][key]
			duk_del_prop(ctx, -2);											// [events][table]
		}
		duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);	// [events][table]
	}
	duk_set_top(ctx, top);

	return(ret);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_Add(duk_context *ctx)
{
	ILibDuktape_EventEmitter *e;
#ifdef WIN32
	if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
	{
		// Adding a Windows Wait Handle
		HANDLE h = (HANDLE)Duktape_GetPointerProperty(ctx, 0, "_ptr");
		if (h != NULL)
		{
			// Normal Add Wait Handle
			char *metadata = "DescriptorEvents";
			int timeout = -1;
			duk_push_this(ctx);														// [events]
			ILibChain_Link *link = (ILibChain_Link*)Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_ChainLink);
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [events][table]
			if (Duktape_GetPointerProperty(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT) == h)
			{
				// We are adding a wait handle from the event handler for this same signal, so remove this attribute,
				// so the signaler doesn't remove the object we are about to put in.
				duk_del_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_CURRENT);
			}
			duk_push_object(ctx);													// [events][table][value]
			duk_push_sprintf(ctx, "%p", h);											// [events][table][value][key]
			duk_dup(ctx, -2);														// [events][table][value][key][value]
			duk_dup(ctx, 0);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_WaitHandle);	// [events][table][value][key][value]
			if (duk_is_object(ctx, 1)) { duk_dup(ctx, 1); }
			else { duk_push_object(ctx); }											// [events][table][value][key][value][options]
			if (duk_has_prop_string(ctx, -1, "metadata"))
			{
				duk_push_string(ctx, "DescriptorEvents, ");							// [events][table][value][key][value][options][str1]
				duk_get_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options][str1][str2]
				duk_string_concat(ctx, -2);											// [events][table][value][key][value][options][str1][newstr]
				duk_remove(ctx, -2);												// [events][table][value][key][value][options][newstr]
				metadata = (char*)duk_get_string(ctx, -1);
				duk_put_prop_string(ctx, -2, "metadata");							// [events][table][value][key][value][options]
			}
			timeout = Duktape_GetIntPropertyValue(ctx, -1, "timeout", -1);
			duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);		// [events][table][value][key][value]
			duk_put_prop(ctx, -4);													// [events][table][value]
			e = ILibDuktape_EventEmitter_Create(ctx);
			ILibDuktape_EventEmitter_CreateEventEx(e, "signaled");
			ILibChain_AddWaitHandleEx(duk_ctx_chain(ctx), h, timeout, ILibDuktape_DescriptorEvents_WaitHandleSink, link->ExtraMemoryPtr, metadata);
			return(1);
		}
		return(ILibDuktape_Error(ctx, "Invalid Parameter"));
	}
#endif

	if (!duk_is_number(ctx, 0)) { return(ILibDuktape_Error(ctx, "Invalid Descriptor")); }
	ILibForceUnBlockChain(Duktape_GetChain(ctx));

	duk_push_this(ctx);													// [obj]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);	// [obj][table]
	duk_dup(ctx, 0);													// [obj][table][key]
	if (duk_has_prop(ctx, -2))											// [obj][table]
	{
		// There's already a watcher, so let's just merge the FD_SETS
		duk_dup(ctx, 0);												// [obj][table][key]
		duk_get_prop(ctx, -2);											// [obj][table][value]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	//..[table][value][options]
		if (Duktape_GetBooleanProperty(ctx, 1, "readset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "readset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "writeset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "writeset"); }
		if (Duktape_GetBooleanProperty(ctx, 1, "errorset", 0) != 0) { duk_push_true(ctx); duk_put_prop_string(ctx, -2, "errorset"); }
		duk_pop(ctx);													// [obj][table][value]
		return(1);
	}

	duk_push_object(ctx);												// [obj][table][value]
	duk_dup(ctx, 0);													// [obj][table][value][key]
	duk_dup(ctx, -2);													// [obj][table][value][key][value]
	e = ILibDuktape_EventEmitter_Create(ctx);	
	ILibDuktape_EventEmitter_CreateEventEx(e, "readset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "writeset");
	ILibDuktape_EventEmitter_CreateEventEx(e, "errorset");
	duk_dup(ctx, 0);													// [obj][table][value][key][value][FD]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_FD);		// [obj][table][value][key][value]
	duk_dup(ctx, 1);													// [obj][table][value][key][value][options]
	duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Options);	// [obj][table][value][key][value]
	char* metadata = Duktape_GetStringPropertyValue(ctx, -1, "metadata", NULL);
	if (metadata != NULL)
	{
		duk_push_string(ctx, "DescriptorEvents, ");						// [obj][table][value][key][value][str1]
		duk_push_string(ctx, metadata);									// [obj][table][value][key][value][str1][str2]
		duk_string_concat(ctx, -2);										// [obj][table][value][key][value][newStr]
		duk_put_prop_string(ctx, -2, "metadata");						// [obj][table][value][key][value]
	}
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

#ifndef WIN32
void ILibDuktape_DescriptorEvents_GetCount_results_final(void *chain, void *user)
{
	duk_context *ctx = (duk_context*)((void**)user)[0];
	void *hptr = ((void**)user)[1];
	duk_push_heapptr(ctx, hptr);											// [promise]
	duk_get_prop_string(ctx, -1, "_RES");									// [promise][res]
	duk_swap_top(ctx, -2);													// [res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));	// [res][this][count]
	duk_pcall_method(ctx, 1); duk_pop(ctx);									// ...
	free(user);
}
void ILibDuktape_DescriptorEvents_GetCount_results(void *chain, void *user)
{
	ILibChain_RunOnMicrostackThreadEx2(chain, ILibDuktape_DescriptorEvents_GetCount_results_final, user, 1);
}
#endif
duk_ret_t ILibDuktape_DescriptorEvents_GetCount_promise(duk_context *ctx)
{
	duk_push_this(ctx);		// [promise]
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, "_RES");
	duk_dup(ctx, 1); duk_put_prop_string(ctx, -2, "_REJ");
	return(0);
}
duk_ret_t ILibDuktape_DescriptorEvents_GetCount(duk_context *ctx)
{
	duk_eval_string(ctx, "require('promise');");								// [promise]
	duk_push_c_function(ctx, ILibDuktape_DescriptorEvents_GetCount_promise, 2);	// [promise][func]
	duk_new(ctx, 1);															// [promise]
	
#ifdef WIN32
	duk_get_prop_string(ctx, -1, "_RES");										// [promise][res]
	duk_dup(ctx, -2);															// [promise][res][this]
	duk_push_int(ctx, ILibChain_GetDescriptorCount(duk_ctx_chain(ctx)));		// [promise][res][this][count]
	duk_call_method(ctx, 1); duk_pop(ctx);										// [promise]
#else
	void **data = (void**)ILibMemory_Allocate(2 * sizeof(void*), 0, NULL, NULL);
	data[0] = ctx;
	data[1] = duk_get_heapptr(ctx, -1);
	ILibChain_InitDescriptorCount(duk_ctx_chain(ctx));
	ILibChain_RunOnMicrostackThreadEx2(duk_ctx_chain(ctx), ILibDuktape_DescriptorEvents_GetCount_results, data, 1);
#endif
	return(1);
}
char* ILibDuktape_DescriptorEvents_Query(void* chain, void *object, int fd, size_t *dataLen)
{
	char *retVal = ((ILibChain_Link*)object)->MetaData;
	*dataLen = strnlen_s(retVal, 1024);

	duk_context *ctx = (duk_context*)((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[0];
	void *h = ((void**)((ILibChain_Link*)object)->ExtraMemoryPtr)[1];
	if (h == NULL || ctx == NULL || !duk_ctx_is_alive(ctx)) { return(retVal); }
	int top = duk_get_top(ctx);

	duk_push_heapptr(ctx, h);												// [events]
	duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);		// [events][table]
	duk_push_int(ctx, fd);													// [events][table][key]
	if (duk_has_prop(ctx, -2) != 0)											// [events][table]
	{
		duk_push_int(ctx, fd); duk_get_prop(ctx, -2);						// [events][table][val]
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Options);	// [events][table][val][options]
		if (!duk_is_null_or_undefined(ctx, -1))
		{
			retVal = Duktape_GetStringPropertyValueEx(ctx, -1, "metadata", retVal, dataLen);
		}
	}

	duk_set_top(ctx, top);
	return(retVal);
}
duk_ret_t ILibDuktape_DescriptorEvents_descriptorAdded(duk_context *ctx)
{
	duk_push_this(ctx);																// [DescriptorEvents]
	if (duk_is_number(ctx, 0))
	{
		duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_Table);			// [DescriptorEvents][table]
		duk_dup(ctx, 0);															// [DescriptorEvents][table][key]
	}
	else
	{
		if (duk_is_object(ctx, 0) && duk_has_prop_string(ctx, 0, "_ptr"))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_DescriptorEvents_HTable);		// [DescriptorEvents][table]	
			duk_push_sprintf(ctx, "%p", Duktape_GetPointerProperty(ctx, 0, "_ptr"));// [DescriptorEvents][table][key]
		}
		else
		{
			return(ILibDuktape_Error(ctx, "Invalid Argument. Must be a descriptor or HANDLE"));
		}
	}
	duk_push_boolean(ctx, duk_has_prop(ctx, -2));
	return(1);
}
void ILibDuktape_DescriptorEvents_Push(duk_context *ctx, void *chain)
{
	ILibChain_Link *link = (ILibChain_Link*)ILibChain_Link_Allocate(sizeof(ILibChain_Link), 2 * sizeof(void*));
	link->MetaData = "DescriptorEvents";
	link->PreSelectHandler = ILibDuktape_DescriptorEvents_PreSelect;
	link->PostSelectHandler = ILibDuktape_DescriptorEvents_PostSelect;
	link->QueryHandler = ILibDuktape_DescriptorEvents_Query;

	duk_push_object(ctx);
	duk_push_pointer(ctx, link); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_ChainLink);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_Table);
	duk_push_object(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_DescriptorEvents_HTable);
	
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_DescriptorEvents_Finalizer);

	((void**)link->ExtraMemoryPtr)[0] = ctx;
	((void**)link->ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_CreateInstanceMethod(ctx, "addDescriptor", ILibDuktape_DescriptorEvents_Add, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "removeDescriptor", ILibDuktape_DescriptorEvents_Remove, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getDescriptorCount", ILibDuktape_DescriptorEvents_GetCount, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "descriptorAdded", ILibDuktape_DescriptorEvents_descriptorAdded, 1);

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

duk_ret_t ILibDuktape_Polyfills_ipv4From(duk_context *ctx)
{
	int v = duk_require_int(ctx, 0);
	ILibDuktape_IPV4AddressToOptions(ctx, v);
	duk_get_prop_string(ctx, -1, "host");
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_global(duk_context *ctx)
{
	duk_push_global_object(ctx);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_isBuffer(duk_context *ctx)
{
	duk_push_boolean(ctx, duk_is_buffer_data(ctx, 0));
	return(1);
}
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
duk_ret_t ILibDuktape_ioctl_func(duk_context *ctx)
{
	int fd = (int)duk_require_int(ctx, 0);
	int code = (int)duk_require_int(ctx, 1);
	duk_size_t outBufferLen = 0;
	char *outBuffer = Duktape_GetBuffer(ctx, 2, &outBufferLen);

	duk_push_int(ctx, ioctl(fd, _IOC(_IOC_READ | _IOC_WRITE, 'H', code, outBufferLen), outBuffer) ? errno : 0);
	return(1);
}
void ILibDuktape_ioctl_Push(duk_context *ctx, void *chain)
{
	duk_push_c_function(ctx, ILibDuktape_ioctl_func, DUK_VARARGS);
	ILibDuktape_WriteID(ctx, "ioctl");
}
#endif
void ILibDuktape_uuidv4_Push(duk_context *ctx, void *chain)
{	
	duk_push_object(ctx);
	char uuid[] = "module.exports = function uuidv4()\
						{\
							var b = Buffer.alloc(16);\
							b.randomFill();\
							var v = b.readUInt16BE(6) & 0xF1F;\
							v |= (4 << 12);\
							v |= (4 << 5);\
							b.writeUInt16BE(v, 6);\
							var ret = b.slice(0, 4).toString('hex') + '-' + b.slice(4, 6).toString('hex') + '-' + b.slice(6, 8).toString('hex') + '-' + b.slice(8, 10).toString('hex') + '-' + b.slice(10).toString('hex');\
							ret = '{' + ret.toLowerCase() + '}';\
							return (ret);\
						};";

	ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(ctx, uuid, sizeof(uuid) - 1);
}

duk_ret_t ILibDuktape_Polyfills_debugHang(duk_context *ctx)
{
	int val = duk_get_top(ctx) == 0 ? 30000 : duk_require_int(ctx, 0);

#ifdef WIN32
	Sleep(val);
#else
	sleep(val);
#endif

	return(0);
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
	ILibDuktape_ModSearch_AddHandler(ctx, "uuid/v4", ILibDuktape_uuidv4_Push);
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	ILibDuktape_ModSearch_AddHandler(ctx, "ioctl", ILibDuktape_ioctl_Push);
#endif


	// Global Polyfills
	duk_push_global_object(ctx);													// [g]
	ILibDuktape_WriteID(ctx, "Global");
	ILibDuktape_Polyfills_Array(ctx);
	ILibDuktape_Polyfills_String(ctx);
	ILibDuktape_Polyfills_Buffer(ctx);
	ILibDuktape_Polyfills_Console(ctx);
	ILibDuktape_Polyfills_byte_ordering(ctx);
	ILibDuktape_Polyfills_timer(ctx);
	ILibDuktape_Polyfills_object(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addCompressedModule", ILibDuktape_Polyfills_addCompressedModule, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModule", ILibDuktape_Polyfills_getJSModule, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugHang", ILibDuktape_Polyfills_debugHang, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugCrash", ILibDuktape_Polyfills_debugCrash, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugGC", ILibDuktape_Polyfills_debugGC, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_Polyfills_debug, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getSHA384FileHash", ILibDuktape_Polyfills_filehash, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_ipv4From", ILibDuktape_Polyfills_ipv4From, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_isBuffer", ILibDuktape_Polyfills_isBuffer, 1);

#ifndef MICROSTACK_NOTLS
	ILibDuktape_CreateInstanceMethod(ctx, "crc32c", ILibDuktape_Polyfills_crc32c, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "crc32", ILibDuktape_Polyfills_crc32, DUK_VARARGS);
#endif
	ILibDuktape_CreateEventWithGetter(ctx, "global", ILibDuktape_Polyfills_global);
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
