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
			duk_push_fixed_buffer(ctx, ILibBase64EncodeLength(bufferLen));
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
	size_t bufferLen;

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
		buffer = duk_push_fixed_buffer(ctx, ILibBase64DecodeLength(strlength));
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
duk_ret_t ILibDuktape_Polyfills_Array_findIndex(duk_context *ctx)
{
	duk_idx_t nargs = duk_get_top(ctx);
	duk_push_this(ctx);								// [array]

	duk_size_t sz = duk_get_length(ctx, -1);
	duk_uarridx_t i;

	for (i = 0; i < sz; ++i)
	{
		duk_dup(ctx, 0);							// [array][func]
		if (nargs > 1 && duk_is_function(ctx, 1))
		{
			duk_dup(ctx, 1);						// [array][func][this]
		}
		else
		{
			duk_push_this(ctx);						// [array][func][this]
		}
		duk_get_prop_index(ctx, -3, i);				// [array][func][this][element]
		duk_push_uint(ctx, i);						// [array][func][this][element][index]
		duk_push_this(ctx);							// [array][func][this][element][index][array]
		duk_call_method(ctx, 3);					// [array][ret]
		if (!duk_is_undefined(ctx, -1) && duk_is_boolean(ctx, -1) && duk_to_boolean(ctx, -1) != 0)
		{
			duk_push_uint(ctx, i);
			return(1);
		}
		duk_pop(ctx);								// [array]
	}
	duk_push_int(ctx, -1);
	return(1);
}
void ILibDuktape_Polyfills_Array(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Array");											// [Array]
	duk_get_prop_string(ctx, -1, "prototype");										// [Array][proto]

	// Polyfill 'Array.includes'
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "includes", ILibDuktape_Polyfills_Array_includes, 1);

	// Polyfill 'Array.partialIncludes'
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "partialIncludes", ILibDuktape_Polyfills_Array_partialIncludes, 1);

	// Polyfill 'Array.findIndex'
	ILibDuktape_CreateProperty_InstanceMethod(ctx, "findIndex", ILibDuktape_Polyfills_Array_findIndex, DUK_VARARGS);
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
	strLen = 0;
	strLen += snprintf(NULL, 0, "%s", PREFIX != NULL ? PREFIX : "");
	for (i = 0; i < numargs; ++i)
	{
		if (duk_is_string(ctx, i))
		{
			strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_require_string(ctx, i));
		}
		else
		{
			duk_dup(ctx, i);
			if (strcmp("[object Object]", duk_to_string(ctx, -1)) == 0)
			{
				duk_pop(ctx);
				duk_dup(ctx, i);
				strLen += snprintf(NULL, 0, "%s", (i == 0 ? "{" : ", {"));
				duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);
				int propNum = 0;
				while (duk_next(ctx, -1, 1))
				{
					strLen += snprintf(NULL, 0, "%s%s: %s", ((propNum++ == 0) ? " " : ", "), (char*)duk_to_string(ctx, -2), (char*)duk_to_string(ctx, -1));
					duk_pop_2(ctx);
				}
				duk_pop(ctx);
				strLen += snprintf(NULL, 0, " }");
			}
			else
			{
				strLen += snprintf(NULL, 0, "%s%s", (i == 0 ? "" : ", "), duk_to_string(ctx, -1));
			}
		}
	}
	strLen += snprintf(NULL, 0, "\n");
	strLen += 1;

	str = Duktape_PushBuffer(ctx, strLen);
	x = 0;
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
		char *tmp = (char*)ILibMemory_SmartAllocate(x + 32);
		int tmpx = ILibGetLocalTime(tmp + 1, (int)ILibMemory_Size(tmp) - 1) + 1;
		tmp[0] = '[';
		tmp[tmpx] = ']';
		tmp[tmpx + 1] = ':';
		tmp[tmpx + 2] = ' ';
		memcpy_s(tmp + tmpx + 3, ILibMemory_Size(tmp) - tmpx - 3, str, x);
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
		ILibMemory_Free(tmp);
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
duk_ret_t ILibDuktape_Polyfills_Timer_Metadata(duk_context *ctx)
{
	duk_push_this(ctx);
	ILibLifeTime_Token token = (ILibLifeTime_Token)Duktape_GetPointerProperty(ctx, -1, "\xFF_token");
	if (token != NULL)
	{
		duk_size_t metadataLen;
		char *metadata = (char*)duk_require_lstring(ctx, 0, &metadataLen);
		ILibLifeTime_SetMetadata(token, metadata, metadataLen);
	}
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_timer_set(duk_context *ctx)
{
	char *metadata = NULL;
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
		metadata = "setImmediate()";
		// We're only saving a reference for immediates
		duk_push_heap_stash(ctx);															//[retVal][stash]
		duk_dup(ctx, -2);																	//[retVal][stash][immediate]
		duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		//[retVal][stash]
		duk_pop(ctx);																		//[retVal]
		break;
	case ILibDuktape_Timer_Type_INTERVAL:
		ILibDuktape_WriteID(ctx, "Timers.interval");
		metadata = "setInterval()";
		break;
	case ILibDuktape_Timer_Type_TIMEOUT:
		ILibDuktape_WriteID(ctx, "Timers.timeout");
		metadata = "setTimeout()";
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

	duk_push_pointer(
		ctx,
		ILibLifeTime_AddEx3(ILibGetBaseTimer(chain), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata));
	duk_put_prop_string(ctx, -2, "\xFF_token");
	ILibDuktape_CreateEventWithSetterEx(ctx, "metadata", ILibDuktape_Polyfills_Timer_Metadata);
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
	duk_peval_string_noresult(ctx, "addModule('promise', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE4IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQp2YXIgcmVmVGFibGUgPSB7fTsNCg0KZnVuY3Rpb24gZ2V0Um9vdFByb21pc2Uob2JqKQ0Kew0KICAgIHdoaWxlKG9iai5wYXJlbnRQcm9taXNlKQ0KICAgIHsNCiAgICAgICAgb2JqID0gb2JqLnBhcmVudFByb21pc2U7DQogICAgfQ0KICAgIHJldHVybiAob2JqKTsNCn0NCg0KZnVuY3Rpb24gZXZlbnRfc3dpdGNoZXJfaGVscGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQsIGZvcndhcmQpDQp7DQogICAgdGhpcy5fT2JqZWN0SUQgPSAnZXZlbnRfc3dpdGNoZXInOw0KICAgIHRoaXMuZnVuYyA9IGZ1bmN0aW9uIGZ1bmMoKQ0KICAgIHsNCiAgICAgICAgdmFyIGFyZ3MgPSBbXTsNCiAgICAgICAgaWYgKGZ1bmMuZm9yd2FyZCAhPSBudWxsKSB7IGFyZ3MucHVzaChmdW5jLmZvcndhcmQpOyB9DQogICAgICAgIGZvcih2YXIgaSBpbiBhcmd1bWVudHMpDQogICAgICAgIHsNCiAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbaV0pOw0KICAgICAgICB9DQogICAgICAgIHJldHVybiAoZnVuYy50YXJnZXQuYXBwbHkoZnVuYy5kZXNpcmVkLCBhcmdzKSk7DQogICAgfTsNCiAgICB0aGlzLmZ1bmMuZGVzaXJlZCA9IGRlc2lyZWRfY2FsbGVlOw0KICAgIHRoaXMuZnVuYy50YXJnZXQgPSB0YXJnZXQ7DQogICAgdGhpcy5mdW5jLmZvcndhcmQgPSBmb3J3YXJkOw0KICAgIHRoaXMuZnVuYy5zZWxmID0gdGhpczsNCn0NCmZ1bmN0aW9uIGV2ZW50X3N3aXRjaGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpDQp7DQogICAgcmV0dXJuIChuZXcgZXZlbnRfc3dpdGNoZXJfaGVscGVyKGRlc2lyZWRfY2FsbGVlLCB0YXJnZXQpKTsNCn0NCg0KZnVuY3Rpb24gZXZlbnRfZm9yd2FyZGVyKHNvdXJjZU9iaiwgc291cmNlTmFtZSwgdGFyZ2V0T2JqLCB0YXJnZXROYW1lKQ0Kew0KICAgIHNvdXJjZU9iai5vbihzb3VyY2VOYW1lLCAgIChuZXcgZXZlbnRfc3dpdGNoZXJfaGVscGVyKHRhcmdldE9iaiwgdGFyZ2V0T2JqLmVtaXQsIHRhcmdldE5hbWUpKS5mdW5jKTsgICAgICANCn0NCg0KZnVuY3Rpb24gUHJvbWlzZShwcm9taXNlRnVuYykNCnsNCiAgICB0aGlzLl9PYmplY3RJRCA9ICdwcm9taXNlJzsNCiAgICB0aGlzLnByb21pc2UgPSB0aGlzOw0KICAgIHRoaXMuX2ludGVybmFsID0geyBfT2JqZWN0SUQ6ICdwcm9taXNlLmludGVybmFsJywgcHJvbWlzZTogdGhpcywgZnVuYzogcHJvbWlzZUZ1bmMsIGNvbXBsZXRlZDogZmFsc2UsIGVycm9yczogZmFsc2UsIGNvbXBsZXRlZEFyZ3M6IFtdLCBpbnRlcm5hbENvdW50OiAwLCBfdXA6IG51bGwgfTsNCiAgICByZXF1aXJlKCdldmVudHMnKS5FdmVudEVtaXR0ZXIuY2FsbCh0aGlzLl9pbnRlcm5hbCk7DQogICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsICJwYXJlbnRQcm9taXNlIiwNCiAgICAgICAgew0KICAgICAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7IHJldHVybiAodGhpcy5fdXApOyB9LA0KICAgICAgICAgICAgc2V0OiBmdW5jdGlvbiAodmFsdWUpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgaWYgKHZhbHVlICE9IG51bGwgJiYgdGhpcy5fdXAgPT0gbnVsbCkNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIC8vIFdlIGFyZSBubyBsb25nZXIgYW4gb3JwaGFuDQogICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLl9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjbGVhckltbWVkaWF0ZSh0aGlzLl9pbnRlcm5hbC51bmNhdWdodCk7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC51bmNhdWdodCA9IG51bGw7DQogICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgdGhpcy5fdXAgPSB2YWx1ZTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfSk7DQoNCg0KDQogICAgdGhpcy5faW50ZXJuYWwub24oJ25ld0xpc3RlbmVyJywgZnVuY3Rpb24gKGV2ZW50TmFtZSwgZXZlbnRDYWxsYmFjaykNCiAgICB7DQogICAgICAgIC8vY29uc29sZS5sb2coJ25ld0xpc3RlbmVyJywgZXZlbnROYW1lLCAnZXJyb3JzLycgKyB0aGlzLmVycm9ycyArICcgY29tcGxldGVkLycgKyB0aGlzLmNvbXBsZXRlZCk7DQogICAgICAgIHZhciByID0gbnVsbDsNCg0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZXNvbHZlZCcgJiYgIXRoaXMuZXJyb3JzICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICByID0gZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCB0aGlzLmNvbXBsZXRlZEFyZ3MpOw0KICAgICAgICAgICAgaWYociE9bnVsbCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJywgcik7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCg0KICAgICAgICBpZiAoZXZlbnROYW1lID09ICdyZWplY3RlZCcgJiYgKGV2ZW50Q2FsbGJhY2suaW50ZXJuYWwgPT0gbnVsbCB8fCBldmVudENhbGxiYWNrLmludGVybmFsID09IGZhbHNlKSkNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHJwID0gZ2V0Um9vdFByb21pc2UodGhpcy5wcm9taXNlKTsNCiAgICAgICAgICAgIHJwLl9pbnRlcm5hbC5leHRlcm5hbCA9IHRydWU7DQogICAgICAgICAgICBpZiAodGhpcy51bmNhdWdodCAhPSBudWxsKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGNsZWFySW1tZWRpYXRlKHRoaXMudW5jYXVnaHQpOw0KICAgICAgICAgICAgICAgIHRoaXMudW5jYXVnaHQgPSBudWxsOw0KICAgICAgICAgICAgfQ0KICAgICAgICAgICAgaWYgKHJwLl9pbnRlcm5hbC51bmNhdWdodCAhPSBudWxsKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGNsZWFySW1tZWRpYXRlKHJwLl9pbnRlcm5hbC51bmNhdWdodCk7DQogICAgICAgICAgICAgICAgcnAuX2ludGVybmFsLnVuY2F1Z2h0ID0gbnVsbDsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KDQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3JlamVjdGVkJyAmJiB0aGlzLmVycm9ycyAmJiB0aGlzLmNvbXBsZXRlZCkNCiAgICAgICAgew0KICAgICAgICAgICAgZXZlbnRDYWxsYmFjay5hcHBseSh0aGlzLCB0aGlzLmNvbXBsZXRlZEFyZ3MpOw0KICAgICAgICB9DQogICAgICAgIGlmIChldmVudE5hbWUgPT0gJ3NldHRsZWQnICYmIHRoaXMuY29tcGxldGVkKQ0KICAgICAgICB7DQogICAgICAgICAgICBldmVudENhbGxiYWNrLmFwcGx5KHRoaXMsIFtdKTsNCiAgICAgICAgfQ0KICAgIH0pOw0KICAgIHRoaXMuX2ludGVybmFsLnJlc29sdmVyID0gZnVuY3Rpb24gX3Jlc29sdmVyKCkNCiAgICB7DQogICAgICAgIGlmIChfcmVzb2x2ZXIuX3NlbGYuY29tcGxldGVkKSB7IHJldHVybjsgfQ0KICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuZXJyb3JzID0gZmFsc2U7DQogICAgICAgIF9yZXNvbHZlci5fc2VsZi5jb21wbGV0ZWQgPSB0cnVlOw0KICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuY29tcGxldGVkQXJncyA9IFtdOw0KICAgICAgICB2YXIgYXJncyA9IFsncmVzb2x2ZWQnXTsNCiAgICAgICAgaWYgKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSAmJiB0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykgIT0gbnVsbCkNCiAgICAgICAgew0KICAgICAgICAgICAgX3Jlc29sdmVyLl9zZWxmLmNvbXBsZXRlZEFyZ3MucHVzaCh0aGlzLmVtaXRfcmV0dXJuVmFsdWUoJ3Jlc29sdmVkJykpOw0KICAgICAgICAgICAgYXJncy5wdXNoKHRoaXMuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICBmb3IgKHZhciBhIGluIGFyZ3VtZW50cykNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuY29tcGxldGVkQXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1thXSk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgaWYgKGFyZ3MubGVuZ3RoID09IDIgJiYgYXJnc1sxXSE9bnVsbCAmJiB0eXBlb2YoYXJnc1sxXSkgPT0gJ29iamVjdCcgJiYgYXJnc1sxXS5fT2JqZWN0SUQgPT0gJ3Byb21pc2UnKQ0KICAgICAgICB7DQogICAgICAgICAgICB2YXIgcHIgPSBnZXRSb290UHJvbWlzZShfcmVzb2x2ZXIuX3NlbGYucHJvbWlzZSk7DQogICAgICAgICAgICBhcmdzWzFdLl9YU0xGID0gX3Jlc29sdmVyLl9zZWxmOw0KICAgICAgICAgICAgYXJnc1sxXS50aGVuKGZ1bmN0aW9uIF9yZXR1cm5SZXNvbHZlZCgpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHBhcm1zID0gWydyZXNvbHZlZCddOw0KICAgICAgICAgICAgICAgIGZvciAodmFyIGFpIGluIGFyZ3VtZW50cykNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goYXJndW1lbnRzW2FpXSk7DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIHRoaXMuX1hTTEYuZW1pdC5hcHBseSh0aGlzLl9YU0xGLCBwYXJtcyk7DQogICAgICAgICAgICB9LA0KICAgICAgICAgICAgZnVuY3Rpb24gX3JldHVyblJlamVjdGVkKGUpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5fWFNMRi5wcm9taXNlLl9fY2hpbGRQcm9taXNlLl9yZWooZSk7DQogICAgICAgICAgICB9KTsNCiAgICAgICAgfQ0KICAgICAgICBlbHNlDQogICAgICAgIHsNCiAgICAgICAgICAgIF9yZXNvbHZlci5fc2VsZi5lbWl0LmFwcGx5KF9yZXNvbHZlci5fc2VsZiwgYXJncyk7DQogICAgICAgICAgICBfcmVzb2x2ZXIuX3NlbGYuZW1pdCgnc2V0dGxlZCcpOw0KICAgICAgICB9DQogICAgfTsNCiAgICB0aGlzLl9pbnRlcm5hbC5yZWplY3RvciA9IGZ1bmN0aW9uIF9yZWplY3RvcigpDQogICAgew0KICAgICAgICBpZiAoX3JlamVjdG9yLl9zZWxmLmNvbXBsZXRlZCkgeyByZXR1cm47IH0NCiAgICAgICAgX3JlamVjdG9yLl9zZWxmLmVycm9ycyA9IHRydWU7DQogICAgICAgIF9yZWplY3Rvci5fc2VsZi5jb21wbGV0ZWQgPSB0cnVlOw0KICAgICAgICBfcmVqZWN0b3IuX3NlbGYuY29tcGxldGVkQXJncyA9IFtdOw0KICAgICAgICB2YXIgYXJncyA9IFsncmVqZWN0ZWQnXTsNCiAgICAgICAgZm9yICh2YXIgYSBpbiBhcmd1bWVudHMpDQogICAgICAgIHsNCiAgICAgICAgICAgIF9yZWplY3Rvci5fc2VsZi5jb21wbGV0ZWRBcmdzLnB1c2goYXJndW1lbnRzW2FdKTsNCiAgICAgICAgICAgIGFyZ3MucHVzaChhcmd1bWVudHNbYV0pOw0KICAgICAgICB9DQoNCiAgICAgICAgdmFyIHIgPSBnZXRSb290UHJvbWlzZShfcmVqZWN0b3IuX3NlbGYucHJvbWlzZSk7DQogICAgICAgIGlmICgoci5faW50ZXJuYWwuZXh0ZXJuYWwgPT0gbnVsbCB8fCByLl9pbnRlcm5hbC5leHRlcm5hbCA9PSBmYWxzZSkgJiYgci5faW50ZXJuYWwudW5jYXVnaHQgPT0gbnVsbCkNCiAgICAgICAgew0KICAgICAgICAgICAgci5faW50ZXJuYWwudW5jYXVnaHQgPSBzZXRJbW1lZGlhdGUoZnVuY3Rpb24gKGEpIA0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHByb2Nlc3MuZW1pdCgndW5jYXVnaHRFeGNlcHRpb24nLCAncHJvbWlzZS51bmNhdWdodFJlamVjdGlvbjogJyArIEpTT04uc3RyaW5naWZ5KGEpKTsNCiAgICAgICAgICAgIH0sIGFyZ3VtZW50c1swXSk7DQogICAgICAgIH0NCg0KICAgICAgICBfcmVqZWN0b3IuX3NlbGYuZW1pdC5hcHBseShfcmVqZWN0b3IuX3NlbGYsIGFyZ3MpOw0KICAgICAgICBfcmVqZWN0b3IuX3NlbGYuZW1pdCgnc2V0dGxlZCcpOw0KICAgIH07DQogICAgdGhpcy5faW50ZXJuYWwucmVqZWN0b3IuaW50ZXJuYWwgPSB0cnVlOw0KDQogICAgdGhpcy5jYXRjaCA9IGZ1bmN0aW9uKGZ1bmMpDQogICAgew0KICAgICAgICB2YXIgcnQgPSBnZXRSb290UHJvbWlzZSh0aGlzKTsNCiAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCBmdW5jKS5mdW5jKTsNCiAgICB9DQogICAgdGhpcy5maW5hbGx5ID0gZnVuY3Rpb24gKGZ1bmMpDQogICAgew0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZXZlbnRfc3dpdGNoZXIodGhpcywgZnVuYykuZnVuYyk7DQogICAgfTsNCiAgICB0aGlzLnRoZW4gPSBmdW5jdGlvbiAocmVzb2x2ZWQsIHJlamVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHJlc29sdmVkKSB7IHRoaXMuX2ludGVybmFsLm9uY2UoJ3Jlc29sdmVkJywgZXZlbnRfc3dpdGNoZXIodGhpcywgcmVzb2x2ZWQpLmZ1bmMpOyB9DQogICAgICAgIGlmIChyZWplY3RlZCkNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVqZWN0ZWQnLCBldmVudF9zd2l0Y2hlcih0aGlzLCByZWplY3RlZCkuZnVuYyk7DQogICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IHRoaXMuX3JlaiA9IGo7IH0pOw0KICAgICAgICByZXRWYWwucGFyZW50UHJvbWlzZSA9IHRoaXM7DQoNCiAgICAgICAgaWYgKHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCkNCiAgICAgICAgew0KICAgICAgICAgICAgLy8gVGhpcyBwcm9taXNlIHdhcyBhbHJlYWR5IHJlc29sdmVkLCBzbyBsZXRzIGNoZWNrIGlmIHRoZSBoYW5kbGVyIHJldHVybmVkIGEgcHJvbWlzZQ0KICAgICAgICAgICAgdmFyIHJ2ID0gdGhpcy5faW50ZXJuYWwuZW1pdF9yZXR1cm5WYWx1ZSgncmVzb2x2ZWQnKTsNCiAgICAgICAgICAgIGlmKHJ2IT1udWxsKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIGlmKHJ2Ll9PYmplY3RJRCA9PSAncHJvbWlzZScpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICBydi5wYXJlbnRQcm9taXNlID0gdGhpczsNCiAgICAgICAgICAgICAgICAgICAgcnYuX2ludGVybmFsLm9uY2UoJ3Jlc29sdmVkJywgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlcik7DQogICAgICAgICAgICAgICAgICAgIHJ2Ll9pbnRlcm5hbC5vbmNlKCdyZWplY3RlZCcsIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IpOw0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyKHJ2KTsNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICB9DQogICAgICAgICAgICBlbHNlDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyKTsNCiAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdyZWplY3RlZCcsIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IpOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQogICAgICAgIGVsc2UNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwub25jZSgncmVzb2x2ZWQnLCByZXRWYWwuX2ludGVybmFsLnJlc29sdmVyKTsNCiAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLm9uY2UoJ3JlamVjdGVkJywgcmV0VmFsLl9pbnRlcm5hbC5yZWplY3Rvcik7DQogICAgICAgIH0NCiAgICAgICAgdGhpcy5fX2NoaWxkUHJvbWlzZSA9IHJldFZhbDsNCiAgICAgICAgcmV0dXJuIChyZXRWYWwpOw0KICAgIH07DQoNCiAgICB0aGlzLl9pbnRlcm5hbC5yZXNvbHZlci5fc2VsZiA9IHRoaXMuX2ludGVybmFsOw0KICAgIHRoaXMuX2ludGVybmFsLnJlamVjdG9yLl9zZWxmID0gdGhpcy5faW50ZXJuYWw7Ow0KDQogICAgdHJ5DQogICAgew0KICAgICAgICBwcm9taXNlRnVuYy5jYWxsKHRoaXMsIHRoaXMuX2ludGVybmFsLnJlc29sdmVyLCB0aGlzLl9pbnRlcm5hbC5yZWplY3Rvcik7DQogICAgfQ0KICAgIGNhdGNoKGUpDQogICAgew0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lcnJvcnMgPSB0cnVlOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWQgPSB0cnVlOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5jb21wbGV0ZWRBcmdzID0gW2VdOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lbWl0KCdyZWplY3RlZCcsIGUpOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5lbWl0KCdzZXR0bGVkJyk7DQogICAgfQ0KDQogICAgaWYoIXRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCkNCiAgICB7DQogICAgICAgIC8vIFNhdmUgcmVmZXJlbmNlIG9mIHRoaXMgb2JqZWN0DQogICAgICAgIHJlZlRhYmxlW3RoaXMuX2ludGVybmFsLl9oYXNoQ29kZSgpXSA9IHRoaXMuX2ludGVybmFsOw0KICAgICAgICB0aGlzLl9pbnRlcm5hbC5vbmNlKCdzZXR0bGVkJywgZnVuY3Rpb24gKCkgeyByZWZUYWJsZVt0aGlzLl9oYXNoQ29kZSgpXSA9IG51bGw7IH0pOw0KICAgIH0NCiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkodGhpcywgImNvbXBsZXRlZCIsIHsNCiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICByZXR1cm4gKHRoaXMuX2ludGVybmFsLmNvbXBsZXRlZCk7DQogICAgICAgIH0NCiAgICB9KTsNCn0NCg0KUHJvbWlzZS5yZXNvbHZlID0gZnVuY3Rpb24gcmVzb2x2ZSgpDQp7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpDQogICAgew0KICAgICAgICBhcmdzLnB1c2goYXJndW1lbnRzW2ldKTsNCiAgICB9DQogICAgcmV0VmFsLl9pbnRlcm5hbC5yZXNvbHZlci5hcHBseShyZXRWYWwuX2ludGVybmFsLCBhcmdzKTsNCiAgICByZXR1cm4gKHJldFZhbCk7DQp9Ow0KUHJvbWlzZS5yZWplY3QgPSBmdW5jdGlvbiByZWplY3QoKSB7DQogICAgdmFyIHJldFZhbCA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyLCBqKSB7IH0pOw0KICAgIHZhciBhcmdzID0gW107DQogICAgZm9yICh2YXIgaSBpbiBhcmd1bWVudHMpIHsNCiAgICAgICAgYXJncy5wdXNoKGFyZ3VtZW50c1tpXSk7DQogICAgfQ0KICAgIHJldFZhbC5faW50ZXJuYWwucmVqZWN0b3IuYXBwbHkocmV0VmFsLl9pbnRlcm5hbCwgYXJncyk7DQogICAgcmV0dXJuIChyZXRWYWwpOw0KfTsNClByb21pc2UuYWxsID0gZnVuY3Rpb24gYWxsKHByb21pc2VMaXN0KQ0Kew0KICAgIHZhciByZXQgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzLCByZWopDQogICAgew0KICAgICAgICB0aGlzLl9fcmVqZWN0b3IgPSByZWo7DQogICAgICAgIHRoaXMuX19yZXNvbHZlciA9IHJlczsNCiAgICAgICAgdGhpcy5fX3Byb21pc2VMaXN0ID0gcHJvbWlzZUxpc3Q7DQogICAgICAgIHRoaXMuX19kb25lID0gZmFsc2U7DQogICAgICAgIHRoaXMuX19jb3VudCA9IDA7DQogICAgfSk7DQoNCiAgICBmb3IgKHZhciBpIGluIHByb21pc2VMaXN0KQ0KICAgIHsNCiAgICAgICAgcHJvbWlzZUxpc3RbaV0udGhlbihmdW5jdGlvbiAoKQ0KICAgICAgICB7DQogICAgICAgICAgICAvLyBTdWNjZXNzDQogICAgICAgICAgICBpZigrK3JldC5fX2NvdW50ID09IHJldC5fX3Byb21pc2VMaXN0Lmxlbmd0aCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICByZXQuX19kb25lID0gdHJ1ZTsNCiAgICAgICAgICAgICAgICByZXQuX19yZXNvbHZlcihyZXQuX19wcm9taXNlTGlzdCk7DQogICAgICAgICAgICB9DQogICAgICAgIH0sIGZ1bmN0aW9uIChhcmcpDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vIEZhaWx1cmUNCiAgICAgICAgICAgIGlmKCFyZXQuX19kb25lKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHJldC5fX2RvbmUgPSB0cnVlOw0KICAgICAgICAgICAgICAgIHJldC5fX3JlamVjdG9yKGFyZyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0pOw0KICAgIH0NCiAgICBpZiAocHJvbWlzZUxpc3QubGVuZ3RoID09IDApDQogICAgew0KICAgICAgICByZXQuX19yZXNvbHZlcihwcm9taXNlTGlzdCk7DQogICAgfQ0KICAgIHJldHVybiAocmV0KTsNCn07DQoNCm1vZHVsZS5leHBvcnRzID0gUHJvbWlzZTsNCm1vZHVsZS5leHBvcnRzLmV2ZW50X3N3aXRjaGVyID0gZXZlbnRfc3dpdGNoZXI7DQptb2R1bGUuZXhwb3J0cy5ldmVudF9mb3J3YXJkZXIgPSBldmVudF9mb3J3YXJkZXI7', 'base64').toString());");

	// util-pathHelper, used to settings/config by the agent. Refer to /modules/util-pathHelper for details.
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJy1VFFP2zAQfo+U/3DrA0lZSEu3J1A1dYVp0VA70bIKiRc3uaQeqe3ZDqFC++87N8kAMWli0vIQK77Pd9/33TmDQ9+bSrXTvNhYGA1HQ0iExRKmUiupmeVS+J7vXfAUhcEMKpGhBrtBmCiW0tJGIviG2hAaRvEQQgfotaFe/9T3drKCLduBkBYqg5SBG8h5iYD3KSoLXEAqt6rkTKQINbebfZU2R+x7120GubaMwIzgir7ypzBg1rEFejbWqpPBoK7rmO2ZxlIXg7LBmcFFMj2fLc6PiK07cSVKNAY0/qi4JpnrHTBFZFK2Joolq0FqYIVGilnpyNaaWy6KCIzMbc00+l7GjdV8XdlnPnXUSO9TADnFBPQmC0gWPfg4WSSLyPdWyfLz/GoJq8nl5WS2TM4XML+E6Xx2liyT+Yy+PsFkdg1fktlZBEguURW8V9qxJ4rcOYgZ2bVAfFY+lw0dozDlOU9JlCgqViAU8g61IC2gUG+5cV00RC7zvZJvud0PgXmpiIocDpx5eSVSh6H23OJXZjehotdxBG4ZRa7f09VZ3/cemtbwHMJmD96MQVRlCQcHjygHaZHuuWNUVd5SRRiD0jIlqXFaZ2E/NiTWht2eKpkllVsYjyGouXg3CuADBDc3AZxAMAjcGHZJm4Sxkir803ZlWg2vLdFkfJpyn4aYt6m/Sy5ezfhnN9TOub2psbFMW7OiAQiDOOi/tK2DHsdWXsga9ZQZJM9QZN0xvEc6CQ+/ObaSq7UbU1GEw6jdKlEUdCGP4H3/1LF5Lu5tc3L0yNYtWBr8SzP/xeHXN3H0H9rhFo220qJ12cX2bdrKrCqRvKXfp3Uqu0tx6qK+9wtCYKEt', 'base64'));");

#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'));");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('eJytV0tz2kgQvlPFf+j1RSjL8rJCEVM+EOxUqPWCC4FTOQ7SCKYsZrSjkTGbyn/fHkkIiad2KzogNNPzdffXL6n5oVoZimAr2XKloNNq92DEFfVhKGQgJFFM8GqlWnliDuUhdSHiLpWgVhQGAXHwlu7U4YXKEKWh02hBTQvcpFs3Zr9a2YoI1mQLXCiIQooILASP+RTou0MDBYyDI9aBzwh3KGyYWsVaUoxGtfI9RRALRVCYoHiAT15eDIjS1gJeK6WCu2Zzs9k0SGxpQ8hl00/kwubTaPg4th//QGv1iTn3aRiCpH9HTKKbiy2QAI1xyAJN9MkGhASylBT3lNDGbiRTjC/rEApPbYik1YrLQiXZIlIFnnamob95AWSKcLgZ2DCyb+DzwB7Z9Wrl22j2dTKfwbfBdDoYz0aPNkymMJyMH0az0WSMT19gMP4Of47GD3WgyBJqoe+B1NajiUwzSF2ky6a0oN4TiTlhQB3mMQed4suILCksxRuVHH2BgMo1C3UUQzTOrVZ8tmYqToLw2CNU8qGpyWs2YUpVJDnygmrW8QEgCxGpJM70nTqR0lRWK17EnXg/IDKkNdx6JmplVis/kri9EYlhUC/Eh3v48bO/X/VCXEkjVDO80DDzmy5uemFDBJTbW+7sgOtgyEVBcrFVNJxS4ubWXBF+xRX07x4+R55HZYP4vnBqXSt/lKvTUp2ClAhSsf4uF2OCiBuT9zCxYRVvJ3uZOYn9Ev/F9ntufW9WHVp16Fp42yliHtSy7fjUHAu33X16rLXMhhI2Jhpf1tpd/TAPMLJDgnSb8Ns9GB8H1oNhJkAp7fpSKyk2UDMiLqkjlpz9oyuBcSK3kMQ1I/LnKdfGs9Ke7ZiMHds9NHzKlzpkx47ddtCxbsvMu58dC3VV1xDIynlurOi7kbrbsj628Lrgsm5LBJ4f45aU91LfQuxGziqnsEC3VaT7WIeDxIPRthzjTtN120FO1X5bX0nCNxKSkS7jvdc1+kWZBWp97R/C9rpdK8HtWmVwUfoKrks9EvkqxpzzVy42/DKobgwe49S9AJzlS3oYawR7APETQm3MNAQ6zW8ny/mzZweuGzfA+wuZA7/jeDtZkTu8QvJmRXxY62eN3Fl5Ke0z1Djvs6cSia/NL/aiaD19GRzQX+BpuKLOqx2tn8V1Ziz86VpFnjWzE28oXB2bva2F45Z56syI42wkvu4fD0SR88d7J4/PeWmAdsfM3N6V6bHo9bZ4tmpbn/NVm3bDYp5nkThj46eO2T9ZQUMqlR7FRNGZHo77ND7rba8kVFpR53Buy5qkccrmD6KeBpVvxFZEqrJlqsE+dUu1v84uPkn3+1/xabfKsno9QJb1awJk/ZdAlw6Q1ft1AWq3D6N9bpAUpXYTNx0tgPoj/XaKbSx+R53suvFfZMmcOzBQ15mea12s6MvTqOj9ENXrUZakStZR9FvG5VQ47hv5yUIi/OWKObqHOnsEbP3cx28Xnqxiy9KP+oTHZKgAz8itucfU/X7lHo2iQo4cjhqUj4cM3rPxcsWXHFoqmbP5ULnGLeRGy7xkzjFgbN3xckljMSv2nl21/ISa/YviAvMFX4sugzxsnmJVCHbC82Jeoe+OL0KaOp+bcfobKc0ovRq/Fa2FG/m0gR9xQipde/GHUZyD1cq/OIedMw==', 'base64'));");

	// Windows Message Pump, refer to modules/win-message-pump.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('eJztWt2P4jgSf2+p/wfvPCywYmmaRSfUrb5VGjJ0NIFwSbqZuReUBgO5DUnOCQPcqO9vv7LjBDsJX72zd/ewCAlwff2qXC6XHW5+ur7qBuGOuItljFrN2w7S/Bh7qBuQMCBO7Ab+9dX1le5OsR/hGVr7M0xQvMRICZ0pfHBKHb1gEgE3ajWaqEoZPnDSh9r99dUuWKOVs0N+EKN1hEGDG6G562GEt1Mcxsj10TRYhZ7r+FOMNm68ZFa4jsb11ReuIXiNHWB2gD2EX3ORDTkxRYvgtYzj8O7mZrPZNByGtBGQxY2X8EU3utZVh5b6M6ClEs++h6MIEfzPtUvAzdcdckIAM3VeAaLnbFBAkLMgGGhxQMFuiBu7/qKOomAebxyCr69mbhQT93UdS3FKoYG/IgNEyvHRB8VCmvUBPSqWZtWvr8aa/WQ822ismKYytDXVQoaJusawp9maMYRfH5Ey/II+acNeHWGIEljB25BQ9ADRpRHEMwiXhbFkfh4kcKIQT925OwWn/MXaWWC0CL5i4oMvKMRk5UZ0FiMAN7u+8tyVG7MkiIoegZGfbmjwvjoEjZ8mXUXXx8PeyDS66AG17zlhMPnbs2bDCGpum83b1n68qxuWCgQ23uTj/QGM8HmoViZ97GPiTgcOiZaOV6GpdH01X/tTCgqNXX8WbKIBeA+ejNarsBqEDG7t+upbkgg00xoT4/UfeBprPVBe2bj+z6tE5OcQZCr3IidXAIz8G6dScBjCEWPyHLteJMLEX7EfR5Vaw/VhQtw4qlJdNS4pSjWmBDsxVqlAtbLc+LPKaTZMSEDO4ONOnaNx68Y8mHvPV9ECnOoPGl3G+uIQl6Z/FUZGgQtlgVjuvzB6gMlFv6JWB92hdqcmBe83yCTs/dIS9Qwhgb7iEQm2u2rlE2dozDyvUi7bWIUgTsfKyYnWAY6Xwaxa6eNYd6JYlUJ0SmIQzNYefoIc97BSiAPUJ3LEhWdGLnEgkTsAnxNlKMmvJIvV7bhcnyzSw/OEH9BMz5SAqhPsEqmzBNwodOLpki+rs4zQoF7APgqilF85h9/EC6idmHQ9J4rOjJSFYx6pIDqLfxlszg+STRw/8tjAftFJeQRre0rhXrCm2nRNdZqS+VRNeV5l1KXrRzHbOx/y6Z9P+Gpm4OZGVjL1nRUuxVsZwKY7Ho/ZBFTKATLpzRnidfQNdvgZvkMxWWP0Vq4OvoSQ44k+8IFvBX0veHW8ruN5r870t2r7qPCJoMXB43o+x6Raa9D9HD9D8/NLS1erMtskgjk65nMjTOYy00Z7k5ySHiZ4fmjemzDvf2nXkUyuCQCPu3m2/c7lNrLM+r1etqiXrd/hZeBDoZGmH1IpawYCf+zPaFWsbum+Wkdb2NDqaBM6xFnVkcc+a4l+3huk+zrVDssY2rIHNHe8CN/v6e4cJT6uwsaEKkY/PCB/7Xnoxx+RRGi8OB71dZv+qO21CAaThYds2gHTJhgas3Ukk0U8dIncy2QKeZaucyt2SJyWbBrDHHMKkTYD+xaBLkH+/Y4FiuJNg3XHP5Mxj495hbHJEm+z8XxyxIEFza6/gC4Hbyu1TIY4m1Smjmik7hCfr1nmxB2497bflkW/AaqJ49R57teE4HhNfIC2xsU2SJzJVDyZwprMkJskPlFjjHze908h7ZC0Ayt19Iqnayc90nDbaONE7KyzZCV3VlTM0k5wI91l5P294UQ7f1qlyXwkp++L6sPGPppyBZS5oJ/3q9kSqkIca0W2krhkmbU301D9mZCHVFWJybf84Jv8E8PqOzkrNHhE3Gh4OSkkP32RZF3yzClhYH7kwB9BKXylYCGtcvXhIVcfaLGChWAvAeqsWqP0/Kzn+5tk3mF2qIgGQqdLiZh5C7pVOvSYOSfBCgVrguRWUwF22secLDsXFp7/09Lzvy8zf5aWP0vLWaVFbjyyFVmDRTOZ4df1ot8FKKmQkL3SWaW8nsi9Wi0/Q8XeiEL4gQn5+xMwS6n0mgXYU9sHWCA8397uJTdPqm1sWJ5Sp89g4xZyBs4QbOBtFO88HGUL9TyDghy7vKKvTgcQUNu0HgfhAA648Bl4/I7qcmwb2na/B5wgyNB1GD6GjpYca/JomD3VvBzR9lIkW4rgXROzu9TU7t2m4CAaLy+PMRNCt833GV1iduF+odVUKjO7N1wQz10tiQVAZCsvFPWLVkE5d+6IXC9pDU7oj93Yw1k39Suix8fi1cLZmgq3Dud5mS2n89i357Ht3hEPlnTnqU8ypY6a2Tu398q1v7o8fRKiqb1Mj7h5dQdkeD1kl7OIXUDTxwxLdzbDPtrkCuOpcCRdZHIXXkeVY0oLPRl9vRWHih3BEUdK4540/GhZYu+4H+zqHzrTMqQHrUW05WaPOc5wMGuH5Pu1vRJ62ZFu/qLqQhsgtRbCTa9YVI53HvX9I4b0a9J0stQstIqHTztw2Eqarr8WcrBk2gpBzN/afpeyCE4d6qVO4CvFmL9+/29iPIKzFOvppKSvQmNeOviebj05Qy3gNOSgCn3OWEmPSWckg/Rg5LtEmeb090yFA9cCzmtA4oPRnmEPx/gwwItLFXtYSNdp4aR8TLZwe0vwKviKFc/TqU8+JlHhNveSYljynID2CRdm2ptwgVyFveVQKxbFQcjOXVlRlc5dlCyW04S99Dy1r36Hq5xUUcVnZVWxdvJH67yIll37Bv4UZ/MnZGTqZGGOpl4QYaBLIUvPmuIuwhhFj7nkH+8y+9fAH+Dz/WmnE9X/lvWW75Y8X4QNmCXMij2Hg845hBVMD2jFfzDc57kaCY/Fz3QFe9mJ7k447tXpcFcZ0X+NJONdYfxJ03t0tJ2cXYXRsTbsGeMiTddGjG6qiboWJ0owKJelPerasG8xrragoqdZyqOuMrscJCfo/Y+mMlATmO09oW8az6NkNLHHRp+srmno+h3/20gRhdY1hlqX0luiCwPlszbQ/p6YuS0hPBqfubHbPU0bZkKyNk7YC7WKSIwX1dSV0Yg7LcqPjFHiW0cctSSN7f34F2ugDp/5eCcbt5VHyzZGEmwJgf2kdT8J0RV02ppegutFoxPIuG+lcTHqSST2C+RIvqrb8oxVP0+Ublcd2R8BhrWHcZuYo+TRaJ+MEnIgQqapQ1vt9dVMtCVQjcHIsDSb+1eaq4wNVHy2n1R9lGlpi1qGNvg8UiDn7UJmAAMk7sDoKboYX+ZDyqArX1QzC3KnDAOwGM+2aeuF7KdE9aNdmCE+nszHo2KmDG2RwTZNVenBOpTE88YHPS0rBU3ufqpiaChdW3tRbLWwYBlVGz6ppmYn+KXFmLEkkRsatvbxi4CjXcAxNCBKmql2abV61OyBMhITLdVoav2nLB63eUIhIJKorecC0ioLiGUrttYV0qolKrENQ5dSkk3qnjoaGJY4X52MZCpDS8ojpjolJzqlZL4Vl9d/AEFbK3M=', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'));");

	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzVV21v2zYQ/m7A/+HmD5XcqkqXFQPmIBi8xG2NJHYXpQ2COAho6SyzkUmXovyywP99R73Y8lvbtWix8oNFkce755473dEHT6uVEzmeKx4ONRy++PUPaAuNEZxINZaKaS5FtVKtnHMfRYwBJCJABXqI0Bwznx75jgPvUcUkDYfuC7CNQC3fqtWPqpW5TGDE5iCkhiRG0sBjGPAIAWc+jjVwAb4cjSPOhI8w5XqYWsl1uNXKTa5B9jUjYUbiY3oblMWAaYMWaAy1HjcODqbTqctSpK5U4UGUycUH5+2TVsdrPSe05sQ7EWEcg8KPCVfkZn8ObExgfNYniBGbglTAQoW0p6UBO1VccxE6EMuBnjKF1UrAY614P9FrPBXQyN+yADHFBNSaHrS9GvzV9NqeU61ct6/edN9dwXXz8rLZuWq3POhewkm3c9q+anc79PYKmp0bOGt3Th1AYoms4GysDHqCyA2DGBBdHuKa+YHM4MRj9PmA++SUCBMWIoRygkqQLzBGNeKxiWJM4IJqJeIjrtMkiLc9IiNPDwx5g0T4RgZC1Gc4j+16tfKYRWHCFJGq4RgeF0fZkj/kUUALOde2lS7cj5X0yQmr7uIM/VeUGXa+5KKY3FpTLgKurDt4BrVez5vHGke/HfZ6fT/AgGtzqubArZW/Ww5YByiSkZk8+olSKPTCuquXUbixDmSi6aEIkGUdrS9LYVsB04xULF20/To8ptmbnnp2DL6rpUdhFaFdP4LFlgFUarcmo2hDfMq4bs24ts3yisGIC4wJ4SZol8yO7LobU9C1bfVUT1iFwvSMGw/5wGjbeC2Um6SwjQVuUjqVqWc7efwKBFo+UMgJQipzy+8Km7A0WIg+4JzksgMlg2WRCYsSXAl9kFykmnJ/StKUO7ek8I6E00P51iJ70G6iiEl6mkOLrVS06ewqGQvxNHrLXE31bx6Pl8edzPB6Sv/AHCYk6ynswArVz5TOZXoDjFDjVoB+MLUZipTIHRT/ZNyW2EVhupbHBnghA/RQTahg23H27LARlj+JnGXi77nC0DSoOZF8Td0tjc8+gTdnrRv3XPosuqDmSkWBCPRuvKvWRa93kvF4IoVWMvJQ01I2p8gQqr6UtNRBPZXqodezKGYlcA6IJIqMumzN2kweHn+Ra1nrCcuptO7D0Uouq1mPlJcDlkS6AZaQAi0oehbJ024mRQrcvxNU84ye8DtSYZIEfKb9IdgfHzDNgvVSRpDcHDQcH+/njG4eX5wT5OxWD9iXBqfLD/nHJ0p9vRmkPNmz9f612Pw26KKkmdI2ffvs+1aeeJhQbZiKZekpFtLao9JfU4dSJL8cm6T/M52XikTDevG/urKkmny6DcoI3UiGdllT/eizJYoPYJUo969RoOL+BVPxkEVE8Fu6CGhUHv8HTTa/hCdPVtGQJgRMUYzraarPfn9prQI4kkFCmOgqLJWmi8pWBu8sio3dy87q2O4Pp7Fn3Snyq1FMnO1y1dheypM1owmjGD/j14ZvZuT3mUYxcfI7TCN/Oqum21hNna/l5Wu4CXNAYQ7oW7gq+Mreuv0P6GtTCanAvFWS/sjoub3OnQM1U0+MpprzKRob5ca7vrshvFYtPyNnRnr33d+Qym3lexXT7tg4ZopPNnuf3n7KV+7yiOl/uGk+k/ru/T1+muEz+tN52NgvYEbRxiyv+ap1f9E9bd13WlfX3cuzvZCK0VfIHj4hU7Ty/wrgmwwvdi8XVia7dO84k7f82Q7W9zC+9KPTvbxonu90YsNQ6TWt24t/ATXtbrU=', 'base64'));");

	// win-dispatcher a helper to run JavaScript as a particular user. Refer to modules/win-dispatcher.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('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', 'base64'));");

	// win-firewall is a helper to Modify Windows Firewall Filters. Refer to modules/win-firewall.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'));"); 

	// win-systray is a helper to add a system tray icon with context menu. Refer to modules/win-systray.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-systray', Buffer.from('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', 'base64'));"); 
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
	char *_servicemanager = ILibMemory_Allocate(30665, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 30664, "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", 16000);
	memcpy_s(_servicemanager + 16000, 14664, "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", 14664);
	ILibDuktape_AddCompressedModule(ctx, "service-manager", _servicemanager);
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'));");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('eJy9V21v2zYQ/m7A/+GWD5XUuHLWDQNmzwNcJ22MtM4WJSuKpiho6SQRkSmNpPyCIP99R0lOZUd2XGwYP9gmeeQ99/Yc3X3Zbo3SbCV5FGt4ffLjrzAWGhMYpTJLJdM8Fe1Wu/We+ygUBpCLACXoGGGYMZ++qp0O/IVSkTS8dk/ANgJH1daR02+3VmkOM7YCkWrIFdINXEHIEwRc+php4AL8dJYlnAkfYcF1XGip7nDbrU/VDelUMxJmJJ7RLKyLAdMGLdCItc563e5isXBZgdRNZdRNSjnVfT8enU28s1eE1py4EQkqBRL/zrkkM6crYBmB8dmUICZsAakEFkmkPZ0asAvJNRdRB1Qa6gWT2G4FXGnJp7ne8NMaGtlbFyBPMQFHQw/G3hG8GXpjr9NufRxfn1/eXMPH4dXVcHI9PvPg8gpGl5PT8fX4ckKztzCcfIKL8eS0A0heIi24zKRBTxC58SAG5C4PcUN9mJZwVIY+D7lPRokoZxFClM5RCrIFMpQzrkwUFYEL2q2Ez7gukkA9tYiUvOwa54W58I0MfJ2hiidpgOPAdtqt+zIScybJsRoGYFn9cklRfP0Y7EymPiF3s4RpAjhzyu3qoBk+I+xWwkW+tHrbywGTCy7q62ZoudpcuN+crjEFU4JURdy2POM6PGWaeTqVaDnuSCLT+IgRl+j/wSgtj8Fyg6nVgXs6zYJLkax6pDRHeHD6T1WVpj/q0Ymiu5OUBSOU2kTCKLmHLFz2CJL7DvWbPAxREiRMQuNNI2g5HciYUlksyfQeWDEPAhQW6XQj1Be4Omcqth1Xpx7lmIhsK8altQ3oYXNKuv3YRmevv7bOTMnou/52KCgOP73ejkS3C2+5VBpGMfp3wMtaJb+PUmGKWBXzImFO/9cYuhIp5Xw6YpYolEVEnUNDajTPSfG+cDUcI/vtufN0vcG2Rh88I2/G9yTb/D/JqPV4aF5uzrADLDH+FXmSHK6uYanwOAzKm+DFi2K2FbYy/SzHgR9KucMjVHp7foCHHp4vQ/iXdRhgyPJE93ZLVRcQ6lwKsOnbQH1ooHA2wy0CF7REtn794J1TShghD+WcGoGRre7noW3EBoOaF2s2lKS/i/MbDN7DLGYQu5yJfIb0SilbncTINNiV6dCK2l/FNwukmwQ9NgR13VxWfFO7qLnA6bZ6KRGMV2sFjSEuvMQD46R6G9wheYerHTuKMPrG159JnXt+cfbJfZ/6LPlAjxgu6KH1uDzKpUShbxTKL7tYipkCerq3iM3Tyy6j+q08St1ugiKiRvc7nBxeC6SpcFfk/pmjXBF92NVtKuahtolcLa96Kt3eXmYowCv2dzKKebHY5Ce69qRvHAa/GS2uyqc0URXK/vExzb6fX3ay6zPnzDC0UoR6ACWLuKFMZ/aG8TuC1+yD21uLnhU14z7TxxeSLrPIdCZrStXwy8/WEz7eYfqBpphR1fa2+h1hqY9tDmoaOxrDM1trSlzuMW+PaTtuPrxr1CvDoWdB5SPrA5U2DCMqO6vfdLbJI83MbEZR7yWP1rmmWno1Y4Ie6JJiXv1ycU14Ffs28ssaq6EhVkJ9KlRUl9HPy/riVF2V3nVlwfExP5wAiP2r85/5F/rPlZnENz3FdgaD7QfY99drZVRNhfjWeZrGvtw8LA+2b3hobKMGxmMfnaVBniCZSX+etdrsBf3tbVd9a6GPoqVR7dY/IoblHA==', 'base64'));");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoyQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO5T1QcmO064uick3H4/zZsjByTo2JDd6JSyQS2LgeyEMMFot0Wg8KCFKpyDSEDGL56DcBNdvUxqxGijy5FPsFohEFwlYy3MZu0ybFbm8JPRRqPN3lLwnjE7x49NpLnKYTil5U8d4Q+jbD1e3n65pREaE1W6Sx5RFfvO02sSAg5OsUIkTWpE0dvGfsUolGJYsCvVfNDh5HpwQ/HxaEtR490tkZAfguDbHTH8jFxF5Jm4hLC+UXYjMVR7GyNYVRo3JtrVlaIbsdi4MxOnXW+XO3328YWdRRH4noe+f8dvm6Ck0nq0UCbCLoc8cWV9E4xaYxxupY18NVUhZbTiz2f1TsfZfC/zry92E57GxwHwY7vQXZ4Sas6h2XFFMYpcsCINoz1lJpNIFnxlYMnqr1rHEkn0Gm2uFCvoMCYg1pLT26r+KbCfMoWxPT/shLKsY4EHbQrr33Z8j2onzmvWwRBzm+9Tl26+3LwAK5fXa1nVDC4Th4XpX20Cn3wswmyvfOkw/LIfYJbDuShWPy1cWHuu+ZI0xQyJDBCyb4J5m2ZV23Cwsy4Ulhq65oks+w3C48UySVToitMyDDjGiLGBE/OY26BCflm9YL7B9KXh/iRRIIpwIChyNeII94eBaKwVl0uwZZegWo2YybHvaqDxxhNJkZ4Z5tZyjFh2k0BTcm3lJo00wA8IYHSio9CXvByK8oPtEatsTeama3UwKl3xB/bH/UWQZGJ6hG1b2oi3bT2QbVhcn6rvztg9F1lrHUuqk1NayFmHPBOH80QgHzVCqkV7CQ3LWN1jyROcbhnbDdsZ0mJfuPCDc3fa6CKSF4yrxgjpcdwMrvYYrKT8K60CBsVVBX9DJIbyv6hFZHddHD3xEIYf096oyeqr4v4r4RTX8khJeVEFwNHs62LazpYKE7wjXjh4c/n5yOW+47Vza1sXGsXb8YftbLYFLPWf0Hz+h8ETI32AXpByZ3sAB57w54LnUD7HkM79RWIePDGLB3YsV6MKxvSIGBezE+qriBwnEab/s4sQFQcNw/qsfJDN4Eo41pzEk52dnZ22tg0FfjzXMBAekW4Dqj/QWsJ+oH8fllK+mMY7w3dCn3yZ39+T6bjK5ub6/+fAvbd4pe/yCI6xCQYps8R5ANaC3/euasJBACjYxInfaWNrJtqG/x2t9nFWY3joM38n7wDuim5jDSmPbZPqn0/Ln1wt+AOZR/UJ7WPlceB1XK32l0wLjwFOujbPl9VtqfrT7g1fuDzEsSd8=', 'base64'));");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'));");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'));");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	duk_peval_string_noresult(ctx, "addCompressedModule('notifybar-desktop', Buffer.from('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', 'base64'));");

	// proxy-helper, refer to modules/proxy-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('eJztXHtz47YR/7ue8XfAMUkp5WhKctppa0VpHZ9v4uZiX092rzeW69IUJHFMkQofljSO+tm7C/ABPkSCqu4m0x7vIYkEdheL3cUPC4Cdrw8PztzF2rOms4Acd3t/IkfwcdwlF05AbXLmegvXMwLLdQ4PDg/eWCZ1fDomoTOmHglmlJwuDBM+oica+Tv1fChNjvUuaWEBJXqktPuHB2s3JHNjTRw3IKFPgYLlk4llU0JXJl0ExHKI6c4XtmU4JiVLK5gxLhEN/fDgQ0TBfQgMKGxA8QX8mojFiBGgtASuWRAsTjqd5XKpG0xS3fWmHZuX8ztvLs7OL4fnRyAt1rhxbOr7xKM/h5YHzXxYE2MBwpjGA4hoG0viesSYehSeBS4Ku/SswHKmGvHdSbA0PHp4MLb8wLMewiCjp1g0aK9YADRlOEQ5HZKLoUK+Px1eDLXDg/cX1z9c3VyT96fv3p1eXl+cD8nVO3J2dfnq4vri6hJ+vSanlx/IjxeXrzRCQUvAha4WHkoPIlqoQToGdQ0pzbCfuFwcf0FNa2KZ0ChnGhpTSqbuE/UcaAtZUG9u+diLPgg3PjywrbkVMCPwiy0CJl93UHmHB5PQMbEUsS0nXN1PafDWc1frVvvw4Jl3hwkkXJvqljNxey31bEbNR2SJ5Szqk9s3F5c3/7hT0VZ4jU6HsFLk3HmyPNeZUycgfzc8y3igts/LWJNW1GUtdeKrbZ2uQMX+cO2YLbVDA7ND08pqu81rRSJViTW13QfDJkJt4tMAO9xnIv4GKz8ZHjFnlj0mA5KIwW7cLzzXhC5hElHzNdg5yPNgOR1/pmrkVoWPu4QOq6L7wdgNA/jwgJyq9rO3Xaeljo3AgNqJsltmmzwzT2K1Xg6IqQfuEEzMmbbafbIpcrAcHQ0X5TQCktcQ+YWAiS+A/y9EJS+JAlTV0chRifovFe4Zy0dy9Bq/q0oV7We16ik6p+sHA0XpE4gx/AvEBM8x5pTfNXx/6Xpj9kNtV5ICu25Zg17f+vbydf/lS6tdx7tWOG5XX1r/7vzziw5qGIwEej6koFGJuj54YADVtcB9BDfRlAHoSo4nr3HbuxsMlB+ur9/ev3139Y8PSm2TsFVEohBcC/TLgR8+gMWgkMcvbepMg1nKuy0lLSNlOcGEKFGk/cpXNE5esv6DR41HmbKb2rZV9ouyUUcOBIZg5OStdmlYwTk8aSX3rQm4Vc4fdfCoeatNXqBfxtb4HH2WRBEy+I68vrq5fHXCvGgLuYQlXh4NQs/Zyjopu+Gha1MIkqB4HE31sWxgTCp0WJ/dQ3gLF01CZELgfyMgKklALNVMFP1UBTpUfY6d/FgDNPCoEebjkQdz90WnuGf1FZSJ+QqWvT2+Azk2o8Qk85ZbNMmdrEvnEqrI4LabqrbG0Eqq5e3NZPZmAGRjzYvHRTLxXK4/eIT/dJB7EiuR/YhNk9TZ5lYKTeyTSWiYjwhx5oYDH14yhpPblCbHHDG1PZhwItjHtOICE+p5FdRiJdnutCVS20quxC+29gr4Rg1Q2E4+wgoVBQgf4x0Y4x0+xjttIlFJhjCPlF865UN9g9qnJjOVkxM2GJ5wz+i05USQlJQk2MLRyDicz9cQeEoZx4BDhiSPTBEgYFQhRGnHWgQL4jvto28aEBWG9triG4lidWXyQ3y2ZCakxo9qBnpFEbpfiDaM6q7DvUhEYsSPi5YM+hVBeJ7x1sRjdwq++4u3McXP0XaHaPs5wH4OsJ8D7KcJsLkQuw7n2RArHUehZuMYyrhtiaGfA2elESeBM9Z7nMxS+CxMMqVVwUEmijRIbO0Slj9JVJapnsTJQpJLhrOY54rmyB8nkEeMIN7ycK6cdDpNYjenkgTt0LOBRBMCaA/gUFARWttgzADriaphvgBUxuwJzIYlE/hT5Y/dP3YV6S6TLFbWPfexETP28Q8QIdGvtBSl5GO34K2LfjQnL1MG+GOfvABVkt/+lqkSv+/Xs2INJVyiJslyamTphTTsyVf+X9j/ipb0lZbIoDGb1FjL+zIwT950qO3TT9E65WO14TMKItlpprugzvBmeL4jBPLXPo7E1pQni5ogoaTq/xX+kQY5Oc2Sjue6QUc3YcTwzKbLeBUMZRyVLykhvKEOLpePJRb0qimWr+lV12mAe7av7NVW3764J8NZHPnY0t79+eXp92/OX30y/DMaKU3gS9ShYEkxBtrjnLOok8KaZ71CJKP/3jTC3a25PiTlFBUCVsq4HaEr7T/VYXqsY9Ol4N5LyxnTFX5Fs26glCwp/KURTot/50puQBDUgDVBAwr30yKDJIGCv9pHx21pH4YrCU4ixa4myIww/6jXxDDiECeSjFWakJQluEe4GwflgbKmPoejaFUMi+43zZdoFWHvL7+kKpFl1ch+eV5N2HCwF6USDmP3Li2PPkxaLU4tNpyMxlAYMHAK85UoUwnxohztf4TAvUeYLA2UVfXXC5TrN1vY7hS00zQbmNb6HwPBJcsdQls/9mJH7EfPUjm4qeeGC4ZbJ5bnB4BK+RfQ8GLQ7e8AZvcYdIkxEBEpT07JQiIw2wQTYfiIANEXSnsw6OE4UXx6rCmEPZZEI03wGROIaTuaGMfbZqCrNvJpLnZxMiyBhHk3ocd68vFWjLgAYNh/J+QZIm6Lm8Kg+2cFVa60tZhTA+KcRle2imzzG4xeDYavXN+k1gGGxyzjG0TSoKD2d73MQz7+/A5Guy8aGU4z6SIJE66PdN1jILYZxx244iWyPW6YIBbFx+owUgMy46psTmQH4Um5mTuhbStaK3UcwdgjOXdoJCENg2fuahIDmheXz1/uru9gvshMupL9t2iywu7bJjSjOD1fpHNaNJ/mhIBEPH1Bat14igU/2AxrR8mipqHdMHS6m4eUWWn8LYnJeVMlEU+c8GPzmrPN2utHsj7ZonucFrJo/mJQOs7KIqhNLYKCqUAdZMtshM2W2yWjXjVRYICZZ5UHLMLl5gCBt87eyNVnksX1/zq8utQXhufTgjj5ucUmN18xAnNGWrRdyWwjzo54w1uceXU9vJLtC5gWLj5OKOn4HMdr4acOcw3qPLWL1UoY4YVatbRosa5fUSagcx8UV+QV7zrW1Lzm4ouD6C6AaEZF54GJwenyCltkxYsLCoIwUrfWXcx+sJU9XmlqrntHBmBouCTl8z3eKqY7ik+jh1tErBETr+qZbZIp3DKlzV/xFLdJvU35o5LbBXvFKzHEMZ0YoV1qiyQ2xqiMYI/RnU9lkll2UlZJWhbU7/aJRb4lGdskn9Y4yWfrrLqduyX83HqkZhonXeIsT+V6Z+h7LMEyTVM1xUwP0B4Ghhfg+VKfUkzyANklJYZHiRc67BSm4bNEXj7PAyJdZDI9WOjIp/y8JogzpPakZKSM6oGR1gyMWPKNO53S8YVzA7Rx/uyFtJ/3a2jEu1RUDON4CDby8+XMgrENRSOW4weGjctHod98nEXhU33/RP3Z6ZQd4tSnNGBKDBdXC3Y0tdXWE17fr1F0hgRwgJcPGSUKbsh0i52W6XViwFSjpPx2K2WUdsUNkRmIQtRjiEInbSmHF5jEK9dRA/LouEuwATfT+cw8wNxREsNZuw47DG0zaaCgdH/kDT6KPzfWuFUWJEqiwBYNVrfshi2g4LHvMYwL3twC+QUzh/sQSB9oXTO6jfo704tbTykn++vZefmbiyTlzZjmc8XxIQFBpey89tHUcef0aEbtBfV8buzs/PYwIt8qIYhWFRHU5+6YsmFlbjihYVcgcLGWEQazc744VW+N28eaaGcQtjumnOxQe0nUE/FBsrcMHvxFfMD26RVKu17QLoQ/vOKxSv34zCvMBfMV+1WctCR1StilSelAXCL35RXBjQH4QoTE6NEdzYCOE2QUzDwIP1CYuSS+V4A92ggvKFi4vrXiyIe5USu0xhp3mNPx2EtfWIAOM+2n31fgNtGqig7g8FZ13AhA3ZE/b3siQEhyQm7vBHpBP10+EoBFuUMaT4ZlsygE2Li1iwdDM9tt7qg4SXYgCKtFfIKNnOr8jRwYZPs5bITTMIab8Q0Yq2J9bMoKQCsGg1Sn5DkFdwAocFkoZ0o4fkBrzID8hBG6BMIgIdDu2H8Pka6l6mhXyKldTh2BVvgwduf4qpASmq0naOlKgNcdgGsRckfhj7eHMDnwkvaotTgyQHi+GnfKv/1Ox4Na0TLZEx601eeG/9hi6YQLJ4B7mApESeTppAovJSY/5nF1RtrcFaSsalFK7mv0Efclg0iR9wr+u7Scsbv08RUjCGPe0Sm+U2X9IxVfNsJMtJ96F5ujbYUR3FfQfa+WDvUuIXa3Yn9eMLcJfCuDoLOI/j2H7wYEJu/JMimDO4Dp/Zkb2uMIF+N7UzhcmBmBgI7wPuJMwoBmSjdjZTndPdK12B5QyZEX6QGa87eQcn1sK/DDj+cf9Deuadg/GeYM0IxG1OGH4fX5T6PRWeh5IMeZ6wSea0P0GI2GvFX+aJTKqUKV+4sU/mbmpkLXRsawWm13J1DgNb4LCOM8wEIEkUm0Y5q0aaD6qA9EWvzVQZSYXE57ncLI3KSpoMQS3vXKjAfzaxetLaPVEjO6iUpvLyRC1sLMttyTVqsaV4q0eMm04/nMGBOtMBXCNM0gtgFDMgQNGIQ1Uakzyh9lFakXeaBXgc49fF3Pf2t+qCm/LLhEKRWQImKl++ED9JEvH77Q43OVhUB/pCZx/jvyexxPX5QUTkea+zPQjk/T6bykFHhx2yqSr8ho8IN9e01r4EcKFbfErm1u1NQ9LB1/t/sZ7tgjL4AS3yvCMdoZC474OrDSWVX2WDN4/s9oVyqO7tlxAsnmMF48RggoD0qVojxRMt7UqgGmnyIhdAZG/+qJep6F8599uARbsELgDHE3eq8YxF3L9Fx8zdho9J5LlwTq6KVroxG+tc1zaEBixIch+q0ooJq83CNdtMnguUxziiNd5jHDeIVbUcYuN0tMgQmbI/aO/6B34U+PpSWzz05OeoCU4y2KGWbw9FsbB63v1DLItwUyYr08rVLECL5wvjLKAWihmT5mgqL48LXOJS5BqcV6bG0VsVqvXQpca/gK+PfrPFdBpgq+Xa3YaVE0PCKVQsnBs7lhun7Z+9/2tFfto+9TyxzUKGFQfX6jCYN0jdQ3w8CyydERD3pS+98q975tWbVlJiJsu2h6+KJEdAwRVTLFxtzK7hbSlPNkjvkGoiDBfUN1jOR48VAV7fDDDQLpbJZtGbgV1qwriUDTJUtOuGJ7/VjFPdmKoGopPZfuiqrbgFCi9Q3TMxgqhxnisYQ6aumOrifD1ohCTjJvQairXty9wfZscH2JGzaAemZvUR3hSWrVMjU2csVice9krSU5SVRvxJt6I87sRJLYfV5zliIyy0GvuG+P2URml1wVLWnjy+5KbWYrmW2nCNyUJrXjntNKdwkBObZTPnoTmxRRCZPZbA+pikSPl+2nkdtWv2WfDG7wyI+U4t4YAdZVJRoYyG221QWtTcdzXDyzj/hL6Sn1E9go5yTmkjkdBiSSVHJ0TyqRzPSDaC6z3pPjLb5xIpPtysIeIbP8NptZLs9NlcEfy2e7bbKrf/iATU4g7glrrRJzkUiwuPtyWdhf51yEG4XKEpu9ypwQ73bLj48gZgvEKPTX2UrMmFFP3XJmpGiWojeWr2BEVeGvv7RYVihJUNpGADBiLrxp2cAN4GxZQD0Rb008Sh/8cXwTr7k7DsH46QqXZjCr80ysqeN6lLXjpLBaopHYtk9yr3omG6GxYhKD8wb1f3PchHNxDi/yzntaDfex4UGNGvYp9ewkppQ29MR/AOS1xlU=', 'base64'));");

	// daemon helper, refer to modules/daemon.js
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyVVU1v2zgQvQvQf5jNoZYKVU6zaA8OcnBTdyu0dRa2u0VPC0Ya2wRkUktScYLA/70z+rbjXWB1oTScr/fmkRq/9r1bXTwZudk6uLq8uoREOczhVptCG+GkVr7ne19lispiBqXK0IDbIkwLkdLS7ETwFxpL3nAVX0LADhfN1kV47XtPuoSdeAKlHZQWKYO0sJY5Aj6mWDiQClK9K3IpVIqwl25bVWlyxL73s8mg750gZ0HuBX2th24gHHcL9GydKybj8X6/j0XVaazNZpzXfnb8NbmdzZezN9QtR3xXOVoLBv8ppSGY908gCmomFffUYi72oA2IjUHac5qb3RvppNpEYPXa7YVB38ukdUbel+6Ip7Y1wjt0IKaEgovpEpLlBXyYLpNl5Hs/ktXnu+8r+DFdLKbzVTJbwt0Cbu/mH5NVcjenr08wnf+EL8n8YwRILFEVfCwMd08tSmYQM6JriXhUfq3rdmyBqVzLlECpTSk2CBv9gEYRFijQ7KTlKVpqLvO9XO6kq0RgXyKiIq/HTJ7vrUuVshdYl+nSfabgHE2Qhr73XI9DrlkU0sYFUaVcu+iiSh7XcSE8Q2F0SmAaS8w0IyW6hoPvHQaV8FH2dXSG/16qrZEaYbcLtE4YB69eAUfBbzdwzpezh3W6Jis/D4II2BVwA1WSE0BuG8EJRLFDR8ciOleDT0WbeLidbmWeUQkqVL//l1/zAUcomoBDvWBu8QWSYSKkGQejTCschX3o4WSujLfGOMTVYjkivzHCzQ2oMs95qp0Jng/XbWcD34rwMwGNHS67IJ6BQbZ1TpP2hXtz2wmc9jkZvMOhwdic9WCED8SCHYXxjF9mxAb5xanI84AK0exMiWFPHekIhcPK+YQ2co8t3aS1LKnFnr/OGgxFzugC1vbZBLHFfE1ZyHrdM9bGFrlwdKh3LOHRXqrfr0bD1FoFo2Xyx2q2+DaKThKHHZtsbwXXEVIZ/m4SES/4iOknuqrPzJ/jT/Tcpey12QPoN5vzzW1mwgnq8ejueJmNttGY/xHAnkwweQ4ui4FfaRTwiNl0LHe6Fmm4vapZdMJsWL8tv/T50KTindjy3wKDtxG8bUs0h6abNaZ/VgSyf0SjGl5Ik0pmdacTeP/u/Ts4hDVYVljUS+m8gDoMO52VOdIG/b5ddeCgKVAtUY1tUi8kvF/A95P8', 'base64'));");

#ifdef _POSIX
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVFFP2zAQfo+U/3CqkJLQLim8jS4PXQERDbWIliFE0eQm19YitTPbIakY/33ntAU6eJzz4Pju8913d18SHbrOQBZrxRdLA8fdo6+QCIM5DKQqpGKGS+E6rnPJUxQaMyhFhgrMEqFfsJS2racDP1FpQsNx2AXfAlpbVyvouc5alrBiaxDSQKmRInANc54jYJ1iYYALSOWqyDkTKULFzbLJso0Rus7dNoKcGUZgRvCCTvP3MGDGsgVaS2OKkyiqqipkDdNQqkWUb3A6ukwGZ8Px2Rdia2/ciBy1BoW/S66ozNkaWEFkUjYjijmrQCpgC4XkM9KSrRQ3XCw6oOXcVEyh62RcG8Vnpdnr044a1fseQJ1iAlr9MSTjFnzvj5Nxx3Vuk8nF6GYCt/3r6/5wkpyNYXQNg9HwNJkkoyGdzqE/vIMfyfC0A0hdoixYF8qyJ4rcdhAzatcYcS/9XG7o6AJTPucpFSUWJVsgLOQTKkG1QIFqxbWdoiZymevkfMVNIwL9sSJKchjZ5s1LkVoMUJfTxytmln7gOs+bOfA5+IWSKREMi5wZ4rGCOAYv56KsvWCD2oLtemKKAvE8g3g3D99rDL+2cbwgxBrTc1KP70UzLiK99Dpw79H2YMW2C9XcCrUh4oo2RRE9r7dvlsL3MmYYBXitw08DeG4k2txqx5CGRo5pdmLhBz14+TSJLM1nSaz5/yXhIrTKo8IxXUo4uOpPLuAPsOoRpt4zrFHH3R6wWJMOjH/Q7cCsA60T+gatAvw6PurV32LWa7drm57P/dl9/RDHrUhTI1vWZmMcUX56CiJjrIGOU28qsOZmKryPzCrGzRk5fet6czbDZ0oj/VT8fxsVUqkrPwisGrrB26V3WrBrJx6NBsWT79mKqY87M9nuN7YHaIN30tSxx/Bl80rbi+W2klmZIymI/m9G07ReVdtQd52/UQCQ8A==', 'base64'));"); 
#endif

	// wget: Refer to modules/wget.js for a human readable version. 
	duk_peval_string_noresult(ctx, "addModule('wget', Buffer.from('LyoNCkNvcHlyaWdodCAyMDE5IEludGVsIENvcnBvcmF0aW9uDQoNCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOw0KeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLg0KWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0DQoNCiAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjANCg0KVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQ0KZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gIkFTIElTIiBCQVNJUywNCldJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLg0KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZA0KbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuDQoqLw0KDQoNCnZhciBwcm9taXNlID0gcmVxdWlyZSgncHJvbWlzZScpOw0KdmFyIGh0dHAgPSByZXF1aXJlKCdodHRwJyk7DQp2YXIgd3JpdGFibGUgPSByZXF1aXJlKCdzdHJlYW0nKS5Xcml0YWJsZTsNCg0KDQpmdW5jdGlvbiB3Z2V0KHJlbW90ZVVyaSwgbG9jYWxGaWxlUGF0aCwgd2dldG9wdGlvbnMpDQp7DQogICAgdmFyIHJldCA9IG5ldyBwcm9taXNlKGZ1bmN0aW9uIChyZXMsIHJlaikgeyB0aGlzLl9yZXMgPSByZXM7IHRoaXMuX3JlaiA9IHJlajsgfSk7DQogICAgdmFyIGFnZW50Q29ubmVjdGVkID0gZmFsc2U7DQogICAgcmVxdWlyZSgnZXZlbnRzJykuRXZlbnRFbWl0dGVyLmNhbGwocmV0LCB0cnVlKQ0KICAgICAgICAuY3JlYXRlRXZlbnQoJ2J5dGVzJykNCiAgICAgICAgLmNyZWF0ZUV2ZW50KCdhYm9ydCcpDQogICAgICAgIC5hZGRNZXRob2QoJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLl9yZXF1ZXN0LmFib3J0KCk7IH0pOw0KDQogICAgdHJ5DQogICAgew0KICAgICAgICBhZ2VudENvbm5lY3RlZCA9IHJlcXVpcmUoJ01lc2hBZ2VudCcpLmlzQ29udHJvbENoYW5uZWxDb25uZWN0ZWQ7DQogICAgfQ0KICAgIGNhdGNoIChlKQ0KICAgIHsNCiAgICB9DQoNCiAgICAvLyBXZSBvbmx5IG5lZWQgdG8gY2hlY2sgcHJveHkgc2V0dGluZ3MgaWYgdGhlIGFnZW50IGlzIG5vdCBjb25uZWN0ZWQsIGJlY2F1c2Ugd2hlbiB0aGUgYWdlbnQNCiAgICAvLyBjb25uZWN0cywgaXQgYXV0b21hdGljYWxseSBjb25maWd1cmVzIHRoZSBwcm94eSBmb3IgSmF2YVNjcmlwdC4NCiAgICBpZiAoIWFnZW50Q29ubmVjdGVkKQ0KICAgIHsNCiAgICAgICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT0gJ3dpbjMyJykNCiAgICAgICAgew0KICAgICAgICAgICAgdmFyIHJlZyA9IHJlcXVpcmUoJ3dpbi1yZWdpc3RyeScpOw0KICAgICAgICAgICAgaWYgKHJlZy5RdWVyeUtleShyZWcuSEtFWS5DdXJyZW50VXNlciwgJ1NvZnR3YXJlXFxNaWNyb3NvZnRcXFdpbmRvd3NcXEN1cnJlbnRWZXJzaW9uXFxJbnRlcm5ldCBTZXR0aW5ncycsICdQcm94eUVuYWJsZScpID09IDEpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdmFyIHByb3h5VXJpID0gcmVnLlF1ZXJ5S2V5KHJlZy5IS0VZLkN1cnJlbnRVc2VyLCAnU29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXEludGVybmV0IFNldHRpbmdzJywgJ1Byb3h5U2VydmVyJyk7DQogICAgICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSByZXF1aXJlKCdodHRwJykucGFyc2VVcmkoJ2h0dHA6Ly8nICsgcHJveHlVcmkpOw0KDQogICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ3Byb3h5ID0+ICcgKyBwcm94eVVyaSk7DQogICAgICAgICAgICAgICAgcmVxdWlyZSgnZ2xvYmFsLXR1bm5lbCcpLmluaXRpYWxpemUob3B0aW9ucyk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQoNCiAgICB2YXIgcmVxT3B0aW9ucyA9IHJlcXVpcmUoJ2h0dHAnKS5wYXJzZVVyaShyZW1vdGVVcmkpOw0KICAgIGlmICh3Z2V0b3B0aW9ucykNCiAgICB7DQogICAgICAgIGZvciAodmFyIGlucHV0T3B0aW9uIGluIHdnZXRvcHRpb25zKSB7DQogICAgICAgICAgICByZXFPcHRpb25zW2lucHV0T3B0aW9uXSA9IHdnZXRvcHRpb25zW2lucHV0T3B0aW9uXTsNCiAgICAgICAgfQ0KICAgIH0NCiAgICByZXQuX3RvdGFsQnl0ZXMgPSAwOw0KICAgIHJldC5fcmVxdWVzdCA9IGh0dHAuZ2V0KHJlcU9wdGlvbnMpOw0KICAgIHJldC5fbG9jYWxGaWxlUGF0aCA9IGxvY2FsRmlsZVBhdGg7DQogICAgcmV0Ll9yZXF1ZXN0LnByb21pc2UgPSByZXQ7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdlcnJvcicsIGZ1bmN0aW9uIChlKSB7IHRoaXMucHJvbWlzZS5fcmVqKGUpOyB9KTsNCiAgICByZXQuX3JlcXVlc3Qub24oJ2Fib3J0JywgZnVuY3Rpb24gKCkgeyB0aGlzLnByb21pc2UuZW1pdCgnYWJvcnQnKTsgfSk7DQogICAgcmV0Ll9yZXF1ZXN0Lm9uKCdyZXNwb25zZScsIGZ1bmN0aW9uIChpbXNnKQ0KICAgIHsNCiAgICAgICAgaWYoaW1zZy5zdGF0dXNDb2RlICE9IDIwMCkNCiAgICAgICAgew0KICAgICAgICAgICAgdGhpcy5wcm9taXNlLl9yZWooJ1NlcnZlciByZXNwb25zZWQgd2l0aCBTdGF0dXMgQ29kZTogJyArIGltc2cuc3RhdHVzQ29kZSk7DQogICAgICAgIH0NCiAgICAgICAgZWxzZQ0KICAgICAgICB7DQogICAgICAgICAgICB0cnkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLl9maWxlID0gcmVxdWlyZSgnZnMnKS5jcmVhdGVXcml0ZVN0cmVhbSh0aGlzLnByb21pc2UuX2xvY2FsRmlsZVBhdGgsIHsgZmxhZ3M6ICd3YicgfSk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhID0gcmVxdWlyZSgnU0hBMzg0U3RyZWFtJykuY3JlYXRlKCk7DQogICAgICAgICAgICAgICAgdGhpcy5fc2hhLnByb21pc2UgPSB0aGlzLnByb21pc2U7DQogICAgICAgICAgICB9DQogICAgICAgICAgICBjYXRjaChlKQ0KICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fcmVqKGUpOw0KICAgICAgICAgICAgICAgIHJldHVybjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIHRoaXMuX3NoYS5vbignaGFzaCcsIGZ1bmN0aW9uIChoKSB7IHRoaXMucHJvbWlzZS5fcmVzKGgudG9TdHJpbmcoJ2hleCcpKTsgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvciA9IG5ldyB3cml0YWJsZSgNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgIHdyaXRlOiBmdW5jdGlvbihjaHVuaywgY2FsbGJhY2spDQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvbWlzZS5fdG90YWxCeXRlcyArPSBjaHVuay5sZW5ndGg7DQogICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb21pc2UuZW1pdCgnYnl0ZXMnLCB0aGlzLnByb21pc2UuX3RvdGFsQnl0ZXMpOw0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICh0cnVlKTsNCiAgICAgICAgICAgICAgICAgICAgfSwNCiAgICAgICAgICAgICAgICAgICAgZmluYWw6IGZ1bmN0aW9uKGNhbGxiYWNrKQ0KICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjaygpOw0KICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgfSk7DQogICAgICAgICAgICB0aGlzLl9hY2N1bXVsYXRvci5wcm9taXNlID0gdGhpcy5wcm9taXNlOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2ZpbGUpOw0KICAgICAgICAgICAgaW1zZy5waXBlKHRoaXMuX2FjY3VtdWxhdG9yKTsNCiAgICAgICAgICAgIGltc2cucGlwZSh0aGlzLl9zaGEpOw0KICAgICAgICB9DQogICAgfSk7DQogICAgcmV0LnByb2dyZXNzID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gKHRoaXMuX3RvdGFsQnl0ZXMpOyB9Ow0KICAgIHJldHVybiAocmV0KTsNCn0NCg0KbW9kdWxlLmV4cG9ydHMgPSB3Z2V0Ow0KDQoNCv==', 'base64').toString());");
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");

	// default_route: Refer to modules/default_route.js 
	duk_peval_string_noresult(ctx, "addCompressedModule('default_route', Buffer.from('eJztVttu4zYQfTfgf5gawUpKHDl2sgs0rltkc6vQxFnESRaLpghoaWQTK5NakoqcJvn3DmV5fY3bvvWhfLBM8nDmzBlyyMZ2tXIs0yfFB0MDrb3mjxAIgwkcS5VKxQyXolqpVi54iEJjBJmIUIEZIhylLKRPOVOHO1Sa0NDy98C1gFo5VfPa1cqTzGDEnkBIA5lGssA1xDxBwHGIqQEuIJSjNOFMhAg5N8PCS2nDr1a+lBZk3zACM4Kn1IvnYcCMZQvUhsakh41Gnuc+K5j6Ug0ayQSnGxfB8Wm3d7pLbO2KW5Gg1qDwW8YVhdl/ApYSmZD1iWLCcpAK2EAhzRlpyeaKGy4GddAyNjlTWK1EXBvF+5lZ0GlKjeKdB5BSTEDtqAdBrwYfj3pBr16tfA5ufr26vYHPR9fXR92b4LQHV9dwfNU9CW6Cqy71zuCo+wV+C7ondUBSibzgOFWWPVHkVkGMSK4e4oL7WE7o6BRDHvOQghKDjA0QBvIRlaBYIEU14tpmURO5qFpJ+IibYhPo1YjIyXbDihdnIrQYypqIZK4fIoxZlphrSZG6XrXyPEnJI1OksIEOiCxJ2rPB80saK7V3nYdzFKh4eMmUHrLE8Upk8IlQ55f+sUJmsEu0HvGTkuMn1wnSYZKylPtRMo8voZdohjJynXM0QXomFWUrurGJLaAzGpr/ifMu7pjiFuYeeO35CDTFRjiyv2LR3asXZurQnK7hsTtZ4t+xBDodaLZa3mSq1GVq2RSbbR0Ba9I38mMWx6hcz6fZ6JYO6n7r4tT1pp5s28yu8LDCcC3LPW82OcdzyhUF7WTU5Kiw6Z+gwthGf+C9TbS9akfJfGl0sUfb1rU43tlr859Kr+2dHe4t4pYoFlLIfIneAeyAy2Eb3n/w6vanvbqKx+DSyn8W0LJQG9jY1mjAyeRoQHE21qMsgx/sOXl5scfFHyEFHcLPMKO1/2EzrzWUNtAqxCrO5TNVNoMqZiEezrlr/o27Okw4Hv4LivC6RnzbXleHl4bmuuXf8kNBZEpQ/tDY1L4uFKeEi2y8qTSFQ55E84WoGHhIlQypujqej2MMz+jKcp1Gn4uGHjp1+N2hzx/TjVSs8LWhSql8KVwnYoYR6jsJN/RI5NcVPNGhjyLvjtNeHH7bjL1Di1U7HQhJ6R7lQAzomK1xwIVvbyzizlPKEkUPL0D3WQqlItRl+Ve4d55tLYCtZqdTK6dq8O4dbB0UA481sK5T8mRg6z25gtd7517gmJt74Sz6zRk3pzTx/eRPE7Qct0/MR5Pj5DjwS3E/wOHidnxjzWzvNSdhL2a9r6P/c+4INJrucdgl8XdjUtVWl7fSX+a2e/afzKymp2E4dMsM+WnCDN0Ro1laQ0avHYeeIvst53BWKUYyyugioLeSVMbeW+seK3MlqU/l6mt73mRRQDaaXC0xGw3G9Jyk/Tk1ORmMmCJmG90s7+k1Tgqp/gL2YXjV', 'base64'));");

	// util-language, to detect current system language. Refer to modules/util-language.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-language', Buffer.from('eJy9XGtz2ziy/e4q/wdu6lZJ3glsk3pYnlQ+yLKTaOLXWs7Mzk5SU5QESYwokiFIO0o2/30beiSyo8Mc3rt39CGOKPIAaBx0N7qbOPj77k4nTuZpMJ5kjnfoHTrdKNOh04nTJE79LIij3Z3dnfNgoCOjh04eDXXqZBPttBN/IH9Wvzx1ftWpkbsdb//Qqdobnqx+erL3bHdnHufOzJ87UZw5udGCEBhnFITa0R8HOsmcIHIG8SwJAz8aaOc+yCaLVlYY+7s7v68Q4n7my82+3J7It9HmbY6f2d468plkWfLzwcH9/f2+v+jpfpyOD8LlfebgvNs5u+ydKemtfeJNFGpjnFR/yINUhtmfO34inRn4feli6N87cer441TLb1lsO3ufBlkQjZ86Jh5l936qd3eGgcnSoJ9nD+S07pqMd/MGkZQfOU/aPafbe+KctHvd3tPdnd+6t6+u3tw6v7VvbtqXt92znnN143SuLk+7t92rS/n2wmlf/u687l6ePnW0SEla0R+T1PZeuhhYCeqhiKun9YPmR/GyOybRg2AUDGRQ0Tj3x9oZx3c6jWQsTqLTWWDsLBrp3HB3JwxmQbYggfl+RNLI3w+s8HZ3Rnk0sHeJbM4Ftnrnh3u7O5+XM3HnpyLY7Nnym5GpHUyc1S32yuo2+xn40tOKe+g1Kj9/u2o/AuA8dyp+qnrtyrOHv/VT7U+3gDQBSH+sTl6yIEcAZOCrsx4L0gIgnybq9jcW5Bj1xKjOv0iQ2iEAGfrq9DUL4iIQrU7PWBAPgOhQvbxhQWoIJFJv2Nmp1RGIkSn+M0v9YRSyWIi4o0C96LIgiLijVL2gRYOIO9Gqe86CIOJOcvXqDQuCiBsY1WUnqY6IG2Sqe8uCIOK+99Uv1ywIIu40Vq/Z2akj4kahumRnp46IG/XV5RULghibhOqa7glibJKpE1omiLHpTHVesSCIsWmsbmiZIMamubphad9AjJ2k6hUrkwZirJmqHquvG4ix5oNqs1PcQIw1d6rHKv0GYmwmhpCd4gZibJaqW1qwiLF5qq5pwSLGBkPVPWVBEGPzqXrD+joNxNi+Vie/kyBNxFgTqh5rvJqIsTpTZyxPmoix4Z06/5UFQYwNM3XOmowmZOxYdeZpqG5/YZGga+CrLkvbJqLtXaB+vWRBoGswV+0LFgTR1v+kzv0sUm3WJ20i7uqcd7GPoLY1fd4pPULknU3VBasVjqC6zdS/2AV9hMibmRIgkLxRCRDE2ztdAgTx9uOkBAji7ae8BAjk7agECKLs1FcvWbK1EGVHsXrBuiotxNhJoLqsQmghxs4ydcFqyhZ0EDTvjbYQ2eaBeqX7KQuD6DYz6oI1hy1Et+lUvWaVWwvRbTpXr9kgRAvRzdyr1yzdjhHdsqm6ZbX+MaJbvtL6b1jBHCPOZRnvYx8jzvUjnv3HSEsmfgkQRNxxXgIE0TZOS4Ag2mZlhoNom+kSIFBL8rPjHiLazsISIIi2vikBArUkPzvuIdSS/OzIBhX1JFIXNAhibD9WHRoEMXYwVy9PWBCoaGfqNbkrFCWJvP1YnZN2XSiLBDtXF6SOFBSkCkLan5UPjDJNeaK4kLIR7x64LuTsUJ3quxLEdRFxzTxVPdIwuy5irgnUOemluy5k7iRVnYlO6QCy68IwQK46fmRUh+WfC53TmTojHTHXRSTOPs1UO/X76oLtj4eoPDULJBYGkTkS15CMu7oe4vJoTodMXQ9ROZEBvWBBEItHQaiuWYUFc1zDO3VBxjhcnOMKInVJ+pcuTHKN8rsSKDBZ4C99Qx4JZgz6fR4F5rrmcQkQRN0P4vGekNsaFya7IhPTu04XZrv6Pu0yuzDbFfbVOQ2CuDsN1Ut2LcI0VzAuMT/Qd0hLgCDmxiXULkxzZQEPAtNc40hds/YRprkm/j1v1WCeK1wuZxYGOg+x6rHrB2a6goD3VXGmy0+UTa+TMIi2fhqpDkt+mKeaxRPeX4A5pj6fKXZheigf88KF6aFZoC7JmIAL00PxoMRw0DQP4hIgaJLH5r4EClJOxp/wGhsmiD7kmXrJahaYIUrv1Q1Zg+LCDNG9LGaWKjClkqQlnDCYTknCTF2wmh/mUz5N1DzX6hW7nYA5lWw4VLd+qPmlBDMr00nfQuUloNCkj4f89hymVqb5cjvR/QeLhJ2pgeqQxsCDIe8P4sQnYTzgcBrQE1rj+BSQh8sF/JSVjYcz/YtCM3UnFIoGAdslqNOF1yR7PJxoH2q2IMPDOXIdsRT0cI5cG3XxTxIEKq9Rqk64KLqH88FBxssE6q73vroW4rHFSB5O5UZhiTEh6UYRm7nxcAI2ydQ1Z6Q8nDpNY3XBFVR4OHWa5iVAYKQqXW5mO5wf7eGspbljSwI9nCvM6dizh1Mu/qdlLQOZsvdwymTIZ9u9giRDpE44l8TDwWOj2bokDwePx77qsiAw7jsz6oScIxzbzFdzRCbYPByV7It0yWWAA5KJv7T9ZK2Uh2OAmc8GbT0cYrKJjzii9yseDjH1Y3VCqiscfDDDktKBW/YgX6kbbkvo4f22jf4uoE5ZBsFd99Qs4v4sDKJ0ROcSPRe6R6PRclTk9sPD+0Mb0TvrkCiwuMxGe7j9odeAe7K1BzqjgGrY5IkHesbthWq4Rkd8RnIfVMOVMeIztrl1VcNFLeIztrltcw0XtSzK+lkQGOpP2SVZw3ZOfImFTid9iRqORouxI32JGo73rJUomUKu4aDP8BOrRGsFO+fZJzZTVXMh7+yqvuZMeB3XTsg6OufCr3VcsSDrqMctxjquE5B1RIbp6zjFr2mDUscpfllHZPSpjh0su464bVMdZwAnsoFjhwPVv5m9Z3c7dRfWQVkrezuyi4jrUAM7RsI50lQ3cEpSOHfBDaqB04CWc5x2aWDHSjhHBoIbOHUnnOtw1rWBk27COXIJNXC0v2+WfgdJvAbWUJZ45E6liZ0pYQtJuSbW2zJH5HaniYP1MkfXdE8KXnW74HyxJg5Qrvfq5Bw1PVydNfNZ5XCEo64yR7ecbT1yYdhA07XbAlIQNztlhwM3+2v3hRTvkQcVjBUvuQRaLiz6FPFecUVaLQ9WBIp4f6FBClzMX8nheLCYT5bADQsC9+mipsrMUcvDb5zNDOtjHnsw+CBz9Ds3qGMPVsjIHLH5WkEp8F/InIOAFPkvXDDl2IMZ9bWeuuH2AccefCfDiA9Pv2fswaiDz1fjCUqBxT9hy8E9mMq25oStcffg3kbmiU1QHnowK7jWeORE2fqsAnv9C1v+4MH9vYj4ls0AezCmLSJuszltD4YJ7FJga2Q9+DbCei1ckHMuS7PA3J6TSU7Pg1s/a2/J/LigFBhcMrbkejW4g7QiJle3V8PFtisWsyKu1WAFsIj4NSmcWg3udETEbNmkoBQYXbb8RlAKrO4FiVKvwQCwyKVNSrdegz69dcfJ14gFpcDOvSGVuaAUGDq2bLhRgy8Bi1xOyJkWlALDwhZmNGpwd2ANCykXQSkwLK9IDdyswdfbRC7/IKXbrEEHWPPv1QhKgTVgC1uP6vCNCRnRIpXNHtdzVIc+owyLfWlPUAo0cI8sq27VYamtDMvuwUkY6GDJkMhQoEUp0HivyPk+rkNPxAbVSV0lKAVa5pLNZtehybYuI1tFUYc+hF3ZZA7GbUDbJn0hcycWpWA1kSW3st+B9sTuSslKDEEpWAJ1l9s3ebUGPskhYo2+RSky11wUzqs3oOK0DjCbbmtCZSUo5K5UUPA7F8u9NofTbOLiXcMXWIs7XlSqwven1SxKU/H9aR3hJNWMxDg+gnXwq1IVFqcg2m/YjGZBbJ2FgMOJOIlYCMw6Or+LBrI6soPFKYhkczUBggFfrs9LTHDtsIVfD45K4UArsHqHj8aBhxOtEkNsPhM64jYb70cZiwMnPeLe3hOIgvg6CwHz6KtjdOgsLzy/0LDDaRUE+d+zGPD13LzMUhKcgrMH6BcsBQfqqFVOn8WBfu+qoonG+dHbtTRQwbu1ZQSN385alUWxQPCUulUhEo3zg7clf4Az1CM/D7OtEFEehvjpL8s/cmueRk5V/trzeb9sHOI61lknT1MdZdVvp7gGo2qSxgNtzH4S+tkoTmfOc+nufRDVvMr3R7naU18HkyAcSodWx+pWK4sLf65wKnv7+qMevAhC/RVaR3d/WMhhkFbeOT85lbdvzdxkelbz3r697+uZ/DsLBvbBylNHbpUv8p9KbOy/0vHll/XZtpWnlYMXVzcX7dufz7u928q7vQ25LDqzb7JhnGfyJ7XCrzx7eDmOqpWhn/kC+1U81cGe83lxgPHiqZ+eO4P9LO5laRCNq3vPnC9bG9Fpuq0Re/m/1Mi9H2RnHwOZtGfrQ5DXExEGkTbS9OMh7wverLq3b5JQnqu8Td9GlU1g+2wWT3VkNi7ak4Sr9pfAnoO8gN779uvnh8RbPi1NL+77I3i3buv5g4ZWDFve/cfhu+fPK1e98/Us7j288VETm2xenT+8wnHf7T1u5Mu3rxv/XT9uV876iS9rIW4wf0HP8/blS2HSd4xfg2y5eT3o/cqeDG6jBftHh0Z/BxaMnO3rbeinsj4qWOLlFl7loB9EB2ayWE3y591jgf0lq+RBQ/+fK+VBQ0G0b0/x1tUnsfHNIA2SzFGinXOjZcnEAz/U9nzxqqgVZ6mFhPCjeK/yNtKyzt5GT7ZDP1iI21gKluHm7Rvk/MaPLbOdpfMfLg7LiDx4wAc7RGX08qxv4cN4OHsTDJ9tf/a/yKa/lFF/Kau2M6uSGEspFTuJTID8sfPwb2ec6sSpiH2zX8XKySX/frq48qTy2Umklcz5H1eawVz71iDk23oCk8XkJ35qdFeMegH9tj+vC6mjs7Po7kUaz66DYVWa2tYLq870vlWGVqzrdbC88lg5bnLffh59HfiL8+M/FhuFUnr+y/IUezvUuP9eBvv5i/x41X+vB9m+eFpiuq7TONFpNq/KDeJiDJb+kTBm1a5I4ecN9nxvHax1s2z6884Pnb8tnTSsxL/as/Uj/yvd8LW95w98OqCVitqyQrKXZ/EwD7Us+CROM2vWRRwL2kB79dU/XHVuu1Qf4oqArWP3TxNe+5koEzjC7VIHNy9nYT1O20Ai6LaTj+ai4Hn7WThFs8SuKN5rtUt70fCKOcu7Hjv5m938uuBGSxUbmMz05tGgatv+yR77f7f/0YSVvS09L+i9/TyWgB0O6MmX7y9vufSV3P83qY429cxi2LJtGYpUF+Ompf2dZ7n+CCm/Oa6j8nJb6NKlxEpO/Ug8X9CplfwejttkfrYctDS3tx+YU/ltkMXpvIrm+wd9XzZTQKvFwBYD+BGzyNbs5zumfWsFcX/zs9i2/uC+LXT8wU8cpx+qxfUQivYTq330fwCSeXJB', 'base64'));");

	// agent-instaler: Refer to modules/agent-installer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('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', 'base64'));");

	// file-search: Refer to modules/file-search.js
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'));");

	// zip-reader, refer to modules/zip-reader.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'));");

	// zip-writer, refer to modules/zip-writer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'));");

	// update-helper, refer to modules/update-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eJytVd9v2zYQfheg/+GaF8mdK2d5jNEHL00xY4UzREmDdhgCWjrJzGSSI6m6XuD/fUdRtiX/QPcwvYgi77777rs7avQ2DG6kWmteLixcXV5dwlRYrOBGaiU1s1yKMAiDTzxDYTCHWuSowS4QJopl9GpPhvAZtSFruEouIXYGF+3RxWAcBmtZw5KtQUgLtUFC4AYKXiHg9wyVBS4gk0tVcSYyhBW3iyZKi5GEwZcWQc4tI2NG5oq+iq4ZMOvYAj0La9X1aLRarRLWME2kLkeVtzOjT9Ob21l6+47YOo9HUaExoPHvmmtKc74GpohMxuZEsWIrkBpYqZHOrHRkV5pbLsohGFnYFdMYBjk3VvN5bXs6balRvl0DUooJuJikME0v4JdJOk2HYfA0ffj17vEBnib395PZw/Q2hbt7uLmbfZg+TO9m9PURJrMv8Nt09mEISCpRFPyutGNPFLlTEHOSK0XshS+kp2MUZrzgGSUlypqVCKX8hlpQLqBQL7lxVTRELg+Dii+5bZrAHGdEQd6OnHjfmAalJbkivN9qGEftVuTKHwZFLTIHBMYybeNa5czi78wuBmHw6kvmcDRawhC42iLGO8eYkhySwcsAXpv+SZ5pp4loxruNl2bjZQwbF9fB8gLiNztW/3D1TiOjXKJBws1XrrpcHDRRaJDjwdita92EtvS18YCtActPJN2Dd4su+vi0f0Kiin2ez95jgRXVIyZAhfnAe7ZCbcVS/7dUW7l80MTNp0kqFCVN45v38PNgb9ah4h7VAMbRo6BuxMx1eCbpJhHWuGkhwGbao24k97SRskoS/+7hZr/EyuDZwFav+xsH555cjsZ2y1QYKk9GNbD4RIOMqaX1slMr+Ami51p4etGQZCwqVppriFbzqC/YAVv3ZMxmC4hx8ENqZ/M/EBZPnW27U/2Ajs8/cW1CIqjxyVPPhM794rSRFHHUcCVJ9t2267KDbPymC7sbqCPlWpcSbVuDbu/9cfnnIFFcYezjn2mQIx02rfAHkxUfj1GvfQ7q0++WWlRc/JWuRXZipE+7uD/UR8rjwOmwt/4r3EkGfbAzAjX92GvHo1TtmT7z2p7V3Rc2yqXYz/ZOfR92Lz92rtcmlG+H3a24v2rDYOP2lzKvK0zoSpHauvvr1f8+rv0LNmT4L6QVhQk=', 'base64'));");

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
	duk_put_prop_index(ctx, -3, (duk_uarridx_t)duk_get_length(ctx, -3));		// [viewer][list][promise]
	ILibForceUnBlockChain(duk_ctx_chain(ctx));
	return(1);
}
duk_ret_t ILibDutkape_ChainViewer_cleanup(duk_context *ctx)
{
	duk_push_current_function(ctx);
	void *link = Duktape_GetPointerProperty(ctx, -1, "pointer");
	ILibChain_SafeRemove(duk_ctx_chain(ctx), link);
	return(0);
}
duk_ret_t ILibDuktape_ChainViewer_getTimerInfo(duk_context *ctx)
{
	char *v = ILibChain_GetMetadataForTimers(duk_ctx_chain(ctx));
	duk_push_string(ctx, v);
	ILibMemory_Free(v);
	return(1);
}
void ILibDuktape_ChainViewer_Push(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);													// [viewer]

	ILibTransport *t = (ILibTransport*)ILibChain_Link_Allocate(sizeof(ILibTransport), 2*sizeof(void*));
	t->ChainLink.MetaData = "ILibDuktape_ChainViewer";
	t->ChainLink.PostSelectHandler = ILibDuktape_ChainViewer_PostSelect;
	((void**)t->ChainLink.ExtraMemoryPtr)[0] = ctx;
	((void**)t->ChainLink.ExtraMemoryPtr)[1] = duk_get_heapptr(ctx, -1);
	ILibDuktape_EventEmitter *emitter = ILibDuktape_EventEmitter_Create(ctx);
	ILibDuktape_EventEmitter_CreateEventEx(emitter, "PostSelect");
	ILibDuktape_CreateInstanceMethod(ctx, "getSnapshot", ILibDuktape_ChainViewer_getSnapshot, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getTimerInfo", ILibDuktape_ChainViewer_getTimerInfo, 0);
	duk_push_array(ctx); duk_put_prop_string(ctx, -2, ILibDuktape_ChainViewer_PromiseList);
	ILibPrependToChain(chain, (void*)t);

	duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));				// [viewer][process]
	duk_events_setup_on(ctx, -1, "exit", ILibDutkape_ChainViewer_cleanup);	// [viewer][process][on][this][exit][func]
	duk_push_pointer(ctx, t); duk_put_prop_string(ctx, -2, "pointer");
	duk_pcall_method(ctx, 2); duk_pop_2(ctx);								// [viewer]
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

extern void checkForEmbeddedMSH_ex2(char *binPath, char **eMSH);
duk_ret_t ILibDuktape_Polyfills_MSH(duk_context *ctx)
{
	duk_eval_string(ctx, "process.execPath");	// [string]
	char *exepath = (char*)duk_get_string(ctx, -1);
	char *msh;
	duk_size_t s = 0;

	checkForEmbeddedMSH_ex2(exepath, &msh);
	if (msh == NULL)
	{
		duk_eval_string(ctx, "require('fs')");			// [fs]
		duk_get_prop_string(ctx, -1, "readFileSync");	// [fs][readFileSync]
		duk_swap_top(ctx, -2);							// [readFileSync][this]
#ifdef _POSIX
		duk_push_sprintf(ctx, "%s.msh", exepath);		// [readFileSync][this][path]
#else
		duk_push_string(ctx, exepath);					// [readFileSync][this][path]
		duk_string_split(ctx, -1, ".exe");				// [readFileSync][this][path][array]
		duk_remove(ctx, -2);							// [readFileSync][this][array]
		duk_array_join(ctx, -1, ".msh");				// [readFileSync][this][array][path]
		duk_remove(ctx, -2);							// [readFileSync][this][path]
#endif
		duk_push_object(ctx);							// [readFileSync][this][path][options]
		duk_push_string(ctx, "rb"); duk_put_prop_string(ctx, -2, "flags");
		if (duk_pcall_method(ctx, 2) == 0)				// [buffer]
		{
			msh = Duktape_GetBuffer(ctx, -1, &s);
		}
	}

	duk_push_object(ctx);														// [obj]
	if (msh != NULL)
	{
		if (s == 0) { s = ILibMemory_Size(msh); }
		parser_result *pr = ILibParseString(msh, 0, s, "\n", 1);
		parser_result_field *f = pr->FirstResult;
		int i;
		while (f != NULL)
		{
			if (f->datalength > 0)
			{
				i = ILibString_IndexOf(f->data, f->datalength, "=", 1);
				if (i >= 0)
				{
					duk_push_lstring(ctx, f->data, (duk_size_t)i);						// [obj][key]
					if (f->data[f->datalength - 1] == '\r')
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 2);	// [obj][key][value]
					}
					else
					{
						duk_push_lstring(ctx, f->data + i + 1, f->datalength - i - 1);	// [obj][key][value]
					}
					duk_put_prop(ctx, -3);												// [obj]
				}
			}
			f = f->NextResult;
		}
		ILibDestructParserResults(pr);
		ILibMemory_Free(msh);
	}
	return(1);
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
	ILibDuktape_CreateInstanceMethod(ctx, "_MSH", ILibDuktape_Polyfills_MSH, 0);

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
