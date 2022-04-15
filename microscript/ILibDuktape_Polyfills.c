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
#include <WinBase.h>
#endif

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

#define ILibDuktape_AltRequireTable				"\xFF_AltRequireTable"
#define ILibDuktape_AddCompressedModule(ctx, name, b64str) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_pcall_method(ctx, 2);duk_pop(ctx);
#define ILibDuktape_AddCompressedModuleEx(ctx, name, b64str, stamp) duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "addCompressedModule");duk_swap_top(ctx, -2);duk_push_string(ctx, name);duk_push_global_object(ctx);duk_get_prop_string(ctx, -1, "Buffer"); duk_remove(ctx, -2);duk_get_prop_string(ctx, -1, "from");duk_swap_top(ctx, -2);duk_push_string(ctx, b64str);duk_push_string(ctx, "base64");duk_pcall_method(ctx, 2);duk_push_string(ctx,stamp);duk_pcall_method(ctx, 3);duk_pop(ctx);

extern void* _duk_get_first_object(void *ctx);
extern void* _duk_get_next_object(void *ctx, void *heapptr);


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
duk_ret_t ILibDuktape_Polyfills_Array_find(duk_context *ctx)
{
	duk_push_this(ctx);								// [array]
	duk_prepare_method_call(ctx, -1, "findIndex");	// [array][findIndex][this]
	duk_dup(ctx, 0);								// [array][findIndex][this][func]
	duk_call_method(ctx, 1);						// [array][result]
	if (duk_get_int(ctx, -1) == -1) { duk_push_undefined(ctx); return(1); }
	duk_get_prop(ctx, -2);							// [element]
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
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "includes", ILibDuktape_Polyfills_Array_includes, 1, 0);

	// Polyfill 'Array.partialIncludes'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "partialIncludes", ILibDuktape_Polyfills_Array_partialIncludes, 1, 0);

	// Polyfill 'Array.find'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "find", ILibDuktape_Polyfills_Array_find, 1, 0);

	// Polyfill 'Array.findIndex'
	ILibDuktape_CreateProperty_InstanceMethod_SetEnumerable(ctx, "findIndex", ILibDuktape_Polyfills_Array_findIndex, DUK_VARARGS, 0);
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
duk_ret_t ILibDuktape_Polyfills_Console_setInfoMask(duk_context *ctx)
{
	ILIBLOGMESSAGEX2_SetMask(duk_require_uint(ctx, 0));
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
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoMask", ILibDuktape_Polyfills_Console_setInfoMask, 1);

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

	duk_eval_string(ctx, "require('events')");			// [events]
	duk_prepare_method_call(ctx, -1, "deleteProperty");	// [events][deleteProperty][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer]
	duk_prepare_method_call(ctx, -4, "hiddenProperties");//[events][deleteProperty][this][timer][hidden][this]
	duk_push_this(ctx);									// [events][deleteProperty][this][timer][hidden][this][timer]
	duk_call_method(ctx, 1);							// [events][deleteProperty][this][timer][array]
	duk_call_method(ctx, 2);							// [events][ret]
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
		char *metadata = ILibLifeTime_GetCurrentTriggeredMetadata(ILibGetBaseTimer(duk_ctx_chain(ctx)));
		ILibLifeTime_AddEx3(ILibGetBaseTimer(Duktape_GetChain(ctx)), ptrs, ptrs->timeout, ILibDuktape_Polyfills_timer_elapsed, NULL, metadata);
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

	duk_dup(ctx, 0);
	duk_del_prop_string(ctx, -1, "\xFF_argArray");

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
duk_ret_t ILibDuktape_Polyfills_getJSModuleDate(duk_context *ctx)
{
	duk_push_uint(ctx, ILibDuktape_ModSearch_GetJSModuleDate(ctx, (char*)duk_require_string(ctx, 0)));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_addModule(duk_context *ctx)
{
	int narg = duk_get_top(ctx);
	duk_size_t moduleLen;
	duk_size_t moduleNameLen;
	char *module = (char*)Duktape_GetBuffer(ctx, 1, &moduleLen);
	char *moduleName = (char*)Duktape_GetBuffer(ctx, 0, &moduleNameLen);
	char *mtime = narg > 2 ? (char*)duk_require_string(ctx, 2) : NULL;
	int add = 0;

	ILibDuktape_Polyfills_getJSModuleDate(ctx);								// [existing]
	uint32_t update = 0;
	uint32_t existing = duk_get_uint(ctx, -1);
	duk_pop(ctx);															// ...

	if (mtime != NULL)
	{
		// Check the timestamps
		duk_push_sprintf(ctx, "(new Date('%s')).getTime()/1000", mtime);	// [str]
		duk_eval(ctx);														// [new]
		update = duk_get_uint(ctx, -1);
		duk_pop(ctx);														// ...
	}
	if ((update > existing) || (update == existing && update == 0)) { add = 1; }

	if (add != 0)
	{
		if (ILibDuktape_ModSearch_IsRequired(ctx, moduleName, (int)moduleNameLen) != 0)
		{
			// Module is already cached, so we need to do some magic
			duk_push_sprintf(ctx, "if(global._legacyrequire==null) {global._legacyrequire = global.require; global.require = global._altrequire;}");
			duk_eval_noresult(ctx);
		}
		if (ILibDuktape_ModSearch_AddModuleEx(ctx, moduleName, module, (int)moduleLen, mtime) != 0)
		{
			return(ILibDuktape_Error(ctx, "Cannot add module: %s", moduleName));
		}
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
	int narg = duk_get_top(ctx);
	duk_eval_string(ctx, "require('compressed-stream').createDecompressor();");
	duk_dup(ctx, 0); duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_FinalizerDebugMessage);
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
		if (narg > 2) { duk_dup(ctx, 2); }
		duk_pcall_method(ctx, narg);
	}

	duk_push_heapptr(ctx, decoder);							// [stream]
	duk_prepare_method_call(ctx, -1, "removeAllListeners");	// [stream][remove][this]
	duk_pcall_method(ctx, 0);

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
duk_ret_t ILibDuktape_Polyfills_function_getter(duk_context *ctx)
{
	duk_push_this(ctx);			// [Function]
	duk_push_true(ctx);
	duk_put_prop_string(ctx, -2, ILibDuktape_EventEmitter_InfrastructureEvent);
	return(1);
}
void ILibDuktape_Polyfills_function(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Function");										// [g][Function]
	duk_get_prop_string(ctx, -1, "prototype");										// [g][Function][prototype]
	ILibDuktape_CreateEventWithGetter(ctx, "internal", ILibDuktape_Polyfills_function_getter);
	duk_pop_2(ctx);																	// [g]
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
#ifdef OLDSSL
		return(ILibDuktape_Error(ctx, "Invalid endian specified"));
#endif
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
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'), '2021-09-29T19:36:45.000-07:00');");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2022-01-03T19:17:33.000-08:00');");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('eJzNGl1v2zjyPUD+A5uHtbz12tk+HRIUh1ya4rzXTRZNtr1FEBiMTNvKKpKOkuz6ur7ffjOkKPFLspLmPvyQ2ORwON8zHHLy/eHBeZptebRcFeTN8Y9/ItOkYDE5T3mWclpEaXJ4cHjwIQpZkrM5KZM546RYMXKW0RD+VTMj8onxHKDJm/ExCRDgqJo6Gp4eHmzTkjzSLUnSgpQ5AwxRThZRzAj7ErKsIFFCwvQxiyOahIxsomIldqlwjA8PfqswpPcFBWAK4Bn8WuhghBZILYHPqiiyk8lks9mMqaB0nPLlJJZw+eTD9Pzi8vriB6AWV/yaxCzPCWf/KCMObN5vCc2AmJDeA4kx3ZCUE7rkDOaKFInd8KiIkuWI5Omi2FDODg/mUV7w6L4sDDkp0oBfHQAkRRNydHZNptdH5C9n19Pr0eHB5+nNX69+vSGfzz5+PLu8mV5ck6uP5Pzq8t30Znp1Cb/ek7PL38jfppfvRoSBlGAX9iXjSD2QGKEE2RzEdc2Ysf0ileTkGQujRRQCU8mypEtGluma8QR4IRnjj1GOWsyBuPnhQRw9RoUwgtzlCDb5foLCW1MOklvcCFm9JV93pzi6KJMQV5KMp4CVTRMQGI2jfzIe8NHD8PDgq9QUmsJ4BhzAWn5qjj3A2AOM7QyMS1Z8TNPiF4k4SO81bJsVGBUOjTNQSqKAhnK2AsIPgAByB7AiYCf/cVaUPCFiC4cMtoZlsxxsFcyLB3OWo+3MQhrHDByioBwIbShTuL6S2dX9AwuL6bsTMjCRDEYE0Z9Ui8f3UTK3EA/Jro0U0DFYIqgpyNOShwy2QfvEr5f0sSZJDMuvONxQWK8ap0ngXTdmYBCSKj+umjSNOMk4ajiN12weNBui5YD0H1H1twMFMLirlIA2GyAMjdDlYJfyEfjMXWUKJOOszFdBDXVLo7uhqU5pVn+//vBeMoI+vg2a0ZFEVDHhMoBaMxjQEFZmPp7NQjDB+S/qJ6wKmI0Rd5foAtpgAxQhOLKgLRgALC0hLF+IAAmrwDgGahc1+VEggUkwJfKa/HR9dTnGIJMso8UWcNsbK5+p8LyHcZsbZZygE7XdQHfLagym8afhsBHkDp7QGKOAYeWKbAUArFRDJ2LpSAZ/BtI9IQsaY0JhnKc8r3/WAGd8CaO3dyOisJ2nZVKckOMRmZXZCUnKOCa7U+V1IqQH0tHywXB8gV8uQMSweIw+FZjEK5uR5I/nbBElDOQG0bGQxjIiR0bMOBo1lqgZJX7AL05ILf1gCHJRcUDuWmbDU7Ibmatyc9WaxqWKYC374CdaVKDk1VsphO++I2oX8laODd11HlT4mUzIZ8ionEHSJnGaLCH8Q8qCwmBFE/8SpMAUZm2oiibP/h004CeMGeXTx0c2j2jB2vArrfk+bSRJiloW7txhz1AjXiJEbyHTVux62RXE+pBHWZHyn1lB57SgTzCuvRaiTM91CkClSPH5BESeP8/eR4nM3+/Yfbn8GSIVlA+DoS35lzFml8T82SSOpG4cQj3KsUwF8uDgX1VSNoSsUSyWGNEJs5nKYV2YE7b5ACUhSxh/A5sEzS6CaZl7xddz4Peehr+7u08mIVRnaczGcbo0UA6qtRLNQIbTCWYJQYr8Db8GTWhtZushXWii0Gu8pplAv6/3wkjT5HKMQa/0DVVManZotW/cy2BfS9gjj9xtBUeLgL9664k6HnuTJEJWmEkn+YQWEzR8jAjvsB+BgW8hugs8nD1CUX0Wx0oXuYYJ4z0JKdR7JPiCCeGpeGQV0olnp2tnMvHpp8KC+ghMITdZvEojf/xB2iFEeh4Ou41Bkdyq6jpz7MkXHs358kNXVjC38eaAXQtxmXGY6KBJeAomBeuoYmDx0MYzLUSwL3U1VXAntSjCjCU9sm1LprWk6MXalmP9JLRm112rsHf7gopmtM+MKd8ST/7PPLxdUJAqi1iX0zcJ5vZOF8RO5bWxXTBbGa4SBwbxOrGpQyD35NHayxpi62r5VOdX13wVf06t2RqF6zvd6Ro/4sRZjbuHUoNUO2E0htmeSYYe57R04dIoz7Z7UdsWS5+3VBM2A+m20tkc0H3n85ZFXQxqh/c7X7ShvSDb3USsj1myLFboKG9QXzh2++OdLBSEArcZSxdBNT4UHpWKon2gwesHZe2k3K5U0ezgT8sJ9V7YYjBP3DZIsWJJYLVaRnbr4jlKri3HCArUFx8VZFBHIF/kqEtHJ2AgkakdMOTgywWMznjwAvGiCt46xH4/6RkAuqx+v28Y6VUV8z2tEYUdcG910lSJbfOyRkTn4d5KYV889K/Ck2VTsTQttVEj4dvjdgH0s+sOm1YtJn/emybYarfM2Z7zWDXqZV25emfANpQTrJv4tX5yaJpMiAgfw8p7wA+oatBhB5lsGEmqu4+KgImUNYkKK8oZZ9zQPELpxuU0Sp3Coeoz91njJD4fGZVj9idDRp7nktE3voq2Xf/jjldXSZr8oPqyMlW1qE1c4ChIcctmK7C26PaGdh6s95yFTYb3cjKP5smgUO0pmmyBAHm3hiw8lHmBNGd0CY4uOBD9nJwsgCbxW1xOxVtxiSXpbGHqf2iSblViBBBZ5zexQnSD/OGBF/64bcdrXnQdDSFX2oc+H/zQTaUdrmXdicmYKjgZ41/nzKBfzCyweRdv9XjZIgQvFSo8P4MIXQ9okgYJejFVVVHeUkTB7cnqHeHRS3eN1k+7ZVmSEINMDyGePr3vhOhZWZvgfgtsNgu8+fubWxQ9OxQ7H67O6PUsI6+l3ktPOgXy/rz4JDo9CdvYl3TazbmOTS4xb6+bI4KnTO5WtlsS3OAbjTpX0JzQmDM635LGIyBAA56cgBzC33EnDMYrmsxjxj21hHsg4nWpo1WO/YoeyVvA131bvAJ4f23UgUGIfd0m8hboDoevVNiWZ+xpt+XSa7vabj3b6SXO07bzXIa5Wb9Ljq28i8sdexqod4oODxnPqUP2heUX1dK+2PJiOvI3Qfaf9PeV7+0HHW874D/NqnukMwsyfFQkEJmRE2JLtYFeBFRlAN86CV57L9FcPrZJRC8TG/I90M4Bw60eK91VXWDPOyY7eHa1OTwZoD+kan2wu3ZgeVDWU6VzlraBnVO1UgOE61d78pZxD0quKZxvOFswiM4hk08DIYPJ85CufflU7dZCPlvRfHWezlkwvHOSUjsXdvHpvY+3HG3OkAubEm1/3cAtS+h8PlAL6Gik79n+UMButBhvUzxy910EtPXzbMkEXbfofS4ALWKfcvG359LP7Yw94fJO3sKJ7pb31qwvA73u3HretRkMVeZmHlvL7HQPhBFH9wBnNZQfrn27p2yje+EL3MV96z2cdQcmZK76AKrf4jb/rPeP3spfO32OyIPYUhmC3m12Hkrueyfp6xE7ryTb6x3ZKHVLM71p2rwxUtkVM2sjFtE1NKQinkEOyX9JJi8hjipvf7s4oJLQZYGFRWXqaIeOobRLhMkTaFt5MNPuVuCrk83qe1kxn7vzGlUAov1yQedpwtruZcHZ8a0mTB8rITfpw9SYKQeLK20SFCbvvvrkN6wSyhAf2TrnyNevQcANgaJsNBmvLg57PbNr5NDydEPC1NfhzmZd5bxeZICtdbL7nkZxyZnD7quGyJdlqLquQ7o6WLB8DFOoK2nUwrGrfEt0HqFZr/fhv3K8w4PHdF7GbMy+ZCkvMGI0mcecGpttHvUWrR5oW1C/wq9X1CPuEijjaBkX2OLRA4E23Ph2k6tUakFXVWNVXEXvJrt/A1nU8Oc=', 'base64'), '2021-08-23T14:25:14.000-07:00');");

	// util-agentlog, used to parse agent error logs. Refer to modules/util-agentlog.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'));");

	// util-pathHelper, used to settings/config by the agent. Refer to /modules/util-pathHelper for details.
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJy1VFFP2zAQfo+U/3DrA0lZSEu3J1A1dYVp0VA70bIKiRc3uaQeqe3ZDqFC++87N8kAMWli0vIQK77Pd9/33TmDQ9+bSrXTvNhYGA1HQ0iExRKmUiupmeVS+J7vXfAUhcEMKpGhBrtBmCiW0tJGIviG2hAaRvEQQgfotaFe/9T3drKCLduBkBYqg5SBG8h5iYD3KSoLXEAqt6rkTKQINbebfZU2R+x7120GubaMwIzgir7ypzBg1rEFejbWqpPBoK7rmO2ZxlIXg7LBmcFFMj2fLc6PiK07cSVKNAY0/qi4JpnrHTBFZFK2Joolq0FqYIVGilnpyNaaWy6KCIzMbc00+l7GjdV8XdlnPnXUSO9TADnFBPQmC0gWPfg4WSSLyPdWyfLz/GoJq8nl5WS2TM4XML+E6Xx2liyT+Yy+PsFkdg1fktlZBEguURW8V9qxJ4rcOYgZ2bVAfFY+lw0dozDlOU9JlCgqViAU8g61IC2gUG+5cV00RC7zvZJvud0PgXmpiIocDpx5eSVSh6H23OJXZjehotdxBG4ZRa7f09VZ3/cemtbwHMJmD96MQVRlCQcHjygHaZHuuWNUVd5SRRiD0jIlqXFaZ2E/NiTWht2eKpkllVsYjyGouXg3CuADBDc3AZxAMAjcGHZJm4Sxkir803ZlWg2vLdFkfJpyn4aYt6m/Sy5ezfhnN9TOub2psbFMW7OiAQiDOOi/tK2DHsdWXsga9ZQZJM9QZN0xvEc6CQ+/ObaSq7UbU1GEw6jdKlEUdCGP4H3/1LF5Lu5tc3L0yNYtWBr8SzP/xeHXN3H0H9rhFo220qJ12cX2bdrKrCqRvKXfp3Uqu0tx6qK+9wtCYKEt', 'base64'));");

	// util-service-check, utility for correcting errors with meshServiceName initialization. Refer to modules/util-service-check.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-service-check', Buffer.from('eJy1Vttu2zgQfRegfxj4xVI3kdLsW4Mu4HVdVEhi70bOBkFdLGh5JBOVSS1JxTaK/vsOZamRb7kA7bxIFOdyzsxwxPCN6/RlsVY8mxs4Pzs/g0gYzKEvVSEVM1wK13GdK56g0DiDUsxQgZkj9AqW0KPeOYF/UGnShvPgDDyr0Km3Ov6F66xlCQu2BiENlBrJA9eQ8hwBVwkWBriARC6KnDORICy5mVdRah+B69zXHuTUMFJmpF7QKm2rATMWLZDMjSneheFyuQxYhTSQKgvzjZ4Or6L+YBgPTgmttbgVOWoNCv8ruSKa0zWwgsAkbEoQc7YEqYBlCmnPSAt2qbjhIjsBLVOzZApdZ8a1UXxamq08NdCIb1uBMsUEdHoxRHEH/uzFUXziOnfR+NPodgx3vZub3nAcDWIY3UB/NPwQjaPRkFYfoTe8h8to+OEEkLJEUXBVKIueIHKbQZxRumLErfCp3MDRBSY85QmRElnJMoRMPqASxAUKVAuubRU1gZu5Ts4X3FRNoPcZUZA3oU2e66SlSKwW1U38q1E9kEZ/jslXz3edb5uCPDAF+uLxXWEG75uMe12yPKVPNkPrrt/SK5iZt5YPLC9RV5ZZ8HeJan2Ja88uPl0O7oMrmbD8murNBfVkNx59HFMuB5PJqEABsSxVgj/c8xS8jb9Al9OvuNb+ZqOGbMXmzbOBua36Qe0dCytEYvvDzr4V3aZfJ+10wQTVRHX9oH4LMjTxZnMH62f+pSHSFp56OuD6Gj3f3989gKPCEiS51GRywKEVhaZUYjdbRxB83/+EucafAmbH984yYSaZg7fyn0x+y6h+/d5MjTCEW1GdeTrlKRczmjOLyikVv91bYdNZYbuxmjZ9VYvex+PB9WTSL5VCYfpSGCXzGM1kUtddv7Zhf02/2oP4E0lNJl34DfYaioyjBTX+XxStu9sBh8rtrZ4pd6VJALgo8Wl/NUP7CDQNUuN1A1zhHgw6YpVOjiIz8z/ePh+/9lyZfT77QsQPe9543+gF2jBl9B0Nea/b6fo+fNtGWE7t70Rk3lv/4tChq2HCezJQklKubczEZvblk2GvM57Rt/KLJluL1xMT7gX4KozPTLxGXjX5GjlQjJfGPWK6aXXEI4SPkD3g7PgAfZyF9tHwFmWeW6zViNR0LyMYTTcVOTM0bhaPP/mE0VXD/st/P+++e3S9kLMyR+o+ulMa2x2794RWMqYKWbOeYcrK3Dzl6cfVw7PnYxt1m13jtuLxPwpX1LY=', 'base64'));");

	// descriptor helper methods, see modules/util-descriptors for details
	duk_peval_string_noresult(ctx, "addCompressedModule('util-descriptors', Buffer.from('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', 'base64'));");

	// DNS helper util. See modules/util-dns for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('util-dns', Buffer.from('eJzdV2uT2jYU/c4M/+HWbWN747V3SSZNlzIZso+UZsNmAkkmAyQVtgyaNZIrycuSLfntvQKzmH0AmWYmnfoDNtJ9nHuudGwFO+XSoUgnkg2GGip7lX1ocE0TOBQyFZJoJni5VC6dspByRSPIeEQl6CGFekpCvOUzHryjUqE1VPw9cIyBlU9ZbrVcmogMRmQCXGjIFMUITEHMEgr0MqSpBsYhFKM0YYSHFMZMD2dZ8hh+ufQhjyD6mqAxQfMU/8VFMyDaoAW8hlqnB0EwHo99MkPqCzkIkrmdCk4bh8fN1vEuojUeb3lClQJJ/8qYxDL7EyApgglJHyEmZAxCAhlIinNaGLBjyTTjAw+UiPWYSFouRUxpyfqZXuFpAQ3rLRogU4SDVW9Bo2XB83qr0fLKpfeN9u9nb9vwvv7mTb3Zbhy34OwNHJ41jxrtxlkT/51AvfkBXjaaRx5QZAmz0MtUGvQIkRkGaYR0tShdSR+LORyV0pDFLMSi+CAjAwoDcUElx1ogpXLElOmiQnBRuZSwEdOzRaBuV4RJdgJDXpzx0Nhg13gkxupTxJXjlktX805cEInEaqhBp1ddDrEUR3LCHfvTC8qpZOErItWQJLbrH0pKNG1i9gv6WorLiWM30mGSkpT5UYIWeSyW5qavqB6KyLFfUN2keizk+WsiyUjNLJd5I6LJNpnfEclM9539vcpjtwA8ofyr/K+d0dHX4nkWx1Q6rm9WEH2L2+1R5fT4OkteVAwOFnazFMeA90wg139HEqjVYM+de+RkX1fJ1SmuNgRqXPwjKmnsrMH8WjDc97LFPlMT9Sk8g8ovFTiAypOnHjx+uoRmrkgsnwuJzYWd9tNMDZ0cwVel9mD/iVvkSIsW7hg+cNwFieaawnhopMNxCmWupNvz1jWokNHNHdylIxY7Z/cHw26edjq/YXWZ5IDlaDMzLSz+hPHs8o6lHyLUqLhgZgOfUilC3LSIhl7S8ATLceygz3ighrYHHRtvvUXymYevdCQyjTeJ0Wy7ujosuGObVqPzNSQndOFqJrUzr4c1CAuMVmF6KwGV8u5IJtBtc8bnq9ixQqIhoDoMUIlEcuGHgsfwN6BipsDJiCoqUWVwBHHYXW6D/aeN/8j4HHZPzLNt3R/dvrLXTOLo0fFpzbKqG6xSrFvHYHU2WqJYOqy2X2W/NU+qDx8yd4P9JnyzHe38xL4EH38MDJVID749Moo9sN0Nnp9rCkVdo7vX9ixAnrbK9rlWq8CDB9Du7PdqNWvZBGtTNdsVVCD0Z9XtdvNfy8NmeO1OpbcFzEXrvI0dMVtwg8mm+QXa3tpk1nTtSuxyesk0LuBVmzFh+hgnnMWwlpNbujwXD+eP1lnTT1GMqHNzY/u4NUeodTdUBzdXOHTobaVfyFGnV/CYrryTRyQUd72R/2eydG87VZhplsDuLlJwvyB9Z0W6+m6KBF8g+Njtqh3Y6Xb1zpKZbrfT2dv9tdcLvplc1AtCdvZyWym7oTPznwNYPFme4doDjNh51Jvf9/+z2jPdSnv+lfrcrz9m2+vZgaYGW4hQ9ZZyzZz9czpRzjeQKIWHvHAITi45fpoQjct8tNSpkODBxZ59WNkHxaEYD2J9FS0GzTUSUYbg8CwkpFZY4fX3WKGOPn6Zn1eLkfDI8qiyNk7hULM2UkQkmq4Nda3F9wSKaEyyRK8LsSp9RXJhekdUJPof7kamjA==', 'base64'));"); 
#ifdef WIN32
	// Adding win-registry, since it is very useful for windows... Refer to /modules/win-registry.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'), '2021-12-03T16:34:49.000-08:00');");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('eJytV0tz2kgQvlPFf+j1RSjL8rJCEVM+EOxUqPWCC4FTOQ7SCKYsZrSjkTGbyn/fHkkIiad2KzogNNPzdffXL6n5oVoZimAr2XKloNNq92DEFfVhKGQgJFFM8GqlWnliDuUhdSHiLpWgVhQGAXHwlu7U4YXKEKWh02hBTQvcpFs3Zr9a2YoI1mQLXCiIQooILASP+RTou0MDBYyDI9aBzwh3KGyYWsVaUoxGtfI9RRALRVCYoHiAT15eDIjS1gJeK6WCu2Zzs9k0SGxpQ8hl00/kwubTaPg4th//QGv1iTn3aRiCpH9HTKKbiy2QAI1xyAJN9MkGhASylBT3lNDGbiRTjC/rEApPbYik1YrLQiXZIlIFnnamob95AWSKcLgZ2DCyb+DzwB7Z9Wrl22j2dTKfwbfBdDoYz0aPNkymMJyMH0az0WSMT19gMP4Of47GD3WgyBJqoe+B1NajiUwzSF2ky6a0oN4TiTlhQB3mMQed4suILCksxRuVHH2BgMo1C3UUQzTOrVZ8tmYqToLw2CNU8qGpyWs2YUpVJDnygmrW8QEgCxGpJM70nTqR0lRWK17EnXg/IDKkNdx6JmplVis/kri9EYlhUC/Eh3v48bO/X/VCXEkjVDO80DDzmy5uemFDBJTbW+7sgOtgyEVBcrFVNJxS4ubWXBF+xRX07x4+R55HZYP4vnBqXSt/lKvTUp2ClAhSsf4uF2OCiBuT9zCxYRVvJ3uZOYn9Ev/F9ntufW9WHVp16Fp42yliHtSy7fjUHAu33X16rLXMhhI2Jhpf1tpd/TAPMLJDgnSb8Ns9GB8H1oNhJkAp7fpSKyk2UDMiLqkjlpz9oyuBcSK3kMQ1I/LnKdfGs9Ke7ZiMHds9NHzKlzpkx47ddtCxbsvMu58dC3VV1xDIynlurOi7kbrbsj628Lrgsm5LBJ4f45aU91LfQuxGziqnsEC3VaT7WIeDxIPRthzjTtN120FO1X5bX0nCNxKSkS7jvdc1+kWZBWp97R/C9rpdK8HtWmVwUfoKrks9EvkqxpzzVy42/DKobgwe49S9AJzlS3oYawR7APETQm3MNAQ6zW8ny/mzZweuGzfA+wuZA7/jeDtZkTu8QvJmRXxY62eN3Fl5Ke0z1Djvs6cSia/NL/aiaD19GRzQX+BpuKLOqx2tn8V1Ziz86VpFnjWzE28oXB2bva2F45Z56syI42wkvu4fD0SR88d7J4/PeWmAdsfM3N6V6bHo9bZ4tmpbn/NVm3bDYp5nkThj46eO2T9ZQUMqlR7FRNGZHo77ND7rba8kVFpR53Buy5qkccrmD6KeBpVvxFZEqrJlqsE+dUu1v84uPkn3+1/xabfKsno9QJb1awJk/ZdAlw6Q1ft1AWq3D6N9bpAUpXYTNx0tgPoj/XaKbSx+R53suvFfZMmcOzBQ15mea12s6MvTqOj9ENXrUZakStZR9FvG5VQ47hv5yUIi/OWKObqHOnsEbP3cx28Xnqxiy9KP+oTHZKgAz8itucfU/X7lHo2iQo4cjhqUj4cM3rPxcsWXHFoqmbP5ULnGLeRGy7xkzjFgbN3xckljMSv2nl21/ISa/YviAvMFX4sugzxsnmJVCHbC82Jeoe+OL0KaOp+bcfobKc0ovRq/Fa2FG/m0gR9xQipde/GHUZyD1cq/OIedMw==', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-authenticode-opus', Buffer.from('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', 'base64'), '2022-02-08T13:23:45.000-08:00');");

	// Windows Message Pump, refer to modules/win-message-pump.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-userconsent', Buffer.from('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', 'base64'), '2022-02-22T14:19:18.000-08:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'), '2022-02-11T16:57:04.000-08:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'));");
	char *_windialog = ILibMemory_Allocate(39033, 0, NULL, NULL);
	memcpy_s(_windialog + 0, 39032, "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", 16000);
	memcpy_s(_windialog + 16000, 23032, "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", 16000);
	memcpy_s(_windialog + 32000, 7032, "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", 7032);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-dialog", _windialog, "2022-02-14T23:36:40.000-08:00");
	free(_windialog);


	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzVV21v2zYQ/m7A/+HmD5XcqkqXFQPmIBi8xG2NJHYXpQ2COAho6SyzkUmXovyywP99R73Y8lvbtWix8oNFkce755473dEHT6uVEzmeKx4ONRy++PUPaAuNEZxINZaKaS5FtVKtnHMfRYwBJCJABXqI0Bwznx75jgPvUcUkDYfuC7CNQC3fqtWPqpW5TGDE5iCkhiRG0sBjGPAIAWc+jjVwAb4cjSPOhI8w5XqYWsl1uNXKTa5B9jUjYUbiY3oblMWAaYMWaAy1HjcODqbTqctSpK5U4UGUycUH5+2TVsdrPSe05sQ7EWEcg8KPCVfkZn8ObExgfNYniBGbglTAQoW0p6UBO1VccxE6EMuBnjKF1UrAY614P9FrPBXQyN+yADHFBNSaHrS9GvzV9NqeU61ct6/edN9dwXXz8rLZuWq3POhewkm3c9q+anc79PYKmp0bOGt3Th1AYoms4GysDHqCyA2DGBBdHuKa+YHM4MRj9PmA++SUCBMWIoRygkqQLzBGNeKxiWJM4IJqJeIjrtMkiLc9IiNPDwx5g0T4RgZC1Gc4j+16tfKYRWHCFJGq4RgeF0fZkj/kUUALOde2lS7cj5X0yQmr7uIM/VeUGXa+5KKY3FpTLgKurDt4BrVez5vHGke/HfZ6fT/AgGtzqubArZW/Ww5YByiSkZk8+olSKPTCuquXUbixDmSi6aEIkGUdrS9LYVsB04xULF20/To8ptmbnnp2DL6rpUdhFaFdP4LFlgFUarcmo2hDfMq4bs24ts3yisGIC4wJ4SZol8yO7LobU9C1bfVUT1iFwvSMGw/5wGjbeC2Um6SwjQVuUjqVqWc7efwKBFo+UMgJQipzy+8Km7A0WIg+4JzksgMlg2WRCYsSXAl9kFykmnJ/StKUO7ek8I6E00P51iJ70G6iiEl6mkOLrVS06ewqGQvxNHrLXE31bx6Pl8edzPB6Sv/AHCYk6ynswArVz5TOZXoDjFDjVoB+MLUZipTIHRT/ZNyW2EVhupbHBnghA/RQTahg23H27LARlj+JnGXi77nC0DSoOZF8Td0tjc8+gTdnrRv3XPosuqDmSkWBCPRuvKvWRa93kvF4IoVWMvJQ01I2p8gQqr6UtNRBPZXqodezKGYlcA6IJIqMumzN2kweHn+Ra1nrCcuptO7D0Uouq1mPlJcDlkS6AZaQAi0oehbJ024mRQrcvxNU84ye8DtSYZIEfKb9IdgfHzDNgvVSRpDcHDQcH+/njG4eX5wT5OxWD9iXBqfLD/nHJ0p9vRmkPNmz9f612Pw26KKkmdI2ffvs+1aeeJhQbZiKZekpFtLao9JfU4dSJL8cm6T/M52XikTDevG/urKkmny6DcoI3UiGdllT/eizJYoPYJUo969RoOL+BVPxkEVE8Fu6CGhUHv8HTTa/hCdPVtGQJgRMUYzraarPfn9prQI4kkFCmOgqLJWmi8pWBu8sio3dy87q2O4Pp7Fn3Snyq1FMnO1y1dheypM1owmjGD/j14ZvZuT3mUYxcfI7TCN/Oqum21hNna/l5Wu4CXNAYQ7oW7gq+Mreuv0P6GtTCanAvFWS/sjoub3OnQM1U0+MpprzKRob5ca7vrshvFYtPyNnRnr33d+Qym3lexXT7tg4ZopPNnuf3n7KV+7yiOl/uGk+k/ru/T1+muEz+tN52NgvYEbRxiyv+ap1f9E9bd13WlfX3cuzvZCK0VfIHj4hU7Ty/wrgmwwvdi8XVia7dO84k7f82Q7W9zC+9KPTvbxonu90YsNQ6TWt24t/ATXtbrU=', 'base64'));");

	// win-dispatcher a helper to run JavaScript as a particular user. Refer to modules/win-dispatcher.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('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', 'base64'), '2022-03-28T11:52:49.000-07:00');");

	// win-firewall is a helper to Modify Windows Firewall Filters. Refer to modules/win-firewall.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'), '2022-04-15T15:12:33.000-07:00');");

	// win-systray is a helper to add a system tray icon with context menu. Refer to modules/win-systray.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-systray', Buffer.from('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', 'base64'));"); 

	// win-com is a helper to add COM support. Refer to modules/win-com.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-com', Buffer.from('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', 'base64'), '2022-04-13T12:34:25.000-07:00');");

	// win-wmi is a helper to add wmi support using win-com. Refer to modules/win-wmi.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-wmi', Buffer.from('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', 'base64'), '2022-04-13T23:23:25.000-07:00');");

	// Simple COM BASED Task Scheduler for Windows. Refer to modules/win-tasks.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-tasks', Buffer.from('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', 'base64'), '2022-03-28T11:39:32.000-07:00');");

#endif

#ifdef _POSIX
	// Helper to locate installed libraries and binaries. 
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJytVl1v4jgUfQaJ/3AnGo2TGRravm0RKzGdjhZtRaXS2WoEaGUSA1aDnbEdaNX2v+9xkjLQj33YHR4wub4fx/cc39D52Gqe6vzOyMXS0fHh0W80UE5kdKpNrg13UqtWs9U8l4lQVqRUqFQYcktB/ZwnWOqdNv0ljIU3HceHFHqHoN4Kom6reacLWvE7UtpRYQUySEtzmQkSt4nIHUlFiV7lmeQqEbSRbllWqXPEreb3OoOeOQ5nDvccT/NdN+LOoyV8ls7lJ53OZrOJeYk01mbRySo/2zkfnJ4NR2cHQOsjvqlMWEtG/CikwTFnd8RzgEn4DBAzviFtiC+MwJ7THuzGSCfVok1Wz92GG9FqptI6I2eF2+vTEzScd9cBneKKgv6IBqOAPvdHg1G71bweXP1x8e2KrvuXl/3h1eBsRBeXdHox/DK4GlwM8fSV+sPv9Odg+KVNAl1CFXGbG48eEKXvoEjRrpEQe+XnuoJjc5HIuUxwKLUo+ELQQq+FUTgL5cKspPUsWoBLW81MrqQrRWBfnghFPnZ88+aFSrwP+FRpqPhKRK3mfavZsKAxWYa50QnwxXnGHWCssNvw242EAxibo6szm7ITb2qsuQENjno0nna3lmQpsxS2mqCQlYa/68wsisWtSL5CTiHrzKTq2CVr05hhmUZVljIgti7VhcNikIyxV7a0ClnKHUf89lxhEtF9Kdky8lOPktjpEbhUizDq0uPzGlLFXh8iDPKbBdQy1xTQJ/KtwRLQAyENm0wU898PDAa+uSGGKrxnQaEL3x+2ybVpEoyW3CvyXM4s4bxrmYr0ZIJLRXIe8l7v2GOrYtz4eNqmTM58XOWTA6PzpvHRFEDpkW2LP7AaQl383iesix+10Wrr08RWI9HvR75Klez9UZVoosStdBMV7J1+w6U7gz2Mujt8WrT7OQMx+rcKo7gqiXSsDoFGQh8m/T1DbFRaS8U0GsD4DraxnCIHN85e4xKEdWcZ0LLIQ020wvUsBKBWcT7hGijuvesJVSkeq4KN/y+vf9PXrxPYKwpjW4UdZBDQVmSeVsyrvLSt4x2rJ3vCdpQGsp2+aVPQqVWFpzGf9nrBfmzwQgOTrQjYPsLnKmis40wn5SR5Wwm1K25/nBd2Ga5rS8UgzIVRIZbaPDOC3/ifftxXoyQD5bflIKH6U0VRuGV2pZV02hz4loHYhXC4WQM8VIMr6u4EbysAwePepFty+1kqbu5CyKGadj5AzunFtKN3vSdg9OEDvbr9NAJ9g58Qz3lmRVTq16f+BVOw7NMbMn2x959lupfp5yDc4E0l8A70cxDY6jFYD55aVMfPp8rPXHuC2iX2DS2VbS1FWRK30mmRCfQHf2qcH0b+VdV9bo+3tMJj+xtu/wBgt82A', 'base64'), '2022-03-21T18:50:50.000-07:00');"); 
#endif

	// monitor-info: Refer to modules/monitor-info.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('eJztPdt220aS7z7H/9DhcYZkDJOirHgdyZwcRaJsrnXxEWlbiaRoIKIpIQYBLgBeFFs5+xHzuH+yD/sv8wP7C1vVF6BxJQDJnmQ2fRJLQndXV1fXrQuN6v/97/9pf/PwwY4zvXHNq2ufrK91npO+7VOL7Dju1HF133Tshw8ePtg3R9T2qEFmtkFd4l9Tsj3VR/BD1GjkHXU9aE3WW2ukgQ1qoqrW3Hr44MaZkYl+Q2zHJzOPAgTTI2PTooQuR3TqE9MmI2cytUzdHlGyMP1rNoqA0Xr44EcBwbn0dWisQ/Mp/DVWmxHdR2wJlGvfn26224vFoqUzTFuOe9W2eDuvvd/f6R0Oek8AW+zx1rao5xGX/sfMdGGalzdEnwIyI/0SULT0BXFcol+5FOp8B5FduKZv2lca8Zyxv9Bd+vCBYXq+a17O/AidJGowX7UBUEq3SW17QPqDGvlhe9AfaA8fvO8PXx29HZL328fH24fDfm9Ajo7JztHhbn/YPzqEv/bI9uGP5HX/cFcjFKgEo9Dl1EXsAUUTKUgNINeA0sjwY4ej403pyBybI5iUfTXTryi5cubUtWEuZErdienhKnqAnPHwgWVOTJ8xgZecEQzyTRuJN9ddMnUd6EpJV9KwUReP6rj82OTNG8czERY02pDPBuav2Om5/PvAtMWjDnnxImx3oC/V59+K5xeHveHF+4OLwXB72Ls47h0cvetBm7UtZIF2G5CZwOzaM0DXRxxhhv5NWtft3V2ELfvphtFe1WV49PLlPo62Lnv5ztUVsEu002B2Cas+G/kzlx5TA0gz8g907wN0bLC5rK9JCqlNDx3fHN9EGna+C0gJIxw4BsCbWvqIshnzmpPti+3h0YFC4gNA+FX/cDi42Ht7uMO5SEIMRg4b7fZ2jo63o806stkOMJftHwCzIeN0ydOnsuJ9b441EXQ7KrpIkJ1r4Dkanfx6vBGfOJJVMsW2fSMrhzdTOduHD8Yze8T46Yr6++Zl3x47Dcu8tPUJbT588JHrAQQwujYtQ2VN9uAC1mkEU6k3W3RJR3ugjBr19qVpt73rukZO6/DjHLFDMKxHy/MNZ+bDDxeg1etpdY7dqBu6rwOEAL/G6Hpmf2iSj0ztse6Pu4Q9bPnOAHSCfdVobpHbxGim3UJFQxu1BUg6BR1iGSPHHptX5BPRFx9I/SOwm2n75NE6ua2f2XRp+md2LQpooZt+DyoazS2pHs0xYhWdUwsQmTSa5CucW5O3E1SUlAxG7yYoInpvhR3ugeyrSP95yJ++BMHcH5MaeTKFBQB7MCX1GjwQbIdVLc9p1aESRqmfndl1Uv+5Lhbryd7PwYKNyVnt9Ky2hYq5YXY7W+aL7uHe1uPHJiCKIOugqi1Ys0emRkDKfY3UmrCu4ik+Oe2c86p1qGtgnTl2lt2wwfrpOrSAh1CvYT2gOerWYNDrxUifdmtrcvyxw1CAHy+6CATxgD+QZua4wSHCg1N8CCB/sT8ASIRWa3a769iMgQ6aADFzOrLRN4OuGa3WlogyxxSewFwQKmH/Q5ETRfr4DnYgnAQN+AtI8xVMFKELate+9j6enSHO8O8mgX++9uAfDX+b6v518ikbOfkYJxp5egvPG+ZX3c73QORNGJThwxYHfy7hJwOlMRrBHG4DnM6B/rdngdjWkwyYIrpYfPcm/EORUSmncxCSfx8cHbamuuvRLElXh5NKYd6yqH0F3hdogTWkn0vBHIEQzVFCwvbKryPdH12TBm2moiQa3kr0wU4eOoEi0dBrsR0YxZtZvhiMGqr6+hyKu4jSSCiMFbqaum46JASUo9rrlkfAMb1s1yOKpN76ps5UjapK/haqEvy9LjTFbm+fibXkq9OIXgnUCgrHo85v7Ubj7AzUVBN/nK49+e78cfOb5qN2UloSggG8DmNpj8wtPqaGDExWM3QKM0fYWOEXyW8F2FeCESwW48MUmKfnSpfbiA8xcWzTd2Aa4ESE3gNb/4ujy1/Aaeujh1gX7Z5gQ2mFeKuricqpFy+pTV1zdAAzuNatetT0Cg5uoZaGhYKeAHph2k/XUwwvBw+7JvfpOgwhR2vtuFT36SH453MKDtLyplHnjVqGZUV0iQpBdDug/rVjNOo9ezbZNUGV6jcHfGpe0a6i/R74+e9N23AWKR0/wNaCWivxls0yMA+qowi8BL9P9/ye6zpuvbiC5DC965Hj0hV4DV7BRpgmsIpDSeK1OzX3HFdQKNI3qTiXy3TNmYKrPbOsdFiRyWMncIrRI4ZOqp/cF/ydMRzaDpP3QiCxKUsxsulCbvgaoZoDFe5YsJXUoB3Ki+M24+DDGSniBmOhleGdN0kSzGbwG+y2qTXeZChqQD7LutRHH/jfbAmB8kLuXlrOpW7tiCaNjSa53SqATEsCbSlkiLQoBMVY7IIVgO4BZlyHDJ03vttItI/ybgHkuLn0YIDT83LTQgsVpY1qq45swbKMT64BAjgvxgjWQsOwTfqKYkGlxkZV5nnxDhZifMOf8yVjMJrpIDIgY0G2NKYmTPe7ZynTVZt516oWjmjrphSkHBA4D485PyhqGZiuwFaisuQoZ5sEoTbe6a6JcSZg0hzMJNSbSlDz4XrXrbjOEou/prFpaGzYVehxzLA9uEo/zMZj6jaawKu68bZv+0/X93uNPBC3eWji1N1LnHhrF3bC4wZg1nnWVAbKgcw4UMhMazrzrhuwYaFjHzTLJcNPorfGnPdp4vkGPGcx0kTNc6i5dHzfmSSqOutQB8TYZIS5zV8GNj+pb5jIoqpT7BLGZa9WzNNtvdMtFsfKaSOUuJsF6Db5OAN3FBau4IR/kOJM4DrBf9kaKa2Oq88mnw3fh6TjKg1Dox44Al30mjlWgdugOgoNBjZr8pw6KZUpVKGWR7MR41YsqesTSjwNlYQo3DZTfAjxg+GR6VVapj1bpniVsA/bM13PR/LbV2RBiS2i2wYoaoxWUx/jwTYlLPbEQr8nnQ5uUVzQLdQjLOot4fGJjq7p6IPqc/Anq1yOZWIn2viKAdx3Riz+fAEj7/d/iCnkFOIzxdvpCOutRAaBEJcAJOHHYcHgeMNcYlxf9E3R/DmWT3SSW+cuRqk/fZKwTs3leYuFALCmtlYrbwAj7myJfli4RW4ZdAxrKQOpjC81Uo/RF3yBj0BCa0Y3I9jjRjAaH0srl6CoPuQr+KwquXdbVjO5GZDTVFmKt5RG3JzVlmJG7flpgoDnuIuuSvJ8yLgABafEyBndWORMLAbgtoAsDgfDgrLoe36GMELNSmkUvUuKo+iVkEfx/I8ikEDkiECq6P8pkaLkSiRSsJxExmieD7msRJIyIlleKHsnRYWSLrOEEmpWCqXoXVIoRa+EUIrnfxShBCJHhFJF/0+hFCVXKJGC5YQyRvN8yJ/TTJaXyb3+SW9QUCrH5pJ6GXLJ6lZKZgChpGwG/RLSGdT8UeSTETwiodEp/CmjouTKKKdiOSlNUH4V9H+aQ0tSBPV10c3lh8t0EYUKPNC2UkZ5/5ICyjslpJM//qOI5uvo/lJB/k+hFCVXKF+X3V6+Lra7fF1hc1nKlc34U76REY/AfqZGsMYupZeekflmtFrMCST23oJOuGp49EyNy8OfT2B9DOrWm2Hw6XTtvHmXCAHAaVmiOm3J7m3vXmxKbAtfek6xPVbpOaWp70J7n2KTYlug0pOK+aj3MqmCzmOxaQkPsvTEEma9xNTih3+yRJwHqdGkldQAwXwpnj/FI0HsIGpvYvo+dVmsXczJd2e02RqxdymsTaP+YT4ZzKZTx/V3qQ/EoEby7AG0uVh2OhcedefU3XNmNh5IGuuWR+NND46G/b2Lvf3tl3h0NlP54FlbPIp7sb2/L59tBgdyiZbR+rg36P/Ui7TuZLdmB6GjsNdzWvcP+wccumz9NKf19km89UZ26539o0Evism3TYU6t3EyXix99naBH/ONVsFqJLW9fLhC4bsUDHHK2mFh4tdIU/7kL38haRo09TkqodXiqlitxNu8FLVwL1gV0iFcAWGX4t5p0CX/JE2qXc1w5QKQsWM1J/z8uNRVqY52gf78rNK2Lz7FSN9U58OxHI+K95wVeju2TRnrHs4ml9StBAF0kT+gFodTAQL78+VO1Z4p571K9B7gZyqVYezSsT6z/B3HAvOgTysDGIAtoBVot0s933VuKqPv6ot9MLkVenKOe0XxIELl7u9Nw78u33uPgtN/qE8q4L1nzbwqI8LyfEnOfkn9bd+ZVJsjdOYMUV07vaY33s1k6MDPkWNUwAFPiLg2zqF83wN9Wo2hP5IJ+2WT1E8OwXNmrlUdD3XgURjkOdwtbjL3K3uHXxK4TRe4TJHHgxt7VC89Qv3kaErtyrr8DbUN074q3/HYcfyqGoTr/b49nVXQAlzr7YAfW7nz0bgyve6GOhCbc0CFrv6e49IrF/33at2Fu1mpM+r7uzgcAOIQjZ31ymSbnAr9A2fhaGFX8TkQxOxywVj2oJJ6AgjvD0A9+s7IsapMwocVrKadmW4o3esHSx99eAO75uTh75V931+bPq3Yd+aPn0tioS0xBctUs/fCnFQgONg06Hzp6K4B5mFaSc/xD2aYUQPjVtVlL4JG6ulR/vXn3b9BlGV0XfxLn2S/+CdI9/L9kVoyDwHGAihqydjXcezCj5SmHnmiL+VHjyepn6wpSxF/hGcU7zQ2rTw0QMv4ik4W/jHsii9hC+DdbpMTMmCBIjJGS5PeLDfylhJvUmNvBdwoOjHTY1siBvYZFkyGVhD+avCxP5MjpYySM0Iy5M0by1CIiCc9fkxekM7zouGZJR/Po/7QnFDgC+VLF/9a97l06n4Yk5LBRqgD8dRIZw0KP92cE+VJhr/CcJZSVYxn+IIzfrmi/mZMM8mT31lxzSb7li8RAUXtBA73vun5+KVBREnht4oaAR1tWNTNDr+hgLHPGlEXpXBmsFZpWK1cMDF8ItibQ/TYx2LszL331jb9GzWyKB7lxBUlSSOv1k52X17svD0+7h0OL3Z7g9fDozf1czZ1Bi7+NVgMj5m9S0eYekUESFSE4nUNg9t4jXDHLD8AerCYMP8xGakLvxVZi1MNO05ER8l3AQA02Mq2M0QnC379ggfJZbqJelMjiSElnuGHHhvqdx7cKgRflIQZKlQYCn7RqGGcZFpidmlPnq6zrxgkZhr5NuOTPm6wqb9tWc6CGtsjnjxFWcNEZRKjsaVfedlriUl7SKxkZfnY528VtLwe0ZQfslMHO6V3C95erB5BfXXRjYDObC1yuIi26/lt5YuLoP3T/Pby1UXQfiO3PX95ETT+NqaMeP4b9cnvXc7uImkpPLZCdAP03jgmYo8pfPLH4KyfQPQziHMsh04Z4ebKFycj11mV7lhtEsOlRthfhn8NtpNFcwFJ037Pn8Bvr+RDfSkf6kv+MF/FewpOWbzxPJX3MC8UdAqTNH3iyZlSXpRJVOVXkmi9A6SDTydZYg+A+akbZHVKvClm0MQcI9DkbNOh8VxQW8ktXzD9YgyNEOO0iIMoz8LLKiDJY7KRD/amItjn+WAZG1YE3VnPh815Oy3LSJyF2PoWHPRZ/qASdPJcghg4hbOKjby+gp0C2BlDxxi9zMgreEOCzhy4+pxXsE+ol1LEUdHa0QhmUicG6Kz0qxb6jXdkD51pwqkKakLwbhBmL+YiLyaHoMAnAx8U5l2sr5ooDm1vwj/lg7Fxti+d+b0NdrH9A7hPwZDJQZcjlsMtxz589yyOrOhTTKk+fdrcIsnSbseyx/k3U5o3TCpDwibqOfmebDwnmyuF4uk6QwS/c0XO88HqR8dTF7s15aMEsDC7ZKMERmuI0ZqyTEojFUnACTCacCJc3IUI3z7DIZ+vHjJGl0TiQ0kmDEG2rNO18ziZQja9K5mebQDO6H0VIJOCUieOEhPluyLzdB2QQXNSBBnJxHzoHD0n3lGl6yBgkMx8kJ8y8j9qkifyVOO1aYiYQH/EMmwGqjFa88dSjYMP5vTeNOPgdf/NxXB78PqH7ePfoYJUy70oy273+fcbzzd/F2qS4bK2+WUUJA727bPNL6cakU3vQplnG5vVdOJ9akVE5On65h9XH8Y04mfIfyVOkWIerqwMWCxrVfDm7sJl51jh363gwS/swS8pb/AANCa8C5VPQj+xQ5pKrLl1sv12+OrouD/8Ec9OR6p2+4M3+9s/FvyoSc12BWQ6YXQKXppiepcnHuWpoetNbPHWNLLrF9eOPjGVDH1qkUiCzw54NurhHOoaR6S11Gf+tQOimdj0pgEQMw16C05Lif8nl1O0DTJ1MaZVjgQ1ggReMSOQRuq0na4YIExlU+BVl6DqmJESFRS+oMYzDI16G5Bu+5NpG5Sj7Q8sfU5h3pFTTGRPh+b8rSELp22Sup5xMgpZDnmykQohowdPH0QTG/tUAnvheaMokZWDSJJILDNPisyZjDcTmc4wwyWr7q5tmS+UgVi6y0J8zzulIRYccgoVV2r+K8AtmlFqTWSQWgsyRimw1TOYKmCceJhHKtmB77GTPTj+m+Kn/LtvAAxN8vZmwOQJFkgJFpjkr0WYVDeM9477wZvqI/qKv39TsJP4rxhPcJ+HuX+TzlgGpykwAs3L5P5iaUwaIs2caeS/jEwckvgqzJQUvClt8NR8cazvKaO4LKvSWyfa3FuK6wjkMNM4P23xxEEq4o/RxAjOXshfMO0sVmfmp61/JEtLZmhe15baWa19hvmZebby5enSwnTOyYzlUcQSGWPDRSyUvjyDBSQbcKsXBsVkOsrb1E8huWkyJtnJz4HW+86Cujs6+AWrmZ+xt8z/mNIsYo1jjgy30LCj8xyL5vK74rVEs4fKyhl/NU9yzT08wmbqiCmg/sXlAtk+/4AV+Z7U8JxUjWwSzD8OAhIRJt+/YTLlTCagNVW5ypCACApCsgo0rcsqoZQxPXTCnud0w0zRG7+1f95sN8t0+1imsYLdo41S2N2WaTxhqQMegT1uP0G/krQet5tlhuNazGObEYRzDNvD4+HjZ9rxfu/w5fDVk2dNjVwg6DAPfRkEWVdgbwkCtnbJ/u12AQi5OJZe/063W8NkiqHIY7LxGr6gYwOyDPsFgNZk1cciPK7UBhclfO1p8r+zmvaoo4FJYShogoG2ykC+Ldw4Zp9KWShUh7CYlJ3+yLIXnLXqWpKKnOYsE2iH50L3mLZiCXUZ2NTtBq9S8kRsFNlw+CwHM+imTYEyu70g3IUFj/E+icCtFM+ewjO6xPNcPXu+Gf6amnA5Oq86G/qvBLksNkf0+lZuMHDGDERqut6UqbbbZAiGgOyjq0d28T4mzHcJu3S8mAq82QW7lulEHOI0bc9n91GZNkt/iYaRCMOoseN/8j4lgMDyYwZ72Va6x5H39TPIVaYJvta9fefKtHf8tKTEmedo780aR0BWuk6hoiFODIyHr1MGzjyTXWbgFUOH2sHCtRj5FrGAhYJ1ynKFE/omG3JducIh87R8SjeDWqkmPqeLLd3zNbyZxMbYVe1vaaYrB0Z4yYTNNt1l+iZ9hZzGRJphhumpea5e+lISENg2dkfM+vnjtWa3mzRxpaZB0rye/PYcB0Rh47wrrqkBDHxQA3iqpTy06K0d0ldP3l0z4IzaN1KqMJAtHx/ZSGZZBVRJtgdjkbgFB5iQ33nz9Dx6B866+PltimOzcnKMtbVyvE3SfMSc9qUaK5edlOhWy9nsRnut+FqBNYya0UAdCVsa19JZ48lwdyf/uqC87p5pZF5DINsAr6xsY2bU8cxZ/E4/k7zg6Ar/ZoskA32yZJhELIgyj9kxYKBMWoFgZE0Vi4wYsB64keORBu45xSH6GLsukTcKy5/2+j4HTrHW3rWzkNYar3DjL7PhFxn4xg0+Y49fHBOQA1OQF+IqY9fhKTBtaHLRetX+VtbeEh71tsHk2i+6ABCsrv0FzBWMtC5wRz1un2tz3dJKuwu8Ii8ksbKzPsKkItX6Klft4YRKeyy8ogL5CDP4QDLQDOQ30v5Z8Fs3JbpSBFg1FLBcebPLhjK+VqtpHK8qKymKXFAOqBqcCl4PiVOVifMXp6kgqRj8PggqePwLk7NCFyC/wLVb47+EVy5KrtgSaRtLwy/T/l6dq0g8pP59PRoJyX0r/sqZ0D3HAuumBspxT9FunQRA6kHgp92G37mtaeOZpCC2khEwKhFp4etDGl9F3ycDkTzfYy+T8fWb8qa9vCMV9UKj4Ni9hOCO7h71BuTwaEh6J/3BMHNJgwW6X/cnXPd/ggsUGfxLu0GRwZW7JgNXiPPtEw/U1sxju4Z7cHyyRlU9n5MVfkMGjJ9ybX5GpyLRlIyuUWch31fIAJFtUjI6EKZST0Dr/9b+ufX4H3//r3/8/T9z7Fk2mCpDk8CWBUOjNTvJt2W58PiiIwTt3fa+lh+tyYUUhji+9mraTwgu9T1JIWA/5QcUsvtm26SMPqU7FAkupHctYgPDngXsIBbcmk/5Fj/l7bFa7pJBWoxQIQSBZVXa58avlZM+F7V9dfkpO3nT3x1kvNLAWTbzyc1eESAx7uUCQqplhlVkEeEV02ZrkDNcgSGxrDpHAN4K3hf7xjTYPJlqWQ0VyUKVw44r8CyIK5aY09Il6jAFMMMSYwWCyz+gvo/Xqp0oniOyhAqeuUhjoAYyDa8uQRMsqxKiy5IjISuqc2Wg3SYD37QsvMA7nChPfaIRzyEW9T3CE7bi2zHvxvPphAS5g5H5LDzYZkzyRKKR6cHW2+7MbgsQ7P7smbw9u71U3O3qYpTgj4JDVlNXeKopfBPRzRMlY/IWmqivDNOJ4xnG5C4EkCHiFVyGzfD2A0+Vf4YRpgE0TDeBUgGAMElGh1VkWK3jlHOiDEsZQM6OH8tSQI+IU2PRaaNfHZsz4xY2fGG1x48fC2bg5PiMui8D1d+TMirxWBwOaAVHvHHrxTLNYLRenJBIHnaVJYeIoPfeh9dlYpZ18kicASeXN6DfnA+o+3Wf6KAcUfOJPSyIB1DYxkqHnyjwUHfguwRdHCCInzxAHYlbwMjZg2zUFuA3UdIoNsUV08QiXt/gpwHsHYczzb2AFstn2sYHoFecCczt89m22pGRUs7SinN/U34KEAVaOUnrs3BJTX0UeSFdCw/V8tDao3XYiZBC3n6IWEGPHwu/H8OmqUeXROgqIwFbHMzU0+D/pUbm8F88qXtaYR4p+yYFvVKGxT2oaNAF/OTA8lyevSokHiXGwJK7CaoAD8s03aYq34SgaDGNHZsic0qoPTfdnLyl8bJCPcsiLoGZerQA9bCUmHFwFuJeMS7EfbIwLgS+5S+e8ZcX8K/y3hke3f/E2fbPOwXY52kfC93TKFjmMDGYj2eZI9qYcxltKupOSnm3MN+oc5ifrvGEZ/LTrBITqTAZLBFLT+YYG6oGJLB21fqzM/3h9yjwRFOUeeoHcXmlIG/LwngcufVx7h3wFUcp0OxLOXfVKM12s8nHuI91yILWXUquHPTOwK27dGc+c7/w+CeABseO2rMJdXW2sUfPLvTqnIUNziA0CVw1jeD5fnDjpnTkM9dOKOIJft85F58Reklk7vkzCixF3abP6yqV+KSi2w0+qPief06xGfmYQrpR6BILp+msxj9KEpvx2qOzpNfUyfvgKERxhaN0B+dI7kTtPNcmQ/mxYfFTRW7kbWnkM1/9NSxb2Ku/VtjjsPhh8WCeZeefnIqE73ATRjM+UC6IHpb897TqgMqL1WDckq9SlUHvoOLvdI8gz2ybcdgdSwa9+HZ15Mwsw677fL+qLAbqqYAmnoM7UZ1Yuodv8NHHo2NgW5giC+b9MoPnuMFlHpLolj5s4MjncnsO3lhKcj0nEwlZ/+6733sTAolbEc4vgBuWpATcG58L8Hd0Z+7F3q9OHy1EQw31sFSCnz5F/cJusU9Df4fxnf9HHkFqwASIs/kdFDVGIr31WOgkcAEqRE0+twNQOCIiPYXcIEiGhkDTnxrrqOIH3Om17uePXKx895sfoFgxgQKBiBwEVgYccJGBE7prW/Dvi6nyViI/urAC65JRhILhMxYMQWjRj1VWd77fUEPV8EKJdyKVwgj3s/UvQs7iW/wvYH3LTVu58JltxQMzEvglmJtJLBXLW0C6Ye/YEoYu7CY3PqH3/33sb9g9atJZFY1lspIozNgNlZuh9po4tuk77hOcJ+ixWMMcMMPBsBgYaJgDpndSEAw0zAHDLvMtBog1Ta5dkJYFFza6iguZEWYAbaYNxzLeRZfz5YFqEC5e4n0S5uhAd71rPbwoKf2uC4SmkdqFh7BrqVeihAOhzsEOKQmdXh6USeU0l3ebBtCCiiBVF1YFT9FJ+i16KRCvUrh3LlOZK/eINuZyyMBVKkKN+bpKinnYOb3bHPscHx0N3/cPIx0FRuG1dNgUdH0ReNs7w/67nrzqIg2skrUReiRXgGdqjN+Z0QwxCFd2gqnhuikw4ElKjs9OB5N8PgtSnmN3kQQvvcO/YfuNFSkc5fx5LnpMSqcgGclTH79sFucPLcQSaGTnPcuOx/PaTQQgFQxzlOaR7P1QtUu9kWtOQXJZd1WqYlXodOmGET5tBAjG7qEFDuRJpTD/kW54eIFM9Lqh5MCtC8VYZrdCoRAwI6IxNlKEAxb5pJerJ+JL31lb31DNjHwJzjLuyQRsfNLiwsZoHZt3dgKdNDiRayej0DRAP27rvQULpTROelk5QpE8AX8VuER6pMO2V/IhT464mbUdUMbNIWpeVuM8XLFxjERRjRCj7oqJpVOdK1txt1VgZ7iMsZut0lpfUX9n5uKvQa6yRqYbluERZZ1qMfglwhk0T+ul3j+kaPqoCU3LqzbX+I3cgljsow4uxOiL5yhmaKFqYzRkt+FHqQErUKknGEP3gMS+vE1pLq5SClFvjZjs8ZyeyZVoRgxhmWujFFYIrovCD2wTQ2BUhy83cwXCfG2R3UjMF0la13kae8SSbCW5JxXXr2LoxMbmN4CpyBXzhaLt2UG4wOwJYY0EQrHVpcnu/ljZzvu1SCtfN60i7VzqgSxktQzbKolhExcmCyU6DxLhztcVOxk+iuoWlkL22Qb7sW3fSGDDmykefjY0RhANpquxyWgCVXUCuILer0I/MlMQCxrHlFSYlxAhBf2K6fWthBLAEr0CL2F+XGdBGvWe6zouGeM93BhgHHHeDJktfq+Y+MH0S2bOQ0N3F6ZdD7XLxDFmFm3xDZknUt2KXYLJkudu5cFU0tmAmK66izJ1TJTLffNS5LwL/+Dj/h/LcQs5', 'base64'), '2022-04-02T20:22:49.000-07:00');");

	// service-host. Refer to modules/service-host.js
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('eJztG2tv20byuwH/h01wKKlEoeVH73J2g0KVZEeoLQmSHKNIA2NNrSTWNMlbriy7qe+33wy5pJbkkqKbpMDhjh+SiDszOzvvmWX2Xu3udPzgkTuLpSAHrf23pO8J5pKOzwOfU+H43u7O7s65YzMvZDOy8maME7FkpB1QG/6SK03ygfEQoMmB1SImAryUSy8bJ7s7j/6K3NFH4vmCrEIGFJyQzB2XEfZgs0AQxyO2fxe4DvVsRtaOWEa7SBrW7s4vkoJ/IygAUwAP4NdcBSNUILcEnqUQwfHe3nq9tmjEqeXzxZ4bw4V75/1ObzDpvQFuEePSc1kYEs7+tXI4HPPmkdAAmLHpDbDo0jXxOaELzmBN+MjsmjvC8RZNEvpzsaac7e7MnFBw52YlMnJKWIPzqgAgKeqRl+0J6U9ekp/ak/6kubtz1Z++H15OyVV7PG4Ppv3ehAzHpDMcdPvT/nAAv05Je/AL+bk/6DYJAynBLuwh4Mg9sOigBNkMxDVhLLP93I/ZCQNmO3PHhkN5ixVdMLLw7xn34CwkYPzOCVGLITA3291xnTtHREYQFk8Em7zaQ+Ht7txTTia98QcQ6vVVf3B4QN6R1kMrevZb5I/0x0HrJAs9mbanPYD+TCbT4WjU6x6nsK39pgo2nl6PeiCHwZkCcqCCDEcaiMMmGV8OBtmXR+Qpx0e70+mNpjEjmVcRXT1TCcD7y2l3eDVQ6ReARsOr3rj3oTeYbsCOWkVavckE9Nx53x6c9TaQb1sRw1mWwSqm4+F5hmf5TsfT980iVOnREggd262uhpKe71ZvI+cI4DqGuJ7+MgKt7+58jp31ajpBUpPheURy0OtE++03i8vd/kSBOFAgxr2L4TSDf1hczaIfKQAJh+fDs2Ekt+9LFk9PcfXv2tXOz7j2D83a5SBZfatZ3fCO4kSof2qgOuMeeAuuUs3qtDe+6A8kwM3uTmwxsfgHw+veeAyhBPwyNaSQ8Xtw5QvqQRjgsCTDn2nIlTd38ZLRiHDmK8/GWJAgvvdDYcp/D+gda6T6xOhuXQ9vfmO26HeBckpxCTjGSQyFPDAIMILxS+G4ocoBu2eeCI2G5XgQ4hwRmkizITFVLMvmjArWQ4SU84mgXBjPAPeDGtCez++oW592FEprQAb+mnEgK1hnCVGZSXkjkjMnZsB9G2hZgUsFhPE78g4Euna8wwOjEUNJsaeiP7tQZXl9xjyQoX1BebikbspQCt6e3dPAARSJbHUi7gYQ+e/ZiPsPj6YRwxweWDO3lILEu2Bi6c/Mz+Qu+scxMSKRTWJZdwR3u04YUAFJmbeNJlAAtFny7pjsk6daGxhjtoCMCqLbUH4PectlvPfQrsekMWEJY6iAVVhE+xmyI3OjnFYhnwRKL590Nbv5GRPnNBQ9zn2uKD1FG7ps274RiH7TeCm7Y8fve1C4UNf5nfUe6uJcQnmQYOn4vJ5sokCB3Q+UO1hGmeIxYFCvZUJGZMtYFXkLg/xIlCVyrP6yPITOc5vse4EV4WZfEKs0+TPXv6Fuh7ruDbVvzYNKCtYIyjhPSEKVkJGDye0qAX0PtJxhAgw+DaS+l2OQ8oXdJPDnfWNDVfFufPb2pn7XPyadJbNvsRq9o7dQ1624rKqxsIZibxWqakq5i8+YMhkbfbnODt6qIou3Rz3O2JyA2la2INdqLXc5KbKLf3avhuMu/D1by42nQKRAOQvZWXHkNQqM20B9T3DfDds2NhNstgX8CoNn78ERHX+2jXQiKFk318SKlDPyHU9sY4U64r0O7Ilk5dokr85H2VcneQ0D8cS9oeSX7gN6Qh3XtQVL+D+t5nPGzYaFTQ67hI7w8OC8Z2Yq/LxZfAnBqAmw1EIeGoEmOaq/Rxz2EzOWIDLeV2YJU0cTA05Tu5u0M4mfhQHnAWbCZVz2aAln0Rv58zlzLZZ6ROsDdTFmthpZ1JzT4ZOUDQws1tzP7/WksR25H0aQEDM2BOVvp2SloduiaqnHfKbeKiu9CmOIhs53kvPzled9g7PLPvRZhr2ddtw5WpquFfruaqBNd7cVNNPgNUkhK/z1+lJhZdWSqW1M6K4roxSm5n+r2XjoTTaNzanjRYRA8DlPU38UvQ6bmvrlt4qVVuHPLMCTp355W8T9who3T6Z+masKIExqkbIypIimOO2aYtTyA6hNinDhl6S2OgTUIUrBvWsRkE5Vqle9O+n9KCzxGXzUMj9T2JuFFFHtdNjPljTcKXYGT58F69TtRzVp1avgczh1avkcyraqXotl2lA2Nkk02cDqV/6zSwVtEhtA2YMor/rRQX7LFTggsksvVGqOhEqhriDmb+TFO+KtXJd89x0SiiltryLCtQNNOYmYx+KjUQTRYOFjU6hBc4NCq3RQ+SU0cIypx08VqbdZZeqjezgTK+6VANRjLTMXLd8pHsdF86L+DLScWobVZZzNzSOMKmrwwIlJGjuqzhDrz0ytrkSHyVOiy9yhC7NcqzhB/UqETk+3UMInzbUrUO0bKUicHsb6tqOp2qxS18lzA5K9rYB7Kl+qQoV+ma5cUXGWMuxCoY7PX1FulZw6jetP6owyM9P5nA2ewyC+QYKQUzYB8qP4VZwAfSY498lMgsjTScIOc0OmGYByf01M42IVCnnb9ZjclKljKp8TyZihnCg5zwvdCSzJxoiKZcnktQIDzr9pyZiNr7L7KrNz6EAAPM0o8NMsbqidDb/Iz4ZzSPhEFzL9M7wwuN5k4XS369xaoQIu2mMexQrqxtun3G89oWJGxyc5PKZjiQd5OEchU5OovgTiMlESTnQpQpwfEnI4frNc5i1AQeT1a6dckDK4qogfnU/bxRVFP+ONg8kbSumSqKDYYXhvy2uajXdt3sEBPLbO3edAVigLVoI/6hcqon9+T0syL+3d1Fl/WbwtYcumUaYqyU4VvEHZE/ous1x/YbKqIJ8ZiVRwV8Kfso3W2TFWkdfEIFI2FSmnFidlKUGaz8r7rzaglP3/m5DGhFLpfFsjiuZ8OvuRNjarsq2q5ANWFu9cpqpvZ5x5Q1uklVG5zBtWJIlSKdZXXDI5tSzr2yoOkmm53sL/Ib35wVdRmx8EX1Nt5QW0ulbvfh8fTQ0nRTuNPlIrvcI7Iq/SpehGivGJ83shyBUucq0gBk57TvzgzlT3VBrSSmrRTehzqDXrMxyG9iw5e9IJlX9tkNmwnGBl1amAYeE58z2WmyJX7M+ZwAZcl4rQFOLlsksejRlkmMoU3bqPVdQn54VPeZjC8ENBwMar3HRdx1s9bDHdO3+2cjPfC+S7xR/1DZUXN4b5TsoKVzfxZwTmPvhzYdmloeh7M/YwnJvGnlGwV+QpOQSOSdQBviS2+RoKI9Moftn35r6537DwJAWnjySkEsU4Gz6Ggt3NDJzDFRZxGmts7x8iyejUjAPxS+/W89ceGSU6iYeNoU/WzOAMZXMD5h9/i0uTIFIarhJ912Pq2saL78CZqQK0l447u5ZixKkMaOXUgdBk7N043l64BP/5aMBfn3SGmqUL8X7mr4TFWbhy0UMNozZO5K5UUNVdTXu58m7T/CXJvn5HovcQkyaxVWHe0s71ZQuoaPKZI9JY6dsGmJnDQDiNbg/S1hoS2GvVp16Tl8l1yh+Erm+J8TmAYwjyt6Mn41cPE9iv3suqOrdqmCUrEGnIf5bzCN0WbsKo5gh/kAVnATGi73tG/e6xkT/O4RceR1OL5JheU0f0koSvi9pmpYGiV8e+TnnI+p6oBI+mYWlQdWbPTABbrmQqDl308Hp7PTfLVKUTfTaZUQ61UEU6gZB36vBQEJcJIyRzhvcV0DhF36qD0YT4nwTklX4S7XJfw2D0j4LU14laEWaiWMhKuiiVgakRmJBMvaiUUt74mkuB6hJ9zXVCkThMQWExZoXBo5wguzOc5eYPaYWBixahoYtowr9lXtgkji7x4jfs+UEgfsNm4mxu/4Q45Id435KxnMYq8In3BBIR7kfnU8qj3lgxX8c4H1uf0Gc3P9CN30TdUfAxffsJa5fkR6GvKQwB0MI/Ks6tqLHGzBDM/IoRqPA2OftFZWVQGQb+dILf7vZFH0fVRtKIwzt4UuBzgYpRviQ/yS/Lb6TVyXT8xvTlbCj93jyuVYmp9JvRx+kJILL4dPIf4qZ5rw==', 'base64'));");


	// power-monitor, refer to modules/power-monitor.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'));");

	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'));");

	// Helper functions for KVM
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('eJytV21v2zYQ/h4g/4H9Ekqora7bp8rwhizJ2gxxMtTJFsANAlqibWIypVGk7Sz1f99Rr6ReGg+NENgOeffc8e654+n46PhooXggWczRksq7lIrUcY+Pno+PEDwbIpCg6QCxAVIKjdHzfpTvCPqPYoI6WIHKMKVpChApdr0zJQTl0qlgHeWiZ40C6mqE9i4g5BiLWCCHIcb1rpuvFYb1wxbISUQcALaXRESC+Bq9GSO8ZfynH3GBOmMP3jQ3fxmCiWJJsRBs2WCltCSSojEAnYKHG4rR16+otXcWc04DScPMkFKzlivjyhX0S9sT3/DkofKr8mlfBuGlU7bConOSJmTLyTwCV5FcsdSL4iXjdyyE5I1q0TrAlYJb7xqYpSNwzEqy9n2MuIoi1xZvaOunWxuZayNby0hQMy6CSiU0e5Q+UbbcGSqdhYhxtcM2bUkUxVsa3l2ea+LNSstZ9CQR8nwCyxgXywGQVyJw+HFNdlm2euiti4SFQI4FWzquNzm9txBWJL3fLOYmQsTmwwXjIRWgDvu/Mk7Ek4N3IDcUimO3ifCRx2taMOkQpKWWL51sw13tQnoITBaWCIRxXaJZJMUS1B8n009wYCOso5rAIKKrRIon+LQj//v05tpLiEhpLrVHAZHBCjn/ui3Zma6Pkgka982pEOTJY2n27RjSbo+2WVbGthdRvpQrzZYf2iWVn7CkFvy38XSAjB5G8m6TU5J4WajSv5hcOXg4NOyMsesWPc6sq4Pj46VJxKSDAWf2/kFDHRqu7wmZUX/filtLvbdKzHZU58Qi0oYJqUh0PrFp1Og2r5ekyl5/inTbzWzrg2bW7Ix4SZwUB2pGzHC8UobmUp893TJIY5ZiGd8lCRVnBFLuts8ZwDrCH88n2G836EZ30MaMbmY3Auv+089cUPL3qGnp6v78oseU7hwNE3WTeBE+pAuiIvnap/hu37KcFBNIyZ3sjvozp0jhlbOB66B7KtE76Ofyuui/UnX31KJjlGkMS41RhxhUECdr+tLdU4g52rcOmGDFovCPvEZMqGz9sSge3KUZJzoQWgn61FNCfQvLm+oA3cJ66t1efJ4MEOUbH0Q/XU5vz26ubz/fXPkIM8idoPNYrrDuTB1mJBVruG8isGPh0x0NfmMRuPpuzvi7dIUHpUv1bVQ+JQiUeBgr6UGycEgkAZ26GwSaHfoSjCPqMb6I3zsB1N5UCsbh6m72gCYu495WMAkOpQph9LbO0FuEv/BWDLt1y0seDTn68AENSQZVchaQ0MnBWHTH5Beef/arbAmTFyDjNCWqgcpmjlEoNEppL5dL9U23/r5VUlCjdkFNVZLEQjrtmiqxe5mv611fKWcyQicn1ZQFP5u9RM/yZXdw++vduKA6B+wItoCi6zhUwB66046n5fBji9rvRZmVauzWMP3tAcaBQ2ZqDQKj80NWmtULho+KdU3NvK0MUPb6AnU4LUduqAjYrGRzCdC/BiKDXEZPzchqv2ww/mFtqNBzW7Xe6L/VENM4cMcbgEmIfPi3+GWnBI17oxtAy5fUpqDf1egHtl4fb/1vMLoBoSOW+tULdWO34p5f/2yIFETzzXlrYEUK/vJyfX6VsBhv61DexhiVVTvaHxyjBQGv/lc4us5qH/U/oNG1yw==', 'base64'), '2022-03-23T13:56:15.000-07:00');");

#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(34701, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 34700, "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", 16000);
	memcpy_s(_servicemanager + 16000, 18700, "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", 16000);
	memcpy_s(_servicemanager + 32000, 2700, "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", 2700);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2021-09-07T16:57:16.000-07:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('eJztff132ri26M+3a/V/UFlzLuaUkJCmX+mhs2hCWt4kpDeQ6cxLcnMdMOAWbI5tSnIzfX/721sftmxLxiak7cyUc6YBe0vakrb2l7a2Nv/58MGeO7vx7NE4INtb9Rek7QTWhOy53sz1zMB2nYcPHj44tPuW41sDMncGlkeCsUWaM7MPf/ibKvnV8nyAJtu1LWIgQIm/KlVePXxw487J1LwhjhuQuW9BDbZPhvbEItZ135oFxHZI353OJrbp9C2ysIMxbYXXUXv44Hdeg3sVmABsAvgMfg1lMGIGiC2BzzgIZrubm4vFomZSTGuuN9qcMDh/87C91+p0WxuALZY4dSaW7xPP+vfc9qCbVzfEnAEyffMKUJyYC+J6xBx5FrwLXER24dmB7YyqxHeHwcL0rIcPBrYfePbVPIiNk0AN+isDwEiZDik1u6TdLZE3zW67W3344EO79+74tEc+NE9Omp1eu9Ulxydk77iz3+61jzvw64A0O7+TX9qd/SqxYJSgFet65iH2gKKNI2gNYLi6lhVrfugydPyZ1beHdh865Yzm5sgiI/ez5TnQFzKzvKnt4yz6gNzg4YOJPbUDSgR+ukfQyD83cfA+mx7pHPfaB79fHhyfXPbetbuX3Va3CwiTBtl6lYJoHh4KgC5A1DnEh6PLD70uf3G5967ZedvCCq63tt9IMO+PP7RO3pwcN/f3mt0eBdiuv+Dv37/pMYBuq9drd95KtbzYqj+RoJrvj7qn3fetzj59uxN/ddLqnh61ZIDnKoDmae/4qNlr71GQ+nYchiHSa/ZOuxIeTQF0crwHfb38r9PWye+X7Q6MDFbFBu16a2dLjFzv+JdWh4GxV1tbors995PlnPowMdEw0me9m5kFz2JwXYvObXuAwALV1skJzEi70z09OGjvtVud3uUb+No6oUAC6l2r+f7y/7ZOji+PWkfHER5bHBc+Ob3uJdBq9/iwhX87rb0eEZ8GMWCAKq/SkPvtbgyYQm7LkCfQZi9dJYN8ooBMVskgd2RIQWaHx29hxBN1PtVBHhwkIJ+pIfd+Ick6n6sgTztxWAr5QgUZjUHv5PiQQ75UQe6dtJq9VqLOpgqy1zo5anciYAr5phLO59vT9v5lc29/jy2py+7x6cle65X08k2z10Pqfd+CF51e820LEW22O7D0ZDhprt8fNn+/xEXRou0M504fGQyw88l86rw3Pd8yBmZgVsnAovzH8ioPH9wyro4VBkjLPiCLUDUfGF5gRKCvIkDPCgDq7II/Ag5o4GMb2TerpMLe8MrxYw9BeNF3Z/ZFbWI5IxBEr8lWhdxifbXZ3B9HAJVX5Asry/8AyNxziAF/EZMv2EOpj7hS+Sr0jahXKAxrl8dXH61+0EZuUwYR6W34HLL8SlROpZNRtj5bTuCXK7UWfmlBx6Hntb45mRhYVZUE3tyqRJ2q9T3LDCwKbZT7Y+D81qCsBZi4/U9Z7+eOAsIcDI6sYOwOwvJVEvbb4MNHx4b1lgHhAGpqCVvR1fMoVdEreTjZcxjMoTnxLfmV62hxTBTFcUxWjKW1uCmbZhWwKpC+Zp7bh6mtzSZmAEQ5JQ2Y8YXtPNkupwmS1Qjk8Bmk7jvXTfcpgprC4hmbE3gfksrlW8uxPLt/xF6VK6lCn0D4W5Mn29hduZbaHp3zDoj/z9Z7z72+Mcq/cNjaYJJVFS8qZvKtFRyaftDyPNfLXwoYFRRs9rH5PVgF7sQKBZhMeZmV7E1c33oHuszEKkeTQIt5N9EPabyjKheBn2dMPgS+ObMVYxKrKd25ljOfWqBhi175zSKl/2tueTdiPBykIqqmfShSx4k1AoU05EgdN0DFkNZTpJpTZ00VHYB6fWRNXe8mVupL9BXq7I8NsBgqyrn7Eptg2pA5+Ayzk2cemxRSS9usogTSzQksdfjddAZtB+wBc2L/r9W1B3nL742t/ieqm0G/r8CAGtuzvGVxtERTyQIoPvKtaAap6TN/GWv3lkzpl11SFtP+3l3g3AdoD8XmHgTRGMoO9m1/hjO3S+pf8rVSPnW8ZbWna/JmfS/I0+sTBNzR9JrWkkRnbg8OPHfaBfvNGTW1pdj7nnt6SuV4KBzk58YIKlMTMH645vIr5eNyudo81alfTc9GC9WoP0uuM3topAozHBN9SYNp2qBoVzlulRpFEMyASrzdRG/wIylFWDKB6Jf4TwsE29IagazcBYH1484nA+pT6LsOWLEB8Wln0EbH7qS4zxclW9HNIIwGp6aCokMjjY5nlvOeCf9yRVVOudClUpRVaFiqsixIUFpGEhFFih+CvjGfNft9d+4EwGx04kWLd4+u/zTaaZ6ewdGjn2qDJFzx6Rk0yk8HT6yX5tOXG9bL/acbO1dbWxvms6vBxnD4ZGc4fFp/9nTnRQy1pXZNZnPmc3PwYmunvnG189Tc2Omb1saL5+aTDcvqX13tPHthvrTq6eaU5lFmO8+G1rOXT58+23i+tQPtPDe3Nl4Mt3c2+tsvBi+fPBsOzJ3nKtHARXQ3gIlC4j4rMw0LeDWsJscBC4SqteIH1TPwd3dsDtwFfgNu3pch26hcwd9DZNfoR8IfJ5ZvBRTaXTgUCuRj+SLJNpEu9yamD6gsXfSoInApC8th5JnT8i7ZqqoBm8x7hwTfMacWQNY1kB9c7xMgvQ/qcj9A3WOXbGtAj1tHoHvukiea95F+ukt2NDBoAnKMnuowsun8RKg/0wDuu1PTFkDPNUB8IumMA9gLHdjEBuPuzdyeDDpz1EUA9mUmrBhX3RQwKHlc67o5YKAwq4M5WMA4fHXdHDDQd6Y3QKcrg9XNB4NtDgboHkVA3aQIVH0wySiiuqkJEQ3cvjtBJxtC6+YHV0bPZqOkm55Dd+Q6Akg3OW2n706BSN/cwKpFQN3MHM+DkSsBbusmR9R4AMuIQermRlQZQWZPDS5phFq2SDiYbkoksNY1AmqnxHWG9khUp5sKUDzsAV1TAlI3IbxhTjW/7iCsdl78E7BXQhMOQV8mFI40C7b9E9cNZO2QPTGydUKQQnMQrJ4d3GhU3FBTSymDUtla4L6ZD4eWZ1RquIdhtZ3ghfG0Sp7GpYVotjkAMsF9CxMWsf/Wc+czTfPvgUoCrPdVuhYTa5H8FkldVXiFuCKhs6sMqSNVYNPkCfz3dGenCnIg+X8F4kxpfZRLaUWsp9Qo03QX98lGiu4qO6Qy9Aw1krV9y7OGBmjarHkt0hrERfustDzdqIqdAtpPtg9bRoVVSW7DueHOrnSNikexznFL1MjozBKln1sIFBO1lkgbHFkBV4SPFw4To/IyUrw2ZjlMLajDmU8mCrJ1WAuZi62+tb2jIvkBFc6rlsaWmXg/ZD7oJfVAJakyqaUeTr6u1SsKnrvFdAW+PQjYzlPxstSrPmd7WVu69zl4T7pk1JfQMJOMKkO7EVcFpZEgBaVsa2KMIwOY+n2ZQXpg2hO2RfxvVJwJd/USG/0l5DGrLO6nYhXG2UXS5DPGVXkXsMrGgnKGRiMHM0tapZFX1Bir+Fe6O9QOIBwntp1It5RnsZ6lFrliFoFECpNHbHAUNi3bkYk4Z3y7s0obrYJKHiPwtTSC6nw1Il0qeTIbkYg8cwzkSvRMPE3vKdGzck/yYZDornJVoKj0HHghtgCS/D9J/ym/A8rKELUIceR41RTfq3Leq3rDGVQR95XoBUOKpLcxOK3LP3N5sRC72qUPqg3leBxr6YnSlQZvbmnRXVbBB3tgbZ/2Dl6Ibu+KiqQ3uAB26b8ZCsGXZes3g43EKEq9svKxn8QOaohLWo8GcX9iLoS6HvDImoRCoIAw/IgxmPAwWz9g1L2CynuFJtgJ7Y2Vj+PpFjJulmRs+eDaSHRJLMpqHItVqJ6SO8G9ZfSrZqDBxEBiquWtv5ra+asYORgthr8gKP53K9GfDL4ovVLMDVtGDKBmorFh5K04UdtVDcPQktQa0qiYu2hry4j3LC/5p2l/CeH/oPo/GdWHez4J0g+5eGqs7kxhCdRk/k/r7rNt91OqsUmBOuLpEo+FpOiFQ5O1q2/QmUrvY9kDUHKvD/gHFAs6S0a54165gxsycUcjoDUbdxjUdqUR101T/YTlgtqPk7YnxWMjc8suFtmiWntzVD/jDu+a5AuuLFnq+8KUlFFjD+8HscixnIna3tzzLCfmyuKPjP5Vzh3O26TWgW9nNmCzAveh+mJh6yLFc9KhGQbzKVFzEFCrspbWwlnSjS3lKWyhLOUqaJ/xiDeqX9rkXwzvDB3wFXn82M7nHeNzRAckIaht8k8xpGIS+LR1qW7bIDvkZ1LfJugArlRJblCFSoyofKRKcchIdiluBTRd/HysSZsuUJ/UraXo7RDcWNF3oxKOD9vF0zYfek5i+3RnRXB5QeiOBNmp6AfgQoEAroIQiQYR+4IVnY/xY03imVoG87Emm+F6DqhAiDWyH3OjrdCExMsUjSh8m4w1nUnVXkDzH/MZR2lpHFsfaYWHRX3WBtbQdjA8ZWZ5wQ0XzlUS7c7eAqFP5mD0+WN3wZ4eOxMBWSFfVFwNuDAU7F+Fwl7jeNUoA9EvrOzRaOJeAc1dOu4RjIw5st7PpzM9m9/cJB8s4vAjEz6MAwHz2SRTVpjMoHQVzxmQoRX0x/BmYTsDYJJjahqmuTsveIkF5RhHKLbB323gO02QAgfhpR1rEavQuMXjKLCWdtXnEGB80/XUZiYXgDxIJLNVGjpqXdtBLGy07w6sMHSU1ReSUWZonSGXGC+cWAxsNhIIHUNinNOHKLUGnR6nqDk97ze2NRmwaR647NgPhl+PEeI6IDSUGVQ4d0ZmsGBBdbf6c9O3yMICeKcckIUJAFARiswcMWdKfIaeO6VtyjRQZsFpZdqmOWdtQv+I2Q/m0NgNntGhhey+5/qB2f/E49nA8pj38XySGci1UooOQaCjY3cyAPyUKOH5HzBgpuZs7HrseM7cx36yJVkj7SHiQ3vtuIsq/sDjTwOoHOOLsYIPdL345Hk0bDYMmA1FAu8GK3NwaG6IPZ1aAxs4++RGM7EhBEyrbwVt8dOIaMS3JsP8W1DQxQ6sZTpGgPrY/GwlV3iVddAhItQPsacj0LeAvYXd49zG1+91IWry2sH1lHxWy454jdWB9F3VnVhKc1HxiTXJwxpptNI7Oqrpl8uoWYGUOgQKtFOdCFW1i+FNa0cqK2aqIH4YB7V2/JRBVhmIbW5yS7cGFqahn9saldT6Yda/Z91U6fL4+cK0mZSan4/F898xLj/1R8v5vL+wURojcI1Xkn/V95EHqeTnrho+2eACRsicKtpb0m68/cRRrIy2xUcWbpYwyFA59UF3BhbvSHwQJ8/PQDEnquKD/ItWeYYDMKEDcJFUCKypHUiHVtLwWp4kf1Kko/pcgfj6tAQuNczsHNtfZqCl8z3f3VDTA4tLRlpZ6OCg6PzQsQiPi62hQxkDl1VUcJX4yd+vxFLAMjPnkyDH2Mniopw+qHx22vmlc/yhQxhGF8zNI6G4ToqJn3DOgXxoTc1QrG5MXccOcJ+TU4F/TYOAD1ut92uhhCSiiePU60KYVXvZgSXQ7oB20tzrtX9t3WMP1jzgHP/7xj11UP3u+K+TbcTQTZ/uz4Esug8Y/xaeJKGKqZ3LfGsQ7UYj4v2XY+saJgX+Lae2VXSt4iFlaJNVwN1A21vV+IMl/rqtrP1M1Ufwv1gj6L9+FmskcJk70uBdWpuopZOltlTyIpNjUpO9pefBkwOXv5qcfYv1casAmuKzZOGY/UEfl35zL9faSX7yrKXkh3alfn9d4Zbh1+3P9v31591x76v0JYeeuUrV0erMMtnvYaEuGd4rE/MY3Bxan60JDLNyORcYvdWGROkl+MG0lkzdgB+dgcUBdsafnnHJ3en86dmW1Jv99tFRK30sNs/nO2BeOaq8Jwt0uRGoK51oMOYXiOeOwZhRDHdRpgeZ2M78ukz++IMoXw89y7ryB4r8Ier9RZYmpjw2/UN3ZDt7ATLcpa7BkRXsyglPcrsFowgLqUU8gILnLtK5YSQgvbeFxnuM7clA3gqkDy5n4ox1zbq2+gf2BN5sXtnOpj+Gbp6V4c+FbgnQGmp+MHDnAfzBGLhyOQ8sOl2Rmcc398Zz51PoY8LqHjcIfRiJDtW2XaoF22FHOIzSYgyyyPYx7MmGZibkD2IuPpHyLVAGGC/kp23ypXzu4D7juVPKrnhh2kELALVGRXrSGqkRqkE3puw8UamkqSdjfostmSxyLo0G01N7UKomyTCbbjXhLdqDQQJgGoUlwFcaDqeBpCOmCblYw2pf0hnWEht6eeTVkBkKBY3MWgz0oyIDzu2BL2ffUn3uYfmG1aaWcJ7Vmlqp+VZprFHL81SN4uOVG83RbMQggNpxTx2302Gy/iBQa/n83CmT8v+UiZYhaCqLuEvBkuXw3dD2/KABrCFT7ciqgTK2oVG6BRxWrsRpsFRxP6HzBZgHMoz/uUuFmE/ObtRf2f9yXmHQ3MoV3a5cEj+sV7RHZ/ZFtVkt7d6lV/hh401K//DPz9k/u+QW/sW9EPwhnlYJ/DOw/L788As8plNeJc2zJxf4b53++/TiblhxOqoWJqRS+O7LykQsSPBL8bEtfeHLrlDLQoLnaGypFMdPLGlN8rPEimRM//90jzvoNvUtI8lhl9kTYmcEQ+HqBq2IJeqxhzcG1F6lEgWs60wDP0N3Z0lk/ne1XZ5UKF+s5u9NRt1Ro4w1XlhWrbPxaIGEquzE9oMw7WVSdAlJVHQNC252VlwCDazJKoJrXaKGSZjtlSXMKoIlIU7w1CVgT1YTKah2up/Odi4aMIw0FNV1AtBtMc/ACtVFcgmlkQg/puIpJpLCwF3FK4xvFo+PHeyneAUaawweBRkQAB0CKsjwb53/3V5JmFF6Ki7AyoUHS4zURXFhmcN4jErGRM/9CB9x1KB+NxFEq1kCQw9MSIclaLM8CTA7GAEkjIYNSwNMX2Oa4Lk41Z9VeaYMxEq/P9lH7VOQ/dxRQ/7zP1nvpbTIK0/rYowyU6rudVZlOSrED0swgHY7myV3lmu7lPfzDIpe1FCfhUkaWNfHQ6PMc0KRI9MxR5ZXrpDXQB7UMhcF2Gl+EKGjwbSsfjPB6xW0b/0BvFpvnBNdI20nMKClClDy1HZybioU2FAQTp1YY3ldy3liqLJBMl5rXqlz26Qfrlnn+6r+iHv1Q2gbiyRP0vsw8qwZKb113KlFEosJnQsYAlVSqHkbB7uSS/PJMpdmDkOInofRuy7LZWRvBvP6hRStKVARa0pyXS8vo0j88vemNjlgTm7sruQGjDiTtPB7uQSvgcIiL07n4BUX8Vx7twFh0H3RnYKa7BCUwMdb/6JBe7aDpR/TLCeMRvHtK74LRL7g/2j7P8j2r0e298UkD+klTD+YpIraRAWp0xpyRmf5XXiwP568gD2hceBoO2YfUl8jiefZVrw/58/SXYLzErJDMSpIbuelGJEJGssgsaUWYbSrpiUD1SFWLPK6EV7BEqVHSepz4oi96AYLsJY6VcYjXeTg+LQTD4GQj4NH38Jhp7txl8cOC2m97GMuR7GLlpECA3HPKlqjZ/HBBnhN6jkSCMTtxxKGduDJJxJG2obHGEf2Z3wxnym5QEjM8Ttm8sTtstFPL8BvsHK+xmK5T+/o0vV5R59oQT9oAd/nXfydq/g4c/k17+zLXIP/8k/psyzop8zlmyzojyzmg8wlZVbwF/LspcqYBZXvMJev0E/7CsN5Vmk6cR5f7rb3AZ/XVIwlHIa+cBgqRucH311ZKwq5LmbZEFyXbMwIy4uCShKd04+uDZiQcgVVJaHAU5iGmkVzozMXo2bUZThglTrMKnVysUWiCiXQbmoDb/vJAb7GsDZpRpFSZM86kTGbs848cIVXdlKlyrZOlmtRm5ukhwF0ZGHiHaeE9VtkklumdfF0LCLTkA/zNHfUulIuzU+d5DOzaGBPaUFNCNaK2t0q6UtphgcSaiYLi6XOgPHBS3Ext4PIAYLJKMyRaS8fX6hQOcTVqI6VR/vx41XH2rcCvKEBKC5Toa+Sp1uZ9mmcoNeQQk2fufyHICikgGsjMUWoJe7cPFoSQqky2tIccDF2M0UE90sKjem29IpKAxOkgcmkgYldDHVuU9ZrlaFb4hvohob5uv5zCUPEShWhFAol8RVQaFj+Swl/nmeHIS1xKK3CVPSBtbkGdw2RJCtEkBSMHLlrxIjWiloSi5g7QmQtkSFai8pgZPd4q/K6ITnTc+NMdBGTWapOsTAUbU0+SxHYKPHcpflnOIHJ/9v871kAi3Jzk9oJvFr2rjBWeW1MlgqPB2uu1/AM4XkCxSJWaVX0v+BgZkbT5NVRNbC5AZdF2hSPsMkVWXOHqJgsSzesWvH8XizesMPfw07SHaIbv0lI5XdhwKoRyWfE6ssW5/CrGrP6eovAAgLQfucganMrf2Nr4Qh2ni05zZafrYnl0gQD8aVNNkj9IkxbK1KVKppQJ1nlOXbr2Vqjej+owY8OLtUnlZGHmm4xnDK4acYo4ifMt/zJusEkl7hJpYbMCLKCQmdQ/oJmND4Nd7LE46qc5RgeVNmi3ZUyxc7pVR/R9qchyqrzHosPDi1AQT9NL/A/2MEYhFvgb5YrSNMgay2YZlGVNtox3/VhNGSRGDkTyyXPA6o8vp+ZQKPd/mx7mMATuu6nbBIuxGB2sES+k4BzKftwmBAei4exn0r6ZmJQnsR5bPZEDTPMwS5mUb6DlU6k1A6D4goWwP72eXi1gRq0BJMWFKnh0mYczpluuKIzoGMOC8149q9qmNKUn9hUXJuR9JfIDWSclczehg01iyGqEwukvryXZtHqP2AJ6gpS1ARaCVDJpjd3NueBIvuwui6qDTAvUkwfAHM+OYwa/FKdS7r87nTY8w7+y1xVLPFj5qlDG9ur4U1pB0SOcbjDdrkGFdUKlX/Gf0mMnN10mo5mYc8NZab2yFGYumhBvO4PRynCxoQkqHF3b5w+0LcV9DepZolcA99HqmmNuQXKGhdReHFfMjs2fqQLCoAhAx7aZPOsCjx87k7mU+c9E8/DEXVElM8DvFMsnq+VldBNC01IQCHOti4oG8HcL0ftTplHmdTgu6xQceB6RvpHTZ3N36I6m7+tUKfARorCF5VJGRSEfptX+1LdMkSh5biYlLua+eOgExENChddpq/6PtzRX32b8Kv7vyMDARQmkliFwmhDIotOaaMhVG80zkucns8lK+inbRqZWmgHTkU1S60Mdkbi5+XmCNlNbpkkr5ihqZJ9meexJ9+A3r7PyL1YJCjO/pPXjSgseUjQBbeLXjgHnXQ/1eG/J8XJID3C1A+sygailweyLKqqpUIoESYOigTaSA5NTUgH5pyeOBcCi12lUIpxas6cz8IHaHqFrBmHKvpkyu2cV7dd8swYEkFTQ+UHGf/Fyfi+KbcuU+5W2kRfjVypwDlNkGz4cAkbXp4i54dycOeVlDpNIFbSuVhKKI/lnTa89F1sOD6vXlVLm/yIy9WZefGoUXJcOsGy6sAW25fzMvMOl2AhlvDfqggTP5f2rM/+4V/gKkUXaMYWck51Y7lDDsyV2cTsw1BUL8rV8kW5knltHXMPJ2k6eppB1LE8VtJFiLe8+C4MztyCWdOFlycdVDIGMb9V5rriUUuNZH80TO5HMMjdRNXMJxsW2XDRI4d/ZuxPfxqe3UFX3F81NjsjquAbx2YbbD+50miUcAJK9xAlSciU+vgiRDd3z7Y2Xl483syNKf1c8iycGE42vwJyjKrEzOsnverJYavztveuWLUp7DbMeTAmtcLo0WI63B4/E9htPCtWr8ibxEITRNTAP3yWOooNSTqQ4BqxST+ehcVjEQUYSSCGt8p6IkILiiFbJOyd5At4/e7C41MbYgqtlEm5LMGb2gNLKJd8g+d6ue0mJOpZStTIOwFJCbr0ZmJ3hk/8b+wl+LPLxfROyncSJJk3DKFEFAe885fVZD3UsZDw3DgKMxaPec3FL490soNptTQLfHylNfBSY/xopZyfKixBaF43GvWKunHVTq2mq7fqGpZJgjDUtGhp7t4uVu4+gj3WE6shH7MWC5idYJAOuW6p9wWWntHOTyLavEzZAQqxO8WR2+r8uwU36DLCAjKQWr7l8SMQ+Ucg8tcMRMYVyhUQ3K3jX2vCam9QJ8HdGDlvp2Bcs2KpqDfF74QJqgGqKOcVsMsZ8qyMRvazzsZKxx5+BB2TnGIrflgrb6zxnyRM2dcl8Usfyu0WO5Qbju+PGOc/cYzzV2Hqwl1ylpVvVV30MjvPem7muv6o7a8oDhVB4AWHUduLzCJE9nT9wy9V2WxUncLTyD6XOZKda8t/fdl/l9j73ISpLv5Vl+WFblnez+AWOFSQaxRXUAKSIGse7lUM0Gj/fcV0wOHu/MfG1quP/8JgOq4ePH78cfWMtrgV//FCDvBjugV/Tg9LaKLFxScjpWlGyN6S0iw/8HXSF5ujV3rfbEaTd10Kq55joWUzzrJkNImfVHBb7JALztvqY5AKwd/cJG8sIEMLsyT45g1x3Ct3cEPYtU4ja0BcB+xvKyj7hIY8YxYF38LrwUCHwkQLAGmSt/tH6swVSNyYBFOcW6D3IikiL7CPslLKb47bwOegk46s4Lc2fDWggmTv6VDT4jwsFX2/+KBGN29cYDg30TO+O7PcF4zVUswbRQ4kxcZzhJxoPqPj56dHzSG/iUEjvju16H1aVbxo6cq8mtwQvPOX/NrZy2DUX+PGsXvW5WMNf+1rIO7HX6auOdf1DwX9Zpoiha99WNV/pilbVG9d4aqH9fjS9DWtoHrftycos/GlFzoUUWU18IWA81z8UFwxjEotvWvojtc15Lk6Lusqh3u5wiHhATpdyQOEn/yXHizRf+m+d647DvKK+GzFFFY4FnjUECdQkpJeOpwiC/zwhMpdtOqEXqbXxPBzx9T/IocsV8i4NgZryhVUsJbcWaJXCsUqfgBSfI2+iX23d6C7HLiTAT1FJ58Ii17gWEUFv0UARAbM140vR6cgLBrmCEylNX5290MxOSyV9HEq6UBx8lifOGc8/zGH8hzO9ZNYX30SlVvq0i030qa8dp612ajxFHc5RD1PDmpBG289dz5TEEf43Bj9oA4ywtGgxDH60xHHSBDHqBhxLMauObVlsmBP/sbH4tgAfA02rlip7xOh/PxRvjBEui+lGD5/YaPnLriZWe4wrGq5DyX7snpBem3nszkBqsPqwRS0+vbQtjg1siZJ1KZG4dJdet83fYuUnfn0yvLKGjxEr8PrL2jDyTQbAgNcHCXdPezZaDDtvBAawsO9eqMuTbKha1TyotfCqyhgFWQhU5MvMgCssrIcxBuwB/JB8ULjTu2iJQ3KbWGNxS0aigcsfEPdcfYacSjo+VZN0Xd6XYHRr9xq75VZV/Dvio1I3gVxEIafgKFX2PGTMFSK8Zkif9Ara5jzTrnFTuW17JtbchGTMsUpbrQa9qNGIqVpIpXpRanwMbSEsM4dMp/nsFqu0HnDSm6iadssGDk/tJ1By/nccjChsiSx5Of5xNaV536imqkJHEexuaBJO4KvZlK2pqSoTA0/Te8EbSjq+Zh4hjQU5hOZ5UrwlNULPsj65CkTuRcwegeeO4XOGDOWkEntCKIuqo+IoWBwNNVSElcNvvixhwa2fRYvf/bx4mK1fGPpeqBbmhaKceCVUu6IKcGt5AxPj04Aa9DJjglGIUbbzX9i5XZZIp9CnqAlqbAUOmdEbwnNM06IeZKIp8g7f7YtTbfWLFXxs/o+2fd2Q1xGc4mULzhWmygqZ8y03bScz7YH7YiNsa0y/huAeKUClcvY0nlQip3IvtUIWPTrvq7DNwFYLb36Eh5aiQRvQxa8yszi4iAeP0CIRbcfMyvZYO+oGRxLMA5SOW9wWdE85ArPbrFMkKtKc/zoMh6mpXoOHNJsRtGEgvMsP671N1rF0lluwBvTTaMiKy2s0PCIPeJJlX6qN85L50CwP23zL9yrtIW3fNKliPm04R/614F/IjcEyUWv//Ef6tGH9a7UPDwpJZqaMpckZoupSjxZWm7aBKyiVCN2mLOkoTXQUMuAQjy7Dn6rqzSJ1TKWaFRchXZr0Cya0Hy2UJxzn2vKKlaEb/3V3Wpg8uGaWHLw82dS2jCvCTXCcO2krURpfc3FHZPRChNe2m+RzycMByyScoon9xGJe5wLvuoURE3vgXRkj3HudUY5gNrEmDhZQXAWrrbVrAG6xHj5dWnXolrqg1IsXQ7OxZaa1gamt8DbfxjobWLN/7jpNVFztIJtvnMmXe4aLTyu6NV5IqsqCDAQcVBzeGzZcmiIDOWc5yXjPNQE8RHLkLby1kqOG2E1EZ9iwhTpY/OKCbGR1t5Xba+19//eW6+2ar81IpjtKm5ZReQCq3ZEyQFzT8I3lneSAeMLJCH468ynSSpiT4XT7itkp0xsySdp4rvckI9Zod8l5XyNPEwDvz8hNRoiSjZPaWLQU8f+99yCJSzrF0maxRMq242G9K4iqxzr4F8aYsvPtQBHrCnnNYb5vEb4yeWE0sYqOG6gueNwiXPqOw1d+LGOUuuIzohP3gO9mt6NkIjSchplLKfRWpfT3a/3LLCNTyn3DmslFbqx2lpZmsno76uCSEmAcA/xvFa+B4NxbeybrMK/E9e0LCPQXNGpFDJTxckTOormwt+X9DiH3MB7ELiqsSmMKNld2Dno4pjtQ//7gevdxPMYi7Trd9Bqiyb7+bY8EYeHKxBsoFblium072vkg3PfowSJk0xJkn8p1/AflIr4l806fhM65h3pNo/ucb/5ie87EXGRAIu1uO4iP3g1dSKEOnI5FdH9TYXXTzooQltPHBRREHo8X3fk+tZnc4ul66YIKVPNsz/CS4iHTlUJvNUmL601y6xN5Zy/e7r5b7SIvjcyTg7h346I03S7NAv9qkRsD3rm1US2KJcIhYCDK2OQViF2e0BJHf58l1S8BtqEKdNTQ4b+K13lVJAa6UTdzCwVQao3FGO7n7ToWT0sUlXfv4aUcMZgGdtVrKZYPz5K+6JZ2zP2wPS8iOI/hogY2s3Q8AAfLYuLRA/HXSgMEntJwyuQDLaq0dNo9VX0+1CKcTjD6i9o/TkL2AMEx2KKAvk2gWiVWQt9b+55eLBDllexuwVVW7Yyk0y+FHwgxkbufBWFYAoTk8q6szL98ldlDAXXOx4EDVdztPXJ2MBSewJFziMmZhQyCgnxflPMZDZN4jezqqHCGz2Tr/3Ankwiyx1IKhydOvk5vIGTgBnVdsz4na5IthiRr8VMd79rZmYYbbrV+0juMjQyx5bfJvwouk44Rkg5xrD4nncehDKvN9YMzDLFR30PK8Umz02sTF9Kr3h+Eyvm24zdtcr1K8X54hAz1dY7TsXCdp5slyuYZuUQ4z+r5MjsH3er5MCzrDfdfVY6uSUfBLEAc/h5f75MHCYUUrv6wt2ZuXB6KMhqvdbJ0Xd5lU8Jx0y4kDZJWbr+6vz8um5hsCX8OS9V6V1+y7xKyarv5ikFMsySEYBXSkoIkQ9F42wOHoDegkzOc92gnKUNdK3JUKYj/H0PzqBItYfFtzH/E8jxZK+XBFKsIYIiMTO2fwKTJ88Ne5L3/iQ2kyzVU7qZkCtRWMuZTy0PWPFp0jEYf2Ok44PogRPPndq+JdMEfxSjPQqKY2ItRBEjmjvPoldWf9R3jymYlwDoTj7z+6KT51ZCmI/UZUxh5HMssamfAeTYdAaTuKs+fMilgBahmYSNwsKW3a6ymqTqFtfKDQklDXEo0rgr0WIDYOhsgRlGXjM7ABGQgMJQD1ESSsH/w+FJSErfnXt9xIZjwRfLr5SfhVlmWOAnOqlkM0LYFqjr+UnwYDoLOWX8LuOwyUTnUTizd6hqcN0iUi4yFw7gy5LWhBUklzTgAyhKDey7UxOw+Vnx7DGeGyjjDaxlmiA3AhCqrUKveMQG6AwaYp6g6CfOEgxHhnYRHyFWND1C4WDzBD3SFLMv2uvrYXyAdYflZdUpmsFwdUk8DgriU5mCRlbQowa9gZwzRjnsBuoULdghJXAAPlcoIWWb3bAb+Mx2Btb18ZDqmVFIEs0PRLDQGdhJ7BLpyA2TUbEdViw9q8RawQQo319LNMs3LIM5Dmiq1pgvI4EUlokUlXCTiwHx+Xz4YOoO5mA0Wdcz1wt8ztqRwrs8xRyt/v8DoYSWXw==', 'base64'), '2022-03-29T11:33:55.000-07:00');");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('eJy9V21v2zYQ/m7A/+EWDJXUOHLWDQMWz8NcJ12MNM4WpSuKJiho6SRxkSmNpPyCIP99R0lOZEdOXGwYP9gmeeQ99/Yc3X3dbg3TbCl5FGt4c/jdTzASGhMYpjJLJdM8Fe1Wu/We+ygUBpCLACXoGGGQMZ++qp0O/IlSkTS8cQ/BNgJ71dae02u3lmkOU7YEkWrIFdINXEHIEwRc+Jhp4AL8dJolnAkfYc51XGip7nDbrU/VDelEMxJmJJ7RLKyLAdMGLdCItc6Out35fO6yAqmbyqiblHKq+340PBl7JweE1pz4IBJUCiT+nXNJZk6WwDIC47MJQUzYHFIJLJJIezo1YOeSay6iDqg01HMmsd0KuNKST3K95qcVNLK3LkCeYgL2Bh6MvD14O/BGXqfd+ji6Or34cAUfB5eXg/HV6MSDi0sYXoyPR1ejizHN3sFg/AnORuPjDiB5ibTgIpMGPUHkxoMYkLs8xDX1YVrCURn6POQ+GSWinEUIUTpDKcgWyFBOuTJRVAQuaLcSPuW6SAL11CJS8rprnBfmwjcy8GWKKh6nAY4C22m37spIzJgkx2rog2X1yiVF8fVjsDOZ+oTczRKmCeDUKberg2b4jLBbCRf5wjraXA6YnHNRXzdDy+X6wt36dIUpmBCkKuK25RnX4THTzNOpRMtxhxKZxgeMuED/d0ZpuQ+WG0ysDtzRaRZciGR5REpzhHun91RVafqDHp0oujtJWTBEqU0kjJI7yMLFEUFyf0P9Ng9DlAQJk9B40whaTgcyplQWSzL9CKyYBwEKi3S6EeozXJ4yFduOq1OPckxEthXjwtoEdL8+Jd1+bKPzrL82zkzI6NveZigoDt+/2YxEtwvvuFQahjH6t8DLWiW/D1NhilgV8yJhjv/XGLoSKeV8OmKWKJRFRJ1dQ2o0z0jxc+FqOEb22zPn6XqDbY0+eEHejK9Jttl/klGrcd+83JxhO1hi/CvyJNldXcNS4XHolzfBq1fFbCNsZfpZjgPflHK7R6j09mwHD92/XIbwL+swwJDliT7aLlVdQKhzKcCmbwP1voHC2RQ3CFzQEtn65dw7pZQwQh7KGTUCI1vdz0PbiPX7NS/WbChJfxvnNxj8DLOYQexyIvIp0iulbHUSI9Ngl6ZDK2p/Fd/MkW4S9NgQ1HVzWfFN7aLmAqfb6qVEMA5WChpDXHiJB8ZJ9Ta4RfIWlx2jYsaaMtxIKMLqG59/JjH39Ozkk/s+9VlyTo8ZLrA4XS4PcylR6A8K5c02tirUPN2bx+YJZpfRfSyTUreboIio4f0Ch7vXBGkq3Ba5f+Qol0QjdnWbinmobSJZy6ueTNfXFxkK8Ir9rcxiXi42+YuuPewZx8HPRour8glNVIWyt79Ps6/nma0s+8I5Mwy9FCHvQ8kmbijTqb1m/JbgNfvg+tqi50XNuM/0cUPSZTYRlyt632nb+pV+/pVyYVv7j4vfPix2TS+zJlQ/P/5gPWHwLU7a0WgzKjbYBLolgPWxyVpNY0sreWFrRaKLZ8x7xrQtN+/eZ+o15NBDovKRdU5kAIOICtTqNZ1t8kgzl5tRMEPJvHV2qpYOpkzQk15SzKtfLq4osuLrRkZaYTXExUqoT4WKOjT6eVmJnOqw0ruqQdjf57tTBfWL6vxnfkP/0jJTIqYL2U6/v/lk+/rKroyqqRCPvappPJebu+XB5g33jY3XwHjovNM0yBMkM+nvtlbr3aO3ue2qx6b7IFoa1W79A3i885M=', 'base64'));");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2022-02-07T14:27:31.000-08:00');");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2021-12-10T12:00:08.000-08:00');");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('eJztPWt32zay33NO/gOi0y6lRpb8SHv32nVzHFtJtbGtXktum+v4+NAUbDGRSJWk/NjE97ffGQAkQRLgQ5KdpGvuNqZAPAbAYGYwD6D9w9Mnu+701rMvRwFZX11fJV0noGOy63pT1zMD23WePnn6ZN+2qOPTIZk5Q+qRYETJztS04I/40iS/U8+H3GS9tUrqmKEmPtUaW0+f3LozMjFvieMGZOZTqMH2yYU9poTeWHQaENshljuZjm3TsSi5toMRa0XU0Xr65J2owT0PTMhsQvYp/LqQsxEzQGgJPKMgmG6229fX1y2TQdpyvcv2mOfz2/vd3c5hv7MC0GKJY2dMfZ949K+Z7UE3z2+JOQVgLPMcQByb18T1iHnpUfgWuAjstWcHtnPZJL57EVybHn36ZGj7gWefz4LEOIWgQX/lDDBSpkNqO33S7dfIq51+t998+uSP7uDX3vGA/LFzdLRzOOh2+qR3RHZ7h3vdQbd3CL9ek53Dd+Rt93CvSSiMErRCb6YeQg8g2jiCdAjD1ac00fyFy8Hxp9SyL2wLOuVczsxLSi7dK+o50Bcypd7E9nEWfQBu+PTJ2J7YAUMCP9sjaOSHNg7e0ycWZAjIwauz3luierbJ6s2qeLYS2Xd3Dnc7+/rsa3L2nVe9o8FRZ3D0rvvmsHfUyWZfl7O/6/QPe9kGpOwbmey5sL+QszM4cmv/Uc4+6P120OsPNLW/SI9MvzN4DT18c9Q7PtzLZF/LZH/XH3QODnp7O0pg1nh2qcBe5/Wr48Ggd7hWaqKi7Ovq7Gua7Bvq7OvJ7F1A8F935H6mgFnLZP+f404fV4Qy+3ome+fP3f2dgx25RJx9I5N9B0bzqNt/q6z9hTyU3T2B8tskRtXunsCLbbIuJTL0xZwbUiJDI0x8ISUK9N4mP0qJgJ+8oZ+kRIGx2+S/osQ/Ds5293v9jgB5jYN7ZXpk6rmwvil8EISubogko8EyXcwcC1c78akz3IXa3DEd0JugPvEvG0+ffOKkNSp8QP3RziV1AqPR6rMSkwnQjfonYrJqNokBBY0mCW6nFH5YvEZIuDLHM0iBr+QOm77jdCRqfwL0DGjTK/emHreLPKN11jv/QK2guwe9MES2lXP3xtiSMlkeNQPsZ1QhT6kHdjAGXmWZU0wFwOwJdWdBE6jhLfvr28MGr0g0io99QXhJsg2NYq93odOeOTYa5BMJvFv8l39XDw4Q/im0cGhO6Ba5g+YDa0TqN1j6jtzFDeEkeTSAahx6HU5XPepEHch8EzJ8YM2y0YAU1qi/FSV8YAkftvjIhlVDtS13ykn5NhQfm1DraBPeJu5wNsbpkUezCVMQjNwhJPtj8wrnzPQu/U1ycoogpyoOO8/+pr6JsYav4i1Tlk0BK83eUt/5zMBn/rIVMnh82m2pW62zIT2fXXZ/28W6vJkMSCqjPbVQzLkEhgbr9kdBHMPMMKHxDwkNUsPYmtlDKO7jvzBhs/GYvIynH4QcbwUkDcZNAQUE7h/bw3qDbGKprWTNiGSZ2rf1FV7S4DfPtSChd+1QD3GrPuUJrSlgcStAXIb5HdIxhcWQqntLxruwfbkv//iHvu2xa32k0BGsPjsiK2uJyqVXgfiUNrQDnAKjkfyayqyekZW11NCmekrHPi1VLS4mBHZL+XnmsRUZpD8nu55EZsQ8mUhYI3s8XAHcQJmWeognnFBJvUqvYqyjNTH9gGEvpKi+u07dgJqGt7BwY/qhH3ZGPIbUtzx7GrjeAQ3MoRmYGiIbPowwYkkOTrSWn4nJC8mU+HwWr3WfBgP+QyJvExCPsQz+5d2gN3ZQbwA6NYmqnR8ISjaJbw0lYsuFQ4JSFsF4WT4IwNoszuSAMDKB0Yi4yWYCRInFBEhdk+AjubzLQRx8SqGpFrid/c7R4H6Ay/CVCOMEIAmc46KDDu1kUqvpog+bQWuE9bRE9xrZTIpy+FgmiDuwEPwpLCRqbKpz4ZPGkhBXER+tMTW9EF2VmbZ0eI4olsHIdLvYtRBGxEsu633+TLIfem8VnS8YhPBJgAjV1lWELXxyQM4i5vxAfEh0fk6AzoHSfdQUHdILczYOcmZeV/oud3UyVla/uMinH6VWDRK5xJKxMoQTB4ozC4K56ZBrSCx3iIIbeU6shkLes8aun5SCMSGHC0RgCborQZ+sOs37ws8MaCYwSs3WsxI1CroSC9NxQ6lRMRJzUZlCCqLAWU45OIlXIA//zImsBrfYWLw5kDt49oZCv2zrwPT8EW4fNEjLiqLQtbGOsiyvqLXLRINDM7CvKIh+N7dcMNtYbw3HpeoSNRwwyZ7tUMQm6w+x/1OVj+RvafjYPoiPDci89Uh58jmlK/is2n9/ltUhn1PaC5SN61yRtITKSgyJNAgt0791rHooT0Qj/rvp2agH5AgUss5PsARx9eFOA5ZebiGx7cwU4WObQ9FbwYg68gZwAeqfZrUVy+MjFpLX+t1MC05z1ogPW0vI2nKItCI/17FUK8NUMNWKMAVNtSJcfVOtDCygkgXwYbgWjMwglv1i0S8Sd1BXwF83CZuzjFSX9+Rx1fRTzGUX7wEqu+6lAzmSRYnPGkEg/RSshYJGwo19hi9n6kls94DipEoC2WlNTY86qDxA7RKbA8FkNPXqxjF/0lWlVOLQndD+RWCPbWd2cza/BpB/hs3sBQgR0Msp9YJbJrY3ifFv6tgBbIq1soLQTNaVm2ZFfl7GI1w4SwszZ2L4YWNPb6j12gaGYLTPbaftjwC5Twz4c6qaT1a65QdD4A/wB8Ukw9hKJqMshJv0pOw4mjkfI/kRSz7fJiyxFbj9wLOdy3paVsw0ajsttG/Reu16RD1q+4SPG3BY8/ojMRCtbCcg362TO+O9g7j13qnpq7w27aCjQ10cvbFrmaGWMNXzFsA8URbErVNcEAcoobS64KNu+4HfR75utGe+18YCYzYDAhWYEktqX5NNuYnLQiA0Ykw+ZuqFraQSSO401/TCWJrBaDMCIVJKb+qGQvT1JbkwYSdGQnlCMULqpQDtNklNtFJr6kjTJQUQtMsgfHLoWrSljvfDSp1LyerCYZvZwya5sZ0Lt4C2L0Pi4RrFUlrdEpyGQS3XN3EBuVxvBdO5TvfPLrzWodmi+sqwJVKni7ElfPgQrC6ze6sLdg4xSzQWaxrDZcdWRVYNmH4WJNoozcPIbHJ0pM4VmlL+3Dke/No76g7ebfLBaN2YM9hseUg7X2aTNkkN1t9et//b/k5URBiL0MxSNExfhEsoAYg4RkQOnxODrKyM6Hi6Yo7HwDkuPToNaVvIM7S71kwD1PPUXaHMilaunlw+JD95MkTtTCKdobxQjVQXNR+icoJ6fglt3bIAUSQrByGPYdGbwDMfhF2xlh6Z1SOzemRW/9HMitGBlfNZELjOt82xItr5EPyKNfbludW8YCyDV11xZ9gH4VairUd+9civHpRfPXKsh+NYyEsUAGhZzIOxzJD4cMXgyusWeR9qBy9I7eR74D7f+6fv3yMp/G4N/ltHB8j3RkV2mmCD90+YcAmkx75lO9Z4NqR+3VjZBRzs7u7skx9+4PpDN4/7nnvuR+rI3DfkqkVLEZ98xi4xGlH3v/q9Q1Tx+7SuYfKNUlaUJDMV7Xw1dLP0qIRDfrLeJGs/nRajPD7L7vvDCDwl4FxQ5MnzemzIQkxUGlfSMwYe16NnXUFyzTUfh7Y5di9le02qePgU2m005XjZpdtv8Pli7CPHjiMGtLohJ663cEsSYknRHoO5GW9GBhBddmU3k+jGU7ZKItVN5ED0iFXLwapwRP/OaBVJvLm45biBfXGL4TOPNuaqNmY+dis4ePdiaL5vBNKwwBBvFopM0gUlJe2qLA4pdD1eW03Il3+HICahodjiwyqnplUWzMHUdvLUC/A5VC3E5fJif+ZXV8yrmkiHztRzAmfUmoT5tAaJ3X1GH4Ce6QgphnmsossFvv+Mw90ocC1mbswDDP32b/2ATqBXDkaEh3tyE2PDPSJklHP3hgBtcMJkTiIIfLqkQ2Jn944a8TS9CDLSqALctNza4jYh6OyO55m3Ldtnf+tideIH/toaU+cyGJFfyFq52KXsoAxdynvqz6ZT1wuINfMDd0K4Ilq04yt3zuXCkvBpt8mbw95Bp/2/ncPu4J1isuRowTBOBP8I+teCKQNCawASfXBtYBPv3xsNKd5EvOTnjlxdUuRuMwrI5MMvQlSEF1La1YXFtpreBGE9CV28TreyM6qcu3K811aMNmuzNZ35o7qxIlaUItuF69Xt7dUt++cEimw9f26XlybtC6hje7W6ojgJpPtxZWye0/E2Bg1wcE5srayp2S7q96yl4ZBNK3PDkh+hUSp+SoIqGRcGcgCA+deM+ojFBsgD8PPaZAclZGY51XKyq2zRsD6yt3TZVGYYGJZXLJ/83I67cu2Z0ww8KTLXkmKZ0rCxDwK6MJYpo9xlwSSlhU+5ZRShmrzRL6LS1Y1EKdLMJb+CoEWrQjRaKxUYpssmhCbBG0QhrarUan20x2OlyHsXkdgoVjLqmAKJNbOuCQzlQ9oksg+urgb56IEgy7ZbGk135tNS9yOJ2tluR9NyyZ2QO0/T6ggwd5hWkipwKkLu3FjFxLpWVZHkiqxMhIBhZLWaV2rgCivGXiA9ZUJiPY5OH5sB8MQJ24hceJSe+0PmuiumL5qKxMasgWJnpopnUhUq6HIgxCfZWYyJzOv+yeqDcEoUN67McRj5lR2QHAUvHvNTZ/IKO5EE/vxM8roUyiJELYyUgBafCBF1A2ef4iReFUYNldD8Z6cMqy2t1L8XJX4aphJEu1icwYcHXCnpAT46PoMhRas5wTjZMcwbwLw4GtbUWoWmYGiGwDfoMNfyt1hEb4SOSusdR02xmzQaEeHJ4G6uyCA/ZfwqHHNC87QHsBE/hiTMVsZBIQkxoMjcVnZ+No+2cH9qXjsDyOO3Bp2jg2L7WRoyifXLn6rUEoqe6aqrQpIRL3Q51Lw+I2FUs6WrGktqXnU5NOAsh5SqOlNcVFpi8tr6GZ7vzo46/eP9wS/wcOt41E7E0bxQH5AtcLJ2WsouroEg1SqPdQsF5MJQv3nmMFJkG/6MrLBofL7anxOjhINDfpX0hmmAxIaH7dOSe55lNCLUKlh5LhsvtzdeDBaS2DArgeFaau5/Eu2X1Vk1u+g5QJL2yRqg+DaLzYeYNYHX29+9hCRr5JJaGt1r3KZRff6Uu4bFKQLX3fsp0VNar2KNrp7KC5gv2uLaRfg4c07pOgFaAnQye0W48SmUetJPNSko/VQJjy6UkopAKyc1LQLinBHcCRjTMlfMUb5E2Ha+q9i9nm+TPyrcCau6lw4+ZQ+r0dg/sGuoSmYwCV8QvRGEGdH8y1i1HrnjkFCvaYgzpJaobWdBtSlbykZ40hxfC2/3uIXIdca3oZXEJ7Mpns27kbWTJM0iquHFqpmNKXNyYPgI2pUAbEk7skLqEM5BpLaFBFS2LbRpW6/S4C31HbVxo3R7G5Xbs/AoaP3BNnmtKqY42YYkGGSzJpQoq1yJUkpdopl9gTs6BUsORSnF01SjV8XKEz5FhLcUF8sA47j3BkseCith4Ri1bHjuxzKVBF4lgPNFyaXvHIqgRfwUhFkCnqttRb1JdLiIc3ViiD2KcVrBuFLeniRYjzAohX3S2MBLGB3mmRLmaDK8zFPjXNjOsONc1ZmNy/hz783Z0fHhoHvQOdvrHiErYt4UWEfsssOrNPRHTDzj7hefP5Nnyc1fnBKbyJKcEo+59cwx6Xie6zWJ5c5g0JnLBQ3wtHeHkj/X1toAKFrkSvPKpUye0iCoNu01cw2F8DU50JtsTDURHnPhR5EtTPSwnDGsokVRgYklLIkaq2AVi2BFG1i+fa3YepdTnot0vnwKtDrjMq1p5aU7vc1NXSBjL0EysjTrlRisE+z2gxisCqwUJWrAp/T+fb59e5ltZel9+mL78zKglN+Pz2F8qgJMhZCRbJIanTSIULEj1ba8YsGFnur6TW+7TQp8cTW0pzw7DIEQ/PBEikgAWc6iyLPZq1jJRpNk5b9Dd3Ot+Y76m+tMBOy9hRcsEw5ZBLakhsHvArGiOre3scaXUJ+xCbWIOqStfTQQXyYosyQTQgYyNwcqKqzm+eGsLdMDZgH+JXaZc5iK8/ZRf3NT8ZzEcwlqOC0BioX3Y4ddPxW4IkhAcow2UjXHP+Y6+HlBT6KoOBcjC1E18vLPneG4Ro0oqxxbzenUbIyUm1r0Lhqa3jU6lEcnTUYjF3im40NWysN+6u75B/Vx1hixwGJvfUZs7Ytblncrmesccr2aXVxQr2WOx65V/xAqOZ+TF3Lmc259OoYN3Mb6fkebT1R2AShc/4BBCNPb+nkzmSccknMplil55ubEtFx/gTM3eSbbsYPub7uvzCTyyemas8CXHC8SV150l8t8MR2KK01KRD5kXH/18QrJ5YxiAjuZEoaqHUymbVRdxQe7Uus3yBAa5NoA9tSd1htoijyjV0YKA53S45OIngnG3EvFoR4shiPTGboTcYdO3VhDqeG/8UnTpfLD5KSiV6TC1yO8KLCuPdkzGqPnJC8EhcU4ZcnMwt1MQZvorqrB58/TXmhaShZOvdzD5MJuAT70qXdlW/SQuxjh+hwdYiydzY9qwM8gUGbL6k7xl9b0suPVHij+DNfxfnhwvdIOtSXjZuqGqnApoWNFFK6SdLLQ2rdUkUAbucThPgLlQuTIBhclTWYmUP4bezKb4EWaoeUsG1pUhlDx+6s0dNT2j1w3qOfHh90PB2CoXOKamfm5gVxDFTc/0WI5UlJ000gIAJ/xQ5ctAT8nWE4UKBkuJhlI47WlsPlWvVwpul3ixIC9LNJX2IemjckKXT0nJ7dT6kaNNph5gp/EYlRqGXa9iiaTCUx4i7SQRviKVDUl9QloWh4FcmUBDpxgtz4ZUsopptxlpiSs9Pk2qRvh5iU0Z9cke1WSwKyQtVNk9rVMhbGSGOq7tK/wktfZlJgXePFKIuYn21nb4sdhs4tm2A8LNvHo76XILHwYAzoeE2vmoc9deIEul6LdKMZT7GFqUpATA17c+cs4QC2KluKf8CcDAZ2+8Ec0UopLA/Hh8MiycU0s3hY0Xocqn7M8zwkOWvqQ/Foj1pkY5yC1/vRCcUFKNcUP9739t3C+/feyvG+LdBQ5l7fNEZyTdFetoJmp4Da7FF1IoR/b+5s1qiSJStU8MvVnUN/J2mnsWSrrRIzd0FdBa8OLi4tABLVtTfA1yJp/8D3LCfNwhjav3vHgLE3yNCODj0LpIWopo2jFp5JeN/Q3Sozo588k7AISfvk3kONl2ELQu/ABjB/VtVblVOdKD3iFrS9f56lwTo7EFLXrsLq4brfZakcishEFeRNJbIZ37qp7/tMLLMxA4KQXJp24vsnJFln/pT2kV21+wAA7/UM+Se49LtjaFrG2eRvf4S1NeKwanvfVrMG64+k8DVYPu2MYvm3WmNG9bm1vr/H7UPA8Efh2so432TJZ4lOy8DoUvpxJZS9nkLa9XUPXsFpcSS1ae7W4pkT9kAz/T/fhLj7+TnMIXjkdngYxU8q4kF4lFGkZRaWKu2lF/vhnu036gekFZB/vyyB8p6lS7WQURAnChv2dqLlWm+83jWTm5IXDfLwy9wyLnPrrhXMFVoUWp1BYVXhaPivygsxvJyWaVtEhZy9OlnNoT69thScv1JBOq04t1CorfDb9MdMFxBDXq3HESCNTXKbFscTLXGYrPqMoAAKcQ9lS0MbBpBU+DOnicogbqWGwJOGHZc9KQJZarjlnwmW55cjzorxOfiYvkNeJFLyiN1LxrjbILyTOGq3cmeOP7IsgbFEpOLAjMEINND/9UdTkgxBO6y+amiYbBV7aoW1/Ou/lq52jo95R3s2rWQY6RSD9/LCNQkuTsdfd2e+9Kbrzdbp4fF9FcSp87ssDnfdK7Bpl+SqRCIQF0xKwi21ljjNKSRDwyQpkYftFXgkFjv35gzMndOUdOOaLEK7gqJwATdA/wfuLRL/IcfmG2E5Ez1oJlWz46MxycYGTm1NkxrUo6Cn5iWkcCnRXQnpMG9Hki6rFMk3eRR3x+PQF1hKnbzKVANQQ6iWaoVpgMw1u+GVP2IMz3Un9FpqVFRQj4yOKYsC4SHGXIJiL374bRzSySY/3zUkcSFgLyin0RTXB7tienrumN5TBktPrFrwN6I1Gf//16HcTaPuta3e/hHI3q8Mz0c4CvVtkq6dVDcqqOENWxXE9oMA6RlMaWyl1nKFRx6VH5ytSxlXSqOnVZlWVY2rlVOHRN8tSEnAMytnt7+8cvtmmztlxv3U8eL3yTzI9R4eF4t1wofXpnjaiVkgY20AlU3vQ+9vtRMthO1oZX+u2iB10m4eBGeaVnt3H7dVC2yu28pB/F290EJdYHMgytzpytV9gs1PNPXHJgbX4lBFx4zlqRgtayJPRUlcIk+VFu0uNaCenKzyvHkW6v5VIl676W5WHvrCFcWnWRfWhGKUMVQ8jr9UU8tjU9AM8xx9Gkjk94b+rGz8a0Q0/4W8jcwy7BsZPJaExCJFMJasbP9W2KpTkh+yubdk/bx++ZkfrVihcBUQJyu/97/1ak+DBvGsva7XNGt5z1GiS7+yttAVTX1/WDWTZw1O7Kz1X34IkfvmAkvijgP0fL2Bje4/ytazFR4B+R5PgVyhqR7O1mEA9dq2PsiCNvxUC9D3RuiH1PwbutI2tPpK6R1L3tzfV7vd231Zpd74gxGXQFwbpYrSFX3MkUxeekgqp+IIRFAvqBSo6BDtSqEolt+C08bGa0+9cPr/3eLeRQJ0FVBpLUmd8ZaoDpV9zjS+ZduDCdrW2uNpBGxpefK7Jci04zL05zfcS3p8q7+O9bv+g2+939oyGMv7l23QJ/Xo3oxz75vJJfBTnHsW5v7s4d9gbdF+/w5a/BZFOQFvdAWkxMZAtdtiqcqeL2BsnTq6Ls6WV+85dHpgbjCjhueOv4ZHUrh/ezi4xcp/HCq9A54HKeFwk6PV/5zkTkxDWM59EEpq3eP+i0g5FSZQ7de9GdCbqqroC+TI68abJWI5gpJbN/ROKeyESRQRCQRxK2ow5G/BHKL2XEwJnvscEQe7QwWRB8ao9gUxqpGVPLcFOSmRW35uQ/HgvNyCn2lHcJZH8+BBAxOJYZEtWMl3gxqWrrXK4fI7+UHENCwvR1UV3FVQXQQnIwrpTxeTOFKibJA3O3bzncC+uVK3Wi/kg1c62jp+WU3kvQh6YfVHQB/5eikA8rvmwncJ70qNll4U6b/Xl4GxEQEpp3rMLLguIHpuXHppZEe7fRayTGvcqw52/0PL0ntUXWYkr31MVPy4rJSs12n12WEp73z73TO+2vet6VByy47cPqDN7/5508AZbv43atNYEkiCTE4AI6rePqO/OPMy6+6bP5WSy4s/8KaCiVpuhgulrXep8Y4mKTtwrfguLnC20Jm6ugpm/SVaXvZDjHa8WxMel/EWWchxgvkLJ+zkNEtNWrkliGl9JVYtjux+XuOK5vyUeqXHubZHnB5TiFj8ONo/CSslL3dk7ceQpnt+bNmbJ1YqjeKYt9oIVxofy8JrwNapGX1F8gNE0OlIdqwvfP/HaxE9p5SFq3xm5gMphpyLODjFUcQxU+OTMeO5JSDKQoiVNC5ppfhB6HIzM4FGn8fDUWz5fqgLdLnHGFLOOGdLhJN/iYSR3FRnUfeuC2NFKqS/SdZ49EJrf7Guv9i5oVdOyVH99ZW39n43c+ku0gQ9rAxd9IaeKIp45hkGKOD2qQMmDz4PFxpfqiVJKKK1eK+jPfZ6PkPbbly6azz1Qq0Iz+MyBE3G4OT9t5dtCiAxqawb6vhAjhjRi75rrcVhFuQSQWdDRNr0s0sdBil2DOIEtuJo45xrLdrvSTqLdLtpLxLQ4k6E8SW63NWPRbuO/D7P7aLc1w9lu61dEAeSK0ZuHfPDKclsqPU6VqQavXzs2+G/e+NwD5AlCoR3ZuXtUcaOXf2GEqpR8GIfOes1kKNSHq/1hZo7twKZVkIFGvvNMKrOmxSiX7FqQc/QIjOIhpUOUo+Oi7szz6fiK+sm8uJEs7x+Y9hKDLVThyfV4BQ1+hBGoMWfS7Rz3BfGGbgz7JnSVe7tyb0+OVKEfgyjL/D+h5sx39HOAbyi+wwCOXZNZTJOnzkO67Xxkp87jFRK2H2Q9SZkD5JAGpjWiQ74kmxUcIvc6g53dXzt7Cm8W5oOnJPSqg2AkhNB7oCTczTKOKElnNK0/SsJhOH06fzi8eH59g59/qhnRRM4ERwy/4LYQ70TZYZgtruqNs8X+fEp/E9GNtEOd0sMUj20GbJBBwv3fKSZGgEY+gahEaRK5QPiJ60wa6Tbn86nBkot69bCg4zx3mvCII8QG5f2E8RUoCkoCHzWnVeGXaK3xsOfYAYiobt25a5IfwxsK013ApUeVfkNskObyflTfeJOIu8qc8oQt/Z9OQkzVr0X8JB3i6J9qU261kBYKCi7TwyQkCiaO/r+bEfomb5VoEtEWkuvNzAlBTU4sBozEGTvHg95Zf7BzNIBhYdeFCYRvZhsVKM8I3yY5MXb+mpnoQD41PWg2APTF1IgZRF2Xj7VuyK50IGRMGYyM/qdWL5J90ZFUhtQlGpg1jxOnKH6UVcnjs5mBRaSEiCRWVeV1ukkLHfxbgpeVcE8U57uKu8TSdyXFtwIJRzLb2ViXFeITdzgbU+gqv16Ch0nI1wpJ/ZSlKV4drIfZTVgdTwpvGy5qgxU9K92SuO+pEPLMtUiKWsWQhf/7f/BguUU=', 'base64'), '2022-01-03T19:05:38.000-08:00');");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	char *_notifybardesktop = ILibMemory_Allocate(27893, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 27892, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 11892, "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", 11892);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2022-03-23T23:09:33.000-07:00");
	free(_notifybardesktop);

	// proxy-helper, refer to modules/proxy-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('util-language', Buffer.from('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', 'base64'));");

	// agent-instaler: Refer to modules/agent-installer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('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', 'base64'), '2022-03-28T23:54:51.000-07:00');");

	// file-search: Refer to modules/file-search.js
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2021-11-03T00:44:29.000-07:00');");

	// zip-reader, refer to modules/zip-reader.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'), '2022-02-01T20:15:31.000-08:00');");

	// zip-writer, refer to modules/zip-writer.js
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'), '2022-02-01T20:10:17.000-08:00');");

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
	t->ChainLink.MetaData = ILibMemory_SmartAllocate_FromString("ILibDuktape_ChainViewer");
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
	}																					// [msh]

	if (duk_peval_string(ctx, "require('MeshAgent').getStartupOptions()") == 0)			// [msh][obj]
	{
		duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);								// [msh][obj][enum]
		while (duk_next(ctx, -1, 1))													// [msh][obj][enum][key][val]
		{
			if (duk_has_prop_string(ctx, -5, duk_get_string(ctx, -2)) == 0)
			{
				duk_put_prop(ctx, -5);													// [msh][obj][enum]
			}
			else
			{
				duk_pop_2(ctx);															// [msh][obj][enum]
			}
		}
		duk_pop(ctx);																	// [msh][obj]
	}
	duk_pop(ctx);																		// [msh]
	return(1);
}
#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
extern size_t ILib_NativeAllocSize;
extern ILibSpinLock ILib_MemoryTrackLock;
duk_ret_t ILibDuktape_Polyfills_NativeAllocSize(duk_context *ctx)
{
	ILibSpinLock_Lock(&ILib_MemoryTrackLock);
	duk_push_uint(ctx, ILib_NativeAllocSize);
	ILibSpinLock_UnLock(&ILib_MemoryTrackLock);
	return(1);
}
#endif
duk_ret_t ILibDuktape_Polyfills_WeakReference_isAlive(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	duk_push_boolean(ctx, ILibMemory_CanaryOK(p));
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference_object(duk_context *ctx)
{
	duk_push_this(ctx);								// [weak]
	void **p = Duktape_GetPointerProperty(ctx, -1, "\xFF_heapptr");
	if (ILibMemory_CanaryOK(p))
	{
		duk_push_heapptr(ctx, p[0]);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_WeakReference(duk_context *ctx)
{
	duk_push_object(ctx);														// [weak]
	ILibDuktape_WriteID(ctx, "WeakReference");		
	duk_dup(ctx, 0);															// [weak][obj]
	void *j = duk_get_heapptr(ctx, -1);
	void **p = (void**)Duktape_PushBuffer(ctx, sizeof(void*));					// [weak][obj][buffer]
	p[0] = j;
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));// [weak][obj]

	duk_pop(ctx);																// [weak]

	duk_push_pointer(ctx, p); duk_put_prop_string(ctx, -2, "\xFF_heapptr");		// [weak]
	ILibDuktape_CreateInstanceMethod(ctx, "isAlive", ILibDuktape_Polyfills_WeakReference_isAlive, 0);
	ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "object", ILibDuktape_Polyfills_WeakReference_object, 1);
	return(1);
}

duk_ret_t ILibDuktape_Polyfills_rootObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_push_heapptr(ctx, h);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_nextObject(duk_context *ctx)
{
	void *h = duk_require_heapptr(ctx, 0);
	void *next = _duk_get_next_object(ctx, h);
	if (next != NULL)
	{
		duk_push_heapptr(ctx, next);
	}
	else
	{
		duk_push_null(ctx);
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_countObject(duk_context *ctx)
{
	void *h = _duk_get_first_object(ctx);
	duk_int_t i = 1;

	while (h != NULL)
	{
		if ((h = _duk_get_next_object(ctx, h)) != NULL) { ++i; }
	}
	duk_push_int(ctx, i);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_hide(duk_context *ctx)
{
	duk_idx_t top = duk_get_top(ctx);
	duk_push_heap_stash(ctx);									// [stash]

	if (top == 0)
	{
		duk_get_prop_string(ctx, -1, "__STASH__");				// [stash][value]
	}
	else
	{
		if (duk_is_boolean(ctx, 0))
		{
			duk_get_prop_string(ctx, -1, "__STASH__");			// [stash][value]
			if (duk_require_boolean(ctx, 0))
			{
				duk_del_prop_string(ctx, -2, "__STASH__");
			}
		}
		else
		{
			duk_dup(ctx, 0);									// [stash][value]
			duk_dup(ctx, -1);									// [stash][value][value]
			duk_put_prop_string(ctx, -3, "__STASH__");			// [stash][value]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_altrequire(duk_context *ctx)
{
	duk_size_t idLen;
	char *id = (char*)duk_get_lstring(ctx, 0, &idLen);

	duk_push_heap_stash(ctx);										// [stash]
	if (!duk_has_prop_string(ctx, -1, ILibDuktape_AltRequireTable))
	{
		duk_push_object(ctx); 
		duk_put_prop_string(ctx, -2, ILibDuktape_AltRequireTable);
	}
	duk_get_prop_string(ctx, -1, ILibDuktape_AltRequireTable);		// [stash][table]

	if (ILibDuktape_ModSearch_IsRequired(ctx, id, idLen) == 0)
	{
		// Module was not 'require'ed yet
		duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	// [stash][table][str]
		duk_eval(ctx);												// [stash][table][value]
		duk_dup(ctx, -1);											// [stash][table][value][value]
		duk_put_prop_string(ctx, -3, id);							// [stash][table][value]
	}
	else
	{
		// Module was already required, so we need to do some additional checks
		if (duk_has_prop_string(ctx, -1, id)) // Check to see if there is a new instance we can use
		{
			duk_get_prop_string(ctx, -1, id);							// [stash][table][value]
		}
		else
		{
			// There is not an instance here, so we need to instantiate a new alt instance
			duk_push_sprintf(ctx, "getJSModule('%s');", id);			// [stash][table][str]
			if (duk_peval(ctx) != 0)									// [stash][table][js]
			{
				// This was a native module, so just return it directly
				duk_push_sprintf(ctx, "global._legacyrequire('%s');", id);	
				duk_eval(ctx);												
				return(1);
			}
			duk_eval_string(ctx, "global._legacyrequire('uuid/v4')();");				// [stash][table][js][uuid]
			duk_push_sprintf(ctx, "%s_%s", id, duk_get_string(ctx, -1));// [stash][table][js][uuid][newkey]

			duk_push_global_object(ctx);				// [stash][table][js][uuid][newkey][g]
			duk_get_prop_string(ctx, -1, "addModule");	// [stash][table][js][uuid][newkey][g][addmodule]
			duk_remove(ctx, -2);						// [stash][table][js][uuid][newkey][addmodule]
			duk_dup(ctx, -2);							// [stash][table][js][uuid][newkey][addmodule][key]
			duk_dup(ctx, -5);							// [stash][table][js][uuid][newkey][addmodule][key][module]
			duk_call(ctx, 2);							// [stash][table][js][uuid][newkey][ret]
			duk_pop(ctx);								// [stash][table][js][uuid][newkey]
			duk_push_sprintf(ctx, "global._legacyrequire('%s');", duk_get_string(ctx, -1));
			duk_eval(ctx);								// [stash][table][js][uuid][newkey][newval]
			duk_dup(ctx, -1);							// [stash][table][js][uuid][newkey][newval][newval]
			duk_put_prop_string(ctx, -6, id);			// [stash][table][js][uuid][newkey][newval]
		}
	}
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_resolve(duk_context *ctx)
{
	char tmp[512];
	char *host = (char*)duk_require_string(ctx, 0);
	struct sockaddr_in6 addr[16];
	memset(&addr, 0, sizeof(addr));

	int i, count = ILibResolveEx2(host, 443, addr, 16);
	duk_push_array(ctx);															// [ret]
	duk_push_array(ctx);															// [ret][integers]

	for (i = 0; i < count; ++i)
	{
		if (ILibInet_ntop2((struct sockaddr*)(&addr[i]), tmp, sizeof(tmp)) != NULL)
		{
			duk_push_string(ctx, tmp);												// [ret][integers][string]
			duk_array_push(ctx, -3);												// [ret][integers]

			duk_push_int(ctx, ((struct sockaddr_in*)&addr[i])->sin_addr.s_addr);	// [ret][integers][value]
			duk_array_push(ctx, -2);												// [ret][integers]
		}
	}
	ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "_integers", 0);			// [ret]
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
	ILibDuktape_Polyfills_function(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "addCompressedModule", ILibDuktape_Polyfills_addCompressedModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModule", ILibDuktape_Polyfills_getJSModule, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "getJSModuleDate", ILibDuktape_Polyfills_getJSModuleDate, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugHang", ILibDuktape_Polyfills_debugHang, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugCrash", ILibDuktape_Polyfills_debugCrash, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debugGC", ILibDuktape_Polyfills_debugGC, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_debug", ILibDuktape_Polyfills_debug, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "getSHA384FileHash", ILibDuktape_Polyfills_filehash, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_ipv4From", ILibDuktape_Polyfills_ipv4From, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_isBuffer", ILibDuktape_Polyfills_isBuffer, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_MSH", ILibDuktape_Polyfills_MSH, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "WeakReference", ILibDuktape_Polyfills_WeakReference, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_rootObject", ILibDuktape_Polyfills_rootObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_nextObject", ILibDuktape_Polyfills_nextObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_countObjects", ILibDuktape_Polyfills_countObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_hide", ILibDuktape_Polyfills_hide, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "_altrequire", ILibDuktape_Polyfills_altrequire, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "resolve", ILibDuktape_Polyfills_resolve, 1);

#if defined(ILIBMEMTRACK) && !defined(ILIBCHAIN_GLOBAL_LOCK)
	ILibDuktape_CreateInstanceMethod(ctx, "_NativeAllocSize", ILibDuktape_Polyfills_NativeAllocSize, 0);
#endif

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
