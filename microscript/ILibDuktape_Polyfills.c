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

#ifdef _POSIX
	#ifdef __APPLE__
		#include <util.h>
	#else
		#include <termios.h>
	#endif
#endif


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
extern duk_ret_t ModSearchTable_Get(duk_context *ctx, duk_idx_t table, char *key, char *id);


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
			char *end = (char*)memchr(buffer, 0, bufferLen);
			duk_push_lstring(ctx, buffer, end == NULL ? bufferLen : (duk_size_t)(end - buffer));
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

	duk_push_int(ctx, ntohl((int)ILibUnaligned_Read32(buffer + offset)));
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
duk_ret_t ILibDuktape_Polyfills_String_splitEx(duk_context *ctx)
{
	duk_ret_t ret = 1;

	if (duk_is_null_or_undefined(ctx, 0))
	{
		duk_push_array(ctx);		// [array]
		duk_push_this(ctx);			// [array][string]
		duk_array_push(ctx, -2);	// [array]
	}
	else if (duk_is_string(ctx, 0))
	{
		const char *delim, *str;
		duk_size_t delimLen, strLen;

		duk_push_this(ctx);
		delim = duk_to_lstring(ctx, 0, &delimLen);
		str = duk_to_lstring(ctx, -1, &strLen);

		parser_result *pr = ILibParseStringAdv(str, 0, strLen, delim, delimLen);
		parser_result_field *f = pr->FirstResult;

		duk_push_array(ctx);
		while (f != NULL)
		{
			duk_push_lstring(ctx, f->data, f->datalength);
			duk_array_push(ctx, -2);
			f = f->NextResult;
		}

		ILibDestructParserResults(pr);
	}
	else
	{
		ret = ILibDuktape_Error(ctx, "Invalid Arguments");
	}
	return(ret);
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
	duk_put_prop_string(ctx, -2, "padStart");										// [string][proto]
	duk_push_c_function(ctx, ILibDuktape_Polyfills_String_splitEx, DUK_VARARGS);	// [string][proto][func]
	duk_put_prop_string(ctx, -2, "splitEx");										// [string][proto]
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
duk_ret_t ILibDuktape_Polyfills_Console_getInfoLevel(duk_context *ctx)
{
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, ILibDuktape_Console_INFO_Level);
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_setInfoMask(duk_context *ctx)
{
	ILIBLOGMESSAGEX2_SetMask(duk_require_uint(ctx, 0));
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_LINE_INPUT) == ENABLE_LINE_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ICANON) == ICANON);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_canonical_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFD;
	}
	else
	{
		mode |= ENABLE_LINE_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ICANON;
	}
	else
	{
		term.c_lflag |= ICANON;
	}
	tcsetattr(fileno(stdin), 0, &term);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(0);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_get(duk_context *ctx)
{
#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	duk_push_boolean(ctx, (mode & ENABLE_ECHO_INPUT) == ENABLE_ECHO_INPUT);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);
	duk_push_boolean(ctx, (term.c_lflag & ECHO) == ECHO);
#else
	duk_push_boolean(ctx, 1);
#endif
	return(1);
}
duk_ret_t ILibDuktape_Polyfills_Console_echo_set(duk_context *ctx)
{
	int val = duk_require_boolean(ctx, 0) ? 1 : 0;

#if defined(WIN32)
	DWORD mode = 0;
	GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
	if (val == 0)
	{
		mode = mode & 0xFFFFFFFB;
	}
	else
	{
		mode |= ENABLE_ECHO_INPUT;
	}
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
#elif defined(_POSIX)
	struct termios term;
	tcgetattr(fileno(stdin), &term);

	if (val == 0)
	{
		term.c_lflag &= ~ECHO;
	}
	else
	{
		term.c_lflag |= ECHO;
	}
	tcsetattr(fileno(stdin), 0, &term);
#endif
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
	ILibDuktape_CreateInstanceMethod(ctx, "getInfoLevel", ILibDuktape_Polyfills_Console_getInfoLevel, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "setInfoMask", ILibDuktape_Polyfills_Console_setInfoMask, 1);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "echo", ILibDuktape_Polyfills_Console_echo_get, ILibDuktape_Polyfills_Console_echo_set);
	ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "canonical", ILibDuktape_Polyfills_Console_canonical_get, ILibDuktape_Polyfills_Console_canonical_set);

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
	duk_push_int(ctx, ntohl(ILibUnaligned_Read32(buffer + offset)));
	return 1;
}
duk_ret_t ILibDuktape_ntohs(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);

	if ((int)bufferLen < 2 + offset) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	duk_push_int(ctx, ntohs(ILibUnaligned_Read16(buffer + offset)));
	return 1;
}
duk_ret_t ILibDuktape_htonl(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (4 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	ILibUnaligned_Write32(buffer + offset, htonl(val));
	return 0;
}
duk_ret_t ILibDuktape_htons(duk_context *ctx)
{
	duk_size_t bufferLen;
	char *buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
	int offset = duk_require_int(ctx, 1);
	unsigned int val = (unsigned int)duk_require_int(ctx, 2);

	if ((int)bufferLen < (2 + offset)) { return(ILibDuktape_Error(ctx, "buffer too small")); }
	ILibUnaligned_Write16(buffer + offset, htons((unsigned short)val));
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
	char *funcName;

	if (!ILibMemory_CanaryOK(ptrs)) { return; }
	
	duk_context *ctx = ptrs->ctx;
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
		// setTimeout/setImmediate: release reference now it has fired.
		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
		duk_pop(ctx);

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

	// save all timer references so they can't be GC'd while running
	duk_push_heap_stash(ctx);															//[retVal][stash]
	duk_dup(ctx, -2);																	//[retVal][stash][timer]
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(duk_get_heapptr(ctx, -1)));		//[retVal][stash]
	duk_pop(ctx);																		//[retVal]

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

	// release timer reference so it can be GC'd
	duk_push_heap_stash(ctx);
	duk_del_prop_string(ctx, -1, Duktape_GetStashKey(ptrs->object));
	duk_pop(ctx);

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
	int len = data->bufferLen - (data->start + data->end);
	memcpy_s(duk_push_fixed_buffer(ctx, len), len, data->buffer + data->start, len);	// [DynamicBuffer][buffer][fixedBuffer]
	duk_push_buffer_object(ctx, -1, 0, len, DUK_BUFOBJ_NODEJS_BUFFER);
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
	// {{ BEGIN AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('eJztfV1z3DiS4Lt+BazYbVa1q0qyp7cvQprqOVlSz2jbIykke9wdtldBkagqtFgEByAlVXi8sY977/cL95dcZOKDAAmyqmT37Fzc6cWWCCSARCK/E9j7dueYFyvB5ouSvNx/uU/O8pJm5JiLgou4ZDzf+Z9xVS64IK/EKs7JFac7O69ZQnNJU1LlKRWkXFByVMTJghL9ZUT+QoVkPCcvJ/tkAA129afd4eHOildkGa9IzktSSUrKBZNkxjJK6GNCi5KwnCR8WWQszhNKHli5wEE0iMnOLxoAvy1jlpOYJLxYET5zW5G43NkhhJBFWRYHe3sPDw+TGGc54WK+l6lWcu/12fHp+fXp+OVkf2fnbZ5RKYmgf62YoCm5XZG4KDKWxLcZJVn8QLgg8VxQmpKSwzwfBCtZPh8RyWflQyzoTspkKdhtVXoIMrNikrgNeE7inOweXZOz613y6uj67Hq08+7szZ8u3r4h746uro7O35ydXpOLK3J8cX5y9ubs4vyaXPxIjs5/IT+dnZ+MCGXlggpCHwsBc+eCMEAdTSc715R6g8+4mowsaMJmLCFZnM+reE7JnN9TkbN8TgoqlkzC5kkS5+lOxpasRFKQ7eVMdr7d29nZ2dvb2dsjb2AbmSQxWdCsoIJUJctYuSLlIi7hQyUVSgHAn6lckKM5zUuFSFnGWUZYKWk2A2AxwLmNk7u54FWeEknFPUvoCDGWZaTI4nLGxVIq6AAyRmiyKgouSjmBWe2UYrXzCcnATLCgghdUlCs11YJnqxnLMsRNnJMjIeLVCOY0o2WycNFFU0IzuoRB2IywktBHJks5IoIu+T3gDhtXAmcMv/+14iWV0Lpc0BWJBW6HoDihi9tfaVJOUjpjOb3Ukxrg+JNC8JKXq4KOSDSn5WUs4iUtqTh9jEbYGX4+2f/Bz32cVfSAzKo8gc0igzxe0hFJ6SyusvIv8HXodfC7KxCCMFhOedj6BugZMDIl+4eEkd/jmZ1kNJ+Xi0Py/Dkbtnq04cMPmwE/YPI9+ziRZSxK+Y6VC5wseU6iaTRsQ+qGBj+ClmRKLMzqFk5XPkeQeobkOXkxbK/JnZOgpTufaDcaDsknDRw/WsAvEEUG9BhAk89906tEjgN0TKHdt/0XA8XbTh9c3enz8HDHp/mvTPLkyQT8W5KvwRGSpn9qBtF4HJHnJAC0F4ufd5K4TBaDx+HOJ/I5xE22xizLU/poZFULzSMPz09G8xkMsh2uN2IOf3e+4Ozb09kDUgX7Cqdv3OQivxG1oEChX51CUprRkj7xLG5EH5oRT1q0qEC0d4DNBuyH6f6mVILAJShkdMBGQab++e+xQd6JRnSRX36BQx3nlmH+/DPoh9AA9JS4JOPxzz9Pf/nlKx1x5F6bbyHbZP+6RKn5C/Kui9kAzuHzEPJ/E0naLUF7dxe0yJ8oLUhJk0XOkjgjs5hllaAkpWXMMgn7ozVPKogsUyrECK2ShOc5RcyNS7ak5O3ZZMficp7zJT3myyLOGc+vqKyyciDwn6GmJ4UH+AugoqRkOp2SiArBRaQ2ot6AQvCESjmRZcqrcgIGBR1EhJDxD+SP5xd/PkV2UFKYVCl4RiQtqwIolOVoJdGSTj7kkYMbByQVwoBUwBIz8QMCnPVfry/OJ2o72GxllgG8tgap0EwzMF+CCwPbTY4FjdNVa3lOj6QSgublNdXmxTffkPAXF7b+NJb62zhOSnZPo2EH5W+NTjjqCBLNTjUaMaM1EFsTHGLj0wajWXyjhSvRCEBMHZKUyruSF2p4NLEIGihoPKiRnRF91AugAUSQRvtGk/FHSng+Y/MKDF3gcLOqhMMh2TwfM7P08AQa+9UYvEVz9bA9RNcGaogwPAewwksq1o2tm/UNbCE1Bvy8o7gIigZ7/AsqlOEp+ZKSZEGTOwlWKXD6wnBnIktRJYBPlBfL+A4tQyXTlyxny2oJBxlkBngbhCPhFY2ANU/zsmY7OJJl/3JQxGIpDcMB7r2UCzIlN3++/tNAkyxgC5t5AnkQpVQmghUANhqRvMqyIZlO8T9wKJdyMXGakGdT3eYTUdCKSqJq5jSa7gJ+mz2fE2D/Bp+d02GyyOLVebykndOpm/RMp27kTMfpudl01IntnY7TpHs6TqN6Om7Pejp2PtAE+IQHucFRDUUmPL+nopRIU+Ox7VYTobYyrIxTugu2LmMxp+X0559/NuqJ6/TS3pbxMs7jORWTX6Ud3eh5bcwpRS8y83D5ZkvNa/BshBXW6+qz72NXL8Ai1i5fY1Wf4N6dXlK5uFZLDe12W5Th/jR6+dvUXpzZrjhNZUOl12jWZmnJyS2KJVkt125DGyGNadWYac7XRVBbqHWv4roEXTjnpAnQLmgymZDXtIwkiTPJFcey1GeXKyeTSUNZFaRcFkBUmpEb7x7sRPTA8t+9jMgfSFQ7DSNyQHD70OkX+Woh6PXu721lV42mKX4Q3SCUc57SszQaTmS9tkGnxgk/Wt987NOtNQl61ECNCwKksLcqkMPvWJ7yBzkC96u7SPxI76lYlQvwLsJuNVHJZgNY27MpGTwVl8N1lsIGZAdzaJKZj76AhGXqeNC8FCtScJaXuGJNP9a/qsaq5aL+rucwQO5n5WJYJZpMJmc1VA3RzBUOIM/ohOUz/mIQRcaZhlSKTIeoA3/Y+POj4opxmC2qNpEjmU2vH6ZkP8Dj1UHSroA4XxG6vKVpCueoiBOK1ouBCu5y9IMncQ7HU5KqUPrJxTWtmYadfmCaaE+aObm2hGqqmbP+7rNoC1b9B9uWg4hEw8mvnOUKhzWFmpUbu28K6yefGsi1FGKxXAj+uPoRwkQ1o6CPNLmMy4Wj73STfcDycgGq/5vZA2i7gAl+dpfh8pgWpzxKUxXUsqIY4kNOkAJpVsW2sgy4vt1bG+zSXIC8lRhyiUuHkbrnoHEyY+do2g6vVgBFHU3L9B5YPhZ0DsGoVTScVJIKkENvOLT9iYJ2rFvCJ2t/RUMkG4Xli4ecCuSTFu0sHU7Q2dMjZxTfpI9JSGaafSeuQPJOxkVOXrO8ehxpXaaxTs+LU/CiyuLSxezbsxOjGVU1cmUXozEDAwlWrtRooqUsV664wPYsRdfoBmSjmvbh/C1LB1UfPruxuQFxAG1ULPW9CPp4PJ8ScwSsXmX8Zu9oJCB+iGjjJBEUTHdA4MWlilZy9G7BxwVItJIH9JpJE47ZNwz2oWmlNpVRSR4o8LkRqSTL52Ye6PHSXPCBggEVS4g3slzrvI4WjB2tDNY9TXCU5wZMLGgelY56Y1kRL1RAdNqxmXAADkJcNqRzPllQj7wxFfs80P9Op8BF/7CJFhCEfaDA+EPofQOGe9BiwY2m4KJ4syroAYmO3r65uLl+c3T1Jhq1+RVaswZZ/vcbu2cHpBRVfRY/KzLU2+DZeEHh1rQxTUfllTY9Gv5xv9OwMaRj5XYN6VnZ7pDAGgPB7ahvKg4wo5GsE3fkkx3VNTunJIpcG3ie8ds4m8wvNFF3mJ1spj3STOK/zX5ogclhlxnE3VZkSoK9Q8yNzVoj3bI8Fqt1hpcZ0aHawLgKVnPgz5a/nc1ITBTzUzkqDzHwiipPR+SBRpC0kCdZlVLw6WuHf8YkenbUWo1dV4DJ97CgeVPS4JFz/MZaBMyA76sowfUqTwaWHw9DPtYGfmunRBPx7z+6DjXvqxIOn4jklUjoQS0BRiSnD+fI1EwHra09t5IBffA1Bg3+2IygL6RYjZdyEYGgtQwVMKhUIFD5QXpAHg+gZALOLOOfVA5LRD4i3qDZOGsfuLhDhs4ETUquRawTsAT8DFh9Tm0co57YdPcFBipCyrh2rjVUzzBHHTTZYlifBFQMh+Sg3R4xip8Pv8b+wtxz+mB16zDDyECdipRDXlNfQ0ZHw4mR1nNaagEG/H2A7pJIrmRJl2k0JH9okIhGwG60a1Y/jmDlfqvDzShSb4NDj/XiDOIsIbrQalET8DN9dqhk2qaRm4wnsTEwNaFYb5anmdo8phwSlBzlcaNpuA01pLP8EuCAbSUqetjgTQ2dSZ2rFXkA5WXGM5OspROjFrzKUmBFtSEBylFTDtzo41QAMT6r/Z4dn6Oo7+Ney+hqJgwEMBNMH/B5u3si6p7t5AG9VDhYrdyBtmcjtArX1nd/bgWN7/q9G8STXiG8rhNdDlIaejuuCA26EPiw6fXZZ4aBQQJ+C2e8Lv7YoFktaNeAV/4Gtgnpz+JM0q2PtCPAXe0HxLcngLwjhM4WFOTaarBxnKfgzo0krMGdr6A9GXeb4KRH53OOslWQco7jSow2AhdyhU49npU8Bu9oojdNPbKsILQrfXUYMkBLSahM4gL8W0qWkCpnpYGG2XwE/Q1ywQqyrKRJHqZEApCMzzHIz1Kal5B2GktIis1YwkoApaiqtuFsYNZ1ZU+9iSm0GZs94J2Lk7KKs2xlGX/IcbCBSG34MPUcwhF9N7T7/uTi/PSjH6Nms/U+sDbHUW4V63puHAuaYwI0+rRM0EKptaLK1beZ4EtyHc/on3lKgf2e01KzJG8gz/90m4C/XUE3fRtImDQyh1xWpvwektENcyren15dXVx9xFAw9Grjlz6ycuBpBUAq8j5xfTObqEbN6Rs6XsbJxTV5HVd5ogzvgzrwBqJRJoLSnCRxgcH454TlRVVCfPlNvOB0YuBAEEGdk7FkKdUQT2K65DoF0mzUkGTsXrmLS9uJxFVaHy7tZyKDWLL0v/7Xf77Y39/ffzEcgbUiwHRZTiANnk4EBXs4xWTuXNA4WcDOgfPGgMLAjzkNMQTLx+hkc1asnCuiymV9eLVFBz46A2l8d79Umst//cf/Jhn2T0nG41RaDj2v2N7vK5b+QPIYUjiyFTpaGWg7sdCeb5hVrhZsV4rOQLMa8EpdI96PFdp/YsqokNiOVxZRqE0BoBsN6AY0WmwbK1MeWqS4C2NZxA85QXmcU5pKb+9Um0iSu/vljaBZvLrBvJ7B0CQfSRWshcghYgEy9ElM3ubs0e4bT+5oqWxK8OQcQ+wEWGDOSoZsNiYnOslET3jS7zlIY/HA8pbSJu+TCWB+sJ4lYbaJpCVURUAUQm2cWsNkMtnMh745y3ToatDS0cJJhLlnx2LsNdjO83YBBuKieM0TtEYHw44+m7i96gFwS6C5PCDvo9d8znLFgqMRiY7+WsXRx3BX13P2PrJHJfrYav25EYLbQJI0BcPZcklToKdsRW45L2Up4kKVgTin2qpMOptKx9GawIAbRJKkfAmlO15UJOFLipErferw2AAZxSDceVXuNYGBzM9JskqACb2ishzT2YyL8oDIO1YQyTKalyCeZxC31jPCKfhh0/URY6UxYP+3/Z76ulUzeEz0yXPgfPONC/XZ1GqI/bPp2Ug8f3aXCkCfewRrvglC0BkbrGf/eDaXX4BbSyv30d5rditisdpzSEAizKajc6yGVwwAYUThMSxGkwXL0hu9PvSB0QSs/kG0d8vyPQUvKbOOYwU/7yOLAjhK7fWO6uV87FjzFjqX+elKPiZGWSGD27WZ1F3jXv90domysD6DPCc5fSzVOQjMKWSR6nlYrak9ia21p6bP9Ec3i6GhSsYpCFxydv7q4u35CXl7cklElanatHf09urNMTmJy1iLqW3CuUCjGQdNrcWsN5Na71QtH5kxQR9Af4GJqcBQiLCJVvX0sfHmgUuakjU7fVLHFw7a4DU23oh4NmNJgNiVv1NlVbL8FvSPQKtLweciXh4AboJfS57w7IBEb08uw93BE3dAosvqNmPJiFwKSOakI3KCPDzQ56QOVhzoAJZRTZSs0Eu7fHnZs7zTdE7fiPieChlnlzxjyeqARHGWgXhst0YjIm0EikgdLCJN48NsczScxGn6o/7tqsroALZve+vLsX3ROtRObdQJXMvQBCnJr2DEWm9cbW6oZtfQj6a+A6SPfrGDk9Hi8PO2DQtnBGfmno7WyK3j98xxF//tbwQKE/gMgTF5VeVYQoptTH4ONvO+Dxqe7Wf+qJgKshD8AVy75BRy5gfRWTOJjKQsxVR9XIOfJNy1XRc/fWwmtevI+ZYGZGvLO/Rpz7PeWGVjQKCVZgmHIPM4i11dA6GN4a9j675o8nzTTxUmQMQrzmKjLg8+afU35P0YobES0HXJ55EJndxg9cOloPeMV1J3bswAHUx2BjqZH4ki5+W4LqiGCGWf9HNzuQER/aUL9YiN8oW1U2vVMKAbrG7lZM1jUxC544d4lcV5Otbp8lFbbVt3XN8pCOSOrm55LFJd2KFHA+NNcQ2U8HqYyW+6LJrKej0daqchr+MFZ+idRfLisxkV12yeX1SluxNrNavmHq8pFahH7tlkFyOqsUuDuEBelWM4VVSWNLWIaTcGggW80LRjg9dt8rUqEohFnKCX1Nx7AC4DUuUlywhchwCTImDyAEHgL5AeQDo3vLPKzah387inMMI7TJrsoDYKxCcg/VqVZwGMQA1GmFXdPbDcspwGw4JvLsOy3Kht6vyd2FM926/Cnn56p6+s6GZP9Yhr2FN4al6J1Zpan598hlLXFB0SqW+EqMveMt4uNeqgqTvaTVM+Brpp6o4Gymy+ngztsGiQaQFldFEofvzHIdFgiaGzgJDArb/2l+aFMWSwlCALlF0Y0n6OaNjg+M7gzTKujprxejAVC9b//72ZgRMFVn/Z1C+CGrRCgIH1Xv37ceKWLnbLDQd9AWGx7vRd6y7EdpmQa3UcWM7kAgT7DKpzLN/3WH3HVRK2+tKZXEqTjOUbTOnKr3h8mgzabGItqfmEukTLrcTaeSurSvn0BVWx/87ptv+C3jiP3taVExqC0KQVZPUaYlB4ulSq6w6Ptzpyf1SdruhMULl46skTqrs6euaX3zdm5BxB3WSbM6i7XOuj6IN+r79ueiR9YEBjGt5Yf9nigKKbfawDbWbt9WHdiNi9+WxL840JbELjytFtuzyJ0IObu2H5bB+5+3A7qb7HFzlHxSIo9D4pXn5gqudH8PucosdLqzAmJSYa6cL+A6vA0iHEP1r+yTrSDV4YnRhlcgWyFUkybjILtLfBpC9gqO2BYoVuynM6Qk2Kxqkq5M1W4P/QxcB/jMUt3K11zLNM+elsFYgBq1PjmYQ88wrCflTKWLBsBd66O+0T2iDPFxQOnPUAlmvSL3Xdo6RneTkI5ijf3ECg5PSRldGI7A+HZBrIUQkHx03lFtyLJsEPQwuIMdtMCxW4aZVr2e9a8/ldo2LLxsgXeAWYE14YWb9Zru9fs7D60dQR1Ow7om/dVTwphIne6DrysXH+gBvQ3LCAwCve83moG3up8mYIl7guUUw3rvKM5XeYbtwK22wfSOw88E8MPYSg+iW+kKfk5DI9s8mcmKItB9GNLHkRtTKoobyVYUFWfbabpFxolb1O96HOvXSqKAX5OMsrfWuhbqduUrS8OFiw2Lxqoz3Bd2pqdbonhPUhQQNvlNET5zlOr1QqlHdIgslJfWf7Go70SzjUhl9ZWGpFnYf6pV7VCBJ23TsKJE14nsZiZQ6F49p2Erbhv2lcxj+qJNZmvWVcFJeCzthj64udiElsazZwanu76ja+YoXOIewb5Ca7TF9Ve6saJF3ZdM+g9k8XJEkVrnYKj6zguqovhsIMecyJZzN7WQQx7pnuYw0bcljb9Eu5QOHbyA1tJkErOfEKs3ROsDalK6FRESom9WMMHitZUCrOTHZAFWc64Wek7kZkJh8QszMNPibEBYolwgh2ERcFFFEgzesYS4DEMdgIYlTZFSqVSZ8SoSMVvisEUtjqvAC/8LWRph2gs0+4XoUchSgVizLxp89NPvXNN6TFnsbjG1X6AzFQnWreRnCNi1mcwB2boIUmGY3zqjB41rfNSMkT5tc/1uUm8OMds8B5gMvzTG7xCRPmjoQaFe5h7Opv2/jdNe/eWBAbDuzx1d4oVztTUxNMP1fcQFQ3Wd5Aum6gJn08LZUTSolzUhVzEadwaxDcdisxVTajsaSOfYCpbIm+qVGqoBhVmW1xotILa8rexNPWJTidb2FHVodgV1ypjk0BH0vXh7ZqNA/63WdOCARB97t1N3OMY+19nPVEm3Ao1+IJ53xs4YzXY27hjvexq7zHHdht+eG3wq4Duold/hBwQ3V7h/sQ64yyHrFbeKR7EBvwSfuI7bjxbY0HeUPktsb8OkaxHX2dWUw8BX2jKxTax7ud9IPasHORpbrW4zfPJU+ZDCWTO8zZsyAagsLmbBhhipcE5C1130OXI0G/+aYWh0+5oO7EKEtKPQbIgaS84B49C+xRe3BiHSDnPB8bJ4i9TLuVrWXwUGurckG1ve3+oLVL72n2Fi7WqTFiqh/3QtEu3WFS8CKUKlnDMw1V+eBeK0eVtK9tIYQcw9xR8yyoriGd/hCaR7sr/DElWF7l7G7oRpvO/mKp+tfqEWRYfrsVgJOjs8vjbWYcRHMH9JSJL12hBWG2yvTvCC2xzBNKa/I85SIakfeRXEShDE3sbA4RzwcRLCMaOVeeJsA//Zknk5JrJoh8tw8uiJLfAi7LzZnvILFwaDjQ31BIIGs73GM3k+RvJH64I9HuZkN82nAqKlnzn/bJv5O9f2uR/YcPk73h5pC2GBRy1hZTWQiWl7PBrliSDx92/1l++LC7OyL/tD883A4U1sYMwELevN/nzZrufo4+5Lub7RNQxt4WZNB1lJ8Cwj3KG/cH75FSn9RPR5+HmJWnytHUauXrQN5NdKRHjHWlGaviG9SslxjPBLHlSLStJdiHD19RhIWBbcckrecuv38Pkj9lIvqoTpui49+9/PAhWaZ48QAw0r1jcMaECOXDh5CkwusAOmmr8dWTAF/Ar7+AJXd3deiuQXNf5tF2ckitT/vJOaR7e+QYL0zEMkDjJ3W8NW3vRp8qibAwm70NrqFTol906wJH15P6nEQnLJ7nXJYsaYLWOfldGfnSBq7WYu5HKBlo7EQnDgL+o340tHzT9ZUL5Eur1fq8Rd3YexJRtkmyPeOnhFmeQurnwQR5Nhv4uA64OPHancZ+uVfvOJbl8dXFOfmV36rbIstNKcO+2tMcBa3PMpZ3RCYLmlYZFYED410gCq3HtjWYoejE7d7lvYIKxlOWXOv09XrWkxvtHzbuVPdbuaD5oOZ72+5vR+lSOyaLDy3ceKEp3ECX6X4N4tpu9HVBss7Ysh/X+pEJJ2Ddim11h7XaoepXdMZVWMG2HbkRaudFHT0MUlfHxb5PrTX/rcNYTv36JUSahD55PEud6xYSwaXEqOSeOp17glqcKEcyOvGhgjBZxPmcyt5qZOuPbrKH8HMZJuIYBd1s0Sj8Qsan7e7q867f60n29IaCEwBOKRUPGtX3Wjl/o3m1pPovGBPtoHoVXsNIc5wl6orEB/MCWh0TtGEvJkfkNpbqqTmM/tQzta8QOU6t+iL5jiK6Le9YVbDgGur62Y99DAvXz358N7R3N6054BZaq4NBTqPyihfe4dMxwwXL7+CSgCU+fHhr44F2gX49k7n8vV3ItE1KyXXJVTmuXzZougZqHafTNV5XVcMFpke3YGj36uPR128uLi9PmzqWO15LWetivi89Nq4yARrqd1iabDfjLqnyFebbnO4QrruhOVx+u2SS9gjqja5U3yxfqRsjNlNKPyABDyyq0Cbk+XReEmwQE04H2toMr2mwD9D29NafUhJWTwMcY+vcuU5lIjQBo1Ec1aFpy2qcELWruEpOMgg0pFxd0E0fSxEb/AAPskdCQzrFGyAHUL1LNrncXJtJKsIFttdzEjn43a6muuVksZqNGyFpFEw3kw54ZW9xR5G5pf3arsbuygMg7/f/+WOvot6o+53T0q37lUcSUmQwoljXTJOcq7ibkdX4fguEL9Wv8EIUr8oD8uJf9vf3PTdEge4KhAbeG99lsZX6/EF8CVrw7gMkhCigT9czBVjeLEVPwE8nI9mJQISP6al0bjnpqcJWWqNfiD1xauQ7pz5jOeR2PNkw+jLkbmhUDb7cngmbM6eNBxPGsyrLAtYM/Nm6Qwa/Sp6rkIWbn4dvO5CpCspj6rDb0NEAnaziltp8T8Utl7Qno9hETyQtT6gsWa5UTPNn529ycnJ2ffTq9emJSqY7+5Fo8PopZaz6N++iDusbZXM+5oUdKOPzflQ7MzrLZ/w1uDMHL0JjBm6vlQv+QCASpNyg5AW+wRDP9QVUalD32QydTHPYyjv1MjcXcVbqWiEvFdWR7DgHc+8n6C8jIl14go7r0G2d85Tw1HlX2yYNTJQaHX5pCid7qR6/Cr99pe9bdy4nqh9vyG3C5W+eb3m9Jt+yJ83SWBG1IzYOH/yQ6bSpf3YymXjO2c4Bdt2nT3e/3GPbuElvA99sM9k244mOh6zZIogoHOD1r83QyAYKmTui/b9vP9Z/dqzIQ9eh7x23On8R3znA9b6zf1OXRg/c3Hmvtx1s6oVJ3Fhew4nd7y3d2yPnvGPbfU1Rp9HgPSEQY1unOTUdrm7T9tWGYQUT5UuPZLEuHXWiQFIQtTG+qDlrCZoRMZeKbityHHinj4ofOcC2nq4quwlONwDeedOzdUc+ZGg1rlKd2p7ubag9jLN+D8xhnD18uGaq6vT6Ce5OBv0/CM/t5red/OCZxw/0OvAK2NbbQjfOC3p4sBpifzCEIRz57U1hRHi5oOKBSYrPMeJ7vtgWXJpKmpdWrP/3qj9PVGAaDrL/J0Rbh1iz38MXfXeIhcMWjp2nwTo+Ge8z0eCIukWy477u7mjoVxYkG1QnbSFZ2saJZ96od5tbxQ/N9w6mqFa0PKmuAA4UnxzqIKFfwcGkLe1QUbwFbddqoUE6alSnQEtVk7KRgNShkE3wbhwmXQ4fcmtjSD3bAy8uLTmEFyf0seDw7Oe0gTJPih34v45Crbw2fgtrJx74vyrkHO6gvH1N53GysqW0f6JZAVU0Wqrig5b6sVyM5WazcVWkcekUg8qVvFF/GzBpTZrb778bNh5mVxtrJGak+qSRjuMrHmflntnnjtovG/6Ykt3d+mvx6DyrY2cTumQQaIBMYZq21vAPrvryqoJC/QlQ4OD2++9GJIIIzPffwRthdZogOWi8LGBeKV33OECD1Tg4BPZiZw6cdRTKsIcxMOLSSsnD8q9CF/Isg4+7xnf0LQ7m13+FZxqY7ZWJuu/WoHZrxSfkxce56DKsovH0IPE8zV4+t8slNYsiBHLC3TZuIyUZVYhoEd/Dg81wMyGDnICCiiXDaxW87XrWeQssk1ecl4PO55BUHC/lUPiNg9GcV/OFM5BEBgLv0/j8SbkcMnYH1/FCNYN6KFRx+EhfiNd8F9Q5R2hMlEpswNIyzgtUzm9pEsON+nimEi7oJDG18aAzJeA4qPQ94uAHSWgeC8aDtAmKV/QtsLAQDtVTPy6vqzRNhXNfbmggecsVLz4ZOGfdUYGdszpokffXDZe77/psr0/bdXRnHAHtAftxngFSVyYOogyZcruSpWaKT0rzQgUrBNDhpubayQ5nQos+CB5/58JKpSC5I/YkN816jpY6yvjSoAn6gvqjXrvHO26axoojheFMeQDxxb8sDTw7ah93UvTrv/GEvxy2IG2e4cmzdETec8h9rHNQlT9lRKIxTLuVaumlWcpS6NfeNsy+xAgo9Ho+JW5OezulvT+xspHbq67Z8Sc2KQVb6sejsOKwQc+hhTiHpknefUPgK0Xr5FQPAIt+qOrS/qYfyIsnzJIE7hoPT4d8wZHtWEb4AsMnHWNLBRsc567ZtCG2cWWO+qw99zDK/Al92+Qn6trm06u/nB2fkvOLNwRDpeTbrlskQ+C6qGxL0L2yrY2NrePyXxETvVNtP+ltlehnxtSFqIa4j1tPSja/I/GVZ/q3Qa3Zjsj38CTJiDSshMPmkLX2C/ljmEjVNpo9pU+/CQCKIRm8Pv3j0fEvw1DbJxZGto/Xl8iQjfJKNhnS9aW3vlqX+v8I10pihlRjkGftUXpKwdfQrn95BajAIA/NI5j+q7PN5famoWh+0rxMcM3p+ZAf5QQrbQlPkkrgM56QZVcZhqfM0L6zs+7o+DSJT4WqbGSl9EOg+Vw7EtR94uY1B/uqxdI1bZrzx8aKwLAmGpwoAPNSXSQg6NiBOlkfPthx/SMmB60rDF+j126shurIMZ0AWVL9tDiV7aw26NVFVfZqO0zq9VuG99ic6PfFx0mhPVFNYtpQ7Bgk3TGo9jYwvde025ve2Hjyf+PROK7NQ3i6FXJPJxPyRqzUqYAnXlhOvt/XSfYymKWnqagzU69p6QUQ500qTO191+M3p9K6GJ/0iUGbx2EjUUc5hhWsa0x7yoyHjAtyDe6wt1q44b1mkESgXsRSMxcQiJDeNUt4OrVIFH9RXwfqV8Vw66iawNde9+uMjbqZq2W7f20xcKO9WqtFO8ja0YDNbZp6wBF5X//ytKgyWEEaGxpX1h5yr/d/bLMhICgy2Pcb/8amU9tk0pvTbxsFJl/vbGc4SLWycarmCI2APJPn8flA0HI4xLuj1AhebqXBGTRCMgc6b7h+dVqgaOWE1ST8wPIbbGOaDCBvpFyIqj+rEYr5RTs1q5n098UJf20m+rTsv/WZf+tiaR9E35rbGX3+yF2ZfAFZ/LQsvHq49WL/KQsMvmxJLLW4TKyhohiydRJedadn09DD9oayi0ZeXTOuwYWp0kApYjBErjqTXnVAySd+cE1Z4l9D9OF8xH9gosfI11lJMaNj/ysehR5MfPlRQN5dT/35869I4j0TD5B4GMyVzkKtcn1xUWPC9YMC/Wq71U8CpG2ebIz9map7e3wSlrRsEbChwTZ/xyeDN0dk/XrWGj3Uezwrcp+//NoPZ7WOR6jp/39F62mvaB2lafB4rDkgTboOEvZIJaGoGLQqvcpmSumGULLn+0GUNli1fi1QBVc7QtI2zyDimQlIj1SAq1gFo9W1Tg0t8NlspR/yYqUyHnZDd3iusfW2dyuBpDTXwDhja0Pw0b3lRrkRPuT4Glft9qg93WBJteVwADqbDTqNhBuY+z2dTm0MoDF8PR6mWWi8+n4Mb0/M7R/wTMLGU1w3vxby16N6RN4/pVMkKrRodh1BH4u5dIgGflXz7hzAg+yONmyCiMa3338H/aPWJzenAXGlLzIRcDydvAab6mDx6oX/DQox/2v7GWO2WDCpAWaqkhrs1T1P38fO8UeIkdr+adv1hgE59v2EXGMUHYLzguIlpLf4CC3cz7lacrjA+bbS93biBbdwUy0A0+CvqwIyfhr5P3pi4DO3fvLDcBvjK4B86oAL4XBnZ613W/G+BnSPQRrh7/7tUGc6fCFXDg3t6hghvaNj6G4TNTCIo+joIZy/mLuOwoNAMukmQ3jmgFmH+7eedahMTk9w7nze+T+wiP+K', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gala-companion', Buffer.from('eJzdVUuP2zYQvvtX0CeSWUvyLpq0taoutg80AVKkgC8F1ouAkUYSC3qokJTX7tr/vaBelrwbtLnWF5Pz/GbmGyp6RdZ//PJn8F6mgBaCdxmgk7kEsyJ3lUhLCG7CJXkVzaKIfHhEyEil6kIikWidUEo4qZFoVIeQ3JHagiFpqWUKRFoiiIVKGOGgN/dqoVTsw1kwO29YV5lwYInAjBjYagck1YiQ+tCWIOzAkEzaSokDEUTpQteOfK7BeoNwltfYmBLZgHcH1kXm5GlGCCEyJ2zeZzseiTtUoPM+f4hiC2SeJIRaZyQW1NvMx9pQARau9PKXxD+Sm9dvyPHYJPO/6H6zXy43ZoMPUejAOjZ24y9gqIQrn2EYK8O0FObOsSVvzSI6TjixHFB9s/zew+rgBJv9db7Zf5snl6C8F+fElUY/kl+N0YbRd7gTSmbkN6HEMKm+wZTHTeqdMKQSxtlkAsBWSjpGI8oXBLXZCiX/hiy5f2i9cm2Y95TJMpY/NP4d5vjqSvZDawfH5o3+Xj4cj/0pSRIaUp5qdBJriMfmE5uQ8icf4oyhy8P/vVRfCOXxyLXSFePxacgGygIZ62tbDvm7Bp1mfRlfgwH2kNZOfFLQN9qAqw0SA59raYDR9du7m9dv1s6A2FIepgaEA8ZDe8D0rbAl+6nOczBhbvSW0d/BlncFoJuWeL1BejXhczc4Qnn4l5bI6EfKr+gGI3o1wt+q/HRp7fLvKOeh0+uGtoyWsKf+/l4/gvlZWGA8np1GO9q+Az33FqQysJO6tudlZZXRKVgbVkq4XJvtPEmokljv6fE4H3qQW8pD2Evr7PqAKaNRbU30SWJUCCUo513TnqwTDlYUtQtEVSmZNp09nSlsnTaQDIE/ev8g1dtKoNQYNGrKYz/G5hxm4CB17CtS6EcEkzx7oBYGbK1c0obte9MYd5OXOWttQp+jtvMkub5MC55DdGGdKGBFuyh0AcagXnXezWWRlgILyHphdz3F585PhzHAV9kZ/GA02TytsnmStNCfvI8BBcJC1hXXXb1d08pe/Z/rckagzcGcC+sCNNdTt5mn8b70gXKpwAYGRHagX+jBQqRO7pqv2aoF3AiA8Vvanmgnd8IU4LwcATIbWFlgIJGuKMLeBY/ioARmg/g0oX+NFwvw/6a9uRj+swXg8TSW6eiQJMn1LTP9dG6HEW71DjJ6HqkTEiGjfGBLR46eFePma/8mrmWBH2rXbdWo/fNWcjyO9g38DMbsGbRnuniTKRNe6o+3gKzvzeV7/oXehxPEzUO61VmtIIR9pf1396mj06r7XwwEWw2nxTjKanw5xbN/AHAcczA=', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-kwin-companion-assets', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-kwin-companion', Buffer.from('eJytV1tT3DYUfudXHF4iO+sLgYZkvN3O0DRp0qZpZkinnQGGEfYxVqKVXEneXc/Cf+9Isr02kGaSlgeQpXP5zk2fSB/D6fuf/orfshyFxvhNgcKwkqHK4KSmeYXxYXIAj9O9NIU3QhvKOSq4ko0oqGozWKFiZQu4vMKiwAJKtsECqNZoNFSoMAJToYACOV5Tg6ArqrCw5pSUJpZr4bQ46pQj1ajBSGDeU1K3QEUBGrVmUkBeSZZ7iW4rqdvE2jpFtWI5AnP4TQtM5LwprGyFgBvMG0OvOEJNTQVaghQIJ9coDOhONadCSGONNaLzD1RIU6HqZYgGhZy2CXyomIZCogYhDSzlCp0jb7FgCnMjVZvslY3IjYXeAws6U+Hedg8AgJUQ7PcQbm7AtDXKsneYCLpE2F8sgGijmLgmVmZ/fJpwFNemsvsPbf8Ah0+P7WF6dr45ODhX5+IiTQxqE4zFQ7i5cXjszx0MLmV3MYwPk7yi6sQEB6EXS8nOYXy+eVKeb56Vd71axTCELZhKyTUIXMNLpaQKyBuxopwV8OufTEAulzUVNoO2UxQJ53DrgK6ogpoqo2ExBaNrzkxAUhJGvtoLOLuYO51SKgisIoMFHMyBwffeRpetOcxmLITtkAlXHSdxxi5sUMN6YQNNiA0gl8Iw0WCPrFe8I+uFO4um6lz+awZcyC4IF7dbJbWsg3DsC7lG2HaHja4Gx4PU7d4omG9y7QwoNI0SoPDvhikMyOnrk8Onx6dGIV2SMMkVUoNBmOhW5K+proIfm7JElZRKLgPyG+rKz4crbN/zT84Fgdm0d7sSAgmTj5KJgFySEGZAzkVqZV0M/iAlYRgmRp66zgxIhRtiv9/KNaoXVGMQzvdud2OoGhHIGhW1XxE8MIy1kjlqndScmlKqpW9pzkSzcQXskrAFbajBDIiQJqZ1zVluLxgSQV5RcY1FBiW1lbkdd2xp23VIYKlJOB88D7h8w3R3EIFHj2C/1AlumDb6tBV5QNJGq/SKifTTmonLNW05FQUJ/zs+X/bF/evqszCHy/JhoCuqUs6u0iXqitrqxxZyvGYKU+dMJx+1FCT8Cu1vVvRuc1qbRmFsW8nHOwPy/xqrURRMXHdGP1sWR35fqEhHpaOucb3oIQy3Y+zF+nayiletQas3HkIvldS05ZIWEZArqvH4u3EXOrWePWzvdzre3M3NV4y/U/nCdI5d6IoePj3+Gk7oApmyggWI2sACfjn9/V3iSYuVbbCFoXczGN0Crm6Z/xNBV9HL3aMhmxBM1HvN4G46fQDZNB64HRUlrxgvxsV0G5fdpUPCxHp9xTiOZtywJcrGkAjOyG5N4riUCq+VfYr570+M85iWBtXiUNutowNNooEndhbr1lRSHDmtnEQ93gp5bTPQJfAigi2gWGWwhfcnH15nOwuZ/UUieHvy7ucMyIvkjw+v4ucEbifBysbUja0DIRHIFaqSyzUsfJdHgBtmD0XDuddxuUi0KWRjEikCUlBDSQTD7R3YjZ5FvfW+U2dgz3avnqPDZ8fPrejIr1GOpHvC7ODNFl51aFNHtX0cAyZU6mFMIWynwlbKxjaRymWBFk4XtP2c33Gypsy83DATjKbRidsRObCj18fy4IWCdlLGl4lNbAQFGsp4BsSNji8xlJRxd/NY+y9kgZkHdjudI93wYYxqqjT2STeKLYNwhHO/E969YP1G4tBNXo9fnu8OpLfwwPPDbk9YvWOgnqwiqBWumGx0T+yTcOwbYGDX3RtgF8wEuiM59/9JrJAWraO53r5dD1Q5OHXh3mPQ8bvS4jGKCl06tnWIdkQ6wj+fvCh7lXFWla2vpRGL5SGBHdH4tnGxjZz3y+lj8V6yl7JoOCa4qaV/dG/7tGf9Itr955SNWr9PwK5p78U71MBO3nzvH2yIzJ4=', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-greeter-source', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('service-manager', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-signout-source', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-startup', Buffer.from('eJzVV11v3LgVfTfg/3Dj1JEUjyQ7DbLZDFTA27hB0HyhzkOAKMhyqCuJa4rUktR4Bo7/e0FS0micceJtm6L1i0ckdXh57zmHV+lDOH/3/EP8ilEUGuOXBQrDSobqGZy2hNYYP0qO4WG6v5emcEZoDUxoQzjHAjSqJaMI8lJokAKhZCss4oIppEaqNWhDlOlaQGHUOoH3NULbLTijDs2NguqEBqLB1AgatWZSQKdRzaFVbEkMwmmFwgAKJTlv7M9hA4babrEeViYO9p1CGxgCrgg1cCHkpQBOOkFrVFBK1RCj4bJGAbQmomKiAlMz3cdDSoMKFHIk2iIuierfhgwO7BOVBWYnc6PWV/ZRZQp/75jCMOBMdKu4ErLBuD9LECWtwpYofCUrJsJozspQJdoQg1mWBYQatsQgunKox/Nr5BqvqBRacky4rMLgxZu3r89AYSMNApXCKMnBvUcMk+IZBEc9YDS/vqbE0DrE6A9hQEkYxyKI5tetkhS1TnDFTGiDiuYH8/29shPUreRYEbr+qxQGhQlbYupof+9qfw8AgJUQmnWLsgQ7AfeyDAJtFBNVAF++uMGE1kSdmvA48tPpZoajqEwNf4HHxz8/saPpx3x1fBznq5MyX/1UZp/SxKDud43gCkyt5CUIvIQzpaQKg5diSTgrJiT17LFvBNEcrn2glssrpPB7J42tP9NQoD1s0df/OeoLI1s4c5zwRwDUlLRMVAm8Q0UtLNMjHgFty2wJWzLkRWzhoFKkaYgCIgpoOm1ggVDIbmEjwyUKGygr0AWCOvFollVuoIAMgoMAjnx+FLacUAzTj4ef0moGweFhEE1G8/zg1z+5mbFaIbVpUmg6JSDIc4tF53AdwZFFno/hv3jFFkBrpBdeirhC2hmy4AgLLKXaOhWuWiIsuxM49aIHFMsRa/IuR6OBM4OKcDg8BCYc+qYoHquwDkAEEFV1VuKTRFgwm4a00ypdMJGiWEIcgz2JT9ImA3nu0pLneR64E0K8ePLYIdjlv3RliSoplWxCL+kZBJ0pnwZRYuS5K3IYLIjGJ4+DqM9Nn7vpu8F9eI269ofwyiKdkc7t4CQXH7fY8ykX79ctZqdtyxl1csvFG9Jg9hXIqMdcWHpmNmgX/ZGPxf4FuXgr+Pq8lpcvReZenOfijXzOdMvJOjOqw1y8R9UwQXhWEq4xFx9itzI+HeKMUdgCFf36YMzEfH/veiJ3ulPoaQp/R2yBuevCrFNXSic97yeO76xS/mkhO1GAkd5n+2tj5gQw4pladlXt2DGatZDApahQ9ZRCDczo8WLYiHzBBFHrnjU7HGq+4ZOWnaIIGex07U0JYr9w5MHE23qIm+52z4/3NrbTnl4zra2T3Kw3jJsNDjVcNPbSwSXhIWtaqYxOFmuDp0qR9Yayw1TFEivjxDP4s3e0MDi4QX2/17eoD0dwEESRd/5bhWhYg7IzEMcXjPPYGWd2ouGphnFN9ZuGmILzMHccazvQ34jBBN0eS0N2d509+r/U2Yd4DCY+9zrIblqTZex3qhPcUOxAUJfFzT3650c/PXm6k4hfEdA3P7iiiIUGQWxX4nU7IWXvhW6XGz5RKUSDandf8GMU+b8lEd95WlqDFHztjOzF89dwXiPn3qoEHS9TZkAhKTTgyqC7SkGjsb3I0ASkKfyNMN4p9I2DwKVtXwnjDprKppWaGalAKiuopeU3l5Rw4LbTTP7I9dVXb0oIe4/1DP3kZXJu+fxOYRb/5ywg7nfOxX34ph6+L4fd91d/R7zw24TaSIUzeSlQzRyuQt1xs93C3vOD1tP9L9ddd9o5/smkofKzW549ZDIDt1XSP5/7L6GXPprQB7BLM1M1D1gPHgxxuA8WLGwI/eQwBBlYh7kp1X7V7qT0YcC2WJ0kbexTRX72YrSsI8Jp0a4Iotlo3PQWdfe5HPIxGvh2KjzM9PDfLMLxpAh3rPC09387CNR/Ilr1MNnpvi0d24+GrG2/7vsYLBI4K5hxva6x356zEU+vG87EhZ7BghTg9tY1a9NGFqhnrhmqiSrALbJfYYSJwWMVlp0mfNr7j/F8lbR/YCOXOORsh61uZXDEsR9Y/e/bqDzMTwj0r9Wtf+/Bg82WE9Zu8/gW0t61otukVlu5+Tc4fQfybteB3laBTS62KZxtKHwX/J11HnL2Yw1rK5D/tl81sug4JrhydzdkcDVQ49nwY9aX/Vn/H67n+3v/BO0bR0k=', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-activation-source', Buffer.from('eJytWVtz27gVfu+vON4HkUwkSpttMh1rtamzdjxuvXFrxdnueD0aiDySsKYAFgCdqLb+e+eA4J1y0pnqRRAu5/KdK6CtjLMEQ/ySSmU0zOC78QuY/+P0X6NLHqHQOLqIURi+4qiO4SRl0QZHr8IJvBj/LsZjOPuCUWYwBqbBbBAMU2s0oFFrLgVkGhUsd3bpZI3CABfasCRBNdaGKZOlsMEkRRVacu/5F4zh5ubiFJiIIWVmo6cgJDC15EYxtQMdKZ6aIeAXg4KYDEEq0GgMF2sN97gDLtLMhL8Lf5WJyJAcfgCPvwsAgEgKbeCcS5gB31qtwzUPz7mcNjZc8mVrxyVfNrZYKWfgbVFvGOk2onmZ4F9pJkJhFEvCSG69xrF3J/MzOjbOtBrrDVM4Xgu5xZHeYJKMS7X02IOXlok7nqCBaMPEGmOYwYolGoegDVsjkWNqnW1RGF1wK3WXmUkz42vDDFrYFIMZPO4DeIRUcWH8v82vPoTaKC7WfLXzr5Z/YGRCpjVfC//RHXSs945EEART2LdYZSJl0b3/wJIMS8Tpw1eQz+b2FxHKlcU4/MQUZ8IEoNBkqkkijBHThZsJgmmT3olSbBdybb8dz5JMfn7LUj8/3j6cCzMYgNmlJEv+ezabgSet+l5D/sp8CnWWGAvgtLm+kgr8fBM5oVyBA/Ied7omH52/vcfdHcwa2tq5oEXUqZOfqq3tq2FdY7ejbRejMm0w9imehhBzhZGRatdQMZecixVFxjmX4XueYCjw82Il1YJO2uNB+O8M1W5BG32PbBkzFR8fE47DTPAvx8cZj91oK+NiUiRc3HvDkvI/icqFWMn3CVvr8MPV+6vLy6tfF/Pffrm8+PD3+RBEliRtsxHXcI1mseIJLoinH8DRbAZ+qRS8LXl83KUYnl5cn/388er6NzhuLlyfnd9cnlwH8PTUxLxkwoxRfJkZXGRcmB9e+V6poJezncDTU02qQwcIBy+AAUzk5NWrLkf/qBJ/MPi6ADmYuQjfBwGYjZKf4UwpqXzvRjhzQyS3KRPkAGQ5L2h6h1G7doieXJ9/ChMUa7PJaZN6R7ceFzqlmBiClypMmcLacLRWiAYVTbmN5dRdyEWUZDFqS/t2cteW9kI8sITHwCLDH1iesFJUduTVzZ/7p+MJM3D08pgtpCJ5+xZKgToE5WqVcFEjGKKI9a/cbHyvPFWXo8y4RSWLR1s0LGaG1anXsgGBT+ng1hsTRpT4i++8ADR/1cvB4ZVaofCGtqjcBa04NyrDuuTFqq1AL8EbF3KHf2gpvGFeU7qY3yaSxRgPYbkzqO8OpocDdIOQzi8iKQzVJ78vro9yFmQ+y6Rwwp/gzevXP7w54DOVfxccQfP/YI/blOszsMUuZUqjX1R3YplXEyPntgz6VopOySkVyzIe2wixTQAFyYdsu0QVcn0hDK5RVXsfUJGZKOqhPQk/5jHWmf8JJl9W7hM0k0UvFKUz9oDSg8cahYsxmHWYt21j6/QaDYoH3zt9dzNfzM/m84urDwsan5yeXp/N515A/YTrNTwhR64FHC0zctDHiuM+mLqaNa2XsTKuilauG6taZipC539zt20ebXDL5nbJJs0YVyxLjN/VWtutMCsIDQZuFCZS3mep70m1Dm2QhUX4tYPIIuIIkd3zYbhhenGPO99DwZaUE2rh2UAmEzpLye0wHpWafgs+ToWiz52BwM8NIPzHXJYFj4+ho8m+C4cTlfBwJCx+2qiHfj06FGKuSxItHIqlBgF428eqf+sx3N51/TaRS5Yku9OvMh7R1aNJkcxd576UMkEmnjnS4S8QY31moYEZHDmQqiJH6SAY5ttuhKMLsxKo1s4afdvdS7Hi60xZvY7qvAYD97skWi81RZtXnvc7zSu5bQc86l3aXEqEuF58VtzQwiGvbrcx9PFbuh+m2Wv2qoP3UpnwaDdaJjK6x9ibdhWqy/701EK9A0EjyRR9QZVsKt+IMWE7v92JF0wPI6afC55hEW5hJEXEjH9LHnAXHIDxq1DqZ8NnWHnciicGlc9jmP0EtaoVEOseiCxMBReFD6golTarzs9ljSnzETVlQhoo7Ov14bfvTlU3WuoLalZgaZqQFRo5LtQ7EdFkdYwSdA+rRix9Y35rRScMBgcM08n6/SnM1odvzHct3oe876jSK/iqTWIeW5ukVNe16ZikZQ4XeNYOvTfN8RgKQ4ykSHbg+mPXlef9RCxRW67U8LHI0OsMy4y0zz0wp2IUNkh+3CAoKQ0kLBPRBukxJ8HI5A9KVWNzfvoLsCiSmTD545CSdAsMm7XZ9fMd16b86lIJzLp15G0n38BxG4mCRXEHoXh0u4Ma7VoWbh12PUCxldJvzU3fgufwHFWzJEY5nYnaQtBoGoY1hx921Nv3Pyv0WzmvdMtMu0ZrmemFdV4KPZp4l2l7gXZdYPemXhUkliTUCG9k3DFI871nmemQdudcat3LvLwGSbXOL0BjN9eNkPa58KyeEnNBhnnjVHt78j1fB94QXEbO9emhTrqfvsv0zyxJileLxcnNx6vF/OPJ9cchvHo9mTg0gn5syQtZym3IFimvBzf7uNJBzF7Yy2eoNNmRsxHC3jmaUlN6U/GCaYdN9ZREJweDfEAX5acnesxqZ4OImWgDPhINamBr9NwdKV8qCbdo7Hv0sk+JVytfoeb0rNzbphSMqk6gzJMjlvJRJtgD44ktMj3RWdCuXaWqMKloulUbagmPzDeRoieF2tXJgui2WNXshu8rJvZRo1fKo/rbYAlHce19eoIO7x971bAtwogeakdcPKtDJeAPDfrV/J/7ELdGbhMutnHR1bDl7QUfeky3Xj0Ex7HrDe1rVpFon56gkrJrudZ6W/aOkzUfxBtJtBDlU87juGsG6jMpPXwt3z6bYsdj+ECdlesJgcY7kIaKXyk+/W8SJcgo1mwpzLkUnR2sErZuFb+2HM+qnqPlDEjVpxged2rh/1ZqnlWdxKzfU/JXuia7Q2J/s1hfE6K8BuT4V42Y13LBHKijGlCHsrLNw/mtoEzFlIb3RSJdUBIdv4D3CvWm+INMQ8Tsv2TWwK5Pw7ho4UJ4MW7nZfuwaOuIMbhNKbAm0/LHj/BmCi9fup+9DX4nIqffFJEHYClTQE9SoQ1/CWCpkN33ULI1ONMJYuq/nkwmk2f609rw/x2+ZXO079S8wu/yRDKER+s4Q4jRMJ4cNwvhPv9DbB/Yvu+76Z/+C3vNZgU=', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-session', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-companion', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2026-09-18T00:37:42.000+10:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVNFu2jAUfY+Uf7jiBaiygNgbVTWxtNOiVVARuqpPk3FugrdgZ7bTFCH+fdchtKTdpPnF2Pfk3HOOrxhd+F6kyp0W+cbCZDwZQywtFhApXSrNrFDS93zvVnCUBlOoZIoa7AZhVjJOW1sJ4DtqQ2iYhGMYOECvLfWGl763UxVs2Q6kslAZJAZhIBMFAj5zLC0ICVxty0IwyRFqYTdNl5Yj9L3HlkGtLSMwI3hJp+wcBsw6tUBrY205HY3qug5ZozRUOh8VR5wZ3cbRzTy5+UBq3Rf3skBjQOPvSmiyud4BK0kMZ2uSWLAalAaWa6SaVU5srYUVMg/AqMzWTKPvpcJYLdaV7eR0kkZ+zwGUFJPQmyUQJz34PEviJPC9h3j1dXG/gofZcjmbr+KbBBZLiBbz63gVL+Z0+gKz+SN8i+fXASClRF3wudROPUkULkFMKa4EsdM+U0c5pkQuMsHJlMwrliPk6gm1JC9Qot4K417RkLjU9wqxFbYZAvPeETW5GLnwnpiGB4qjyerqFOKgT2aRbfvD8FS8dGjfyyrJHSdwqlsc0DxEy+jjhA99b398PUep0RKbxPqFfHAsurV//emWew2cwgvzgG8q+SuArKjMZtjFvvnULTeN4Q9eaY3SNT2eG1ERfCKdnNSdODvgIUyP5b9XL9/3aiQN3lYOQfecCcmKc0P/6eQf7K/Hw6lG8Z5bHp9ft86v4OVpKAWrKyS3GSsMtuDF+idyG6ZIcvFOKxoguxsQRQD9J1ZU2A9gDznacydDuiJIpaX7n+ikBYeOvgZCu7s6uMnZqrQqMKSBV9oa0rdvZ2ja7nAg6B/4IHJ3', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyVVU1v2zgQvQvQf5jNoZYKVU6zaA8OcnBTdyu0dRa2u0VPC0Ya2wRkUktScYLA/70z+rbjXWB1oTScr/fmkRq/9r1bXTwZudk6uLq8uoREOczhVptCG+GkVr7ne19lispiBqXK0IDbIkwLkdLS7ETwFxpL3nAVX0LADhfN1kV47XtPuoSdeAKlHZQWKYO0sJY5Aj6mWDiQClK9K3IpVIqwl25bVWlyxL73s8mg750gZ0HuBX2th24gHHcL9GydKybj8X6/j0XVaazNZpzXfnb8NbmdzZezN9QtR3xXOVoLBv8ppSGY908gCmomFffUYi72oA2IjUHac5qb3RvppNpEYPXa7YVB38ukdUbel+6Ip7Y1wjt0IKaEgovpEpLlBXyYLpNl5Hs/ktXnu+8r+DFdLKbzVTJbwt0Cbu/mH5NVcjenr08wnf+EL8n8YwRILFEVfCwMd08tSmYQM6JriXhUfq3rdmyBqVzLlECpTSk2CBv9gEYRFijQ7KTlKVpqLvO9XO6kq0RgXyKiIq/HTJ7vrUuVshdYl+nSfabgHE2Qhr73XI9DrlkU0sYFUaVcu+iiSh7XcSE8Q2F0SmAaS8w0IyW6hoPvHQaV8FH2dXSG/16qrZEaYbcLtE4YB69eAUfBbzdwzpezh3W6Jis/D4II2BVwA1WSE0BuG8EJRLFDR8ciOleDT0WbeLidbmWeUQkqVL//l1/zAUcomoBDvWBu8QWSYSKkGQejTCschX3o4WSujLfGOMTVYjkivzHCzQ2oMs95qp0Jng/XbWcD34rwMwGNHS67IJ6BQbZ1TpP2hXtz2wmc9jkZvMOhwdic9WCED8SCHYXxjF9mxAb5xanI84AK0exMiWFPHekIhcPK+YQ2co8t3aS1LKnFnr/OGgxFzugC1vbZBLHFfE1ZyHrdM9bGFrlwdKh3LOHRXqrfr0bD1FoFo2Xyx2q2+DaKThKHHZtsbwXXEVIZ/m4SES/4iOknuqrPzJ/jT/Tcpey12QPoN5vzzW1mwgnq8ejueJmNttGY/xHAnkwweQ4ui4FfaRTwiNl0LHe6Fmm4vapZdMJsWL8tv/T50KTindjy3wKDtxG8bUs0h6abNaZ/VgSyf0SjGl5Ik0pmdacTeP/u/Ts4hDVYVljUS+m8gDoMO52VOdIG/b5ddeCgKVAtUY1tUi8kvF/A95P8', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('heci', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('eJzFGl1z2zju3TP5D4wfVvJWVeL09uau3uxNmqbT7PWSm7q9zE4mk1Ek2tbGFrUSFdfXyX8/gB8SKVN2nHb29BBLJAACIACCQA5+3OudsnxVpNMZJ0eHw7+T84zTOTllRc6KiKcs2+vt9T6kMc1KmpAqS2hB+IySkzyK4UfNBOQ/tCgBmhyFh8RHgL6a6g9Ge70Vq8giWpGMcVKVFCikJZmkc0rol5jmnKQZidkin6dRFlOyTPlMrKJohHu93xQFdscjAI4APIeviQlGIo7cEnhmnOevDw6Wy2UYCU5DVkwP5hKuPPhwfnp2MT57CdwixudsTsuSFPSPKi1AzLsViXJgJo7ugMV5tCSsING0oDDHGTK7LFKeZtOAlGzCl1FB93pJWvIivau4pSfNGshrAoCmooz0T8bkfNwnb07G5+Ngr3d1/un95edP5Ork48eTi0/nZ2Ny+ZGcXl68Pf90fnkBX+/IycVv5J/nF28DQkFLsAr9khfIPbCYogZpAuoaU2otP2GSnTKncTpJYxAqm1bRlJIpe6BFBrKQnBaLtMRdLIG5ZK83TxcpF0ZQrksEi/x4gMrb6z1EhVCI0NaxVqPvgbg0WniD8EpNjiTsIvnJBPvX25/GGjKGX059tJm93qTKYlydwP7F92cPNOPvWAHaToBdP0mntOQfgQr8gDZw+iJa0MFe76s0gnRCbKhwDltAM1qcsirjfoNCfiGHA4mkcPFBXqlaERiu2bnVg/6gATbwNG4OSNcaNrytl7sZ2bC4OT4ipIBwOIKfn0lUTKsFwJfhnGZTPhuRFy/SAflK8jCvyplfz1+nN4MRebQp3jar2gqgsKMh2vbK74IJSD4wGHw03h2yAMf1uxPSog3Q1reBYfN5W6gXljXbFNRkNYMg9qNlKVPcXbCgk4rP3tMIbLb000UJjspyYciBWqixElR8BOAjHTvQbBCH7B+TrJrP1w0DwUGUr2DD0XzxWkAFENwgdukPlkcggP76g+Xy1VKn8JvlEijhcuFM8nvtXV1dvUQBQGwIQZx6Ny0kzu7BBQEP41sJPs/Pvvhe4A1qGWoTjNKiNLANU4MoJul0G7HAhmUkHFiaXMz3jr1By4ZRaQJc2Ss5PiZHAxumRR2fEkJ9PFOo14c3IWcf2BIcNCohCoQQLxf+YLCO5yCFTwxoxJM7LDfHe+2G1NsYCiiQUXIwbPtmW8YGB7hFIb2+h25p0Wo+wrK6w6gP8WoYmONKSy/JcN17zecOwO87eJLSCrPbKqaA2lFMgeMQU9NqPhxiyvHvJ6Z0qK1ySrAdBZVIDklrasaXQ1Y18f2EhXixSVJ0YAB5upQAbEsnseGvLQ0OPFUKg4QMCgTO799ZmvkevKixYC1QtFlTcTlEcjrgavU3S6RZPK8SWprgA/IPYmLLCLuRZzrHVEwqpKHp4WIv04x7g9bSzcxzybpJbibXZR8tFOPTeJXBL7xVZ5Q62QwgZHbtREPm932FY5IQ7BeUV0VW8/zYTq8kqBTQVBr54Yd6h1hGyxnjZ3Cm8RWC6Z2uiZODA/KOycMY0QOypCRTOfcsKuWVgEoCdyxZYfaNXABYwjKPA9AD7INEXFTiCEDa+lBEt4H8Lx8aMmr24FZSZJjPvCDeaw/+GgFdD7Vx8qgsl6xIlH4FhqYPOW5YrrL4PfDti0E4zdhYepo3o1+8gX3WjdpcHgEVvdKC8hlLakYaBurNrWPZDptguJtc8MUx8eUKFvtO7C3iNLGjVsuRSy1HT1VLW0B3ZqaV90rHbLkf1qbK48saEpwYHlcPvnLx/Go7z9v8TZvSxSkqfTj6FgkaWg1bw7+2eAJbScY8Krj/t4B4h3AItNFPLy4vTs/shVDXf4qiGtMHl8Uo+VbmcNotj/suBzSdth8IZ5WAtvP2A6EwY6pWYD+oilROmE4lpry2a6lsYN+KXdJpAjlnLKGABaHGGRoEuLPnsJyJIvWoMJx233kjaegCmEFSbSBoILZVuLux9IPYUOO61fQ9az8b7ve1ZtUFBxXXGsLL1GOtpNbktYeXIVak/xW1CO9GFA/03VGGeOLDL65vXwexDKRuoH5z48PqU3h7efc7jfn5W6DWR7iXEq4/MoBkOcK4+/vrqk8nfvuyjvFpiHGXr3LKjHmdhDGxtjfovnppsTK6NKW4TbOSY43MojmwLuxbWTvqYG0geJPZoOeEGdow38D+V+27r4nJQkD0oWqOD28eu0Tks4Itwe7Ps4donibk31EBRDmYjddZJHAypIxug5V4hpWEGs8zzUUHpubkNmcRnUgHtpDgDMCyjzmkvMookiEyhE9d37hAT0THreOEQJyK4FkbK8Q2Z6gQWyMQVJlFQLbOLXPerH7BXb0Yuk/eOJqDlYlaWQSnXutUk5EdLUIXC/2t9QGEBBNpFo9nVXYfkMm8KmdPrwtgGJKaBfZoghFIG44sPZJoDj/Jioh5r/vmAy61LyndVZMJLZCYG7KDlVq1NQFQyhvxGoL6WCxFVO666fYk4bAO7rc46kDqEKlJUL6DCDEYZsT9a3s+kMyCe9vjOii9IE8RunNL9OYqa3XYxRZpahLC3k7RjJM3q7MscRafnkCwUZEuZIJhyZ3dtKVb7pjfiRUh5LOZeTRrjOaDShR+aWZIYsDv9qc6GhUVdTHzGKyPTdIsmptB4f8WDQwqWCYFGTr0Ke/XAlyfEXi+Gt9hQufRCjsltMvmnmLAepOR/H6XSQuB28bZLeX3jxv2ujt7+05W1q6amOuB9VlBzDib62m9u+0jTZeuZZKkjsXujCihk6iac0dVrzOFcdbOXMUhWTRUSZljBZSjSU3qZATS/KKkn4tU8u5YrDnQO2y7mxuV4m7lBpd+AuFHc1dUTiQaQ5DnhaI1eLZIOccTCHjG20AgeG65ksroBYLv6TuYtxGKFgUrNoNU+bSAu8pmIDgaeZpVW6B4uqCs4t6amaquhtw/q9EjrojtPP8X8wZCHDm8Dp+bs/hQJJqNpgIrLW8l5c3HwYH5Tk6xgatKdXGUkShJiNGiIxlbunFd/TzZUjOsSGYVdvMLFr2a0YyUbEGxVkhmjN2XpMplu7LEmqJK5eN5CiN199MsOgKOKDpiKUEiEnV/sLFaW9VkzY2v6Uzb4Htti3VYBMaahmlz1W22xPcgjf6gmtmwJ81RSB9kpxS94C6K77s3F61GQmMkrU0YjcYYlsbfGqwtuTWubbc1nBRRmnmOQrLJin0wtBv1sksPZnu4vaco2vYP4zS7t5v2Ysh/epog+6fFAqPUtUIPO5v4+pmwQjZYjw9H6c9rbXzZxRdkXY38TXlGYxVmG781FUiWnamUY6wtlWjnt3r5FhN2Y1515QWR9pJme8L2TcvW1+JLY8vYFe+2XzDCks0p3MQnbNhQIHAv51UJ0wlI8wvBYpVor8vxUxh29a5bIGhqfzkcbje22nSN3WkyCp3jmZNGzmnPdHRK1ilo8s50x76Hr+Fqtd8qGMc+63+IAPTuf6foYH59Qp1bzuzC2sFfx5cXocxh0slK1DwD9e8Tw8HO6J38baLYpS2XItXhYcX2jkV3WcqO/S2oXeg83a82WPe6mr00A5MgO3qbm7LMoNuut/vlRySc4K0bOuYuVWEQ1dldUHccJlE6F6c/I4soWxE808qNXWx8NrX08enO/rdzaOyh2LlvYMV1PXK6lusf7tZOmibtfT4JlVw/n0CTVT+fhivn3pGEynFGTevDfPCUUAH36Y7X6dpdt2bH7rrv6NvqIjueZc8rAnRJ1snBn1HW3KgC16HdKqptYH5Tcc+5bGei8PyyTfd/kLg15tDUs2JUOxc05V73C8ctdC1v0SUJe7btGca6tnCOu5BVC1KXlfb22jDOe0xTM1qjsb5dVlXD6mOKWd3P3OstWFLBGUy/5KzgpWqjWN1NEXn+B4KW44w=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJztVl1v2zYUfbYA/YdboSil1pGTvDWGN7hpihkLHCBOGxS2MdASZRORSY2k7BhJ/vsuJUaxnWQY1u5tfrCsy/txeM/hpTvvfe9UFhvF5wsDx4dHH2EgDMvhVKpCKmq4FL7ne+c8YUKzFEqRMgVmwaBf0AQfbqUN35jS6A3H8SGE1iFwS0HU9b2NLGFJNyCkgVIzzMA1ZDxnwG4TVhjgAhK5LHJORcJgzc2iquJyxL733WWQM0PRmaJ7gW/ZthtQY9ECfhbGFCedznq9jmmFNJZq3slrP905H5yeDUdnB4jWRnwVOdMaFPuz5Aq3OdsALRBMQmcIMadrkAroXDFcM9KCXStuuJi3QcvMrKlivpdybRSflWanT4/QcL/bDtgpKiDoj2AwCuBTfzQYtX3venD128XXK7juX172h1eDsxFcXMLpxfDz4GpwMcS3L9AffoffB8PPbWDYJazCbgtl0SNEbjvIUmzXiLGd8pms4eiCJTzjCW5KzEs6ZzCXK6YE7gUKppZcWxY1gkt9L+dLbioR6Oc7wiLvO7Z5WSkS64N8ijQUdMki37vzvZZGGpNFWCiZIL64yKlBGEtcbdnlVkIRGMmwqzOdkhNraq2oQhoM9GA87TaWZMHzFG2OoJBUhj9cZhLF7JYlX1BOIenMuOjoBWnDmOBjGtVZqoBYm1SWBh8KkxHywpIUIUmpoRjf7CtMIrirJFtFfuhBEhs5Qi7FPIy68LBfg4vY6oOFQXEzR7VkEgL4ALY1+AjgHjANmUwEsd/3BA10fQMEq9CeRgpN+PawDaYNk2C0oFaR53ymAfe74ilLTyZ4qIBnIe31ji22OsaMj6dtyPnMxtU+BWI01jQ+miJQeCBN8XviILjidzahK37UxlZrmybWEhP9cmSr1MneHtWJJoLdcjMRwc7u15SbM7SHUXeLT43t3mcgxv4twyiuS2I64kJQI6EN4/acYWxUWSvFtFqI8Q3axnyKOagy+hoPQeg6SxAtiSzURAo8niVDqHWcTbhCFHfW9QTqFA91wdaPy+vv9PXzBPaCwkijsIMcBdSIzNKK86qobKt4y2rJnpAtpSHZRt60Ieg4VeHbmE57vWA3NnimgUkjArKLcF8FrVWcy6SaJK8rwbni6Y+LUi/ClbPUDKK5VCLEhzPPFKM39qcd9/UoyZHy22qQgPvUURA2zC6l4EaqA9syJHbODJ6sAb7UgyvqbgU3FRDBw86kW1D9iQuqNiHKoZ52NoBn8GzawZveIzB49w5eXH4cgbbBj4gzmmsWVfq1qX/CFKz69IpMn639a5nuZHoahGu8qRjegXYOIjY3Bt3gcaI63p8qT7l2BPXYj/qeeEVNVWN3toa+osxzZ3pSRiWoh7177L+m1yL5n90fYjcI4NdX10+2uf5H9PveUqZlzrDP+NfX2CvLCqG7b4+bw48eze/nbk8qcpkax78AD6qD/w==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-companion-assets', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVFFP2zAQfo+U/3CqkJLQLim8jS4PXQERDbWIliFE0eQm19YitTPbIakY/33ntAU6eJzz4Pju8913d18SHbrOQBZrxRdLA8fdo6+QCIM5DKQqpGKGS+E6rnPJUxQaMyhFhgrMEqFfsJS2racDP1FpQsNx2AXfAlpbVyvouc5alrBiaxDSQKmRInANc54jYJ1iYYALSOWqyDkTKULFzbLJso0Rus7dNoKcGUZgRvCCTvP3MGDGsgVaS2OKkyiqqipkDdNQqkWUb3A6ukwGZ8Px2Rdia2/ciBy1BoW/S66ozNkaWEFkUjYjijmrQCpgC4XkM9KSrRQ3XCw6oOXcVEyh62RcG8Vnpdnr044a1fseQJ1iAlr9MSTjFnzvj5Nxx3Vuk8nF6GYCt/3r6/5wkpyNYXQNg9HwNJkkoyGdzqE/vIMfyfC0A0hdoixYF8qyJ4rcdhAzatcYcS/9XG7o6AJTPucpFSUWJVsgLOQTKkG1QIFqxbWdoiZymevkfMVNIwL9sSJKchjZ5s1LkVoMUJfTxytmln7gOs+bOfA5+IWSKREMi5wZ4rGCOAYv56KsvWCD2oLtemKKAvE8g3g3D99rDL+2cbwgxBrTc1KP70UzLiK99Dpw79H2YMW2C9XcCrUh4oo2RRE9r7dvlsL3MmYYBXitw08DeG4k2txqx5CGRo5pdmLhBz14+TSJLM1nSaz5/yXhIrTKo8IxXUo4uOpPLuAPsOoRpt4zrFHH3R6wWJMOjH/Q7cCsA60T+gatAvw6PurV32LWa7drm57P/dl9/RDHrUhTI1vWZmMcUX56CiJjrIGOU28qsOZmKryPzCrGzRk5fet6czbDZ0oj/VT8fxsVUqkrPwisGrrB26V3WrBrJx6NBsWT79mKqY87M9nuN7YHaIN30tSxx/Bl80rbi+W2klmZIymI/m9G07ReVdtQd52/UQCQ8A==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('mac-powerutil', Buffer.from('eJztVk1v00AQvVvyfxjlYgdSp+qRiENog7BAiVQXEKIIbdaTeMHeNbvjuhHqf2fWcdMUAhISHxLCF9uzzzNv3r5ZefwgDE5NvbFqXRCcHJ8cQ6oJSzg1tjZWkDI6DMLghZKoHebQ6BwtUIEwrYXkW78ygldoHaPhJDmG2AMG/dJgOAmDjWmgEhvQhqBxyBmUg5UqEfBaYk2gNEhT1aUSWiK0ioquSp8jCYM3fQazJMFgwfCa31b7MBDk2QJfBVH9aDxu2zYRHdPE2PW43OLc+EV6OptnsyNm6794qUt0Dix+apTlNpcbEDWTkWLJFEvRgrEg1hZ5jYwn21pFSq9H4MyKWmExDHLlyKplQ/d0uqXG/e4DWCmhYTDNIM0G8GSapdkoDF6nF88WLy/g9fT8fDq/SGcZLM7hdDE/Sy/SxZzfnsJ0/gaep/OzESCrxFXwuraePVNUXkHMWa4M8V75ldnScTVKtVKSm9LrRqwR1uYKreZeoEZbKed30TG5PAxKVSnqTOC+7YiLPBh78VaNlh4DtWnRNqTKeBgGn7f74Dc6eb9YfkBJ6Rk8hqgS8miHjCa3G9YBXYlYM2iXsgv4dB7Sp/TXlbAgC1Xmk7uYY9fIAuLaGsl6JHUpiNuuhneQvQz+koKViXJhW6WjR/fXunVfgen0voijLvC+LxANE7xG+ZRdHEfjpdJjV0QjeBvx7d1w8p10iaPcNMQ369WIJvfDRsdMiAQn2okQy6LRH4fwuReJv3z4GLpgQiZjT+l1PJzAzQ+LorWHivrw7yuqdOInhQUyTjhpFY/6EcJlxIdMeTtjXb1BtnGEFcyuUJMb+DHrNv8yutR4rehSR9+v1ApFMwbFhyBLi+LjV/EcV6Ip6cCeU2FNC3HUO687sfxYYcW8toPbHV637jrI6uuSN9vHmz2r88iSsLRv9j70U3b/7/bDRf+y213RcIethiPLDmr/tHl3Tvpt9t01uH9Y97H/5/U/5eDibzj4zku/2sI3/o+jMnlTIvuB/3LJscYa2/3/l8kX1l4yWQ==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");

	char *_notifybardesktop = ILibMemory_Allocate(28421, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 28420, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 12420, "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", 12420);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2026-05-23T15:21:45.000+00:00");
	free(_notifybardesktop);

	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'), '2026-09-21T02:36:36.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");

	char *_servicemanager = ILibMemory_Allocate(34993, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 34992, "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", 16000);
	memcpy_s(_servicemanager + 16000, 18992, "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", 16000);
	memcpy_s(_servicemanager + 32000, 2992, "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", 2992);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2026-09-19T17:40:19.000+02:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eJytVd9v2zYQfheg/+GaF8mdK2d5jNEHL00xY4UzREmDdhgCWjrJzGSSI6m6XuD/fUdRtiX/QPcwvYgi77777rs7avQ2DG6kWmteLixcXV5dwlRYrOBGaiU1s1yKMAiDTzxDYTCHWuSowS4QJopl9GpPhvAZtSFruEouIXYGF+3RxWAcBmtZw5KtQUgLtUFC4AYKXiHg9wyVBS4gk0tVcSYyhBW3iyZKi5GEwZcWQc4tI2NG5oq+iq4ZMOvYAj0La9X1aLRarRLWME2kLkeVtzOjT9Ob21l6+47YOo9HUaExoPHvmmtKc74GpohMxuZEsWIrkBpYqZHOrHRkV5pbLsohGFnYFdMYBjk3VvN5bXs6balRvl0DUooJuJikME0v4JdJOk2HYfA0ffj17vEBnib395PZw/Q2hbt7uLmbfZg+TO9m9PURJrMv8Nt09mEISCpRFPyutGNPFLlTEHOSK0XshS+kp2MUZrzgGSUlypqVCKX8hlpQLqBQL7lxVTRELg+Dii+5bZrAHGdEQd6OnHjfmAalJbkivN9qGEftVuTKHwZFLTIHBMYybeNa5czi78wuBmHw6kvmcDRawhC42iLGO8eYkhySwcsAXpv+SZ5pp4loxruNl2bjZQwbF9fB8gLiNztW/3D1TiOjXKJBws1XrrpcHDRRaJDjwdita92EtvS18YCtActPJN2Dd4su+vi0f0Kiin2ez95jgRXVIyZAhfnAe7ZCbcVS/7dUW7l80MTNp0kqFCVN45v38PNgb9ah4h7VAMbRo6BuxMx1eCbpJhHWuGkhwGbao24k97SRskoS/+7hZr/EyuDZwFav+xsH555cjsZ2y1QYKk9GNbD4RIOMqaX1slMr+Ami51p4etGQZCwqVppriFbzqC/YAVv3ZMxmC4hx8ENqZ/M/EBZPnW27U/2Ajs8/cW1CIqjxyVPPhM794rSRFHHUcCVJ9t2267KDbPymC7sbqCPlWpcSbVuDbu/9cfnnIFFcYezjn2mQIx02rfAHkxUfj1GvfQ7q0++WWlRc/JWuRXZipE+7uD/UR8rjwOmwt/4r3EkGfbAzAjX92GvHo1TtmT7z2p7V3Rc2yqXYz/ZOfR92Lz92rtcmlG+H3a24v2rDYOP2lzKvK0zoSpHauvvr1f8+rv0LNmT4L6QVhQk=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2026-11-07T00:00:00.000Z');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-descriptors', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-dns', Buffer.from('eJzdV2uT2jYU/c4M/+HWbWN747V3SSZNlzIZso+UZsNmAkkmAyQVtgyaNZIrycuSLfntvQKzmH0AmWYmnfoDNtJ9nHuudGwFO+XSoUgnkg2GGip7lX1ocE0TOBQyFZJoJni5VC6dspByRSPIeEQl6CGFekpCvOUzHryjUqE1VPw9cIyBlU9ZbrVcmogMRmQCXGjIFMUITEHMEgr0MqSpBsYhFKM0YYSHFMZMD2dZ8hh+ufQhjyD6mqAxQfMU/8VFMyDaoAW8hlqnB0EwHo99MkPqCzkIkrmdCk4bh8fN1vEuojUeb3lClQJJ/8qYxDL7EyApgglJHyEmZAxCAhlIinNaGLBjyTTjAw+UiPWYSFouRUxpyfqZXuFpAQ3rLRogU4SDVW9Bo2XB83qr0fLKpfeN9u9nb9vwvv7mTb3Zbhy34OwNHJ41jxrtxlkT/51AvfkBXjaaRx5QZAmz0MtUGvQIkRkGaYR0tShdSR+LORyV0pDFLMSi+CAjAwoDcUElx1ogpXLElOmiQnBRuZSwEdOzRaBuV4RJdgJDXpzx0Nhg13gkxupTxJXjlktX805cEInEaqhBp1ddDrEUR3LCHfvTC8qpZOErItWQJLbrH0pKNG1i9gv6WorLiWM30mGSkpT5UYIWeSyW5qavqB6KyLFfUN2keizk+WsiyUjNLJd5I6LJNpnfEclM9539vcpjtwA8ofyr/K+d0dHX4nkWx1Q6rm9WEH2L2+1R5fT4OkteVAwOFnazFMeA90wg139HEqjVYM+de+RkX1fJ1SmuNgRqXPwjKmnsrMH8WjDc97LFPlMT9Sk8g8ovFTiAypOnHjx+uoRmrkgsnwuJzYWd9tNMDZ0cwVel9mD/iVvkSIsW7hg+cNwFieaawnhopMNxCmWupNvz1jWokNHNHdylIxY7Z/cHw26edjq/YXWZ5IDlaDMzLSz+hPHs8o6lHyLUqLhgZgOfUilC3LSIhl7S8ATLceygz3ighrYHHRtvvUXymYevdCQyjTeJ0Wy7ujosuGObVqPzNSQndOFqJrUzr4c1CAuMVmF6KwGV8u5IJtBtc8bnq9ixQqIhoDoMUIlEcuGHgsfwN6BipsDJiCoqUWVwBHHYXW6D/aeN/8j4HHZPzLNt3R/dvrLXTOLo0fFpzbKqG6xSrFvHYHU2WqJYOqy2X2W/NU+qDx8yd4P9JnyzHe38xL4EH38MDJVID749Moo9sN0Nnp9rCkVdo7vX9ixAnrbK9rlWq8CDB9Du7PdqNWvZBGtTNdsVVCD0Z9XtdvNfy8NmeO1OpbcFzEXrvI0dMVtwg8mm+QXa3tpk1nTtSuxyesk0LuBVmzFh+hgnnMWwlpNbujwXD+eP1lnTT1GMqHNzY/u4NUeodTdUBzdXOHTobaVfyFGnV/CYrryTRyQUd72R/2eydG87VZhplsDuLlJwvyB9Z0W6+m6KBF8g+Njtqh3Y6Xb1zpKZbrfT2dv9tdcLvplc1AtCdvZyWym7oTPznwNYPFme4doDjNh51Jvf9/+z2jPdSnv+lfrcrz9m2+vZgaYGW4hQ9ZZyzZz9czpRzjeQKIWHvHAITi45fpoQjct8tNSpkODBxZ59WNkHxaEYD2J9FS0GzTUSUYbg8CwkpFZY4fX3WKGOPn6Zn1eLkfDI8qiyNk7hULM2UkQkmq4Nda3F9wSKaEyyRK8LsSp9RXJhekdUJPof7kamjA==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-language', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-pathHelper', Buffer.from('eJy1VFFP2zAQfo+U/3DrA0lZSEu3J1A1dYVp0VA70bIKiRc3uaQeqe3ZDqFC++87N8kAMWli0vIQK77Pd9/33TmDQ9+bSrXTvNhYGA1HQ0iExRKmUiupmeVS+J7vXfAUhcEMKpGhBrtBmCiW0tJGIviG2hAaRvEQQgfotaFe/9T3drKCLduBkBYqg5SBG8h5iYD3KSoLXEAqt6rkTKQINbebfZU2R+x7120GubaMwIzgir7ypzBg1rEFejbWqpPBoK7rmO2ZxlIXg7LBmcFFMj2fLc6PiK07cSVKNAY0/qi4JpnrHTBFZFK2Joolq0FqYIVGilnpyNaaWy6KCIzMbc00+l7GjdV8XdlnPnXUSO9TADnFBPQmC0gWPfg4WSSLyPdWyfLz/GoJq8nl5WS2TM4XML+E6Xx2liyT+Yy+PsFkdg1fktlZBEguURW8V9qxJ4rcOYgZ2bVAfFY+lw0dozDlOU9JlCgqViAU8g61IC2gUG+5cV00RC7zvZJvud0PgXmpiIocDpx5eSVSh6H23OJXZjehotdxBG4ZRa7f09VZ3/cemtbwHMJmD96MQVRlCQcHjygHaZHuuWNUVd5SRRiD0jIlqXFaZ2E/NiTWht2eKpkllVsYjyGouXg3CuADBDc3AZxAMAjcGHZJm4Sxkir803ZlWg2vLdFkfJpyn4aYt6m/Sy5ezfhnN9TOub2psbFMW7OiAQiDOOi/tK2DHsdWXsga9ZQZJM9QZN0xvEc6CQ+/ObaSq7UbU1GEw6jdKlEUdCGP4H3/1LF5Lu5tc3L0yNYtWBr8SzP/xeHXN3H0H9rhFo220qJ12cX2bdrKrCqRvKXfp3Uqu0tx6qK+9wtCYKEt', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-service-check', Buffer.from('eJy1Vttu2zgQfRegfxj4xVI3kdLsW4Mu4HVdVEhi70bOBkFdLGh5JBOVSS1JxTaK/vsOZamRb7kA7bxIFOdyzsxwxPCN6/RlsVY8mxs4Pzs/g0gYzKEvVSEVM1wK13GdK56g0DiDUsxQgZkj9AqW0KPeOYF/UGnShvPgDDyr0Km3Ov6F66xlCQu2BiENlBrJA9eQ8hwBVwkWBriARC6KnDORICy5mVdRah+B69zXHuTUMFJmpF7QKm2rATMWLZDMjSneheFyuQxYhTSQKgvzjZ4Or6L+YBgPTgmttbgVOWoNCv8ruSKa0zWwgsAkbEoQc7YEqYBlCmnPSAt2qbjhIjsBLVOzZApdZ8a1UXxamq08NdCIb1uBMsUEdHoxRHEH/uzFUXziOnfR+NPodgx3vZub3nAcDWIY3UB/NPwQjaPRkFYfoTe8h8to+OEEkLJEUXBVKIueIHKbQZxRumLErfCp3MDRBSY85QmRElnJMoRMPqASxAUKVAuubRU1gZu5Ts4X3FRNoPcZUZA3oU2e66SlSKwW1U38q1E9kEZ/jslXz3edb5uCPDAF+uLxXWEG75uMe12yPKVPNkPrrt/SK5iZt5YPLC9RV5ZZ8HeJan2Ja88uPl0O7oMrmbD8murNBfVkNx59HFMuB5PJqEABsSxVgj/c8xS8jb9Al9OvuNb+ZqOGbMXmzbOBua36Qe0dCytEYvvDzr4V3aZfJ+10wQTVRHX9oH4LMjTxZnMH62f+pSHSFp56OuD6Gj3f3989gKPCEiS51GRywKEVhaZUYjdbRxB83/+EucafAmbH984yYSaZg7fyn0x+y6h+/d5MjTCEW1GdeTrlKRczmjOLyikVv91bYdNZYbuxmjZ9VYvex+PB9WTSL5VCYfpSGCXzGM1kUtddv7Zhf02/2oP4E0lNJl34DfYaioyjBTX+XxStu9sBh8rtrZ4pd6VJALgo8Wl/NUP7CDQNUuN1A1zhHgw6YpVOjiIz8z/ePh+/9lyZfT77QsQPe9543+gF2jBl9B0Nea/b6fo+fNtGWE7t70Rk3lv/4tChq2HCezJQklKubczEZvblk2GvM57Rt/KLJluL1xMT7gX4KozPTLxGXjX5GjlQjJfGPWK6aXXEI4SPkD3g7PgAfZyF9tHwFmWeW6zViNR0LyMYTTcVOTM0bhaPP/mE0VXD/st/P+++e3S9kLMyR+o+ulMa2x2794RWMqYKWbOeYcrK3Dzl6cfVw7PnYxt1m13jtuLxPwpX1LY=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('wget', Buffer.from('eJy9V0tz2zYQvmtG/2Hji6iEoZykhzYedUZRnLGaxE5Du55M1clA1IpEQgEMAFpWPf7vXYAPkXrYnR7Ki0RgH98udr8FB0+7nbHM1orHiYGXxy9+gYkwmMJYqkwqZrgU3U6384FHKDTOIRdzVGAShFHGIvopd3z4A5UmaXgZHINnBY7KraP+Sbezljks2RqENJBrJAtcw4KnCHgbYWaAC4jkMks5ExHCipvEeSltBN3Ol9KCnBlGwozEM3pbNMWAGYsW6EmMyV4PBqvVKmAOaSBVPEgLOT34MBmfnoenzwmt1bgSKWoNCn/kXFGYszWwjMBEbEYQU7YCqYDFCmnPSAt2pbjhIvZBy4VZMYXdzpxro/gsN608VdAo3qYAZYoJOBqFMAmP4M0onIR+t3M9uTy7uLqE69Hnz6Pzy8lpCBefYXxx/nZyObk4p7d3MDr/Au8n5299QMoSecHbTFn0BJHbDOKc0hUittwvZAFHZxjxBY8oKBHnLEaI5Q0qQbFAhmrJtT1FTeDm3U7Kl9y4ItC7EZGTpwObvG7nhinIlCRlhGGVRa9XLvVsAVgReybNffteb9qEumw3BChdyJa9fnBdbp4U/ha5iCwqWMVoPIVLafBKcR9SGbH0HZXVJ2YS323LzOHvdzt3RWVYZwoN+RG4qmB7tUkyp30S+NaHO1emwVdacaj0Sb3wzS18O4F7i78yS+kUZiyFwMie8RAWLNVYCtRR4Q1JaYrq1P45pRQbVAEBT8m38cGoHPuFjn2CiJJg0Al7vdnaIOke2mYzqUxrm83nH9Ekcl5t+rCJtRnjjxy1CZyM1y8DK+wYtS7+3G3s7oRah/cRdTKyuxQh1yRilEzHCSPRtFYoc3Jf/ETMRAl4VdR39WbxZzCAa6SOSYk/yg6kho6+28O7XYNGY1tRAy/IwEGz/WbJJqo8+jDDiFnuWSUoNoK1i1KSDp8bYLmRS6p8eypru7XgcW7rwOoVbm1H/cZuWBgpnpmgsEMQvCft3PR3cmeFyEZETRtkKTNkaQnDIfRWXLx62Ty9htKmdONmtknlOS1ZZln3qlpsOqLN4Pcc1fo9rt3L2fvTL8E4V4pAXmlUPvTCksOm0488UtJS2nR6zcVcrvR0WsqWBD+d2gmhBHVQWCaeSqr3yebkVNgm7fVtMC/6bSxboVThuFxS77qY/j+kISpivZ2EVahK0tglqyBjSluuKRZowvTgWR3EpmWaD1WPlikGqYwdJ1LtDH+Fbb1trdpxnMoZS5+b3DaQ7SlBk4el/G/0Km7bUr/fvN5vtVJRQT8uHo+vZtXKui2mNqFuHattCM864CLLTeHCjcqG0nYZbLD82dD6i4A1tFpbJ/uCK0yZ4KuRhqVvLEeSieOTxk5JcLRsIw2KwVE57zclW0OE5Fvve0wGzdFn9glIQayvlFQt8sWafUsDbrDQcmOq7Jh5gMMrK0gTpZ4ED9kiPssoeGyZ40sd76MstxFoug7kROpzhCdDujAeHyar3ch6RddB5Xde3PNCZxOs0deuLbY89XeP3D5Io/Ww82pkHdivAX51l9BGHyzsZC5mqr11YOjuIF47mq17xh0sUhZrQr+a9TYJ33WmE9b0FZ6NXv38U1jdcgqv3oPqjWJrQjrMAPZx89XDxxl5bzXu4yaTK/Gwzw1iW2oJ00mrzJJ9xa+9JDCS8kFcTTp42+s3C7htmkVRvsxpfBLtFHe56grp7SLeE6t9rAYVXQXLi5JcfPfBTv0Zi77392sdMLabwAYbPRuCMx6kKOKaRh41UfRycenzD1rfd0bVU5wVfZLZW+UBuXt///qCC5Y20/Of81Jp7i1uB2F3+fFz/3fN4Ogk4xl6m47fuSltyTScPCZKJb6HoVqsS7hi94k23OLt+nCcpeaBwv1G34nQrzXpJvlSznO6UNCHH3G8Lodl+W30D9/snQ8=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-authenticode-opus', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzVV21v2zYQ/m7A/+HmD5XcqkqXFQPmIBi8xG2NJHYXpQ2COAho6SyzkUmXovyywP99R73Y8lvbtWix8oNFkce755473dEHT6uVEzmeKx4ONRy++PUPaAuNEZxINZaKaS5FtVKtnHMfRYwBJCJABXqI0Bwznx75jgPvUcUkDYfuC7CNQC3fqtWPqpW5TGDE5iCkhiRG0sBjGPAIAWc+jjVwAb4cjSPOhI8w5XqYWsl1uNXKTa5B9jUjYUbiY3oblMWAaYMWaAy1HjcODqbTqctSpK5U4UGUycUH5+2TVsdrPSe05sQ7EWEcg8KPCVfkZn8ObExgfNYniBGbglTAQoW0p6UBO1VccxE6EMuBnjKF1UrAY614P9FrPBXQyN+yADHFBNSaHrS9GvzV9NqeU61ct6/edN9dwXXz8rLZuWq3POhewkm3c9q+anc79PYKmp0bOGt3Th1AYoms4GysDHqCyA2DGBBdHuKa+YHM4MRj9PmA++SUCBMWIoRygkqQLzBGNeKxiWJM4IJqJeIjrtMkiLc9IiNPDwx5g0T4RgZC1Gc4j+16tfKYRWHCFJGq4RgeF0fZkj/kUUALOde2lS7cj5X0yQmr7uIM/VeUGXa+5KKY3FpTLgKurDt4BrVez5vHGke/HfZ6fT/AgGtzqubArZW/Ww5YByiSkZk8+olSKPTCuquXUbixDmSi6aEIkGUdrS9LYVsB04xULF20/To8ptmbnnp2DL6rpUdhFaFdP4LFlgFUarcmo2hDfMq4bs24ts3yisGIC4wJ4SZol8yO7LobU9C1bfVUT1iFwvSMGw/5wGjbeC2Um6SwjQVuUjqVqWc7efwKBFo+UMgJQipzy+8Km7A0WIg+4JzksgMlg2WRCYsSXAl9kFykmnJ/StKUO7ek8I6E00P51iJ70G6iiEl6mkOLrVS06ewqGQvxNHrLXE31bx6Pl8edzPB6Sv/AHCYk6ynswArVz5TOZXoDjFDjVoB+MLUZipTIHRT/ZNyW2EVhupbHBnghA/RQTahg23H27LARlj+JnGXi77nC0DSoOZF8Td0tjc8+gTdnrRv3XPosuqDmSkWBCPRuvKvWRa93kvF4IoVWMvJQ01I2p8gQqr6UtNRBPZXqodezKGYlcA6IJIqMumzN2kweHn+Ra1nrCcuptO7D0Uouq1mPlJcDlkS6AZaQAi0oehbJ024mRQrcvxNU84ye8DtSYZIEfKb9IdgfHzDNgvVSRpDcHDQcH+/njG4eX5wT5OxWD9iXBqfLD/nHJ0p9vRmkPNmz9f612Pw26KKkmdI2ffvs+1aeeJhQbZiKZekpFtLao9JfU4dSJL8cm6T/M52XikTDevG/urKkmny6DcoI3UiGdllT/eizJYoPYJUo969RoOL+BVPxkEVE8Fu6CGhUHv8HTTa/hCdPVtGQJgRMUYzraarPfn9prQI4kkFCmOgqLJWmi8pWBu8sio3dy87q2O4Pp7Fn3Snyq1FMnO1y1dheypM1owmjGD/j14ZvZuT3mUYxcfI7TCN/Oqum21hNna/l5Wu4CXNAYQ7oW7gq+Mreuv0P6GtTCanAvFWS/sjoub3OnQM1U0+MpprzKRob5ca7vrshvFYtPyNnRnr33d+Qym3lexXT7tg4ZopPNnuf3n7KV+7yiOl/uGk+k/ru/T1+muEz+tN52NgvYEbRxiyv+ap1f9E9bd13WlfX3cuzvZCK0VfIHj4hU7Ty/wrgmwwvdi8XVia7dO84k7f82Q7W9zC+9KPTvbxonu90YsNQ6TWt24t/ATXtbrU=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-com', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	
	char *_windialog = ILibMemory_Allocate(39145, 0, NULL, NULL);
	memcpy_s(_windialog + 0, 39144, "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", 16000);
	memcpy_s(_windialog + 16000, 23144, "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", 16000);
	memcpy_s(_windialog + 32000, 7144, "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", 7144);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-dialog", _windialog, "2026-05-23T15:21:45.000+00:00");
	free(_windialog);

	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'), '2026-09-20T10:49:17.000+02:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-systray', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-tasks', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	
	char *_winuserconsent = ILibMemory_Allocate(53869, 0, NULL, NULL);
	memcpy_s(_winuserconsent + 0, 53868, "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", 16000);
	memcpy_s(_winuserconsent + 16000, 37868, "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", 16000);
	memcpy_s(_winuserconsent + 32000, 21868, "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", 16000);
	memcpy_s(_winuserconsent + 48000, 5868, "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", 5868);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-userconsent", _winuserconsent, "2026-05-23T15:21:45.000+00:00");
	free(_winuserconsent);

	duk_peval_string_noresult(ctx, "addCompressedModule('win-utils', Buffer.from('eJzNVk1v4zYQvQvQfxjkInvryKlzKRwYrZN4ESFbe2s5DYLVoqClscyGJlWS8geC/PcOJSV1GnvbU1EChkVq+Oa9xxna3Q++d6WKneb50kLvrNeDSFoUcKV0oTSzXEnf+4mVdqk0XOodkzBV6Hu+94mnKA1mUMoMNdglwrBgKX01bzrwK2pDANALz6DlAk6aVyftC9/bqRJWbAdSWSgNEgI3sOACAbcpFha4hFStCsGZTBE23C6rLA1G6HsPDYKaW0bBjMILmi32w4BZxxZoLK0t+t3uZrMJWcU0VDrvijrOdD9FV6NxPDoltm7HnRRoDGj8o+SaZM53wAoik7I5URRsA+QIyzXSO6sc2Y3mlsu8A0Yt7IZpsinjxmo+L+0bn16okd79AHKK7D0ZxhDFJ3A5jKO443v30exmcjeD++F0OhzPolEMkylcTcbX0SyajGn2EYbjB7iNxtcdQHKJsuC20I49UeTOQczIrhjxTfqFqumYAlO+4CmJknnJcoRcrVFL0gIF6hU37hQNkct8T/AVt1VdmPeKKMmHrjOv23UfOjN5WlouDBRarXmGBpYoCBMWpUxrEMfinstMbQx8FszSfGVqhDXT5H8Og5dTaAUOkZaca7vAVZHvvUC5bFWyVtv3nuojdzUV/jaZ/46pja4JKHilFFzshVhmHi8p26Bec+Ppr0c3qAXUDSnov1J/XWpZw7MOrJkosf12199A3HCiMrVyBbunixpAn1IVVk4H7TBHe10FVeDti8M4btc/oNzRkmQr/CbOI+4qmDwsm/CZchtvcdd6atj2m+9OlbVf534+hMgXrcqLwUCWQrTfBxxwxQ0qmF9K1Luqoq5KrVFaiKnY8HB8VR7rhni10/F1k5vb0UPoBJhOpe07CJIknnycURONkuRnnmrlmjRJmspLkiZfc2UlyWhbCKVR0z5bpo9TKiBzHnQgiNG6LjfBIeluaLSlltDS6y8/fIXBAM4PRT6/X0JhDig9Ytb/VXwtum4GEj8Aq+nhRziHPvSOOpaH93R54n8qoUNkj8lw7hY8M/vNRVdYSq11umKS7khdt9fnenG0bQXYZAxxi0f9od5wuKFAmdPvGfnz/YEG+ca5u9EwCR+5EBXcl7OvxxIeqLPa8rpIq9vvzUXW/hfVujd9puhndw373kplpUCST/8crLNO4mbvUr74ExcNcX8=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-wmi', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-writer', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	// }} END OF AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2022-12-14T18:05:36.000+00:00');");

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
duk_ret_t ILibDuktape_Polyfills_getModules(duk_context *ctx)
{
	char *id;
	duk_idx_t top;
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_enum(ctx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);					// [stash][table][enum]
	duk_push_array(ctx);												// [stash][table][enum][array]
	top = duk_get_top(ctx);
	while (duk_next(ctx, -2, 0))										// [stash][table][enum][array][key]
	{
		id = (char*)duk_to_string(ctx, -1);
		if (ModSearchTable_Get(ctx, -4, "\xFF_Modules_File", id) > 0)	// [stash][table][enum][array][key][value]
		{	
			duk_pop(ctx);												// [stash][table][enum][array][key]
			duk_array_push(ctx, -2);									// [stash][table][enum][array]
		}
		duk_set_top(ctx, top);
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
	ILibDuktape_Polyfills_function(ctx);
	
	ILibDuktape_CreateInstanceMethod(ctx, "addModuleObject", ILibDuktape_Polyfills_addModuleObject, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "addModule", ILibDuktape_Polyfills_addModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "addCompressedModule", ILibDuktape_Polyfills_addCompressedModule, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "getModules", ILibDuktape_Polyfills_getModules, 0);
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
