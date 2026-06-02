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
	// {{ BEGIN AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVNFu2jAUfY+Uf7jiBaiygNgbVTWxtNOiVVARuqpPk3FugrdgZ7bTFCH+fdchtKTdpPnF2Pfk3HOOrxhd+F6kyp0W+cbCZDwZQywtFhApXSrNrFDS93zvVnCUBlOoZIoa7AZhVjJOW1sJ4DtqQ2iYhGMYOECvLfWGl763UxVs2Q6kslAZJAZhIBMFAj5zLC0ICVxty0IwyRFqYTdNl5Yj9L3HlkGtLSMwI3hJp+wcBsw6tUBrY205HY3qug5ZozRUOh8VR5wZ3cbRzTy5+UBq3Rf3skBjQOPvSmiyud4BK0kMZ2uSWLAalAaWa6SaVU5srYUVMg/AqMzWTKPvpcJYLdaV7eR0kkZ+zwGUFJPQmyUQJz34PEviJPC9h3j1dXG/gofZcjmbr+KbBBZLiBbz63gVL+Z0+gKz+SN8i+fXASClRF3wudROPUkULkFMKa4EsdM+U0c5pkQuMsHJlMwrliPk6gm1JC9Qot4K417RkLjU9wqxFbYZAvPeETW5GLnwnpiGB4qjyerqFOKgT2aRbfvD8FS8dGjfyyrJHSdwqlsc0DxEy+jjhA99b398PUep0RKbxPqFfHAsurV//emWew2cwgvzgG8q+SuArKjMZtjFvvnULTeN4Q9eaY3SNT2eG1ERfCKdnNSdODvgIUyP5b9XL9/3aiQN3lYOQfecCcmKc0P/6eQf7K/Hw6lG8Z5bHp9ft86v4OVpKAWrKyS3GSsMtuDF+idyG6ZIcvFOKxoguxsQRQD9J1ZU2A9gDznacydDuiJIpaX7n+ikBYeOvgZCu7s6uMnZqrQqMKSBV9oa0rdvZ2ja7nAg6B/4IHJ3', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyVVU1v2zgQvQvQf5jNoZYKVU6zaA8OcnBTdyu0dRa2u0VPC0Ya2wRkUktScYLA/70z+rbjXWB1oTScr/fmkRq/9r1bXTwZudk6uLq8uoREOczhVptCG+GkVr7ne19lispiBqXK0IDbIkwLkdLS7ETwFxpL3nAVX0LADhfN1kV47XtPuoSdeAKlHZQWKYO0sJY5Aj6mWDiQClK9K3IpVIqwl25bVWlyxL73s8mg750gZ0HuBX2th24gHHcL9GydKybj8X6/j0XVaazNZpzXfnb8NbmdzZezN9QtR3xXOVoLBv8ppSGY908gCmomFffUYi72oA2IjUHac5qb3RvppNpEYPXa7YVB38ukdUbel+6Ip7Y1wjt0IKaEgovpEpLlBXyYLpNl5Hs/ktXnu+8r+DFdLKbzVTJbwt0Cbu/mH5NVcjenr08wnf+EL8n8YwRILFEVfCwMd08tSmYQM6JriXhUfq3rdmyBqVzLlECpTSk2CBv9gEYRFijQ7KTlKVpqLvO9XO6kq0RgXyKiIq/HTJ7vrUuVshdYl+nSfabgHE2Qhr73XI9DrlkU0sYFUaVcu+iiSh7XcSE8Q2F0SmAaS8w0IyW6hoPvHQaV8FH2dXSG/16qrZEaYbcLtE4YB69eAUfBbzdwzpezh3W6Jis/D4II2BVwA1WSE0BuG8EJRLFDR8ciOleDT0WbeLidbmWeUQkqVL//l1/zAUcomoBDvWBu8QWSYSKkGQejTCschX3o4WSujLfGOMTVYjkivzHCzQ2oMs95qp0Jng/XbWcD34rwMwGNHS67IJ6BQbZ1TpP2hXtz2wmc9jkZvMOhwdic9WCED8SCHYXxjF9mxAb5xanI84AK0exMiWFPHekIhcPK+YQ2co8t3aS1LKnFnr/OGgxFzugC1vbZBLHFfE1ZyHrdM9bGFrlwdKh3LOHRXqrfr0bD1FoFo2Xyx2q2+DaKThKHHZtsbwXXEVIZ/m4SES/4iOknuqrPzJ/jT/Tcpey12QPoN5vzzW1mwgnq8ejueJmNttGY/xHAnkwweQ4ui4FfaRTwiNl0LHe6Fmm4vapZdMJsWL8tv/T50KTindjy3wKDtxG8bUs0h6abNaZ/VgSyf0SjGl5Ik0pmdacTeP/u/Ts4hDVYVljUS+m8gDoMO52VOdIG/b5ddeCgKVAtUY1tUi8kvF/A95P8', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('default_route', Buffer.from('eJztVttu4zYQfTfgf5gawUpKHDl2sgs0rltkc6vQxFnESRaLpghoaWQTK5NakoqcJvn3DmV5fY3bvvWhfLBM8nDmzBlyyMZ2tXIs0yfFB0MDrb3mjxAIgwkcS5VKxQyXolqpVi54iEJjBJmIUIEZIhylLKRPOVOHO1Sa0NDy98C1gFo5VfPa1cqTzGDEnkBIA5lGssA1xDxBwHGIqQEuIJSjNOFMhAg5N8PCS2nDr1a+lBZk3zACM4Kn1IvnYcCMZQvUhsakh41Gnuc+K5j6Ug0ayQSnGxfB8Wm3d7pLbO2KW5Gg1qDwW8YVhdl/ApYSmZD1iWLCcpAK2EAhzRlpyeaKGy4GddAyNjlTWK1EXBvF+5lZ0GlKjeKdB5BSTEDtqAdBrwYfj3pBr16tfA5ufr26vYHPR9fXR92b4LQHV9dwfNU9CW6Cqy71zuCo+wV+C7ondUBSibzgOFWWPVHkVkGMSK4e4oL7WE7o6BRDHvOQghKDjA0QBvIRlaBYIEU14tpmURO5qFpJ+IibYhPo1YjIyXbDihdnIrQYypqIZK4fIoxZlphrSZG6XrXyPEnJI1OksIEOiCxJ2rPB80saK7V3nYdzFKh4eMmUHrLE8Upk8IlQ55f+sUJmsEu0HvGTkuMn1wnSYZKylPtRMo8voZdohjJynXM0QXomFWUrurGJLaAzGpr/ifMu7pjiFuYeeO35CDTFRjiyv2LR3asXZurQnK7hsTtZ4t+xBDodaLZa3mSq1GVq2RSbbR0Ba9I38mMWx6hcz6fZ6JYO6n7r4tT1pp5s28yu8LDCcC3LPW82OcdzyhUF7WTU5Kiw6Z+gwthGf+C9TbS9akfJfGl0sUfb1rU43tlr859Kr+2dHe4t4pYoFlLIfIneAeyAy2Eb3n/w6vanvbqKx+DSyn8W0LJQG9jY1mjAyeRoQHE21qMsgx/sOXl5scfFHyEFHcLPMKO1/2EzrzWUNtAqxCrO5TNVNoMqZiEezrlr/o27Okw4Hv4LivC6RnzbXleHl4bmuuXf8kNBZEpQ/tDY1L4uFKeEi2y8qTSFQ55E84WoGHhIlQypujqej2MMz+jKcp1Gn4uGHjp1+N2hzx/TjVSs8LWhSql8KVwnYoYR6jsJN/RI5NcVPNGhjyLvjtNeHH7bjL1Di1U7HQhJ6R7lQAzomK1xwIVvbyzizlPKEkUPL0D3WQqlItRl+Ve4d55tLYCtZqdTK6dq8O4dbB0UA481sK5T8mRg6z25gtd7517gmJt74Sz6zRk3pzTx/eRPE7Qct0/MR5Pj5DjwS3E/wOHidnxjzWzvNSdhL2a9r6P/c+4INJrucdgl8XdjUtVWl7fSX+a2e/afzKymp2E4dMsM+WnCDN0Ro1laQ0avHYeeIvst53BWKUYyyugioLeSVMbeW+seK3MlqU/l6mt73mRRQDaaXC0xGw3G9Jyk/Tk1ORmMmCJmG90s7+k1Tgqp/gL2YXjV', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('heci', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJztVl1v2zYUfbYA/YdboSil1pGTvDWGN7hpihkLHCBOGxS2MdASZRORSY2k7BhJ/vsuJUaxnWQY1u5tfrCsy/txeM/hpTvvfe9UFhvF5wsDx4dHH2EgDMvhVKpCKmq4FL7ne+c8YUKzFEqRMgVmwaBf0AQfbqUN35jS6A3H8SGE1iFwS0HU9b2NLGFJNyCkgVIzzMA1ZDxnwG4TVhjgAhK5LHJORcJgzc2iquJyxL733WWQM0PRmaJ7gW/ZthtQY9ECfhbGFCedznq9jmmFNJZq3slrP905H5yeDUdnB4jWRnwVOdMaFPuz5Aq3OdsALRBMQmcIMadrkAroXDFcM9KCXStuuJi3QcvMrKlivpdybRSflWanT4/QcL/bDtgpKiDoj2AwCuBTfzQYtX3venD128XXK7juX172h1eDsxFcXMLpxfDz4GpwMcS3L9AffoffB8PPbWDYJazCbgtl0SNEbjvIUmzXiLGd8pms4eiCJTzjCW5KzEs6ZzCXK6YE7gUKppZcWxY1gkt9L+dLbioR6Oc7wiLvO7Z5WSkS64N8ijQUdMki37vzvZZGGpNFWCiZIL64yKlBGEtcbdnlVkIRGMmwqzOdkhNraq2oQhoM9GA87TaWZMHzFG2OoJBUhj9cZhLF7JYlX1BOIenMuOjoBWnDmOBjGtVZqoBYm1SWBh8KkxHywpIUIUmpoRjf7CtMIrirJFtFfuhBEhs5Qi7FPIy68LBfg4vY6oOFQXEzR7VkEgL4ALY1+AjgHjANmUwEsd/3BA10fQMEq9CeRgpN+PawDaYNk2C0oFaR53ymAfe74ilLTyZ4qIBnIe31ji22OsaMj6dtyPnMxtU+BWI01jQ+miJQeCBN8XviILjidzahK37UxlZrmybWEhP9cmSr1MneHtWJJoLdcjMRwc7u15SbM7SHUXeLT43t3mcgxv4twyiuS2I64kJQI6EN4/acYWxUWSvFtFqI8Q3axnyKOagy+hoPQeg6SxAtiSzURAo8niVDqHWcTbhCFHfW9QTqFA91wdaPy+vv9PXzBPaCwkijsIMcBdSIzNKK86qobKt4y2rJnpAtpSHZRt60Ieg4VeHbmE57vWA3NnimgUkjArKLcF8FrVWcy6SaJK8rwbni6Y+LUi/ClbPUDKK5VCLEhzPPFKM39qcd9/UoyZHy22qQgPvUURA2zC6l4EaqA9syJHbODJ6sAb7UgyvqbgU3FRDBw86kW1D9iQuqNiHKoZ52NoBn8GzawZveIzB49w5eXH4cgbbBj4gzmmsWVfq1qX/CFKz69IpMn639a5nuZHoahGu8qRjegXYOIjY3Bt3gcaI63p8qT7l2BPXYj/qeeEVNVWN3toa+osxzZ3pSRiWoh7177L+m1yL5n90fYjcI4NdX10+2uf5H9PveUqZlzrDP+NfX2CvLCqG7b4+bw48eze/nbk8qcpkax78AD6qD/w==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJytVFFP2zAQfo+U/3CqkJLQLim8jS4PXQERDbWIliFE0eQm19YitTPbIakY/33ntAU6eJzz4Pju8913d18SHbrOQBZrxRdLA8fdo6+QCIM5DKQqpGKGS+E6rnPJUxQaMyhFhgrMEqFfsJS2racDP1FpQsNx2AXfAlpbVyvouc5alrBiaxDSQKmRInANc54jYJ1iYYALSOWqyDkTKULFzbLJso0Rus7dNoKcGUZgRvCCTvP3MGDGsgVaS2OKkyiqqipkDdNQqkWUb3A6ukwGZ8Px2Rdia2/ciBy1BoW/S66ozNkaWEFkUjYjijmrQCpgC4XkM9KSrRQ3XCw6oOXcVEyh62RcG8Vnpdnr044a1fseQJ1iAlr9MSTjFnzvj5Nxx3Vuk8nF6GYCt/3r6/5wkpyNYXQNg9HwNJkkoyGdzqE/vIMfyfC0A0hdoixYF8qyJ4rcdhAzatcYcS/9XG7o6AJTPucpFSUWJVsgLOQTKkG1QIFqxbWdoiZymevkfMVNIwL9sSJKchjZ5s1LkVoMUJfTxytmln7gOs+bOfA5+IWSKREMi5wZ4rGCOAYv56KsvWCD2oLtemKKAvE8g3g3D99rDL+2cbwgxBrTc1KP70UzLiK99Dpw79H2YMW2C9XcCrUh4oo2RRE9r7dvlsL3MmYYBXitw08DeG4k2txqx5CGRo5pdmLhBz14+TSJLM1nSaz5/yXhIrTKo8IxXUo4uOpPLuAPsOoRpt4zrFHH3R6wWJMOjH/Q7cCsA60T+gatAvw6PurV32LWa7drm57P/dl9/RDHrUhTI1vWZmMcUX56CiJjrIGOU28qsOZmKryPzCrGzRk5fet6czbDZ0oj/VT8fxsVUqkrPwisGrrB26V3WrBrJx6NBsWT79mKqY87M9nuN7YHaIN30tSxx/Bl80rbi+W2klmZIymI/m9G07ReVdtQd52/UQCQ8A==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('mac-powerutil', Buffer.from('eJztVk1v00AQvVvyfxjlYgdSp+qRiENog7BAiVQXEKIIbdaTeMHeNbvjuhHqf2fWcdMUAhISHxLCF9uzzzNv3r5ZefwgDE5NvbFqXRCcHJ8cQ6oJSzg1tjZWkDI6DMLghZKoHebQ6BwtUIEwrYXkW78ygldoHaPhJDmG2AMG/dJgOAmDjWmgEhvQhqBxyBmUg5UqEfBaYk2gNEhT1aUSWiK0ioquSp8jCYM3fQazJMFgwfCa31b7MBDk2QJfBVH9aDxu2zYRHdPE2PW43OLc+EV6OptnsyNm6794qUt0Dix+apTlNpcbEDWTkWLJFEvRgrEg1hZ5jYwn21pFSq9H4MyKWmExDHLlyKplQ/d0uqXG/e4DWCmhYTDNIM0G8GSapdkoDF6nF88WLy/g9fT8fDq/SGcZLM7hdDE/Sy/SxZzfnsJ0/gaep/OzESCrxFXwuraePVNUXkHMWa4M8V75ldnScTVKtVKSm9LrRqwR1uYKreZeoEZbKed30TG5PAxKVSnqTOC+7YiLPBh78VaNlh4DtWnRNqTKeBgGn7f74Dc6eb9YfkBJ6Rk8hqgS8miHjCa3G9YBXYlYM2iXsgv4dB7Sp/TXlbAgC1Xmk7uYY9fIAuLaGsl6JHUpiNuuhneQvQz+koKViXJhW6WjR/fXunVfgen0voijLvC+LxANE7xG+ZRdHEfjpdJjV0QjeBvx7d1w8p10iaPcNMQ369WIJvfDRsdMiAQn2okQy6LRH4fwuReJv3z4GLpgQiZjT+l1PJzAzQ+LorWHivrw7yuqdOInhQUyTjhpFY/6EcJlxIdMeTtjXb1BtnGEFcyuUJMb+DHrNv8yutR4rehSR9+v1ApFMwbFhyBLi+LjV/EcV6Ip6cCeU2FNC3HUO687sfxYYcW8toPbHV637jrI6uuSN9vHmz2r88iSsLRv9j70U3b/7/bDRf+y213RcIethiPLDmr/tHl3Tvpt9t01uH9Y97H/5/U/5eDibzj4zku/2sI3/o+jMnlTIvuB/3LJscYa2/3/l8kX1l4yWQ==', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-border', Buffer.from('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', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");

	char *_notifybardesktop = ILibMemory_Allocate(28421, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 28420, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 12420, "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", 12420);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2026-05-23T15:21:45.000+00:00");
	free(_notifybardesktop);

	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");

	char *_servicemanager = ILibMemory_Allocate(35777, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 35776, "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", 16000);
	memcpy_s(_servicemanager + 16000, 19776, "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", 16000);
	memcpy_s(_servicemanager + 32000, 3776, "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", 3776);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2026-05-23T16:21:45.000+01:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('eJztHWtv2zjye4D8B9bYq+w2kZJ0W1zzWngd92Ks87jYabdoikKRaFuNLPkkKo6RzX+/GVKS9bQl107b3WixiEwOh8PhvMihWOXF+lrDHk0coz9gZGdr+y1pWYyapGE7I9tRmWFb62vra21Do5ZLdeJZOnUIG1BSH6ka/PFrNsh76rgATXbkLVJFgIpfVantra9NbI8M1QmxbEY8lwIGwyU9w6SE3ml0xIhhEc0ejkxDtTRKxgYb8F58HPL62kcfg33NVABWAXwEv3pRMKIypJbAM2BstKso4/FYVjmlsu30FVPAuUq71WiedpqbQC22uLRM6rrEof/zDAeGeT0h6giI0dRrINFUx8R2iNp3KNQxG4kdOwYzrP4Gce0eG6sOXV/TDZc5xrXHYnwKSIPxRgGAU6pFKvUOaXUq5Pd6p9XZWF/70Ooen112yYf6xUX9tNtqdsjZBWmcnR61uq2zU/j1jtRPP5I/WqdHG4QCl6AXejdykHog0UAOUh3Y1aE01n3PFuS4I6oZPUODQVl9T+1T0rdvqWPBWMiIOkPDxVl0gTh9fc00hgbjQuCmRwSdvFCQebeqQ0aODU0pOQh4WJX8IgmnH0Fc6txCy6FqQa9OFNKv2fSrwhbDPoJZdJxoW0WA9TVFURmDqT2i114fi+/JmF6D2LJd8vbt29cbZKwa8L5NHmoyEG5VNRiIbVLZtPsCRc+zNBweYap7U62tr90L6UHxlL+cXX+lGmsdARESAmy6IEe6ZwKJe4GcGT1ShZFqMAHyyFQZ8HlIDqDB2LBe7Ug1AeWjDVH3KesCwj+HJuAOiZiWVi11SGvTRpH2+CBztIFh6lEu8oIvPi1STaZ3VHsHGhaSR63bT0iWbjjSZ/KSSFdX7sRldPhqB960AQ7RxWbSBvkkBQXwQ1L+e9m8+MjfuqekIkFjJPClVOFlf560pc/I0CiNnBzZZbrtMfiDMylJe/Fi26pKuspUwBIyoarVyL3gErZ6eUA0mdkdUByrDxMPc5nXEXWcrI6weIkdoUw17wxWTVajJCRpkQHbsFojz5Am0Z1jj0lVurS4ZQFb0qNMG3D52yUBY7H3OHKHMs+xIh34XPU7iNLykJa1Oh9xwx6CAukJiYvVcbnbIHdDM1/4cJzP4hAZUD+QmCKOGYL6qML6qAJbQGhXLrj43HEzl+RxgpKHtIm7a5p0SC0GjQGF7IJvY1VpX2mCyBxKtU9bn8OyoGj7816GqQwFP8A4xeULfgJdpDSFMVRFARNTvb2E7lHdyFe+VKWvfSovg79OX0zuk0I+KeR3Uci0Ko3Ydo427sV6UBS/E2ggf7UNKwqZhXZHwGbo9F4crQDi0DsB5nzEERMC8KjMSV5EEGN9xEjsZTPg1Rw7sjflQLTzVyEbIqBZ+H8V4NnmaC9G8KuAE78GyGfintpBaJHPC4H7V8EMv02KFyGAsFZ7ydoSpBVhUxajXmdORN3pe1ji+txKzsPrsIMYZFYHb0SD6EwksQfceh0M902Afg52MO4CfsY8hNjf+Kx2+ilWCDyhq0jNQ6xpvKoUzcV4mOwirVHx+qKqPMuWpHnrRt1bD32a5lCV0Q+wZqfAJ6oOq2G9jfVsOALvBuZ16qBk6BOM/T3pmWrfBYs6vpbSFh27u4bufvd6PerIqmnaWnUnCXUthrl19+5dqmbbr2mmhuLKuMlAq9dJdEGF32kPFtpV9P9T5yN5rLf9RqqlW1IIM7K5tuTAQBvqYUwA7/+cBSJgNCx/hqRO47hb7/zRIcpRs93sNgkGQtE4iCjvyJWVEviZqBoXzXomKgineEkh4S7WK3VUl5ZBSiGqyUUdC3viAIoS2Z0pss6d0SgeMyUj9ESMruq3uOeoN2fF6rlAeTH7I2zedEJd+wDl9tg9t8fU6QyoaV5d3W7LW1dXIyxxsSTUxUTRP1Mtf4E5xED2lI43O/6mno57b2JuySa6F49RsWYRk8tXLWQz8Hh+VTDfvLagIlMW7zSxMoI+RIecyjIaFasup03RpavY95R12jMseu7YI+qwSRU5vkEqgSZ0vBFutVY20vJtenSXVKcT9ogL08V0QmmQyn9gVk5snBOy2TZcVr9VDZMvrTZPcWZiM+ZWnpatKZA5e5T+0jW5yqxFxSPsmi8+I3vxIoCLWmRRUrVHPD2R3mdHkQKK/ASCn4yICKVDQZod+jXkxRco4eLn7oUFX3nB1wRPjF7QrcyV9vlzEvz2ExX51t8dG7BKT6UM5quIxv2wyCrspquDIY9UZ4jDSGzENDi3+OvFJel87HSbJ1JyZyt4MFdURWQ9NhlRzHbFuZx8MqhNDJcjAiG7HIEtacBIwPjkN5qBb8qJk9bpZbeZx4o47PHZ5UX7YzHYo3qrKOiHZvOPorAnZ6fd4/nA+PAplEeeO6hKSqfBg68sBubMXi6qkzOOyp/LTxxlphVLPtcgPDdz4ALmlR/h0cqp4rwvTdfJyunqtk7mCnCKrE535XSd1hegK9jgjRMWbJwo4L/F0v3qSqqJDeDlEt1pXrxvNRag+4JULPATLlMdlsHa5dGasRE7ozgavwmCBf9IelUfPODu5NVu73NC5nafCoAKwmcHKwPPukkFLFg4P2hJ9ZIfEgW9FMATPeuQ3NJKQ2N3GMHHu7N1ir3xnX54xxMDW+Eg/Q54RMLHRqgJ/aVrvwpEAAFkk2xK8qRSaI1pWN5dns4gdfF9NBiIy9zOxNJAcyjTFM2xLVlXImrDQ6K02n+BN79QDgtBlMuHFMhaPnaJr50+JftGEf5M6iaMW58QQfFM/Q3iVvibB5ajo/yQCnCQR6bSizxBR7CB7TlzgXR1MhdmaFtsMBdqTOnNPGx/ozAPH54GDQQBXSvG5WEBM2IHahakKXgik66kXUYBX5EjUNGnuOsrFt7i85g8CiX+B+BQoaAen0BnFqO5OEHFlg744JQlIhJwFtvLmydYzYYSAPF7TCKAHQU6KtEZPlPbtFWAp/gUkIUCIOhEl8a1qRc6s8wJObM0qnyAgcG7K3bGxCHPNnewRcJHH+s8VxR9lqwjZeVRHosB//VX6ICFXC9POKeysgoDslSJWB2Zy19R+rY5e622y89CFSA99IL5eFKnp75tfCV2UaZx0mpsef5qLj8q8xMJQFTnuNluHyjXhqW4gyvrvN49PlA811FMW1NNxYWK3chv/lMUhjVTGHi5gv/y4rwgfXFAqv6MYbIQmcLFIPiB8hu8C+YFvwIlxN9go2ybwZ9cm+bHgvmnu2X/DU+mdkRlFyYlN1acoX9CKgwLlldzRKJchkHyZ0acaBtkb/bHCCmx7s1ss5K1b6qnb1j/pnCFCa3KeEAdarjBKX3yF1HHN0S6HwGBjPyy8yCBeIosVqUY+pl5hlweCr7npB/mIIooSQpnoAeJTX5eLraNDhWd3iqWZ5pk5/D5dlZGP/nMsy9CtL0R7+BJuov0tFrpRiujMfNvKd2pzc+YjK9MusU+o/4k3UV6WrHt5lPxJN9Lkm+d9lTPZHMEe7qIvLRuLHtsET8eIud+Xng3fvSqRCw1ZwCLb3oyZ1I6TuMbl6lTmY3jk7OjL/B/syN3vrQuLjsXIH0zYT4UgLk46x7P3O6NtuVqgHZjiZva0+NgsdOjGxBW63QXGJGrqHm5IBUj6ry9uSJ75XQ1G+A+fjdXQWdnH3TVGRvWrOMMmHzim/oHi03FjC1yAHbxeIi0/xseL74V3y8fVLblrQqhlmaDlewfVC677zb/XfntMH99BY/A9RKRPTs6a3Q/njf9svPL39utBqlsKkp9NDIpadjDEazBHEU56h6R83ar0yXQpaI0TyukEvtsGcBlzR4ioKsE57DwbNImNJB1plcKUyVeY2Ms2paQfd3QWHFwfPZv6OSwrV5Tc1/B12KNq6L1vsvd4yEqYCgAYKj3Fb9itoHOpAXY13fUYXhevQxZAR7VcdSSbaaD4VGJqYLXHoCXjQ5lEWzcoZVEUpUSSHL84aJsVhbgD5+bC8+qs7at6otMSk81XaoUbXR/f9867TYv3tfbDw8PReVfKaMA+wp/P5x+I558FvWg7q0287P5jGCgmpjfWW6AJ4egD9lwcTKoDlEEeDAsMeF3NftbsuARxGEQtYhvc7/FubmYAi/mxPLdAQS7wCLVnD0I7jioY4BzwOF++pw7yUvPrpJVpFcLJ8ZEetowJ+85i0aq49KWxarlzyGhmIWY9sk2pg/C34fk1RJTW9P4umXB1Bo6ORPkSsUEJvoU2KePjexwmTk6vgL2HAc81xFPM1TxUOsRHoCt1VDdxese/15si2wCF4sjhmDVU02Bd9pJwYyVbi89PxgZKNjTgKEF6cGHn6qZIuEyFWdf5Me/oLYE7kD5xfGx0KX6ngwQBj5sWoGWBawyd7fRsaGrCOrQ1RZNEj6Q8QBvzqk+i45yPzKPz5/HGPAyZGINmBGCFerwsbNocf7mR/AlaVxVZj7PDuJh9230nok8sc1vNxJpU9x1CVLFKYNU1N5EM/f7oPqRXCwWHZI30SKdC8pWsgig4rRiU9tjeL2So1p9uhTyDoRnjR6X5zlTUbw8Y/mNKpo2rRP+mdsC2vqPU54S+dmodPi52rR8cHzLl5DwHN0SwpkAn29vT/y0c1KKePncfcwoQmGnebuDGPbv7pnFGME3T3m4mHcWiCBS2qkl+Rf7+S+AWJqP5igLeemTIAu+LD8tEO5Hpzbqq4P+pmyd+mte92R05qLIXeP9HOuxcsddwzXrM990gl8Pp8OkVp9r11bct89bChVy7dPFcrAPE3OhuWHRC/JmK+1Ml3pGqNxp2J+Thd/Kx1kQxbYNCjE41Dkd9S1g6/IjvU/659gGZ9FQL/2lT9zSf5fwqRRjhytm7DCTsQVc6I/G2qInI7NswvKVP5w/tuL5Y5nzd2x7Tpnpi58MTU2mfzAw0sEJP2e4aBfb301eyn2iF5WV8lFEkH/kf2WHjkxVo9VkhmIjlinpYNqn5XcZZkuAWyEZZbe++SZGhr97vOE0VOhWV53ksHw4kVQKU5Aw1pBc/4NIARfkaPyfAXxtKpw+SCRPVTrbPevkQNu4dlRnorR5ju9IpRDGu0oyhylz/uCnlPg3fQ1O8KzozFOJc0u5hxQyrjQJ85oEM0WkFC9yLziJ95e4OiiPbwufSJh9Ymdq/k9txq/Z5heaiW88uFAmL3Qo0X1E3CKv8UVaQvPS7uhcdYCtoELuBhl6oIoqIyZV4UVc+T0RF8zgvUZ+LjDG8EjHGYmR4HYYfpbNsHp29CYO/B29sDpC6gov4QgWYTNu0kjwLH+GlzK7yZktwVGdmjR+u8kXUfQzsHXOxSSr/yg9cdXJEedc6tLZWTcRIOy7bKNZ5qP21X/QvoyP2Yt/yP7YH7Fn05tlMed8vF7uw/Vv/mA9Jypa5JhHnGrPgiHeLIPqf8J5w4w22RudOQPIulhgeqGAboMJxX++hItSZrCSQUC+8OaffUyce/zW845zlKFU2FpC+n/WABZ07lFC2CywJVuMclO7gIkgTzZiRTbih4tV/Qv5hvyGRNBbPLbg+gGo+Mdz+LLs/7vFlKc=', 'base64'), '2026-05-23T16:21:45.000+01:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('update-helper', Buffer.from('eJytVd9v2zYQfheg/+GaF8mdK2d5jNEHL00xY4UzREmDdhgCWjrJzGSSI6m6XuD/fUdRtiX/QPcwvYgi77777rs7avQ2DG6kWmteLixcXV5dwlRYrOBGaiU1s1yKMAiDTzxDYTCHWuSowS4QJopl9GpPhvAZtSFruEouIXYGF+3RxWAcBmtZw5KtQUgLtUFC4AYKXiHg9wyVBS4gk0tVcSYyhBW3iyZKi5GEwZcWQc4tI2NG5oq+iq4ZMOvYAj0La9X1aLRarRLWME2kLkeVtzOjT9Ob21l6+47YOo9HUaExoPHvmmtKc74GpohMxuZEsWIrkBpYqZHOrHRkV5pbLsohGFnYFdMYBjk3VvN5bXs6balRvl0DUooJuJikME0v4JdJOk2HYfA0ffj17vEBnib395PZw/Q2hbt7uLmbfZg+TO9m9PURJrMv8Nt09mEISCpRFPyutGNPFLlTEHOSK0XshS+kp2MUZrzgGSUlypqVCKX8hlpQLqBQL7lxVTRELg+Dii+5bZrAHGdEQd6OnHjfmAalJbkivN9qGEftVuTKHwZFLTIHBMYybeNa5czi78wuBmHw6kvmcDRawhC42iLGO8eYkhySwcsAXpv+SZ5pp4loxruNl2bjZQwbF9fB8gLiNztW/3D1TiOjXKJBws1XrrpcHDRRaJDjwdita92EtvS18YCtActPJN2Dd4su+vi0f0Kiin2ez95jgRXVIyZAhfnAe7ZCbcVS/7dUW7l80MTNp0kqFCVN45v38PNgb9ah4h7VAMbRo6BuxMx1eCbpJhHWuGkhwGbao24k97SRskoS/+7hZr/EyuDZwFav+xsH555cjsZ2y1QYKk9GNbD4RIOMqaX1slMr+Ami51p4etGQZCwqVppriFbzqC/YAVv3ZMxmC4hx8ENqZ/M/EBZPnW27U/2Ajs8/cW1CIqjxyVPPhM794rSRFHHUcCVJ9t2267KDbPymC7sbqCPlWpcSbVuDbu/9cfnnIFFcYezjn2mQIx02rfAHkxUfj1GvfQ7q0++WWlRc/JWuRXZipE+7uD/UR8rjwOmwt/4r3EkGfbAzAjX92GvHo1TtmT7z2p7V3Rc2yqXYz/ZOfR92Lz92rtcmlG+H3a24v2rDYOP2lzKvK0zoSpHauvvr1f8+rv0LNmT4L6QVhQk=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
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

	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('eJztGWtv2zjye4D8B9YoIHnryI8tFlj7eofUcXd9m9pF5FxRxEEgS7StVha1Eh0n1/X99pshKYmS5dhpd4H7cP6QSOTMcN4PqvnD6UmfRY+xv1hy0mm1fybDkNOA9FkcsdjhPgtPT05PLn2Xhgn1yDr0aEz4kpLzyHHhn9ppkH/ROAFo0rFaxESAmtqq1XunJ49sTVbOIwkZJ+uEAgU/IXM/oIQ+uDTixA+Jy1ZR4DuhS8nG50txiqJhnZ58UhTYjDsA7AB4BG9zHYw4HLkl8FtyHnWbzc1mYzmCU4vFi2Yg4ZLm5bA/GNmDM+AWMa7DgCYJienvaz8GMWePxImAGdeZAYuBsyEsJs4iprDHGTK7iX3uh4sGSdicb5yYnp54fsJjf7bmBT2lrIG8OgBoyglJ7dwmQ7tG3p7bQ7txevJxOPl1fD0hH8+vrs5Hk+HAJuMr0h+PLoaT4XgEb+/I+egT+W04umgQClqCU+hDFCP3wKKPGqQeqMumtHD8nEl2koi6/tx3QahwsXYWlCzYPY1DkIVENF75CVoxAea805PAX/lcOEGyKxEc8kMTlTdfhy7CELqK+OMdvpr105Ov0hD3Tkwi8kZY3IpAUSHvyR1/TsyIvHhDwnUQ1OWaQsq2rTs/cuvkK5FPigCROGTbqwLv5PCdIkKPbHcQXFBYyBWKfLHu9mNlQOnmLkEW8pgFKUX5doikhNqlGRWXAGtbqfCO0vi2YBDQwJ0f3rMv1FxRvmRegzjxIikaBxaXcMrb9XxOY8sJAuaar+vqQC/fmcdsZf7THo8s9OJw4c8fza8YtCvwlS4x5EFGA4gGa9oF8eWZXaKf3RV/yZZs6+kZSwuDiV5D5vmxczkwPSug4QISwCuS8SG8J1OmgDeXT216uLmjjfbd3A+dwP839TQXbTYBN2EBtQK2MI3hh36bvEvhDEVIJ9M5kkznaTLtu4TGEHxHM2UL8EO8PYto50iigBdS8W5q/qMFte7ESW//thYJuK1DugFLqFmvQJa+BSi5RyuoxAKODBp64HhaONR7ICu5GJPReEIuBpeDyUDWnMAPqY75H8ArWrRC/KOkT7NCtfDlxPK07AfjMrE8mrixH3EWv6fc8RzuALCx8cMzKDORw6HkxQ1iQBDpjLBIZHMrcEC8pbVi3hoK3CtiWIcgRQwjpFk3emmVxapiIrMrrIlV6PKEZDe9PyOzOJ73XpDRk0vorOD/E0ferG4tBGqQz8lBQKnLQlo6NjVJc5RSkr7o1fPs/UzJpfJ1sRMo8LxaHGUpAUH+QXi8pqRL5k6A7ZmU9UlECdLI0vZBb0gz+hOA35Tsd7S5o8lC7LaLsVuOPQo9jGnkEQxIyW5xyIPmLlmuucc2oVmKdNGAVOQo2Wjs2SjW7xw+X6/mw1SKzHnA9uKFWiV//EFelNy4sCbVX7GUhnzVjgzxih3RNIDz8WXMNgTqRgj+6HvkgxNDgHHo/KFokG2aFTAhgIw4SSxonK/FFDPfV6Kod9OHrI9T/Tfk83uwHBC1BvgwAAvCIZYLSdAEIg3h23XLjanDqQApGLie5ScATq2Q0Q4pN1JcWfvAahlk3jDCSq9IpXM8mc5TdITzCn8pFK16+bgj4QDMpVo0lOt/FV0NYbdhyPW3WeKIZgp17zbomYl1vfAA7bagIYXxkV5BHmMrBWYa7VarBacaP8PP0HNlytsHh2PRM6bws6bTyI/odMqd5MsV9YC8sO8Zlqr8cI1K/sTjx/xF47mgtwDmMRpCwoWIW3YLPDTEgIfT33kQdGUu3eoMFxX6BCUsmX3jKHozcKYv2po2I7iYE4j5UK+UaluoLxhqUE5KVaaWWQh7BNUGgqWWvodpq7CbJ0N0cRlYplErqB1eamDCWt3izBbFyzRmTkJ/em3sc7hCDi51lXucuoyyB0MECQhckcUzX85cQlMcqmqdCAcuDV6iA2MrvGqoGPTS7GxJ5MIIW+FxmLozBSPKWULlnC1ChX+ImQsL4w0EzQgyqhnJBSvyPdBvAqkWzmjVi1RLh+BPyWLYn+zJ4L1RBNgWXyn0BQcJilQezpke4c8VoLeXT6QserQKkEz5Aki+lcC2RA95TbyiaCWxhM2Brm7C3q691jetW9S6AV4ONQsx1laynslGzWw34FW1LmekXe+V1YvHcJhToLwJTOzKTMhrRlkf4E0STpF78aaT1VoTp2pRaoXGoN1eOVB2eqWzlDolmZv2bemETJUKoHVbTDJamlHTIeq8rSwtZgh8grwtKckl+ZzXikxoyNaizMsO3XhPk+U1oE9gHYIYKXUVPUmiq/5DjXugImd2Seo/6YpoNdcr7Aq65MY4m/30GrcEI2CR28JVUCGXITvopTBEIAcmvtcPAYNLC+BqISBzW/E6NA+S8WgA3ZGgVKRQKn3rOMQEwUuDgkj65sPDbukt2gkgckSFWjTkdYL3e3b/18m5/ZttWZbWI6U2S5sxNB0N73HYuOOgdcqrzHEnW/8dS8COtDDEDawU8uQrsbjNbJVNj26b4vyYnRLe74qssYgAN4AD8anjiKWyIgR56GI8PYOJhTuFCnZCAd5Bp2Pq1NCS0HMYt8j3dGo/Qolf/diZTj/COtskH9iGxvaSBsF0et+2WtCt4EqCK0gRfP3GyJew7TkLGZyA197qLWALJh7VyCeejduGLm1qW8E0zIkejWPRGeLMX771KIGyNT8W1A/VkGWkbkKa/avB+WRAmu9IczIiugeTpt0n41EfNu0JabW6rRbJvBrTp274Cv/dPbV5dU1eot8J/8mJqVjIU3rpivjPraulWtFskksGY4c0fnFvjwyy9JJCiBf7syrEyRWpSellyClVYJDVpvE0NJ6w10uOQTuim7Px7DP0RuSsz1bq0YZeCOc9C3t836VH0MoavvoRwHMWeKL2ICLwLd/N2nRaOwJdVoqMjPWLSrs13dWOJOTRuaAFj9YFhVnGRwc8FtWyKcfvOYllcxYN578weBmHbx0cPH2KCn4pblKeT/DCT/DybmODZflw/l1Ez10ZVUPwRrNdt9S4pHvON9M6TwtsRhC972gfsK7oAqcgYbPcAKa0yEhcxKVnN8hreMGeufgvt/QRyenqerSTlg5xm2OrO+GK1IY06IPPK3nZOD4fwKapTR969S5e5qSRhN+wCt9cnjnpqrMWAZs5gYWTUz+9ba68j+jn19XpSFqYRsm2QTImzYpai9dUWt3IYd39uVJU2kuKfaZrARtedsfX2m15gRKC/h1AZdd7eLYRTK3DZOnPuelWTRXSFuUhoYLLFXYD4to1cuKEmq6V4JdhE7wS2dJG2nr5nGTji0kcaFiqaB9m3YW5OPtA1t3dx58yLnYlD49wOnVWN3iIuPlVd3O3Fn6VfjQrYBskBxbXdRX6wV/5jkGpaI99/pbbR4wkugWUzoTCiuNPdrGRPeSe+82Oe6zLpvdlGjB+ic0aWBG7xbuX/7v7X+Hu+VebPR6fAZi568oPNvn752c5cn64+nCy52TUCpt91rxQizTB0r5TKyIPrxJmn/fGKuwdG5vCTzJIcWNQr4asUPoTHFo4BmCBMdGpGmK+89SXod1bSP0nv6MgZhVZHNmPp7WPsfz77TNCVv9tq5d377e+UXt/vua+W21/kcqyRPhdxP83SoyUI45ZfLwkOw3Wc4kIMWUGgY2IxVzep6T30t3sqZE2h930QVyLnJ78F0uKjSY=', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'), '2026-05-23T15:21:45.000+00:00');");
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
	duk_peval_string_noresult(ctx, "addCompressedModule('win-wmi', Buffer.from('eJzlXFlv20gSfjfg/9CThxE10W0n1jgbLGQdGWJtOWPJMYIgMGiyZTGmSA5JWfZm/d+3+iDZTTYpyZYHCyyRRFIfdXxdVV19MM3f9vf6nv8Y2LfzCHVanTbS3Qg7qO8FvhcYke25+3v7e6e2id0QW2jpWjhA0Ryjnm+Y8MFraugLDkJojTqNFtJIgze86k31w/7eo7dEC+MRuV6EliEGCnaIZraDEX4wsR8h20Wmt/Ad23BNjFZ2NKdcOI3G/t5XTsG7iQxobEBzH37NxGbIiIi0CJ55FPnHzeZqtWoYVNKGF9w2HdYubJ7q/eF4MqyDtKTHpevgMEQB/mtpB6DmzSMyfBDGNG5ARMdYIS9Axm2AoS7yiLCrwI5s97aGQm8WrYwA7+9ZdhgF9s0yknCKRQN9xQaAlOGiN70J0idv0Elvok9q+3tX+vSP88spuupdXPTGU304QecXqH8+HuhT/XwMv0aoN/6K/qWPBzWEASXggh/8gEgPItoEQWwBXBOMJfYzj4kT+ti0Z7YJSrm3S+MWo1vvHgcu6IJ8HCzskIxiCMJZ+3uOvbAjagRhXiNg8luTgHdvBMgPPOiK0ccYQ63Ciypk+EmTT2di7fUn7OLANs+MIJwbDm1lAp8I9U8n+uD66gYvetbCdglmIMI9PvVMIwItPqLKz/5J9927d/1+/fd2p1tvtwftem/w+0m91eq3DkeD7mgwGj1VEpI6JyiSsMx2x3jfPaofHRzNgIQ5q3e7hxaQMIxW6/CmgzuHAomrk+HZ9ei09+n6RB/oF8M+GY/eKZBqyW308Ugf69Mh1NTbiu6906ve14nUb3g9PtfH0+HFqNcn/VoP3RaI0Gp1OHTnDu4to4MO1H06a/QDbER4TEH5HHgPj1olbtCwHAZlUsAan+Fo7llaZWLMcC8IjMeeaYLJDIzIoM0Zm9XCvp7DwDvgysDq5xOtYTJy6EZL12T28BF9q/y5xMEjCRjBzDBxpYYqPcu6wDPy7QI72AhpYd9zXWxGU2+CA7C1yndKt9kkfxE0xwEmTk9MVCfDRJqBjYXIBBe5IRVgfODbx7QD8ewQXBvIB25jYZuBR3ywAeGjid36MmyubNfyVvTzoNM0fLu5AqqmYzddt86/1m3yJeScmDRMU85d0pTFlJy+vDhWmv9MNOe/z33sjo0FDn2xU58EOqcXPrpm34BRq4k8zm9+AGAT271Lyj/hiJXmSyiRpPjzMuo7RhjmCuRmA5AywnJLoUxuzKyIVgzd5aKoPCeIDoASPVVlKnFy7eVilVBxnUIusUruOnzAJgU6X5JvOPYiEjFpHMx3ytXmCTDvUxSxpvt7BQ4BM41OZCc+QTFmw/26boGBIfsBDD3KUPSOCxwunShUeEeJhyi8ROUpvCzEkVQyxg/5AgllNuaO58qkJne2X47u34rsWlQLQF0DbAG4RQDHoePPpeGA4eJgIsMd1+fKwHVzZcw9Vd1pwMtVnOBb2yUmjVlumWuQHWtaOHStsj7ADaZBSF6ix1KlcgYS92aDP1WxnvjGyh1AonKPLSlWyi2ycSvlCTktJIdTr0zqc0i/7bxeugvZnQ2+BomUqrscVpIaGKeCGjZaBZV0aFjdugEqoADDtL5/Ivc6+2OtODRrnTidMHfjw5AKhdZdk/osc9cQaIsum8b6P1jKhD4yJQTP/SmrZT4co3arhsAiFuExOqghF7zkOO/caAaR4Jj+S0BE2o8aCmzbgq7+fVUmmuFBHpLLBTgSs8UvRmCTtYx2SNK9bAeikefghu3OvLaWF4fwboAX4JkG4rffVxuRd7KcwSBo5OsEVjXurVaZ44dKVUU/hPWcOUfaVnTyZBSqUukhwqFKK/P0pV+H7yvHCOyArAT0S/fO9Vaumhp5fjR8zyb6J8KRxaYG4KfSA7SfWaOJ/W8saqJCIH5gWABlM8AL7EaETBQscVmHZvPtW7JYbvgNYGyCUUclrUsHEmmi9lUYV0o4JlsmxQ0Y0V1BPYe/fdTtvjvqd9tHB/1Ruw1rqUGr1esB9CedYedQgP9qYafu+n86CBIGOxsKC88MyCOON1VdWniuh0FWbBtnhkUgcF6ybQaJa+U5uj7FuzwZ1YABBBmcw+8p/flUKw/P7SQ8t5PwnCxqs2F5fSjmdlNiNRlrSXitNYhYX1WMfwEAHQUA6Vp+ewTq9S0RSJmthcCeka1GoRH6+BG1tpg5ZM5jD515AU7Ti5Bvjqj6Ur4miOoufa3IiGmjeJOhQWALG1w/Ta5jjlRdwy9uDlO7u3ScMq5+eZsEOtNwnBvDvBvYoW/ALI0tBX4lGJIHVmz6YoEtG6xQE7KWKvoJYdxJdt2oPGCBVMIizJ7UxdgJ8daCUQ0z/Lfi+ky7Qd+G48F3ZWxTMHolTz5QZJq6a5G9ioIck/pQDRlBsN6vMxgIhCmVxhfDUalPclPg5C5wDTnYhW+u0uTJZqBGGtt0qxQ+/pES/gBx1d7czX8ACdCJ+5hmo9+yiQN6i/LZRJl3BWwbpOEvw7mG+XoH8wWdjUOCJm0IKxzHCpXpiHIW2zp33ziZ2c38eJgY1bvEqGAFN4mMaBmqrcoZOcZtWENztstRQ2EUfDYCYwGkIAmiX7e2N5EnJxyb3GuCqp6DBAG2nIGSrBJ0u8eaaFsbBg91XFzHjqSeWga3DZhtaEPsK1uy7+8lxlDgJ9xF9ve40GSNzT7lhb7i8EKrKpb7vO9ztu3AwIxl5DXdWZ1/rYfA1SBcDcrVAq6pmOwbMa9MQIuL/URTsqf3Xai5N5wlFo5ZSPkPliKI52QgWx0krlQbC3ZSlmwSaj/ipKGW3T9MLRVwGNlBGKEVRi4/vUyGgZ7m9c/PEEWVdSDmzAYE/cImTPTrr6xBww7ppxbHNNZDMDVJW9aKa8xNIjVWoRdAJ3omD8FSTsWBacQbi6Lu4J3Z0zVaCGRFEjA2JANY4Lgn/5SDPnHfLvon6hwiCHbva+hQWtaAgNYlrOUOOqdDSUDXXadCciKnMmNBLGJAVe45cV/VZAj6ZKfBjNPH9kcQI6q7ieZpaFPMhUmrK9vCncvpqJvxdGIiMd0GiHEbzQE2EvYg3YMwHdnuEn/Iho/UNtikGVMQMXpKjCWx3rG3Em0XxAQ39slePb2EQHAECyeWxrqooBJYM3FF4ATQSLdo4beV80RHmigIBoJRivaY75ry/2Z/rwFIK0D2mM4p6IlZMGFLv7SqqlkkM7JxhEx/q45RhYON42MiZFGwFMi86KxjVnjWUb/FUV6FvLnC3+jRJ9ZKAFF5Xvt9xvPirjw4QVctpvIraj10Wi2wy1+oLRAFv0yvyd2Kr2gGSUmeyg2szKZMApFKazQa5WZ/YgOc6/r0BVizfWJEJxNESIdIS8T5D2VNixXZAxEtjONGjA6zuG5+F4ybYkH2TfmfcrdNqe40HOb4kSi3LkLGT2mkTOStpYRVREpk+RLPvMl8LD5JALljAeQOAogAGQkdd5vnd/HOd2xX26+t6fYqWGCr1Tkmv5kN653iHuQRFGXhNgErM/3dwQTQqaFOblwTXyvboCNP2YakrMCBqMDhBj3a78Ue4+kOdT5U2XJiyrvT+UTQ4OT8/PRvGzYa83amR7sljkR7V1rUUFulQXeHI9BuC5Jfvq7ol7uWvSPJ/uo+f7l7p28fSCps5PVHUpfXd/vLV/D7ruj3k+nFDnWQp+jC6T/N31+ilWITQFHEFrPfpET3O9t1i/Uq3i4gT34XozSHCk3DIck6SaLy7eJJl2dwW54k0+ETw93w7PP067oOYpQZX56WxPkirEo2p8mz9gh2qxyhSIjyxLJornmx2JtkBs/ICnalZWF+u52Wm+cCuxWcLX9eKv1QkH4w7OtnvRIFNiK5cVKxKzi6Lx/EzdOJnQh9uSOpN04kdib1biLDZunDc1KHnSn6ouDQbKayH4re0C1qvw3FdxIazyb5nKzmefCu23oUn5ddhMkcJ33pXUy/foYQV0Fv452fZ95MKfiZ3duMj1IYUITXk3RY8ldyv1Ajp0PLwMTsSk2NVcU/sqcndNeXpBN4Fb+Vo+XfyWlwhHTXTk5y2CkZY6XcAs3KkdnIFMgkLxepyLy5+vP0TVlvqp+yq6R5MQF+gla04ZRsLk9gDHy2kUyApmch/AUYug+U3vGESTQlL7wjU3xOk9z40nI3RWNRYzrC9RXUztfFuiTbVUkdP6jJnLUk1enFB4WYpvSKhKZoQV/EIpeP+VWuNS9mVWsqNtKVwwIBtzr1ynau5V5NSoc4aSvcmyl+A61ga5Ie8ColbmRebFLIFrsM29uX/+SkY1v/v/CTlGgeeCukVYZBAGNIrumQy3MSS+hUqX5IY0qO4vOQzV5KquXeicqNJIk4Pi9M3OvMuEvPGIkCCkAzl6Pk13DKRIpDDA+HtaI39CSoBYRzpz8y3rbLvD+5wyMeSv3hORYyAFThdJroGd+lQvEbHqS9+Fbdt0QhKArnfc/CWpVMi3H5B3ly8Pm8IM8K208I/19hnfsIHZI4BpqsjGBIIvvVmS6o9T8aJ58THkujYqzwS8NheRTcKPjtLObBeJOgseTXGajTsppnBcHNYx8Boih6KchsFa/iK0Al4AgBSkwq2bW0bTSO+2Quk4RKy2GBCVt9nq7kfbmb99iyg7/0ata376IPD6VLKlxGHlDn5P8N0CRdG+S9pLwq0hvZNXKjOeB30CRFcmfuwrRAroIV3vKLqWVu+anHI7n5mxEz7lVwT1h1RTgXHZLWvDSNh5krW1S0hWctYe2DH3wvoPH0JzPK49g208XHsfAdkZtK/wVGhKn6', 'base64'), '2026-05-23T15:21:45.000+00:00');");
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
