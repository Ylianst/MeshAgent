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
	duk_peval_string_noresult(ctx, "addCompressedModule('AgentHashTool', Buffer.from('eJzFV1Fz2kYQftev2PhFIiECHJLYOMkMdkjDNLE9ltNMnjqHtIJrhU69OwWo4//evZMQkgHbmWmnesDS3d7uft9+u5I7T50zka0kn840HHZ7RzBONSZwJmQmJNNcpI7ziYeYKowgTyOUoGcIw4yF9KfcacNvKBXZwqHfBc8YHJRbB60TZyVymLMVpEJDrpAccAUxTxBwGWKmgacQinmWcJaGCAuuZzZI6cJ3vpUOxEQzsmVkndFTXLcCph0H6JppnQ06ncVi4TObpS/ktJMUVqrzaXw2Og9GzylTx/mSJqgUSPwr55IATlbAMsojZBPKLmELEBLYVCLtaWHyXEiueTptgxKxXjCJTsSVlnyS6wZB66wIad2AKGIpHAwDGAcHcDoMxkHb+Tq+/njx5Rq+Dq+uhufX41EAF1dwdnH+fnw9vjinpw8wPP8Gv47P37cBiR4KgstMmtwpQW6ow8h3AsRG8FgUyagMQx7zkBCl05xNEabiO8qUgECGcs6VKZ6i1CIn4XOubeHVNhzfedpxnJD2NCWAn1HNLgXRtfol5xG8Bff0+PhVt/fy6Kj7st8f9o5PX394PTo+HfX7x73+We/YPXGcTgdEVgR4IyZ/YKjfmTViNJchXjI9G8AbQ1k6fQejJYa5tuUwO9ZQMzlFHWiJbF6Y0o1vKoPG8B18ZGpmsBUm9kyWME10zGuuL2wSLPEhYHOE7yzJSUUKMilCYtZfHwHPXfD0xaELP8BNeJov7V3EJC27LceJ8zQ0rmBGcT+Qrr0SX8u5sZLksfekXPI3KOHHD6iW65hacKNnUiw89zJBptb1W9UYMqVq8OC2Tm4L/X9nEmJFxShV7bmxol1nK5M1vpbdKTI1F9H1HrWRRUqkr0nQqwzrJtdyZVoiqiwXM6atVireuKoOaLmq7jeRzFVlgzyNRT3ty9Hvl0wqlG7L22aPEO10sw5OYiyqtrG7re5CpsMZeNjal0zNizDttuXF/jr1M4q6BunADabRmBpnOei2gcZP+GeQz6sFK+XqyZxRg7g4HKzScBfQ203ttvOrYN6tYt3aUuufodRmClCa1yaLYRSZCfLkbZdoaKDw1xAIzuOcnGy4bXra4H3YV8D/xkuh4Dn0T/a4a/C5w2O5TV5OyjKV1IG3D+Fb6O7ogK8If+Q05dJy9NvAdqCO5hOMIlr9HHy0b7HqmO08MwapoCLDdE9B2+DKiVvTrzk3LQboaR7HKH2WJCL0eq/uGE1WGtUVsqhUhLmqtSIuzYLIxo2jtnXahm5x4yeYTk30JhFWgr4i6on3RkRSkD2nRWAnpufOcOm2DGNbs7+1p7sflV3/3pwOu3tafa9UdzqhH4vGpPCFPnJeHH4aeXXXGwVjovCBafXo2Lv8ExFhIhSWTLQekGpT80926PVOcKu0gvCQ4Go0BSheEzvleANxwqZqYHVph5LUA1MYwje4rwGf9+C2ta9Viwi+SD2X/JDf6jXp7VPLrpdh8V73Go3Rb92RhGmOfwn2fdw/M1LdQcpmyN1hxFyP4mGbi5/h4+guH/8pJ7WR/gyOdhKybowddNyj1+LmceZ+xrPqO6v59VQbjrav7h0f9wb/ucCGPctFzGiANOI+2CU/67QYJtWg+l9GwZ4iP4xvLaNGzQpUNATnIsoT8r6kf0C1+Y5df1VTXZ1/AK2RoHU=', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvftX8EYK9SpGk5O9aZFNA2wWXacf6WldGIo0sumlSZWknBiB//sOqQ9Tsp20q4MNkTNvZvjejDjYJJoUWq25AXJJNPwouQZG6yUaTQbOQqoMeBYazJMFSDvF9duMRqy240X6KbFLNESAFIyJC5HYXOk1ubwk9JHL87eUvCeMzvCJZ7OCFzCbUfKmCfGG0N8+XN1+uqYRGRPWwKSPGYvc5lm9ORkM8lKmlitJssQmfyYyE6BZuizlv9HgeUDwcSkJkBP/wnNS7ca4tMAkfycXEXkmdslNXEqz5Lmt3SdYpy21nJBd68rQC+uqEDQk2bdbac/ffrxhoygi70gI/ROwbX4u+RbXCJ4Cuxi6rLHai2jS2hXJVqjEcSBLIap1q7f+v6rWPXurv77eTeMi0QaYCxFb9dVqLhcsqkGr0tLEpkvCIOoB+fRrFcRzDStGb+UmEUjRFzCFkqiXL5AC30BGa0T31BUGEQ6TPDvroxtWJ44na0ph33dfxzQM8Zrz0Fscq/IprLJHrTttlMTrNDYkoQea4Wki0m4vxh8l6O2Vaw6mHlZDbATY4C92RahKPCbHJDw2zcdaAIZVDNFg1YZ3NfreM5N2YeUXVhi8LhQR4zlGxPVnkq6zMaE+FTrEgKKEMXGbu30vuMRcVzo59dl3YKngWETY8xIsjeIUxW/hWkkJPmH27Ksb+98GEHu8mQX1xq4rkho+Rn+aVliY6f4QotZ4n1VLvnNyokaPoPeDAB1LkNkJ6EP4E9JPhTJdnXsFuSkULjhmHQF/lHkOOs4Rg/k+NL71eL5lDU1RD8u5PpT53jkRQqVeZatGjl0PtI4fNbfQDqLG0Gl5SEY9+1WcqmLL0G3YDpZOyR7M7Qebu04bgTDwklKcpI6yrGGtNnAlxEduLEjQpibwuCiOmTsWT0voRTX0bE/r4YjUXtNBRwP/k/9f4/5XeD/FeXAifdZ3g55BeDuw7azBIe8mlUWvXfApNjbRljWTDhvbKAGxUAtGP7tphKdA/gazJH5COnMLcRw3J7oQ6iER8dytl8birYEYsPd8Daq0rE/Znq5OoG8yeRBArHLLNkltEDGI5Z7mejGHJ25ZcwJDcj4ajRpig4HeTCrMAQehXYLsj+29QT9FN3L9HK8nLk7paqzTf6Z39+T6bjq9ub6/+fCdNreOg8KCg6vjQIZl4qRH5hHs4DNMWJh8BibVvLBKG9rJtKn7oKTNSwWFqW2C0J2UD68G3ZwsUoutkaufzcidWy/yETNn1efWmfl7wOt2XtNrlZUYBJ4Kpa3xn1Wv7nH1N6yEMQ70gV/X/wBv5FS0', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyNVU1z0zAQvetXLD0QmzFOKVMO6eQQSko9lJRJAgwnRrE3iWYUyUhy004n/52Vv+KEwJBDba+e3u57u1L7r9i1zp+MWK0dXJxfnEOiHEq41ibXhjuhFWN3IkVlMYNCZWjArRFGOU/pUa9E8A2NJSxcxOcQeMBZvXQWXrEnXcCGP4HSDgqLRCAsLIVEwMcUcwdCQao3uRRcpQhb4dZlkpoiZj9qAr1wnLCc0Dl9Lbso4I4xoN/auXzQ72+325iXVcbarPqyQtn+XXI9nszGr6lSxr4qidaCwV+FMCRw8QQ8pzpSvqDqJN+CNsBXBmnNaV/n1ggn1CoCq5duyw2yTFhnxKJwBwY1VZHSLoAs4grORjNIZmfwfjRLZhH7nsxv77/O4ftoOh1N5sl4BvdTuL6ffEjmyf2Evm5gNPkBn5LJhwiQ7KEk+JgbXzsVKLx1mMVshniQfKmrYmyOqViKlBSpVcFXCCv9gEaREMjRbIT1zbNUWsak2AhXNt7+KSdmr/qMsWWhUo8A6zJduFvaJ9EEacieyxaIpR8CYeOcDFKueei8pI2rXSE8Q250SiLqSOzNRaK5gh3b7bPgo9jn0Bn+LU3Dnxpu11O0jhsHL1+C3wMvhnAK67nDkq3i9L8HTqI3OQyhpDiS4tYRHInjG3R0AKJTGWj+G97uaroWMqMMlKd6/wes/oADBRV+V/5FafFIQ5cEqaNBL9MKe2GzbXfQRa+yUtZV0yjo2F2HYDgEVUjpe9iG4Hl3VRfUgZYOn8DXcThv9njXDfpQixk0L74utx7AcY2DzjvsKm31YQ56+EDibS+Mx/5lTCYQLE65lAHloWaZAsPWMJoa5A5L7KFZBI4tXZDVBFJ9e+PaaNCdZq8s8EN8an9sUS6JhKJXrVfNzlxyR4d246e1txXq7UWvS6xV0JslH+fj6ededMQbNj76cDNdrRdl4GfNQ5bgI6Y3dAOf6Lrffzi7LeN+ENvq92v1GfY1ZtxxKvDgdviDi1bRmP/He6B3loCdC2EPK4wC31iKdIebbjtqaDPDfsi4WflpbUylz4eKxC/E1l//GLyJ4E3NXR+PtrmYfilN8/CIutO9bgblVFUVDuDd5btL2IWVRj9R0X52Tk9MVfxGZ4VEitL/YFeeLKjZy0dUiRpUDxqz3xT3kPA=', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('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', 'base64'), '2025-11-13T11:30:10.000-07:00');");
	// }} END OF AUTO-GENERATED BODY
	duk_peval_string_noresult(ctx, "Object.defineProperty(this, 'wget', {get: function() { return(require('wget'));}});");
	duk_peval_string_noresult(ctx, "Object.defineProperty(process, 'arch', {get: function() {return( require('os').arch());}});");
	duk_peval_string_noresult(ctx, "addCompressedModule('code-utils', Buffer.from('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', 'base64'), '2022-12-14T10:05:36.000-08:00');");

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
