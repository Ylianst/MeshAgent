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
	// The following can be overriden by calling addModule() or by having a .js file in the module path

	// CRC32-STREAM, refer to /modules/crc32-stream.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('crc32-stream', Buffer.from('eJyNVNFu2jAUfY+Uf7jiBaiygNgbVTWxtNOiVVARuqpPk3FugrdgZ7bTFCH+fdchtKTdpPnF2Pfk3HOOrxhd+F6kyp0W+cbCZDwZQywtFhApXSrNrFDS93zvVnCUBlOoZIoa7AZhVjJOW1sJ4DtqQ2iYhGMYOECvLfWGl763UxVs2Q6kslAZJAZhIBMFAj5zLC0ICVxty0IwyRFqYTdNl5Yj9L3HlkGtLSMwI3hJp+wcBsw6tUBrY205HY3qug5ZozRUOh8VR5wZ3cbRzTy5+UBq3Rf3skBjQOPvSmiyud4BK0kMZ2uSWLAalAaWa6SaVU5srYUVMg/AqMzWTKPvpcJYLdaV7eR0kkZ+zwGUFJPQmyUQJz34PEviJPC9h3j1dXG/gofZcjmbr+KbBBZLiBbz63gVL+Z0+gKz+SN8i+fXASClRF3wudROPUkULkFMKa4EsdM+U0c5pkQuMsHJlMwrliPk6gm1JC9Qot4K417RkLjU9wqxFbYZAvPeETW5GLnwnpiGB4qjyerqFOKgT2aRbfvD8FS8dGjfyyrJHSdwqlsc0DxEy+jjhA99b398PUep0RKbxPqFfHAsurV//emWew2cwgvzgG8q+SuArKjMZtjFvvnULTeN4Q9eaY3SNT2eG1ERfCKdnNSdODvgIUyP5b9XL9/3aiQN3lYOQfecCcmKc0P/6eQf7K/Hw6lG8Z5bHp9ft86v4OVpKAWrKyS3GSsMtuDF+idyG6ZIcvFOKxoguxsQRQD9J1ZU2A9gDznacydDuiJIpaX7n+ikBYeOvgZCu7s6uMnZqrQqMKSBV9oa0rdvZ2ja7nAg6B/4IHJ3', 'base64'));");

	// http-digest. Refer to /modules/http-digest.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'), '2022-07-01T10:24:45.000-07:00');");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2022-06-30T01:17:01.000-07:00');");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('eJzNGl1v2zjyPUD+A5uHtbz12tk+HRIUh1ya4rzXTRZNtr1FEBiMTNvKKpKOkuz6ur7ffjOkKPFLspLmPvyQ2ORwON8zHHLy/eHBeZptebRcFeTN8Y9/ItOkYDE5T3mWclpEaXJ4cHjwIQpZkrM5KZM546RYMXKW0RD+VTMj8onxHKDJm/ExCRDgqJo6Gp4eHmzTkjzSLUnSgpQ5AwxRThZRzAj7ErKsIFFCwvQxiyOahIxsomIldqlwjA8PfqswpPcFBWAK4Bn8WuhghBZILYHPqiiyk8lks9mMqaB0nPLlJJZw+eTD9Pzi8vriB6AWV/yaxCzPCWf/KCMObN5vCc2AmJDeA4kx3ZCUE7rkDOaKFInd8KiIkuWI5Omi2FDODg/mUV7w6L4sDDkp0oBfHQAkRRNydHZNptdH5C9n19Pr0eHB5+nNX69+vSGfzz5+PLu8mV5ck6uP5Pzq8t30Znp1Cb/ek7PL38jfppfvRoSBlGAX9iXjSD2QGKEE2RzEdc2Ysf0ileTkGQujRRQCU8mypEtGluma8QR4IRnjj1GOWsyBuPnhQRw9RoUwgtzlCDb5foLCW1MOklvcCFm9JV93pzi6KJMQV5KMp4CVTRMQGI2jfzIe8NHD8PDgq9QUmsJ4BhzAWn5qjj3A2AOM7QyMS1Z8TNPiF4k4SO81bJsVGBUOjTNQSqKAhnK2AsIPgAByB7AiYCf/cVaUPCFiC4cMtoZlsxxsFcyLB3OWo+3MQhrHDByioBwIbShTuL6S2dX9AwuL6bsTMjCRDEYE0Z9Ui8f3UTK3EA/Jro0U0DFYIqgpyNOShwy2QfvEr5f0sSZJDMuvONxQWK8ap0ngXTdmYBCSKj+umjSNOMk4ajiN12weNBui5YD0H1H1twMFMLirlIA2GyAMjdDlYJfyEfjMXWUKJOOszFdBDXVLo7uhqU5pVn+//vBeMoI+vg2a0ZFEVDHhMoBaMxjQEFZmPp7NQjDB+S/qJ6wKmI0Rd5foAtpgAxQhOLKgLRgALC0hLF+IAAmrwDgGahc1+VEggUkwJfKa/HR9dTnGIJMso8UWcNsbK5+p8LyHcZsbZZygE7XdQHfLagym8afhsBHkDp7QGKOAYeWKbAUArFRDJ2LpSAZ/BtI9IQsaY0JhnKc8r3/WAGd8CaO3dyOisJ2nZVKckOMRmZXZCUnKOCa7U+V1IqQH0tHywXB8gV8uQMSweIw+FZjEK5uR5I/nbBElDOQG0bGQxjIiR0bMOBo1lqgZJX7AL05ILf1gCHJRcUDuWmbDU7Ibmatyc9WaxqWKYC374CdaVKDk1VsphO++I2oX8laODd11HlT4mUzIZ8ionEHSJnGaLCH8Q8qCwmBFE/8SpMAUZm2oiibP/h004CeMGeXTx0c2j2jB2vArrfk+bSRJiloW7txhz1AjXiJEbyHTVux62RXE+pBHWZHyn1lB57SgTzCuvRaiTM91CkClSPH5BESeP8/eR4nM3+/Yfbn8GSIVlA+DoS35lzFml8T82SSOpG4cQj3KsUwF8uDgX1VSNoSsUSyWGNEJs5nKYV2YE7b5ACUhSxh/A5sEzS6CaZl7xddz4Peehr+7u08mIVRnaczGcbo0UA6qtRLNQIbTCWYJQYr8Db8GTWhtZushXWii0Gu8pplAv6/3wkjT5HKMQa/0DVVManZotW/cy2BfS9gjj9xtBUeLgL9664k6HnuTJEJWmEkn+YQWEzR8jAjvsB+BgW8hugs8nD1CUX0Wx0oXuYYJ4z0JKdR7JPiCCeGpeGQV0olnp2tnMvHpp8KC+ghMITdZvEojf/xB2iFEeh4Ou41Bkdyq6jpz7MkXHs358kNXVjC38eaAXQtxmXGY6KBJeAomBeuoYmDx0MYzLUSwL3U1VXAntSjCjCU9sm1LprWk6MXalmP9JLRm112rsHf7gopmtM+MKd8ST/7PPLxdUJAqi1iX0zcJ5vZOF8RO5bWxXTBbGa4SBwbxOrGpQyD35NHayxpi62r5VOdX13wVf06t2RqF6zvd6Ro/4sRZjbuHUoNUO2E0htmeSYYe57R04dIoz7Z7UdsWS5+3VBM2A+m20tkc0H3n85ZFXQxqh/c7X7ShvSDb3USsj1myLFboKG9QXzh2++OdLBSEArcZSxdBNT4UHpWKon2gwesHZe2k3K5U0ezgT8sJ9V7YYjBP3DZIsWJJYLVaRnbr4jlKri3HCArUFx8VZFBHIF/kqEtHJ2AgkakdMOTgywWMznjwAvGiCt46xH4/6RkAuqx+v28Y6VUV8z2tEYUdcG910lSJbfOyRkTn4d5KYV889K/Ck2VTsTQttVEj4dvjdgH0s+sOm1YtJn/emybYarfM2Z7zWDXqZV25emfANpQTrJv4tX5yaJpMiAgfw8p7wA+oatBhB5lsGEmqu4+KgImUNYkKK8oZZ9zQPELpxuU0Sp3Coeoz91njJD4fGZVj9idDRp7nktE3voq2Xf/jjldXSZr8oPqyMlW1qE1c4ChIcctmK7C26PaGdh6s95yFTYb3cjKP5smgUO0pmmyBAHm3hiw8lHmBNGd0CY4uOBD9nJwsgCbxW1xOxVtxiSXpbGHqf2iSblViBBBZ5zexQnSD/OGBF/64bcdrXnQdDSFX2oc+H/zQTaUdrmXdicmYKjgZ41/nzKBfzCyweRdv9XjZIgQvFSo8P4MIXQ9okgYJejFVVVHeUkTB7cnqHeHRS3eN1k+7ZVmSEINMDyGePr3vhOhZWZvgfgtsNgu8+fubWxQ9OxQ7H67O6PUsI6+l3ktPOgXy/rz4JDo9CdvYl3TazbmOTS4xb6+bI4KnTO5WtlsS3OAbjTpX0JzQmDM635LGIyBAA56cgBzC33EnDMYrmsxjxj21hHsg4nWpo1WO/YoeyVvA131bvAJ4f23UgUGIfd0m8hboDoevVNiWZ+xpt+XSa7vabj3b6SXO07bzXIa5Wb9Ljq28i8sdexqod4oODxnPqUP2heUX1dK+2PJiOvI3Qfaf9PeV7+0HHW874D/NqnukMwsyfFQkEJmRE2JLtYFeBFRlAN86CV57L9FcPrZJRC8TG/I90M4Bw60eK91VXWDPOyY7eHa1OTwZoD+kan2wu3ZgeVDWU6VzlraBnVO1UgOE61d78pZxD0quKZxvOFswiM4hk08DIYPJ85CufflU7dZCPlvRfHWezlkwvHOSUjsXdvHpvY+3HG3OkAubEm1/3cAtS+h8PlAL6Gik79n+UMButBhvUzxy910EtPXzbMkEXbfofS4ALWKfcvG359LP7Yw94fJO3sKJ7pb31qwvA73u3HretRkMVeZmHlvL7HQPhBFH9wBnNZQfrn27p2yje+EL3MV96z2cdQcmZK76AKrf4jb/rPeP3spfO32OyIPYUhmC3m12Hkrueyfp6xE7ryTb6x3ZKHVLM71p2rwxUtkVM2sjFtE1NKQinkEOyX9JJi8hjipvf7s4oJLQZYGFRWXqaIeOobRLhMkTaFt5MNPuVuCrk83qe1kxn7vzGlUAov1yQedpwtruZcHZ8a0mTB8rITfpw9SYKQeLK20SFCbvvvrkN6wSyhAf2TrnyNevQcANgaJsNBmvLg57PbNr5NDydEPC1NfhzmZd5bxeZICtdbL7nkZxyZnD7quGyJdlqLquQ7o6WLB8DFOoK2nUwrGrfEt0HqFZr/fhv3K8w4PHdF7GbMy+ZCkvMGI0mcecGpttHvUWrR5oW1C/wq9X1CPuEijjaBkX2OLRA4E23Ph2k6tUakFXVWNVXEXvJrt/A1nU8Oc=', 'base64'), '2021-08-23T14:25:14.000-07:00');");

	// util-agentlog, used to parse agent error logs. Refer to modules/util-agentlog.js
	duk_peval_string_noresult(ctx, "addCompressedModule('util-agentlog', Buffer.from('eJyVWG1v2kgQ/o7Ef5hUVbELMRCdTjpSWnFJqkOXJlVIr6qAVotZw7Z+O++6kKvy32/WaxuvX0KbDzHYM88+8z6m/7LdugjCh4httgLOBmdDmPqCunARRGEQEcECv91qt66ZTX1O1xD7axqB2FKYhMTGS/qkB//QiKM0nFkDMKTAs/TRM/O83XoIYvDIA/iBgJhTRGAcHOZSoHubhgKYD3bghS4jvk1hx8Q2OSXFsNqtTylCsBIEhQmKh/jNKYoBEZIt4N9WiHDU7+92O4skTK0g2vRdJcf719OLq5vZ1SmylRoffJdyDhH9N2YRmrl6ABIiGZuskKJLdhBEQDYRxWcikGR3ERPM3/SAB47YkYi2W2vGRcRWsdD8lFFDe4sC6Cniw7PJDKazZ/DnZDad9dqtj9P7v24/3MPHyd3d5OZ+ejWD2zu4uL25nN5Pb2/w21uY3HyCv6c3lz2g6CU8he7DSLJHikx6kK7RXTNKteOdQNHhIbWZw2w0yt/EZENhE3ynkY+2QEgjj3EZRY7k1u2WyzwmkiTgVYvwkJd96bx2y4l9W0pBSCJOr5lPDeqL6MFst36ocHwnqEu5gDEkTyyPCHtr9D8v5tbLd4tlXyaJFGQOZk8iOAY/dl1T3U5h5F8dDKJ0YfwarO5oPjj9Y9ktIGqoJxpqCVn+9fvwkfnrYMfhIiJ8C1fyHF1GGpPk7jghMx8sLR6vZGz9jTE0M1LGmxNkZVpd4814ZGp8MhQXXVVAOSiOTGUHqi6Wz+uVHb9WdTFXR6I/lJ6uKV2RkM9cAT+SarQwh2JXcCuk9JthWg6CSzkJjpZ5hnkOj1WoxIIjUC5CSTmEqsVAQ46RkaY6fhmg8JG6nDYGtTbz5gtr0V9a3YWxMGExH+ylx8mpMzl9K/PnecXnTyRRzZlpMmExxPs0lWaC2N9Ub/MD4A/eKnB5VStlWxtZnWVTdvwE2wbGuWZNEPg+L8qGMEkJmFeDnFtWq2PFPt8yRxipxXXWlABLX/XgN5jW1H66Xwou/TH8/bEu9sovCcOT8a+5s5QE08sG3zRF/YtZ4vdU1BOkGi9vD9A/5d3j9YPMPmOHWfS7edOtK5lmlx2vl5rWq0Ab8vNoejZnZ634scQs4dT2pYiKOPJTxfS+Huq8Q8uevl6nD4oTpafuuNTfYOs4HWY8pIKN8uu1xXHuC6MDneIzeYg9Hy6zp6NOccra87Ol9Fjn/btO4jHkggrJCMcl0Egshi4Mz86Vy5PnYzj7rSA9QG8e8iWxAO9eEkGtBAhPQbkudO47+F9YXwPmJ0SKPD2+ybPrYHbBZjObQAedrUyQsVQt1HKlkLW1IlE5aVorUkB5KQ30Xn4ziwAMi6mg6EsmByWpkYl34axkQJoHh7ZV5aEbVllnkgMqZVUqqTpiZSqlYyXgeSWRtQC7gUTFDBjBOyK2luMGQWSsoQ/DwWBg9sAbJSc/NrkedRHDyrx9foDH+r/YUpyRclt9i8tHX+6Sct3eUJ9GcmvFw+mhLaSVVHRW3o1gYagPvXQlNKtLZmM2SIKeXFvktZSUh0yo8aVUcKp9/LPaAhUTJKL3YankHtsDq/Y814ByL+q9LOZbA/Elx0dtV48oWV8Hmy9rIoixih2HRvq+Llc22TLVM0sEM+UDzYvyLCWALzXFCKfKukBX3c9bcCaVXLM2tfC1LsbyBimzwmCq6zB4pZZPXqxKOIdul1XDmb+XWDZx3YR1Tx06Z0uz7MBsr82hsesNfwlUnxW6D7Qie6oTlNUUdNnmQvhr43u1N0IsUz20OJXULEwzJqunwulSTIYmfSc2Og7vmJaNqILeITQmAyWewi7Y2mSoepZmZQIrtCcBjgWZiZ2elphmRd2jRvnNrj4DizAqQhiegyi+zlS5Fie3PM7Dd+OJ617ji7tsQDzlqLGqDaidVPB/etLkCaaWAjDw2liXhh0xgT2P9KAav2D1ldqpH4tRzjYgeANGGAU25dyie2q/l406LS95AyOpJnFHTviOhQ0CP42gGM1SnhRq/iGkgVwgUoJmskWoBtmpeV8v7nClCZUsDEqztDZk2KUxld1H6eLwSSHSEVQdYNWQlMiUB12znX7srWhUYycO5ZzdK0XkqV8Z7lQOyB9UXIKjaL/fJ5ON0dIroYpBGnGLy5+wjOxb3gaMw9mvQX9qYjKU5Ee5H80GZz35On1gnxJGK4gAElHw6S75lYj40qBqsFkpnuWWXiL64kV2B/u0JeDVOGeuOj3W+eNxd7EaK5/qvBpGeTrUFa8XrGOXYmWFQZSUpWo/o6w8VVO72o8O9aoA/wcoVbbr', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('win-registry', Buffer.from('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', 'base64'), '2022-07-25T09:31:37.000-07:00');");

	// Adding PE_Parser, since it is very userful for windows.. Refer to /modules/PE_Parser.js to see a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('PE_Parser', Buffer.from('eJytV0tz2kgQvlPFf+j1RSjL8rJCEVM+EOxUqPWCC4FTOQ7SCKYsZrSjkTGbyn/fHkkIiad2KzogNNPzdffXL6n5oVoZimAr2XKloNNq92DEFfVhKGQgJFFM8GqlWnliDuUhdSHiLpWgVhQGAXHwlu7U4YXKEKWh02hBTQvcpFs3Zr9a2YoI1mQLXCiIQooILASP+RTou0MDBYyDI9aBzwh3KGyYWsVaUoxGtfI9RRALRVCYoHiAT15eDIjS1gJeK6WCu2Zzs9k0SGxpQ8hl00/kwubTaPg4th//QGv1iTn3aRiCpH9HTKKbiy2QAI1xyAJN9MkGhASylBT3lNDGbiRTjC/rEApPbYik1YrLQiXZIlIFnnamob95AWSKcLgZ2DCyb+DzwB7Z9Wrl22j2dTKfwbfBdDoYz0aPNkymMJyMH0az0WSMT19gMP4Of47GD3WgyBJqoe+B1NajiUwzSF2ky6a0oN4TiTlhQB3mMQed4suILCksxRuVHH2BgMo1C3UUQzTOrVZ8tmYqToLw2CNU8qGpyWs2YUpVJDnygmrW8QEgCxGpJM70nTqR0lRWK17EnXg/IDKkNdx6JmplVis/kri9EYlhUC/Eh3v48bO/X/VCXEkjVDO80DDzmy5uemFDBJTbW+7sgOtgyEVBcrFVNJxS4ubWXBF+xRX07x4+R55HZYP4vnBqXSt/lKvTUp2ClAhSsf4uF2OCiBuT9zCxYRVvJ3uZOYn9Ev/F9ntufW9WHVp16Fp42yliHtSy7fjUHAu33X16rLXMhhI2Jhpf1tpd/TAPMLJDgnSb8Ns9GB8H1oNhJkAp7fpSKyk2UDMiLqkjlpz9oyuBcSK3kMQ1I/LnKdfGs9Ke7ZiMHds9NHzKlzpkx47ddtCxbsvMu58dC3VV1xDIynlurOi7kbrbsj628Lrgsm5LBJ4f45aU91LfQuxGziqnsEC3VaT7WIeDxIPRthzjTtN120FO1X5bX0nCNxKSkS7jvdc1+kWZBWp97R/C9rpdK8HtWmVwUfoKrks9EvkqxpzzVy42/DKobgwe49S9AJzlS3oYawR7APETQm3MNAQ6zW8ny/mzZweuGzfA+wuZA7/jeDtZkTu8QvJmRXxY62eN3Fl5Ke0z1Djvs6cSia/NL/aiaD19GRzQX+BpuKLOqx2tn8V1Ziz86VpFnjWzE28oXB2bva2F45Z56syI42wkvu4fD0SR88d7J4/PeWmAdsfM3N6V6bHo9bZ4tmpbn/NVm3bDYp5nkThj46eO2T9ZQUMqlR7FRNGZHo77ND7rba8kVFpR53Buy5qkccrmD6KeBpVvxFZEqrJlqsE+dUu1v84uPkn3+1/xabfKsno9QJb1awJk/ZdAlw6Q1ft1AWq3D6N9bpAUpXYTNx0tgPoj/XaKbSx+R53suvFfZMmcOzBQ15mea12s6MvTqOj9ENXrUZakStZR9FvG5VQ47hv5yUIi/OWKObqHOnsEbP3cx28Xnqxiy9KP+oTHZKgAz8itucfU/X7lHo2iQo4cjhqUj4cM3rPxcsWXHFoqmbP5ULnGLeRGy7xkzjFgbN3xckljMSv2nl21/ISa/YviAvMFX4sugzxsnmJVCHbC82Jeoe+OL0KaOp+bcfobKc0ovRq/Fa2FG/m0gR9xQipde/GHUZyD1cq/OIedMw==', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-authenticode-opus', Buffer.from('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', 'base64'), '2022-02-08T13:23:45.000-08:00');");

	// Windows Message Pump, refer to modules/win-message-pump.js
	char *_winuserconsent = ILibMemory_Allocate(53869, 0, NULL, NULL);
	memcpy_s(_winuserconsent + 0, 53868, "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", 16000);
	memcpy_s(_winuserconsent + 16000, 37868, "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", 16000);
	memcpy_s(_winuserconsent + 32000, 21868, "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", 16000);
	memcpy_s(_winuserconsent + 48000, 5868, "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", 5868);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-userconsent", _winuserconsent, "2022-04-22T11:03:23.000-07:00");
	free(_winuserconsent);

	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('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', 'base64'), '2022-04-22T11:58:23.000-07:00');");
	duk_peval_string_noresult(ctx, "addCompressedModule('win-console', Buffer.from('eJytWFtv4kgWfkfiP5zNw2B6aXMJyWYSRSs6mMRaLhEmHfW+IMcUuHaMy1MummTS+e97qmzANwLRxIoUXHWu37nUKde/lEs3LHjhdOEKaDWaF19bjVYDTF8QD24YDxi3BWV+uVQu9alD/JDMYOXPCAfhEugEtoP/4p0afCc8RGpo6Q3QJMFJvHVSvSqXXtgKlvYL+EzAKiQogYYwpx4B8uyQQAD1wWHLwKO27xBYU+EqLbEMvVz6EUtgT8JGYhvJA3ybJ8nAFtJawMcVIris19frtW4rS3XGF3UvogvrffPGGFrGV7RWcjz4HglD4OTPFeXo5tML2AEa49hPaKJnr4FxsBec4J5g0tg1p4L6ixqEbC7WNifl0oyGgtOnlUjhtDEN/U0SIFK2DycdC0zrBL51LNOqlUuP5uRu9DCBx8543BlOTMOC0RhuRsOuOTFHQ3zrQWf4A/5jDrs1IIgSaiHPAZfWo4lUIkhmCJdFSEr9nEXmhAFx6Jw66JS/WNkLAgv2k3AffYGA8CUNZRRDNG5WLnl0SYVKgjDvESr5Upfg/bQ5TLj9YjrM73n2IoTrKAav0T/5DM3edGBYVufWuITGcyN6mrU0hYmeJrZbme2JeZ/YbWd2rUlnkhR+kRU+7I12281GZvv2wezutlvZ7bHR6U/MQUJBO0ti3Y0eUyZeSIokzWDa6SaUNNISBtPBqGv2fuwFaDDtGn0j5WQrQ2AZk97o5sFKkJzmSb4bY8tMQd2OaN6uonAORxM0RIZjGtNO23AN7Xh7gOmGqTN5CQgGG17hET27V55fSK/k+4NljJWCdqOh5M5XviNTCR6pP2Pr8AazinlEq5ZLcaLQOWgBZw5K1wPPFpizS7i+hsqa+qetSjWXVbKL6NPR0/+II8wuRJRfnUhw5SpLOLB56Noe0sWFrlWmt8QnnDrxVqWaY/oDi4N4py3kSknRbzixBRliefwk95w9v2gnG1p95nkneVHY+PhxgiLKPWK2WiLGAREum2knt0TEkEYAH81ZkZwrzokvJi5uzApQiA1Ka7Rctt6rq5Cjz+yZucTU6RzJ8QpL9eMSpJVx3nUqNWSRlnZpGNjCcS+hCW95iaFLvONCV7EiUgl5gfuxoAxuimc6ZILOVfPrKM4sr4utFA+R62wMsvHScmqX1McG/Jfk3RaPVk0WQA68XUi0pPYanCelv2U14fkhGP8URb+/q8ils0/R0nhXS4hsn6HlLKslH10PM5pi7FPqqEzxe1u4Ob2ye7rbXIj176pCa9QKU/W7zakcRRKSa9BEGKK/7ZkGv+IX2Ya3L/Ksql5BvQ798bQ/6nR749GgZ/YNpMAV664zNrrR767R6zz0J5b5XyNtOCdixdE1Nw9JChCLiM0skIQksayxQE0U1R1nAUgzW9h76nYLRnrznlEcXbmlCgbPKvg3nDUu4BLOWhdJo+VTr8eHhO6xhVbBsWzlCAijWqvAP5V6LHtcOMA64copdeTFA46ca9GQWFLsrR4tZqUpPYJ9W83nhGtVXY6V5AFn8NNW39B2VsQZn8dJIKryHEZtqRlMjwcmDGt+PTY0LS1tKMpLnvJ6dMKjP80iD7qEk/nheDTPMRytdg3a1f1O5wFLK5RTwj82RD77ZnseYz5W2g6LX0VgyPnvCt6KxG2kyUKuprdfIfOkt+VzQC0OUVd5JtUI4ir5CIR4Q7uE01a2TSQosymWjK10UA8i2i388iKlKVsSQclKyeF2lNFfoPV+sJuFBXFsOrVkOjXe17CJzt9R1FaJ2z494EzR1FxcteFfExp8NPJtaQN628z3s0im6c/ZB4U2z2U+Nf91XoPW2fl+sRMq1AzzIdRUrrZPUfZ5AQ7JwlN4yBKOkNXnnC0zm1Gaqt+pNJWZuV+stH2/XLW7ESxfPihZofK++IgkqUOt5BQVZUncgO9XyyB5Z5F3nGW09TXAvUo2bHhWf1fXnFfYXo5wgE7fu/RNq8JhOqHoEnyyTi5sj+vUmLUxMVJl/MS7Q5i0kaiVSlWnvov3KxFqEWWxqRG/7qjjXb3gwcrsUNx41PmDzPZ4WMQmPbqTXzQ+wKNU4VVCfvzYq0wfRTiglzEixWQJ6PTEJBTtHmaJbhPdaPqR1XaYJR3XeGg6zIaTWIU8U4Hx345pzDdwRXPYTKV1atJRaSi3FUSqGlQL2DipTuDkAt4qlhgJTSZ4+nb2jkXu2p+lLbrDFRw7M8dy/ozLDGa3TMDd47CbC6d8NjUqtSFgbgGJW3xOKg93QUr2wkx9FbXG+Ng+grKaOYvzBtI9ajd31dztVMsOJ+pzVGzSzqWqrprHNU6ceaUFuEfYg8XkTV1+RlxjUcGaM3+RJ8601GOzIm536cSIHY9ptWW4OJwkCBrS6bE86WU6ZUfp4fNoANQ4p26NMp/mtheSgpyKLABlwjqwua0+bzXht99ALnm7pUbr9wLl7xggn7QrZEkPtdHks7MeL0P7jH/7Gz6dNVuf49L+Fv+Z/hTnxVN02xj53svGw4zTWi6SF/DrV1F8PzHA+w+v/ezb7vz5GB5Z5ZEFyc8EG5sO1rFyZf8h+LEuGH1Vr+WFJppigfM58lCwoBDPGfGIIHmGjSnHs2RvZXlg1Vea4mEr/8UMA6VmzyWbrRA18hwwrgY5OQRmv9Nf/R+GdORq', 'base64'));");
	char *_windialog = ILibMemory_Allocate(39145, 0, NULL, NULL);
	memcpy_s(_windialog + 0, 39144, "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", 16000);
	memcpy_s(_windialog + 16000, 23144, "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", 16000);
	memcpy_s(_windialog + 32000, 7144, "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", 7144);
	ILibDuktape_AddCompressedModuleEx(ctx, "win-dialog", _windialog, "2022-04-20T10:46:39.000-07:00");
	free(_windialog);


	// Windows Cert Store, refer to modules/win-certstore.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-certstore', Buffer.from('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', 'base64'));");

	// win-bcd is used to configure booting in Safe-Mode. refer to modules/win-bcd.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-bcd', Buffer.from('eJzVV21v2zYQ/m7A/+HmD5XcqkqXFQPmIBi8xG2NJHYXpQ2COAho6SyzkUmXovyywP99R73Y8lvbtWix8oNFkce755473dEHT6uVEzmeKx4ONRy++PUPaAuNEZxINZaKaS5FtVKtnHMfRYwBJCJABXqI0Bwznx75jgPvUcUkDYfuC7CNQC3fqtWPqpW5TGDE5iCkhiRG0sBjGPAIAWc+jjVwAb4cjSPOhI8w5XqYWsl1uNXKTa5B9jUjYUbiY3oblMWAaYMWaAy1HjcODqbTqctSpK5U4UGUycUH5+2TVsdrPSe05sQ7EWEcg8KPCVfkZn8ObExgfNYniBGbglTAQoW0p6UBO1VccxE6EMuBnjKF1UrAY614P9FrPBXQyN+yADHFBNSaHrS9GvzV9NqeU61ct6/edN9dwXXz8rLZuWq3POhewkm3c9q+anc79PYKmp0bOGt3Th1AYoms4GysDHqCyA2DGBBdHuKa+YHM4MRj9PmA++SUCBMWIoRygkqQLzBGNeKxiWJM4IJqJeIjrtMkiLc9IiNPDwx5g0T4RgZC1Gc4j+16tfKYRWHCFJGq4RgeF0fZkj/kUUALOde2lS7cj5X0yQmr7uIM/VeUGXa+5KKY3FpTLgKurDt4BrVez5vHGke/HfZ6fT/AgGtzqubArZW/Ww5YByiSkZk8+olSKPTCuquXUbixDmSi6aEIkGUdrS9LYVsB04xULF20/To8ptmbnnp2DL6rpUdhFaFdP4LFlgFUarcmo2hDfMq4bs24ts3yisGIC4wJ4SZol8yO7LobU9C1bfVUT1iFwvSMGw/5wGjbeC2Um6SwjQVuUjqVqWc7efwKBFo+UMgJQipzy+8Km7A0WIg+4JzksgMlg2WRCYsSXAl9kFykmnJ/StKUO7ek8I6E00P51iJ70G6iiEl6mkOLrVS06ewqGQvxNHrLXE31bx6Pl8edzPB6Sv/AHCYk6ynswArVz5TOZXoDjFDjVoB+MLUZipTIHRT/ZNyW2EVhupbHBnghA/RQTahg23H27LARlj+JnGXi77nC0DSoOZF8Td0tjc8+gTdnrRv3XPosuqDmSkWBCPRuvKvWRa93kvF4IoVWMvJQ01I2p8gQqr6UtNRBPZXqodezKGYlcA6IJIqMumzN2kweHn+Ra1nrCcuptO7D0Uouq1mPlJcDlkS6AZaQAi0oehbJ024mRQrcvxNU84ye8DtSYZIEfKb9IdgfHzDNgvVSRpDcHDQcH+/njG4eX5wT5OxWD9iXBqfLD/nHJ0p9vRmkPNmz9f612Pw26KKkmdI2ffvs+1aeeJhQbZiKZekpFtLao9JfU4dSJL8cm6T/M52XikTDevG/urKkmny6DcoI3UiGdllT/eizJYoPYJUo969RoOL+BVPxkEVE8Fu6CGhUHv8HTTa/hCdPVtGQJgRMUYzraarPfn9prQI4kkFCmOgqLJWmi8pWBu8sio3dy87q2O4Pp7Fn3Snyq1FMnO1y1dheypM1owmjGD/j14ZvZuT3mUYxcfI7TCN/Oqum21hNna/l5Wu4CXNAYQ7oW7gq+Mreuv0P6GtTCanAvFWS/sjoub3OnQM1U0+MpprzKRob5ca7vrshvFYtPyNnRnr33d+Qym3lexXT7tg4ZopPNnuf3n7KV+7yiOl/uGk+k/ru/T1+muEz+tN52NgvYEbRxiyv+ap1f9E9bd13WlfX3cuzvZCK0VfIHj4hU7Ty/wrgmwwvdi8XVia7dO84k7f82Q7W9zC+9KPTvbxonu90YsNQ6TWt24t/ATXtbrU=', 'base64'));");

	// win-dispatcher a helper to run JavaScript as a particular user. Refer to modules/win-dispatcher.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-dispatcher', Buffer.from('eJztWW1v4kgS/o7Ef+hFI9nsEkOyo5WW3NyJIcwutxkYYXKjUYgiYzfgjOn22k1INMt/v6ru9huYl8zMSvfh/CGxu6urq6ueemuaP1YrXR4+R/58IchF6/xX0meCBqTLo5BHjvA5q1aqlWvfpSymHlkxj0ZELCjphI4L//RMg/yHRjFQkwurRUwkqOmpWv2yWnnmK7J0ngnjgqxiChz8mMz8gBL65NJQEJ8Rly/DwHeYS8naFwu5i+ZhVSufNAc+FQ4QO0AewtcsT0YcgdISeBZChO1mc71eW46U1OLRvBkourh53e/2BnbvDKTFFTcsoHFMIvrnyo/gmNNn4oQgjOtMQcTAWRMeEWceUZgTHIVdR77w2bxBYj4Tayei1YrnxyLypytR0FMiGpw3TwCachipdWzSt2vkbcfu241q5WN//PvwZkw+dkajzmDc79lkOCLd4eCqP+4PB/D1jnQGn8gf/cFVg1DQEuxCn8IIpQcRfdQg9UBdNqWF7WdciROH1PVnvguHYvOVM6dkzh9pxOAsJKTR0o/RijEI51Urgb/0hQRBvHsi2OTHJiqvWpmtmItUeMLQEe7C5KFcVa9Wvih7+DNi/qBHyV9/keTdWnJvBcovjAUOMFyUDGnq0hkqFtwrm3GieVwnX0D2iK+JafTZoxP4HvngRA6sAtwa9UuySZDz6IAeQxf9YE6jbCyigrwBNpp7O3khm0tFpNFjGvSRMgFMrR6+9ECHsInlOkFgApMGEdGK1i03oo6gksQ0XM4YlTo00F0ShsK6B1Fg25Q3o8JI1to0AtOZIHxCaYWARCbkAnFZ5HJxOpuLQ3wszkDegMfUaJDU8iZqeFPf3vMYsSJfLzASmFIvakSjRiIntUX+ACJABc8poxCl6AjgypeazDTOW60W7Gf8Co+RyJSX64MD8eUNMSbwWJNJ6Id0MhFO/HlEPWAvpTwzyE+5zXNcsjcRPWcfOZkL+grA7SkzvxBwjUW7IENDxhEMMp0gaEtgZErcZnRxiBPIanSNk/hNweqfc2Ob7NVF5yXmU730VJpwk/kExDNQ49vVbAYAn0V8adZSC619dgawjnlAwVIL36MAscJsEi1ohFhUHmAatYLa4aMGJqzVLcFtiJ5sbhpTJ6a/vDbKwObSgi/lMMdZV+8Q72IM05HGvHUP60XEAzhYfHmYxLpP/QSnt6kl7s36HiY+e+SfKSzN3ELFsAaREWsvsFDxQLTINA+Rhbvm621De1u2+bc9HFixVKI/ewYYQcZdgue0iaGEAX1BaFzRNrinkqVN8jK15V+yAUxt77WwEHn0Bsz288V1z/SsgLK5xOWOXFILqQ7lOnNxCpGXJ9rk3mMZZyjzyqIMaTbJ1ZAMhmNy1bvujXuq+gh8RjWgt5H0vYAEuViCYz+OJMWLYXQSAmLLo7Eb+aHg0XsqHM8RDsa8oudBlAQT5YUqz7gQXqxjlCoDA6VZN9LYjg8WHyYKvcTSqYyFrgL2g/4FWHY8771kl4czg1TfPrT17fLOQqIGeYiPEiq9frMjxPvAH5cCPnt9gTaUcfKqiKFGFOVH1JaUFP/C7NGeOQFW9+rsBxcpkkYaOI4iJYkpBwhLw82pGi7Vbqlm8xJQKNe2XD9OaHMlS5r5vxTdEpobTIlsFQTbDsuX2LjszPmzpFq21GJFsd8VsJRO8yguOYOORlbtsiISHyLuwsBwDbXRABBthmrACn0P0mgMpS/s0aoXuW5tgo8+i2F/sse990aRYFP8pACTowxlac1mPF/IvfQAl3vlRM7ShUtIUuVLIvW1RbYh+coud7zi0UqSsYDUCX3AG5K3o3IiE0pMY1tmsLhaooH7w5uLtD8xMRXL9kSeCiLn0oFS/XJL3frIis3t+d125k+Oqwlad8U4UkQmFr6ytVFB0nhP48UNbDCGcYA/7tWWfxuacVv/hxb0icrys00SGyUj0rtXS+yE2uTWOJv+8hqnZLqBSHVXyN+FshDFQSRAHEcJTPyuHyMG2Eji8kOA51rRiplH2Xg0gI5Qcipy2OoiVhFDJxRpZFD/ZP1sPj3tFga6ErYQf+dIkS3MymmUIukq0R6UPWLAvhegSirKdHyvQuiOemFGmc2o4UghwPwkBzepAdLs7J5TzM/pLuyxpMDJRESCW1hzB7Lm1sihstO50OV5edeXA/d6KSgfD/AOOkEzzw3NAz2ZcYdyTyb2M7RAy58vJpOPMM7X8Qe+ppG9oEEwmTyeWy3o5nAkxhHkCAC+NbIhbAvPGIcd8PZJfwV8zuWrTpvy3bhr5E+bGEwKDbnWo1Ekq06sqwplp1tohVN6vhIvoveZTlWG3f193LH/sEmzO+p1oH5tviPN8YDkAUqadpcMB12YtMek1Wq3WiQFLWaMPARK4Lm7a3N0Q14hAiWSMmYa6llUzPfq3z01bYVbKOWvuesECgbFuT1nUNmLGCWl1GavypvjEamp0yvn06pAd6tNogkzDtjrlUD3HdD12XD6AFUEOevypX61oejGOskC5Tz6Lj2BV9oa108gnvHAk6kBF4Lc6tusTSa1E5arRJCysX7TUbWWh9qJjDw6k7zg1bqiM5/5CMBTl1o2FXjBGlu24GF/9huHjyF76+Bdmk9Rwa9kbfpyhld+jO3S2gbLiv7sm5h2XOVVfUCjeV639MVSHjlfzauT5M+UIaLvZAxYIzrH+yJps8wAprLIQLY6yd4N8ho+sOws/sssfUJwGt0MdsLSMWmz1bo1LwltyIM++aJUlrXjix5MmoVr03x63hRuqBNfgi4/u5zWV74vuRXUR5oHfOoEFt4+dZNuv/SStZs2FOn1XeHmjmwKNxflFwt70sfB4tS9plgIuhaI4aU9U2u3JgVOSPpPIFVl6fEGQQq1YvHCnwmQo6TuVrbYrrRLpFxiZSDbWOjDYmq6Vow/1piASxQrd/2303HHa1/eWgIPSyfw46K7TkzTa6/27jw+2rhYoTw9w+7UWd7iJrKT1k3snYU/FD2bJbQNkhHLG70S/eCzfR+rVbTHPv/I7CN7hrwFtM6kwtRPGim/QgubOxyA8KuBeypky+//s2JWem/xnvr/cP874J7djO1BfEpgZtBVl2LZ98OLgJxtri+i9uyMWuHThxwKc54mRdq3a4nnYSs+fdjrqzB3qm9KnKSUsqWvl1OWKP2AhBZ2A5hgTARVQ/Z6XpvI4mP3F5v8o+6qcGUZW+zJT+e1T7B9l+kHXTb/bMqHdy+JvlJ7319z36y2v0llaSD8Jub/GylGnSOKeHT6SXYKrJcykcdUEQQmQh4JdbeS/ATSTt8aSXHYTl7kFUm18l9WVyC9', 'base64'), '2022-07-25T09:30:24.000-07:00');");

	// win-firewall is a helper to Modify Windows Firewall Filters. Refer to modules/win-firewall.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-firewall', Buffer.from('eJztPG1z2kjS313l/zBJ1S1ig2SMiZPY59tHCLBVMYID7GRra8slwwBKQOIkYewn6/9+M6OX6dELLzbO5qqiDzaa6e7p7unpnulpOPh1f09z5g+uNZ74qFKulGXy5xDpto+nSHPcueOavuXY+3v/Zy78ieOimvtg2qjr4P29/b1La4BtDw/Rwh5iF/kTjNS5OSD/wp4SusauRwigilJGEgV4HXa9Lp7u7z04CzQzH5Dt+GjhYULB8tDImmKE7wd47iPLRgNnNp9apj3AaGn5EzZKSEPZ3/s9pODc+iYBNgn4nLyNIBgyfcotIs/E9+cnBwfL5VIxGaeK444PpgGcd3Cpaw2j15AJtxTjyp5iz0Mu/s/CcomYtw/InBNmBuYtYXFqLhHRiDl2MenzHcrs0rV8yx6XkOeM/KXpEjUNLc93rduFL+gpYo3ICwGIpoh6X6s9pPdeo5ra03ul/b1Pev+ifdVHn9RuVzX6eqOH2l2ktY263tfbBnlrItX4HX3UjXoJYaIlMgq+n7uUe8KiRTWIh0RdPYyF4UdOwI43xwNrZA2IUPZ4YY4xGjt32LWJLGiO3Znl0Vn0CHPD/b2pNbN8ZhdeWiIyyK8HVHkD0u2j8xY6ixQoFW7OsY1da9AyXW9iTgvUBu5MF7WnWF34BPK8pWguNn1sEPp3uOM69w9SIeg+qijDaYATNISgLUwscygVrk2XmImvTbHpMqiIh/HCGnY/dRdkzs7Q628V7W1Nqx415KOj4w9yVTs6ktVaWZNrjQ/V4w/H796pzerj69MIW7vs6fUbA/vNZcchc/9QYVQaldqR9uFdUz5WG4dy9VDV5PeH71S5edz8UDk8Pq6/q9ezqTyVEZ0Q0FN8fHh/VHlbrr6TteN3lI93Vfl9/f2hXG80tfpRs3x0+P44SaRhL2bXalcntsRolMtk6VfLVZl8KAd/tOhT8FRTNKAohW9qs3JUrlfeyTW1psrVRrUiq1qjLjffVqrNSkVrao3KYwHMyZX91XaWdnNhDwJDOkN/FP69wO4DdT7uyBzgQgkV1OGwi0f0UxeTefVw4c+YjSYxqaU5nQo0gmWeohQ2R+TC14hm9H6O/f7DHOv2yNGche1ndcA2ve61R4Y5w17cqtt3zldOcYz9G23hutj2iS1Tz0bpeEJ/JEfDpm5lGPfNF/l9FK9xP5guhngYi+kJqCu6KXZt6gy+qtOpbt8SUYd91xyR9S9QWANCqRiOT91G4AzqlpeWYDUEpXFlk27P72Jv7lAv3Hdai6nP2mquYw7ph0zST0KkI1KzFbXRw+4d8V+EFHHFzJri7kD1FOXcdRZzPtNe3JacHUrGcfGlMzCn0QzW8cgk3InDho2hglVxYCriSgBAob3w15DIgaA0gCShrU4fsgyOyRP4npYztEYPPRIFcGF/j69JptkffkEKpAgLYPwZCXsc18czAZM48CV1noLMzJsGsWd3khv4nrPY+2rNoXFh3qVNHTs9BT/GDNC2/FmgQKKngA2BbXsD15pnWHS6ncKrwd6Mtge0AAMUL9WfdgApprLaKTzx5r4zcKYCcKoRrBrXF91zRjNzTcQCfZwGz2qPqZM5pFs9nDFCuouPko2W18c8xWA2ZwFMtYeaM0xg5vey2SSOMMM7pVrZONkhLSeUxc1ibBUw0mE3K9xmeT3mF8k+WABMNYY2QSO8l7QJsZGNPRxjEk7JDtszRRPK7mHWnVZe2BSsfhRYe+AE5qElGovZLSEF3MBFu9Pu9LmL01od/nIOXs7PQUfnrsq9EcfuaxxGq/H2BsQFn2s1Q+5qmtxqG9zTXXdkXY9fO1ccXO2eX/U40ZYG0D4bDT6edqG2OeBVnZNoXX2OP9c1Q241VA54AcTtdFuAdk/WAZF+98r4KB8m3ivx+2VDbYJu9sp7u4CS3u2Dl15b7ne4YolEtUsuVKvZkI0eEKXR1fuybnSAQED/Rx2NU653ulwaMGQd8kKAZK0FevudN2949yWc/mM+/fWuYBjHctchZ1exqemaYzAQwOj2roGNdRuctR5nuWaofNqBCtQLTlQ2LkFP75Pe4bQMFYzYatf0S97XF9A+6glhxAVBWwzHALGYNbXnwA1zK2wCXfIh1L7c+NxRP8YtH7u/d/rtS5Ubc/e6DgYAEylQgavmWu+pAEW75lx0jM/g5aIWv3zqcfwOmIVaV06S710ZssF5+lQTesmrKBG1ZKDIa2hUvYZ21W3IQtu1bjT4MuzDNdHp83Vo9JpkTcjQg9TB577W5Fain4Mpb/c6TYjVm7uWj+Uu0OylYCKAA/WzUnkL+AFytXSw3nrEjwFLavQvyPoE74amZljDORxKb0IHZBjAC+pcC+Sg3gOjdvjLv8FMqwcGYFpzZnzH2AMug3aY/5E7GLsA/LNs2cIEdoFyOuettByXFcGrcD50Fc49/AxIXvW5qD2ggx4fqSM4Sr2HaD4KCYGoqQP3oUHPqnVhDOj1tHanpTWAwMDN9oBCO9CJ9DRAsckth3owuVFpELs02oCDlnNrTS3/AV1gcwjUS1i5tICDbHUuewl9z0wb7OkvQE9vYs247/0EnWG3fcGZatCcHyUSbAb290bhEQCFG5CW6X3tOz1yvLXH0oy8FPf3vgXINAN3Z07pJiHaSFgjiQGhX1D5/rB4dkb/om8UTJkvvIlUqLdbqm4UiqePGRgVhlERMTpd/VrtN3JQqgylmkC5ql3qGsdwsb9wbSRRiC+OZUs0M1Skub5HQWayX2InUXZkkbikAb5EuqNjOQOTvg0o4Any3QV+jOhBagK46j3Yg4o0FzU4cU/5i0vgSsifzcO2MGEJU5TSXLkjoEGiMlAHIm0OO9d4im/NMImr6NUZshfTKfrlFyTVyXFbsZ2lVEQymiueb7p+n8AV0b9QCrMYUA05pM9cgdlDhcrnKeGBTxI7i6cQzcVfyCZdgo2BJsOGxzi97hIjmiuYnIixa/qOGw5CT7OS0F7HLh5JxRI6LKFAEfT/CPuDCR4WT7lGJi7RGrHNM1ROS0RVPR/QxHHL9CfKaOo4riSRkdh8YvfNmyI6QOFrEf2KDstlKAVTOcH/B3oLR0iMwicH32GbpukJ7MicergoAiVwAuXhmeVLBbIhH9MDFTFYOuAbVPhHAXIC4KMxmDUmQB75K/iICSu5nEOKjOnTTBpukMqNE/AdsryIBoVJJ/bM5pdOVziD70sUJQTuWf+PE/CBAcA7gCVxfQNnVigqs+AWIE5WSBQ+NoxkhhgSZnYWU1fE1IZIJmNclotvus4s9IZiPpvi0H+nom62EoQhxCwIGRlxZVFH5ju1xWhEVa3Q6yN8RSQ5qlw2pDL3DZEJcgdBHQJf88y8zBlt5MwqGUmRBGuMg2K8wgKilKkQgvUQF1QWbSprbCLHpbPErka9SZGSEyl9soa4ctVvvhcBi+ivv9ArLpbwFtHOX5fO7RcyJ98eT7OWa5Yg65csIal0Qn3mCpG/LukjLsiccdbPPhPjZeaTxtnNBE3K9ph0L0+RYhes1y1vPjUfKKkt2KfMAAObWbY1I+O+0GyBVOWzxeWkthD36azzBOVzOeeUvgvjIFX6XM4Bqe+n8zj1uhO9x9S+o+53JkGC3HcR4W93sE9nXcx2P5dzkdp3ESDMv6/mPOIvBE4wVi6hShEOTHaz9A788JgMW2QC7pDh+PpiDcvp8TJCDH28pUWOQOLmhYhUzRKJMVbMoL2CPn0GZOOFDk/QwQHSjVr7yqjnw9KHKnsYCUrLPazgOrqQcX6Bzy3h8+sKGMZHhfHRvuo/hREnvNR+LifD4I6csXJlfDTan4ynE8wwrp3ZW3TDuNkKiaDpEhEvhP7Y3L7+3OX6hrdbG65yiBJkJ7Zf8eg3VFCnU2dZQCeowOpaCjsUK7rj23hWWInjWWZqLsUBleaKr/b1+/Eg4UBZKZTogMk0g5hnsp0u9ojtUz3RhAPlcq6Yrhuk4Bh+egyxPzehkMgxQfVALA/7+myGh5bp41RyLsi2EW0WebaJ/uNnrN2kuDxneoezFHN2FmiGGBHLxJ0E8gN2ViQfK1JIjycLqf6j0+5ZkN1jphE1kdMsis6zLMHlOjPLwzD1EDbFGSQKtgjyJatyOCwziWm6zMbLiK4U/leGUa2R5UcIBFhJVBxmpD8GbDDd9nxapSttkHFJ11RmZ2pYZiZMBOXxtF1iJoFcSlcRwnGowXqrNEqBeFZzHSTNm0EYlg4mexhJTKFRq3hPrK1SJbZ2eAwphAnSTCJVCMitKfwE2WC5/pWcEvuG1wG0KUypIrqBAsJn5hbjqWDdHpmJBv3QIJ6JkFDIsWRKp6IUeBy+DkNTYsAgZ5oLwZwcz5Jlm4YSl/xlTH88y8xPJ6d+a9sKsITMnydYFh/g5oZpdP1UAk6UuHxNufHm5tLuT2h4EHPFgHiQHcslksUywC5mElQCD0L+Znc71AcUhrQsrYRipyi52dl7N/SxrPRfAaTyQyDIL0c4K5x+JoyQpI4AohAQsBS7d6iF6FLmjIasfvAiQRmJH3f5dQl6LKG35XKZaRXQYXdYYVMqdqSD388Q8jOE/AwhP0NIKoQknXpUnpxFZyEugfB1K+4inLVXdALx5O1cisqmN3TgWythnOLLJnsxba37rAvqrPJuPg10OT4njmdNVRB8E8YUDZIZHOPYKJhHXB9A0HjpQAyy0akrjFJ5oSs3cKVjFo8csU/ILJtY6Sy3iFKb+VRW+/Isn0qRN/KpFNCfzYPrZTj8al8agtxMHXucPwC0R7ILE+zzRwu/Tw69G4TdYARWH7DSjSdceMp9b++6N3PbG/oLJkCOw1jjLGgBuDPFimWPnEOpECT86DdiGUsnqIDerHEiYkkSqDeIUiOhAGFeJG9jv5G3ilBW7ODzNu4Jb0SbxEKk/PD494VGxtj3iI/p2PjEuPi0mGhZbJeHvnwBu73lhOY9V5d0ZVXKRXVyEQxTYnaRWU6JWVBgBsrLODFrlMFQgqnIJawrkKJPUCS1aYlUiPEyZVKxrr5fqVSkqZcol4o8UpZLemoBVOpOdH3xE33SI6fLnzYufoKlT/mFTxkmSZ+cAqiwS7kJzRbsOTJBlBsrETIzoKnyN6ipyuE0Go/fiG9SWUWfjIuadIXVilF3XwawkdmkSwA2vz/PaNpRndVWrIs1Vpuzv9taqe1YFuqkXpbl3BqprTgW6qNeluH82qitOBbror6DjvMqirbXMywm+h663gnn6Tqol2X9b3Z+O6992orjVN3TyzKeXfO0puLp+fVOu6x2emat089Kp/WM/A9XOu2wzmnbKqfn1TjtusJpi/qml6lu2mFt0xMqm7asa6IPzWJnlRklLO0xkf3ZMpm08kZ2GPyAkJjcNt0xvIyVXqmuaz4olsf+s+50ZiOTUipvznBTWa5kfotlzkFmZeS4Eku70B+hC7hLjD5Bf53Rnj+sP8MTX6AY8LMXktAdT3UZZhfjr24iaRJHTX/iOkskFRqu67ihnPSX41ierRBMLbwswPZalaLNdJpFaXcqRS+mU/lwS6UyQVfp1GU/XQQFF1XKc7LRLSsfdBNN51hYAiqimM0NVQQ4URZZuQTjiZWv5Hy7MTvPG43kk02aQ/5TlqgzKnjM2xSys9L2YnYqtmyQjI/Vt+52KgL80S5c6PPyly5sRTz34oVN+O4vXwT+tr1XoVazzV1GapDgZ8WSI6QtjthwiSyJJTljBN9FR4+C49o+aZ3iOeMbphD+GfdOgLXVmvonUef6vCbwC+vifrZ5P/H+iP7LLC0Ofzsgw7NlBxyxPjj20+ZwKCCzBLoY+FjKliaDg5gBUnBxIz8bxE3RQRs2BPti2EJ3ZWnXGMUa3SabNGuIVHe8mAVlN2mPKzKQyHu/AoemOBm/Cjg82PgFGPMiPvivg9GAF68A6PcFUYMIYLPdPxte7Eb/JJtlog2x8V/JY4MyxfbYnxSzOIp/4o1vWNdwE8Yjxk1yoJFlk3UxxPegiPAujIrBD11QEiJRMm6RCrIJe2Bns3WZxTzezJfTrTfBLRe0KoWYKf3iQSm2GXEHBTDTBhikAiQAQ/cKgrUoRI8zIQmQ9HX0kF2Yu9Yd/VXKk7RLiSQim7byfdb9RtZZN6S6ILuvwVqi1a2IDp2ZadlriR5uQPRRWKVsp4OX0dXPjrcf0c3fZnuPkI+twnmIk3EVGNBkUUogrEQ/IMlx0+E16U5zY20OfZ7+igdZ6d7OoC/8DR2S03llzRDJxOs6aUKnnytJ7K/BrQj1G3kSgiuYtYrksBnDpwJGVp7jFS9dzmFITKeIas+i+Bs5WRE1l7MYCJOnGwwaHt0Sw4X46SFyyMQ5rJjOBjHrt0RwOkkFp6fGjDWWF+d5Ym5DJ5Qypfi6aoUKwcXYOjuKQTexIn7xtGJweMm1bnQOmzP8z0K6H7OQLnVSUYfDJG44+RxJtJXogADAEiwL31yMCcdJwoMD0/fNwaSObxfjMdk/EQvCt3NiTCfow4cPb0toaVp+bFCKP8G2FNXnTZ1xCYEXSnXmDCl7+H4eXK2m9knCdwtPxNdSDlglAVcRAYWjy0mqZQUwqxFOY7BmgJaV9zzJaQdoGam9k5x2gJU4Xp3ktAOM9IHuJKcdINnY9/BgQQ7TD417y/O9cCCWWwv3Yqf/BRK8LE8=', 'base64'), '2022-04-24T22:30:10.000-07:00');");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJztVl1v4jgUfSYS/+E2Go2TGRravm0Ru2I6HS3aikqls9UI0MokDlgNdsZ2+FDLf9/rxE2BtvswO/u2PGByfT+O7zm+of2h6V3IfKP4bG7g7OT0F+gLwzK4kCqXihouRdNrelc8ZkKzBAqRMAVmzqCX0xgXt9OCP5nS6A1n0QkE1sF3W37YaXobWcCCbkBIA4VmmIFrSHnGgK1jlhvgAmK5yDNORcxgxc28rOJyRE3vm8sgp4aiM0X3HJ/SXTegxqIF/MyNyc/b7dVqFdESaSTVrJ1Vfrp91b+4HAwvjxGtjfgqMqY1KPa94AqPOd0AzRFMTKcIMaMrkAroTDHcM9KCXSluuJi1QMvUrKhiTS/h2ig+Lcxen56g4Xl3HbBTVIDfG0J/6MOn3rA/bDW9u/7t79dfb+Gud3PTG9z2L4dwfQMX14PP/dv+9QCfvkBv8A3+6A8+t4Bhl7AKW+fKokeI3HaQJdiuIWN75VNZwdE5i3nKYzyUmBV0xmAml0wJPAvkTC24tixqBJc0vYwvuClFoF+eCIt8aNvmpYWIrQ/yKZJA0AULm95D02topDGeB7mSMeKL8owahLHA3YbdbsQUgZEUuzrVCTm3psaSKqTBQBdGk05tiec8S9DmCApIafjLZSZhxNYs/oJyCkh7ykVbz0kLRgSXSVhlKQMibRJZGFwUJiPklS0pApJQQzG+PlcQh/BQSraM/NiFODJyiFyKWRB2YHtYg4vI6oMFfn4/Q7WkEnz4CLY1uPjwCJiGjMeC2O9Hgga6ugeCVWhXI4UmeHfSAtOCsT+cU6vIKz7VgOdd8oQl52O8VMDTgHa7ZxZbFWNGZ5MWZHxq4yqfHDEaaxqdThAobEld/JE4CK74g03oip+2sNXapom0xES/ntoqVbJ3p1WisWBrbsbC3zv9inJzifYg7OzwqbHdhwxE2L9FEEZVSUxHXAhqJLBh3N4zjA1La6mYRgMxHqFtxCeYgyqj7/ASBK6zBNGS0EKNpcDrWTCEWsXZhEtE8WBdz6FKsa0KNv69vP5JXz9PYK8ojNQKO85QQLXILK04r/LStox2rJbsMdlRGpJt5H0L/LZTFT6N6KTb9fdj/RcaGNciIPsID1XQWEaZjMtJ8rYSnCve/igv9DxYOkvFIJoLJQJcnHmqGL23P+24r0ZJhpSvy0EC7lNFQVAzu5CCG6mObcuQ2BkzeLP6+FANrrCzE1xXQATbvUk3p/oTF1RtApRDNe1sAE/hxbSDo+4TMHj/Hl7dfhqBtsFPiFOaaRaW+rWpf8IULPv0hkxf7P2wTPcyPQ/CFb6pGL4D7RxEbG4MusHjRHV2OFWec+0JapfYN7RUtrUU5fbgBfVf8yaKLPufth+k7ajr+7+9sXdeddZdxYVMioxh6/BvqrGvF8tt59Ae1RcVPerfL92eheEy1Y5/Ayp3boc=', 'base64'), '2022-04-25T17:56:30.000-07:00');"); 
#endif

	// monitor-info: Refer to modules/monitor-info.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2022-04-02T20:22:49.000-07:00');");

	// service-host. Refer to modules/service-host.js
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'));");


	// power-monitor, refer to modules/power-monitor.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('eJztWm1v4kgS/h4p/6EX3cpmF0zIfLhTUGbFEGaW2wBzIblolIm4jt1AT4ztbbdDUC7//araNtimzcvs3GlPGms0QHd1dXW9PtVO46fjo44fLAWfziQ5PWn+rX56cnpCep5kLun4IvAFldz3jo+Ojy65zbyQOSTyHCaInDHSDqgNH8lMjfyTiRCoyal1QkwkqCRTlWrr+GjpR2ROl8TzJYlCBhx4SCbcZYQ92yyQhHvE9ueBy6lnM7LgcqZ2SXhYx0efEg7+g6RATIE8gF+TLBmhEqUl8MykDM4ajcViYVElqeWLacON6cLGZa/THYy6dZAWV9x4LgtDItjvERdwzIcloQEIY9MHENGlC+ILQqeCwZz0UdiF4JJ70xoJ/YlcUMGOjxweSsEfIpnTUyoanDdLAJqiHqm0R6Q3qpB37VFvVDs+uu1d/zq8uSa37aur9uC61x2R4RXpDAcXvevecAC/3pP24BP5rTe4qBEGWoJd2HMgUHoQkaMGmQPqGjGW237ix+KEAbP5hNtwKG8a0SkjU/+JCQ/OQgIm5jxEK4YgnHN85PI5l8oJws0TwSY/NVB5T1SQ2/549GnUGfb77cEFOScnzyfN5mkrnhx1xv3hoHc9vPo4vO1eqen3zb+eJNO/3g4uxu+uhu2LTnt0rWYn8CSz3dH4ojf6eNn+NL7q/uOmd9VN+McP7nF8NIk8G8Ukgb9gou97XPrCrB4fvcTegO5mjYcPX5gte7jeUIT1eUxptGKyxP6mwZ6YJ0OjanXxSxe0IJmwbOq6JrKqESkiVo0X4WPZglHJFLVp2DPQLXOMUoLwuXzugeJey0sQwS2norZjl8+CowUuXRrVVhoOsQLanRGYk8H5m63s+LvMnjBZb67W8QkxA+Hb4F8WsJTgRnNyDvpbcO/NaSrBy1qQRoNczxg43DwKJXlgoNMpuD3DqHrXfT+86hKPLS5xyAN/gqiY+f4jRkywZqKk8r2CMmpkZWbTxZEqedEfQM22yGu1peGpVJflNV/zWSvIjI/Z7hjkF9IkZ+SkmmH4mtMrcs0cKsfco3NIjug5D9R+3NQXKhhp1G6xVUGalD7ncnkJwYYgmRLwjBjv2tfX3atPBgpZwjzvWLAJzmrU9xaia7sMWXLcMN3ytehvHBQZMtmbz5nDQWpzrZeQuZNNbawCEGqEqEOiVskIT6X8CrwF/nmQhTFHM5uuSgn8W0AujHPeLfccfxGSPqyHDAfJDCYSL4aFSSqEpXGYr7d3mMtAtygbCJ/aOj52dXdMuNyLnjUxkVruI4Wqdk68yHWLjpnqNCG5u1/thg/mQYc9Qd4NYXKlpAlmKIh7x+FitPRs02iEy7BhuzQMGyrBjcMIylicCFJmeHwTOXKsYwnbTCrJCJ6ednPH91C6t27ZMMjPKfM7fg8/jIZcBgzWS38EZdCbmvBV8LlZVcrrQ1UPsylNI4tGmYfsb7Q22T3AaR4L45kIev3T6y1xnL01l3E0K4jC2UGS5BypXFXrzJLY6YfY68u1VUy/ARUhAyi6TYW5HUA634MA1CoqK7VWzKxSXOZNgeFbyII7xJ0yWSg8q/xWnDN3mwddK4zmCG40fqocTzOuvFJ55MZJqpvUmm3xwW1/PkTpmV0S17ARZXO53KV+jRmyUpyTPtpg4vqA33CgoXHb2EI6roLJSGB1ieZbPBUfLW7QmtWs5nIxPlCMRhz7lISOKMK4zmCHA9UhoFOKOF91MuCjvRpZMFW6sIEApM19h2NlXRJoTuxHVbiSEh3jl13ydtSyrM9tzO7pdU90++GLazBucM0P5zpAsLfXaU0AfDU7rsgZQPENWAhr9nCx11aZRpWusO8VsSYQsiS/9Ihly8Fi7LBhiRhEKRZFv6yRN6qTWcMMzQFiYakdcHC8vNXTQRO/qAZge1FakVkZ3DmmDg1A5D3KyGpDKz7rOmmvOYPmIqYxSWFtbM0EkBdWlyPc3SJpAmFL3drAYjluSWRkiFbZUeG9OlJD1otbC/haK3DJ9AypCbTo0aECmioNfIzbVsthEyhvHyG1MCGXCSCvjG06mTDugQUqtaK5lCLPSMaJ90sI9oy7ThZpqoFxIjYclj0zG0sCgIcH7jXCGZz6zoCPe5151GorlI4fSfgQCNuMVn4Y1edQSXPNk73qzHAVVCg7U1wK/d3GZtyz8JIGZFSdAXQIa1V99tgzl589rTfFHBaUyy4QaTNgWmeKJyspeK/VrOI329KvRRIb5v6mplsdjgmhMxsOfxOz/c/8Y9M3KsEcsj2pT1XtJf8mwMf4DI5BjH8Z8JMuHkn9PX43Kru5GS8bDqUhglGFs8/DwAX/+kuzFixErdLuVKpvm79UmpWzykmltSenhMdpTR0AEgIBOQ9ai+vuTu9r9mxaq/y4/+oA1CwnpPLy+XOF2vDfGfkxrMGnQi/J79dKTZ21Bkymd837FtmDe+XVSAO0ROm54CyUdbHcK8dxb+KDo/19NBxYCvjuG8z4pPGPTHYATZtKe0ZMtjvzpkxfoBSekWYthoFnpN7c9OSt9ethK0rcmN2RUfBmayc+zi5St07JIovaa5iYIIX9e/wUWGS4aYyRAYYJlNjzqmyr3XKnUJbYC+/u6rtTVeZZbz9VAe7qLuH28g60ppwHexmyaAJYl9e+voECqvRAW/rszEXjjhb7vwPPN0Lgj8Dz5CMuQy5jwUV8+54NutU4XZoA+Gy2ifLQOFCl5zxk2fKdDOW8NYj9JyXPKEEwwISCfVnfaIvkyjBsrQa+qIEvrex9rdIN9KqYqorotNxGNgVhk1cBZ/o+sexG1wLn+xhvNFx4TAygF1nvzJ2qJUPuYOye7N9RQl9+y1QXLiJPvdKiIbn0wbijZSjZHN/WYRs+o08M23AA1A6h+EJSkES05HYY0CLML3zxqN8JreUH8Zuxc1C2S8EGszP4NvedyAXQXXjDVCNzJme+AxNZJ8G+R0zDM3J3j/foZa1vsabt0AM+iXSWOtx56c062uEGhrAXLDeWDR++y264o6+H+GhudPBJ618x7e9xhEB5q2kMfGWikLj+dMocwvW4PX3SOhocKGlg6cFzHU6P75yxO07es5mJdst2SFhZ64AOdlAivkXIk8O3qzBO+KhwLu18NMdibsj2jp5cuGpOjiMo0YoGAr+eeAbMz7jDzPz7p+yDEfOhn1Xu+AO+LeN2H9DXjLqlNsWVaP83p7D6Q9/qKBMMqORP2A4/L03jRk1bjlvOJeaQLO6rWDSNEfOc5C1Re9fKLK2Zf2ddy7//rhXfeNfIabmnJDb9YzZJM+eYxahYZwXNkO7tR5zUk9sITVYvC5Ovvh7YL1hSqm2NJ2pCGxqZxaXN5M7F3yBEM3Kse6m4BU3e2avi4PmLrTcUOrM5bEIjV2oNlqZRSUZREPhC4h8n7ME34zEbSTWtVerwC/rINLAnM2z+eRBPyjTGOwfDnfLIWOPc9U3T/uDlkLgq7oLhtf4FDmrUI/W/JKf6oMvs+HVRUWBweExmGWhDy/Yddlh4ZVluzyYH5cLvAPcwgJsJ++/49ju+/Y5vd+PbR/BQ5m5BuL8lBFsxbsplA+XK6xm+xe9C/YhQ9epWZzebkoWm5m8y/3/w7Q6gpJf1UGSk/kAwzpRQtRFyhSmEyf2FKpD+BzWsPaA=', 'base64'));");

	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'), '2022-07-12T12:23:27.000-07:00');");

	// Helper functions for KVM
	duk_peval_string_noresult(ctx, "addCompressedModule('kvm-helper', Buffer.from('eJytWG1v2zYQ/h4g/4H9Ekqora7bvlSGN2RO2maIk6FOtgBpENASbRNTKJUibWep//uOeiX10nhrjCAv5N3D491zD8kcHhweLBQPJIs5WlJ5nVKROu7hwdPhAYLPmggkaDpAbICUQmP0tBvlM4J+UUxQBytwGaY0TQEixa43UUJQLp0K1lEuetIo4K5GaOcCQo6xiAVyGGJcz7r5WLGw/rAFchIRB4DtJRGRYP6AXo0R3jD+04+4QL1ld94sX/4shCWKIcVCWMsGK60lkRSNAegYIlxTjL5+Ra25Scw5DSQNs4WUum2FMq5CQb+2I/GNSO6quKqYdmUSnttlKy26JmlCNpzMIwgVyRVLvSheMn7NQijeqDatE1w5uPWsgVkGAtusLOvYx4irKHJt84a3/nR7I3NsZHsZBWrmRVCphGaP0jvKhjtTpasQMa622KYtiaJ4Q8PrsxNNvNty5Sx7kgh5MoVhjIvhAMgrEQR8/0C2WbV66K2bhIVAjgVbOq43Pb6xEFYkvVkv5iZCxObDBeMhFeAO878xTsSjg7dgNxSKY7eJ8IHHD7Rg0j5IS21fBtmGO9+GdB+YLC0RGLchbhbB/hBbMP4Z122eVUMswf9+OvsISTNKM6qbAEx0p0nxCN/t6v0+u7zwEiJSmlvtUEBksELOP27L9lb3WMkmjfvqWAjy6LE0++kY1m6Pt9maxrQXUb6UK824H9ptme+wpCf8tfZ0hgwdJLli5bQmXpar9C8mVw4eDo11xth1C500e3Pv/HhpEjHpYMC5fXunofZN1/ekzOjhb+Wt5d7baaak1TWxiLRmQioSnUxtGjUU6+WKVK3XXyIt3dnaeqPZanZFvCROig01M2YEXjmDQNV7TzcMypiVWMbXSULFhEDJ3fY+AxhH+MPJFPttkW8ojF7MUERbTKwzVH/mgpK/R82Vzm9OTnuW0urTWKIWmj3hb95P+uC1MnXB5yL0LH5IF0RF8qWz9L/2/v07yphS3K1KRmen7585cYu9OGs46LrvW3oG/VIehP2XBa3p2nSMMo9h6THqMIO+5uSBPneqFmaOjq0DJlixKPwj71wTKhu/L1oad3nGiU6EdgL1fEyob2F5M52gKxhPvavTT9MBonztg+nHs9nV5PLi6tPluY8wg4oLOo/lCmu97FhGUvEAx2AE61j4dEuD9yyCUN/MGX+TrvCgDKk+I8tPCQLCE8ZKelAsHBJJwKfWqEDTQ5/NcUQ9xhfxWycARZhJwThcSprK1MRl3NsIJiGgVCGMXtcVeo3wZ97KYbdveX1BQ47evUNDkkGVpAUkdLQ3Ft0y+Znn3/tdNoTJU7BxmhbVVdFmjtEoNEppL5dL93W3/67VUtCkdkPNVJLEQjrtniqxe5mvVUIfdBMZoaOj6v4IvzYVSL9SSk1x+/vdODY7nw4RTAFFH+JQAXvoVgeellcy29R+8WWrVA8KDdMvD3BJ2ee1oEHgUXCXtWb1dPJRMa6pmcvKAGUPM+jDWfmYgI6Ayco2twD/CyAy2GX01Iys5kuB8feTocLPbfV6Q3+rq1Vjwx1vG5MQ+bPG4pddEjTuzW4Aki+pTUG/S+gHtl8fb/1vMLoBoTOW+tW/ChqzFff8+teGSUE037wFDqxMwVferk8vkhbj/xDQ3sblLut2tNs7RwsCUf2ndHTt1d7qvzfc8eU=', 'base64'), '2022-04-27T22:29:22.000-07:00');");

#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(35345, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 35344, "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", 16000);
	memcpy_s(_servicemanager + 16000, 19344, "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", 16000);
	memcpy_s(_servicemanager + 32000, 3344, "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", 3344);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2022-06-27T10:25:56.000-07:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2022-03-29T11:33:55.000-07:00');");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('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', 'base64'), '2022-06-03T01:08:06.000-07:00');");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoqQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO6T1QcmO064O/iDfvJnhvBlqcLJONCm0WnED5JJo+F5yDYxWSzQaDzxEqgx4FiJmyRykneD6bUYjVgN5kX5K7AKRSJGCMXEhEpsrvSKXl4Q+cnn+jpL3hNEpPvF0WvACplNK3tQ+3hD69sPV7adrGpERYTVN+pixyG2eVpvocHCSlzK1XEmSJTb5M5GZAM3SRSn/iwYnz4MTgo8LS4Ac7/7xnOwAMa7NMdLfyEVEnoldcBOX0ix4biuGMWZrSy3HZNvaMjTD7HYUGpLs66205+8+3rCzKCK/k5D7Z3jbGF0KDbMRPAV2MXSRY9YX0bgFFslGqMRVQ5ZCVBtWb3Y/qqzd0wL/+nI3iYtEG2DOTWzVF6u5nLOoJq5STBObLgiDaI/MJ1LpIp5pWDJ6K9eJwJJ9BlMoiQr6DCnwNWS0ZnVPlWzHzaFoT0/7LgyrMsCDNqWw77t/R7Tj5zXroUcczvepm2+/3q4AKJTXa1vXDS0QhofrqLaBTr+XoDdXrnWYelgOsUtgjZ/YMl3B4qG5+sJj3Z2soWCYzhAByyYEl6zvTTNuFpZ+YYkB1BkjZTxDp7jxTNJVNiLUR0OH6FGUMCJucxv0iQvOta2T2b4gHF8qOKYSzgUJlkZxip1h4VpJCT5o9uxzHPnPmhLHQD0uqo1tTzcVf4wENN2RYbTtSUQtOgisEYMzc3JHm2A+hD46UJDZS+wHPLzQE6lQptcAXlG7eRUuuTK7YvxR5jnoOEca5vvU+Nbk+YbVJYv6dM72ocxb60QIlXrdLWuB9kwQHj9qbqEZWDXSyXtIzvoGyzhVxYah3bCdP53MPZ0DhLvbXoeBMHBcO05mh+uuYaXWcCXER24sSNCmKugLOjmEd1U9Iqvj+uiBjyjkkP5eVUZPFf9XEb+ohl9SwosqCI5mTwfbduJUkPAdw7YDCS8GN8+sM9x2LnRjE21ZOxSx/Y0SEAs1Z/QfN7fwRMjfYBbEj1NnYCGO4+aA50I9JCKeuY3SWHwBIQbsPV+BKi3bK2JQwI6vrzJ5EECscss2SW3gNHTnnvplZQZP3LLmNIbk/OzsrK11cAnUYw0jwbFpFyD7g74F7AfqhrSf/dWMxsG+uwrot8ndPbm+m0xuru9vPvxLm3eYvfyCI6xcQYbZ4u2AakC2/aucsDCBDEyqeWGVNrQTbZP+Xl7r41mF4a1D9524D7xjdAOzWGlsm1z9dFju/HrOD8Acql9oB/OvEq/jaqWvVFaiH3gqlLbGX8pe86Pd13CnklEgFrybfwDySlmh', 'base64'), '2022-02-07T14:27:31.000-08:00');");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('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', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'), '2021-12-10T12:00:08.000-08:00');");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'), '2022-06-30T14:27:52.000-07:00');");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('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', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	char *_notifybardesktop = ILibMemory_Allocate(28269, 0, NULL, NULL);
	memcpy_s(_notifybardesktop + 0, 28268, "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", 16000);
	memcpy_s(_notifybardesktop + 16000, 12268, "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", 12268);
	ILibDuktape_AddCompressedModuleEx(ctx, "notifybar-desktop", _notifybardesktop, "2022-07-15T20:18:43.000-07:00");
	free(_notifybardesktop);

	// proxy-helper, refer to modules/proxy-helper.js
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'), '2022-06-14T12:14:57.000-07:00');");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('agent-installer', Buffer.from('eJztPf1TG8uRv7vK/8OYSiLxLAR23r2rguPlMOCEiwMU4Pi5jI9aViO0j9Wush+AyuH+9uvu+diZ2dnVSuBLru5UL8HSzkdPT393z+zmDy9f7KezeRbdTAr2duvtFjtKCh6z/TSbpVlQRGny8sW/B2UxSTP2LpsHCTtL+csXL198iEKe5HzEymTEM1ZMONubBSH8kU8G7K88y2EA9na4xfrYYE0+WlvfeflinpZsGsxZkhaszDmMEOVsHMWc8YeQzwoWJSxMp7M4CpKQs/uomNAscozhyxef5QjpdRFA4wCaz+Db2GzGggKhZfCZFMVse3Pz/v5+GBCkwzS72YxFu3zzw9H+4fH54QZAiz0+JjHPc5bxv5VRBsu8nrNgBsCEwTWAGAf3DDAS3GQcnhUpAnufRUWU3AxYno6L+yADNI2ivMii67Kw8KRAg/WaDQBTgN61vXN2dL7G3u2dH50PXr74dHTxp5OPF+zT3tnZ3vHF0eE5Ozlj+yfHB0cXRyfH8O092zv+zP58dHwwYBywBLPwh1mG0AOIEWKQjwBd55xb049TAU4+42E0jkJYVHJTBjec3aR3PEtgLWzGs2mU4y7mANzo5Ys4mkYF0UVeXxFM8sMmIu/li81N/B+7wE2F/wI24TEMxsoiiqNiDr2CAh+UucAtjvIXnk/Y3g1PCoHRvAjimEVFzuMxjRbgQNdBeHuTpTA5y3l2BzMPCHXQdBYHBaxqmovhccyAhsvLGZBzkQ8FYC9fFNn85Ytvgi4UmABeCv8D4AjgWRrPgRxjwhNszF6WBfMBQjbmRTgxUQdL4DGf4kzRGAAG/MO+5gOgnml6h3ikxmVGYOP3v5VpwXNsDU+AsjLaGiQZhOjk+lceFsMRH0cJP5VQ9QmA4SxLi7SYz2DVvRtenAZZMOUFzw4fegPRGz/fqn/i5y6IS77NxmUS4taxfgKdBgwmCMq4+Cs+Xbd7OAOIQYCacE3FTv0hIqkfsV22tcMi9m/EzcOYJzfFZIe9fh2t17t4psAP4KSPvb9EX4dAAbBrn4CoCWL2mvV2e+uesVrGww/ADKDpUctr5LrkhgaVUMLYb9Y9CzPBgmFMkHprAAv7Jkenh3rkN4QoNfYGjs0eWwEss4RmaALC09vzkxrI2lpnRKPbIz5z2OCZuYCtTtPfm6IVsohYbWbq9zY2ekATnmEXoRO+hwHgpv8AEHzDx15pszSaIxC3D0q91XA+sJC+Os6PcJZlEd9RePwj5Iaxj08RH0Qn0fPw5kZN0HxfEiItxJ+fbEYwRsFX5taORCMF97BGpGIQz45E43708+5Wd9Kh8XM07ngfNJxXDzz+T+6YxfeEPPb5M7I+tFIy9pdf0OjEBmjygLmzsfHLL7ufPz+XICBht8yeurzasKFNulj9QmLuZNxHVn3t3Yrvo4pbVPDiza6MXY0PwLGwRfMURA+4G+FtjoYq7thMIZkBjGUIE3Pa92lwS3aiYNZplETTcgpmboF7j65IZrBuTmYjGvrw5eULPTFNpbcx78Nk03xd0yLuwRQM7V129ZfzP/XVWhGp1NJitD4weR5m0QxH7g1YUsbxOtvdpX+w3/0ORxoaTdirXdnmGxOjzcqchLDRaHcNJbLbE4QzbKLemkZ4ImDUYH4M3xvhqZq0wFM1MuAxenaEB13UIGmFx2jSDI/RqILH7GnAU0GEjdBntsYWjw32U7QZpgk4dkVO1LWxoTtW5CitC+l78UxII2oNzAYr3/0F5I4UOKZvLF2xjWmQgMuVDX/Nq+mVGK+jT8jxngKkZzJeXYo7AkUM1yC2DZa18SyXoVGskSDxK/pZSPZt+xR81XOxZt/W1/cAloPTOf2cPfOsUu1dMBrljgqXOJc2KmzUNcctzsvp4j2pI8aBrMKQC7KFKAfXPM5521LOC9R3CUg6Z1C9quFwyD7wogcrjvNUCDNNj3rNOTRz1VHGiukMySxLoQEsTEYDcE9691Hy+7c99gfWq6IMPbbNaCMpSNBzhD7pb/MHjz4TE0o+6PeuaKDjdMSPRr31YV6tr9+iUvAj1clDuwrVVGlg9AJIQronaFVYy0O74hPo0/Q+H2D4xlwtPeQgDuageJMb2rkaUoFocYlApP1Vseqa2x4sdqBDhKJGdw4eHzXrWgo5EmwDsGRzMLkiMJ1w6ZKkdHBGzGioUdlAgtInGWmoUYWPvBilZTHE4B9QAGDwqBpYDqqBRuZMYw4mzjh90+/1KuebqJckExMCYcf9/UEI0MAvQUWbnqnMVbefwbfyqgTBZdI5AC3D+PSaj0bIZLMgxOhUwtTAGHqjmFoIFugUQ4vlTBg2J+fcECt6DR5QyaBUYJn7KNtKSS4bOPJcDyz+QY2Lfo8Bm/0KeyqRWdGtWr8y+3YRC6B0bSQbNFPhG3b2Yf4eA9GVLOEPPDwNwCc1tEIzQ9TR7Ywp/q0WgaPrdQzpsbUaSxLVZereaCSC51qNYwjaiH4SJYsYOghfUBJ6o3VQXUoJ9jGniG5QGCLXYg+HbwODcXWPd3McRjCulo2AmY2M32C8G1Y3LKEF6q2LFNv+mc/7uiU+2si5iDpDU6QhgeuT+4RnJE418qPR+pD8wFa1JMQrfwj9eraiAvxT6TCbX04S9iFKSqBMYRA567Wcu1k6K4EuTBR/PDpQ5lVZYTlvFERqZiTJ0tQyLn4KcOXMdVOHaEQxlW5EJFq3bcDHaNQv25HbitoO5ILUAoBYgkFzzWvgLckZpoWmvetPvJdh3oKwCFZDxgH5hM+TU5EmSckFxocT1ITwt24eDd1x1DZSdoEcN7HHEUjHe47CcACbCY01IOQVS1l5z9E/C3JMcYDaSV3Tmnpq5S17qqxMmqhhwMtLeoVhIVWiKp2JTMxu49Yib2z7pLHPhF1Zxw/sSYWQ3ZZ/d3dR1v6hiwXhHXxbDOPMIXcPhfJ2TUy7bTFQcDGfASZ6ex8vTq7OL/bOLnoDjzgjl1khzGlwpfcOlpaVBo8+SqKU+2H5kV5d6PqxqqMIaakeToDN7rTuzmn40k1zWr68OSdKT09mrdcGizFYZcgs0oyggtW8pnMLDXqWq30Tp9dBPLw5kRTe6NuCiSriWFFOf92e5ODl680OVmq2A0C8/f2SD+Z2W19HSQB25kK3Ts1qkLFnbjFaffJHQ/QdjVnAhGwU6fP7AKUI7OIAJFAPM6hJGJcjjkFBGTGMQQ2jMhJrVp7jDJ3K+wlPXJ1EjFjtjVYUY9QOIs54Pk/CvpbX6759Yn0H1VUoxN2DL1+tEJ31WCiQb2DilFnItyslAS44vz8meac6SGvvtVYeIn5nYFKjEeCjKMxsvgFObw81s5a4iEhhPKEPgfoFCw0QM0OMpIFZP45uSlEuIfaA8K+wHZZZhnbYfZrdksQH5IVFqhSymRpBLPWjin91MLQCbXftDQU7/Xa9jO455qtf5PZdsek3SBEdMN92vT0hlh7vPM9GI/SwidpI94uSGK2wHkbXNCU6uhyAV1odBpJKDhVAnyI0vXyeF3wKPjpgwaYViYK13ppa/0YP12632ulIm3InDMqsVqdwV5GkOVyljHwRrkeTWnbrtHIVp2GgXFdJMFUszTZrdZ1FgvUTpuXZDRazpRzrKDnFkdBbAzXphtTq5ppgtDnIngCd81iVlcjijUlaxiMUUZVPguZUTVlcSQabIWm+qmKwDY97vbaHmx4vzk1WehDkT106wt9kkapvPXEp14usVs9begIpvrVY4QTzcw028u3CaIoAtw3Di3WcgR7H+KeVkZ/om6DJo3t0ZKVnHk+IxJiyWXw6hCzV8oIJRGAj6sQQ4wC8y1X43dT3puWE2t5SVBZnUWyH9L50P3S+aSUcmsmOhTi07bvVcdgRNS1Wo8Hn2rRKUpobtZMQU6Z6qqasdJSYRbvRvlhaAJiF3Z5rmep16DsoLSf2KMFyXGNP+JF9OTg5Pvx6mbiZlMXBKg//ipiHDiA7pMUTqoSkyJPKRAhLMisT8WycpVN2Hoz5X9IRR6F2zAvJ4PZMVpToOsTguRhedXYwMXRT/7ZkEBGJPOLeQJwXb4dnZydnXxmKIuznwTTYuUXfUcBor+R3oRk86WKJ1JahmXsahCfnYCTwERYIfAjKJJzoikgsoRTxJIq8ljkMK2MEiSxDBdQLrGMzaX5StEmGcwaVwZunMoSB+eVyxsBkyXl8J/yBIBSlt/mExh8ucO5GQQY759GYgJxhnAajfgfaZWzjZ4QFi2gxvBzT6oURMBwOO4dEu/OXgd9+XUE2FIsklodBuTd/QytCgYgIZrMPYJdhx74bMtGdOoUqqiloV7F9vs2+9D6kN1EiGLb3taGPGeb40tu4vZu+6X2tN7WsUuq3hMRxo4PMYEb8uJncpZnS4we/N5NdjqwKRiMsnTk6fnfy8fiAfTw4BU6JRQn0J359drHPDoIiUFS+XGwfhQDY2yAEapvckeg/icpxcB0zfo96A4EToUBcey1QI8WIYgobFFrYLltoLB5UsaTt+hQSKxdZMB5HoY/+hBcLvYBSo+QaHV5fs9MsvQGC20YU+R8XaZjGMAjsSsMA6FtBg9PyGtT/AH6J7oICvKqDdBqA2PF0OqiCU9sycLmPGcAglgXmcn2nb0/b1ng4uuHw+A6YJYhPU5h9DsPBDgF/+ZqTzhq50UH8PBqkYGk7tecgnYBK38tvZ7CJfdzJVXS+yRXCMJFhCxIuplGi4tTs1zI3Uj6idxvFnuNIRorTlM8+Ewk5g2bvwhNfTv7sLAf/yDTD0jq9ATGVZYPrlz4mf0ADMyrAhAvjNOcWrqTyEBEy6IPVV6M0ATpExPFgJIq04jniRRZ6/THIrvFExX4KeCVu0bk5NaxMTEQ5BvnBcuK4liCLAAZgmVu1Gx0Cq4hkAruPZUJMBbdkCUvOj0DNeePCV1f5bTQ7BAOnNwCLfl1kSxvx7FpCVbodD8YAIQE2ZhhPKBMjkBh4cuy6gZRov6+l2bVNNAkci2igiVcZP3q0Va2VNor/aK5lVdOEVAX1FaGNrnajaah0zOVYJRiOKjdAGJZJzT6zZBTFeKFRlNxSjNfsiwZirVjyaXbCylaCf2S3jgsdPsMpfKVDZxQhz4EV8iKd9TzxayxeiiiJXnG+S+CzjN9FaZlXHiA3DilJaztME5CcpTzRJtvJk3ZqMn/tiS0Pm9LUnwR8VXANFsTwbBEVBkvo04RgLLg4jmQyj99pXcT758jyb5HplVzTA8q1NTL9W7m+AYZL7TrVnAO2gF3nil3M8IkZN8d/j8CCey+Ch7UaGrDKTjM+jh7qjzQ4KmhQa2HUcTVl1p4xl7qDm4gBYlNJiBI/kTCWeei7CCs4ZPaYjpLhSUodCjJU3VlV/0/5CspQQHtdOozt0ET41sz2uDWoVCSbwlcKmLihODcULTTLO0pjHVAGsTluJGiX0izYiVHGkXSpqJoQ0RUmcmIDcXYuyqXpSnEwhZUhs0alMjAadwJ0gOkt4gNpFHnInlwG1L4io3OP3KM4B4Mbahd0Pph8bqN2zq5ocqPlHor7RksWGBLYEkakthsfa2IMxFdNem1sXIk8LXozMu7vw3OFkXEQ4oFMrHEIYx4kGAgQ6BYpmiDP0zCyK1mMdCB+LL7zcAceplJx3YMoU6WyBkJM7mwaQLdx+msJ31l5Kyltyd5FBmw9xifJZ4Hc7KDfXXnYN+TNoEYsqwcBu5SsOauWK3dca1JjxqEiUVr5/UOCoyj3xQQNdDkWgLt92hFSpE7hsaSmq22sGfQNPKfpcGlDhSjxQAk1odFwbNeAbNytV77d8swvFwweznGabCgvRx+OrkVHFDYq9QLSXVnR5ofMV37H449Y9lzhReWNN2vrwI/sMZyls5qZaTyHEVVLkXjddIIb6uNU0cIv+7gA0hQzLrPwuz97Yan3xR9HjHJQxkZ7a40bB4C9oQEqOYbJ3R+WG+Fg7+h0fymg/ehuGH8UZU9epR5DbZkewE8r4SSKrcpC+uFKEjbVjvAQE+Sw2aDWN/MJCPcvPfjz1QsV9lZclQKF4FKgR3UELUSbxAY+HBbpuTgIto4WTOvAPMu+z8BRosRAA7E50rplAEUql0kTf9T6rMU5+zsL7m9hoo6zfOsKDqOA6W+22H+xzf+sMcHl5XBzfYmhlpkWPvlkN5/BFhTj/hrg5fJy7bc5/N/agP1ma31nybGoJqSPdu4SHR87tl177F0ma103DKlkcxmSaOLulcYwubv7AOgZUmvZpKnTfRAVh8KLrDdzjsXYx4nw06jqmkL/+Sy4F3fDTKdY+EuqzdB6y2u5y8tnVXMNwy0nP7V7ntx9QRsB9rL3VTCgoOvfv728DKcjquxCGbu5j/6Vj2YAHo8qo2qrRjJznlrq4Smi/CnSuqWvQYI18ntyMMsMV1fxrKeGq/fpHBxmhHRMxPTDfC5LmxlKw1HKqT6ia49SCGTpFLcZNAE6OIiCmyTNiyisjS1zZ42Zs1wHtRfj8D3m99yNaUQEqzuHC3BRC0gZBW7WPjh7gZ8nuoItWFyRUj1k6gF7xbCrZ/AOPHDclMoCG8PGvTeuQbXQzhaa9dCG07p/dnLMfk2vxWHAojO16Cud3GnIsy2C/Jbl4YSPyhj208NJ1oFRbL6hm6OLS9Gb5m3fBAcnSkdRSAk4m8qHVzIypIIo1kNYc9KvROTy++0jJPzUczh0ncaVHbSmzTRl9DMR3JIQdImhNyal6lHv91FmpLtqke+WoLcv0fWOAy1SoFG3Hpj5LePGJTkT0VzTMe9Vi5O+d4DbKnj6JJMiQRyKk1b36ua2KlStA7ERmHfXQS7uyqNIZKUy9MVIZginuuuiqTRj6ZOcYjg8F1/dMLJFqYvqhpEf13V1dwd60yN6Omk8OXn8dGbRgQxoT6LkFqs9p3Sd47UOVldLRTRE+ZmMYat7Kv7+d2Y96Huixu3VAOlshgM6hSmqr6eiZnd3YeBR1AygNd0ivDz92mTI+cXJ6elhzUIwp6wbG02C4a0lZ0T6yjUoG0TekmA3ir7nALoG8zrWvwKrnoJ0iXLeple6Xv3QMRffghpdCCCvwcGrI0X8HfPXzYeUFYYa8tyrOJwVYbYPtgIRtudGGw0tr1xZumKkWQV6wTD04F6VVNEiyUiumCZYnoJ7WORslIoqVv5QZIFCFckqzTByqEM6YNbH+jHW7RYG6QdsU/UcuhcgWE1sL1vhV4swaJVsJhKc6j03c5aW+tIJhscblnXU6rWBTYks9mXrt1/bDU+n8gx0vVl5lu/lmPP9hpBVxXssSc94XsaFSE0OxP1UQay+FtGUA/zb7M2/bG1t2f73jBx1Gg4jF7azvqQleJk9BTVIEoIgel7LsIIWR7MgzVqTZDLLroHBrFgkwWnee/w07YrwVuySwKFRttkC/zhKMEn5BIP/aVju6iz0n8lGbzbRD517XzbGYPH4LHT8XYcC+r/maSKi+3ZFCt1VA5z0H+cnx0OqqjObmkalUXFXs6bveHYNUre12k5lG3JeHHDw/RJhuKqfjd/y4cHR+d67D4cHonjk6D2TE8grpqkqVV0Ju16dZk3SDTAk1YhxerMY8QZUR8k4/YCRvv4b37ye07P5JL1nmD0REUL2hq6SwVMM1sTmfUCyHmunVn9lFS9NgrhgwRhvMLNKsgyrgKBQBw3RBAJVZI6X8Y0q/1kl9cN0ZNw9rgs+hso091+2R+CeigsA/ff/yUshjGp88wqaRJcaffdKo/MFlUatBUbaPanCk4FfKnjds+5RSxAqVsiycY4187LXtWeIY7onjbpELN2KM2gvkwcL9gpj79t09rSWRuhgzZlT6n/bbmr1s+Gs7thxb4v9qroduqCF1vxJ/yaOsfetAlOru55v10oq2HkwN8C7MHoIBHecNtCAbWrKYhUqb8cE1fIRSLOt7wiY30gVqqhVB+kIj+A1VChMbJSjlI5qKmnA1DHGFZSTMeThg5BXxnirQC0q2P1Qe6bQINOJTfeCD6Bj9xTnru67Y8VEWgRsdUmiKWBbBLYpfQV7O0WgZqXpP4l4bhHNjRLjlSUx5ELoGvzajWpX1m2jxHOOudBfx0kMnW9BMWApvtPgPso5XWFLdxlTW3wBhLAACm0K/MMtpyfYPvVw3f8dfdikC6sW/lsJGjTJTh3d5m2JDc9O1fLlgEwcumy4WKAtufj8uqdLvf8yyqju+Nj+k7jH2l6OKQr05S27ZJh4Ir2mAvfUb+/ITJtdAQ3cr0qjRSZswuuHIMj5HTjl3dhSFHV3VKwk+7ttgIrTNEWb2LXOubTtk7xsbpping4wSC+TUbeuGaizFN+2/XXgbWY1cppob3Tb/irRtKPetMM+8JsgnOvzbH8Sr9pR6piuBpa3kVN6NB5vlLNRUJgnsfJ5fiV+7Ee5dpmuf/pxvXaJvdhppWl7oteoJxPmUhhWylJtfdOxCp3A2WVra8bj2cNOlfxlFVT+A7hIGjACAKzP9/zBtIPeleMxCDIkzT40GrAeJpJ++hHvT6zK+EADO7elqPufF9924ogkA6EohjT4KIcHJJkIOmHxgU9Ks1DeqF4vR8crZrI6fuq9QTu45R9pNud8RQOwHoDPVGJ7rRpsrTKfvKkHAkeecpi5V7YavCz/aUpRS6JKYcYY1nXbrax2Qq2KbNckuMO78vHoboT59+pVVfbuvWq81zLKz9K06LfcDScSlKMUj2bSfDxJy5uJ+VoskjR4N5ctykTAI45ueTxn4yCKxQXMQifgbY6Yv6/dt2ywGLkshdA0uLw4TWdk+l/zMMD3pRG7hSC8hqE6vormV4hRC5KLsg4/5ABPlPqJFY243g8o7XyIFFedmWKxlDTWUHxyxX1VVZZGcqjCEASGVW3wcL9G8s+bjDbvNVveRK8W0lb5g2SIksm4CK2YZOk96/diEt29+ispKrG5Ut2V5wUrdXmrDm83xTFqlMJILBjnvoWNZc7ZWmY0bmU1wd10M6tKaaMBRXfrcQaGUc0TMtQ38pg9Il2QSvWTjffcCXK2r7ujLzv1oboXY8KkA/YlxSLFqmJUBHRA8m8g4PWqSKsiErSCvBKzY6GkeIMN9Hq9y8zCdE9d+oISSLciF2nXhW0Io0/lVXp0iZpD3L61GExUo/W2OeiitsXKrGUIvQtgR6uw18+gqlYAFD+19wI0QISfVZm4YSUNb65ajbHVpwuDN8HjGdKDMcX8Yw/8DYizgfrBlTLiFpTDs78e7R+y45MLRvle9oPXSGkar4nilh27Xfl5cLJKzcFzIqQdYO8bFSo7/JVyqDEBk90Fnit53RZEkMWR/NavLOMB+2kLPgPmuBxu/ZNl/9OFbXQO3Oec2+aiQBpZlaz/4fCPe/uf1/2tVz4eWWe+J2mbrgU1XaY1A/+1pzr+/6+NhyapYMyZ51V9ombcdHmFin3iHA1p1KHqOmH7Vm931Qvqb6TcCTu8ac5ir8tkL2E8yzBxH4ZlRrciYyFiqYSjcHVbmasDbzm0Stcvi1pi4UNgJv1YBjDE1T3qfQ4KXja1/CV3FdRaUJ14lTKYzzjoaczB+cWUpzHssFPKQ0GtNIws0GusNzBwrXdajm2oQJ6UUzy5yeWLHnheL/rDXs2kRlezijIXzKrabRs2XfH8l9nX4UxGxFwK66yxFMJuwe+rRrXfZ+Ahgxop4Od/Kd/sV04o3o+NtbtAbBfZXLAMvqMb/vtpS5bO5/5qRklYzRWNNXfSi0MLMj8ntN5i5cJTv70KP82qtCpjMXNqewnlRHSoTkbuVMQOiPgcw3MfpXqkG46wakK8w0gsIMMsSm7fqUIcLLVqJt+73hdfpYg20oTiJYnq5SDIBVVL04w3f62/Cce8A5NMKR2u86UxuntP1azgRFVfVkugo78lsSKRVnle1r1iDz55JV4IueV2+N6emsdDU1vV7op512BsdVtyK1OvbRK5N3cetxQhyo+DY3pXZvXazS3zfUomBuUrNR91wNqJVMtCyqxWPGdQOOzxFTVSbfpYRFNMsnJRNSjeDpDVK9hqhZJPLpKsy90VKyY7VEsuzBBeZm3r9lRBOrM3Vj/6NPqKhYvGlF0MiFUW2ngViiQeU945No8mZrNsWHZ7tet/G4mi+JmnEtFNz+D796Tdg8ArdLGzxvJhlSWzmQKjZpopFjKDv5zzn5oZKKN3VHCqbdl6Xh5pQcfz8AjJ+2oFr18/M+23LMBH+/5xzmRJL0ApAj4O1HQu3L1vwu8imNaOh+LV/c6BDbC4Q8ihbGjroWtFmXWFQLe4L4XV6r7chZaudV0uBQnVhbLPf1VujXe8bf//3twn3Zu7Nxp5+WYR59TJvYngB6I0R2TexfG4eCxMe8yeW9GpvRv7Jd5E3aKB6GFwgJOI1+UWvTRWafiB9ZYiN0dvGO7YhF5xIE1P+C5KP9Z8FwIucDOXj3yhltVX0hiTSxf0wbx2R0Q1LpNDiszoWEwVrx/S68pcJe4bHjR5oyNyhdDfcfHWOt/81YRUbyJxa8dVrH1RV4/EUcK7w7gIwOa3NzViGxyqVTqBniO3ac00DoLsJjcpB78LyBunsMY251uvjdHbuP7pRxygV39mlnIQvuQ9KhkyrFHOoSs8KuRaBQ8Kj1QitzzQVFDnreRAUEUlR3WT0Oq72QjAgHBiO1b1eIISSUZcYcjOqV4A6xAyTpcZXtNrIvCS/Pk0xatir0t6OWlO7+um+y9xMDn8eTnDCii3IEpCh+F+HeLfaWikghRYqu6JXZBUXRyTlwLRmcGSm8pSMH/bEUL0ydLaN7dpkfislIa5W1xgzyyGZSTnMH5RFzD5Z8FK3E5zWH6FWon5W8tKRPWrpVmJSv8bikXMxw==', 'base64'), '2022-06-28T11:11:27.000-07:00');");

	// file-search: Refer to modules/file-search.js
	duk_peval_string_noresult(ctx, "addCompressedModule('file-search', Buffer.from('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', 'base64'));");

	// identifer: Refer to modules/identifers.js
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('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', 'base64'), '2022-06-16T18:38:05.000-07:00');");

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
