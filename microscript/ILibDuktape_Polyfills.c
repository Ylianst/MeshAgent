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
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('eJzFGl1v2zjy3YD/A+uHlbxVlTi9PdzVmwWybhY1tucc6vaCRRAEikTbusiilqLi5or89xt+SaRE2Ulb3OkhlsiZ4cxwZjjDydGPw8GMFA80XW8YOjme/B3Nc4YzNCO0IDRiKcmHg+HgfRrjvMQJqvIEU8Q2GJ0VUQw/aiZA/8K0BGh0Eh4jnwOM1NRoPB0OHkiFttEDyglDVYmBQlqiVZphhD/HuGAozVFMtkWWRnmM0S5lG7GKohEOB38oCuSWRQAcAXgBXysTDEWMc4vg2TBWvDk62u12YSQ4DQldH2USrjx6P5+dL5bnr4BbjvEpz3BZIor/rFIKYt4+oKgAZuLoFljMoh0iFEVrimGOEc7sjqYszdcBKsmK7SKKh4MkLRlNbytm6UmzBvKaAKCpKEejsyWaL0fo17PlfBkMB5fzj+8uPn1El2cfPpwtPs7Pl+jiA5pdLN7OP84vFvD1Gzpb/IF+ny/eBgiDlmAV/LmgnHtgMeUaxAmoa4mxtfyKSHbKAsfpKo1BqHxdRWuM1uQe0xxkQQWm27Tku1gCc8lwkKXblAkjKLsSwSI/HnHlDQf3ERUKEdo61Wr0PRAXR1tvHF6qyamE3SY/mWD/ePvTUkPG8Muwz21mOFhVecxXR7B/8d35Pc7Zb4SCthNg10/SNS7ZB6ACP6ANPr2Itng8HHyRRpCukA0VZrAFOMd0Rqqc+Q0K+gUdjyWSwuUP5xWrFYHhmp0bPeiPG2ADT+MWgHSlYcObernrqQ3LN8fnCCkgHE/h52cU0XW1BfgyzHC+ZpspevkyHaMvqAiLqtz49fxVej2eokeb4k2zqq0ADDsactt+8PtgAlSMDQYfjXeHLMBx/e6EtGgDtPVtYNh83lD1QvJmm4KarGYQxH60LGXNdxcs6Kxim3c4Apst/XRbgqOSQhhyoBZqrIQrPgLwqY4d3Gw4DnpxivIqy7qGwcFBlC9gw1G2fSOgAghuELv0BykiEEB//UkK+WqpU/jNbgeU+HLhRvJ75V1eXr7iAoDYEIIY9q5bSIzcgQsCHo9vJfg8873AG9cS1AYYpbQ0cA1DgxgmqfSbsMCGRSQc2Jle6tQbtyyYq0yAK2tFp6foZGzDtKjzp4RAH28U6tXxdcjIe7ID94xKiAEhRMutPx538Ryk+BMDGvLk/sqt8d64IfUmhgIKZJQcTNqe2ZaxwQFuuZDeyONOadFqPsKyuuUxH6LVJDDHlZZeoUnXd83nFsDveniS0gqjOyimgHqmmALHIaam1Xw4xJTj309M6U4H5ZRgzxRUIjkkrakZXw5Z1cT3ExaixUFJAeaZYgKGQ0ZJR786pOOj3ypaC8X4NF6l34Y3KriqkGwA4azEnVDMxXvhKxyTxHgs4jOraF7z/KgDJI+BkAkUEwNJHRAh5Kc05yfbS+S98eCv4dx6qI1TRGW5IzRRDAsMTR+ynbB8yON3ERzbYhAiG1lKLXsb/Nkb23Fv2ubyBKjolbaYbUhSM9IwUGurXvzEtfjJUxZvzsHGRvrOQs3ka21GUm5LeTJkWEOCF8NU6sHXLq5fH+b6kKHoLVvM0MtTNJl+iwQNrYatyV9bPMGeJEsWUeb/LUDeMbhcG322uFjMzu2FuK7/J4pqTAycBEh5b+W5qc3/dOQydNM5RoFwCgloO8koEAozpmoFjoKKpnLCNF4x5U1blqcisE7EpEfz/YN8R84ZSyhgQaiJUw0CVEkFLGeiSD0qDKfd9+aADV0AM0iqDQQNxLYKn28soyA21Ni1mpFn7WfD/QutWZVScsW1hnj6+lgrqTV55fH0k9D0P6L6865FuaazdRlUkQ+/fH07AeeFt8r5/SbH5vV+eHNx+28cs/lboDbicK8k3GhqAMkC0Ki2/K7q05XfLo94fJqgH35A7KHAxJjXRx4Ra3vj/nRXi5XjnSnFTZqXjN9KWDTHVol0kLWTHtbGgjd54npOmIkN8w3sf9G++waZLEC5pw4vc3xy/dgnIttQsgO7n+f3UZYm6J8RBaIMzMbrLcucDCmj22MlnmElocbzTHPRgak5Ic1Zjo6kA1tIcAbwQtscUl5lXEtwZAifuqJccE/kjlvHCYG4FsGzNlaIbc5QIbZGIKjCVkC2zi1z3rxvgPqITtwnbxxlYGXidiKCU691qsnIzi1CX8/4B2syDgkm0iweb6r8LkCrrCo3T6/FeBiSmgX2cMIjkDYcedmDogx+kgck5r3+xBJc6oWkdFutVphyYm7IHlZq1dYEQCm/itcQ1EdiKaJy13Zpaz4Sjt88+i2OepB6RGoSlO8gQgyGGTH/yp4PJLPg3va4Dkov0VOEfjRvFMyn2V5lrw7LOCBPTUJY3IwbcvLrw3meOEv+JxBslKQvj8C05N7u29Q99Uz/Pj2bFSHkVzPT6xrIF35pZkhiwO/3pzoa0Qq7WHkMumOrNI8yMyj836KBQYVfTYEMPdrsWCg/Xl/0GZxgqG06+2LSMxXfroBNxcOGWH5tHFf1tBa4HeX1DZrMG9RJ0Z8kJHgVVRlzXC70nuqduz7+uAp9eXeh8hTHClyO5rSuz2fIfGmJP9FU8u5YrDnjera7nxuV9R3khi/9BMKP5q6oNEHcTkPqE4r+xPk2ZYwHZeCZJ8iB4LnlKCrJFQi+p8sSby8UppTQ/SBVsaaQvu8HgtOCpXl1AIqlW0wq5nXMVF2uyv2z7ptF1dROfX8xk3LkSGt1RNmf2IYi92o0FViZaitPbT6Ojsx3NONdJM7nDoN55ChKEmT0CVBOdm5cV1NB3usbViQPWvsOHha93OAclWSLbwlEtw0hdyWqCtkzKXkzUWW3cZbCSN2CARZz1W3kOKLxxqtriYhUSm1jtbaqSSQbX9PJp8F3Z4t1BATGmq5NU/01W+J7kFm+Vx012JPmdMD3sl3DveA2iu/6N5dbjYTmkbQ2YW40xrA0/tZgbcmtcW27reGERmnuOS4FTVbsM6DdLZStQjDb48OtDdE7vF+m+Z3dORRD/tNPTtnGoVsepa4UetjbSdTPilDZ5zk9nqY/d3qJspUoyLq6ifuO3sYqzF5iayqQLDuzC8dYWyrRU2w1FC0m7O6gag0KIu0lzatm2zctW+/El8aWeWtuv/2K5h3UpqwqZyTB3ED+cjx5mokYZ1tLuzVvNwrGoQzdugT0/sZnm7AVr6wVVWd06kr6+9hzca5CmhVxerhwmUivJqyI1IJ6Dp2n7/ae3eOPzL7aBvD8UkgkK2Aze5o+LoG4A+rMIKgvcFdRmomTg6BtlD8gHg9LZxZnPvu6UvzpzxwPc2hoWuj3G1hxpdbOnNH1HyOdKNWkTF9PQiVmX0+gyci+noYrX3smCXU+OgjwGKdi0NNdo9f5ZGF1sELij7v8PlRimos2N0Zf+jmSpXk/7t4qsINmFLh7NfCUKtH+7KrDoYqv8sD2KWkK2N15R37eOax0sWbPtvfeWNcWznHKWlWySuPae2jDODO8ppru0Ojui1XvWU0PMaubH8PBliRVhkP8uSCUlerO1WqFiEP1v6tqJqM=', 'base64'), '2021-08-09T11:56:31.000-07:00');");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('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', 'base64'), '2021-08-31T11:05:47.000-07:00');");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'), '2021-08-23T14:25:14.000-07:00');");

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

	// win-systray is a helper to add a system tray icon with context menu. Refer to modules/win-systray.js
	duk_peval_string_noresult(ctx, "addCompressedModule('win-systray', Buffer.from('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', 'base64'));"); 
#endif

#ifdef _FREEBSD
	// Helper to locate installed libraries. Currently only supports FreeBSD
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJytVVFv2zYQfrYA/YebUIBSq8px3pbAA7w0xYwGDhCnCwrbGGiJtonIpEZSdoIk/30fJc1w0m4vmx9M83j33Xd3H+n++zC40NWjkeuNo9OTwc80Vk6UdKFNpQ13UqswCIMrmQtlRUG1KoQhtxE0qniOpTtJ6XdhLLzpNDuh2DtE3VGUnIfBo65pyx9JaUe1FUCQllayFCQeclE5kopyva1KyVUuaC/dpsnSYWRh8K1D0EvH4czhXmG3OnYj7jxbwmfjXHXW7+/3+4w3TDNt1v2y9bP9q/HF5WR6+RFsfcRXVQpryYg/a2lQ5vKReAUyOV+CYsn3pA3xtRE4c9qT3RvppFqnZPXK7bkRYVBI64xc1u5Vn/6mhnqPHdAprigaTWk8jejX0XQ8TcPgbnz72/XXW7ob3dyMJrfjyyld39DF9eTT+HZ8PcHuM40m3+jLePIpJYEuIYt4qIxnD4rSd1AUaNdUiFfpV7qlYyuRy5XMUZRa13wtaK13wijUQpUwW2n9FC3IFWFQyq10jQjs9xUhyfu+b96qVrn3wTxVESu+FUkYPIVBz2KM+SaujM7BL6tK7kBji9OeP+7lHMTYCl1d2oKdeVNvxw3G4GhIs8X5wZJvZFnA1g0oZo3hjw6ZJZl4EPlnyClm/aVUfbthKc0YlkXSojQBmXWFrh0WAzDGfnCkVcwK7jjiD3XFeUJPjWSbyA9DyjOnp5ilWsfJOb28zSFV5vUh4qi6X0MtK00RfSDfGiwRPRNg2HyumP9+ZjDw/T0xZOFDixG6+N1JSi6leTTdcK/IK7m0hHp3shDF2RyXiuQq5sPhqefWxrjZ6SKlUi59XOtTgaPzptlgAaL0wg7Jn1lHoUv+5AG75IMUrbYeJrMaQL8MfJYW7N2gBZor8SDdXEWvqt9z6S5hj5Pzo3latPvtBDL0bxsnWZsScKwLgUZiHyb9PUNs0lgbxfR64PgTbDO5AAY3zt7hEsRdZxnYssRTzbXC9awFqLZxHnAHFk/e9YxaiJc2Ye+/y+vf9PX/CewHCmMHhX0sIaCDyPxY8V5VjW2XHVn9sOfsSGkYttP3KUX9TlXYzfhiOIxex0bfaWB+EAF7zfCtCnq7rNR585L8sxI6V9z+rKrtJt51lnaCMNdGxVha89IIfu9/4fjFP0NbXdSlwKjwx+W84PxzBIe/ALtaHGg=', 'base64'));"); 
#endif

	// monitor-info: Refer to modules/monitor-info.js
	duk_peval_string_noresult(ctx, "addCompressedModule('monitor-info', Buffer.from('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', 'base64'), '2021-08-24T23:40:27.000-07:00');");

	// service-host. Refer to modules/service-host.js
	duk_peval_string_noresult(ctx, "addCompressedModule('service-host', Buffer.from('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', 'base64'));");


	// power-monitor, refer to modules/power-monitor.js for details
	duk_peval_string_noresult(ctx, "addCompressedModule('power-monitor', Buffer.from('eJztWm1v4kgS/h4p/6EX3cpmF0zIfLhTUGbFEGaW2wBzIblolIm4jt1AT4ztbbdDUC7//araNtimzcvs3GlPGms0QHd1dXW9PtVO46fjo44fLAWfziQ5PWn+rX56cnpCep5kLun4IvAFldz3jo+Ojy65zbyQOSTyHCaInDHSDqgNH8lMjfyTiRCoyal1QkwkqCRTlWrr+GjpR2ROl8TzJYlCBhx4SCbcZYQ92yyQhHvE9ueBy6lnM7LgcqZ2SXhYx0efEg7+g6RATIE8gF+TLBmhEqUl8MykDM4ajcViYVElqeWLacON6cLGZa/THYy6dZAWV9x4LgtDItjvERdwzIcloQEIY9MHENGlC+ILQqeCwZz0UdiF4JJ70xoJ/YlcUMGOjxweSsEfIpnTUyoanDdLAJqiHqm0R6Q3qpB37VFvVDs+uu1d/zq8uSa37aur9uC61x2R4RXpDAcXvevecAC/3pP24BP5rTe4qBEGWoJd2HMgUHoQkaMGmQPqGjGW237ix+KEAbP5hNtwKG8a0SkjU/+JCQ/OQgIm5jxEK4YgnHN85PI5l8oJws0TwSY/NVB5T1SQ2/549GnUGfb77cEFOScnzyfN5mkrnhx1xv3hoHc9vPo4vO1eqen3zb+eJNO/3g4uxu+uhu2LTnt0rWYn8CSz3dH4ojf6eNn+NL7q/uOmd9VN+McP7nF8NIk8G8Ukgb9gou97XPrCrB4fvcTegO5mjYcPX5gte7jeUIT1eUxptGKyxP6mwZ6YJ0OjanXxSxe0IJmwbOq6JrKqESkiVo0X4WPZglHJFLVp2DPQLXOMUoLwuXzugeJey0sQwS2norZjl8+CowUuXRrVVhoOsQLanRGYk8H5m63s+LvMnjBZb67W8QkxA+Hb4F8WsJTgRnNyDvpbcO/NaSrBy1qQRoNczxg43DwKJXlgoNMpuD3DqHrXfT+86hKPLS5xyAN/gqiY+f4jRkywZqKk8r2CMmpkZWbTxZEqedEfQM22yGu1peGpVJflNV/zWSvIjI/Z7hjkF9IkZ+SkmmH4mtMrcs0cKsfco3NIjug5D9R+3NQXKhhp1G6xVUGalD7ncnkJwYYgmRLwjBjv2tfX3atPBgpZwjzvWLAJzmrU9xaia7sMWXLcMN3ytehvHBQZMtmbz5nDQWpzrZeQuZNNbawCEGqEqEOiVskIT6X8CrwF/nmQhTFHM5uuSgn8W0AujHPeLfccfxGSPqyHDAfJDCYSL4aFSSqEpXGYr7d3mMtAtygbCJ/aOj52dXdMuNyLnjUxkVruI4Wqdk68yHWLjpnqNCG5u1/thg/mQYc9Qd4NYXKlpAlmKIh7x+FitPRs02iEy7BhuzQMGyrBjcMIylicCFJmeHwTOXKsYwnbTCrJCJ6ednPH91C6t27ZMMjPKfM7fg8/jIZcBgzWS38EZdCbmvBV8LlZVcrrQ1UPsylNI4tGmYfsb7Q22T3AaR4L45kIev3T6y1xnL01l3E0K4jC2UGS5BypXFXrzJLY6YfY68u1VUy/ARUhAyi6TYW5HUA634MA1CoqK7VWzKxSXOZNgeFbyII7xJ0yWSg8q/xWnDN3mwddK4zmCG40fqocTzOuvFJ55MZJqpvUmm3xwW1/PkTpmV0S17ARZXO53KV+jRmyUpyTPtpg4vqA33CgoXHb2EI6roLJSGB1ieZbPBUfLW7QmtWs5nIxPlCMRhz7lISOKMK4zmCHA9UhoFOKOF91MuCjvRpZMFW6sIEApM19h2NlXRJoTuxHVbiSEh3jl13ydtSyrM9tzO7pdU90++GLazBucM0P5zpAsLfXaU0AfDU7rsgZQPENWAhr9nCx11aZRpWusO8VsSYQsiS/9Ihly8Fi7LBhiRhEKRZFv6yRN6qTWcMMzQFiYakdcHC8vNXTQRO/qAZge1FakVkZ3DmmDg1A5D3KyGpDKz7rOmmvOYPmIqYxSWFtbM0EkBdWlyPc3SJpAmFL3drAYjluSWRkiFbZUeG9OlJD1otbC/haK3DJ9AypCbTo0aECmioNfIzbVsthEyhvHyG1MCGXCSCvjG06mTDugQUqtaK5lCLPSMaJ90sI9oy7ThZpqoFxIjYclj0zG0sCgIcH7jXCGZz6zoCPe5151GorlI4fSfgQCNuMVn4Y1edQSXPNk73qzHAVVCg7U1wK/d3GZtyz8JIGZFSdAXQIa1V99tgzl589rTfFHBaUyy4QaTNgWmeKJyspeK/VrOI329KvRRIb5v6mplsdjgmhMxsOfxOz/c/8Y9M3KsEcsj2pT1XtJf8mwMf4DI5BjH8Z8JMuHkn9PX43Kru5GS8bDqUhglGFs8/DwAX/+kuzFixErdLuVKpvm79UmpWzykmltSenhMdpTR0AEgIBOQ9ai+vuTu9r9mxaq/y4/+oA1CwnpPLy+XOF2vDfGfkxrMGnQi/J79dKTZ21Bkymd837FtmDe+XVSAO0ROm54CyUdbHcK8dxb+KDo/19NBxYCvjuG8z4pPGPTHYATZtKe0ZMtjvzpkxfoBSekWYthoFnpN7c9OSt9ethK0rcmN2RUfBmayc+zi5St07JIovaa5iYIIX9e/wUWGS4aYyRAYYJlNjzqmyr3XKnUJbYC+/u6rtTVeZZbz9VAe7qLuH28g60ppwHexmyaAJYl9e+voECqvRAW/rszEXjjhb7vwPPN0Lgj8Dz5CMuQy5jwUV8+54NutU4XZoA+Gy2ifLQOFCl5zxk2fKdDOW8NYj9JyXPKEEwwISCfVnfaIvkyjBsrQa+qIEvrex9rdIN9KqYqorotNxGNgVhk1cBZ/o+sexG1wLn+xhvNFx4TAygF1nvzJ2qJUPuYOye7N9RQl9+y1QXLiJPvdKiIbn0wbijZSjZHN/WYRs+o08M23AA1A6h+EJSkES05HYY0CLML3zxqN8JreUH8Zuxc1C2S8EGszP4NvedyAXQXXjDVCNzJme+AxNZJ8G+R0zDM3J3j/foZa1vsabt0AM+iXSWOtx56c062uEGhrAXLDeWDR++y264o6+H+GhudPBJ618x7e9xhEB5q2kMfGWikLj+dMocwvW4PX3SOhocKGlg6cFzHU6P75yxO07es5mJdst2SFhZ64AOdlAivkXIk8O3qzBO+KhwLu18NMdibsj2jp5cuGpOjiMo0YoGAr+eeAbMz7jDzPz7p+yDEfOhn1Xu+AO+LeN2H9DXjLqlNsWVaP83p7D6Q9/qKBMMqORP2A4/L03jRk1bjlvOJeaQLO6rWDSNEfOc5C1Re9fKLK2Zf2ddy7//rhXfeNfIabmnJDb9YzZJM+eYxahYZwXNkO7tR5zUk9sITVYvC5Ovvh7YL1hSqm2NJ2pCGxqZxaXN5M7F3yBEM3Kse6m4BU3e2avi4PmLrTcUOrM5bEIjV2oNlqZRSUZREPhC4h8n7ME34zEbSTWtVerwC/rINLAnM2z+eRBPyjTGOwfDnfLIWOPc9U3T/uDlkLgq7oLhtf4FDmrUI/W/JKf6oMvs+HVRUWBweExmGWhDy/Yddlh4ZVluzyYH5cLvAPcwgJsJ++/49ju+/Y5vd+PbR/BQ5m5BuL8lBFsxbsplA+XK6xm+xe9C/YhQ9epWZzebkoWm5m8y/3/w7Q6gpJf1UGSk/kAwzpRQtRFyhSmEyf2FKpD+BzWsPaA=', 'base64'));");

	// service-manager, which on linux has a dependency on user-sessions and process-manager. Refer to /modules folder for human readable versions.
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('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', 'base64'));");

#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('eJzNWW1z4jgS/k4V/6HHNbM2G2OSzNxdHSy1lZ0kNdztJqmQ7NRWkssqRoAmRvZJMi+VcL/9WrINBszLzmZmxx/AyFLrUffTj9qi9n259D6MJoL1+goO9w/+CVX8OtyHFlc0gPehiEJBFAt5uVQu/cx8yiXtQMw7VIDqUziKiI9f6RMXfqVCYm849PbB0R2s9JFVaZRLkzCGAZkADxXEkqIFJqHLAgp07NNIAePgh4MoYIT7FEZM9c0sqQ2vXPottRA+KIKdCXaP8Fc33w2I0mgBr75SUb1WG41GHjFIvVD0akHST9Z+br0/OWufVBGtHnHNAyolCPrfmAlc5sMESIRgfPKAEAMyglAA6QmKz1SowY4EU4z3XJBhV42IoOVSh0kl2EOsFvyUQcP15jugpwgH66gNrbYFPx21W223XPrYuvpwfn0FH48uL4/OrlonbTi/hPfnZ8etq9b5Gf46haOz3+DfrbNjFyh6CWeh40ho9AiRaQ/SDrqrTenC9N0wgSMj6rMu83FRvBeTHoVeOKSC41ogomLApI6iRHCdcilgA6YMCeTqinCS72vaeeVSN+a+7gUB4/H4vkfVL2HM1UXIuJJOpVx6SoIyJAL8Pgs60Mx87dim4T4SoY+LsCseHVP/FJnh2LUHxmuyb7twY+PXnSaSNmNGeFJ1wljhl0Brtt1YbA65Y3eIIjh4hs7xK/BkqGdG7TXB91TYxpjwnlNpwHRlAsY9HWjqWAO9IIBnwIH27S23wf7dxp9k9Ai2tX6g/WRveIitEc6uumA9WY0tPXlTYnSV83rfRT9T6Vq/48RbBmHcHdY8aLAfeGNvj1W2dN+GFq9xCsNguGF3LmbEIxLCBQu248HrExowi3YsUJOIwhtpZUZuxtWDu12M0CZDQo5zKD7tMkyuDLN0Ku6EO9J0bsr4AcmTMyD33mEqVmX13U5G0nC/kbe3yUc9u7Fch71qHvxouVbdsipuMuGCZ7ZNMN2RbNONZLOm9i2nY6Zu+RKzR4SpE3zgZM3JpxKT5CbNc30JqmKBOfev9vmZFxEhqbOct5XMyjSdgyi/Dw7uCJW15p6muUHTBfHp8XBAtfhciHA8aVOlBVo6Meu8mAK5qB+UD+v49eH8l5P63AZuaqKKO4tRT7SBMD4gnNMwQNk0GGC6qi9UiCIB083rBWzVzJfQwbU06snUs6j2UlUF9WPc+Yc0wN1Y9DwTBU9OpKIDL9KRSETTQtG09Oezlcrmrb2JrduUyNeCPFdEjIRWoGeTyZvGIbua1s2d1QASq37Twpto1DHfOoacDKj5Qbne+82DHSSWNPcb5AeDCWWWvIDMJivDVd0QpN0g7FAsYvzHnVWWdZ3ZoJvDO2g2wdIN1jZsu8GbIZxP8hZxRmLs6iDvv/sHojSwkZXYihB2AL1Nv5bXdXDXbFrFrPN0BWjBd99B3g3YvR9KZekEKMLflyqPX/dF/Niq8X8VeFh2J/D0Dc6dx/d1EGAaVHVuUK6wANaKYfCYdPliaIqAMOwmaFUHQRoImLvokXQHzlLj7d8xUD1sdNK4mQDibqq7V76Oy1KxSEAm939J6BbDVtWC9nL5vihJnXgwmLjzVJmJp3nw7aT7kksiIuUoFJ0XdIvePhY5+be3uyj0ttVve46uwan/V/uPiUFNcy9LAytJAn3pW+y2LkeSR7vWjU84SPtXl62Q1a2uvktZbx68kaZJ5+1qRy1r+V46PiergzM6FRhII5jvnRwi6NIrbZ1ayZ7pZunoGi13jaq6RsvcGWWNF4xcvFBV/Jn1sIcV2MCpFJbFDv1zNfExlY8qjD6SIIhIlJak30ZZXFDQfsN18ZokmVfFuMRcIdxJ/O49EP+xJ7A+7EDEfIwbrcaCZYSytxCqYEVryOMlIm3rs7V6rYYuj8JoZod1YZV1lHfkR6b6jm3ZFXh+XjU962HZVmU9D1fGJaqovYcF+srTgPKe6kMVDpYZTwNJd55lC/dlMfddc/p4QVR/ngXaO69mzUiF7F4TqNahwxqPgwCZNM1ej3TeDPHpZ/G+MbcRsY7Mp16adNUB4aRHRWLgImlErumFZdZn1NEnfI42xvT5pLa4Gin9mOYnKsB5woenIhxcsI6jjdyw2blb5iPqXbdPLvVeu8nONRpIelZeNRO1yYzkEBl2h7g/85jmppnmMHvHP12379sn7Xbr/Oxe3x8dH1/iT1wIXftwCfN6KzrQD4KSx0Y260J4/6Qs4sLrYPhmBHL4UmL3R1TqL5FB+QdkEDK1gr15zu2BvYs8mmDJEdN7ZBoULwqIwnQYzFPbJ5KCbY6n7fqcGVgixAHFEOqyADNwkZdLNNXX8ulSfc2pk1s4dFmI6uv35wIDBUpWXy9yBQbMGTZCLjqlX+w9zWXP+cMn6iuMYJdxiotE22riLHrOBfs+CJMSG6m05LghCWJaB2fOsMpWR7/QXwX5qzgftvQrTpB+zB9XkkQ3FidKofV5YTnqU0EZVg6z5En/V3hKCm94fQgFxeeq1ZW6IX+t3aXTqnNpyLSSj9LCUnZkBBkSFujiWzNC07+ec6H2XobIeHHGH3il4wI/YhUdU8AxBKsB7c3PAiF9wSKV/jlpuzvwbpGry1RdMywZKvSSTDkwIJ9CzE4sewaMm7uFnMpf+Bo3I3g3YTWTSrYn3Edex1Ik3DbrsCsFcDZAymC9cCZl1xffYTZOunaDXHgZ2GhivnEl/oXqr7PD6eyA8PXZqQtX+MLs6WOOhTdhHWT9wpm+hZpQJ7/x/fPq5uAOP8y54e3qVrYe18Yszq7ZK2bRtYEN+kpIusOL6Ib5pxtWkfyNM15DVQNw3fg1zZlS4HcRqEWtSlpy3ZLqDkuF/wOMU7WV', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(34657, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 34656, "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", 16000);
	memcpy_s(_servicemanager + 16000, 18656, "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", 16000);
	memcpy_s(_servicemanager + 32000, 2656, "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", 2656);
	ILibDuktape_AddCompressedModuleEx(ctx, "service-manager", _servicemanager, "2021-09-01T10:33:10.000-07:00");
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'), '2021-08-24T15:51:21.000-07:00');");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('eJy9V21v2zYQ/m7A/+EWDJXUOHLWDQMWz8NcJ12MNM4WpSuKJiho6SRxkSmNpPyCIP99R0lOZEdOXGwYP9gmeeQ99/Yc3X3dbg3TbCl5FGt4c/jdTzASGhMYpjJLJdM8Fe1Wu/We+ygUBpCLACXoGGGQMZ++qp0O/IlSkTS8cQ/BNgJ71dae02u3lmkOU7YEkWrIFdINXEHIEwRc+Jhp4AL8dJolnAkfYc51XGip7nDbrU/VDelEMxJmJJ7RLKyLAdMGLdCItc6Out35fO6yAqmbyqiblHKq+340PBl7JweE1pz4IBJUCiT+nXNJZk6WwDIC47MJQUzYHFIJLJJIezo1YOeSay6iDqg01HMmsd0KuNKST3K95qcVNLK3LkCeYgL2Bh6MvD14O/BGXqfd+ji6Or34cAUfB5eXg/HV6MSDi0sYXoyPR1ejizHN3sFg/AnORuPjDiB5ibTgIpMGPUHkxoMYkLs8xDX1YVrCURn6POQ+GSWinEUIUTpDKcgWyFBOuTJRVAQuaLcSPuW6SAL11CJS8rprnBfmwjcy8GWKKh6nAY4C22m37spIzJgkx2rog2X1yiVF8fVjsDOZ+oTczRKmCeDUKberg2b4jLBbCRf5wjraXA6YnHNRXzdDy+X6wt36dIUpmBCkKuK25RnX4THTzNOpRMtxhxKZxgeMuED/d0ZpuQ+WG0ysDtzRaRZciGR5REpzhHun91RVafqDHp0oujtJWTBEqU0kjJI7yMLFEUFyf0P9Ng9DlAQJk9B40whaTgcyplQWSzL9CKyYBwEKi3S6EeozXJ4yFduOq1OPckxEthXjwtoEdL8+Jd1+bKPzrL82zkzI6NveZigoDt+/2YxEtwvvuFQahjH6t8DLWiW/D1NhilgV8yJhjv/XGLoSKeV8OmKWKJRFRJ1dQ2o0z0jxc+FqOEb22zPn6XqDbY0+eEHejK9Jttl/klGrcd+83JxhO1hi/CvyJNldXcNS4XHolzfBq1fFbCNsZfpZjgPflHK7R6j09mwHD92/XIbwL+swwJDliT7aLlVdQKhzKcCmbwP1voHC2RQ3CFzQEtn65dw7pZQwQh7KGTUCI1vdz0PbiPX7NS/WbChJfxvnNxj8DLOYQexyIvIp0iulbHUSI9Ngl6ZDK2p/Fd/MkW4S9NgQ1HVzWfFN7aLmAqfb6qVEMA5WChpDXHiJB8ZJ9Ta4RfIWlx2jYsaaMtxIKMLqG59/JjH39Ozkk/s+9VlyTo8ZLrA4XS4PcylR6A8K5c02tirUPN2bx+YJZpfRfSyTUreboIio4f0Ch7vXBGkq3Ba5f+Qol0QjdnWbinmobSJZy6ueTNfXFxkK8Ir9rcxiXi42+YuuPewZx8HPRour8glNVIWyt79Ps6/nma0s+8I5Mwy9FCHvQ8kmbijTqb1m/JbgNfvg+tqi50XNuM/0cUPSZTYRlyt632nb+pV+/pVyYVv7j4vfPix2TS+zJlQ/P/5gPWHwLU7a0WgzKjbYBLolgPWxyVpNY0sreWFrRaKLZ8x7xrQtN+/eZ+o15NBDovKRdU5kAIOICtTqNZ1t8kgzl5tRMEPJvHV2qpYOpkzQk15SzKtfLq4osuLrRkZaYTXExUqoT4WKOjT6eVmJnOqw0ruqQdjf57tTBfWL6vxnfkP/0jJTIqYL2U6/v/lk+/rKroyqqRCPvappPJebu+XB5g33jY3XwHjovNM0yBMkM+nvtlbr3aO3ue2qx6b7IFoa1W79A3i885M=', 'base64'));");

	// Mesh Agent Status Helper, refer to modules/_agentStatus.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentStatus', Buffer.from('eJydVk1v2zgQvQfwf+CNFOoyQZOTvdkimwbYLLpOt01P9cJQpJFNL02qJOXECPzfO5T1QcmO064uick3H4/zZsjByTo2JDd6JSyQS2LgeyEMMFot0Wg8KCFKpyDSEDGL56DcBNdvUxqxGijy5FPsFohEFwlYy3MZu0ybFbm8JPRRqPN3lLwnjE7x49NpLnKYTil5U8d4Q+jbD1e3n65pREaE1W6Sx5RFfvO02sSAg5OsUIkTWpE0dvGfsUolGJYsCvVfNDh5HpwQ/HxaEtR490tkZAfguDbHTH8jFxF5Jm4hLC+UXYjMVR7GyNYVRo3JtrVlaIbsdi4MxOnXW+XO3328YWdRRH4noe+f8dvm6Ck0nq0UCbCLoc8cWV9E4xaYxxupY18NVUhZbTiz2f1TsfZfC/zry92E57GxwHwY7vQXZ4Sas6h2XFFMYpcsCINoz1lJpNIFnxlYMnqr1rHEkn0Gm2uFCvoMCYg1pLT26r+KbCfMoWxPT/shLKsY4EHbQrr33Z8j2onzmvWwRBzm+9Tl26+3LwAK5fXa1nVDC4Th4XpX20Cn3wswmyvfOkw/LIfYJbDuShWPy1cWHuu+ZI0xQyJDBCyb4J5m2ZV23Cwsy4Ulhq65oks+w3C48UySVToitMyDDjGiLGBE/OY26BCflm9YL7B9KXh/iRRIIpwIChyNeII94eBaKwVl0uwZZegWo2YybHvaqDxxhNJkZ4Z5tZyjFh2k0BTcm3lJo00wA8IYHSio9CXvByK8oPtEatsTeama3UwKl3xB/bH/UWQZGJ6hG1b2oi3bT2QbVhcn6rvztg9F1lrHUuqk1NayFmHPBOH80QgHzVCqkV7CQ3LWN1jyROcbhnbDdsZ0mJfuPCDc3fa6CKSF4yrxgjpcdwMrvYYrKT8K60CBsVVBX9DJIbyv6hFZHddHD3xEIYf096oyeqr4v4r4RTX8khJeVEFwNHs62LazpYKE7wjXjh4c/n5yOW+47Vza1sXGsXb8YftbLYFLPWf0Hz+h8ETI32AXpByZ3sAB57w54LnUD7HkM79RWIePDGLB3YsV6MKxvSIGBezE+qriBwnEab/s4sQFQcNw/qsfJDN4Eo41pzEk52dnZ22tg0FfjzXMBAekW4Dqj/QWsJ+oH8fllK+mMY7w3dCn3yZ39+T6bjK5ub6/+fAvbd4pe/yCI6xCQYps8R5ANaC3/euasJBACjYxInfaWNrJtqG/x2t9nFWY3joM38n7wDuim5jDSmPbZPqn0/Ln1wt+AOZR/UJ7WPlceB1XK32l0wLjwFOujbPl9VtqfrT7g1fuDzEsSd8=', 'base64'));");

	// Task Scheduler, refer to modules/task-scheduler.js
	duk_peval_string_noresult(ctx, "addCompressedModule('task-scheduler', Buffer.from('eJztHWtz2zbyu2f8HxBNL5QSm7SdJnPxq6PKyllT+XGWnDQTZzI0CUmMKVJHgpY1rv/77QIkxadEypLbtGanYwpYLBaLfQELIsqr9bWGPZo4Rn/AyM7W9nvSshg1ScN2RrajMsO21tfW19qGRi2X6sSzdOoQNqCkPlI1+OPXbJCP1HEBmuzIW6SKABW/qlLbW1+b2B4ZqhNi2Yx4LgUMhkt6hkkJvdPoiBHDIpo9HJmGammUjA024L34OOT1tc8+BvuaqQCsAvgIfvWiYERlSC2BZ8DYaFdRxuOxrHJKZdvpK6aAc5V2q9E87TQ3gVpscWmZ1HWJQ//nGQ4M83pC1BEQo6nXQKKpjontELXvUKhjNhI7dgxmWP0N4to9NlYdur6mGy5zjGuPxfgUkAbjjQIAp1SLVOod0upUyK/1Tquzsb72qdU9Prvskk/1i4v6abfV7JCzC9I4Oz1qdVtnp/DrA6mffia/tU6PNggFLkEv9G7kIPVAooEcpDqwq0NprPueLchxR1QzeoYGg7L6ntqnpG/fUseCsZARdYaGi7PoAnH6+pppDA3GhcBNjwg6eaUg825Vh4wcG5pSchDwsCr5RRJOP4K41LmFlkPVgl6dKKRfs+lXhS2GfQSz6DjRtooA62uKojIGU3tEr70+Ft+TMb0GsWW75P379283yFg14H2bPNRkINyqajAQ26SyafcFip5naTg8wlT3plpbX7sX0oPiKX87u/5ONdY6AiIkBNh0QY50zwQS9wI5M3qkCiPVYALkkaky4POQHECDsWG92ZFqAspHG6LuU9YFhL8PTcAdEjEtrVrqkNamjSLt8UHmaAPD1KNc5AXffFqkmkzvqPYBNCwkj1q3X5As3XCkr+Q1ka6u3InL6PDNDrxpAxyii82kDfJFCgrgh6T897J58Zm/dU+JBG2RPvz5+0lb+oq8jJLHKZFdptsegz84iZK0Fy+2raqkq0wFpOH4q1qN3AsGYavXB0STmd0BnbH6MOcwjXkdUcfJ6giLl9gRilPzzmDVZDUKQZIWGbANqzXyAmkS3Tn2mFSlS4sbFTAjPcq0ARe93ZCp2HscuUOZ51iRDnyu+h1EaXlIi1mdj7hhD0F39ISwxeqqYkrvhma+3OE4X8QhMqB+AAl9Uil9UkktIK0rl1h87rhpS/I4QclD2qzdNU06pBaDxoBCdsGfsaq0rzRBVg6l2petr2FZULT9dS/DPIYSH2Cc4vIlPoEuUprCGOqggInp3F5C6ahu5GtdqtJXO5WXwV+nLyb3WROfNfFpNTGtQyO2naOGe7EeFMXvBBrI323DikJmod0RsBnKvBdHK4A49E6AOR9xxHYAPGpxkhcRxFgfsQ572Qx4M8eA7E05EO38TciGCGgW/p8FeLYd2osR/CbgxM8B8pm4pwYQWuTzQuD+WTDDb5PiRQggzNResrYEaUXYlMWot5kTUXf6Hpa4PreS8/A27CAGmdXBO9EgOhNJ7AG33gbDfRegn4MdrLqAnzEPIfZ3PqudfooVAk/oI1LzEGsarypFczEeJrtIa1S8vqgqz7Ilad66Ub/WQ2emOVRl9BMs0CnwiarDalhvYz0bjsCtgXkVVhO9mwx9grG/Jz1T7btgUcfXUtqiY3fX0N2vXq9HHVk1TVur7iShrsUwt+4+fEjVbPs1zdRQXBl3FGj1OokuqPA77cGquoqOf+p8JI/1tt9JtXRLCvFFNteWHBFoQz0MBuD9n7MkBIyG5c+Q1Gkcd+ud3zpEOWq2m90miUZAyDKifCBXVkrgZ6JqXDTrmaggnOIlhYS7WK/UUV1aBimFqCYXdSzsiQMoSmQrpsjKdkajeMyUDM0Twbmq3+IGo96cFaTnAuUF60+wU9MJde0TlNtj99weU6czoKZ5dXW7LW9dXY2wxMWSUBcTRf9MtfwJ5hAD2VM63uz4O3g6brSJuSWb6F48RkkFJV9MLjK9QjYDj+dXBfPNawsqMmXxTgWqQI2wD9Ehp7KMRsWqy2lTdM0qNjllnfYMi5479og6bFJFjm+QSqAJHW+E+6qVjbR8mx7dJdXphD3hinQxnVAapPIfmJUTG+eEbLYNl9VvVcPkS6vNU5yZ2Iy5ledlawpkzq6kv3RNrjJrUfEIu+aLz8jGuwjgohZZlFTtEc9FpDfVUaSAIj9b4GceIkLpUJBmh34PefENSrj4uXthwXde8D3BE6MXdCtzpX35kgS//axEvvV3xwas0lP5gfkqonE/LFIIu+nqYMgj1RniMBI7MA3OLf56cUk6nzvd5omU3NIKHkwMVRFZj01GFFNbcS4nnwxqE8PliEDILkdgSxowEjA++Y1m4Jty4qR1etlt5rEiDnt8dnnR/lwM9qjeKgr6qdn8rSjsydlp93g+MD58CuWR5w6qktJp8OAri4E5s5eL6uSMo/Ln8gtHmWnFks81CM/NHLiAeeVHeLRyqjjvS9N1snK6uq2TuQKcIqvTXTldp/UF6ILFSCVNWLBxooD/Fkv3qyupxsOclCt4HNGd5sXHVmMBui9IxQI/4TLVYRmsXR6tGRuxM4qj8ZsgWPCPpFf1wQPuTl7tvj4nZG73qQCoIHx2sDLwrJtUwIKF84OWVC/5IVHQSwE80YMNyS2tNDR2hxF8vDtbp9gb3+mHdzwesBUO0u+ARyR8bISa0F+69rtABBBANsmmJE8qhdaYhuXd5ekMUhffR4OBuMztTCwNNIcyTdEc25J1JaI2PCRKq/03ePML5bAQRLl8SIGs5WOX+NrpS7JvFOGvpG7CuPUJERTP1N8gboW/eWA5OspPpAAHeWQqvcoTdAQb2J4zF0hXJ3NhhrbFBnOhxpTezMP2Nwrz8OH5z0AQ0LViXB4WMCN2emZBmoInMulK2mUU8BU5AhV9iru+YuEtPk/Jo1Di/wIcKhTU4xPozGI0Fyeo2NIBH5yyREQCzmJ7efMEq9lQAiB+j0kEsKNARyU6w2dqm7YK8BSfArJQAASd6NK4NvVCZ5Y5IWeWRpVPMDB4d8XOmDjR2eYOtkj46GOd54qiz5J1pKw8ymMx4D/+CB2wkOvlCedUVlZhQJYqEasjc/krSt82Z6/VdvkhqAKkh14wH0/q2NTjxldiF2UaJ63Gluev5vKjMj+RAER1jpvt9oFybViKO7iyzuvd4wPFcx3FtDXVVFyo2I385j9FYVgzhYGXK/gvL84L0hcHpOrPGCYLkSlcDIIfKL/Bu2Be8CtQQvwNNsq2GfzJtWl+LJh/lFv23/AsakdUdmFScmPFGfonpMKwYHk1RyTKZRgkf2bEUbZB9mZ/jJAS697MNitZ+6Z6esT6N4UrTGhVxgPqUMMNjuSTP4g6viHS/QgIZOSnnQcJxFNksSrF0M/MM+TyUPA9J/0wB1FESVI4Az1IbPLzcrFtdKjo9FaxPNMkO4cvt7My+slnnn0Rou2NeAfP0l2kp9VKN1oZjZl/S+lObX7GZHxl0i32GfVn6S7S04ptN5+KZ/leknzrtKd6Jpsj2NNF5KV1Y9lji/jxEDn388K78aNXJWKpOQNYfNOTOZPScRrfuEydymwcn5wdfYP/mx258611cdm5AOmbCfOpAMzFWfd45nZvtC1XA7QbS9zUnh4Hi50e3YCwWqe7wIhcRc3LBakYUeftzRXZK6er2QD38bu5Cjo7+6CrztiwZh1nwOQT39Q/WGwqZmyRA7CLx0Ok/V/wePGt+Fj5oLItb1UItTQbrGT/oHLZ/bD578ovh/nrK3gErteI7MXRWaP7+bzpl51f/tpuNUhlU1Hqo5FJScMejmAN5ijKUfeInLdbnS6BLhWleVohldg3ygAua/YQAV0lOIeFZ5M2oYGsM71SmCrxGhtj0baE7OuGxoqD47N/QyeHbfWamvsKvhZrXBWt913uHg9RAUMBAEO9r/gVsw10Ji3Avr6jDsPz6mXICvCojqOWbDMdDI9KTBW89gC8bHQoi2DjDq0kkqqUQJLjDxdls7IAf/jcXHhWnbVtVV9kUnqq6VKlaKP7+/vWabd58bHefnh4KCr/ShkF2Ff4++H0g/Dks6gHdW+1md/IZwQD1cT8znIDPDkEfciGi5NBdYgiwINhiQm/q9nfkgWPIA6DqEV8m/sY5+ZiCryYE8t3BxDsAotUc/YguOOgjgHOAYf75WvuJC89u0pWkV4tnBgT6WnDnHzkLBqpjktbFquWP4eEYhZi2ifbmD4Ifx+SN0tMbU3j65YFU2vo5EyQKxUTmOhTYJ8+NrLDZebo+ArYcxzwXEc8zVDFQ61HeAC2VkN1F697/HuxLbIJXCyOGIJVTzUF3mknBTNWur30/GBkoGBPA4YWpAcffqpmioTLVJx9kR//gtoSuAPlF8fHQpfqezJAGPiwaQVaFrDK3N1Gx4auIqhDV1s0SfhAxgO8Jqf6IjrK/cg8vnwZY8DrkIk1YEYIVqjDp86ixfmbH8GXpHFVmfk8O4iH3bfReybyxDa/ykikTXHXJUgVpwxSUXsTzdzvg+pHcrFYdEjeRYt0LihbySKAitOKTW2P4V1Kjmr16VLIOxCeNXpcnudMRfHyjOUjVTRtWif8M7cFtPUfpzwl8rNR6fBztWn54PiWLyHhObolhDMBPt/envhp56QU8fK5+5hRhMJO83YHMex/umcWYwTfPOXhYt5ZIIJIaaeW5F/s578AYmk+mqMs5KVPgiz4svy0QLgfndqorw76m7J16q953bPRmYsid433Y6zHyh13DdesL3zTCX49nA6TWn2uXVtx3z5vKVTItU8Xy8E+TMyF5oZFr8i7rbQzXeoZoXKnYX9MFj6Wj7Mgim0bFGJwqHM66lvA1uVHel/0r7ENzqKhXvpLn7il/1PCp1KMHa6YscNMxhZwoX811hY9GZllE5av/OH8sRXPH8ucv2Pbc8pMX/xkaGoy/YOBkQ5O+DnDRbvY/tPkpdwnelFZKR9FBPlH/ld26MhUNVpNZig2YpmSDqZ9Wn6XYbYEuBWSUXbrm29iZPi7pxtOQ4VuddVJDsuHE0mlMAUJYw3J9T+IFHBBjsb/GcDXpsLpg0TyVKWz3bNODrSNa0d1Jkqb5/iOVAphvKskc5gy5w9+Sol/09fgBM+KzjyVOLeUe0gh40qTMK9JMFNESvEi94KTeH+Jq4Py+LbwiYTZJ3am5v/UZvxObX6hmfjGgwtl8kKHEt1HxC3yGl+kJTQv7Y7OVQfYCirkbpChB6qoMmJSFV7E/d4TccEM3mvk5wJjDI90nJEYCW6H4WfZDKtnR2/iwN/R26kjpK7wEo5gETbjJo0Ez/JneCmzm5zZEhzVqUnjt5t8E0U/AlvnXEyy+o/SE1edHHHOBbfNhlcrzbqJAGE/ZBvNMh+1r/6D9mV8zF78Q/an/og9m94siznn4/VyH64/+oP1nKhokWMecao9C4Z4swyq/wnnDTPaZG905gwg62KB6YUCug0mFP+tEi5KmcFKBgH5wpt/9jFx7vGx5x3nKEOpsLWE9P+oASzo3JOEsFlgS7YY5aZ2ARNBnm3EimzEXy5W9S/kG/IbEkFv8diC6weg4l/K4cuy/wPfkZHw', 'base64'));");

	// Child-Container, refer to modules/child-container.js
	duk_peval_string_noresult(ctx, "addCompressedModule('child-container', Buffer.from('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', 'base64'));");

	// message-box, refer to modules/message-box.js
	duk_peval_string_noresult(ctx, "addCompressedModule('message-box', Buffer.from('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', 'base64'));");

	// toaster, refer to modules/toaster.js
	duk_peval_string_noresult(ctx, "addCompressedModule('toaster', Buffer.from('eJztW+tz2zYS/xzP+H9ANJmSavWwk+ncjV2348ROq0liZyy5aRtlXIiEJMQUwQNBS2ri//12QVIiKb5kO9feTPDBFvFYLBaL3d/i0f12d+eF8JaST6aKPN3b/zfpuYo55IWQnpBUceHu7uzuvOYWc31mk8C1mSRqysixRy34F5W0yK9M+lCbPO3sERMrNKKiRvNwd2cpAjKjS+IKRQKfAQXukzF3GGELi3mKcJdYYuY5nLoWI3OuprqXiEZnd+f3iIIYKQqVKVT34GucrEaoQm4JpKlS3kG3O5/PO1Rz2hFy0nXCen73de/F6Vn/tA3cYotL12G+TyT7T8AlDHO0JNQDZiw6AhYdOidCEjqRDMqUQGbnkivuTlrEF2M1p5Lt7tjcV5KPApWSU8wajDdZASRFXdI47pNev0GeH/d7/dbuzrve4JfzywF5d3xxcXw26J32yfkFeXF+dtIb9M7P4OslOT77nbzqnZ20CAMpQS9s4UnkHljkKEFmg7j6jKW6H4uQHd9jFh9zCwblTgI6YWQibph0YSzEY3LGfZxFH5izd3ccPuNKK4G/OSLo5NsuCu+GSuJJAU0ZOYplaBpRloHTv7vDx8SEHAsY7XgOVcDPjBwdEcPhbrAwyOfPJLfYpnLO3eLyMczJyLeN5u7Op3Dmx4FrIcugXq79lqqpCVPZDMuiKpiQa2vKHTvJs864ijoymh22YNZL0FLT6I642/WnRou8N+DfBxxVTEq36vjKFoGCfxIoGkZRuXBNGJSiQGnFqWlNA/e6ST7pdaFJfHdEdGZHiT4ojTsxm4fkNtnrXSWakFhMKiGWFL/c7aCeM7MxB0VjoMIN8h2uDPjbIJ8JnV8T4xN0w11Fnjwlt8bQZQuuhm4jyent+idzfHbPfqu6CKnMKVenUM+smKhsVgeEPTNryTkWJPnmmxzKqANYstKtcahQYAP8/tK1QKUCX3YdYVFHK5cRDrGJaiCZCiToRVGdw+SA48oFPPxE3MBxyMEGj/EggdQtLtGVOg4E9RWT5npNabW8Oh99ZJbqnaB+q7BOrOa6gm4HhWlCpuLKAQdhUQ8zW0T53M5fjzCSX6kDFFw2j02KuV4lYOVaUOfjaqFcQY5evv7hKuOjzviYs1g0H1oob5g/fcFcJaljaGJyiX/D8vWMYbXjCdSDiQPbDZO/PKMzBqRhMMqaEnOBrW/Jbex1oumAQXRiavr/4UZxJA3UwPDXYZKGDw4Q6Wf1rmTNUrC+BpjKZ0+Ng3RRTu2k0C1uH+aXRqwKL/QARzBW5t4cwL8rPaoDEk3tVTSGg3gwKJMCouiITN3vPkNHGg8RKDfzWxTwvskh0ngPZD8AqwmyOquAm9v8bFCI+/IScPQsqOuocnoJ/rRWLcBAsg1ARDtbUC8L/gmHXXLbbMJSxWYFHGNCbc7r7giMAE85tGw/E6behpI5n7tMojqvlQyWZUcvzoKJqBAAJps5TLEcWZSMpmAOMKXdxZa88LGpxf84Ej+a6fBzr2SANQhjikaIBsc0eq4fjAFUcbAVCRSFUDGyG0TbS0IBR3H7gKAd15IuEUuiJ23ewx6rWpQIM8F2PDFq6bEy/NP36NwdQCW/c9k/vdh+EguyI/PJ2J2XfCj4F9TFiCIWMmo7hhgIcDVsJYAfMFbQBQAjsLIjJhMA4AAqy2RZT+opw5/DZX2AmbRXaMZtLo0PoCXGcNhfgqedPXs6HL6DfDH334o5k/0pc5zh8Ga/szccepjjYw5S1CB1nQWfRtsV0AMGXNEXSEHonxB1zQDs69/Gh1ZGQ4oGnhxfx2a+JbmnhHzDFEVwm4MQSimoCDmEmXVarGAMgMVVw04CQdYkwqS8P5FiXI/4AK21lcDxHe5aTgBCM40fTnr9N71+//TkR6OZwP9rBGyEYNdAyJeGNFWjEhBIF7G02c0TMfr4nDqOEK7GOgKQV/Mw0Xndrtck34eK27lgY4fp3jvHvs9mI2f54eDgtaD2Owhg31KpOHW0J2pELSI977wEyOM3mkM5LF6sxf0nhgSTe8bm7RDAkrxeOmdoNpY9cMT3766DZKDPWAInksKSnnTCTyz0QQI9FyGdtlMP0OWv3OcjjTifDGTA7kjxgk04rtpIVKc36NHaPdcLVCS8pFTbuhynjkRZA+69cATuFLWPQ4X7RPJV6x122P5FwLpv/PDnah38+WMDwsgCt1BPEv2pmK/ZMff3ILXIE4SuVxFgDT9WEcneFiqm+IzBegc5+0wNwg8zuby29mhWgiYClRKvZG21aAt8VotEIkmOq9bY0cYh9ZRB2X7AOhhDCxSPO0JoaJksh1EZizVZKR3zZlNYE72IDgpNY6VQxXIoKigURAUgyGFvJBm9hqqP4owwTIt3DjKBWlgYbt/Uj+HuEauso46ymCEZm5QjJqS54GDWkuRmwuUADdqYH0Ygv6HlMzd4QOKPHj3KoYkcuWhlyiOby6haPuk8nsvh6WJxT3yKBL4cxgyjwFjKIAk6Ye2RWIAw/mIg8+XdVmbZniKEUI9XXeq8tj0KUPxT6veZvOGIOYScdFDFAeJcK+GFrjVC5FD37tFlt0vOBDlpPw98sL66N4yxpoBfwfMlgb+PG/NkzsgsAAczptcMooB0ZIBHDH+cnvUGv5O2Vs6qaLJC2itDde/YEoYZWUDSDzxPSMXs2hFp/ZCjfDQeVVOMI8JPHR6ES1j/0n70CMPY5HZXWMQWKlmy8rK6mR7W0fcYaXwKY+GNxdqKd5l+O74c/HJ+ATN0kLIunQUN1FSAD1y2CBj6t6+PszXiiLAEM8epImIu34LAVG9GQXEzk7qpolz930/zP2des8KqRm4IP7JYDHKuuePo05cW+b42bopTvf2YGnE0McMp6kbTCLPYNEr2Y4oKyjfbapi5kRTXzMXjpfJ6N+GB8Pu9D+QH8gzrVxBONACX8yx1eFLaYB972N+rcCyVriVyBklvhXtG4Xjv7By001n6zLUfxDFc+nhSGxJtI9XqVinmsrBpPhV0xs2m9vJSCFUUe23JasTuO2ZIRpBuytrJwA1P/KXEmBJsBJqTelTx7GBhT8qwIJ78nro3mzgQLNdvJz9fXVyeDXpvTq9Oehe4t4EC0hTXYUjYgWGUBh3JtLVZLj1RrttTOhz0A9ImCZO8gs3fQW7bIg22QL8Tm9ak9U5bV6h/SKLKGXnpRigdXSehh2RoZP2E3r400gXxAZEuWp3llm7FxqnGTFQ7a0zbqi8F5ieBA3qHEo0V2RauoYgbXQmxBaHuEsJQWJ36jgV1vpDiVNqZlU9PzI7RynjwjNd+IPlv484S3JU5sho9PxREe0mvV8b1rmECpocKFWpyHnF/h5ABUxyvzkapoD3FtSUZVauwOleDABu1yP6WNgw6rbf1X9Z+ytwEilvtbhdtBiGMW1dnNepvMagtDuow/Q0W7aHCEExfQ5EtQpGswP6ecATTA9vxrcKSiv6/1FUADZxZHsKvH559IQ1Pepuspueo+N+/m5IjpgePcZNCKY1yq7e4da8elXiQVcPL5J8Pb1zprNPsPjc9y21K/fPnuLf65HLPeCxhF22FY6q8iJM+77nHOQ8mXTuc0dqHPZgKZVDQX7HFKRlvoDheYFzdPTaubQgFxKSUMxQQNmySjROQasOG1+lfnfSOX5//XF73nxU4Y9vHqTOjz5/J41yzs1GwtlgPfpFLYcjskFMphawVlW59PevRo1rm8iqMj2p5HdQd9Cuxrq3dyEbcBwUehfm+YZ7wAs/YxPFGPXdS6ila9bxNRqUOtPbUwFNpEVX5lEgqVbAkQ7S+y8hpfH+bnE+02q1sS7TY3Mc+qtDSlvf15W51ft1qzWX361br163Wr1utZenrVuuDbLWWmeBF9PlwuKzGvmT2gdH3YHvOX9VFb/FGIvzcZhuyxhYkVKncgKys/E+4vpDCyH+EIfqrE42quvGM67v1YxHAArgHy/WfEZTctkvmhXfqolekOZfq4qGtt6FLlnxG0/LGmaJXA0Sm62c06SYXhN0Ub2Kvq32E3ALtyYop+3otJ5yJH3Pxcf71sPDd2eajvvBRHmIOyl0mNx4IZorM9RtBFHTxazcEJlpih5v5o/BC7GH2xH/jnmSO4m9oAQysHWGaXLUere6XhxPYZ2ogqb5Gbn4i/l940/FgbZnCjEHq8VxE4tx1lpAnA1Ywa9E9XwTsWlgn3Md3Rsw2svZk9ZYkfP+6Se82u0aUNTWzNjtHPBnCpUTriDvtgdsrZYAFFy0/FKKiKvAPiCGuYaQeRqWJF2s1x/bAg9P6V7RzP8I5QH8yEzd4H3tzPlrkX3rnPprTnIfM8ZvcmbADh3VCgOhHL2NX73MPq9/V17mxuX7nW1UzuXYTNz4R+f5vXtintmNJje3Wja3W4gf1+c/467zev0sn61gCVJTod97+FMx3F4Xe3u9G91v97red+KrrZzKRzCMNxPhxsBE/w2+/PAL0j4+NTPLk6dFRplJoFsJn+vol0dDIDQhKHs/Lgmfm0Yt5vMRvGEmHcftftCriLg==', 'base64'));");

	// notifybar-desktop, refer to modules/notifybar-desktop.js
	duk_peval_string_noresult(ctx, "addCompressedModule('notifybar-desktop', Buffer.from('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', 'base64'));");

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
