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
		duk_pcall_method(ctx, 2);
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
	duk_peval_string_noresult(ctx, "addCompressedModule('http-digest', Buffer.from('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', 'base64'));");

	// Clipboard. Refer to /modules/clipboard.js for a human readable version
	duk_peval_string_noresult(ctx, "addCompressedModule('clipboard', Buffer.from('eJztPWtz2ziS31OV/4BR7S2phJZtOZPNRuvdUmzFqxu/zpKTTCVTOpqEJMYUySMpSx6P77dfN8AXSPAhx76Z2g2rMrKIRr/Q3UA3IMz2i+fPDlzv1rdm85B0d3b/SoZOSG1y4Pqe6+uh5TrPnz1/dmwZ1AmoSZaOSX0Szinpe7oBH1GLRj5QPwBo0u3sEBUBWlFTq917/uzWXZKFfkscNyTLgAIGKyBTy6aErg3qhcRyiOEuPNvSHYOSlRXOGZUIR+f5s58jDO5VqAOwDuAefJtmwYgeIrcEnnkYem+3t1erVUdnnHZcf7Ztc7hg+3h4MDgdDbaAW+xx6dg0CIhP/2dp+SDm1S3RPWDG0K+ARVtfEdcn+syn0Ba6yOzKt0LLmWkkcKfhSvfp82emFYS+dbUMBT3FrIG8WQDQlO6QVn9EhqMWedcfDUfa82cfh+N/nl2Oycf+xUX/dDwcjMjZBTk4Oz0cjodnp/DtPemf/kx+Gp4eaoSCloAKXXs+cg8sWqhBaoK6RpQK5KcuZyfwqGFNLQOEcmZLfUbJzL2hvgOyEI/6CyvAUQyAOfP5M9taWCEzgqAoERB5sY3Ku9F94vkudKVkP9ahqkSvFBx+DtR3bs99F6iEt+NbD4F3erzlYOn71AnH1iL79tR1sl+x74lr0gvq2bqRbRlRmxrI5oFN4es+6f4133Lqhtb0Fpr2dvNNF8AxDUJsixF+6k/OL4Yn/Yuf4W3c4eD9ZDz4NBbfXJ4OD84OB3HDXiLs2rAtb8zsZ5/c3bP306XDKBIHlHpD+6Z5ADaPg0dNkGxpU9XRF7T9/Nkdt2JEdKPbS8Qxo+F/jrJQvRTmV8vLqt5IsG6BxVF9obQ7BnyGNKbn+mrcH/p2rpbTKUXFOUvbzrx3HVUx9VBXNJLwrhptDhDxiI81VdGjEzwcUTsFyMDiIwCTd+yPjuE6hh6qn41fYtbwuU//pHZAH4Yy06gRKf77rDqoY6pM7Vkd36DzgpfsZzTWCd0Re6sqV3pAX79Ssj18ikbVMpfXE48CvgnHMHFcGIKlHapGuNbIl5YusQOlRV4SHGb4aIH6I4Gm4FS8LWaHNyfk270vEHBbERfWlKjARcemzgwi6t/J7uu9nZ3i+G1vk5MR+WAFS90mo3BpWi6Z6xAFIOSuA+tXiIFJKEh7oYzhAi0vYiajVi67YswB5sVEiYTpBBCfQlXZAoP86lpgXUobmhQAHR5bVyd04fq3k75tuzBsoARoU4FCzP9LssvANbKjkdPL42P+X5DZUXoiX1YUHuJ3qzlONqpF/kZShOUGiiiM+dK5BjQIHyyvuIiqpQFuYOT1DiiyJ/ZCoV/uE1VZ0IXh3U4CtV5y/s/iYuUF3iJWJHALmzhH8L3FQdn3VDkKU0SeKQtZykLKnSvhHQficHkd6h6dyCIUM9qWkponclMrZ4G1hN4UZtV6PQn9I7YXjKEOzH+uHwZo6AhwL4uz3xRdN/Djpt6bfcEjjSSU5H07Bfmd3LwR108fBBjp9Gv3DxETXv5rR4R3bHQPqQELsMFaVZdOYM0cWMji4L5o10rF2ROGEd5tjCb6J+Ipjy3MZZfBfDKz3StwXPfqK6z50F/bPWwDr5/AOtWLPJo78tYuKDfx5RaHDFa6NwldLwLp8rcMd7avGBdLgJ5ESkO37cmChnPX5FSARcJaONO/TwCGlMfTQ2N+QXVTDSxTDL6WGXlkHMYQZH8/s3YU1phEhbEyYC7qQAIQQkazwJWmsrKcva5S7be6gRNBdo0MWai/BakgS3dA1igFUdudPoPN+wxQ50jSKLvTFmFydFk3lNDT/YBCXh0h+LzzS2fECQ/NvG/eS12xcuXLaJTKBUvgwLXppWWqsmUv/0jxZxWOeGFA0jFPZxtsg6Ejv/1GpGNi6j4Mi1LajjZ3FZgMQD6qtuUs1wr5858zaQ1kVFeu7psgFkuv2kUrARtc+pCkiKbZ8dH+2jnzlUrNo7xlm1GqatEAEzgSxCP2FhVz32tgmFyEcsNcW87UzY7dwnWs0PW38D3ICNHp0xD+BG3nzSTHIWQsN4zLT/3L8T/PLobjn99y9J21voSY4FvhrUYOh6Pz437ShM5p67eCMMkox7rgc7hDV3GOr6aZICx/NAD42gbKLMWa+Exb8N9e8uIre/G1l6ZY0TjBBGqg0qB9qsNQ5FoXehCyXC5Rz8jwLS88cB2sAFEfnZYltWpOG3k6HFMnW6MI5SDSfNesyWMjvBlxQn+Zjx8CJKpJLYwpA6FrCL6Co5ZIg6wisJiaw+xczi0a6g8yluvjWJ79r6oy8H0XzUM3MQ3N+GZ5RMPHpDYNqYiQi9RA6MGaGsuQRkvOFqs86Ri2K82kJw8hPCZ0wjl1EptWb9p3HGMnYFWAdu8+VbBK23dRPO1QFB9e9GLXj0YOWG/luGcBKZocI43cC+WgeJb8CG5KVTRAjTSbLHOlFrEk83vOluJk+ffvU+UfdarMzZTM+r5PlBtOlDVrUxw6Hnh5HKuZUB5n5suh6ySBEl9WwJVPLKA2FJSHbh4kI3mgRYjr2UaY+MV4LiMomXQBZxxrbXeG02U1mofODRGzEi6A5l3o397JvAr5uTcwaOOkUDFQbBqBaeK+JiDf5eeR/ESSiXFZsRl+5rQ90SLrYkUje4wL+xGx0FpQdxnWB3MDN2LGHFqKoVfsIwETdyQkmijvF9Awpp9aVUDtaT3zCBUjLKzHJEAlXGoEK0I7GmOwLQsdhYUAjM6EhesJLk5Cug7ZuiG3DohQgWnKJ6JNJrhIl8ySiUqlswRf8NH6VU3K5AMiNhJi4UzYycIXk8iSoR8FJ39v2VQtn+k08llZ2/gXFp1A/GibD78Z7JWr/KJBdFlabIrSCMwJcaTns+DAuVHbabRJOJOmEGlrEJqwKoQPtAhF6RWbSvbT4vQJe2JpLlPo7cnYAGxg12WEsOmRCEnnAnlpJsKbaOAH5Kxh5sTsK4egA3wt0pQ9Y6v41G8FCrlWjDvSWtn+XyJ+1rZFD4WVWN5DRfd8gny5JCr0GrCLXf//GJVFpJIIUIw+Kl1LdpbT8AOtGwSgT7u7FeFnAs2ZvZMf4GsFaQWRJWdD8CTFQRx0yInuWN7SZlsm+fKoPFVgezWly/RSo642ggq1CKqJ1XN0UqWd2SKXfmOhHMP1efGYRzGws7ieT+BzGDoTPnWeV9Rk8l2ERB0rfE51qQMANqrVol5Wc8jAgRsY8c6nj/jl3FpTG3FhLholAhqJvgcGJGeYmnY+6Law/oof7iyCsJ2D4+H58DCmggeufKcfuosClaOTaJ3/QfctPEqiKtj33Vn/4lBpa6Sw3VRG8f3J+KEEL8fv30xG44vh6dFGJM8vzh4s5KfR4Hhy2B/3N6I4PD24eChF7LsRsYuzs/HH4WlM7cJ1w4+WY7qrWlNpOmT9nwYZApzhER7woiWEKthkm6M7CS/suJ9GfmTvmMlHH22pDTMGRreOUSApVRfn13VuICdNDlk14pY7hryNmbC8iZtaSTeuRi17xKyU6XIZm7r2IQ1YBuj6g5tc6plrwtWsbprpWzXWmxOdWFsurqifY4cFGly84iQAKc5bVmsuJsYN+SuGYUmnh6KOqyb7RJThgfhwLRpJLSxHp2a7iFAS3vFhK4MBcFQMAbs73VcyLeITHRRgA3QO+TYumDnL2WGRsFHBCj4M4SlM5UxCZn0CWg2YLeMJH8jOPw1AUT6dquDJr/A4Bj+jofLy9iVEwb3u8QCyGUj+c4chS/it4TlWI8s0EzWeuxbGW2mmnO95ZYXBQ/sGvz60Z6hb9kP78mM+Zb2r+7MxPqLR7BCff82Pc2Xoqop5MOyvf/xxj4fy3AFbjWW3qG4NFKcxFWiRMPWMy6iyZIojiMyu3eEJZJ0amRre40kDsXujfhAKQt+9jea95qprKKRPF+4NzUTiqXSWzj5XYAXXFTD38ibJ60Lozm5raETYbsrlF7WZH88X8KC8Gq7DJ0//nrY69a9TnMI/2LE2xv5cD+YHrklVfsxGVrR60nJVeakoW343hMOHFUWpx0I3wRKys8Rjhwme+J3qFU2Bb0c1Gh5l+8pytoO5gqMBH8J5cGNeLK+l776prpai/3a9M3cq23WKtwzL82POhuV0VmzLWfECsqWvXeKBi265+FOche6YJIuhafVNhpoi0hj3ohRvvutvZOZTj7RSj/EK/tIiv7HDci2IOET58sVRiPLfCrzUV9dk6z3+rbSKI5ASuVOqWuEVqFW19nd71t9O3/devrTadR1qMeLDj9n9ydJC95o6gdYiwGWTjnhIb5+fPcXuhJc4VI7m8+4v7ZfdZojwBAFHgyi1XW23vb+PbIAJ1hPZQ2tsQsaYX2exRbReI49NWIy770dW0KpVP2k6BPB44FnhlLT+I2jBSiKWrpH6aoWvBGjdK18cLK1/cfLWudKtcJDfdkJfF0NTTYE9DgzXlm2rybEKAUUbJpfR8Oin4fGxwGrGI6Nd3fTHTJ8FD/wlnl4funOQQSxW7TM0yjbzKoqlXm4SAdisfBrppjtzMc0sRHEHIVlISCe+ZFhhmVUtMD/k5ZhVCFF3/9tgy6WJ8mp2YBIFlWliw+0RXHXiepPVpwtrzkcoyodzH1KAP0RFPlaEZKVd4k0bVt6f+PjlBDjFis+6pvD+vdpfUu3Po/y3rfX/+xXDaVrZPls5hTKtlvkF8WPUpWvJbVxNf6yyeJPR+14U/14Ub8YKPt9aFA9WFjvL1LQy/vAyuKGDdYh3D7yt7sF6Rdk9TqG7qjJyF/TKNW/Z2oS4KyeoOEsve+pKkUVOowsPvoHXlQ6+SpYBXoaBBxDxXogFYdWM+porPmhz9EZqc/Amqq6P8Bep+/vkDfkH+UuXvCV7r5sohO0T+BOfS+n6nIoEZ2Ihr8BE3rSBQPKmy4ymObGkYNeA2JsCsVebEfOiGn89rdev8rT2upvRCnV/RsN6Sj++Lkj1ZkNK/PKPGjp/6RYker0ZnTQC15DqFpS3Gyuvnhi9KYs+LFFMwk9+T66hHPSmgX0nPOzFSkve7G6iNCBWb98J6sSZkjcbORMQq7G5lNKbAqVNPAkpVdlcgjXxIkGhm9Cp9dgEc+JHqUyb+BFOHZh7SyOrdEcP09VGFp0Nqcnmn8dFSYybZcBZ48xYfruXn08uBv91ORiNzy7eshJuIwrphQNzulZq9w8jzhP7reU8hazifDQ4HhzglUwJ5/UUHsY5d4ZatiOwKp7H/YujwThhuAbxA7kFh6rnFYEqOR2eDFI+q1BKuKznE8sFRQXAYhW9sTSlrljNZp+aNWP85CTGzJvEF1FNXZ9LH3tzwz12Oe50yuNpktTL4pY4UBUaispqyg3P4Oa6M6PJ6YcMTxFGOV9SniT8QMzU8veDaYn60r86E3bLyRbZ3Yh7loTIeJZWSGSPTLVl7pEACi5ST6fkzEH2ETfuyp4HmrBz7UD6Qt67/kIPY2NulMIw1jKC5zUjLpnwWrgmWO+bxIKovuKYLNvcwDB3Wb2I3jxGivbop0VsNwkWhd8Yrcp/EhBfBJMWnhUl80osXU+OqEN9yzjR/WCu28LNZ3i0Y6+bXYScspuYwEXXt/zkx163Y9pir2vqO9Su6BcDCD2Tl7zDCb8CRTliN76wW4SagR67xnUzyEvHjmE5dCSPCHtguwE9KKTyUthhkABy9+nf6JaNi7bqfkc0TDoextl3KfSZRx2RIQFYaFYz9T2cLyOYckZV8TJEPp/+sE8k11DhKY0IX16APJbcDug8jzWHOTHk5CLAZCDTQVbneSeKwKPZYZ9s7eYAuDPEYB8tk3Zxxs5B5WhxMxGpNfgtOfvh6lPs+XjRr1niQJ1umQmmE8nLtra8TBTJG7tg3pmDkE/CvxcfPSz87MkrbkKuKjchj04GJ5OTsw+D/rtjrHrurHd2drqZMCTe8/k9/FWEv0cJfoOFF94+caAshr5S0JEspqajtAjLsmtcaN6B8Zk03YAgmcm1GI3Y8KiCQWqMAI9EMZvzjr4MXXZ4ll2UkzWahpEuDl1FRLydEc0UqdhaNO6UFLLULnmB+8XxVXns8j1hmZozn2IgrJtxMq2iXai51vww5WYOjczzo1wMWNmbyha64QZp2GBHK2g2dqTnHuK9cBoE+oxuXblr9jv/lJ+0t5yKZPlVg32Wxd5OQh7f6ygcAkzRssJ/dMVApt4v3vkBxpMNmb0yOLZxEgHHImSAs6tcTpdfNlBF196Eri2ne8Yu9euYdGo5aYopotCiQ4QtTZyyJanODDcQC0dvajrhk/wKmp8GabMNST6q2de9suV+cqHKtx9izT4lPxl/vJ+LlxJMD7ut5hBCrIAf94rOZip3/PQd+VMXTxJKT8MV0UoPx+VHIS9y9FtyXDi2WpvvSMoNDDUDZjWJ7Ap0xe4lfVtQeEy9VGGliWpsPpXykH+UUnzL74aSkM2ZoMBa0Y/j88QZTxYOTU25ZVpBGLBSibK9DPxtvL/VZlbKVKS0y9fs0riQnqnqVUHH0aH4y/xct83iRDqecmlEnTW/msB3VwTXR/Hae7T0kDL+DwHejQ5jx49cpexYZnGIolukqmKtOMPVRltxqpLYB/CT65m7bhmTAPFNr7xL/p7pbOd8WxGNcIMadBW+l4NfcFGzX3v/BxArq4U=', 'base64'));");

	// Promise: This is very important, as it is used everywhere. Refer to /modules/promise.js to see a human readable version of promise.js
	duk_peval_string_noresult(ctx, "addCompressedModule('promise', Buffer.from('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', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('lib-finder', Buffer.from('eJylVV1v2kgUfQaJ/3DXqjSmdU3I2yaiEk1TLdqISCFtVAFaDfYYRjEz3pkxJEr473vGdikku6tKzUMcn7kf595zxum97bQvdPFo5HLl6PSk/zuNlBM5XWhTaMOd1KrT7rSvZCKUFSmVKhWG3ErQsOAJHs1JRF+FsYim0/iEQh8QNEdB97zTftQlrfkjKe2otAIVpKVM5oLEQyIKR1JRotdFLrlKBG2lW1Vdmhpxp/2tqaAXjiOYI7zAW3YYRtx5toSflXPFWa+33W5jXjGNtVn28jrO9q5GF5fjyeV7sPUZX1QurCUj/i6lwZiLR+IFyCR8AYo535I2xJdG4MxpT3ZrpJNqGZHVmdtyIzrtVFpn5KJ0R3v6Tg3zHgZgU1xRMJzQaBLQx+FkNIk67bvR7R/XX27pbnhzMxzfji4ndH1DF9fjT6Pb0fUYb59pOP5Gf47GnyIS2BK6iIfCePagKP0GRYp1TYQ4ap/pmo4tRCIzmWAotSz5UtBSb4RRmIUKYdbSehUtyKWddi7X0lUmsK8nQpO3Pb+8rFSJjyHr0oIbK0yYdDvtp1oImXk7SBtjdhoMSJV53qUn+oERY+e0q6P36LsBJbHTEyxMLUNvod1Rr0yqNFR8LepOLQvLJKuwMDrBLuIi5w4jr3Ha8sethGMJLIOCC5uyMw+1NtxAcgcG0/n5HklWMk+BNWYIWQX81VRm3Vg8iOQzrBuy3kKqnl2xiKYMj3m3rlIlYIpUl+7HiK+PtApZyh1H/n51L0tIFXuriTAo7pcwXqYpoHfkJ8cjoGdCfTabKeZ/PzMAfHtPDBvmAws3uPDNSUQuolkwWXFv7iu5sIRxNjIV6dkM9xMihXwwOPW61DluejqPKJcLn1fHFFDCeWjan0Mv2rF982fWUGiaP/mCTfN+hE1aXya2GoU+9H2Xutibfl1opsSDdDMVHE2/5dJdAg+75wdyWWzz5YJjuGQdduO6JcqxJgUWCH2a9FcWud0KrQzRaoHjb8Cmco4a3Dh7h/sUNptlYMu6nmqiFW56KSqPthoeG7B48qFnVJfY1Q1bv+6e/7PPT/vnXwzE9gZ6n8Mfew951fBlKypsEx+gXssZOzAStHT6PqKg15gGb1M+HwyC49zglcSzvcbsmOFLkVubONdJ9c35b6GbUNzduCjtKtw0SC0Q4NKoEI8aXhjB7/1fu+YjstZpmQsogX9xzvvJf0wQ8A/21ie7', 'base64'));"); 
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
	char *_servicemanager = ILibMemory_Allocate(33193, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 33192, "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", 16000);
	memcpy_s(_servicemanager + 16000, 17192, "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", 16000);
	memcpy_s(_servicemanager + 32000, 1192, "IEL8Bh/xlAENJYyZT8kWE93AoBHOku0LsbkJDbWUHWGRuRooZG6zZcDmxXLBZp6JDNAmOZGREzQN2UyH7DMRo/biULO0ge7QExyH9GXburJLS/SGwAT3hWjjFrpj975r3xUeKxJbeYP5SU2iUIOBLjdy0aJ2hxZtNDL68E/PHmIi95n9UvxGlPKlRuOisHRRgHbxj4vCRWENUfn4cw3OM7hldFHA/49bJwolvPpc/4JxefCVQKnSGKCVueEj8EWC+qe20kYZggbZqXODYijENIEPIdHDgvvUtUDJKx73LJFSGeikxx8GJbKuRFXZvVUIr4Yn7XKU7HtYMsS6amMSIkeLCkUc3Rs7lkB/VuxhLVhVyUSmaUfFtYq+KY1I0twgNUDKaSQQU95wxC2lINOnkLdAQJMWxf+tuOMuLVxaKpMX7LjzIlqKn9/hPj2QBdzV10DfHmKHkMgkPdQckkqicBGmmyhSiW6OJAUC8IXE9KXgAyisRSoLp9JMe0CvZVuIlPnmu/1d3dvQXc+wqDORvxbeuZXdg+2t9u4mlm+h/Dm79mAAXmPahFupVMgOY6QpcLlGW7+I8lEebDbaneb67ubGQrTj0ZYFQvQmfRgyrreQu0VDH+N4+7zYM3XNGo+aVp9K6MzOhPNUGn2i7sGi5dx/SzQgo+XXHvxdnm8PMeQSkSVJX1vAW0qI5ljYgQtZ1oICWd3hRdqBNvSWlPfNqAsMjiSmQauhD1X/PUAmUGF2EhsCztMWymQG4HdQs1BYIAW/xIafEZ70INr3pP77NEhROajGIXK+qHFQlSMLdIIrdmbQttVjoSVhHcnu6wtRoZJFB0Y/f1bAUXx2HJxkGRI4CyPGzsfHZkd8IvFH3pcszpZPJZVEZKx42Z/1+EWEupG2Ql2MfONAYBQ77W2IgRIHUlEqUOYEspHhuzFMM4lkMcJKygR3VshKYIIXhCUvYuixtelzxgyO3Iohn80JhfyZ/UVAgzRcGY3d61JxsfvrClQKmfZCAfHahGBFXQhG0b/9QwTAGeCS95H8KynQ1z2td62DAIQMEpISHrWhV0KKwJRnUxlxyhH8Ap1mLTZQROXweSa8cUuYFZZfv801wSNAnAL0HkTc8sh2PDc4rLxHDcm1aIkKszBBLdEnkdLMR62QOI5pZRHY2GY96LDjk7gB8ecawff/Azfh+GU=", 1192);
	ILibDuktape_AddCompressedModule(ctx, "service-manager", _servicemanager);
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('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', 'base64'));");

	// Mesh Agent NodeID helper, refer to modules/_agentNodeId.js
	duk_peval_string_noresult(ctx, "addCompressedModule('_agentNodeId', Buffer.from('eJy9V21v2zYQ/m7A/+EWDJXUOHLWDQMWz8NcJ12MNM4WpSuKJiho6SRxkSmNpPyCIP99R0lOZEdOXGwYP9gmeeQ99/Yc3X3dbg3TbCl5FGt4c/jdTzASGhMYpjJLJdM8Fe1Wu/We+ygUBpCLACXoGGGQMZ++qp0O/IlSkTS8cQ/BNgJ71dae02u3lmkOU7YEkWrIFdINXEHIEwRc+Jhp4AL8dJolnAkfYc51XGip7nDbrU/VDelEMxJmJJ7RLKyLAdMGLdCItc6Out35fO6yAqmbyqiblHKq+340PBl7JweE1pz4IBJUCiT+nXNJZk6WwDIC47MJQUzYHFIJLJJIezo1YOeSay6iDqg01HMmsd0KuNKST3K95qcVNLK3LkCeYgL2Bh6MvD14O/BGXqfd+ji6Or34cAUfB5eXg/HV6MSDi0sYXoyPR1ejizHN3sFg/AnORuPjDiB5ibTgIpMGPUHkxoMYkLs8xDX1YVrCURn6POQ+GSWinEUIUTpDKcgWyFBOuTJRVAQuaLcSPuW6SAL11CJS8rprnBfmwjcy8GWKKh6nAY4C22m37spIzJgkx2rog2X1yiVF8fVjsDOZ+oTczRKmCeDUKberg2b4jLBbCRf5wjraXA6YnHNRXzdDy+X6wt36dIUpmBCkKuK25RnX4THTzNOpRMtxhxKZxgeMuED/d0ZpuQ+WG0ysDtzRaRZciGR5REpzhHun91RVafqDHp0oujtJWTBEqU0kjJI7yMLFEUFyf0P9Ng9DlAQJk9B40whaTgcyplQWSzL9CKyYBwEKi3S6EeozXJ4yFduOq1OPckxEthXjwtoEdL8+Jd1+bKPzrL82zkzI6NveZigoDt+/2YxEtwvvuFQahjH6t8DLWiW/D1NhilgV8yJhjv/XGLoSKeV8OmKWKJRFRJ1dQ2o0z0jxc+FqOEb22zPn6XqDbY0+eEHejK9Jttl/klGrcd+83JxhO1hi/CvyJNldXcNS4XHolzfBq1fFbCNsZfpZjgPflHK7R6j09mwHD92/XIbwL+swwJDliT7aLlVdQKhzKcCmbwP1voHC2RQ3CFzQEtn65dw7pZQwQh7KGTUCI1vdz0PbiPX7NS/WbChJfxvnNxj8DLOYQexyIvIp0iulbHUSI9Ngl6ZDK2p/Fd/MkW4S9NgQ1HVzWfFN7aLmAqfb6qVEMA5WChpDXHiJB8ZJ9Ta4RfIWlx2jYsaaMtxIKMLqG59/JjH39Ozkk/s+9VlyTo8ZLrA4XS4PcylR6A8K5c02tirUPN2bx+YJZpfRfSyTUreboIio4f0Ch7vXBGkq3Ba5f+Qol0QjdnWbinmobSJZy6ueTNfXFxkK8Ir9rcxiXi42+YuuPewZx8HPRour8glNVIWyt79Ps6/nma0s+8I5Mwy9FCHvQ8kmbijTqb1m/JbgNfvg+tqi50XNuM/0cUPSZTYRlyt632nb+pV+/pVyYVv7j4vfPix2TS+zJlQ/P/5gPWHwLU7a0WgzKjbYBLolgPWxyVpNY0sreWFrRaKLZ8x7xrQtN+/eZ+o15NBDovKRdU5kAIOICtTqNZ1t8kgzl5tRMEPJvHV2qpYOpkzQk15SzKtfLq4osuLrRkZaYTXExUqoT4WKOjT6eVmJnOqw0ruqQdjf57tTBfWL6vxnfkP/0jJTIqYL2U6/v/lk+/rKroyqqRCPvappPJebu+XB5g33jY3XwHjovNM0yBMkM+nvtlbr3aO3ue2qx6b7IFoa1W79A3i885M=', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('proxy-helper', Buffer.from('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', 'base64'));");

	// daemon helper, refer to modules/daemon.js
	duk_peval_string_noresult(ctx, "addCompressedModule('daemon', Buffer.from('eJyVVU1v2zgQvQvQf5jNoZYKVU6zaA8OcnBTdyu0dRa2u0VPC0Ya2wRkUktScYLA/70z+rbjXWB1oTScr/fmkRq/9r1bXTwZudk6uLq8uoREOczhVptCG+GkVr7ne19lispiBqXK0IDbIkwLkdLS7ETwFxpL3nAVX0LADhfN1kV47XtPuoSdeAKlHZQWKYO0sJY5Aj6mWDiQClK9K3IpVIqwl25bVWlyxL73s8mg750gZ0HuBX2th24gHHcL9GydKybj8X6/j0XVaazNZpzXfnb8NbmdzZezN9QtR3xXOVoLBv8ppSGY908gCmomFffUYi72oA2IjUHac5qb3RvppNpEYPXa7YVB38ukdUbel+6Ip7Y1wjt0IKaEgovpEpLlBXyYLpNl5Hs/ktXnu+8r+DFdLKbzVTJbwt0Cbu/mH5NVcjenr08wnf+EL8n8YwRILFEVfCwMd08tSmYQM6JriXhUfq3rdmyBqVzLlECpTSk2CBv9gEYRFijQ7KTlKVpqLvO9XO6kq0RgXyKiIq/HTJ7vrUuVshdYl+nSfabgHE2Qhr73XI9DrlkU0sYFUaVcu+iiSh7XcSE8Q2F0SmAaS8w0IyW6hoPvHQaV8FH2dXSG/16qrZEaYbcLtE4YB69eAUfBbzdwzpezh3W6Jis/D4II2BVwA1WSE0BuG8EJRLFDR8ciOleDT0WbeLidbmWeUQkqVL//l1/zAUcomoBDvWBu8QWSYSKkGQejTCschX3o4WSujLfGOMTVYjkivzHCzQ2oMs95qp0Jng/XbWcD34rwMwGNHS67IJ6BQbZ1TpP2hXtz2wmc9jkZvMOhwdic9WCED8SCHYXxjF9mxAb5xanI84AK0exMiWFPHekIhcPK+YQ2co8t3aS1LKnFnr/OGgxFzugC1vbZBLHFfE1ZyHrdM9bGFrlwdKh3LOHRXqrfr0bD1FoFo2Xyx2q2+DaKThKHHZtsbwXXEVIZ/m4SES/4iOknuqrPzJ/jT/Tcpey12QPoN5vzzW1mwgnq8ejueJmNttGY/xHAnkwweQ4ui4FfaRTwiNl0LHe6Fmm4vapZdMJsWL8tv/T50KTindjy3wKDtxG8bUs0h6abNaZ/VgSyf0SjGl5Ik0pmdacTeP/u/Ts4hDVYVljUS+m8gDoMO52VOdIG/b5ddeCgKVAtUY1tUi8kvF/A95P8', 'base64'));");

#ifdef _POSIX
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-pathfix', Buffer.from('eJyNVN9v2jAQfo+U/+GEKiUUltC+rSwPjFItWgVVoauqUk0mOcBqsDPbaYI6/vedA7Sl7cPMQ5Tz5/P340h47Dp9ma8VXywNnHZOvkIsDGbQlyqXihkuheu4ziVPUGhMoRApKjBLhF7OEnrsdtrwC5UmNJwGHfAtoLHbajS7rrOWBazYGoQ0UGikDlzDnGcIWCWYG+ACErnKM85EglBys6xv2fUIXOdu10HODCMwI3hOb/O3MGDGsgVaS2PyszAsyzJgNdNAqkWYbXE6vIz7g+F48IXY2hM3IkOtQeGfgiuSOVsDy4lMwmZEMWMlSAVsoZD2jLRkS8UNF4s2aDk3JVPoOinXRvFZYQ582lMjvW8B5BQT0OiNIR434HtvHI/brnMbT36MbiZw27u+7g0n8WAMo2voj4bn8SQeDentAnrDO/gZD8/bgOQS3YJVrix7ositg5iSXWPEg+vncktH55jwOU9IlFgUbIGwkE+oBGmBHNWKa5uiJnKp62R8xU09BPqjIrrkOLTmuc68EIlFgTZpzpRG5SdN13neRmGzDkg5tCJIAiPHZIJY+HYsNm/OUkbJ4xUzS//1KJ+DnyuZkLwgz5ghFSuIIvAyLorKa25RO7BdT0xRI56lEO3T9L268HvXx2sGWGFyQbPne+GMi1AvvTbce/R4sJz2repTxJtkq5o+Xet1D8tS+F7KDKMGL9I/7SEL81kPW/7vHlwEduqINiZLCUdXvckP+AusfISp9wxr1FGnCyzSNAPGP+q0YdaGxhn9/2z6fhWddKtvEeu2WlUTnslbf3ZfPURRI9RkQ8PWbI+TLmzol1NIxhbodepNBVbcTIX3kVnJuBnQZh3o62YdnRVDHxT/vQ8BjcDKbzZtlp3m66E3Sdq1j16jQfHke1Yx2bQvU+1+W3uAFnhntY4Dhpt3ZMl/UWTZDrGpB9B1VjItMqSxoE+e0YR5GcXudr7/AWFelKk=', 'base64'));"); 
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
	duk_peval_string_noresult(ctx, "addCompressedModule('identifiers', Buffer.from('eJztHGtT4zjyO1X8B01qbx12HAcyd1V3ybJXPGdyS4AjwNwWUJxjK4nAsX22nAzH8t+vW/JDfkGG4YbZu3UVJJb6IXW3Wi2plfYPqys7nn8XsMmUk876xl9anfXOOum7nDpkxwt8LzA589zVldWVA2ZRN6Q2iVybBoRPKdnyTQs+4hqdnNMgBGjSMdZJEwEacVVjrbe6cudFZGbeEdfjJAopUGAhGTOHEvrJoj4nzCWWN/MdZroWJQvGp4JLTMNYXfklpuCNuAnAJoD78DZWwYjJsbUEninnfrfdXiwWhilaanjBpO1IuLB90N/ZOxzutaC1iHHmOjQMSUD/FbEAujm6I6YPjbHMETTRMRfEC4g5CSjUcQ8buwgYZ+5EJ6E35gszoKsrNgt5wEYRz8kpaRr0VwUASZkuaWwNSX/YINtbw/5QX1352D/9cHR2Sj5unZxsHZ7294bk6ITsHB3u9k/7R4fwtk+2Dn8hP/cPd3VCQUrAhX7yA2w9NJGhBKkN4hpSmmM/9mRzQp9abMws6JQ7icwJJRNvTgMX+kJ8GsxYiFoMoXH26orDZowLIwjLPQImP7RReOPItRCGQOdmfZu6HBiANTTnprO2unIvFQINgIKAzFF6sgaL41p82Jg030DNxfyK/Porib9tbhLt0HOpVijT1sg9salDOY2Le+RBEoOPh1zDQm77ZhDSoGllDUJ2aIYGKAUpupHjIM2sDJikNNPSt5vEMrg3hM66kybadp6Xw9zo0zVTxJCxxP4rNcDh/qGXVQWUF4ugZxHNAQopxYba1MahtmbQT2BY4fDOtZpaO7wL25ZjhmHbnrE2s7U12anAW5CmJsad75gc1DEjtge0cUhOzTklu4M+SArUHXJmAd2079gQaHTAREvyvANq2jYLapn38tpnqP2YVrUF5Mlje2potzXyNiF1wa7WDBbug0Nprq1lBBXa+ICALzKMq8rOII1lOWZmYKDtC2vIc5Q9KnBNLFqx4AJM7yEjkxm1IJiZz4U2Yl54bZucarIvPFfUq8OYU9f2ggJOUvgIlnDwJbS4tBLPMwP72jVnagOVsnocGKvMdIpYSWk9XqlrudLH8IqdyxdXYfqBZ0cWv44iMPQUMV+aGgQavzVljq0anSi4BgwL/LcYyNQSNqy1R8xth1NNJxcafFwl40hgwKiwvYgrTipX7LlNDSzABOTU8ZXwmWvgFIaNMDlpYxvalh8xd+yRXwnMdD5pzDywToKqakAZGn8DOGqXl65GtC44ZGIubklrv0u0e+LDQODkuw550C5d8Ej80m3kuS5MxvegorlWJU1gnllKsZvq8JK47TbZp9yakvfHZwRb/Y2LueGEvsUS0Wrk/P0WQQlmAv1nIlAQprkZwkTOm9+t6zCf0LABstf0xj9BolLQY9K4aPSEW2WbGz32o9l7+5ahQ5GIAgs8iT7xI70RdImK+Yfw8lL+a+gE8Dc3/tpodBt6Yw3BLzo4k6bAV8Dm4TLVqfaETnlwB43IaXaiavZvw6NDQwirWaNknHcIGCXotvnpE3bpoaT0IYfgFGKX/m9C8dMFaYl5BCPA2xqlCxXfE4e6Bd3rjR+q1d4BtW8CfKJ5MVw3G1BvmT7GIuJ7yP5NZWFGOrUOaOAsNiukeQM0b360JM2bzJoQ7OLmSufeLUR+OtgKIMgqWXSxcaXf0ju9IeyMjZvwAmWbmw2bhlbARHMaSDBpWhiNQLwJeudK7wi9q6ixJ21kfVsCCbsrMES/KxEAQ+BImiCbjEHcupho/PYGQDD4FCBvYvhsLN3DONqRkPCtmwwtHf4GiFEsHELD1LKHho5jsJOOwZitLvjp2A9sz4sOyVCOn2ubziGYD798ZMo41cgHt8pbLwcmYmQ5YaZtLC0dCvSS3gBOFLgkhijH3wsGc/0ivF7MmHUN66LI4WET+pCPwsUIgBZknTOkPWuXgSJRBAXTQkg5ZtavEjg9B8R0hBP/oGFKhTS9XJCPTQKCF1lwgIuzJoOyDRg85EfJy4BhOOHTHsHhXQqVkZQ3ulFXBkKOgl3aXFbR3JQhtBUA13vYaGCK/VR4wmt9IC3WTnJQAdxVYh95oAIOPtBiRMhhoe2VafXyyOV4GJ84eAaqxiEMFgVHStnwo3DahOqE3EPehiRUvQ3NPSea0eIKDvwSLJOpOtHERTmT8DcAwqWLBL6Zkke+OiDfpMtNNFRBL+ylBTei4AbGXI5q5yWpSrr+hnEt6PqdmJPfgRJsv7/xzAg2LjKoO7/QUJ4Mo/K3OO8N70KYT951Li8/SjkfewsaDKfUAV853zDWLy99LAmxBCmKWTorglet5XrAATeQ4jfHm3jiq+XNZqZri+/ZvA5dTNouPnMeM1Oo6G5WsXQckCnBym0hFDcLMl1WBOLvKW+dC4uDmGAIpm3x1tHoBj5I6zjwfBrwO7IbsDk9oJzTQJdLVRTmgTmCqSJ7P73zqY4TjS7g8RVo7nguLGj4qdfaCeekdehhOYZQwUxs8tRMKNhPrCj0s9IlmTq6wjhOQJfSy9crWxxZhYkeQIqsMONUOuXUgSke06zwlhU+KHWPZq1rxEdxb+tX5I3YbXrSt+HqL0VKaDe0NYhLwMWV4WvIJA9GzF2Shld5gno9Hgedpnid5fEwzkjx3i2PF9CZN8dt0hT5jwVkseFxkoBp1aQelnL4wkri4SrcW/OewOIGRA9GlzQgG2R5H8en1FXc5U21BUsLvTGCguWmpnNj8Jz1/qb9ohBNp9I34lPyj51SZSqXXKST1f8XfWiOSd6PbjN+4Fm3NHjSoQ68yOXHHkTWuoQdcpNHoQ4AnIoGyYLn+M+sgZU+tN5PiZCyVy57hqfEZ1lvWdESMeqW85r4yJiy5Aa7uJU7ZWOeNRR8g+F7finSwyfZNcV4EN2v2Jovg9V4zwTTmCv6zFpV9KUV/HNU/KIhbNZ51wpKD7VeTQi25M6AqyqQvCeLmyVCV79TH7bWHz7E028C2YWZ+KGXO2SQpgd+KIy/ZiVKFPrC/m4xojP4Dyu21K3hC/oq3GTGzwnFsaO1z7cOzvZeer8mt2RWFnUohqrdyGysqaNN7Mrg+YbAqzjdgGJcFWOtMpA2cwNJ6uJC7LisiyMK8TU1rnTFLTabFU2LNXy6FizXFk8LYkYwMTvUDOmuemRQi61sryf4A9ONxqYFVkmDZQhk++wJheFgu380xL9zZbtd0c9XMbTtreHe9tHWye5vx9rIVzG3Wn3mD3cSbR7LXbvHTaF4xpOagig6jGajp4ypeNrz+eZYOvdJSLymFe4ME/n9boVLWWHpEC7R4tlZfzc1gOL2IlAq7i1mItgZnqNI2/tHJ4Ot024DD75SzUecOa0kdwI0j4r7R+gcm3yKarbCeUN7BbsZ7A2OTn7Z+dA/xreD/vAUPqEj/02jiVVixMGEMYMlXoDhX+UWbLEBa68gpaMh/n+/9wrC8UJxtLqscGAYvIJ8jrdOTkWi0esZESBwJjOOvmFD2jk+U0SkbZ/09/a/vqwsP/qWhXS8dfoBPz8y913n+hz8rQcraB54jgNzczoQtUMIIfSdKAjAH3/wAvZvADKdExrC8k0chMV1MC9zZqk1X1/kk29b5Hi+bOOO7zdgnaIdzxjF7Tbpu8CKi9QOjC/DjLgyaRtJXkFylpbGIziJT+JcFohMCvqrSzvLAV3E+FcGWifuR9Vxl2dMj6OrmYnFTiapDLvyKLa6q4Xz2soe2/NiZ6UGyv19grrs0T2JD7W7FTQv7PmVEdfrRBxz14KJWp0Mxf5yDQxWKpsdiZTkyXWxuVam94I3xB0nFLh6Th0fU6vjELeTCtsp8b7Lg7KbMjMtb5m9FAUC91OImr6Z7Kd+rh94qfyUFzmXYl5AJ6Rld0jLIv2j4zh7dO8TbqBKs03ymsSiqsXsNDVsk1xqSRbJdx08ngx10sDMoySlBYtkytHyGQ1Fi8iWok/kjv1/aCGrVdfTr6ITucb/XSuglZmyM/EqupC7Jb/rAnQRb/u8khok79/1oHoq3K75yupQt47+d7UR3oUWd0hLBDRTm/oYKBmjwHTBOwsKz5WfEoc9JrvP2IH7jDAtf+x1bU3NMGQhHsgWwrSvt/iSQHuu5XghOHllB3cna134GtZAg6CKARa/AIOKnWQI3EurjjiJ4pG95Xtxipq8PWjxLphKYC6CCSCjHEPnodIDUlyv9l0ubqEV8v/itQGtXBoJbMwThjVa5N663sJNkcuGF6b5VgW7e4ld5K9vwzvezI84DSSwYsLHO1lm2ZftJfyW7LhkTDWOTrFGmdSwVu2mcKbbhxjQC5qxx8J0rap1pba7N/z59Og4MYNwwYTN5tEK1muZISUbG138Dtb7AXz8lDp2AeDdegJwiglZvFid4sf5LgyAijCdBGaXcphWzBxILDnsxenW9sHeqdbLV44Cat72CjT/IkgizQPT555f7Fba6kOP05Hn3RYB/pgADKNRBZDSqoOtY0W0da2y6diMHN6tIlEc+pjj1iF/JdrgaLt/sKeRbkmDVWweioamTnBS5emQTm5tZtYiuq2JZHpNaeUMwhqHwtD2vYCLtA5yLdOe+rvQLPUATScwvLvlO6u5dDy1wZLlAnd0v4xlRa6KTpRZvFuc1nWSDZ5uYTDpJNNFt6CbJ7pimwHAf1lfSjtFtTzLJlXBTdBUssSU67tnbhj5CEltkkTO4qJuJUewojx5g4W7IisO+KQMkrJm/mp00exEGqy0tXg7VBjs2HTCeIPzOfPV17yIlV10DKkzbluTwIv85DZW7jJWax+/Z0uQjWQJgjNpox3fcZJLELzjJOTXWLuXS5PGRqP38JkLEyHLUp9l5jFqslehym0Ts8DvRJYotfMqjeuOYMllgrFUbl0K1eWmlypfg7X3TznFSode9kwJ/2wbe7nL5CLH9RpN37mrTm5M75bHpJ9OaizfNa+9/a2yF3fAYyYXTIRWbZyMtYrb4CLxOdZEMYG8plWxOWCMG0S0Vw1QlHbyPJ5sWK2jkivHB6X5fqCq5/o9dWnArAEMsqnplJSAGHhXH3X6fmDsAC9Oz82AYWTQ3OhUwcOYcanzrqOiHJqczelx4H26a2o/xwCG7ZQ5Jtgx4oDyqWeL5F8ZqMrkaZGxWZnfn+JXYTRFX9aMc1huwCBcX8acJA5YwXY0HqM7xdR3QN7o/Jl8/z2pqe386U8vZBkP5SIKA3xp4iKyIrG5golj0iu18QdOCASJITgvat2i6PBHR8TvmYi5KJQ/iTKixHMrmOGDys4m6zh6UkLh0gK+Kic47r+cdBRiWTiHdzQLNXH4WVETx2lVnJ4zjMphRNLxF5gLU1bPW2jBMmjpdPocm89bbj2bTTZD+7MQLLw1ISOwwup70unUDAPucP+nTnoXl1w2cGBc4t3Yip8gyHMtTcHJg7d+q5d48WQsQ59kFD5mHKW7hrx2Jj8f5Gfv88GTE7b8KZnkOgCEjNmvKoBzY3Z8xxYcT/LdgAktPgMoT+vJ8rIeuICQmf75AH/+SCd91zKKA0BC/H1vcFZd8w9aGjOxzOr9XNXsVx2VVEEXfk1Fyiq3SZ/lOdeJ6WmULxBWhUhkxZCamCP9zclLPVuS5lZ/9LRZkEDNcKplg9vNjxrvoyj1WmEBj0xn2ytFq7l6MjDBObj01VTwyOoMRStjOVTCG/Q2JTnlfoSpIKwkneWxO99FASc4Iq+Xm+DLPjI+bcYqJtoSF8I/W2yVP4ykSkZ0PTMr9I7ZCrf3iFdeXXlCsJlLLjjw+Jr4dXZPrnCBPNnRgRArvYQBUDicWz8pFzAyiPSsVsKoWe0qUHKSKKFKFykkqJockd5yaP0UJ5pjsjUe2LWT3A0FKT29V9ByKQUJrgRsuUmigSytzkNQ6Ge9zOirXU3pz0r9LxylKgTSvq+u/AdqACGf', 'base64'));");

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
	ILibDuktape_CreateInstanceMethod(ctx, "WeakReference", ILibDuktape_Polyfills_WeakReference, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_rootObject", ILibDuktape_Polyfills_rootObject, 0);
	ILibDuktape_CreateInstanceMethod(ctx, "_nextObject", ILibDuktape_Polyfills_nextObject, 1);
	ILibDuktape_CreateInstanceMethod(ctx, "_countObjects", ILibDuktape_Polyfills_countObject, 0);

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
