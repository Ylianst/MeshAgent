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
	if (stream->Reserved == 0)
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
	duk_peval_string_noresult(ctx, "addCompressedModule('win-message-pump', Buffer.from('eJztWt1z4jgSf09V/gftPCywxRLCUldUUrktBzzENQZzthNm7oVyQIBvje2TzQA3lfvbryXLRrLNV3b27h7WlSpA/fXrVqvVknPz0/VVNwh3xF0sY9Rq3naQ5sfYQ92AhAFxYjfwr6+ur3R3iv0Iz9Dan2GC4iVGSuhM4YNT6ugFkwi4UavRRFXK8IGTPtTur692wRqtnB3ygxitIwwa3AjNXQ8jvJ3iMEauj6bBKvRcx59itHHjJbPCdTSur75wDcFr7ACzA+wh/JqLbMiJKVoEzzKOw7ubm81m03AY0kZAFjdewhfd6FpXHVrqz4CWSjz7Ho4iRPA/1y4BN193yAkBzNR5BYies0EBQc6CYKDFAQW7IW7s+os6ioJ5vHEIvr6auVFM3Nd1LMUphQb+igwQKcdHHxQLadYH9KhYmlW/vhpr9pPxbKOxYprK0NZUCxkm6hrDnmZrxhB+fUTK8Av6pA17dYQhSmAFb0NC0QNEl0YQzyBcFsaS+XmQwIlCPHXn7hSc8hdrZ4HRIviKiQ++oBCTlRvRWYwA3Oz6ynNXbsySICp6BEZ+uqHB++oQNH6adBVdHw97I9PoogfUvueEweRvz5oNI6i5bTZvW/vxrm5YKhDYeJOP9wcwwuehWpn0sY+JOx04JFo6XoWm0vXVfO1PKSg0dv1ZsIkG4D14MlqvwmoQMri166tvSSLQTGtMjNd/4Gms9UB5ZeP6P68SkZ9DkKnci5xcATDyb5xKwWEIR4zJc+x6kQgTf8V+HFVqDdeHCXHjqEp11bikKNWYEuzEWKUC1cpy488qp9kwIQE5g487dY7GrRvzYO49X0ULcKo/aHQZ64tDXJr+VRgZBS6UBWK5/8LoASYX/YpaHXSH2p2aFLzfIJOw90tL1DOEBPqKRyTY7qqVT5yhMfO8SrlsYxWCOB0rJydaBzheBrNqpY9j3YliVQrRKYlBMFt7+Aly3MNKIQ5Qn8gRF54ZucSBRO4AfE6UoSS/kixWt0q5Plmkh+cJP6CZnikBVSfYJVJnCbhR6MTTJV9WZxmhQb2AfRREF/GbeAG1E5Ou50TRmZGycMwjFURn8S+DzflBsonjRx4b2C86KY9gbU8p3AvWVJuuqU5TMp+qKc+rjLp0/Shme+dDPv3zCV89YGDqOytcirYygC13PB6z8FfKpeFLCCmZyINJXrn7XvDqeF3H816d6W/V9lHhEz7GweN6PsekWmvQ7Rc/Q6/yS0tXqzLbJIKQHnGxESaRz5TRTiKno4cJnh+apSbM0l/adSSTawK+416ebb9zuY0sD36vly3qZet3eBn4UBak2a/UUbZ1B/7Yn9EaVt3SXbCOtrD91NEmdIizqiOPfdYS/XwnT3dhqh0WHTRRD2jueBG+39PdOUp8XIWNCVWMfnhA/trz0I8/IonQeHE86us2/VHbaxEM0ufmBtm0X6UtK7RR60gmi3hishbhpJBn6aq0YofEaYGlMcwxpxDp1r3f0OvoG+Lf71igKN40WHf8Mxnz+JhXGJss8TYbzydHHFjQmvoL6EnwtlLLZIizSWXqiEbqDvH5mmVO3IF7b/tNVPQboJo4Tp3nfk0IjtfEB2hrXGxaxJlMxZMprMkMuUniEzXGyOdd+hTSDsn7ZR294unaSQ8g3DbaOBE7mSxZgZwVFbO0E9xI9wRZe8OJdv60SpP5SE7fF9WHjX005QIoc0H37VezJVSFONaKbCVxyTJrb6ah+jMhD6mqEpNv+cE3+SeG1XdyVmjwiLiv8HJSSH76kGRd8swpYWB+5MAfQSl8pWAhrXL14SFXH2ixgoVgLwHqrFqj9Pys57uRZN5hdqiIBkKnS4mYeQu6Uzr0UDgnwQoFa4JyjSGw067jZNm5sPD8n5ae/32Z+bO0/FlaziotcuORrcgaLJrJDL+uF/0uQEmFhOyVThbl9UTu1Wr5GSr2RhTCD0zI359XWUqllyLAnto+wALh+fZ2L7l5Um1jw/KUOn0GG7eQM3CGYANvo3jn4ShbqOcZFOTYVRN9Oh1AQG3TehyEAziOwmfg8Ruly7FtaNv9HnCCIEPXYfgYOlpyrMmjYfZU83JE20uRbCmCd03M7lJTu3eb2rizeHl5jJkQum2+z+gSs+vxC62mUpnZveGCeG6/FwuAyFZeKOoXrYJybvmEXC/pDE6oj93Yw1kz9Suip8fiRcLZmmrnOZWtnvPYt+ex7d7hP8ux89QniVFHzewvt9XKpb66PH3woZm8TE+0eXUHZHj5YzeniN0O03cAS3c2wz7a5OrgqXAkTWNyUV1HlWNKCy0Yfd6KQ8UG4IgjpXFP+nu0LLF33A92Lw+NaBnSg9Yi2mGzdxBnOJh1P2/yXWOmhN5tpHu9qLqw60udhHANK9aQ441GfX//n35NekyWmoXO8PDhBs5WSY/110IOlkxbIYj5K9XvUgXBqUOt0wl8pRjzd+P/TYxHcJZiPZ2U9Cn04aWD72nOkyPTAg4/DqrQl4CV9FR0RjJIby2+S5RpTn/PVDhwC+C8BiQ+GO0Z9nCMDwO8uFSxN3l0nRYOxsdkC5e1BK+Cr1jxPJ365GMSFS5vLymGJW8FaF9wYaa9CffFVdhbDnVeURyE7JiVFVXpmEXJYjlN2EuPT/vqd7jKSRVVfJFVFWsnf+/Ni2jZLW/gT3E2f0JGpk4W5mjqBREGuhSy9Ggp7iKMUfSYS/7xLrNX+n+Az/ennU5U/1vWW75b8nwRNmCWMCv2kgwa5RBWMD2PFf+94D7P1Uh4LH6EK9jLDnB3wumuToe7yoj+S0cy3hXGnzS9R0fbyVFVGB1rw54xLtJ0bcToppqoa3GiBINyWdqjrg37FuNqCyp6mqU86iqzy0Fygt7/aCoDNYHZ3hP6pvE8SkYTe2z0yeqahq7f8f/pKKLQusZQ61J6S3RhoHzWBtrfEzO3JYRH4zM3drunacNMSNbGCXuhVhGJ8aKaujIacadF+ZExSnzriKOWpLG9H/9iDdThMx/vZOO28mjZxkiCLSGwn7TuJyG6gk5b00twvWh0Ahn3rTQuRj2JxH6BHMlXdVuesernidLtqiP7I8Cw9jBuE3OUPBrtk1FCDkTINHVoq72+mom2BKoxGBmWZnP/SnOVsYGKz/aTqo8yLW1Ry9AGn0cK5LxdyAxggMQdGD1FF+PLfEgZdOWLamZB7pRhABbj2TZtvZD9lKh+tAszxMeT+XhUzJShLTLYpqkqPViHknje+KCnZaWgyd1PVQwNpWtrL4qtFhYso2rDJ9XU7AS/tBgzliRyQ8PWPn4RcLQLOIYGREkz1S6tVo+aPVBGYqKlGk2t/5TF4zZPKAREErX1XEBaZQGxbMXWukJatUQltmHoUkqySd1TRwPDEuerk5FMZWhJecRUp+REp5TMt+Ly+g+4Bwl1', 'base64'));");
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
	duk_peval_string_noresult(ctx, "addCompressedModule('process-manager', Buffer.from('eJztGttS20j2eanyP3RUmZU8CNkYkmLwOFMMmMSzYBgMSaWApWS5bXeQJW2rFcOw/vc9p3WxroCzbGofolSM1X3u925o/Fxb23e9e84mU0Fazc0d0nMEtcm+yz2Xm4K5Tm2ttnbELOr4dEQCZ0Q5EVNK9jzTgh/Rjk4+Uu4DNGkZTaIhgBJtKfV2be3eDcjMvCeOK0jgU6DAfDJmNiX0zqKeIMwhljvzbGY6FiVzJqaSS0TDqK19jii4Q2ECsAngHryN02DEFCgtgWcqhLfbaMznc8OUkhounzTsEM5vHPX2u/1BdwOkRYwLx6a+Tzj9V8A4qDm8J6YHwljmEES0zTlxOTEnnMKecFHYOWeCOROd+O5YzE1Oa2sj5gvOhoHI2CkWDfRNA4ClTIcoewPSGyjk971Bb6DX1j71zj+cXJyTT3tnZ3v98153QE7OyP5J/6B33jvpw9sh2et/Jv/o9Q90QsFKwIXeeRylBxEZWpCOwFwDSjPsx24oju9Ri42ZBUo5k8CcUDJxv1LugC7Eo3zGfPSiD8KNams2mzEhg8AvagRMfm6g8WprX01O3h+TTmxATb15Tx3KmXVscn9q2irGAEKdf9hq7Q9uBv2909Ozk/3uYABYzbtmq7h/fHJwcdTdakmAzWYVQIi/E21HRG/+vOiefb456h33zrsHN73+4cnZ8R6aMKLWRHr4r9EgF37oj0/MGblzqTro6AR36OoJxdgE682kHYg5dANBeOCEFuOuBaanfm1tHDiWhIjWjk0HrMu1OnkIIxJD3rg5GX6hlugdgBxqBLkxC0HVNomlQW+N6DCYTGSMmbaNgmESRSKhH1xJioh7DwMfZRJshm5BbuEn0BtQEXgS3rNNgYosY8ACwn6E4EPOWVOiRUIZMXQ93I6UwMcyIZ7UOXO2Wurucnmp4y3EE7Wl594fG/ucmoL2wXxf6Sl37+41NQYwRnYYGtU0IvRjKqbuSFP3bdenH8BDNl0N8T0VR6Yvupy7fEWW8u3cde0ptb2t1sAxPX/qitWoHLujwKZbrUPGffHp23D79G5V1BOPOqehR1dDjJC+TeAE+Rsk/jOg/P4wsO2ISG8GudE3Z7RIZwiIt7D2tzAix1Ceh/4oHZPhho3JXFwemRyCuDyErSmzR5EE6bom12+8CovGAsXvIzo2A1sUOHB3Xkw0sk5U2R/9wIPeC03iUfqLVFWhTjCj0K3paVyPQOakIBV3tWJSY/EEiaD+07S+0VJGEgTlUIM6xKHzGElL2GnQjHQA+AKVL7Imp6ER/Xay8EUufGmTRZo0kDWwKA1N6zatQrymeX59Cf2QtU4MZKBIkimCp6gvyhlJeCmOSAFLQaHULo2WxskJHXCpt6hnnQPl9yzcNONq7Y53icdGZONd3CjS7cVIOTXNO22LjEyJPAWHhvW8qpyXmK88WFMBq3ajQMp0PuycKsTuN4RzPqSXjkw1GDRi3JlT7TZPR8YvG5VwiML1o2mDFR8WFRBT2CytS8XCrxWHGJ00y5RDwujddCP8aHKGU6UGK6cug2mbD9hfkHQdskN+I2/e7pBd8ubN2yp6YyiNnimmpTRbze2dKkRECjmVIG5XYk3b8UidflArQ7i/B+MxzjgGjsP0As4OW62jriZ3b3xg9ohhHOgNywqbs32u/WhTXbIsozWf4jFCS5EzwNd1UoR8KC7hg+nYCTU6oJyOtR2dbNfT2oGtRolypQrhEwbZJZC7xkhDujLXdWLN4FuKQdH12+D6rbfg+e1tnbTeNuvGJzairYvzwx2yKPWA9MKYaJpXErqptq89ORKDj3SUs15Hw5FXHbKxWS9nWGFBacUovKqjIo7cMDKqrBjrldOoeiwAA0gNYvJ6IkqiT7NCnSdUyjnViNIu0SNx0SOqLKq38uVmOdqCSlXmKaNXDin4/cpOTGsLx3SeHgXwfQNqrzwfqvVUfzqZw1kPfaFhFBkOfFtBeoIFH1sVpatFXQWx8tXnVRs5rz5WbEp4PuLGUi9icCdtG8pEMobgjcO9jHudXIaeuK63y1hWN81o1MWmGR5hn2qZjwy3Br2j1iEUV01tDJnT8KcqCKbCj+syvTzDFyM4HMMPjBsVjrPJkutoMG4LU9WXc4xmJQMiYqx3iAW1YyA4jBdaPTcYZphQzvNMcOllmTAnLF8wA/tkw7wjG244uLl4gcV3f/kFv1rubIb3Bf+GdJNjkKJeXTkqgU+hwqo5vyUbhwoOQwosKeRKhcYA3MWYKA9KG0/6Guu02uzX/mF7fZ2huL5nM6G9Zrpwb3WFKCAncO7A2+XmdVuyly8teIHW0vGDISiHCDZ1JmKqhZD19c1mC3AnsK81ruBp6MpV9Pxd0QE12VWqt/55Sa7XYTtejaX/yb+6Cj92H+ADJMSv8ZoO/1HQ/BrQSC8tFF1jrzqt3xRd2VWUuo79Ev8jLjIEFyUcF2CvxZV6BbnMBFi53Hdzk4kuAGj18sklnX7PnxEMk0+wclxeV5Q2vLLR5MAHUJtt+PErARyYmB3hG6Fj2iTycEjO8AJ/qiVAlyxK98dEMALHn7Kx0P4YnPShI3E4eqUzr17VOErLTEizotCtUnfKz9KV5/L4+VGCVilBmQL0P6s++ax/zUDIFytJqdcWvP6oT3mAH/Xp5epTNDotD1AwFr0vvdA3l5fi8bUM7MkRqvRKphee6ksuZXBHzsHf40Ymx7aevXCRPi+7m1ntIqZwfRo/GE2+MEWQuSIdY93GEzPW7cG9Y0HtRgEaUhIoYFCNGiFaaYakLk0qb2tAJHkpFpJJlVMjLFRqRfZhvZP0O02oeZJKHPoY+c9ON6QBJYw6KIQkA8kR894tZY2PPNdKtIgreUc2ZXeQi1Ag8WwSfzdAp5lWfgKQ1MBIlxF08zqD+ryTS3xxWXXYeTKd2Lh4iw3H7ejqrpgB4S+/DIhrMBkErke5iFNdvfEmnHrQOXM2/2raAd0lqQvmnJ9KfIT+kaPEy80WErswXzwBVz4PTAPntjAT4OLTc0FCPZkNlPmUcsp8Is0XNf24zZPXLbJIGpJSTTHTlPIgcZzkTRAFaB5lUU97aJFtc8urnVBeDBe1ugTmym55ydWw8f//xMRzQuAbRsKEanb2zCy/PLNlnIX+mjjujMbXQNHgmZ455bAZD56FmfMymTk3MzMnFBL2TlbCGFJX0pPVTyNFJ69Zeuk6HLZKa21R+seHsmfkgBzL8h4Ig1daV/bjPECSIGXVN0Mxm1F4I5wlPBslv08Zu4GDv0spH4HiXE2NX1VpW8jbbKlfvuSSsHtXnobdu1wiFgr5iybgd0u+75Z4JWFbuHtaHvlkOuJMFQaHUpKMjx8Aq5IxOevx6KQH2cnhtPaqoyBP5VkJ60PCcnk2XDwjaVdJ2JJkzQI8nVhP9opH0i6XM9lXavv0SeL/TYoWh7HamszVmfwbEUgfHP395e/mM3+KBNT+A1z35HY=', 'base64'));"); 
#if defined(_POSIX) && !defined(__APPLE__) && !defined(_FREEBSD)
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-dbus', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-gnome-helpers', Buffer.from('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', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-cpuflags', Buffer.from('eJytXHtz4kiS/3scMd+hjrhb4xnbGLAx3b2OCyEJW9s81JKM8TyCkKEAdQuJlYQf09v72S+zqgQl7JY0s+foaAMl/ZSV78xKXPvpQA3XL5G3WCakcVZ/R4wgoT5Rw2gdRm7ihcHBQc+b0iCmM7IJZjQiyZISZe1O4ZdYOSYjGsVwLWmcnpEqXlARS5WjDwcv4Yas3BcShAnZxBQAvJjMPZ8S+jyl64R4AZmGq7XvucGUkicvWbKHCIjTg3sBED4kLlzrwtVreDeXryJucnBA4GeZJOv3tdrT09Opy6g8DaNFzedXxbWeoeoDWz8BSg8ObgOfxjGJ6D83XgQbfHgh7hromLoPQJ3vPpEwIu4iorCWhEjnU+QlXrA4JnE4T57ciB7MvDiJvIdNkmFQShXsVL4AWOQGpKLYxLArpKPYhn18cGc4N8Nbh9wplqUMHEO3ydAi6nCgGY4xHMC7LlEG9+SjMdCOCQX2wEPo8zpC2oFAD1lHZ6cHNqWZh89DTky8plNv7k1hR8Fi4y4oWYSPNApgI2RNo5UXo/BiIG124HsrL2GCj19v5/Tgp9qPBz8ePLoRma43kzl1k01EyRX5+u0DLtR+4gp0MqNzL4ANq+YtEVfFx/jO0IhPH0HFzp7P+E+dVHVtfHRMnsJoRs4IPkICPx23W5Ourji3lj7pmrc//PDDFamSs5+ajZ/J2dEHAs8cBg+hCzfDcu7to76eub3Obx95UbJxfdIPZ5Tozwlsle0/D0rLIjU4kkYfNosF8rUkjGlncZocx0Qh2d4fpclxbDWDc85xHG8FOIm7WoNJb0AyUS5K37YyKBccBfnin9ipFll0ASoNFp+/MyW7s5bY2fIlBvvyiTKbMQUuucG+moW7FKSBhYOiEXVJp18AC/0JOqI8KHXczkC1OZTaN8fqzXUbzBwMdjMtxFFMQ5Vx3mWVEZdz77d1U6ajLrTRvrf1gaNbNXwxNpx8tjiWJWMIPezTVRi9EOdlTYkFRk/LCu06w+W6rI7XfvgActMD5hzzZaVkUM7fkpUSwbuETpkDyRVXfziS0S5ScQ1HsqhiUl37m5h0cWE6PYYXw77Bown4haMCZXUyFLekfSuJcN/EKdw5mHOzJQMJNW22Th68hMByAf8HGTKEZppROAVTAW8e08gDGQSb1UOBKau9bu/WvpHRhH6KldJqrtkyTQ2hpZVZEle4vwMHExbIUFFNQwYRaoofk0fPJeB48jWqP84QIfSyv/ET8HAzQCjpRrpjW7aXhlBN+FgZ6bXu2LKdoQWByjo/Hdp4cS7auN/PkCVUsxJD4lN0Y0O+sbW7sZF/p633uvZgODSluy+3d1dYwI2pPydxEIbrXKibjM43hLLdgM+ITpxlRN0ZBrJ8sWaiTkNoWCVZVYiyScIVJBJTMvVDsPdpGCRR6OfiGUrrXMJrivBuKCetc7LeWkGuBXV0kv4AEKQTpNkgEFiF3po0YNvqwP6+yM6MJS9KXyuVurRF6iKSlnq+yO5tVen1+Mbqe64eV9DTW3qBo09jRV225b5JVMhyi9zSYCzf3BBs1Z/pFN2a5sXFLr0/1seODJKacF8jsAj5aGn7mwxNRwK6eMsESQhxfOX9ITLRPMjrjqlc67ZMW2pO69ma1hcPFXLdIWvw5flAlgZZlCnjCMPiC7n39voZDgvx9ELQNJZVVp/bLVDiY9I6Z5Eg3qyhwEryo1JTGwzvkO1b4NQikOuwGj6V5TuD2plFfd8sONjWDpzIDeIVTdyS1tBuSdbQyOeyrg5HunXPNtWQs3h8BJRYEZ1idfJCVsi4XKYPB9fW7eAHCaq+Y3y0Ccg6fII4Wcb19CzHkPxGY8ugHaAFgAmzFA8z6bk7lTzHkFVlOw71vGDzvOXeCspKVjYyBjW3lHTfTE9ZtMM9NTPsgTL9+Xu29hbQx5aUHjZl9qD6fGxBQQ4pABR9mK3ilflw6r1ljCdQo0p4DZk0BRGqVxzqKB8LMlzl1oJM0UJuN/e4rdIgcTcRgeW3EN+S38c0p2/K9U+lQoZrkFUYHEMet/TDAAJJLsxlBuZiC8Pvzg89zcy9re29ZjP/vvMMDy539+XTqg4HtqMMHCz+MggikuPHEH+/QGGfsKYJk3ZCIjfJt6tbM7MR4cxsCDZfaBSAyYNpseYBMOQ23y8qlpMhrZ46MP/JfYm3QJjFRaQKV+dLWbHUm4mpW93+cJDFFZrN21dSbQHZsgm22i+Snd6xpT2ndZQJzsiL6Yn+CBpJOi52wWwX+y0FmVHHsbP0Cc3ugGOdLtG/TmmJvFkkCM0GkPZDSttOt+OXGEppH72mocBzNlAfxOvUL+WAsgIzi3oho1LWKvhzsJZuTq6HQ00GFTYAS2TlTSGBQ5cOPhB08on6BR65qw9UEZUlyPaWTn4BkAscBQv3/oD4zq4uylknJoTVrONJEyr0jMp0ulltfBcbdiYLIH06XbqBF6/ys6yh2ZN0KE2znCUluATJaJfUu0fZojWX1N6dcp/Vo235VREmdIJtQFTOtBeXW3Y4Q3PYG17fSzJKEzmMvkm4Dv1w8UIoVJhlUwtgOMi+Zyidni7BNndOyIvJlyB8CrCH+kAhwPteccqKzm1ovvJtacWGn89CkDh2lWMgHLVVhVcgtnx6ee6SwbzYsWDpxiK7ketjL2E1VR4s5Gkaawntg7fSbBu4OaO8LwTXVNsEEsGCqAbqONHUfhbwcqeqKyyATwK0qnLlkcKcJ/6XxUw7DSc2MhC4EM2wuw1BAxIWL2BpOKgYnT24WMthzeH5XvICPhvBahwSyviCDUlindjNnbGkiW0q1uBwJ1W7ycVaqIUfIccdTLqW/imbVNR32Cherotz7PrTYPqyy+H+Uuta3bau86M1ZHVN7h3O06yOlSiBVyG2rZ8U5Ahqr3/b+6R9khDqDGG7Ur6h4+h2Wmefp2kcIInSpGxPp3+nGI6M0uQ7WoErhpsrBGK0AaVcjV2YVjwFrSY1daHnaRrHek3xZLr2sbnRO/nnxvW9uQcCqs49H8IUnR2Vpnm07SOdp/kdtjxSbX/kBwGi7MwPontILYZku3MMF2iPdFzKe+q2k8G5ZDh6sMSzMEg21mBzdkLzOzkOdpMkkDYDgcATrdixBhNIQV1mgxJmFPQd3xGIzacrTMj9EnoKnk2mpM61XIUCDKIJAQvKJUHrXMs3cwW3wdFA7ipknNtc6CuZh3O17m4wa2Oecu2/nLizWcHpQL0lg3CtFocD9VantJmNHdOSgbgu2xAEiOPGXyC39MIIXWgf3HZhc8KEMCCjcc3F1LbGGaOmPtkDpKJ+qsnktEPjWif6zDtxzUDsaGsFpwaamuU7Vz/Ng+Q5AbrwpBhyKkQucJDnk7qMwzUQm6KwwL3k+Wl+r42BNCSQxpkE0khB8k1h3Ngd7ZynTW8A4Z/nO8XhqKPLd3IdZB+X1hxzaKoDVjedbwM0V0OxUhYIg6KmK1rPGMAbo8+T3vM3cynqznw8neGlWG4OoduyuNPsCT4un9qyZp8MIrIk3gTkPcDa2Nadzqg2vsZf5bGH9iv0XU3NljIMpKwHPMNMA4+6h3b+5kcZv58mTsrskTvsEeg8+NqyxxH1VkbPRBVS58dFXROL9kc+W1HUu7SUgZaRbppSiaWyOnNzD6ncyLCHWV1JkyhrV/q7ZIlnBY9emnSyJGpkKDXWD6qJLk6phErNNtQvCpQHtEPI90LuQ1WiYFEh1uCapFVR9TnGpCA/KeV4E30gITZ3iBMacNBUU3KxVOvedGTa0j4Q1M8VYNsJsmEavayhGKo+sxcF1DHELHWXO0xGXRa2DJ2KqjdkKvf1WGVQi8hdL18gHVmga3jMd5sIiWRKqGlVDWU63FyGLvMmPYG+SBMIfhI76+Ep0o0bL1NyCmCypKQNIlgoR8f2aO8i0xASdEBOlSzCFbap+zyz8Aq8JgACRdsG88V+ZwjWM4QxY+pjQku3lSNUfHPfXcTvv3scBeWIMKFWfnNFuemyQwtBDmnJrWZcrdnwHzpFHw8xCnvxkCBNevq1ot5zrrXkfrMxJy+QlbCjxd3JIlbuj5Bt5wvCHqEgsmQKYdh0ih2P7fiOmC8oqNJ5bM8CNt+o0Ulxy0u12m9sWkRVWET2NRvMlxcyUOm83ufFnlEyIDfw1tidKqxQbP1c2UcUzohlQUp+JmPYSs+4Hti2Lm8unbvxYpDcAt06XFC8O3b+ZFp6V3fUGwmuLR8/gdOe02S6/DOhfnS3v8V0DMcGxYg97DPdhdEXNwo3Qb6mGdgCzoKl7seQguef6AKPh+YrRGESO6Mejcvv1/5oDLDozkKm5sAWa7ZzbZRHvNOcVyQKa7hzQRazcFEiJezdvd6oUN4emy29o+wXVBhQtBexDeq48300objnJAQf4gYzqHEUtfw2HTY+loUUqszOOoU98WJlm7wVtLI03dD4zNwOVGjfAAzCmBXWYc5ro087vEAW51QHjL4vGX3BRofmkJ3UZ0GFijjbBu8uP01DiTsvqEB1q6s61kTF3GuHnB7ZYaQC0czDaMXGeKdi3rBkFzlFH3QkbqYFyqDzn0B3zDcYIvRJcxOXPOAsyDr0IF+kpURvsnHLLOBlOl+yoxPt5iRm05fTEtOXKQt6PVXmgXCRPTdOSI8FfK6l/wFHWEduvJ2TwV20tkVhOlrCunY7flRFO29cE3fLtnckjdBsnkFvXUiMWKqSX7UYg+um1Ee8lJMQC5W/uddFLG3wTKsnXeW2l8HOHBNyzZ+7mMAVuCTV7EiGeilnIZiVMe2XRd8Jwzi/16m/gdhM552amEjr1vU9U4pJx1DsUg1UVXEmveY+bJqQ8E6M74dT7u0cOl0G3B/0Ctp6iNvYx70ogZtfMqia+Qa9rdSlQFIBrp4bqWiXpb3ZAoKNwQh7XBMbNKynSwogzFSfz6FQ98CaXoi4lvztb2zuD1/rV/ltppu7iWk7iqPLutXe6cPN3YlpF55ZmNZQhTe61lHUjxKQdBaJLbmuOHYxMlMn329M6/t6VZemhkTOLAaE9YCVjMX+zniFKSzpI58IYJOyfD7WiEMRTcvUWZbumEPsT0mcTBOaSoVc04BGbOY8gciF2f0KdGAhzqPCCBvk0wRb927k4XBD0fCReBqerEkPbG4fiDz6f3qYMXD03sQ0jYG8t3PZA+0me40ARwxQJoMSw71oNvvmuB2MzjWbfJIhX5nYpq5OIA71JKJ3syyY0WyvwJNd/PYJOx8oELRtd7R9ioUxIltZcvOYzkR0XtZuHJebTOwor3SznZmC7wAznrxZspR9VK6W2B3Y3ti+k+X2bsuCruf7BK7BHthUtMrjJw+S5YIevq2P9kltvDZNYZPYSyx/HHVrY/1idiSKpVEBI5jxZrwYPzEjOvPSaiaKsHVRxlb5Qyx70r3DHVxuU4advd7G4ADgEjLbRBhTI8hL8Dsocy9a8QNl1/cLuITaxTtynXtTse2JBqVop6dnnylOGytbJfmeFp3mVy72RO1eC+3c8e484xBwdafoXBo4ts5vLszykSH7cufnN/uCsSh+V2ya8JO/aZkyn0s9C956E/wNqefKwQHofeRLcSQXLIDjvJXzveeEBadGv2B/bg++nQqVzYLGvOPlrjyI0mfP9UtS/YUG+d3SXt3pQrzSIajL8nyXAuM6m0ASDQG4FJJK0WMvlCJkZTfKQNW1jC42z7KHtswAdg3xrBWLBh6bDyWiNS5adu38ys4E33yjaEPhltpysszDCVxC7KU7E6O83z0FH/SNHefbrxPjtKMG1+UX6j19bFrG0DKce4mmhozV9enz9qgzPyGWOxHtTELMkLbdOSnZyN2maWj7gOdvbVOKwvkH1KN+n0/yZ0DTwGti+yoi4iIcdhrxV7ktIn1gjvYBd+F2TAOydiNXTCaQxYYW1hXORNnfdxppv89Ilx3QnoAlg5iwz5jPh7fYsJvMu9mdC4mqJWZna4IfZY+iRv27lOX4mPb+sB48adRnUYV1DsHfpFezgykxGpl91l8b9Ll8f0aqemc76vMu3yzsa7ujpH3Td5miVuuypWNyZ6WvLO16+xl/lSlziw54Fe0ft7YjP0uad3JnnzdxglGLRamz52Ynv1fSN+o7ub6TjbAOircAp7l+3YYu2Xa46cmlyTvZILcjOOx0Rfe9QnesjMaNfbC0Xw5L5TsFXUim9bFqOoPJcNC7l/i4M0P8YvEM02nWJQIj36xnLv9CN4QmoPS5fSm+zV7cw+3r5j7haSK82dqN+C4yfkMHOQEuCueZi5gC4nvFFGGWDQh2/5n4dKtv74MLS9yGPpz07Q9HdqcGGZzdKS8FUYTv4e/67+ygCAvqnbMuOVVkOf19rUuLVyndYl1glxGKR0m8csitwT69hk1HaVlD5FNop6NXRd2lX3RrOOmqkFhr9k7/pKr0FxqFJNwkTBFVm5V3+FLLH1bom+NXNJ5naiNJr8p1vS0Nwss+5sWWneEmmlIx+gMikjpBJWsvsN2LeqO7/4TW1rJPYJl0MXcrC6Z9kpxjGglTJO0TqWrhBkJg7dPGRRNxA7CL6Eg+8ymavbB1/ZXmtlOHj4vlv1OuvZZY2g7S1DETPKSAf+bIqK/su5u06Nx3N2JIC/IY7EWUY67Bhu520PUsezHSLsBf8iG8fjqEp8xmf6KVy7+wPDTlILc9d9guluax2rvr7HMkbZHCUmkc0d/JUHXxdneHf9+jmJtmVwbbU3ozPR4txtEtGWdP5fXndRiggMHRoT5ZdOrh9Lib/30MjqxqMnI7iwweee6DPyUaLROtoJqZDIx9UaRfN7pR6jX4r3HRyhy/lpys4tR27iRqt1+eFNR27ki185LQ2h2mdH/B8PkzRiw5fbc/KJU+BZar9Ua7hvsQw2E9GiyS5dH+VsTfVVl6/gwQxR+lqR6yDyZivP/w6JRCUtD1fFipPXhBLV4eHpNfD+HX70cfgFa8+jROZhAt4FcESIeHH0jm4zCoHmI2AzfONwFna3V6RL6yP83D7vr5ikxPk9BOMHZVYUffMuBecIp/CYdWK+DSSQ2JqwGXvGAekn8BK+lanP78iwDY4W+/BYfk8N+H8NZ9+kJOuv8mh18haYdcak4qwLTDyq+VD9hirXpX9Q/e368G3ZP6h59/9pCoeO17SfW/vWOCPdljUnlfAYKer/jn+Nmvjd+PcZQE0vcKwcUU+n/ir5VjUvX+66r+v5VjuBEX8TGf4TGf/371DM/4jM/Y3fDbb/y/96SOt36WbuXP+PXz7x8I+ba95Vsl8/Z3ePvtt8PfAvrsJbDvDN9oFOVwX+Lxk+slOgBUj9jf1fHmpCo04HQNWRueM5ErEK2PbYTDox8Pvv7I/vpREr3wF+I9/qzC2canoDe8ELsi/7CHg1OoKmNa3VeXUxD4qnqET8Vbv/FfU5wEINXno2JssCE/e7M3r2aveo0yfPgMlnHKCzLwmhCWkpe9u0C0fD0GsXxFSWzo+8xfIfomUQ3/qB/TLV++R+c35O7/Ad07ZDo=', 'base64'));");
	duk_peval_string_noresult(ctx, "addCompressedModule('linux-acpi', Buffer.from('eJx9VVFvm0gQfkfiP8z5Bago5Ny3WHlwHJ8OXWWfQnJV1VbVGga8F7zL7S6xLSv//WYBO7h1ui8G9ttvvvlmZh2/c52ZrPeKl2sD46vxFSTCYAUzqWqpmOFSuI7rfOQZCo05NCJHBWaNMK1ZRj/9Tgj/oNKEhnF0Bb4FjPqtUTBxnb1sYMP2IKSBRiMxcA0FrxBwl2FtgAvI5KauOBMZwpabdRul54hc53PPIFeGEZgRvKa3YggDZqxaoLU2pr6O4+12G7FWaSRVGVcdTscfk9l8kc7fk1p74lFUqDUo/K/hitJc7YHVJCZjK5JYsS1IBaxUSHtGWrFbxQ0XZQhaFmbLFLpOzrVRfNWYM5+O0ijfIYCcYgJG0xSSdAS30zRJQ9f5lDz8uXx8gE/T+/vp4iGZp7C8h9lycZc8JMsFvf0B08Vn+CtZ3IWA5BJFwV2trHqSyK2DmJNdKeJZ+EJ2cnSNGS94RkmJsmElQimfUQnKBWpUG65tFTWJy12n4htu2ibQP2dEQd7F1jzXKRqRWRRUXDS77yyruR+4zqErha119H25+hczk9zBDXgt7L2FeZMO0zvve/iMwmgviOb2YU7xDaooY1XlW54QjGow6A7ZFWUKmcEW7XstZdBzdhGjHAsu8G8lKT2z71lGuqmpwakSoxAO8MyqBq9fVRRWAe6oXjrdi8z34memYtWI2EbIIy2zJzReAC/HYLxomaMTb6/x8Cq18yGjAglDLpyCCcvU5zGTQmDrpX+Ampn1NbwRO4QNGpYzw67PDIWXEE718AdODZSc1FAYz1J4wzPZuhFPwTn6h8N2kSpYVSRGTy5vNqumKKhnbkA0VfUGyMgnaibCtFEjI1MaEVH6QaSplamkX8WpoMPFC7pl2rNRhaKk6+LmBn4PqJZtYo3Qa16YPpcJvPySoUZ88gP4jVrTsxSvym/bh6hQcnMCy9oPLlNiRZN2gCHwIs4Oo2+z5/Yq6eDBz7ALptvVmU7iuoNf+LejV3DRKrtaUxSaCDf8OCe28QXbUN93jF+uvtF47Wv6MEy73xzTprfGHbUqdWr+SP8TH8a3cz8Ij9Nz4dCHtw69Ds5w/WDVGebsZThKNi1rBn3qEUTzYq+ljcybCmmO7URawwRuz66oyf8tuBKP', 'base64'));"); 
#endif
	char *_servicemanager = ILibMemory_Allocate(27633, 0, NULL, NULL);
	memcpy_s(_servicemanager + 0, 27632, "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", 16000);
	memcpy_s(_servicemanager + 16000, 11632, "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", 11632);
	ILibDuktape_AddCompressedModule(ctx, "service-manager", _servicemanager);
	free(_servicemanager);

	duk_peval_string_noresult(ctx, "addCompressedModule('user-sessions', Buffer.from('eJztPf1X27iyP7+e0/9Bzdl749yGkAD9gsvuSSG0eQsJl4Tt3QccnomVxG1i59pOA4/lf38zkmzLtuQ4QLvd3Xq3JLFH0kiaL82M5PV/PH2y585uPHs0DshGvfGatJ2ATsie681czwxs13n65OmTQ3tAHZ9aZO5Y1CPBmJLmzBzAh3hSJb9QzwdoslGrEwMBSuJRqbLz9MmNOydT84Y4bkDmPoUabJ8M7Qkl9HpAZwGxHTJwp7OJbToDShZ2MGatiDpqT5/8KmpwrwITgE0An8GvoQxGzACxJXCNg2C2vb6+WCxqJsO05nqj9QmH89cP23utTq+1BthiiVNnQn2fePQ/c9uDbl7dEHMGyAzMK0BxYi6I6xFz5FF4FriI7MKzA9sZVYnvDoOF6dGnTyzbDzz7ah4kxilEDforA8BImQ4pNXuk3SuRt81eu1d9+uRDu/++e9onH5onJ81Ov93qke4J2et29tv9drcDvw5Is/Mr+bnd2a8SCqMErdDrmYfYA4o2jiC1YLh6lCaaH7ocHX9GB/bQHkCnnNHcHFEycj9Tz4G+kBn1praPs+gDctbTJxN7ageMCPxsj6CRf6zj4H02PdLp9tsHv14edE8u++/bvcteq9cDhMkuqe9kIJqHhyFADyAaAuLD0eWHfk88uNx73+y8a2EF1/WNtxLMcfdD6+TtSbe5v9fs9RnARuO1eH78ts8Beq1+v915J9Xyut7YlKCax0e9095xq7PPnm4lH520eqdHLRnglQqgedrvHjX77T0G0thIwnBE+s3+aU/CoxkCnXT3oK+X/zptnfx62e7AyGBVfNCu61v1cOT63Z9bHQ7GH9XrYXf77ifqnPowMfEwsnv9mxmFewm4HmVz27YQOES1dXICM9Lu9E4PDtp77Vanf/kWvrZOGFAI9b7VPL78n9ZJ9/KoddSN8agLXMTk9HuXQKu97mELPzutvT4Jr11iwABVdrKQ++1eAphBbsiQJ9BmP1slh9xUQKar5JBbMmRIZofddzDiqTpf6CAPDlKQL9WQez+TdJ2vVJCnnSQsg3ytgozHoH/SPRSQb1SQeyetZr+VqrOpguy3To7anRiYQb6tRPP57rS9f9nc29/jLHXZ656e7LV2pIdvm/0+Uu9xCx50+s13LUS02e4A68lw0lwfHzZ/vUSmaLF2hnNngAIGxPlkPnWOTc+nhmUGZpVYlMkf6lWePrnlUh0rDJCWfUAWoWo+CLzAiEF3YkCPBgB1diFugQQ08LaN4ptXUuFPROV42UNQXuzZmX1Rm1BnBIroR1KvkFusrzab++MYoLJD7nhZ8QEgc88hBnwiJnfYQ6mPyKmCC30j7hUqw9pl9+ojHQRtlDZlUJHemi8gyzth5Uw7GWX6mTqBX67UWvilBR2HntcG5mRiYFVVEnhzWok7VRt41AwogzbKgzFIfmqVtQATd/Ap7/ncCSF2Qm2Lwzbz3AFgXJtNzADGekp2oSML29ncKGfHmXcZevkZlMl7FwYUpdLQnPh0Jw01BZoYmxN4Ho3A5TvqUM8eHPFH5Uqm0CfQaXSyuQGlErXU9lhXOqDVPtNjz72+Mco/C9iaNcmrShQ9osHYtYzyOxocmn7Q8jzXK14K+A8KNgfY/B5MrjuhkVyWhzy3kr2J69P3oKInVJoEVsy7iX9I4x1XuQj8ImPyIfDNma0Yk0RN2c61nPmUguEY9spvrlL6X3Pq3YTj4SAVMevjwyp1nNAR2FkRo3XcAO0dVs8q1Zw6j1TRAViNR3TqejeJUnfxV6hzMDbAEK4o5+4uMcGsIdP6DLNTZB6bDFJL27yiFNLNCTA4/G46VtsBM9ec2P9He7ZVtPzemA4+MZMD+n0F64KxPStaFkcrbCpdAKViMY7mkJo+i4eJdm/JlH3ZJuVw2o/dBc59gGZ+Yu5Bvo6hrLVv+zOcuW3SuCvWSvnU8ZbVnq3Jmw28oEivTxBwS9NrVksanbltHXjutAfLEmfU1Jbiz/vu6SlTT5E+k+8bI6hMTcB4CYX8C5PjcrnaPNOpX0zPxoWX0XiZ5jN7aGQKcxxTfcmCadpgaFcFbpUaQxCs20qy3VRv8JJ0PZZMIXqX/ElBsS2tEcjKXRDgH3c+sdhSeeA6sDgLiM86g0tP7E5G+twpxYpuBmE0BDWtqDo02qg7o84xV/7liqqcktGlUkxUaESqsixoUFZGUhGrFD8Ee2M+aw4G7twJQNjo1IsW7z7j/yzaWZmeI9Hjn2o7O+L47Awa5RfWJn1jvnizRt/sv1jbuqrX18yXV9bacLi5NRy+aLx8sfU6gdpScz23OfOVab2ubzXWrrZemGtbA5OuvX5lbq5ROri62nr52nxDG9nmlFZ/bjsvh/TlmxcvXq69qm9BO6/M+trr4cbW2mDjtfVm8+XQMrdeqVSDUNG9ACYKifuszC0skNXATY4DhjXYq/EPZmfg797YtNwFfgNpPpAh22hcwechimt0j+CPE+rTgEG7C4dBgX4sX6TFJtLl3sT0AZWlTI8mgtCywA4jz5yWt0m9qgZscqcUEnzHnFKAbGggP7jeJ0B6H8zlQYC2xzbZ0IB2W0dge26TTc3z2D7dJlsaGFzZCIxe6DCy2fzEqL/UAO67U9MOgV5pgMREshkHsNc6sIkNa5a3c3tideZoiwDsm1zYcFx1U8Ch5HFt6OaAg8KsWnNY2OHwNXRzwEHfm56FvkQOq5sPDtu0LPT6IaBuUkJUYY1sMkR1UxMhGriwDEffEULr5gc5o2/zUdJNz6E7cp0QSDc5bWfgToFI394A1yKgbma682DkSoAbuskJazwANuKQurkJq4wh86cGWRqhljGJANNNiQTWukZA7ZS4ztAehdXppgIMD9tiPBVC6iZENCyo5pcthNXOi38C65VoCYegb1IGR1YE2/6J6waydcjvGPk2IWihOShWzw5uNCZuZKlljEGpbC1w386HQ+oZlRq65mnbCV4bL6rkRVJbhM02LSATdMebwMT+O8+dzzTNHwOVBFjvTrYWE2uR/BZpW5UYCUNCt64ypI5UQUyTTfj3YmurCnog/b8CcW60PitktCLWU7Yo03QXwz8jRXeVHVIt9Aw1krV96tGhAZY2b16LtAbxsH1eWp5uNMVOAe3NjcOWUeFVkttobtAXtpM2x/FS3Ep0TqxEjZzOLDH6xQqBYaK2ElmDIxoIQ7i7cLgaldlI8diYFVhqQR3OfDJRkK3DW8hltkZ9Y0tF8hZTzvctjS1z9X7IXatL6oFKMmUyrB5Nvq7VKwZeuMVsBb5tBTygsnpZ5iye8xBNXfe8gOzJloz7Ei3MpEWVoY0vVcFoJEhBmbU1McbxAhh4KFyQHpj2hEc+/4OGMxGuXmKjv4Q855Ul/VS8wqS4SC/5jHFVDm5V+VgwybC7W0CYpVelsVfUGKvkV7Y7bB1ABE48SsYipbNEzzJMrphFIJGVySMxOIo1LQ80xJIzGcWrskarYJInCPxRGkFzvhqTLtM8uY1IRJ47BnIleiGepfeM6rl3T4phkOqukitQVXoOPAhDAGn5n6b/jN8BdWWEWow4SrxqRu5VhexVPRECahX3VdgLjhTJhjEErcs/C3mxELvapQ+mDZN4AmvpjtKVBk9uWdFtXsEH26Ibp/2D12G3t8OKpCfIANvsb45BcLeMf3PESIKi1JxVTPykAoMRLlk7GtT9ibkIzfVAJIykDAIFhOHHgsGEm/n2Aafue5i8V7gEO2G9ocUkno6RMViSE/JB3kh1KWTKahKL+1A9I3eCIVP0q+agwdVAaqrl0F9N7fxVjByMFsc/JCjxWU/1J0cuSo8Uc8PZiAPUTFxsGEUrTtV2VcPsqjS1RjQazl0c2jKSPStK/lnaX0L436n+D0b1UcwnRfqRFM+M1YMpLIWaLP9Z3QMedj9lFpuUfxLeXeKxkAy9aGjyovoGm6lsHMu2wMi9PhAXGBZsloxyx71yrRsycUcjoDUbIwzqdaWRtE0z/QR2QevHya4nw9tGbsgubEbHmli6mnJ41yRfcCWP1ffmnkedhL9I3DIGVwXDiLdp1Y5PZzbgcg8WZ0bZyiZ8hrGz+Q8Gd9ywNRegVuUtPQr7ZhtbyricGpeyLi6CRLYUM+Js8k+Od46htUOeP7eLuaDEHLEBSWlDm/wjHNJwEsS09ZgBuUu2yE+ksUHQy1qpksKgCrsTUfnILM+IW7cZbiuYk3h9rEmRDahP6tZS9LYIRi/03ahE48NDZdrmI/dEIhh2tgourwlz+5Otin4ALhQIIBdESOySMPhW0TnyPtYkwaQVLx9r8lpXL2YUCPFG9hO+qns0EUeiVI0oHIhcNJ1J1V5A8x+LrUCyKi/BH1mrgmcM1iw6tB3MAZlRL7gRGrBK4hDoLRD6ZA4rK3/sLvjdrjMJIYGkVVINpDAUHFxFGlXj3dRo3PgXVvZsNHGvgOYuHfcIRsYc0eP5dKYX8+vr5AMljki392EcCKxRTTLlhckMSlcxR50MaTAYw5OF7VggJMds/ZWV7qLgJRaUEwmh2Jp4tobPNJkAAkSUdugiUaFxi1sZgJe21TnsML7ZemozUyhAkYmR22rNdYwyvbYx+BwpTGPgWpR7JACc1xeRUW7+miGXGC8c5r5b2nWGBEInkBgXdNRJrUGnxxlqzs77jU0nFp9my+VbRjB1d4wQ1wFhabBgJ7kzMgOGBfuYDuamT8mCArxTDsjCBACoCFVmgcQuJT5Dz52yNmUaKPMMsDJr05zzNqF/xBwEc2jsBvd3sEL2wHP9wBx8EkljYN7PB7i3xQzkWhlFRyDQ0bE7sQA/JUq4dwRWCVNzNnY9vrVj7mM/OUvWSHuI+LBeO+6iij9w64wFlWPqLlbwgfGLT17Fw2bDgNlQJPBusDIHh+aG2NMptWyQ7JMbzcRGEDCtPg3a4U8jphGfTobF4zzQxQ7wMhsjQH1sfqZpDq/yDjokzKdD7NkIDCiIt6h7Qtr4+oASoibzDvJT+l4tP600UQfSd1W32yUrRcMr0aTIHWQpQe/ZqGYfLqNmBVLqPCOwTnUqVNUu5hA9OlJ5iUkr4ofJRo+OnzKTKQex9XWxnKzBMs7Qz22NaWr9MOuf826qbHm87rg1kzHzi4l48Tsh5af+aLmc9xc2amMErolKinP9AGWQSn9uq+HTDS5ghMypor0l7SbbT23jyWk7vGTlRsMFGRqnPtjOIOIdSQ7i5Pk5KBZENbxQfrEqz3AAJmwALtIGAZ3a8aaOKsnCa2WSfGVIR3Vdgfr6tAQuM8x8D9SfZqCj3THf4FCzzW5LRlpZ6OBg1flhYxFtNXqEDuUMXF7RUKokd41+JZECKzNzPgkKjJ2sLsrZTa5np52fO90PHcIxuuBuHgnFx6SY5O7YAshHq6kZqtW1qevYAQYTBRX41yzT9rDVOn4USkgjmtqK+1gI82ovO8AC7Q5YJ829fvuX1hfswSMPuMD/S+Oe2eT8cPwfU2wk0M3uDC+ALLoPuPwOPUmhKaZ2Lov4G64bjVj2X47pNUwK/C1nYhe6VnGDK7TJKxBuoI16NXljib+unhc0VF2h/Es0gv7rl4lGApe7Iw3RpUdTtWyy1CuVosgUmNR0b9le4vTAFa+mYN8SfayvgGZ4LWEcc2ANkPWbe4V4J30V4aX0xbrS+HJdESvDr9ufjS/Xn/fd/lfpSwE78z5Vx9yZt2T/Aoy6ZHivTNwDf3NIP9MJDLOSnVcYvfsNidJL8F1oLZk6S+xPAeaAdcYfXnDJ3en84cWW1Jv99tFRK7v3tMj1DQivAlV+oRXo8kWgrnSqwYRfIHnuCCZmYk6J8gyOie3Mr8vkt9+I8vHQo/TKtxSHdKjji/yIkdLImp7aVqmaFiMjGmxLfsNi+QDa7QohwDSO48JXlqSjgRyM7Yklh/jYjctZuEG5Rq/p4MCewJP1K9tZ98dA3Gdl+LhQVclK1/zAcucBfGDyWLm8k7yNPlOUxcnYXOQewlLPd8kglviqaFuiMep5qsbw9uM3Zjt8H4VRhrnDkBpG0xYW+Y2MPDojpXeOO6VEbCMkR6ZjjqhXgsfogyhBe+Xzc6dMyv8LNEbMxSeydrBNyrdAbbAgIj9skrvyuYOxy3OnpEdkYdpBC4C0O4/SM1GD7k35hp9ymfz97ywSjUkleIRQG/OI1AUqFfJPpCdxpA+LYS8vo9jeEOH+l6Q22WMlN/ZQcgO5kkta+L1cgsdAYXikk73b2LH/2TnYweQjjN2xA6F+sAFhkFLbQHEoGIdnmxfP6/9kXjMQJVD6Ocvl5zSKT3eEGCZ3+B9r/89LtmEFmQCWfJJE5jQQzBxMJk3yO8w1jtk8+Xl7j8graj7JgVHT8XjufMowDt7MZ54sKZeSpHxeQgINRwVJ6byUkI2haMyRjAryyg7pEtJR5fVgkR93oxPN4rTstLkRZh2G3eA+Z6lTZYxyk4PuaSdpFcoZcikKekDW5xennq9BMCtL2sej0MXYBRJcKlIZZQ5J6ba0w8SrCeLV5OLVREScXSFgTbZ1CUQsQREbFvubf37O/2yT8BvYiIb5Y+OnUhXEcanCyp1tXPDPBgheELhh+bsS/jyP2CKz3FiBLW7vMg8TZ9woCA0vXvi/e91OjTGWVrgqBH6UNvuJ3mCuEjJWFkqz8AbgMyh3wRJSTyOuC29X5SRVuAG/MeFyW0r0m7PtULGoNsKy6rTV9PoiNdKZE2wUuGe0izYnsWBCoshGzMqthHzQjOLgSj4FUbF7JXlQUvxDe34hXzvlSybrih2oFAkmVmYN72aolwtgATdEqbXAUVYmyvLcDFbZBwRiG1cUhUHeARbr3txZnweKDEZ1XTUU5Jdiq4k6CVFTEAUVj9AkRBXIg/QMaWYpqldGoUDoJyPlUgSbVl8RG/CzNLJ2C79vKEc/JUZUjwfDUWZG0BuHSqh34wxgYmgwWAcDGaQwMAQ+j6W2OLm0rJBxYQP8nNE8McPOMgU8tJnW0WGp8vGqUODMBnlSPg9w12oyWUmcjKpxZkjno9YvGIeg4/Oo3SmHJ6TCd9kkEcCNnNwHTZ3Nf8d1Nv99jzpDbJ5xzwLa2mFl4hbWH1r9S8UjXpp9bAx6RyNbJKcFdCKmwdCP8dWtnq9uhHx1Myu2ekCJkRQXhgtNJDJhAoHdA2vEHxq7u+clQc/npXh5+MMGWxWuZKurqGbpco0Z5uSn5WtBsk1e1BOLt8y5fyz5SJZ5/M7vQG/f5hot4arC2d/8cTd2CQwJGq/baL8652DA/tCAf5urk0F2hEGXsiPqMlOr1weyLqqqtUKkESYOqgTWSIG8/FA7MPiziXMRYrGtVEoJSS2E81l0Aw3XSDTjUMVXrt4uuDn4EqzbFEHDjaz2/k7GfzIy/tKU25Apt36RsQXuR65M4ZymSDa6uUQMLw93fDcOHsxJGf9zyEnnISuhPpZcxuxYsdD/8ap6VS2tC/fy1Zl58Wy35LhsgmXTgTPb3XmZO19KwIgl/FsNHYLnktPl7G/+BXJpfWdVH4iKQJe7MGC5AqvdAQxF9aJcLV+UK7l7th+4cf67B+/LevBuNZI8UQlRBE2KlbstAldm96MYDHoIuYPwWvCN8P3ZwbRamgU+PlJ6STLemGfZULWG1nSYAZ9e7+42KtkG054vTbdusyV1oHBxARD6OFcpKZakxcvcFYQsAld6iGWQCHiFrMIiXXK4oa46KmtJpKyAMZv27Wrg8EofbYHCSx9DK+QaYO5SkvGXapDImhjJG+vr5C0d4u7OBSU+e3EaOxXE9sODQVynSiY0KPswKxS3l7rEp5gEgttKPfa+MZO82z8Kj5PJymOMtIZ741kyh8LEEAc1RCJb5Aet4X2Q2DB0/8Yd8wZUoOJiXlz4X377jTxjG9qvzejI1+ieSDQqfhiGkzomBbf5ck30KKeYhRSi6Jj6tP2UroSRee9O6YE7sZjjVnY9xg+MZed4/nUWMhh/AsPiOVFGSl8+3PtSIIyT9ds99Aydv94czvWT2Lj/JCr1Q+b1XPnzrA1wh4d9ctSLhLVD2mCnASuII7pvjL5TBxmx47WROEZ/OOIYhcQxWo04wFg3p7ZMFvzO771G+h2pgQ/A1xDjCk49TnlixC3DnbHXm+bPCosXKIaPJ+IbePSqO4yqWm7D5KcEx+fLfsbj/Qk7elq8t5UKauRNkrhNTbxOl1rM8sXLjnglhrps2OsoETQ6WkxWfyEGyByl9AAVQ4O/3WglNESrD2jUZYkKukbteGxrUXYbcEEeMjU5Nwqw0sUmRbK21ABMshSRXGncsXBlSYNyW1ijZo+IZq0UzQEwvqHuOH+MOOjoUIOZaoqUx0j+/r4jY1C51SbYPpa/6J6NxIv8mU/WKFlz8eBy/GBncsPnYGpxLSZmivzGMly5N0npTGL6uhx5JkU6mD7bVpkM9je/VDXsZ7up5K9U0tdFaWV/Z0pZF0vrKugVXfZaB5EYtSQzKm7TOMvQoLyETCuroe1YLedzy8FzmCSNJd8vprauPPcTs0xTr1UNn2vyW/gpmlb0mtC0qlTGg0BVpYM57HTFbIAnTlzBRpYPYl4vxCDrs3Qmci9g9PANgdAZfIEGf4GvKjuaRaE+IoahgGPpaqrzRDQy0x4a2PZZsvzZx4uL1WUvRqqy9UC3NC2sJoGzzpACKIVTwt6tkgem3xW1PN9G4SFk7RZ/M+PtsoyxlTxBS9IJFTZnTG8pyzNJiEXe5JIh7+IZi5pufd8rldNYTnOp3CIcq/USf1MIatR16ny2PWgnjNTUy/g3APXKFKrQsaXzoJQI/d1qFCweFP1jA76FgNXSzl0UTYkV766seJU52Fzx4vmDV9BxVnTjOV8lG/wZWwYnUrFBKytNOoXlodXeMXyOBsfrPg78e2hzvHT++6xWL4BDVswomlBIHj0PF49z/Wm4OGYrxNsPgLfAkJUYK1p4JG6J7L0fGrvnpXMg2B82xBfhVarjVi7GinD7HP6wTwf+xG4IUohe/+u/1KMP/K60PDwp91YTfc/PAE6YSiIrtzBtAlZxTosdJcfsahdoaGVAIZHGhd8aKkvifqkxGhNXYd3yM+Wh+XylOE+dHZ1wxivM0D+zWw2WfMgT+ZKE/ERKa+Y1YYsw5J3sKlHir3m4bS3msNBL+3skjkVZYavkNoossjBDzLkQXKcgapTDE0f2GBfmMyYB1EuMiZOXRE+R2+63GmAsJso/lnUdVst8UArWLXLOgGV6C3xdBQe9TfH8982jqZpjDrZF5EzaLxoznjD0GiJjsgoKDFQc1Bzl01CH7aZjkvO8ZJxHliDe4qm4Xz51vVCkrL2vipO19//aMVRbFTiNZ36jirGneN6B/UZsXnG3AnzjOxU4MD5AWoBPZz5NkwO/G3rfvjZRKOTBtxhZTywnv0nK+Rq5hpY/mJAa6E4f1rjsjF1y6tj/mVNgYdlQSNMsps1u7O5Kzyqy7fCQGO9D88NWCCCm6BWvQq4ibUaB4wZgxcyd7MbGJS6kbzTB4DuTZJiEzYhPjoGYTO8mVHcSr4xyeGX01+WVTILF/XjlW89N/x3tCylvHCN957XyF1jWcTe1hl4UvmuEX5EYUwcbLKPCQomiDDLXSCmSxYmW+1+XvoQYXMO978JYWA/XM7LnrnPQwzHbh/4PAte7UZ4WtvEAu/QRksi/ppHg4wujyvFA3Vf0Zbf6PqKwm/seI0icZEaS4ku5hn9Q9eEnn3X8FlqJD6TbIgbGl92T9qU3n62S6/AoXrTYJV0ltuJZSEWKY3OYA056EyRrXfjL+FsfC+zRjL3Q2Y0teGW2aPLXZ6i2F/OP0GG3RhrKTZvqRSt/M0jOwjSzz/jhW4x/Jyb61sg4PYR/OSLO0u3Sncf3JWLb6uMbayU6XqIUAgGuTAe6D7HbFiN1+PgmqfgRaBOmTE8NqjfoFiM5Nhs3M6qiOnUALxFtZEXPGlGRqvpEKJzuMw7LZauCZRL9+CjFIfPCIbZlel5M1h8jRAxt8DF6rTYri5yghxPOEA6JvWTpDDjX9Wp8N2axij7uoxiHM6z+gtVfsIDNXvGKxe4dLmVV5nGz4tjEpeclJiRh+mHI7AlZ8eAzBkLOn5hMoZ2V2Zc/K/evyO94/FTEzXGoseBLs9lLdLkuUSgiJMQVzl5T5dnkwOOV2zRJHliohoqOK0w/9gN86aj0uvt4dBrkp+jUQAJrpbZjJo86RLLFDHgtZqqsULw02ZDqMw+j8Sl2SJg6pVIzuPbQyB1b8VbtZ/FbtROEVGAMV48xF0EoxuchIejkDfXZkQybIqdHcqMo/23W8vmQwohS7OeNMFOFunEqFrazuVGu4DbtQ8y3rJIjc9DtVQm+vPttb5+XTofAe3QylGU4/v4CS/XY8IJRW5v/AQSw/HhpcDE3qmj7J66bUJT8Ts4wJ9yLfEownUF1ulpEFww2+Q5Kuc302ykz5MBS7D13avtUnlxxK6FbGCjhLx0Xz6X3XHqUHXT6Ud89ruIvAdCdfBZniKpfNw4wH5lnjsHImfuJOZwBJH8Jc8IjGt3MvHszhdBMwkaxkJG9W7KiUnUrPDtaQklDHIrTGZRo8QEwdNaY/q3tEdmGJaEU/B8NT0pW+e7cGyA2AgvhQv/FnEDVZ6H9y1Pd0BcgG3KhdYfa1k+DB9NZZNEkjwmNmkx1nr0Emz1DYS+keyzecxkH8K3N5v44riDNzoAPoCg1sO9OTcDmJ8W955gpXcbDDfG8kOckBgiNC4Vkf8YH6Awa4gvu+CfOEgxHjnxPjhAvmh2haLB5X21pivkX7aHH7PXN0Qnqvqy84hmMuEtKnxTvdZYpaESDPltSGSgEE5TDD3fN0IIdUYIAEHOFdqy8ajLsXbxnOxa97g6Zpo9zNxYgfinBQmdgqfLzWePVbk7FdlSxdK+SaAWPfPj2WsKhwwRkdqpzptbEajKFFJaJFxRRLIEDifl8+mTqWnMwW+n1zPUCX4h2pHBxvrfPqv9/V2qGZw==', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('notifybar-desktop', Buffer.from('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', 'base64'));");

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
	duk_peval_string_noresult(ctx, "addCompressedModule('zip-reader', Buffer.from('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', 'base64'));");

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
