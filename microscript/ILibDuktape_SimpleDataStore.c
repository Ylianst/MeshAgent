/*
Copyright 2006 - 2017 Intel Corporation

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

#include "ILibDuktape_SimpleDataStore.h"
#include "microstack/ILibParsers.h"
#include "ILibDuktapeModSearch.h"
#include "ILibDuktape_Helpers.h"
#include "microstack/ILibSimpleDataStore.h"

#define ILibDuktape_DataStore_PTR		"\xFF_DataStorePTR"
typedef struct ILibDuktape_SimpleDataStore_Enumerator
{
	duk_context *ctx;
	int count;
	char* GuidHex;
	int GuidHexLen;
}ILibDuktape_SimpleDataStore_Enumerator;

duk_ret_t ILibDuktape_SimpleDataStore_Finalizer(duk_context *ctx)
{
	ILibSimpleDataStore dataStore;
	duk_get_prop_string(ctx, 0, ILibDuktape_DataStore_PTR);				// [dataStore]
	dataStore = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);

	ILibSimpleDataStore_Close(dataStore);

	return 0;
}
duk_ret_t ILibDuktape_SimpleDataStore_Put(duk_context *ctx)
{
	char *cguid = Duktape_GetContextGuidHex(ctx);
	duk_size_t keyLen;
	char *key;
	char *value;
	duk_size_t valueLen;
	ILibSimpleDataStore dataStore;

	if (!duk_is_string(ctx, 0)) { return(ILibDuktape_Error(ctx, "SimpleDataStore.Put(): 'key' invalid parameter")); }
	key = (char*)duk_get_lstring(ctx, 0, &keyLen);

	if (duk_is_string(ctx, 1))
	{
		value = (char*)duk_get_lstring(ctx, 1, &valueLen);
		++valueLen;
	}
	else
	{
		value = Duktape_GetBuffer(ctx, 1, &valueLen);
	}

	duk_push_this(ctx);																						// [ds]
	duk_get_prop_string(ctx, -1, ILibDuktape_DataStore_PTR);												// [ds][ptr]
	dataStore = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);

	if (cguid != NULL)
	{
		keyLen = sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s/%s", cguid, key);
		key = ILibScratchPad2;
	}

	duk_push_int(ctx, ILibSimpleDataStore_PutEx(dataStore, key, (int)keyLen, value, (int)valueLen));		// [ds][ptr][retVal]
	return 1;
}

duk_ret_t ILibDuktape_SimpleDataStore_Get(duk_context *ctx)
{
	char *cguid = Duktape_GetContextGuidHex(ctx);
	char *key = (char*)duk_require_string(ctx, 0);
	ILibSimpleDataStore dataStore;
	char *buffer;
	int bufferSize;
	int written;

	duk_push_this(ctx);														// [ds]
	duk_get_prop_string(ctx, -1, ILibDuktape_DataStore_PTR);				// [ds][ptr]
	dataStore = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);

	if (cguid != NULL)
	{
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s/%s", cguid, key);
		key = ILibScratchPad2;
	}

	bufferSize = ILibSimpleDataStore_Get(dataStore, key, NULL, 0);
	if (bufferSize == 0)
	{
		duk_push_null(ctx);
		return 1;
	}
	
	duk_push_fixed_buffer(ctx, bufferSize);									// [ds][ptr][buffer]
	buffer = Duktape_GetBuffer(ctx, -1, NULL);
	written = ILibSimpleDataStore_Get(dataStore, key, buffer, bufferSize);
	if (written != bufferSize)
	{
		duk_push_null(ctx);													// [ds][ptr][buffer][null]
	}
	else
	{
		if (buffer[bufferSize - 1] == 0)
		{
			int i = 0;
			for (i = 0; i < bufferSize - 1; ++i)
			{
				if (buffer[i] == 0)
				{
					break;
				}
			}
			if (i == bufferSize - 1)
			{
				duk_push_string(ctx, buffer);
			}
		}
	}

	return 1;
}
duk_ret_t ILibDuktape_SimpleDataStore_Compact(duk_context *ctx)
{
	ILibSimpleDataStore dataStore;

	duk_push_this(ctx);														// [ds]
	duk_get_prop_string(ctx, -1, ILibDuktape_DataStore_PTR);				// [ds][ptr]
	dataStore = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);
	duk_push_int(ctx, ILibSimpleDataStore_Compact(dataStore));				// [ds][ptr][retVal]
	return 1;
}
void ILibDuktape_SimpleDataStore_Keys_EnumerationSink(ILibSimpleDataStore sender, char* Key, int KeyLen, void *user)
{
	ILibDuktape_SimpleDataStore_Enumerator * en = (ILibDuktape_SimpleDataStore_Enumerator*)user;
	if (en->GuidHex == NULL || (KeyLen > en->GuidHexLen && memcmp(en->GuidHex, Key, en->GuidHexLen) == 0))
	{
		if (en->GuidHex != NULL)
		{
			duk_push_lstring(en->ctx, Key + en->GuidHexLen, KeyLen - en->GuidHexLen);
		}
		else
		{
			duk_push_lstring(en->ctx, Key, KeyLen);
		}
		duk_put_prop_index(en->ctx, -2, en->count++);
	}
}
duk_ret_t ILibDuktape_SimpleDataStore_Keys(duk_context *ctx)
{
	ILibSimpleDataStore ds;
	ILibDuktape_SimpleDataStore_Enumerator enumerator;
	memset(&enumerator, 0, sizeof(ILibDuktape_SimpleDataStore_Enumerator));

	duk_push_this(ctx);																				// [DataStore]
	duk_get_prop_string(ctx, -1, ILibDuktape_DataStore_PTR);										// [DataStore][ptr]
	ds = (ILibSimpleDataStore)duk_get_pointer(ctx, -1);

	enumerator.ctx = ctx;
	enumerator.count = 0;
	enumerator.GuidHex = Duktape_GetContextGuidHex(ctx);
	if (enumerator.GuidHex != NULL) 
	{ 
		enumerator.GuidHexLen = 1 + (int)strnlen_s(enumerator.GuidHex, sizeof(ILibScratchPad)); 
		enumerator.GuidHex[enumerator.GuidHexLen - 1] = '/';
		enumerator.GuidHex[enumerator.GuidHexLen] = 0;
	}

	duk_push_array(ctx);																			// [DataStore][ptr][retVal]
	ILibSimpleDataStore_EnumerateKeys(ds, ILibDuktape_SimpleDataStore_Keys_EnumerationSink, &enumerator);
	return 1;
}
duk_ret_t ILibDuktape_SimpleDataStore_Create(duk_context *ctx)
{
	ILibSimpleDataStore dataStore;
	char *filePath;

	duk_push_this(ctx);										// [DataStore]
	duk_push_object(ctx);									// [DataStore][RetVal]
	
	duk_push_current_function(ctx);							// [DataStore][RetVal][func]
	duk_get_prop_string(ctx, -1, "_shared");				// [DataStore][RetVal][func][shared]
	if (duk_to_int(ctx, -1) != 0)
	{
		duk_push_heap_stash(ctx);									// [DataStore][RetVal][func][shared][stash]
		if (!duk_has_prop_string(ctx, -1, "_sharedDB"))
		{
			duk_push_null(ctx);
			return 1;
		}
		duk_get_prop_string(ctx, -1, "_sharedDB");					// [DataStore][RetVal][func][shared][stash][sharedDB]
		dataStore = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);
		duk_pop_n(ctx, 4);											// [DataStore][RetVal]
		duk_push_int(ctx, 1);										// [DataStore][RetVal][shared]
		duk_put_prop_string(ctx, -2, "\xFFShared");					// [DataStore][RetVal]
	}
	else
	{
		filePath = (char*)duk_require_string(ctx, 0);
		dataStore = ILibSimpleDataStore_Create(filePath);
		duk_pop_2(ctx);												// [DataStore][RetVal]
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_SimpleDataStore_Finalizer);
	}

	duk_push_pointer(ctx, dataStore);						// [DataStore][RetVal][ds]
	duk_put_prop_string(ctx, -2, ILibDuktape_DataStore_PTR);// [DataStore][RetVal]

	ILibDuktape_CreateInstanceMethod(ctx, "Put", ILibDuktape_SimpleDataStore_Put, 2);
	ILibDuktape_CreateInstanceMethod(ctx, "Get", ILibDuktape_SimpleDataStore_Get, DUK_VARARGS);
	ILibDuktape_CreateInstanceMethod(ctx, "Compact", ILibDuktape_SimpleDataStore_Compact, 0);
	ILibDuktape_CreateEventWithGetter(ctx, "Keys", ILibDuktape_SimpleDataStore_Keys);

	return 1;
}

void ILibDuktape_SimpleDataStore_PUSH(duk_context *ctx, void *chain)
{
	duk_push_object(ctx);				// [DataStore]
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_shared", 0, "Create", ILibDuktape_SimpleDataStore_Create, 1);
	ILibDuktape_CreateInstanceMethodWithIntProperty(ctx, "_shared", 1, "Shared", ILibDuktape_SimpleDataStore_Create, 0);
}

void ILibDuktape_SimpleDataStore_init(duk_context * ctx, ILibSimpleDataStore sharedDb)
{
	ILibDuktape_ModSearch_AddHandler(ctx, "SimpleDataStore", ILibDuktape_SimpleDataStore_PUSH);
	if (sharedDb != NULL)
	{
		duk_push_heap_stash(ctx);					// [stash]
		duk_push_pointer(ctx, sharedDb);			// [stash][ptr]
		duk_put_prop_string(ctx, -2, "_sharedDB");	// [stash]
		duk_pop(ctx);								// ..
	}
}

#ifdef __DOXY__
/*!
\brief Provides a compact Key/Value datastore. <b>Note:</b> To use, must <b>require('SimpleDataStore').Create() or require('SimpleDataStore').Shared()</b>
*/
class SimpleDataStore
{
public:
	/*!
	\brief Adds the specified Key/Value pair to the SimpleDataStore. If the key already exists, the old value will be overwritten.
	\param key \<String\> The Key to be added to the SimpleDataStore instance. Value will be overwritten if it already exists.
	\param value \<Buffer\|String\> The value to be added to the SimpleDataStore instance.
	*/
	void Put(key, value);
	/*!
	\brief Retrieves the given 'key' from the SimpleDataStore instance.
	\param key \<String\> The key to retrieve from the SimpleDataStore instance
	\return \<Buffer\|String\> The value bound to the specified key. NULL if the key does not exist.
	*/
	Object Get(key);
	/*!
	\brief Compacts the SimpleDataStoreInstance, removing <b>'dealloc'</b>ed blocks.
	*/
	void Compact();
	/*!
	\brief Enumerates all the keys in the SimpleDataStore instance
	\return Array<String> of all the valid keys.
	*/
	Array<String> Keys;




	/*!
	\brief Creates a new SimpleDataStore instance, using the specified path
	\param path \<String\> Path of the datastore to use/create.
	*/
	static SimpleDataStore Create(path);
	/*!
	\brief Creates a shared SimpleDataStore instance bound to the datastore created by the JavaScriptEngine (if available)
	*/
	static SimpleDataStore Shared();
};
#endif