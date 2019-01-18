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

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include "ILibDuktapeModSearch.h"
#include "microstack/ILibParsers.h"
#include "microscript/ILibDuktape_Helpers.h"
#include "microscript/duk_module_duktape.h"

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#define ILibDuktape_ModSearch_ModuleFile	(void*)0xFF
#define ILibDuktape_ModSearch_ModuleObject	(void*)0xFE
#define ILibDuktape_ModSearch_JSInclude		"\xFF_ModSearch_JSINCLUDE"
#define ILibDuktape_ModSearch_ModulePath	"\xFF_ModSearch_Path"

duk_ret_t ILibDuktape_ModSearch_GetJSModule(duk_context *ctx, char *id)
{
	ILibHashtable table = NULL;
	int idLen = (int)strnlen_s(id, 1024);
	char *retVal = NULL;

	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, "ModSearchTable"))
	{
		duk_get_prop_string(ctx, -1, "ModSearchTable");		// [stash][ptr]
		table = (ILibHashtable)duk_to_pointer(ctx, -1);
		duk_pop(ctx);										// [stash]
	}
	else
	{
		table = ILibHashtable_Create();
		duk_push_pointer(ctx, table);						// [stash][ptr]
		duk_put_prop_string(ctx, -2, "ModSearchTable");		// [stash]
	}
	duk_pop(ctx);											// ...

	retVal = ILibHashtable_Get(table, ILibDuktape_ModSearch_ModuleFile, id, idLen);
	if (retVal == NULL)
	{
		duk_push_heap_stash(ctx);
		char *mpath;
		duk_size_t mpathLen;
		mpath = Duktape_GetStringPropertyValueEx(ctx, -1, ILibDuktape_ModSearch_ModulePath, NULL, &mpathLen);
		duk_pop(ctx);

		char *fileName = ILibMemory_AllocateA(idLen + 4 + mpathLen + 1);
		if (mpath == NULL)
		{
			sprintf_s(fileName, idLen + 4, "%s.js", id);
		}
		else
		{
			sprintf_s(fileName, idLen + 5 + mpathLen, "%s/%s.js", mpath, id);
		}
		int dataLen = ILibReadFileFromDiskEx(&retVal, fileName);
		if (dataLen > 0) { duk_push_lstring(ctx, retVal, dataLen); free(retVal); }
		else
		{
			return(0);
		}
	}
	else
	{
		duk_push_string(ctx, retVal);
	}
	return(1);
}
void ILibDuktape_ModSearch_AddModuleObject(duk_context *ctx, char *id, void *heapptr)
{
	int idLen = (int)strnlen_s(id, 1024);
	ILibHashtable table = NULL;

	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, "ModSearchTable"))
	{
		duk_get_prop_string(ctx, -1, "ModSearchTable");		// [stash][ptr]
		table = (ILibHashtable)duk_to_pointer(ctx, -1);
		duk_pop(ctx);										// [stash]
	}
	else
	{
		table = ILibHashtable_Create();
		duk_push_pointer(ctx, table);						// [stash][ptr]
		duk_put_prop_string(ctx, -2, "ModSearchTable");		// [stash]
	}

	duk_push_heapptr(ctx, heapptr);
	duk_put_prop_string(ctx, -2, Duktape_GetStashKey(heapptr));
	heapptr = ILibHashtable_Put(table, ILibDuktape_ModSearch_ModuleObject, id, idLen, heapptr);

	if (heapptr != NULL)
	{
		// Remove the old object that was in the table
		duk_del_prop_string(ctx, -1, Duktape_GetStashKey(heapptr));
	}
	duk_pop(ctx);											// ...
}
int ILibDuktape_ModSearch_AddModule(duk_context *ctx, char *id, char *module, int moduleLen)
{
	ILibHashtable table = NULL;
	int idLen = (int)strnlen_s(id, 1024);

	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, "ModSearchTable"))
	{
		duk_get_prop_string(ctx, -1, "ModSearchTable");		// [stash][ptr]
		table = (ILibHashtable)duk_to_pointer(ctx, -1);
		duk_pop(ctx);										// [stash]
	}
	else
	{
		table = ILibHashtable_Create();
		duk_push_pointer(ctx, table);						// [stash][ptr]
		duk_put_prop_string(ctx, -2, "ModSearchTable");		// [stash]
	}
	duk_pop(ctx);											// ...

	//if (ILibHashtable_Get(table, NULL, id, idLen) != NULL || ILibHashtable_Get(table, ILibDuktape_ModSearch_ModuleFile, id, idLen) != NULL) { return 1; }
	char *newModule = (char*)ILibDuktape_Memory_Alloc(ctx, moduleLen+1);
	memcpy_s(newModule, moduleLen + 1, module, moduleLen);
	newModule[moduleLen] = 0;

	ILibHashtable_Put(table, ILibDuktape_ModSearch_ModuleFile, id, idLen, newModule);
	return 0;
}
int ILibDuktape_ModSearch_AddHandler(duk_context *ctx, char *id, ILibDuktape_ModSearch_PUSH_Object handler)
{
	ILibHashtable table = NULL;
	int idLen = (int)strnlen_s(id, 1024);

	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, "ModSearchTable"))
	{
		duk_get_prop_string(ctx, -1, "ModSearchTable");		// [stash][ptr]
		table = (ILibHashtable)duk_to_pointer(ctx, -1);
		duk_pop(ctx);										// [stash]
	}
	else
	{
		table = ILibHashtable_Create();
		duk_push_pointer(ctx, table);						// [stash][ptr]
		duk_put_prop_string(ctx, -2, "ModSearchTable");		// [stash]
	}
	duk_pop(ctx);											// ...

	if (ILibHashtable_Get(table, NULL, id, idLen) != NULL || ILibHashtable_Get(table, ILibDuktape_ModSearch_ModuleFile, id, idLen) != NULL) { return 1; }
	ILibHashtable_Put(table, NULL, id, idLen, handler);
	return 0;
}

duk_ret_t mod_Search_Files(duk_context *ctx, char* id)
{
	char fileName[255];
	char *data;
	int dataLen;
	char *mpath = NULL;

	duk_push_heap_stash(ctx);
	mpath = Duktape_GetStringPropertyValue(ctx, -1, ILibDuktape_ModSearch_ModulePath, NULL);
	duk_pop(ctx);

	if (mpath == NULL)
	{
		sprintf_s(fileName, sizeof(fileName), "%s.js", id);
	}
	else
	{
		sprintf_s(fileName, sizeof(fileName), "%s/%s.js", mpath, id);
	}
	dataLen = ILibReadFileFromDiskEx(&data, fileName);
	if (dataLen > 0)
	{
		duk_push_lstring(ctx, data, dataLen);
		free(data);
		return 1;
		//if (duk_peval_string(ctx, data) == 0)
		//{
		//	duk_put_prop_string(ctx, 3, "exports");
		//	return 0;
		//}
		//else
		//{
		//	snprintf(fileName, sizeof(fileName), "Module: %s (ERROR)", id);
		//	duk_push_string(ctx, fileName);
		//	duk_throw(ctx);
		//	return DUK_RET_ERROR;
		//}
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Module: %s (NOT FOUND)", id));
	}
}
void ILibDuktape_ModSearch_AddHandler_AlsoIncludeJS(duk_context *ctx, char *js, size_t jsLen)
{
	duk_push_heap_stash(ctx);										// [stash]
	duk_push_lstring(ctx, js, jsLen);								// [stash][str]
	duk_put_prop_string(ctx, -2, ILibDuktape_ModSearch_JSInclude);	// [stash]
	duk_pop(ctx);													// ...
}

duk_ret_t mod_Search(duk_context *ctx)
{
	duk_size_t idLen;
	char *id;
	ILibHashtable *table;
	ILibDuktape_ModSearch_PUSH_Object func = NULL;
	void *chain;
	ILibSimpleDataStore mDS = NULL;
	char *module;
	void *j;

	if (!duk_is_string(ctx, 0)) { return ILibDuktape_Error(ctx, "mod_search(): Invalid 'ID' parameter"); }
	id = (char*)duk_get_lstring(ctx, 0, &idLen);

	duk_push_current_function(ctx);				// [func]
	duk_get_prop_string(ctx, -1, "chain");		// [func][chain]
	chain = duk_to_pointer(ctx, -1);

	duk_get_prop_string(ctx, -2, "SimpleDS");	// [func][chain][DB]
	mDS = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);

	duk_push_heap_stash(ctx);
	duk_get_prop_string(ctx, -1, "ModSearchTable");
	table = (ILibHashtable)duk_to_pointer(ctx, -1);

	// First check if there is a JS override
	j = ILibHashtable_Get(table, ILibDuktape_ModSearch_ModuleObject, id, (int)idLen);
	if (j != NULL)
	{
		duk_push_heapptr(ctx, j);
		duk_put_prop_string(ctx, 3, "exports");
		return(0);
	}

	func = (ILibDuktape_ModSearch_PUSH_Object)ILibHashtable_Get(table, NULL, id, (int)idLen);
	if (func == NULL)
	{
		if ((module = (char*)ILibHashtable_Get(table, ILibDuktape_ModSearch_ModuleFile, id, (int)idLen)) != NULL)
		{
			duk_push_string(ctx, module);
			return(1);
		}
		else if (mDS == NULL)
		{
			return mod_Search_Files(ctx, id);
		}
		else
		{
			char key[255];
			int keyLen;
			char *value;
			int valueLen;

			keyLen = sprintf_s(key, sizeof(key), "__MODULE:%s", id);
			valueLen = ILibSimpleDataStore_GetEx(mDS, key, keyLen, NULL, 0);
			if (valueLen > 0)
			{
				value = ILibMemory_Allocate(valueLen, 0, NULL, NULL);
				ILibSimpleDataStore_GetEx(mDS, key, keyLen, value, valueLen);
				duk_push_lstring(ctx, value, valueLen);
				return 1;
			}
			else
			{
				return mod_Search_Files(ctx, id);
			}
		}
	}
	else
	{
		// Init this temp value, to detect if the module wants to add JS code
		duk_push_heap_stash(ctx);
		duk_del_prop_string(ctx, -1, ILibDuktape_ModSearch_JSInclude);
		duk_pop(ctx);

		func(ctx, chain);
		duk_put_prop_string(ctx, 3, "exports");

		duk_push_heap_stash(ctx);
		if (duk_has_prop_string(ctx, -1, ILibDuktape_ModSearch_JSInclude))
		{
			duk_get_prop_string(ctx, -1, ILibDuktape_ModSearch_JSInclude);
			return(1);
		}
		else
		{
			return 0;
		}
	}
}
void ILibDuktape_ModSearch_Destroy(duk_context *ctx, void *user)
{
	duk_push_heap_stash(ctx);								// [stash]
	if (duk_has_prop_string(ctx, -1, "ModSearchTable"))
	{
		duk_get_prop_string(ctx, -1, "ModSearchTable");		// [stash][ptr]
		ILibHashtable_Destroy((ILibHashtable)duk_to_pointer(ctx, -1));
		duk_del_prop_string(ctx, -2, "ModSearchTable");
		duk_pop_2(ctx);
	}
	else
	{
		duk_pop(ctx);
	}
}

duk_ret_t ILibDuktape_ModSearch_setModulePath(duk_context *ctx)
{
	if (duk_is_string(ctx, 0))
	{
		duk_push_heap_stash(ctx);
		duk_dup(ctx, 0);
		duk_put_prop_string(ctx, -2, ILibDuktape_ModSearch_ModulePath);
	}
	else
	{
		return(ILibDuktape_Error(ctx, "Invalid Path"));
	}
	
	return(0);
}

void ILibDuktape_ModSearch_Init(duk_context * ctx, void * chain, ILibSimpleDataStore mDB)
{
	duk_module_duktape_init(ctx);

	duk_push_heap_stash(ctx);									// [stash]
	duk_push_pointer(ctx, chain);								// [stash][chain]
	duk_put_prop_string(ctx, -2, ILibDuktape_Context_Chain);	// [stash]
	duk_pop(ctx);												// ...

	duk_get_global_string(ctx, "Duktape");		// [globalString]
	duk_push_c_function(ctx, mod_Search, 4);	// [globalString][func]
	duk_push_pointer(ctx, chain);				// [globalString][func][chain]
	duk_put_prop_string(ctx, -2, "chain");		// [globalString][func]

	if (mDB != NULL)
	{
		duk_push_pointer(ctx, mDB);					// [globalString][func][DB]
		duk_put_prop_string(ctx, -2, "SimpleDS");	// [globalString][func]
	}

	duk_put_prop_string(ctx, -2, "modSearch");	// [globalString]
	duk_pop(ctx);								// ...

	duk_push_global_object(ctx);				// [g]
	ILibDuktape_CreateInstanceMethod(ctx, "setModulePath", ILibDuktape_ModSearch_setModulePath, 1);
	duk_pop(ctx);								// ...


	ILibDuktape_Helper_AddHeapFinalizer(ctx, ILibDuktape_ModSearch_Destroy, NULL);
}
