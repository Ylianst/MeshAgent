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

#define ILibDuktape_ModSearch_ModuleFile		"\xFF_Modules_File"
#define ILibDuktape_ModSearch_ModuleFunc		"\xFF_Modules_Func"
#define ILibDuktape_ModSearch_ModuleFileDate	"\xFF_Modules_FileDate"
#define ILibDuktape_ModSearch_ModuleRequired	"\xFF_Modules_Requried"
#define ILibDuktape_ModSearch_ModuleObject		"\xFF_Modules_Object"


#define ILibDuktape_ModSearch_JSInclude			"\xFF_ModSearch_JSINCLUDE"
#define ILibDuktape_ModSearch_ModulePath		"\xFF_ModSearch_Path"

int ILibDuktape_ModSearch_ShowNames = 0;

duk_ret_t ModSearchTable_Get(duk_context *ctx, duk_idx_t table, char *key, char *id)
{
	if (!duk_has_prop_string(ctx, table, id))
	{
		return(-1);
	}
	duk_get_prop_string(ctx, table, id);			// [table][...][module]
	if (!duk_has_prop_string(ctx, -1, key))
	{
		duk_pop(ctx);								// [table][...]
		return(-1);
	}
	duk_get_prop_string(ctx, -1, key);				// [table][...][module][value]
	duk_remove(ctx, -2);							// [table][...][value]
	return(1);
}
duk_ret_t ModSearchTable_Put(duk_context *ctx, duk_idx_t table, char *key, char *id)
{
	if (!duk_has_prop_string(ctx, table, id))
	{
		duk_dup(ctx, table);						// [table][...][val][table]
		duk_push_object(ctx);						// [table][...][val][table][objtable]
		duk_put_prop_string(ctx, -2, id);			// [table][...][val][table]
		duk_pop(ctx);								// [table][...][val]
	}
	duk_dup(ctx, table);							// [table][...][val][table]
	duk_get_prop_string(ctx, -1, id);				// [table][...][val][table][objtable]
	duk_dup(ctx, -3);								// [table][...][val][table][objtable][val]
	duk_put_prop_string(ctx, -2, key);				// [table][...][val][table][objtable]
	duk_pop_3(ctx);									// [table][...]
	return(0);
}


uint32_t ILibDuktape_ModSearch_GetJSModuleDate(duk_context *ctx, char *id)
{
	uint32_t retVal;
	char *mpath;
	duk_size_t mpathLen;
	char *fileName = NULL;
	int top = duk_get_top(ctx);

	duk_push_heap_stash(ctx);																			// [stash]
	mpath = Duktape_GetStringPropertyValueEx(ctx, -1, ILibDuktape_ModSearch_ModulePath, NULL, &mpathLen);

	if (mpath == NULL)
	{
		fileName = (char*)duk_push_sprintf(ctx, "%s.js", id);
	}
	else
	{																									
		fileName = (char*)duk_push_sprintf(ctx, "%s/%s.js", mpath, id);
	}

	duk_push_sprintf(ctx, "(new Date(require('fs').statSync('%s').mtime)).getTime()/1000", fileName);	// [stash][fileName][str]
	if (duk_peval(ctx) == 0)										// [stash][fileName][result]
	{
		// use result from disc
		retVal = duk_get_uint(ctx, -1);
	}
	else
	{
		// use result from module table
		retVal = 0;
		duk_get_prop_string(ctx, -3, "ModSearchTable");				// [stash][fileName][result][table]
		if (ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleFileDate, id) > 0)
		{
			retVal = (uint32_t)duk_get_uint(ctx, -1);
		}
	}
	
	duk_set_top(ctx, top);
	return(retVal);
}
int ILibDuktape_ModSearch_IsRequired(duk_context *ctx, char *id, size_t idLen)
{
	int top = duk_get_top(ctx);
	int ret = 0;
	UNREFERENCED_PARAMETER(idLen);

	duk_push_heap_stash(ctx);										// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");					// [stash][table]
	if (ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleRequired, id) > 0)
	{
		ret = duk_get_boolean(ctx, -1) ? 1 : 0;
	}
	duk_set_top(ctx, top);
	return(ret);
}
duk_ret_t ILibDuktape_ModSearch_GetJSModule(duk_context *ctx, char *id)
{
	char *retVal = NULL;
	char *fileName;
	char *mpath;
	duk_size_t mpathLen;

	duk_push_heap_stash(ctx);										// [stash]
	mpath = Duktape_GetStringPropertyValueEx(ctx, -1, ILibDuktape_ModSearch_ModulePath, NULL, &mpathLen);

	if (mpath == NULL)
	{
		duk_push_sprintf(ctx, "%s.js", id);							// [stash][str]
	}
	else
	{
		duk_push_sprintf(ctx, "%s/%s.js", mpath, id);				// [stash][str]
	}
	fileName = (char*)duk_get_string(ctx, -1);

	int dataLen = ILibReadFileFromDiskEx(&retVal, fileName);
	if (dataLen > 0) 
	{ 
		duk_push_lstring(ctx, retVal, dataLen); free(retVal); 
		return(1);
	}
	else
	{
		duk_get_prop_string(ctx, -2, "ModSearchTable");			// [stash][str][table]
		if(ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleFile, id)>0)
		{
			return(1);
		}
		else
		{
			return(0);
		}
	}
}
void ILibDuktape_ModSearch_AddModuleObject(duk_context *ctx, char *id, void *heapptr)
{
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_push_heapptr(ctx, heapptr);										// [stash][table][object]
	ModSearchTable_Put(ctx, -2, ILibDuktape_ModSearch_ModuleObject, id);// [stash][table]
	duk_pop_2(ctx);														// ...
}
int ILibDuktape_ModSearch_AddModuleEx(duk_context *ctx, char *id, char *module, int moduleLen, char *mtime)
{
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_push_lstring(ctx, module, moduleLen);							// [stash][table][module]
	ModSearchTable_Put(ctx, -2, ILibDuktape_ModSearch_ModuleFile, id);	// [stash][table]
	if (mtime != NULL)
	{
		duk_push_sprintf(ctx, "(new Date('%s')).getTime()/1000", mtime);		// [stash][table][string]
		duk_eval(ctx);															// [stash][table][uint]
		ModSearchTable_Put(ctx, -2, ILibDuktape_ModSearch_ModuleFileDate, id);	// [stash][table]
	}
	duk_pop_2(ctx);																// ...
	return(0);
}
int ILibDuktape_ModSearch_AddHandler(duk_context *ctx, char *id, ILibDuktape_ModSearch_PUSH_Object handler)
{
	duk_push_heap_stash(ctx);											// [stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");						// [stash][table]
	duk_push_pointer(ctx, (void*)handler);								// [stash][table][ptr]
	ModSearchTable_Put(ctx, -2, ILibDuktape_ModSearch_ModuleFunc, id);	// [stash][table]
	duk_pop_2(ctx);														// ...
	return(0);
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
	}
	else
	{
		return(0);
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
	ILibDuktape_ModSearch_PUSH_Object func = NULL;
	void *chain;
	ILibSimpleDataStore mDS = NULL;

	if (!duk_is_string(ctx, 0)) { return ILibDuktape_Error(ctx, "mod_search(): Invalid 'ID' parameter"); }
	id = (char*)duk_get_lstring(ctx, 0, &idLen);

	if (ILibDuktape_ModSearch_ShowNames != 0) { printf("ModuleLoader: %s\n", (char*)duk_require_string(ctx, 0)); }

	duk_push_current_function(ctx);													// [func]
	duk_get_prop_string(ctx, -1, "chain");											// [func][chain]
	chain = duk_to_pointer(ctx, -1);

	duk_get_prop_string(ctx, -2, "SimpleDS");										// [func][chain][DB]
	mDS = (ILibSimpleDataStore)duk_to_pointer(ctx, -1);

	duk_push_heap_stash(ctx);														// [func][chain][DB][stash]
	duk_get_prop_string(ctx, -1, "ModSearchTable");									// [func][chain][DB][stash][table]

	// First check if there is a JS Object override
	if (ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleObject, id) > 0)	// [func][chain][DB][stash][table][obj]
	{
		duk_put_prop_string(ctx, 3, "exports");										// [func][chain][DB][stash][table][obj]
		return(0);
	}
	 
	// Check if there is a native handler
	if (ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleFunc, id) > 0)		// [func][chain][DB][stash][table][ptr]
	{
		// Init this temp value, to detect if the module wants to add JS code
		duk_del_prop_string(ctx, -3, ILibDuktape_ModSearch_JSInclude);
		func = (ILibDuktape_ModSearch_PUSH_Object)duk_get_pointer(ctx, -1);

		func(ctx, chain);															// [func][chain][DB][stash][table][ptr][obj]
		duk_put_prop_string(ctx, 3, "exports");										// [func][chain][DB][stash][table][ptr]

		if (duk_has_prop_string(ctx, -3, ILibDuktape_ModSearch_JSInclude))
		{
			duk_get_prop_string(ctx, -3, ILibDuktape_ModSearch_JSInclude);
			return(1);
		}
		else
		{
			return 0;
		}
	}
	else
	{																				// [func][chain][DB][stash][table]
		// Check the local filesystem, becuase if present, those should take precedence
		if(mod_Search_Files(ctx, id) == 1)
		{
			return(1);
		}

		if (ModSearchTable_Get(ctx, -1, ILibDuktape_ModSearch_ModuleFile, id) > 0)
		{																			// [func][chain][DB][stash][table][string]
			//
			// Let's mark that this was already "require'ed"
			//
			duk_push_true(ctx);														// [func][chain][DB][stash][table][string][true]
			ModSearchTable_Put(ctx, -3, ILibDuktape_ModSearch_ModuleRequired, id);	// [func][chain][DB][stash][table][string]
			return(1);
		}
		else if (mDS == NULL)
		{ 
			// If No database, then nothing more we can do
			return(ILibDuktape_Error(ctx, "Module: %s (NOT FOUND)", id));
		}
		else
		{
			// Next Check the database
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
				// Not in database, then nothing more we can do
				return(ILibDuktape_Error(ctx, "Module: %s (NOT FOUND)", id));
			}
		}
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
	if (duk_ctx_chain(ctx) == NULL) { duk_ctx_context_data(ctx)->chain = chain; }

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


	duk_push_heap_stash(ctx);							// [stash]
	duk_push_object(ctx);								// [stash][table]
	duk_put_prop_string(ctx, -2, "ModSearchTable");		// [stash]
	duk_pop(ctx);										// ...
}
