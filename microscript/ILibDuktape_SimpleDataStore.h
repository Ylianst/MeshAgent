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

#ifndef __DUKTAPE_SIMPLEDATASTORE__
#define __DUKTAPE_SIMPLEDATASTORE__


#include "duktape.h"
#include "microstack/ILibSimpleDataStore.h"

void ILibDuktape_SimpleDataStore_init(duk_context *ctx, ILibSimpleDataStore sharedDb);
void ILibDuktape_SimpleDataStore_raw_GetCachedValues_Array(duk_context *ctx, ILibSimpleDataStore dataStore);
void ILibDuktape_SimpleDataStore_raw_GetCachedValues_Object(duk_context *ctx, ILibSimpleDataStore dataStore);

#endif
