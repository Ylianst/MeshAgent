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

#ifndef ___ILIBDUKTAPEMODSEARCH___
#define ___ILIBDUKTAPEMODSEARCH___

#include "duktape.h"
#include "microstack/ILibSimpleDataStore.h"

typedef void (*ILibDuktape_ModSearch_PUSH_Object)(duk_context *ctx, void *chain);

int ILibDuktape_ModSearch_AddHandler(duk_context *ctx, char *id, ILibDuktape_ModSearch_PUSH_Object handler);
int ILibDuktape_ModSearch_AddModule(duk_context *ctx, char *id, char *module, int moduleLen);
void ILibDuktape_ModSearch_Init(duk_context *ctx, void *chain, ILibSimpleDataStore mDB);

#endif
