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

#if !defined(_NOHECI)

#ifndef __ILibLMS__
#define __ILibLMS__
#include "../../microstack/ILibAsyncServerSocket.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
void __fastcall ILibLMS_setregistryA(char* name, char* value);
int __fastcall ILibLMS_getregistryA(char* name, char** value);
int __fastcall ILibLMS_deleteregistryA(char* name);
#endif

struct cimString {
	char *data;
	int dataLen;
};

struct cimAlertIndication {
	struct cimString MessageID;
	struct cimString MessageArguments;
	struct cimString IndicationTime;

	/*
	int AlertType;
	struct cimString AlertingManagedElement;
	int AlertingElementFormat;
	struct cimString CorrelatedIndications;
	struct cimString Description;
	struct cimString EventID;
	struct cimString EventTime;
	struct cimString IndicationFilterName;
	struct cimString IndicationIdentifier;
	struct cimString OtherAlertType;
	struct cimString OtherAlertingElementFormat;
	struct cimString OtherSeverity;
	struct cimString OwningEntity;
	int PerceivedSeverity;
	int ProbableCause;
	struct cimString ProbableCauseDescription;
	struct cimString ProviderName;
	struct cimString RecommendedActions;
	struct cimString SequenceContext;
	long SequenceNumber;
	struct cimString SystemCreationClassName;
	struct cimString SystemName;
	int Trending;
	struct cimString __any;
	struct cimString __anyAttribute;
	*/
};

extern int ILibMemory_ILibLMS_CONTAINERSIZE;
typedef void(*ILibLMS_OnNotification)(void *module, struct cimAlertIndication *values, char* xml, int xmllen);

void *ILibLMS_CreateEx(void *Chain, char* SelfExe, ILibLMS_OnNotification callback, int extraMemorySize);
#define ILibLMS_Create(Chain, SelfExe, callback) ILibLMS_CreateEx(Chain, SelfExe, callback, 0)
int ILibLMS_GetMeInformation(char** data, int loginmode);
int ILibLMS_GetAmtVersion();

#ifdef __cplusplus
}
#endif

#endif

#endif
