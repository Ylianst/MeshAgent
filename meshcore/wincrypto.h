/*   
Copyright 2006 - 2015 Intel Corporation

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

#include <windows.h>

typedef void* wincrypto_object;
void __fastcall wincrypto_setregistry(LPWSTR name, LPWSTR value);
void __fastcall wincrypto_setregistryA(char* name, char* value);
int  __fastcall wincrypto_getregistry(LPCWSTR name, char** value);
int  __fastcall wincrypto_getregistryA(char* name, char** value);

int  __fastcall wincrypto_isopen(wincrypto_object j);
void __fastcall wincrypto_close(wincrypto_object j);
wincrypto_object __fastcall wincrypto_open(int newcert, char *rootSubject);
void __fastcall wincrypto_random(int length, char* result);
int  __fastcall wincrypto_md5(char* data, int datalen, char* result);
int  __fastcall wincrypto_sha256(char* data, int datalen, char* result);
int  __fastcall wincrypto_sha384(char* data, int datalen, char* result);
int  __fastcall wincrypto_sign(wincrypto_object j, char* data, int len, char** signature);
int  __fastcall wincrypto_decrypt(wincrypto_object j, char* encdata, int encdatalen, char** data);
int  __fastcall wincrypto_getcert(char** data, wincrypto_object j);
int  __fastcall wincrypto_mkCert(wincrypto_object j, char* rootSubject, wchar_t* subject, int certtype, wchar_t* password, char** data); // certtype: 1=Root, 2=Server, 3=Client

#endif
