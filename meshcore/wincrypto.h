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

void __fastcall wincrypto_setregistry(LPWSTR name, LPWSTR value);
void __fastcall wincrypto_setregistryA(char* name, char* value);
int  __fastcall wincrypto_getregistry(LPCWSTR name, char** value);
int  __fastcall wincrypto_getregistryA(char* name, char** value);
int  __fastcall wincrypto_isopen();
void __fastcall wincrypto_close_ex(PCCERT_CONTEXT certCtx);
#define wincrypto_close() wincrypto_close_ex(NULL)
#define wincrypto_open(newCert, rootSubject) wincrypto_open_ex(newCert, rootSubject, NULL)
int __fastcall wincrypto_open_ex(int newcert, char *rootSubject, PCCERT_CONTEXT *certCtx);
void __fastcall wincrypto_random(int length, char* result);
int  __fastcall wincrypto_md5(char* data, int datalen, char* result);
int  __fastcall wincrypto_sha256(char* data, int datalen, char* result);
int  __fastcall wincrypto_sha384(char* data, int datalen, char* result);
int  __fastcall wincrypto_sign(char* data, int len, char** signature);
int  __fastcall wincrypto_decrypt(char* encdata, int encdatalen, char** data);
#define wincrypto_getcert(data) wincrypto_getcert_ex(data, NULL)
int  __fastcall wincrypto_getcert_ex(char** data, PCCERT_CONTEXT certCtx);
int  __fastcall wincrypto_mkCert(char* rootSubject, wchar_t* subject, int certtype, wchar_t* password, char** data); // certtype: 1=Root, 2=Server, 3=Client

#endif
