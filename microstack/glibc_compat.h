/*
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

#ifndef MESH_GLIBC_COMPAT_H_
#define MESH_GLIBC_COMPAT_H_

// glibc 2.29 re-versioned these libm functions to @GLIBC_2.29. Built on a newer glibc (the armhf
// CI image is Raspbian bullseye, glibc 2.31) the agent then refuses to load on Raspbian 10/Buster
// (glibc 2.28) with "version `GLIBC_2.29' not found". They are the only symbols above 2.28 on
// armhf, so bind the base armhf version to keep the floor at Buster. The makefile force-includes
// this only for the glibc armhf target; the gate is a predefined-macro safety net (__GLIBC__ is
// not defined this early, before any libc header, so it cannot be tested here).
#if defined(__linux__) && defined(__arm__)
__asm__(".symver exp,exp@GLIBC_2.4");
__asm__(".symver log,log@GLIBC_2.4");
__asm__(".symver log2,log2@GLIBC_2.4");
__asm__(".symver pow,pow@GLIBC_2.4");
#endif

#endif
