/*   
Copyright 2010 - 2011 Intel Corporation

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

#ifndef LINUX_COMPRESSION_H_
#define LINUX_COMPRESSION_H_

#include <stdio.h>
#include <stdlib.h>
#ifdef __APPLE__
#include "lib-jpeg-turbo/includes/jpeglib.h"
#include "lib-jpeg-turbo/includes/jerror.h"
#else
#include <jpeglib.h>
#include <jerror.h>
#endif

#define MAX_BUFFER  22528 // 22 KiB should be fine.

typedef void(*JPEG_error_handler)(char *msg);

extern int write_JPEG_buffer (JSAMPLE * image_buffer, int image_width, int image_height, int quality);
extern JPEG_error_handler default_JPEG_error_handler;

#endif // LINUX_COMPRESSION_H_ 
