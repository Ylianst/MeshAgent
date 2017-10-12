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

#ifndef LINUX_TILE_H_
#define LINUX_TILE_H_

#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "linux_compression.h"

enum TILE_FLAGS_ENUM {
	TILE_TODO,						//The tile CRC needs to be calculated.
	TILE_SENT,						//CRC has been calculated and the tile has been sent.
	TILE_MARKED_NOT_SENT,   		//CRC has been calculated, but the tile was not sent.
	TILE_DONT_SEND		  //CRC has been calculated, tile need not be sent.
	//TILE_SKIPPED		  //CRC has been calculated, tile need not be sent, but was skipped to include a greater region
};

struct tileInfo_t {
	int crc;
	enum TILE_FLAGS_ENUM flag;
};

extern int reset_tile_info(int old_height_count);
extern int adjust_screen_size(int pixles);
extern int getTileAt(int x, int y, void** buffer, long long *bufferSize, void *desktop, long long desktopsize, int row, int col);
extern int getScreenBuffer(char **desktop, long long *desktopsize, XImage *image);
extern void set_tile_compression(int type, int level);


#endif /* LINUX_TILE_H_ */
