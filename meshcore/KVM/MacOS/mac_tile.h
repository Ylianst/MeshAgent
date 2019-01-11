/*
 *  mac_tile.h
 *  
 *
 *  Created by Ylian Saint-Hilaire on 8/18/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef LINUX_TILE_H_
#define LINUX_TILE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <Carbon/Carbon.h>
#include "../Linux/linux_compression.h"

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
extern int getScreenBuffer(unsigned char **desktop, long long *desktopsize, CGImageRef image);
extern void set_tile_compression(int type, int level);


#endif /* LINUX_TILE_H_ */

