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
	TILE_DONE = 0,			// Nothing to send, the tile is unchanged or was sent in this pass
	TILE_CHANGED			// The tile differs from the reference and was not sent yet
};

struct tileInfo_t {
	unsigned char stale;	// 1 when the reference frame does not hold this tile, so it counts as changed
	unsigned char flag;
};

extern void tile_info_alloc(void);
extern void tile_info_free(void);
extern void tile_request_refresh(void);
extern int tile_pass_pending(void);
extern void tile_start_pass(const unsigned char *desktop, long long desktopsize);
extern int adjust_screen_size(int pixles);
extern int getTileAt(int x, int y, void** buffer, long long *bufferSize, void *desktop, long long desktopsize, int row, int col);
extern int getScreenBuffer(unsigned char **desktop, long long *desktopsize, CGImageRef image);
extern void set_tile_compression(int type, int level);


#endif /* LINUX_TILE_H_ */

