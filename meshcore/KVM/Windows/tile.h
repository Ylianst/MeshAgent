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

#if defined(_LINKVM)

#include <Windows.h>
#include <tchar.h>

#if defined(_cplus_plus) || defined(__cplusplus) || defined(_cplusplus)
extern "C"
{
#endif

struct tileInfo_t {
	unsigned char stale;	// 1 when the reference frame in tile.cpp does not hold this tile, so it counts as changed
	unsigned char flags;	// See TILE_FLAGS_ENUM
};

enum TILE_FLAGS_ENUM {
	TILE_TODO = 0,			// The tile needs to be compared with the reference frame
	TILE_CHANGED,			// The tile has changed, but was not sent yet
	TILE_DONE				// The tile was handled this pass, nothing is left to send
};

short initialize_gdiplus();
void teardown_gdiplus();
int get_tile_at(int x, int y, void** buffer, long long *bufferSize, void *desktop, int row, int col);
void tile_mark_all_stale(void);
int get_desktop_buffer(void **buffer, long long *bufferSize, long*);
BITMAPINFO get_bmp_info(int width, int height);
void set_tile_compression(int type, int level);
void switch_to_desktop_context();

#if defined(_cplus_plus) || defined(__cplusplus) || defined(_cplusplus)
}
#endif

#endif
