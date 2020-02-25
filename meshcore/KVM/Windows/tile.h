/*   
Copyright 2006 - 2018 Intel Corporation

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
	int crc;
	char flags; // See TILE_FLAGS_ENUM
};

enum TILE_FLAGS_ENUM {
	TILE_TODO,				// The tile CRC needs to be calculated.
	TILE_SENT,				// CRC has been calculated and the tile has been sent.
	TILE_MARKED_NOT_SENT,	// CRC has been calculated, but the tile was not sent.
	TILE_DONT_SEND			// CRC has been calculated, tile need not be sent.
	//TILE_SKIPPED			// CRC has been calculated, tile need not be sent, but was skipped to include a greater region
};

short initialize_gdiplus();
void teardown_gdiplus();
int get_tile_at(int x, int y, void** buffer, long long *bufferSize, void *desktop, int row, int col);
int get_desktop_buffer(void **buffer, long long *bufferSize, long*);
BITMAPINFO get_bmp_info(int width, int height);
void set_tile_compression(int type, int level);
void switch_to_desktop_context();

#if defined(_cplus_plus) || defined(__cplusplus) || defined(_cplusplus)
}
#endif

#endif
