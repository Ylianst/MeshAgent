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

// Owned by tile.cpp, the capture loop in kvm.c only reads them
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;

short initialize_gdiplus();
void teardown_gdiplus();
void get_tile_at(void** buffer, long long *bufferSize, void *desktop, int row, int col);
void tile_info_alloc(void);			// Sizes the tile table for the current scaled screen
void tile_info_free(void);
void tile_start_pass(void *desktop);	// Called by the capture loop before it walks the tiles, marks the changed ones
void tile_request_refresh(void);	// Safe from any thread
int get_desktop_buffer(void **buffer, long long *bufferSize, long*);
BITMAPINFO get_bmp_info(int width, int height);
void set_tile_compression(int type, int level);
void switch_to_desktop_context();

#if defined(_cplus_plus) || defined(__cplusplus) || defined(_cplusplus)
}
#endif

#endif
