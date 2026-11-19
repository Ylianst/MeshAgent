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

#ifndef __DXGI_CAPTURE_H__
#define __DXGI_CAPTURE_H__

#if defined(_LINKVM)

#ifdef __cplusplus
extern "C" {
#endif

// Captures the screen rectangle (x, y, w, h) bottom-up into dest, starting the duplication when needed.
// destCurrent says dest still holds the last frame this function wrote, so an unchanged screen needs no copy until the next release.
// Returns 0 when dest holds the current screen, 1 when the caller has to capture this frame with GDI.
int dxgi_capture_frame(int x, int y, int w, int h, unsigned char *dest, int destWidth, int destHeight, int destCurrent);

void dxgi_capture_release(void);

// Set once Desktop Duplication cannot work on this system at all, for example on Windows 7
int dxgi_capture_unsupported(void);

#ifdef __cplusplus
}
#endif

#endif
#endif
