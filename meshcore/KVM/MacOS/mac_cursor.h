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

#ifndef MAC_CURSOR_H_
#define MAC_CURSOR_H_

#include "../../../microstack/ILibParsers.h"

// Returns the viewer's index of the current pointer shape, or -1 when the pointer cannot be read
int kvm_cursor_current(void);

// Queues an MNG_KVM_MOUSE_CURSOR message when the pointer shape changed, read on every pass while the viewer uses the mouse and at most ten times a second otherwise
void kvm_cursor_check(ILibQueue queue);

// The viewer moved or clicked, so the pointer is read on every pass for a while
void kvm_cursor_moved(void);

// A new session's viewer starts with its default pointer, so the next check sends the current shape even when it did not change
void kvm_cursor_reset(void);

#endif
