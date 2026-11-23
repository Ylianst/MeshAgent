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

#ifndef MAC_SCK_H_
#define MAC_SCK_H_

#include <CoreGraphics/CoreGraphics.h>

struct tileFrame_t;

// 0 before macOS 12.3, which has no ScreenCaptureKit
int kvm_sck_available(void);

// Starts a ScreenCaptureKit stream of the display at width x height pixels, at most one frame per intervalMs, and returns 0 when it runs
int kvm_sck_start(CGDirectDisplayID display, int width, int height, int intervalMs);

// Changes the interval of the running stream and returns 0 when the stream took it
int kvm_sck_set_interval(int intervalMs);

// Describes the newest changed frame in *frame. Its pixels stay valid until the next take that returns 1, or kvm_sck_stop().
// Returns 1 for a new frame, 0 when none came within timeoutMs, -1 when the stream stopped.
int kvm_sck_take_frame(struct tileFrame_t *frame, int timeoutMs);

// Describes the frame taken last once more, and returns 0 when there is none
int kvm_sck_last_frame(struct tileFrame_t *frame);

void kvm_sck_stop(void);

#endif
