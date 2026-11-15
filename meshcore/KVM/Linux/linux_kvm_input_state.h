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

#ifndef LINUX_KVM_INPUT_STATE_H_
#define LINUX_KVM_INPUT_STATE_H_

#include <stdint.h>

#define KVM_INPUT_STATE_MAX_CODE 0x2ffu

typedef struct kvm_input_state
{
	unsigned char down[KVM_INPUT_STATE_MAX_CODE + 1];
	uint16_t unicode_high;
	uint64_t unicode_started_ms;
} kvm_input_state;

typedef int (*kvm_input_release_handler)(void *context, unsigned int code);

// Unicode key packets carry UTF-16 units, with key-up packets between the halves.
// A pending high surrogate expires after one second or any non-text input/reset.
void kvm_input_state_cancel_unicode(kvm_input_state *state);
int kvm_input_state_unicode(kvm_input_state *state, uint16_t unit, int up,
    uint64_t now_ms, uint32_t *codepoint);

void kvm_input_state_set(kvm_input_state *state, unsigned int code, int down);
int kvm_input_state_release_all(kvm_input_state *state, kvm_input_release_handler release_handler,
	void *context);

#endif
