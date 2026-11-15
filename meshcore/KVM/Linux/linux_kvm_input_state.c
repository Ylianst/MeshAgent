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

#include "linux_kvm_input_state.h"

#include <string.h>

void kvm_input_state_cancel_unicode(kvm_input_state *state)
{
    if (state == NULL) { return; }
    state->unicode_high = 0;
    state->unicode_started_ms = 0;
}

int kvm_input_state_unicode(kvm_input_state *state, uint16_t unit, int up,
    uint64_t now_ms, uint32_t *codepoint)
{
    uint16_t high;
    uint64_t started;
    if (state == NULL || codepoint == NULL || up != 0) { return 0; }
    high = state->unicode_high;
    started = state->unicode_started_ms;
    kvm_input_state_cancel_unicode(state);
    if (unit >= 0xd800 && unit <= 0xdbff)
    {
        state->unicode_high = unit;
        state->unicode_started_ms = now_ms;
        return 0;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff)
    {
        if (high == 0 || now_ms < started || now_ms - started > 1000) { return 0; }
        *codepoint = 0x10000u + (((uint32_t)high - 0xd800u) << 10) + unit - 0xdc00u;
        return 1;
    }
    *codepoint = unit;
    return 1;
}

void kvm_input_state_set(kvm_input_state *state, unsigned int code, int down)
{
	if (state == NULL || code > KVM_INPUT_STATE_MAX_CODE) { return; }
	state->down[code] = down ? 1 : 0;
}

int kvm_input_state_release_all(kvm_input_state *state, kvm_input_release_handler release_handler,
	void *context)
{
	unsigned int code;
	int released = 0;
	if (state == NULL) { return 0; }
	for (code = 0; code <= KVM_INPUT_STATE_MAX_CODE; ++code)
	{
		if (state->down[code])
		{
			if (release_handler != NULL) { release_handler(context, code); }
			++released;
		}
	}
	memset(state, 0, sizeof(*state));
	return released;
}
