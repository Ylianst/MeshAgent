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

#ifndef LINUX_KVM_XKB_H_
#define LINUX_KVM_XKB_H_

#include <stdint.h>

// Resolves unicode codepoints to evdev key strokes through the Wayland session's real XKB keymap
// (wl_seat/wl_keyboard + libxkbcommon, both dlopen'd), so the uinput injector can type characters
// that exist in any configured layout instead of only US-position ASCII. Everything degrades to
// "not found" when Wayland or libxkbcommon is unavailable; callers keep their ASCII fallback.

typedef struct kvm_xkb_match
{
	unsigned int keycode;	// evdev keycode (KEY_*)
	int shift;
	int altgr;
} kvm_xkb_match;

// 1 = codepoint reachable on the session keymap; fills *match. capslockOn selects the table built
// with CapsLock locked, so caps interaction is exact for every script. Lazily connects to the
// session's Wayland display on first use (privileges must already be dropped to the session user).
int kvm_xkb_lookup_unicode(uint32_t codepoint, int capslockOn, kvm_xkb_match *match);

// Builds the lookup tables directly from an XKB keymap text (xkb_v1). Used by the wl_keyboard
// keymap event internally; exposed so tests can exercise the resolver without a Wayland session.
int kvm_xkb_build_from_keymap_string(const char *keymapText);

void kvm_xkb_shutdown(void);

#endif
