/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LINUX_KVM_EIS_H_
#define LINUX_KVM_EIS_H_
#include <stdint.h>
/* Only called by the single-threaded capture worker after its session UID drop.
 * 0: unavailable, no text queued; 1: server roundtrip completed; -1: discard,
 * delivery ambiguous or session invalidated. A roundtrip is not an application
 * acknowledgement. Do not retry -1 through another input backend.
 */
int kvm_eis_type_unicode(uint32_t codepoint);
/* Evdev keycodes, pressed 0/1; the adapter keeps a press/release on the same
 * route even if lock state changes. Same no-retry rule as native text. */
int kvm_eis_key_action(uint32_t keycode, int pressed);
/* Release only this adapter's held keys, after checking session identity.
 * Shutdown additionally closes the EIS context and resets cached capability,
 * modifier, keymap and epoch state. Neither call targets a replacement login. */
void kvm_eis_release_keys(void);
void kvm_eis_shutdown(void);
#endif
