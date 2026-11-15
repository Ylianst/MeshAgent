/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LINUX_KVM_CINNAMON_H
#define LINUX_KVM_CINNAMON_H
#include <stdint.h>
/* Optional Cinnamon/Muffin adapter, used only by the capture worker after its
 * session UID drop. The implementation owns one session-bound D-Bus connection
 * and a separate virtual keyboard for this worker; calls stay on one thread.
 *
 * Return contract shared with the other native input adapters:
 *   0: unavailable or explicitly declined before injection; fallback is safe.
 *   1: compositor completion barrier acknowledged the operation.
 *  -1: session invalidated or delivery uncertain; discard without fallback.
 * Completion orders compositor work; it is not application text readback.
 */
/* Raw keys use evdev codes, with pressed equal to 0 or 1. */
int kvm_cinnamon_key_action(uint32_t key, int pressed);
/* One printable Unicode scalar, after the caller has assembled UTF-16 units. */
int kvm_cinnamon_type_unicode(uint32_t codepoint);
/* Best-effort release of this worker's keys; closes and resets adapter state. */
void kvm_cinnamon_shutdown(void);
#endif
