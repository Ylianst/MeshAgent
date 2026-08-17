/*
Copyright 2024 Intel Corporation

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

#ifndef KVM_MIC_H
#define KVM_MIC_H

#if defined(_KVM_AUDIO)

#include "microstack/ILibParsers.h"

/*
 * Capture of the managed device's microphone, streamed to the operator.
 *
 * The sibling of kvm_audio.h, travelling the same way (device -> browser).
 * kvm_audio captures the machine's audio output, so the operator hears what it
 * plays; this captures the microphone input, so the operator hears the room -
 * the user speaking, and noises worth diagnosing such as fans or drives.
 *
 * Listening to a room is not something a user should discover afterwards, so
 * capture is gated on explicit local consent, which the agent's JavaScript
 * layer obtains through the same prompt used for desktop, terminal and file
 * sessions.
 *
 * The gate is enforced here rather than only in the browser or the server:
 * capture refuses to start until kvm_mic_set_consent(1) is called and stops as
 * soon as consent is withdrawn, so a caller that skips the handshake, or a
 * tampered client, still gets silence. Consent lasts for the session and is
 * dropped on stop and on cleanup.
 */

/*
 * kvm_mic_init - prepare the Opus encoder and advertise capability.
 *   writeHandler / reserved: the KVM relay's write path, used to send
 *   MNG_MIC_CAPS and MNG_MIC_DATA to the browser.
 * Does NOT open the microphone and does NOT grant consent.
 */
void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_mic_set_consent - record the local user's decision for this session.
 *   granted: non-zero to allow capture, zero to revoke it.
 * Revoking stops the capture thread promptly, so a user who withdraws consent
 * is not recorded for the remainder of a buffer.
 */
void kvm_mic_set_consent(int granted);

/*
 * kvm_mic_has_consent - non-zero when capture is currently permitted.
 */
int kvm_mic_has_consent(void);

/*
 * kvm_mic_start - open the microphone and begin streaming to the browser, or
 * (re-)apply encoder settings to an already-open one.
 *   frame / size: the whole MNG_MIC_START wire frame (cmd+len header
 *   included), or NULL/0 to start/continue with whatever settings are
 *   already in effect. A frame shorter than the 13-byte extended form is
 *   treated the same as NULL/0 -- this is what keeps a legacy 4-byte START,
 *   or one from a server that predates configurable encoding, behaving
 *   exactly as before. See mic_apply_params() in the platform .c file for
 *   the payload layout, including the trailing device-index byte (0xFF =
 *   system default input; anything else indexes the most recent
 *   kvm_mic_query_devices() result, out-of-range falling back to default).
 * Refuses to start unless consent has been granted. When refused for that
 * reason specifically (a real microphone exists, consent alone is missing),
 * also emits MNG_MIC_CONSENT_NEEDED so the agent's JavaScript layer can
 * prompt the local user; safe to call speculatively (e.g. once at KVM
 * session start) for exactly this purpose.
 * If capture is already running, any settings in frame are applied to the
 * live encoder in place (no interruption) instead of being ignored. Changing
 * the input device specifically does restart capture (there is no live
 * "switch device" primitive in either platform's audio API), but does not
 * touch consent.
 */
void kvm_mic_start(const unsigned char *frame, int size);

/*
 * kvm_mic_query_devices - enumerate available input devices and send the
 * result as MNG_MIC_DEVICE_LIST: [count(1)][{nameLen(1), name(nameLen)}...],
 * using writeHandler/reserved exactly like kvm_mic_resend_caps(). Names are
 * truncated to a bounded length and the list capped at a bounded count (see
 * the platform .c file) so a device with a pathological name, or a system
 * with an unreasonable number of them, can't produce an oversized frame.
 * The returned order becomes this session's index space for a subsequent
 * MNG_MIC_START's device-index byte, valid only until the next call to this
 * function. Safe to call whether or not capture is currently running;
 * enumeration itself needs no consent, since nothing is captured by it.
 */
void kvm_mic_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_mic_stop - stop capture and revoke this session's consent, so a later
 * start prompts the user again.
 */
void kvm_mic_stop(void);

/*
 * kvm_mic_feed - accepts an inbound MNG_MIC_DATA frame and discards it.
 * Audio only travels device -> browser here; this exists so the KVM command
 * switch can stay symmetrical with the audio path.
 */
void kvm_mic_feed(char *buffer, int bufferLen);

/*
 * kvm_mic_resend_caps - send MNG_MIC_CAPS using the supplied handler, in
 * response to MNG_MIC_QUERY. Reports microphone availability and the current
 * consent state without changing either.
 */
void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_mic_cleanup - stop capture and release the encoder. Call once when the
 * KVM session ends.
 */
void kvm_mic_cleanup(void);

/*
 * kvm_mic_set_slave_fd - register the slave2master write fd so captured audio
 * reaches the parent process. Call in the slave immediately after fork,
 * before the main loop starts. Linux only; Windows and macOS do not fork.
 */
#ifdef __linux__
void kvm_mic_set_slave_fd(int fd);
#endif

#endif /* _KVM_AUDIO */

#endif /* KVM_MIC_H */
