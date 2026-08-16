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
 * Playback of the operator's microphone on the managed device.
 *
 * This is the reverse of kvm_audio.h: audio travels browser -> device and is
 * rendered on the device's default output. Because that makes a remote
 * operator audible in the room, playback is gated on explicit local consent,
 * which the agent's JavaScript layer obtains through the same prompt used for
 * desktop, terminal and file sessions.
 *
 * The gate is enforced here rather than only in the browser or the server: the
 * decoder refuses every frame until kvm_mic_set_consent(1) is called, so a
 * caller that skips the handshake, or a tampered client, still cannot produce
 * sound. Consent is per session and is dropped again on stop and cleanup.
 */

/*
 * kvm_mic_init - prepare the Opus decoder and advertise capability.
 *   writeHandler / reserved: the KVM relay's write path, used to send
 *   MNG_MIC_CAPS back to the browser.
 * Does NOT open the audio device and does NOT grant consent.
 */
void kvm_mic_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_mic_set_consent - record the local user's decision for this session.
 *   granted: non-zero to allow playback, zero to revoke it.
 * Revoking also stops playback and flushes any buffered audio, so a user who
 * withdraws consent is not left hearing the tail of the stream.
 */
void kvm_mic_set_consent(int granted);

/*
 * kvm_mic_has_consent - non-zero when playback is currently permitted.
 */
int kvm_mic_has_consent(void);

/*
 * kvm_mic_start - open the output device and begin playback.
 * Refuses unless consent has been granted.
 */
void kvm_mic_start(void);

/*
 * kvm_mic_stop - stop playback, drop buffered audio and revoke consent.
 */
void kvm_mic_stop(void);

/*
 * kvm_mic_feed - decode and play one MNG_MIC_DATA frame.
 *   buffer / bufferLen: the complete KVM packet, header included.
 * Silently discards the frame when consent is absent or playback is not
 * running. Safe to call from the KVM command thread.
 */
void kvm_mic_feed(char *buffer, int bufferLen);

/*
 * kvm_mic_resend_caps - send MNG_MIC_CAPS using the supplied handler, in
 * response to MNG_MIC_QUERY. Reports playback capability and the current
 * consent state without changing either.
 */
void kvm_mic_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_mic_cleanup - stop playback and release the decoder. Call once when the
 * KVM session ends.
 */
void kvm_mic_cleanup(void);

#endif /* _KVM_AUDIO */

#endif /* KVM_MIC_H */
