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

#ifndef KVM_AUDIO_H
#define KVM_AUDIO_H

#if defined(_KVM_AUDIO)

#include "microstack/ILibParsers.h"

/*
 * kvm_audio_init - called once at kvm_relay_setup time.
 *   writeHandler : the same function pointer used by the KVM relay to send
 *                  data back to the browser; the audio thread calls it to
 *                  push MNG_AUDIO_DATA / MNG_AUDIO_CAPS frames.
 *   reserved     : opaque user context forwarded to writeHandler.
 *
 * Sends MNG_AUDIO_CAPS to the browser immediately (capability advertisement).
 * Audio capture is NOT started until kvm_audio_start() is called.
 */
void kvm_audio_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_audio_start - spawns the capture thread; called on receipt of
 *                   MNG_AUDIO_START (cmd 92) from the browser.
 */
void kvm_audio_start(void);

/*
 * kvm_audio_set_slave_fd - register the slave2master write fd so the audio
 *   capture thread can push frames through the pipe to the parent.
 *   Call this in the slave process immediately after fork(), before the
 *   main loop starts.  Linux-only (Windows/macOS don't use fork).
 */
#ifdef __linux__
void kvm_audio_set_slave_fd(int fd);
#endif

/*
 * kvm_audio_stop  - signals the capture thread to exit and waits for it;
 *                   called on MNG_AUDIO_STOP (cmd 93) and on audio toggle.
 *                   Does NOT destroy the encoder so audio can be re-enabled.
 */
void kvm_audio_stop(void);

/*
 * kvm_audio_cleanup - stops capture thread AND destroys the encoder; call
 *                     exactly once from kvm_cleanup() to release all resources.
 */
void kvm_audio_cleanup(void);

/*
 * kvm_audio_resend_caps - re-send MNG_AUDIO_CAPS using the provided handler.
 *   Called from the parent process when the browser sends MNG_AUDIO_QUERY (94).
 *   Does NOT create an encoder or touch global state — safe to call from parent.
 */
void kvm_audio_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

#endif /* _KVM_AUDIO */

#endif /* KVM_AUDIO_H */
