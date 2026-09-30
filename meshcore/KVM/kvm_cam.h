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

#ifndef KVM_CAM_H
#define KVM_CAM_H

#if defined(_KVM_CAMERA)

#include "microstack/ILibParsers.h"

/*
 * Capture of the managed device's webcam, streamed to the operator.
 *
 * The visual sibling of kvm_mic.h, travelling the same way (device ->
 * browser) and gated by the same rules. Where the microphone lets an
 * operator hear the room, this lets them see it: whether someone is at the
 * desk, whether a machine's indicator lights are on, whether the thing being
 * described actually looks the way it is being described.
 *
 * Pointing a camera at someone is at least as sensitive as listening to them,
 * so capture is gated on explicit local consent exactly as the microphone is:
 * kvm_cam_start() refuses until kvm_cam_set_consent(1) has been called, and
 * stops the moment consent is withdrawn. The gate lives here, in native code,
 * rather than only in the browser or the server, so a caller that skips the
 * handshake or a tampered client still gets nothing. Consent lasts for the
 * session and is dropped on stop and on cleanup.
 *
 * ---------------------------------------------------------------------------
 * Why there is no video codec here
 * ---------------------------------------------------------------------------
 * This deliberately streams a sequence of complete JPEG frames rather than
 * H.264/VP8/AV1. That is not a shortcut, it is the cheaper answer:
 *
 *   - Essentially every UVC webcam already produces MJPEG in hardware. The
 *     common path therefore forwards the camera's own bytes untouched and
 *     spends *zero* CPU encoding -- which matters enormously on the ARM
 *     boards and thin clients this agent runs on, where a software H.264
 *     encoder would saturate the machine it is supposed to be diagnosing.
 *   - Complete self-contained frames mean no inter-frame state, so a dropped
 *     frame costs exactly one frame rather than corrupting everything until
 *     the next keyframe -- and the browser needs nothing but an <img>-style
 *     decode it already does for desktop tiles.
 *
 * Cameras that cannot produce MJPEG fall back to capturing raw frames and
 * encoding them with libjpeg-turbo, which the KVM build already links for
 * desktop tiles. No new third-party library is introduced by this feature.
 *
 * ---------------------------------------------------------------------------
 * Why the desktop's tile-differencing is NOT reused
 * ---------------------------------------------------------------------------
 * Desktop capture sends only the screen tiles that changed, which works
 * because desktop content is mostly static: most tiles are byte-identical
 * frame to frame. Camera sensors are the opposite -- thermal and shot noise
 * perturb essentially every pixel of every frame, so exact-match tile
 * differencing would find almost nothing to skip and would cost CPU for no
 * saving at all.
 *
 * The equivalent that does work for a camera is whole-frame suppression with
 * a tolerance: decide whether the *scene* changed rather than whether the
 * bytes did, and skip transmitting when it did not. An unattended room then
 * costs near-zero bandwidth while remaining live the instant anything moves.
 * See MNG_CAM_START's staticThreshold below.
 */

/*
 * kvm_cam_init - prepare capture state and advertise capability.
 *   writeHandler / reserved: the KVM relay's write path, used to send
 *   MNG_CAM_CAPS and MNG_CAM_DATA to the browser.
 * Does NOT open the camera and does NOT grant consent.
 */
void kvm_cam_init(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_cam_set_consent - record the local user's decision for this session.
 *   granted: non-zero to allow capture, zero to revoke it.
 * Revoking stops the capture thread promptly, so a user who withdraws consent
 * is not filmed for the remainder of a buffer.
 */
void kvm_cam_set_consent(int granted);

/*
 * kvm_cam_has_consent - non-zero when capture is currently permitted.
 */
int kvm_cam_has_consent(void);

/*
 * kvm_cam_consent_granted - the local user just said yes to a prompt this
 * module raised itself via MNG_CAM_CONSENT_NEEDED (MNG_CAM_CONSENT carries no
 * payload saying which kind of request it was answering). Call this instead
 * of kvm_cam_start(NULL, 0) from the MNG_CAM_CONSENT dispatch case: native
 * remembers whether the outstanding request was a stream start, a snapshot,
 * or both, and replays exactly that -- including the settings the original
 * MNG_CAM_START asked for, which would otherwise be silently discarded in
 * favour of whatever was already in effect.
 */
void kvm_cam_consent_granted(void);

/*
 * kvm_cam_start - open the camera and begin streaming, or re-apply settings
 * to an already-running capture.
 *
 *   frame / size: the whole MNG_CAM_START wire frame (cmd+len header
 *   included), or NULL/0 to start with whatever settings are already in
 *   effect. A frame shorter than the 14-byte extended form is treated the
 *   same as NULL/0, which is what keeps a short START from an older server
 *   working exactly as before.
 *
 * MNG_CAM_START payload layout (byte offsets into the whole frame):
 *   [0..3]  standard KVM header: cmd(2) + len(2)
 *   [4..5]  requested width,  uint16 big-endian (0 = let the camera choose)
 *   [6..7]  requested height, uint16 big-endian (0 = let the camera choose)
 *   [8]     frames per second, 1..60 (0 = default)
 *   [9]     JPEG quality 1..100 (0 = default). Only consulted on the raw
 *           re-encode path; an MJPEG passthrough frame is already encoded by
 *           the camera and is never re-compressed just to honour this.
 *   [10]    flags:
 *              bit0 (0x01) enable static-scene suppression
 *              bit1 (0x02) request that the interactive consent prompt be
 *                          skipped. Only a *request*: native never grants
 *                          consent itself, it merely forwards this to the
 *                          agent's JS layer (see MNG_CAM_CONSENT_NEEDED).
 *              bit2 (0x04) force the raw re-encode path even when the camera
 *                          offers MJPEG (diagnostic / quality override)
 *   [11]    static-scene threshold, 0..255. Mean absolute luma difference,
 *           measured on a cheap 1/8-scale decode, below which a frame counts
 *           as "the scene did not change" and is not sent. 0 disables
 *           suppression as surely as clearing bit0 does.
 *   [12]    device index: 0xFF = system default, otherwise an index into the
 *           most recent kvm_cam_query_devices() result. Out of range falls
 *           back to the default rather than failing.
 *   [13]    reserved, must be 0.
 *
 * Refuses to start unless consent has been granted. When consent is
 * specifically why it refused (a camera exists, permission alone is missing),
 * it also emits MNG_CAM_CONSENT_NEEDED carrying the skip-prompt request from
 * bit1 above as a one-byte payload, so the agent's JS layer can prompt the
 * local user or decide not to.
 *
 * If capture is already running, resolution/fps/device changes restart the
 * capture thread (V4L2 and Media Foundation both require reconfiguring a
 * stopped stream); quality and suppression settings apply in place. Neither
 * case touches consent.
 */
void kvm_cam_start(const unsigned char *frame, int size);

/*
 * kvm_cam_query_devices - enumerate cameras and send the result as
 * MNG_CAM_DEVICE_LIST: [count(1)][{nameLen(1), name(nameLen)}...], using
 * writeHandler/reserved exactly like kvm_cam_resend_caps().
 *
 * Runs the enumeration on its own detached thread and returns immediately.
 * That is not incidental: this is called from the same single-threaded KVM
 * command dispatch loop that also processes MNG_CAM_START, and opening every
 * /dev/video* node (or every Media Foundation source) can block for a
 * noticeable time on a machine with an unresponsive device. Doing it inline
 * would stall the very start-request that triggers the consent prompt --
 * exactly the bug that had to be fixed for the microphone.
 *
 * The returned order becomes this session's index space for a subsequent
 * MNG_CAM_START / MNG_CAM_SNAPSHOT device byte, valid only until the next
 * call. Safe whether or not capture is running; enumeration needs no consent
 * because it opens nothing for capture and reads no frames.
 */
void kvm_cam_query_devices(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_cam_snapshot - capture exactly one still and send it as
 * MNG_CAM_SNAPSHOT_DATA. Independent of streaming: works whether or not a
 * stream is running, and when one is, the running stream is reused rather
 * than fighting it for the device (cameras are single-open on both
 * platforms).
 *
 * MNG_CAM_SNAPSHOT request payload:
 *   [0..3]  cmd(2) + len(2)
 *   [4..5]  requested width,  uint16 BE (0 = the camera's native/full size)
 *   [6..7]  requested height, uint16 BE (0 = native)
 *   [8]     JPEG quality 1..100 (0 = default; stills default higher than the
 *           stream, since one frame's bytes do not have to be repeated 15
 *           times a second)
 *   [9]     device index, 0xFF = default (see kvm_cam_start)
 *   [10]    flags: bit1 (0x02) skip the interactive consent prompt, exactly
 *           as in MNG_CAM_START
 *   [11]    reserved, must be 0.
 *
 * MNG_CAM_SNAPSHOT_DATA response layout:
 *   [0..1]  MNG_CAM_SNAPSHOT_DATA
 *   [2..3]  length, or reserved when JUMBO-wrapped (see below)
 *   [4..5]  width,  uint16 BE
 *   [6..7]  height, uint16 BE
 *   [8..11] capture time, uint32 BE, seconds since the Unix epoch, UTC
 *   [12]    image format: 1 = JPEG (the only value today)
 *   [13]    flags: bit0 (0x01) came straight from the camera as MJPEG with no
 *           re-encoding, so it is pixel-for-pixel what the sensor produced
 *   [14..15] milliseconds spent capturing, uint16 BE (saturates at 65535)
 *   [16..]  the JPEG itself
 *
 * Consent is required exactly as it is for streaming: a still photograph is
 * not a lesser intrusion than a moving one.
 */
void kvm_cam_snapshot(const unsigned char *frame, int size, ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_cam_stop - stop capture and revoke this session's consent, so a later
 * start prompts the user again.
 */
void kvm_cam_stop(void);

/*
 * kvm_cam_feed - accepts an inbound MNG_CAM_DATA frame and discards it.
 * Video only travels device -> browser here; this exists so the KVM command
 * switch can stay symmetrical with the microphone and audio paths.
 */
void kvm_cam_feed(char *buffer, int bufferLen);

/*
 * kvm_cam_resend_caps - send MNG_CAM_CAPS using the supplied handler, in
 * response to MNG_CAM_QUERY. Reports camera availability and the current
 * consent state without changing either.
 *
 * MNG_CAM_CAPS layout (14 bytes):
 *   [0..1]  MNG_CAM_CAPS
 *   [2..3]  14
 *   [4]     flags: bit0 (0x01) a usable camera exists
 *                  bit1 (0x02) consent is currently granted
 *                  bit2 (0x04) the live stream is MJPEG passthrough
 *   [5]     platform: 1 = Linux, 2 = Windows
 *   [6..7]  current (or last requested) width,  uint16 BE
 *   [8..9]  current (or last requested) height, uint16 BE
 *   [10]    current frames per second
 *   [11]    protocol version; 1 = understands the MNG_CAM_START payload above
 *   [12]    current JPEG quality
 *   [13]    number of cameras found by the last enumeration
 */
void kvm_cam_resend_caps(ILibTransport_DoneState(*writeHandler)(char*, int, void*), void *reserved);

/*
 * kvm_cam_cleanup - stop capture and release capture state. Call once when
 * the KVM session ends.
 */
void kvm_cam_cleanup(void);

/*
 * kvm_cam_set_slave_fd - register the slave2master write fd so captured
 * frames reach the parent process. Call in the slave immediately after fork,
 * before the main loop starts. Linux only; Windows does not fork.
 */
#ifdef __linux__
void kvm_cam_set_slave_fd(int fd);
#endif

/*
 * Frames larger than the KVM header's 16-bit length field (which a JPEG at
 * any useful resolution routinely is) are sent wrapped in MNG_JUMBO, exactly
 * as desktop tiles already are:
 *
 *   [0..1] MNG_JUMBO   [2..3] 8   [4..7] uint32 BE inner length
 *   [8..]  the inner frame, starting with its own cmd(2)
 *
 * Nothing new is needed to receive these: the agent's own relay read path
 * already understands MNG_JUMBO generically, and so does the browser's
 * (agent-redir-ws-0.1.1.js unwraps it before dispatch and reassembles
 * WebSocket fragmentation on its own). Note that the inner frame's own
 * length field is not meaningful in the wrapped case -- the browser takes
 * the length from the JUMBO header -- which is why the layouts above mark
 * bytes [2..3] as reserved-when-wrapped.
 */

#endif /* _KVM_CAMERA */

#endif /* KVM_CAM_H */
