/*
Copyright 2006 - 2022 Intel Corporation

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

#if !defined(__MeshDefines__)
#define __MeshDefines__

#define MESH_AGENT_PORT 16990					 //!< Default Mesh Agent Port
#define MESH_AGENT_STUN_PORT 16991				 //!< Default Mesh Agent STUN Port
#define MESH_AGENT_VERSION 1					 //!< Used for self-update system.

typedef enum RemoteManagementCommands
{
	MNG_KVM_INPUT_LOCK = 87,
	MNG_KVM_DISPLAY_INFO = 82,
	MNG_KVM_NOP = 0,
	MNG_KVM_KEY = 1,
	MNG_KVM_KEY_UNICODE = 85,
	MNG_KVM_MOUSE = 2,
	MNG_KVM_MOUSE_CURSOR = 88,
	MNG_KVM_MOUSE_MOVE = 89,
	MNG_KVM_PICTURE = 3,
	MNG_KVM_COPY = 4,
	MNG_KVM_COMPRESSION = 5,
	MNG_KVM_REFRESH = 6,
	MNG_KVM_SCREEN = 7,
	MNG_KVM_PAUSE = 8,
	MNG_TERMTEXT = 9,
	MNG_CTRLALTDEL = 10,
	MNG_KVM_GET_DISPLAYS = 11,
	MNG_KVM_SET_DISPLAY = 12,
	MNG_KVM_FRAME_RATE_TIMER = 13,
	MNG_KVM_INIT_TOUCH = 14,
	MNG_KVM_TOUCH = 15,
	MNG_KVM_CONNECTCOUNT = 16,
	MNG_KVM_MESSAGE = 17,
	MNG_KVM_KEYSTATE = 18,
	MNG_ECHO = 21,
	MNG_JUMBO = 27,
	MNG_GETDIR = 50,
	MNG_FILEMOVE = 51,
	MNG_FILEDELETE = 52,
	MNG_FILECOPY = 53,
	MNG_FILECREATEDIR = 54,
	MNG_FILETRANSFER = 55,
	MNG_FILEUPLOAD = 56,
	MNG_FILESEARCH = 57,
	MNG_FILETRANSFER2 = 58,
	MNG_KVM_DISCONNECT = 59,
	MNG_GETDIR2 = 60,						// Same as MNG_GETDIR but with date/time.
	MNG_FILEUPLOAD2 = 61,					// Used for slot based fast upload.
	MNG_FILEDELETEREC = 62,					// Same as MNG_FILEDELETE but recursive
	MNG_USERCONSENT = 63,					// Used to notify management console of user consent state
	MNG_DEBUG = 64,							// Debug/Logging Message for ILibRemoteLogging
	MNG_ERROR = 65,
	MNG_ENCAPSULATE_AGENT_COMMAND = 70,
	MNG_AUDIO_DATA = 90,					// Opus-encoded audio chunk (device -> browser)
	MNG_AUDIO_CAPS = 91,					// Agent capability advertisement
	MNG_AUDIO_START = 92,					// Start audio streaming
	MNG_AUDIO_STOP = 93,					// Stop audio streaming
	MNG_AUDIO_QUERY = 94,					// Pull CAPS re-send
	// Microphone: the device's own mic, streamed to the operator so they can
	// hear the user and any noise worth diagnosing. Same direction as the audio
	// commands above; the difference is the source. The agent refuses to open
	// the microphone until the local user has agreed.
	MNG_MIC_QUERY = 95,						// Ask for mic availability + consent state
	MNG_MIC_CAPS = 96,						// Mic availability / consent advertisement
	MNG_MIC_START = 97,						// Request capture; prompts the local user
	MNG_MIC_STOP = 98,						// Stop capture and revoke the session's consent
	MNG_MIC_DATA = 99,						// Opus-encoded microphone chunk
	// Sent only by the agent's own consent flow once the local user accepts.
	// Kept separate from MNG_MIC_START so that a browser frame can request
	// capture but can never grant permission for it.
	MNG_MIC_CONSENT = 100,
	// Native -> agent JS only; never sent to the browser. Emitted by
	// kvm_mic_start() when it refuses to open the microphone specifically
	// because local consent is missing (device has a microphone, the
	// operator asked, but nobody has said yes yet), so the JS layer can show
	// the consent prompt. agentcore.c intercepts this on the way up and
	// drops it rather than forwarding it, so it never reaches the tunnel.
	MNG_MIC_CONSENT_NEEDED = 101,
	// Native -> agent JS only; never sent to the browser. The counterpart of
	// MNG_MIC_CONSENT_NEEDED: emitted by kvm_mic_stop() when capture is
	// stopped while consent was still outstanding, so the JS layer can take
	// down a prompt nobody is waiting on any more (the operator changed
	// their mind, or clicked by mistake). Leaving it up would ask the local
	// user to decide about a request that no longer exists.
	MNG_MIC_CONSENT_CANCEL = 102,
	// Input device enumeration, so the operator can pick something other
	// than the system's default microphone. QUERY carries no payload;
	// LIST's ordering is only valid for that one round-trip (see
	// kvm_mic_query_devices() for the wire format) -- a later MNG_MIC_START
	// referencing a device by index must use the most recently sent list.
	MNG_MIC_DEVICE_QUERY = 103,
	MNG_MIC_DEVICE_LIST = 104,
	// Camera: the device's own webcam, streamed to the operator as a sequence
	// of complete JPEG frames. Deliberately not a video codec -- UVC webcams
	// already emit MJPEG in hardware, so the common path forwards the camera's
	// own bytes untouched and spends no CPU encoding at all (see kvm_cam.h).
	// Mirrors the microphone commands above in both shape and consent rules;
	// pointing a camera at someone is at least as sensitive as listening.
	MNG_CAM_QUERY = 105,					// Ask for camera availability + consent state
	MNG_CAM_CAPS = 106,						// Camera availability / consent advertisement
	MNG_CAM_START = 107,					// Request capture; prompts the local user
	MNG_CAM_STOP = 108,						// Stop capture and revoke the session's consent
	MNG_CAM_DATA = 109,						// One complete JPEG frame (device -> browser)
	// Sent only by the agent's own consent flow once the local user accepts.
	// Kept separate from MNG_CAM_START for the same reason MNG_MIC_CONSENT is:
	// a browser frame may request capture but can never grant permission.
	MNG_CAM_CONSENT = 110,
	// Native -> agent JS only; never sent to the browser. Exact counterparts of
	// MNG_MIC_CONSENT_NEEDED / MNG_MIC_CONSENT_CANCEL, intercepted and dropped
	// by agentcore.c on the way up so they never reach the tunnel.
	MNG_CAM_CONSENT_NEEDED = 111,
	MNG_CAM_CONSENT_CANCEL = 112,
	// Camera enumeration, so the operator can pick something other than the
	// system default. Same index-space rule as the microphone's: a LIST's
	// ordering is only valid until the next LIST.
	MNG_CAM_DEVICE_QUERY = 113,
	MNG_CAM_DEVICE_LIST = 114,
	// Single still capture, independent of whether streaming is running.
	// SNAPSHOT_DATA carries a small metadata header ahead of the JPEG so the
	// browser can label what it is showing (see kvm_cam.h for the layout).
	MNG_CAM_SNAPSHOT = 115,
	MNG_CAM_SNAPSHOT_DATA = 116
}RemoteManagementCommands;


#endif
