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
	// Microphone: the reverse direction, browser -> device. Because this plays
	// an operator's voice into the room, the agent requires explicit local
	// consent and drops MNG_MIC_DATA until it is granted.
	MNG_MIC_QUERY = 95,						// Ask for playback capability + consent state
	MNG_MIC_CAPS = 96,						// Playback capability / consent advertisement
	MNG_MIC_START = 97,						// Request playback; prompts the local user
	MNG_MIC_STOP = 98,						// Stop playback and revoke the session's consent
	MNG_MIC_DATA = 99						// Opus-encoded microphone chunk
}RemoteManagementCommands;


#endif
