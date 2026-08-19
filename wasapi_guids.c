/*
 * wasapi_guids.c — explicit WASAPI GUID definitions for MinGW static cross-builds.
 *
 * MinGW's headers declare these GUIDs as `extern` (no INITGUID).  Using -DINITGUID
 * triggers redefinition conflicts inside <winioctl.h>, so we define the four GUIDs
 * that windows_audio.c actually needs here, by value, in one translation unit.
 */
#include <windows.h>

/* CLSID_MMDeviceEnumerator {BCDE0395-E52F-467C-8E3D-C4579291692E} */
const GUID CLSID_MMDeviceEnumerator = {
    0xBCDE0395, 0xE52F, 0x467C,
    {0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E}
};

/* IID_IMMDeviceEnumerator {A95664D2-9614-4F35-A746-DE8DB63617E6} */
const GUID IID_IMMDeviceEnumerator = {
    0xA95664D2, 0x9614, 0x4F35,
    {0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6}
};

/* IID_IAudioClient {1CB9AD4C-DBFA-4C32-B178-C2F568A703B2} */
const GUID IID_IAudioClient = {
    0x1CB9AD4C, 0xDBFA, 0x4C32,
    {0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2}
};

/* IID_IAudioCaptureClient {C8ADBD64-E71E-48A0-A4DE-185C395CD317} */
const GUID IID_IAudioCaptureClient = {
    0xC8ADBD64, 0xE71E, 0x48A0,
    {0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17}
};
