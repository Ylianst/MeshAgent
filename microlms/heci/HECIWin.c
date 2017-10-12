/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 * 
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 
 *   - Neither the name of Intel Corp. nor the names of its
 *     contributors may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef _MINCORE

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <winioctl.h>
#include "HECIWin.h"
#include "heci_if.h"

#define false 0
#define true 1
#define HECI_MAX_LINE_LEN 300 

DEFINE_GUID(GUID_DEVINTERFACE_HECI, 0xE2D1FF34, 0x3458, 0x49A9, 0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5);
DEFINE_GUID(HECI_PTHI_GUID        , 0x12F80028, 0xB4B7, 0x4b2d, 0xAC, 0xA8, 0x46, 0xE0, 0xFF, 0x65, 0x81, 0x4c);
DEFINE_GUID(LME_GUID              , 0x6733a4db, 0x0476, 0x4e7b, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7);

//VOID _displayHECIError(UINT32 errorCode,DWORD lastError);
//VOID _displayHECIData(UINT32 messageId);
int heci_doIoctl(struct MEImodule* module, DWORD code, void *inbuf, int inlen, void *outbuf, int outlen);

struct MEImodule MEI_global;

/***************************** public functions *****************************/

unsigned int heci_GetBufferSize(struct MEImodule* module) { if (module != NULL) return module->_bufSize; else return MEI_global._bufSize; }
unsigned char heci_GetProtocolVersion(struct MEImodule* module) { if (module != NULL) return module->_protocolVersion; else return MEI_global._protocolVersion; }
bool heci_IsInitialized(struct MEImodule* module) { if (module != NULL) return module->_initialized; else return MEI_global._initialized; }

bool heci_GetHeciVersion(struct MEImodule* module, HECI_VERSION *version)
{
	if (module == NULL) module = &MEI_global;
	
	if (module->m_haveHeciVersion)
	{
		memcpy_s(version, sizeof(HECI_VERSION), &(module->m_heciVersion), sizeof(HECI_VERSION));
		return true;
	}

	return false;
}

bool heci_Init(struct MEImodule* module, int client)
{
    PSP_DEVICE_INTERFACE_DETAIL_DATA deviceDetail = NULL;
    HDEVINFO hDeviceInfo;
    DWORD bufferSize;
	SP_DEVICE_INTERFACE_DATA interfaceData;  
    LONG ii = 0;
	int result;
	HECI_CLIENT properties;
	GUID guid;

	if (client == 0) guid = HECI_PTHI_GUID;
	if (client == 1) guid = LME_GUID;
	if (module == NULL) module = &MEI_global;
	module->_verbose = false;

	if (module->_initialized) {
		heci_Deinit(module);
	}

	// Find all devices that have our interface
	hDeviceInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVINTERFACE_HECI, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDeviceInfo == INVALID_HANDLE_VALUE) {        
		if (module->_verbose) {
            //_displayHECIError(GET_CLASS_DEVS,GetLastError());
		}
        return false; //GET_CLASS_DEVS;
    }

	// Setup the interface data struct
    interfaceData.cbSize = sizeof(interfaceData);
	for (ii = 0; 
         SetupDiEnumDeviceInterfaces(hDeviceInfo, NULL, (LPGUID)&GUID_DEVINTERFACE_HECI, ii, &interfaceData);
         ++ii) {
        // Found our device instance
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, NULL,  0, &bufferSize, NULL)) {
			DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) {
				if (module->_verbose) {
                     //_displayHECIError(GET_INTERFACE_DETAIL,err);
				}
                continue;
            }
        }

        // Allocate a big enough buffer to get detail data
        deviceDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA) malloc(bufferSize);
        if (deviceDetail == NULL) {
			if (module->_verbose) {
                //_displayHECIError(ALLOCATE_MEMORY_ERROR,0);
			}
            continue;
        }

        // Setup the device interface struct
        deviceDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        // Try again to get the device interface detail info
        if (!SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &interfaceData, deviceDetail, bufferSize, NULL, NULL))
		{
			/*
			if (_verbose)
			{
                DWORD err = GetLastError();
                _displayHECIError(GET_INTERFACE_DETAIL,err);
			}
			*/
            free(deviceDetail);
			deviceDetail = NULL;
            continue;
        }

		break;
    }
	SetupDiDestroyDeviceInfoList(hDeviceInfo);

	if (deviceDetail == NULL) {
		if (module->_verbose) {
            //_displayHECIError(FIND_HECI_FAILURE,0);
		}
		return false; //FIND_HECI_FAILURE;
	}

	module->_handle = CreateFile(deviceDetail->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	free(deviceDetail);

	if (module->_handle == INVALID_HANDLE_VALUE) {
		if (module->_verbose) {			
            //_displayHECIError(CREATE_HECI_FILE_FAILURE,GetLastError());
		}
		return false; //CREATE_HECI_FILE_FAILURE;
	}
	module->_initialized = true;

	result = heci_doIoctl(module, (DWORD)IOCTL_HECI_GET_VERSION, NULL, 0, &(module->m_heciVersion), sizeof(HECI_VERSION));
	if (result != sizeof(HECI_VERSION)) {
		if (module->_verbose) {
            //_displayHECIError(GET_HECI_DRIVER_VERSION_FAILURE,0);
		}
		heci_Deinit(module);
		return false; //GET_HECI_DRIVER_VERSION_FAILURE;
	}
	module->m_haveHeciVersion = true;

	if (module->_verbose) {
        //_displayHECIData(HECI_DRIVER_VERSION);
		//_ftprintf(stdout,_T("%d.%d.%d.%d\n"), (m_heciVersion).major, (m_heciVersion).minor, (m_heciVersion).hotfix, (m_heciVersion).build);
	}

	memset(&properties, 0, sizeof(properties));
	result = heci_doIoctl(module, (DWORD)IOCTL_HECI_CONNECT_CLIENT, (void*)(&guid), sizeof(GUID), &properties, sizeof(properties));
	if (result != sizeof(properties))
	{
		if (module->_verbose) {
            //_displayHECIError(HECI_CONNECT_TO_PTHI_CLIENT_FAILURE,0);
		}
		//Deinit();
		return false; //HECI_CONNECT_TO_PTHI_CLIENT_FAILURE;
	}
	module->_bufSize = properties.MaxMessageLength;

	return true;
}

void heci_Deinit(struct MEImodule* module)
{
	if (module == NULL) module = &MEI_global;
	if (module->_initialized == false) return;
	module->_initialized = false;
	module->_bufSize = 0;

	if (module->_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(module->_handle);
		module->_handle = INVALID_HANDLE_VALUE;
	}
}

int heci_ReceiveMessage(struct MEImodule* module, unsigned char *buffer, int len, unsigned long timeout) // Timeout default is 2000
{
	DWORD bytesRead = 0;
	int res;
	HANDLE h_event = NULL;
	OVERLAPPED overlapped;
	DWORD error;
	DWORD eventRes;
	
	if (module == NULL) module = &MEI_global;
	if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
	overlapped.hEvent = h_event;
	overlapped.Offset = 0;
	overlapped.OffsetHigh = 0;

	res = ReadFile(module->_handle, buffer, len, &bytesRead, &overlapped);
	error = GetLastError();
	if ((0 == res) && (ERROR_IO_PENDING != error)) {
		if (module->_verbose) {
			//_displayHECIError(READ_FILE,GetLastError());
		}
		bytesRead = (DWORD)-1;
		goto out;
	}

	eventRes = WaitForSingleObject(h_event, timeout);
	if (eventRes == WAIT_TIMEOUT) {
		bytesRead = 0;
		goto out;
	}
	
	res = GetOverlappedResult(module->_handle, &overlapped, &bytesRead, true);
	
	if (res == 0) {
		if (module->_verbose) {
            //_displayHECIError(READ_FILE,GetLastError());
		}
		bytesRead = (DWORD)-1;
		goto out;
	}

out:
	if (h_event != NULL) CloseHandle(h_event);
	if (bytesRead <= 0) heci_Deinit(module);

	return bytesRead;
}

int heci_SendMessage(struct MEImodule* module, const unsigned char *buffer, int len, unsigned long timeout)  // Timeout default is 2000
{
	DWORD bytesWritten = 0;
	int res;
	HANDLE h_event = NULL;
	OVERLAPPED overlapped;
	DWORD lastError;
	DWORD eventRes;

	if (module == NULL) module = &MEI_global;
	if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
	overlapped.hEvent = h_event;
	overlapped.Offset = 0;
	overlapped.OffsetHigh = 0;
    
	res = WriteFile(module->_handle, buffer, len, &bytesWritten, &overlapped);
	
    lastError = GetLastError();
	if ((0 == res) && (ERROR_IO_PENDING !=lastError )) {
		if (module->_verbose) {
            //_displayHECIError(WRITE_FILE,GetLastError());
		}
		bytesWritten = (DWORD)-1;
		goto out;
	}

	eventRes = WaitForSingleObject(h_event, timeout);
	if (eventRes == WAIT_TIMEOUT) {
		if (module->_verbose) {
            //_displayHECIError(WRITE_FILE_TIME_OUT,0);
		}
		bytesWritten = 0;
		goto out;
	}

	res = GetOverlappedResult(module->_handle, &overlapped, &bytesWritten, false);

	if (res == 0) {
		if (module->_verbose) {
            //_displayHECIError(WRITE_FILE,GetLastError());
		}
		bytesWritten = (DWORD)-1;
		goto out;
	}

out:
	if (h_event != NULL) CloseHandle(h_event);
	if (bytesWritten <= 0) heci_Deinit(module);

	return bytesWritten;
}

int heci_doIoctl(struct MEImodule* module, DWORD code, void *inbuf, int inlen, void *outbuf, int outlen)
{
	int res;
	DWORD bytesRead = 0;
	HANDLE h_event = NULL;
	OVERLAPPED overlapped;

	if (module == NULL) module = &MEI_global;
	if (!module->_initialized) return -1;

	if ((h_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == 0) goto out;
	overlapped.hEvent = h_event;
	overlapped.Offset = 0;
	overlapped.OffsetHigh = 0;

	res = DeviceIoControl(module->_handle, code, inbuf, inlen, outbuf, outlen, &bytesRead, &overlapped);
	
	if ((0 == res) && (ERROR_IO_PENDING != GetLastError())) {
		if (module->_verbose) {
			 //_displayHECIError(IOCTL_COMMAND,GetLastError());
		}
		bytesRead = (DWORD)-1;
		goto out;
	}

	WaitForSingleObject(h_event, INFINITE);

	res = GetOverlappedResult(module->_handle, &overlapped, &bytesRead, true);
	if (res == 0) {
		if (module->_verbose) {
            //_displayHECIError(IOCTL_COMMAND,GetLastError());
		}
		bytesRead = (DWORD)-1;
		goto out;
	}

out:
	if (h_event != NULL) CloseHandle(h_event);
	if (bytesRead == (DWORD)-1) heci_Deinit(module);

	return bytesRead;
}

TCHAR *_getErrMsg(DWORD err)
{
	static TCHAR buffer[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					err,
					0,
					buffer,
					sizeof(buffer) - 1,
					0);

	return buffer;
}

/*
// Display a HECI error message
void _displayHECIError(UINT32 errorCode, DWORD lastError)
{
    TCHAR str[HECI_MAX_LINE_LEN];
    TCHAR *msg; 
    LoadString(GetModuleHandle(NULL), HECI_ERROR_MESSAGE, str, sizeof(str)/sizeof(TCHAR));
    _ftprintf(stderr, _T("%s"), str);
	_ftprintf(stderr, _T("%s"), L" ");
	LoadString(GetModuleHandle(NULL), errorCode , str, sizeof(str)/sizeof(TCHAR));
    if(0!= lastError)
    {
         msg = _getErrMsg(lastError);
	    _ftprintf(stderr, _T("%s (%d): %s\n"),str, lastError, msg);
    }
    else
    {
        _ftprintf(stderr, _T("%s\n"),str);
    }
}

// Display a HECI data message
void _displayHECIData(UINT32 messageId)
{
    TCHAR str[HECI_MAX_LINE_LEN];
    LoadString(GetModuleHandle(NULL), messageId , str, sizeof(str)/sizeof(TCHAR));
    _ftprintf(stdout,_T("%s"),str);
	_ftprintf(stdout,_T("%s"),L" ");
}
*/

#endif
