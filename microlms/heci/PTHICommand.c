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

//----------------------------------------------------------------------------
//
//  File:       PTHICommand.cpp
//
//----------------------------------------------------------------------------

#include "PTHICommand.h"
#include "../../microstack/ILibParsers.h"

#include <stdlib.h>
#if !defined(__APPLE__) && !defined(WIN32) && !defined(_VX_CPU)
#include <malloc.h>
#endif
#include <string.h>

AMT_STATUS _call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 rcmd, unsigned int expSize); // expSize default is 0
AMT_STATUS _verifyResponseHeader(const UINT32 command, const PTHI_MESSAGE_HEADER *response_header, UINT32 response_size);
AMT_STATUS _verifyCodeVersions(const CFG_GET_CODE_VERSIONS_RESPONSE *response);
AMT_STATUS _verifyCurrentPowerPolicy(const CFG_GET_CURRENT_POWER_POLICY_RESPONSE *response);
AMT_STATUS _verifyGetDNSSuffixList(const CFG_GET_DNS_SUFFIX_LIST_RESPONSE *response);
AMT_STATUS _verifyRemoteAccessConnectionStatus(const CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *response);
AMT_STATUS _verifyHashHandles(const CFG_GET_HASH_HANDLES_RESPONSE *response);
AMT_STATUS _verifyGetCertificateHashEntry(const CFG_GET_CERTHASH_ENTRY_RESPONSE *response);
AMT_STATUS _verifyGetDnsSuffix(const CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *response);

unsigned long m_sendTimeout = 2000;


const AMT_UUID AMT_UUID_LINK_STATE =
	{0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x01};



const PTHI_MESSAGE_HEADER GET_CODE_VERSION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{CODE_VERSIONS_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_PROVISIONING_MODE_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{PROVISIONING_MODE_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_PROVISIONING_STATE_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{PROVISIONING_STATE_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_MAC_ADDRESSES_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_MAC_ADDRESSES_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_FEATURES_STATE_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_FEATURES_STATE_REQUEST}}, (sizeof(CFG_GET_FEATURES_STATE_REQUEST) - sizeof(PTHI_MESSAGE_HEADER))
};

const PTHI_MESSAGE_HEADER GET_CURRENT_POWER_POLICY_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_CURRENT_POWER_POLICY_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_LAST_HOST_RESET_REASON_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_LAST_HOST_RESET_REASON_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_LAN_INTERFACE_SETTINGS_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_LAN_INTERFACE_SETTINGS_REQUEST}}, (sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_REQUEST) - sizeof(PTHI_MESSAGE_HEADER))
};

const PTHI_MESSAGE_HEADER GET_SECURITY_PARAMETERS_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_SECURITY_PARAMETERS_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_DNS_SUFFIX_LIST_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_DNS_SUFFIX_LIST_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER SET_ENTERPRISE_ACCESS_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{SET_ENTERPRISE_ACCESS_REQUEST}}, (sizeof(CFG_SET_ENTERPRISE_ACCESS_REQUEST) - sizeof(PTHI_MESSAGE_HEADER))
};

const PTHI_MESSAGE_HEADER OPEN_USER_INITIATED_CONNECTION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{OPEN_USER_INITIATED_CONNECTION_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER CLOSE_USER_INITIATED_CONNECTION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{CLOSE_USER_INITIATED_CONNECTION_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_REMOTE_ACCESS_CONNECTION_STATUS_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_AMT_STATE_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_AMT_STATE_REQUEST}}, sizeof(AMT_UUID)
};

const PTHI_MESSAGE_HEADER GENERATE_RNG_SEED_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GENERATE_RNG_SEED_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_RNG_SEED_STATUS_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_RNG_SEED_STATUS_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_ZERO_TOUCH_ENABLED_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_ZERO_TOUCH_ENABLED_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_PROVISIONING_TLS_MODE_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_PROVISIONING_TLS_MODE_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER START_CONFIGURATION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{START_CONFIGURATION_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER STOP_CONFIGURATION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{STOP_CONFIGURATION_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER ENUMERATE_HASH_HANDLES_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{ENUMERATE_HASH_HANDLES_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_CERTHASH_ENTRY_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_CERTHASH_ENTRY_REQUEST}}, sizeof(UINT32)
};

const PTHI_MESSAGE_HEADER GET_PKI_FQDN_SUFFIX_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MAJOR_VERSION}, 0, {{GET_PKI_FQDN_SUFFIX_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER SET_HOST_FQDN_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MAJOR_VERSION}, 0, {{SET_HOST_FQDN_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_LOCAL_SYSTEM_ACCOUNT_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_LOCAL_SYSTEM_ACCOUNT_REQUEST}}, 40
};

const PTHI_MESSAGE_HEADER UNPROVISION_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{UNPROVISION_REQUEST}}, 4
};

const PTHI_MESSAGE_HEADER GET_EHBC_STATE_REQUEST_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_EHBC_STATE_REQUEST}}, 0
};

const PTHI_MESSAGE_HEADER GET_CONTROL_MODE_REQUEST_HEADER = {
	{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{GET_CONTROL_MODE_REQUEST}}, 0
};

AMT_STATUS _call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 rcmd, unsigned int expSize)
{
	UINT32 inBuffSize;
	UINT32 outBuffSize = 0;
	int bytesWritten;
	AMT_STATUS status;

	inBuffSize = heci_GetBufferSize(NULL);
	*readBuffer = (UINT8 *)malloc(sizeof(UINT8) * inBuffSize);
	if (NULL == *readBuffer)
	{
		return PTSDK_STATUS_RESOURCES;
	}
	memset(*readBuffer, 0, inBuffSize);

	bytesWritten = heci_SendMessage(NULL, command, command_size, m_sendTimeout);
	if ((UINT32)bytesWritten != command_size)
	{
		return AMT_STATUS_INTERNAL_ERROR;
	}
	outBuffSize = heci_ReceiveMessage(NULL, *readBuffer, inBuffSize, 2000);
	if (0 == outBuffSize)
	{
		return 0xFFFF; //PTHI_STATUS_EMPTY_RESPONSE;
	}
	status = ((PTHI_RESPONSE_MESSAGE_HEADER *)*readBuffer)->Status;
	if (status != AMT_STATUS_SUCCESS)
	{
		return status;
	}
	status = _verifyResponseHeader(rcmd, &(((PTHI_RESPONSE_MESSAGE_HEADER *)*readBuffer)->Header), outBuffSize);
	if (status != AMT_STATUS_SUCCESS)
	{
		return status;
	}
	if ((expSize != 0) && (expSize != outBuffSize))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Confirms the correctness of the response message header
* and the response message size
* Arguments:
*	command	- appropriate Host interface command
*	response_header	- reference to the response message header
*	response_size	- value that holds the actual size of the
*                         response message
*	expected_size	- value that holds the expected size of the
*                         response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyResponseHeader(
	const UINT32 command, const PTHI_MESSAGE_HEADER *response_header,
	UINT32 response_size)
{
	AMT_STATUS status = AMT_STATUS_SUCCESS;

	if (response_size < sizeof(PTHI_RESPONSE_MESSAGE_HEADER)) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_size != (response_header->Length + sizeof(PTHI_MESSAGE_HEADER))) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header->Command.cmd.val != command) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header->Reserved != 0) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header->Version.MajorNumber != AMT_MAJOR_VERSION
		|| response_header->Version.MinorNumber < AMT_MINOR_VERSION) {
			status = AMT_STATUS_INTERNAL_ERROR;
	}

	return status;
}

/*
* Confirms the correctness of the GetCodeVersions response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyCodeVersions(const CFG_GET_CODE_VERSIONS_RESPONSE *response)
{
	AMT_STATUS status = AMT_STATUS_SUCCESS;
	UINT32 codeVerLen;
	UINT32 ptVerTypeCount;
	UINT32 len = 0;
	UINT32 i;

	do {
		codeVerLen = response->Header.Header.Length - sizeof(AMT_STATUS);
		ptVerTypeCount = codeVerLen - sizeof(response->CodeVersions.BiosVersion)- sizeof(response->CodeVersions.VersionsCount);
		if (response->CodeVersions.VersionsCount != (ptVerTypeCount/sizeof(AMT_VERSION_TYPE)))
		{
			status = AMT_STATUS_INTERNAL_ERROR;
			break;
		}

		for (i = 0; i < (response->CodeVersions.VersionsCount); i ++)
		{
			len = response->CodeVersions.Versions[i].Description.Length;

			if (len > UNICODE_STRING_LEN)
			{
				status = AMT_STATUS_INTERNAL_ERROR;
				break;
			}

			len = response->CodeVersions.Versions[i].Version.Length;
			if (response->CodeVersions.Versions[i].Version.String[len] != '\0' ||
				(len != strnlen_s((CHAR *)(response->CodeVersions.Versions[i].Version.String), 65535)))
			{
				status = AMT_STATUS_INTERNAL_ERROR;
				break;
			}
		}
	} while (0);

	return status;
}

/*
* GetVersions response message PTHI command
* Arguments:
*	response - reference to the CODE_VERSIONS struct
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	AMT_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS pthi_GetCodeVersions(CODE_VERSIONS *codeVersions)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_CODE_VERSION_HEADER);
	unsigned char command[sizeof(GET_CODE_VERSION_HEADER)];
	AMT_STATUS status;
	CFG_GET_CODE_VERSIONS_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_CODE_VERSION_HEADER), (void*)&(GET_CODE_VERSION_HEADER), sizeof(GET_CODE_VERSION_HEADER));

	status = _call(command, command_size, (void*)&readBuffer, CODE_VERSIONS_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		tmp_response = (CFG_GET_CODE_VERSIONS_RESPONSE *)readBuffer;
		status = _verifyCodeVersions(tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		memcpy_s(codeVersions, sizeof(CODE_VERSIONS), (void*)&(tmp_response->CodeVersions), sizeof(CODE_VERSIONS));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetProvisioningMode Host interface command
* Arguments:
*	mode - reference to the pre-allocated structure
*       which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetProvisioningMode(CFG_PROVISIONING_MODE *mode, AMT_BOOLEAN *legacy)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_PROVISIONING_MODE_HEADER);
	unsigned char command[sizeof(GET_PROVISIONING_MODE_HEADER)];
	AMT_STATUS status;
	CFG_GET_PROVISIONING_MODE_RESPONSE* tmp_response;

	memcpy_s(command, sizeof(GET_PROVISIONING_MODE_HEADER), (void*)&(GET_PROVISIONING_MODE_HEADER), sizeof(GET_PROVISIONING_MODE_HEADER));

	status = _call(command, command_size, &readBuffer, PROVISIONING_MODE_RESPONSE, sizeof(CFG_GET_PROVISIONING_MODE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		tmp_response = (CFG_GET_PROVISIONING_MODE_RESPONSE *)readBuffer;

		*mode = tmp_response->ProvisioningMode;
		*legacy = tmp_response->LegacyMode;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}


/*
* Calls to GetProvisioningState Host interface command
* Arguments:
*	state - reference to the pre-allocated structure
*       which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetProvisioningState(AMT_PROVISIONING_STATE *state)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_PROVISIONING_STATE_HEADER);
	unsigned char command[sizeof(GET_PROVISIONING_STATE_HEADER)];
	AMT_STATUS status;
	CFG_GET_PROVISIONING_STATE_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_PROVISIONING_STATE_HEADER), (void*)&(GET_PROVISIONING_STATE_HEADER), sizeof(GET_PROVISIONING_STATE_HEADER));

	status = _call(command, command_size, &readBuffer, PROVISIONING_STATE_RESPONSE, sizeof(CFG_GET_PROVISIONING_STATE_RESPONSE));
	if (status == AMT_STATUS_SUCCESS)
	{
		tmp_response = (CFG_GET_PROVISIONING_STATE_RESPONSE *)readBuffer;
		*state = tmp_response->ProvisioningState;
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to GetProvisioningState Host interface command
* Arguments:
*	state - reference to the pre-allocated structure
*       which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetMacAddresses(UINT8 DedicatedMac[6], UINT8 HostMac[6])
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_MAC_ADDRESSES_HEADER);
	unsigned char command[sizeof(GET_MAC_ADDRESSES_HEADER)];
	AMT_STATUS status;
	CFG_GET_MAC_ADDRESSES_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_MAC_ADDRESSES_HEADER), (void*)&(GET_MAC_ADDRESSES_HEADER), sizeof(GET_MAC_ADDRESSES_HEADER));

	status = _call(command, command_size, &readBuffer, GET_MAC_ADDRESSES_RESPONSE, sizeof(CFG_GET_MAC_ADDRESSES_RESPONSE));
	if (status == AMT_STATUS_SUCCESS)
	{
		tmp_response = (CFG_GET_MAC_ADDRESSES_RESPONSE *)readBuffer;
		memcpy_s(DedicatedMac, 6, tmp_response->DedicatedMac, 6);
		memcpy_s(HostMac, 6, tmp_response->HostMac, 6);
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to GetFeatureState Host interface command
* Arguments:
*	requestID Indicates what feature status to query:
*		0	Redirection Sessions Status
*		1	System Defense Status
*		2	WebUI Status
*  requestStatus The requested feature state(the size depand on the requestID).(OUT)
*
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetFeaturesState(UINT32 requestID, AMT_BOOLEAN (*requestStatus)[2])
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GET_FEATURES_STATE_REQUEST);
	unsigned char command[sizeof(CFG_GET_FEATURES_STATE_REQUEST)];
	AMT_STATUS status;
	CFG_GET_FEATURES_STATE_RESPONSE *tmp_response;
	GET_FEATURES_REDIRECTION_SESSION_STATUS redirectionState;
	GET_FEATURES_SYSTEM_DEFENSE_STATUS_RESPONSE systemDefenseState;
	GET_FEATURES_WEB_UI_STATUS_RESPONSE webUIState;

	memcpy_s(command, sizeof(GET_FEATURES_STATE_HEADER), (void*)&GET_FEATURES_STATE_HEADER, sizeof(GET_FEATURES_STATE_HEADER));
	memcpy_s(command + sizeof(GET_FEATURES_STATE_HEADER), sizeof(UINT32), (void*)&(requestID), sizeof(UINT32));

	status = _call(command, command_size, &readBuffer, GET_FEATURES_STATE_RESPONSE, sizeof(CFG_GET_FEATURES_STATE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		tmp_response = (CFG_GET_FEATURES_STATE_RESPONSE *)readBuffer;

		switch (requestID)
		{
		case REDIRECTION_SESSION:
			redirectionState = tmp_response->Data.rs;
			(*requestStatus)[0] = redirectionState.SolOpen;
			(*requestStatus)[1] = redirectionState.IderOpen;
			break;

		case SYSTEM_DEFENSE:
			systemDefenseState = tmp_response->Data.sd;
			(*requestStatus)[0] = systemDefenseState.SystemDefenseActivated;
			break;

		case WEB_UI:
			webUIState = tmp_response->Data.webUI;
			(*requestStatus)[0] = webUIState.WebUiEnabled;
			break;
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetLastHostResetReason Host interface command
* Arguments:
*	reason Indicates whether the last host reason was because of remote control operation(0)
*		or other reason(1). (OUT)
*  remoteControlTimeStamp In case the reason was due to remote control then this field
*		indicates the timestamp of when the remote control command has been executed.
*		(The timestamp is the number of seconds since 1/1/1970)
*
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetLastHostResetReason(UINT32 *reason, UINT32 *remoteControlTimeStamp)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_LAST_HOST_RESET_REASON_HEADER);
	unsigned char command[sizeof(GET_LAST_HOST_RESET_REASON_HEADER)];
	AMT_STATUS status;
	CFG_GET_LAST_HOST_RESET_REASON_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_LAST_HOST_RESET_REASON_HEADER), (void*)&(GET_LAST_HOST_RESET_REASON_HEADER), sizeof(GET_LAST_HOST_RESET_REASON_HEADER));

	status = _call(command, command_size, &readBuffer, GET_LAST_HOST_RESET_REASON_RESPONSE, sizeof(CFG_GET_LAST_HOST_RESET_REASON_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		tmp_response = (CFG_GET_LAST_HOST_RESET_REASON_RESPONSE *)readBuffer;

		*reason = tmp_response->Reason;
		*remoteControlTimeStamp = tmp_response->RemoteControlTimeStamp;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetCurrentPowerPolicy Host interface command
* Arguments:
*	 policyName The power policy name. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetCurrentPowerPolicy(AMT_ANSI_STRING *policyName)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_CURRENT_POWER_POLICY_HEADER);
	unsigned char command[sizeof(GET_CURRENT_POWER_POLICY_HEADER)];
	AMT_STATUS status;
	CFG_GET_CURRENT_POWER_POLICY_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_CURRENT_POWER_POLICY_HEADER), (void*)&(GET_CURRENT_POWER_POLICY_HEADER), sizeof(GET_CURRENT_POWER_POLICY_HEADER));

	status = _call(command, command_size, &readBuffer, GET_CURRENT_POWER_POLICY_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_CURRENT_POWER_POLICY_RESPONSE *)readBuffer;
		status = _verifyCurrentPowerPolicy(tmp_response);
		if (status != AMT_STATUS_SUCCESS) break;

		policyName->Length = tmp_response->PolicyName.Length;
		policyName->Buffer = (CHAR *)malloc(policyName->Length * sizeof(CHAR));
		if (NULL == policyName->Buffer) {
			status = AMT_STATUS_INTERNAL_ERROR;
		} else {
			memcpy_s(policyName->Buffer, policyName->Length * sizeof(CHAR), (void*)&(tmp_response->PolicyName.Buffer), policyName->Length * sizeof(CHAR));
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Confirms the correctness of the GetCurrentPowerPolicy response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyCurrentPowerPolicy(const CFG_GET_CURRENT_POWER_POLICY_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_CURRENT_POWER_POLICY_RESPONSE)
	                  - sizeof(PTHI_MESSAGE_HEADER) - sizeof(CHAR *)
	                  + response->PolicyName.Length))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GetLanInterfaceSttings Host interface command
* Arguments:
*	 interfaceSettings The interface to get the settings for.
*	 lanSettings reference to a pre allocated struct which will hold the lan settings. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetLanInterfaceSettings(UINT32 interfaceSettings, LAN_SETTINGS *lanSettings)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_REQUEST);
	unsigned char command[sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_REQUEST)];
	AMT_STATUS status;
	CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_LAN_INTERFACE_SETTINGS_HEADER), (void*)&(GET_LAN_INTERFACE_SETTINGS_HEADER), sizeof(GET_LAN_INTERFACE_SETTINGS_HEADER));
	memcpy_s(command + sizeof(GET_LAN_INTERFACE_SETTINGS_HEADER), sizeof(UINT32), (void*)&(interfaceSettings), sizeof(UINT32));
	
	status = _call(command, command_size, &readBuffer, GET_LAN_INTERFACE_SETTINGS_RESPONSE, sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE *)readBuffer;

		lanSettings->Enabled = tmp_response->Enabled;
		lanSettings->Ipv4Address = tmp_response->Ipv4Address;
		lanSettings->DhcpEnabled = tmp_response->DhcpEnabled;
		lanSettings->DhcpIpMode = tmp_response->DhcpIpMode;
		lanSettings->LinkStatus = tmp_response->LinkStatus;
		memcpy_s(lanSettings->MacAddress, sizeof(tmp_response->MacAddress), tmp_response->MacAddress, sizeof(tmp_response->MacAddress));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/**
* Gets the HECI driver version
* Arguments:
*	heciVersion - pointewr to HECI_VERSION struct (out)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INVALID_PARAM - on failure
*/
AMT_STATUS pthi_GetHeciVersion(HECI_VERSION *heciVersion)
{
	if (heci_GetHeciVersion(NULL, heciVersion)) return AMT_STATUS_SUCCESS;
	return AMT_STATUS_INTERNAL_ERROR;
}

/*
* Calls to GetSecurityParameters Host interface command
* Arguments:
*	tlsEnabled true if AMT on TLS mode. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetTLSEnabled(AMT_BOOLEAN *tlsEnabled)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_SECURITY_PARAMETERS_HEADER);
	unsigned char command[sizeof(GET_SECURITY_PARAMETERS_HEADER)];
	AMT_STATUS status;
	CFG_GET_SECURITY_PARAMETERS_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_SECURITY_PARAMETERS_HEADER), (void*)&(GET_SECURITY_PARAMETERS_HEADER), sizeof(GET_SECURITY_PARAMETERS_HEADER));

	status = _call(command, command_size, &readBuffer, GET_SECURITY_PARAMETERS_RESPONSE, sizeof(CFG_GET_SECURITY_PARAMETERS_RESPONSE));
	if (status == AMT_STATUS_SUCCESS)
	{
		tmp_response = (CFG_GET_SECURITY_PARAMETERS_RESPONSE *)readBuffer;
		*tlsEnabled = tmp_response->TLSEnabled;
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to GetDNSSuffixList Host interface command
* Arguments:
*	 dnsSuffixList reference to list of DNS suffix strings. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
/*
AMT_STATUS pthi_GetDNSSuffixList(std::list<std::string> &dnsSuffixList)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_DNS_SUFFIX_LIST_HEADER);
	unsigned char command[command_size];
	memcpy_s(command, sizeof(GET_DNS_SUFFIX_LIST_HEADER), &(GET_DNS_SUFFIX_LIST_HEADER), sizeof(GET_DNS_SUFFIX_LIST_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_DNS_SUFFIX_LIST_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_DNS_SUFFIX_LIST_RESPONSE *tmp_response = (CFG_GET_DNS_SUFFIX_LIST_RESPONSE *)readBuffer;
		status = _verifyGetDNSSuffixList(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		char *current = (char *)tmp_response->Data;
		while (current < (char *)tmp_response->Data + tmp_response->DataLength)
		{
			std::string dnsSuffix = current;
			if (dnsSuffix.length() > tmp_response->DataLength)
			{
				status = PTSDK_STATUS_INTERNAL_ERROR;
				break;
			}
			if (!dnsSuffix.empty())
			{
				dnsSuffixList.push_back(dnsSuffix);
			}
			current += dnsSuffix.length() + 1;
		}
	} while (0);

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}
*/

/*
* Confirms the correctness of the GetDNSSuffixList response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyGetDNSSuffixList(const CFG_GET_DNS_SUFFIX_LIST_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_DNS_SUFFIX_LIST_RESPONSE) - sizeof(PTHI_MESSAGE_HEADER) + response->DataLength)) return PTSDK_STATUS_INTERNAL_ERROR;
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to SetEnterpriseAccess Host interface command
* Arguments:
*	Flags flags
*	HostIPAddress host IP address for enterprise access
*	EnterpriseAccess enterprise access mode
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_SetEnterpriseAccess(UINT8 Flags, UINT8 HostIPAddress[16], UINT8 EnterpriseAccess)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_SET_ENTERPRISE_ACCESS_REQUEST);
	unsigned char command[sizeof(CFG_SET_ENTERPRISE_ACCESS_REQUEST)];
	AMT_STATUS status;

	memcpy_s(command, sizeof(SET_ENTERPRISE_ACCESS_HEADER), (void*)&(SET_ENTERPRISE_ACCESS_HEADER), sizeof(SET_ENTERPRISE_ACCESS_HEADER));
	memcpy_s(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER), sizeof(UINT8), (void*)&(Flags), sizeof(UINT8));
	memcpy_s(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER) + sizeof(UINT8), (int)sizeof(UINT8[16]/*HostIPAddress*/), HostIPAddress, (int)sizeof(UINT8[16]/*HostIPAddress*/));
	memcpy_s(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER) + sizeof(UINT8) + sizeof(UINT8[16]/*HostIPAddress*/), (int)sizeof(UINT8), (void*)&(EnterpriseAccess), (int)sizeof(UINT8));

	status = _call(command, command_size, &readBuffer, SET_ENTERPRISE_ACCESS_RESPONSE, sizeof(CFG_SET_ENTERPRISE_ACCESS_RESPONSE));

	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Get FW last reset reason
* Arguments:
*	reason - last FW reason
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetFWResetReason(UINT8 *MEResetReason)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(STATE_GET_AMT_STATE_REQUEST);
	unsigned char command[sizeof(STATE_GET_AMT_STATE_REQUEST)];
	AMT_STATUS status;
	STATE_GET_AMT_STATE_RESPONSE *tmp_response = NULL;

	memcpy_s(command, sizeof(GET_AMT_STATE_HEADER), (void*)&(GET_AMT_STATE_HEADER), sizeof(GET_AMT_STATE_HEADER));
	memcpy_s(command + sizeof(GET_AMT_STATE_HEADER), sizeof(AMT_UUID), (void*)&(AMT_UUID_LINK_STATE), sizeof(AMT_UUID));

	status = _call(command, command_size, &readBuffer, GET_AMT_STATE_RESPONSE, sizeof(STATE_GET_AMT_STATE_RESPONSE));
	if (status != AMT_STATUS_SUCCESS)
	{
		if (readBuffer == NULL) return AMT_STATUS_INTERNAL_ERROR;
		tmp_response = (STATE_GET_AMT_STATE_RESPONSE *)readBuffer;
		*MEResetReason = tmp_response->StateData.LastMEResetReason;
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/* Calls to OpenUserInitiatedConnection Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_OpenUserInitiatedConnection()
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER);
	unsigned char command[sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER)];
	AMT_STATUS status;

	memcpy_s(command, sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER), (void*)&(OPEN_USER_INITIATED_CONNECTION_HEADER), sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER));
	status = _call(command, command_size, &readBuffer, OPEN_USER_INITIATED_CONNECTION_RESPONSE, sizeof(CFG_OPEN_USER_INITIATED_CONNECTION_RESPONSE));

	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/* Calls to CloseUserInitiatedConnection Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_CloseUserInitiatedConnection()
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER);
	unsigned char command[sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER)];
	AMT_STATUS status;
	
	memcpy_s(command, sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER), (void*)&(CLOSE_USER_INITIATED_CONNECTION_HEADER), sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER));
	status = _call(command, command_size, &readBuffer, CLOSE_USER_INITIATED_CONNECTION_RESPONSE, sizeof(CFG_CLOSE_USER_INITIATED_CONNECTION_RESPONSE));

	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/* Calls to GetRemoteAccessConnectionStatus Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetRemoteAccessConnectionStatus(REMOTE_ACCESS_STATUS *remoteAccessStatus)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER);
	unsigned char command[sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER)];
	CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *tmp_response;
	AMT_STATUS status;

	memcpy_s(command, sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER), (void*)&(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER), sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER));

	status = _call(command, command_size, &readBuffer, GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *)readBuffer;
		status = _verifyRemoteAccessConnectionStatus(tmp_response);
		if (status != AMT_STATUS_SUCCESS) break;

		remoteAccessStatus->AmtNetworkConnectionStatus    = tmp_response->AmtNetworkConnectionStatus;
		remoteAccessStatus->RemoteAccessConnectionStatus  = tmp_response->RemoteAccessConnectionStatus;
		remoteAccessStatus->RemoteAccessConnectionTrigger = tmp_response->RemoteAccessConnectionTrigger;

		remoteAccessStatus->MpsHostname.Length = tmp_response->MpsHostname.Length;
		remoteAccessStatus->MpsHostname.Buffer = (CHAR *)malloc(remoteAccessStatus->MpsHostname.Length * sizeof(CHAR));
		if (NULL == remoteAccessStatus->MpsHostname.Buffer) {
			status = AMT_STATUS_INTERNAL_ERROR;
		} else {
			memcpy_s(remoteAccessStatus->MpsHostname.Buffer, tmp_response->MpsHostname.Length * sizeof(CHAR),
			       (void*)&(tmp_response->MpsHostname.Buffer),
			       tmp_response->MpsHostname.Length * sizeof(CHAR));
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}


/*
* Confirms the correctness of the GetRemoteAccessConnectionStatus response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyRemoteAccessConnectionStatus(const CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE) - sizeof(PTHI_MESSAGE_HEADER) - sizeof(CHAR *) + response->MpsHostname.Length)) return PTSDK_STATUS_INTERNAL_ERROR;
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GenerateRngKey Host interface command
* Arguments:
*	None
* Return values:
*	AMT_STATUS_SUCCESS - or AMT_STATUS_IN_PROGRESS on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GenerateRngKey()
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GENERATE_RNG_SEED_HEADER);
	unsigned char command[sizeof(GENERATE_RNG_SEED_HEADER)];
	AMT_STATUS status;
	
	memcpy_s(command, sizeof(GENERATE_RNG_SEED_HEADER), (void*)&(GENERATE_RNG_SEED_HEADER), sizeof(GENERATE_RNG_SEED_HEADER));

	status = _call(command, command_size, &readBuffer, GENERATE_RNG_SEED_RESPONSE, sizeof(CFG_GENERATE_RNG_SEED_RESPONSE));
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to GetRngSeedStatus Host interface command
* Arguments:
*	rngStatus - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetRngSeedStatus(AMT_RNG_STATUS *rngStatus)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_RNG_SEED_STATUS_HEADER);
	unsigned char command[sizeof(GET_RNG_SEED_STATUS_HEADER)];
	CFG_GET_RNG_SEED_STATUS_RESPONSE *tmp_response;
	AMT_STATUS status;

	memcpy_s(command, sizeof(GET_RNG_SEED_STATUS_HEADER), (void*)&(GET_RNG_SEED_STATUS_HEADER), sizeof(GET_RNG_SEED_STATUS_HEADER));
	status = _call(command, command_size, &readBuffer, GET_RNG_SEED_STATUS_RESPONSE, sizeof(CFG_GET_RNG_SEED_STATUS_RESPONSE));
	if ((tmp_response = (CFG_GET_RNG_SEED_STATUS_RESPONSE *)readBuffer) == NULL) exit(254);
	*rngStatus = tmp_response->RngStatus;
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to ZeroTouchEnabled Host interface command
* Arguments:
*	zeroTouchEnabled - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetZeroTouchEnabled(AMT_BOOLEAN *zeroTouchEnabled)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_ZERO_TOUCH_ENABLED_HEADER);
	unsigned char command[sizeof(GET_ZERO_TOUCH_ENABLED_HEADER)];
	AMT_STATUS status;
	CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_ZERO_TOUCH_ENABLED_HEADER), (void*)&(GET_ZERO_TOUCH_ENABLED_HEADER), sizeof(GET_ZERO_TOUCH_ENABLED_HEADER));
	status = _call(command, command_size, &readBuffer, GET_ZERO_TOUCH_ENABLED_RESPONSE, sizeof(CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE));
	if ((tmp_response = (CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE *)readBuffer) == NULL) exit(254);
	*zeroTouchEnabled = tmp_response->ZeroTouchEnabled;
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to GetProvisioningTlsMode Host interface command
* Arguments:
*	provisioningTlsMode - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetProvisioningTlsMode(AMT_PROVISIONING_TLS_MODE *provisioningTlsMode)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_PROVISIONING_TLS_MODE_HEADER);
	unsigned char command[sizeof(GET_PROVISIONING_TLS_MODE_HEADER)];
	AMT_STATUS status;
	CFG_GET_PROVISIONING_TLS_MODE_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_PROVISIONING_TLS_MODE_HEADER), (void*)&(GET_PROVISIONING_TLS_MODE_HEADER), sizeof(GET_PROVISIONING_TLS_MODE_HEADER));
	status = _call(command, command_size, &readBuffer, GET_PROVISIONING_TLS_MODE_RESPONSE, sizeof(CFG_GET_PROVISIONING_TLS_MODE_RESPONSE));
	if ((tmp_response = (CFG_GET_PROVISIONING_TLS_MODE_RESPONSE *)readBuffer) == NULL) exit(254);
	*provisioningTlsMode = tmp_response->ProvisioningTlsMode;
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to StartConfiguration Host interface command
* Arguments:
*	None
* Return values:
*	AMT_STATUS_SUCCESS - or AMT_STATUS_CERTIFICATE_NOT_READY on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_StartConfiguration()
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(START_CONFIGURATION_HEADER);
	unsigned char command[sizeof(START_CONFIGURATION_HEADER)];
	AMT_STATUS status;

	memcpy_s(command, sizeof(START_CONFIGURATION_HEADER), (void*)&(START_CONFIGURATION_HEADER), sizeof(START_CONFIGURATION_HEADER));
	status = _call(command, command_size, &readBuffer, START_CONFIGURATION_RESPONSE, sizeof(CFG_START_CONFIGURATION_RESPONSE));
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to StopConfiguration Host interface command
* Arguments:
*	None
* Return values:
*   A status code that indicates the success or specific reason for failure of the operation is returned in the Status field of the response message. The following table lists the possible Status values. 
*
*	Status  Description
*	AMT_STATUS_INVALID_AMT_MODE  Returned when FW not in in- provision state or when provisioning period expired  
*	AMT_STATUS_SUCCESS  Request succeeded.  
*	AMT_STATUS_INTERNAL_ERROR  An internal error to the AMT device has occurred. This may indicate an interface error, or a AMT application error  
*	AMT_STATUS_INVALID_MESSAGE_LENGTH  Length field of header is invalid.  
*	AMT_STATUS_NOT_READY  Management controller has not progressed far enough in its initialization to process the command.  
*/
AMT_STATUS pthi_StopConfiguration()
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(STOP_CONFIGURATION_HEADER);
	unsigned char command[sizeof(STOP_CONFIGURATION_HEADER)];
	AMT_STATUS status;

	memcpy_s(command, sizeof(STOP_CONFIGURATION_HEADER), (void*)&(STOP_CONFIGURATION_HEADER), sizeof(STOP_CONFIGURATION_HEADER));
	status = _call(command, command_size, &readBuffer, STOP_CONFIGURATION_RESPONSE, sizeof(CFG_STOP_CONFIGURATION_RESPONSE));
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to SetProvisioningServerOTP Host interface command
* Arguments:
*	passwordOTP AMT_ANSI_STRING structure of OTP password
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_SetProvisioningServerOTP(AMT_ANSI_STRING passwordOTP)
{
	UINT8 *readBuffer = NULL;
	UINT32 msgLength = sizeof(passwordOTP.Length) + (passwordOTP.Length * sizeof(CHAR));
	PTHI_MESSAGE_HEADER SET_PROVISIONING_SERVER_OTP_HEADER = {{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{SET_PROVISIONING_SERVER_OTP_REQUEST}}, msgLength};
	UINT32 command_size;
	unsigned char *command;
	AMT_STATUS status;

	if (NULL == passwordOTP.Buffer) return PTSDK_STATUS_INVALID_PARAM;

	command_size = sizeof(SET_PROVISIONING_SERVER_OTP_HEADER) + msgLength;
	command = (unsigned char *)malloc(command_size);
	if (command == NULL) return PTSDK_STATUS_INTERNAL_ERROR;
	memcpy_s(command, sizeof(SET_PROVISIONING_SERVER_OTP_HEADER), (void*)&SET_PROVISIONING_SERVER_OTP_HEADER, sizeof(SET_PROVISIONING_SERVER_OTP_HEADER));
	memcpy_s(command + sizeof(SET_PROVISIONING_SERVER_OTP_HEADER), sizeof(passwordOTP.Length), (void*)&(passwordOTP.Length), sizeof(passwordOTP.Length));
	memcpy_s(command + sizeof(SET_PROVISIONING_SERVER_OTP_HEADER) + sizeof(passwordOTP.Length), passwordOTP.Length, passwordOTP.Buffer, passwordOTP.Length);

	status = _call(command, command_size, &readBuffer, SET_PROVISIONING_SERVER_OTP_RESPONSE, sizeof(CFG_SET_PROVISIONING_SERVER_OTP_RESPONSE));

	if (NULL != command) free(command);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to SetDnsSuffix Host interface command
* Arguments:
*	dnsSuffix AMT_ANSI_STRING structure of DNS suffix
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_SetDnsSuffix(AMT_ANSI_STRING dnsSuffix)
{
	UINT8 *readBuffer = NULL;
	UINT32 msgLength = sizeof(dnsSuffix.Length) + (dnsSuffix.Length * sizeof(CHAR));
	PTHI_MESSAGE_HEADER SET_DNS_SUFFIX_HEADER = {{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{SET_DNS_SUFFIX_REQUEST}}, msgLength};
	UINT32 command_size;
	unsigned char *command;
	AMT_STATUS status;

	if (dnsSuffix.Buffer == NULL) return PTSDK_STATUS_INVALID_PARAM;
	command_size = sizeof(SET_DNS_SUFFIX_HEADER) + msgLength;
	command = (unsigned char *)malloc(command_size);
	if (command == NULL) return PTSDK_STATUS_INTERNAL_ERROR;
	memcpy_s(command, sizeof(SET_DNS_SUFFIX_HEADER), (void*)&SET_DNS_SUFFIX_HEADER, sizeof(SET_DNS_SUFFIX_HEADER));
	memcpy_s(command + sizeof(SET_DNS_SUFFIX_HEADER), sizeof(dnsSuffix.Length), (void*)&(dnsSuffix.Length), sizeof(dnsSuffix.Length));
	memcpy_s(command + sizeof(SET_DNS_SUFFIX_HEADER) + sizeof(dnsSuffix.Length), dnsSuffix.Length, dnsSuffix.Buffer, dnsSuffix.Length);

	status = _call(command, command_size, &readBuffer, SET_DNS_SUFFIX_RESPONSE, sizeof(CFG_SET_DNS_SUFFIX_RESPONSE));

	if (command != NULL) free(command);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Calls to EnumerateHashHandles Host interface command
* Arguments:
*	hashHandles - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_EnumerateHashHandles(AMT_HASH_HANDLES *hashHandles)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(ENUMERATE_HASH_HANDLES_HEADER);
	unsigned char command[sizeof(ENUMERATE_HASH_HANDLES_HEADER)];
	AMT_STATUS status;
	CFG_GET_HASH_HANDLES_RESPONSE *tmp_response;
	
	memcpy_s(command, sizeof(ENUMERATE_HASH_HANDLES_HEADER), (void*)&(ENUMERATE_HASH_HANDLES_HEADER), sizeof(ENUMERATE_HASH_HANDLES_HEADER));

	status = _call(command, command_size, &readBuffer, ENUMERATE_HASH_HANDLES_RESPONSE, 0);
	do
	{
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_HASH_HANDLES_RESPONSE *)readBuffer;
		status = _verifyHashHandles(tmp_response);
		if (status != AMT_STATUS_SUCCESS) break;

		memset(hashHandles->Handles, 0, sizeof(UINT32) * CERT_HASH_MAX_NUMBER);
		hashHandles->Length = tmp_response->HashHandles.Length;
		if (CERT_HASH_MAX_NUMBER < hashHandles->Length)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}

		memcpy_s(hashHandles->Handles, sizeof(UINT32) * hashHandles->Length, tmp_response->HashHandles.Handles, sizeof(UINT32) * hashHandles->Length);

	} while (0);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
* Confirms the correctness of the EnumerateHashHandles response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyHashHandles(const CFG_GET_HASH_HANDLES_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != sizeof(AMT_STATUS) + sizeof(response->HashHandles.Length) + (sizeof(UINT32) * response->HashHandles.Length)) return PTSDK_STATUS_INTERNAL_ERROR;
	return AMT_STATUS_SUCCESS;
}


/*
* Calls to GetCertificateHashEntry Host interface command
* Arguments:
*	passwordOTP AMT_ANSI_STRING structure of DNS suffix
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetCertificateHashEntry(UINT32 hashHandle, CERTHASH_ENTRY *hashEntry)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GET_CERTHASH_ENTRY_REQUEST);
	unsigned char command[sizeof(CFG_GET_CERTHASH_ENTRY_REQUEST)];
	AMT_STATUS status;
	CFG_GET_CERTHASH_ENTRY_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_CERTHASH_ENTRY_HEADER), (void*)&(GET_CERTHASH_ENTRY_HEADER), sizeof(GET_CERTHASH_ENTRY_HEADER));
	memcpy_s(command + sizeof(GET_CERTHASH_ENTRY_HEADER), sizeof(hashHandle), (void*)&(hashHandle), sizeof(hashHandle));

	status = _call(command, command_size, &readBuffer, GET_CERTHASH_ENTRY_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_CERTHASH_ENTRY_RESPONSE *)readBuffer;
		status = _verifyGetCertificateHashEntry(tmp_response);
		if (status != AMT_STATUS_SUCCESS) break;

		hashEntry->IsActive = tmp_response->Hash.IsActive;
		hashEntry->IsDefault = tmp_response->Hash.IsDefault;
		hashEntry->Name.Length = tmp_response->Hash.Name.Length;
		hashEntry->HashAlgorithm = tmp_response->Hash.HashAlgorithm;
		memcpy_s(hashEntry->CertificateHash, sizeof(tmp_response->Hash.CertificateHash), tmp_response->Hash.CertificateHash, sizeof(tmp_response->Hash.CertificateHash));
		hashEntry->Name.Buffer = (CHAR *)malloc(hashEntry->Name.Length * sizeof(CHAR));
		if (NULL == hashEntry->Name.Buffer)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}
		memcpy_s(hashEntry->Name.Buffer, hashEntry->Name.Length * sizeof(CHAR), (void*)&(tmp_response->Hash.Name.Buffer), hashEntry->Name.Length * sizeof(CHAR));

	} while (0);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}
/*
* Confirms the correctness of the GetCertificateHashEntry response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyGetCertificateHashEntry(const CFG_GET_CERTHASH_ENTRY_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_CERTHASH_ENTRY_RESPONSE) - sizeof(PTHI_MESSAGE_HEADER) - sizeof(CHAR *) + response->Hash.Name.Length)) return PTSDK_STATUS_INTERNAL_ERROR;
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GetDnsSuffix Host interface command
* Arguments:
*	dnsSuffix - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS pthi_GetDnsSuffix(AMT_ANSI_STRING *dnsSuffix)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(GET_PKI_FQDN_SUFFIX_HEADER);
	unsigned char command[sizeof(GET_PKI_FQDN_SUFFIX_HEADER)];
	AMT_STATUS status;
	CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *tmp_response;

	memcpy_s(command, sizeof(GET_PKI_FQDN_SUFFIX_HEADER), (void*)&(GET_PKI_FQDN_SUFFIX_HEADER), sizeof(GET_PKI_FQDN_SUFFIX_HEADER));

	status = _call(command, command_size, &readBuffer, GET_PKI_FQDN_SUFFIX_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *)readBuffer;
		status = _verifyGetDnsSuffix(tmp_response);
		if (status != AMT_STATUS_SUCCESS) break;

		dnsSuffix->Length = tmp_response->Suffix.Length;
		dnsSuffix->Buffer = (CHAR *)malloc(dnsSuffix->Length * sizeof(CHAR));
		if (NULL == dnsSuffix->Buffer)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}
		memcpy_s(dnsSuffix->Buffer, dnsSuffix->Length * sizeof(CHAR), (void*)&(tmp_response->Suffix.Buffer), dnsSuffix->Length * sizeof(CHAR));

	} while (0);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}
/*
* Confirms the correctness of the GetDnsSuffix response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS _verifyGetDnsSuffix(const CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *response)
{
	ULONG ByteCount = response->Header.Header.Length;
	if (ByteCount != sizeof(AMT_STATUS) + sizeof(response->Suffix.Length) + response->Suffix.Length * sizeof(CHAR)) return PTSDK_STATUS_INTERNAL_ERROR;
	return AMT_STATUS_SUCCESS;
}

AMT_STATUS pthi_GetLocalSystemAccount(LOCAL_SYSTEM_ACCOUNT *localAccount)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GET_LOCAL_SYSTEM_ACCOUNT_REQUEST);
	unsigned char command[sizeof(CFG_GET_LOCAL_SYSTEM_ACCOUNT_REQUEST)];
	AMT_STATUS status;
	CFG_GET_LOCAL_SYSTEM_ACCOUNT_RESPONSE *tmp_response;

	memset(command, 0, sizeof(CFG_GET_LOCAL_SYSTEM_ACCOUNT_REQUEST));
	memcpy_s(command, sizeof(GET_LOCAL_SYSTEM_ACCOUNT_HEADER), (void*)&(GET_LOCAL_SYSTEM_ACCOUNT_HEADER), sizeof(GET_LOCAL_SYSTEM_ACCOUNT_HEADER));

	status = _call(command, command_size, &readBuffer, GET_LOCAL_SYSTEM_ACCOUNT_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS) break;
		tmp_response = (CFG_GET_LOCAL_SYSTEM_ACCOUNT_RESPONSE *)readBuffer;
		status = tmp_response->Status;
		if( status != AMT_STATUS_SUCCESS ) break;
		memcpy_s(localAccount, sizeof(LOCAL_SYSTEM_ACCOUNT), (void*)&(tmp_response->Account), sizeof(LOCAL_SYSTEM_ACCOUNT));
	} while (0);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

/*
 * Unprovision AMTHI command
 * Arguments:
 *	provisionMode - indicates the provisioining mode of the device upon unprovisioining
 * Return values:
 *	AMT_LOCAL_AGENT_STATUS_SUCCESS - on success
 *	AMT_STATUS_INTERNAL_ERROR - on failure
 *  AMT_STATUS_NOT_READY - Management controller has not progressed far enough in its
 *						   initialization to process the command.
 *  AMT_STATUS_INVALID_MESSAGE_LENGTH - Length field of header is invalid.
 *  AMT_STATUS_BLOCKING_COMPONENT - One of the ME components is not ready for unprovisioning.
 */
AMT_STATUS pthi_Unprovision(CFG_PROVISIONING_MODE provisionMode)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_UNPROVISION_REQUEST);
	unsigned char command[sizeof(CFG_UNPROVISION_REQUEST)];
	AMT_STATUS status;

	if ((CFG_PROVISIONING_MODE_NONE != provisionMode) && (CFG_PROVISIONING_MODE_ENTERPRISE != provisionMode)) return PTSDK_STATUS_INVALID_PARAM;
	memset(command, 0, sizeof(CFG_UNPROVISION_REQUEST));
	memcpy_s(command, sizeof(UNPROVISION_HEADER), (void*)&(UNPROVISION_HEADER), sizeof(UNPROVISION_HEADER));
	status = _call(command, command_size, &readBuffer, UNPROVISION_RESPONSE, 0);
	if (readBuffer != NULL) free(readBuffer);
	return status;
}


/*
* Sets host FQDN in AMT Calls to CFG_SET_HOST_FQDN_REQUEST command
* Arguments:
*	host - host FQDN
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS pthi_SetHostFQDN(char* str)
{
	//send requeast message to FW:
	AMT_STATUS status;
	UINT8 *readBuffer = NULL;
	CFG_SET_HOST_FQDN_REQUEST command;
	int len = (int)strnlen_s(str, 65535);
	
	memset(&command, 0, sizeof(CFG_SET_HOST_FQDN_REQUEST)); // Fix the valgrind warning
	command.Header = SET_HOST_FQDN_HEADER;
	command.Header.Length = sizeof(UINT16) + len;
	command.FQDNL = (unsigned short)len;
	memcpy_s(&command.FQDN, len, str, len);
	status = _call((UINT8 *)&command, sizeof(command), &readBuffer, SET_HOST_FQDN_RESPONSE, sizeof(CFG_SET_HOST_FQDN_RESPONSE));
	if (readBuffer != NULL) { free(readBuffer); }
	return status;
}



/*
 * Get EHBC state AMTHI command
 *  This command returns EHBC enable state. Note: This command is supported from MR 8.1.20
 * Arguments:
 *	None
 * Return values: (A status code returned in a response message that indicates whether the operation specified in the corresponding request message succeeded or failed. If the operation failed, this code indicates the specific reason for failure. Possible values described below.)
 *	AMT_STATUS_SUCCESS - Request succeeded.
 *  AMT_STATUS_INTERNAL_ERROR - An internal error to the AMT device has occurred. This may indicate an interface error, or a AMT application error.
 *  AMT_STATUS_INVALID_MESSAGE_LENGTH - Length field of header is invalid.
 */
AMT_STATUS pthi_GetStateEHBC(AMT_EHBC_STATE *state)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GETEHBPSTATE_REQUEST);
	unsigned char command[sizeof(CFG_GETEHBPSTATE_REQUEST)];
	AMT_STATUS status;
	CFG_GETEHBPSTATE_RESPONSE *tmp_response;

	memset(command, 0, sizeof(CFG_GETEHBPSTATE_REQUEST));
	memcpy_s(command, sizeof(GET_EHBC_STATE_REQUEST_HEADER), (void*)&(GET_EHBC_STATE_REQUEST_HEADER), sizeof(GET_EHBC_STATE_REQUEST_HEADER));
	status = _call(command, command_size, &readBuffer, GET_EHBC_STATE_RESPONSE, sizeof(CFG_GETEHBPSTATE_RESPONSE));
	if (status == AMT_STATUS_SUCCESS)
	{
		tmp_response = (CFG_GETEHBPSTATE_RESPONSE*)readBuffer;
		*state = tmp_response->EHBCState;
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}


/*
 * Get control mode AMTHI command
 *  gets the current control mode of AMT (client or admin control mode). The machine will be in client control mode if it was configured this way using host based configuration.
 *  If the machine was configured using RCFG or using host based provisioning to admin control mode in admin control mode. If the machine is not provisioned this command will return the value None.
 * Arguments:
 *	None
 * Return values: (A status code returned in a response message that indicates whether the operation specified in the corresponding request message succeeded or failed. If the operation failed, this code indicates the specific reason for failure. Possible values described below.)
 *	AMT_STATUS_SUCCESS - Request succeeded.
 *  AMT_STATUS_INTERNAL_ERROR - An internal error to the AMT device has occurred. This may indicate an interface error, or a AMT application error.
 *  AMT_STATUS_INVALID_MESSAGE_LENGTH - Length field of header is invalid.
 */
AMT_STATUS pthi_GetControlMode(int *state)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(CFG_GET_CONTROL_MODE_REQUEST);
	unsigned char command[sizeof(CFG_GET_CONTROL_MODE_REQUEST)];
	AMT_STATUS status;
	CFG_GET_CONTROL_MODE_RESPONSE *tmp_response;

	memset(command, 0, sizeof(CFG_GET_CONTROL_MODE_REQUEST));
	memcpy_s(command, sizeof(GET_CONTROL_MODE_REQUEST_HEADER), (void*)&(GET_CONTROL_MODE_REQUEST_HEADER), sizeof(GET_CONTROL_MODE_REQUEST_HEADER));
	status = _call(command, command_size, &readBuffer, GET_CONTROL_MODE_RESPONSE, sizeof(CFG_GET_CONTROL_MODE_RESPONSE));
	if (status == AMT_STATUS_SUCCESS)
	{
		tmp_response = (CFG_GET_CONTROL_MODE_RESPONSE*)readBuffer;
		*state = tmp_response->state;	// 0 - None (or RPAT for 6.x) 1 - Client 2 - Admin
	}
	if (readBuffer != NULL) free(readBuffer);
	return status;
}

#endif
