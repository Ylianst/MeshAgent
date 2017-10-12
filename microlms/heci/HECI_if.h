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

#ifndef __HECI_INTRFACE_H__
#define __HECI_INTRFACE_H__

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef char            CHAR;
typedef unsigned long   ULONG;
typedef UINT32          AMT_STATUS;
typedef UINT32          AMT_BOOLEAN;

typedef enum _HECI_STATUS {
	HECI_STATUS_OK                    = 0x0,
	HECI_STATUS_GENERAL_ERROR         = 0x2000,
	HECI_STATUS_LOCATE_DEVICE_ERROR,
	HECI_STATUS_MEMORY_ACCESS_ERROR,
	HECI_STATUS_WRITE_REGISTER_ERROR,
	HECI_STATUS_MEMORY_ALLOCATION_ERROR,
	HECI_STATUS_BUFFER_OVEREFLOW_ERROR,
	HECI_STATUS_NOT_ENOUGH_MEMORY,
	HECI_STATUS_MSG_TRANSMISSION_ERROR,
	HECI_STATUS_VERSION_MISMATCH,
	HECI_STATUS_UNEXPECTED_INTERRUPT_REASON,
	HECI_STATUS_TIMEOUT_ERROR,
	HECI_STATUS_UNEXPECTED_RESPONSE,
	HECI_STATUS_UNKNOWN_MESSAGE,
	HECI_STATUS_CANNOT_FOUND_HOST_CLIENT,
	HECI_STATUS_CANNOT_FOUND_ME_CLIENT,
	HECI_STATUS_CLIENT_ALREADY_CONNECTED,
	HECI_STATUS_NO_FREE_CONNECTION,
	HECI_STATUS_ILLEGAL_PARAMETER,
	HECI_STATUS_FLOW_CONTROL_ERROR,
	HECI_STATUS_NO_MESSAGE,
	HECI_STATUS_BUFFER_TOO_LARGE,
	HECI_STATUS_BUFFER_TOO_SMALL,
	HECI_STATUS_BUFFER_NOT_EMPTY,
	NUM_OF_HECI_STATUSES
} HECI_STATUS;

#ifdef WIN32
	// Win32 code

	#define AMT_LOCAL_AGENT_STATUS_SUCCESS  0
	#define USAGE                           1
	#define ERROR_MESSAGE                   2
	#define VERSION_MESSAGE                 3
	#define HECI_ERROR_MESSAGE              4
	#define UNKNOWN                         5
	#define HECI_CONNECT_TO_FWU_CLIENT_FAILURE 6
	#define WRITE_FILE_TIME_OUT             7
	#define ME_FW_INFO                      8
	#define ME_MODE                         9
	#define IOCTL_COMMAND                   10
	#define WRITE_FILE                      11
	#define READ_FILE                       12
	#define GET_CLASS_DEVS                  13
	#define GET_INTERFACE_DETAIL            14
	#define ICH_VERSION                     15
	#define FIND_HECI_FAILURE               16
	#define CREATE_HECI_FILE                17
	#define CREATE_HECI_FILE_FAILURE        17
	#define GET_HECI_DRIVER_VERSION_FAILURE 18
	#define LA_STATUS_INTERNAL_ERROR        19
	#define HECI_CONNECT_TO_PTHI_CLIENT_FAILURE 20
	#define LA_HECI_ERROR                   21
	#define ALLOCATE_MEMORY_ERROR           22
	#define LA_HECI_NOT_INSTALLED_ERROR     23
	#define FW_BUFFER_IS_TO_SMALL           24
	#define SEND_DATA_TO_FW_FAILURE         25
	#define RECEIVE_DATA_FROM_FW_FAILURE    26
	#define GET_INFO_FROM_HECI_FAILURE      27
	#define MCH_VERSION                     28
	#define OEM_VENDOR                      29
	#define HECI_DRIVER_VERSION             30
	#define CODE_MAJOR_VERSION              31
	#define CODE_MINOR_VERSION              32
	#define CODE_HOTFIX_VERSION             33
	#define CODE_BUID_VERSION               34
	#define BIOS_VERSION                    35
	#define AMT_CODE_VERSION                36
	#define AMT_MODE                        37
	#define AMT_MODE_1                      38
	#define IDS_STRING39                    39
	#define AMT_MODE_2                      39
	#define PROVISIONING_STATE              40
	#define STATE_PRE                       41
	#define STATE_IN                        42
	#define STATE_POST                      43
	#define IDS_STRING44                    44
	#define PARSE_KEYWORD_DISCOVERY_TEST    44
	#define DISCOVERY_PASS                  45
	#define IDS_STRING46                    46
	#define DISCOVERY_FAILED                46
	#define IDS_STRING47                    47
	#define PARSE_KEYWORD_ACTIVATE          47
	#define PARSE_KEYWORD_OTP               48
	#define PARSE_KEYWORD_DNS               49
	#define PARSE_KEYWORD_VERBOSE           50
	#define INVALID_PARAM_INPUT             51
	#define USAGE_LOCAL_AGENT               52
	#define USAGE_OPTIONS                   53
	#define USAGE_OPTIONS_OTP               54
	#define USAGE_OPTIONS_DNS               55
	#define USAGE_OPTIONS_DISCOVERY         56
	#define USAGE_OPTIONS_ACTIVATE          57
	#define USAGE_OPTIONS_VERBOSE           58
	#define WORD_ZTC                        59
	#define WORD_ENABLED                    60
	#define WORD_DISABLED                   61
	#define WORD_PROVISIONING_TLS_MODE      62
	#define WORD_PKI                        63
	#define WORD_PSK                        64
	#define WORD_RNG_SEED_STATUS            65
	#define WORD_EXIST                      66
	#define WORD_IN_PROGRESS                67
	#define WORD_NOT_EXIST                  68
	#define WORD_AMT_CONFIG_ACTIVATE        69
	#define WORD_SUCCESS                    70
	#define IDS_STRING71                    71
	#define WORD_FAILURE                    71
	#define WORD_NOT_READY                  72
	#define IDS_STRING73                    73
	#define HASH_ENTRY                      73
	#define HECI_CONNECT_TO_WD_CLIENT_FAILURE 74
	#define CHANGE_TO_AMT_FAILURE           75
	#define IDS_STRING76                    76
	#define WORD_CHANGE_TO_AMT              76
	#define FOUND                           77
	#define CERT_HASHES_IN_FW               78
	#define NO_HANDLES_FOUND                79
	#define CERT_HASH                       80
	#define FRIENDLY_NAME                   81

	#define FILE_DEVICE_HECI  0x8000
	#define HECI_IOCTL(index) CTL_CODE(FILE_DEVICE_HECI, index, METHOD_BUFFERED, FILE_READ_DATA)
	#define IOCTL_HECI_GET_VERSION CTL_CODE(FILE_DEVICE_HECI, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
	#define IOCTL_HECI_CONNECT_CLIENT CTL_CODE(FILE_DEVICE_HECI, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
	#define IOCTL_HECI_WD CTL_CODE(FILE_DEVICE_HECI, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#endif

#pragma pack(1)

typedef struct _HECI_VERSION {
	UINT8 major;
	UINT8 minor;
	UINT8 hotfix;
	UINT16 build;
} HECI_VERSION;

typedef struct _HECI_CLIENT {
	UINT32  MaxMessageLength;
	UINT8 ProtocolVersion;
} HECI_CLIENT;

typedef union _MEFWCAPS_SKU
{
	UINT32   Data;
	struct {
		UINT32   Reserved    :1; //Legacy
		UINT32   Qst         :1; //QST
		UINT32   Asf         :1; //ASF2
		UINT32   Amt         :1; //AMT Professional
		UINT32   AmtFund     :1; //AMT Fundamental
		UINT32   Tpm         :1; //TPM
		UINT32   Dt          :1;
		UINT32   Fps         :1; //Fingerprint Sensor
		UINT32   HomeIT      :1; //Home IT
		UINT32   Mctp        :1; //MCTP
		UINT32   WoX         :1;
		UINT32   PmcPatch    :1; //PMC Patch
		UINT32   Ve          :1; //VE
		UINT32   Tdt         :1; //Theft Deterrent Technology
		UINT32   Corp        :1; //Corporate
		UINT32   Reserved2   :17;
	} Fields;
} MEFWCAPS_SKU;

typedef enum _MEFWCAPS_MANAGEABILITY_SUPP
{
	MEFWCAPS_MANAGEABILITY_SUPP_NONE = 0,
	MEFWCAPS_MANAGEABILITY_SUPP_AMT,
	MEFWCAPS_MANAGEABILITY_SUPP_ASF,
	MEFWCAPS_MANAGEABILITY_SUPP_CP
} MEFWCAPS_MANAGEABILITY_SUPP;


#pragma pack()

#endif // __HECI_INTRFACE_H__

#endif
