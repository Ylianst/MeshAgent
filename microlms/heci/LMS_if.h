/*******************************************************************************
 * Copyright (C) 2004-2011 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corporation. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corporation. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef _MINCORE

#ifndef _LMS_IF_H_
#define _LMS_IF_H_

#include "LMS_if_constants.h"

#pragma pack(1)

typedef struct {
	unsigned char  MessageType;
} APF_MESSAGE_HEADER;


/**
 * APF_GENERIC_HEADER - generic request header (note that its not complete header per protocol (missing WantReply)
 *
 * @MessageType:
 * @RequestStringLength: length of the string identifies the request
 * @RequestString: the string that identifies the request
 **/

typedef struct {
	unsigned char MessageType;
	unsigned int  StringLength;
	unsigned char  String[0];
} APF_GENERIC_HEADER;

/**
 * TCP forward reply message
 * @MessageType - Protocol's Major version
 * @PortBound - the TCP port was bound on the server
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  PortBound;
} APF_TCP_FORWARD_REPLY_MESSAGE;

/**
 * response to ChannelOpen when channel open succeed
 * @MessageType - APF_CHANNEL_OPEN_CONFIRMATION
 * @RecipientChannel - channel number given in the open request
 * @SenderChannel - channel number assigned by the sender
 * @InitialWindowSize - Number of bytes in the window
 * @Reserved - Reserved
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  RecipientChannel;
	unsigned int  SenderChannel;
	unsigned int  InitialWindowSize;
	unsigned int  Reserved;
} APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE;

/**
 * response to ChannelOpen when a channel open failed
 * @MessageType - APF_CHANNEL_OPEN_FAILURE
 * @RecipientChannel - channel number given in the open request
 * @ReasonCode - code for the reason channel could not be open
 * @Reserved - Reserved
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  RecipientChannel;
	unsigned int  ReasonCode;
	unsigned int  Reserved;
	unsigned int  Reserved2;
} APF_CHANNEL_OPEN_FAILURE_MESSAGE;

/**
 * close channel message
 * @MessageType - APF_CHANNEL_CLOSE
 * @RecipientChannel - channel number given in the open request
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  RecipientChannel;
} APF_CHANNEL_CLOSE_MESSAGE;

/**
 * used to send/receive data.
 * @MessageType - APF_CHANNEL_DATA
 * @RecipientChannel - channel number given in the open request
 * @Length - Length of the data in the message
 * @Data - The data in the message
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  RecipientChannel;
	unsigned int  DataLength;
	// unsigned char Data[0];
} APF_CHANNEL_DATA_MESSAGE;

/**
 * used to adjust receive window size.
 * @MessageType - APF_WINDOW_ADJUST
 * @RecipientChannel - channel number given in the open request
 * @BytesToAdd - number of bytes to add to current window size value
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  RecipientChannel;
	unsigned int  BytesToAdd;
} APF_WINDOW_ADJUST_MESSAGE;

/**
 * This message causes immediate termination of the connection with AMT.
 * @ReasonCode -  A Reason code for the disconnection event
 * @Reserved - Reserved must be set to 0
 **/
typedef struct {
	unsigned char  MessageType;
	unsigned int   ReasonCode;
	unsigned short Reserved;
} APF_DISCONNECT_MESSAGE;

/**
 * Used to request a service identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  ServiceNameLength;
	unsigned char ServiceName[0];
} APF_SERVICE_REQUEST_MESSAGE;

/**
 * Used to send a service accept identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  ServiceNameLength;
	unsigned char ServiceName[0];
} APF_SERVICE_ACCEPT_MESSAGE;

/**
 * holds the protocl major and minor version implemented by AMT.
 * @MajorVersion - Protocol's Major version
 * @MinorVersion - Protocol's Minor version
 * @Trigger - The open session reason
 * @UUID - System Id
 **/
typedef struct {
	unsigned char MessageType;
	unsigned int  MajorVersion;
	unsigned int  MinorVersion;
	unsigned int  TriggerReason;
	unsigned char UUID[16];
	unsigned char Reserved[64];
} APF_PROTOCOL_VERSION_MESSAGE;


/**
 * holds the user authentication request success reponse.
 **/
typedef struct {
	unsigned char MessageType;
} APF_USERAUTH_SUCCESS_MESSAGE;

#pragma pack()

#endif

#endif
