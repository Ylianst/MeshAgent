/*   
Copyright 2006 - 2015 Intel Corporation

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

#ifndef _MINCORE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "LMEConnection.h"
#include "LMS_if.h"
#include "../../microstack/ILibParsers.h"

#define MEI_IO_TIMEOUT 1000

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

const unsigned int LME_RX_WINDOW_SIZE = 4096;
int LME_sendMessage(struct LMEConnection* module, unsigned char *buffer, int len);
void LME_doRX(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead);
void LME_apfGlobalRequest(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead, int *status);
void LME_Deinit(struct LMEConnection* module);

bool LME_IsInitialized(struct LMEConnection* module)
{
	// Lock il(_initLock);
	bool ret = (bool)(module->initState == INIT_STATE_CONNECTED);
	return ret;
}

#ifdef WIN32
DWORD WINAPI LME_Thread(void* obj)
#else
void LME_Thread(void* obj)
#endif
{
#ifdef WIN32
	HECI_VERSION version;
#endif
	int len = 0;
	int bufsize = 0;
	unsigned char* data = NULL;
	struct LMEConnection* module = (struct LMEConnection*)obj;

	//printf("LMS THREAD START\r\n");

	do {
		bufsize = heci_GetBufferSize(&(module->mei));
		if ((data = (unsigned char*)malloc(bufsize)) == NULL) ILIBCRITICALEXIT(254);

		do {
			len = heci_ReceiveMessage(&(module->mei), data, bufsize, 0xFFFFFFFF);
			//printf("LMS THREAD READ LEN=%d\r\n", len);
			if (len > 0 && data != NULL) LME_doRX(module, data, len);
		} while (len >= 0);
		
		module->cb(module, module->cbParam, NULL, 0);
		module->initState = INIT_STATE_DISCONNECTED;
		free(data);
		
		// printf("LMS TRYING RECONNECT\r\n");

		while (module->exit == 0 && module->initState == INIT_STATE_DISCONNECTED)
		{
			// Setup the MEI interface with the LME GUID
			#ifdef WIN32
				if (heci_Init(&(module->mei), 1) == TRUE && heci_GetHeciVersion(&(module->mei), &version) == TRUE && version.major >= LMS_PROTOCOL_VERSION) { module->initState = INIT_STATE_CONNECTED; }
			#else
				if (heci_Init(&(module->mei), 1) == TRUE && heci_GetProtocolVersion(&(module->mei)) >= LMS_PROTOCOL_VERSION) { module->initState = INIT_STATE_CONNECTED; }
			#endif

			if (module->exit == 0 && module->initState == INIT_STATE_DISCONNECTED)
			{
				// printf("LMS THREAD SLEEP\r\n");
#ifdef WIN32
				Sleep(2000);
#else
				sleep(2);
#endif
			}
			//if (module->initState == INIT_STATE_CONNECTED) printf("LMS THREAD RECONNECT\r\n");
		}
	}
	while (module->exit == 0);

	// printf("LMS THREAD QUIT\r\n");
	module->exit = 2;

#ifdef WIN32
	return 0;
#endif
}

// Setup the LME connection
bool LME_Init(struct LMEConnection* module, MEICallback cb, void *param)
{
#ifdef WIN32
	HECI_VERSION version;
#endif

	// Setup the state object
	memset(module, 0, sizeof(struct LMEConnection));
	module->initState = INIT_STATE_DISCONNECTED;
	module->cb = cb;
	module->cbParam = param;

	// Setup the MEI interface with the LME GUID
#ifdef WIN32
	if (heci_Init(&(module->mei), 1) == FALSE || heci_GetHeciVersion(&(module->mei), &version) == FALSE || version.major < LMS_PROTOCOL_VERSION) { module->initState = INIT_STATE_DISCONNECTED; return FALSE; }
#else
	if (heci_Init(&(module->mei), 1) == FALSE || heci_GetProtocolVersion(&(module->mei)) < LMS_PROTOCOL_VERSION) { module->initState = INIT_STATE_DISCONNECTED; return FALSE; }
#endif

	module->initState = INIT_STATE_CONNECTED;
	if ((module->txBuffer = (unsigned char*)malloc(LME_GetMeiBufferSize(module))) == NULL) ILIBCRITICALEXIT(254);

	// Create the thread that will read the MEI/LME stream
	ILibSpawnNormalThread((voidfp1)(&LME_Thread), module);

	return TRUE;
}

// Disconnect the LME connection
void LME_Deinit(struct LMEConnection* module)
{
	//printf("LME_Deinit()\r\n");
	if (module == NULL) return;
	if (module->initState == INIT_STATE_CONNECTED) { heci_Deinit(&(module->mei)); }
	module->initState = INIT_STATE_DISCONNECTED;
}

// Exit LME
void LME_Exit(struct LMEConnection* module)
{
	int l = 0;

	//printf("LME_Exit()\r\n");
	if (module == NULL) return;
	if (module->exit == 0) module->exit = 1;
	LME_Deinit(module);
#ifdef WIN32
	while (module->exit != 2 && l < 40) { Sleep(100); l++; }
#else
	/*
	while (module->exit != 2 && l < 4)
	{
		printf("LME_Holding %d\r\n", l);
		Sleep(1);
		l++;
	}
	*/
#endif
	if (module->txBuffer != NULL && l < 40) { free(module->txBuffer); module->txBuffer = NULL; }
}

// Send the APF disconnect message to the MEI
bool LME_Disconnect(struct LMEConnection* module, APF_DISCONNECT_REASON_CODE reasonCode)
{
	unsigned char buf[sizeof(APF_DISCONNECT_MESSAGE)];
	APF_DISCONNECT_MESSAGE *disconnectMessage = (APF_DISCONNECT_MESSAGE *)buf;
	memset(disconnectMessage, 0, sizeof(buf));
	disconnectMessage->MessageType = APF_DISCONNECT;
	disconnectMessage->ReasonCode = htonl(reasonCode);
	return (LME_sendMessage(module, buf, sizeof(buf)) == sizeof(buf));
}

// Send the AFP service accept message to the MEI
bool LME_ServiceAccept(struct LMEConnection* module, char* serviceName)
{
	int len;
	int res;
	int servicenamelen = (int)strnlen_s(serviceName, 65535);
	unsigned char *buf;
	unsigned char *pCurrent;

	if (!LME_IsInitialized(module)) return FALSE;
	if ((buf = (unsigned char*)malloc(sizeof(APF_SERVICE_ACCEPT_MESSAGE) + servicenamelen)) == NULL) ILIBCRITICALEXIT(254);
	pCurrent = buf;

	*pCurrent = APF_SERVICE_ACCEPT;
	++pCurrent;
	*((unsigned int *)pCurrent) = htonl(servicenamelen);
	pCurrent += 4;

	memcpy_s(pCurrent, servicenamelen, serviceName, servicenamelen);
	pCurrent += servicenamelen;

	len = (int)(pCurrent - buf);
	res = LME_sendMessage(module, buf, len);
	free(buf);

	return (res == len);
}

bool LME_ProtocolVersion(struct LMEConnection* module, unsigned int majorversion, unsigned int minorversion, unsigned int triggerreason)
{
	APF_PROTOCOL_VERSION_MESSAGE protVersion;
	memset(&protVersion, 0, sizeof(protVersion));
	protVersion.MessageType = APF_PROTOCOLVERSION;
	protVersion.MajorVersion = htonl(majorversion);
	protVersion.MinorVersion = htonl(minorversion);
	protVersion.TriggerReason = htonl(triggerreason);
	return (LME_sendMessage(module, (unsigned char *)&protVersion, sizeof(protVersion)) == sizeof(protVersion));
}

bool LME_TcpForwardReplySuccess(struct LMEConnection* module, unsigned int port)
{
	APF_TCP_FORWARD_REPLY_MESSAGE message;
	memset(&message, 0, sizeof(message));
	message.MessageType = APF_REQUEST_SUCCESS;
	message.PortBound = htonl(port);
	return (LME_sendMessage(module, (unsigned char *)&message, sizeof(message)) == sizeof(message));
}

bool LME_SendShortMessage(struct LMEConnection* module, unsigned char buf)
{
	return (LME_sendMessage(module, &buf, sizeof(buf)) == sizeof(buf));
}

bool LME_ChannelOpenForwardedRequest(struct LMEConnection* module, unsigned int senderChannel, char* connectedIP, unsigned int connectedPort, char* originatorIP, unsigned int originatorPort)
{
	int res;
	int connectedIPlen = (int)strnlen_s(connectedIP, 65535);
	int originatorIPlen = (int)strnlen_s(originatorIP, 65535);
	unsigned char *buf;
	unsigned char *pCurrent;
	if (!LME_IsInitialized(module)) return FALSE;

	if ((buf = (unsigned char*)malloc(5 + APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED) + 16 + connectedIPlen + 8 + originatorIPlen + 4)) == NULL) ILIBCRITICALEXIT(254);
	pCurrent = buf;

	if (strnlen_s(originatorIP, 65535) > 63) { free(buf); return FALSE; }
	*pCurrent = APF_CHANNEL_OPEN;
	++pCurrent;

	*((unsigned int *)pCurrent) = htonl(APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED));
	pCurrent += sizeof(unsigned int);

	memcpy_s(pCurrent, APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED), APF_OPEN_CHANNEL_REQUEST_FORWARDED, APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED));
	pCurrent += APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED);

	*((unsigned int *)pCurrent) = htonl(senderChannel);
	pCurrent += sizeof(unsigned int);

	*((unsigned int *)pCurrent) = htonl(LME_RX_WINDOW_SIZE);
	pCurrent += sizeof(unsigned int);

	*((unsigned int *)pCurrent) = 0xFFFFFFFF;
	pCurrent += sizeof(unsigned int);

	*((unsigned int *)pCurrent) = htonl(connectedIPlen);
	pCurrent += sizeof(unsigned int);

	memcpy_s(pCurrent, connectedIPlen, connectedIP, connectedIPlen);
	pCurrent += connectedIPlen;

	*((unsigned int *)pCurrent) = htonl(connectedPort);
	pCurrent += sizeof(unsigned int);

	*((unsigned int *)pCurrent) = htonl((unsigned int)originatorIPlen);
	pCurrent += sizeof(unsigned int);

	memcpy_s(pCurrent, originatorIPlen, originatorIP, originatorIPlen);
	pCurrent += originatorIPlen;

	*((unsigned int *)pCurrent) = htonl(originatorPort);
	pCurrent += sizeof(unsigned int);

	res = LME_sendMessage(module, buf, (int)(pCurrent - buf));
	free(buf);

	return (res == pCurrent - buf);
}

bool LME_ChannelOpenReplySuccess(struct LMEConnection* module, unsigned int recipientChannel, unsigned int senderChannel)
{
	APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE message;
	message.MessageType = APF_CHANNEL_OPEN_CONFIRMATION;
	message.RecipientChannel = htonl(recipientChannel);
	message.SenderChannel = htonl(senderChannel);
	message.InitialWindowSize = htonl(LME_RX_WINDOW_SIZE);
	message.Reserved = 0xFFFFFFFF;
	return (LME_sendMessage(module, (unsigned char*)&message, sizeof(message)) == sizeof(message));
}

bool LME_ChannelOpenReplyFailure(struct LMEConnection* module, unsigned int recipientChannel, unsigned int reason)
{
	APF_CHANNEL_OPEN_FAILURE_MESSAGE message;
	message.MessageType = APF_CHANNEL_OPEN_FAILURE;
	message.RecipientChannel = htonl(recipientChannel);
	message.ReasonCode = htonl(reason);
	message.Reserved = 0x00000000;
	message.Reserved2 = 0x00000000;
	return (LME_sendMessage(module, (unsigned char*)&message, sizeof(message)) == sizeof(message));
}

bool LME_ChannelClose(struct LMEConnection* module, unsigned int recipientChannel, unsigned int senderChannel )
{
	APF_CHANNEL_CLOSE_MESSAGE message;
	UNREFERENCED_PARAMETER( senderChannel );

	message.MessageType = APF_CHANNEL_CLOSE;
	message.RecipientChannel = htonl(recipientChannel);
	return (LME_sendMessage(module, (unsigned char*)&message, sizeof(message)) == sizeof(message));
}

int LME_ChannelData(struct LMEConnection* module, unsigned int recipientChannel, unsigned int len, unsigned char *buffer)
{
	APF_CHANNEL_DATA_MESSAGE *message;
	if (len > (LME_GetMeiBufferSize(module) - sizeof(APF_CHANNEL_DATA_MESSAGE)) || module->txBuffer == NULL) return -1;
	message = (APF_CHANNEL_DATA_MESSAGE*)module->txBuffer;
	message->MessageType = APF_CHANNEL_DATA;
	message->RecipientChannel = htonl(recipientChannel);
	message->DataLength = htonl(len);
	memcpy_s(module->txBuffer + sizeof(APF_CHANNEL_DATA_MESSAGE), len, buffer, len);
	return LME_sendMessage(module, (unsigned char *)message, sizeof(APF_CHANNEL_DATA_MESSAGE) + len) - sizeof(APF_CHANNEL_DATA_MESSAGE);
}

bool LME_ChannelWindowAdjust(struct LMEConnection* module, unsigned int recipientChannel, unsigned int len)
{
	APF_WINDOW_ADJUST_MESSAGE message;
	message.MessageType = APF_CHANNEL_WINDOW_ADJUST;
	message.RecipientChannel = htonl(recipientChannel);
	message.BytesToAdd = htonl(len);
	return (LME_sendMessage(module, (unsigned char *)&message, sizeof(message)) == sizeof(message));
}

int LME_sendMessage(struct LMEConnection* module, unsigned char *buffer, int len)
{
	int result;
	if (!LME_IsInitialized(module)) { return -1; }
	result = heci_SendMessage(&(module->mei), buffer, len, MEI_IO_TIMEOUT);
	if (result < 0) LME_Deinit(module);
	return result;
}

bool LME_checkMinMsgSize(unsigned char *buf, unsigned int bytesRead)
{
	switch (buf[0]) {
	case APF_DISCONNECT:
		if (bytesRead < sizeof(APF_DISCONNECT_MESSAGE)) { return FALSE; }
		break;
	case APF_SERVICE_REQUEST:
		if (bytesRead < sizeof(APF_SERVICE_REQUEST)) { return FALSE; }
		if (bytesRead < (sizeof(APF_SERVICE_REQUEST) + ntohl(((APF_SERVICE_REQUEST_MESSAGE *)buf)->ServiceNameLength))) { return FALSE; }
		break;
	case APF_USERAUTH_REQUEST:
		if (bytesRead < (3 * sizeof(unsigned int))) { return FALSE; }
		break;
	case APF_GLOBAL_REQUEST:
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) + sizeof(UINT8))) { return FALSE; }
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) + sizeof(UINT8) + ntohl(((APF_GENERIC_HEADER *)buf)->StringLength))) { return FALSE; }
		break;
	case APF_CHANNEL_OPEN:
		if (bytesRead < sizeof(APF_GENERIC_HEADER)) { return FALSE; }
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) + ntohl(((APF_GENERIC_HEADER *)buf)->StringLength))) { return FALSE; }
		break;
	case APF_CHANNEL_OPEN_CONFIRMATION:
		if (bytesRead < sizeof(APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE)) { return FALSE; }
		break;
	case APF_CHANNEL_OPEN_FAILURE:
		if (bytesRead < sizeof(APF_CHANNEL_OPEN_FAILURE_MESSAGE)) { return FALSE; }
		break;
	case APF_CHANNEL_CLOSE:
		if (bytesRead < sizeof(APF_CHANNEL_CLOSE_MESSAGE)) { return FALSE; }
		break;
	case APF_CHANNEL_DATA:
		if (bytesRead < sizeof(APF_CHANNEL_DATA_MESSAGE)) { return FALSE; }
		if (bytesRead < (sizeof(APF_CHANNEL_DATA_MESSAGE) + ntohl(((APF_CHANNEL_DATA_MESSAGE *)buf)->DataLength))) { return FALSE; }
		break;
	case APF_CHANNEL_WINDOW_ADJUST:
		if (bytesRead < sizeof(APF_WINDOW_ADJUST_MESSAGE)) { return FALSE; }
		break;
	case APF_PROTOCOLVERSION:
		if (bytesRead < sizeof(APF_PROTOCOL_VERSION_MESSAGE)) { return FALSE; }
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

void LME_doRX(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead)
{
	if (bytesRead == 0) return;
	if (!LME_checkMinMsgSize(rxBuffer, bytesRead)) { LME_Deinit(module); return; }
	module->cb(module, module->cbParam, rxBuffer, bytesRead);
}

/*
void LME_apfChannelOpen(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead, int *status)
{
	APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

	if (_strnicmp((char *)pHeader->String, APF_OPEN_CHANNEL_REQUEST_DIRECT, APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT)) == 0)
	{
		unsigned int senderChannel = 0;

		LME_apfChannelOpenDirect(module, rxBuffer, bytesRead, &senderChannel, status);
		if (LME_IsInitialized(module) && (*status == 1)) {
			if (plugin.retry(rxBuffer, bytesRead) != LMS_DROPPED) { LME_apfChannelOpenDirect(module, rxBuffer, bytesRead, NULL, status); }
		}

		if (LME_IsInitialized(module) && (*status == 1)) {
			LME_ChannelOpenReplyFailure(module, senderChannel, OPEN_FAILURE_REASON_CONNECT_FAILED);
		}
	}
}

void LME_apfChannelOpenDirect(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead, unsigned int *senderChannel, int *status)
{
	unsigned char *pCurrent;
	APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

	if (bytesRead < sizeof(APF_GENERIC_HEADER) +
	    ntohl(pHeader->StringLength) +
	    7 + (5 * sizeof(unsigned int))) {
		ILIBMESSAGE("apfChannelOpenDirect: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	pCurrent = rxBuffer + sizeof(APF_GENERIC_HEADER) +
		APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT);

	LMEChannelOpenRequestMessage channelOpenRequest;
	channelOpenRequest.ChannelType = APF_CHANNEL_DIRECT;

	channelOpenRequest.SenderChannel = ntohl(*((unsigned int *)pCurrent));
	if (senderChannel) {
		*senderChannel = channelOpenRequest.SenderChannel;
	}
	pCurrent += sizeof(unsigned int);
	channelOpenRequest.InitialWindow = ntohl(*((unsigned int *)pCurrent));
	pCurrent += 2 * sizeof(unsigned int);

	unsigned int len = ntohl(*((unsigned int *)pCurrent));
	pCurrent += sizeof(unsigned int);
	channelOpenRequest.Address.append((char *)pCurrent, len);
	pCurrent += len;
	channelOpenRequest.Port = ntohl(*((unsigned int *)pCurrent));
	pCurrent += sizeof(unsigned int);

	module->_cb(module, module->_cbParam, &channelOpenRequest, sizeof(channelOpenRequest), status);
}
*/

/*
void LME_apfUserAuthRequest(struct LMEConnection* module, unsigned char *rxBuffer, unsigned int bytesRead, int *status)
{
	unsigned char *pCurrent = rxBuffer;

	++pCurrent;

	LMEUserAuthRequestMessage userAuthRequest;

	unsigned int len = ntohl(*((unsigned int *)pCurrent));
	pCurrent += sizeof(unsigned int);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		ILIBMESSAGE("_apfUserAuthRequest1: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	userAuthRequest.Username.append((char *)pCurrent, len);
	pCurrent += len;

	if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(unsigned int)) {
		ILIBMESSAGE("_apfUserAuthRequest2: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	len = ntohl(*((unsigned int *)pCurrent));
	pCurrent += sizeof(unsigned int);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		ILIBMESSAGE("_apfUserAuthRequest3: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	userAuthRequest.ServiceName.append((char *)pCurrent, len);
	pCurrent += len;

	if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(unsigned int)) {
		ILIBMESSAGE("_apfUserAuthRequest4: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	len = ntohl(*((unsigned int *)pCurrent));
	pCurrent += sizeof(unsigned int);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		ILIBMESSAGE("_apfUserAuthRequest5: Error receiving data from MEI\n");
		LME_Deinit(module);
		return;
	}

	userAuthRequest.MethodName.append((char *)pCurrent, len);
	pCurrent += len;

	if (_strnicmp(userAuthRequest.MethodName.c_str(), APF_AUTH_PASSWORD,
			userAuthRequest.MethodName.size()) == 0) {

		if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(unsigned int) + 1) {
			ILIBMESSAGE("_apfUserAuthRequest6: Error receiving data from MEI\n");
			LME_Deinit(module);
			return;
		}

		++pCurrent;

		len = ntohl(*((unsigned int *)pCurrent));
		pCurrent += sizeof(unsigned int);

		if ((bytesRead - (pCurrent - rxBuffer)) < len) {
			ILIBMESSAGE("_apfUserAuthRequest7: Error receiving data from MEI\n");
			LME_Deinit(module);
			return;
		}

		AuthPasswordData authData;
		authData.Password.append((char *)pCurrent, len);
		pCurrent += len;

		userAuthRequest.MethodData = &authData;
	}

	module->_cb(module, module->_cbParam, &userAuthRequest, sizeof(userAuthRequest), status);
}
*/

unsigned int LME_GetMeiBufferSize(struct LMEConnection* module)
{
	return heci_GetBufferSize(&(module->mei));
}

#endif
