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

#ifndef __HECI_LINUX_H__
#define __HECI_LINUX_H__

#include "HECI_if.h"
#include "mei.h"
#include <semaphore.h>
#include <stdint.h>

#ifndef bool
#define bool int
#endif

/***************************************************************************
 * Intel Advanced Management Technology ME Client
 ***************************************************************************/

#define AMT_MAJOR_VERSION 1
#define AMT_MINOR_VERSION 1

#define AMT_STATUS_SUCCESS                0x0
#define AMT_STATUS_INTERNAL_ERROR         0x1
#define AMT_STATUS_NOT_READY              0x2
#define AMT_STATUS_INVALID_AMT_MODE       0x3
#define AMT_STATUS_INVALID_MESSAGE_LENGTH 0x4

#define AMT_STATUS_HOST_IF_EMPTY_RESPONSE  0x4000
#define AMT_STATUS_SDK_RESOURCES      0x1004


#define AMT_BIOS_VERSION_LEN   65
#define AMT_VERSIONS_NUMBER    50
#define AMT_UNICODE_STRING_LEN 20

struct amt_unicode_string {
	uint16_t length;
	char string[AMT_UNICODE_STRING_LEN];
} __attribute__((packed));

struct amt_version_type {
	struct amt_unicode_string description;
	struct amt_unicode_string version;
} __attribute__((packed));

struct amt_version {
	uint8_t major;
	uint8_t minor;
} __attribute__((packed));

struct amt_code_versions {
	uint8_t bios[AMT_BIOS_VERSION_LEN];
	uint32_t count;
	struct amt_version_type versions[AMT_VERSIONS_NUMBER];
} __attribute__((packed));

struct mei {
	uuid_le guid;
	bool initialized;
	bool verbose;
	unsigned int buf_size;
	unsigned char prot_ver;
	int fd;
	sem_t Lock;
};

struct amt_host_if {
	struct mei mei_cl;
	unsigned long send_timeout;
	bool initialized;
};

struct MEImodule
{
	struct amt_code_versions ver;
	struct amt_host_if acmd;
	unsigned int i;
	unsigned int status;
	bool verbose;
	bool inited;
};

bool heci_Init(struct MEImodule* module, int client);
void heci_Deinit(struct MEImodule* module);
int heci_ReceiveMessage(struct MEImodule* module, unsigned char *buffer, int len, unsigned long timeout); // Timeout default is 2000
int heci_SendMessage(struct MEImodule* module, const unsigned char *buffer, int len, unsigned long timeout);  // Timeout default is 2000
unsigned int heci_GetBufferSize(struct MEImodule* module);
unsigned char heci_GetProtocolVersion(struct MEImodule* module);
bool heci_GetHeciVersion(struct MEImodule* module, HECI_VERSION *version);
bool heci_IsInitialized(struct MEImodule* module);

#endif	// __HECI_LINUX_H__
