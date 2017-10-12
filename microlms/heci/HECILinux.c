/******************************************************************************
 * Intel Management Engine Interface (Intel MEI) Linux driver
 * Intel MEI Interface Header
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *	Intel Corporation.
 *	linux-mei@linux.intel.com
 *	http://www.intel.com
 *
 * BSD LICENSE
 *
 * Copyright(c) 2003 - 2012 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include "HECILinux.h"
//#include "../core/utils.h"

/*****************************************************************************
 * Intel Management Engine Interface
 *****************************************************************************/

#ifdef _HECIDEBUG
	#define mei_msg(_me, fmt, ARGS...) do { printf(fmt, ##ARGS); } while (0)
	#define mei_err(_me, fmt, ARGS...) do { printf(fmt, ##ARGS); } while (0)
#else
	#define mei_msg(_me, fmt, ARGS...)
	#define mei_err(_me, fmt, ARGS...)
#endif

static void mei_deinit(struct mei *cl)
{
	// mei_err(cl, "mei_deinit()\n");
	if (cl->initialized == false) return;
	cl->initialized = false;
	if (cl->fd != -1) close(cl->fd);
	cl->fd = -1;
	cl->buf_size = 0;
	cl->prot_ver = 0;
	sem_destroy(&(cl->Lock));
}

static bool mei_init(struct mei *me, const uuid_le *guid, unsigned char req_protocol_version, bool verbose)
{
	int result;
	struct mei_client *cl;
	struct mei_connect_client_data data;

	mei_deinit(me);

	me->verbose = verbose;

	me->fd = open("/dev/mei", O_RDWR);
	if (me->fd == -1) {
		me->fd = open("/dev/mei0", O_RDWR);
		if (me->fd == -1) {
			// mei_err(me, "Cannot establish a handle to the Intel MEI driver\n");
			goto err;
		}
	}
	memcpy(&me->guid, guid, sizeof(*guid));
	memset(&data, 0, sizeof(data));
	me->initialized = true;

	memcpy(&data.in_client_uuid, &me->guid, sizeof(me->guid));
	result = ioctl(me->fd, IOCTL_MEI_CONNECT_CLIENT, &data);
	if (result) {
		mei_err(me, "IOCTL_MEI_CONNECT_CLIENT receive message. err=%d,%d\n", result, errno);
		goto err;
	}
	cl = &data.out_client_properties;
	//mei_msg(me, "max_message_length %d\n", cl->max_msg_length);
	//mei_msg(me, "protocol_version %d\n", cl->protocol_version);

	if ((req_protocol_version > 0) && (cl->protocol_version != req_protocol_version)) {
		mei_err(me, "Intel MEI protocol version not supported\n");
		goto err;
	}

	me->buf_size = cl->max_msg_length;
	me->prot_ver = cl->protocol_version;
	sem_init(&(me->Lock), 0, 1);

	mei_msg(me, "mei init succ");
	return true;
err:
	mei_deinit(me);
	return false;
}

static ssize_t mei_recv_msg(struct mei *me, unsigned char *buffer, ssize_t len, unsigned long timeout)
{
	ssize_t rc;

	mei_msg(me, "call read length = %zd\n", len);
	rc = read(me->fd, buffer, len);
	if (rc < 0) {
		mei_err(me, "read failed with status %zd %s\n", rc, strerror(errno));
		mei_deinit(me);
	} else {
		mei_msg(me, "read succeeded with result %zd\n", rc);
	}
	return rc;
}

static ssize_t mei_send_msg(struct mei *me, const unsigned char *buffer, ssize_t len, unsigned long timeout)
{
//	struct timeval tv;
	ssize_t written;
	ssize_t rc;
//	fd_set set;

//	tv.tv_sec = timeout / 1000;
//	tv.tv_usec = (timeout % 1000) * 1000000;

	mei_msg(me, "call write length = %zd, cmd=%d\n", len, (int)buffer[0]);

	sem_wait(&(me->Lock));

	written = write(me->fd, buffer, len);
	if (written < 0) {
		rc = -errno;
		mei_err(me, "write failed with status %zd %s\n", written, strerror(errno));
		goto out;
	}

/*
	FD_ZERO(&set);
	FD_SET(me->fd, &set);
	rc = select(me->fd + 1 , &set, NULL, NULL, &tv);
	if (rc > 0 && FD_ISSET(me->fd, &set)) {
		mei_msg(me, "write success\n");
	} else if (rc == 0) {
		mei_err(me, "write failed on timeout with status 0, timeout = %ld, written=%ld, cmd=%d\n", timeout, written, (int)buffer[0]);
		goto out;
	} else { // rc < 0
		mei_err(me, "write failed on select with status %zd\n", rc);
		goto out;
	}
*/
	rc = written;
out:
	sem_post(&(me->Lock));
	mei_msg(me, "call write written = %zd\n", written);
	if (rc < 0) mei_deinit(me);
	return rc;
}

/***************************************************************************
 * Intel Advanced Management Technology Host Interface
 ***************************************************************************/

struct amt_host_if_msg_header {
	struct amt_version version;
	uint16_t _reserved;
	uint32_t command;
	uint32_t length;
} __attribute__((packed));

struct amt_host_if_resp_header {
	struct amt_host_if_msg_header header;
	uint32_t status;
	unsigned char data[0];
} __attribute__((packed));

const uuid_le MEI_IAMTHIF = {.b={0x28, 0x00, 0xf8, 0x12, 0xb7, 0xb4, 0x2d, 0x4b, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c}};
const uuid_le MEI_LMEIF   = {.b={0xdb, 0xa4, 0x33, 0x67, 0x76, 0x04, 0x7b, 0x4e, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7}};

#define AMT_HOST_IF_CODE_VERSIONS_REQUEST  0x0400001A
#define AMT_HOST_IF_CODE_VERSIONS_RESPONSE 0x0480001A

const struct amt_host_if_msg_header CODE_VERSION_REQ = {
	.version = {AMT_MAJOR_VERSION, AMT_MINOR_VERSION},
	._reserved = 0,
	.command = AMT_HOST_IF_CODE_VERSIONS_REQUEST,
	.length = 0
};


static bool amt_host_if_init(struct amt_host_if *acmd, unsigned long send_timeout, bool verbose, int client)
{
	acmd->send_timeout = (send_timeout) ? send_timeout : 20000;
	if (client == 0) { acmd->initialized = mei_init(&acmd->mei_cl, &MEI_IAMTHIF, 0, verbose); }
	else if (client == 1) { acmd->initialized = mei_init(&acmd->mei_cl, &MEI_LMEIF, 0, verbose); }
	return acmd->initialized;
}

static void amt_host_if_deinit(struct amt_host_if *acmd)
{
	mei_deinit(&acmd->mei_cl);
	acmd->initialized = false;
}

static uint32_t amt_verify_code_versions(const struct amt_host_if_resp_header *resp)
{
	uint32_t status = AMT_STATUS_SUCCESS;
	struct amt_code_versions *code_ver;
	size_t code_ver_len;
	uint32_t ver_type_cnt;
	uint32_t len;
	uint32_t i;

	code_ver = (struct amt_code_versions *)resp->data;
	/* length - sizeof(status) */
	code_ver_len = resp->header.length - sizeof(uint32_t);
	ver_type_cnt = code_ver_len -
			sizeof(code_ver->bios) -
			sizeof(code_ver->count);
	if (code_ver->count != ver_type_cnt / sizeof(struct amt_version_type)) {
		status = AMT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	for (i = 0; i < code_ver->count; i++) {
		len = code_ver->versions[i].description.length;

		if (len > AMT_UNICODE_STRING_LEN) {
			status = AMT_STATUS_INTERNAL_ERROR;
			goto out;
		}

		len = code_ver->versions[i].version.length;
		if (code_ver->versions[i].version.string[len] != '\0' ||
		    len != strlen(code_ver->versions[i].version.string)) {
			status = AMT_STATUS_INTERNAL_ERROR;
			goto out;
		}
	}
out:
	return status;
}

static uint32_t amt_verify_response_header(uint32_t command, const struct amt_host_if_msg_header *resp_hdr, uint32_t response_size)
{
	if (response_size < sizeof(struct amt_host_if_resp_header)) {
		return AMT_STATUS_INTERNAL_ERROR;
	} else if (response_size != (resp_hdr->length +
				sizeof(struct amt_host_if_msg_header))) {
		return AMT_STATUS_INTERNAL_ERROR;
	} else if (resp_hdr->command != command) {
		return AMT_STATUS_INTERNAL_ERROR;
	} else if (resp_hdr->_reserved != 0) {
		return AMT_STATUS_INTERNAL_ERROR;
	} else if (resp_hdr->version.major != AMT_MAJOR_VERSION ||
		   resp_hdr->version.minor < AMT_MINOR_VERSION) {
		return AMT_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

static uint32_t amt_host_if_call(struct amt_host_if *acmd, const unsigned char *command, ssize_t command_sz, uint8_t **read_buf, uint32_t rcmd, unsigned int expected_sz)
{
	uint32_t in_buf_sz;
	uint32_t out_buf_sz;
	ssize_t written;
	uint32_t status;
	struct amt_host_if_resp_header *msg_hdr;

	in_buf_sz = acmd->mei_cl.buf_size;
	*read_buf = (uint8_t *)malloc(sizeof(uint8_t) * in_buf_sz);
	if (*read_buf == NULL) return AMT_STATUS_SDK_RESOURCES;
	memset(*read_buf, 0, in_buf_sz);
	msg_hdr = (struct amt_host_if_resp_header *)*read_buf;

	written = mei_send_msg(&acmd->mei_cl, command, command_sz, acmd->send_timeout);
	if (written != command_sz)
		return AMT_STATUS_INTERNAL_ERROR;

	out_buf_sz = mei_recv_msg(&acmd->mei_cl, *read_buf, in_buf_sz, 2000);
	if (out_buf_sz <= 0)
		return AMT_STATUS_HOST_IF_EMPTY_RESPONSE;

	status = msg_hdr->status;
	if (status != AMT_STATUS_SUCCESS)
		return status;

	status = amt_verify_response_header(rcmd, &msg_hdr->header, out_buf_sz);
	if (status != AMT_STATUS_SUCCESS)
		return status;

	if (expected_sz && expected_sz != out_buf_sz)
		return AMT_STATUS_INTERNAL_ERROR;

	return AMT_STATUS_SUCCESS;
}


static uint32_t amt_get_code_versions(struct amt_host_if *cmd, struct amt_code_versions *versions)
{
	struct amt_host_if_resp_header *response = NULL;
	uint32_t status;

	status = amt_host_if_call(cmd,
			(const unsigned char *)&CODE_VERSION_REQ,
			sizeof(CODE_VERSION_REQ),
			(uint8_t **)&response,
			AMT_HOST_IF_CODE_VERSIONS_RESPONSE, 0);

	if (status != AMT_STATUS_SUCCESS)
		goto out;

	status = amt_verify_code_versions(response);
	if (status != AMT_STATUS_SUCCESS)
		goto out;

	memcpy(versions, response->data, sizeof(struct amt_code_versions));
out:
	if (response != NULL)
		free(response);

	return status;
}

/************************** end of amt_host_if_command ***********************/

int MEI_globalSetup = 0;
struct MEImodule MEI_global;

bool heci_Init(struct MEImodule* module, int client)
{
	if (module == NULL && client != 0) return false;
	if (module == NULL) { module = &MEI_global; if (MEI_globalSetup == 1) return true; }
	memset(module, 0 , sizeof(struct MEImodule));
	if (!amt_host_if_init(&(module->acmd), 5000, module->verbose, client)) return false;
	if (module == &MEI_global) MEI_globalSetup = 1;
	module->inited = true;
	if (client == 0) module->status = amt_get_code_versions(&(module->acmd), &(module->ver));
	return true;
}

void heci_Deinit(struct MEImodule* module)
{
	if (module == NULL) { module = &MEI_global; MEI_globalSetup = 0; }
	amt_host_if_deinit(&(module->acmd));
	memset(module, 0, sizeof(struct MEImodule));
}

int heci_ReceiveMessage(struct MEImodule* module, unsigned char *buffer, int len, unsigned long timeout) // Timeout default is 2000
{
	if (module == NULL) module = &MEI_global;
	return mei_recv_msg(&(module->acmd.mei_cl), buffer, len, timeout);
}

int heci_SendMessage(struct MEImodule* module, const unsigned char *buffer, int len, unsigned long timeout) // Timeout default is 2000
{
	if (module == NULL) module = &MEI_global;
	return mei_send_msg(&(module->acmd.mei_cl), buffer, len, timeout);
}

unsigned int heci_GetBufferSize(struct MEImodule* module)
{
	if (module == NULL) module = &MEI_global;
	if (module->inited) return module->acmd.mei_cl.buf_size;
	return -1;
}

unsigned char heci_GetProtocolVersion(struct MEImodule* module)
{
	if (module == NULL) module = &MEI_global;
	if (module->inited) return module->acmd.mei_cl.prot_ver;
	return 0;
}

// Get the version of MEI from the last MEI init.
bool heci_GetHeciVersion(struct MEImodule* module, HECI_VERSION *version)
{
	version->major = AMT_MAJOR_VERSION;
	version->minor = AMT_MINOR_VERSION;
	return true;
}

bool heci_IsInitialized(struct MEImodule* module)
{
	return module->inited;
}

