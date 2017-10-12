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

#ifndef __HECI_WIN_H__
#define __HECI_WIN_H__

#include "HECI_if.h"

#include <stdio.h>
#include <windows.h>
#define bool int

struct MEImodule
{
	bool _initialized;
	bool _verbose;
	unsigned int  _bufSize;
	unsigned char _protocolVersion;
	int _fd;
	bool m_haveHeciVersion;
	HECI_VERSION m_heciVersion;
	HANDLE _handle;
	OVERLAPPED overlapped;
};

bool heci_Init(struct MEImodule* module, int client);
void heci_Deinit(struct MEImodule* module);
int heci_ReceiveMessage(struct MEImodule* module, unsigned char *buffer, int len, unsigned long timeout); // Timeout default is 2000
int heci_SendMessage(struct MEImodule* module, const unsigned char *buffer, int len, unsigned long timeout);  // Timeout default is 2000
unsigned int heci_GetBufferSize(struct MEImodule* module);
unsigned char heci_GetProtocolVersion(struct MEImodule* module);
bool heci_GetHeciVersion(struct MEImodule* module, HECI_VERSION *version);
bool heci_IsInitialized(struct MEImodule* module);

#endif	// __HECI_WIN_H__

#endif
