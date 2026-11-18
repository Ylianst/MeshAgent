/*
 *  mac_kvm.h
 *  
 *
 *  Created by Ylian Saint-Hilaire on 8/17/11.
 *  Copyright 2011 __MyCompanyName__. All rights reserved.
 *
 */
#ifndef LINUX_KVM_H_
#define LINUX_KVM_H_

#include <ApplicationServices/ApplicationServices.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <unistd.h>

#include "mac_tile.h"
#include "mac_events.h"
#include "../../../microstack/ILibParsers.h"

typedef ILibTransport_DoneState(*ILibKVM_WriteHandler)(char *buffer, int bufferLen, void *reserved);

int kvm_permissions(void);
// What the prompt does with its own process once Screen Recording was granted, which only a new process can use
#define KVM_PROMPT_RESTART 1		// The LaunchAgent, restarted through launchd
#define KVM_PROMPT_EXIT 2			// The -kvm0 child, the next session starts a new one
void kvm_permission_prompt_start(int onGrant);
void kvm_flags_prepare(void);

int kvm_relay_feeddata(char* buf, int len);
void kvm_pause(int pause);
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid);
void kvm_set_listener_path(const char *path);
void kvm_socket_path(char *buf, size_t bufLen, unsigned int uid, int legacy);
void kvm_relay_reset();
void kvm_cleanup();
// In agentcore.c, called when the -kvm0 child of a session exits
void ILibDuktape_MeshAgent_RemoteDesktop_KVM_Exited(void *reserved);

#endif /* LINUX_KVM_H_ */

