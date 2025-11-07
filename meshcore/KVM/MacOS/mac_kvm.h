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

// Initialize dynamic paths based on binary location (call once at startup with argv[0])
int initialize_kvm_paths(const char *argv0);

void kvm_check_permission();

int kvm_create_session(void);      // Create KVM session on-demand (directory + signal file + socket)
void kvm_cleanup_session(void);    // Cleanup KVM session (triggers -kvm1 exit)
void kvm_pause(int pause);
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid);
void kvm_relay_reset(void *reserved);
void kvm_cleanup();

#endif /* LINUX_KVM_H_ */

