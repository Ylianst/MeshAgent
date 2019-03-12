/*   
Copyright 2010 - 2011 Intel Corporation

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

#ifndef LINUX_KVM_H_
#define LINUX_KVM_H_

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <unistd.h>
#include <linux/stat.h>

#include "linux_tile.h"
#include "linux_events.h"
#include "microstack/ILibParsers.h"

typedef ILibTransport_DoneState(*ILibKVM_WriteHandler)(char *buffer, int bufferLen, void *reserved);

void kvm_set_x11_locations(char *libx11, char *libx11tst, char *libx11ext);
int kvm_relay_feeddata(char* buf, int len);
void kvm_pause(int pause);
void* kvm_relay_setup(void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid, char *authToken, char *dispid);
void kvm_relay_reset();
void kvm_cleanup();

#endif /* LINUX_KVM_H_ */
