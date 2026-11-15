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

#ifndef LINUX_KVM_DMABUF_SYNC_H_
#define LINUX_KVM_DMABUF_SYNC_H_

#include <stddef.h>

typedef int (*kvm_dmabuf_wait_readable_fn)(void *context, unsigned int timeout_ms);
typedef int (*kvm_dmabuf_sync_fn)(void *context, int start);

typedef struct kvm_dmabuf_access_ops
{
	void *context;
	kvm_dmabuf_wait_readable_fn wait_readable;
	kvm_dmabuf_sync_fn sync;
} kvm_dmabuf_access_ops;

// Callback results are 1/0/-errno for wait and 0/-errno for sync.
int kvm_dmabuf_cpu_access(const kvm_dmabuf_access_ops *ops, int start,
	char *error, size_t error_size);

#endif
