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

#include "linux_kvm_dmabuf_sync.h"

#include <stdio.h>

static void kvm_dmabuf_set_error(char *error, size_t error_size, const char *operation, int result)
{
	if (error == NULL || error_size == 0) { return; }
	if (result < 0) { snprintf(error, error_size, "%s (errno=%d)", operation, -result); }
	else { snprintf(error, error_size, "%s", operation); }
}

int kvm_dmabuf_cpu_access(const kvm_dmabuf_access_ops *ops, int start,
	char *error, size_t error_size)
{
	int result;
	if (ops == NULL || ops->sync == NULL || (start && ops->wait_readable == NULL))
	{
		kvm_dmabuf_set_error(error, error_size, "DMA-BUF CPU access operations are unavailable", 0);
		return 0;
	}
	if (start)
	{
		result = ops->wait_readable(ops->context, 100);
		if (result == 0)
		{
			kvm_dmabuf_set_error(error, error_size, "Timed out waiting for DMA-BUF producer", 0);
			return 0;
		}
		if (result < 0)
		{
			kvm_dmabuf_set_error(error, error_size, "Failed waiting for DMA-BUF producer", result);
			return 0;
		}
	}

	result = ops->sync(ops->context, start);
	if (result < 0)
	{
		kvm_dmabuf_set_error(error, error_size,
			start ? "DMA-BUF CPU access start failed" : "DMA-BUF CPU access end failed", result);
		return 0;
	}
	return 1;
}
