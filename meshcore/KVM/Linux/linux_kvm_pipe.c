/*
Copyright 2026

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

#include "linux_kvm_pipe.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

static pthread_mutex_t g_kvmPipeWriteLock = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t *kvm_pipe_write_lock(void)
{
	return &g_kvmPipeWriteLock;
}

int kvm_pipe_write_packet(int fd, const char *buffer, size_t len, const volatile int *abortFlag)
{
	size_t offset = 0;
	int result = 0;

	if (fd < 0 || buffer == NULL) { return -1; }

	pthread_mutex_lock(&g_kvmPipeWriteLock);
	while (offset < len)
	{
		ssize_t written = write(fd, buffer + offset, len - offset);
		if (written > 0) { offset += (size_t)written; continue; }
		if (written < 0 && errno == EINTR) { continue; }
		if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		{
			// A non-blocking pipe with no room right now (the master applies backpressure by not reading it): wait for room
			// instead of giving up on the rest of the packet. A packet that is abandoned half way cannot be recovered.
			struct pollfd pfd;
			pfd.fd = fd;
			pfd.events = POLLOUT;
			pfd.revents = 0;
			if (abortFlag != NULL && *abortFlag != 0) { result = -1; break; }
			if (poll(&pfd, 1, 1000) < 0 && errno != EINTR) { result = -1; break; }
			if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) { result = -1; break; }
			continue;
		}
		result = -1;	// The master closed its end (EPIPE), or the write failed
		break;
	}
	pthread_mutex_unlock(&g_kvmPipeWriteLock);
	return result;
}
