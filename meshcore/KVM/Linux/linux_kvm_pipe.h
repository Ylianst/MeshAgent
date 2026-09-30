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

#ifndef LINUX_KVM_PIPE_H_
#define LINUX_KVM_PIPE_H_

#include <stddef.h>
#include <pthread.h>

/*
 * Writing to the KVM slave -> master pipe from more than one thread.
 *
 * Besides the screen capture on the slave's main thread, the audio, microphone and camera capture each have a thread of
 * their own that sends its frames down the same pipe. A pipe write is only atomic up to PIPE_BUF (4 KiB), so a frame that
 * is larger than that, or written while the pipe is nearly full, can be split, and bytes from two writers would then be
 * interleaved into two corrupt packets. And the Wayland/DRM screen capture keeps the pipe non-blocking, where write()
 * returns after a partial write (or EAGAIN) instead of waiting, and a caller that ignores that truncates the packet.
 *
 * kvm_pipe_write_packet() is the one way to write a packet from a thread: it holds a lock for the whole packet and waits
 * for room when the pipe is non-blocking. The DRM capture thread takes the same lock (kvm_pipe_write_lock()) around its
 * own packets, without ever blocking on it while viewer input is waiting to be read, see kvm_drm_write_all().
 */

/* Writes all len bytes of one packet to fd. Returns 0, or -1 if the reader went away, the write failed, or *abortFlag
   became non-zero while it was waiting for room (abortFlag may be NULL). */
int kvm_pipe_write_packet(int fd, const char *buffer, size_t len, const volatile int *abortFlag);

/* The lock kvm_pipe_write_packet() holds while it writes a packet. */
pthread_mutex_t *kvm_pipe_write_lock(void);

/* kvm_pipe_write_packet() for the slave's pipe, with the slave's shutdown flag as the abort flag. For the audio, microphone
   and camera threads (linux_kvm.c). */
int kvm_slave_write_from_thread(int fd, const char *buffer, size_t len);

#endif /* LINUX_KVM_PIPE_H_ */
