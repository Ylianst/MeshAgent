/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "meshcore/KVM/Linux/linux_kvm_peer_message.h"
#include <assert.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>

int main(void)
{
    int sockets[2], enabled = 1;
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (child == 0)
    {
        close(sockets[0]);
        assert(write(sockets[1], "AB", 2) == 2);
        int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(descriptor >= 0);
        char value = 'C'; struct iovec iov = { &value, 1 };
        union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
        struct msghdr message = {0};
        message.msg_iov = &iov; message.msg_iovlen = 1;
        message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&message);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &descriptor, sizeof(descriptor));
        assert(sendmsg(sockets[1], &message, 0) == 1);
        close(descriptor); close(sockets[1]); _exit(0);
    }
    close(sockets[1]); char value;
    assert(kvm_peer_recv(sockets[0], &value, 1, child, getuid()) == 1 && value == 'A');
    errno = EAGAIN;
    assert(kvm_peer_recv(sockets[0], &value, 1, child + 1, getuid()) == -1 && errno == EPERM);
    assert(kvm_peer_recv(sockets[0], &value, 1, child, getuid()) == -1 && errno == EPERM);
    close(sockets[0]); int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("Authenticated sender accepted; mismatched sender and ancillary FD rejected");
}
