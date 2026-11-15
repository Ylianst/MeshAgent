/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_KVM_PEER_MESSAGE_H
#define MESH_KVM_PEER_MESSAGE_H
#if defined(__linux__)
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* SO_PEERCRED names the socket creator, not a later holder. Verify the kernel
 * sender on each reply before trusting status or sending remote input. */
static int kvm_peer_recv(int fd, void *buffer, size_t size, pid_t pid, uid_t uid)
{
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(4 * sizeof(int))]; } control;
    struct iovec iov = { buffer, size };
    struct msghdr message = {0};
    struct ucred sender = {0};
    int credentials = 0, unexpected = 0;
    message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
    ssize_t n = recvmsg(fd, &message, 0);
    if (n <= 0) return (int)n;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
    {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(0))
        {
            size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int *fds = (int *)CMSG_DATA(c);
            for (size_t i = 0; i < count; i++) close(fds[i]);
            unexpected = 1;
        }
        else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS && c->cmsg_len == CMSG_LEN(sizeof(sender)) && !credentials)
        { memcpy(&sender, CMSG_DATA(c), sizeof(sender)); credentials = 1; }
        else unexpected = 1;
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || unexpected || credentials != 1 || sender.pid != pid || sender.uid != uid)
    { errno = EPERM; return -1; }
    return (int)n;
}
#endif
#endif
