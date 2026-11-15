/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_KVM_BRIDGE_AUTH_H
#define MESH_KVM_BRIDGE_AUTH_H
#if defined(__linux__)
#include <sys/stat.h>
#include <sys/syscall.h>
#include "linux_kvm_syscall_compat.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <stdint.h>
#include <errno.h>
#ifndef KVM_BRIDGE_SCRIPT
#define KVM_BRIDGE_SCRIPT "/usr/local/lib/meshagent-kwin-wire/wire_bridge.py"
#endif
#define KVM_WORKER_DIRECTORY "/run/meshagent-kwin-workers"
/** Read parent PID and Linux start ticks; a PID alone is not a lifetime ID.
 * The final ')' terminates comm, which may itself contain spaces/parentheses.
 * Callers combine these observations with pidfds and repeat identity checks.
 */
static __attribute__((unused)) int kvm_bridge_process(pid_t pid, pid_t *parent, unsigned long long *start)
{
    char path[64], data[4096], *p, *save, *token; int fd, n, field = 3;
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    n = read(fd, data, sizeof(data)-1); close(fd); if (n <= 0) return 0;
    data[n] = 0; p = strrchr(data, ')'); if (!p) return 0;
    for (token = strtok_r(p+2, " ", &save); token; token = strtok_r(NULL, " ", &save), ++field)
    {
        if (field == 4) *parent = (pid_t)strtol(token, NULL, 10);
        if (field == 22) { *start = strtoull(token, NULL, 10); return *start != 0; }
    }
    return 0;
}
/** Resolve symlinks, then require every resolved component to be root-owned
 * and unwritable by group/other. Ownership of the final script alone is unsafe
 * if a desktop user can replace a containing directory.
 */
static __attribute__((unused)) int kvm_bridge_trusted_path(const char *path)
{
    char resolved[4096]; struct stat st; char *p;
    if (!realpath(path, resolved)) return 0;
    for (p = resolved+1; ; ++p)
    {
        if (*p && *p != '/') continue;
        char saved = *p; *p = 0;
        if (lstat(resolved, &st) || st.st_uid != 0 || (st.st_mode & 022)) return 0;
        *p = saved; if (!saved) break;
    }
    return 1;
}
/** Authenticate a kernel-reported peer against an independently pinned KWin.
 * Require the intended isolated Python invocation and trusted installed script,
 * plus direct parentage and unchanged live start times. This is a point-in-time
 * check, not a transferable authorization token: authenticate every connection
 * before writing protocol bytes. A returned epoch or matching UID is insufficient.
 */
static __attribute__((unused)) int kvm_bridge_server(pid_t pid, pid_t compositor, unsigned long long expectedStart)
{
    const char *script = KVM_BRIDGE_SCRIPT;
    char path[64], args[4096], exe[4096], python[4096];
    pid_t parent, afterParent; unsigned long long start, afterStart, compositorStart;
    struct pollfd pins[2]; int fd, n, ok = 0;
    if (pid <= 0 || compositor <= 0) return 0;
#ifdef SYS_pidfd_open
    pins[0].fd = syscall(SYS_pidfd_open, pid, 0);
    pins[1].fd = syscall(SYS_pidfd_open, compositor, 0);
#else
    return 0;
#endif
    pins[0].events = pins[1].events = POLLIN;
    if (pins[0].fd < 0 || pins[1].fd < 0) goto done;
    if (!kvm_bridge_process(pid, &parent, &start) || parent != compositor ||
        !kvm_bridge_process(compositor, &afterParent, &compositorStart) || compositorStart != expectedStart ||
        !kvm_bridge_trusted_path(script) || !kvm_bridge_trusted_path("/usr/bin/python3")) goto done;
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    n = readlink(path, exe, sizeof(exe)-1); if (n <= 0) goto done; exe[n] = 0;
    if (!realpath("/usr/bin/python3", python) || strcmp(exe, python)) goto done;
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) goto done;
    n = read(fd, args, sizeof(args)); close(fd);
    /* Fixed prefix; subsequent arguments belong to the stock input method. */
    if (n < (int)(sizeof("/usr/bin/python3\0-I\0")-1 + strlen(script)+1) ||
        memcmp(args, "/usr/bin/python3\0-I\0", sizeof("/usr/bin/python3\0-I\0")-1) ||
        memcmp(args+sizeof("/usr/bin/python3\0-I\0")-1, script, strlen(script)+1)) goto done;
    if (!kvm_bridge_process(pid, &afterParent, &afterStart) || afterParent != parent || afterStart != start || poll(pins, 2, 0) != 0) goto done;
    ok = 1;
done:
    if (pins[0].fd >= 0) close(pins[0].fd);
    if (pins[1].fd >= 0) close(pins[1].fd);
    return ok;
}
/** Publish/remove the privileged parent's designated-worker registration.
 * Atomic rename prevents readers seeing partial records; the root-owned,
 * non-writable directory and no-follow opens prevent desktop-user replacement.
 * Record both process lifetimes and the session UID. Readers must still pin and
 * validate live processes: the presence of a record never authorizes a reused PID.
 */
static __attribute__((unused)) int kvm_bridge_worker_record(pid_t worker, uid_t uid, int removeRecord)
{
    int directory, fd, result = 0; struct stat st; char name[40], temporary[64], record[256];
    pid_t parent, ignored; unsigned long long workerStart, parentStart;
    if (geteuid() != 0) return 0;
    if (mkdir(KVM_WORKER_DIRECTORY, 0755) && errno != EEXIST) return 0;
    directory = open(KVM_WORKER_DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return 0;
    if (fstat(directory, &st) || st.st_uid || (st.st_mode & 022) || fchmod(directory, 0755)) goto done;
    snprintf(name, sizeof(name), "%d", (int)worker);
    if (removeRecord) { result = unlinkat(directory, name, 0) == 0 || errno == ENOENT; goto done; }
    if (!kvm_bridge_process(worker, &parent, &workerStart) || parent != getpid() ||
        !kvm_bridge_process(getpid(), &ignored, &parentStart)) goto done;
    snprintf(temporary, sizeof(temporary), ".%d.%d", (int)getpid(), (int)worker);
    fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) goto done;
    int length = snprintf(record, sizeof(record), "1 %d %llu %d %llu %u\n", (int)worker, workerStart, (int)getpid(), parentStart, (unsigned)uid);
    result = fchmod(fd, 0644) == 0 && write(fd, record, length) == length;
    close(fd);
    if (result) result = renameat(directory, temporary, directory, name) == 0;
    unlinkat(directory, temporary, 0);
done:
    close(directory); return result;
}
#endif
#endif
