/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_KVM_SYSCALL_COMPAT_H
#define MESH_KVM_SYSCALL_COMPAT_H
#if defined(__linux__)
#include <sys/syscall.h>
/* Stable Linux UAPI numbers, shared by x86, ARM EABI and asm-generic (AArch64).
 * Keep the existing old-glibc sysroots; feature availability is checked against
 * the running kernel, never replaced by a UID-only authentication fallback.
 * Source: Linux v5.4 arch/{x86/entry/syscalls,arm/tools}/syscall*.tbl and
 * include/uapi/asm-generic/unistd.h. */
#if defined(__x86_64__) && defined(__ILP32__)
#define MESH_KVM_LATE_SYSCALL_BASE 0x40000000u
#elif defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || (defined(__arm__) && defined(__ARM_EABI__))
#define MESH_KVM_LATE_SYSCALL_BASE 0u
#endif
#ifdef MESH_KVM_LATE_SYSCALL_BASE
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal (MESH_KVM_LATE_SYSCALL_BASE + 424u)
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open (MESH_KVM_LATE_SYSCALL_BASE + 434u)
#endif
#ifndef SYS_clone3
#define SYS_clone3 (MESH_KVM_LATE_SYSCALL_BASE + 435u)
#endif
#endif
#if defined(__i386__)
#ifndef SYS_sendmsg
#define SYS_sendmsg 370
#endif
#ifndef SYS_recvmsg
#define SYS_recvmsg 372
#endif
#endif
#endif
#endif
