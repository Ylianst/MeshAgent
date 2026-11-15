/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_KVM_CAPTURE_HELPER_H
#define MESH_KVM_CAPTURE_HELPER_H
#include <stdint.h>
#include <sys/types.h>
#include <sys/select.h>
#include "linux_kvm_wayland.h"

#define KVM_CAPTURE_HELPER_ROLE "--meshagent-kwin-capture-helper"
#define KVM_CAPTURE_HELPER_TIMEOUT 2500
typedef struct kvm_capture_broker kvm_capture_broker;
/**
 * @file linux_kvm_capture_helper.h
 * Capture-only connection broker for the Agent's protected capture worker.
 *
 * The privileged parent owns the broker; the nondumpable desktop-UID worker
 * owns the worker API. Neither channel carries input or Agent identity data.
 * Calls on each side are serialized by that process's existing event loop.
 */

/** Dispatch an internal exec role before Agent configuration/identity startup.
 * @return -1 for an ordinary invocation; otherwise the internal role's exit code.
 */
int kvm_capture_helper_dispatch(int argc, char **argv);
/** Create a parent-side broker for one pinned direct child and generation.
 * Consumes fd on both success and failure. NULL leaves native capture available.
 */
kvm_capture_broker *kvm_capture_broker_new(int fd, pid_t worker, uid_t uid, uint64_t generation);
/** Copy up to six borrowed channel/pidfd descriptors into the caller's array.
 * The broker retains ownership; callers must not close or read these themselves.
 */
int kvm_capture_broker_fds(kvm_capture_broker *broker, int fds[6]);
/** Return the borrowed readiness-proof descriptor awaiting output, or -1. */
int kvm_capture_broker_write_fd(kvm_capture_broker *broker);
/** Add broker interests to initialized, non-NULL select sets without blocking.
 * Returns 0 before modifying any set if a descriptor exceeds FD_SETSIZE.
 * A proof awaiting output is write-only to avoid readable-channel busy loops.
 */
int kvm_capture_broker_select(kvm_capture_broker *broker, fd_set *readset, fd_set *writeset, fd_set *errorset);
/** Return the absolute monotonic-millisecond phase deadline, or 0 if none. */
uint64_t kvm_capture_broker_deadline(kvm_capture_broker *broker);
/** Advance available protocol work and enforce deadlines/pinned lifetimes.
 * The parent calls this after readiness or timer wakeups; it does not wait.
 */
void kvm_capture_broker_step(kvm_capture_broker *broker);
/** Destroy broker state and close its channels and identity pins.
 * @return -1, or an owned helper pidfd to reap asynchronously and then close.
 */
int kvm_capture_broker_free(kvm_capture_broker *broker);
/** Signal/reap only the pinned helper, without resolving a numeric PID again.
 * Returns 1 when reaped/already reaped, 0 while pending. Caller closes the pidfd.
 */
int kvm_capture_helper_reap(int pidfd);
/** Consume the worker's private channel and pin its parent; reset old state. */
void kvm_capture_worker_attach(int fd, pid_t parent, uint64_t generation);
/** Obtain an authenticated compositor socket for the selected session/display.
 * May wait up to KVM_CAPTURE_HELPER_TIMEOUT. Success transfers socket ownership
 * to the caller; -1 releases worker broker state. Worker remains nondumpable.
 */
int kvm_capture_worker_connect(const kvm_wayland_console_session *session, const char *display);
/** Request the helper's restricted steady state; return 1 only after its ACK. */
int kvm_capture_worker_seal(void);
/** Check all pinned participants/channel; no numeric PID or UID-only fallback. */
int kvm_capture_worker_alive(void);
/** Close worker-owned control/pidfd state, not the returned compositor socket. */
void kvm_capture_worker_release(void);
#endif
