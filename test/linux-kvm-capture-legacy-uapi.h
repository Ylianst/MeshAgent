/* Hide late UAPI declarations to exercise old-header builds on a current kernel. */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#undef SYS_clone3
#undef SYS_pidfd_open
#undef SYS_pidfd_send_signal
#undef CLONE_PIDFD
#undef PR_CAP_AMBIENT
#undef PR_CAP_AMBIENT_CLEAR_ALL
#undef SECCOMP_RET_KILL_PROCESS
#undef SYS_close_range
