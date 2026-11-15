/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gala_consent.h"
#if defined(__linux__)
#include "linux_kvm_gala.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef MESH_GALA_CONSENT_IMAGE
#define MESH_GALA_CONSENT_IMAGE "addons/gala/activate"
#endif
__asm__(".pushsection .rodata\n.balign 8\n.global mesh_gala_consent_start\nmesh_gala_consent_start:\n.incbin \"" MESH_GALA_CONSENT_IMAGE "\"\n.global mesh_gala_consent_end\nmesh_gala_consent_end:\n.popsection\n");
extern const unsigned char mesh_gala_consent_start[],mesh_gala_consent_end[];
static uint64_t now(void){struct timespec t;return clock_gettime(CLOCK_MONOTONIC,&t)?0:(uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
int mesh_gala_offer_signout(void){
    kvm_gala_target target;int fd=-1,status=0;
    if(geteuid()!=0||getuid()!=0||!kvm_gala_find_target(&target)||kvm_gala_available())return 3;
    fd=(int)syscall(SYS_memfd_create,"meshagent-gala-setup",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(fd<0)return 3;
    const unsigned char *bytes=mesh_gala_consent_start;size_t size=(size_t)(mesh_gala_consent_end-bytes),offset=0;
    while(offset<size){ssize_t n=write(fd,bytes+offset,size-offset);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return 3;}offset+=(size_t)n;}
    if(fchmod(fd,0555)||fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)){close(fd);return 3;}
    char pid[32];snprintf(pid,sizeof(pid),"%d",target.pid);
    char *args[]={"meshagent-gala-setup",pid,target.session.id,NULL};
    char *environment[]={"PATH=/usr/bin:/bin","LANG=C.UTF-8",NULL};
    long limit=sysconf(_SC_OPEN_MAX);if(limit<0||limit>1048576)limit=1048576;
    pid_t child=fork();
    if(child<0){close(fd);return 3;}
    if(child==0){
        /* Only async-signal-safe operations until a fresh executable image.
         * Account lookup and privilege drop happen there, before loading Gtk. */
        setpgid(0,0);
        if(fd!=3){if(dup2(fd,3)<0)_exit(3);close(fd);}
        if(fcntl(3,F_SETFD,FD_CLOEXEC)<0)_exit(3);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        if(null<0||dup2(null,0)<0||dup2(null,1)<0||dup2(null,2)<0)_exit(3);
        if(null>3)close(null);
#ifdef SYS_close_range
        if(syscall(SYS_close_range,4u,~0u,0u))
#endif
        {for(int i=4;i<limit;++i)close(i);}
#ifdef SYS_execveat
        syscall(SYS_execveat,3,"",args,environment,AT_EMPTY_PATH);
#else
        fexecve(3,args,environment);
#endif
        _exit(3);
    }
    close(fd);setpgid(child,child);uint64_t deadline=now()+55000;
    for(;;){pid_t result=waitpid(child,&status,WNOHANG);if(result==child)break;if(result<0&&errno!=EINTR)return 3;
        if(now()>=deadline){kill(-child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}return 3;}poll(NULL,0,50);}
    return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:(WIFEXITED(status)&&WEXITSTATUS(status)==2?2:3);
}
#else
int mesh_gala_offer_signout(void){return 3;}
#endif
