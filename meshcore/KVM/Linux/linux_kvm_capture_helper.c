/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file linux_kvm_capture_helper.c
 * Parent broker, isolated exec helper and protected-worker connection protocol.
 *
 * An inherited Wayland socket can report its launcher as SO_PEERCRED rather
 * than KWin. The broker first validates/pins that launcher and the independently
 * identified compositor, then sends only a fixed non-secret 12-byte sync request.
 * Each reply fragment must carry KWin's kernel SCM_CREDENTIALS before the socket
 * reaches normal capture traffic. UID, pathname and claimed epochs are not proof.
 *
 * Parent-side phases launch, prove, transfer and seal under bounded deadlines;
 * retained pidfds invalidate the connection when any participant is replaced.
 * The helper's exec occurs before Agent configuration or credentials initialize.
 * No input descriptor or registration is delegated to this helper.
 */
#define _GNU_SOURCE
#include "linux_kvm_capture_helper.h"
#if defined(__linux__)
#include "linux_kvm_bridge_auth.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <stddef.h>
#include <grp.h>
#include <pwd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <limits.h>

#if defined(SYS_clone3) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal) && defined(SYS_waitid) && !defined(KVM_CAPTURE_DISABLE_HELPER)
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#define CAPTURE_MAGIC 0x4d434831u
enum { CAP_CONNECT=1, CAP_READY, CAP_SEAL, CAP_SEALED };
/* Anonymous, local, versioned channel. Never contains input or Agent secrets. */
typedef struct capture_message {
    uint32_t magic, version, kind, reserved;
    uint64_t generation, parent_start, worker_start, compositor_start, helper_start;
    uint32_t parent, worker, uid, gid, compositor, helper;
    char session[64], display[64];
} capture_message;
static uint64_t capture_now(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void capture_debug(const char *stage,int detail) {
    const char *enabled=getenv("MESH_KVM_DRM_DEBUG");
    if(enabled&&atoi(enabled)>0)fprintf(stderr,"KWin capture helper: %s (%d)\n",stage,detail);
}
static void capture_close(int *fd) { if (*fd>=0) close(*fd); *fd=-1; }
static int capture_pin(pid_t pid, uint64_t start) {
    pid_t parent; unsigned long long observed; int fd;
#ifdef SYS_pidfd_open
    fd=(int)syscall(SYS_pidfd_open,pid,0);
#else
    return -1;
#endif
    if (fd<0) return -1;
    struct pollfd p={.fd=fd,.events=POLLIN};
    if (!kvm_bridge_process(pid,&parent,&observed)||observed!=start||poll(&p,1,0)!=0) { close(fd); return -1; }
    return fd;
}
static int capture_live(int fd) {
    struct pollfd p={.fd=fd,.events=POLLIN}; return fd>=0&&poll(&p,1,0)==0;
}
int kvm_capture_helper_reap(int pin) {
#if defined(SYS_waitid) && defined(SYS_pidfd_send_signal)
    siginfo_t info={0};
    syscall(SYS_pidfd_send_signal,pin,SIGKILL,NULL,0);
    int result=(int)syscall(SYS_waitid,3 /* P_PIDFD */,pin,&info,WEXITED|WNOHANG,NULL);
    if(result==0&&info.si_pid){capture_debug("helper exit code",info.si_code);capture_debug("helper exit status",info.si_status);}
    return (result==0&&info.si_pid!=0)||(result<0&&errno==ECHILD);
#else
    (void)pin;return 0;
#endif
}
static int capture_wait_supported(void) {
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal) && defined(SYS_waitid) && defined(SYS_clone3) && defined(CLONE_PIDFD)
    int pin=(int)syscall(SYS_pidfd_open,getpid(),0);if(pin<0)return 0;
    siginfo_t info={0};int result=(int)syscall(SYS_waitid,3,pin,&info,WEXITED|WNOHANG,NULL);
    int supported=result<0&&errno==ECHILD;close(pin);return supported;
#else
    return 0;
#endif
}
static __attribute__((unused)) int capture_parent_policy(void) {return prctl(PR_GET_SECCOMP)==0;}
#ifndef KVM_CAPTURE_PARENT_POLICY
#define KVM_CAPTURE_PARENT_POLICY capture_parent_policy
#endif
static int capture_start(pid_t pid,uint64_t *start) {
    pid_t parent; unsigned long long value;
    if (!kvm_bridge_process(pid,&parent,&value)) return 0;
    *start=value; return 1;
}
static int capture_socket(int fd,int type) {
    int actual,domain; socklen_t n=sizeof(actual);
    return getsockopt(fd,SOL_SOCKET,SO_TYPE,&actual,&n)==0&&n==sizeof(actual)&&actual==type&&
        (n=sizeof(domain),getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&n)==0)&&domain==AF_UNIX;
}
static int capture_send(int fd,const capture_message *m,int descriptor) {
    struct iovec iov={.iov_base=(void*)m,.iov_len=sizeof(*m)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
    if (descriptor>=0) {
        memset(&control,0,sizeof(control));msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&descriptor,sizeof(descriptor));
    }
    ssize_t n=sendmsg(fd,&msg,MSG_DONTWAIT|MSG_NOSIGNAL);
    return n==(ssize_t)sizeof(*m)?1:n<0&&(errno==EAGAIN||errno==EINTR)?0:-1;
}
/* SO_PEERCRED on a pre-fork pair names its creator. Authenticate each actual
 * sender with kernel SCM_CREDENTIALS instead. Close every FD on rejection. */
static int capture_receive(int fd,capture_message *m,struct ucred *credentials,int *descriptor) {
    struct iovec iov={.iov_base=m,.iov_len=sizeof(*m)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(8*sizeof(int))]; } control;
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    int count=0,have_credentials=0,invalid=0,received[8]; *descriptor=-1;
    ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (n<0&&(errno==EAGAIN||errno==EINTR)) return 0;
    if (n<0) return -1;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if (c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS) {
            size_t bytes=c->cmsg_len>=CMSG_LEN(0)?c->cmsg_len-CMSG_LEN(0):0;
            if (bytes%sizeof(int)) invalid=1;
            for (size_t i=0;i<bytes/sizeof(int);++i) {
                int value;memcpy(&value,(char*)CMSG_DATA(c)+i*sizeof(int),sizeof(value));
                if(count<8)received[count++]=value;else{close(value);invalid=1;}
            }
        } else if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof(*credentials))&&!have_credentials) {
            memcpy(credentials,CMSG_DATA(c),sizeof(*credentials));have_credentials=1;
        } else invalid=1;
    }
    if(n!=(ssize_t)sizeof(*m)||msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)||!have_credentials||count>1||invalid||
        m->magic!=CAPTURE_MAGIC||m->version!=1||m->reserved!=0) {
        for(int i=0;i<count;++i) { close(received[i]); }
        return -1;
    }
    if(count) { *descriptor=received[0]; }
    return 1;
}
static int capture_channel(int fd) {
    int on=1,flags=fcntl(fd,F_GETFL);
    return capture_socket(fd,SOCK_SEQPACKET)&&flags>=0&&fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0&&
        fcntl(fd,F_SETFD,FD_CLOEXEC)==0&&setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&on,sizeof(on))==0;
}
static int capture_same(const capture_message *a,const capture_message *b) {
    return a->generation==b->generation&&a->parent==b->parent&&a->parent_start==b->parent_start&&
        a->worker==b->worker&&a->worker_start==b->worker_start&&a->uid==b->uid&&a->gid==b->gid&&
        a->compositor==b->compositor&&a->compositor_start==b->compositor_start&&
        !memcmp(a->session,b->session,sizeof(a->session))&&!memcmp(a->display,b->display,sizeof(a->display));
}
static int capture_session(const capture_message *m) {
    kvm_wayland_console_session s;
    return m->uid>0&&m->uid<=INT_MAX&&memchr(m->session,0,sizeof(m->session))&&m->session[0]&&
        memchr(m->display,0,sizeof(m->display))&&m->display[0]&&!strchr(m->display,'/')&&
        kvm_wayland_active_console_session(&s)&&s.uid==(int)m->uid&&!strcmp(s.type,"wayland")&&!strcmp(s.id,m->session);
}
static int capture_trusted_process(pid_t pid,uid_t uid,uint64_t start,const char *image) {
    char path[64],exe[PATH_MAX],expected[PATH_MAX];struct stat st;
    int pin=capture_pin(pid,start),ok=0;ssize_t n;
    if(pin<0)return 0;
    snprintf(path,sizeof(path),"/proc/%d",pid);
    if(stat(path,&st)||st.st_uid!=uid)goto done;
    snprintf(path,sizeof(path),"/proc/%d/exe",pid);n=readlink(path,exe,sizeof(exe)-1);
    if(n<=0)goto done;
    exe[n]=0;
    ok=realpath(image,expected)&&!strcmp(exe,expected)&&kvm_bridge_trusted_path(expected)&&capture_live(pin);
done:close(pin);return ok;
}
static __attribute__((unused)) int capture_compositor_process(pid_t pid,uid_t uid,uint64_t start) {
    return capture_trusted_process(pid,uid,start,"/usr/bin/kwin_wayland");
}
static __attribute__((unused)) int capture_wrapper_process(pid_t pid,uid_t uid,uint64_t start) {
    return capture_trusted_process(pid,uid,start,"/usr/bin/kwin_wayland_wrapper");
}
#ifndef KVM_CAPTURE_WRAPPER_PROCESS
#define KVM_CAPTURE_WRAPPER_PROCESS capture_wrapper_process
#endif
#ifndef KVM_CAPTURE_COMPOSITOR_PROCESS
#define KVM_CAPTURE_COMPOSITOR_PROCESS capture_compositor_process
#endif
static void capture_erase(void *memory,size_t length) {
    volatile unsigned char *bytes=memory;while(length--)*bytes++=0;
}
static int capture_environment_session(pid_t pid,const char *session) {
    char path[64],chunk[2048],entry[128];size_t length=0,total=0;int found=0,matched=0,complete=0;
    const char key[]="XDG_SESSION_ID=";
    snprintf(path,sizeof(path),"/proc/%d/environ",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
    for(;;) {
        ssize_t n=read(fd,chunk,sizeof(chunk));
        if(n<0&&errno==EINTR)continue;
        if(n<=0){complete=n==0;break;}
        total+=(size_t)n;if(total>65536)break;
        for(ssize_t i=0;i<n;++i) {
            if(chunk[i]) {if(length<sizeof(entry)-1)entry[length]=chunk[i];++length;}
            else {
                if(length>=sizeof(key)-1&&!memcmp(entry,key,sizeof(key)-1)) {
                    ++found;
                    if(length<sizeof(entry)){entry[length]=0;matched=!strcmp(entry+sizeof(key)-1,session);}
                    else matched=0;
                }
                length=0;
            }
        }
    }
    close(fd);int result=complete&&length==0&&found==1&&matched;
    /* The privileged lookup may read unrelated compositor environment values.
     * Do not retain those bytes when the fresh helper later becomes readable. */
    capture_erase(chunk,sizeof(chunk));capture_erase(entry,sizeof(entry));return result;
}
static __attribute__((unused)) int capture_compositor_session(const capture_message *m) {
    void *library=dlopen("libsystemd.so.0",RTLD_NOW|RTLD_LOCAL);char *session=NULL;int result=-ENODATA;
    if(library) {
        int (*get_session)(pid_t,char**)=(void*)dlsym(library,"sd_pid_get_session");
        if(get_session)result=get_session(m->compositor,&session);
        int matched=result>=0&&session&&!strcmp(session,m->session);
        free(session);dlclose(library);
        if(result>=0)return matched;
        if(result!=-ENODATA&&result!=-ENOENT&&result!=-ENXIO)return 0;
    }
    /* Plasma may run under the per-user service manager, outside a login
     * scope. Only the pinned, trusted compositor's initial session ID is a
     * fallback; an arbitrary worker-supplied UID or environment is insufficient. */
    return capture_environment_session(m->compositor,m->session);
}
#ifndef KVM_CAPTURE_COMPOSITOR_SESSION
#define KVM_CAPTURE_COMPOSITOR_SESSION capture_compositor_session
#endif
/* Kernel identity for directly created listeners. Inherited listeners require
 * the separate root-mediated actual-writer proof below; UID alone never grants
 * compositor authority. Executable/session checks remain privileged. */
static int capture_peer_identity(int fd,const capture_message *m) {
    struct ucred peer;socklen_t size=sizeof(peer);struct sockaddr_un remote;socklen_t remote_size=sizeof(remote);
    if(!(capture_socket(fd,SOCK_STREAM)&&getpeername(fd,(struct sockaddr*)&remote,&remote_size)==0&&
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)==0&&size==sizeof(peer)&&peer.pid==(pid_t)m->compositor&&peer.uid==m->uid&&
        peer.pid>0))return 0;
    int pin=capture_pin(peer.pid,m->compositor_start);
    if(pin<0)return 0;
    close(pin);return 1;
}
static int capture_peer(int fd,const capture_message *m) {
    return capture_peer_identity(fd,m)&&KVM_CAPTURE_COMPOSITOR_PROCESS(m->compositor,m->uid,m->compositor_start);
}
/* This only checks transport lineage, not compositor authorization. The helper
 * may transfer this FD privately without sending Wayland bytes. The worker may
 * use it only after authenticating root's CAP_READY attestation. Root separately
 * authenticates the wrapper and the actual compositor's credentialed reply. */
static int capture_related_pin(int fd,const capture_message *m) {
    struct ucred peer;socklen_t size=sizeof(peer);struct sockaddr_un remote;socklen_t n=sizeof(remote);
    pid_t parent,ignored;unsigned long long start,peer_start;
    if(!capture_socket(fd,SOCK_STREAM)||getpeername(fd,(struct sockaddr*)&remote,&n)||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.uid!=m->uid||peer.pid<=0||
        !kvm_bridge_process(m->compositor,&parent,&start)||start!=m->compositor_start)return -1;
    if(peer.pid==(pid_t)m->compositor)return capture_pin(peer.pid,m->compositor_start);
    if(peer.pid!=parent||!kvm_bridge_process(peer.pid,&ignored,&peer_start))return -1;
    return capture_pin(peer.pid,peer_start);
}
static int capture_related(int fd,const capture_message *m) {
    int pin=capture_related_pin(fd,m);if(pin<0)return 0;close(pin);return 1;
}

/* Read-only owner discovery is separate from libei/EIS: no input connection is
 * opened and a missing libei never prevents capture authorization. */
struct sd_bus;struct sd_bus_message;struct sd_bus_error;
static __attribute__((unused)) int capture_identify(const kvm_wayland_console_session *session,const char *display,capture_message *m) {
    void *library=dlopen("libsystemd.so.0",RTLD_NOW|RTLD_LOCAL);struct sd_bus *bus=NULL;struct sd_bus_message *reply=NULL;
    const char *value;char owner[128],address[128];uint32_t uid=UINT32_MAX,pid=0;int ok=0;
#define BUS(ret,name,args) ret (*name) args=(void*)dlsym(library,#name);if(!name)goto done
    if(!library)return 0;
    BUS(int,sd_bus_new,(struct sd_bus **));BUS(int,sd_bus_set_address,(struct sd_bus *,const char *));
    BUS(int,sd_bus_set_bus_client,(struct sd_bus *,int));BUS(int,sd_bus_set_method_call_timeout,(struct sd_bus *,uint64_t));
    BUS(int,sd_bus_start,(struct sd_bus *));BUS(struct sd_bus *,sd_bus_close_unref,(struct sd_bus *));
    BUS(int,sd_bus_call_method,(struct sd_bus *,const char *,const char *,const char *,const char *,struct sd_bus_error *,struct sd_bus_message **,const char *,...));
    BUS(int,sd_bus_message_read,(struct sd_bus_message *,const char *,...));BUS(struct sd_bus_message *,sd_bus_message_unref,(struct sd_bus_message *));
#undef BUS
    snprintf(address,sizeof(address),"unix:path=/run/user/%u/bus",(unsigned)geteuid());
    if(sd_bus_new(&bus)<0||sd_bus_set_address(bus,address)<0||sd_bus_set_bus_client(bus,1)<0||
        sd_bus_set_method_call_timeout(bus,250000)<0||sd_bus_start(bus)<0)goto cleanup;
#define CALL(method,signature,arg) sd_bus_call_method(bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus",method,NULL,&reply,signature,arg)
    if(CALL("GetNameOwner","s","org.kde.KWin")<0||sd_bus_message_read(reply,"s",&value)<0||!value||value[0]!=':'||strlen(value)>=sizeof(owner))goto cleanup;
    strcpy(owner,value);reply=sd_bus_message_unref(reply);
    if(CALL("GetConnectionUnixProcessID","s",owner)<0||sd_bus_message_read(reply,"u",&pid)<0||!pid)goto cleanup;
    reply=sd_bus_message_unref(reply);
    if(CALL("GetConnectionUnixUser","s",owner)<0||sd_bus_message_read(reply,"u",&uid)<0||uid!=(uint32_t)geteuid())goto cleanup;
    reply=sd_bus_message_unref(reply);
    if(CALL("GetNameOwner","s","org.kde.KWin")<0||sd_bus_message_read(reply,"s",&value)<0||!value||strcmp(value,owner))goto cleanup;
    if(strlen(session->id)>=sizeof(m->session)||!display||!display[0]||strlen(display)>=sizeof(m->display)||strchr(display,'/'))goto cleanup;
    /* Discovery is unprivileged; only the root broker may attest the executable.
     * No Wayland request is sent until its authenticated descriptor is returned. */
    m->uid=uid;m->compositor=pid;if(!capture_start(pid,&m->compositor_start))goto cleanup;
    strcpy(m->session,session->id);strcpy(m->display,display);ok=1;
cleanup:if(reply)sd_bus_message_unref(reply);if(bus)sd_bus_close_unref(bus);
done:dlclose(library);return ok;
#undef CALL
}
#ifndef KVM_CAPTURE_IDENTIFY
#define KVM_CAPTURE_IDENTIFY capture_identify
#endif

static int capture_sandbox(void) {
#if defined(__x86_64__)
#define CAP_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CAP_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define CAP_ARCH AUDIT_ARCH_I386
#elif defined(__arm__)
#define CAP_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define CAP_ARCH AUDIT_ARCH_RISCV64
#else
    return 0;
#endif
#ifdef CAP_ARCH
#define ALLOW(call) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##call,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,CAP_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#ifdef SYS_recvmsg
        ALLOW(recvmsg),
#endif
#ifdef SYS_sendmsg
        ALLOW(sendmsg),
#endif
        ALLOW(close),ALLOW(ppoll),
#ifdef SYS_poll
        ALLOW(poll),
#endif
        ALLOW(exit),ALLOW(exit_group),ALLOW(rt_sigreturn),ALLOW(clock_gettime),
#ifdef SYS_ppoll_time64
        ALLOW(ppoll_time64),
#endif
#ifdef SYS_clock_gettime64
        ALLOW(clock_gettime64),
#endif
#ifdef SYS_socketcall
        /* Old i386 libc uses this multiplexer. Permit only existing-socket
         * sendmsg/recvmsg (Linux socketcall operations 16/17), never socket or connect. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socketcall,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,16,2,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,17,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_DUMPABLE,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS)};
    struct sock_fprog program={.len=sizeof(filter)/sizeof(filter[0]),.filter=filter};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0&&prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)==0;
#undef ALLOW
#undef CAP_ARCH
#endif
}
static int capture_close_unlisted(int first_pin,int second_pin) {
    DIR *directory=opendir("/proc/self/fd");if(!directory)return 0;
    struct dirent *entry;
    while((entry=readdir(directory))) {
        char *tail;long value=strtol(entry->d_name,&tail,10);
        if(!*tail&&value>3&&value!=first_pin&&value!=second_pin&&value!=dirfd(directory))close((int)value);
    }
    closedir(directory);return 1;
}
static int capture_helper_main(void) {
    int channel=3,parent_pin=-1,compositor_pin=-1,fd=-1,received=-1;capture_message m,next;struct ucred credentials;
    uint64_t end=capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;pid_t parent=getppid();
    /* Spawn actions already close inherited descriptors before exec. Audit again
     * before becoming visible; only the private bootstrap and null stdio survive. */
#ifdef SYS_close_range
    if(syscall(SYS_close_range,4,~0u,0)!=0)
#endif
    {
        DIR *directory=opendir("/proc/self/fd");if(!directory)return 125;struct dirent *entry;
        while((entry=readdir(directory))) {char *tail;long value=strtol(entry->d_name,&tail,10);if(!*tail&&value>3&&value!=dirfd(directory))close((int)value);}
        closedir(directory);
    }
    struct rlimit no_core={0,0};
    if(getuid()!=0||geteuid()!=0||setrlimit(RLIMIT_CORE,&no_core)||!capture_channel(channel))return 125;
    for(;;) {
        int r=capture_receive(channel,&m,&credentials,&received);if(r<0)return 125;
        if(r>0)break;
        struct pollfd p={.fd=channel,.events=POLLIN};uint64_t now=capture_now();
        if(now>=end||poll(&p,1,(int)(end-now))<=0)return 125;
    }
    if(received>=0){close(received);return 125;}
    if(credentials.pid!=parent||credentials.uid||m.parent!=(uint32_t)parent||m.helper!=(uint32_t)getpid()||m.kind!=CAP_CONNECT||
        !capture_session(&m)||(parent_pin=capture_pin(parent,m.parent_start))<0||
        (compositor_pin=capture_pin(m.compositor,m.compositor_start))<0||!KVM_CAPTURE_COMPOSITOR_PROCESS(m.compositor,m.uid,m.compositor_start)||
        !KVM_CAPTURE_COMPOSITOR_SESSION(&m))return 125;
    /* The root broker checked passwd/group identity. Do not invoke NSS in the
     * helper or retain descriptors opened by session-discovery libraries. */
    if(m.gid==0||!capture_close_unlisted(parent_pin,compositor_pin))return 125;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0}};
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)||prctl(PR_SET_KEEPCAPS,0,0,0,0)||setgroups(0,NULL)||
        setresgid(m.gid,m.gid,m.gid)||setresuid(m.uid,m.uid,m.uid)||syscall(SYS_capset,&header,caps)||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 125;
    if(syscall(SYS_capget,&header,caps)||caps[0].effective||caps[0].permitted||caps[0].inheritable||
        caps[1].effective||caps[1].permitted||caps[1].inheritable||getuid()!=m.uid||geteuid()!=m.uid||getgid()!=m.gid||getegid()!=m.gid)return 125;
    char runtime[64];struct stat st;struct sockaddr_un address={.sun_family=AF_UNIX};
    snprintf(runtime,sizeof(runtime),"/run/user/%u",m.uid);
    if(lstat(runtime,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=m.uid||(st.st_mode&077)||
        snprintf(address.sun_path,sizeof(address.sun_path),"%s/%s",runtime,m.display)>=(int)sizeof(address.sun_path)||
        lstat(address.sun_path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=m.uid)return 125;
    /* The newly exec'd helper has no Agent memory, credentials, input device or
     * input registration. This visibility is never applied to the worker. */
    if(prctl(PR_SET_DUMPABLE,1,0,0,0)||(fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0))<0||
        connect(fd,(struct sockaddr*)&address,sizeof(address))||!capture_related(fd,&m)||!capture_live(parent_pin)||!capture_live(compositor_pin))return 125;
    if(!capture_sandbox())return 125;
    m.kind=CAP_READY;if(capture_send(channel,&m,fd)!=1)return 125;close(fd);fd=-1;
    int sealed=0;
    for(;;) {
        struct pollfd p[3]={{.fd=channel,.events=POLLIN},{.fd=parent_pin,.events=POLLIN},{.fd=compositor_pin,.events=POLLIN}};
        int r=poll(p,3,sealed?-1:KVM_CAPTURE_HELPER_TIMEOUT);if(r<0&&errno==EINTR)continue;
        if(r<=0||p[1].revents||p[2].revents||p[0].revents&(POLLHUP|POLLERR|POLLNVAL))return 125;
        r=capture_receive(channel,&next,&credentials,&received);if(r==0)continue;
        if(received>=0)close(received);
        if(r<0||received>=0||sealed||credentials.pid!=parent||credentials.uid||next.kind!=CAP_SEAL||!capture_same(&m,&next))return 125;
        if(prctl(PR_SET_DUMPABLE,0,0,0,0))return 125;
        next.kind=CAP_SEALED;if(capture_send(channel,&next,-1)!=1)return 125;sealed=1;
    }
}
int kvm_capture_helper_dispatch(int argc,char **argv) {
    for(int i=1;i<argc;++i)if(!strncmp(argv[i],"--meshagent-kwin-capture",strlen("--meshagent-kwin-capture")))
        return argc==2&&i==1&&!strcmp(argv[i],KVM_CAPTURE_HELPER_ROLE)?capture_helper_main():125;
    return -1;
}

typedef struct capture_sync_proof {size_t written,received;unsigned char bytes[25];} capture_sync_proof;
/* One bounded operation per event-loop wake. Credentials, never response bytes
 * alone, authenticate the actual writer behind a wrapper-created listener. */
static int capture_sync_step(int fd,const capture_message *m,capture_sync_proof *proof) {
    static const uint32_t request[3]={1,12u<<16,2};
    if(proof->written<sizeof(request)) {
        ssize_t n=send(fd,(const char*)request+proof->written,sizeof(request)-proof->written,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(n<0)return errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK?0:-1;
        if(!n)return -1;
        proof->written+=(size_t)n;if(proof->written<sizeof(request))return 0;
    }
    if(proof->received<24) {
        union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(8*sizeof(int))];} control;
        struct iovec iov={.iov_base=proof->bytes+proof->received,.iov_len=sizeof(proof->bytes)-proof->received};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
        ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if(n<0)return errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK?0:-1;
        int valid=n>0&&!(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)),credentials=0;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
            if(c->cmsg_len<CMSG_LEN(0)||c->cmsg_len>(size_t)((char*)msg.msg_control+msg.msg_controllen-(char*)c)){valid=0;break;}
            size_t bytes=c->cmsg_len-CMSG_LEN(0);
            if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS) {
                for(size_t i=0;i+sizeof(int)<=bytes;i+=sizeof(int)){int received;memcpy(&received,(char*)CMSG_DATA(c)+i,sizeof(received));close(received);}
                valid=0;
            } else if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&bytes==sizeof(struct ucred)) {
                struct ucred peer;memcpy(&peer,CMSG_DATA(c),sizeof(peer));++credentials;
                if(peer.pid!=(pid_t)m->compositor||peer.uid!=m->uid)valid=0;
            } else valid=0;
        }
        if(!valid||credentials!=1)return -1;
        proof->received+=(size_t)n;
        if(proof->received>24)return -1;
        if(proof->received<24)return 0;
    }
    uint32_t events[6];memcpy(events,proof->bytes,sizeof(events));
    if(events[0]!=2||events[1]!=(12u<<16)||events[3]!=1||events[4]!=(12u<<16|1)||events[5]!=2)return -1;
    unsigned char extra;ssize_t n=recv(fd,&extra,1,MSG_PEEK|MSG_DONTWAIT);
    if(n>=0)return -1; /* Extra traffic or a closed connection. */
    return errno==EAGAIN||errno==EWOULDBLOCK?1:errno==EINTR?0:-1;
}
static int capture_wrapper_pin(int fd,const capture_message *m) {
    struct ucred peer;socklen_t size=sizeof(peer);uint64_t start;
    if(!KVM_CAPTURE_COMPOSITOR_PROCESS(m->compositor,m->uid,m->compositor_start)||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.pid==(pid_t)m->compositor)return -1;
    int pin=capture_related_pin(fd,m);if(pin<0)return -1;
    if(!capture_start(peer.pid,&start)||!KVM_CAPTURE_WRAPPER_PROCESS(peer.pid,m->uid,start)){close(pin);return -1;}
    capture_message wrapper=*m;wrapper.compositor=peer.pid;wrapper.compositor_start=start;
    (void)wrapper; /* Test hooks may not evaluate their argument. */
    if(!KVM_CAPTURE_COMPOSITOR_SESSION(&wrapper)){close(pin);return -1;}
    return pin;
}
struct kvm_capture_broker {
    int channel,bootstrap,helper_pin,worker_pin,compositor_pin,state,proof_fd,listener_pin;
    pid_t worker,helper;uid_t uid;uint64_t generation,worker_start,deadline;
    capture_message request,pending;
    capture_sync_proof proof;
};
static void capture_broker_fail(kvm_capture_broker *b) {
    if(b->state>=0)capture_debug("closing broker state",b->state);
    capture_close(&b->proof_fd);capture_close(&b->listener_pin);
    capture_close(&b->channel);capture_close(&b->bootstrap);capture_close(&b->compositor_pin);b->state=-1;b->deadline=0;
#ifdef SYS_pidfd_send_signal
    if(b->helper_pin>=0)syscall(SYS_pidfd_send_signal,b->helper_pin,SIGKILL,NULL,0);
#endif
    if(b->helper>0&&b->helper_pin<0)b->deadline=capture_now()+100;
}
/* Async-signal-safe child side, before exec. The child's descriptor table is
 * already separate, so concurrent parent opens cannot escape this close pass. */
static int capture_exec_descriptors(int executable_fd) {
#if defined(SYS_close_range) && !defined(KVM_CAPTURE_FORCE_PROC_CLOSE)
    int lower=executable_fd==4||syscall(SYS_close_range,4,(unsigned)executable_fd-1,0)==0;
    int upper=syscall(SYS_close_range,(unsigned)executable_fd+1,~0u,0)==0;
    if(lower&&upper)return 1;
#endif
#ifdef SYS_getdents64
    struct capture_dirent {uint64_t inode;int64_t offset;unsigned short length;unsigned char type;char name[];};
    int scan=(int)syscall(SYS_openat,AT_FDCWD,"/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0);if(scan<0)return 0;
    union {uint64_t align;char bytes[4096];} buffer;int ok=1;
    for(;;) {
        long n=syscall(SYS_getdents64,scan,buffer.bytes,sizeof(buffer.bytes));
        if(n<0&&errno==EINTR)continue;
        if(n<=0){ok=n==0;break;}
        long position=0;
        while(position<n) {
            if(n-position<(long)offsetof(struct capture_dirent,name)+1){ok=0;break;}
            struct capture_dirent *entry=(void*)(buffer.bytes+position);
            if(entry->length<=offsetof(struct capture_dirent,name)||entry->length>n-position||entry->length%8){ok=0;break;}
            size_t limit=entry->length - offsetof(struct capture_dirent,name);unsigned value=0;size_t i=0;
            while(i<limit&&entry->name[i]>='0'&&entry->name[i]<='9') {
                unsigned digit=(unsigned)(entry->name[i++]-'0');
                if(value>((unsigned)INT_MAX-digit)/10){ok=0;break;}
                value=value*10+digit;
            }
            if(!ok)break;
            if(i&&i<limit&&!entry->name[i]&&value>3&&value!=(unsigned)executable_fd&&value!=(unsigned)scan)syscall(SYS_close,(int)value);
            position+=entry->length;
        }
        if(!ok)break;
    }
    syscall(SYS_close,scan);return ok;
#else
    return 0;
#endif
}
static __attribute__((noreturn)) void capture_child_exit(void) {
    syscall(SYS_exit_group,125);__builtin_unreachable();
}
static int capture_child_duplicate(int source,int target) {
    if(source==target)return syscall(SYS_fcntl,target,F_SETFD,0)==0;
#ifdef SYS_dup3
    return syscall(SYS_dup3,source,target,0)>=0;
#else
    return syscall(SYS_dup2,source,target)>=0;
#endif
}
static int capture_spawn(kvm_capture_broker *b) {
    char executable[PATH_MAX],exec_path[64];struct stat installed,running,pinned;int pair[2],exec_fd;
    ssize_t length=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    if(length<=0)return 0;
    executable[length]=0;
    if(!kvm_bridge_trusted_path(executable)||stat(executable,&installed)||stat("/proc/self/exe",&running)||
        installed.st_dev!=running.st_dev||installed.st_ino!=running.st_ino)return 0;
    int opened=open(executable,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(opened<0)return 0;
    exec_fd=fcntl(opened,F_DUPFD_CLOEXEC,4);close(opened);
    if(exec_fd<0)return 0;
    if(fstat(exec_fd,&pinned)||pinned.st_dev!=running.st_dev||pinned.st_ino!=running.st_ino||
        pinned.st_uid||(pinned.st_mode&022)||!S_ISREG(pinned.st_mode)) {close(exec_fd);return 0;}
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)){close(exec_fd);return 0;}
    int child_endpoint=fcntl(pair[1],F_DUPFD_CLOEXEC,4);
    close(pair[1]);pair[1]=child_endpoint;
    if(child_endpoint<0||!capture_channel(pair[0])||!capture_channel(pair[1])){close(pair[0]);if(pair[1]>=0)close(pair[1]);close(exec_fd);return 0;}
    int ok=0;
    char *args[]={executable,KVM_CAPTURE_HELPER_ROLE,NULL};char *environment[]={"PATH=/usr/bin:/bin","LANG=C","LD_BIND_NOW=1",NULL};
    /* Resolve execution through the pinned descriptor, closing it atomically on
     * exec. A concurrent installed-file replacement cannot select another build. */
    snprintf(exec_path,sizeof(exec_path),"/proc/self/fd/%d",exec_fd);
    sigset_t blocked,empty;sigfillset(&blocked);sigemptyset(&empty);
    struct sigaction action={0},previous;action.sa_handler=SIG_DFL;sigemptyset(&action.sa_mask);
    /* Resolve these libc entrypoints in the parent. The child uses only
     * async-signal-safe operations and the pinned exec before any allocation. */
    if(sigaction(SIGPIPE,NULL,&previous))goto done;
    volatile int error_snapshot=errno;(void)error_snapshot;
#if defined(SYS_clone3) && defined(CLONE_PIDFD)
    /* Version-zero Linux clone3 UAPI: eight aligned u64 fields, 64 bytes.
     * Do not require a struct declaration absent from the old release sysroot. */
    struct capture_clone_args {uint64_t flags,pidfd,child_tid,parent_tid,exit_signal,stack,stack_size,tls;} __attribute__((aligned(8)));
    struct capture_clone_args clone={.flags=CLONE_PIDFD,.pidfd=(uint64_t)(uintptr_t)&b->helper_pin,.exit_signal=SIGCHLD};
    b->helper=(pid_t)syscall(SYS_clone3,&clone,sizeof(clone));
#else
    b->helper=-1;
#endif
    if(b->helper<0){capture_debug("clone3 failed",errno);b->helper=0;goto done;}
    if(b->helper==0) {
        if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,&blocked,NULL,(NSIG-1)/8)||syscall(SYS_prctl,PR_SET_DUMPABLE,0,0,0,0)||
            !capture_child_duplicate(pair[1],3))capture_child_exit();
        int nullfd=(int)syscall(SYS_openat,AT_FDCWD,"/dev/null",O_RDWR|O_CLOEXEC,0);if(nullfd<0)capture_child_exit();
        for(int i=0;i<3;++i)if(!capture_child_duplicate(nullfd,i))capture_child_exit();
        if(!capture_exec_descriptors(exec_fd))capture_child_exit();
        for(int signal_number=1;signal_number<NSIG;++signal_number) {
            if(signal_number!=SIGKILL&&signal_number!=SIGSTOP)sigaction(signal_number,&action,NULL);
        }
        if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,&empty,NULL,(NSIG-1)/8))capture_child_exit();
        syscall(SYS_execve,exec_path,args,environment);capture_child_exit();
    }
    b->request.helper=b->helper;
    if(b->helper_pin<0||!capture_start(b->helper,&b->request.helper_start)||!capture_live(b->helper_pin))goto done;
    b->bootstrap=pair[0];pair[0]=-1;
    if(capture_send(b->bootstrap,&b->request,-1)!=1)goto done;
    ok=1;
done:
    if(pair[0]>=0)close(pair[0]);
    close(pair[1]);close(exec_fd);return ok;
}
kvm_capture_broker *kvm_capture_broker_new(int fd,pid_t worker,uid_t uid,uint64_t generation) {
    capture_debug("initializing broker",0);
    kvm_capture_broker *b=calloc(1,sizeof(*b));pid_t parent;unsigned long long start;
    if(!b){close(fd);return NULL;}b->channel=fd;b->bootstrap=b->helper_pin=b->worker_pin=b->compositor_pin=b->proof_fd=b->listener_pin=-1;
    b->worker=worker;b->uid=uid;b->generation=generation;
    /* Do not probe new creation syscalls through an inherited filter whose
     * denial action may kill the Agent. Retain native capture in that case. */
    if(geteuid()!=0||!generation||uid==0||!KVM_CAPTURE_PARENT_POLICY()||!capture_wait_supported()||!capture_channel(fd)||!kvm_bridge_process(worker,&parent,&start)||parent!=getpid()||
        (b->worker_pin=capture_pin(worker,start))<0){capture_debug("broker unavailable",errno);capture_close(&b->channel);free(b);return NULL;}
    b->worker_start=start;capture_debug("broker ready",0);return b;
}
int kvm_capture_broker_fds(kvm_capture_broker *b,int fds[6]) {
    int n=0;if(!b)return 0;if(b->channel>=0)fds[n++]=b->channel;if(b->bootstrap>=0)fds[n++]=b->bootstrap;
    if(b->helper_pin>=0)fds[n++]=b->helper_pin;
    if(b->state>=0&&b->worker_pin>=0)fds[n++]=b->worker_pin;
    if(b->proof_fd>=0)fds[n++]=b->proof_fd;
    if(b->listener_pin>=0)fds[n++]=b->listener_pin;
    return n;
}
int kvm_capture_broker_write_fd(kvm_capture_broker *b) {
    return b&&b->state==5&&(b->proof.written<12||b->proof.received==24)?b->proof_fd:-1;
}
int kvm_capture_broker_select(kvm_capture_broker *b,fd_set *readset,fd_set *writeset,fd_set *errorset) {
    int fds[6],count=kvm_capture_broker_fds(b,fds),writefd=kvm_capture_broker_write_fd(b);
    if(writefd>=FD_SETSIZE)return 0;
    for(int i=0;i<count;++i)if(fds[i]>=FD_SETSIZE)return 0;
    for(int i=0;i<count;++i){if(fds[i]!=writefd)FD_SET(fds[i],readset);FD_SET(fds[i],errorset);}
    if(writefd>=0)FD_SET(writefd,writeset);
    return 1;
}
uint64_t kvm_capture_broker_deadline(kvm_capture_broker *b){return b?b->deadline:0;}
void kvm_capture_broker_step(kvm_capture_broker *b) {
    capture_message m;struct ucred credentials;int received=-1,r;
    if(!b)return;
    if(b->state<0&&b->helper>0&&b->helper_pin<0) {
        b->helper=0;b->deadline=0;
        return;
    }
    if(b->helper_pin>=0&&!capture_live(b->helper_pin)) {
        capture_broker_fail(b);
        if(kvm_capture_helper_reap(b->helper_pin)){b->helper=0;capture_close(&b->helper_pin);}
        return;
    }
    if(b->state<0)return;
    if(!capture_live(b->worker_pin)||(b->deadline&&capture_now()>=b->deadline)){capture_broker_fail(b);return;}
    if(b->state==5) {
        if(!capture_live(b->compositor_pin)||!capture_live(b->listener_pin)||!capture_session(&b->pending)){capture_broker_fail(b);return;}
        /* Neither peer may submit another control message before CAP_READY.
         * Drain/reject immediately rather than spinning on a readable channel. */
        int channels[2]={b->bootstrap,b->channel};
        for(int i=0;i<2;++i) {
            r=capture_receive(channels[i],&m,&credentials,&received);
            if(r!=0){if(received>=0)close(received);capture_broker_fail(b);return;}
        }
        r=capture_sync_step(b->proof_fd,&b->pending,&b->proof);
        if(r<0){capture_broker_fail(b);return;}if(!r)return;
        int pin=capture_wrapper_pin(b->proof_fd,&b->pending),disabled=0;
        if(pin<0){capture_broker_fail(b);return;}close(pin);
        if(!capture_live(b->compositor_pin)||!capture_live(b->listener_pin)||!capture_session(&b->pending)||
            setsockopt(b->proof_fd,SOL_SOCKET,SO_PASSCRED,&disabled,sizeof(disabled))||
            capture_send(b->channel,&b->pending,b->proof_fd)!=1){capture_broker_fail(b);return;}
        capture_debug("authenticated compositor readiness reply",0);
        capture_close(&b->proof_fd);capture_close(&b->listener_pin);
        b->state=2;b->deadline=capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;return;
    }
    if(b->bootstrap>=0) {
        r=capture_receive(b->bootstrap,&m,&credentials,&received);
        if(r<0){capture_debug("helper bootstrap closed",0);capture_broker_fail(b);return;}
        if(r>0) {
            if(credentials.pid!=b->helper||credentials.uid!=b->uid||m.helper!=(uint32_t)b->helper||m.helper_start!=b->request.helper_start||
                !capture_same(&m,&b->request)||!capture_session(&m)||!capture_live(b->compositor_pin)||
                (b->state==1?(m.kind!=CAP_READY||received<0):
                 b->state==3?(m.kind!=CAP_SEALED||received>=0):1)) {
                if(received>=0)close(received);
                capture_broker_fail(b);return;
            }
            if(b->state==1&&!capture_peer(received,&m)) {
                int enabled=1;
                b->listener_pin=capture_wrapper_pin(received,&m);
                if(b->listener_pin<0||setsockopt(received,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))){close(received);capture_broker_fail(b);return;}
                b->proof_fd=received;b->pending=m;memset(&b->proof,0,sizeof(b->proof));b->state=5;
                capture_debug("proving inherited socket responder",0);return;
            }
            if(capture_send(b->channel,&m,received)!=1){if(received>=0)close(received);capture_broker_fail(b);return;}
            if(received>=0)close(received);
            b->state=b->state==1?2:4;b->deadline=b->state==4?0:capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;
        }
    }
    r=capture_receive(b->channel,&m,&credentials,&received);
    if(r<0){capture_broker_fail(b);return;}if(r==0)return;
    if(received>=0)close(received);
    if(received>=0||credentials.pid!=b->worker||credentials.uid!=b->uid||m.uid!=b->uid||m.worker!=(uint32_t)b->worker||m.worker_start!=b->worker_start||
        m.parent!=(uint32_t)getpid()||m.generation!=b->generation||!capture_session(&m)) {capture_broker_fail(b);return;}
    if(b->state==0&&m.kind==CAP_CONNECT&&m.helper==0&&m.helper_start==0) {
        capture_debug("validating worker request",0);
        uint64_t parent_start;struct passwd *account=getpwuid(b->uid);
        if(!account||!m.gid||account->pw_gid!=m.gid||!capture_start(getpid(),&parent_start)||parent_start!=m.parent_start||
            !KVM_CAPTURE_COMPOSITOR_PROCESS(m.compositor,b->uid,m.compositor_start)||
            (b->compositor_pin=capture_pin(m.compositor,m.compositor_start))<0||!KVM_CAPTURE_COMPOSITOR_SESSION(&m)){capture_broker_fail(b);return;}
        b->request=m;b->state=1;b->deadline=capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;
        if(!capture_spawn(b)){capture_debug("helper spawn failed",errno);capture_broker_fail(b);}
        else capture_debug("helper spawned",0);
    } else if(b->state==2&&m.kind==CAP_SEAL&&capture_same(&m,&b->request)) {
        if(capture_send(b->bootstrap,&m,-1)!=1){capture_broker_fail(b);return;}
        b->state=3;b->deadline=capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;
    } else capture_broker_fail(b);
}
int kvm_capture_broker_free(kvm_capture_broker *b) {
    int reap=-1;if(!b)return -1;capture_broker_fail(b);
    if(b->helper_pin>=0&&!kvm_capture_helper_reap(b->helper_pin)){reap=b->helper_pin;b->helper_pin=-1;}
    capture_close(&b->helper_pin);capture_close(&b->worker_pin);free(b);return reap;
}

static struct {int channel,parent_pin,helper_pin,compositor_pin,listener_pin;pid_t parent;uint64_t generation;capture_message request;} worker={.channel=-1,.parent_pin=-1,.helper_pin=-1,.compositor_pin=-1,.listener_pin=-1};
void kvm_capture_worker_release(void) {
    capture_close(&worker.channel);capture_close(&worker.parent_pin);capture_close(&worker.helper_pin);capture_close(&worker.compositor_pin);
    capture_close(&worker.listener_pin);
}
void kvm_capture_worker_attach(int fd,pid_t parent,uint64_t generation) {
    uint64_t start;kvm_capture_worker_release();worker.parent=parent;worker.generation=generation;
    if(!capture_channel(fd)||!capture_start(parent,&start)||(worker.parent_pin=capture_pin(parent,start))<0){close(fd);return;}
    worker.channel=fd;memset(&worker.request,0,sizeof(worker.request));worker.request.parent_start=start;
}
static int capture_exchange(uint32_t kind,int want_fd,capture_message *reply,int *output) {
    capture_message m=worker.request;struct ucred credentials;uint64_t end=capture_now()+KVM_CAPTURE_HELPER_TIMEOUT;
    int sent=0,r,descriptor=-1;m.kind=kind;
    for(;;) {
        if(!capture_live(worker.parent_pin))return 0;
        if(!sent){r=capture_send(worker.channel,&m,-1);if(r<0)return 0;sent=r;}
        if(sent) {
            r=capture_receive(worker.channel,reply,&credentials,&descriptor);if(r<0)return 0;
            if(r>0) {
                if(credentials.pid!=worker.parent||credentials.uid||!capture_same(reply,&m)||!capture_session(reply)||reply->kind!=(want_fd?CAP_READY:CAP_SEALED)||
                    (want_fd?(descriptor<0||!capture_related(descriptor,reply)):descriptor>=0)) {if(descriptor>=0)close(descriptor);return 0;}
                *output=descriptor;return 1;
            }
        }
        uint64_t now=capture_now();if(now>=end)return 0;
        struct pollfd p={.fd=worker.channel,.events=sent?POLLIN:POLLOUT};r=poll(&p,1,(int)(end-now));
        if(r<0&&errno==EINTR)continue;
        if(r<=0||p.revents&(POLLERR|POLLHUP|POLLNVAL))return 0;
    }
}
int kvm_capture_worker_connect(const kvm_wayland_console_session *session,const char *display) {
    capture_message reply;int descriptor=-1;
    capture_debug("worker connecting",worker.channel>=0);
    if(worker.channel<0||prctl(PR_GET_DUMPABLE)!=0||session->uid!=(int)geteuid()||
        !KVM_CAPTURE_IDENTIFY(session,display,&worker.request))goto fail;
    capture_debug("worker identified compositor",0);
    worker.request.magic=CAPTURE_MAGIC;worker.request.version=1;worker.request.generation=worker.generation;
    worker.request.parent=worker.parent;worker.request.worker=getpid();worker.request.gid=getgid();
    if(!capture_start(getpid(),&worker.request.worker_start)||!capture_session(&worker.request)||
        !capture_exchange(CAP_CONNECT,1,&reply,&descriptor))goto fail;
    worker.request=reply;
    capture_debug("worker received authenticated socket",0);
    worker.helper_pin=capture_pin(reply.helper,reply.helper_start);
    worker.compositor_pin=capture_pin(reply.compositor,reply.compositor_start);
    worker.listener_pin=capture_related_pin(descriptor,&reply);
    if(worker.helper_pin<0||worker.compositor_pin<0||worker.listener_pin<0||prctl(PR_GET_DUMPABLE)!=0)goto fail;
    return descriptor;
fail:capture_debug("worker connection unavailable",errno);if(descriptor>=0)close(descriptor);kvm_capture_worker_release();return -1;
}
int kvm_capture_worker_seal(void) {
    capture_message reply;int descriptor=-1;
    if(!kvm_capture_worker_alive()||!capture_exchange(CAP_SEAL,0,&reply,&descriptor)||prctl(PR_GET_DUMPABLE)!=0){kvm_capture_worker_release();return 0;}
    return 1;
}
int kvm_capture_worker_alive(void) {
    struct pollfd pins[5]={{.fd=worker.parent_pin,.events=POLLIN},{.fd=worker.helper_pin,.events=POLLIN},
        {.fd=worker.compositor_pin,.events=POLLIN},{.fd=worker.channel,.events=POLLIN},{.fd=worker.listener_pin,.events=POLLIN}};
    return worker.channel>=0&&worker.parent_pin>=0&&worker.helper_pin>=0&&worker.compositor_pin>=0&&worker.listener_pin>=0&&poll(pins,5,0)==0;
}
#else
/* Unsupported syscall ABIs still build and retain the existing native path. */
int kvm_capture_helper_dispatch(int argc,char **argv) {
    for(int i=1;i<argc;++i)if(!strncmp(argv[i],"--meshagent-kwin-capture",strlen("--meshagent-kwin-capture")))return 125;
    return -1;
}
kvm_capture_broker *kvm_capture_broker_new(int fd,pid_t pid,uid_t uid,uint64_t generation){(void)pid;(void)uid;(void)generation;if(fd>=0)close(fd);return NULL;}
int kvm_capture_broker_fds(kvm_capture_broker *b,int fds[6]){(void)b;(void)fds;return 0;}
int kvm_capture_broker_write_fd(kvm_capture_broker *b){(void)b;return -1;}
int kvm_capture_broker_select(kvm_capture_broker *b,fd_set *r,fd_set *w,fd_set *e){(void)b;(void)r;(void)w;(void)e;return 1;}
uint64_t kvm_capture_broker_deadline(kvm_capture_broker *b){(void)b;return 0;}
void kvm_capture_broker_step(kvm_capture_broker *b){(void)b;}
int kvm_capture_broker_free(kvm_capture_broker *b){(void)b;return -1;}
int kvm_capture_helper_reap(int fd){(void)fd;return 1;}
void kvm_capture_worker_attach(int fd,pid_t pid,uint64_t generation){(void)pid;(void)generation;if(fd>=0)close(fd);}
int kvm_capture_worker_connect(const kvm_wayland_console_session *s,const char *display){(void)s;(void)display;return -1;}
int kvm_capture_worker_seal(void){return 0;}
int kvm_capture_worker_alive(void){return 0;}
void kvm_capture_worker_release(void){}
#endif
#endif
