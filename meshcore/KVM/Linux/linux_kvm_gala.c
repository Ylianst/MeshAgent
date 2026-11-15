/* SPDX-License-Identifier: Apache-2.0 */
/* Native Agent transport for elementary's Agent-owned Gala addition.
 * Unlike the GNOME companion, Gala supplies text only: DRM/uinput and the
 * real keymap remain responsible for capture, pointer and mapped input.
 *
 * AGL1 uses fixed network-endian records, a compositor epoch and one
 * monotonic deadline. Preparation authenticates without reading replies;
 * capture-worker text calls follow its privilege drop. The installer also
 * uses a separate bounded status-only probe while root. Exact executable and
 * user-service identities below are intentional vendor compatibility cases,
 * not interchangeable matches for arbitrary same-UID processes.
 * See addons/gala/README.md for ownership, activation and licensing.
 */
#define _GNU_SOURCE
#include "linux_kvm_gala.h"
#include "linux_kvm_peer_message.h"
#if defined(__linux__)
#include "linux_gala_assets.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define GALA_TIMEOUT 500u
static struct {int fd,failed,ready;pid_t peer;unsigned char epoch[16];kvm_wayland_console_session session;} gala={.fd=-1};
static uint64_t gala_now(void){struct timespec t;return clock_gettime(CLOCK_MONOTONIC,&t)?0:(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
static uint32_t get32(const unsigned char *p){uint32_t n;memcpy(&n,p,4);return ntohl(n);}
static void put32(unsigned char *p,uint32_t n){n=htonl(n);memcpy(p,&n,4);}
static int wait_fd(int fd,short events,uint64_t deadline){
    for(;;){uint64_t now=gala_now();if(!now||now>=deadline)return 0;
        struct pollfd p={fd,events,0};int r=poll(&p,1,(int)(deadline-now));
        if(r<0&&errno==EINTR){continue;}return r>0&&(p.revents&events)&&!(p.revents&(POLLERR|POLLNVAL));}
}
static int connect_peer(const char *path,struct ucred *peer,uint64_t deadline){
    struct sockaddr_un address={.sun_family=AF_UNIX};socklen_t n=sizeof(*peer);
    if(strlen(path)>=sizeof(address.sun_path))return -1;
    strcpy(address.sun_path,path);int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(fd<0)return -1;
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))){
        int error=0;socklen_t size=sizeof(error);
        if(errno!=EINPROGRESS||!wait_fd(fd,POLLOUT,deadline)||getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error){close(fd);return -1;}
    }
    int passcred=1;
    if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,peer,&n)||n!=sizeof(*peer)||
       setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred))){close(fd);return -1;}
    return fd;
}
static int trusted_exe(pid_t pid){
    char path[64],name[PATH_MAX];struct stat expected,actual;
    snprintf(path,sizeof(path),"/proc/%d/exe",(int)pid);ssize_t n=readlink(path,name,sizeof(name)-1);
    if(n<=0||n>=(ssize_t)sizeof(name)-1){return 0;}name[n]=0;
    if(strcmp(name,"/usr/bin/gala")&&strcmp(name,"/usr/bin/gala (deleted)"))return 0;
    if(lstat("/usr/bin/gala",&expected)||!S_ISREG(expected.st_mode)||expected.st_uid||(expected.st_mode&0022)||
        stat(path,&actual)||!S_ISREG(actual.st_mode)||actual.st_uid||(actual.st_mode&0022))return 0;
    return (actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino)||!strcmp(name,"/usr/bin/gala (deleted)");
}
static int trusted_scope(const char *groups,int uid){
    char legacy[256],current_name[256];
    snprintf(legacy,sizeof(legacy),"/user.slice/user-%d.slice/user@%d.service/session.slice/_io.elementary.gala@wayland.service",uid,uid);
    snprintf(current_name,sizeof(current_name),"/user.slice/user-%d.slice/user@%d.service/session.slice/io.elementary.gala@wayland.service",uid,uid);
    const char *line=groups;
    while(line&&*line){
        const char *end=strchr(line,'\n');size_t size=end?(size_t)(end-line):strlen(line);
        const char *first=memchr(line,':',size),*second=first?memchr(first+1,':',size-(size_t)(first+1-line)):NULL;
        if(second){size_t length=size-(size_t)(second+1-line);
            if((length==strlen(legacy)&&!memcmp(second+1,legacy,length))||
                (length==strlen(current_name)&&!memcmp(second+1,current_name,length)))return 1;}
        line=end?end+1:NULL;
    }
    return 0;
}
static int process_scope(pid_t pid,int uid){
    char path[64],groups[4097];snprintf(path,sizeof(path),"/proc/%d/cgroup",(int)pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
    ssize_t n=read(fd,groups,sizeof(groups)-1);close(fd);if(n<=0||n>=(ssize_t)sizeof(groups)-1)return 0;
    groups[n]=0;return trusted_scope(groups,uid);
}
static int compositor_peer(const struct ucred *peer,const char *runtime,uint64_t deadline){
    DIR *dir=opendir(runtime);struct dirent *entry;int matched=0,count=0;
    if(!dir)return 0;
    while((entry=readdir(dir))&&++count<=256&&gala_now()<deadline){
        if(strncmp(entry->d_name,"wayland-",8)||!entry->d_name[8]||strspn(entry->d_name+8,"0123456789")!=strlen(entry->d_name+8))continue;
        char path[256];struct stat st;struct ucred other;
        if(snprintf(path,sizeof(path),"%s/%s",runtime,entry->d_name)>=(int)sizeof(path)||lstat(path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=peer->uid)continue;
        int fd=connect_peer(path,&other,deadline);
        if(fd>=0){matched=other.pid==peer->pid&&other.uid==peer->uid;close(fd);if(matched)break;}
    }
    closedir(dir);return matched;
}
int kvm_gala_find_target(kvm_gala_target *target){
    char runtime[64],path[256];struct stat st;struct dirent *entry;int count=0,good=0;
    if(!target){return 0;}memset(target,0,sizeof(*target));
    if(!kvm_wayland_active_console_session(&target->session)||target->session.uid<=0||strcmp(target->session.type,"wayland"))return 0;
    snprintf(runtime,sizeof(runtime),"/run/user/%d",target->session.uid);
    if(lstat(runtime,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=(uid_t)target->session.uid||(st.st_mode&0077))return 0;
    DIR *dir=opendir(runtime);uint64_t deadline=gala_now()+GALA_TIMEOUT;if(!dir)return 0;
    while((entry=readdir(dir))&&++count<=256&&gala_now()<deadline){
        if(strncmp(entry->d_name,"wayland-",8)||!entry->d_name[8]||strlen(entry->d_name)>=sizeof(target->display)||
            strspn(entry->d_name+8,"0123456789")!=strlen(entry->d_name+8))continue;
        if(snprintf(path,sizeof(path),"%s/%s",runtime,entry->d_name)>=(int)sizeof(path)||lstat(path,&st)||
            !S_ISSOCK(st.st_mode)||st.st_uid!=(uid_t)target->session.uid)continue;
        struct ucred peer;int fd=connect_peer(path,&peer,deadline);if(fd<0)continue;
        close(fd);if(peer.uid!=(uid_t)target->session.uid||peer.pid<=1||!trusted_exe(peer.pid)||!process_scope(peer.pid,target->session.uid))continue;
        if(good){good=0;break;} /* Ambiguous Gala instances are ineligible. */
        target->pid=peer.pid;strcpy(target->display,entry->d_name);good=1;
    }
    closedir(dir);kvm_wayland_console_session current;
    return good&&kvm_wayland_active_console_session(&current)&&kvm_wayland_console_session_equal(&current,&target->session);
}
void kvm_gala_shutdown(void){if(gala.fd>=0)close(gala.fd);memset(&gala,0,sizeof(gala));gala.fd=-1;}
static int current(void){kvm_wayland_console_session s;return gala.fd>=0&&kvm_wayland_active_console_session(&s)&&kvm_wayland_console_session_equal(&s,&gala.session);}
int kvm_gala_prepare(const kvm_wayland_console_session *session){
    kvm_wayland_console_session active;struct stat st;struct ucred peer;char runtime[64],path[128];
    kvm_gala_shutdown();
    if(geteuid()!=0||!session||session->uid<=0||strcmp(session->type,"wayland")||
        !kvm_wayland_active_console_session(&active)||!kvm_wayland_console_session_equal(session,&active)||!mesh_gala_assets_trusted())return 0;
    snprintf(runtime,sizeof(runtime),"/run/user/%d",session->uid);snprintf(path,sizeof(path),"%s/meshagent-gala.sock",runtime);
    if(lstat(runtime,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=(uid_t)session->uid||(st.st_mode&0077)||
        lstat(path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=(uid_t)session->uid||(st.st_mode&0077))return 0;
    uint64_t deadline=gala_now()+GALA_TIMEOUT;int fd=connect_peer(path,&peer,deadline);
    if(fd<0)return 0;
    if(peer.uid!=(uid_t)session->uid||peer.pid<=1||!trusted_exe(peer.pid)||!process_scope(peer.pid,session->uid)||!compositor_peer(&peer,runtime,deadline)){close(fd);return 0;}
    gala.fd=fd;gala.peer=peer.pid;gala.session=*session;return 1;
}
static int io_bytes(int writing,unsigned char *data,size_t size,uint64_t deadline){
    size_t offset=0;while(offset<size){
        if(!wait_fd(gala.fd,writing?POLLOUT:POLLIN,deadline))return 0;
        ssize_t n=writing?send(gala.fd,data+offset,size-offset,MSG_NOSIGNAL):
            kvm_peer_recv(gala.fd,data+offset,size-offset,gala.peer,(uid_t)gala.session.uid);
        if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        if(n<=0){return 0;}offset+=(size_t)n;
    }return 1;
}
static int request(uint32_t op,uint32_t cp){
    unsigned char data[40]={0},reply[32];uint64_t deadline=gala_now()+GALA_TIMEOUT;
    memcpy(data,"AGL1",4);put32(data+4,op);memcpy(data+8,gala.epoch,16);
    put32(data+24,(uint32_t)(deadline>>32));put32(data+28,(uint32_t)deadline);put32(data+32,cp);
    if(!current()||!io_bytes(1,data,sizeof(data),deadline)||!io_bytes(0,reply,sizeof(reply),deadline)||
        memcmp(reply,"AGL1",4)||get32(reply+4)>3||!get32(reply+24)||get32(reply+28)||
        (op==2&&memcmp(reply+8,gala.epoch,16))||!current())return -1;
    if(op==1)memcpy(gala.epoch,reply+8,16);
    /* Result 1 is an explicit pre-injection refusal (for example XWayland
     * focus). Preserve the existing keymap/uinput route in that case only. */
    return get32(reply+4)==0?1:get32(reply+4)==1?0:-1;
}
int kvm_gala_type_unicode(uint32_t cp){
    if(gala.failed)return -1;
    if(gala.fd<0)return 0;
    if(cp<0x20||(cp>=0x7f&&cp<0xa0)||(cp>=0xd800&&cp<=0xdfff)||cp>0x10ffff)return 0;
    int result=gala.ready?1:request(1,0);
    if(result==0){kvm_gala_shutdown();return 0;}
    if(result>0){gala.ready=1;result=request(2,cp);}
    if(result<0){
        kvm_gala_shutdown();gala.failed=1;return -1; /* No ambiguous replay. */
    }
    return result;
}
int kvm_gala_available(void){
    kvm_wayland_console_session session;int good=0;
    if(kvm_wayland_active_console_session(&session)&&kvm_gala_prepare(&session))good=request(1,0)==1;
    kvm_gala_shutdown();return good;
}
#else
int kvm_gala_find_target(kvm_gala_target *t){(void)t;return 0;}
int kvm_gala_prepare(const kvm_wayland_console_session *s){(void)s;return 0;}
int kvm_gala_type_unicode(uint32_t cp){(void)cp;return 0;}
int kvm_gala_available(void){return 0;}
void kvm_gala_shutdown(void){}
#endif
