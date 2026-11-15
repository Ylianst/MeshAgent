/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "../meshcore/KVM/Linux/linux_kvm_capture_helper.h"
#include <stdint.h>
static int fixture_process(pid_t,uid_t,uint64_t);
static int fixture_identify(const kvm_wayland_console_session*,const char*,void*);
static int fixture_parent_policy(void);
static int fixture_wrapper_process(pid_t,uid_t,uint64_t);
#define KVM_CAPTURE_COMPOSITOR_PROCESS fixture_process
#define KVM_CAPTURE_COMPOSITOR_SESSION(m) 1
#define KVM_CAPTURE_IDENTIFY(s,d,m) fixture_identify(s,d,m)
#define KVM_CAPTURE_PARENT_POLICY fixture_parent_policy
#define KVM_CAPTURE_WRAPPER_PROCESS fixture_wrapper_process
#include "../meshcore/KVM/Linux/linux_kvm_capture_helper.c"

static int passed,failed;
static pid_t compositor;
static const uid_t desktop_uid=65534;
static char runtime[64],display[64],socket_path[108],test_directory[128],installed[160];
static int made_runtime;
static int fixture_stale_start,fixture_stale_session;
static int fixture_inherited,fixture_reply_mode,fixture_reject_wrapper;
static pid_t fixture_wrapper;
/* WSL itself runs under a filter. Positive protocol fixtures bypass only this
 * availability policy; the explicit negative test uses the real policy. */
static int fixture_allow_filter=1;
static int fixture_parent_policy(void) {return fixture_allow_filter||capture_parent_policy();}
#define CHECK(e) do{if(e)++passed;else{++failed;fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#e);}}while(0)
int kvm_wayland_active_console_session(kvm_wayland_console_session *s) {
    memset(s,0,sizeof(*s));s->uid=desktop_uid;strcpy(s->id,"capture-fixture");strcpy(s->type,"wayland");return 1;
}
static int fixture_process(pid_t pid,uid_t uid,uint64_t start) {
    char path[64];struct stat st;uint64_t actual;
    snprintf(path,sizeof(path),"/proc/%d",pid);
    /* KWin with file capabilities is not inspectable by the desktop UID.
     * Model the privilege required for its executable/session validation. */
    return geteuid()==0&&uid==desktop_uid&&!stat(path,&st)&&st.st_uid==uid&&capture_start(pid,&actual)&&actual==start;
}
static int fixture_wrapper_process(pid_t pid,uid_t uid,uint64_t start) {
    return !fixture_reject_wrapper&&fixture_process(pid,uid,start);
}
static int fixture_identify(const kvm_wayland_console_session *s,const char *d,void *message) {
    capture_message *m=message;
    m->uid=desktop_uid;m->compositor=compositor;
    strcpy(m->session,fixture_stale_session?"retired-fixture":s->id);strcpy(m->display,d);
    if(!capture_start(compositor,&m->compositor_start))return 0;
    if(fixture_stale_start)++m->compositor_start;
    return 1;
}
static int descriptor_count(void) {
    DIR *d=opendir("/proc/self/fd");struct dirent *entry;int count=0;
    while((entry=readdir(d)))if(entry->d_name[0]!='.')++count;
    closedir(d);return count;
}
static void test_ancillary(void) {
    uint64_t start;CHECK(capture_start(getpid(),&start));CHECK(capture_pin(getpid(),start+1)<0);
    int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair));CHECK(capture_channel(pair[0]));
    capture_message m={.magic=CAPTURE_MAGIC,.version=1},out;struct ucred cred;int fd;
    CHECK(capture_send(pair[1],&m,-1)==1);CHECK(capture_receive(pair[0],&out,&cred,&fd)==1);
    CHECK(fd==-1&&cred.pid==getpid()&&cred.uid==0);
    for(int n=1;n<=12;n+=n==1?1:10) {
        int sent[12];for(int i=0;i<n;++i)sent[i]=open("/dev/null",O_RDONLY);
        union {struct cmsghdr align;char bytes[CMSG_SPACE(12*sizeof(int))];} control;
        struct iovec iov={.iov_base=&m,.iov_len=sizeof(m)};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=CMSG_SPACE(n*sizeof(int))};
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(n*sizeof(int));
        memcpy(CMSG_DATA(c),sent,n*sizeof(int));int before=descriptor_count();
        CHECK(sendmsg(pair[1],&msg,0)==sizeof(m));
        CHECK(capture_receive(pair[0],&out,&cred,&fd)==(n==1?1:-1));
        if(n==1){CHECK(fd>=0&&fcntl(fd,F_GETFD)&FD_CLOEXEC);close(fd);}
        CHECK(descriptor_count()==before);
        for(int i=0;i<n;++i)close(sent[i]);
    }
    m.version=2;CHECK(capture_send(pair[1],&m,-1)==1);CHECK(capture_receive(pair[0],&out,&cred,&fd)==-1);
    char oversized[sizeof(m)+1];memcpy(oversized,&m,sizeof(m));CHECK(send(pair[1],oversized,sizeof(oversized),0)==sizeof(oversized));
    CHECK(capture_receive(pair[0],&out,&cred,&fd)==-1);close(pair[0]);close(pair[1]);
}
static pid_t start_server(int *reports) {
    int ready[2],result[2];CHECK(!pipe(ready));CHECK(!pipe(result));pid_t pid=fork();
    if(!pid) {
        close(ready[0]);close(result[0]);struct passwd *a=getpwuid(desktop_uid);
        if(!a||setgroups(0,NULL)||setgid(a->pw_gid)||setuid(desktop_uid))_exit(80);
        int listener=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,socket_path);
        if(bind(listener,(struct sockaddr*)&address,sizeof(address))||listen(listener,8))_exit(81);
        if(fixture_inherited) {
            pid_t server=fork();if(server<0)_exit(82);
            if(server>0) {
                if(write(ready[1],&server,sizeof(server))!=sizeof(server))_exit(82);
                close(ready[1]);
                if(fixture_reply_mode!=1){close(listener);int status;waitpid(server,&status,0);_exit(0);}
                signal(SIGCHLD,SIG_IGN); /* Reap the dummy child after rejection. */
            } else {
                close(ready[1]);
                if(prctl(PR_SET_DUMPABLE,0,0,0,0))_exit(82);
                if(fixture_reply_mode==1){close(listener);for(;;)pause();}
            }
        } else {if(write(ready[1],"1",1)!=1)_exit(82);close(ready[1]);}
        for(;;) {
            int peer=accept(listener,NULL,NULL);if(peer<0)continue;
            char b[64];int total=0;ssize_t n;
            if(fixture_inherited) {
                uint32_t request[3];size_t got=0;
                while(got<sizeof(request)&&(n=read(peer,(char*)request+got,sizeof(request)-got))>0)got+=(size_t)n;
                total=(int)got;
                if(got==sizeof(request)&&fixture_reply_mode!=2) {
                    uint32_t events[6]={2,12u<<16,42,1,12u<<16|1,2};
                    if(request[0]!=1||request[1]!=(12u<<16)||request[2]!=2||write(peer,events,sizeof(events))!=sizeof(events))_exit(83);
                }
            }
            while((n=read(peer,b,sizeof(b)))>0)total+=(int)n;
            if(write(result[1],&total,sizeof(total))!=sizeof(total))_exit(83);
            close(peer);
        }
    }
    close(ready[1]);close(result[1]);fixture_wrapper=0;
    if(fixture_inherited){pid_t server;CHECK(read(ready[0],&server,sizeof(server))==sizeof(server));fixture_wrapper=pid;pid=server;}
    else {char byte;CHECK(read(ready[0],&byte,1)==1);}close(ready[0]);
    CHECK(fcntl(result[0],F_SETFL,O_NONBLOCK)==0);*reports=result[0];return pid;
}
static void test_sync_credentials(void) {
    for(int scenario=0;scenario<11;++scenario) {
        int before=descriptor_count(),pair[2],enabled=1;
        CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair));
        CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)));
        capture_message m={.compositor=getpid(),.uid=getuid()};capture_sync_proof proof={0};
        CHECK(capture_sync_step(pair[0],&m,&proof)==0);
        uint32_t request[3];CHECK(read(pair[1],request,sizeof(request))==sizeof(request));
        CHECK(request[0]==1&&request[1]==12u<<16&&request[2]==2);
        uint32_t events[7]={2,12u<<16,42,1,12u<<16|1,2,0};
        if(scenario==1) {
            for(size_t i=0;i<24;++i){CHECK(write(pair[1],(char*)events+i,1)==1);CHECK(capture_sync_step(pair[0],&m,&proof)==(i==23?1:0));}
        } else if(scenario==9) {
            CHECK(write(pair[1],events,12)==12);CHECK(capture_sync_step(pair[0],&m,&proof)==0);
            pid_t other=fork();if(!other)_exit(write(pair[1],(char*)events+12,12)==12?0:1);
            int status;waitpid(other,&status,0);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
            CHECK(capture_sync_step(pair[0],&m,&proof)==-1);
        } else if(scenario==10) {
            close(pair[1]);pair[1]=-1;CHECK(capture_sync_step(pair[0],&m,&proof)==-1);
        } else {
            if(scenario==2)++m.compositor;
            if(scenario==3)++m.uid;
            if(scenario==4)events[5]=3;
            if(scenario==8){enabled=0;CHECK(!setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)));}
            if(scenario==6||scenario==7) {
                int fds[12],count=scenario==6?1:12;
                for(int i=0;i<count;++i)fds[i]=open("/dev/null",O_RDONLY);
                union {struct cmsghdr align;char bytes[CMSG_SPACE(12*sizeof(int))];} control;
                struct iovec iov={.iov_base=events,.iov_len=24};
                struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=CMSG_SPACE(count*sizeof(int))};
                struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(count*sizeof(int));memcpy(CMSG_DATA(c),fds,count*sizeof(int));
                CHECK(sendmsg(pair[1],&msg,0)==24);
                CHECK(capture_sync_step(pair[0],&m,&proof)==-1);
                for(int i=0;i<count;++i)close(fds[i]);
            } else {
                size_t length=scenario==5?25:24;CHECK(write(pair[1],events,length)==(ssize_t)length);
                CHECK(capture_sync_step(pair[0],&m,&proof)==(scenario==0?1:-1));
            }
        }
        close(pair[0]);if(pair[1]>=0)close(pair[1]);CHECK(descriptor_count()==before);
    }
    uint64_t start;CHECK(capture_start(getpid(),&start));int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    kvm_capture_broker broker={.channel=-1,.bootstrap=-1,.helper_pin=-1,.worker_pin=capture_pin(getpid(),start),
        .compositor_pin=capture_pin(getpid(),start),.listener_pin=capture_pin(getpid(),start),.proof_fd=pair[0],.state=5,.deadline=capture_now()-1};
    CHECK(kvm_capture_broker_write_fd(&broker)==pair[0]);
    kvm_capture_broker_step(&broker);CHECK(broker.state==-1&&broker.proof_fd==-1&&broker.listener_pin==-1&&broker.compositor_pin==-1);
    close(broker.worker_pin);close(pair[1]);
}
static void test_sync_select(void) {
    int before=descriptor_count(),pair[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair));
    char buffer[4096]={0};ssize_t n;
    while((n=send(pair[0],buffer,sizeof(buffer),MSG_DONTWAIT|MSG_NOSIGNAL))>0){}
    CHECK(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK));CHECK(write(pair[1],"X",1)==1);
    struct pollfd readable={.fd=pair[0],.events=POLLIN};CHECK(poll(&readable,1,0)==1&&(readable.revents&POLLIN));
    kvm_capture_broker b={.channel=-1,.bootstrap=-1,.helper_pin=-1,.worker_pin=-1,.compositor_pin=-1,
        .listener_pin=-1,.proof_fd=pair[0],.state=5};
    fd_set rd,wr,er;FD_ZERO(&rd);FD_ZERO(&wr);FD_ZERO(&er);
    CHECK(kvm_capture_broker_select(&b,&rd,&wr,&er));CHECK(!FD_ISSET(pair[0],&rd)&&FD_ISSET(pair[0],&wr));
    struct timeval timeout={.tv_usec=20000};CHECK(select(pair[0]+1,&rd,&wr,&er,&timeout)==0);
    while(recv(pair[1],buffer,sizeof(buffer),MSG_DONTWAIT)>0){}
    FD_ZERO(&rd);FD_ZERO(&wr);FD_ZERO(&er);CHECK(kvm_capture_broker_select(&b,&rd,&wr,&er));
    timeout=(struct timeval){0};CHECK(select(pair[0]+1,&rd,&wr,&er,&timeout)>0&&FD_ISSET(pair[0],&wr)&&!FD_ISSET(pair[0],&rd));
    b.proof.written=12;FD_ZERO(&rd);FD_ZERO(&wr);FD_ZERO(&er);CHECK(kvm_capture_broker_select(&b,&rd,&wr,&er));
    timeout=(struct timeval){0};CHECK(select(pair[0]+1,&rd,&wr,&er,&timeout)>0&&FD_ISSET(pair[0],&rd));
    fd_set oldrd=rd,oldwr=wr,older=er;
    b.proof_fd=FD_SETSIZE;b.proof.written=0;
    CHECK(!kvm_capture_broker_select(&b,&rd,&wr,&er));
    CHECK(!memcmp(&rd,&oldrd,sizeof(rd))&&!memcmp(&wr,&oldwr,sizeof(wr))&&!memcmp(&er,&older,sizeof(er)));
    b.state=2;CHECK(!kvm_capture_broker_select(&b,&rd,&wr,&er));
    close(pair[0]);close(pair[1]);CHECK(descriptor_count()==before);
}
static void test_sync_extra_control(void) {
    for(int sender=0;sender<2;++sender) {
        int before=descriptor_count(),bootstrap[2],channel[2],stream[2];uint64_t start;
        CHECK(capture_start(getpid(),&start));
        CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,bootstrap));
        CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel));
        CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,stream));
        CHECK(capture_channel(bootstrap[0])&&capture_channel(channel[0]));
        kvm_capture_broker b={.bootstrap=bootstrap[0],.channel=channel[0],.helper_pin=-1,.worker_pin=capture_pin(getpid(),start),
            .compositor_pin=capture_pin(getpid(),start),.listener_pin=capture_pin(getpid(),start),.proof_fd=stream[0],.state=5,.deadline=capture_now()+1000,
            .pending={.uid=65534,.session="capture-fixture",.display="fixture"}};
        int extra=open("/dev/null",O_RDONLY);capture_message message={.magic=CAPTURE_MAGIC,.version=1};
        CHECK(capture_send(sender?channel[1]:bootstrap[1],&message,extra)==1);
        kvm_capture_broker_step(&b);CHECK(b.state==-1&&b.proof_fd==-1);
        char byte;CHECK(recv(stream[1],&byte,1,MSG_DONTWAIT)==0); /* No sync bytes. */
        close(extra);close(b.worker_pin);close(bootstrap[1]);close(channel[1]);close(stream[1]);
        CHECK(descriptor_count()==before);
    }
}
static void stop_child(pid_t pid) { if(pid>0){kill(pid,SIGKILL);while(waitpid(pid,NULL,0)<0&&errno==EINTR){}} }
static void stop_wrapper(pid_t pid) {
    if(pid<=0)return;
    uint64_t end=capture_now()+500;int status;
    while(capture_now()<end) {
        pid_t reaped=waitpid(pid,&status,WNOHANG);
        if(reaped==pid||(reaped<0&&errno==ECHILD))return;
        struct pollfd delay={.fd=-1};poll(&delay,0,1);
    }
    stop_child(pid);
}
static void check_desktop_visibility(pid_t pid,int visible) {
    pid_t child=fork();if(!child) {
        struct passwd *account=getpwuid(desktop_uid);
        if(!account||setgroups(0,NULL)||setgid(account->pw_gid)||setuid(desktop_uid))_exit(101);
        char path[64],target[PATH_MAX];snprintf(path,sizeof(path),"/proc/%d/exe",pid);
        ssize_t n=readlink(path,target,sizeof(target));
        _exit(visible?n>0?0:1:n<0&&errno==EACCES?0:1);
    }
    int status;waitpid(child,&status,0);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
static void inspect_helper(kvm_capture_broker *b,int sentinel) {
    (void)sentinel;
    char path[128],target[PATH_MAX];snprintf(path,sizeof(path),"/proc/%d/fd",b->helper);
    DIR *d=opendir(path);CHECK(d!=NULL);if(!d)return;struct dirent *entry;int count=0;
    while((entry=readdir(d)))if(entry->d_name[0]!='.') {
        char descriptor[256];snprintf(descriptor,sizeof(descriptor),"%s/%.32s",path,entry->d_name);
        ssize_t n=readlink(descriptor,target,sizeof(target)-1);CHECK(n>0);if(n>0){target[n]=0;CHECK(!strstr(target,"sentinel"));if(atoi(entry->d_name)<3)CHECK(!strcmp(target,"/dev/null"));}
        ++count;
    }
    CHECK(count<=6);closedir(d);
    check_desktop_visibility(b->helper,1);
    snprintf(path,sizeof(path),"/run/meshagent-kwin-workers/%d",b->helper);CHECK(access(path,F_OK)!=0);
}
static void test_handoff(int fake_server,int readable_worker,int stale_generation) {
    int original_reports,fake_reports=-1;compositor=start_server(&original_reports);pid_t impostor=0,original_wrapper=fixture_wrapper,impostor_wrapper=0;
    if(fake_server){CHECK(!unlink(socket_path));impostor=start_server(&fake_reports);impostor_wrapper=fixture_wrapper;}
    int pair[2],finish[2],launch[2];CHECK(!pipe(launch));CHECK(!pipe(finish));CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));uint64_t generation=123;
    pid_t parent=getpid();pid_t child=fork();
    if(!child) {
        close(launch[1]);char permitted;if(read(launch[0],&permitted,1)!=1)_exit(96);close(launch[0]);
        close(finish[1]);close(pair[0]);kvm_capture_worker_attach(pair[1],parent,stale_generation?generation+1:generation);
        struct passwd *a=getpwuid(desktop_uid);
        if(!a||setgroups(0,NULL)||setgid(a->pw_gid)||setuid(desktop_uid)||prctl(PR_SET_DUMPABLE,readable_worker,0,0,0))_exit(90);
        kvm_wayland_console_session s;kvm_wayland_active_console_session(&s);
        int fd=kvm_capture_worker_connect(&s,display);
        if(fake_server||readable_worker||stale_generation||fixture_stale_start||fixture_stale_session||fixture_reply_mode||fixture_reject_wrapper)_exit(fd<0?0:91);
        if(fd<0)_exit(92);
        if(prctl(PR_GET_DUMPABLE)!=0||write(fd,"R",1)!=1||!kvm_capture_worker_seal()||!kvm_capture_worker_alive())_exit(93);
        if(prctl(PR_GET_DUMPABLE)!=0)_exit(94);
        char acknowledged;if(read(finish[0],&acknowledged,1)!=1)_exit(95);close(finish[0]);
        close(fd);kvm_capture_worker_release();_exit(0);
    }
    close(finish[0]);close(pair[1]);kvm_capture_broker *b=kvm_capture_broker_new(pair[0],child,desktop_uid,generation);CHECK(b!=NULL);
    close(launch[0]);CHECK(write(launch[1],"1",1)==1);close(launch[1]);
    uint64_t end=capture_now()+9000;int status=0,done=0,inspected=0,sealed=0;
    while(capture_now()<end) {
        kvm_capture_broker_step(b);
        if(b&&b->state==2&&!inspected){inspect_helper(b,-1);inspected=1;}
        if(b&&b->state==4&&!sealed){CHECK(capture_live(b->helper_pin));check_desktop_visibility(b->helper,0);sealed=1;CHECK(write(finish[1],"1",1)==1);}
        pid_t r=waitpid(child,&status,WNOHANG);if(r==child){done=1;break;}
        struct pollfd p={.fd=-1};poll(&p,0,2);
    }
    CHECK(done);if(!done)stop_child(child);else{CHECK(WIFEXITED(status));CHECK(WEXITSTATUS(status)==0);}
    if(!fake_server&&!readable_worker&&!stale_generation&&!fixture_stale_start&&!fixture_stale_session&&!fixture_reply_mode&&!fixture_reject_wrapper){CHECK(inspected);CHECK(sealed);}
    pid_t helper=b?b->helper:0;int reap=kvm_capture_broker_free(b);
    if(reap>=0){uint64_t stop=capture_now()+1000;while(!kvm_capture_helper_reap(reap)&&capture_now()<stop){struct pollfd p={.fd=reap,.events=POLLIN};poll(&p,1,2);}close(reap);}
    if(helper>0){char path[64];snprintf(path,sizeof(path),"/proc/%d",helper);CHECK(access(path,F_OK)!=0);}
    if(fake_server) {
        struct pollfd p={.fd=fake_reports,.events=POLLIN};CHECK(poll(&p,1,500)>0);
        int bytes=-1;CHECK(read(fake_reports,&bytes,sizeof(bytes))==sizeof(bytes));CHECK(bytes==0);
    }
    if(!fake_server&&(fixture_reply_mode||fixture_reject_wrapper)) {
        struct pollfd p={.fd=original_reports,.events=POLLIN};CHECK(poll(&p,1,1000)>0);
        int bytes=-1;CHECK(read(original_reports,&bytes,sizeof(bytes))==sizeof(bytes));CHECK(bytes==(fixture_reject_wrapper?0:12));
    }
    stop_child(compositor);stop_child(impostor);stop_wrapper(original_wrapper);stop_wrapper(impostor_wrapper);
    close(original_reports);if(fake_reports>=0)close(fake_reports);unlink(socket_path);
    close(finish[1]);
}
static void test_unrelated_sender(void) {
    int pair[2],gate[2];CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));CHECK(!pipe(gate));pid_t parent=getpid();
    pid_t designated=fork();if(!designated){close(pair[0]);close(gate[1]);char c;_exit(read(gate[0],&c,1)==1?0:1);}
    kvm_capture_broker *b=kvm_capture_broker_new(pair[0],designated,desktop_uid,456);CHECK(b!=NULL);
    if(!b){close(pair[1]);close(gate[0]);close(gate[1]);stop_child(designated);return;}
    pid_t attacker=fork();if(!attacker) {
        close(pair[0]);struct passwd *a=getpwuid(desktop_uid);if(setgroups(0,NULL)||setgid(a->pw_gid)||setuid(desktop_uid))_exit(98);
        capture_message m={.magic=CAPTURE_MAGIC,.version=1,.kind=CAP_CONNECT,.generation=456,.parent=parent,.worker=designated,.uid=desktop_uid};
        capture_start(designated,&m.worker_start);strcpy(m.session,"capture-fixture");strcpy(m.display,display);
        _exit(capture_send(pair[1],&m,-1)==1?0:99);
    }
    close(pair[1]);int status;waitpid(attacker,&status,0);CHECK(WIFEXITED(status)&&!WEXITSTATUS(status));
    kvm_capture_broker_step(b);CHECK(b->state<0&&b->helper==0);kvm_capture_broker_free(b);
    close(gate[0]);CHECK(write(gate[1],"1",1)==1);close(gate[1]);waitpid(designated,NULL,0);
}
static void test_forged_helper_sender(int fail_pin) {
    int reports;compositor=start_server(&reports);
    int pair[2],bootstrap[2],gate[2];CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));
    CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,bootstrap));CHECK(!pipe(gate));
    pid_t designated=fork();if(!designated) {
        close(pair[0]);close(bootstrap[0]);close(bootstrap[1]);close(gate[1]);char c;
        _exit(read(gate[0],&c,1)==1?0:1);
    }
    pid_t helper=fork();if(!helper) {
        close(pair[0]);close(pair[1]);close(bootstrap[0]);close(bootstrap[1]);close(gate[1]);
        struct passwd *a=getpwuid(desktop_uid);if(!a||setgroups(0,NULL)||setgid(a->pw_gid)||setuid(desktop_uid))_exit(109);
        for(;;)pause();
    }
    kvm_capture_broker *b=kvm_capture_broker_new(pair[0],designated,desktop_uid,765);CHECK(b!=NULL);
    if(!b){close(pair[1]);close(bootstrap[0]);close(bootstrap[1]);close(gate[0]);close(gate[1]);stop_child(designated);stop_child(helper);stop_child(compositor);close(reports);unlink(socket_path);return;}
    b->bootstrap=bootstrap[0];CHECK(capture_channel(b->bootstrap));b->state=1;b->helper=helper;
    b->request=(capture_message){.magic=CAPTURE_MAGIC,.version=1,.kind=CAP_READY,.generation=765,.parent=getpid(),.worker=designated,.uid=desktop_uid,.compositor=compositor,.helper=helper};
    b->request.gid=getpwuid(desktop_uid)->pw_gid;capture_start(getpid(),&b->request.parent_start);
    capture_start(designated,&b->request.worker_start);capture_start(helper,&b->request.helper_start);capture_start(compositor,&b->request.compositor_start);
    strcpy(b->request.session,"capture-fixture");strcpy(b->request.display,display);
    int helper_pin=fail_pin==1?-1:capture_pin(helper,b->request.helper_start);
    int compositor_pin=fail_pin==2?-1:capture_pin(compositor,b->request.compositor_start);
    CHECK(fail_pin||(helper_pin>=0&&compositor_pin>=0));
    if(helper_pin<0||compositor_pin<0) {
        /* No broker operation has occurred: an unpinned helper is still our
         * unreaped direct fixture child. After acquisition, use its pidfd. */
        if(helper_pin<0)stop_child(helper);
        else {uint64_t end=capture_now()+1000;while(!kvm_capture_helper_reap(helper_pin)&&capture_now()<end){struct pollfd p={.fd=helper_pin,.events=POLLIN};poll(&p,1,2);}close(helper_pin);}
        if(compositor_pin>=0)close(compositor_pin);
        b->helper=0;kvm_capture_broker_free(b);close(pair[1]);close(bootstrap[1]);close(gate[0]);close(gate[1]);
        stop_child(designated);stop_child(compositor);close(reports);unlink(socket_path);
        char path[64];snprintf(path,sizeof(path),"/proc/%d",helper);CHECK(access(path,F_OK)!=0);
        return;
    }
    b->helper_pin=helper_pin;b->compositor_pin=compositor_pin;
    pid_t attacker=fork();if(!attacker) {
        close(pair[0]);close(pair[1]);close(bootstrap[0]);struct passwd *a=getpwuid(desktop_uid);
        if(!a||setgroups(0,NULL)||setgid(a->pw_gid)||setuid(desktop_uid))_exit(110);
        int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,socket_path);
        if(fd<0||connect(fd,(struct sockaddr*)&address,sizeof(address)))_exit(111);
        _exit(capture_send(bootstrap[1],&b->request,fd)==1?0:112);
    }
    close(bootstrap[1]);int status;waitpid(attacker,&status,0);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    kvm_capture_broker_step(b);CHECK(b->state<0);capture_message unexpected;
    if(b->state<0)CHECK(read(pair[1],&unexpected,sizeof(unexpected))==0);
    close(pair[1]);int pin=kvm_capture_broker_free(b);
    if(pin>=0){uint64_t end=capture_now()+1000;while(!kvm_capture_helper_reap(pin)&&capture_now()<end){struct pollfd p={.fd=pin,.events=POLLIN};poll(&p,1,2);}close(pin);}
    close(gate[0]);CHECK(write(gate[1],"1",1)==1);close(gate[1]);waitpid(designated,NULL,0);
    struct pollfd report={.fd=reports,.events=POLLIN};CHECK(poll(&report,1,500)>0);int bytes=-1;
    CHECK(read(reports,&bytes,sizeof(bytes))==sizeof(bytes));CHECK(bytes==0);
    stop_child(compositor);close(reports);unlink(socket_path);
}
static void test_sandbox(void) {
    for(int operation=0;operation<3;++operation) {
        pid_t child=fork();if(!child){if(!capture_sandbox())_exit(70);
            if(operation==0)syscall(SYS_openat,AT_FDCWD,"/etc/passwd",O_RDONLY,0);
            else if(operation==1)syscall(SYS_socket,AF_UNIX,SOCK_SEQPACKET,0);
            else syscall(SYS_execve,"/bin/true",NULL,NULL);
            _exit(71);
        }
        int status;waitpid(child,&status,0);CHECK(WIFSIGNALED(status)&&WTERMSIG(status)==SIGSYS);
    }
}
static void test_worker_death(void) {
    int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));pid_t child=fork();
    if(!child){close(pair[0]);for(;;)pause();}
    kvm_capture_broker *b=kvm_capture_broker_new(pair[0],child,desktop_uid,987);CHECK(b!=NULL);
    if(!b){stop_child(child);close(pair[1]);return;}
    int fds[6],found=0,count=kvm_capture_broker_fds(b,fds);
    for(int i=0;i<count;++i)if(fds[i]==b->worker_pin)found=1;
    CHECK(found);stop_child(child);kvm_capture_broker_step(b);CHECK(b->state<0&&b->channel<0);
    close(pair[1]);CHECK(kvm_capture_broker_free(b)==-1);
}
static void test_existing_parent_filter(void) {
    pid_t child=fork();if(!child) {
        int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))_exit(102);
        pid_t target=fork();if(!target){for(;;)pause();}
        struct sock_filter filter[]={BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog program={.len=1,.filter=filter};
        if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))_exit(103);
        fixture_allow_filter=0;
        kvm_capture_broker *b=kvm_capture_broker_new(pair[0],target,desktop_uid,789);
        int result=b?1:0;if(b)kvm_capture_broker_free(b);close(pair[1]);stop_child(target);_exit(result);
    }
    int status;waitpid(child,&status,0);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
static void test_session_environment(void) {
    pid_t child=fork();if(!child){char *args[]={"sleep","10",NULL};char *env[]={"XDG_SESSION_ID=capture-fixture",NULL};execve("/bin/sleep",args,env);_exit(100);}
    uint64_t end=capture_now()+1000;
    while(capture_now()<end&&!capture_environment_session(child,"capture-fixture")){struct pollfd p={.fd=-1};poll(&p,0,2);}
    CHECK(capture_environment_session(child,"capture-fixture"));CHECK(!capture_environment_session(child,"other-session"));stop_child(child);
    child=fork();if(!child){char *args[]={"sleep","10",NULL};char *env[]={"XDG_SESSION_ID=capture-fixture","XDG_SESSION_ID=other-session",NULL};execve("/bin/sleep",args,env);_exit(100);}
    struct pollfd p={.fd=-1};poll(&p,0,30);CHECK(!capture_environment_session(child,"capture-fixture"));stop_child(child);
}
static void test_parent_death(void) {
    int previous=0;CHECK(!prctl(PR_GET_CHILD_SUBREAPER,&previous));CHECK(!prctl(PR_SET_CHILD_SUBREAPER,1));
    int reports;compositor=start_server(&reports);int ready[2];CHECK(!pipe(ready));pid_t parent=fork();
    if(!parent) {
        close(ready[0]);kvm_capture_broker b={.channel=-1,.bootstrap=-1,.helper_pin=-1,.worker_pin=-1,.compositor_pin=-1,.proof_fd=-1,.listener_pin=-1};
        b.request=(capture_message){.magic=CAPTURE_MAGIC,.version=1,.kind=CAP_CONNECT,.generation=654,.parent=getpid(),.worker=getpid(),.uid=desktop_uid,.compositor=compositor};
        b.request.gid=getpwuid(desktop_uid)->pw_gid;
        capture_start(getpid(),&b.request.parent_start);b.request.worker_start=b.request.parent_start;capture_start(compositor,&b.request.compositor_start);
        strcpy(b.request.session,"capture-fixture");strcpy(b.request.display,display);
        if(!capture_spawn(&b))_exit(104);
        uint64_t stop=capture_now()+2000;capture_message message;struct ucred credentials;int fd=-1;
        for(;;) {
            int r=capture_receive(b.bootstrap,&message,&credentials,&fd);
            if(r<0)_exit(105);
            if(r>0)break;
            if(capture_now()>=stop)_exit(106);
            struct pollfd p={.fd=b.bootstrap,.events=POLLIN};poll(&p,1,2);
        }
        if(message.kind!=CAP_READY||credentials.pid!=b.helper||fd<0)_exit(107);
        close(fd);if(write(ready[1],&b.helper,sizeof(b.helper))!=sizeof(b.helper))_exit(108);
        for(;;)pause();
    }
    close(ready[1]);struct pollfd notification={.fd=ready[0],.events=POLLIN};CHECK(poll(&notification,1,2500)>0);
    pid_t helper=0;ssize_t n=read(ready[0],&helper,sizeof(helper));CHECK(n==sizeof(helper)&&helper>0);close(ready[0]);
    uint64_t start;int helper_pin=-1;
    if(helper>0&&capture_start(helper,&start))helper_pin=capture_pin(helper,start);
    CHECK(helper_pin>=0);stop_child(parent);
    if(helper_pin>=0) {
        struct pollfd pin={.fd=helper_pin,.events=POLLIN};CHECK(poll(&pin,1,1000)>0);
        uint64_t end=capture_now()+1000;while(!kvm_capture_helper_reap(helper_pin)&&capture_now()<end){struct pollfd p={.fd=helper_pin,.events=POLLIN};poll(&p,1,2);}
        close(helper_pin);
    } else if(helper>0)waitpid(helper,NULL,WNOHANG);
    stop_child(compositor);close(reports);unlink(socket_path);CHECK(!prctl(PR_SET_CHILD_SUBREAPER,previous));
}
int main(int argc,char **argv) {
    int role=kvm_capture_helper_dispatch(argc,argv);if(role>=0)return role;
    if(geteuid()!=0){fprintf(stderr,"Requires an isolated root test environment\n");return 1;}
    struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core))return 1;
    if(argc==2&&!strcmp(argv[1],"--protocol-only")){test_ancillary();test_sync_credentials();test_sync_select();test_sync_extra_control();printf("Capture protocol and readiness: %d passed, %d failed\n",passed,failed);return failed?1:0;}
    if(argc==1) {
        snprintf(test_directory,sizeof(test_directory),"/run/meshagent-capture-helper-test-%d",getpid());if(mkdir(test_directory,0755))return 2;
        snprintf(installed,sizeof(installed),"%s/probe",test_directory);int in=open("/proc/self/exe",O_RDONLY),out=open(installed,O_WRONLY|O_CREAT|O_EXCL,0755);char buffer[16384];ssize_t n;
        if(in<0||out<0)return 3;
        while((n=read(in,buffer,sizeof(buffer)))>0) { if(write(out,buffer,n)!=n)return 4; }
        close(in);close(out);
        char *args[]={installed,"--installed-test",test_directory,NULL};execv(installed,args);return 5;
    }
    if(argc!=3||strcmp(argv[1],"--installed-test"))return 6;
    snprintf(test_directory,sizeof(test_directory),"%s",argv[2]);snprintf(installed,sizeof(installed),"%s/probe",test_directory);
    snprintf(runtime,sizeof(runtime),"/run/user/%u",desktop_uid);
    if(!mkdir(runtime,0700)){made_runtime=1;CHECK(chown(runtime,desktop_uid,getpwuid(desktop_uid)->pw_gid)==0);}
    struct stat st;if(stat(runtime,&st)||st.st_uid!=desktop_uid||(st.st_mode&077))return 7;
    snprintf(display,sizeof(display),"mesh-capture-%d",getpid());snprintf(socket_path,sizeof(socket_path),"/run/user/%u/mesh-capture-%d",desktop_uid,getpid());
    char sentinel_path[160];snprintf(sentinel_path,sizeof(sentinel_path),"%s/sentinel",test_directory);int sentinel=open(sentinel_path,O_RDWR|O_CREAT|O_EXCL,0600);
    CHECK(sentinel>=0);CHECK(fcntl(sentinel,F_SETFD,0)==0);CHECK(write(sentinel,"private fixture",15)==15);
    test_ancillary();test_sync_credentials();test_sync_select();test_sync_extra_control();test_sandbox();test_existing_parent_filter();test_worker_death();test_session_environment();test_unrelated_sender();
    test_forged_helper_sender(0);test_forged_helper_sender(1);test_forged_helper_sender(2);
    test_handoff(0,0,0);test_handoff(1,0,0);test_handoff(0,1,0);test_handoff(0,0,1);
    test_handoff(0,0,0); /* Fresh worker/helper generation after all rejection paths. */
    fixture_stale_start=1;test_handoff(0,0,0);fixture_stale_start=0;
    fixture_stale_session=1;test_handoff(0,0,0);fixture_stale_session=0;
    fixture_inherited=1;
    test_handoff(0,0,0);test_handoff(1,0,0);
    fixture_reject_wrapper=1;test_handoff(0,0,0);fixture_reject_wrapper=0;
    fixture_reply_mode=1;test_handoff(0,0,0); /* Genuine launcher, forged writer. */
    fixture_reply_mode=2;test_handoff(0,0,0);fixture_reply_mode=0; /* Timeout. */
    test_handoff(0,0,0);fixture_inherited=0;
    test_parent_death();
    char *bad[]={argv[0],KVM_CAPTURE_HELPER_ROLE,"extra",NULL};CHECK(kvm_capture_helper_dispatch(3,bad)==125);
    close(sentinel);unlink(sentinel_path);if(made_runtime)rmdir(runtime);unlink(installed);rmdir(test_directory);
    printf("Capture helper boundary: %d passed, %d failed\n",passed,failed);return failed?1:0;
}
