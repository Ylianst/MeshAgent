/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "meshcore/KVM/Linux/linux_kvm_gala.c"
#include <assert.h>
#include <sys/wait.h>
int mesh_gala_assets_trusted(void){return 0;}
static kvm_wayland_console_session active={.id="c1",.uid=1000,.type="wayland",.state="active"};
static uint32_t source_revision=2;
int kvm_wayland_active_console_session(kvm_wayland_console_session *s){*s=active;return 1;}
int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a,const kvm_wayland_console_session *b){return a->uid==b->uid&&!strcmp(a->id,b->id)&&!strcmp(a->type,b->type);}
static void scenario_sender(int status,int bad_magic,int truncated,int change_epoch,int expected,int wrong_sender){
    int sockets[2];assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    pid_t child=fork();assert(child>=0);
    if(!child){
        close(sockets[0]);unsigned char request_bytes[40],response[32]={0};size_t offset=0;
        while(offset<sizeof(request_bytes)){ssize_t n=read(sockets[1],request_bytes+offset,sizeof(request_bytes)-offset);if(n<=0)_exit(5);offset+=(size_t)n;}
        assert(!memcmp(request_bytes,"AGL1",4)&&get32(request_bytes+4)==2&&get32(request_bytes+32)==0x4e2d);
        uint64_t deadline=(uint64_t)get32(request_bytes+24)<<32|get32(request_bytes+28);assert(deadline>=gala_now());
        memcpy(response,bad_magic?"BAD!":"AGL1",4);put32(response+4,(uint32_t)status);memset(response+8,change_epoch?7:6,16);put32(response+24,source_revision);
        assert(write(sockets[1],response,truncated?12:32)==(truncated?12:32));close(sockets[1]);_exit(0);
    }
    close(sockets[1]);kvm_gala_shutdown();gala.fd=sockets[0];gala.session=active;gala.peer=child+(wrong_sender?1:0);gala.ready=1;memset(gala.epoch,6,16);
    int passcred=1;assert(!setsockopt(gala.fd,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred)));
    assert(kvm_gala_type_unicode(0x4e2d)==expected);
    if(expected<0)assert(gala.failed&&gala.fd<0);else assert(!gala.failed&&gala.fd>=0);
    kvm_gala_shutdown();int child_status;assert(waitpid(child,&child_status,0)==child&&WIFEXITED(child_status)&&!WEXITSTATUS(child_status));
}
static void scenario(int status,int bad_magic,int truncated,int change_epoch,int expected){scenario_sender(status,bad_magic,truncated,change_epoch,expected,0);}
int main(void){
    active.uid=getuid();
    assert(kvm_gala_type_unicode('a')==0); /* Other desktops keep their route. */
    scenario(0,0,0,0,1);scenario(1,0,0,0,0); /* Explicit pre-injection refusal permits fallback. */
    scenario(2,0,0,0,-1);scenario(0,1,0,0,-1);scenario(0,0,1,0,-1);scenario(0,0,0,1,-1);
    source_revision=99;scenario(0,0,0,0,1);source_revision=0;scenario(0,0,0,0,-1);
    source_revision=2;scenario_sender(0,0,0,0,-1,1); /* Socket holder is not the authenticated compositor. */
    assert(trusted_scope("0::/user.slice/user-1000.slice/user@1000.service/session.slice/_io.elementary.gala@wayland.service\n",1000));
    assert(trusted_scope("0::/user.slice/user-1000.slice/user@1000.service/session.slice/io.elementary.gala@wayland.service\n",1000));
    assert(!trusted_scope("0::/user.slice/user-1000.slice/user@1000.service/session.slice/io.elementary.gala@wayland.service/child\n",1000));
    assert(!trusted_scope("0::/user.slice/user-1000.slice/user@1000.service/session.slice/io.elementary.gala@wayland.service\n",1001));
    assert(!trusted_scope("0::/user.slice/user-1000.slice/session-c1.scope\n",1000));
    kvm_wayland_console_session x11=active;strcpy(x11.type,"x11");assert(!kvm_gala_prepare(&x11));
    assert(kvm_gala_type_unicode('a')==0);
    puts("Gala transport: exact request, successful text, safe fallback, expired/malformed/truncated/stale replies and non-Gala/X11 isolation passed");
}
