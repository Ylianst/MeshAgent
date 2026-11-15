/* SPDX-License-Identifier: Apache-2.0 */
/* Cinnamon/Muffin's input method and Clutter virtual keyboard provide the
 * ordered native path needed by the tested Debian, Mint/LMDE and Fedora
 * Wayland sessions. GNOME Shell's extension cannot run inside Cinnamon.
 *
 * Use the existing session-local Eval API only after authenticating its unique
 * bus owner, root-owned compositor image and matching Wayland socket peer.
 * The evaluated program is fixed Agent source plus numeric input arguments;
 * input text is never interpolated as executable JavaScript. Missing APIs do
 * not enable Eval, replace an input method or change desktop policy.
 *
 * See docs/Wayland-Maintenance.md for routing, regeneration and focused tests.
 */
#include "linux_kvm_cinnamon.h"
#if defined(__linux__)
#include "linux_kvm_wayland.h"
#include "linux_kvm_cinnamon_source.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
struct sd_bus; struct sd_bus_message; struct sd_bus_error;
#define CINNAMON_BUS_API(_) \
 _(int, sd_bus_new, (struct sd_bus **)) \
 _(int, sd_bus_set_address, (struct sd_bus *, const char *)) \
 _(int, sd_bus_set_bus_client, (struct sd_bus *, int)) \
 _(int, sd_bus_set_method_call_timeout, (struct sd_bus *, uint64_t)) \
 _(int, sd_bus_start, (struct sd_bus *)) \
 _(struct sd_bus *, sd_bus_close_unref, (struct sd_bus *)) \
 _(int, sd_bus_call_method, (struct sd_bus *, const char *, const char *, const char *, const char *, struct sd_bus_error *, struct sd_bus_message **, const char *, ...)) \
 _(int, sd_bus_message_read, (struct sd_bus_message *, const char *, ...)) \
 _(struct sd_bus_message *, sd_bus_message_unref, (struct sd_bus_message *))
#define DECL(ret, name, args) static ret (*c_##name) args;
CINNAMON_BUS_API(DECL)
#undef DECL
static struct {
 void *library; struct sd_bus *bus; char owner[128], token[33];
 int unavailable, failed; uint32_t nonce; kvm_wayland_console_session session;
} cinnamon;

/* The private JavaScript operation result is not the public adapter result:
 * -1 invalid/uncertain, 0 completed, 1 pending, 2 declined before injection.
 * Keep parsing bounded and reject unexpected values rather than guessing
 * whether it is safe to send the same input through another backend. */
static int cinnamon_eval(const char *script)
{
 struct sd_bus_message *reply=NULL; const char *text=NULL; int success=0, result=-1;
 if(c_sd_bus_call_method(cinnamon.bus,cinnamon.owner,"/org/Cinnamon","org.Cinnamon","Eval",NULL,&reply,"s",script)>=0 &&
    c_sd_bus_message_read(reply,"bs",&success,&text)>=0 && success && text && strlen(text)<8) {
  char *end;long value=strtol(text,&end,10);if(end!=text&&!*end&&value>=-1&&value<=2)result=(int)value;
 }
 if(reply)c_sd_bus_message_unref(reply);
 return result;
}
/* Internal operations: 1 raw key, 2 scalar text, 3 completion poll, 4 dispose.
 * The random hex token identifies this capture worker's keyboard record.
 * It isolates ownership between workers, not a separate user privilege level. */
static int cinnamon_command(unsigned op,uint32_t nonce,uint32_t key,int pressed)
{
 char code[256];
 snprintf(code,sizeof(code),"global._meshAgentCinnamonInputV1 ? global._meshAgentCinnamonInputV1('%s',%u,%u,%u,%d) : -1",cinnamon.token,op,nonce,key,pressed);
 return cinnamon_eval(code);
}
void kvm_cinnamon_shutdown(void)
{
 if(cinnamon.bus) { if(cinnamon.token[0]) (void)cinnamon_command(4,0,0,0); cinnamon.bus=c_sd_bus_close_unref(cinnamon.bus); }
 cinnamon.owner[0]=0;cinnamon.token[0]=0;cinnamon.nonce=0;cinnamon.failed=0;cinnamon.unavailable=0;
 memset(&cinnamon.session,0,sizeof(cinnamon.session));
}
/* A D-Bus name alone is insufficient: require the same process to own the
 * Wayland connection and the trusted executable. A vendor update may unlink
 * the running image; the old image must still be root-owned and non-writable. */
static int cinnamon_peer(uint32_t pid,const char *runtime)
{
 char proc[64],exe[PATH_MAX],socketPath[PATH_MAX];struct stat current,installed,info;
 struct {pid_t pid;uid_t uid;gid_t gid;} peer; socklen_t size=sizeof(peer); struct sockaddr_un address;
 const char *display=getenv("WAYLAND_DISPLAY");int fd,ok=0;ssize_t length;
 if(!pid||!display||!*display||strchr(display,'/')||strlen(display)>=64)return 0;
 snprintf(proc,sizeof(proc),"/proc/%u/exe",pid);length=readlink(proc,exe,sizeof(exe)-1);
 if(length<=0||length>=(ssize_t)sizeof(exe)-1)return 0;
 exe[length]=0;
 if(strcmp(exe,"/usr/bin/cinnamon")&&strcmp(exe,"/usr/bin/cinnamon (deleted)"))return 0;
 if(stat("/usr/bin/cinnamon",&installed)||stat(proc,&current)||installed.st_uid||current.st_uid||
    !S_ISREG(installed.st_mode)||!S_ISREG(current.st_mode)||(installed.st_mode&0022)||(current.st_mode&0022)||
    ((current.st_dev!=installed.st_dev||current.st_ino!=installed.st_ino)&&!strstr(exe," (deleted)")))return 0;
 snprintf(socketPath,sizeof(socketPath),"%s/%s",runtime,display);
 if(strlen(socketPath)>=sizeof(address.sun_path)||lstat(socketPath,&info)||!S_ISSOCK(info.st_mode)||info.st_uid!=geteuid())return 0;
 memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;strcpy(address.sun_path,socketPath);
 fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return 0;
 if(!connect(fd,(struct sockaddr*)&address,sizeof(address))&&!getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)&&
    size==sizeof(peer)&&peer.uid==geteuid()&&peer.pid==(pid_t)pid)ok=1;
 close(fd);return ok;
}
/* Absence is cached only for this capture worker. A session change after
 * activation invalidates delivery instead of targeting the next login's UI.
 * GetNameOwner deliberately avoids auto-starting a compositor on the bus. */
static int cinnamon_ready(void)
{
 kvm_wayland_console_session session;struct stat info;struct sd_bus_message *reply=NULL;
 const char *owner;uint32_t uid,pid;char runtime[64],address[128];unsigned char random[16];char *script=NULL;int ok=0;
 if(cinnamon.failed)return -1;
 if(cinnamon.unavailable)return 0;
 if(!kvm_wayland_active_console_session(&session)||session.uid!=(int)geteuid()||session.uid<=0||strcmp(session.type,"wayland")) {
  if(cinnamon.bus){kvm_cinnamon_shutdown();cinnamon.failed=1;return -1;}
  return 0;
 }
 if(cinnamon.bus) {
  if(kvm_wayland_console_session_equal(&session,&cinnamon.session))return 1;
  kvm_cinnamon_shutdown();cinnamon.failed=1;return -1;
 }
 if(!cinnamon.library) {
  void *lib=dlopen("libsystemd.so.0",RTLD_NOW|RTLD_LOCAL);if(!lib)goto fail;
#define LOAD(ret,name,args) c_##name=(__typeof__(c_##name))dlsym(lib,#name);if(!c_##name){dlclose(lib);goto fail;}
  CINNAMON_BUS_API(LOAD)
#undef LOAD
  cinnamon.library=lib;
 }
 snprintf(runtime,sizeof(runtime),"/run/user/%u",(unsigned)geteuid());
 if(lstat(runtime,&info)||!S_ISDIR(info.st_mode)||info.st_uid!=geteuid()||(info.st_mode&0077))goto fail;
 snprintf(address,sizeof(address),"unix:path=%s/bus",runtime);
 if(c_sd_bus_new(&cinnamon.bus)<0||c_sd_bus_set_address(cinnamon.bus,address)<0||c_sd_bus_set_bus_client(cinnamon.bus,1)<0||
    c_sd_bus_set_method_call_timeout(cinnamon.bus,250000)<0||c_sd_bus_start(cinnamon.bus)<0)goto fail;
 if(c_sd_bus_call_method(cinnamon.bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner",NULL,&reply,"s","org.Cinnamon")<0||
    c_sd_bus_message_read(reply,"s",&owner)<0||!owner||owner[0]!=':'||strlen(owner)>=sizeof(cinnamon.owner))goto fail;
 strcpy(cinnamon.owner,owner);reply=c_sd_bus_message_unref(reply);
 if(c_sd_bus_call_method(cinnamon.bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetConnectionUnixUser",NULL,&reply,"s",cinnamon.owner)<0||
    c_sd_bus_message_read(reply,"u",&uid)<0||uid!=geteuid())goto fail;
 reply=c_sd_bus_message_unref(reply);
 if(c_sd_bus_call_method(cinnamon.bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetConnectionUnixProcessID",NULL,&reply,"s",cinnamon.owner)<0||
    c_sd_bus_message_read(reply,"u",&pid)<0||!cinnamon_peer(pid,runtime))goto fail;
 reply=c_sd_bus_message_unref(reply);
 /* Read entropy without adding a newer glibc getrandom dependency to Agent
  * builds that must still load on older supported Linux installations. */
 {
  int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);size_t done=0;
  if(fd<0)goto fail;
  while(done<sizeof(random)) {
   ssize_t count=read(fd,random+done,sizeof(random)-done);
   if(count<0&&errno==EINTR)continue;
   if(count<=0)break;
   done+=(size_t)count;
  }
  close(fd);if(done!=sizeof(random))goto fail;
 }
 for(unsigned i=0;i<sizeof(random);i++)snprintf(cinnamon.token+i*2,3,"%02x",random[i]);
 script=malloc(sizeof(cinnamon_source)+128);if(!script)goto fail;
 snprintf(script,sizeof(cinnamon_source)+128,"%s(%u,'%s')",cinnamon_source,(unsigned)getpid(),cinnamon.token);
 if(cinnamon_eval(script)!=0)goto fail;
 cinnamon.session=session;
 if(!kvm_wayland_active_console_session(&session)||!kvm_wayland_console_session_equal(&session,&cinnamon.session))goto fail;
 ok=1;
fail:
 free(script);if(reply)c_sd_bus_message_unref(reply);
 if(!ok){kvm_cinnamon_shutdown();cinnamon.unavailable=1;}
 return ok;
}
/* Poll an explicit compositor completion token under one monotonic deadline.
 * The 1 ms wait is acknowledgment polling, not key pacing or text replay.
 * A timeout may follow successful injection, so it must latch failure. */
static int cinnamon_input(unsigned op,uint32_t code,int pressed)
{
 int ready=cinnamon_ready(),result;struct timespec start,now,pause={0,1000000};uint64_t deadline;
 if(ready!=1)return ready;
 if(++cinnamon.nonce==0)++cinnamon.nonce;
 if(clock_gettime(CLOCK_MONOTONIC,&start))return -1;
 deadline=(uint64_t)start.tv_sec*1000+start.tv_nsec/1000000+250;
 result=cinnamon_command(op,cinnamon.nonce,code,pressed);
 if(result==2)return 0; /* Explicitly declined before any input was queued. */
 while(result==1) {
  if(clock_gettime(CLOCK_MONOTONIC,&now)||(uint64_t)now.tv_sec*1000+now.tv_nsec/1000000>=deadline)break;
  nanosleep(&pause,NULL);result=cinnamon_command(3,cinnamon.nonce,0,0);
 }
 if(result==0)return 1;
 /* Delivery may have begun; release owned keys and never replay input. */
 kvm_cinnamon_shutdown();cinnamon.failed=1;return -1;
}
int kvm_cinnamon_key_action(uint32_t key,int pressed)
{return key>0&&key<=767&&(pressed==0||pressed==1)?cinnamon_input(1,key,pressed):0;}
int kvm_cinnamon_type_unicode(uint32_t cp)
{return cp>=0x20&&!(cp>=0x7f&&cp<0xa0)&&cp<=0x10ffff&&!(cp>=0xd800&&cp<=0xdfff)?cinnamon_input(2,cp,0):0;}
#else
int kvm_cinnamon_key_action(uint32_t key,int pressed){(void)key;(void)pressed;return 0;}
int kvm_cinnamon_type_unicode(uint32_t cp){(void)cp;return 0;}
void kvm_cinnamon_shutdown(void){}
#endif
