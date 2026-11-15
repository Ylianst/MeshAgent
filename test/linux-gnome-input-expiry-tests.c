/* Focused expiry negotiation/serialization using real local socket transport. */
#include "../meshcore/KVM/Linux/linux_kvm_gnome.c"
#include <sys/wait.h>
#include <signal.h>
int kvm_wayland_active_console_session(kvm_wayland_console_session *out)
{ *out=g_gnome.session; return 1; }
int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a,const kvm_wayland_console_session *b)
{ return a->uid==b->uid && !strcmp(a->id,b->id); }
static int passed,failed;
static void check(int ok,const char *name)
{ if(ok)++passed;else {++failed;fprintf(stderr,"FAIL: %s\n",name);} }
static void put(unsigned char *b,size_t at,uint32_t value)
{ value=htonl(value);memcpy(b+at,&value,4); }
static void header(unsigned char *b,unsigned op,unsigned flags)
{
 memset(b,0,76);memcpy(b,"AGN1",4);put(b,4,op);b[12]=1;put(b,28,1);put(b,32,flags);
 put(b,36,1);put(b,40,1);put(b,44,1);put(b,68,1);put(b,72,1);
}
static int line(int fd,char *out,size_t size)
{
 size_t n=0;while(n+1<size && read(fd,out+n,1)==1) {if(out[n++]=='\n'){out[n]=0;return 1;}}
 return 0;
}
static void peer(int fd,int mode)
{
 char request[512];unsigned char b[76];
 if(!line(fd,request,sizeof(request))||!strstr(request,"\"op\":\"status\""))_exit(10);
 if(mode==2||mode==3) {
  if(!strstr(request,"\"features\":7"))_exit(11);
  header(b,1,mode==2?32:96);if(write(fd,b,76)!=76)_exit(12);_exit(0);
 }
 header(b,1,96);if(write(fd,b,76)!=76)_exit(13);
 if(!line(fd,request,sizeof(request)))_exit(14);
 const char *at=strstr(request,"\"deadlineMs\":");if(!at)_exit(15);
 uint64_t deadline=strtoull(at+13,NULL,10),now=gnome_now();
 if(deadline<=now||deadline>now+400)_exit(16);
 if(mode==6){usleep(600000);_exit(0);}
 header(b,(mode==1||mode==5)?2:5,(mode==4||mode==5)?32:96);
 if(write(fd,b,76)!=76)_exit(17);
 _exit(0);
}
static void scenario(int mode,int expected)
{
 int pair[2],status;check(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0,"socketpair");
 pid_t pid=fork();if(pid==0){close(pair[0]);peer(pair[1],mode);}
 close(pair[1]);g_gnome.fd=pair[0];g_gnome.active=1;g_gnome.session.uid=getuid();strcpy(g_gnome.session.id,"expiry-test");
 g_gnome.status.epoch[0]=1;g_gnome.status.revision=1;g_gnome.status.flags=96;
 kvm_gnome_reply reply;int result;
 if(mode==2||mode==3)result=kvm_gnome_activate(&reply);
 else if(mode==1||mode==5)result=kvm_gnome_type_unicode('X');
 else result=kvm_gnome_key_action(30,1);
 check(result==expected,"negotiation or input outcome");
 if(expected==-1) {
  check(kvm_gnome_key_action(30,0)==-1,"failure latch forbids keyboard replay");
  check(kvm_gnome_type_unicode('Z')==-1,"failure latch forbids text replay");
 }
 kvm_gnome_shutdown();waitpid(pid,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"peer verified exact deadline and feature contract");
}
int main(void)
{
 signal(SIGPIPE,SIG_IGN);
 if(geteuid()==0){struct passwd *pw=getpwnam("nobody");if(!pw||setgroups(0,NULL)||setresgid(pw->pw_gid,pw->pw_gid,pw->pw_gid)||setresuid(pw->pw_uid,pw->pw_uid,pw->pw_uid))return 2;}
 if(prctl(PR_SET_NO_NEW_PRIVS,1L,0L,0L,0L))return 2;
 scenario(0,1);scenario(1,1);scenario(2,0);scenario(3,1);scenario(4,-1);scenario(5,-1);scenario(6,-1);
 unsigned char b[76];kvm_gnome_reply reply;header(b,1,64);
 check(kvm_gnome_decode_header(b,76,&reply),"expiry flag accepted");put(b,32,128);
 check(!kvm_gnome_decode_header(b,76,&reply),"unknown next flag rejected");
 printf("%d native input-expiry checks passed, %d failed\n",passed,failed);return failed?1:0;
}
