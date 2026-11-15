/* SPDX-License-Identifier: Apache-2.0 */
/* Transport-only harness: mock logind identity, real privilege gate, sockets,
 * SCM_RIGHTS, kernel size/write seals and native transaction decoder. */
#include "../meshcore/KVM/Linux/linux_kvm_gnome.c"
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>

int kvm_wayland_active_console_session(kvm_wayland_console_session *out)
{ *out = g_gnome.session; return 1; }
int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a, const kvm_wayland_console_session *b)
{ return a->uid == b->uid && !strcmp(a->id,b->id); }
static int passed, failed;
static void check(int value, const char *name)
{ if(value)++passed;else {++failed;fprintf(stderr,"FAIL: %s\n",name);} }
static void put(unsigned char *b,size_t at,uint32_t n)
{ n=htonl(n);memcpy(b+at,&n,4); }
static void header(unsigned char *b,int result,int revision,int flags)
{
 memset(b,0,76);memcpy(b,"AGN1",4);put(b,4,4);put(b,8,result);b[12]=1;
 put(b,28,revision);put(b,32,flags);put(b,36,1024);put(b,40,768);put(b,44,1);put(b,68,1024);put(b,72,768);
}
static void peer(int socket_fd,int mode)
{
 char request[256];size_t count=0;unsigned char b[76],byte=0;
 struct iovec iov={&byte,1};union {struct cmsghdr align;unsigned char b[CMSG_SPACE(sizeof(int))];} control;
 struct msghdr msg={0};int frame_fd=-1;void *mapping=MAP_FAILED;
 while(count<sizeof(request)&&read(socket_fd,request+count,1)==1&&request[count++]!='\n'){}
 if(!count)_exit(1);
 if(mode>=12) {
   if(count>=sizeof(request)){_exit(16);}
   request[count]=0;
   if(!strstr(request,"\"op\":\"status\""))_exit(17);
   header(b,mode==16?1:0,1,96);put(b,4,1);if(write(socket_fd,b,76)!=76)_exit(18);
   if(mode==16)_exit(0);
   count=0;while(count<sizeof(request)&&read(socket_fd,request+count,1)==1&&request[count++]!='\n'){}
   if(!count||count>=sizeof(request)){_exit(19);}
   request[count]=0;
   if(!strstr(request,"\"op\":\"key\"")||!strstr(request,"\"code\":30")||!strstr(request,"\"value\":1"))_exit(20);
   header(b,mode==13?1:0,mode==14?2:1,96);put(b,4,5);if(mode==15)b[12]=2;
   if(write(socket_fd,b,76)!=76){_exit(21);}
   _exit(0);
 }

 if(mode==1){header(b,0,1,16);if(write(socket_fd,b,76)!=76)_exit(13);_exit(0);} // No READY.
 if(mode==2){header(b,2,1,20);if(write(socket_fd,b,76)!=76)_exit(13);_exit(0);} // Asleep before READY.
 if(mode==10){usleep(1700000);_exit(0);} // Real bounded receive deadline.
 header(b,3,1,16);if(write(socket_fd,b,76)!=76)_exit(2);
 msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=control.b;msg.msg_controllen=sizeof(control.b);
 if(recvmsg(socket_fd,&msg,MSG_CMSG_CLOEXEC)!=1)_exit(3);
 struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
 if(!c||c->cmsg_type!=SCM_RIGHTS||c->cmsg_level!=SOL_SOCKET||c->cmsg_len!=CMSG_LEN(sizeof(int)))_exit(4);
 memcpy(&frame_fd,CMSG_DATA(c),sizeof(frame_fd));
 struct stat st;if(fstat(frame_fd,&st)||st.st_size!=KVM_GNOME_MAX_PAYLOAD||(st.st_mode&0777)!=0600)_exit(5);
 if((fcntl(frame_fd,F_GET_SEALS)&(F_SEAL_GROW|F_SEAL_SHRINK))!=(F_SEAL_GROW|F_SEAL_SHRINK))_exit(6);
 if(ftruncate(frame_fd,KVM_GNOME_MAX_PAYLOAD+1)!=-1||errno!=EPERM)_exit(7);
 if(mode==3){close(frame_fd);_exit(0);} // Disconnect after descriptor receipt.
 if(mode==4){mapping=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,frame_fd,0);if(mapping==MAP_FAILED)_exit(8);}
 if(mode!=5&&write(frame_fd,"PNG",3)!=3)_exit(9); // Empty output.
 header(b,mode==6?2:0,mode==7?2:1,mode==6?20:16);
 if(mode==8)put(b,48,3); // Forbidden inline payload.
 if(mode==9){if(write(socket_fd,b,12)!=12)_exit(14);_exit(0);} // Truncated completion.
 if(write(socket_fd,b,76)!=76)_exit(10);
 if(mode==0) {
   if(read(socket_fd,&byte,1)!=1||byte!='D')_exit(11);
   if(pwrite(frame_fd,"X",1,0)!=-1||errno!=EPERM)_exit(12);
 }
 if(mode==4&&read(socket_fd,&byte,1)!=0)_exit(15);
 if(mapping!=MAP_FAILED)munmap(mapping,4096);
 close(frame_fd);_exit(0);
}
static int descriptor_count(void)
{
 DIR *directory=opendir("/proc/self/fd");int count=0;struct dirent *entry;
 if(!directory)return -1;
 while((entry=readdir(directory)))if(entry->d_name[0]!='.')++count;
 closedir(directory);return count;
}
static void scenario(int mode,int expected,const char *name)
{
 int before=descriptor_count();
 int pair[2];check(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)==0,"socketpair");
 pid_t pid=fork();if(pid==0){close(pair[0]);peer(pair[1],mode);}
 close(pair[1]);g_gnome.fd=pair[0];g_gnome.peer=pid;g_gnome.active=1;g_gnome.session.uid=getuid();strcpy(g_gnome.session.id,"fixture");
 int passcred=1;check(setsockopt(g_gnome.fd,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred))==0,"reply credentials enabled");
 g_gnome.status.epoch[0]=1;g_gnome.status.revision=1;g_gnome.status.flags=mode>=12?96:16;
 kvm_gnome_reply reply;unsigned char *payload=NULL;
 int result;
 if(mode>=12){result=kvm_gnome_key_action(30,1);if(mode==14)check(g_gnome.status.revision==2,"own lock transition acknowledged without replay");}
 else if(mode==11){const unsigned char *rgb=NULL;uint32_t width=0,height=0;result=kvm_gnome_frame(&rgb,&width,&height,&reply);check(!rgb,"invalid PNG never yields pixels");}
 else result=gnome_request("{\"op\":\"captureFd\",\"wire\":1}\n",4,&reply,&payload);
 check(result==expected,name);
 if(mode>=12&&expected==-1) {
   check(kvm_gnome_key_action(30,0)==-1,"failed GNOME key route forbids later backend fallback");
   check(kvm_gnome_type_unicode('x')==-1,"failed GNOME key route forbids later text fallback");
 }
 if(mode<12&&expected==0) {
   check(kvm_gnome_key_action(30,1)==-1,"failed selected capture route forbids keyboard fallback");
   check(kvm_gnome_type_unicode('x')==-1,"failed selected capture route forbids text fallback");
 }
 if(mode==0&&result){check(reply.payload_size==3&&payload&&!memcmp(payload,"PNG",3),"sealed descriptor bytes");send(g_gnome.fd,"D",1,MSG_NOSIGNAL);}
 if((mode==2||mode==6)&&result)check(reply.result==2&&!payload,"suspension has no image");
 free(payload);kvm_gnome_shutdown();int status;waitpid(pid,&status,0);check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"peer completed and descriptors closed");
 check(before==descriptor_count(),"no native descriptor leak");
}
int main(void)
{
 signal(SIGPIPE,SIG_IGN);
 if(geteuid()==0){struct passwd *pw=getpwnam("nobody");if(!pw||setgroups(0,NULL)||setresgid(pw->pw_gid,pw->pw_gid,pw->pw_gid)||setresuid(pw->pw_uid,pw->pw_uid,pw->pw_uid))return 2;}
 if(prctl(PR_SET_NO_NEW_PRIVS,1L,0L,0L,0L))return 2;
 scenario(0,1,"valid bounded sealed frame");scenario(1,0,"no unsolicited completion");
 scenario(2,1,"power-off before descriptor");scenario(3,0,"disconnect awaiting image");
 scenario(4,0,"retained writable mapping rejected");scenario(5,0,"empty image rejected");
 scenario(6,1,"power-off after descriptor");scenario(7,0,"changed generation rejected");
 scenario(8,0,"inline payload rejected");scenario(9,0,"truncated completion rejected");
 scenario(10,0,"missing reply hits deadline");
 scenario(11,0,"PNG decoder failure closes transaction");
 scenario(12,1,"compositor key acknowledged");scenario(13,-1,"declined key never falls back");
 scenario(14,1,"key advances Shell mode");scenario(15,-1,"key epoch change rejected");
 scenario(16,-1,"key status failure rejected");
 check(kvm_gnome_key_action(30,1)==0,"unavailable compositor route leaves legacy input available");
 check(kvm_gnome_type_unicode('x')==0,"explicit teardown resets text failure latch");
 printf("%d descriptor transaction checks passed, %d failed\n",passed,failed);return failed?1:0;
}
