/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gnome_autostart.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int passed,failed,fail_sync=-1;
#define need(value) do{if(!(value)){perror(#value);return 2;}}while(0)
int __real_fsync(int fd);
int __wrap_fsync(int fd){if(fd==fail_sync||fail_sync==-2){errno=EIO;return -1;}return __real_fsync(fd);}
static void check(int ok,const char *text){if(ok)++passed;else{++failed;fprintf(stderr,"FAIL %s (errno %d)\n",text,errno);}}
static int count(int parent){int copy=openat(parent,".",O_RDONLY|O_DIRECTORY);DIR *dir=fdopendir(copy);struct dirent *entry;int n=0;while((entry=readdir(dir)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,".."))++n;closedir(dir);return n;}
int main(void)
{
 if(geteuid()!=0)return 2;
 char path[]="/tmp/meshagent-autostart.XXXXXX",a[65],b[65],name[100],other[100];
 memset(a,'a',64);a[64]=0;memset(b,'b',64);b[64]=0;
 if(!mkdtemp(path))return 2;
 int parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW),changed=-1,r;struct stat st;
 if(parent<0)return 2;
 const unsigned char text[]="[Desktop Entry]\nType=Application\nName=fixture\n",different[]="changed";
 size_t size=sizeof(text)-1;
 snprintf(name,sizeof(name),"meshagent-gnome-%s.desktop",a);snprintf(other,sizeof(other),"meshagent-gnome-%s.desktop",b);
 r=mesh_gnome_autostart_install(parent,a,text,size,&changed);check(r==1&&changed==1,"publish new entry");
 check(!fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)&&S_ISREG(st.st_mode)&&(st.st_mode&07777)==0644&&!st.st_uid&&st.st_nlink==1,"root regular mode0644 nlink1");
 check(count(parent)==1,"no temporary file after publish");
 check(mesh_gnome_autostart_install(parent,a,text,size,&changed)==1&&!changed,"idempotent install");
 check(mesh_gnome_autostart_install(parent,a,different,sizeof(different)-1,&changed)==0&&!changed,"preserve differing entry on install");
 check(mesh_gnome_autostart_remove(parent,a,different,sizeof(different)-1,&changed)==0&&!changed,"preserve edited entry on remove");
 check(mesh_gnome_autostart_install(parent,b,text,size,&changed)==1&&changed,"independent service entry");
 check(mesh_gnome_autostart_remove(parent,a,text,size,&changed)==1&&changed&&count(parent)==1,"remove only one service entry");
 check(mesh_gnome_autostart_remove(parent,a,text,size,&changed)==1&&!changed,"absent remove is neutral");
 need(!symlinkat(other,parent,name));
 check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed,"refuse symlink install");
 check(!mesh_gnome_autostart_remove(parent,a,text,size,&changed)&&!changed,"refuse symlink remove");unlinkat(parent,name,0);
 need(!linkat(parent,other,parent,name,0));
 check(!mesh_gnome_autostart_remove(parent,a,text,size,&changed)&&!changed,"refuse hardlinked entry");unlinkat(parent,name,0);
 mkfifoat(parent,name,0644);
 check(!mesh_gnome_autostart_remove(parent,a,text,size,&changed)&&!changed,"refuse FIFO without blocking");unlinkat(parent,name,0);
 mkdirat(parent,name,0755);
 check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed,"refuse directory");unlinkat(parent,name,AT_REMOVEDIR);
 need(!fchmodat(parent,other,0664,0));
 check(!mesh_gnome_autostart_remove(parent,b,text,size,&changed)&&!changed,"preserve unsafe file mode");need(!fchmodat(parent,other,0644,0));
 need(!fchownat(parent,other,65534,65534,0));
 check(!mesh_gnome_autostart_remove(parent,b,text,size,&changed)&&!changed,"preserve non-root entry");need(!fchownat(parent,other,0,0,0));
 fchmod(parent,0777);
 check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed,"refuse writable parent");fchmod(parent,0700);
 int second=open(path,O_RDONLY|O_DIRECTORY);flock(second,LOCK_EX|LOCK_NB);
 check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed,"nonblocking lock contention");close(second);
 check(!mesh_gnome_autostart_install(parent,"../bad",text,size,&changed)&&!changed,"refuse path-like owner");
 a[0]='A';check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed,"refuse uppercase owner");a[0]='a';
 check(!mesh_gnome_autostart_install(parent,a,NULL,size,&changed)&&!changed,"refuse null data");
 check(!mesh_gnome_autostart_install(parent,a,text,0,&changed)&&!changed,"refuse empty data");
 check(!mesh_gnome_autostart_install(parent,a,text,32769,&changed)&&!changed,"refuse oversized data before read");
 check(!mesh_gnome_autostart_install(parent,a,text,sizeof(text),&changed)&&!changed,"refuse embedded NUL");
 fail_sync=-2;check(!mesh_gnome_autostart_install(parent,a,text,size,&changed)&&!changed&&count(parent)==1,"file fsync failure cleans temporary entry without publish");fail_sync=-1;
 fail_sync=parent;check(mesh_gnome_autostart_install(parent,a,text,size,&changed)==-1&&changed&&count(parent)==2,"publish durability failure preserves applied state");fail_sync=-1;
 check(mesh_gnome_autostart_install(parent,a,text,size,&changed)==1&&!changed,"inspect applied entry after durability failure");
 fail_sync=parent;check(mesh_gnome_autostart_remove(parent,a,text,size,&changed)==-1&&changed&&count(parent)==1,"remove durability failure reports applied state");fail_sync=-1;
 pid_t pid=fork();need(pid>=0);if(!pid){if(setgid(65534)||setuid(65534))_exit(2);_exit(mesh_gnome_autostart_install(parent,a,text,size,&changed)==0&&!changed?0:1);}int status;need(waitpid(pid,&status,0)==pid);
 check(WIFEXITED(status)&&!WEXITSTATUS(status),"non-root writer refused");
 check(mesh_gnome_autostart_remove(parent,b,text,size,&changed)==1&&changed&&count(parent)==0,"last entry removal leaves private parent empty");
 snprintf(name,sizeof(name),"meshagent-gnome-%s.conf",a);
 check(mesh_gnome_greeter_startup_install(parent,a,text,size,&changed)==1&&changed,"publish separate owned GDM drop-in");
 check(!fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)&&S_ISREG(st.st_mode),"GDM drop-in has fixed conf suffix");
 check(!mesh_gnome_greeter_startup_remove(parent,a,different,sizeof(different)-1,&changed)&&!changed,"preserve edited GDM drop-in");
 check(mesh_gnome_greeter_startup_remove(parent,a,text,size,&changed)==1&&changed&&count(parent)==0,"remove only exact GDM drop-in");
 pid=fork();need(pid>=0);if(!pid){
  if(chroot(path)||chdir("/"))_exit(2);
  if(mesh_gnome_greeter_startup_open_parent(0)>=0||errno!=ENOENT)_exit(3);
  umask(0077);
  int target=mesh_gnome_greeter_startup_open_parent(1);if(target<0||fstat(target,&st)||(st.st_mode&0777)!=0755)_exit(4);close(target);
  const char *dir="/etc/systemd/user/org.gnome.Shell@gdm.service.d";
  if(rmdir(dir)||symlink("/tmp",dir))_exit(5);
  target=mesh_gnome_greeter_startup_open_parent(1);if(target>=0)_exit(6);
  if(unlink(dir)||rmdir("/etc/systemd/user")||rmdir("/etc/systemd")||rmdir("/etc"))_exit(7);
  _exit(0);
 }need(waitpid(pid,&status,0)==pid);
 check(WIFEXITED(status)&&!WEXITSTATUS(status),"GDM fixed parent creates trusted directories, leaves uninstall absent, refuses symlink traversal");
 close(parent);check(!rmdir(path),"private fixture cleaned");
 printf("%d focused GNOME autostart checks passed, %d failed\n",passed,failed);return failed?1:0;
}
