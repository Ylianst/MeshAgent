/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gnome_assets.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
static int child_case(const char *root,int mode)
{
 if(chroot(root)||chdir("/"))return 20;
 if(mode==0){int fd=mesh_gnome_assets_open_parent();if(fd>=0||errno!=ENOENT)return 21;}
 int fd=mesh_gnome_assets_prepare_parent();
 if(mode==2||mode==3||mode==4){if(fd>=0){close(fd);return 22;}if(mode!=3&&errno!=EPERM)return 29;return 0;}
 if(fd<0)return 23;
 struct stat first,second;if(fstat(fd,&first))return 24;close(fd);
 fd=mesh_gnome_assets_prepare_parent();if(fd<0||fstat(fd,&second))return 25;close(fd);
 if(first.st_ino!=second.st_ino||first.st_uid!=0)return 26;
 if((first.st_mode&0777)!=(mode==1?0700:0755))return 27;
 fd=mesh_gnome_assets_open_parent();if(fd<0)return 28;close(fd);return 0;
}
int main(void)
{
 if(geteuid()!=0){fprintf(stderr,"Run isolated parent tests as root\n");return 2;}
 for(int mode=0;mode<5;mode++){
  char root[]="/tmp/meshagent-parent-tests.XXXXXX",p[512];if(!mkdtemp(root))return 2;
  const char *dirs[]={"usr","usr/share","usr/share/gnome-shell"};
  for(int i=0;i<3;i++){snprintf(p,sizeof(p),"%s/%s",root,dirs[i]);if(mkdir(p,0755))return 2;}
  char parent[512],extension[512];snprintf(parent,sizeof(parent),"%s/usr/share/gnome-shell",root);snprintf(extension,sizeof(extension),"%s/usr/share/gnome-shell/extensions",root);
  if(mode==1&&mkdir(extension,0700))return 2;
  if(mode==2&&chmod(parent,0777))return 2;
  if(mode==3&&symlink("/tmp",extension))return 2;
  if(mode==4&&chown(parent,1000,1000))return 2;
  pid_t pid=fork();if(pid<0)return 2;if(pid==0)_exit(child_case(root,mode));
  int status;if(waitpid(pid,&status,0)!=pid||!WIFEXITED(status)||WEXITSTATUS(status)){fprintf(stderr,"Parent case %d failed (%d)\n",mode,status);return 1;}
  if(mode==3)unlink(extension);else rmdir(extension);
  chmod(parent,0755);chown(parent,0,0);rmdir(parent);
  snprintf(p,sizeof(p),"%s/usr/share",root);rmdir(p);snprintf(p,sizeof(p),"%s/usr",root);rmdir(p);if(rmdir(root))return 2;
 }
 puts("5 isolated GNOME parent-directory checks passed");return 0;
}
