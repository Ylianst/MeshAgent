/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#ifdef __linux__
#include "linux_gnome_autostart.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define LIMIT 32768
static int trusted(int fd)
{ struct stat st; return !fstat(fd,&st) && S_ISDIR(st.st_mode) && !st.st_uid && !(st.st_mode & 0022); }
int mesh_gnome_autostart_open_parent(void)
{
    const char *parts[]={"etc","xdg","autostart"};
    if (geteuid()!=0) { errno=EPERM; return -1; }
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    for(size_t i=0;i<sizeof(parts)/sizeof(parts[0]);++i)
    {
        if(!trusted(fd)){close(fd);errno=EPERM;return -1;}
        int next=openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),error=errno;
        close(fd);fd=next;if(fd<0){errno=error;return -1;}
    }
    if(!trusted(fd)){close(fd);errno=EPERM;return -1;}
    return fd;
}
int mesh_gnome_greeter_startup_open_parent(int create)
{
    const char *parts[]={"etc","systemd","user","org.gnome.Shell@gdm.service.d"};
    if(geteuid()!=0){errno=EPERM;return -1;}
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    for(size_t i=0;i<sizeof(parts)/sizeof(parts[0]);++i)
    {
        if(!trusted(fd)){close(fd);errno=EPERM;return -1;}
        int next=openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(next<0&&errno==ENOENT&&create)
        {
            int created=mkdirat(fd,parts[i],0755)==0;
            if(!created&&errno!=EEXIST){int error=errno;close(fd);errno=error;return -1;}
            next=openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(created&&(next<0||!trusted(next)||fchmod(next,0755)||fsync(fd)))
            {int error=errno;if(next>=0)close(next);close(fd);errno=error;return -1;}
        }
        int error=errno;close(fd);fd=next;if(fd<0){errno=error;return -1;}
    }
    if(!trusted(fd)){close(fd);errno=EPERM;return -1;}
    return fd;
}
static int lock(int parent,const char *owner,const unsigned char *data,size_t size,char name[100],const char *suffix)
{
    if(geteuid()!=0||!trusted(parent)){errno=EPERM;return 0;}
    if(!owner||strlen(owner)!=64||!data||!size||size>LIMIT||memchr(data,0,size)){errno=EINVAL;return 0;}
    for(size_t i=0;i<64;++i)
        if(!((owner[i]>='0'&&owner[i]<='9')||(owner[i]>='a'&&owner[i]<='f'))){errno=EINVAL;return 0;}
    snprintf(name,100,"meshagent-gnome-%s.%s",owner,suffix);
    return flock(parent,LOCK_EX|LOCK_NB)==0;
}
static int done(int parent,int result)
{ int error=errno;flock(parent,LOCK_UN);errno=error;return result; }
/* 1 exact existing entry, 2 absent, 0 refusal/error. */
static int exact(int parent,const char *name,const unsigned char *data,size_t size)
{
    struct stat st,entry;unsigned char bytes[LIMIT];
    int fd=openat(parent,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return errno==ENOENT?2:0;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||
       (st.st_mode&07777)!=0644||st.st_size!=(off_t)size)
    {close(fd);errno=EPERM;return 0;}
    size_t offset=0;
    while(offset<size)
    {
        ssize_t n=read(fd,bytes+offset,size-offset);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){int error=n<0?errno:EIO;close(fd);errno=error;return 0;}
        offset+=(size_t)n;
    }
    if(memcmp(bytes,data,size)||fstatat(parent,name,&entry,AT_SYMLINK_NOFOLLOW)||
       st.st_dev!=entry.st_dev||st.st_ino!=entry.st_ino)
    {close(fd);errno=ESTALE;return 0;}
    close(fd);return 1;
}
static int install(int parent,const char *owner,const unsigned char *data,size_t size,int *changed,const char *suffix)
{
    char name[100],temp[100];unsigned char random[16];size_t offset=0;
    if(changed)*changed=0;
    if(!lock(parent,owner,data,size,name,suffix))return 0;
    int exists=exact(parent,name,data,size);
    if(exists!=2)return done(parent,exists==1?1:0);
    while(offset<sizeof(random))
    {
        ssize_t n=syscall(SYS_getrandom,random+offset,sizeof(random)-offset,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){if(!n)errno=EIO;return done(parent,0);}
        offset+=(size_t)n;
    }
    const char *prefix=".meshagent-gnome-";size_t prefixSize=strlen(prefix);
    memcpy(temp,prefix,prefixSize);
    for(size_t i=0;i<sizeof(random);++i)snprintf(temp+prefixSize+2*i,3,"%02x",random[i]);
    int fd=openat(parent,temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return done(parent,0);
    int result=0,error=0;offset=0;
    while(offset<size)
    {
        ssize_t n=write(fd,data+offset,size-offset);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){error=n<0?errno:EIO;goto cleanup;}
        offset+=(size_t)n;
    }
    if(fchmod(fd,0644)||fsync(fd)){error=errno;goto cleanup;}
    if(close(fd)){error=errno;fd=-1;goto cleanup;}fd=-1;
    if(syscall(SYS_renameat2,parent,temp,parent,name,RENAME_NOREPLACE)){error=errno;goto cleanup;}
    if(changed)*changed=1;
    result=fsync(parent)?-1:1;error=errno;
cleanup:
    if(fd>=0)close(fd);
    if(!result)unlinkat(parent,temp,0);
    errno=error;return done(parent,result);
}
static int remove_entry(int parent,const char *owner,const unsigned char *data,size_t size,int *changed,const char *suffix)
{
    char name[100];if(changed)*changed=0;
    if(!lock(parent,owner,data,size,name,suffix))return 0;
    int exists=exact(parent,name,data,size);
    if(exists!=1)return done(parent,exists==2?1:0);
    if(unlinkat(parent,name,0))return done(parent,0);
    if(changed)*changed=1;
    return done(parent,fsync(parent)?-1:1);
}
int mesh_gnome_autostart_install(int p,const char *o,const unsigned char *d,size_t s,int *c){return install(p,o,d,s,c,"desktop");}
int mesh_gnome_autostart_remove(int p,const char *o,const unsigned char *d,size_t s,int *c){return remove_entry(p,o,d,s,c,"desktop");}
int mesh_gnome_greeter_startup_install(int p,const char *o,const unsigned char *d,size_t s,int *c){return install(p,o,d,s,c,"conf");}
int mesh_gnome_greeter_startup_remove(int p,const char *o,const unsigned char *d,size_t s,int *c){return remove_entry(p,o,d,s,c,"conf");}
#endif
