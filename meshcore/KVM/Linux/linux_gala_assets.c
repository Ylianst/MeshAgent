/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gala_assets.h"
#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#define RECORD "user.meshagent.gala"
#define PREFIX "MeshAgent Gala "
#define MAX_OWNERS 32u
#define MAX_SIZE (1024u*1024u)
#define RECORD_SIZE (sizeof(PREFIX)+11+65*(MAX_OWNERS+1))
#ifndef MESH_GALA_ASSET_TEST
__asm__(".pushsection .rodata\n.balign 8\n.global mesh_gala_blob_start\nmesh_gala_blob_start:\n.incbin \"addons/gala/console.so\"\n.global mesh_gala_blob_end\nmesh_gala_blob_end:\n.popsection\n");
extern const unsigned char mesh_gala_blob_start[],mesh_gala_blob_end[];
#endif
typedef struct {char hash[65];char owners[MAX_OWNERS][65];unsigned int count,generation;} Registry;
static int hex(const char *s) {return s&&strlen(s)==64&&strspn(s,"0123456789abcdef")==64;}
static int safe(int fd,int directory) {
    struct stat st;
    return !fstat(fd,&st)&&!st.st_uid&&!(st.st_mode&0022)&&
        (directory?S_ISDIR(st.st_mode):(S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_size>0&&st.st_size<=MAX_SIZE));
}
static void digest(const unsigned char *data,size_t size,char text[65]) {
    unsigned char value[SHA256_DIGEST_LENGTH];SHA256(data,size,value);
    for(unsigned int i=0;i<sizeof(value);++i)snprintf(text+i*2,3,"%02x",value[i]);
}
static int file_hash(int fd,char text[65]) {
    unsigned char data[8192],value[SHA256_DIGEST_LENGTH];SHA256_CTX ctx;size_t total=0;
    if(lseek(fd,0,SEEK_SET)<0||!SHA256_Init(&ctx))return 0;
    for(;;){ssize_t n=read(fd,data,sizeof(data));if(n<0&&errno==EINTR)continue;if(n<0)return 0;if(!n)break;
        if((total+=(size_t)n)>MAX_SIZE||!SHA256_Update(&ctx,data,(size_t)n))return 0;}
    if(!SHA256_Final(value,&ctx))return 0;
    for(unsigned int i=0;i<sizeof(value);++i)snprintf(text+i*2,3,"%02x",value[i]);
    return total>0;
}
static int registry_read(int fd,Registry *r) {
    char record[RECORD_SIZE+1],actual[65];ssize_t n=fgetxattr(fd,RECORD,record,RECORD_SIZE);
    size_t prefix=sizeof(PREFIX)-1;
    if(n<(ssize_t)(prefix+2+130)||n>(ssize_t)RECORD_SIZE||memcmp(record,PREFIX,prefix)){errno=EPERM;return 0;}
    memset(r,0,sizeof(*r));record[n]=0;
    char *line_end=memchr(record+prefix,'\n',(size_t)n-prefix);
    if(!line_end||line_end==record+prefix||line_end-(record+prefix)>10||record[prefix]=='0'){errno=EPERM;return 0;}
    *line_end=0;
    if(strspn(record+prefix,"0123456789")!=strlen(record+prefix)){errno=EPERM;return 0;}
    errno=0;unsigned long generation=strtoul(record+prefix,NULL,10);
    if(errno==ERANGE||generation<1||generation>0xfffffffful){errno=EPERM;return 0;}
    r->generation=(unsigned int)generation;prefix=(size_t)(line_end-record)+1;
    if(((size_t)n-prefix)%65){errno=EPERM;return 0;}
    unsigned int lines=(unsigned int)(((size_t)n-prefix)/65);
    if(lines<2||lines>MAX_OWNERS+1){errno=EPERM;return 0;}
    for(unsigned int i=0;i<lines;++i){char *p=record+prefix+65*i;
        if(p[64]!='\n'){errno=EPERM;return 0;}p[64]=0;
        if(!hex(p)){errno=EPERM;return 0;}
        if(!i)memcpy(r->hash,p,65);else{
            for(unsigned int j=0;j<r->count;++j)if(!strcmp(r->owners[j],p)){errno=EPERM;return 0;}
            memcpy(r->owners[r->count++],p,65);
        }
    }
    if(!safe(fd,0)||!file_hash(fd,actual)||strcmp(actual,r->hash)){errno=EPERM;return 0;}
    return 1;
}
static int registry_write(int fd,const Registry *r) {
    char record[RECORD_SIZE];int header=snprintf(record,sizeof(record),"%s%u\n",PREFIX,r->generation);
    if(header<=0||(size_t)header>=sizeof(record)){errno=EINVAL;return 0;}size_t n=(size_t)header;
    memcpy(record+n,r->hash,64);record[n+64]='\n';n+=65;
    for(unsigned int i=0;i<r->count;++i){memcpy(record+n,r->owners[i],64);record[n+64]='\n';n+=65;}
    return !fsetxattr(fd,RECORD,record,n,0)&&!fsync(fd);
}
static int lock_parent(int parent) {
    if(geteuid()!=0||!safe(parent,1)){errno=EPERM;return 0;}
    return !flock(parent,LOCK_EX|LOCK_NB);
}
int mesh_gala_assets_acquire_at(int parent,const unsigned char *data,size_t size,const char *owner,int *changed) {
    Registry r;int fd=-1,result=0,error=0,stage=-1,old=-1,staged_link=0;char expected[65],candidate[64]={0};
    if(changed)*changed=0;
    if(!data||!size||size>MAX_SIZE||!hex(owner)){errno=EINVAL;return 0;}
    if(!lock_parent(parent))return 0;
    digest(data,size,expected);fd=openat(parent,MESH_GALA_FILE,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd>=0){
        if(!registry_read(fd,&r))goto done;
        unsigned int i;for(i=0;i<r.count;++i)if(!strcmp(r.owners[i],owner))break;
        if(i==r.count){if(r.count>=MAX_OWNERS){errno=ENOSPC;goto done;}memcpy(r.owners[r.count++],owner,65);}
        if(r.generation>=MESH_GALA_GENERATION){result=registry_write(fd,&r);goto done;}
        /* Wire ABI 1 updates retain every service lease. Stage off the watched
         * directory so Gala never loads a partially written candidate. */
        if(mkdirat(parent,".meshagent-gala",0700)&&errno!=EEXIST)goto done;
        stage=openat(parent,".meshagent-gala",O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(stage<0||!safe(stage,1)){errno=EPERM;goto done;}
        old=fd;fd=-1;
    } else {
        if(errno!=ENOENT)goto done;
        memset(&r,0,sizeof(r));memcpy(r.owners[0],owner,65);r.count=1;
    }
    fd=openat(stage>=0?stage:parent,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0755);
    if(fd<0)goto done;
    size_t offset=0;
    while(offset<size){ssize_t n=write(fd,data+offset,size-offset);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;offset+=(size_t)n;}
    strcpy(r.hash,expected);r.generation=MESH_GALA_GENERATION;
    if(fchmod(fd,0755)||!registry_write(fd,&r))goto done;
    if(stage<0){if(linkat(fd,"",parent,MESH_GALA_FILE,AT_EMPTY_PATH))goto done;}
    else {
        int linked=0;
        for(unsigned int attempt=0;attempt<16;++attempt){
            snprintf(candidate,sizeof(candidate),"candidate-%u-%u",(unsigned)getpid(),attempt);
            if(!linkat(fd,"",stage,candidate,AT_EMPTY_PATH)){linked=1;staged_link=1;break;}
            if(errno!=EEXIST)goto done;
        }
        if(!linked){errno=EBUSY;goto done;}
        if(renameat(stage,candidate,parent,MESH_GALA_FILE))goto done;
        candidate[0]=0;
    }
    if(changed)*changed=1;
    result=fsync(parent)==0?1:-1;
done:
    error=errno;if(staged_link&&candidate[0]&&stage>=0)unlinkat(stage,candidate,0);
    if(fd>=0){close(fd);}if(old>=0){close(old);}if(stage>=0){fsync(stage);close(stage);unlinkat(parent,".meshagent-gala",AT_REMOVEDIR);}
    flock(parent,LOCK_UN);errno=error;return result;
}
int mesh_gala_assets_release_at(int parent,const char *owner,int *changed) {
    Registry r;int fd=-1,result=0,error;
    if(changed)*changed=0;
    if(!hex(owner)){errno=EINVAL;return 0;}if(!lock_parent(parent))return 0;
    fd=openat(parent,MESH_GALA_FILE,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){result=errno==ENOENT;goto done;}
    if(!registry_read(fd,&r))goto done;
    unsigned int i;for(i=0;i<r.count;++i)if(!strcmp(r.owners[i],owner))break;
    if(i==r.count){result=1;goto done;}
    memmove(r.owners+i,r.owners+i+1,(r.count-i-1)*sizeof(r.owners[0]));--r.count;
    if(r.count){result=registry_write(fd,&r);goto done;}
    if(unlinkat(parent,MESH_GALA_FILE,0))goto done;
    if(changed)*changed=1;
    result=fsync(parent)==0?1:-1;
done:error=errno;if(fd>=0)close(fd);flock(parent,LOCK_UN);errno=error;return result;
}
int mesh_gala_assets_trusted_at(int parent) {
    Registry r;int fd=openat(parent,MESH_GALA_FILE,O_RDONLY|O_CLOEXEC|O_NOFOLLOW),result=0;
    if(fd>=0){result=safe(parent,1)&&registry_read(fd,&r);close(fd);}return result;
}
static int open_path(const char *path) {
    char copy[256],*save,*part;int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC),next;
    if(strlen(path)>=sizeof(copy)){if(fd>=0)close(fd);errno=ENAMETOOLONG;return -1;}
    strcpy(copy,path);
    for(part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
        if(fd<0)return -1;
        if(!safe(fd,1)){close(fd);errno=EPERM;return -1;}
        next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);close(fd);fd=next;
    }
    if(fd>=0&&!safe(fd,1)){close(fd);errno=EPERM;return -1;}return fd;
}
int mesh_gala_assets_open_parent(void) {
    static const char *paths[]={"/usr/lib/x86_64-linux-gnu/gala/plugins","/usr/lib/aarch64-linux-gnu/gala/plugins","/usr/lib/arm-linux-gnueabihf/gala/plugins","/usr/lib64/gala/plugins","/usr/lib/gala/plugins"};
    struct stat st;
    if(lstat("/usr/bin/gala",&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0022)){errno=ENOENT;return -1;}
    for(unsigned int i=0;i<sizeof(paths)/sizeof(paths[0]);++i){int fd=open_path(paths[i]);if(fd>=0)return fd;if(errno!=ENOENT&&errno!=ENOTDIR)return -1;}
    errno=ENOENT;return -1;
}
int mesh_gala_assets_trusted(void) {int fd=mesh_gala_assets_open_parent(),r=0;if(fd>=0){r=mesh_gala_assets_trusted_at(fd);close(fd);}return r;}
int mesh_gala_assets_install(const char *owner,int *changed) {
#ifndef MESH_GALA_ASSET_TEST
    int fd=mesh_gala_assets_open_parent();if(fd<0)return 0;
    int r=mesh_gala_assets_acquire_at(fd,mesh_gala_blob_start,(size_t)(mesh_gala_blob_end-mesh_gala_blob_start),owner,changed),error=errno;close(fd);errno=error;return r;
#else
    (void)owner;(void)changed;return 0;
#endif
}
int mesh_gala_assets_release(const char *owner,int *changed) {int fd=mesh_gala_assets_open_parent();if(fd<0)return errno==ENOENT;int r=mesh_gala_assets_release_at(fd,owner,changed),error=errno;close(fd);errno=error;return r;}
#else
int mesh_gala_assets_open_parent(void){return -1;}
int mesh_gala_assets_install(const char *owner,int *changed){(void)owner;(void)changed;return 0;}
int mesh_gala_assets_release(const char *owner,int *changed){(void)owner;(void)changed;return 0;}
int mesh_gala_assets_trusted(void){return 0;}
#endif
