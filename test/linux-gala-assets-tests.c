/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "meshcore/KVM/Linux/linux_gala_assets.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
static int calls,fail_at;
int __real_fsync(int);
int __wrap_fsync(int fd){if(++calls==fail_at){errno=EIO;return -1;}return __real_fsync(fd);}
static const unsigned char first[]="Agent-owned test image one",second[]="Agent-owned updated image two";
static const char owner1[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char owner2[]="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static void revision(int parent,char digit){
    int fd=openat(parent,MESH_GALA_FILE,O_RDONLY);assert(fd>=0);char record[4096];
    ssize_t n=fgetxattr(fd,"user.meshagent.gala",record,sizeof(record));assert(n>0);
    record[strlen("MeshAgent Gala ")]=digit;assert(!fsetxattr(fd,"user.meshagent.gala",record,(size_t)n,0));close(fd);
}
int main(void){
    char root[]="/tmp/meshagent-gala-assets-XXXXXX";assert(geteuid()==0&&mkdtemp(root));
    int parent=open(root,O_DIRECTORY|O_RDONLY|O_CLOEXEC),changed=-1;assert(parent>=0);
    assert(mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed)==1&&changed==1);
    assert(mesh_gala_assets_trusted_at(parent));
    struct stat before,after;assert(!fstatat(parent,MESH_GALA_FILE,&before,0));
    assert(mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed)==1&&!changed);
    assert(!fstatat(parent,MESH_GALA_FILE,&after,0)&&before.st_ino==after.st_ino);
    assert(mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner2,&changed)==1&&!changed);
    /* A rebuilt image of the same source revision must not interrupt Gala.
     * Older Agent builds also keep a newer installed revision and its leases. */
    assert(mesh_gala_assets_acquire_at(parent,second,sizeof(second),owner1,&changed)==1&&!changed);
    assert(!fstatat(parent,MESH_GALA_FILE,&after,0)&&before.st_ino==after.st_ino);
    revision(parent,'4');
    assert(mesh_gala_assets_acquire_at(parent,second,sizeof(second),owner1,&changed)==1&&!changed);
    revision(parent,'1');
    assert(mesh_gala_assets_acquire_at(parent,second,sizeof(second),owner1,&changed)==1&&changed);
    assert(!fstatat(parent,MESH_GALA_FILE,&after,0)&&before.st_ino!=after.st_ino);
    assert(mesh_gala_assets_release_at(parent,owner1,&changed)==1&&!changed&&mesh_gala_assets_trusted_at(parent));
    assert(mesh_gala_assets_release_at(parent,owner2,&changed)==1&&changed);
    assert(faccessat(parent,MESH_GALA_FILE,F_OK,0)<0&&errno==ENOENT);
    /* A durable file publication followed by a parent sync failure is reported
     * as applied/uncertain, rather than silently retried or claimed unchanged. */
    calls=0;fail_at=2;
    assert(mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed)==-1&&changed==1);
    fail_at=0;assert(mesh_gala_assets_trusted_at(parent));
    int fd=openat(parent,MESH_GALA_FILE,O_WRONLY);assert(fd>=0&&write(fd,"!",1)==1);close(fd);
    assert(!mesh_gala_assets_acquire_at(parent,second,sizeof(second),owner1,&changed)&&!changed);
    assert(!mesh_gala_assets_release_at(parent,owner1,&changed)&&!changed);
    assert(!unlinkat(parent,MESH_GALA_FILE,0));
    fd=openat(parent,"foreign",O_CREAT|O_EXCL|O_RDWR,0600);assert(fd>=0&&write(fd,"foreign",7)==7);close(fd);
    assert(!symlinkat("foreign",parent,MESH_GALA_FILE));
    assert(!mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed)&&!changed);
    assert(!mesh_gala_assets_release_at(parent,owner1,&changed));assert(!unlinkat(parent,MESH_GALA_FILE,0));
    assert(!linkat(parent,"foreign",parent,MESH_GALA_FILE,0));
    assert(!mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed));
    assert(!unlinkat(parent,MESH_GALA_FILE,0));
    fd=openat(parent,MESH_GALA_FILE,O_CREAT|O_EXCL|O_RDWR,0755);assert(fd>=0&&write(fd,first,sizeof(first))==sizeof(first));close(fd);
    assert(!mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed));
    assert(!mesh_gala_assets_release_at(parent,owner1,&changed));assert(!unlinkat(parent,MESH_GALA_FILE,0));
    assert(!fchmod(parent,0770));assert(!mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed));assert(!fchmod(parent,0700));
    assert(mesh_gala_assets_acquire_at(parent,first,sizeof(first),owner1,&changed)==1);
    revision(parent,'1');
    assert(!symlinkat(".",parent,".meshagent-gala"));
    assert(!mesh_gala_assets_acquire_at(parent,second,sizeof(second),owner1,&changed)&&!changed);
    assert(mesh_gala_assets_trusted_at(parent));assert(!unlinkat(parent,".meshagent-gala",0));
    assert(mesh_gala_assets_release_at(parent,owner1,&changed)==1);
    assert(!unlinkat(parent,"foreign",0));close(parent);assert(!rmdir(root));
    puts("Gala assets: owned install/no-op, shared leases, atomic upgrade, durable-failure reporting, changed/unmanaged/symlink/hardlink/writable-parent refusal passed");
}
