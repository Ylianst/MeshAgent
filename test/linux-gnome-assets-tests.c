/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gnome_assets.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int passed,failed,fail_sync_after;
int __real_fsync(int fd);
int __wrap_fsync(int fd)
{
 if(fail_sync_after>0&&--fail_sync_after==0){errno=EIO;return -1;}
 return __real_fsync(fd);
}
static void check(int value,const char *name)
{if(value)++passed;else{++failed;fprintf(stderr,"FAIL: %s (errno %d)\n",name,errno);}}
static int file_equals(int parent,const char *path,const char *text)
{char data[64];int fd=openat(parent,path,O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;ssize_t n=read(fd,data,sizeof(data));close(fd);return n==(ssize_t)strlen(text)&&!memcmp(data,text,(size_t)n);}
#include "linux-gnome-owner-rollback-cases.h"
int main(void)
{
 if(geteuid()!=0){fprintf(stderr,"Run only in an isolated root-owned test directory as root\n");return 2;}
 int changed=-1;
 char path[]="/tmp/meshagent-gnome-assets-tests.XXXXXX",backup[MESH_GNOME_ASSET_BACKUP_SIZE],other[MESH_GNOME_ASSET_BACKUP_SIZE];
 if(!mkdtemp(path))return 2;
 int parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(parent<0)return 2;
 mesh_gnome_asset a[3]={{(const unsigned char*)"metadata-a",10},{(const unsigned char*)"protocol-a",10},{(const unsigned char*)"extension-a",11}};
 mesh_gnome_asset b[3]={{(const unsigned char*)"metadata-b",10},{(const unsigned char*)"protocol-b",10},{(const unsigned char*)"extension-b",11}};
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1&&!backup[0]&&changed==1,"first install reports changed");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"exact payload");
 struct stat st;check(!fstatat(parent,MESH_GNOME_ASSET_UUID,&st,AT_SYMLINK_NOFOLLOW)&&(st.st_mode&0777)==0755&&st.st_uid==0,"root-owned readable directory");
 check(!fstatat(parent,MESH_GNOME_ASSET_UUID "/protocol.js",&st,AT_SYMLINK_NOFOLLOW)&&(st.st_mode&0777)==0644,"read-only public file mode");
 ino_t inode=st.st_ino;
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1&&!backup[0]&&changed==0,"idempotent install reports unchanged");
 check(!fstatat(parent,MESH_GNOME_ASSET_UUID "/protocol.js",&st,AT_SYMLINK_NOFOLLOW)&&st.st_ino==inode,"no rewrite on unchanged install");
 mesh_gnome_asset invalid[3];memcpy(invalid,a,sizeof(invalid));invalid[1].size=0;
 check(!mesh_gnome_assets_install(parent,invalid,backup,NULL),"empty asset rejected before mutation");
 fail_sync_after=1;
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==0,"stage sync failure refuses publication");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"old files survive stage sync failure");
 fail_sync_after=6;
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==-1&&backup[0],"publication sync failure explicitly reports applied state");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-b"),"applied state matches durability warning");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"durability-error rollback");
 check(mesh_gnome_assets_commit(parent,backup)==1,"durability-error candidate cleanup");
 pid_t full=fork();if(full==0){
  signal(SIGXFSZ,SIG_IGN);struct rlimit limit={8,8};if(setrlimit(RLIMIT_FSIZE,&limit))_exit(2);
  _exit(mesh_gnome_assets_install(parent,b,backup,NULL)==0?0:3);
 }
 int full_status;waitpid(full,&full_status,0);
 check(WIFEXITED(full_status)&&!WEXITSTATUS(full_status),"short/failed stage writes refuse publication");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"failed writes preserve old content");
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==1&&backup[0],"atomic update retains backup");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-b"),"new payload visible");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"update rollback");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"rollback exact old payload");
 check(mesh_gnome_assets_commit(parent,backup)==1,"remove rolled-back candidate only");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==1&&backup[0],"uninstall detaches owned directory");
 check(fstatat(parent,MESH_GNOME_ASSET_UUID,&st,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"uninstall removes current name");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"uninstall rollback restores files");
 int fd=openat(parent,MESH_GNOME_ASSET_UUID "/extension.js",O_WRONLY);check(fd>=0&&write(fd,"X",1)==1,"simulate administrator edit");close(fd);
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==0,"update preserves changed asset");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==0,"uninstall preserves changed asset");
 fd=openat(parent,MESH_GNOME_ASSET_UUID "/extension.js",O_WRONLY);if(fd<0||write(fd,"e",1)!=1)return 2;close(fd);
 check(!symlinkat("/etc/passwd",parent,MESH_GNOME_ASSET_UUID "/unexpected"),"add unexpected entry");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==0,"unknown entries preserve directory");
 check(!unlinkat(parent,MESH_GNOME_ASSET_UUID "/unexpected",0),"remove test symlink only");
 check(!linkat(parent,MESH_GNOME_ASSET_UUID "/protocol.js",parent,"hardlink",0),"add hard link");
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==0,"hard-linked asset rejected");
 check(!unlinkat(parent,"hardlink",0),"remove test hard link");
 check(!fchmodat(parent,MESH_GNOME_ASSET_UUID "/protocol.js",0664,0),"simulate writable asset");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==0,"writable asset rejected");
 if(fchmodat(parent,MESH_GNOME_ASSET_UUID "/protocol.js",0644,0))return 2;
 check(!fchmod(parent,0777),"simulate unsafe parent");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==0,"unsafe parent rejected");
 if(fchmod(parent,0700))return 2;
 check(!mesh_gnome_assets_rollback(parent,"../outside"),"rollback traversal rejected");
 check(!mesh_gnome_assets_commit(parent,MESH_GNOME_ASSET_UUID),"current directory never accepted as backup token");
 int second=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(second<0||flock(second,LOCK_EX))return 2;
 check(mesh_gnome_assets_install(parent,b,backup,NULL)==0,"concurrent transaction refused");flock(second,LOCK_UN);close(second);
 pid_t child=fork();if(child==0){if(setgid(65534)||setuid(65534))_exit(2);_exit(mesh_gnome_assets_uninstall(parent,other,NULL)==0?0:3);}
 int status;waitpid(child,&status,0);check(WIFEXITED(status)&&!WEXITSTATUS(status),"unprivileged caller rejected");
 check(mesh_gnome_assets_uninstall(parent,backup,NULL)==1,"clean uninstall transaction");
 check(!symlinkat(backup,parent,MESH_GNOME_ASSET_UUID),"simulate symlink destination");
 check(!mesh_gnome_assets_install(parent,b,other,NULL),"symlink destination never followed");
 check(!unlinkat(parent,MESH_GNOME_ASSET_UUID,0),"remove destination test symlink");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit detached owned installation");
 check(mesh_gnome_assets_uninstall(parent,backup,&changed)==1&&!backup[0]&&changed==0,"already absent uninstall reports unchanged");
 check(!mkdirat(parent,MESH_GNOME_ASSET_UUID,0755),"create unmanaged destination");
 check(!mesh_gnome_assets_install(parent,a,backup,NULL),"unmanaged destination preserved");
 check(!unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR),"remove empty test directory");

 char ownerA[65],ownerB[65],ownerC[65];memset(ownerA,'a',64);ownerA[64]=0;memset(ownerB,'b',64);ownerB[64]=0;memset(ownerC,'c',64);ownerC[64]=0;
 check(!mesh_gnome_assets_acquire(parent,a,"../bad",1,backup,&changed)&&!changed,"owner is an identity, never a filesystem path");
 check(!mesh_gnome_assets_acquire(parent,a,ownerA,0,backup,&changed),"zero generation rejected");
 check(mesh_gnome_assets_acquire(parent,a,ownerB,1,backup,&changed)==1&&changed&&!backup[0],"first service acquires assets atomically");
 check(mesh_gnome_assets_acquire(parent,a,ownerB,1,backup,&changed)==1&&!changed&&!backup[0],"same service acquisition is idempotent");
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1&&changed&&backup[0],"second service joins shared payload");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"rollback second service acquisition");
 check(mesh_gnome_assets_commit(parent,backup)==1,"discard rolled-back owner candidate");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&!changed,"rolled-back service has no lease");
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1&&changed,"second service reacquires");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit second service acquisition");
 check(!mesh_gnome_assets_uninstall(parent,backup,&changed)&&!changed,"legacy uninstall cannot remove service-owned companion");
 check(!mesh_gnome_assets_install(parent,b,backup,&changed)&&!changed,"legacy update cannot replace service-owned payload");
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1&&!changed,"legacy identical call preserves ownership");
 check(mesh_gnome_assets_release(parent,ownerB,backup,&changed)==1&&changed,"remove one of two service owners");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"other service retains companion after release");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit nonfinal owner release");
 check(mesh_gnome_assets_release(parent,ownerC,backup,&changed)==1&&!changed&&!backup[0],"unknown service release is neutral");
 check(!mesh_gnome_assets_acquire(parent,b,ownerA,1,backup,&changed)&&!changed,"same-generation conflicting payload refused");
 check(mesh_gnome_assets_acquire(parent,b,ownerA,2,backup,&changed)==1&&changed,"higher generation updates payload and retains owners");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"rollback payload and owner receipt together");
 check(mesh_gnome_assets_commit(parent,backup)==1,"discard rejected payload generation");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"rollback restored payload bytes");
 check(mesh_gnome_assets_acquire(parent,b,ownerA,2,backup,&changed)==1&&changed,"retry explicit upgrade after rollback");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit higher generation");
 check(!mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)&&!changed,"older installer cannot downgrade shared companion");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed&&backup[0],"last service detaches companion");
 check(fstatat(parent,MESH_GNOME_ASSET_UUID,&st,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT,"last release removes current directory atomically");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"rollback final uninstall restores owner and payload");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-b"),"final-release rollback restored active payload");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed,"restored last owner can release again");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit final service removal");
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1,"start owner durability fixture");
 fail_sync_after=1;
 check(!mesh_gnome_assets_acquire(parent,a,ownerB,1,backup,&changed)&&!changed,"owner stage fsync failure never publishes lease");
 check(mesh_gnome_assets_release(parent,ownerB,backup,&changed)==1&&!changed,"failed acquisition left no phantom owner");
 fail_sync_after=6;
 check(mesh_gnome_assets_acquire(parent,a,ownerB,1,backup,&changed)==-1&&changed&&backup[0],"owner publication durability failure reports applied state");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"rollback uncertain owner publication");
 check(mesh_gnome_assets_commit(parent,backup)==1,"discard uncertain owner candidate");
 check(mesh_gnome_assets_release(parent,ownerB,backup,&changed)==1&&!changed,"owner receipt rolled back after durability failure");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed,"remove durability fixture owner");
 check(mesh_gnome_assets_commit(parent,backup)==1,"clean durability fixture");
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1,"install pre-registry fixture");
 check(mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)==1&&changed,"adopt known assets with conservative legacy hold");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit legacy adoption");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed,"release owner while legacy dependents may remain");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit legacy owner release");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"legacy companion survives last registered owner");
 check(!mesh_gnome_assets_uninstall(parent,backup,&changed),"old API cannot bypass legacy hold");
 /* The unregistered legacy hold deliberately requires administrative cleanup.
  * This fixture owns this private temporary directory and its four files. */
 const char *ownedFiles[]={"metadata.json","protocol.js","extension.js","meshagent-owned.txt"};
 int privateDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(privateDir<0)return 2;
 for(size_t oi=0;oi<4;++oi)if(unlinkat(privateDir,ownedFiles[oi],0))return 2;
 close(privateDir);if(unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR))return 2;


 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1&&changed,"seed exact unmanifested legacy payload");
 int unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 check(!unlinkat(unmanifestedDir,"meshagent-owned.txt",0),"remove prior ownership receipt");
 close(unmanifestedDir);
 check(mesh_gnome_assets_acquire(parent,a,ownerA,2,backup,&changed)==1&&changed&&backup[0],"adopt exact unmanifested assets transactionally");
 check(mesh_gnome_assets_rollback(parent,backup)==1,"rollback unmanifested legacy adoption");
 check(fstatat(parent,MESH_GNOME_ASSET_UUID "/meshagent-owned.txt",&st,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"rollback restores no-manifest legacy state");
 check(mesh_gnome_assets_commit(parent,backup)==1,"discard rolled-back legacy candidate");
 check(mesh_gnome_assets_acquire(parent,a,ownerA,2,backup,&changed)==1&&changed&&backup[0],"re-adopt exact unmanifested assets");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit exact legacy adoption");
 check(mesh_gnome_assets_release(parent,ownerA,backup,&changed)==1&&changed,"release adopted legacy owner");
 check(mesh_gnome_assets_commit(parent,backup)==1,"commit adopted legacy release");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-a"),"adopted legacy payload retained after release");
 int manifestFd=openat(parent,MESH_GNOME_ASSET_UUID "/meshagent-owned.txt",O_RDONLY|O_NOFOLLOW);
 char manifestText[1024];ssize_t manifestLength=manifestFd<0?-1:read(manifestFd,manifestText,sizeof(manifestText)-1);
 if(manifestFd>=0)close(manifestFd);
 if(manifestLength>=0)manifestText[manifestLength]=0;
 check(manifestLength>0&&strstr(manifestText,"Owners 1 00000002 1\n")!=NULL,"unmanifested adoption retains legacy hold");
 check(!mesh_gnome_assets_uninstall(parent,backup,&changed),"legacy uninstall preserves adopted assets");
 const char *adoptedFiles[]={"metadata.json","protocol.js","extension.js","meshagent-owned.txt"};
 unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 for(size_t i=0;i<4;i++)if(unlinkat(unmanifestedDir,adoptedFiles[i],0))return 2;
 close(unmanifestedDir);if(unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR))return 2;
 check(mesh_gnome_assets_install(parent,a,backup,&changed)==1&&changed,"seed unmanifested bundle with an extra entry");
 unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 if(unlinkat(unmanifestedDir,"meshagent-owned.txt",0))return 2;
 close(unmanifestedDir);
 int extraFd=openat(parent,MESH_GNOME_ASSET_UUID "/unexpected",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);
 if(extraFd<0)return 2;
 close(extraFd);
 check(!mesh_gnome_assets_acquire(parent,a,ownerA,2,backup,&changed)&&!changed&&!backup[0],"refuse unmanifested bundle with extra entry");
 if(unlinkat(parent,MESH_GNOME_ASSET_UUID "/unexpected",0))return 2;
 unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 const char *extraFiles[]={"metadata.json","protocol.js","extension.js"};
 for(size_t i=0;i<3;i++)if(unlinkat(unmanifestedDir,extraFiles[i],0))return 2;
 close(unmanifestedDir);if(unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR))return 2;
 check(mesh_gnome_assets_install(parent,b,backup,&changed)==1&&changed,"seed mismatched unmanifested payload");
 unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 if(unlinkat(unmanifestedDir,"meshagent-owned.txt",0))return 2;
 close(unmanifestedDir);
 check(!mesh_gnome_assets_acquire(parent,a,ownerA,2,backup,&changed)&&!changed&&!backup[0],"refuse mismatched unmanifested payload");
 check(file_equals(parent,MESH_GNOME_ASSET_UUID "/extension.js","extension-b"),"mismatched legacy payload remains unchanged");
 const char *unownedFiles[]={"metadata.json","protocol.js","extension.js"};
 unmanifestedDir=openat(parent,MESH_GNOME_ASSET_UUID,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(unmanifestedDir<0)return 2;
 for(size_t i=0;i<3;i++)if(unlinkat(unmanifestedDir,unownedFiles[i],0))return 2;
 close(unmanifestedDir);if(unlinkat(parent,MESH_GNOME_ASSET_UUID,AT_REMOVEDIR))return 2;
 owner_rollback_cases(parent,a,b);
 for(unsigned oi=0;oi<64;++oi){char id[65];snprintf(id,sizeof(id),"%064x",oi);check(mesh_gnome_assets_acquire(parent,a,id,1,backup,&changed)==1,"bounded owner set accepts registered service");if(backup[0])check(mesh_gnome_assets_commit(parent,backup)==1,"commit bounded owner fixture");}
 check(!mesh_gnome_assets_acquire(parent,a,ownerA,1,backup,&changed)&&!changed,"owner capacity fails without discarding existing owners");
 for(unsigned oi=0;oi<64;++oi){char id[65];snprintf(id,sizeof(id),"%064x",oi);check(mesh_gnome_assets_release(parent,id,backup,&changed)==1&&changed,"release bounded service owner");check(mesh_gnome_assets_commit(parent,backup)==1,"clean bounded owner fixture");}
 close(parent);check(!rmdir(path),"all private test files cleaned");
 printf("%d asset transaction checks passed, %d failed\n",passed,failed);return failed?1:0;
}
