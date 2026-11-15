/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdio.h>
#include "linux_gnome_update.h"
static int privileged=1,present=1,kwin_present=0,gala_present=0,spawn_error=0,child_status=0,spawns=0;
static const char *expected_name="mesh agent-'\";$(not-a-command)";
uid_t __wrap_getuid(void){return privileged?0:1000;}
uid_t __wrap_geteuid(void){return privileged?0:1000;}
int __wrap_access(const char *p,int mode){assert(mode==F_OK);if(!strcmp(p,"/usr/bin/gnome-shell"))return present?0:-1;if(!strcmp(p,"/usr/bin/kwin_wayland"))return kwin_present?0:-1;assert(!strcmp(p,"/usr/bin/gala"));return gala_present?0:-1;}
int __wrap_posix_spawn(pid_t *pid,const char *file,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attr,char *const argv[],char *const env[])
{
    (void)actions;(void)attr;(void)env;spawns++;
    assert(!strcmp(file,"/usr/bin/timeout"));
    assert(!strcmp(argv[1],"--foreground")&&!strcmp(argv[2],"--kill-after=2s")&&!strcmp(argv[3],"30s"));
    assert(!strcmp(argv[4],"/lab/agent path/meshagent")&&!strcmp(argv[5],"-b64exec")&&!argv[8]);
    unsigned char *decoded=NULL;
    int n=ILibBase64Decode((unsigned char*)argv[7],(int)strlen(argv[7]),&decoded);
    assert(n==(int)strlen(expected_name)&&!memcmp(decoded,expected_name,(size_t)n));free(decoded);decoded=NULL;
    n=ILibBase64Decode((unsigned char*)argv[6],(int)strlen(argv[6]),&decoded);
    assert(n>0&&strstr((char*)decoded,"linux-gnome-companion")&&strstr((char*)decoded,"linux-kwin-companion")&&strstr((char*)decoded,"linux-gala-companion")&&!strstr((char*)decoded,"offerSignOut")&&!strstr((char*)decoded,"offerGreeterRefresh"));free(decoded);
    *pid=61001;return spawn_error;
}
pid_t __wrap_waitpid(pid_t pid,int *status,int options){assert(pid==61001&&options==0);*status=child_status;return pid;}
int main(void)
{
    assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==0&&spawns==1);
    child_status=124<<8;errno=0;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==-1&&errno==ETIMEDOUT);
    child_status=1<<8;errno=0;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==-1&&errno==EIO);
    spawn_error=EACCES;errno=0;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==-1&&errno==EACCES);
    int count=spawns;present=0;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==0&&spawns==count);
    kwin_present=1;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==-1&&spawns==count+1);count=spawns;
    kwin_present=0;gala_present=1;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==-1&&spawns==count+1);count=spawns;
    present=1;privileged=0;assert(mesh_gnome_after_update("/lab/agent path/meshagent",expected_name)==0&&spawns==count);
    puts("PASS: bounded companion-update launch, literal service identity, timeout/failure propagation, and GNOME/KWin detection and non-root skips");
    return 0;
}
