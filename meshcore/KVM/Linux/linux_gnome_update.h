/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MESH_GNOME_UPDATE_H
#define MESH_GNOME_UPDATE_H
#if defined(__linux__) && defined(_LINKVM)
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "microstack/ILibParsers.h"
extern char **environ;
/* Called after a verified binary replacement, before service restart. This
 * installs owned files and prepares sessions; it never offers logout/refresh
 * consent or runs on a remote connection. Timeout bounds a failed desktop bus. */
static int mesh_gnome_after_update(const char *installed, const char *service)
{
    if (getuid()!=0 || geteuid()!=0 || (access("/usr/bin/gnome-shell",F_OK)!=0 && access("/usr/bin/kwin_wayland",F_OK)!=0 && access("/usr/bin/gala",F_OK)!=0)) { return 0; }
    if (!installed || installed[0]!='/' || !service || !service[0] || strlen(service)>256) { errno=EINVAL;return -1; }
    static const char script[] = "var rc=0,a=process.argv,n=Buffer.from(a[a.length-1],'base64').toString(),names=['linux-gnome-companion','linux-kwin-companion','linux-gala-companion'];for(var i=0;i<names.length;++i){try{var r=require(names[i]).install({name:n,path:process.execPath});if(r.state!=='files-ready'&&r.state!=='not-applicable'){rc=1;console.error('MeshAgent: companion update incomplete: '+names[i]+' '+r.state);}}catch(e){rc=1;console.error('MeshAgent: companion update failed: '+names[i]+' '+String(e));}}process.exit(rc);";
    unsigned char *name=NULL,*payload=NULL;
    if (ILibBase64Encode((unsigned char*)service,(int)strlen(service),&name)<=0 || !name) { free(name);errno=ENOMEM;return -1; }
    if (ILibBase64Encode((unsigned char*)script,(int)strlen(script),&payload)<=0 || !payload) { free(name);free(payload);errno=ENOMEM;return -1; }
    char *args[]={"/usr/bin/timeout","--foreground","--kill-after=2s","30s",(char*)installed,"-b64exec",
        (char*)payload,(char*)name,NULL};
    posix_spawn_file_actions_t actions;pid_t child;int status=0,error;
    error=posix_spawn_file_actions_init(&actions);
    if (error) { free(name);free(payload);errno=error;return -1; }
    error=posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0);
    if (!error) { error=posix_spawn(&child,args[0],&actions,NULL,args,environ); }
    posix_spawn_file_actions_destroy(&actions);free(name);free(payload);
    if (error) { errno=error;return -1; }
    pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    if (waited<0) { return -1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status)!=0) { errno=WIFEXITED(status)&&WEXITSTATUS(status)==124?ETIMEDOUT:EIO;return -1; }
    return 0;
}
#endif
#endif
