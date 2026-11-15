/* SPDX-License-Identifier: Apache-2.0 */
#include "addons/gala/console.c"
#include <assert.h>
#include <stdlib.h>
static void image(const char *path,int revision){
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0644);assert(fd>=0&&write(fd,"module",6)==6);close(fd);
    char metadata[256];snprintf(metadata,sizeof(metadata),"MeshAgent Gala %d\n%064d\n%064d\n",revision,1,2);
    assert(!setxattr(path,"user.meshagent.gala",metadata,strlen(metadata),0));
}
int main(void){
    assert(!needs_physical_keys(0)); /* Public Mutter WAYLAND enum. */
    assert(needs_physical_keys(1));  /* Public Mutter X11 enum. */
    assert(needs_physical_keys(2));assert(needs_physical_keys(-1));
    char root[]="/tmp/meshagent-gala-revision-XXXXXX",next[PATH_MAX];assert(geteuid()==0&&mkdtemp(root));
    snprintf(bridge.asset,sizeof(bridge.asset),"%s/image.so",root);image(bridge.asset,MESH_GALA_GENERATION);assert(installed());
    snprintf(next,sizeof(next),"%s/next.so",root);image(next,MESH_GALA_GENERATION+1);assert(!rename(next,bridge.asset));assert(installed());
    assert(!removexattr(bridge.asset,"user.meshagent.gala"));assert(!installed());
    assert(!unlink(bridge.asset));assert(!rmdir(root));
    puts("Gala public client types: native Wayland text, XWayland/unknown physical-key fallback passed");
    puts("Gala revision replacement keeps the resident bridge usable; unmanaged/removal disables it: passed");
}
