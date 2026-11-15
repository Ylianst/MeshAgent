/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
static char fixtureScript[256];
#define KVM_BRIDGE_SCRIPT fixtureScript
#include "meshcore/KVM/Linux/linux_kvm_eis.c"
#include <sys/wait.h>
int main(void)
{
    char directory[]="/run/meshagent-bridge-test-XXXXXX", path[108];
    if (geteuid() || !mkdtemp(directory)) { fprintf(stderr,"Requires isolated root test environment\n"); return 1; }
    chmod(directory,0755);
    snprintf(fixtureScript,sizeof(fixtureScript),"%s/bridge.py",directory);
    snprintf(path,sizeof(path),"%s/socket",directory);
    FILE *script=fopen(fixtureScript,"w");
    if (!script) return 1;
    fputs("import os,socket,struct,sys,time\n"
          "s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600);time.sleep(.02);s.listen(2)\n"
          "os.write(int(sys.argv[2]),b'1');os.close(int(sys.argv[2]))\n"
          "for i in range(2 if sys.flags.isolated else 1):\n"
          " c,_=s.accept();raw=c.recv(128)\n"
          " if not sys.flags.isolated:\n"
          "  assert raw==b'', 'Impostor received input';break\n"
          " r=struct.unpack('=12I',raw);assert r[2]==(0x4b455931 if i==0 else 0x54585431);assert r[3]==(30 if i==0 else 0x4e2d)\n"
          " c.send(struct.pack('=9I',r[0],r[1],4,123,0,*r[6:10]));c.close()\n",script);
    fclose(script); chmod(fixtureScript,0644);
    pid_t unused; kvm_bridge_process(getpid(),&unused,&g_eisCompositorStart);g_eisCompositorPid=getpid();
    int failures=0;
    for (int attempt=0;attempt<3;++attempt) {
        int fake = attempt == 0;
        int ready[2]; if (pipe(ready)) return 1;
        pid_t child=fork();
        if(child<0){close(ready[0]);close(ready[1]);failures++;continue;}
        if (!child) {
            char descriptor[24]; close(ready[0]); snprintf(descriptor,sizeof(descriptor),"%d",ready[1]);
            if (fake) execl("/usr/bin/python3","/usr/bin/python3",fixtureScript,path,descriptor,NULL);
            else execl("/usr/bin/python3","/usr/bin/python3","-I",fixtureScript,path,descriptor,NULL);
            _exit(127);
        }
        close(ready[1]); struct pollfd notification={ready[0],POLLIN,0}; char marker=0;
        int listening=poll(&notification,1,2000)>0 && read(ready[0],&marker,1)==1 && marker=='1'; close(ready[0]);
        if (!listening) { kill(child,SIGKILL); waitpid(child,NULL,0); unlink(path); failures++; continue; }
        g_eisBridgeEpoch=0; uint32_t mods[4]={0};
        int result=eis_bridge_request(path,mods,0x4b455931,30,1);
        if ((fake && result!=-1) || (!fake && result!=1)) failures++;
        if (!fake && eis_bridge_request(path,mods,0x54585431,0x4e2d,0)!=1) failures++;
        int status=0,done=0;
        for(int n=0;n<100 && !done;++n) { done=waitpid(child,&status,WNOHANG)==child; if(!done)usleep(10000); }
        if(!done){kill(child,SIGKILL);waitpid(child,&status,0);}
        if(!done||!WIFEXITED(status)||WEXITSTATUS(status)) failures++;
        unlink(path);
    }
    unlink(fixtureScript);rmdir(directory);
    printf("Real native boundary: same-UID impostor gets zero bytes; trusted keys/Unicode and reconnect: %s\n",failures?"FAIL":"PASS");
    return failures!=0;
}
