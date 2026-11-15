/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#define KVM_CAPTURE_DISABLE_HELPER
#include "../meshcore/KVM/Linux/linux_kvm_capture_helper.c"
int main(void) {
    int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair))return 1;
    if(kvm_capture_broker_new(pair[0],getpid(),getuid(),1)!=NULL||fcntl(pair[0],F_GETFD)>=0)return 2;
    kvm_capture_worker_attach(pair[1],getppid(),1);if(fcntl(pair[1],F_GETFD)>=0)return 3;
    char *normal[]={"agent","-help",NULL},*role[]={"agent",KVM_CAPTURE_HELPER_ROLE,NULL};int fds[6];
    if(kvm_capture_helper_dispatch(2,normal)!=-1||kvm_capture_helper_dispatch(2,role)!=125)return 4;
    if(kvm_capture_worker_connect(NULL,NULL)!=-1||kvm_capture_worker_seal()||kvm_capture_worker_alive())return 5;
    if(kvm_capture_broker_fds(NULL,fds)||kvm_capture_broker_deadline(NULL)||kvm_capture_broker_write_fd(NULL)!=-1||kvm_capture_broker_free(NULL)!=-1)return 6;
    puts("Unsupported helper ABI: native fallback and role rejection passed");return 0;
}
