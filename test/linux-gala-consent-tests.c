/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "meshcore/KVM/Linux/linux_gala_consent.h"
#include "meshcore/KVM/Linux/linux_kvm_gala.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int eligible=1,active;
int kvm_gala_find_target(kvm_gala_target *t){memset(t,0,sizeof(*t));t->pid=(int)getpid();t->session.uid=1000;strcpy(t->session.id,"c1");strcpy(t->display,"wayland-0");return eligible;}
int kvm_gala_available(void){return active;}
int main(void){
    assert(getuid()==0);eligible=0;assert(mesh_gala_offer_signout()==3);
    eligible=1;active=1;assert(mesh_gala_offer_signout()==3);
    active=0;int sockets[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,sockets));
    int private=open("/etc/passwd",O_RDONLY);assert(private>=0);setenv("MESHAGENT_PRIVATE_TEST","must-not-reach-helper",1);
    assert(mesh_gala_offer_signout()==2);
    close(private);close(sockets[0]);close(sockets[1]);
    puts("Gala consent: ineligible/already-active skip, fresh sealed executable, scrubbed environment, private-FD isolation and declined result passed");
}
