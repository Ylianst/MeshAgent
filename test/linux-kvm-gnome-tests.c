/* SPDX-License-Identifier: Apache-2.0 */
#include "linux_kvm_gnome.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int passed, failed;
static void check(int value, const char *name)
{ if (value) { ++passed; } else { ++failed; fprintf(stderr, "FAIL: %s\n", name); } }
static void put(unsigned char *b, size_t at, uint32_t n)
{ n = htonl(n); memcpy(b + at, &n, 4); }
static void fixture(unsigned char *b)
{
    memset(b, 0, 316); memcpy(b, "AGN1", 4); put(b, 4, 1); b[12] = 1;
    put(b, 28, 1); put(b, 36, 1024); put(b, 40, 768); put(b, 44, 1);
    put(b, 68, 1024); put(b, 72, 768);
}
int main(void)
{
    unsigned char b[316], original[316];
    kvm_gnome_reply r, untouched;
    fixture(b); memcpy(original, b, sizeof(b));
    check(kvm_gnome_decode_header(b, 76, &r), "single output");
    check(r.width == 1024 && r.height == 768 && r.count == 1 && r.monitors[0].width == 1024,
        "decoded dimensions");
    for (size_t i = 0; i < 76; ++i)
        check(!kvm_gnome_decode_header(b, i, &r), "truncated header or geometry");
    check(!kvm_gnome_decode_header(NULL, 76, &r), "null input");
    check(!kvm_gnome_decode_header(b, 76, NULL), "null output");
    struct { size_t offset; uint32_t value; const char *name; } invalid[] = {
        {0,0,"magic"}, {4,0,"zero opcode"}, {4,6,"unknown opcode"}, {8,3,"unknown result"},
        {28,0,"zero revision"}, {32,128,"unknown flags"}, {36,0,"zero width"}, {40,0,"zero height"},
        {36,16385,"excess width"}, {40,16385,"excess height"}, {44,0,"zero monitors"},
        {44,17,"excess monitors"}, {48,1,"status payload forbidden"},
        {52,1,"reserved field one"}, {56,1,"reserved field two"},
        {60,32769,"x excessive"}, {60,(uint32_t)-32769,"x negative excessive"},
        {64,32769,"y excessive"}, {64,(uint32_t)-32769,"y negative excessive"},
        {68,0,"zero monitor width"}, {72,0,"zero monitor height"},
        {68,16385,"monitor width excessive"}, {72,16385,"monitor height excessive"},
        {68,1023,"incomplete desktop width"}, {72,767,"incomplete desktop height"}
    };
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++)
    {
        memcpy(b, original, sizeof(b)); put(b, invalid[i].offset, invalid[i].value);
        memset(&r, 0xa5, sizeof(r)); untouched = r;
        check(!kvm_gnome_decode_header(b, 76, &r), invalid[i].name);
        check(memcmp(&r, &untouched, sizeof(r)) == 0, "failure leaves output unchanged");
    }
    fixture(b); put(b, 4, 5); put(b, 32, 32);
    check(kvm_gnome_decode_header(b,76,&r),"negotiated compositor key reply");
    put(b,48,1);check(!kvm_gnome_decode_header(b,76,&r),"key reply cannot carry pixels");
    fixture(b); put(b, 4, 4); put(b, 8, 3); put(b, 32, 16);
    check(kvm_gnome_decode_header(b, 76, &r), "negotiated FD ready");
    put(b, 8, 0);
    check(kvm_gnome_decode_header(b, 76, &r), "FD complete has no inline payload");
    put(b, 48, 1);
    check(!kvm_gnome_decode_header(b, 76, &r), "FD reply rejects inline payload");
    fixture(b); put(b, 4, 3);
    check(!kvm_gnome_decode_header(b, 76, &r), "capture requires pixels");
    put(b, 48, KVM_GNOME_MAX_PAYLOAD);
    check(kvm_gnome_decode_header(b, 76, &r), "bounded capture payload");
    put(b, 48, KVM_GNOME_MAX_PAYLOAD + 1);
    check(!kvm_gnome_decode_header(b, 76, &r), "capture payload overflow");
    put(b, 48, 1); put(b, 8, 1);
    check(!kvm_gnome_decode_header(b, 76, &r), "declined capture cannot carry pixels");
    put(b,48,0);put(b,8,2);put(b,32,4);
    check(kvm_gnome_decode_header(b,76,&r),"asleep display carries no black substitute frame");
    put(b,32,8);
    check(kvm_gnome_decode_header(b,76,&r),"unknown power state explicit");
    fixture(b); put(b, 36, 2048); put(b, 44, 2); put(b, 76, 1024); put(b, 84, 1024); put(b, 88, 768);
    check(kvm_gnome_decode_header(b, 92, &r), "two adjacent monitors");
    put(b, 60, (uint32_t)-1024); put(b, 76, 0);
    check(kvm_gnome_decode_header(b, 92, &r) && r.monitors[0].x == -1024, "negative monitor origin");
    put(b, 76, 1);
    check(!kvm_gnome_decode_header(b, 92, &r), "monitor union mismatch");
    fixture(b); put(b, 44, 2); put(b, 84, 1024); put(b, 88, 768);
    check(kvm_gnome_decode_header(b, 92, &r), "mirrored monitors share desktop");
    fixture(b); put(b, 36, 8192); put(b, 40, 8192); put(b, 68, 8192); put(b, 72, 8192);
    check(!kvm_gnome_decode_header(b, 76, &r), "pixel allocation bound");
    check(kvm_gnome_type_unicode(0xd800) == 0 && kvm_gnome_type_unicode(0x110000) == 0,
        "invalid Unicode never queued");
    {
        kvm_wayland_console_session s = {.id="c4",.uid=1000,.type="wayland"};
        const char args[] = "/usr/bin/gnome-shell";
        const char nested[] = "/usr/bin/gnome-shell\0--nested";
        const char headless[] = "/usr/bin/gnome-shell\0--headless";
        const char *scope = "0::/user.slice/user-1000.slice/session-c4.scope\n";
        const char *service = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service\n";
        check(kvm_gnome_process_identity_matches(&s,scope,args,sizeof(args)),"attached session scope");
        check(kvm_gnome_process_identity_matches(&s,service,args,sizeof(args)),"GNOME managed Wayland service");
        const char *modern = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@user.service\n";
        check(kvm_gnome_process_identity_matches(&s,modern,args,sizeof(args)),"GNOME 51 managed user service");
        const char *ubuntu = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@ubuntu.service\n";
        check(kvm_gnome_process_identity_matches(&s,ubuntu,args,sizeof(args)),"Ubuntu GNOME 50 managed session mode");
        const char *classic = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@classic.service\n";
        check(kvm_gnome_process_identity_matches(&s,classic,args,sizeof(args)),"GNOME Classic managed session mode");
        check(!kvm_gnome_process_identity_matches(&s,classic,nested,sizeof(nested)),"Classic unit rejects nested compositor");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1001.slice/user@1001.service/session.slice/org.gnome.Shell@classic.service\n",args,sizeof(args)),"Classic unit retains UID binding");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@classic.service/subgroup\n",args,sizeof(args)),"Classic unit rejects subgroups");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@classic-evil.service\n",args,sizeof(args)),"Classic unit rejects different instance");
        check(!kvm_gnome_process_identity_matches(&s,ubuntu,nested,sizeof(nested)),"Ubuntu unit rejects nested compositor");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1001.slice/user@1001.service/session.slice/org.gnome.Shell@ubuntu.service\n",args,sizeof(args)),"Ubuntu unit retains UID binding");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@ubuntu.service/subgroup\n",args,sizeof(args)),"Ubuntu unit rejects subgroups");
        check(!kvm_gnome_process_identity_matches(&s,modern,nested,sizeof(nested)),"modern unit does not permit nested compositor");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1001.slice/user@1001.service/session.slice/org.gnome.Shell@user.service\n",args,sizeof(args)),"modern unit retains UID binding");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@user.service/subgroup\n",args,sizeof(args)),"modern unit rejects subgroups");
        check(!kvm_gnome_process_identity_matches(&s,scope,nested,sizeof(nested)),"nested GNOME rejected");
        check(!kvm_gnome_process_identity_matches(&s,scope,headless,sizeof(headless)),"headless GNOME rejected");
        check(!kvm_gnome_process_identity_matches(&s,scope,args,sizeof(args)-1),"unterminated argv rejected");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/session-c3.scope\n",args,sizeof(args)),"other session rejected");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1001.slice/session-c4.scope\n",args,sizeof(args)),"other UID scope rejected");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@x11.service\n",args,sizeof(args)),"X11 service rejected");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/user@1000.service/session.slice/app-nested.scope\n",args,sizeof(args)),"unrelated user service rejected");
        check(!kvm_gnome_process_identity_matches(&s,"0::/user.slice/user-1000.slice/session-c4.scope/subgroup\n",args,sizeof(args)),"scope child rejected");
    }
    kvm_gnome_shutdown(); kvm_gnome_shutdown();
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
