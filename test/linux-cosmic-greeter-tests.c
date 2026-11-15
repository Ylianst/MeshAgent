/* SPDX-License-Identifier: Apache-2.0 */
#include "../meshcore/KVM/Linux/linux_kvm_wayland.c"
#include <assert.h>
#include <stdlib.h>

int main(void)
{
    char root[] = "/tmp/meshagent-cosmic-role-XXXXXX", path[512];
    kvm_wayland_console_session session = {0};
    assert(mkdtemp(root));
    snprintf(path, sizeof(path), "%s/systemd", root); assert(!mkdir(path, 0700));
    snprintf(path, sizeof(path), "%s/systemd/sessions", root); assert(!mkdir(path, 0700));
    snprintf(path, sizeof(path), "%s/systemd/sessions/c1", root);
    strcpy(session.id, "c1"); strcpy(session.type, "tty"); session.uid = 988;
    const char *rows[] = {
        "CLASS=greeter\nSERVICE=cosmic-greeter\n",
        "CLASS=user\nSERVICE=cosmic-greeter\n",
        "CLASS=greeter\nSERVICE=login\n",
        "CLASS=greeter\n",
        "SERVICE=cosmic-greeter\n",
        "CLASS=greeter-extra\nSERVICE=cosmic-greeter\n"
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i)
    {
        FILE *f = fopen(path, "w"); assert(f); fputs(rows[i], f); fclose(f);
        assert(kvm_wayland_cosmic_greeter_role(root, &session) == (i == 0));
    }
    FILE *f = fopen(path, "w"); assert(f); fputs(rows[0], f); fclose(f);
    strcpy(session.type, "x11"); assert(!kvm_wayland_cosmic_greeter_role(root, &session));
    strcpy(session.type, "wayland"); assert(!kvm_wayland_cosmic_greeter_role(root, &session));
    strcpy(session.type, "tty"); session.uid = 0; assert(!kvm_wayland_cosmic_greeter_role(root, &session));
    session.uid = 988; strcpy(session.id, "../c1"); assert(!kvm_wayland_cosmic_greeter_role(root, &session));
    assert(!unlink(path));
    snprintf(path, sizeof(path), "%s/systemd/sessions", root); assert(!rmdir(path));
    snprintf(path, sizeof(path), "%s/systemd", root); assert(!rmdir(path)); assert(!rmdir(root));
    puts("10 COSMIC greeter role checks passed; user tty, X11 and Wayland stay outside the exception");
    return 0;
}
