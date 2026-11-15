/* SPDX-License-Identifier: Apache-2.0
 * Installer-only consent helper. Executed from the Agent's sealed embedded
 * image after dropping all root identities/capabilities and inherited FDs.
 * Gtk and sd-bus are optional runtime APIs; no extra packages are installed.
 */
#define _GNU_SOURCE
#include "glib-abi.h"
#include "../../meshcore/KVM/Linux/linux_kvm_gala.h"
#include <dlfcn.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct sd_bus;struct sd_bus_message;struct sd_bus_error;
static int (*bus_open)(struct sd_bus **);
static int (*bus_timeout)(struct sd_bus *,uint64_t);
static int (*bus_call)(struct sd_bus *,const char *,const char *,const char *,const char *,struct sd_bus_error *,struct sd_bus_message **,const char *,...);
static int (*message_read)(struct sd_bus_message *,const char *,...);
static struct sd_bus_message *(*message_unref)(struct sd_bus_message *);
static struct sd_bus *(*bus_unref)(struct sd_bus *);
static void (*dialog_response)(void *,int);
typedef struct {void *dialog;guint timer;} Timeout;
static gboolean cancel_dialog(void *data){Timeout *t=data;t->timer=0;dialog_response(t->dialog,-6);return 0;}
static int manager(struct sd_bus *bus,char name[128]){
    struct sd_bus_message *reply=NULL;const char *owner=NULL;uint32_t uid=(uint32_t)-1;int good=0;
    if(bus_call(bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner",NULL,&reply,"s","org.gnome.SessionManager")<0||
        message_read(reply,"s",&owner)<0||!owner||owner[0]!=':'||strlen(owner)>=128)goto done;
    strcpy(name,owner);reply=message_unref(reply);
    if(bus_call(bus,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetConnectionUnixUser",NULL,&reply,"s",name)<0||
        message_read(reply,"u",&uid)<0||uid!=(uint32_t)getuid())goto done;
    good=1;
done:if(reply)message_unref(reply);return good;
}
int main(int argc,char **argv){
    if(argc!=3||getuid()!=geteuid()||strlen(argv[1])>10||strspn(argv[1],"0123456789")!=strlen(argv[1]))return 3;
    kvm_gala_target before,after;
    unsigned long expected=strtoul(argv[1],NULL,10);
    if(!expected||expected>INT_MAX||!kvm_gala_find_target(&before)||
        (getuid()!=0&&before.session.uid!=(int)getuid())||before.pid!=(int)expected||strcmp(before.session.id,argv[2]))return 3;
    if(getuid()==0){
        struct passwd *pw=getpwuid(before.session.uid);char home[4096],name[256];
        if(!pw||!pw->pw_dir||pw->pw_dir[0]!='/'||strlen(pw->pw_dir)>=sizeof(home)||!pw->pw_name||strlen(pw->pw_name)>=sizeof(name))return 3;
        uid_t uid=pw->pw_uid;gid_t gid=pw->pw_gid;strcpy(home,pw->pw_dir);strcpy(name,pw->pw_name);
        struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0}};
        if(prctl(PR_SET_KEEPCAPS,0L,0L,0L,0L)||initgroups(name,gid)||setresgid(gid,gid,gid)||
            setresuid(uid,uid,uid)||syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1L,0L,0L,0L))return 3;
        char runtime[64],bus[128];snprintf(runtime,sizeof(runtime),"/run/user/%u",(unsigned)uid);snprintf(bus,sizeof(bus),"unix:path=%s/bus",runtime);
        clearenv();setenv("HOME",home,1);setenv("USER",name,1);setenv("LOGNAME",name,1);setenv("PATH","/usr/bin:/bin",1);setenv("LANG","C.UTF-8",1);
        setenv("XDG_RUNTIME_DIR",runtime,1);setenv("DBUS_SESSION_BUS_ADDRESS",bus,1);setenv("WAYLAND_DISPLAY",before.display,1);setenv("GDK_BACKEND","wayland",1);
        if(chdir(home)&&chdir("/"))return 3;
    }
    void *systemd=dlopen("libsystemd.so.0",RTLD_NOW|RTLD_LOCAL),*gtk=dlopen("libgtk-3.so.0",RTLD_NOW|RTLD_LOCAL);
    if(!systemd||!gtk)return 3;
#define LOAD(target,handle,symbol) do {target=(__typeof__(target))dlsym(handle,symbol);if(!target)return 3;} while(0)
    LOAD(bus_open,systemd,"sd_bus_open_user");LOAD(bus_timeout,systemd,"sd_bus_set_method_call_timeout");
    LOAD(bus_call,systemd,"sd_bus_call_method");LOAD(message_read,systemd,"sd_bus_message_read");
    LOAD(message_unref,systemd,"sd_bus_message_unref");LOAD(bus_unref,systemd,"sd_bus_close_unref");
    int (*session_class)(const char *,char **),(*session_remote)(const char *);
    LOAD(session_class,systemd,"sd_session_get_class");LOAD(session_remote,systemd,"sd_session_is_remote");
    char *role=NULL;int local=session_class(before.session.id,&role)>=0&&role&&!strcmp(role,"user")&&session_remote(before.session.id)==0;
    free(role);if(!local)return 3;
    int (*gtk_init)(int *,char ***);void *(*dialog_new)(void *,int,int,int,const char *,...);
    void *(*add_button)(void *,const char *,int);void (*default_response)(void *,int);
    void (*title)(void *,const char *),(*destroy)(void *);int (*run)(void *);
    guint (*timeout_add)(int,guint,GSourceFunc,void *,void (*)(void *));gboolean (*remove_source)(guint);
    LOAD(gtk_init,gtk,"gtk_init_check");LOAD(dialog_new,gtk,"gtk_message_dialog_new");
    LOAD(add_button,gtk,"gtk_dialog_add_button");LOAD(default_response,gtk,"gtk_dialog_set_default_response");
    LOAD(title,gtk,"gtk_window_set_title");LOAD(destroy,gtk,"gtk_widget_destroy");LOAD(run,gtk,"gtk_dialog_run");
    LOAD(dialog_response,gtk,"gtk_dialog_response");LOAD(timeout_add,gtk,"g_timeout_add_full");LOAD(remove_source,gtk,"g_source_remove");
#undef LOAD
    struct sd_bus *bus=NULL;char owner[128],current_owner[128];
    if(bus_open(&bus)<0||bus_timeout(bus,1000000)<0||!manager(bus,owner))return 3;
    if(!gtk_init(NULL,NULL)){bus_unref(bus);return 3;}
    void *dialog=dialog_new(NULL,1,2,0,"%s","Sign out and back in to finish Wayland keyboard setup. Save your work first. If you choose Later, some characters may not work until your next sign-in.");
    if(!dialog){bus_unref(bus);return 3;}
    title(dialog,"MeshAgent");add_button(dialog,"Later",-6);add_button(dialog,"Sign Out",-3);default_response(dialog,-6);
    Timeout timeout={dialog,0};timeout.timer=timeout_add(0,45000,cancel_dialog,&timeout,NULL);
    int response=run(dialog);if(timeout.timer)remove_source(timeout.timer);destroy(dialog);
    if(response!=-3){bus_unref(bus);return 2;}
    if(!kvm_gala_find_target(&after)||after.pid!=before.pid||!kvm_wayland_console_session_equal(&after.session,&before.session)||
        !manager(bus,current_owner)||strcmp(owner,current_owner)){bus_unref(bus);return 3;}
    /* Explicit consent above. Mode 1 retains session inhibitors; never force. */
    int result=bus_call(bus,owner,"/org/gnome/SessionManager","org.gnome.SessionManager","Logout",NULL,NULL,"u",1u);
    bus_unref(bus);return result<0?3:0;
}
