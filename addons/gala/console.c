/* SPDX-License-Identifier: GPL-3.0-or-later
 * Agent-owned Gala addition, using public Gala and Clutter APIs only.
 * No capture, raw input, keymap, package, input-source or user-setting changes.
 */
#define _GNU_SOURCE
#include "glib-abi.h"
#include "../../meshcore/KVM/Linux/linux_gala_assets.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#define GENERATION MESH_GALA_GENERATION
#define REQUEST_SIZE 40u
#define REPLY_SIZE 32u
#define MAX_CLIENTS 8u
typedef struct {char *name,*author;GType type;int provides,priority;char *module;} PluginInfo;
void register_plugin(PluginInfo *info);
typedef struct Client {
    void *connection,*cancel;
    guint timer;
    unsigned char request[REQUEST_SIZE], reply[REPLY_SIZE];
} Client;
static struct {
    void *backend,*owned_method,*focus,*service,*file_monitor,*display;
    int (*client_type)(void *);
    void *(*get_method)(void *);
    void (*set_method)(void *,void *);
    void (*commit)(void *,const char *);
    void (*end_focus)(void *);
    unsigned char epoch[16];
    char socket[128];
    char asset[PATH_MAX];
    struct stat asset_identity,socket_identity;
    int enabled;
    guint clients;
} bridge;
static uint64_t now_ms(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC,&t)?0:(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static uint32_t read32(const unsigned char *p) {uint32_t v;memcpy(&v,p,4);return ntohl(v);}
static void write32(unsigned char *p,uint32_t v) {v=htonl(v);memcpy(p,&v,4);}
static uint64_t read64(const unsigned char *p) {return (uint64_t)read32(p)<<32|read32(p+4);}
static int scalar(uint32_t cp) {return cp>=0x20 && !(cp>=0x7f&&cp<0xa0) && !(cp>=0xd800&&cp<=0xdfff) && cp<=0x10ffff;}
static int new_epoch(void){
    int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
    size_t offset=0;
    while(offset<sizeof(bridge.epoch)){
        ssize_t n=read(fd,bridge.epoch+offset,sizeof(bridge.epoch)-offset);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){close(fd);return 0;}offset+=(size_t)n;
    }
    close(fd);return 1;
}
static int installed(void) {
    struct stat st;char record[4096];const char *prefix="MeshAgent Gala ";size_t size=strlen(prefix);
    if(!bridge.asset[0]||lstat(bridge.asset,&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0022)||st.st_nlink!=1)return 0;
    ssize_t n=getxattr(bridge.asset,"user.meshagent.gala",record,sizeof(record)-1);
    if(n<=(ssize_t)size||memcmp(record,prefix,size)){return 0;}record[n]=0;
    char *end=memchr(record+size,'\n',(size_t)n-size);
    if(!end||end==record+size||end-(record+size)>10||record[size]=='0'){return 0;}*end=0;
    if(strspn(record+size,"0123456789")!=strlen(record+size))return 0;
    size_t remaining=(size_t)n-(size_t)(end+1-record);
    if(remaining<130||remaining%65||remaining/65>33)return 0;
    for(char *line=end+1;line<record+n;line+=65){
        if(line[64]!='\n')return 0;
        for(int i=0;i<64;++i)if(!strchr("0123456789abcdef",line[i]))return 0;
    }
    /* A compatible owned image update must not interrupt the running desktop.
     * It takes effect on Gala's next normal start. Deletion/unmanaged files
     * still disable this addition immediately. */
    errno=0;unsigned long revision=strtoul(record+size,NULL,10);
    return errno!=ERANGE&&revision>=GENERATION&&revision<=0xfffffffful;
}
static void disable(void) {
    bridge.enabled=0;
    if(bridge.service){g_socket_service_stop(bridge.service);g_socket_listener_close(bridge.service);}
    struct stat st;
    if(bridge.socket[0]&&!lstat(bridge.socket,&st)&&st.st_dev==bridge.socket_identity.st_dev&&
        st.st_ino==bridge.socket_identity.st_ino)unlink(bridge.socket);
    if(bridge.owned_method&&bridge.get_method(bridge.backend)==bridge.owned_method){
        if(bridge.focus&&bridge.end_focus)bridge.end_focus(bridge.owned_method);
        bridge.set_method(bridge.backend,NULL);
    }
}
static void asset_changed(void *monitor,void *file,void *other,int event,void *data) {
    (void)monitor;(void)file;(void)other;(void)event;(void)data;
    if(!installed())disable();
}

/* ClutterInputMethod's public virtual methods, following GObjectClass. Runtime
 * type queries supply the parent size; no private instance layout is assumed.
 * A method is supplied only on Gala releases that have none. Existing IMEs are
 * never replaced, filtered or reset by this module.
 */
static void focus_in(void *im,void *focus) {
    (void)im;
    if(bridge.focus)g_object_unref(bridge.focus);
    bridge.focus=focus?g_object_ref(focus):NULL;
}
static void focus_out(void *im) {(void)im;if(bridge.focus)g_object_unref(bridge.focus);bridge.focus=NULL;}
static void noop(void *im) {(void)im;}
static void cursor(void *im,void *rect) {(void)im;(void)rect;}
static void surrounding(void *im,const char *text,guint cursor_pos,guint anchor) {(void)im;(void)text;(void)cursor_pos;(void)anchor;}
static void content(void *im,guint value) {(void)im;(void)value;}
static gboolean filter(void *im,void *event) {(void)im;(void)event;return 0;}
static void method_class(void *klass,void *data) {
    GTypeQuery q;(void)data;g_type_query(g_object_get_type(),&q);
    void (**v)(void)=(void (**)(void))((char *)klass+q.class_size);
    v[0]=(void (*)(void))focus_in;v[1]=(void (*)(void))focus_out;v[2]=(void (*)(void))noop;
    v[3]=(void (*)(void))cursor;v[4]=(void (*)(void))surrounding;
    v[5]=(void (*)(void))content;v[6]=(void (*)(void))content;v[7]=(void (*)(void))filter;
}
static int method_ready(void) {
    GType (*method_type)(void)=dlsym(RTLD_DEFAULT,"clutter_input_method_get_type");
    GTypeQuery parent,q;
    if(!method_type)return 0;
    if(bridge.get_method(bridge.backend))return 1;
    g_type_query(g_object_get_type(),&parent);g_type_query(method_type(),&q);
    if(q.class_size<parent.class_size+8*sizeof(void (*)(void)))return 0;
    GType type=g_type_from_name("MeshAgentGalaInputMethod");
    if(!type)type=g_type_register_static_simple(method_type(),"MeshAgentGalaInputMethod",q.class_size,method_class,q.instance_size,NULL,0);
    if(!type)return 0;
    bridge.owned_method=g_object_new(type,NULL);
    bridge.set_method(bridge.backend,bridge.owned_method);
    return bridge.get_method(bridge.backend)==bridge.owned_method;
}
static void close_client(Client *c) {
    if(c->timer)g_source_remove(c->timer);
    g_io_stream_close(c->connection,NULL,NULL);
    g_object_unref(c->connection);g_object_unref(c->cancel);
    --bridge.clients;g_free(c);
}
static gboolean timeout_client(void *data) {
    Client *c=data;c->timer=0;g_cancellable_cancel(c->cancel);return 0;
}
static void read_request(Client *c);
static void wrote(void *stream,void *result,void *data) {
    Client *c=data;size_t n=0;GError *error=NULL;
    if(!g_output_stream_write_all_finish(stream,result,&n,&error)||n!=REPLY_SIZE) {
        if(error){g_error_free(error);}close_client(c);return;
    }
    read_request(c);
}
static void reply(Client *c,uint32_t result) {
    memset(c->reply,0,sizeof(c->reply));memcpy(c->reply,"AGL1",4);
    write32(c->reply+4,result);memcpy(c->reply+8,bridge.epoch,16);
    write32(c->reply+24,GENERATION);
    g_output_stream_write_all_async(g_io_stream_get_output_stream(c->connection),c->reply,sizeof(c->reply),0,c->cancel,wrote,c);
}
/* MetaWindowClientType's public ABI: WAYLAND=0, X11=1. Unknown client kinds
 * also retain their existing physical-key path instead of swallowing text. */
static int needs_physical_keys(int client_type){return client_type!=0;}
static gboolean acknowledged(void *data) {
    Client *c=data;
    if(g_cancellable_is_cancelled(c->cancel)){close_client(c);return 0;}
    reply(c,0);return 0;
}
static gboolean inject(void *data) {
    Client *c=data;uint64_t now=now_ms(),deadline=read64(c->request+24);
    if(g_cancellable_is_cancelled(c->cancel)){close_client(c);return 0;}
    if(!now||deadline<now||deadline-now>1000){reply(c,2);return 0;}
    if(!bridge.enabled||!installed()){disable();reply(c,1);return 0;}
    if(bridge.display&&bridge.client_type){
        void *window=NULL;g_object_get(bridge.display,"focus-window",&window,NULL);
        if(window){int type=bridge.client_type(window);g_object_unref(window);if(needs_physical_keys(type)){reply(c,1);return 0;}}
    }
    void *method=bridge.get_method(bridge.backend);
    if(!method||(method==bridge.owned_method&&!bridge.focus)){reply(c,1);return 0;}
    char text[8]={0};g_unichar_to_utf8(read32(c->request+32),text);
    bridge.commit(method,text);
    /* Let Mutter flush text-input done before the caller's next character. */
    g_idle_add_full(2,acknowledged,c,NULL);return 0;
}
static void read_done(void *stream,void *result,void *data) {
    Client *c=data;size_t n=0;GError *error=NULL;
    if(!g_input_stream_read_all_finish(stream,result,&n,&error)||n!=REQUEST_SIZE-1) {
        if(error){g_error_free(error);}close_client(c);return;
    }
    uint32_t op=read32(c->request+4);
    if(memcmp(c->request,"AGL1",4)||read32(c->request+36)||(op!=1&&op!=2)){reply(c,3);return;}
    if(op==1){reply(c,bridge.enabled&&installed()?0:1);return;}
    if(memcmp(c->request+8,bridge.epoch,16)||!scalar(read32(c->request+32))){reply(c,3);return;}
    /* Defer behind already queued raw keyboard events; recheck expiry there. */
    g_idle_add_full(2,inject,c,NULL);
}
static void first_byte(void *stream,void *result,void *data) {
    Client *c=data;size_t n=0;GError *error=NULL;
    if(!g_input_stream_read_all_finish(stream,result,&n,&error)||n!=1) {
        if(error){g_error_free(error);}close_client(c);return;
    }
    c->timer=g_timeout_add_full(0,2000,timeout_client,c,NULL);
    g_input_stream_read_all_async(stream,c->request+1,REQUEST_SIZE-1,0,c->cancel,read_done,c);
}
static void read_request(Client *c) {
    if(c->timer)g_source_remove(c->timer);
    c->timer=0;
    /* Idle authenticated connections stay usable. Only a partial request gets
     * a timeout; a user pausing between keystrokes must not lose the bridge. */
    g_input_stream_read_all_async(g_io_stream_get_input_stream(c->connection),c->request,1,0,c->cancel,first_byte,c);
}
static gboolean incoming(void *service,void *connection,void *source,void *data) {
    (void)service;(void)source;(void)data;GError *error=NULL;
    void *credentials=g_socket_get_credentials(g_socket_connection_get_socket(connection),&error);
    int authorized=credentials&&g_credentials_get_unix_user(credentials,NULL)==0&&bridge.clients<MAX_CLIENTS;
    if(credentials){g_object_unref(credentials);}if(error){g_error_free(error);}
    if(!authorized){g_io_stream_close(connection,NULL,NULL);return 1;}
    Client *c=g_malloc0(sizeof(*c));c->connection=g_object_ref(connection);c->cancel=g_cancellable_new();
    ++bridge.clients;read_request(c);return 1;
}
static void initialize(void *self,void *wm) {
    (void)self;
    if(geteuid()==0)return;
    int (*wayland)(void)=dlsym(RTLD_DEFAULT,"meta_is_wayland_compositor");
    void *(*backend)(void)=dlsym(RTLD_DEFAULT,"clutter_get_default_backend");
    bridge.get_method=dlsym(RTLD_DEFAULT,"clutter_backend_get_input_method");
    bridge.set_method=dlsym(RTLD_DEFAULT,"clutter_backend_set_input_method");
    bridge.commit=dlsym(RTLD_DEFAULT,"clutter_input_method_commit");
    bridge.end_focus=dlsym(RTLD_DEFAULT,"clutter_input_method_focus_out");
    if(!wayland||!wayland()||!bridge.get_method||!bridge.set_method||!bridge.commit)return;
    Dl_info module;
    if(!dladdr(register_plugin,&module)||!module.dli_fname||strlen(module.dli_fname)>=sizeof(bridge.asset))return;
    strcpy(bridge.asset,module.dli_fname);
    if(lstat(bridge.asset,&bridge.asset_identity)||!installed())return;
    if(backend)bridge.backend=backend();
    else {
        void *(*stage)(void *)=dlsym(RTLD_DEFAULT,"gala_window_manager_get_stage");
        void *(*context)(void *)=dlsym(RTLD_DEFAULT,"clutter_actor_get_context");
        void *(*context_backend)(void *)=dlsym(RTLD_DEFAULT,"clutter_context_get_backend");
        if(stage&&context&&context_backend){void *actor=stage(wm),*ctx=actor?context(actor):NULL;if(ctx)bridge.backend=context_backend(ctx);}
    }
    if(!bridge.backend)return;
    void *(*display)(void *)=dlsym(RTLD_DEFAULT,"meta_plugin_get_display");
    bridge.client_type=dlsym(RTLD_DEFAULT,"meta_window_get_client_type");
    if(display)bridge.display=display(wm);
    char runtime[64];struct stat st;
    snprintf(runtime,sizeof(runtime),"/run/user/%u",(unsigned)geteuid());
    if(lstat(runtime,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077))return;
    snprintf(bridge.socket,sizeof(bridge.socket),"%s/meshagent-gala.sock",runtime);
    if(lstat(bridge.socket,&st)==0) {
        /* A previous compositor can leave its socket after ordinary exit.
         * Unlink only an unchanged, private, same-UID socket with no listener. */
        struct stat again;struct sockaddr_un addr={.sun_family=AF_UNIX};
        if(!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077))return;
        int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if(fd<0)return;
        strcpy(addr.sun_path,bridge.socket);
        int result=connect(fd,(struct sockaddr *)&addr,sizeof(addr)),error=errno;close(fd);
        if(result==0||error!=ECONNREFUSED||lstat(bridge.socket,&again)||
            again.st_dev!=st.st_dev||again.st_ino!=st.st_ino||unlink(bridge.socket))return;
    }
    errno=0;
    if(lstat(bridge.socket,&st)==0)return;
    if(errno!=ENOENT||!new_epoch())return;
    void *address=g_unix_socket_address_new(bridge.socket);GError *error=NULL;
    bridge.service=g_socket_service_new();mode_t mask=umask(0077);
    int bound=g_socket_listener_add_address(bridge.service,address,1,0,NULL,NULL,&error);
    umask(mask);g_object_unref(address);
    if(!bound||!method_ready()) {
        if(error){g_error_free(error);}g_socket_listener_close(bridge.service);g_object_unref(bridge.service);bridge.service=NULL;
        if(bound){unlink(bridge.socket);}return;
    }
    if(lstat(bridge.socket,&bridge.socket_identity)){disable();return;}
    bridge.enabled=1;
    void *file=g_file_new_for_path(bridge.asset);
    bridge.file_monitor=g_file_monitor_file(file,0,NULL,NULL);g_object_unref(file);
    if(!bridge.file_monitor){disable();return;}
    g_signal_connect_data(bridge.file_monitor,"changed",(GCallback)asset_changed,NULL,NULL,0);
    g_signal_connect_data(bridge.service,"incoming",(GCallback)incoming,NULL,NULL,0);
    g_socket_service_start(bridge.service);
}
static void destroy(void *self) {
    (void)self;
    disable();
    if(bridge.service){g_object_unref(bridge.service);bridge.service=NULL;}
    if(bridge.file_monitor){g_file_monitor_cancel(bridge.file_monitor);g_object_unref(bridge.file_monitor);bridge.file_monitor=NULL;}
    if(bridge.owned_method){g_object_unref(bridge.owned_method);}bridge.owned_method=NULL;
    focus_out(NULL);
}
static void plugin_class(void *klass,void *data) {
    GTypeQuery q;(void)data;g_type_query(g_object_get_type(),&q);
    void (**v)(void)=(void (**)(void))((char *)klass+q.class_size);
    v[0]=(void (*)(void))initialize;v[1]=(void (*)(void))destroy;
}
__attribute__((visibility("default"))) void register_plugin(PluginInfo *info) {
    GType (*base_type)(void)=dlsym(RTLD_DEFAULT,"gala_plugin_get_type");GTypeQuery parent,q;
    memset(info,0,sizeof(*info));if(!base_type)return;
    g_type_query(g_object_get_type(),&parent);g_type_query(base_type(),&q);
    if(q.class_size<parent.class_size+2*sizeof(void (*)(void)))return;
    GType type=g_type_register_static_simple(base_type(),"MeshAgentGalaConsole",q.class_size,plugin_class,q.instance_size,NULL,0);
    *info=(PluginInfo){g_strdup("meshagent-gala-console"),g_strdup("MeshAgent"),type,0,0,NULL};
}
