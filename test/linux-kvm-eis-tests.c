/* SPDX-License-Identifier: Apache-2.0 */
/* Fault-injection tests of the adapter's real state machine. Live compositor
 * tests, separately, establish actual application delivery and consent policy. */
#include <sys/types.h>
static char fixtureRuntime[40];
#define KVM_EIS_RUNTIME_ROOT fixtureRuntime
static int fixture_server_auth(pid_t pid, pid_t compositor, unsigned long long start);
#define KVM_BRIDGE_SERVER_AUTH fixture_server_auth
#include "meshcore/KVM/Linux/linux_kvm_eis.c"
static int fixtureAuth = 1;
static int fixture_server_auth(pid_t pid, pid_t compositor, unsigned long long start)
{ (void)pid; (void)compositor; (void)start; return fixtureAuth; }
#include <sys/wait.h>
#include <stdarg.h>
static int passed, failed;
#define CHECK(name, x) do { if (x) { ++passed; } else { ++failed; fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,name); } } while (0)
static int ctxToken, deviceToken, pingToken, otherPing, busToken, eventToken;
static int queue[256], qRead, qWrite, ack, released, frames, starts, stops, sent, wrongSession, badUid;
static struct ei_device *queueDevice[256];
static int keyboardToken, lateToken, closes, closeAck, teardownSize;
static char teardown[512];
static void teardown_step(char step) { if(teardownSize<511)teardown[teardownSize++]=step; }
static int testPipe[2];
static int keySent, keyPressed, keyReleased, newPingFails;
static char order[64]; static int orderSize;
static char lastText[8];
static uint32_t fakeMods[4];
static uint32_t fake_depressed(struct ei_event *e) { (void)e; return fakeMods[0]; }
static uint32_t fake_latched(struct ei_event *e) { (void)e; return fakeMods[1]; }
static uint32_t fake_locked(struct ei_event *e) { (void)e; return fakeMods[2]; }
static uint32_t fake_group(struct ei_event *e) { (void)e; return fakeMods[3]; }
static int bridge_reply_case(int mode)
{
    char dir[]="/tmp/meshagent-eis-bridge-XXXXXX",path[108];
    struct sockaddr_un addr; uint32_t mods[4]={4,2,1,3};
    int listener, result, status; pid_t child;
    if(mkdtemp(dir)==NULL)return -99;
    snprintf(path,sizeof(path),"%s/socket",dir);
    memset(&addr,0,sizeof(addr));addr.sun_family=AF_UNIX;strcpy(addr.sun_path,path);
    listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(listener<0 || bind(listener,(struct sockaddr*)&addr,sizeof(addr))!=0 || chmod(path,0600)!=0 || listen(listener,1)!=0)return -99;
    child=fork();
    if(child==0)
    {
        uint32_t request[6],reply[9]; int peer=accept(listener,NULL,NULL);
        if (!fixtureAuth) { if (peer < 0 || recv(peer,request,sizeof(request),0) != 0) _exit(3); close(peer); _exit(0); }
        if(peer<0 || recv(peer,request,sizeof(request),0)!=sizeof(request))_exit(3);
        reply[0]=request[0];reply[1]=request[1];reply[2]=1;reply[3]=123;reply[4]=456;memcpy(reply+5,request+2,16);
        if(mode==1)reply[1]++;
        if(mode==2)reply[5]++;
        if(mode==3)reply[2]=3;
        if(mode==6 || mode==7) { reply[2]=mode==6?3:1;memcpy(reply+5,mods,16); }
        if(mode==8) {reply[2]=7;memcpy(reply+5,mods,16);}
        if(mode==9) {reply[2]=8;memcpy(reply+5,mods,16);}
        if(mode==5)usleep(350000);
        else (void)send(peer,reply,sizeof(reply)-(mode==4),MSG_NOSIGNAL);
        close(peer);close(listener);_exit(0);
    }
    close(listener);
    if(child<0)result=-99;
    else { result=eis_bridge_exchange(path,mode>=6?NULL:mods);waitpid(child,&status,0);if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)result=-99; }
    unlink(path);rmdir(dir);return result;
}


static int keymapFd; static size_t keymapSize;
static struct ei_keymap *fake_keymap(struct ei_device *d) { (void)d; return (struct ei_keymap *)&deviceToken; }
static size_t fake_keymap_size(struct ei_keymap *m) { (void)m; return keymapSize; }
static int fake_keymap_type(struct ei_keymap *m) { (void)m; return 1; }
static int fake_keymap_fd(struct ei_keymap *m) { (void)m; return keymapFd; }
static int keymap_fixture(int remapped)
{
    char path[]="/tmp/meshagent-keymap-XXXXXX";
    const char *normal="xkb_keymap { xkb_keycodes { include \"evdev+aliases(qwerty)\" }; xkb_types { include \"complete\" }; xkb_compatibility { include \"complete\" }; xkb_symbols { include \"pc+us\" }; };";
    const char *mapped="xkb_keymap { xkb_keycodes { include \"evdev+aliases(qwerty)\" }; xkb_types { include \"complete\" }; xkb_compatibility { include \"complete\" }; xkb_symbols { include \"pc+us\" replace key <AC01> { [ Control_L ] }; modifier_map Control { <AC01> }; }; };";
    const char *super="xkb_keymap { xkb_keycodes { include \"evdev+aliases(qwerty)\" }; xkb_types { include \"complete\" }; xkb_compatibility { include \"complete\" }; xkb_symbols { include \"pc+us\" replace key <AC01> { [ Super_L ] }; modifier_map Mod4 { <AC01> }; }; };";
    const char *altgr="xkb_keymap { xkb_keycodes { include \"evdev+aliases(qwerty)\" }; xkb_types { include \"complete\" }; xkb_compatibility { include \"complete\" }; xkb_symbols { include \"pc+us\" replace key <RALT> { [ ISO_Level3_Shift ] }; modifier_map Mod5 { <RALT> }; }; };";
    const char *text=remapped==3?altgr:remapped==2?super:remapped?mapped:normal;
    keymapFd=mkstemp(path);if(keymapFd<0)return 0;unlink(path);keymapSize=strlen(text)+1;
    if(write(keymapFd,text,keymapSize)!=(ssize_t)keymapSize)return 0;
    p_ei_device_keyboard_get_keymap=fake_keymap;p_ei_keymap_get_size=fake_keymap_size;p_ei_keymap_get_type=fake_keymap_type;p_ei_keymap_get_fd=fake_keymap_fd;
    return 1;
}

static int sessionClassMode;
static int fake_session_class(const char *id, char **value)
{ (void)id; if(sessionClassMode<0)return -1; *value=strdup(sessionClassMode?"greeter":"user");return 0; }

int kvm_wayland_active_console_session(kvm_wayland_console_session *s)
{ memset(s,0,sizeof(*s)); strcpy(s->id,wrongSession?"new":"old"); strcpy(s->type,"wayland"); s->uid=(int)geteuid()+badUid; return 1; }
int kvm_wayland_console_session_equal(const kvm_wayland_console_session *a,const kvm_wayland_console_session *b)
{ return a->uid==b->uid && !strcmp(a->id,b->id) && !strcmp(a->type,b->type); }
static struct ei *fake_unref(struct ei *ctx) { (void)ctx; teardown_step('E'); released++; return NULL; }
static struct sd_bus *fake_bus_unref(struct sd_bus *bus) { (void)bus; teardown_step('B'); released++; return NULL; }
static struct ei_device *fake_dev_unref(struct ei_device *dev) { (void)dev; teardown_step('D'); released++; return NULL; }
static void fake_close(struct ei_device *dev)
{
    closes++;teardown_step('C');
    if(closeAck && qWrite<256){queueDevice[qWrite]=dev;queue[qWrite++]=6;}
}
static struct ei_ping *fake_ping_unref(struct ei_ping *p) { (void)p; released++; return NULL; }
static struct ei_ping *fake_ping_new(struct ei *ctx) { (void)ctx; return newPingFails?NULL:(struct ei_ping *)&pingToken; }
static void fake_dispatch(struct ei *ctx) { (void)ctx; }
static int fake_fd(struct ei *ctx) { (void)ctx; return testPipe[0]; }
static struct ei_event *fake_event(struct ei *ctx) { (void)ctx; return qRead<qWrite?(struct ei_event *)&eventToken:NULL; }
static int fake_type(struct ei_event *e) { (void)e; return queue[qRead]; }
static struct ei_event *fake_event_unref(struct ei_event *e) { (void)e; if(queue[qRead]==6)teardown_step('R'); qRead++; return NULL; }
static struct ei_device *fake_event_dev(struct ei_event *e) { (void)e; return queueDevice[qRead]?queueDevice[qRead]:(struct ei_device *)&deviceToken; }
static struct ei_ping *fake_pong(struct ei_event *e) { (void)e; return (struct ei_ping *)(ack==2?&otherPing:&pingToken); }
static uint64_t fake_now(struct ei *ctx) { (void)ctx; return 100; }
static void fake_start(struct ei_device *dev, uint32_t seq) { (void)dev; CHECK("sequence increases",seq==(uint32_t)starts+1); starts++; }
static void fake_stop(struct ei_device *dev) { (void)dev; stops++; }
static void fake_frame(struct ei_device *dev,uint64_t now) { (void)dev; CHECK("frame timestamp",now==100); frames++; }
static void fake_text(struct ei_device *dev,const char *text) { (void)dev; order[orderSize++]='T'; sent++; snprintf(lastText,sizeof(lastText),"%s",text); }
static void fake_key(struct ei_device *dev,uint32_t code,bool pressed)
{ (void)dev; CHECK("valid evdev keycode",code>0 && code<=EIS_MAX_KEY); keySent++; keyPressed+=pressed; keyReleased+=!pressed; order[orderSize++]=pressed?'D':'U'; }
static void fake_ping(struct ei_ping *p) { (void)p; if (ack) { queue[qWrite++]=90; } }
static void reset(void)
{
    g_eisSelected=0; memset(&g_eisSelectedSession,0,sizeof(g_eisSelectedSession));
    g_eis=(struct ei *)&ctxToken; g_eisDevice=(struct ei_device *)&deviceToken; g_eisBus=(struct sd_bus *)&busToken;
    g_eisKeyboard=NULL; g_eisKeyboardOffered=0; g_eisTextOffered=0; memset(g_eisKeys,0,sizeof(g_eisKeys));
    keySent=keyPressed=keyReleased=orderSize=newPingFails=0;
    g_eisModsValid=0;g_eisBridgeEpoch=0;memset(g_eisMods,0,sizeof(g_eisMods));memset(order,0,sizeof(order));
    g_eisPing=NULL; g_eisPong=0; g_eisSequence=0; g_eisLastAttempt=0;
    qRead=qWrite=frames=starts=stops=sent=released=wrongSession=badUid=0; ack=1;
    closes=teardownSize=0;closeAck=1;memset(teardown,0,sizeof(teardown));memset(queueDevice,0,sizeof(queueDevice));
    kvm_wayland_active_console_session(&g_eisSession);
    p_ei_unref=fake_unref; p_sd_bus_close_unref=fake_bus_unref; p_ei_device_unref=fake_dev_unref;
    p_ei_device_close=fake_close;
    p_ei_ping_unref=fake_ping_unref; p_ei_new_ping=fake_ping_new; p_ei_dispatch=fake_dispatch;
    p_ei_get_fd=fake_fd; p_ei_get_event=fake_event; p_ei_event_get_type=fake_type;
    p_ei_event_unref=fake_event_unref; p_ei_event_get_device=fake_event_dev; p_ei_event_pong_get_ping=fake_pong;
    p_ei_event_keyboard_get_xkb_mods_depressed=fake_depressed; p_ei_event_keyboard_get_xkb_mods_latched=fake_latched;
    p_ei_event_keyboard_get_xkb_mods_locked=fake_locked; p_ei_event_keyboard_get_xkb_group=fake_group;
    p_ei_now=fake_now; p_ei_device_start_emulating=fake_start; p_ei_device_stop_emulating=fake_stop;
    p_ei_device_frame=fake_frame; p_ei_device_text_utf8=fake_text; p_ei_device_keyboard_key=fake_key; p_ei_ping=fake_ping;
}
static int focusAdoptionCalls,focusAdoptionFails;
static int focus_adopt(struct sd_bus *bus,const char *destination,const char *path,const char *interface,const char *method,struct sd_bus_error *error,struct sd_bus_message **reply,const char *types,...)
{
    (void)bus;(void)error;
    if(strcmp(interface,"org.freedesktop.DBus.Properties") || strcmp(method,"Set"))return -1;
    CHECK("pending raw chord uses pinned compositor owner",!strcmp(destination,":1.focus") && !strcmp(path,"/VirtualKeyboard") && !strcmp(types,"ssv"));
    va_list args;va_start(args,types);
    const char *propertyInterface=va_arg(args,const char *),*property=va_arg(args,const char *),*type=va_arg(args,const char *);
    int active=va_arg(args,int);va_end(args);
    CHECK("pending raw chord requests existing text-state adoption",!strcmp(propertyInterface,"org.kde.kwin.VirtualKeyboard") && !strcmp(property,"active") && !strcmp(type,"b") && active==1);
    focusAdoptionCalls++;if(focusAdoptionFails)return -1;
    *reply=(struct sd_bus_message *)&eventToken;return 0;
}
static struct sd_bus_message *focus_adopt_unref(struct sd_bus_message *reply)
{ CHECK("pending reply released",reply==(struct sd_bus_message *)&eventToken);return NULL; }

/* A valid bridge's focus epoch changed while no synthetic keys were held.
 * Exercise the public key state machine and real readiness/barrier sockets;
 * only compositor transport and process authentication use existing fakes. */
static void focus_epoch_case(int mode)
{
    char path[108],markerPath[108];struct sockaddr_un address;uint32_t marker=0x4d414234u;
    reset();g_eisKeyboard=(struct ei_device *)&keyboardToken;g_eisCompositorPid=getpid();
    g_eisModsValid=1;g_eisBridgeEpoch=44;g_eisGlobalChord=0;
    if(mode==1){g_eisKeys[29]=1;g_eisKeyRoute[29]=1;}
    snprintf(path,sizeof(path),"%s/%u/meshagent-ime-bridge.%u.sock",fixtureRuntime,(unsigned)geteuid(),g_eisCompositorPid);
    snprintf(markerPath,sizeof(markerPath),"%s/%u/meshagent-ime-bridge.%u.required",fixtureRuntime,(unsigned)geteuid(),g_eisCompositorPid);
    int record=open(markerPath,O_WRONLY|O_CREAT|O_EXCL,0600);CHECK("focus marker created",record>=0);
    if(record<0)return;
    CHECK("focus marker written",write(record,&marker,sizeof(marker))==sizeof(marker));close(record);
    int server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;strcpy(address.sun_path,path);
    int listening=server>=0 && bind(server,(struct sockaddr *)&address,sizeof(address))==0 && chmod(path,0600)==0 && listen(server,4)==0;
    CHECK("focus bridge listening",listening);
    if(!listening){if(server>=0)close(server);unlink(path);unlink(markerPath);return;}
    __typeof__(p_sd_bus_call_method) savedCall=p_sd_bus_call_method;
    __typeof__(p_sd_bus_message_unref) savedUnref=p_sd_bus_message_unref;
    p_sd_bus_call_method=focus_adopt;p_sd_bus_message_unref=focus_adopt_unref;
    strcpy(g_eisOwner,":1.focus");focusAdoptionCalls=0;focusAdoptionFails=mode==4;
    pid_t child=fork();CHECK("focus responder started",child>=0);
    if(!child){
        int count=0,bad=0,maximum=mode==0?3:mode==3?4:mode==5?2:1;
        while(count<maximum){
            struct pollfd wait={server,POLLIN,0};if(poll(&wait,1,500)<=0)break;
            int peer=accept(server,NULL,NULL);uint32_t request[6],reply[9];
            if(peer<0 || recv(peer,request,sizeof(request),MSG_TRUNC)!=sizeof(request))_exit(4);
            if(!count && (request[1]==0)!=(mode!=1))bad=1;
            if(mode!=2){
                reply[0]=request[0];reply[1]=request[1];reply[2]=request[1]?2:7;
                if((mode>=3 && count==0) || (mode==5 && count==1))reply[2]=8;
                reply[3]=mode>=3 && count>0?46:45;reply[4]=0;
                memcpy(reply+5,request+2,16);if(send(peer,reply,sizeof(reply),MSG_NOSIGNAL)!=sizeof(reply))_exit(5);
            }
            close(peer);count++;
        }
        close(server);_exit(bad || count!=maximum?6:0);
    }
    close(server);
    if(child>0){
        int result=kvm_eis_key_action(mode==1?38:29,1);
        if(mode==0 || mode==3){
            CHECK("new focus prepared before Ctrl",result==1 && g_eisKeys[29] && g_eisBridgeEpoch==(mode==3?46:45));
            CHECK("following chord key retains Ctrl ownership",result==1 && kvm_eis_key_action(38,1)==1 && g_eisKeys[29] && g_eisKeys[38] && keyPressed==2);
        }else if(mode==1){
            CHECK("held chord never adopts replacement context",result==-1 && keySent==1 && !g_eis && !eis_keys_held());
        }else{
            CHECK("failed fresh-chord preparation emits zero keys",result==-1 && keySent==0 && !g_eis);
        }
        int status=0;CHECK("focus responder reaped",waitpid(child,&status,0)==child);
        CHECK("focus probe and barrier order",WIFEXITED(status) && WEXITSTATUS(status)==0);
        CHECK("pending preparation performs exactly one adoption",focusAdoptionCalls==(mode>=3?1:0));
    }
    unlink(path);unlink(markerPath);kvm_eis_shutdown();
    p_sd_bus_call_method=savedCall;p_sd_bus_message_unref=savedUnref;
}

int main(void)
{
    char text[5]; uint64_t then; size_t i;
    char runtime[]="/tmp/eis-focus-XXXXXX",userdir[64];
    if(!mkdtemp(runtime))return 1;
    snprintf(fixtureRuntime,sizeof(fixtureRuntime),"%s",runtime);
    snprintf(userdir,sizeof(userdir),"%s/%u",runtime,(unsigned)geteuid());
    if(mkdir(userdir,0700)){rmdir(runtime);return 1;}
    reset(); g_eisDevice=NULL; g_eisKeyboardOffered=1;
    CHECK("keyboard-only handshake waits for keyboard",!eis_devices_ready());
    g_eisKeyboard=(struct ei_device *)&deviceToken; p_ei_device_text_utf8=NULL;
    CHECK("older keyboard-only libei is eligible",eis_devices_ready());
    g_eisTextOffered=1;
    CHECK("advertised text handshake still waits for text device",!eis_devices_ready());
    g_eisDevice=(struct ei_device *)&deviceToken;
    CHECK("combined handshake retains both-device requirement",eis_devices_ready());
    reset();
    const uint32_t invalid[]={0,0x1f,0x7f,0x80,0x9f,0xd800,0xdbff,0xdc00,0xdfff,0x110000,0xffffffff};
    {
        char path[]="/tmp/meshagent-eis-marker-XXXXXX";uint32_t marker=0x4d414233u;
        int fd=mkstemp(path);CHECK("marker fixture created",fd>=0);
        if(fd>=0){
            CHECK("write stock marker",write(fd,&marker,sizeof(marker))==sizeof(marker));
            CHECK("stock marker preserves desktop route",eis_bridge_marker_path(path)==1);
            marker++;CHECK("write owned text marker",pwrite(fd,&marker,sizeof(marker),0)==sizeof(marker));
            CHECK("owned marker selects text capability check",eis_bridge_marker_path(path)==2);
            marker=0x4d414231u;CHECK("write legacy stock marker",pwrite(fd,&marker,sizeof(marker),0)==sizeof(marker));
            CHECK("legacy relay marker fails closed",eis_bridge_marker_path(path)==-1);
            marker++;CHECK("write legacy headless marker",pwrite(fd,&marker,sizeof(marker),0)==sizeof(marker));
            CHECK("legacy headless marker fails closed",eis_bridge_marker_path(path)==-1);
            fchmod(fd,0666);CHECK("writable marker refused",eis_bridge_marker_path(path)==-1);
            close(fd);unlink(path);CHECK("absent marker preserves stock path",eis_bridge_marker_path(path)==0);
        }
    }
    const struct { uint32_t cp; const char *utf8; } valid[]={
        {0x20," "},{0x7e,"~"},{0xa0,"\xc2\xa0"},{0xe9,"\xc3\xa9"},
        {0x3a9,"\xce\xa9"},{0x7ff,"\xdf\xbf"},{0x800,"\xe0\xa0\x80"},
        {0x4e2d,"\xe4\xb8\xad"},{0xffff,"\xef\xbf\xbf"},
        {0x10000,"\xf0\x90\x80\x80"},{0x1f600,"\xf0\x9f\x98\x80"},{0x10ffff,"\xf4\x8f\xbf\xbf"}};
    CHECK("test pipe",pipe(testPipe)==0);
    reset();g_eisKeyboard=g_eisDevice;g_eisKeys[29]=1;g_eisKeyRoute[29]=1;
    eis_disconnect();
    CHECK("shared keyboard closes once before both refs and contexts",closes==1 && !strcmp(teardown,"CRDDEB"));
    CHECK("disconnect never replays an owned held key",keySent==0 && !g_eisKeys[29] && !g_eisKeyRoute[29]);
    reset();g_eisKeyboard=(struct ei_device *)&keyboardToken;
    eis_disconnect();
    CHECK("distinct devices both removed before context destruction",closes==2 && !strcmp(teardown,"CCRRDDEB"));
    reset();queue[qWrite++]=3;queue[qWrite++]=9;queue[qWrite++]=90;queue[qWrite++]=5;
    queueDevice[qWrite]=(struct ei_device *)&lateToken;queue[qWrite++]=8;
    eis_disconnect();
    CHECK("teardown closes late resumed device without activating input",closes==2 && starts==0 && frames==0 && sent==0 && keySent==0);
    CHECK("teardown ignores unrelated protocol events",!g_eisModsValid && !g_eisPong);
    reset();closeAck=0;then=eis_now_ms();eis_disconnect();
    CHECK("missing removal acknowledgement has bounded cleanup",eis_now_ms()-then>=200 && eis_now_ms()-then<800 && !strcmp(teardown,"CDEB"));
    reset();closeAck=0;queue[qWrite++]=2;then=eis_now_ms();eis_disconnect();
    CHECK("disconnected server does not delay cleanup",eis_now_ms()-then<100 && !strcmp(teardown,"CDEB"));
    reset();closeAck=0;for(i=0;i<200;i++)queue[qWrite++]=91;then=eis_now_ms();eis_disconnect();
    CHECK("teardown event flood bounded",qRead==128 && eis_now_ms()-then<100 && keySent==0);
    reset();g_eisDevice=NULL;eis_disconnect();
    CHECK("partial handshake without devices tears down directly",closes==0 && !strcmp(teardown,"EB"));
    teardownSize=0;teardown[0]=0;eis_disconnect();
    CHECK("repeated disconnect is neutral",teardownSize==0);
    reset();fakeMods[0]=4;fakeMods[1]=2;fakeMods[2]=1;fakeMods[3]=3;queue[qWrite++]=9;
    CHECK("EIS full modifier state captured",eis_drain()==1 && g_eisModsValid && !memcmp(g_eisMods,fakeMods,sizeof(fakeMods)));
    fixtureAuth=0; CHECK("same-UID fake endpoint receives no request",bridge_reply_case(0)==-1); fixtureAuth=1;
    CHECK("wire bridge acknowledges complete masks",bridge_reply_case(0)==1 && g_eisBridgeEpoch==((uint64_t)456<<32|123));
    CHECK("wire bridge accepts same epoch",bridge_reply_case(0)==1);
    CHECK("wire bridge rejects wrong nonce",bridge_reply_case(1)==-1);
    CHECK("wire bridge rejects wrong modifiers",bridge_reply_case(2)==-1);
    CHECK("wire bridge rejects unknown status",bridge_reply_case(3)==-1);
    CHECK("wire bridge rejects short reply",bridge_reply_case(4)==-1);
    then=eis_now_ms();CHECK("wire bridge times out",bridge_reply_case(5)==-1);
    CHECK("wire bridge timeout bounded",eis_now_ms()-then<1000);
    g_eisModsValid=0;memset(g_eisMods,0,sizeof(g_eisMods));
    CHECK("initial snapshot is a fresh HELLO",bridge_reply_case(6)==1 && g_eisModsValid && !memcmp(g_eisMods,fakeMods,sizeof(fakeMods)));
    g_eisModsValid=0;CHECK("HELLO rejects ordinary acknowledgement",bridge_reply_case(7)==-1 && !g_eisModsValid);
    g_eisBridgeEpoch=0;CHECK("owned no-grab method advertises public text commit",bridge_reply_case(8)==1&&g_eisBridgeCommit&&!g_eisBridgeGrab);
    CHECK("owned context without serial requires preparation",bridge_reply_case(9)==1&&g_eisBridgeCommit&&g_eisBridgePendingContext&&!g_eisBridgeGrab);
    CHECK("fresh ready context clears pending preparation",bridge_reply_case(8)==1&&!g_eisBridgePendingContext);
    g_eisBridgeEpoch=999;CHECK("wire bridge replacement invalidates chord",bridge_reply_case(0)==-1 && g_eisBridgeEpoch==999);
    kvm_eis_shutdown();CHECK("disconnect clears bridge epoch and modifiers",!g_eisModsValid && !g_eisBridgeEpoch);

    {
        const char separate[]="kwin_wayland\0--socket\0wayland-1\0--xwayland\0";
        const char joined[]="kwin_wayland\0--socket=wayland-0\0";
        const char missing[]="kwin_wayland\0--socket\0";
        char dir[]="/tmp/meshagent-eis-socket-XXXXXX",path[108];
        struct sockaddr_un addr;
        int listener;
        CHECK("explicit socket argument",eis_socket_argument(separate,sizeof(separate),"wayland-1"));
        CHECK("different display rejected",!eis_socket_argument(separate,sizeof(separate),"wayland-0"));
        CHECK("joined socket argument",eis_socket_argument(joined,sizeof(joined),"wayland-0"));
        CHECK("missing socket value rejected",!eis_socket_argument(missing,sizeof(missing),"wayland-0"));
        CHECK("unterminated argument rejected",!eis_socket_argument("--socket",8,"wayland-0"));
        CHECK("temporary socket directory",mkdtemp(dir)!=NULL);
        snprintf(path,sizeof(path),"%s/display",dir);
        memset(&addr,0,sizeof(addr));addr.sun_family=AF_UNIX;strcpy(addr.sun_path,path);
        listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
        CHECK("local test listener",listener>=0 && bind(listener,(struct sockaddr *)&addr,sizeof(addr))==0 && listen(listener,4)==0);
        CHECK("kernel peer identifies exact PID and UID",eis_socket_peer((uint32_t)getpid(),path));
        CHECK("different server PID rejected",!eis_socket_peer((uint32_t)getpid()+100000,path));
        close(listener);unlink(path);rmdir(dir);
    }
    strcpy(g_eisSession.id,"fixture");p_sd_session_get_class=fake_session_class;
    sessionClassMode=1;CHECK("greeter selects unified ordered input",eis_console_uses_ordered_input()==1);
    sessionClassMode=0;CHECK("ordinary unlocked session retains normal input",eis_console_uses_ordered_input()==0);
    sessionClassMode=-1;CHECK("missing session class has safe query fallback",eis_console_uses_ordered_input()==0);
    p_sd_session_get_class=NULL;
    CHECK("stock keymap fixture",keymap_fixture(0));
    CHECK("keymap identifies Ctrl",eis_key_is_modifier(29)==1);
    CHECK("keymap identifies Shift",eis_key_is_modifier(42)==1);
    CHECK("keymap identifies Caps Lock",eis_key_is_modifier(58)==1);
    CHECK("ordinary A is not a modifier",eis_key_is_modifier(30)==0);
    CHECK("Backspace is not a modifier",eis_key_is_modifier(14)==0);
    CHECK("left Super starts a global shortcut",eis_key_is_global_modifier(125)==1);
    CHECK("right Super starts a global shortcut",eis_key_is_global_modifier(126)==1);
    CHECK("Alt starts a global shortcut",eis_key_is_global_modifier(56)==1);
    CHECK("Ctrl retains the ordered input route",eis_key_is_global_modifier(29)==0);
    CHECK("ordinary L does not start a global chord",eis_key_is_global_modifier(38)==0);
    {
        uint32_t wanted[4];
        memset(g_eisMods,0,sizeof(g_eisMods));g_eisModsValid=1;
        CHECK("owned Ctrl chord predicts press without an EIS modifier echo",eis_chord_modifiers(29,1,wanted)==1 && wanted[0]==4);
        CHECK("owned Ctrl chord predicts release without a stale IME snapshot",eis_chord_modifiers(29,0,wanted)==1 && wanted[0]==0);
        CHECK("Shift is independent of the previous Ctrl chord",eis_chord_modifiers(42,1,wanted)==1 && wanted[0]==1);
        CHECK("Shift release restores unmodified input",eis_chord_modifiers(42,0,wanted)==1 && wanted[0]==0);
        p_xkb_state_unref(g_xkbKeys);g_xkbKeys=NULL;
        g_eisMods[0]=1;g_eisMods[2]=2;
        CHECK("physical Shift and Caps state seed the owned chord",eis_chord_modifiers(29,1,wanted)==1 && wanted[0]==5 && wanted[2]==2);
        CHECK("owned Ctrl release preserves physical Shift and Caps",eis_chord_modifiers(29,0,wanted)==1 && wanted[0]==1 && wanted[2]==2);
        p_xkb_state_unref(g_xkbKeys);g_xkbKeys=NULL;
    }
    close(keymapFd);CHECK("updated keymap fixture",keymap_fixture(1));
    CHECK("remapped A is identified as a modifier",eis_key_is_modifier(30)==1);
    {
        uint32_t wanted[4];memset(g_eisMods,0,sizeof(g_eisMods));g_eisModsValid=1;
        CHECK("modifier prediction follows remapped A",eis_chord_modifiers(30,1,wanted)==1 && wanted[0]==4);
        CHECK("remapped modifier release is exact",eis_chord_modifiers(30,0,wanted)==1 && wanted[0]==0);
        p_xkb_state_unref(g_xkbKeys);g_xkbKeys=NULL;
    }
    close(keymapFd);CHECK("remapped Super fixture",keymap_fixture(2));
    CHECK("global shortcut follows a remapped Super key",eis_key_is_global_modifier(30)==1);
    close(keymapFd);CHECK("AltGr fixture",keymap_fixture(3));
    CHECK("AltGr remains on the text input route",eis_key_is_global_modifier(100)==0);
    close(keymapFd);
    for (i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) { CHECK("reject invalid scalar/control",eis_utf8(invalid[i],text)==0); }
    for (i=0;i<sizeof(valid)/sizeof(valid[0]);i++)
    { CHECK("UTF-8 scalar bytes",eis_utf8(valid[i].cp,text)==(int)strlen(valid[i].utf8) && !strcmp(text,valid[i].utf8)); }
    reset();
    CHECK("first committed text",kvm_eis_type_unicode(0xe9)==1 && sent==1 && !strcmp(lastText,"\xc3\xa9"));
    CHECK("second committed text reuses context",kvm_eis_type_unicode(0x4e2d)==1 && sent==2 && released==2);
    CHECK("each send framed and stopped",frames==2 && starts==2 && stops==2);
    kvm_eis_shutdown(); CHECK("all resources released",released==5 && g_eis==NULL && g_eisBus==NULL && g_eisDevice==NULL);
    reset(); wrongSession=1;
    CHECK("session replacement never queues or retries",kvm_eis_type_unicode('x')==-1 && sent==0 && g_eis==NULL);
    reset(); badUid=1;
    CHECK("wrong session UID rejected",kvm_eis_type_unicode('x')==0 && sent==0 && g_eis==NULL);
    reset(); queue[qWrite++]=7;
    CHECK("paused device discarded before send",kvm_eis_type_unicode('x')==-1 && sent==0 && g_eis==NULL);
    reset(); queue[qWrite++]=6;
    CHECK("removed device discarded",kvm_eis_type_unicode('x')==-1 && sent==0 && g_eis==NULL);
    reset(); queue[qWrite++]=2;
    CHECK("disconnect discarded",kvm_eis_type_unicode('x')==-1 && sent==0 && g_eis==NULL);
    reset(); ack=0; then=eis_now_ms();
    CHECK("ambiguous delivery forbids fallback",kvm_eis_type_unicode('x')==-1 && sent==1 && stops==1 && released==4);
    CHECK("timeout bounded",eis_now_ms()-then>=200 && eis_now_ms()-then<1000);
    reset(); ack=2; then=eis_now_ms();
    CHECK("unrelated pong cannot acknowledge text",kvm_eis_type_unicode('x')==-1 && sent==1 && eis_now_ms()-then>=200);
    reset(); for(i=0;i<129;i++) { queue[qWrite++]=91; }
    CHECK("event flood bounded",!eis_drain() && qRead==128 && sent==0);
    eis_disconnect();
    CHECK("flood cleanup sends no input and closes the device",sent==0 && closes==1 && g_eis==NULL);
    reset(); CHECK("invalid scalar avoids backend",kvm_eis_type_unicode(0xd800)==0 && sent==0 && qRead==0);
    kvm_eis_shutdown();
    reset();
    CHECK("text-only context preserves uinput keyboard fallback",kvm_eis_key_action(29,1)==0 && keySent==0);
    g_eisKeyboard=(struct ei_device *)&deviceToken;
    CHECK("shortcut modifier press",kvm_eis_key_action(29,1)==1);
    CHECK("held modifier keeps emulation active",starts==1 && stops==0);
    CHECK("duplicate press is neutral",kvm_eis_key_action(29,1)==1 && keySent==1);
    CHECK("shortcut key press",kvm_eis_key_action(30,1)==1);
    CHECK("chord reuses active emulation",starts==1 && stops==0);
    CHECK("shortcut key release",kvm_eis_key_action(30,0)==1);
    CHECK("releasing chord key keeps modifier active",starts==1 && stops==0);
    CHECK("shortcut modifier release",kvm_eis_key_action(29,0)==1);
    CHECK("last release ends keyboard emulation",starts==1 && stops==1);
    CHECK("native text follows released shortcut",kvm_eis_type_unicode('m')==1 && !strcmp(order,"DDUUT"));
    CHECK("unmatched release belongs to fallback",kvm_eis_key_action(42,0)==0 && keySent==4);
    CHECK("invalid key does not mutate state",kvm_eis_key_action(0,1)==0 && kvm_eis_key_action(EIS_MAX_KEY+1,1)==0 && kvm_eis_key_action(29,2)==0 && keySent==4);
    kvm_eis_shutdown();
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;g_eisGlobalChord=1;g_eisModsValid=1;g_eisBridgeEpoch=123;
    CHECK("global Meta press uses the compositor keyboard",kvm_eis_key_action(125,1)==1 && g_eisKeyRoute[125]==1);
    CHECK("global L press stays on the same keyboard",kvm_eis_key_action(38,1)==1 && g_eisKeyRoute[38]==1);
    CHECK("early Meta release keeps the chord route",kvm_eis_key_action(125,0)==1 && g_eisGlobalChord);
    CHECK("final L release resets text context and modifier snapshot",kvm_eis_key_action(38,0)==1 && !g_eisGlobalChord && !g_eisModsValid && !g_eisBridgeEpoch);
    CHECK("global chord has one emulation lifetime",keyPressed==2 && keyReleased==2 && starts==1 && stops==1);
    kvm_eis_shutdown();
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;g_eisGlobalChord=1;
    CHECK("global modifier held before cleanup",kvm_eis_key_action(125,1)==1);
    kvm_eis_release_keys();
    CHECK("disconnect cleanup clears global routing and held keys",!g_eisGlobalChord && !eis_keys_held() && keyReleased==1);
    g_eisKeys[30]=1;g_eisKeyRoute[30]=2;
    CHECK("held relay key prevents splitting its chord",eis_relay_keys_held());
    g_eisKeys[30]=0;g_eisKeyRoute[30]=0;
    kvm_eis_shutdown();
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;
    CHECK("hold two keys",kvm_eis_key_action(29,1)==1 && kvm_eis_key_action(42,1)==1);
    kvm_eis_release_keys();
    CHECK("release batch covers every held key in one frame",keyReleased==2 && frames==3 && !g_eisKeys[29] && !g_eisKeys[42]);
    CHECK("batch releases existing emulation exactly once",starts==1 && stops==1);
    kvm_eis_release_keys();CHECK("repeated release is neutral",keyReleased==2 && frames==3);
    kvm_eis_shutdown();
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;ack=0;
    CHECK("ambiguous key delivery is never retried",kvm_eis_key_action(29,1)==-1 && keySent==1 && g_eis==NULL && g_eisKeyboard==NULL && !g_eisKeys[29]);
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;queue[qWrite++]=7;
    CHECK("paused keyboard rejects input before send",kvm_eis_key_action(29,1)==-1 && keySent==0 && g_eis==NULL);
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;
    CHECK("key held before session changes",kvm_eis_key_action(29,1)==1);
    wrongSession=1;kvm_eis_release_keys();
    CHECK("stale key releases never reach replacement session",keyReleased==0 && g_eis==NULL && !g_eisKeys[29]);
    kvm_eis_shutdown();
    reset();g_eisKeyboard=(struct ei_device *)&deviceToken;
    CHECK("hold modifier before allocation failure",kvm_eis_key_action(29,1)==1);
    newPingFails=1;
    CHECK("allocation failure never sends a plain fallback key after losing chord",kvm_eis_key_action(30,1)==-1 && keySent==1 && g_eis==NULL && !g_eisKeys[29]);
    reset();newPingFails=1;
    CHECK("allocation failure discards text without fallback",kvm_eis_type_unicode('x')==-1 && sent==0 && g_eis==NULL);
    reset();newPingFails=1;g_eisLastAttempt=eis_now_ms();
    CHECK("failed selected route drops the first character",kvm_eis_type_unicode('D')==-1 && sent==0);
    CHECK("retry delay cannot switch later text to native fallback",kvm_eis_type_unicode('R')==-1 && sent==0);
    CHECK("retry delay cannot split a shortcut across keyboards",kvm_eis_key_action(125,1)==-1 && keySent==0);
    badUid=1;
    CHECK("temporarily missing selected console never permits fallback",kvm_eis_type_unicode('O')==-1 && sent==0);
    badUid=0;
    kvm_eis_shutdown();
    g_eisLastAttempt=eis_now_ms();
    CHECK("explicit shutdown resets route selection",kvm_eis_type_unicode('P')==0);
    reset(); eis_disconnect();g_eisLastAttempt=eis_now_ms();
    CHECK("unselected backend retains safe initial fallback",kvm_eis_type_unicode('x')==0);
    kvm_eis_shutdown();
    reset();CHECK("focus keymap fixture",keymap_fixture(0));
    focus_epoch_case(0);focus_epoch_case(1);focus_epoch_case(2);
    focus_epoch_case(3);focus_epoch_case(4);focus_epoch_case(5);close(keymapFd);
    close(testPipe[0]); close(testPipe[1]);
    rmdir(userdir);rmdir(runtime);
    printf("%d passed, %d failed\n",passed,failed);
    return failed?1:0;
}
