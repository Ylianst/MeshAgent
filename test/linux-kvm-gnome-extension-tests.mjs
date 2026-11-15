import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const protocolSource = fs.readFileSync(new URL('../addons/gnome-shell/meshagent-console@meshcentral.com/protocol.js', import.meta.url));
const protocol = await import('data:text/javascript;base64,' + protocolSource.toString('base64'));
const source = fs.readFileSync(new URL('../addons/gnome-shell/meshagent-console@meshcentral.com/extension.js', import.meta.url),'utf8')
    .replace(/^import .*;\n/gm,'').replace('export default class MeshAgentConsole','globalThis.TestExtension = class MeshAgentConsole');
let passed = 0;
function setup(options = {}) {
    const state = {deleted:0,closed:0,stopped:0,cancelled:0,committed:0,composited:0,callbacks:[],written:[]};
    let inode = 1, nextTimer = 1;
    const info = () => {const capturedInode=inode;return {get_attribute_uint64:()=>capturedInode,
        get_attribute_uint32:key=>key==='unix::uid' ? (options.foreignSocket ? 1001 : 1000) :
            key==='unix::mode' ? (options.regularFile ? 0o100600 : 0o140600) : 1};};
    class Text {}
    class Service {
        add_address() { if(options.bindFailure) throw new Error('Address in use'); }
        connect(_name,callback) {state.incoming=callback;return 1;}
        disconnect() {} start() {} stop() {state.stopped++;} close() {state.closed++;}
    }
    const content = {get_texture:()=>({get_width:()=>options.largeTexture ? 8192 : 1024,get_height:()=>options.largeTexture ? 8192 : 768})};
    let resolveCapture;
    const capturePromise = options.delayed ? new Promise(resolve=>{resolveCapture=()=>resolve([content,1]);}) : Promise.resolve([content,1]);
    class Screenshot {
        async screenshot(_cursor, stream) {await capturePromise;state.composited++;state.captureStream=stream;return [true,{}];}
    }
    const Main = {sessionMode:{currentMode:'user',isLocked:false,isGreeter:false,connect:()=>1,disconnect(){}},
        layoutManager:{monitors:[{x:0,y:0,width:1024,height:768}],connect:()=>1,disconnect(){}},
        inputMethod:{currentFocus:{},commit(){state.committed++;}}};
    const context = vm.createContext({TextDecoder,TextEncoder,Uint8Array,DataView,console,
        ...protocol,Extension:class {},Config:{PACKAGE_VERSION:options.shellVersion??'48.0'},
        GioUnix:{OutputStream:class {
            constructor({fd,close_fd}) {state.frameStream=this;this.fd=fd;this.owned=close_fd;this.closed=false;}
            close(){this.closed=true;state.frameClosed=(state.frameClosed??0)+1;}
            is_closed(){return this.closed;}
        }},
        imports:{gi:{get GLibUnix(){
            if(options.missingGLibUnix)throw new Error('GLibUnix typelib not installed');
            return {fd_add_full(_priority,_fd,_events,callback){state.fdWatch=callback;state.fdApi='current';return nextTimer++;}};
        }}},Clutter:{Text,KeyState:{PRESSED:1,RELEASED:0},InputDeviceType:{KEYBOARD_DEVICE:1},
            get_default_backend:()=>({get_default_seat:()=>({create_virtual_device(){
                return {notify_key(time,code,value){(state.keys??=[]).push({time,code,value});},
                    run_dispose(){state.keyDisposed=(state.keyDisposed??0)+1;}};
            }})})},Shell:{Screenshot},Main,
        global:{stage:{width:1024,height:768,get_key_focus:()=>null,
            connect(name,callback){assert.equal(name,'after-update');state.frameCallback=callback;return 91;},
            disconnect(){state.frameDisconnected=(state.frameDisconnected??0)+1;},
            queue_redraw(){state.redraws=(state.redraws??0)+1;}},display:{get_monitor_scale:()=>options.largeTexture ? 8 : 1}},
        GLib:{get_monotonic_time:()=>12345,get_user_runtime_dir:()=>'/run/user/1000',build_filenamev:a=>a.join('/'),
            unix_fd_add_full(_priority,_fd,_events,callback){state.fdWatch=callback;state.fdApi='legacy';return nextTimer++;},
            uuid_string_random:()=> '01234567-89ab-cdef-0123-456789abcdef',chmod:()=>options.chmodFailure ? -1 : 0,
            PRIORITY_DEFAULT:0,PRIORITY_DEFAULT_IDLE:200,SOURCE_REMOVE:0,
            idle_add(priority,callback){state.idlePriority=priority;state.idleCallback=callback;return nextTimer++;},
            timeout_add_seconds:()=>nextTimer++,
            timeout_add(_p,_ms,cb){state.fdTimeout=cb;return nextTimer++;},
            IOCondition:{IN:1,HUP:2,ERR:4},
            file_read_link:()=>options.badFd ? '/tmp/not-a-memfd' : '/memfd:meshagent-gnome-frame (deleted)',
            close(){state.fdClosed=(state.fdClosed??0)+1;},
            Source:{remove(){}},base64_encode:()=>''},
        Gio:{SocketService:Service,UnixSocketAddress:{new:p=>p},SocketType:{STREAM:1},SocketProtocol:{DEFAULT:0},
            DBus:{session:{}},DBusProxyFlags:{DO_NOT_AUTO_START:1},
            DBusProxy:{new(...args){args.at(-1)(null,{});},new_finish:()=>({
                get_cached_property:()=>({deep_unpack:()=>Object.hasOwn(options,'powerMode') ? options.powerMode : 0}),connect:()=>1,disconnect(){}})},
            FileType:{REGULAR:1},FileQueryInfoFlags:{NOFOLLOW_SYMLINKS:1,NONE:0},File:{new_for_path:path=>({query_exists:()=>Boolean(options.existingSocket),
                query_info:()=>path.startsWith('/proc/') ? {
                    get_file_type:()=>1,get_size:()=>options.badFdSize ? 5 : 16777216,
                    get_attribute_uint32:key=>key==='unix::uid' ? 1000 : 0o100600,
                } : info(),delete:()=>state.deleted++})},
            Credentials:{new:()=>({get_unix_user:()=>1000})},SocketFamily:{UNIX:1},IOErrorEnum:{CONNECTION_REFUSED:1},
            Socket:{new:()=>({set_blocking(){},connect(){
                if(options.staleSocket) throw {matches:()=>true};
                if(options.blockedSocket) throw {matches:()=>false};
            },close(){}})},
            Cancellable:class {cancel(){state.cancelled++;}},
            MemoryOutputStream:{new_resizable:()=>{let closed=false;return {close(){closed=true;},is_closed:()=>closed,
                steal_as_bytes:()=>({get_size:()=>3,get_data:()=>new Uint8Array([1,2,3])})};}}}});
    if (options.modernBackend) {
        context.global.stage.context = {get_backend:context.Clutter.get_default_backend};
        delete context.Clutter.get_default_backend;
    }
    vm.runInContext(source,context);
    const extension = new context.TestExtension();
    const connection = () => ({closed:0,get_socket:()=>({get_credentials:()=>({get_unix_user:()=>options.nonRoot ? 1000 : 0}),get_fd:()=>17,set_blocking(){}}),
        receive_fd(){if(options.missingFd)throw new Error('No descriptor');return 23;},
        close(){this.closed++;},get_input_stream:()=>({read_bytes_async(_n,_p,_c,cb){state.callbacks.push(cb);}}),
        get_output_stream:()=>({write_all_async(bytes,_p,_c,cb){state.written.push(bytes);state.writeComplete=cb;}})});
    return {extension,state,connection,replaceSocket:()=>{inode=2;},resolveCapture};
}
function check(fn) {fn();passed++;}
{
 const {extension:e,state:s}=setup({bindFailure:true});
 check(()=>assert.throws(()=>e.enable(),/Address in use/));
 check(()=>assert.equal(s.deleted,0));
 check(()=>assert.equal(s.closed,1));
}
{
 const {extension:e,state:s}=setup({chmodFailure:true});
 check(()=>assert.throws(()=>e.enable(),/permissions/));
 check(()=>assert.equal(s.deleted,1));
 check(()=>assert.equal(s.cancelled,1));
}
{
 const {extension:e,state:s}=setup();e.enable();e.disable();e.disable();
 check(()=>assert.equal(s.deleted,1));
 check(()=>assert.equal(s.closed,1));
}
{
 const {extension:e,state:s,replaceSocket}=setup();e.enable();replaceSocket();e.disable();
 check(()=>assert.equal(s.deleted,0));
}
{
 const {extension:e,state:s,connection}=setup({nonRoot:true});e.enable();const c=connection();s.incoming(null,c);
 check(()=>assert.equal(c.closed,1));
 check(()=>assert.equal(e._connection,null));
 e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();s.incoming(null,c);
 const callback=s.callbacks[0];e.disable();
 callback({read_bytes_finish:()=>({get_size:()=>16,get_data:()=>new TextEncoder().encode('{"op":"status"}\n')})},{});
 check(()=>assert.equal(s.written.length,0));
 check(()=>assert.equal(e._connection,null));
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'text',wire:1,epoch:'bad',revision:1,text:'X'},c);
 check(()=>assert.equal(s.committed,0));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),1));
 e.disable();
}
{
 const {extension:e,state:s,resolveCapture}=setup({delayed:true});e.enable();
 const promise=e._capture(e._generation,e._revision);e._invalidate();resolveCapture();
 await assert.rejects(promise,/generation changed/);passed++;
 check(()=>assert.equal(s.composited,1));e.disable();
}
{
 const {extension:e,state:s}=setup({largeTexture:true});e.enable();
 await assert.rejects(e._capture(e._generation,e._revision),/too large/);passed++;
 check(()=>assert.equal(s.composited,0));e.disable();
}
{
 const {extension:e,connection,resolveCapture}=setup({delayed:true});e.enable();const c=connection();e._connection=c;
 const promise=e._dispatch({op:'capture',wire:1},c);e.disable();e.enable();e._busy=true;resolveCapture();await promise;
 check(()=>assert.equal(e._busy,true));e.disable();
}
for (const powerMode of [3,null]) {
 const {extension:e,state:s,connection}=setup({powerMode});e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'capture',wire:1},c);
 check(()=>assert.equal(s.composited,0));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),2));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(32),powerMode===3 ? 4 : 8));
 e.disable();
}
{
 const {extension:e,state:s}=setup({existingSocket:true,staleSocket:true});e.enable();
 check(()=>assert.equal(s.deleted,1));e.disable();
}
for (const options of [{existingSocket:true},{existingSocket:true,foreignSocket:true},
 {existingSocket:true,regularFile:true},{existingSocket:true,blockedSocket:true}]) {
 const {extension:e,state:s}=setup(options);
 check(()=>assert.throws(()=>e.enable()));
 check(()=>assert.equal(s.deleted,0));
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 const pending=e._dispatch({op:'text',wire:1,epoch:e._epoch,revision:e._revision,text:'X'},c);
 check(()=>assert.equal(s.committed,1));
 check(()=>assert.equal(s.written.length,0));
 check(()=>assert.equal(s.idlePriority,2));
 s.idleCallback();await pending;
 check(()=>assert.equal(s.written.length,1));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),0));
 e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 const pending=e._dispatch({op:'text',wire:1,epoch:e._epoch,revision:e._revision,text:'X'},c);
 e.disable();await pending;
 check(()=>assert.equal(s.written.length,0));
 check(()=>assert.equal(e._textIdleId,0));
}
for (const powerMode of [3,null]) {
 const {extension:e,state:s,connection,resolveCapture}=setup({delayed:true});
 e.enable();const c=connection();e._connection=c;
 const pending=e._dispatch({op:'capture',wire:1},c);
 e._powerSaveMode=powerMode;resolveCapture();await pending;
 const view=new DataView(s.written[0].buffer);
 check(()=>assert.equal(view.getUint32(8),2));
 check(()=>assert.equal(view.getUint32(32),powerMode===3 ? 4 : 8));
 check(()=>assert.equal(view.getUint32(48),0));
 e.disable();
}
{
 const {extension:e,state:s,connection,resolveCapture}=setup({delayed:true});
 e.enable();const c=connection();e._connection=c;
 const pending=e._dispatch({op:'capture',wire:1},c);
 e._invalidate();resolveCapture();await pending;
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),1));
 e.disable();
}
// Descriptor transfer has a READY boundary: it cannot start an ordinary JSON
// read while waiting for ancillary data, and must close on ambiguity.
const tick = async () => {for(let i=0;i<8;i++)await Promise.resolve();};
for (const options of [{}, {missingGLibUnix:true}, {badFd:true}, {badFdSize:true}, {missingFd:true}, {timeout:true}, {disconnect:true}]) {
 const {extension:e,state:s,connection}=setup(options);e.enable();const c=connection();e._connection=c;e._frameFd=true;
 const pending=e._dispatch({op:'captureFd',wire:1,epoch:e._epoch,revision:e._revision},c);
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),3));
 check(()=>assert.equal(s.composited,0));
 s.writeComplete({write_all_finish(){}},{});await tick();
 if(options.timeout)s.fdTimeout();
 else if(options.disconnect)e._close(c);
 else s.fdWatch();
 await pending;
 if(Object.keys(options).some(key=>key!=='missingGLibUnix')) {
   check(()=>assert.equal(s.composited,0));
   check(()=>assert.equal(e._connection,null));
   if(options.badFd||options.badFdSize)check(()=>assert.equal(s.fdClosed,1));
 } else {
   check(()=>assert.equal(s.fdApi,options.missingGLibUnix?'legacy':'current'));
   check(()=>assert.equal(s.composited,1));
   check(()=>assert.equal(s.captureStream,s.frameStream));
   check(()=>assert.equal(s.frameStream.closed,true));
   check(()=>assert.equal(s.written[1].length,76));
   check(()=>assert.equal(new DataView(s.written[1].buffer).getUint32(8),0));
   check(()=>assert.equal(new DataView(s.written[1].buffer).getUint32(48),0));
 }
 check(()=>assert.equal(e._fdWaitCancel,null));e.disable();
}
for(const features of [undefined,1]) {
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'status',wire:1,features},c);
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(32),features===1 ? 16 : 0));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'captureFd',wire:1,epoch:e._epoch,revision:e._revision},c);
 check(()=>assert.equal(s.composited,0));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),1));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;e._frameFd=true;
 const pending=e._dispatch({op:'captureFd',wire:1,epoch:e._epoch,revision:e._revision},c);
 s.writeComplete({write_all_finish(){}},{});await tick();e._invalidate();s.fdWatch();await pending;
 check(()=>assert.equal(s.composited,0));check(()=>assert.equal(s.frameStream.closed,true));e.disable();
}
for(const powerMode of [3,null]) {
 const {extension:e,state:s,connection,resolveCapture}=setup({delayed:true});e.enable();
 const c=connection();e._connection=c;e._frameFd=true;
 const pending=e._dispatch({op:'captureFd',wire:1,epoch:e._epoch,revision:e._revision},c);
 s.writeComplete({write_all_finish(){}},{});await tick();s.fdWatch();await tick();
 e._powerSaveMode=powerMode;resolveCapture();await pending;
 check(()=>assert.equal(new DataView(s.written[1].buffer).getUint32(8),2));
 check(()=>assert.equal(e._connection,c));check(()=>assert.equal(s.frameStream.closed,true));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;e._frameFd=true;
 const pending=e._dispatch({op:'captureFd',wire:1,epoch:e._epoch,revision:e._revision},c);
 s.writeComplete({write_all_finish(){}},{});await tick();e.disable();await pending;
 check(()=>assert.equal(s.composited,0));check(()=>assert.equal(e._fdWaitCancel,null));
}
function activateKeys(e,s,c){
 e._connection=c;e._keyboard={notify_key(time,code,value){(s.keys??=[]).push({time,code,value});},run_dispose(){s.keyDisposed=(s.keyDisposed??0)+1;}};e._keyInput=true;
}
for(const features of [2,3]) {
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'status',wire:1,features},c);
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(32),features===2 ? 32 : 48));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 const pending=e._dispatch({op:'key',wire:1,epoch:e._epoch,revision:e._revision,code:30,value:1},c);
 check(()=>assert.equal(s.keys.length,1));check(()=>assert.equal(s.keys[0].code,30));
 check(()=>assert.equal(s.keys[0].time,12345));check(()=>assert.equal(s.written.length,0));
 s.frameCallback();await pending;
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(4),5));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),0));
 e._close(c);check(()=>assert.equal(s.keys.at(-1).value,0));check(()=>assert.equal(e._pressedKeys.size,0));e.disable();
}
for(const transition of ['invalidate','disable']) {
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 const pending=e._dispatch({op:'key',wire:1,epoch:e._epoch,revision:e._revision,code:29,value:1},c);
 if(transition==='disable'){e.disable();await pending;check(()=>assert.equal(s.written.length,0));check(()=>assert.equal(s.keyDisposed,1));}
 else {e._invalidate();s.frameCallback();await pending;check(()=>assert.equal(e._revision,2));e.disable();}
 check(()=>assert.equal(s.keys.at(-1).value,0));check(()=>assert.equal(e._pressedKeys.size,0));
}
for(const patch of [{code:0},{code:768},{code:1.5},{value:2},{value:true},{epoch:'bad'},{wire:undefined}]) {
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 await e._dispatch({op:'key',wire:1,epoch:e._epoch,revision:e._revision,code:30,value:1,...patch},c);
 check(()=>assert.equal(s.keys?.length??0,0));
 if(patch.wire===undefined&&Object.hasOwn(patch,'wire'))check(()=>assert.equal(JSON.parse(new TextDecoder().decode(s.written[0])).ok,false));
 else check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),1));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 for(const value of [1,1,0,0]){const pending=e._key(30,value);s.frameCallback();await pending;}
 check(()=>assert.equal(s.keys.length,2));check(()=>assert.equal(e._pressedKeys.size,0));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 const pending=e._dispatch({op:'key',wire:1,epoch:e._epoch,revision:e._revision,code:29,value:1},c);
 check(()=>assert.equal(s.redraws,1));check(()=>assert.equal(s.written.length,0));
 s.fdTimeout();await pending;
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(8),1));
 check(()=>assert.equal(s.keys.at(-1).value,0));check(()=>assert.equal(e._keyFrameCancel,null));
 check(()=>assert.equal(s.frameDisconnected,1));e.disable();
}
{
 const {extension:e,state:s,connection}=setup();e.enable();const c=connection();activateKeys(e,s,c);
 const pending=e._dispatch({op:'key',wire:1,epoch:e._epoch,revision:e._revision,code:29,value:1},c);
 e._close(c);await pending;
 check(()=>assert.equal(s.written.length,0));check(()=>assert.equal(e._keyFrameCancel,null));
 check(()=>assert.equal(s.keys.at(-1).value,0));e.disable();
}
{
 const {extension:e,state:s,connection}=setup({modernBackend:true});e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'status',wire:1,features:7},c);
 check(()=>assert.equal(Boolean(e._keyInput),false));check(()=>assert.equal(e._keyboard,undefined));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(32),80));e.disable();
}
for (const shellVersion of ['49.4','50.1','51.1']) {
 const {extension:e,state:s,connection}=setup({shellVersion});e.enable();const c=connection();e._connection=c;
 await e._dispatch({op:'status',wire:1,features:7},c);
 check(()=>assert.equal(Boolean(e._keyInput),false));check(()=>assert.equal(e._keyboard,undefined));
 check(()=>assert.equal(new DataView(s.written[0].buffer).getUint32(32),80));e.disable();
}
console.log(`${passed} extension lifecycle checks passed`);
