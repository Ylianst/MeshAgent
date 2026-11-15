/* Focused input-expiry tests; no capture, installer or desktop matrix. */
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const root = process.argv[2] ?? '.';
const protocol = await import('data:text/javascript;base64,' + fs.readFileSync(
    root + '/addons/gnome-shell/meshagent-console@meshcentral.com/protocol.js').toString('base64'));
const source = fs.readFileSync(root + '/addons/gnome-shell/meshagent-console@meshcentral.com/extension.js','utf8')
    .replace(/^import .*;\n/gm,'').replace('export default class MeshAgentConsole','globalThis.TestExtension = class MeshAgentConsole');
let passed=0;
function check(value,name) {assert.ok(value,name);passed++;}
function fixture(negotiated=true) {
    const state={keys:0,text:0,released:0,written:[],now:1000000};
    const ctx=vm.createContext({...protocol,TextEncoder,Uint8Array,DataView,
        Extension:class {},GLib:{get_monotonic_time:()=>state.now,PRIORITY_DEFAULT:0},
        Clutter:{InputDeviceType:{KEYBOARD_DEVICE:1},get_default_backend:()=>({get_default_seat:()=>({create_virtual_device:()=>({})})})}});
    vm.runInContext(source,ctx);
    const e=new ctx.TestExtension();
    Object.assign(e,{_enabled:true,_generation:1,_revision:1,_epoch:'01'.repeat(16),_busy:false,_inputExpiry:negotiated,
        _key:async()=>{state.keys++;return {};},_text:async()=>{state.text++;return {};},
        _releaseKeys:()=>state.released++,_read:()=>{},_close:()=>{},
        _status:()=>({epoch:'01'.repeat(16),revision:1,width:1,height:1,monitors:[{x:0,y:0,width:1,height:1}],
            frameFd:Boolean(e._frameFd),keyInput:Boolean(e._keyInput),inputExpiry:Boolean(e._inputExpiry)})});
    const c={get_output_stream:()=>({write_all_async(bytes,_p,_c,cb){state.written.push(bytes);cb({write_all_finish(){}},{});}})};
    e._connection=c;
    return {e,c,state,request:(op,deadlineMs)=>({op,wire:1,epoch:e._epoch,revision:1,code:30,value:1,text:'X',deadlineMs})};
}
for (const op of ['key','text']) {
    for (const deadline of [undefined,null,0,999,1000,NaN,Infinity,1000.5,'1100',2501]) {
        const {e,c,state,request}=fixture();await e._dispatch(request(op,deadline),c);
        check(state.keys+state.text===0,op+' invalid or expired deadline never injects');
        if (op==='key') check(state.released===1,'expired key releases held modifiers');
        check(new DataView(state.written[0].buffer).getUint32(8)===1,op+' rejection acknowledged');
    }
    for (const deadline of [1001,1400,2500]) {
        const {e,c,state,request}=fixture();await e._dispatch(request(op,deadline),c);
        check(state.keys+state.text===1,op+' valid deadline injects once');
        check(new DataView(state.written[0].buffer).getUint32(8)===0,op+' success acknowledged');
    }
    const {e,c,state,request}=fixture();const queued=request(op,1400);state.now=1500000;
    await e._dispatch(queued,c);check(state.keys+state.text===0,op+' queued request rejected after Shell resumes');
}
{
    const {e,c,state}=fixture(false);await e._dispatch({op:'status',wire:1,features:7},c);
    check(e._inputExpiry===true,'new peer negotiates expiry');
    check((new DataView(state.written[0].buffer).getUint32(32)&64)!==0,'expiry advertised only after negotiation');
}
{
    const {e,c,state}=fixture(false);await e._dispatch({op:'status',wire:1,features:3},c);
    check(e._inputExpiry===false,'legacy negotiation unchanged');
    check((new DataView(state.written[0].buffer).getUint32(32)&64)===0,'old Agent receives no unknown flag');
    await e._dispatch({op:'text',text:'X'},c);check(state.text===1,'legacy text unchanged');
}
{
    const {e,c,state}=fixture(false);await e._dispatch({op:'status',wire:1,features:8},c);
    check(e._inputExpiry===false,'unknown negotiation rejected');
    check((new DataView(state.written[0].buffer).getUint32(32)&64)===0,'unknown feature cannot opt in');
}
console.log(`${passed} input-expiry checks passed`);
