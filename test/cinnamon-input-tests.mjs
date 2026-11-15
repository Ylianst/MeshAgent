// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('../meshcore/KVM/Linux/cinnamon-input.js',import.meta.url),'utf8');
const idles=[],timers=new Map(),events=[],commits=[],devices=[];let start='42',focus=null,next=1;
class Text { constructor(){this.editable=true;this.inserted='';} delete_selection(){this.deleted=true;}get_cursor_position(){return 0;}insert_text(text){this.inserted+=text;} }
const method={commit(text){commits.push(text);}};
const GLib={PRIORITY_DEFAULT:0,SOURCE_REMOVE:false,SOURCE_CONTINUE:true,
 file_get_contents(){const a=Array(20).fill('0');a[0]='S';a[19]=start;return [true,Buffer.from('123 (meshagent) '+a.join(' '))];},
 idle_add(priority,callback){assert.equal(priority,2);idles.push(callback);return next++;},
 timeout_add_seconds(priority,seconds,callback){assert.equal(seconds,2);const id=next++;timers.set(id,callback);return id;},
 source_remove(id){timers.delete(id);}};
const backend={get_input_method(){return method;},get_default_seat(){return {create_virtual_device(){
 const d={notify_key(time,code,pressed){events.push({d,code,pressed});},run_dispose(){d.disposed=true;}};devices.push(d);return d;}};}};
const global={stage:{get_key_focus(){return focus;}}};
const init=vm.runInNewContext(source,{global,imports:{gi:{Clutter:{Text,KeyState:{PRESSED:1,RELEASED:0},InputDeviceType:{KEYBOARD_DEVICE:1},get_default_backend(){return backend;}},GLib,Meta:{is_wayland_compositor(){return true;}}},byteArray:{toString(bytes){return bytes.toString();}}}});
function drain(){while(idles.length)idles.shift()();}
assert.equal(init(123,'one'),0);
const act=global._meshAgentCinnamonInputV1;
assert.equal(act('one',2,1,0x4e2d,0),1);
assert.deepEqual(commits,['中']);assert.equal(act('one',3,1,0,0),1);
assert.equal(act('one',2,2,0xe9,0),-1);assert.equal(commits.length,1);
drain();assert.equal(act('one',3,1,0,0),0);
for(const cp of [0,31,127,0xd800,0xdfff,0x110000])assert.equal(act('one',2,2,cp,0),-1);
assert.equal(commits.length,1);
assert.equal(act('one',1,3,29,1),1);drain();assert.equal(timers.size,1);
assert.equal(act('one',1,4,29,0),1);drain();assert.equal(timers.size,0);
assert.deepEqual(events.map(x=>[x.code,x.pressed]),[[29,1],[29,0]]);
assert.equal(act('one',1,5,42,1),1);drain();
assert.equal(init(123,'two'),0);assert.equal(act('two',1,1,30,1),1);drain();
assert.equal(act('one',4,0,0,0),0);drain();assert.equal(devices[0].disposed,true);
assert.equal(devices[1].disposed,undefined);assert.equal(act('two',3,1,0,0),0);
start='99';const timer=[...timers.values()][0];assert.equal(timer(),false);drain();
assert.equal(devices[1].disposed,true);assert.equal(act('two',3,1,0,0),-1);
assert.equal(events.at(-1).code,30);assert.equal(events.at(-1).pressed,0);
assert.equal(backend.get_input_method(),method);
focus=new Text();assert.equal(init(123,'three'),0);assert.equal(act('three',2,1,0x1f600,0),1);drain();
assert.equal(focus.inserted,'😀');assert.equal(focus.deleted,true);assert.equal(commits.length,1);
assert.equal(act('three',4,0,0,0),0);drain();
assert.equal(init(123,'orphan'),0);const orphan=devices.at(-1);
start='100';assert.equal(init(123,'replacement'),0);drain();assert.equal(orphan.disposed,true);
assert.equal(act('orphan',3,1,0,0),-1);assert.equal(act('replacement',4,0,0,0),0);drain();
console.log('Cinnamon input contracts passed: idle ordering, scalars, modifier release, worker incarnation, route isolation');
