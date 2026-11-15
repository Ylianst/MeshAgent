import fs from 'node:fs';
import assert from 'node:assert/strict';
const source = fs.readFileSync(new URL('../addons/gnome-shell/meshagent-console@meshcentral.com/protocol.js', import.meta.url));
const {encodeHeader, HEADER_SIZE} = await import('data:text/javascript;base64,' + source.toString('base64'));
const base = {epoch:'0123456789abcdef0123456789abcdef',revision:7,locked:false,greeter:true,
    width:2048,height:768,monitors:[{x:-1024,y:0,width:1024,height:768},{x:0,y:0,width:1024,height:768}]};
let passed = 0;
function check(fn) { fn(); ++passed; }
const frame = encodeHeader(base,'capture',0,123);
const view = new DataView(frame.buffer);
check(() => assert.equal(frame.length, HEADER_SIZE + 32));
check(() => assert.equal(Buffer.from(frame.subarray(0,4)).toString(),'AGN1'));
check(() => assert.equal(view.getUint32(4),3));
check(() => assert.equal(view.getUint32(8),0));
check(() => assert.equal(Buffer.from(frame.subarray(12,28)).toString('hex'),base.epoch));
check(() => assert.equal(view.getUint32(28),7));
check(() => assert.equal(view.getUint32(32),2));
check(() => assert.equal(view.getUint32(36),2048));
check(() => assert.equal(view.getUint32(40),768));
check(() => assert.equal(view.getUint32(44),2));
check(() => assert.equal(view.getUint32(48),123));
check(() => assert.equal(view.getUint32(52),0));
check(() => assert.equal(view.getUint32(56),0));
check(() => assert.equal(view.getInt32(60),-1024));
check(() => assert.equal(view.getUint32(68),1024));
check(() => assert.equal(view.getUint32(72),768));
check(() => assert.equal(view.getInt32(76),0));
for (const patch of [{epoch:''},{epoch:'x'.repeat(32)},{revision:0},{revision:2**32},{width:0},
    {height:0},{width:8192,height:8192},{width:1.5},{monitors:[]},{monitors:Array(17).fill(base.monitors[0])},
    {monitors:[{x:32769,y:0,width:1024,height:768}]},{monitors:[{x:0,y:0,width:0,height:768}]}])
    check(() => assert.throws(() => encodeHeader({...base,...patch},'status',0)));
check(() => assert.throws(() => encodeHeader(base,'exec',0)));
check(() => assert.throws(() => encodeHeader(base,'capture',0,16777217)));
check(() => assert.throws(() => encodeHeader(base,'capture',0,-1)));
check(() => assert.throws(() => encodeHeader(base,'capture',3,1)));
const ready = new DataView(encodeHeader({...base,frameFd:true},'captureFd',3).buffer);
check(()=>assert.equal(ready.getUint32(4),4));
check(()=>assert.equal(ready.getUint32(8),3));
check(()=>assert.equal(ready.getUint32(32),18));
check(()=>assert.equal(ready.getUint32(48),0));
check(()=>assert.throws(()=>encodeHeader(base,'captureFd',0,1)));
const key = new DataView(encodeHeader({...base,keyInput:true},'key',0).buffer);
check(()=>assert.equal(key.getUint32(4),5));check(()=>assert.equal(key.getUint32(32),34));
check(()=>assert.throws(()=>encodeHeader(base,'key',3)));
console.log(`${passed} wire encoder checks passed`);
