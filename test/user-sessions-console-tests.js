'use strict';
// Exercise the real module with controlled OS responses and deterministic timers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const EventEmitter = require('node:events');
const path = require('node:path');
const sourcePath = process.argv[2] || path.join(__dirname, '..', 'modules', 'user-sessions.js');
const source = fs.readFileSync(sourcePath, 'utf8');
let passed = 0;
function test(name, fn) { fn(); console.log('ok - ' + name); ++passed; }
function state(properties = {}) {
    return Object.entries(Object.assign({Id:'c2',User:'111',Seat:'seat0',Remote:'no',Active:'yes',Type:'x11',Class:'greeter',Display:':1'},properties)).map(([k,v])=>k+'='+v).join('\n')+'\n';
}
function fixture(options = {}) {
    const watches = new Map(), timers = new Map(), commands = [], spawnedChildren = [];
    let session = state(), nextTimer = 1;
    const module = {exports:{}};
    const mockFs = {
        existsSync(p) { return p === '/run/systemd/seats' ? options.seats !== false : p === '/var/run/utmp' && options.utmp === true; },
        watch(p) { const watcher=new EventEmitter();watches.set(p,watcher);return watcher; }
    };
    function child() {
        const c={stdout:new EventEmitter(),stderr:new EventEmitter(),input:''}; spawnedChildren.push(c);
        c.stdin={write(s){c.input+=s;}};
        c.waitExit=function(){
            commands.push(c.input);
            let output;
            if(c.input.includes('whereis loginctl')) output=options.loginctl===false?'':'/usr/bin/loginctl\n';
            else if(c.input.startsWith('sid=$(loginctl show-seat')) output=session;
            else if(c.input.includes('cat /etc/login.defs')) output='1000\n';
            else if(c.input.startsWith('loginctl list-sessions')) output='[{"uid":"1000","sid":"18"},{"uid":"1001","sid":"22"}]\n';
            else if(c.input.startsWith('loginctl show-session -p State')) output='[1,2]\n';
            else throw new Error('Unexpected OS command: '+c.input);
            c.stdout.emit('data',Buffer.from(output));
        };
        return c;
    }
    const context={module,Buffer,process:{platform:options.platform||'linux',env:{}},console:{info1(){}},
        setTimeout(fn){const id=nextTimer++;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},
        require(name){
            if(name==='fs')return mockFs;
            if(name==='child_process')return {execFile:child};
            if(name==='user-sessions')return module.exports;
            if(name==='events')return {EventEmitter:function(){
                EventEmitter.call(this);Object.setPrototypeOf(this,EventEmitter.prototype);
                this.createEvent=function(){return this;};this.addMethod=function(){return this;};return this;
            }};
            throw new Error('Unexpected dependency: '+name);
        }};
    vm.runInNewContext(source,context,{filename:sourcePath});
    return {sessions:module.exports,watches,commands,timers,spawnedChildren,setSession(value){session=value;},flush(){const work=[...timers.values()];timers.clear();work.forEach(fn=>fn());}};
}
test('selects active X11 greeter instead of another logged-in UID',()=>{
    const f=fixture();assert.equal(f.sessions.consoleUid(),111);assert.equal(f.sessions.activeConsoleSession().display,':1');
    assert(!f.commands.some(s=>s.startsWith('loginctl list-sessions')));
});
test('display-manager UID follows validated low and high greeter identities',()=>{
 const f=fixture();assert.equal(f.sessions.gdmUid,111);
 f.setSession(state({User:'60578',Type:'wayland',Display:''}));assert.equal(f.sessions.gdmUid,60578);
 assert(!f.commands.some(x=>x.includes('getent passwd')));
});

test('selects active Wayland user and preserves session identity',()=>{
    const f=fixture();f.setSession(state({Id:'137',User:'1000',Type:'wayland',Class:'user',Display:''}));
    assert.equal(f.sessions.consoleUid(),1000);assert.equal(f.sessions.activeConsoleSession().id,'137');
});
for(const [label,invalid] of Object.entries({remote:{Remote:'yes'},inactive:{Active:'no'},otherSeat:{Seat:'seat1'},invalidUid:{User:'1000bad'},invalidId:{Id:'c2;command'},missingId:{Id:''}})) {
    test('rejects '+label+' active-console response',()=>{const f=fixture();f.setSession(state(invalid));assert.equal(f.sessions.activeConsoleSession(),null);});
}
test('missing loginctl returns no active console',()=>{const f=fixture({loginctl:false});assert.equal(f.sessions.activeConsoleSession(),null);assert.equal(f.commands.length,1);});
test('non-Linux keeps active-console lookup disabled',()=>{const f=fixture({platform:'freebsd'});assert.equal(f.sessions.activeConsoleSession(),null);assert.equal(f.watches.size,0);});
test('active UID array retains the existing caller contract',()=>{const f=fixture();assert.equal(JSON.stringify(f.sessions.consoleUid({active:true})),'[1000,1001]');});
test('missing utmp still watches the local seat',()=>{const f=fixture();assert(!f.watches.has('/var/run/utmp'));assert(f.watches.has('/run/systemd/seats'));});
test('seat notifications debounce and ignore unchanged state and other seats',()=>{
    const f=fixture();let changes=0;f.sessions.on('changed',()=>changes++);const w=f.watches.get('/run/systemd/seats');
    w.emit('change','change','seat1');assert.equal(f.timers.size,0);
    w.emit('change','change','seat0');f.flush();assert.equal(changes,0);
    f.setSession(state({Id:'18',User:'1000',Class:'user',Display:':0'}));
    w.emit('change','change',Buffer.from('seat0'));w.emit('change','rename','seat0');assert.equal(f.timers.size,1);f.flush();assert.equal(changes,1);
    w.emit('change','change','seat0');f.flush();assert.equal(changes,1);
});
test('new session for the same UID causes a fresh notification',()=>{
    const f=fixture();let changes=0;f.sessions.on('changed',()=>changes++);f.setSession(state({Id:'c3'}));
    f.watches.get('/run/systemd/seats').emit('change','change','seat0');f.flush();assert.equal(changes,1);
});
test('transient empty seat does not replace a valid generation',()=>{
    const f=fixture();let changes=0;f.sessions.on('changed',()=>changes++);const w=f.watches.get('/run/systemd/seats');
    f.setSession('');w.emit('change','change','seat0');f.flush();assert.equal(changes,0);
    f.setSession(state({Id:'c3'}));w.emit('change','change',null);f.flush();assert.equal(changes,1);
});
test('legacy utmp notification remains available without loginctl',()=>{
    const f=fixture({loginctl:false,utmp:true,seats:false});let changes=0;f.sessions.on('changed',()=>changes++);
    f.watches.get('/var/run/utmp').emit('change','change','utmp');assert.equal(changes,1);
});
console.log(passed+' console-session regression cases passed.');

for(const method of ['Current','consoleUid']) test(method+' does not abandon an unwritten shell when UID discovery throws',()=>{ const f=fixture(); f.sessions.minUid=()=>{throw new Error('UID discovery interrupted');}; const before=f.spawnedChildren.length; assert.throws(()=>f.sessions[method]({active:true}),/UID discovery interrupted/); assert.equal(f.spawnedChildren.slice(before).filter(c=>c.input==='').length,0); });
