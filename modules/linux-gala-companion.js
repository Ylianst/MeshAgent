/* SPDX-License-Identifier: Apache-2.0 */
// Owned plugin installation only. A user choice is a separate installer call;
// service updates and remote connections never display a logout question.
function identity(service) {
    if (!service || typeof service.name !== 'string' || !service.name.length || service.name.length > 256 ||
        /[\x00\r\n]/.test(service.name) || typeof service.path !== 'string' || service.path.charAt(0) !== '/' ||
        service.path.length > 4096 || /[\x00-\x1f\x7f=]/.test(service.path)) throw Error('Invalid Gala service identity');
    var parts=service.path.split('/'), normalized=[];
    for(var i=0;i<parts.length;++i) {
        if(!parts[i]||parts[i]==='.')continue;
        if(parts[i]==='..'){if(!normalized.length)throw Error('Invalid Gala service path');normalized.pop();}
        else normalized.push(parts[i]);
    }
    if(!normalized.length)throw Error('Invalid Gala executable');
    return require('SHA256Stream').create().syncHash(Buffer.from('MeshAgent Gala service 1\n'+service.name.split(' ').join('_')+'\n/'+normalized.join('/'),'utf8')).toString('hex').toLowerCase();
}
function install(service, previous) {
    if(process.platform!=='linux'||!require('fs').existsSync('/usr/bin/gala'))return {state:'not-applicable'};
    var store=require('_gala-companion-store');if(!store.detect())return {state:'not-applicable'};
    var owner=identity(service),result=store.install(owner);
    if(result.status!==1)return {state:'error',stage:'install',errno:result.errno,changed:result.changed};
    if(previous) {
        var old=identity(previous);
        if(old!==owner){var released=store.release(old);if(released.status!==1)return {state:'error',stage:'transfer',errno:released.errno};}
    }
    return {state:'files-ready',changed:result.changed,activation:store.active()?'active':store.target()?'needs-sign-in':'next-wayland-sign-in'};
}
function uninstall(service) {
    if(process.platform!=='linux'||!require('fs').existsSync('/usr/bin/gala'))return {state:'not-applicable'};
    var store=require('_gala-companion-store');if(!store.detect())return {state:'not-applicable'};
    var r=store.release(identity(service));return {state:r.status===1?(r.changed?'files-removed':'files-retained'):'error',errno:r.errno};
}
function offerSignOut(result) {
    if(!result||result.state!=='files-ready'||result.activation!=='needs-sign-in')return {state:'not-needed'};
    return require('_gala-companion-store').offerSignOut();
}
module.exports={install:install,uninstall:uninstall,offerSignOut:offerSignOut};
