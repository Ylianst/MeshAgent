// Run with a built Windows MeshAgent: MeshAgent.exe windows-process-environment-tests.js
// These exercise the native child-process environment builder and real DLL activation.
var cp = require('child_process');
var path = process.execPath;
var expectedRoot = process.env.SystemRoot || process.env.SYSTEMROOT;
var sentinel = 'mesh-environment-test-parent-only';
var gm = require('_GenericMarshal');
var envKernel = gm.CreateNativeProxy('kernel32.dll');
envKernel.CreateMethod('SetEnvironmentVariableA');
if (envKernel.SetEnvironmentVariableA(gm.CreateVariable('MESH_ENV_PARENT_ONLY'), gm.CreateVariable(sentinel)).Val === 0) { throw 'Unable to set test sentinel'; }
var cases = [
    { name: 'isolated', env: { Z_TEST: 'last', A_TEST: 'first', UNICODE_TEST: 'caf\u00e9 \u03a9 \u6f22\u5b57' } },
    { name: 'empty-value', env: { EMPTY_TEST: '' } },
    { name: 'empty-object-inherits', env: {}, inherits: true },
    { name: 'explicit-case', env: { sYsTeMrOoT: expectedRoot, Z_TEST: 'last', A_TEST: 'first' } },
    { name: 'inherited' }
];
for (var i = 0; i < 8; ++i) { cases.push({ name: 'repeat-' + i, env: { TEST_REPEAT: '' + i } }); }
var index = 0;
function fail(message) { console.log('FAIL: ' + message); process.exit(1); }
function next() {
    if (index === cases.length) { console.log('PASS: ' + cases.length + ' native Windows child-environment cases'); process.exit(0); return; }
    var item = cases[index++];
    // The existing JS adapter treats an empty object as unspecified/inherited.
    var config = { root: expectedRoot, inherited: !item.env || item.inherits === true, unicode: item.env && item.env.UNICODE_TEST, sentinel: sentinel };
    var body = "var c=" + JSON.stringify(config) + ";var rootCount=0,rootValue;for(var envKey in process.env){if(envKey.toLowerCase()==='systemroot'){++rootCount;rootValue=process.env[envKey];}}if(rootCount!==1||rootValue.toLowerCase()!==c.root.toLowerCase()){throw 'SystemRoot missing, duplicated or replaced';}if(c.inherited){if(process.env.MESH_ENV_PARENT_ONLY!==c.sentinel){throw 'inheritance lost';}}else if(process.env.MESH_ENV_PARENT_ONLY!=null||process.env.PATH!=null||process.env.Path!=null){throw 'parent environment leaked';}var gm=require('_GenericMarshal');if(c.unicode){var k=gm.CreateNativeProxy('kernel32.dll');k.CreateMethod('GetEnvironmentVariableW');var uv=gm.CreateVariable(256);k.GetEnvironmentVariableW(gm.CreateVariable('UNICODE_TEST',{wide:true}),uv,128);for(var ui=0;ui<c.unicode.length;++ui){if(uv.toBuffer().readUInt16LE(ui*2)!==c.unicode.charCodeAt(ui)){throw 'Unicode value changed';}}if(uv.toBuffer().readUInt16LE(c.unicode.length*2)!==0){throw 'Unicode value unterminated';}}var u=gm.CreateNativeProxy('user32.dll');u.CreateMethod('GetLastInputInfo');var v=gm.CreateVariable(8);v.toBuffer().writeUInt32LE(8,0);if(u.GetLastInputInfo(v).Val===0){throw 'user32 call failed';}console.log('CHILD_ENV_OK');";
    body = "try{" + body + "}catch(e){console.log('CHILD_ENV_FAILURE:'+e);process.exit(1);}process.exit(0);";
    var options = {};
    if (item.env) { options.env = item.env; }
    var child = cp.execFile(path, [path.split('\\').pop(), '-b64exec', Buffer.from(body).toString('base64')], options);
    var output = '';
    child.stdout.on('data', function(data) { output += data.toString(); });
    child.stderr.on('data', function() {});
    var deadline = setTimeout(function() { child.kill(); fail(item.name + ' exceeded startup deadline'); }, 10000);
    child.on('exit', function(code) {
        clearTimeout(deadline);
        if (code !== 0 || output.indexOf('CHILD_ENV_OK') < 0) { fail(item.name + ' child failed: ' + code + ' ' + output.trim()); return; }
        console.log('PASS: ' + item.name);
        next();
    });
}
next();
