// waitExit() test. Covers nesting, the timeout that throws, the wait forever escapes, two waits on one child, promise.wait(), process.exit() inside a wait and the depth cap.
// Works on Windows, Linux, BSD and macOS.
var cp = require('child_process');
var win = process.platform == 'win32';
var pass = 0, fail = 0;
function ok(cond, name) { console.log((cond ? 'PASS ' : 'FAIL ') + name); if (cond) { ++pass; } else { ++fail; } }
function sh(c) { return (win ? cp.execFile(process.env['windir'] + '\\System32\\cmd.exe', ['cmd.exe', '/c', c]) : cp.execFile('/bin/sh', ['sh', '-c', c])); }
function slp(s) { return (sh(win ? ('ping -n ' + (s + 1) + ' 127.0.0.1 > nul') : ('sleep ' + s))); }
// Debug builds expose child_process._stackRemaining(). The stack lines are information only, pass and fail never depend on them.
var stackLeft = cp._stackRemaining, stackPrev = -1;
function kb(n) { return (Math.round(n / 1024) + ' KB'); }
if (stackLeft) { var s0 = stackLeft(); console.log(s0 < 0 ? 'stack: bound not available, depth cap only' : ('stack: ' + kb(s0) + ' free at start')); }

// 1) Nested waitExit. A timer fires inside the outer wait and waits on a second child there.
var nestOK = false, code = -1, nestErr = null, innerExits = 0, timerAt = -1, innerPid = -1, t0 = Date.now();
var outer = slp(3);
// t1 keeps the timer object referenced. The timer finalizer cancels a timer that gets garbage collected, so an unreferenced timer may never fire.
var t1 = setTimeout(function ()
{
    timerAt = Date.now() - t0;
    var inner = sh('exit 5');
    innerPid = inner.pid;
    inner.on('exit', function (c) { code = c; ++innerExits; });
    try { inner.waitExit(); nestOK = true; } catch (e) { nestErr = '' + e; }
}, 400);
outer.waitExit();
var nest1 = nestOK && code == 5, innerState = '';
// A child still listed as a zombie means nothing ever reaped it, so its 'exit' came from a SIGCHLD relay that ran before the child was reapable.
// Gone means it was reaped, so a wrong code came from the pipe close path's waitpid() failing, for example with EINTR.
if (!nest1 && !win) { var ps = sh('ps -o stat= -p ' + innerPid); ps.stdout.on('data', function (d) { innerState += d.toString(); }); try { ps.waitExit(); } catch (e) { } }
// On failure print everything that tells the possible causes apart: the timer not firing, the nested wait throwing, a wrong exit code, or 'exit' firing twice.
ok(nest1, 'nested waitExit inside outer waitExit' + (nest1 ? '' : (' (timer at ' + timerAt + ' ms, inner pid ' + innerPid + ', waitExit ok=' + nestOK + ', code=' + code +
    ', exit events=' + innerExits + ', error=' + nestErr + ', outer returned after ' + (Date.now() - t0) + ' ms, inner process now: ' + (innerState.trim() || 'gone') + ')')));

// 2) The timeout throws, and the catcher decides what to do. This one kills the child, it could also retry or wait longer.
var hung = slp(30);
var threw = false, t = Date.now();
try
{
    hung.waitExit(500);            // Without an argument the 2 minute default applies and throws the same way.
}
catch (e)
{
    threw = true;                  // e is "waitExit() timed out after 500ms, child (pid=N) still running"
    hung.kill();
}
ok(threw && Date.now() - t >= 400 && Date.now() - t < 1500, 'waitExit(500) threw on timeout after about 500 ms: catcher killed child');

// 3) The timed out child above exits later, from the kill. Its exit must not disturb a later wait.
var later = slp(2);
t = Date.now();
later.waitExit();
ok(Date.now() - t > 1500, 'later waitExit unaffected by timed-out wait');

// 4) waitExit(-1) never times out.
var c2 = slp(2);
t = Date.now();
c2.waitExit(-1);
ok(Date.now() - t > 1500, 'waitExit(-1) waited for full child duration');

// 5) waitExit(0) is the same escape. It used to spin at 100% CPU, because the select() timeout became 0.
var c0 = slp(1);
t = Date.now();
c0.waitExit(0);
ok(Date.now() - t > 800, 'waitExit(0) waited for full child duration');

// 6) waitExit() on a child that already exited returns at once.
t = Date.now();
c2.waitExit();
ok(Date.now() - t < 500, 're-waitExit on exited child is instant');

// 7) Two waits pending on the same child. A timer inside the outer wait calls waitExit() on that same child.
// The one exit must end both. Before the fix the outer wait sat out its full default timeout.
var twice = slp(2), innerDone = false;
t = Date.now();
var t2 = setTimeout(function () { try { twice.waitExit(); innerDone = true; } catch (e) { } }, 300);
twice.waitExit();
ok(innerDone && Date.now() - t > 1500 && Date.now() - t < 5000, 'outer and inner waitExit on one child both ended by its exit');

// 8) promise.wait() uses the same wait entries. A promise settled inside an outer waitExit() ends only its own wait.
var promise = require('promise');
var pw = slp(2), pv = 0;
var t3 = setTimeout(function () { pv = promise.wait(new promise(function (res, rej) { setTimeout(function () { res(7); }, 200); })); }, 300);
pw.waitExit();
ok(pv == 7, 'promise.wait() nested inside waitExit()');

// 9) process.exit() inside a wait. A child agent calls process.exit(3) from a timer two waits deep.
// Every wait must throw and unwind before the script engine is destroyed, so the child ends with code 3 and does not crash.
var exitScript = [
    "var cp = require('child_process'), win = process.platform == 'win32';",
    "function slp() { return (win ? cp.execFile(process.env['windir'] + '\\\\System32\\\\cmd.exe', ['cmd.exe', '/c', 'ping -n 3 127.0.0.1 > nul']) : cp.execFile('/bin/sh', ['sh', '-c', 'sleep 2'])); }",
    "var a = slp();",
    "var k1 = setTimeout(function () { var b = slp(); var k2 = setTimeout(function () { console.log('EXIT_CALLED'); process.exit(3); }, 100); b.waitExit(); console.log('INNER_RETURNED'); }, 100);",
    "a.waitExit();",
    "console.log('OUTER_RETURNED');"
].join('\n');
var ex = cp.execFile(process.execPath, ['meshagent', '-b64exec', Buffer.from(exitScript).toString('base64')]), exOut = '', exCode = -1;
ex.stdout.on('data', function (d) { exOut += d.toString(); });
ex.stderr.on('data', function (d) { exOut += d.toString(); });
ex.on('exit', function (c) { exCode = c; });
try { ex.waitExit(20000); } catch (e) { exOut += ' [' + e + ']'; ex.kill(); }
var exOK = exCode == 3 && exOut.indexOf('EXIT_CALLED') >= 0 && exOut.indexOf('RETURNED') < 0;
ok(exOK, 'process.exit(3) two waits deep ended the child agent with code 3' + (exOK ? '' : (' (code=' + exCode + ', output: ' + exOut.replace(/\s+/g, ' ').substring(0, 300) + ')')));

// 10) Nest 16 deep. The 17th nested wait must throw and the loop must survive.
// refs keeps every timer object referenced, same reason as t1 above: a garbage collected timer is cancelled by its finalizer.
var refs = [], depth = 0, maxD = 0, capHit = 0, okWaits = 0, launched = 0;
function nest()
{
    ++depth; if (depth > maxD) { maxD = depth; }
    if (stackLeft) { var sl = stackLeft(); if (sl >= 0) { console.log('depth ' + depth + ': ' + kb(sl) + ' free' + (stackPrev >= 0 ? (' (' + kb(stackPrev - sl) + ' per level)') : '')); stackPrev = sl; } }
    var c = slp(3);
    if (++launched < 17) { refs.push(setTimeout(nest, 30)); }
    try { c.waitExit(); ++okWaits; }
    catch (e) { if (('' + e).indexOf('nesting depth') >= 0) { ++capHit; } c.kill(); }
    --depth;
    if (depth == 0)
    {
        ok(maxD == 17 && okWaits == 16 && capHit == 1, 'depth cap: 16 nested OK, 17th threw');
        var last = sh('exit 0');
        last.waitExit();
        ok(true, 'loop healthy after full unwind');
        console.log(fail == 0 ? ('ALL ' + pass + ' TESTS PASSED') : (fail + ' TEST(S) FAILED'));
        process.exit(fail == 0 ? 0 : 1);
    }
}
nest();
