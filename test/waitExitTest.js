// waitExit() test. Covers nesting, the timeout that throws, the wait forever escapes, two waits on one child, promise.wait(), process.exit() inside a wait,
// detached child, closed stdio, stopped child, retried wait after process.exit(), wait from an ended wait's last pass,
// socket.close() inside a wait, clearTimeout() inside a nested wait and the depth cap.
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
    hung.waitExit(500);            // Without an argument the 1 minute default applies and throws the same way.
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

// 10) A detached child has no pipes, so its exit only arrives through the SIGCHLD relay. That path never ended the wait, so waitExit()
// ran to its deadline and then read the freed child record. Now it returns as soon as the child is reaped. POSIX only.
if (!win)
{
    var det = cp.execFile('/bin/sh', ['sh', '-c', 'exit 4'], { detached: true, type: cp.SpawnTypes.DETACHED }), detCode = -1, detExits = 0, detErr = null;
    det.on('exit', function (c) { detCode = c; ++detExits; });
    t = Date.now();
    try { det.waitExit(3000); } catch (e) { detErr = '' + e; }
    var detOK = detErr == null && detExits == 1 && detCode == 4 && Date.now() - t < 2000;
    ok(detOK, 'detached child: waitExit() ended by the SIGCHLD relay' + (detOK ? '' : (' (err=' + detErr + ', exits=' + detExits + ', code=' + detCode + ', took ' + (Date.now() - t) + ' ms)')));
}

// 11) A child that closes its own stdout and stderr and keeps running. The pipe reap used to block the whole event loop in waitpid()
// until the child exited, so a timer armed inside the wait could only fire afterwards. Now the reap polls. POSIX only.
if (!win)
{
    var quiet = sh('exec >/dev/null 2>&1; sleep 0.6'), quietCode = -1, quietExits = 0, tickAt = -1, quietErr = null;
    quiet.on('exit', function (c) { quietCode = c; ++quietExits; });
    t = Date.now();
    var t4 = setTimeout(function () { tickAt = Date.now() - t; }, 150);
    try { quiet.waitExit(3000); } catch (e) { quietErr = '' + e; }
    var quietOK = quietErr == null && quietExits == 1 && quietCode == 0 && Date.now() - t >= 500 && tickAt >= 0 && tickAt < 450;
    ok(quietOK, 'child with closed stdio: loop stayed live and exit still arrived' + (quietOK ? '' : (' (err=' + quietErr + ', exits=' + quietExits + ', code=' + quietCode + ', timer at ' + tickAt + ' ms, took ' + (Date.now() - t) + ' ms)')));
}

// 12) A stopped child raises SIGCHLD too. The relay used to publish that as an exit with code 0, which ended the wait and closed the pipes
// of a live child. Now only a real reap is published, so the wait lasts until the continued child really exits. POSIX only.
if (!win)
{
    var stopped = slp(1), stopCode = -1, stopExits = 0, stopErr = null;
    stopped.on('exit', function (c) { stopCode = c; ++stopExits; });
    t = Date.now();
    sh('kill -STOP ' + stopped.pid).waitExit(3000);
    var t5 = setTimeout(function () { sh('kill -CONT ' + stopped.pid).waitExit(3000); }, 300);
    try { stopped.waitExit(4000); } catch (e) { stopErr = '' + e; }
    var stopOK = stopErr == null && stopExits == 1 && stopCode == 0 && Date.now() - t >= 900;
    ok(stopOK, 'stopped then continued child: a stop did not count as an exit' + (stopOK ? '' : (' (err=' + stopErr + ', exits=' + stopExits + ', code=' + stopCode + ', took ' + (Date.now() - t) + ' ms)')));
}

// 13) process.exit() inside a wait, and the script catches the abort and waits again. The chain refuses every wait after the abort at once,
// so the retry throws without running a loop pass and the process still ends with the requested code.
var stickyScript = [
    "var cp = require('child_process'), win = process.platform == 'win32';",
    "function slp() { return (win ? cp.execFile(process.env['windir'] + '\\\\System32\\\\cmd.exe', ['cmd.exe', '/c', 'ping -n 4 127.0.0.1 > nul']) : cp.execFile('/bin/sh', ['sh', '-c', 'sleep 3'])); }",
    "var a = slp();",
    "var k = setTimeout(function () { process.exit(3); }, 100);",
    "try { a.waitExit(); console.log('FIRST_RETURNED'); }",
    "catch (e) { var b = slp(); var t = Date.now(); try { b.waitExit(); console.log('SECOND_RETURNED'); } catch (e2) { console.log('SECOND_REFUSED after ' + (Date.now() - t) + 'ms: ' + e2); } }"
].join('\n');
var st = cp.execFile(process.execPath, ['meshagent', '-b64exec', Buffer.from(stickyScript).toString('base64')]), stOut = '', stCode = -1;
st.stdout.on('data', function (d) { stOut += d.toString(); });
st.stderr.on('data', function (d) { stOut += d.toString(); });
st.on('exit', function (c) { stCode = c; });
t = Date.now();
try { st.waitExit(20000); } catch (e) { stOut += ' [' + e + ']'; st.kill(); }
var stOK = stCode == 3 && stOut.indexOf('SECOND_REFUSED') >= 0 && stOut.indexOf('RETURNED') < 0 && Date.now() - t < 2500;
ok(stOK, 'process.exit(3) with a retried wait: retry refused at once, child agent ended with code 3' + (stOK ? '' : (' (code=' + stCode + ', took ' + (Date.now() - t) + ' ms, output: ' + stOut.replace(/\s+/g, ' ').substring(0, 300) + ')')));

// 14) A wait started from a handler that runs after its enclosing wait has already ended is refused, because the enclosing wait cannot
// return until the new one ends. Whether the second child's 'exit' runs inside the first wait's last pass or in the main loop depends on
// timing, so both outcomes pass. Only a hang or another error is a failure.
var fa = sh('exit 0'), fb = sh('exit 0'), lateErr = null, lateOK = false, lateRan = false;
fb.on('exit', function () { lateRan = true; var fc = sh('exit 0'); try { fc.waitExit(2000); lateOK = true; } catch (e) { lateErr = '' + e; } });
fa.waitExit(2000);
if (!lateRan) { fb.waitExit(2000); }
ok(lateRan && (lateOK || (lateErr != null && lateErr.indexOf('enclosing wait') >= 0)), "wait from another child's exit handler: " + (lateOK ? 'ran in a later pass, allowed' : ('ran in the ended wait\'s last pass, refused (err=' + lateErr + ')')));

// 15) socket.close() then waitExit() inside a dgram 'message' handler. close() removes the socket's chain link through the base timer, which
// the nested wait runs, so the link's list node was freed while the enclosing loop was parked on it. The removal is now deferred.
var dg = require('dgram').createSocket({ type: 'udp4' }), dgOK = false, dgErr = null, dgGot = false;
dg.bind({ port: 0, address: '127.0.0.1', exclusive: true });
var pdg = new promise(function (res)
{
    dg.on('message', function () { dgGot = true; dg.close(); var c = sh('exit 0'); var cc = -1; c.on('exit', function (x) { cc = x; }); try { c.waitExit(2000); dgOK = cc == 0; } catch (e) { dgErr = '' + e; } res(); });
});
dg.send(Buffer.from('x'), dg.address().port, '127.0.0.1');
try { promise.wait(pdg, 3000); } catch (e) { dgErr = '' + e; }
var afterDg = sh('exit 0'), afterCode = -1; afterDg.on('exit', function (x) { afterCode = x; }); afterDg.waitExit(2000);
var dgAll = dgGot && dgOK && dgErr == null && afterCode == 0;
ok(dgAll, 'socket.close() then waitExit() inside a dgram message handler' + (dgAll ? '' : (' (got=' + dgGot + ', ok=' + dgOK + ', err=' + dgErr + ', later wait code=' + afterCode + ')')));

// 16) clearTimeout() inside a nested wait, of a timer already due in the same timer pass as the caller. The due timers of the outer pass
// used to be invisible to clearTimeout() while a nested wait ran, so the cleared timer fired anyway on freed memory. Now every pass is searched.
var tbFired = false, tbCleared = false, tbFiredAfterClear = false, tb = null;
var ta = setTimeout(function () { var c = slp(1); c.waitExit(3000); clearTimeout(tb); tbCleared = true; }, 0);
tb = setTimeout(function () { tbFired = true; if (tbCleared) { tbFiredAfterClear = true; } }, 0);
var t6 = null;
try { promise.wait(new promise(function (res) { t6 = setTimeout(res, 1500); }), 5000); } catch (e) { }
ok(tbCleared && !tbFiredAfterClear, 'clearTimeout() inside a nested wait cancelled a timer of the outer pass' + ((tbCleared && !tbFiredAfterClear) ? '' : (' (cleared=' + tbCleared + ', fired=' + tbFired + ', fired after clear=' + tbFiredAfterClear + ')')));

// 17) Nest 16 deep. The 17th nested wait must throw and the loop must survive.
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
