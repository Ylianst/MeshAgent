// Default timeout test for waitExit() and promise.wait(). Covers the 60 s default, an explicit timeout that throws, 0 and -1 waiting forever, the wait flag being cleared after a timeout, and the flag being kept when waitExit() is called on a child whose wait is already in progress.
// The deadline in ILibChain_Continue() is still whole seconds on this branch, so every explicit timeout may run up to a second long and the bounds allow for that.
// Run it as: meshagent test/waitTimeoutTest.js [quick] (on Windows pass an absolute path). 'quick' skips the three checks that wait out the full 60 s default. The exit code is 0 when every check passed.
var cp = require('child_process');
var promise = require('promise');
var win = process.platform == 'win32';
var quick = (process.argv || []).join(' ').indexOf('quick') >= 0;
var pass = 0, fail = 0;
function ok(cond, name) { console.log((cond ? 'PASS ' : 'FAIL ') + name); if (cond) { ++pass; } else { ++fail; } }
function skip(name) { console.log('SKIP ' + name); }
function slp(s) { return (win ? cp.execFile(process.env['windir'] + '\\System32\\cmd.exe', ['cmd.exe', '/c', 'ping -n ' + (s + 1) + ' 127.0.0.1 > nul']) : cp.execFile('/bin/sh', ['sh', '-c', 'exec sleep ' + s])); }
// Kills a child that is still running and collects its exit, so a later check never sees a stale exit.
function reap(c) { try { c.kill(); } catch (e) { } try { c.waitExit(3000); } catch (e) { } }
function timed(f) { var t = Date.now(), e = null; try { f(); } catch (x) { e = x; } return ({ ms: Date.now() - t, err: e }); }
// The native errors are thrown as plain strings, while a rejection is whatever the promise rejected with, so match on either.
function text(e) { return (e == null ? "" : String(e.message ? e.message : e)); }
function msg(e) { return (e == null ? "no error" : ("\"" + text(e) + "\"")); }

// 1) waitExit(500) on a child that runs for 30 s throws, and the child is still running afterwards.
var c1 = slp(30), r = timed(function () { c1.waitExit(500); });
ok(r.err != null && text(r.err).indexOf('timed out after 500 ms') >= 0 && r.ms < 1500, 'waitExit(500) threw after about 500 ms (' + msg(r.err) + ' after ' + r.ms + ' ms)');

// 2) The wait flag was cleared by that timeout, so c1 exiting later must not end an unrelated wait.
// c1 is killed here and its exit arrives during the promise wait, which proves it was still running after the timeout. With the flag still set, that exit would have ended the wait at once.
// The unrelated wait is a promise.wait() and not a waitExit(), because on Windows waitExit() only waits on its own child's handles and would never see c1 exit.
function later(v, ms) { return (new promise(function (res, rej) { setTimeout(function () { res(v); }, ms); })); }
var exited1 = false; c1.on('exit', function () { exited1 = true; });
try { c1.kill(); } catch (e) { }
r = timed(function () { promise.wait(later('three', 3000), 0); });
ok(exited1, 'the timed-out child was still running and exited during the next wait');
ok(r.err == null && r.ms >= 2500, 'a 3 s promise.wait(p, 0) was not ended by that exit (waited ' + r.ms + ' ms)');

// 3) waitExit(-1) waits for the child as well.
var c3 = slp(2);
r = timed(function () { c3.waitExit(-1); });
ok(r.err == null && r.ms >= 1800, 'waitExit(-1) waited for a 2 s child (waited ' + r.ms + ' ms)');

// 4) waitExit() called on a child whose wait is already in progress throws, and the outer wait still ends when the child exits.
// The inner call runs from a timer, which fires inside the outer wait. It must not clear the outer wait's flag, or the outer wait sits out the whole default timeout.
var c4 = slp(2), inner = null;
var h4 = setTimeout(function () { try { c4.waitExit(100); } catch (e) { inner = e; } }, 300);
r = timed(function () { c4.waitExit(); });
ok(inner != null && text(inner).indexOf('already in progress') >= 0, 'a nested waitExit() on the same child threw (' + msg(inner) + ')');
ok(r.err == null && r.ms >= 1800 && r.ms < 5000, 'the outer waitExit() still ended when the child exited (waited ' + r.ms + ' ms)');

// 5) promise.wait(500) on a promise that never settles throws after about 500 ms.
var never = new promise(function (res, rej) { });
r = timed(function () { promise.wait(never, 500); });
ok(r.err != null && text(r.err).indexOf('wait() timeout') >= 0 && r.ms < 1500, 'promise.wait(p, 500) threw after about 500 ms (' + msg(r.err) + ' after ' + r.ms + ' ms)');

// 6) and 7) promise.wait(p, 0) and promise.wait(p, -1) wait for the promise and return its value.
var v = null;
r = timed(function () { v = promise.wait(later('zero', 1500), 0); });
ok(r.err == null && v == 'zero' && r.ms >= 1300, 'promise.wait(p, 0) waited 1.5 s for the value (got ' + v + ' after ' + r.ms + ' ms)');
r = timed(function () { v = promise.wait(later('minus', 1500), -1); });
ok(r.err == null && v == 'minus' && r.ms >= 1300, 'promise.wait(p, -1) waited 1.5 s for the value (got ' + v + ' after ' + r.ms + ' ms)');

// 8) A rejection still comes back as a throw of the rejected value.
var rejected = new promise(function (res, rej) { setTimeout(function () { rej(new Error('nope')); }, 100); });
r = timed(function () { promise.wait(rejected); });
ok(r.err != null && String(r.err.message) == 'nope', 'promise.wait() on a rejected promise threw the rejection (' + msg(r.err) + ')');

// 9) to 11) The 60 s defaults. Each one really waits a minute, so 'quick' skips them.
// The bounds allow up to two extra seconds because the deadline is whole seconds on this branch.
if (quick)
{
    skip('waitExit() with no argument throws after the 60 s default');
    skip('promise.wait(p) with no timeout throws after the 60 s default');
    skip('waitExit() on a child that already exited returns after the 60 s default');
}
else
{
    var c9 = slp(90);
    r = timed(function () { c9.waitExit(); });
    ok(r.err != null && text(r.err).indexOf('timed out after 60000 ms') >= 0 && r.ms >= 59000 && r.ms < 65000, 'waitExit() with no argument threw after the 60 s default (' + msg(r.err) + ' after ' + r.ms + ' ms)');
    reap(c9);

    r = timed(function () { promise.wait(never); });
    ok(r.err != null && text(r.err).indexOf('wait() timeout') >= 0 && r.ms >= 59000 && r.ms < 65000, 'promise.wait(p) with no timeout threw after the 60 s default (' + msg(r.err) + ' after ' + r.ms + ' ms)');

    // No exit event can come for a child that has already exited, so this wait can only end by timeout. It returns without an error because the child is gone.
    // Not run on Windows: waitExit() there reads the native process object for its wait handles, and that object is already freed when the child has exited.
    if (win)
    {
        skip('waitExit() on a child that already exited returns after the 60 s default');
    }
    else
    {
        var c11 = slp(1);
        c11.waitExit();
        r = timed(function () { c11.waitExit(); });
        ok(r.err == null && r.ms >= 59000 && r.ms < 65000, 'waitExit() on a child that already exited returned without error after the 60 s default (waited ' + r.ms + ' ms)');
    }
}

console.log(fail == 0 ? ('ALL ' + pass + ' TESTS PASSED') : (fail + ' TEST(S) FAILED'));
process.exit(fail == 0 ? 0 : 1);
