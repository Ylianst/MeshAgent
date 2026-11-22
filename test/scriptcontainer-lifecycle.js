/* Run only as a standalone MeshAgent.exe script, never eval inside a service. */
(function () {
    if (process.platform !== 'win32') {
        console.log('SKIP: Windows ScriptContainer handle lifecycle regression');
        process.exit(0);
    }
    var GM = require('_GenericMarshal');
    var kernel = GM.CreateNativeProxy('kernel32.dll');
    kernel.CreateMethod('GetCurrentProcess');
    kernel.CreateMethod('GetProcessHandleCount');
    var create = require('ScriptContainer').Create;
    var cycles = parseInt(process.env.MESH_LIFECYCLE_CYCLES || '20', 10);
    if (!(cycles >= 2 && cycles <= 100)) throw Error('Invalid cycle count');
    var modes = ['natural-exit', 'exit2-retained-until-exit', 'abandon-live-container-then-gc', 'abandon-during-data-and-gc', 'natural-burst-exit', 'abandon-before-first-data'];
    var state = { pid: process.pid, cycles: cycles, cases: [], group: 0, iteration: 0, owner: null, finished: false };
    var current;
    var caseTimer;
    var deadline = setTimeout(function () { finish('OVERALL_TIMEOUT'); }, 180000);
    function handles() {
        var out = GM.CreateVariable(4);
        if (!kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), out).Val) throw Error('GetProcessHandleCount failed');
        return out.toBuffer().readUInt32LE(0);
    }
    function finish(error) {
        if (state.finished) return;
        state.finished = true;
        clearTimeout(deadline);
        if (caseTimer) clearTimeout(caseTimer);
        if (state.owner) { try { state.owner.exit2(); } catch (ignored) {} state.owner = null; }
        state.error = error || null;
        state.finalHandles = handles();
        state.passed = !error;
        delete state.owner;
        console.log('SCRIPTCONTAINER_LIFECYCLE_RESULT ' + JSON.stringify(state));
        setTimeout(function () { process.exit(error ? 1 : 0); }, 100);
    }
    function record() {
        if (state.finished) return;
        clearTimeout(caseTimer);
        Duktape.gc(); Duktape.gc();
        current.after = handles();
        state.cases.push(current);
        if (current.mode === 'natural-burst-exit' && current.dataEvents !== 65) { finish('LOST_OR_DUPLICATE_DATA'); return; }
        state.iteration++;
        if (state.iteration === cycles) {
            var group = state.cases.slice(state.cases.length - cycles);
            // The first process warms up runtime handle caches. Subsequent cycles
            // must return to the same handle range rather than grow with workload.
            var floor = group[0].after;
            var growth = group[group.length - 1].after - floor;
            if (growth > 2) { finish('CUMULATIVE_HANDLE_GROWTH:' + current.mode + ':' + growth); return; }
            state.group++; state.iteration = 0;
        }
        if (state.group === modes.length) { finish(null); return; }
        setTimeout(start, 10);
    }
    function exit() {
        if (state.finished) return;
        current.exitEvent = true;
        state.owner = null;
        if (current.mode.indexOf('abandon-') !== 0) setTimeout(record, 100);
    }
    function data() {
        if (state.finished) return;
        current.dataEvents++;
        if (current.dataEvents !== 1) return;
        if (current.mode === 'exit2-retained-until-exit') {
            state.owner.exit2();
        } else if (current.mode === 'abandon-live-container-then-gc') {
            state.owner = null;
            setTimeout(function () { Duktape.gc(); Duktape.gc(); setTimeout(record, 180); }, 10);
        } else if (current.mode === 'abandon-during-data-and-gc') {
            state.owner = null;
            Duktape.gc(); Duktape.gc();
            setTimeout(function () { Duktape.gc(); Duktape.gc(); setTimeout(record, 180); }, 10);
        }
    }
    function start() {
        current = { mode: modes[state.group], iteration: state.iteration + 1, before: handles(), dataEvents: 0, exitEvent: false };
        try {
            state.owner = create({ processIsolation: 1 });
            state.owner.on('data', data);
            state.owner.on('exit', exit);
            state.owner.on('error', function () { finish('CONTAINER_ERROR'); });
            var burst = current.mode === 'natural-burst-exit' || current.mode === 'abandon-during-data-and-gc';
            var child = "var s=require('ScriptContainer');s.send('ready');";
            if (burst) child += "for(var i=0;i<64;i++)s.send({index:i,payload:Array(513).join('x')});console.log('lifecycle-stdout');";
            child += "setTimeout(function(){process.exit();}," + (current.mode.indexOf('abandon-') === 0 ? 10000 : 80) + ");";
            state.owner.ExecuteString(child);
            caseTimer = setTimeout(function () { finish('CASE_TIMEOUT:' + current.mode); }, 5000);
            if (current.mode === 'abandon-before-first-data') {
                state.owner = null;
                Duktape.gc(); Duktape.gc();
                setTimeout(record, 180);
            }
        } catch (error) { finish(String(error)); }
    }
    state.baseline = handles();
    start();
})()
