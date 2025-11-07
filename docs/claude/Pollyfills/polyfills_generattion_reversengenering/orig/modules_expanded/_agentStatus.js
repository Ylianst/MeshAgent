// Module: _agentStatus
// Timestamp: 2025-11-04T19:56:07.000-07:00
// Original compressed size: 1416 bytes
// Decompressed size: 4613 bytes
// Compression ratio: 69.3%


var promise = require('promise');
var nodeid = require('_agentNodeId')();
var ipcPath = process.platform == 'win32' ? ('\\\\.\\pipe\\' + nodeid + '-DAIPC') : (process.cwd() + '/DAIPC');

function dataHandler(chunk)
{
    var len;
    console.log('DEBUG [_agentStatus.js:8] dataHandler called, chunk.length=' + chunk.length);

    if (chunk.length < 4) {
        console.log('DEBUG [_agentStatus.js:11] Chunk too small (<4 bytes), unshifting');
        this.unshift(chunk);
        return;
    }

    len = chunk.readUInt32LE(0);
    console.log('DEBUG [_agentStatus.js:17] Read length prefix: len=' + len + ', chunk.length=' + chunk.length);

    if (len > chunk.length) {
        console.log('DEBUG [_agentStatus.js:20] Length mismatch, unshifting');
        this.unshift(chunk);
        return;
    }

    var data = chunk.slice(4, len + 4);
    console.log('DEBUG [_agentStatus.js:26] Extracted data: [' + data.toString().substring(0, 200) + ']');

    var payload = null;
    try
    {
        payload = JSON.parse(data.toString());
        console.log('DEBUG [_agentStatus.js:32] JSON.parse succeeded');
    }
    catch (e)
    {
        console.log('DEBUG [_agentStatus.js:36] JSON.parse FAILED: ' + e.message);
        console.log('DEBUG [_agentStatus.js:37] Failed data (hex): ' + data.toString('hex').substring(0, 100));
        console.log('DEBUG [_agentStatus.js:38] Failed data (string): [' + data.toString() + ']');
        this.promise._rej('Invalid Response Received');
        return;
    }
    try
    {
        //this.promise._res(payload.result?payload.result:'');
        this.promise._res(payload.result, this);
    }
    catch (x)
    {
    }
    if ((len + 4) < chunk.length) { this.unshift(chunk.slice(4 + len)); }
}
function queryAgent(obj, prev, path)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret._obj = { cmd: 'query', value: obj };
    if (prev == null)
    {
        console.log('DEBUG [_agentStatus.js:57] Creating new connection to: ' + (path == null ? ipcPath : path));
        ret.client = require('net').createConnection({ path: path == null ? ipcPath : path });
        ret.client.on('connect', function ()
        {
            console.log('DEBUG [_agentStatus.js:60] Connected to IPC socket');
            this.on('data', dataHandler);
            this.on('end', function ()
            {
                console.log('DEBUG [_agentStatus.js:64] Connection closed');
                this.promise._rej('closed');
            });

            var j = Buffer.from(JSON.stringify(ret._obj));
            var buf = Buffer.alloc(4 + j.length);
            buf.writeUInt32LE(j.length + 4, 0);
            j.copy(buf, 4);
            console.log('DEBUG [_agentStatus.js:72] Sending query: ' + JSON.stringify(ret._obj));
            this.write(buf);
        });
        ret.client.on('error', function(err) {
            console.log('DEBUG [_agentStatus.js:76] Connection error: ' + err.message);
        });
    }
    else
    {
        ret.client = prev;
        ret.client.removeAllListeners('data');
        ret.client.removeAllListeners('end');
        ret.client.on('data', dataHandler);
        ret.client.on('end', function ()
        {
            this.promise._rej('closed');
        });

        var j = Buffer.from(JSON.stringify(ret._obj));
        var buf = Buffer.alloc(4 + j.length);
        buf.writeUInt32LE(j.length + 4, 0);
        j.copy(buf, 4);
        ret.client.write(buf);
    }
    ret.client.promise = ret;
    return (ret);
}

function start()
{
    console.log('DEBUG [_agentStatus.js:76] start() called - attempting to query existing agent');
    console.log('DEBUG [_agentStatus.js:77] IPC path: ' + ipcPath);
    console.log('DEBUG [_agentStatus.js:78] Stack trace:');
    try { throw new Error('trace'); } catch(e) { console.log(e.stack); }

    console.log('Querying Mesh Agent state...');
    global._statustm = setTimeout(function ()
    {
        console.log('Unable to contact Mesh Agent...');
        process._exit();
    }, 3000);

    queryAgent('connection').then(function (res, connection)
    {
        if (res == null) { res = '[NOT CONNECTED]'; }
        console.log('Mesh Agent connected to: ' + res);
        return (queryAgent('descriptors', connection));
    }).then(function (v, connection)
    {
        console.log(v);
        console.log('');
        return (queryAgent('timerinfo', connection));
    }).then(function (v) { console.log(v); }).then(function () { process._exit(); }).catch(function () { process._exit(); });
}

module.exports = { start: start, query: queryAgent };