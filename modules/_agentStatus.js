
var promise = require('promise');
var nodeid = require('_agentNodeId')();
var ipcPath = process.platform == 'win32' ? ('\\\\.\\pipe\\' + nodeid + '-DAIPC') : (process.cwd() + '/DAIPC');

function dataHandler(chunk)
{
    var len;
    if (chunk.length < 4) { this.unshift(chunk); return; }
    if ((len = chunk.readUInt32LE(0)) > chunk.length) { this.unshift(chunk); return; }

    var data = chunk.slice(4, len + 4);
    var payload = null;
    try
    {
        payload = JSON.parse(data.toString());
    }
    catch (e)
    {
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
function queryAgent(obj, prev)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret._obj = { cmd: 'query', value: obj };
    console.log(obj, prev);
    if (prev == null)
    {
        ret.client = require('net').createConnection({ path: ipcPath });
        ret.client.on('connect', function ()
        {
            console.log('ON CONNECT');
            this.on('data', dataHandler);
            this.on('end', function ()
            {
                this.promise._rej('closed');
            });

            var j = Buffer.from(JSON.stringify(ret._obj));
            var buf = Buffer.alloc(4 + j.length);
            buf.writeUInt32LE(j.length + 4, 0);
            j.copy(buf, 4);
            this.write(buf);
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
    }).then(console.log).then(function () { process._exit(); }).catch(function () { process._exit(); });
}

module.exports = { start: start };