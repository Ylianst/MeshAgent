var proxy;
var i;

var http = require('http');
var net = require('net');
var host = null;
var port = 443;
var id = null;
var req;
var local = 0;

var remoteHost = "";
var remotePort = 0;

process.on("uncaughtException", function (e) { console.log("UncaughtException: " + e); });
process.on("exit", function (code) { console.log("Process Exiting with code: " + code); });

function onWebSocket(response, s, head)
{
    console.log("WebSocket connected");
    s.data = onWebSocketData;
}
function OnNewConnection(connection)
{
    console.log("New Local Connection");
    this.parent.pipe(connection);
    connection.pipe(this.parent);
}

function OnClientConnection()
{
    console.log("New Client Connection Established");
    this.parent.pipe(this);
    this.pipe(this.parent);
}

function onWebSocketData(buffer)
{
    if(buffer == 'c')
    {
        console.log("tunnel established");
        this.pause();

        if (local != 0)
        {
            this.server = net.createServer();
            this.server.parent = this;
            this.server.on('connection', OnNewConnection);
            this.server.listen({ port: local });
        }
        if(remotePort != 0)
        {
            this.client = net.createConnection({ port: remotePort, host: remoteHost }, OnClientConnection);
            this.client.parent = this;
        }
    }
}


for (i = 1; i < process.argv.length; ++i)
{
    if(process.argv[i] == 'local')
    {
        console.log("binding local port " + (local = parseInt(process.argv[i + 1])));
        ++i;
    }
    else if(process.argv[i] == 'remote')
    {
        remoteHost = process.argv[i + 1];
        remotePort = parseInt(process.argv[i + 2])
        console.log("binding remote " + remoteHost + ":" + remotePort);
        i += 2;
    }
    else if(process.argv[i] == 'proxy')
    {
        console.log("Using Proxy: " + process.argv[i + 1] + ":" + parseInt(process.argv[i + 2]));
        proxy = require('global-tunnel');
        try
        {
            proxy.initialize({ host: process.argv[i + 1], port: parseInt(process.argv[i + 2]) });
        }
        catch(e)
        {
            console.log("Unable to bind proxy: " + e);
        }
        i += 2;
    }
    else if(process.argv[i] == 'relayHost')
    {
        host = process.argv[i + 1];
        ++i;
    }
    else if(process.argv[i] == 'relayId')
    {
        id = process.argv[i + 1];
        ++i;
    }
    else if(process.argv[i] == 'relayPort')
    {
        port = parseInt(argv[i + 1]);
        ++i;
    }
}

if (host != null && id != null)
{
    console.log("using relay: [" + host + ":" + port + "] using id: " + id);
    req = http.request({ protocol: "wss:", host: host, port: port, path: "/meshrelay.ashx?id='" + id + "'" });
    req.upgrade = onWebSocket;
}



