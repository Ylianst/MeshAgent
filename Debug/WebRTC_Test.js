var mesh;
var http = require('http');
var relayId = null;
var req;
var proxy;
var relayHost = null;
var relayPort;
var rtc = require('ILibWebRTC');
var peerConnection;
var signalingChannel;
var dc;

var webServer = null;
var processMgr;
var p;

for (var i = 1; i < process.argv.length; ++i)
{
    if(process.argv[i] == 'relayId')
    {
        relayId = process.argv[i + 1];
        ++i;
    }
    else if (process.argv[i] == 'proxy')
    {
        console.log("Using Proxy: " + process.argv[i + 1] + ":" + parseInt(process.argv[i + 2]));
        proxy = require('global-tunnel');
        try
        {
            proxy.initialize({ host: process.argv[i + 1], port: parseInt(process.argv[i + 2]) });
        }
        catch (e)
        {
            console.log("Unable to bind proxy: " + e);
        }
        i += 2;
    }
    else if(process.argv[i] == 'relay')
    {
        relayHost = process.argv[i + 1];
        relayPort = parseInt(argv[i + 2]);
        i += 2;
    }
    else if(process.argv[i] == 'browser')
    {
        console.log("Local Web Server started on port 8585...");
        webServer = http.createServer(OnLocalWebRequest);
        webServer.listen(8585);
    }
}
try
{
    mesh = require('MeshAgent');
    mesh.AddConnectHandler(OnMeshConnected)
}
catch(e)
{
    mesh = null;
}


if (mesh == null && webServer == null)
{
    console.log("Running as Standalone Mode");
    var options = { host: relayHost, port: relayPort, path: "/meshrelay.ashx?id='" + relayId + "'", protocol: "wss:" };
    req = http.request(options);
    req.upgrade = OnTunnelWebSocket;
}

if (mesh == null && webServer != null)
{
    processMgr = require('ILibProcessPipe');
    p = processMgr.CreateProcess("c:\\windows\\system32\\cmd.exe", "/c", "start", "http://localhost:8585/start.html");
}

function OnLocalWebRequest(request, response)
{
    if(request.method == 'GET' && request.url == '/start.html')
    {
        var fs = require('fs');
        try
        {
            var stream = fs.createReadStream('WebRTC_Test.html');
            response.statusCode = 200;
            response.statusMessage = "OK";
            stream.pipe(response);
        }
        catch(e)
        {
            response.statusCode = 404;
            response.statusMessage = "Not Found";
            response.end();
        }
    }
    else
    {
        response.statusCode = 404;
        response.statusMessage = "Not Found";
        response.end();
    }
}
function OnMeshConnected()
{
    console.log("Mesh Agent Connected: " + mesh.ConnectedServer);
    console.log("Attempting to create WebRTC Control Channel using TunnelID: " + relayId);

    var options = http.parseUri(mesh.ConnectedServer);
    options.path = "/meshrelay.ashx?id='" + relayId + "'";

    req = http.request(options);
    req.upgrade = OnTunnelWebSocket;
}

function OnTunnelWebSocket(response, sckt, head)
{
    console.log("Websocket Connection to RelayServer established");
    signalingChannel = sckt;
    sckt.on('data', OnTunnelData);
    sckt.on('end', function () { console.log("Relay connection closed"); });
}
function OnWebRTC_Connected()
{
    console.log("WebRTC Session Established");
    if(mesh != null)
    {
        // Let create a data channel
        this.dc = this.createDataChannel("remoteDesktop", OnKVMChannel)
        this.tempTimeout = setTimeout(function (dc) { console.log("sending: 'test'"); dc.write("test"); }, 10000, this.dc);
    }
}
function OnKVMChannel()
{
    console.log("Successfully established Data Channel to test Data throughput");
    dc = this;
    dc.kvm = mesh.getRemoteDesktopStream();
    dc.on('data', function (buffer) { console.log("Peer Received: " + buffer.toString() + " bytes"); });
    dc.on('end', function () { this.kvm.end(); console.log("Closing KVM Session"); });
    dc.kvm.pipe(dc);
}
function OnWebRTC_DataChannel(dataChannel)
{
    console.log("Data Channel (" + dataChannel.name + ") was created");
    dc = dataChannel;
    dc.on('data', function (buffer) { console.log("Received: " + buffer.length + " bytes"); dc.write(buffer.length.toString());});
}
function OnTunnelData(buffer)
{
    if (buffer == 'c')
    {
        console.log("Tunnel Established");
        peerConnection = rtc.createConnection();
        peerConnection.on('connected', OnWebRTC_Connected);
        peerConnection.on('dataChannel', OnWebRTC_DataChannel);
        if(mesh!=null)
        {
            console.log("Generating WebRTC Offer...");
            this.write({ cmd: "offer", data: peerConnection.generateOffer() });
        }
    }
    else
    {
        ProcessCommand(JSON.parse(buffer.toString()));
    }
}
function ProcessCommand(cmd)
{
    console.log("Received Command: " + cmd.cmd);
    if(cmd.cmd == 'offer')
    {
        console.log("setting offer...");
        console.log(cmd.data);
        var counter = peerConnection.setOffer(cmd.data);
        if(mesh == null)
        {
            signalingChannel.write({ cmd: "offer", data: counter });
        }
    }
    if(cmd.cmd == 'candidate')
    {
        console.log("Received Candidate: " + cmd.data);
    }
}

