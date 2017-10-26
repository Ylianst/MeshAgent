
var http = require('http');
var rtc = require('ILibWebRTC');
var peerConnection;
var signalingChannel;
var dc;

var webServer = http.createServer(OnLocalWebRequest);
var processMgr = require('ILibProcessPipe');
var p;

webServer.on('upgrade', OnUpgrade);
webServer.listen(8585);
//p = processMgr.CreateProcess("c:\\windows\\system32\\cmd.exe", "/c", "start", "http://localhost:8585/start.html");

function OnUpgrade(imsg, sck, head)
{
    console.log("WebSocket Connected");
    signalingChannel = sck.upgradeWebSocket();
    signalingChannel.on('data', OnSignalData);

    peerConnection = rtc.createConnection();
    peerConnection.on('connected', OnWebRTC_Connected);
    peerConnection.on('dataChannel', OnWebRTC_DataChannel);

    //console.log("Generating WebRTC Offer...");
    //signalingChannel.write({ cmd: "offer", data: peerConnection.generateOffer() });
}

function OnSignalData(chunk)
{
    var j = JSON.parse(chunk);
    if (j.cmd == 'offer')
    {
        console.log("Received Offer");
        signalingChannel.write({ cmd: "offer", data: peerConnection.setOffer(j.data) });
    }
}
function OnLocalWebRequest(request, response)
{
    if(request.method == 'GET' && request.url == '/start.html')
    {
        var fs = require('fs');
        try
        {
            var stream = fs.createReadStream('WebRTC_Test2.html');
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

function OnWebRTC_Connected()
{
    console.log("WebRTC Session Established");
    //this.dc = this.createDataChannel("testChannel", OnTestChannel);
    //if(mesh != null)
    //{
    //    // Let create a data channel
    //    this.dc = this.createDataChannel("remoteDesktop", OnKVMChannel)
    //    this.tempTimeout = setTimeout(function (dc) { console.log("sending: 'test'"); dc.write("test"); }, 10000, this.dc);
    //}
}
function OnTestChannel()
{
    console.log("Successfully established Data Channel");
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
    dc.on('data', function (buffer) { console.log("Received: " + buffer.length + " bytes"); dc.write(buffer.length.toString()); });
    dc.on('end', function () { console.log("Data Channel: " + this.name + " was closed"); });
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

