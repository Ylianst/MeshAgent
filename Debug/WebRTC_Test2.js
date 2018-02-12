console.enableWebLog(9595);
var mesh = null;
var kvmStream = null;
var Readable = require('stream').Readable;
var RS = new Readable({
    read: function (options)
    {
        var min = 62000;
        var max = 65535;
        var size = Math.floor(Math.random() * (max - min)) + min;
        var retVal = Buffer.alloc(size).fill(this.val++);
        retVal.writeUInt32BE(size, 0);
        if (this.val == 10) { this.val = 0; }
        return (retVal);
    }
});
RS.val = 0;

var http = require('http');
var rtc = require('ILibWebRTC');
var peerConnection;
var signalingChannel;
var dc;

var webServer = http.createServer(OnLocalWebRequest);

var childprocess = require('child_process');
var p;

webServer.on('upgrade', OnUpgrade);
webServer.listen(8585);

if (process.platform == 'win32') {
    p = childprocess.execFile("c:\\windows\\system32\\cmd.exe", ["/c", "start", "http://localhost:8585/start.html"]);
}
else {
    console.log('Manually point your browser to http://localhost:8585/start.html');
}


try
{
    mesh = require('MeshAgent');
}
catch(e)
{

}


function OnUpgrade(imsg, sck, head)
{
    console.log("WebSocket Connected");
    signalingChannel = sck.upgradeWebSocket();
    signalingChannel.on('data', OnSignalData);

    peerConnection = rtc.createConnection();
    peerConnection.on('disconnected', function () { console.log('SCTP was disconnected'); });
    peerConnection.on('connected', OnWebRTC_Connected);
    peerConnection.on('dataChannel', OnWebRTC_DataChannel);

    try
    {
       // peerConnection.on('_hold', function (val) { console.log('Holding Count: ' + val);});
        peerConnection.on('_congestionWindowSizeChange', function (val) { console.log('Congestion Window: ' + val); });
       // peerConnection.on('_receiverCredits', function (val) { console.log('Receiver Credits: ' + val); });
        peerConnection.on('_t3tx', function (val) { console.log('T3TX: ' + val); });
        //peerConnection.on('_fastRecovery', function (val) { console.log('Fast Recovery: ' + val);});
        //peerConnection.on('_rttCalculated', function (val) { console.log('Calculated RTT Value = ' + val); });
        peerConnection.on('_lastSackTime', function (val) { console.log('Last SACK Time = ' + val); });
        peerConnection.on('_retransmit', function (val) { console.log('Retransmit: ' + (new Uint32Array([val]))[0]); });
        //peerConnection.on('_retransmitPacket', function (val) { DebugPacket(val); console.log('RetransmitPacket: ' + val.toString('hex')); });
        //peerConnection.on('_lastSentTime', function (val) { console.log('Last Sent Time = ' + val); });
        peerConnection.on('_sackReceived', function (val) { console.log('SACK: ' + (new Uint32Array([val]))[0]); });
    }
    catch(e)
    {
    }

    console.log("Generating WebRTC Offer...");
    signalingChannel.write({ cmd: "offer", data: peerConnection.generateOffer() });
}


function FOURBYTEBOUNDARY(a)
{
    return ((a) + ((4 - ((a) % 4)) % 4));
}
function crc32c(crc, bytes)
{
    var POLY = 0x82f63b78;
    var n;

    crc ^= 0xffffffff;
    for (n = 0; n < bytes.length; n++) {
        crc ^= bytes[n];
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ POLY : crc >>> 1;
    }
    return crc ^ 0xffffffff;
}

function DebugPacket(val)
{
    console.log('BufferLen: ' + val.length);
    console.log('CRC32C: ' + val.readInt32LE(8))
    val.writeUInt32BE(0, 8);
    console.log('CRC32C/Calc: ' + crc32c(0, val));
    console.log('VTAG: ' + val.readUInt32LE(4));
    var ptr = 12;

    while (ptr + 4 <= val.length)
    {
        var hdr = val.slice(ptr);

        var chunkType = hdr[0];
        var chunkFlags = hdr[1];
        var chunkSize = hdr.readUInt16BE(2);

        switch (chunkType) {
            case 0:
                console.log('DATA Chunk');
                console.log('...chunkFlags: ' + chunkFlags);
                console.log('...chunkLength: ' + chunkSize);
                console.log('...TSN: ' + hdr.readUInt32BE(4));
                console.log('...StreamID: ' + hdr.readUInt16BE(8));
                console.log('...Seq: ' + hdr.readUInt16BE(10));
                console.log('...ProtocolID: ' + hdr.readUInt32BE(12));
                break;
            default:
                console.log('UNKNOWN Chunk');
                console.log('...chunkFlags: ' + chunkFlags);
                console.log('...chunkLength: ' + chunkSize);
                break;
        }

        ptr += FOURBYTEBOUNDARY(chunkSize);
    }
}
function OnSignalData(chunk)
{
    var j = JSON.parse(chunk);
    if (j.cmd == 'offer')
    {
        console.log("Received Offer");
        //signalingChannel.write({ cmd: "offer", data: peerConnection.setOffer(j.data) });
        peerConnection.setOffer(j.data);
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

    this.jsdc = this.createDataChannel("testChannel", OnTestChannel);
}
function OnTestChannel()
{
    console.log("Successfully established JavaScript Data Channel");

    if (mesh == null) {
        RS.pipe(this);
    }
    else {
        kvmStream = mesh.getRemoteDesktopStream();
        kvmStream.pipe(this);
    }
}
function OnKVMChannel()
{
    console.log("Successfully established Data Channel to test Data throughput");
    dc = this;
    dc.kvm = mesh.getRemoteDesktopStream();
    dc.on('data', function (buffer)
    {
        console.log("Peer Received: " + buffer.toString() + " bytes");
    });
    dc.on('end', function () { this.kvm.end(); console.log("Closing KVM Session"); });
    dc.kvm.pipe(dc);
}
function OnWebRTC_DataChannel(dataChannel)
{
    console.log("Data Channel (" + dataChannel.name + ") was created");
    dc = dataChannel;
    dc.on('data', function (buffer)
    {
        //console.log("Received: " + buffer);
    });
    dc.on('end', function () { console.log("Data Channel: " + this.name + " was closed"); });

    //if (mesh == null)
    //{
    //    RS.pipe(dc);
    //}
    //else
    //{
    //    kvmStream = mesh.getRemoteDesktopStream();
    //    kvmStream.pipe(dc);
    //}
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

