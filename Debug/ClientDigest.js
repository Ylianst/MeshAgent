var http = require('http');
var agent = require('MeshAgent');
var server = "";
var req = "";
var gtunnel = "";
var digest = require('http-digest').create("bryan", "roe");

agent.on('Connected', function (connectState)
{
    console.log("Connection State = " + connectState.toString());
    console.log("Connected: " + this.ServerUrl);

    //gtunnel = require('global-tunnel');
    //gtunnel.initialize({ host: "proxy.jf.intel.com", port: 911 });

    //req = http.get({ uri: "http://www.google.com/", proxy: { host: "proxy.jf.intel.com", port: 911 } }, OnGoogle);
    //req = http.request({ protocol: "wss:", hostname: "alt.meshcentral.com", port: 443, method: "GET", path: "/agent.ashx", MeshAgent: agent /* proxy: { host: "proxy.jf.intel.com", port: 911 }*/}, OnResponse);
    //req.upgrade = OnWebSocket;
    //req.on('error', function (msg) { console.log(msg); });
    //req.end();

    //digest.clientRequest = http.get("http://127.0.0.1:9093/");
    //digest.on('response', function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!");})

    digest.http = require('http');
    //digest.get("http://127.0.0.1:9093/", function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });
    //digest.request({ protocol: "http:", method: "GET", host: "127.0.0.1", path: "/", port: 9093 }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); }).end();
    var req = digest.request({ MeshAgent: agent, protocol: "wss:", method: "GET", host: "127.0.0.1", path: "/", port: 9093, checkServerIdentity:onVerifyServer }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });

    req.on('upgrade', function (res, sk, h) { console.log("Upgraded to WebSocket!"); });
    req.end();
});

function OnAlt(imsg)
{
    console.log("OnAlt, StatusCode = " + imsg.statusCode);
}
function OnGoogle(imsg)
{
    console.log("Response Code = " + imsg.statusCode);
}
agent.Ready = function()
{
    console.log("Starting Digest Test (Agent Connected)");
    //server = http.createServer({ "MeshAgent": agent, "requestCert": true, "checkClientIdentity": onVerifyClient }, OnRequest);
    server = http.createServer({ "MeshAgent": agent }, OnRequest);
    server.listen(9093);

    //req = http.request({ "protocol":"ws:", "hostname": "127.0.0.1", "port": 9093, "method": "GET", "path": "/", "MeshAgent": agent }, OnResponse);
    //req.upgrade = OnWebSocket;
    //req.end();
}

function OnWebSocket(msg, s, head)
{
    console.log("WebSocket connected\n");
    console.log(JSON.stringify(msg) + "\n");
    console.log(JSON.stringify(s) + "\n");
    s.end();
}
function OnResponse(msg)
{
    if (msg == null)
    {
        console.log("Receive Error\n");
        return;
    }

    console.log("Status Code = " + msg.statusCode.toString() + "\n");
}
function onVerifyServer(clientName, certs) {
    console.log("Server Name = " + clientName + "\n");

    for (var i = 0; i < certs.length; ++i) {
        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
    }
    //throw ("Not Valid");
}
function onVerifyClient(clientName, certs)
{
    console.log("Client Name = " + clientName + "\n");

    for (var i = 0; i < certs.length; ++i) {
        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
    }
    //throw ("Not Valid");
}
function onVerify(serverName, certs)
{
    console.log("ServerName = " + serverName + "\n");

    for (var i = 0; i < certs.length;++i)
    {
        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
    }
    //throw ("Not Valid");
}

function OnRequest(req, res)
{
    console.log("Received Request for: " + req.url);
    if (req.NativeSession.Digest_IsAuthenticated("meshcentral.com") == 0)
    {
        req.NativeSession.Digest_SendUnauthorized("meshcentral.com", "<html>Oops</html>");
    }
    else
    {
        var username = req.NativeSession.Digest_GetUsername();
        console.log("Username = " + username + "\n");
        if(username == "bryan" && req.NativeSession.Digest_ValidatePassword("roe")==1)
        {
            console.log("Validated!\n");
            if (req.NativeSession.WebSocket_GetDataType() == 0xFF)
            {
                req.NativeSession.WebSocket_Upgrade();
            }
            else
            {
                res.statusCode = 200;
                res.statusMessage = "OK";
                res.write("<HTML>SUCCESS!</HTML>");
                res.end();
            }
        }
        else
        {
            console.log("Nope!\n");
            res.end();
        }
    }
}



