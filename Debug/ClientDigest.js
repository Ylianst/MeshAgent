var http = require('http');
var server = "";
var req = "";
var gtunnel = "";
var digest = require('http-digest').create("bryan", "roe");

console.log("Starting Digest Test (Agent Connected)");
//server = http.createServer({ "MeshAgent": agent, "requestCert": true, "checkClientIdentity": onVerifyClient }, OnRequest);
server = http.createServer(OnRequest);
server.listen(9093);

server.on('upgrade', OnServerUpgrade);

function OnServerUpgrade(imsg, sck, head)
{
    if(imsg.Digest_IsAuthenticated('www.meshcentral.com')==1)
    {
        var uname = imsg.Digest_GetUsername();
        console.log("Digest Username was: " + uname);
        if(uname == 'bryan' && imsg.Digest_ValidatePassword('roe')==1)
        {
            sck.upgradeWebSocket();
        }
        else
        {
            console.log("Bad Username/Password");
            sck.end();
        }
    }
    else
    {
        console.log("Sending Unauthorized");
        imsg.Digest_SendUnauthorized('www.meshcentral.com', 'oops');
    }
}


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
    var req = digest.request({ protocol: "ws:", method: "GET", host: "127.0.0.1", path: "/", port: 9093 }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });

    req.on('upgrade', function (res, sk, h) { console.log("Upgraded to WebSocket!"); });
    req.on('error', function () { console.log("Error occured"); });
    req.end();


function OnAlt(imsg)
{
    console.log("OnAlt, StatusCode = " + imsg.statusCode);
}
function OnGoogle(imsg)
{
    console.log("Response Code = " + imsg.statusCode);
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



