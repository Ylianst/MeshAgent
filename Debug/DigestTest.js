var http = require('http');
var https = require('https');
var agent = require('MeshAgent');
var server = "";
var req = "";
var db = require('SimpleDataStore').Shared();
var signer = require('SHA256Stream_Signer');


var keys = db.Keys;

Microstack_print("Enumerating Keys...\n");
for (var i = 0; i < keys.length; ++i)
{
    Microstack_print("DB Key=> " + keys[i] + "\n");
}
Microstack_print("Done...\n");

Microstack_print("[TestKey] = " + db.Get("TestKey") + "\n");
//db.Put("TestKey", "TestValue");


agent.Ready = function()
{
    signer.Create(agent);
    signer.OnSignature = OnSignature;

    server = http.createServer({ "MeshAgent": agent, "requestCert": true, "checkClientIdentity": onVerifyClient }, OnRequest);
    server.listen(9093);
    
    //req = https.get("https://127.0.0.1:443/", OnResponse);

    //req = https.request({ "hostname": "127.0.0.1", "method": "GET", "path": "/", "checkServerIdentity": onVerify }, OnResponse)
    //req = https.request({ "hostname": "127.0.0.1", "port": 9093, "method": "GET", "path": "/", "MeshAgent": agent }, OnResponse);

    req = https.request(https.addWebSocketHeadersToOptions({ "hostname": "127.0.0.1", "port": 443, "method": "GET", "path": "/", "MeshAgent": agent }, 4096, null), OnResponse);
    req.upgrade = OnWebSocket;
    //req.end();
}

function OnSignature(sig)
{
    //var test = Buffer.from(sig.toString('base64'), 'base64');
    var test = Buffer.from(sig.toString('hex'), 'hex');
    Microstack_print("sig Length: " + sig.length.toString() + " test.length = " + test.length.toString() + "\n");
    Microstack_print("Signature (base64) = " + sig.toString('base64') + "\n");
    Microstack_print("Signature (hex) = " + sig.toString('hex') + "\n");
}

function OnWebSocket(msg, s, head)
{
    //Microstack_print("WebSocket connected\n");
    //Microstack_print(JSON.stringify(msg) + "\n");
    //Microstack_print(JSON.stringify(s) + "\n");
    s.end();
}
function OnResponse(msg)
{
    if (msg == null)
    {
        Microstack_print("Receive Error\n");
        return;
    }

    Microstack_print("Status Code = " + msg.statusCode.toString() + "\n");
    msg.pipe(signer);
}
function onVerifyClient(clientName, certs)
{
    Microstack_print("Client Name = " + clientName + "\n");

    for (var i = 0; i < certs.length; ++i) {
        Microstack_print("   Fingerprint = " + certs[i].fingerprint + "\n");
    }
    //throw ("Not Valid");
}
function onVerify(serverName, certs)
{
    Microstack_print("ServerName = " + serverName + "\n");

    for (var i = 0; i < certs.length;++i)
    {
        Microstack_print("   Fingerprint = " + certs[i].fingerprint + "\n");
    }
    //throw ("Not Valid");
}

function OnRequest(req, res)
{
    if (req.NativeSession.Digest_IsAuthenticated("meshcentral.com") == 0)
    {
        req.NativeSession.Digest_SendUnauthorized("meshcentral.com", "<html>Oops</html>");
    }
    else
    {
        var username = req.NativeSession.Digest_GetUsername();
        Microstack_print("Username = " + username + "\n");
        if(username == "bryan" && req.NativeSession.Digest_ValidatePassword("roe")==1)
        {
            Microstack_print("Validated!\n");
            res.statusCode = 200;
            res.statusMessage = "OK";
            res.write("<HTML>SUCCESS!</HTML>");
            res.end();
        }
        else
        {
            Microstack_print("Nope!\n");
            res.end();
        }
    }
}



