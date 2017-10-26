var http = require('http');
var server = "";
var req = "";
var gtunnel = "";
var digest = require('http-digest').create("bryan", "roe");

console.log("Starting POST Digest Test");


server = http.createServer(OnRequest);
server.listen(9093);
server.on('upgrade', OnServerUpgrade);
server.on('checkContinue', OnCheckContinue);
//server.on('checkContinue', OnCheckContinue_NoDigest);

digest.http = require('http');
//var req = digest.request({ protocol: "ws:", method: "GET", host: "127.0.0.1", path: "/", port: 9093 }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });
//var req = http.request({ protocol: "http:", method: "POST", host: "127.0.0.1", path: "/", port: 9093, headers: { Expect: '100-Continue' } }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });
var req = digest.request({ protocol: "http:", method: "POST", host: "127.0.0.1", path: "/", port: 9093, headers: { Expect: '100-Continue' } }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });

req.on('upgrade', function (res, sk, h) { console.log("Upgraded to WebSocket!"); });
req.on('error', function () { console.log("Error occured"); });
req.on('continue', function () { console.log("Received Continue"); this.write("test"); this.end(); });

function OnCheckContinue(imsg, resp)
{
    console.log("Recevied: Expect-100 Continue");
    if (imsg.Digest_IsAuthenticated('www.meshcentral.com') == 1)
    {
        var uname = imsg.Digest_GetUsername();
        console.log("Digest Username was: " + uname);
        if (uname == 'bryan' && imsg.Digest_ValidatePassword('roe') == 1)
        {
            console.log("Validated");
            imsg.on('data', function (chunk) { console.log('Received: ' + chunk.toString()); });
            imsg.on('end', function () { console.log('Received Complete'); });
            resp.writeContinue();
        }
        else
        {
            console.log("Bad Username/Password");
            resp.statusCode = "500";
            resp.statusMessage = "Error";
            resp.end();
        }
    }
    else
    {
        console.log("Sending Unauthorized");
        imsg.Digest_SendUnauthorized('www.meshcentral.com', 'oops');
    }
}
function OnCheckContinue_NoDigest(imsg, resp)
{
    console.log("Recevied: Expect-100 Continue");

    imsg.on('data', function (chunk) { console.log('Received: ' + chunk.toString()); });
    imsg.on('end', function () { console.log('Received Complete'); });
    resp.writeContinue();
}
function OnServerUpgrade(imsg, sck, head)
{
    if(imsg.Digest_IsAuthenticated('www.meshcentral.com')==1)
    {
        var uname = imsg.Digest_GetUsername();
        console.log("Digest Username was: " + uname);
        if(uname == 'bryan' && imsg.Digest_ValidatePassword('roe')==1)
        {
            console.log("Upgrading to WebSocket");
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

}



