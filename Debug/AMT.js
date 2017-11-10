var http = require('http');
var digest = require('http-digest').create("admin", "P@ssw0rd");
console.log("Starting AMT Test");


digest.http = require('http');



//console.log("First Test: HTTP/GET on '/'");
//var req = digest.request({ protocol: "http:", method: "GET", host: "172.16.2.249", path: "/", port: 16992 }, OnGet1);
//req.end();

//console.log('First Test: POST /wsman');
//WSManTest();

console.log('First Test: POST /wsman, [immediate]');
WSManTest_Immediate();

function OnGet1(imsg)
{
    if(imsg.statusCode == 303)
    {
        console.log("...SUCCESS!");
        console.log("Next Test: Redirect to '" + imsg.header['Location'] + "'");
        req = digest.request({ protocol: "http:", method: "GET", host: "172.16.2.249", path: imsg.header['Location'], port: 16992 }, OnGet2);
        req.end();
    }
    else
    {
        console.log("...FAILED!");
    }
}

function OnGet2(imsg)
{
    if (imsg.statusCode == 200)
    {
        console.log("...SUCCESS!");
        console.log("...Reading body of message");
        imsg.on('end', function ()
        {
            console.log("...Finished");
            console.log("Next Test: '/index.htm'");
            req = digest.request({ protocol: "http:", method: "GET", host: "172.16.2.249", path: "/index.htm", port: 16992 }, OnGet3);
            req.end();
        });
    }
    else
    {
        console.log("...FAILED, status code was: " + imsg.statusCode);
    }
}
function OnGet3(imsg)
{
    if (imsg.statusCode == 200)
    {
        console.log("...SUCCESS!");
        console.log("Next Test: 'POST /wsman'");
        WSManTest();
    }
}

function WSManTest()
{
    req = digest.request({ protocol: "http:", method: "POST", host: "172.16.2.249", path: "/wsman", port: 16992, headers: { Expect: '100-Continue' }, timeout: 2000 });
    req.on('continue', WSManTest_Continue);
    req.on('timeout', WSManTest_Timeout);
    req.on('response', WSManTest_Response);
}

function WSManTest_Immediate()
{
    req = digest.request({ protocol: "http:", method: "POST", host: "172.16.2.249", path: "/wsman", port: 16992 });
    req.on('response', WSManTest_Response);

    var xml = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48RW52ZWxvcGUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHNkPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6YT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNC8wOC9hZGRyZXNzaW5nIiB4bWxuczp3PSJodHRwOi8vc2NoZW1hcy5kbXRmLm9yZy93YmVtL3dzbWFuLzEvd3NtYW4ueHNkIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMy8wNS9zb2FwLWVudmVsb3BlIiA+PEhlYWRlcj48YTpBY3Rpb24+aHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNC8wOS90cmFuc2Zlci9HZXQ8L2E6QWN0aW9uPjxhOlRvPi93c21hbjwvYTpUbz48dzpSZXNvdXJjZVVSST5odHRwOi8vc2NoZW1hcy5kbXRmLm9yZy93YmVtL3dzY2ltLzEvY2ltLXNjaGVtYS8yL0NJTV9Db21wdXRlclN5c3RlbVBhY2thZ2U8L3c6UmVzb3VyY2VVUkk+PGE6TWVzc2FnZUlEPjQ8L2E6TWVzc2FnZUlEPjxhOlJlcGx5VG8+PGE6QWRkcmVzcz5odHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA0LzA4L2FkZHJlc3Npbmcvcm9sZS9hbm9ueW1vdXM8L2E6QWRkcmVzcz48L2E6UmVwbHlUbz48dzpPcGVyYXRpb25UaW1lb3V0PlBUNjBTPC93Ok9wZXJhdGlvblRpbWVvdXQ+PC9IZWFkZXI+PEJvZHkgLz48L0VudmVsb3BlPg==';
    var b = Buffer.from(xml, 'base64');
    req.write(b);
    req.end();
}

function WSManTest_Continue()
{
    console.log("Got Continue!");
}
function WSManTest_Timeout()
{
    console.log("Timeout waiting for 100 Continue... Sending body anyways...");
    var xml = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48RW52ZWxvcGUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHNkPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6YT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNC8wOC9hZGRyZXNzaW5nIiB4bWxuczp3PSJodHRwOi8vc2NoZW1hcy5kbXRmLm9yZy93YmVtL3dzbWFuLzEvd3NtYW4ueHNkIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMy8wNS9zb2FwLWVudmVsb3BlIiA+PEhlYWRlcj48YTpBY3Rpb24+aHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNC8wOS90cmFuc2Zlci9HZXQ8L2E6QWN0aW9uPjxhOlRvPi93c21hbjwvYTpUbz48dzpSZXNvdXJjZVVSST5odHRwOi8vc2NoZW1hcy5kbXRmLm9yZy93YmVtL3dzY2ltLzEvY2ltLXNjaGVtYS8yL0NJTV9Db21wdXRlclN5c3RlbVBhY2thZ2U8L3c6UmVzb3VyY2VVUkk+PGE6TWVzc2FnZUlEPjQ8L2E6TWVzc2FnZUlEPjxhOlJlcGx5VG8+PGE6QWRkcmVzcz5odHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA0LzA4L2FkZHJlc3Npbmcvcm9sZS9hbm9ueW1vdXM8L2E6QWRkcmVzcz48L2E6UmVwbHlUbz48dzpPcGVyYXRpb25UaW1lb3V0PlBUNjBTPC93Ok9wZXJhdGlvblRpbWVvdXQ+PC9IZWFkZXI+PEJvZHkgLz48L0VudmVsb3BlPg==';
    var b = Buffer.from(xml, 'base64');
    this.write(b);
    this.end();
}
function WSManTest_Response(imsg)
{
    imsg.on('data', function (chunk) { console.log(chunk); });
}


//var req = digest.request({ protocol: "ws:", method: "GET", host: "127.0.0.1", path: "/", port: 9093 }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });
//var req = http.request({ protocol: "http:", method: "POST", host: "127.0.0.1", path: "/", port: 9093, headers: { Expect: '100-Continue' } }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });
//var req = digest.request({ protocol: "http:", method: "POST", host: "127.0.0.1", path: "/", port: 9093, headers: { Expect: '100-Continue' } }, function (imsg) { console.log(imsg.statusCode == 200 ? "SUCCESS!" : "FAIL!"); });

//req.on('upgrade', function (res, sk, h) { console.log("Upgraded to WebSocket!"); });
//req.on('error', function () { console.log("Error occured"); });
//req.on('continue', function () { console.log("Received Continue"); this.write("test"); this.end(); });

//function OnCheckContinue(imsg, resp)
//{
//    console.log("Recevied: Expect-100 Continue");
//    if (imsg.Digest_IsAuthenticated('www.meshcentral.com') == 1)
//    {
//        var uname = imsg.Digest_GetUsername();
//        console.log("Digest Username was: " + uname);
//        if (uname == 'bryan' && imsg.Digest_ValidatePassword('roe') == 1)
//        {
//            console.log("Validated");
//            imsg.on('data', function (chunk) { console.log('Received: ' + chunk.toString()); });
//            imsg.on('end', function () { console.log('Received Complete'); });
//            resp.writeContinue();
//        }
//        else
//        {
//            console.log("Bad Username/Password");
//            resp.statusCode = "500";
//            resp.statusMessage = "Error";
//            resp.end();
//        }
//    }
//    else
//    {
//        console.log("Sending Unauthorized");
//        imsg.Digest_SendUnauthorized('www.meshcentral.com', 'oops');
//    }
//}
//function OnCheckContinue_NoDigest(imsg, resp)
//{
//    console.log("Recevied: Expect-100 Continue");

//    imsg.on('data', function (chunk) { console.log('Received: ' + chunk.toString()); });
//    imsg.on('end', function () { console.log('Received Complete'); });
//    resp.writeContinue();
//}
//function OnServerUpgrade(imsg, sck, head)
//{
//    if(imsg.Digest_IsAuthenticated('www.meshcentral.com')==1)
//    {
//        var uname = imsg.Digest_GetUsername();
//        console.log("Digest Username was: " + uname);
//        if(uname == 'bryan' && imsg.Digest_ValidatePassword('roe')==1)
//        {
//            console.log("Upgrading to WebSocket");
//            sck.upgradeWebSocket();
//        }
//        else
//        {
//            console.log("Bad Username/Password");
//            sck.end();
//        }
//    }
//    else
//    {
//        console.log("Sending Unauthorized");
//        imsg.Digest_SendUnauthorized('www.meshcentral.com', 'oops');
//    }
//}


//function onVerifyServer(clientName, certs) {
//    console.log("Server Name = " + clientName + "\n");

//    for (var i = 0; i < certs.length; ++i) {
//        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
//    }
//    //throw ("Not Valid");
//}
//function onVerifyClient(clientName, certs)
//{
//    console.log("Client Name = " + clientName + "\n");

//    for (var i = 0; i < certs.length; ++i) {
//        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
//    }
//    //throw ("Not Valid");
//}
//function onVerify(serverName, certs)
//{
//    console.log("ServerName = " + serverName + "\n");

//    for (var i = 0; i < certs.length;++i)
//    {
//        console.log("   Fingerprint = " + certs[i].fingerprint + "\n");
//    }
//    //throw ("Not Valid");
//}

//function OnRequest(req, res)
//{
//    console.log("Received Request for: " + req.url);

//}



