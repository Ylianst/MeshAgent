var http = require('http');
var https = require('https');
var WS;
console.log("Starting HTTP (Rewrite) Test");

var cert = https.generateCertificate('test');

var server = https.createServer();

server.on('request', function (imsg, rsp)
{
    console.log('Received inbound request: ' + imsg.method + ' ' + imsg.url);
    rsp.writeHead(200, 'OK', {'Content-Length': 0});
});
server.on('upgrade', function (imsg, sck, head)
{
    console.log('Server On Upgrade');
    WS = sck.upgradeWebSocket();
    WS.on('pong', function () { console.log('Server received PONG'); WS.write('this is test'); WS.write(Buffer.from("This is a good day")); WS.end();});
    WS.on('data', function (chunk) { console.log('Server received: ' + chunk); });
    WS.ping();
});


server.listen({ port: 9095, pfx: cert, passphrase: 'test' });
//var req = http.get("http://127.0.0.1:9095/test.html");
//var req = http.get("ws://127.0.0.1:9095/test.html");
var req = http.request({ protocol: 'wss:', host: '127.0.0.1', port: 9095, method: 'GET', path: '/test.html', rejectUnauthorized: false})
req.end();

var req2 = http.request({ protocol: 'https:', host: '127.0.0.1', port: 9095, method: 'GET', path: '/test.html', rejectUnauthorized: false })
req2.end();

req.on('upgrade', function (imsg, sck, head)
{
    console.log('client upgraded to WebSocket');
    sck.on('ping', function () { console.log('Client received ping'); this.write('Client says hello');});
    sck.on('data', function (chunk) { console.log('client received: ' + chunk, typeof (chunk)); });
    sck.on('end', function () { console.log('Client side closed'); });
});
req.on('response', function (imsg)
{
    console.log('received response', imsg.statusCode, imsg.statusMessage);
    imsg.on('end', function () {
        console.log('Done reading IncomingMessageStream');
    });
})
req.on('error', function (err) { console.log('error received', err); });

req2.on('response', function (imsg) {
    console.log('received response', imsg.statusCode, imsg.statusMessage);
    imsg.on('end', function () {
        console.log('Done reading IncomingMessageStream');
    });
})
req2.on('error', function (err) { console.log('error received', err); });