var http = require('http');

console.log('starting client test');
console.log('Sending Request');
var req = http.request({host: '127.0.0.1', port: 9093, protocol: 'ws:'});


req.on('upgrade', function (res, sk, h)
{
    sk.on('ping', function () { console.log('received ping'); });
    sk.on('pong', function () { console.log('received pong'); });
    this.websocket = sk;

    console.log("Upgraded to WebSocket!"); sk.write(JSON.stringify({ a: 'hello' }));
});
//req.end();


