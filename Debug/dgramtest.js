var dgram = require('dgram');
var os = require('os');
var interfaces = os.networkInterfaces();
var broadcastSockets = {};
var multicastSockets = {};
var httpHeaders = require('http-headers');

for (var adapter in interfaces)
{
    if (interfaces.hasOwnProperty(adapter))
    {
        for (var i = 0 ; i < interfaces[adapter].length; ++i)
        {
            var addr = interfaces[adapter][i];

            multicastSockets[i] = dgram.createSocket({ type: (addr.family == "IPv4" ? "udp4" : "udp6") });
            //multicastSockets[i].bind({ address: addr.address, port:1900, exclusive:false});
            multicastSockets[i].bind({ address: addr.address, exclusive: false });

            if(addr.family == "IPv4")
            {
                //multicastSockets[i].addMembership("239.255.255.250");
                //multicastSockets[i].setMulticastLoopback(true);
                multicastSockets[i].once('message', OnMulticastMessage);

                multicastSockets[i].send("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: upnp:rootdevice\r\nMAN: \"ssdp:discover\"\r\nMX: 4\r\nContent-Length: 0\r\n\r\n", 1900, "239.255.255.250");
            }
        }
    }
}

function OnMulticastMessage(msg, rinfo)
{
    console.log("Received " + rinfo.size + " bytes from " + rinfo.address + ":" + rinfo.port);
    var packet = httpHeaders(msg);

    if (packet.hasOwnProperty('statusCode'))
    {
        console.log("Status (" + packet.statusCode + ") " + packet.statusMessage);
    }
    else
    {
        console.log(packet.method + " " + packet.url);
    }
    for (var header in packet.headers) {
        console.log("  " + header + ":" + packet.headers[header]);
    }
}

function SendWakeOnLan()
{
    var magic = new Buffer(102);
    for (var x = 0; x < 6; ++x)
    {
        magic[x] = 0xFF;
    }
    for (var x = 1; x <= 16; ++x) {
        magic[(x * 6)] = 0xB8;
        magic[(x * 6) + 1] = 0xAE;
        magic[(x * 6) + 2] = 0xED;
        magic[(x * 6) + 3] = 0x74;
        magic[(x * 6) + 4] = 0xAB;
        magic[(x * 6) + 5] = 0xC3;
    }

    for (var adapter in interfaces) {
        if (interfaces.hasOwnProperty(adapter)) {
            console.log(adapter + " => ");
            for (var i = 0 ; i < interfaces[adapter].length; ++i) {
                var addr = interfaces[adapter][i];

                console.log("   " + addr.family + " => " + addr.address + " [" + addr.mac + "]");
                if (addr.hasOwnProperty('netmask')) { console.log("      Netmask = " + addr.netmask); }

                broadcastSockets[i] = dgram.createSocket({ type: (addr.family == "IPv4" ? "udp4" : "udp6") });
                broadcastSockets[i].bind({ address: addr.address });
                broadcastSockets[i].setBroadcast(true);

                if (addr.family == "IPv4") {
                    broadcastSockets[i].send(magic, 7, "255.255.255.255");
                }

            }
        }
    }
}


