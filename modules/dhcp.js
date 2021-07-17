/*
Copyright 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

* @description Mini DHCP Client Module, to fetch configuration data
* @author Bryan Roe & Ylian Saint-Hilaire
*/

// DHCP Information
var promise = require('promise');
function promise_default(res, rej)
{
    this._res = res;
    this._rej = rej;
}


function  buf2addr(buf)
{
    return (buf[0] + '.' + buf[1] + '.' + buf[2] + '.' + buf[3]);
}
function parseDHCP(buffer)
{
    var i;
    var packet = Buffer.alloc(buffer.length);
    for (i = 0; i < buffer.length; ++i) { packet[i] = buffer[i]; }

    var ret = { op: packet[0] == 0 ? 'REQ' : 'RES', hlen: packet[2] };   // OP Code
    ret.xid = packet.readUInt32BE(4);                   // Transaction ID
    ret.ciaddr = buf2addr(packet.slice(12, 16));
    ret.yiaddr = buf2addr(packet.slice(16, 20)); 
    ret.siaddr = buf2addr(packet.slice(20, 24));
    ret.giaddr = buf2addr(packet.slice(24, 28));
    ret.chaddr = packet.slice(28, 28 + ret.hlen).toString('hex:');
    if (packet[236] == 99 && packet[237] == 130 && packet[238] == 83 && packet[239] == 99)
    {
        // Magic Cookie Validated
        ret.magic = true;
        ret.options = {};

        i = 240;
        while(i<packet.length)
        {
            switch(packet[i])
            {
                case 0:
                    i += 1;
                    break;
                case 255:
                    ret.options[255] = true;
                    i += 2;
                    break;
                default:
                    ret.options[packet[i]] = packet.slice(i + 2, i + 2 + packet[i + 1]);
                    switch(packet[i])
                    {
                        case 1:     // Subnet Mask
                            ret.options.subnetmask = buf2addr(ret.options[1]);
                            delete ret.options[1];
                            break;
                        case 3:     // Router
                            ret.options.router = [];
                            var ti = 0;
                            while (ti < ret.options[3].length)
                            {
                                ret.options.router.push(buf2addr(ret.options[3].slice(ti, ti + 4)));
                                ti += 4;
                            }
                            delete ret.options[3];
                            break;
                        case 6:     // DNS
                            ret.options.dns = buf2addr(ret.options[6]);
                            delete ret.options[6];
                            break;
                        case 15:    // Domain Name
                            ret.options.domainname = ret.options[15].toString();
                            delete ret.options[15];
                            break;
                        case 28:    // Broadcast Address
                            ret.options.broadcastaddr = buf2addr(ret.options[28]);
                            delete ret.options[28];
                            break;
                        case 51:    // Lease Time
                            ret.options.lease = { raw: ret.options[51].readInt32BE() };
                            delete ret.options[51];
                            ret.options.lease.hours = Math.floor(ret.options.lease.raw / 3600);
                            ret.options.lease.minutes = Math.floor((ret.options.lease.raw % 3600) / 60);
                            ret.options.lease.seconds = (ret.options.lease.raw % 3600) % 60;
                            break;
                        case 53:    // Message Type
                            ret.options.messageType = ret.options[53][0];
                            delete ret.options[53];
                            break;  
                        case 54:    // Server
                            ret.options.server = buf2addr(ret.options[54]);
                            delete ret.options[54];
                            break;
                    }
                    i += (2 + packet[i + 1]);
                    break;
            }
        }
    }


    return (ret);
}

function createPacket(messageType, data)
{
    var b = Buffer.alloc(245);

    switch(messageType)
    {
        //case 0x02:
        //case 0x04:
        //case 0x05:
        //case 0x06:
        //    b[0] = 0x00;      // Reply
        //    break;
        //case 0x01:
        //case 0x03:
        //case 0x07:
        case 0x08:
            b[0] = 0x01;        // Request
            break;
        default:
            throw ('DHCP(' + messageType + ') NOT SUPPORTED');
            break;
    }

    // Headers
    b[1] = 0x01;        // Ethernet
    b[2] = 0x06;        // HW Address Length
    b[3] = 0x00;        // HOPS

    // Transaction ID
    var r = Buffer.alloc(4); r.randomFill();
    b.writeUInt32BE(r.readUInt32BE(), 4);
    b.writeUInt16BE(0x8000, 10);

    // Magic Cookie
    b[236] = 99;
    b[237] = 130;
    b[238] = 83;
    b[239] = 99;

    // DHCP Message Type
    b[240] = 53;
    b[241] = 1;
    b[242] = messageType;
    b[243] = 255;

    switch(messageType)
    {
        case 0x08:
            if (data.ciaddress == null) { throw ('ciadress missing'); }
            if (data.chaddress == null) { throw ('chaddress missing'); }

            // ciaddress
            var a = data.ciaddress.split('.');
            var ci = parseInt(a[0]);
            ci = ci << 8;
            ci = ci | parseInt(a[1]);
            ci = ci << 8;
            ci = ci | parseInt(a[2]);
            ci = ci << 8;
            ci = ci | parseInt(a[3]);
            b.writeInt32BE(ci, 12);

            // chaddress
            var y = data.chaddress.split(':').join('');
            y = Buffer.from(y, 'hex');
            y.copy(b, 28);

            break;
    }

    return (b);
}

function raw(localAddress, port, buffer, handler)
{
    var ret = new promise(promise_default);
    ret.socket = require('dgram').createSocket({ type: 'udp4' });
    try
    {
        ret.socket.bind({ address: localAddress, port: (port != null && port != 0) ? port : null });
    }
    catch (e)
    {
        ret._rej('Unable to bind to ' + localAddress);
        return (ret);
    }

    ret.socket.setBroadcast(true);
    ret.socket.setMulticastInterface(localAddress);
    ret.socket.setMulticastTTL(1);
    ret.socket.descriptorMetadata = 'DHCP (' + localAddress + ')';
    ret.socket.on('message', handler.bind(ret));
    ret.socket.send(buffer, 67, '255.255.255.255');
    return (ret);
}

function info(interfaceName, port)
{
    var f = require('os').networkInterfaces();
    if (f[interfaceName] != null)
    {
        var i;
        for(i=0;i<f[interfaceName].length;++i)
        {
            if(f[interfaceName][i].family == 'IPv4' && f[interfaceName][i].mac != '00:00:00:00:00:00')
            {
                try
                {
                    var b = createPacket(8, { ciaddress: f[interfaceName][i].address, chaddress: f[interfaceName][i].mac });
                    _hide(raw(f[interfaceName][i].address, port, b, function infoHandler(msg)
                    {
                        var res = parseDHCP(msg);
                        if (res.chaddr.toUpperCase() == this.hwaddr.toUpperCase() && res.options != null && res.options.lease != null)
                        {
                            clearTimeout(this.timeout);
                            setImmediate(function (s) { s.removeAllListeners('message'); }, this.socket); // Works around bug in older dgram.js
                            this._res(res);
                        }
                    }));
                    _hide().hwaddr = f[interfaceName][i].mac;
                    _hide().timeout = setTimeout(function (x)
                    {
                        x.socket.removeAllListeners('message');
                        x._rej('timeout');
                    }, 2000, _hide());
                    return (_hide(true));
                }
                catch(e)
                {
                    var ret = new promise(promise_default);
                    ret._rej(e);
                    return (ret);
                }
            }
        }
    }

    var ret = new promise(promise_default);
    ret._rej('interface (' + interfaceName + ') not found');
    return (ret);
}

module.exports = 
    {
        client: { info: info, raw: raw }, 
        MESSAGE_TYPES: 
            {
                DISCOVER: 1,
                OFFER: 2,
                REQUEST: 3,
                DECLINE: 4,
                ACK: 5,
                NACK: 6,
                RELEASE: 7,
                INFO: 8 
            } 
    };

