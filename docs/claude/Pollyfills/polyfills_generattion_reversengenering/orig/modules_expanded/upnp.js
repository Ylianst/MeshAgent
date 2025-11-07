// Module: upnp
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 5593 bytes
// Decompressed size: 26044 bytes
// Compression ratio: 78.5%

/*
Copyright 2019 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

var promise = require('promise');
var parseXml = require('parseXml');
var http = require('http');
var dgram = require('dgram');
var os = require('os');
var MemoryStream = require('MemoryStream');
var net = require('net');

function upnpdevice(descriptionUrl, usn, cp, localInterface)
{
    var d = descriptionUrl.split('/');
    this.BaseURL = d[0] + '//' + d[2];
    var emitterUtils = require('events').inherits(this);
    emitterUtils.createEvent('bye');
    emitterUtils.createEvent('error');
    emitterUtils.createEvent('alive');
    emitterUtils.createEvent('serviceLoaded');
    this.locationUrl = descriptionUrl;
    this.localInterface = localInterface;
    this.pendingServices = 0;
    this.usn = usn;
    this.cp = cp;
    this.req = http.get(descriptionUrl);
    this.req.device = this;
    this.req.on('error', function ()
    {
        this.device.emit('error', 'Error fetching Description Document from ' + this.device.BaseURL);
    });
    this.req.on('response', function (msg)
    {
        if (msg.statusCode == 200)
        {
            msg.device = this.device;
            this.device.dd = new MemoryStream();
            this.device.dd.device = this.device;
            msg.pipe(this.device.dd);
            this.device.dd.on('end', function ()
            {
                upnpdevice_parseXml.apply(this.device, [this.buffer.toString()]);
            });
        }
        else
        {
            this.device.emit('error', 'Error (' + msg.statusCode + ') Fetching Description Document from: ' + this.device.BaseURL);
        }
    });
    this.loadAllServices = function () { this.rootDevice.loadAllServices(); };
    this.makeUrl = function (url)
    {
        if(url.startsWith('/'))
        {
            if (this.BaseURL.endsWith('/'))
            {
                return (this.BaseURL + url.substring(1));
            }
            else
            {
                return (this.BaseURL + url);
            }
        }
        else
        {
            if (this.BaseURL.endsWith('/'))
            {
                return (this.BaseURL + url);
            }
            else
            {
                return (this.BaseURL + '/' + url);
            }
        }
    };
    this.on('~', upnpdevice_Cleanup);
    this.on('serviceLoaded', function (svc)
    {
        if(--this.pendingServices == 0)
        {
            // All Services have been loaded
            this.cp.emit('device', this.rootDevice);
        }
    });
    this.getDevice = function (udn)
    {
        return (this.rootDevice.getDevice(udn));
    };
    this._eventServer = null;
    this._startEventServer = function _startEventServer()
    {
        if (this._eventServer) { return; }
        this._eventServer = http.createServer();
        this._eventServer.root = this;
        this._eventServer.listen({ port: 0, host: this.localInterface });
        this._eventServer.on('request', function (imsg, rsp)
        {
            if (imsg.method != 'NOTIFY')
            {
                rsp.statusCode = 400;
                rsp.statusMessage = 'Bad Request';
                rsp.end();
            }
            else
            {
                rsp.statusCode = 200;
                rsp.statusMessage = 'OK';
                imsg.__rsp = rsp;
                imsg.on('end', function () { this.__rsp.end(); });
            }            

            var sp = imsg.url.split('/');
            var dv = this.root.getDevice(sp[1]);
            if (dv)
            {
                var sv = dv.getService(sp[2]);
                if (sv)
                {
                    sv.notify(imsg);
                }
                else
                {
                    rsp.end();
                }
            }            
        });
        console.info1('Event Server bound on: ' + JSON.stringify(this._eventServer.address()));
    }
}

function upnpdevice_Cleanup()
{
    try
    {
        console.info1('Finalizing: ' + this.rootDevice.friendlyName + ' [' + this.rootDevice.locationUrl + ']');
    }
    catch(e)
    {

    }
}
function upnpservice(parentDevice, xmlDoc)
{
    require('events').EventEmitter.call(this, true)
        .createEvent('stateVariableChanged')

    this.device = parentDevice;

    this.serviceType = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'serviceType')[0].textContent;
    this.serviceId = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'serviceId')[0].textContent;
    this.controlURL = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'controlURL')[0].textContent;
    this.eventSubURL = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'eventSubURL')[0].textContent;
    this.SCPDURL = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'SCPDURL')[0].textContent;

    if (!this.controlURL.startsWith('http:') && !this.controlURL.startsWith('https:')) { this.controlURL = this.device.rootDevice.makeUrl(this.controlURL); }
    if (!this.eventSubURL.startsWith('http:') && !this.eventSubURL.startsWith('https:')) { this.eventSubURL = this.device.rootDevice.makeUrl(this.eventSubURL); }
    if (!this.SCPDURL.startsWith('http:') && !this.SCPDURL.startsWith('https:')) { this.SCPDURL = this.device.rootDevice.makeUrl(this.SCPDURL); }
    
    this.load = function ()
    {
        ++this.device.rootDevice.pendingServices;
        this.req = http.get(this.SCPDURL);
        this.req.service = this;
        this.req.on('error', function () { this.service.device.rootDevice.emit('error', 'Error fetching SCPD from: ' + this.service.SCPDURL); });
        this.req.on('response', function (msg)
        {
            if (msg.statusCode == 200)
            {
                msg.service = this.service;
                this.service.scpdxml = new MemoryStream();
                this.service.scpdxml.service = this.service;
                msg.pipe(this.service.scpdxml);

                this.service.scpdxml.on('end', function ()
                {
                    try
                    {
                        upnpservice_parseScpd.apply(this.service, [this.buffer.toString()]);
                    }
                    catch(e)
                    {
                        this.service.device.rootDevice.emit('error', 'error parsing SCPD: ' + e);
                    }
                });
            }
            else
            {
                this.service.device.rootDevice.emit('error', 'Error loading SCPD from: ' + this.service.SCPDURL);
            }
        });
    }
    this.getAction = function(name)
    {
        for(var a in this.actions)
        {
            if (this.actions[a].name == name) { return (this.actions[a]); }
        }
        return (undefined);
    }


    //this.on('~', function ()
    //{
    //    if(this._sid)
    //    {
    //        // UNSUBSCRIBE from events

    //        var options = http.parseUri(this.eventSubURL);
    //        options.method = 'UNSUBSCRIBE';
    //        options.headers =
    //            {
    //                HOST: options.host,
    //                SID: this._sid
    //            };
    //        console.log('Sending: ' + JSON.stringify(options));
    //        r = http.request(options);
    //        r.end();
    //    }
    //});
}

function upnpargument(action, xmlDoc)
{
    this.action = action;
    this.name = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'name')[0].textContent;
    this.direction = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'direction')[0].textContent;
    this.relatedStateVariable = action.service.stateVariables.get(xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'relatedStateVariable')[0].textContent);
}

function upnpaction(service, xmlDoc)
{
    this.pendingPosts = [];
    this.arguments = []; Object.defineProperty(this.arguments, "get", { value: function (name) { for (var i in this) { if (this[i].name == name) { return (this[i]); } } return (undefined); } });
    this.service = service;
    
    this.name = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'name')[0].textContent;
    var argumentList = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'argumentList')[0];

    if (argumentList)
    {
        var arguments = argumentList.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'argument');
        for (var i in arguments)
        {
            this.arguments.push(new upnpargument(this, arguments[i]));
        }
    }
    else
    {
        //console.log(this.service.scpdxml.buffer.toString());
    }

    this.invoke = function (args)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });

        var parameters = '';
        for (var i in this.arguments)
        {
            if(this.arguments[i].direction == 'in' &&  args[this.arguments[i].name])
            {
                parameters += ('<u:' + this.arguments[i].name + '>' + args[this.arguments[i].name] + '</u:' + this.arguments[i].name + '>');
            }
            else if(this.arguments.direction == 'in')
            {
                ret._rej('missing parameter: [' + this.arguments[i].name + '] when invoking Action: ' + this.name);
                return (ret);
            }
        }

        var controlUri = http.parseUri(this.service.controlURL);
        console.info1(controlUri);
        var headers = { HOST: (controlUri.host + ':' + controlUri.port), SOAPACTION: '"' + this.service.serviceType + '#' + this.name + '"', 'Content-Type': 'text/xml; charset="utf-8"' };
        this.pendingPosts.push(http.request({ protocol: 'http', host: controlUri.host, port: controlUri.port, method: 'POST', path: controlUri.path, headers: headers }));
        this.pendingPosts.peek().action = this;

        this.pendingPosts.peek().promise = ret;
        this.pendingPosts.peek().on('response', function invokeResponse(msg)
        {
            if (msg.statusCode != 200)
            {
                this.promise._rej(msg);
                return;
            }

            var buff = new MemoryStream();
            buff.promise = this.promise;
            buff.req = this;
            msg.pipe(buff);
            buff.on('end', function ()
            {
                var body = {};
                var xml = parseXml(this.buffer.toString());
                var action = this.req.action;
                var userArgs = this.req.args;
                var actionResponse = xml.getElementsByTagNameNS(action.service.serviceType, action.name + 'Response')[0];
                if (actionResponse)
                {
                    for (var child in actionResponse.childNodes)
                    {
                        if (action.arguments.get(actionResponse.childNodes[child].name))
                        {
                            body[actionResponse.childNodes[child].name] = actionResponse.childNodes[child].textContent;
                        }
                    }
                    this.promise._res(body);
                }
            });
        });
        this.pendingPosts.peek().on('error', function (err) { this.promise._rej(err); });

        var txt = '<?xml version="1.0" encoding="utf-8"?>\r\n<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>';
        txt += ('<u:' + this.name + ' xmlns:u="' + this.service.serviceType + '">');

        if (parameters != '')
        {
            txt += parameters;
        }
        txt += ('</u:' + this.name + '>');
        txt += ('</s:Body></s:Envelope>');

        this.pendingPosts.peek().end(txt);
        return (ret);
    };
}
function upnpvariable(service, xmlDoc)
{
    require('events').EventEmitter.call(this, true)
        .createEvent('changed')

    this.service = service;
    this.name = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'name')[0].textContent;
    this.dataType = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'dataType')[0].textContent;
    this.evented = xmlDoc.attributes.get('sendEvents').value;
    if (this.evented == 'yes')
    {
        this.currentValue = null;
    }
}
function upnpservice_parseScpd(scpd)
{
    this.stateVariables = []; Object.defineProperty(this.stateVariables, "get", { value: function (name) { for (var i in this) { if (this[i].name == name) { return (this[i]); } } return (undefined); } });
    this.actions = []; Object.defineProperty(this.actions, "get", { value: function (name) { for (var i in this) { if (this[i].name == name) { return (this[i]); } } return (undefined); } });
    var doc = parseXml(scpd);
    var stateTable = doc.getElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'serviceStateTable');
    if (stateTable.length > 0)
    {
        var variables = stateTable[0].getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'stateVariable');
        for (var i in variables)
        {
            this.stateVariables.push(new upnpvariable(this, variables[i]));
        }
    }

    var actionList = doc.getElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'actionList');
    if (actionList.length > 0)
    {
        var actions = actionList[0].getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'action');
        for (var i in actions)
        {
            try 
	    {
                this.actions.push(new upnpaction(this, actions[i]));
            }
            catch (e) 
	    {
                this.device.rootDevice.emit('error', 'error parsing SCPD/Action: ' + e);
                return;
            }
        }
    }

    // Subscribe for UPnP Events
    this.subscribe = function ()
    {
        var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
        // First make sure our listening server is up
        this.device.rootDevice._startEventServer();

        // Now send an event subcription
        var options = http.parseUri(this.eventSubURL);
        options.method = 'SUBSCRIBE';
        options.headers =
            {
                HOST: options.host,
                TIMEOUT: 'Second-300',
                NT: 'upnp:event',
                CALLBACK: '<http://' + this.device.rootDevice._eventServer.address().address + ':' + this.device.rootDevice._eventServer.address().port + '/' + this.device.UDN + '/' + this.serviceId + '>'
            };
        console.info1(JSON.stringify(options));
        this.subreq = http.request(options);
        this.subreq.promise = ret;
        this.subreq.service = this;
        this.subreq.end();
        this.subreq.on('response', function (msg)
        {
            if (msg.statusCode == 200)
            {
                this.promise._res(msg);
            }
            else
            {
                this.promise._rej(msg);
                return;
            }
            this.service._sid = msg.headers.SID;
        });
        return (ret);
    };
    this.notify = function notify(imsg)
    {
        imsg.service = this;
        imsg.str = '';
        imsg.on('data', function (chunk) { this.str += chunk.toString(); });
        imsg.on('end', function ()
        {
            var doc = parseXml(this.str);

            var propTable = doc.getElementsByTagNameNS('urn:schemas-upnp-org:event-1-0', 'propertyset')[0];
            var properties = propTable.getChildElementsByTagNameNS('urn:schemas-upnp-org:event-1-0', 'property');
            for (var i in properties)
            {
                for (var v in this.service.stateVariables)
                {
                    if(this.service.stateVariables[v].name == properties[i].childNodes[0].localName)
                    {
                        if(this.service.stateVariables[v].evented == 'yes')
                        {
                            this.service.stateVariables[v].currentValue = properties[i].childNodes[0].textContent;
                            this.service.stateVariables[v].emit('changed', properties[i].childNodes[0].textContent);
                            this.service.emit('stateVariableChanged', this.service.stateVariables[v]);
                        }
                    }
                }
            }
        });
    }
    this.device.rootDevice.emit('serviceLoaded', this);
}

function upnpdevice_child(rootDevice, xmlDoc)
{
    this.rootDevice = rootDevice;
    this.services = []; Object.defineProperty(this.services, "get", { value: function (id) { for (var i in this) { if (this[i].serviceType == id || this[i].serviceId == id) { return (this[i]); } } return (undefined); } });
    this.embeddedDevices = []; Object.defineProperty(this.embeddedDevices, "get", { value: function (id) { for (var i in this) { if (this[i].UDN == id || this[i].deviceType == id) { return (this[i]); } } return (undefined); } });

    var emitterUtils = require('events').inherits(this);
    emitterUtils.createEvent('bye');
    emitterUtils.createEvent('error');

    this.locationUrl = rootDevice.locationUrl;
    this.friendlyName = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'friendlyName')[0].textContent;
    this.deviceType = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'deviceType')[0].textContent;
    this.UDN = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'UDN')[0].textContent;
    this.manufacturer = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'manufacturer')[0].textContent;

    var serviceList = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'serviceList')[0]
    for (var i in serviceList.childNodes)
    {
        if(serviceList.childNodes[i].namespace == 'urn:schemas-upnp-org:device-1-0')
        {
            this.services.push(new upnpservice(this, serviceList.childNodes[i]));
        }
    }

    var deviceList = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'deviceList')[0]

    if (deviceList != null)
    {
        var devices = deviceList.getChildElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'device')
        for (var device in devices)
        {
            this.embeddedDevices.push(new upnpdevice_child(rootDevice, devices[device]));
        }
        //console.log(devices);
    }
    this.loadAllServices = function () { for (var i in this.services) { this.services[i].load();} for (var i in this.embeddedDevices) { this.embeddedDevices[i].loadAllServices(); } };
    this.getDevice = function (udn)
    {
        if (this.UDN == udn || this.deviceType == udn) { return (this); }
        for(var ed in this.embeddedDevices)
        {
            var ret = this.embeddedDevices[ed].getDevice(udn);
            if (ret) { return (ret); }
        }
        return (undefined);
    };
    this.getService = function(id)
    {
        for (var s in this.services)
        {
            if (this.services[s].serviceId == id) { return (this.services[s]); }
        }
        return (undefined);
    }
}

function upnpdevice_parseXml(xml)
{
    this.dd = null;
    var doc = parseXml(xml);
    //var URLBase = doc.getElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'URLBase')[0];
    //if (URLBase != null) { console.log("old base: " + this.BaseURL); this.BaseURL = URLBase.textContent; }

    var root = doc.getElementsByTagNameNS('urn:schemas-upnp-org:device-1-0', 'device')[0];
    if (root != null)
    {
        this.rootDevice = new upnpdevice_child(this, root);
        if (!this.cp.searchString.startsWith('ssdp:') && !this.cp.searchString.startsWith('upnp:') && !this.cp.searchString.startsWith('urn:') && !this.cp.searchString.startsWith('uuid:'))
        {
            // Friendly Name Search
            if(this.rootDevice.friendlyName == this.cp.searchString)
            {
                //console.log(xml);
                this.rootDevice.loadAllServices();
            }
        }
        else
        {
            console.info1(this.cp.searchString.split(':')[0]);
            switch(this.cp.searchString.split(':')[0])
            {
                case 'ssdp':
                    break;
                case 'upnp':
                    this.rootDevice.loadAllServices();
                    break;
                case 'uuid':
                    this.rootDevice.loadAllServices();
                    break;
                case 'urn':
                    this.rootDevice.loadAllServices();
                    break;
            }
        }
        //console.log(this.rootDevice.friendlyName);
    }
}

function upnpcp_onSearch(msg, rinfo)
{
    var header = require('http-headers')(msg);
    if (header.statusCode != 200) { return; }
    var usn = header.headers.usn.split('::')[0];

    if(this.cp.deviceTable[usn] == null)
    {
        this.cp.deviceTable[usn] = new upnpdevice(header.headers.location, usn, this.cp, this.address().host);
        this.cp.deviceTable[usn].on('error', function (e) { console.info1('Removing Device/' + this.usn + ' due to error: ' + e); this.cp.deviceTable[this.usn] = null; });
        this.cp.deviceTable[usn].on('alive', function () { this.cp.emit('device', this); });
    }
}

function upnpcp(search)
{
    this.searchString = search;
    if (!search.startsWith('ssdp:') && !search.startsWith('upnp:') && !search.startsWith('uuid:') && !search.startsWith('urn:'))
    {
        // Search by Friendly Name
        search = 'upnp:rootdevice';
    }

    var MSEARCH = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ' + search + '\r\nMAN: "ssdp:discover"\r\nMX: 5\r\nContent-Length: 0\r\n\r\n';
    var emitterUtils = require('events').inherits(this);
    emitterUtils.createEvent('device');


    this.deviceTable = {};
    this.searchSockets = {};

    var interfaces = os.networkInterfaces();
    for(var name in interfaces)
    {
        for (var i in interfaces[name])
        {
            if (interfaces[name][i].family == 'IPv4' && interfaces[name][i].status == 'up')
            {
                var searchSocket = dgram.createSocket({ type: 'udp4' });
                this.searchSockets[interfaces[name][i].address] = searchSocket
                searchSocket.cp = this;
                searchSocket.bind({ port: 0, address: interfaces[name][i].address });
                searchSocket.on('message', upnpcp_onSearch);

                console.info1('Sending Multicast on: ' + interfaces[name][i].address + ' to: 239.255.255.250:1900');
                searchSocket.setMulticastTTL(1);
                searchSocket.setMulticastLoopback(true);
                searchSocket.setMulticastInterface(interfaces[name][i].address);
                searchSocket.send(MSEARCH, 1900, '239.255.255.250');
            }
        }
    }
}


//var testCP = new upnpcp("Samsung CLX-3300 Series (10.128.125.118)");

function display_device(dv, prefix)
{
    if (!dv) { console.log('No match'); return; }
    if (!prefix) { prefix = ''; }
    console.log(prefix + 'FriendlyName/ ' + dv.friendlyName);
    console.log(prefix + '   DeviceType/ ' + dv.deviceType);
    console.log(prefix + '   DeviceUDN/ ' + dv.UDN);

    for (var svc in dv.services)
    {
        //console.log(prefix + '   ServiceType/ ' + dv.services[svc].serviceType + ' (ServiceID/ ' + dv.services[svc].serviceId + ')');
        console.log(prefix + '   ServiceID/ ' + dv.services[svc].serviceId);
    }
    for (var ed in dv.embeddedDevices)
    {
        console.log(prefix + '      Embedded Device: ' + dv.embeddedDevices[ed].friendlyName + ' [' + dv.embeddedDevices[ed].UDN + ']');
        display_device(dv.embeddedDevices[ed], prefix + '         ');
    }
}
function display_action(action)
{
    var argString = null;
    for (var arg in action.arguments)
    {
        if (action.arguments[arg].direction == 'in')
        {
            if (argString)
            {
                argString += (', ' + action.arguments[arg].name);
            }
            else
            {
                argString = action.arguments[arg].name;
            }
        }
    }
    console.log('   ' + action.name + '(' + (argString?argString:'') + ')');
}
function display_actionDetail(action)
{
    if (!action) { console.log('no match'); return; }

    console.log('Action: ' + action.name);
    console.log('   Input Parameters:');
    console.log('      {');
    for (var arg in action.arguments)
    {
        if (action.arguments[arg].direction == 'in')
        {
            console.log('         [' + action.arguments[arg].relatedStateVariable.dataType + '] ' + action.arguments[arg].name);
        }
    }
    console.log('      }');
    console.log('   Output Parameters:');
    console.log('      {');
    for (var arg in action.arguments)
    {
        if (action.arguments[arg].direction == 'out')
        {
            console.log('         [' + action.arguments[arg].relatedStateVariable.dataType + '] ' + action.arguments[arg].name);
        }
    }
    console.log('      }');
}
function display_service(svc)
{
    if (!svc) { console.log('No match'); return; }
    console.log('ServiceID/ ' + svc.serviceId);
    console.log('ServiceType/ ' + svc.serviceType);
    console.log('Actions:');
    for(var action in svc.actions)
    {
        display_action(svc.actions[action]);
    }
}

module.exports.cp = upnpcp;
module.exports.displayDevice = display_device;
module.exports.displayService = display_service;
module.exports.displayActionDetail = display_actionDetail;


