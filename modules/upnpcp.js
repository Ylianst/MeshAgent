
var parseXml = require('parseXml');
var http = require('http');
var dgram = require('dgram');
var os = require('os');
var MemoryStream = require('MemoryStream');
var net = require('net');

//var networkMonitor = require('NetworkMonitor');

function upnpdevice(descriptionUrl, usn, cp)
{
    var d = descriptionUrl.split('/');
    this.BaseURL = d[0] + '//' + d[2];
    var emitterUtils = require('events').inherits(this);
    emitterUtils.createEvent('bye');
    emitterUtils.createEvent('error');
    emitterUtils.createEvent('alive');
    emitterUtils.createEvent('serviceLoaded');
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
            this.cp.emit('device', this);
        }
    });
    this.getDevice = function (udn)
    {
        return (this.rootDevice.getDevice(udn));
    };
}

function upnpdevice_Cleanup()
{
    console.log('Finalizing: ' + this.rootDevice.friendlyName);
}
function upnpservice(parentDevice, xmlDoc)
{
    var emitterUtils = require('events').inherits(this);
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
}

function upnpargument(action, xmlDoc)
{
    this.action = action;
    this.name = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'name')[0].textContent;
    this.direction = xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'direction')[0].textContent;
    this.relatedStateVariable = action.service.stateVariables.get(xmlDoc.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'relatedStateVariable')[0].textContent);
}

function post_response(msg)
{
    if (msg.statusCode != 200)
    {
        var userArgs = this.args;
        if (userArgs.length > 0 && typeof (userArgs[0] == 'function'))
        {
            var fn = userArgs.shift();
            userArgs.unshift(msg.StatusCode ? msg.StatusCode : msg.url);
            fn.apply(this.action, userArgs);
        }
        return;
    }

    var buff = new MemoryStream();
    buff.req = this;
    msg.pipe(buff);
    buff.on('end', function ()
    {
        var body = {};
        var xml = parseXml(this.buffer.toString());
        var action = this.req.action;
        var userArgs = this.req.args;
        var actionResponse = xml.getElementsByTagNameNS(action.service.serviceType, action.name + 'Response')[0];
        if(actionResponse)
        {
            for(var child in actionResponse.childNodes)
            {
                if(action.arguments.get(actionResponse.childNodes[child].name))
                {
                    body[actionResponse.childNodes[child].name] = actionResponse.childNodes[child].textContent;
                }
            }
            if(userArgs.length > 0 && typeof(userArgs[0]) == 'function')
            {
                var fn = userArgs.shift();
                userArgs.unshift(body);
                fn.apply(action, userArgs);
            }
        }

    });
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
        var parameters = '';
        for (var i in this.arguments)
        {
            if(this.arguments[i].direction == 'in' &&  args[this.arguments[i].name])
            {
                parameters += ('<u:' + this.arguments[i].name + '>' + args[this.arguments[i].name] + '</u:' + this.arguments[i].name + '>');
            }
            else if(this.arguments.direction == 'in')
            {
                throw ('missing parameter: [' + this.arguments[i].name + '] when invoking Action: ' + this.name);
            }
        }

        var controlUri = http.parseUri(this.service.controlURL);
        console.log(controlUri);
        var headers = { HOST: (controlUri.host + ':' + controlUri.port), SOAPACTION: '"' + this.service.serviceType + '#' + this.name + '"', 'Content-Type': 'text/xml; charset="utf-8"' };
        this.pendingPosts.push(http.request({ protocol: 'http', host: controlUri.host, port: controlUri.port, method: 'POST', path: controlUri.path, headers: headers }));
        this.pendingPosts.peek().action = this;
        this.pendingPosts.peek().args = [];
        for (var i = 1; i < arguments.length; ++i)
        {
            this.pendingPosts.peek().args.push(arguments[i]);
        }
        this.pendingPosts.peek().on('response', post_response);

        var txt = '<?xml version="1.0" encoding="utf-8"?>\r\n<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>';
        this.pendingPosts.peek().write(txt);
        console.log(txt);

        txt = '<u:' + this.name + ' xmlns:u="' + this.service.serviceType + '">';
        this.pendingPosts.peek().write(txt);
        console.log(txt);

        if (parameters != '')
        {
            this.pendingPosts.peek().write(parameters);
            console.log(parameters);
        }
        this.pendingPosts.peek().write('</u:' + this.name + '>');
        this.pendingPosts.peek().write('</s:Body></s:Envelope>');

        console.log('</u:' + this.name + '>' + '</s:Body></s:Envelope>');

        this.pendingPosts.peek().end();
    };
    this.invokeLegacy = function (args)
    {
        var controlUri = http.parseUri(this.service.controlURL);
        var parameters = '';
        for (var i in this.arguments) {
            if (this.arguments[i].direction == 'in' && args[this.arguments[i].name]) {
                parameters += ('<u:' + this.arguments[i].name + '>' + args[this.arguments[i].name] + '</u:' + this.arguments[i].name + '>');
            }
            else if (this.arguments.direction == 'in') {
                throw ('missing parameter: [' + this.arguments[i].name + '] when invoking Action: ' + this.name);
            }
        }

        this.pendingPosts.push(net.connect({ host: controlUri.host, port: controlUri.port }));
        this.pendingPosts.peek().path = controlUri.path;
        this.pendingPosts.peek().args = args;
        this.pendingPosts.peek().parameters = parameters;
        this.pendingPosts.peek().action = this;
        this.pendingPosts.peek().headers = { HOST: (controlUri.host + ':' + controlUri.port), SOAPACTION: '"' + this.service.serviceType + '#' + this.name + '"', 'Content-Type': 'text/xml; charset="utf-8"' };
        this.pendingPosts.peek().on('connect', function ()
        {
            console.log('legacy connected');
            this.write('POST ' + this.path + ' HTTP/1.1\r\n');
            var headers = this.headers;
            this.write('HOST: ' + headers.HOST + '\r\n');
            this.write('SOAPACTION: ' + headers.SOAPACTION + '\r\n');
            this.write('Content-Type: ' + headers['Content-Type'] + '\r\n');

            var txt = '<?xml version="1.0" encoding="utf-8"?>\r\n<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>';
            txt += '<u:' + this.action.name + ' xmlns:u="' + this.action.service.serviceType + '">';
            txt += this.parameters;
            txt += ('</u:' + this.name + '>' + '</s:Body></s:Envelope>');
            
            var b = Buffer.from(txt);
            this.write('Content-Length: ' + b.length + '\r\n\r\n');
            this.write(b);
        });
        this.pendingPosts.peek().http = http.createStream();
        this.pendingPosts.peek().pipe(this.pendingPosts.peek().http);
        this.pendingPosts.peek().http.on('response', post_response);
    };
}
function upnpvariable(service, xmlDoc)
{
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

    var stateTable = doc.getElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'serviceStateTable')[0];
    var variables = stateTable.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'stateVariable');
    for (var i in variables)
    {
        this.stateVariables.push(new upnpvariable(this, variables[i]));
    }

    var actionList = doc.getElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'actionList')[0];
    var actions = actionList.getChildElementsByTagNameNS('urn:schemas-upnp-org:service-1-0', 'action');
    for (var i in actions)
    {
        try
        {
            this.actions.push(new upnpaction(this, actions[i]));
        }
        catch(e)
        {
            this.device.rootDevice.emit('error', 'error parsing SCPD/Action: ' + e);
            return;
        }
    }

    this.subscribe = function ()
    {

    };
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
        if (this.UDN == udn) { return (this); }
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
            console.log(this.cp.searchString.split(':')[0]);
            switch(this.cp.searchString.split(':')[0])
            {
                case 'ssdp':
                    break;
                case 'upnp':
                    this.rootDevice.loadAllServices();
                    break;
                case 'uuid':
                    break;
                case 'urn':
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
        this.cp.deviceTable[usn] = new upnpdevice(header.headers.location, usn, this.cp);
        this.cp.deviceTable[usn].on('error', function (e) { console.log('Removing Device/' + this.usn + ' due to error: ' + e); this.cp.deviceTable[this.usn] = null; });
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

    this.searchSocket = dgram.createSocket({ type: 'udp4' });
    this.searchSocket.cp = this;
    this.searchSocket.bind({ port: 0, address:'0.0.0.0' });
    this.deviceTable = {};

    this.searchSocket.on('message', upnpcp_onSearch);

    var interfaces = os.networkInterfaces();
    for(var name in interfaces)
    {
        for (var i in interfaces[name])
        {
            if (interfaces[name][i].family == 'IPv4' && interfaces[name][i].status == 'up')
            {
                console.log('Sending Multicast on: ' + interfaces[name][i].address + ' to: 239.255.255.250:1900');
                this.searchSocket.setMulticastTTL(1);
                this.searchSocket.setMulticastLoopback(true);
                this.searchSocket.setMulticastInterface(interfaces[name][i].address);
                this.searchSocket.send(MSEARCH, 1900, '239.255.255.250');
            }
        }
    }
}


//var testCP = new upnpcp("Samsung CLX-3300 Series (10.128.125.118)");

function display_device(dv)
{
    if (!dv) { console.log('No match'); return; }
    console.log('FriendlyName/ ' + dv.friendlyName);
    console.log('   DeviceType/ ' + dv.deviceType);
    console.log('   DeviceUDN/ ' + dv.UDN);

    for (var svc in dv.services)
    {
        console.log('   ServiceID/ ' + dv.services[svc].serviceId);
    }
    for (var ed in dv.embeddedDevices)
    {
        console.log('      Embedded Device: ' + dv.embeddedDevices[ed].friendlyName + ' [' + dv.embeddedDevices[ed].UDN + ']');
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

var testCP;

if (process.argv.length > 1)
{
    if(process.argv[1].startsWith('discover='))
    {
        testCP = new upnpcp(process.argv[1].split('=')[1]);
    }
}

if (!testCP) { process.exit(); }
testCP.on('device', function (dv)
{
    var selectedDevice = null;
    var selectedService = null;
    var selectedAction = null;

    console.log('');


    console.log('Device Added: ');
    display_device(dv.rootDevice);
    console.log('');
    

    for (var arg in process.argv)
    {
        if(process.argv[arg].startsWith('dv='))
        {
            var i = parseInt(process.argv[arg].split('=')[1]);
            console.log('Selected Embedded Device: ' + i);
            display_device(dv.rootDevice.embeddedDevices[i]);
            selectedDevice = dv.rootDevice.embeddedDevices[i];
        }
        if(process.argv[arg].startsWith('udn='))
        {
            console.log('Selected Device: ' + process.argv[arg].split('=')[1]);
            selectedDevice = dv.getDevice(process.argv[arg].split('=')[1]);
            display_device(selectedDevice);
        }
        if(selectedDevice && process.argv[arg].startsWith('serviceId='))
        {
            selectedService = selectedDevice.getService(process.argv[arg].split('=')[1]);
            display_service(selectedService);
        }
        if(selectedService && process.argv[arg].startsWith('action='))
        {
            selectedAction = selectedService.getAction(process.argv[arg].split('=')[1]);
            display_actionDetail(selectedAction);
        }
        if(selectedAction && process.argv[arg].startsWith('invoke='))
        {
            var txt = process.argv[arg].split('=')[1];

            console.log('Invoking with: ' + txt);
            selectedAction.invoke(JSON.parse(process.argv[arg].split('=')[1]), function ()
            {
                console.log('Response: ', arguments[0]);
                process.exit();
            });
        }
        if (selectedAction && process.argv[arg].startsWith('invokeLegacy=')) {
            var txt = process.argv[arg].split('=')[1];

            console.log('Invoking with: ' + txt);
            selectedAction.invokeLegacy(JSON.parse(process.argv[arg].split('=')[1]), function () {
                console.log('Response: ', arguments[0]);
                process.exit();
            });
        }
    }

});


