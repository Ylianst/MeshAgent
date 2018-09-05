

function heciRedirector()
{
    this.redirect = function redirect(options)
    {
        options.protocol = 'ws:';
        options.method = 'GET';
        options.path = '/heciRedirect'
        var heciRedirect =
            {
                ObjectID: 'heci.heciRedirect',
                create: function create()
                {
                    console.log('Heci Redirection: Create()');
                    var stream = require('stream');
                    var retVal = new stream.Duplex({
                        read: function read()
                        {
                            console.log('read');
                        },
                        write: function write(chunk, callback)
                        {
                            console.log('received chunk of ' + chunk.length + ' bytes');
                            this.request._WS.WriteDrains.push(callback);
                            this.request._WS.write(chunk, function onWriteFlushed() { this.WriteDrains.shift().apply(this, []);});
                        },
                        final: function final()
                        {
                        }
                    });

                    retVal._ObjectID = 'heci.redirectedSession';
                    retVal.GUIDS = this.GUIDS;
                    retVal.options = this.options;
                    retVal.parent = this;
                    retVal.request = require('http').request(this.options);
                    console.log('HECI Redirection Client', this.options);
                    var utils = require('events').inherits(retVal);
                    utils.createEvent('connect');
                    utils.createEvent('error');

                    retVal.request.redirector = retVal;
                    retVal.request.on('upgrade', function onclientUpgrade(resp, sck, head)
                    {
                        console.log('Heci Redirection Tunnel established');
                        this._WS = sck;
                        this._WS.redirector = this.redirector;
                        this._WS.WriteDrains = [];
                        sck.on('data', function onClientRedirectData(chunk)
                        {
                            if (typeof chunk == 'string')
                            {
                                var cmd = JSON.parse(chunk);
                                switch(cmd.Command)
                                {
                                    case 'Event':
                                        console.log('emitting [' + cmd.Name + ']');
                                        this.redirector.emit(cmd.Name, cmd.Data);
                                        console.log('done emitting');
                                        break;
                                }
                            }
                            else
                            {
                                if (chunk.length > 0)
                                {
                                    console.log('pushing');
                                    if(!this.redirector.push(chunk))
                                    {
                                        this.pause();
                                    }
                                }
                            }
                        });
                        if (this.redirector.connectcmd)
                        {
                            console.log('writing connect command');
                            this._WS.write(JSON.stringify(this.redirector.connectcmd));
                        }
                    });
                    retVal.request.on('error', function onRequestError(e) { console.log('Could not connect HECI tunnel', e); });
                    utils.addMethod('connect', function _connect(target, options)
                    {
                        // This method needs to be added using utils, because it needs to be added as a defproperty, due to the event of the same name
                        console.log('HECI Redirection Client: Connect');
                        var cmd = { Command: 'Connect', Data: { Service: target, Options: options } };
                        if (!this._WS) { this.connectcmd = cmd; }
                        else
                        {
                            this._WS.write(JSON.stringify(cmd));
                        }
                    });
                    retVal.disconnect = function disconnect()
                    {
                        console.log('disconnecting');
                        this.request._WS.end();
                        delete this.request._WS;
                        this.request._WS = null;
                    };
                    retVal.request.end();
                    return (retVal);
                },
                GUIDS: { LME: 'LME', AMT: 'AMT' },
                options: options
            };
        addModuleObject('heci', heciRedirect);
    };
    this.listen = function listen(options)
    {
        console.log('Starting Heci Redirection Server on port: ' + options.port);
        this._server = require('http').createServer();
        this._server.redirector = this;
        this._server.options = options;
        this._server.listen(options);
        this._server.on('upgrade', function onUpgrade(req, sck, head)
        {
            this.redirector.WS = sck.upgradeWebSocket();
            this.redirector.WS.redirector = this.redirector;
            console.log('Heci Redirection Tunnel Established');
            this.redirector.WS.on('data', function onRedirectorServerData(chunk)
            {
                if(typeof chunk == 'string')
                {
                    var cmd = JSON.parse(chunk);
                    switch(cmd.Command)
                    {
                        default:
                            console.log('Unknown Command: ' + cmd.Command);
                            delete this.redirector.WS;
                            this.end();
                            break;
                        case 'Connect':
                            console.log("'Connect' received'");
                            this.heci = require('heci').create();
                            this.heci.WS = this;
                            this.heci.WS.redirector = this;
                            switch(cmd.Data.Service)
                            {
                                case 'AMT':
                                    console.log('Connecting to PTHI Service');
                                    this.heci.connect(require('heci').GUIDS.AMT, cmd.Data.Options);
                                    break;
                                case 'LME':
                                    console.log('Connecting to LME Service')
                                    this.heci.connect(require('heci').GUIDS.LME, cmd.Data.Options);
                                    break;
                                default:
                                    console.log('Invalid Service Request: ' + cmd.Data.Service);
                                    delete this.redirector.WS;
                                    this.end();
                                    break;
                            }
                            this.heci.once('error', function onHeciError(e) { console.log('HECI Error: ', e); delete this.redirector.WS; this.end(JSON.stringify({ Command: 'Event', Name: 'error', Data: e.toString() })); });
                            this.heci.on('connect', function onHeciConnect()
                            {
                                console.log('HECI Service Connection Established');
                                this.WS.write(JSON.stringify({ Command: 'Event', Name: 'connect' }));
                                this.pipe(this.WS).pipe(this, { end: false });
                                this.WS.on('end', function wsEndSink() { console.log('HECI Session Closed'); this.redirector.end(); });
                            });
                            break;
                    }
                }
            });
        });
    };
}

module.exports = new heciRedirector();