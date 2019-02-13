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


var writable = require('stream').Writable;
var md5 = require('MD5Stream').create();

function checkEventForwarding(digestRequest, eventName)
{
    if (digestRequest.listenerCount(eventName) > 0)
    {
        var eForward = function _eForward()
        {
            var p = [eForward._eventName];
            for (var i = 0; i < arguments.length; ++i) { p.push(arguments[i]); }
            _eForward._digestRequest.emit.apply(_eForward._digestRequest, p);
        };
        eForward._eventName = eventName;
        eForward._digestRequest = digestRequest;
        digestRequest._request.on(eventName, eForward);
    }
}

function generateAuthHeaders(imsg, options, digest)
{
    var auth;

    if (imsg != null)
    {
        auth = { realm: null, nonce: null, opaque: null, qop: null };
        var www = imsg.headers['WWW-Authenticate'];
        var tokens = www.split(',');

        var pairs;
        for (var i in tokens)
        {
            pairs = tokens[i].split('=');
            if (pairs.length == 2)
            {
                switch (pairs[0].toLowerCase().trim())
                {
                    case 'digest realm':
                        auth.realm = pairs[1];
                        if (auth.realm[0] == '"') { auth.realm = auth.realm.substring(1, auth.realm.length - 1); }
                        break;
                    case 'nonce':
                        auth.nonce = pairs[1];
                        if (auth.nonce[0] == '"') { auth.nonce = auth.nonce.substring(1, auth.nonce.length - 1); }
                        break;
                    case 'opaque':
                        auth.opaque = pairs[1];
                        if (auth.opaque[0] == '"') { auth.opaque = auth.opaque.substring(1, auth.opaque.length - 1); }
                        break;
                    case 'qop':
                        auth.qop = pairs[1];
                        if (auth.qop[0] == '"') { auth.qop = auth.qop.substring(1, auth.qop.length - 1); }
                        break;
                }
            }
        }
        digest._auth = auth;
    }
    else
    {
        if (!(auth = digest._auth)) { return; }
    }

    var step1 = digest._options.username + ':' + auth.realm + ':' + digest._options.password;
    auth.step1 = md5.syncHash(step1).toString('hex').toLowerCase();

    var step2 = options.method + ':' + options.path;
    auth.step2 = md5.syncHash(step2).toString('hex').toLowerCase();


    if (auth.qop == null)
    {
        var step3 = auth.step1 + ':' + auth.nonce + ':' + auth.step2;
        auth.step3 = md5.syncHash(step3).toString('hex').toLowerCase();
    }
    else
    {
        digest._NC += 1;
        var step3 = auth.step1 + ':' + auth.nonce + ':' + digest._NC.toString(16).toLowerCase().padStart(8, '0') + ':' + digest._CNONCE + ':' + auth.qop + ':' + auth.step2;
        auth.step3 = md5.syncHash(step3).toString('hex').toLowerCase();
    }

    var ret = 'Digest username="' + digest._options.username + '",realm="' + auth.realm + '",nonce="' + auth.nonce + '",uri="' + options.path + '"';
    if (auth.opaque != null) { ret += (',opaque="' + auth.opaque + '"'); }
    ret += (',response="' + auth.step3 + '"');

    if (auth.qop != null)
    {
        ret += (',qop="' + auth.qop + '",nc="' + digest._NC.toString(16).toLowerCase().padStart(8, '0') + '",cnonce="' + digest._CNONCE + '"');
    }


    if (!options.headers) { options.headers = {}; }
    options.headers['Authorization'] = ret;
    return (ret);
}

function http_digest()
{
    this._ObjectID = "http-digest";
    this.create = function()
    {
        if(arguments.length == 1 && typeof(arguments[0] == 'object'))
        {
            return (new http_digest_instance(arguments[0]));
        }
        if(arguments.length == 2 && typeof(arguments[0]) == 'string' && typeof(arguments[1]) == 'string')
        {
            return (new http_digest_instance({username: arguments[0], password: arguments[1]}));
        }
        throw ('Invalid Parameters');
    }
}

function http_digest_instance(options)
{
    this._ObjectID = 'http-digest.instance';
    this._options = options;
    this.http = null;
    this._NC = 0;
    this._CNONCE = require('http').generateNonce(16);

    this.get = function(uri)
    {
        return (this.request(uri));
    }
    this.request = function (par1)
    {
        var callend = false;
        var ret = new writable(
            {
                write: function (chunk, flush)
                {
                    if (this._ended) { throw ('Stream already ended'); }
                    if(!this._buffered) 
                    {
                        this._buffered = Buffer.alloc(chunk.length);
                        chunk.copy(this._buffered);
                    }
                    else
                    {
                        this._buffered = Buffer.concat([this._buffered, chunk], this._buffered.length + chunk.length);
                    }

                    if (this._request) { this._request.write(chunk); }
                    if (flush != null) { flush(); }
                    return (true);
                },
                final: function (flush)
                {
                    if (this._ended) { throw ('Stream already ended'); }
                    this._ended = true;
                    if (this._request) { this._request.end(); }
                    if (flush != null) { flush(); }
                }
            });
        ret._buffered = null;
        ret._ended = false;
        switch (typeof (par1))
        {
            default:
                throw ('Invalid Parameter');
                break;
            case 'string':
                ret.options = this.http.parseUri(par1);
                callend = true;
                break;
            case 'object':
                ret.options = par1;
                break;
        }
        require('events').EventEmitter.call(ret, true)
            .createEvent('response')
            .createEvent('error')
            .createEvent('upgrade')
            .createEvent('continue')
            .createEvent('timeout');
        ret._digest = this;

        if (arguments.length > 1 && typeof (arguments[1]) == 'function')
        {
            ret.once('response', arguments[1]);
        }

        //
        // Check if we can add AuthHeaders now
        //
        generateAuthHeaders(null, ret.options, this);

        // When somebody hooks up events to digest.clientRequest, we need to hook the real event on http.clientRequest
        ret._request = this.http.request(ret.options);
        ret._request.digRequest = ret;
        ret.on('newListener', function (evName, callback)
        {
            if (evName != 'upgrade' && evName != 'error' && evName != 'continue' && evName != 'timeout' && evName != 'drain') { return; }
            if (this._request.listenerCount(evName) == 0)
            {
                var evSink = function _evSink()
                {
                    var parms = [_evSink.eventName];
                    for(var i=0;i<arguments.length;++i) {parms.push(arguments[i]);}
                    this.digRequest.emit.apply(this.digRequest, parms);
                };
                evSink.eventName = evName;
                this._request.on(evName, evSink);
            }
        });

        ret._request.once('response', function (imsg)
        {
            if (imsg.statusCode == 401)
            {
                var callend = this.digRequest._request._callend;
                var auth = generateAuthHeaders(imsg, this.digRequest.options, this.digRequest._digest);

                this.digRequest._request = this.digRequest._digest.http.request(this.digRequest.options);
                this.digRequest._request.digRequest = this.digRequest;
                this.digRequest._request.once('response', function (imsg)
                {
                    switch(imsg.statusCode)
                    {
                        case 401:
                            this.digRequest.emit('error', 'Digest failed too many times');
                            break;
                        default:
                            this.digRequest.emit('response', imsg);
                            break;
                    }
                });
                checkEventForwarding(this.digRequest, 'upgrade');
                checkEventForwarding(this.digRequest, 'error');
                checkEventForwarding(this.digRequest, 'continue');
                checkEventForwarding(this.digRequest, 'timeout');
                checkEventForwarding(this.digRequest, 'drain');
                if (callend)
                {
                    this.digRequest._request.end();
                }
                else
                {
                    if (this.digRequest._buffered) { this.digRequest._request.write(this.digRequest._buffered); }
                    if (this.digRequest._ended) { this.digRequest._request.end(); }
                }
            }
            else
            {
                this.digRequest.emit('response', imsg);
            }
        });
        if (callend)
        {
            ret._request._callend = true; ret._request.end();
        }
        else
        {
            if (ret._buffered) { ret._request.write(ret._buffered); }
            if (ret._ended) { ret._request.end(); }
        }
        return (ret);
    };
}


module.exports = new http_digest();

