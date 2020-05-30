/*
Copyright 2018 Intel Corporation

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

var refTable = {};

function getRootPromise(obj)
{
    while(obj.parentPromise)
    {
        obj = obj.parentPromise;
    }
    return (obj);
}
function getDepth(obj)
{
    var count = 1;
    while (obj.parentPromise)
    {
        ++count;
        obj = obj.parentPromise;
    }
    return (count);
}

function event_switcher_helper(desired_callee, target, forward)
{
    this._ObjectID = 'event_switcher';
    this.func = function func()
    {
        var args = [];
        if (func.forward != null) { args.push(func.forward); }
        for(var i in arguments)
        {
            args.push(arguments[i]);
        }
        return (func.target.apply(func.desired, args));
    };
    this.func.desired = desired_callee;
    this.func.target = target;
    this.func.forward = forward;
    this.func.self = this;
}
function event_switcher(desired_callee, target)
{
    return (new event_switcher_helper(desired_callee, target));
}

function event_forwarder(sourceObj, sourceName, targetObj, targetName)
{
    sourceObj.on(sourceName,   (new event_switcher_helper(targetObj, targetObj.emit, targetName)).func);      
}

function Promise(promiseFunc)
{
    this._ObjectID = 'promise';
    this.promise = this;
    this._internal = { _ObjectID: 'promise.internal', promise: this, func: promiseFunc, completed: false, errors: false, completedArgs: [], rejStarted: false, rejCount: 0, depth: 0 };
    require('events').EventEmitter.call(this._internal);
    this._internal.on('newListener', function (eventName, eventCallback)
    {
        //console.log('newListener', eventName, 'errors/' + this.errors + ' completed/' + this.completed);
        var r = null;

        if (eventName == 'resolved' && !this.errors && this.completed)
        {
            r = eventCallback.apply(this, this.completedArgs);
            if(r!=null)
            {
                this.emit_returnValue('resolved', r);
            }
        }
        if (eventName == 'rejected' && this.errors && this.completed)
        {
            var rt = getRootPromise(this.promise);
            var ch = rt;
            var chx = 1;
            var ncnt = 1;
            while(ch)
            {
                if (ch._internal.listenerCount('rejected') > 0)
                {
                    ncnt += ch._internal.listenerCount('rejected');
                }
                chx++;
                ch = ch.__childPromise;
            }
            if (chx > rt._internal.depth) { rt._internal.depth = chx; }
            if (ncnt > rt._internal.rejCount) { rt._internal.rejCount = ncnt; }

            if (rt._internal._imm && rt._internal.rejCount >= rt._internal.depth)
            {
                clearImmediate(rt._internal._imm);
                rt._internal._imm = null;
                rt._internal._haltUncaught = true;
            }
            eventCallback.apply(this, this.completedArgs);
        }
        if (eventName == 'settled' && this.completed)
        {
            eventCallback.apply(this, []);
        }
    });
    this._internal.resolver = function _resolver()
    {
        if (_resolver._self.completed) { return; }
        _resolver._self.errors = false;
        _resolver._self.completed = true;
        _resolver._self.completedArgs = [];
        var args = ['resolved'];
        if (this.emit_returnValue && this.emit_returnValue('resolved') != null)
        {
            _resolver._self.completedArgs.push(this.emit_returnValue('resolved'));
            args.push(this.emit_returnValue('resolved'));
        }
        else
        {
            for (var a in arguments)
            {
                _resolver._self.completedArgs.push(arguments[a]);
                args.push(arguments[a]);
            }
        }
        if (args.length == 2 && args[1]!=null && typeof(args[1]) == 'object' && args[1]._ObjectID == 'promise')
        {
            var pr = getRootPromise(_resolver._self.promise);
            pr._internal._haltUncaught = true;
            args[1]._XSLF = _resolver._self;
            args[1].then(function ()
            {
                var parms = ['resolved'];
                for (var ai in arguments)
                {
                    parms.push(arguments[ai]);
                }
                this._XSLF.emit.apply(this._XSLF, parms);
            },
            function (e)
            {
                this._XSLF.promise.__childPromise.parentPromise = null;
                this._XSLF.promise.__childPromise._internal._haltUncaught = false;
                this._XSLF.promise.__childPromise._rej(e);
                //var parms = ['rejected', e];
                //this._XSLF.emit.apply(this._XSLF, parms);
            });
        }
        else
        {
            _resolver._self.emit.apply(_resolver._self, args);
            _resolver._self.emit('settled');
        }
    };
    this._internal.rejector = function _rejector()
    {
        if (_rejector._self.completed) { return; }
        _rejector._self.errors = true;
        _rejector._self.completed = true;
        _rejector._self.completedArgs = [];
        var args = ['rejected'];
        for (var a in arguments)
        {
            _rejector._self.completedArgs.push(arguments[a]);
            args.push(arguments[a]);
        }

        var r = getRootPromise(_rejector._self.promise);
        var me = false;
        if (r._internal.rejStarted == false)
        {
            r._internal.rejStarted = true;
            r._internal.rejCount = 0;
            r._internal.depth = 0;
            me = true;
        }

        var d = getDepth(_rejector._self.promise);
        if (d > r._internal.depth) { r._internal.depth = d; }

        if (_rejector._self.listenerCount('rejected') > 0)
        {
            r._internal.rejCount += _rejector._self.listenerCount('rejected');
        }

        _rejector._self.emit.apply(_rejector._self, args);
        if (me)
        {
            r._internal.rejStarted = false;
            if(r._internal.rejCount < r._internal.depth && !r._internal._imm && !r._internal._haltUncaught)
            {
                r._internal._imm = setImmediate(function (e, i) { i._imm = null; process.emit('uncaughtException', 'promise.uncaughtRejection: ' + e); }, args[1], r._internal);
            }
        }

        _rejector._self.emit('settled');
    };
    this.catch = function(func)
    {
        var rt = getRootPromise(this);
        if (rt._internal._imm) { clearInterval(rt._internal._imm); rt._internal._imm = null; }
        this._internal.once('rejected', event_switcher(this, func).func);
    }
    this.finally = function (func)
    {
        this._internal.once('settled', event_switcher(this, func).func);
    };
    this.then = function (resolved, rejected)
    {
        if (resolved) { this._internal.once('resolved', event_switcher(this, resolved).func); }
        if (rejected)
        {
            this._internal.once('rejected', event_switcher(this, rejected).func);
        }
                      
        var retVal = new Promise(function (r, j) { this._rej = j; });
        retVal._internal._haltUncaught = true;
        this._internal.once('resolved', retVal._internal.resolver);
        this._internal.once('rejected', retVal._internal.rejector);
        retVal.parentPromise = this;
        this.__childPromise = retVal;
        return (retVal);
    };

    this._internal.resolver._self = this._internal;
    this._internal.rejector._self = this._internal;;

    try
    {
        promiseFunc.call(this, this._internal.resolver, this._internal.rejector);
    }
    catch(e)
    {
        this._internal.errors = true;
        this._internal.completed = true;
        this._internal.completedArgs = [e];
        this._internal.emit('rejected', e);
        this._internal.emit('settled');
    }

    if(!this._internal.completed)
    {
        // Save reference of this object
        refTable[this._internal._hashCode()] = this._internal;
        this._internal.once('settled', function () { refTable[this._hashCode()] = null; });
    }
    Object.defineProperty(this, "completed", {
        get: function ()
        {
            return (this._internal.completed);
        }
    });
}

Promise.resolve = function resolve()
{
    var retVal = new Promise(function (r, j) { });
    var args = [];
    for (var i in arguments)
    {
        args.push(arguments[i]);
    }
    retVal._internal.resolver.apply(retVal._internal, args);
    return (retVal);
};
Promise.reject = function reject() {
    var retVal = new Promise(function (r, j) { });
    var args = [];
    for (var i in arguments) {
        args.push(arguments[i]);
    }
    retVal._internal.rejector.apply(retVal._internal, args);
    return (retVal);
};
Promise.all = function all(promiseList)
{
    var ret = new Promise(function (res, rej)
    {
        this.__rejector = rej;
        this.__resolver = res;
        this.__promiseList = promiseList;
        this.__done = false;
        this.__count = 0;
    });

    for (var i in promiseList)
    {
        promiseList[i].then(function ()
        {
            // Success
            if(++ret.__count == ret.__promiseList.length)
            {
                ret.__done = true;
                ret.__resolver(ret.__promiseList);
            }
        }, function (arg)
        {
            // Failure
            if(!ret.__done)
            {
                ret.__done = true;
                ret.__rejector(arg);
            }
        });
    }
    if (promiseList.length == 0)
    {
        ret.__resolver(promiseList);
    }
    return (ret);
};

module.exports = Promise;
module.exports.event_switcher = event_switcher;
module.exports.event_forwarder = event_forwarder;