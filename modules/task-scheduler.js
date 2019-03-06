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
var servicemanager = require('service-manager');
var mgr = new servicemanager();

//attachDebugger({ webport: 9995, wait: 1 }).then(console.log);

function task()
{
    this._ObjectID = 'task-scheduler';

    this.create = function create(options)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        if(options.name && options.service)
        {
            switch(process.platform)
            {
                case 'win32':
                    var parms = ['schtasks', '/Create', '/RU SYSTEM'];
                    for (var ftype in options)
                    {
                        switch(ftype.toUpperCase())
                        {
                            case 'MINUTE':
                            case 'HOURLY':
                            case 'DAILY':
                            case 'WEEKLY':
                            case 'MONTHLY':
                                parms.push('/SC ' + ftype.toUpperCase());
                                parms.push('/MO ' + options[ftype]);
                                break;
                            case 'NAME':
                                parms.push('/TN "' + options[ftype].split('/').join('\\') + '"');
                                break;
                            case 'SERVICE':
                                parms.push('/TR "net start ' + options[ftype] + '"');
                                break;
                        }
                    }
                    console.log(parms.join(' '));
                    ret.child = require('child_process').execFile(process.env['windir'] + '\\system32\\schtasks.exe', parms);
                    ret.child.stdout.str = '';
                    ret.child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    ret.child.stderr.on('data', function (chunk) { });
                    ret.child.promise = ret;
                    ret.child.on('exit', function (code) { if (code == 0) { this.promise._res(); } else { this.promise._rej(code); }}); 
                    break;
                default:
                    ret._rej('Not implemented on ' + process.platform);
                    break;
            }
        }
        else
        {
            ret._rej('Invalid Parameers');
        }
        return (ret);
    };
    this.info = function info(name)
    {
    };
    this.delete = function _delete(name)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        switch (process.platform)
        {
            case 'win32':
                ret.child = require('child_process').execFile(process.env['windir'] + '\\system32\\schtasks.exe', ['schtasks', '/Delete', '/TN "' + name.split('/').join('\\') + '"', '/F']);
                ret.child.stdout.str = '';
                ret.child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                ret.child.stderr.on('data', function (chunk) { });
                ret.child.promise = ret;
                ret.child.on('exit', function (code) { if (code == 0) { this.promise._res(); } else { this.promise._rej(code); } });
                break;
            default:
                ret._rej('Not implemented on ' + process.platform);
                break;
        }
        return (ret);
    };
}


module.exports = new task();

