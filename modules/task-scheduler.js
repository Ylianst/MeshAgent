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
                            case 'DAY':
                                parms.push('/D ' + options[ftype]);
                                break;
                            case 'MONTH':
                                parms.push('/M ' + options[ftype]);
                                break;
                            case 'TIME':
                                parms.push('/ST ' + options[ftype]);
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
                case 'linux':
                    if (require('fs').existsSync('/etc/cron.d/' + options.name.split('/').join('_').split('.').join('')))
                    {
                        ret._rej('Task [' + options.name + '] Already exists');
                        return (ret);
                    }
                    var minute = '*';
                    var hour = '*';
                    var day = '*';
                    var month = '*';
                    var weekday = '*';
                    for (var ftype in options)
                    {
                        switch(ftype.toUpperCase())
                        {
                            case 'MINUTE':
                                if (!options.TIME && !options.time)
                                {
                                    minute = '*/' + options[ftype];
                                }
                                break;
                            case 'HOURLY':
                                if (!options.TIME && !options.time)
                                {
                                    hour = '*/' + options[ftype];
                                }
                                break;
                            case 'DAILY':
                                day = '*/' + options[ftype];
                                break;
                            case 'WEEKLY':
                                if (options[ftype] == 1)
                                {
                                    if(!options.DAY && !options.day)
                                    {
                                        weekday = 0;
                                    }
                                }
                                else
                                {
                                    ret._rej('Only Once/Weekly supported on Linux');
                                    return (ret);
                                }
                                break;
                            case 'DAY':
                                if (options.weekly || options.WEEKLY)
                                {
                                    weekday = options[ftype];
                                }
                                else
                                {
                                    day = options[ftype];
                                }
                                break;
                            case 'TIME':
                                hour = options[ftype].split(':')[0];
                                minute = options[ftype].split(':')[1];
                                break;
                            case 'MONTHLY':
                                month = '*/' + options[ftype];
                                break;
                        }
                    }

                    var action = 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n';
                    action += (minute + ' ' + hour + ' ' + day + ' ' + month + ' ' + weekday + '   root   ');
                    switch(require('service-manager').manager.getServiceType())
                    {
                        case 'init':
                        case 'upstart':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.str = '';
                            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stderr.on('data', function (chunk) { });
                            child.stdin.write("whereis service | awk '{print $2}'\n\exit\n");
                            child.waitExit();
                            child.stdout.str = child.stdout.str.trim();
                            action += (child.stdout.str + ' ' + options.service + ' restart >/dev/null 2>&1 \n');
                            break;
                        case 'systemd':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.str = '';
                            child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stderr.on('data', function (chunk) { });
                            child.stdin.write("whereis systemctl | awk '{print $2}'\n\exit\n");
                            child.waitExit();
                            child.stdout.str = child.stdout.str.trim();
                            action += (child.stdout.str + ' restart ' + options.service + ' >/dev/null 2>&1 \n');
                            break;
                        default:
                            ret._rej('Unknown Service Platform: ' + require('service-manager').manager.getServiceType());
                            return (ret);
                    }
                    try
                    {
                        var m = require('fs').CHMOD_MODES.S_IRUSR | require('fs').CHMOD_MODES.S_IWUSR | require('fs').CHMOD_MODES.S_IROTH;
                        require('fs').writeFileSync('/etc/cron.d/' + options.name.split('/').join('_').split('.').join(''), action, { flags: 'wb', mode: m });
                    }
                    catch(e)
                    {
                        ret._rej(e);
                        return (ret);
                    }
                    ret._res();
                    break;
                default:
                    ret._rej('Not implemented on ' + process.platform);
                    break;
            }
        }
        else
        {
            ret._rej('Invalid Parameters, must at least specify name and service');
        }
        return (ret);
    };
    this.info = function info(name)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        switch (process.platform)
        {
            default:
                ret._rej('Not implemented on ' + process.platform);
                break;
        }
        return (ret);
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
            case 'linux':
                if (require('fs').existsSync('/etc/cron.d/' + name.split('/').join('_').split('.').join('')))
                {
                    try
                    {
                        require('fs').unlinkSync('/etc/cron.d/' + name.split('/').join('_').split('.').join(''));
                    }
                    catch(e)
                    {
                        ret._rej(e);
                    }
                }
                else
                {
                    ret._rej('Task [' + name + '] does not exist');
                }
                break;
            default:
                ret._rej('Not implemented on ' + process.platform);
                break;
        }
        return (ret);
    };
}


module.exports = new task();

