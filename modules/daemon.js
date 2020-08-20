/*
Copyright 2020 Intel Corporation

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


function stdoutHandler(c)
{
    if (this.parent.parent.options.stdout) { process.stdout.write(c); }
}
function exitHandler(code)
{
    if (this.parent.options.crashRestart && code != this.parent.options.exit)
    {
        var tmp = start(this.parent.path, this.parent.parameters, this.parent.options);
        this.parent.child = tmp.child;
        this.parent.child.parent = this.parent;
    }
    else
    {
        this.parent.emit('done');
    }
}

function start(path, parameters, options)
{
    if (options == null) { options = {}; }
    if (options.exit == null) { options.exit = 0; }
    var ret = { options: options, path: path, parameters: parameters };
    require('events').EventEmitter.call(ret, true)
        .createEvent('done');
    ret.child = require('child_process').execFile(path, parameters, ret.options);
    ret.child.parent = ret;
    ret.child.stdout.on('data', stdoutHandler);
    ret.child.stderr.on('data', stdoutHandler);
    ret.child.on('exit', exitHandler);
    return (ret);
}

function agent()
{
    var args = process.argv;
    args.splice(1, 1);
    start(process.execPath, args, { crashRestart: true, exit: 6565 }).on('done', function () { process.exit(); });
}

module.exports = { start: start, agent: agent };