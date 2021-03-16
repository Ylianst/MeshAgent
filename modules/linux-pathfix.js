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


function stdparser(c)
{
    this.str += c.toString();
}
function checkPath()
{
    if (process.platform == 'linux')
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', stdparser);
        child.stdout.str = ''; child.stdout.on('data', stdparser);
        child.stdin.write('echo $PATH | awk \'{ yes=0; a=split($0, b, ":"); for(x=1;x<=a;++x) { if(b[x]=="/sbin") { yes=1; } } print yes; }\'\nexit\n');
        child.waitExit();

        if (parseInt(child.stdout.str.trim()) == 0)
        {
            process.setenv('PATH', process.env['PATH'] + ':/sbin');
        }
        child = null;
    }
}

module.exports = checkPath;


