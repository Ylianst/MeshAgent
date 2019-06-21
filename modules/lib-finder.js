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

function find(name)
{
	switch(process.platform)
	{
		case 'freebsd':
			var ret = [];
			var child = require('child_process').execFile('/bin/sh', ['sh']);
			child.stdout.str = '';
			child.stdout.on('data', function (c) { this.str += c.toString(); });
			child.stdin.write("pkg info " + name + " | tr '\\n' '\\|' | awk ' { a=split($0, t, \"Shared Libs provided:\"); if(a==2) { split(t[2], lib, \":\"); print lib[1]; } }' | tr '\\|' '\\n' | awk '{ if(split($1, res, \".so\")>1) { print $1; } }'\nexit\n");
			child.waitExit();
			var res = child.stdout.str.trim().split('\n');
			for(var i in res)
			{
				if(!res[i].startsWith(name + '.so')) { continue; }
				var v = {name: res[i]};
				child = require('child_process').execFile('/bin/sh', ['sh']);
				child.stdout.str = '';
				child.stdout.on('data', function (c) { this.str += c.toString(); });
				child.stdin.write('pkg info -l ' + name + ' | grep ' + v.name + ' | awk \'{ a=split($1, tok, "/"); if(tok[a]=="' + v.name + '") { print $1; } }\'\nexit\n');
				child.waitExit();
				v.location = child.stdout.str.trim();
				ret.push(v);
			}
			return(ret);
		break;
	}
}

module.exports = find;
