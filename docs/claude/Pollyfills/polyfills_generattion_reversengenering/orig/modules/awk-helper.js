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

var child = { stdin: { str: '', write: function (v) { this.str += v.trim(); } } };
child.stdin.write("loginctl list-sessions | tr '\\n' '`' | awk '{");
child.stdin.write('printf "[";');
child.stdin.write('del="";');
child.stdin.write('n=split($0, lines, "`");');
child.stdin.write('for(i=1;i<n;++i)');
child.stdin.write('{');
child.stdin.write('   split(lines[i], tok, " ");');
child.stdin.write('   if((tok[2]+0)>=1000)');
child.stdin.write('   {');
child.stdin.write('      if(tok[4]=="" || tok[4]~/^pts\\//) { continue; }');
child.stdin.write('      printf "%s{\\"uid\\": \\"%s\\", \\"sid\\": \\"%s\\"}", del, tok[2], tok[1];');
child.stdin.write('      del=",";');
child.stdin.write('   }');
child.stdin.write('}');
child.stdin.write('printf "]";');
child.stdin.write("}'");
//child.stdin.write('\nexit\n');

child.stdin.write('\n\n\n');
require('clipboard')(child.stdin.str);

if (process.platform == 'linux')
{
    console.log('clipboard active for 5 seconds');
    var t = setTimeout(function () { process.exit(); }, 5000);
}
else
{
    process.exit();
}
