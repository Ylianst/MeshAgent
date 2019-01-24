var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdin.write('ps -e -o user -o command | awk {\'printf "%s,",$1;$1="";printf "%s\\n", $0\'} | grep X\nexit\n');
child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
child.waitExit();

var lines = child.stdout.str.split('\n');
for (var i in lines)
{
    var tokens = lines[i].split(',');
    console.log(tokens[0] + ' => ' + tokens[1]);
}


//console.log(child.stdout.str);
process.exit();
