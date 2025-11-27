function getAuthToken()
{
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdin.write('ps -e -o user -o command | awk {\'printf "%s,",$1;$1="";printf "%s\\n", $0\'} | grep X\nexit\n');
    child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
    child.waitExit();

    var lines = child.stdout.str.split('\n');
    for (var i in lines) {
        var tokens = lines[i].split(',');
        if (tokens[0]) {
            var items = tokens[1].split(' ');
            for (var x = 0; x < items.length; ++x) {
                if (items[x] == '-auth' && items.length > (x + 1)) {
                    return (items[x + 1]);
                }
            }
        }
    }
    return (null);
}

console.log('AuthToken => ' + getAuthToken());
process.exit();
