
var manager = require('ILibProcessPipe');
var child = manager.CreateProcess("/sbin/iwlist", "iwlist", "wlan0", "scan");
var MemoryStream = require('MemoryStream');

var ms = new MemoryStream();
ms.on('end', function ()
{
    var str = this.buffer.toString();
    tokens = str.split(' - Address: ');
    for (var block in tokens)
    {
        var ln = tokens[block].split('\n');

        console.log("MAC Address = " + ln[0]);

        for(var lnblock in ln)
        {
            lnblock = ln[lnblock].trim();
            lnblock = lnblock.trim();
            if(lnblock.startsWith('ESSID:'))
            {
                console.log("SSID = " + lnblock.slice(6));
            }
            if(lnblock.startsWith('Signal level='))
            {
                console.log("Signal Strength = " + lnblock.slice(13));
            }
        }
        console.log("");
    }
});

console.log("starting...");
child.on('data', function (buffer) { ms.write(buffer); });
child.on('end', function () { ms.end(); });

//child.write("iwlist wlan0 scan\n");