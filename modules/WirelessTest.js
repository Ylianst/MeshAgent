
var wifi = require('WiFiScanner');
var scanner = new wifi();

console.log('Has Wireless = ' + scanner.hasWireless());

if (scanner.hasWireless())
{
    scanner.on('accessPoint', function (ap)
    {
        console.log(ap);
    });
    scanner.Scan();
}