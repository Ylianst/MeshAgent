
var WiFiScanner = require('WiFiScanner');
var scanner = new WiFiScanner();

scanner.on('accessPoint', function (ap) { console.log("[" + ap.bssid + "] (" + ap.lq + ") " + ap.ssid); });
if (scanner.hasWireless())
{
    console.log("This Computer has wireless");
    scanner.Scan();
}
else
{
    console.log("This Computer DOES NOT have wireless");
}

