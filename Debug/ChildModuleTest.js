var parent = require('ScriptContainer');
var Wireless = require('Wireless');

Wireless.on('Scan', function (ap) { parent.send(ap.toString()); });
Wireless.Scan();
