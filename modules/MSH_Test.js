
var fs = require('fs');

var options = { sourceFileName: process.execPath, destinationStream: fs.createWriteStream('test.exe', { flags: 'wb' }), msh: 'WebProxy: proxy.jf.intel.com:911' };

options.destinationStream.on('finish', function () { console.log('finished'); process.exit(); });

require('MSH_Installer')(options);
