var heci = require('heci');
var amt = null;

console.log("Starting HECI test...");
console.log("LME GUID = " + heci.GUIDS.LME.toString('hex'));
console.log("AMT GUID = " + heci.GUIDS.AMT.toString('hex'));
heci.doIoctl(heci.IOCTL.HECI_VERSION, null, new Buffer(16), OnVersion);

function OnVersion(status, buffer, arg)
{
    if(status == 0)
    {
        console.log("HECI Driver Version = " + buffer[0] + "." + buffer[1]);
        console.log("Attempting to create AMT/HECI connection");
        amt = heci.create();
        amt.connect(heci.GUIDS.AMT);
        amt.on('connect', OnAMT);
        amt.on('error', function (e) { console.log(e); });
    }
    else {
        console.log("Could not determine HECI Driver Version");
    }
}
function OnAMT()
{
    console.log('AMT Connected');
    amt.on('data', OnAMTData);

    var header = Buffer.from('010100001A00000400000000', 'hex');
    amt.write(header);
}

function OnAMTData(chunk)
{
    console.log('Received ' + chunk.length + ' bytes of AMT Data');
}