var nm = require('NetworkMonitor');
nm.on('change', function () { console.log("Change detected..."); });
nm.on('add', function (addr) { console.log("Address (" + addr + ") added"); });
nm.on('remove', function (addr) { console.log("Address (" + addr + ") removed"); });

console.log("Started Test");

function OnChange()
{
    var interfaces = require('os').networkInterfaces();
    for(var key in interfaces)
    {
        for (var i in interfaces[key])
        {
            console.log("Address ==> " + interfaces[key][i].address);
            console.log("  status ==> " + interfaces[key][i].status);
        }
    }
}
