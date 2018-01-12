var amt_heci = require('amt_heci');
var amt = new amt_heci();

amt.getProtocolVersion(function (result)
{
    console.log('protocol version = ' + result);
});
amt.on('error', function (e) { console.log(e);});
amt.on('connect', function()
{
	console.log("Connected!");
	
	this.getVersion(OnVersion);
	this.getProvisioningState(OnProvisioningState);
	this.getProvisioningMode(OnProvisioningMode);
	this.getEHBCState(OnEHBC);
	this.getControlMode(OnEHBC);
	this.getMACAddresses(OnEHBC);
	this.getDnsSuffix(OnDns);
	this.getCertHashEntries(OnHashEntries);
	//this.getHashHandles(OnGetHashHandles);
});
function OnGetHashHandles(handles)
{
    console.log(handles.length + " HashHandles");
    for (var i = 0; i < handles.length; ++i)
    {
        amt.getCertHashEntry(handles[i], OnEHBC);
    }
}
function OnHashEntries(entries)
{
    for(var i=0;i<entries.length;++i)
    {
        console.log(entries[i]);
    }
}
function OnDns(dns)
{
    console.log("Dns Suffix = " + dns);
}
function OnVersion(val)
{
	console.log("Bios Version = " + val.BiosVersion.toString());
	for(var version in val.Versions)
	{
		console.log("   " + val.Versions[version].Description + " = " + val.Versions[version].Version);
	}
}
function OnProvisioningState(state)
{
	console.log("ProvisioningState = " + state);
}
function OnProvisioningMode(result)
{
    console.log("ProvisioningMode = " + result.mode + "  [Legacy = " + result.legacy + "]");
}
function OnEHBC(result)
{
    console.log(result);
}
