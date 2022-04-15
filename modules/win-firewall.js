/*
Copyright 2020-2021 Intel Corporation
@author Bryan Roe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

const GM = require('_GenericMarshal');
var OleAut = GM.CreateNativeProxy('OleAut32.dll');
OleAut.CreateMethod('VariantClear');

const guidRWRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
const CLSID_NetFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
const CLSID_NetFwRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
const IID_INetFwPolicy2 = "{98325047-C671-4174-8D81-DEFCD3F03186}";
const IID_IEnumVARIANT = "{00020404-0000-0000-C000-000000000046}";
const IID_INetFwRule = '{AF230D27-BABA-4E42-ACED-F524F22CFCE2}';

const UnknownFunctions = ['QueryInterface', 'AddRef', 'Release'];
const FirewallFunctions = [
    'QueryInterface',
    'AddRef',
    'Release',
    'GetTypeInfoCount',
    'GetTypeInfo',
    'GetIDsOfNames',
    'Invoke',
    'get_CurrentProfileTypes',
    'get_FirewallEnabled',
    'put_FirewallEnabled',
    'get_ExcludedInterfaces',
    'put_ExcludedInterfaces',
    'get_BlockAllInboundTraffic',
    'put_BlockAllInboundTraffic',
    'get_NotificationsDisabled',
    'put_NotificationsDisabled',
    'get_UnicastResponsesToMulticastBroadcastDisabled',
    'put_UnicastResponsesToMulticastBroadcastDisabled',
    'get_Rules',
    'get_ServiceRestriction',
    'EnableRuleGroup',
    'IsRuleGroupEnabled',
    'RestoreLocalFirewallDefaults',
    'get_DefaultInboundAction',
    'put_DefaultInboundAction',
    'get_DefaultOutboundAction',
    'put_DefaultOutboundAction',
    'get_IsRuleGroupCurrentlyEnabled',
    'get_LocalPolicyModifyState'
];
const RulesFunctions = [
    'QueryInterface',
    'AddRef',
    'Release',
    'GetTypeInfoCount',
    'GetTypeInfo',
    'GetIDsOfNames',
    'Invoke',
    'get_Count',
    'Add',
    'Remove',
    'Item',
    'get__NewEnum'
];
const EnumVariantFunctions = [
    'QueryInterface',
    'AddRef',
    'Release',
    'Next',
    'Skip',
    'Reset',
    'Clone'
];
const RuleFunctions = [
    'QueryInterface',
    'AddRef',
    'Release',
    'GetTypeInfoCount',
    'GetTypeInfo',
    'GetIDsOfNames',    
    'Invoke',
    'get_Name',
    'put_Name',
    'get_Description',
    'put_Description',
    'get_ApplicationName',    
    'put_ApplicationName',
    'get_ServiceName',
    'put_ServiceName',
    'get_Protocol',
    'put_Protocol',
    'get_LocalPorts',
    'put_LocalPorts',
    'get_RemotePorts',
    'put_RemotePorts',
    'get_LocalAddresses',
    'put_LocalAddresses',
    'get_RemoteAddresses',
    'put_RemoteAddresses',
    'get_IcmpTypesAndCodes',
    'put_IcmpTypesAndCodes',
    'get_Direction',
    'put_Direction',
    'get_Interfaces',
    'put_Interfaces',
    'get_InterfaceTypes',
    'put_InterfaceTypes',
    'get_Enabled',
    'put_Enabled',
    'get_Grouping',
    'put_Grouping',
    'get_Profiles',
    'put_Profiles',
    'get_EdgeTraversal',
    'put_EdgeTraversal',
    'get_Action',
    'put_Action'
];
     
const protocolNumbers = [
    'HOPOPT',
    'ICMP',
    'IGMP',
    'GGP',
    'IPv4',
    'ST',
    'TCP',
    'CBT',
    'EGP',
    'IGP',
    'BBN-RCC-MON',
    'NVP-II',
    'PUP',
    'ARGUS',
    'EMCON',
    'XNET',
    'CHAOS',
    'UDP',
    'MUX',
    'DCN-MEAS',
    'HMP',
    'PRM',
    'XNS-IDP',
    'TRUNK-1',
    'TRUNK-2',
    'LEAF-1',
    'LEAF-2',
    'RDP',
    'IRTP',
    'ISO-TP4',
    'NETBLT',
    'MFE-NSP',
    'MERIT-INP',
    'DCCP',
    '3PC',
    'IDPR',
    'XTP',
    'DDP',
    'IDPR-CMTP',
    'TP++',
    'IL',
    'IPv6',
    'SDRP',
    'IPv6-Route',
    'IPv6-Frag',
    'IDRP',
    'RSVP',
    'GRE',
    'DSR',
    'BNA',
    'ESP',
    'AH',
    'I-NLSP',
    'SWIPE',
    'NARP',
    'MOBILE',
    'TLSP',
    'SKIP',
    'IPv6-ICMP',
    'IPv6-NoNxt',
    'IPv6-Opts',
    '',
    'CFTP',
    '',
    'SAT-EXPAK',
    'KRYPTOLAN',
    'RVD',
    'IPPC',
    '',
    'SAT-MON',
    'VISA',
    'IPCV',
    'CPNX',
    'CPHB',
    'WSN',
    'PVP',
    'BR-SAT-MON',
    'SUN-ND',
    'WB-MON',
    'WB-EXPAK',
    'ISO-IP',
    'VMTP',
    'SECURE-VMTP',
    'VINES',
    'TTP',
    'IPTM',
    'NSFNET-IGP',
    'DGP',
    'TCF',
    'EIGRP',
    'OSPFIGP',
    'Sprite-RPC',
    'LARP',
    'MTP',
    'AX.25',
    'IPIP',
    'MICP',
    'SCC-SP',
    'ETHERIP',
    'ENCAP',
    '',
    'GMTP',
    'IFMP',
    'PNNI',
    'PIM',
    'ARIS',
    'SCPS',
    'QNX',
    'A/N',
    'IPComp',
    'SNP',
    'Compaq-Peer',
    'IPX-in-IP',
    'VRRP',
    'PGM',
    '',
    'L2TP',
    'DDX',
    'IATP',
    'STP',
    'SRP',
    'UTI',
    'SMP',
    'SM',
    'PTP',
    'ISIS over IPv4',
    'FIRE',
    'CRTP',
    'CRUDP',
    'SSCOPMCE',
    'IPLT',
    'SPS',
    'PIPE',
    'SCTP',
    'FC',
    'RSVP-E2E-IGNORE',
    'Mobility Header',
    'UDPLite',
    'MPLS-in-IP',
    'manet',
    'HIP',
    'Shim6',
    'WESP',
    'ROHC',
    'Ethernet'
];

function ProfileMaskToString(mask)
{
    var val = [];
    if((mask & 0x1)==0x1) { val.push('DOMAIN');}
    if((mask & 0x2)==0x2) { val.push('PRIVATE');}
    if((mask & 0x4)==0x4) { val.push('PUBLIC');}
    return (val.join(', '));
}

function getRulesCount()
{
    return(getFirewallRules({count: true}));
}
function getFirewallRulesAsync2(p)
{
    var hr;
    var rule, tmp;
    OleAut.VariantClear(p.vvar);

    hr = p.enumerator.funcs.Next(p.enumerator.Deref(), 1, p.vvar, p.fetched);
    if (hr.Val == 0)
    {
        var pct = Math.floor(((p.counter++) / p.count) * 100);
        if (pct % 5 == 0)
        {
            if (p.evented == false)
            {
                p.emit('progress', pct + '%');
                p.evented = true;
            }
        }
        else
        {
            p.evented = false;
        }
        rule = GM.CreatePointer();
        tmp = p.vvar.Deref(8, GM.PointerSize);
        tmp.funcs = require('win-com').marshalFunctions(tmp.Deref(), UnknownFunctions);
        hr = tmp.funcs.QueryInterface(tmp.Deref(), require('win-com').CLSIDFromString(IID_INetFwRule), rule);
        rule.funcs = require('win-com').marshalFunctions(rule.Deref(), RuleFunctions);
        p.val.toBuffer().writeUInt32LE(0);

        if ((p.options && p.options.program && rule.funcs.get_ApplicationName(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0
            && p.options.program.toLowerCase() == p.val.Deref().Wide2UTF8.toLowerCase()) || !p.options || !p.options.program)
        {
            obj = {};
            obj._rule = rule;
            obj._rule._i = p.NetFwPolicy2;
            if (p.val.Deref().Val != 0)
            {
                obj.Program = p.val.Deref().Wide2UTF8;
            }
            else
            {
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_ApplicationName(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.Program = p.val.Deref().Wide2UTF8; }
            }
            p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Name(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.DisplayName = p.val.Deref().Wide2UTF8; }
            if (!p.options.minimal)
            {
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Description(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.Description = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_LocalPorts(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.LocalPorts = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_RemotePorts(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.RemotePorts = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_LocalAddresses(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.LocalAddresses = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_RemoteAddresses(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.RemoteAddresses = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_ApplicationName(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.Program = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_InterfaceTypes(rule.Deref(), p.val).Val == 0 && p.val.Deref().Val != 0) { obj.InterfaceTypes = p.val.Deref().Wide2UTF8; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Enabled(rule.Deref(), p.val).Val == 0) { obj.Enabled = p.val.Deref(0, 2).toBuffer().readInt16LE() != 0; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Direction(rule.Deref(), p.val).Val == 0)
                {
                    switch (p.val.Deref(0, 4).toBuffer().readInt32LE())
                    {
                        case 1: // INBOUND
                            obj.direction = 'inbound';
                            break;
                        case 2: // OUTBOUND
                            obj.direction = 'outbound';
                            break;
                        default: // UNKNOWN
                            break;
                    }
                }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Protocol(rule.Deref(), p.val).Val == 0) { obj.Protocol = protocolNumbers[p.val.Deref(0, 4).toBuffer().readInt32LE()]; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_EdgeTraversal(rule.Deref(), p.val).Val == 0) { obj.EdgeTraversalPolicy = p.val.Deref(0, 2).toBuffer().readInt16LE() != 0 ? 'Allow' : 'Block'; }
                p.val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Profiles(rule.Deref(), p.val).Val == 0) { obj.Profile = ProfileMaskToString(p.val.toBuffer().readUInt32LE()); }
            }
            p.emit('rule', obj);
            if (p.options.noResult != true) { p.arr.push(obj); }
            p.arr.push(obj);
        }
        setImmediate(getFirewallRulesAsync2, p);
    }
    else
    {
        p.resolve(p.options.noResult === true ? null : p.arr);
    }
}
function getFirewallRulesAsync(options)
{
    if (options == null) { options = {} };
    var promise = require('promise');
    var unknown = GM.CreatePointer();
    var ret = new promise(promise.defaultInit);
    ret.NetFwPolicy2 = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_NetFwPolicy2), require('win-com').IID_IUnknown);
    ret.NetFwPolicy2.funcs = require('win-com').marshalFunctions(ret.NetFwPolicy2, FirewallFunctions);
    ret.rules = GM.CreatePointer();
    ret.enumerator = GM.CreatePointer();
    ret.vvar = GM.CreateVariable(GM.PointerSize == 8 ? 24 : 16);
    ret.fetched = GM.CreateVariable(4);
    ret.options = options;
    ret.val = GM.CreatePointer();
    ret.arr = [];
    ret.counter = 0;
    ret.evented = false;
    require('events').EventEmitter.call(ret, true)
        .createEvent('progress')
        .createEvent('rule');

    ret.NetFwPolicy2.funcs.get_Rules(ret.NetFwPolicy2, ret.rules).Val;
    ret.rules.funcs = require('win-com').marshalFunctions(ret.rules.Deref(), RulesFunctions);

    ret.rules.funcs.get__NewEnum(ret.rules.Deref(), unknown);
    unknown.funcs = require('win-com').marshalFunctions(unknown.Deref(), UnknownFunctions);
    unknown.funcs.QueryInterface(unknown.Deref(), require('win-com').CLSIDFromString(IID_IEnumVARIANT), ret.enumerator);
    ret.enumerator.funcs = require('win-com').marshalFunctions(ret.enumerator.Deref(), EnumVariantFunctions);

    var count = GM.CreateVariable(4);
    ret.rules.funcs.get_Count(ret.rules.Deref(), count).Val;
    ret.count = count.toBuffer().readInt32LE();

    setImmediate(getFirewallRulesAsync2, ret);

    return (ret);
}
function getFirewallRules(options)
{
    var ret = [];
    var hr;
    var rules = GM.CreatePointer();
    var unknown = GM.CreatePointer();
    var enumerator = GM.CreatePointer();
    var vvar = GM.CreateVariable(GM.PointerSize == 8 ? 24 : 16);
    var fetched = GM.CreateVariable(4);
    var tmp, rule;
    var val = GM.CreatePointer();
    var val_long = GM.CreateVariable(4);


    var obj;

    var NetFwPolicy2 = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_NetFwPolicy2), require('win-com').IID_IUnknown);
    NetFwPolicy2.funcs = require('win-com').marshalFunctions(NetFwPolicy2, FirewallFunctions);

    hr = NetFwPolicy2.funcs.get_Rules(NetFwPolicy2, rules).Val;
    rules.funcs = require('win-com').marshalFunctions(rules.Deref(), RulesFunctions);

    var count = GM.CreateVariable(4);
    hr = rules.funcs.get_Count(rules.Deref(), count).Val;
   
    console.info1('Number of Rules: ' + count.toBuffer().readInt32LE());

    if (options && options.count === true)
    {
        var ret = count.toBuffer().readInt32LE();
        NetFwPolicy2.funcs.Release(NetFwPolicy2);
        return (ret);
    }

    hr = rules.funcs.get__NewEnum(rules.Deref(), unknown);
    unknown.funcs = require('win-com').marshalFunctions(unknown.Deref(), UnknownFunctions);
    hr = unknown.funcs.QueryInterface(unknown.Deref(), require('win-com').CLSIDFromString(IID_IEnumVARIANT), enumerator);
    enumerator.funcs = require('win-com').marshalFunctions(enumerator.Deref(), EnumVariantFunctions);

    var ii = 0; jj = 0;
    while (hr.Val == 0)
    {
        OleAut.VariantClear(vvar);
        hr = enumerator.funcs.Next(enumerator.Deref(), 1, vvar, fetched);

        if(hr.Val == 0)
        {
            rule = GM.CreatePointer();
            tmp = vvar.Deref(8, GM.PointerSize);
            tmp.funcs = require('win-com').marshalFunctions(tmp.Deref(), UnknownFunctions);
            hr = tmp.funcs.QueryInterface(tmp.Deref(), require('win-com').CLSIDFromString(IID_INetFwRule), rule);
            rule.funcs = require('win-com').marshalFunctions(rule.Deref(), RuleFunctions);
            if ((options && options.program && rule.funcs.get_ApplicationName(rule.Deref(), val).Val == 0 && val.Deref().Val != 0
                && options.program.toLowerCase() == val.Deref().Wide2UTF8.toLowerCase()) || !options || !options.program)
            {
                obj = {};
                obj._rule = rule;
                obj._rule._i = NetFwPolicy2;
                if (val.Deref().Val != 0)
                {
                    obj.Program = val.Deref().Wide2UTF8;
                }
                else
                {
                    val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_ApplicationName(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.Program = val.Deref().Wide2UTF8; }
                }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Name(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.DisplayName = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Description(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.Description = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_LocalPorts(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.LocalPorts = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_RemotePorts(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.RemotePorts = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_LocalAddresses(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.LocalAddresses = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_RemoteAddresses(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.RemoteAddresses = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_ApplicationName(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.Program = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_InterfaceTypes(rule.Deref(), val).Val == 0 && val.Deref().Val != 0) { obj.InterfaceTypes = val.Deref().Wide2UTF8; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Enabled(rule.Deref(), val).Val == 0) { obj.Enabled = val.Deref(0, 2).toBuffer().readInt16LE() != 0; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Direction(rule.Deref(), val).Val == 0)
                {
                    switch (val.Deref(0, 4).toBuffer().readInt32LE())
                    {
                        case 1: // INBOUND
                            obj.direction = 'inbound';
                            break;
                        case 2: // OUTBOUND
                            obj.direction = 'outbound';
                            break;
                        default: // UNKNOWN
                            break;
                    }
                }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Protocol(rule.Deref(), val).Val == 0) { obj.Protocol = protocolNumbers[val.Deref(0, 4).toBuffer().readInt32LE()]; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_EdgeTraversal(rule.Deref(), val).Val == 0) { obj.EdgeTraversalPolicy = val.Deref(0, 2).toBuffer().readInt16LE() != 0 ? 'Allow' : 'Block'; }
                val.toBuffer().writeUInt32LE(0); if (rule.funcs.get_Profiles(rule.Deref(), val).Val == 0) { obj.Profile = ProfileMaskToString(val.toBuffer().readUInt32LE()); }
                ret.push(obj);
            }
        }
    }

    NetFwPolicy2.funcs.Release(NetFwPolicy2);
    return (ret);
}

function disableFirewallRules(arg)
{
    if(!Array.isArray(arg))
    {
        disableFirewallRules(getFirewallRules(arg));
        return;
    }

    var h = 0;
    for(var i in arg)
    {
        h |= arg[i]._rule.funcs.put_Enabled(arg[i]._rule.Deref(), 0).Val;
    }
    if (h != 0) { throw ('Error disabling rules'); }
}
function enableFirewallRules(arg)
{
    if (!Array.isArray(arg))
    {
        enableFirewallRules(getFirewallRules(arg));
        return;
    }

    var h = 0;
    for (var i in arg)
    {
        h |= arg[i]._rule.funcs.put_Enabled(arg[i]._rule.Deref(), -1).Val;
    }
    if (h != 0) { throw ('Error enabling rules'); }
}
function removeFirewallRule(arg)
{
    var ret = false;

    if (Array.isArray(arg))
    {
        for(var i in arg)
        {
            if (removeFirewallRule(arg[i].DisplayName)) { ret = true; }
        }
        return (ret);
    }
    if (typeof (arg) == 'string')
    {
        var num;
        var count = GM.CreateVariable(4);
        var rules = GM.CreatePointer();
        var NetFwPolicy2 = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_NetFwPolicy2), require('win-com').IID_IUnknown);
        NetFwPolicy2.funcs = require('win-com').marshalFunctions(NetFwPolicy2, FirewallFunctions);

        hr = NetFwPolicy2.funcs.get_Rules(NetFwPolicy2, rules).Val;
        rules.funcs = require('win-com').marshalFunctions(rules.Deref(), RulesFunctions);
        hr = rules.funcs.get_Count(rules.Deref(), count).Val; num = count.toBuffer().readInt32LE();
        hr = rules.funcs.Remove(rules.Deref(), GM.CreateVariable(arg, { wide: true }));
        
        if(hr.Val == 0)
        {
            count.toBuffer().writeUInt32LE(0);
            hr = rules.funcs.get_Count(rules.Deref(), count).Val;
            if(count.toBuffer().readInt32LE()<num)
            {
                ret = true;
            }
        }
        NetFwPolicy2.funcs.Release(NetFwPolicy2);
        return (ret);
    }
    else
    {
        return(removeFirewallRule(getFirewallRules(arg)));
    }
}
function addFirewallRule(rule)
{
    if (!rule || !rule.DisplayName || !rule.direction || !rule.Program || !rule.Protocol || !rule.Profile)
    {
        throw ('Invalid Arguments');
    }
    if (rule.direction.toLowerCase() != 'inbound' && rule.direction.toLowerCase() != 'outbount') { throw ('Invalid Direction'); }   
    if (typeof (rule.Protocol) == 'number' && (rule.Protocol < 0 || rule.Protocol > protocolNumbers.length)) { throw ('Invalid Protocol'); }
    if (typeof (rule.Protocol) == 'string' && (protocolNumbers.findIndex(function (v) { return (v == rule.Protocol); }) < 0)) { throw ('Invalid Protocol'); }

    var hr;
    var rules = GM.CreatePointer();
    var profile = 0;
    var profile_tmp = rule.Profile.split(',');
    for (var i in profile_tmp)
    {
        switch(profile_tmp[i].toLowerCase().trim())
        {
            case 'private':
                profile |= 0x2;
                break;
            case 'public':
                profile |= 0x4;
                break;
            case 'domain':
                profile |= 0x1;
                break;
        }
    }
    var newrule = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_NetFwRule), require('win-com').IID_IUnknown);
    newrule.funcs = require('win-com').marshalFunctions(newrule, RuleFunctions);

    hr = newrule.funcs.put_Name(newrule, GM.CreateVariable(rule.DisplayName, { wide: true }));
    hr = newrule.funcs.put_Direction(newrule, rule.direction.toLowerCase() == 'inbound' ? 1 : 2);
    hr = newrule.funcs.put_ApplicationName(newrule, GM.CreateVariable(rule.Program, { wide: true }));
    if (rule.Description) { hr = newrule.funcs.put_Description(newrule, GM.CreateVariable(rule.Description, { wide: true })); }
    if (rule.EdgeTraversalPolicy != null) { hr = newrule.funcs.put_EdgeTraversal(newrule, rule.EdgeTraversalPolicy ? -1 : 0); }
    if (rule.Enabled != null) { hr = newrule.funcs.put_Enabled(newrule, rule.Enabled ? -1 : 0); }
    hr = newrule.funcs.put_Protocol(newrule, typeof (rule.Protocol) == 'number' ? rule.Protocol : protocolNumbers.findIndex(function (v) { return (v == rule.Protocol); }));
    hr = newrule.funcs.put_Profiles(newrule, profile);
    if (rule.LocalPort) { hr = newrule.funcs.put_LocalPorts(newrule, GM.CreateVariable(rule.LocalPort, { wide: true })); }
    if (rule.RemotePort) { hr = newrule.funcs.put_RemotePorts(newrule, GM.CreateVariable(rule.RemotePort, { wide: true })); }


    var NetFwPolicy2 = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_NetFwPolicy2), require('win-com').IID_IUnknown);
    NetFwPolicy2.funcs = require('win-com').marshalFunctions(NetFwPolicy2, FirewallFunctions);

    hr = NetFwPolicy2.funcs.get_Rules(NetFwPolicy2, rules).Val;
    rules.funcs = require('win-com').marshalFunctions(rules.Deref(), RulesFunctions);

    hr = rules.funcs.Add(rules.Deref(), newrule);

    newrule.funcs.Release(newrule);
    rules.funcs.Release(rules.Deref());
}

//attachDebugger({ webport: 9995, wait: true }).then(console.log, console.log);
module.exports =
    {
        getRulesCount: getRulesCount,
        getFirewallRules: getFirewallRules,
        getFirewallRulesAsync: getFirewallRulesAsync,
        disableFirewallRules:   disableFirewallRules,
        enableFirewallRules:    enableFirewallRules,
        addFirewallRule:        addFirewallRule,
        removeFirewallRule:     removeFirewallRule,
        netsecurityExists:      false
    };