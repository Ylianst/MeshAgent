var mei, lme;
var pthi, lms;
var realm;
var amt, transport, wsman;
var command;
var ERRORS = { JSON:65535, UnknownCommand:65534, UnknownResourceUri:65533, Pthi:65532, Lms:65531, Unknown:65530, ActivState:65529, Wsman:65528, Hbs:65527, Fetch:65526, Privileges:65525, NoParam:65524, NotAuthToken:65523 };
var comObject = new ComObjectInterop();

if (!isAdmin())
{
    process.stdout.write('Error: Could not invoke amtcsp_engine.dll, system privileges are required.\n');
    process.exit(ERRORS.Privileges);
}

if (process.argv.length == 1)
{
    process.stdout.write('Usage: CSP [JSON-Value][-debug]\n');
    process.stdout.write('   Example: CSP "{""Action"": ""GET"", ""ResourceUri"": ""DeviceInfo""}" -debug\n');
    process.stdout.write('   Example: CSP "{""Action"": ""GET"", ""ResourceUri"": ""Settings/Configuration""}\n');
    process.exit(ERRORS.NoParam);
}


try
{
    command = JSON.parse(process.argv[1]);
    console.log("Running command: '" + command.Action + "' on '" + command.ResourceUri + "'");
}
catch(e)
{
    console.log('JSON Error');
    comObject.dispatch({ErrorDescription: 'JSON Error - ' + e, ErrorCode: ERRORS.JSON});
    process.exit(ERRORS.JSON);
}

process.on('uncaughtException', function onUncaughtException(e) { comObject.dispatch({ErrorDescription:'Unexpected Exception' + e, ErrorCode: ERRORS.Unknown}); process.exit(ERRORS.Unknown); });  // Something unexpected happened, so exit with '-1'


try
{
    mei = require('amt-mei');
    lme = require('amt-lme');

    pthi = new mei();
    pthi.on('error', function (e) { comObject.dispatch({ErrorDescription: 'Error during PTHI connection: ' + e, ErrorCode: ERRORS.Pthi}); process.exit(ERRORS.Pthi); });

    lms = new lme();
    lms.on('error', function (e)
    {
        if (e.errno && e.errno == 31)
        {
            // LMS already bound, so we can just ignore this
            init();
        }
        else
        {
            comObject.dispatch({ ErrorDescription: 'Error during LMS connection: ' + e, ErrorCode: ERRORS.Lms });
            process.exit(ERRORS.Lms);
        }
    });
    lms.on('bind', function lmsOnBind(mapping) { if (mapping[16992]) { this.removeAllListeners('bind'); init(); } });

    transport = require('amt-wsman-duk');
    wsman = require('amt-wsman');
    amt = require('amt');
}
catch (e)
{
    comObject.dispatch({ErrorDescription: 'Error establishing PTHI connection: ' + e, ErrorCode: ERRORS.Unknown});
    process.exit(ERRORS.Unknown); // could not establish PTHI connection
}


function init()
{
    console.log('Getting AMT Realm...');

    // Find the AMT Realm
    this.cr = require('http').get('http://127.0.0.1:16992/wsman', function getRealmResponse(imsg)
    {
        if (imsg.statusCode == 401)
        {
            var tokens = imsg.headers['WWW-Authenticate'].split(',');
            for (var i in tokens)
            {
                var token = tokens[i].split('=');
                if(token[0].toUpperCase() == 'DIGEST REALM')
                {
                    realm = token[1];
                    if (realm[0] == '"') { realm = realm.substring(1, realm.length - 1); }
                    console.log('AMT Realm is: ' + realm);
                    console.log('Getting LocalSystemAccount...');

                    // Get localSystemAccount
                    pthi.getLocalSystemAccount(function onGetLocalSystemAccount(x)
                    {
                        console.log('LocalSystemAccount = ' + x.user + ' / ' + x.pass);
                        if (command.AuthToken && command.Action.toUpperCase() == 'REPLACE' && command.ResourceUri == 'Settings/Activate')
                        {
                            pthi.wsstack = new wsman(transport, '127.0.0.1', 16992, x.user, x.pass, false);
                            console.log('AuthToken = ' + command.AuthToken);
                            console.log('Using Local OS/Admin');
                        }
                        else if (command.AuthToken)
                        {
                            console.log('AuthToken', command.AuthToken);
                            pthi.wsstack = new wsman({ transport: transport, host: '127.0.0.1', port: 16992, tls: false, authToken: command.AuthToken });
                            console.log('Using supplied AuthToken');
                        }
                        else
                        {
                            pthi.wsstack = new wsman(transport, '127.0.0.1', 16992, x.user, x.pass, false);
                            console.log('Using Local OS/Admin');
                        }
                            

                        pthi.amtstack = new amt(pthi.wsstack);
                        run(); // Now we can actually start!
                    });
                    break;
                }

            }
        }
    });
}

function isAdmin()
{
    var marshal = require('_GenericMarshal');
    var AdvApi = marshal.CreateNativeProxy('Advapi32.dll');
    AdvApi.CreateMethod('AllocateAndInitializeSid');
    AdvApi.CreateMethod('CheckTokenMembership');
    AdvApi.CreateMethod('FreeSid');

    var NTAuthority = marshal.CreateVariable(6);
    NTAuthority.toBuffer().writeInt8(5, 5);
    var AdministratorsGroup = marshal.CreatePointer();
    var admin = false;

    if (AdvApi.AllocateAndInitializeSid(NTAuthority, 2, 32, 544, 0, 0, 0, 0, 0, 0, AdministratorsGroup).Val != 0) {
        var member = marshal.CreateInteger();
        if (AdvApi.CheckTokenMembership(0, AdministratorsGroup.Deref(), member).Val != 0) {
            if (member.toBuffer().readUInt32LE() != 0) { admin = true; }
        }
        AdvApi.FreeSid(AdministratorsGroup.Deref());
    }
    return admin;
}

function run() {
    switch (command.Action.toUpperCase()) {
        case 'GET':
            switch (command.ResourceUri) {
                case 'Settings/ActivationState':
                    pthi.getControlMode(function (val) {
                        console.log('Current Control Mode ', val);
                        if (val.controlMode == undefined) {
                            comObject.dispatch({ ErrorDescription: 'Activation State Undefined', ErrorCode: ERRORS.ActivState });
                            process.exit(ERRORS.ActivState);
                        }
                        else {
                            comObject.dispatch(val.controlMode);
                            process.exit(0);
                        }
                    });
                    break;
                case 'Settings/Certificates':
                    EnumerateCertificates(function OnEnumerateCerts(status, certs)
                    {
                        for(var i in certs)
                        {
                            console.log(certs[i]);
                        }
                        process.exit(0);
                    });
                    break;
                case 'Settings/ConfigurationHash':
                case 'Settings/Configuration':
                    var wsman_commands = "AMT_WebUIService,CIM_KVMRedirectionSAP,AMT_RedirectionService,AMT_EnvironmentDetectionSettingData,IPS_AlarmClockOccurrence,AMT_WiFiPortConfigurationService,AMT_TLSSettingData,AMT_PublicKeyCertificate".split(',');

                    pthi.amtstack.BatchEnum(null, wsman_commands, function getConfigurationResponse(stack, name, responses, status, arg) {
                        var WinCrypto = require('WinCrypto');
                        var config = {};
                        config.Redirection = {};
                        config.EnvironmentDetection = { DetectionStrings: [] };
                        config.AlarmClock = [];
                        config.TLS = {};
                        if (responses.AMT_WebUIService.responses.length > 0) {
                            config.WebUi = { State: (responses.AMT_WebUIService.responses[0].EnabledState == '2' || responses.AMT_WebUIService.responses[0].EnabledState == '6') ? 1 : 0 };
                        }
                        if (responses.CIM_KVMRedirectionSAP.responses.length > 0) {
                            config.Redirection.EnableKvm = (responses.CIM_KVMRedirectionSAP.responses[0].EnabledState == '2' || responses.CIM_KVMRedirectionSAP.responses[0].EnabledState == '6') ? 1 : 0;
                        }
                        if (responses.AMT_RedirectionService.responses.length > 0) {
                            var solider = parseInt(responses.AMT_RedirectionService.responses[0].EnabledState);
                            config.Redirection.EnableSol = (((solider & 32768) == 32768) && ((solider & 2) == 2)) ? 1 : 0;
                            config.Redirection.EnableStorage = (((solider & 32768) == 32768) && ((solider & 1) == 1)) ? 1 : 0;
                        }

                        if (responses.AMT_EnvironmentDetectionSettingData.responses.length > 0) { config.EnvironmentDetection.DetectionStrings = responses.AMT_EnvironmentDetectionSettingData.responses[0].DetectionStrings; }
                        if (responses.IPS_AlarmClockOccurrence.responses.length > 0) {
                            for (var i in responses.IPS_AlarmClockOccurrence.responses) {
                                if (responses.IPS_AlarmClockOccurrence.responses[i].StartTime) {
                                    console.log('--> ', responses.IPS_AlarmClockOccurrence.responses[i]);
                                    config.AlarmClock.push({ StartTime: responses.IPS_AlarmClockOccurrence.responses[i].StartTime, Interval: responses.IPS_AlarmClockOccurrence.responses[i].Interval });
                                }
                            }
                        }

                        if (responses.AMT_WiFiPortConfigurationService.responses.length > 0 && responses.AMT_WiFiPortConfigurationService.responses[0].localProfileSynchronizationEnabled != undefined)
                        {
                            config.WiFi = { AmtWiFiSync: parseInt(responses.AMT_WiFiPortConfigurationService.responses[0].localProfileSynchronizationEnabled) };
                        }

                        if (responses.AMT_TLSSettingData.responses.length > 0) {
                            config.TLS.Enabled = responses.AMT_TLSSettingData.responses[0].Enabled ? 1 : 0;
                        }
                        if (responses.AMT_PublicKeyCertificate.responses.length > 0) {
                            var x509 = Buffer.from(responses.AMT_PublicKeyCertificate.responses[0].X509Certificate, 'base64');
                            var pcert = WinCrypto.loadCert(x509, { encodingType: WinCrypto.X509_ASN_ENCODING });
                            config.TLS.Sha1Thumbprint = pcert.getInfo({ thumbprint: 'SHA1' }).thumbprint;
                        }


                        console.log('config.WebUi', config.WebUi);
                        console.log('config.Redirection', config.Redirection);
                        console.log('config.EnvironmentDetection', config.EnvironmentDetection);
                        console.log('config.AlarmClock', config.AlarmClock);
                        console.log('config.WiFi', config.WiFi ? config.WiFi : 'Not Supported');
                        console.log('config.TLS', config.TLS);

                        if (arg == 'Settings/ConfigurationHash')
                        {
                            pthi.amtstack.GetAuditLog(function OnConfigurationHash_GetAuditLog(statck, status, logs, cfg)
                            {
                                var lastProvisionTime = '';
                                if (status == 200)
                                {
                                    for (var i in logs) {
                                        if (logs[i].Event == 'Provisioning Started') {
                                            lastProvisionTime = logs[i].Time;
                                        }
                                    }
                                }
                                console.log('GetAuditLog Status: ' + status);
                                console.log('Last Provisioning Time = ' + lastProvisionTime);

                                var configHash = require('SHA1Stream').create().syncHash(lastProvisionTime + ':' + JSON.stringify(config)).toString('hex');
                                console.log('SHA1 Hash = ' + configHash);
                                console.log('StdOut =>');
                                comObject.dispatch(configHash);
                                process.exit(0);
                            }, config);


                        }
                        else
                        {
                            console.log('StdOut =>');
                            comObject.dispatch(config);
                            process.exit(0);
                        }                        
                    }, command.ResourceUri, true);
                    break;
                case 'DeviceInfo':
                    this.smbios = require('smbios');
                    this.smbios.get(function onSMBiosGet(data) {
                        pthi.getVersion(function onGetVersion(version, self, smData) {
                            var amt = self.amtInfo(smData);
                            var sysInfo = self.systemInfo(smData);
                            var codeVersion = { BiosVersion: version.BiosVersion };
                            for (var vi in version.Versions) {
                                codeVersion[version.Versions[vi].Description] = version.Versions[vi].Version;
                            }

                            var devInfo = {};
                            devInfo.Device = {};
                            devInfo.Device.IntelPlatform = amt.AMT;
                            devInfo.Device.UUID = sysInfo.uuid;

                            // OSPrimaryDNSSuffix
                            var registry = require('windows_registry');
                            devInfo.Device.OSPrimaryDNSSuffix = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 'Domain');
                            if (devInfo.Device.OSPrimaryDNSSuffix.length == 0) { delete devInfo.Device.OSPrimaryDNSSuffix; }                      

                            console.log('devInfo.Device', devInfo.Device);

                            devInfo.Me = {};
                            devInfo.Me.MeFwVersion = codeVersion.BiosVersion;
                            if ((codeVersion.Sku & 8) == 8) {
                                devInfo.Me.MeSku = 2;
                            }
                            else if ((codeVersion.Sku & 16) == 16) {
                                devInfo.Me.MeSku = 1;
                            }
                            else {
                                devInfo.Me.MeSku = 0;
                            }


                            devInfo.Me.DriverStatus = 0;
                            var Devices = require('DeviceManager').getDevices({ manufacturer: 'Intel*', class: 'System' });
                            for (var i in Devices) {
                                if (Devices[i].description.includes('Management Engine Interface')) {
                                    devInfo.Me.DriverVersion = Devices[i].version;
                                    switch (Devices[i].status) {
                                        case 'ENABLED':
                                            devInfo.Me.DriverStatus = 2;
                                            break;
                                        case 'DISABLED':
                                            devInfo.Me.DriverStatus = 1;
                                            break;
                                        default:
                                            break;
                                    }
                                    break;
                                }
                            }

                            console.log('devInfo.Me', devInfo.Me);

                            devInfo.Amt = {};
                            devInfo.Amt.DigestRealm = realm;
                            devInfo.Amt.AmtVersion = codeVersion.AMT;
                            devInfo.Amt.CcmEnabled = '';
                            devInfo.Amt.NetworkInterfaces = [];
                            //  Type (0-Wired 1-Wireless)
                            //  Status (0-Disabled 1-Enabled S0 2 - Enabled S0, Wake in Sx)
                            //  IPv4Address (string)
                            //console.log('devInfo.Amt', devInfo.Amt);

                            var amtNics = [];
                            pthi.getLanInterfaceSettings(0, function (info, dv, nics) {
                                nics.push(info);
                                pthi.getLanInterfaceSettings(1, function (info, dv, nics) {
                                    nics.push(info);
                                    var n = require('os').networkInterfaces();
                                    for (var nx in n) {
                                        var intfc = n[nx];
                                        for (var nxi in intfc) {
                                            for (var infox in nics) {
                                                if (intfc[nxi] && nics[infox]) {
                                                    if (intfc[nxi].mac == nics[infox].mac && intfc[nxi].family == 'IPv4')
                                                    {
                                                        console.log('OS => ' + intfc[nxi].address);
                                                        console.log('nics[' + infox + '] => ');

                                                        for (var z in nics[infox])
                                                        {
                                                            console.log('   [' + z + '] =>' + nics[infox][z]);
                                                        }

                                                        dv.Amt.NetworkInterfaces.push({ dnsSuffix: intfc[nxi].fqdn, type: (intfc[nxi].type == 'wireless' ? 1 : 0), Status: (nics[infox].enabled ? 1 : 0), IPv4Address: nics[infox].address });
                                                    }
                                                }
                                            }
                                        }
                                    }


                                    pthi.getControlMode(function onDeviceInfo_getControlMode(ccm, dev) {
                                        dev.Amt.CcmEnabled = ccm.controlMode == 1 ? 1 : 0;
                                        console.log('devInfo.Amt', dev.Amt);

                                        for (var ii in dev.Amt.NetworkInterfaces) {
                                            console.log('devInfo.Amt.NetworkInterfaces[' + ii + ']', dev.Amt.NetworkInterfaces[ii]);
                                        }
                                        console.log('Return value to StdOut =>');
                                        comObject.dispatch(dev);
                                        process.exit(0);
                                    }, dv);



                                }, dv, nics);
                            }, devInfo, amtNics);

                        }, this, data);
                    });
                    break;
                default:
                    comObject.dispatch({ ErrorDescription: 'Unknown ResourceUri', ErrorCode: ERRORS.UnknownResourceUri });
                    process.exit(ERRORS.UnknownResourceUri)
                    break;
            }
            break;
        case 'DELETE':
            switch (command.ResourceUri) {
                case 'Settings/Activate':
                    pthi.unprovision(1, function unprovisionResponse(status) { console.log('Unprovision', status); process.exit(status); });
                    break;
                default:
                    comObject.dispatch({ ErrorDescription: 'Unknown ResourceUri', ErrorCode: ERRORS.UnknownResourceUri });
                    process.exit(ERRORS.UnknownResourceUri);
                    break;
            }
            break;
        case 'REPLACE':
            switch (command.ResourceUri)
            {
                case 'Settings/Configuration':
                    if (command.AuthToken == undefined || command.AuthToken == '') {
                        comObject.dispatch({ ErrorDescription: 'Access Denied: AuthToken not included.', ErrorCode: ERRORS.NotAuthToken });
                        process.exit(ERRORS.NotAuthToken);
                    }
                    var wsman_commands = "AMT_WebUIService,CIM_KVMRedirectionSAP,AMT_RedirectionService,AMT_EnvironmentDetectionSettingData,IPS_AlarmClockOccurrence,AMT_WiFiPortConfigurationService,AMT_TLSSettingData,AMT_TLSCredentialContext,".split(',');
                    pthi.amtstack.BatchEnum(null, wsman_commands, function replaceResponse1(stack, name, responses, status, arg) {
                        NextReplace(responses);
                    }, command, true);
                    break;
                case 'Settings/Activate':
                    if (command.ActivationState <= 0)
                    {
                        console.log('Bad ActivationState: ' + command.ActivationState);
                        comObject.dispatch({ ErrorDescription: 'Bad ActivationState: ' + command.ActivationState, ErrorCode: ERRORS.ActivState });
                        process.exit(ERRORS.ActivState);
                    }
                    if (command.RequestedStateChange == null || command.RequestedStateChange != 1)
                    {
                        console.log('Bad RequestedStateChange: ' + command.RequestedStateChange);
                        comObject.dispatch({ ErrorDescription: 'Bad RequestedStateChange: ' + command.RequestedStateChange, ErrorCode: ERRORS.ActivState });
                        process.exit(ERRORS.ActivState);
                    }
                    pthi.amtstack.BatchEnum(null, ['*IPS_HostBasedSetupService'], function ccmActivate_Response1(stack, name, responses, status, arg) {
                        if (status != 200) {
                            if (status == 600) {
                                console.log('WSMAN Internal Error: ' + status);
                                comObject.dispatch({ ErrorDescription: 'WSMAN Internal Error: ' + status, ErrorCode: ERRORS.Wsman });
                            }
                            else {
                                console.log('WSMAN HTTP Error code: ' + status);
                                comObject.dispatch({ ErrorDescription: 'WSMAN HTTP Error code: ' + status, ErrorCode: ERRORS.Wsman });
                            }
                            process.exit(ERRORS.Wsman);
                        }
                        else if (responses['IPS_HostBasedSetupService'].response['AllowedControlModes'].length != 2) {
                            console.log('Received invalid WSMAN response');
                            comObject.dispatch({ ErrorDescription: 'Received invalid WSMAN response', ErrorCode: ERRORS.Wsman });
                            process.exit(ERRORS.Wsman);
                        }
                        else {
                            pthi.amtstack.IPS_HostBasedSetupService_Setup(2, command.Payload.AuthToken, null, null, null, null, function ccmActivate_Response2(stack, name, responses, status, args) {
                                if (status != 200) {
                                    console.log('HostBasedSetup returned HTTP error code: ' + status);
                                    comObject.dispatch({ ErrorDescription: 'HostBasedSetup returned HTTP error code: ' + status, ErrorCode: ERRORS.Hbs });
                                    process.exit(ERRORS.Hbs);
                                }
                                else if (responses.Body.ReturnValue != 0) {
                                    var HbsRetVals = ['SUCCESS', 'INTERNAL ERROR', 'INVALID STATE', 'INVALID PARAM', 'METHOD DISABLED', 'AUTH_FAILED', 'FLASH_WRITE_LIMIT_EXCEEDED'];
                                    if (responses.Body.ReturnValue > 0 && responses.Body.ReturnValue < 7) {
                                        console.log('IPS_HostBasedSetupService returned: ' + HbsRetVals[responses.Body.ReturnValue] + ' (' + responses.Body.ReturnValue + ')');
                                        comObject.dispatch({ ErrorDescription: 'IPS_HostBasedSetupService returned: ' + HbsRetVals[responses.Body.ReturnValue] + ' (' + responses.Body.ReturnValue + ')', ErrorCode: ERRORS.Hbs });
                                    }
                                    else {
                                        console.log('IPS_HostBasedSetupService returned a Unknown status (' + responses.Body.ReturnValue + ')');
                                        comObject.dispatch({ ErrorDescription: 'IPS_HostBasedSetupService returned a Unknown status (' + responses.Body.ReturnValue + ')', ErrorCode: ERRORS.Hbs });
                                    }
                                    process.exit(ERRORS.Hbs);
                                }
                                else { console.log('Provisioned in CCM'); process.exit(0); }
                            }, arg);
                        }
                    }, { AuthToken: command.Payload.AuthToken, RequestedStateChange: command.Payload.RequestedStateChange, pwd: command.pwd });
                    break;
                default:
                    comObject.dispatch({ ErrorDescription: 'Unknown ResourceUri', ErrorCode: ERRORS.UnknownResourceUri });
                    process.exit(ERRORS.UnknownResourceUri);
                    break;
            }
            break;
        default:
            comObject.dispatch({ ErrorDescription: 'Unknown ResourceCommand', ErrorCode: ERRORS.UnknownCommand });
            process.exit(ERRORS.UnknownCommand);
            break;
    }

    function NextReplaceResults(action, status) {
        if (status == 200) {
            --pthi.amtstack.ReplaceCounter;
            if (pthi.amtstack.ReplaceCounter == 0) {
                console.log('Success');
                process.exit(0);
            }
        }
        else {
            console.log('Error Replacing: ' + action + ' [' + status + ']');
            process.exit(1);
        }
    }
    function NextReplace(responses) {
        pthi.amtstack.ReplaceCounter = 0;

        if (command.Payload.WiFi) {
            if (responses.AMT_WiFiPortConfigurationService && responses.AMT_WiFiPortConfigurationService.responses.length > 0)
            {
                ++pthi.amtstack.ReplaceCounter;
                responses.AMT_WiFiPortConfigurationService.responses[0].localProfileSynchronizationEnabled = command.Payload.WiFi.AmtWiFiSync ? 1 : 0;
                pthi.amtstack.Put('AMT_WiFiPortConfigurationService', responses.AMT_WiFiPortConfigurationService.responses[0], function replaceResponse2_wifi(xstack, xname, xresponse, xstatus, xtag) {
                    NextReplaceResults('WiFi', xstatus);
                }, responses)
            }
            else
            {
                ++pthi.amtstack.ReplaceCounter;
                AMT_SupportsWireless(function OnWirelessCheck(supported)
                {
                    if(supported)
                    {
                        console.log('[WiFi] Error Fetching State');
                        comObject.dispatch({ ErrorDescription: '[WiFi] Error Fetching State', ErrorCode: ERRORS.Fetch });
                        process.exit(ERRORS.Fetch);
                    }
                    else
                    {
                        NextReplaceResults('WiFi', 200);
                    }
                });
            }
        }
        if (command.Payload.WebUi) {
            if (responses.AMT_WebUIService && responses.AMT_WebUIService.responses.length > 0) {
                ++pthi.amtstack.ReplaceCounter;
                pthi.amtstack.AMT_WebUIService_RequestStateChange(command.Payload.WebUi.State == 0 ? 3 : 2, null, function webUiStateChangeRequestSink(xstack, xname, xresponse, xstatus, xtag) {
                    NextReplaceResults('WebUi', xstatus);
                });
            }
            else {
                console.log('[WebUI] Error Fetching State');
                comObject.dispatch({ ErrorDescription: '[WebUI] Error Fetching State', ErrorCode: ERRORS.Fetch });
                process.exit(ERRORS.Fetch);
            }
        }
        if (command.Payload.Redirection) {
            if (command.Payload.Redirection.EnableSol != undefined || command.Payload.Redirection.EnableStorage != undefined) {
                ++pthi.amtstack.ReplaceCounter;
                var mask = 32768;
                if (command.Payload.Redirection.EnableSol) { mask |= 2; }
                if (command.Payload.Redirection.EnableStorage) { mask |= 1; }

                pthi.amtstack.AMT_RedirectionService_RequestStateChange(mask, function redirectionOnRequestedStateChange(xstack, xname, xresponse, xstatus, xtag) {
                    NextReplaceResults('Redirection/SOL/IDER', xstatus);
                });
            }
            if (command.Payload.Redirection.EnableKvm != undefined) {
                ++pthi.amtstack.ReplaceCounter;
                pthi.amtstack.CIM_KVMRedirectionSAP_RequestStateChange(command.Payload.Redirection.EnableKvm ? 2 : 3, 0, function redirectionOnKvmRequestStateChange(xstack, xname, xresponse, xstatus, xtag) {
                    NextReplaceResults('Redirection/Kvm', xstatus);
                });
            }
        }
        if (command.Payload.TLS != undefined) {
            console.log('TLS', command.Payload.TLS);
            console.log('Counter', pthi.amtstack.ReplaceCounter);
            if (command.Payload.TLS.Enabled == false || command.Payload.TLS.Enabled == 0) {
                console.log(' Disabling TLS');
                if (responses.AMT_TLSSettingData && responses.AMT_TLSSettingData.responses.length > 0) {
                    if (responses.AMT_TLSCredentialContext && responses.AMT_TLSCredentialContext.responses.length > 0)
                    {
                        // TLS is Currently Set
                        for (var i in responses.AMT_TLSSettingData.responses) {
                            ++pthi.amtstack.ReplaceCounter;
                            var setting = JSON.parse(JSON.stringify(responses.AMT_TLSSettingData.responses[i]));
                            setting.Enabled = false;

                            console.log(i, setting);
                            pthi.amtstack.Put('AMT_TLSSettingData', setting, function replaceResponse2_tls(xstack, xname, xresponse, xstatus, xtag) {
                                console.log('xstatus=' + xstatus);
                                NextReplaceResults('TLS', xstatus);
                            }, 0, 1, setting);
                        }
                        ++pthi.amtstack.ReplaceCounter;
                        pthi.amtstack.AMT_SetupAndConfigurationService_CommitChanges(null, function onTlsCommitchanges(xstack, xname, xresponse, xstatus, xtag)
                        {
                            if (xstatus != 200) {
                                NextReplaceResults('TLS-Commit-Change', xstatus);
                            }
                            else {
                                // Set a timeout, and try this in 2 seconds, because AMT has a bug, where if you try to delete a cert too fast, it will fail
                                console.log('Setting 2 second delay, before attempting to delete TLS Certificate...');
                                pthi.amtstack._tlsTimeout = setTimeout(function tlsDeleteCredential_wait(credential)
                                {
                                    EnumerateCertificates(function onEnumerateCerts(xstatus, xcerts, xcredential)
                                    {
                                        if (xstatus != 200) { NextReplaceResults('TLS-Enumerate-Certificates', xstatus); return; }
                                        for(var i in xcerts)
                                        {
                                            if(xcerts[i].isTlsCertificate && xcerts[i].privateKeyInstanceID)
                                            {
                                                xcerts[i].Delete(function OnDelete(xxstatus)
                                                {
                                                    NextReplaceResults('TLS-Disable', xxstatus);
                                                });
                                                break;
                                            }
                                        }
                                    }, credential);                                    
                                }, 2000, xtag);
                            }
                        }, JSON.parse(JSON.stringify(responses.AMT_TLSCredentialContext.responses[0])));
                    }
                }
            }
            else {
                // Before we can enable TLS, we have to issue a certificate
                IssueSelfSignedCertificate();
            }
        }


        if (command.Payload.AlarmClock) {
            console.log('command.Payload.AlarmClock', command.Payload.AlarmClock);

            if (responses.IPS_AlarmClockOccurrence && responses.IPS_AlarmClockOccurrence.responses.length > 0) {
                // If there are any existing 
                for (var i in responses.IPS_AlarmClockOccurrence.responses) {
                    console.log('==> Deleting AlarmClock Occurrence');
                    ++pthi.amtstack.ReplaceCounter;
                    pthi.amtstack.Delete('IPS_AlarmClockOccurrence', responses.IPS_AlarmClockOccurrence.responses[i], function onAlarmClockDelete(xstack, xname, xresponse, xstatus, xtag) {
                        NextReplaceResults('AlarmClock_Delete', xstatus);
                    });
                }
            }
            for (var i in command.Payload.AlarmClock) {
                ++pthi.amtstack.ReplaceCounter;
                var alarmClockInstance = { StartTime: { Datetime: command.Payload.AlarmClock[i].StartTime }, DeleteOnCompletion: true };
                alarmClockInstance.ElementName = ('Alarm' + i);
                alarmClockInstance.InstanceID = ('Alarm' + i);
                if (command.Payload.AlarmClock[i].Interval) {
                    alarmClockInstance.Interval = { Datetime: command.Payload.AlarmClock[i].Interval };
                }
                pthi.amtstack.AMT_AlarmClockService_AddAlarm(alarmClockInstance, function onAlarmClockAddAlarm(xstack, xname, xresponse, xstatus, xtag) {
                    NextReplaceResults('AlarmClock_AddAlarm', xstatus);
                });
            }
        }
    }

    function IssueSelfSignedCertificate() {
        ++pthi.amtstack.ReplaceCounter;
        pthi.amtstack.AMT_PublicKeyManagementService_GenerateKeyPair(0, 2048, function onIssueSelfSignedCertificate(stack, serviceName, response, status) {
            if (status != 200) {
                NextReplaceResults('AMT_PublicKeyManagementService_GenerateKeyPair (Too Soon?)', xstatus);
            }
            else {
                if (response.Body['ReturnValue'] != 0) { NextReplaceResults('AMT_PublicKeyManagementService_GenerateKeyPair: ' + response.Body['ReturnValueStr'], 600); return; }

                // Get the new key pair
                pthi.amtstack.Enum('AMT_PublicPrivateKeyPair', function onFetchPublicPrivateKeyPair(stack, serviceName, response, status, tag) {
                    if (status != 200) {
                        NextReplaceResults('AMT_PublicPrivateKeyPair', xstatus);
                    }
                    else {
                        var DERKey = null;
                        for (var i in response) { if (response[i]['InstanceID'] == tag) DERKey = response[i]['DERKey']; }

                        var WinCrypto = require('WinCrypto');
                        var options =
                            {
                                _algorithm: 'SHA256',
                                _years: 10,
                                CN: 'UntrustedRoot',
                                T: 'UntrustedCert',
                                O: 'Intel',
                                C: 'USA',
                                ST: 'CA'
                            };
                        console.log(' Generating Dummy Root Certificate');
                        var untrustedRoot = WinCrypto.makeCert(options);

                        var AmtPublicKey = Buffer.from(DERKey, 'base64');
                        AmtPublicKey.oid = WinCrypto.CRYPT_KEY_ALGORITHMS_OIDS['RSA_RSA'];

                        console.log(' Using AMT Public Key to generate Certificate');
                        var child = WinCrypto.MakeCertFromPublicKey(
                        {
                            Issuer: 'CN=UntrustedRoot', Subject: { CN: 'SelfSigned', ST: 'CA', O: 'Intel', C: 'USA', T: 'SelfSignedCert' }, PublicKey: AmtPublicKey, SigningCert: untrustedRoot, SignatureAlgorithm: WinCrypto.CRYPT_KEY_ALGORITHMS_OIDS['RSA_SHA256RSA'],
                            EnhancedKeyUsages: [WinCrypto.CRYPT_ENHANCED_KEY_USAGES.SERVER_AUTH],
                            KeyUsage: ['CERT_DATA_ENCIPHERMENT_KEY_USAGE', 'CERT_DIGITAL_SIGNATURE_KEY_USAGE', 'CERT_KEY_ENCIPHERMENT_KEY_USAGE', 'CERT_NON_REPUDIATION_KEY_USAGE', 'CERT_KEY_CERT_SIGN_KEY_USAGE']
                        });

                        console.log(' Signing certificate with dummy root');
                        var signedCert = WinCrypto.SignCertificate(untrustedRoot, child);
                        signedCert.blob = signedCert.toBuffer().toString('base64');

                        pthi.amtstack.AMT_PublicKeyManagementService_AddCertificate(signedCert.blob, function onAddCertificate(stack, serviceName, response, status, tag) {
                            if (status != 200) {
                                NextReplaceResults('AMT_PublicKeyManagementService_AddCertificate', status);
                            }
                            else {
                                SetupTLS(response);
                            }
                        }, signedCert.blob);
                    }
                }, response.Body['KeyPair']['ReferenceParameters']['SelectorSet']['Selector']['Value']);
            }
        });
    }
    function SetupTLS(response) {
        console.log('fetching AMT_TLSProtocolEndpointCollection');
        pthi.amtstack.BatchEnum(null, ['AMT_TLSProtocolEndpointCollection'], function onEnableTLS_getCollection(stack, name, responses, status, xtag) {
            if (status != 200) {
                NextReplaceResults('AMT_TLSProtocolEndpointCollection', status);
            }
            else {
                XmlObjToXmlObj(xtag.Body.CreatedCertificate);

                var _certificate =
                    {
                        'a:Address': { Value: '/wsman' },
                        'a:ReferenceParameters': {
                            Value:
                              {
                                  'w:ResourceURI': { Value: 'http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate' },
                                  'w:SelectorSet': { Value: { 'w:Selector': { '@Name': 'InstanceID', Value: xtag.Body.CreatedCertificate.ReferenceParameters.Value.SelectorSet.Value.Selector.Value } } }
                              }
                        }
                    };

                var CreatedCertificate = ObjToXml(_certificate);
                var _provider =
                    {
                        'a:Address': { Value: '/wsman' },
                        'a:ReferenceParameters': {
                            Value: {
                                'w:ResourceURI': { Value: 'http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSProtocolEndpointCollection' },
                                'w:SelectorSet': { Value: { 'w:Selector': { '@Name': 'ElementName', Value: 'TLSProtocolEndpointInstances Collection' } } }
                            }
                        }
                    };

                var Provider = ObjToXml(_provider);

                pthi.amtstack.AMT_TLSCredentialContext_Create(CreatedCertificate, Provider, function onEnableTLS_createContext(xstack, xname, xresponses, xstatus, xtag) {
                    if (xstatus != 200) {
                        NextReplaceResults('AMT_TLSCredentialContext_Create', xstatus);
                    }
                    else {
                        pthi.amtstack.BatchEnum(null, ['AMT_TLSSettingData'], function onCreateTLSCredentialContext_GetTLSSettingsData(xstack, xname, responses, xstatus, xarg) {
                            if (xstatus != 200) {
                                NextReplaceResults('AMT_TLSSettingData', xstatus);
                            }
                            else {
                                EnableTLS(responses.AMT_TLSSettingData);
                            }
                        }, null, true);
                    }

                });
            }
        }, response, true);
    }
    function EnableTLS(AMT_TLSSettingData)
    {
        if (AMT_TLSSettingData && AMT_TLSSettingData.responses.length > 0)
        {
            for (var i in AMT_TLSSettingData.responses)
            {
                var setting = JSON.parse(JSON.stringify(AMT_TLSSettingData.responses[i]));
                setting.Enabled = true;
                setting.AcceptNonSecureConnections = true;
                setting.MutualAuthentication = false;

                pthi.amtstack.Put('AMT_TLSSettingData', setting, function (xstack, xname, xresponse, xstatus, xtag)
                {
                    if (xstatus != 200)
                    {
                        NextReplaceResults('AMT_TLSSettingData', xstatus);
                    }                
                }, 0, 1, setting);
            }
            pthi.amtstack.AMT_SetupAndConfigurationService_CommitChanges(null, function (xstack, xname, xresponse, xstatus, xtag)
            {
               NextReplaceResults('TLS-Commit-Change', xstatus);      
            });
        }
    }
    function EnumerateCertificates(callback_func)
    {
        var tag = [];
        for(var i in arguments) {tag.push(arguments[i]);}

        pthi.amtstack.BatchEnum(null, ['AMT_PublicKeyCertificate', 'AMT_TLSCredentialContext', 'AMT_PublicPrivateKeyPair'], function onEnumerateCertificates(stack, name, responses, status, xtag)
        {
            if (status != 200) { var cb = xtag.shift(); xtag.unshift([]); xtag.unshift(status); cb.apply(null, xtag); return; }
            var WinCrypto = require('WinCrypto');
            var certs = [];

            if(responses.AMT_PublicKeyCertificate && responses.AMT_PublicKeyCertificate.responses.length>0)
            {
                for(var i in responses.AMT_PublicKeyCertificate.responses)
                {
                    var cert = responses.AMT_PublicKeyCertificate.responses[i];
                    var x509 = Buffer.from(cert.X509Certificate, 'base64');
                    var _cert = WinCrypto.loadCert(x509, { encodingType: WinCrypto.X509_ASN_ENCODING });
                    var _info = _cert.getInfo();
                    certs.push(cert);

                    cert.Delete = Certificate_Delete;

                    if(responses.AMT_PublicPrivateKeyPair && responses.AMT_PublicPrivateKeyPair.responses.length>0)
                    {
                        for(var x in responses.AMT_PublicPrivateKeyPair.responses)
                        {
                            if ((cert.hasPrivateKey = responses.AMT_PublicPrivateKeyPair.responses[x]['DERKey'] == _info.publicKey))
                            {
                                cert.privateKeyInstanceID = responses.AMT_PublicPrivateKeyPair.responses[x]['InstanceID']
                                break;
                            }
                        }
                    }
                    if(responses.AMT_TLSCredentialContext && responses.AMT_TLSCredentialContext.responses.length>0)
                    {
                        for(var x in responses.AMT_TLSCredentialContext.responses)
                        {
                            if ((cert.isTlsCertificate = responses.AMT_TLSCredentialContext.responses[x].ElementInContext.ReferenceParameters.SelectorSet.Selector.Value == cert.InstanceID))
                            {
                                cert.tlsCredentialContext = JSON.parse(JSON.stringify(responses.AMT_TLSCredentialContext.responses[x]));
                                break;
                            }
                        }
                    }
                }
            }

            var cb = xtag.shift();
            xtag.unshift(certs);
            xtag.unshift(status);
            cb.apply(null, xtag);
        }, tag, true);
    }
}

function ComObjectInterop()
{
    this._ObjectID = 'ComObjectInterop';
    this._marshal = require('_GenericMarshal');
    this._native = this._marshal.CreateNativeProxy();

    console.setDestination(console.Destinations.DISABLED);
    for (var i in process.argv) {
        if (process.argv[i] == '-debug') {
            console.setDestination(console.Destinations.STDOUT);
            break;
        }
    }

    try {
        this._native.CreateMethod({ method: 'ExternalDispatchSink', dereferencePointer: 1 });
        this.dispatch = function dispatch(obj) { this._native.ExternalDispatchSink(this._marshal.CreateVariable(JSON.stringify(obj))); };
    }
    catch (e) {
        this.dispatch = function dispatch(obj) { process.stdout.write(JSON.stringify(obj)); }
    }
}
function XmlObjToXmlObj(j)
{
    var inlineValue = false;
    for (var i in j)
    {
        if(typeof(j[i]=='object'))
        {
            if(j[i].Value == null)
            {
                var tmp = { Value: j[i] };
                j[i] = tmp;
            }
            XmlObjToXmlObj(j[i].Value);
        }
        else
        {
            var tmp = { Value: j[i] };
            j[i] = tmp;
        }
    }
}
function ObjToXml(key, value)
{
    if (arguments.length == 1 && typeof (key) == 'object')
    {
        retVal = '';
        for(var i in key)
        {
            retVal += ObjToXml(i, key[i]);
        }
        return (retVal);
    }

    var retVal = '<' + key;
    var attr = false;
    for (var i in value)
    {
        if(i.startsWith('@'))
        {
            retVal += (' ' + i.substring(1) + '="' + value[i] + '"'); attr = true;
        }
    }
    retVal += ((attr ? ' ' : '') + '>');

    if (value.Value) { retVal += (typeof (value.Value) == 'string' ? value.Value : ObjToXml(value.Value)); }
    retVal += ('</' + key + '>');

    return (retVal);
}

function Certificate_Delete(callback_func)
{
    var tag = [this];
    for (var i in arguments) { tag.push(arguments[i]); }

    // First Step is to delete TLSCredentialContext if it exists
    if(this.tlsCredentialContext)
    {
        console.log('Deleting TLSCredentialContext');
        pthi.amtstack.Delete('AMT_TLSCredentialContext', this.tlsCredentialContext, function onDeleteTLSCredentialContext(xstack, xname, xresponse, xstatus, xtag)
        {
            if (xstatus != 200)
            {
                var self = xtag.shift();
                var cb = xtag.shift();
                xtag.unshift(xstatus);
                cb.apply(self, xtag);
            }
            else
            {
                Certificate_Delete_2.call(xtag[0], xtag);
            }
        }, tag);
    }
    else
    {
        Certificate_Delete_2.call(xtag[0], xtag);
    }
}
function Certificate_Delete_2(xtag)
{
    // Check if there is a private key
    if(this.hasPrivateKey && this.privateKeyInstanceID)
    {
        console.log('Deleting Public/Private Key Pair: [' + this.privateKeyInstanceID + ']');
        var sset = { InstanceID: this.privateKeyInstanceID };
        pthi.amtstack.Delete('AMT_PublicPrivateKeyPair', sset, function onCertificate_Delete_2(xstack, xname, xresponse, xstatus, xxtag)
        {
            if (xstatus != 200)
            {
                var self = xxtag.shift();
                var cb = xxtag.shift();
                xxtag.unshift(xstatus);
                cb.apply(self, xxtag);
            }
            else
            {
                Certificate_Delete_3.call(xxtag[0], xxtag);
            }
        }, xtag);
    }
    else
    {
        Certificate_Delete_3.call(xtag[0], xtag);
    }
}
function Certificate_Delete_3(xtag)
{
    // Delete the Certificate
    console.log('Deleting Certificate: [' + this.InstanceID + ']');
    var sset = { InstanceID: this.InstanceID };
    pthi.amtstack.Delete('AMT_PublicKeyCertificate', sset, function onCertificate_Delete_3(xstack, xname, xresponse, xstatus, xxtag)
    {
        var self = xxtag.shift();
        var cb = xxtag.shift();
        xxtag.unshift(xstatus);
        cb.apply(self, xxtag);
    }, xtag);
}

function AMT_SupportsWireless(func_callback)
{
    var opt = [];
    for (var i in arguments) { opt.push(arguments[i]); }

    pthi.getLanInterfaceSettings(1, function onAMTSupportsWireless(info, tag)
    {
        var cb = tag.shift();
        tag.unshift(info != null);
        cb.apply(null, tag);
    }, opt);
}