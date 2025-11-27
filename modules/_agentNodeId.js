/*
Copyright 2019 Intel Corporation

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

function _meshNodeId()
{
    var ret = '';
    // Determine database path
    var dbPath;
    if (process.platform == 'win32')
    {
        dbPath = process.execPath.replace('.exe', '.db');
    }
    else
    {
        // Linux/macOS - check if running from bundle
        // Bundle detection changes cwd to parent of .app, so .db file is in cwd
        if (process.execPath.indexOf('.app/Contents/MacOS/') !== -1)
        {
            // Running from bundle - use current working directory
            dbPath = process.cwd() + '/meshagent.db';
        }
        else
        {
            // Standalone binary - use path next to executable
            dbPath = process.execPath + '.db';
        }
    }

    switch (process.platform)
    {
        case 'linux':
        case 'darwin':
            try
            {
                var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
                ret = require('tls').loadCertificate({ pfx: db.GetBuffer('SelfNodeCert'), passphrase: 'hidden' }).getKeyHash().toString('hex');
            }
            catch(e)
            {
            }
            break;
        case 'win32':
            // First Check if the db Contains the NodeID
            try
            {
                var db = require('SimpleDataStore').Create(dbPath, { readOnly: true });
                var v = db.GetBuffer('SelfNodeCert');
                if (v)
                {
                    try
                    {
                        ret = require('tls').loadCertificate({ pfx: v, passphrase: 'hidden' }).getKeyHash().toString('hex');
                    }
                    catch(e)
                    {
                        v = null;
                    }
                }
                if (v == null && (v = db.GetBuffer('NodeID')) != null)
                {
                    ret = v.toString('hex');
                }
            }
            catch (e)
            {
            }
            break;
        default:
            break;
    }
    return (ret);
}

function _meshName()
{
    var name = _MSH().meshServiceName;
    if(name==null)
    {
        switch(process.platform)
        {
            case 'win32':
                // Enumerate the registry to see if the we can find our NodeID           
                var reg = require('win-registry');
                var nid = _meshNodeId();
                var key, regval;
                var source = [reg.HKEY.LocalMachine, reg.HKEY.CurrentUser];
                var val;

                while (name == null && source.length > 0)
                {
                    val = reg.QueryKey(source.shift(), 'Software\\Open Source');
                    for (key = 0; key < val.subkeys.length;++key)
                    {
                        try
                        {
                            if (nid == Buffer.from(reg.QueryKey(reg.HKEY.LocalMachine, 'Software\\Open Source\\' + val.subkeys[key], 'NodeId').split('@').join('+').split('$').join('/'), 'base64').toString('hex'))
                            {
                                name = val.subkeys[key];
                                break;
                            }
                        }
                        catch (ex)
                        {
                        }
                    }
                }
                if (name == null) { name = 'Mesh Agent'; }
                break;
            default:
                var service = require('service-manager').manager.enumerateService();
                name = 'meshagent';
                for (var i = 0; i < service.length; ++i)
                {
                    if(service[i].appLocation()==process.execPath)
                    {
                        name = service[i].name;
                        break;
                    }
                }
                break;
        }
    }
    return (name);
}

function _resetNodeId()
{
    var name = _meshName();
    require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId', 1);
    console.log('Resetting NodeID for: ' + name);
}
function _checkResetNodeId(name)
{
    var status = false;
    try
    {
        // Check if reset node id was set in the registry
        status = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId') == 1 ? true : false;
    }
    catch(x)
    {
    }
    if (status)
    {
        try
        {
            // Delete the reset node id field in the registry
            require('win-registry').DeleteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId');
        }
        catch(y)
        {
            // If we can't delete it, we must pretend that it was never set, otherwise we risk getting in a loop where we constantly reset the node id
            status = false;
        }
    }
    return (status);
}

module.exports = _meshNodeId;
module.exports.serviceName = _meshName;
module.exports.resetNodeId = _resetNodeId;
module.exports.checkResetNodeId = _checkResetNodeId;

