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
    switch (process.platform)
    {
        case 'linux':
        case 'darwin':
            try
            {
                var db = require('SimpleDataStore').Create(process.execPath + '.db', { readOnly: true });
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
                var db = require('SimpleDataStore').Create(process.execPath.replace('.exe', '.db'), { readOnly: true });
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

module.exports = _meshNodeId;
module.exports.serviceName = _meshName;

