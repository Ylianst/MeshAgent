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
            try
            {
                var reg = require('win-registry');
                ret = Buffer.from(reg.QueryKey(reg.HKEY.LocalMachine, 'Software\\Open Source\\MeshAgent2', 'NodeId').toString(), 'base64').toString('hex');
            }
            catch(e)
            {
            }
            break;
        default:
            break;
    }
    return (ret);
}

module.exports = _meshNodeId;

