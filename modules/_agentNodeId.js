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
                var v = db.GetBuffer('NodeID');
                if(v!=null)
                {
                    ret = v.toString('hex');
                }
                else
                {
                    ret = require('tls').loadCertificate({ pfx: db.GetBuffer('SelfNodeCert'), passphrase: 'hidden' }).getKeyHash().toString('hex');
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

module.exports = _meshNodeId;

