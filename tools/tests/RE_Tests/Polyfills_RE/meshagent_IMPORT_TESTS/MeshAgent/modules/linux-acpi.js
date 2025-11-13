/*
Copyright 2020 Intel Corporation

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


function linux_acpi()
{
    this._ObjectID = 'linux-acpi';
    require('events').EventEmitter.call(this, true)
        .createEvent('acpi');
    Object.defineProperty(this, "supported", { value: require('fs').existsSync('/var/run/acpid.socket') });
    if(this.supported)
    {
        this._client = require('net').createConnection({ path: '/var/run/acpid.socket', metadata: 'linux-acpi' }, function ()
        {
            this.on('data', function (chunk)
            {
                var blocks;
                var ubuffer = null;
                var tokens = chunk.toString().split('\n');
                if (tokens.length == 1) { this.unshift(chunk); }
                if (tokens.peek() != '') { ubuffer = Buffer.from(tokens.pop()); }
                else { tokens.pop(); }
                for (var i in tokens)
                {
                    blocks = tokens[i].split(' ');
                    this.ret.emit('acpi', { name: blocks[0], type: Buffer.from(blocks[2], 'hex').readUInt32BE(), value: Buffer.from(blocks[3], 'hex').readUInt32BE() });
                }
            });
        });
        this._client.ret = this;
    }
}

module.exports = new linux_acpi();