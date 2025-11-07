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

var Writable = require('stream').Writable;


function create(useCRC32c)
{
    var ret = new Writable(
        {
            write: function (chunk, flush)
            {
                this._current = this._CRC32C ? crc32c(chunk, this._current) : crc32(chunk, this._current);
                flush();
            },
            final: function (flush)
            {
                flush();
            }
        });
    ret._current = 0;
    ret._CRC32C = useCRC32c ? true : false;
    Object.defineProperty(ret, 'value', { get: function () { return (this._current); } });
    return (ret);
}

module.exports = { create: create };
