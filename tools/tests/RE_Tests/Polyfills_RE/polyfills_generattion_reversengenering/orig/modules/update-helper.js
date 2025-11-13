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

var promise = require('promise');

function start(updatePath)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (!require('zip-reader').isZip(updatePath)) { ret._res(); return (ret); }
    ret._readpromise = require('zip-reader').read(updatePath);
    ret._readpromise.then(function _updatehelper(zipped)
    {
        var p = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        if (zipped.files.length != 1)
        {
            p._rej('Unexpected contents in zip file');
            zipped.close();
        }
        else
        {
            try
            {
                p.dest = require('fs').createWriteStream(updatePath + '_unzipped', { flags: 'wb' });
            }
            catch (e)
            {
                zipped.close();
                p._rej(e);
                return (p);
            }
            p.dest.prom = p;
            p.dest.zipped = zipped;
            p.dest.on('close', function () { this.zipped.close(); this.prom._res(); });
            zipped.getStream(zipped.files[0]).pipe(p.dest);
        }
        return (p);
    })
    .then(function ()
    {
        try
        {
            require('fs').unlinkSync(updatePath);
            require('fs').copyFileSync(updatePath + '_unzipped', updatePath);
            require('fs').unlinkSync(updatePath + '_unzipped');
        }
        catch(e)
        {
            ret._rej(e);
            return;
        }
        ret._res('done');
    })
    .catch(function (e) { ret._rej(e); });

    return (ret);
}

module.exports = { start: start };
