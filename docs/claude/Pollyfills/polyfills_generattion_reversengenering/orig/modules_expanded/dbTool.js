// Module: dbTool
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 1415 bytes
// Decompressed size: 5161 bytes
// Compression ratio: 72.6%

/*
Copyright 2018 Intel Corporation

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


var db;
var readonlyDb = true;

if (process.argv.length > 1)
{
    switch (process.argv[1])
    {
        case 'compact':
        case 'put':
        case 'putx':       
        case 'delete':
        case 'import':
            readonlyDb = false;
            break;
    }
}

if (process.platform == 'win32')
{
    db = require('SimpleDataStore').Create(process.execPath.replace('.exe', '.db'), { readOnly: readonlyDb });
}
else
{
    db = require('SimpleDataStore').Create(process.execPath + '.db', { readOnly: readonlyDb });
}


if (process.argv.length > 1)
{
    switch(process.argv[1])
    {
        case 'compact':
            db.Compact();
            console.log('Compacted');
            process.exit();
            break;
        case 'put':
            console.log('PUT ' + process.argv[2] + ' = ' + process.argv[3]);
            db.Put(process.argv[2], process.argv[3]);
            process.exit();
            break;
        case 'putx':
            console.log('PUTX ' + process.argv[2] + ' = ' + process.argv[3]);
            db.Put(process.argv[2], Buffer.from(process.argv[3], 'hex'));
            process.exit();
            break;
        case 'get':
            console.log('GET ' + process.argv[2] + ' = ');
            var val = db.Get(process.argv[2]);
            if (process.argv[2] == 'CoreModule') { val = val.slice(4); }
            console.log(val);
            process.exit();
            break;
        case 'getx':
            console.log('GETX ' + process.argv[2] + ' = ');
            var val = db.GetBuffer(process.argv[2]);
            console.log('len = ' + val.length);
            console.log(val==null?'0x00':('0x' + val.toString('hex')));
            process.exit();
            break;
        case 'list':
        case 'keys':
        case 'keynum':
            if (process.argv[1] != 'keynum')
            {
                console.log('Number of Keys: ' + db.Keys.length);
            }
            var skeys = db.Keys.sort(function (a, b)
            {
                var aL = a.toLowerCase();
                var bL = b.toLowerCase();

                if (aL < bL) { return (-1); }
                if (aL > bL) { return (1); }
                return (0);
            });
            if (process.argv[1] == 'keynum')
            {
                console.log('Key[' + parseInt(process.argv[2]) + '] = ' + db.Get(skeys[parseInt(process.argv[2])-1]));
            }
            else
            {
                for (var x = 0; x < skeys.length; ++x)
                {
                    console.log((x + 1) + ': ' + skeys[x]);
                }
            }
            process.exit();
            break;
        case 'delete':
            console.log('Deleting ' + process.argv[2]);
            db.Delete(process.argv[2]);
            process.exit();
            break;
        case 'export':
            if (process.argv[2] == 'CoreModule' || process.argv[2] == 'RecoveryModule')
            {
                db.target = require('fs').createWriteStream(process.argv[2]+'.js', { flags: 'wb' });
                db.target.write(db.GetBuffer('CoreModule').slice(4), function () { console.log('finished exporting'); process.exit(); });
            }
            else
            {
                db.target = require('fs').createWriteStream(process.argv[2], 'wb');
                db.target.write(db.GetBuffer(process.argv[2]), function () { console.log('finished exporting'); process.exit(); });
            }
            break;
        case 'import':
            if (process.argv[2] == 'CoreModule' || process.argv[2] == 'RecoveryModule')
            {
                var src = require('fs').readFileSync(process.argv[2] + '.js', 'rb');
                var src2 = Buffer.concat([Buffer.alloc(4), src]);
                db.PutCompressed('CoreModule', src2);
                console.log(process.argv[2] + ' imported');
            }
            else
            {
                var src = require('fs').readFileSync(process.argv[2] + '.js', 'rb');
                db.PutCompressed(process.argv[2], src);
                console.log(process.argv[2] + ' imported');
            }
            process.exit();
            break;
        default:
            console.log('unknown command "' + process.argv[1] + '"');
            process.exit();
            break;
    }
}
else
{
    console.log('usage: ');
    console.log('   [get/getx/delete/export/import] [KEY]');
    console.log('   [put/putx] [KEY] [value]');
    console.log('   [list]');
    console.log('   Commonly used keys are: disableUpdate and noUpdateCoreModule');
    process.exit();
}
