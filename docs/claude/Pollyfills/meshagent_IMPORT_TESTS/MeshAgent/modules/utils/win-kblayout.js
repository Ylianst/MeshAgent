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

var table = require('fs').readFileSync(process.argv[0].split('\\win-kblayout.js').join('\\win-kblayout_table.txt'));
var lines = table.toString().split('\r\n');

var str = 'function toLang(val)\r\n';
str += '{\r\n';
str += '   var ret;\r\n';
str += '   switch(val)\r\n';
str += '   {\r\n';
for (var i = 0; i < lines.length; ++i)
{
    var code = lines[i].split(' ')[0];
    var text = lines[i].substring(lines[i].indexOf(' ')).split(',')[0].trim();
    str += ("      case '" + Buffer.from(code,'hex').readUInt32BE() + "':\r\n");
    str += ("         ret = '" + text + "';\r\n");
    str += ("         break\r\n");
}
str += ("      default:\r\n");
str += ("            ret = null;\r\n");
str += ("      break\r\n");
str += '   }\r\n';
str += '   return(ret);\r\n';
str += '}';

console.log('Value saved to clipboard...');
require('clipboard')(str);
process.exit();



var check = {};
var buffer = Buffer.alloc(8);

var str = ' switch(((int64_t*)val)[0])\r\n';
str += '    {\r\n';

for (var i = 0; i < lines.length; ++i)
{
    var code = lines[i].split(' ')[0];
    var text = lines[i].substring(lines[i].indexOf(' ')).split(',')[0].trim();
    if (text.length < 8)
    {
        buffer.fill(0);
        Buffer.from(text).copy(buffer);
        var n = require('bignum').fromBuffer(buffer, { endian: 'little' });
        str += ('        case ' + n.toString() + ': // ' + text + '\r\n');
        str += ('           ret = "' + code + '";\r\n');
        str += ('           break;\r\n');
    }
}

var tst = {};
for (var i = 0; i < lines.length; ++i)
{
    var code = lines[i].split(' ')[0];
    var text = lines[i].substring(lines[i].indexOf(' ')).split(',')[0].trim();
    if (text.length >= 8)
    {
        if (tst[text.substring(0, 8)] == null) { tst[text.substring(0, 8)] = []; }

        buffer.fill(0);
        Buffer.from(text.substring(0,8)).copy(buffer);
        var primary = require('bignum').fromBuffer(buffer, { endian: 'little' }).toString();
        buffer.fill(0);
        Buffer.from(text.substring(8)).copy(buffer);
        var secondary = require('bignum').fromBuffer(buffer, { endian: 'little' }).toString();

        tst[text.substring(0, 8)].push({ code: code, text: text, primary: primary, secondary: secondary });
    }
}

for (var i in tst)
{
    if(tst[i].length == 1)
    {
        var val = tst[i].pop();
        str += ('        case ' + val.primary + ': // ' + val.text + '\r\n');
        str += ('           ret = "' + val.code + '";\r\n');
        str += ('           break;\r\n');
    }
    else
    {
        var top = tst[i].peek();
        str += ('        case ' + top.primary + ':\r\n');
        str += ('           switch(((int64_t*)val)[1])\r\n');
        str += ('           {\r\n');
        while (tst[i].length > 0)
        {
            top = tst[i].pop();
            str += ('               case ' + top.secondary + ':     // ' + top.text + '\r\n');
            str += ('                   ret = "' + top.code + '";\r\n');
            str += ('                   break;\r\n');
        }
        str += ('           }\r\n');
        str += ('           break;\r\n');
    }
}

str += '    }\r\n';

console.log('Value saved to clipboard...');
require('clipboard')(str);
process.exit();

