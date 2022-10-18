/*
Copyright 2022 Intel Corporation
@author Bryan Roe

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


function expand(options)
{
    if (options == null) { options = {}; }
    if (options.filePath == null) { options.filePath = 'C:/GITHub//MeshAgent/microscript/ILibDuktape_Polyfills.c'; }

    var file = require('fs').readFileSync(options.filePath);
    var section = file.toString().split('void ILibDuktape_Polyfills_JS_Init(');

    var match = section[1].split('// {{ BEGIN AUTO-GENERATED BODY')[1].split('// }} END OF AUTO-GENERATED BODY')[0];

    var lines = match.split('\n');
    var i, line, token, encoded = '';

    var modules = [];

    for (i = 0; i < lines.length; ++i)
    {
        line = lines[i].trim();
        if (line.startsWith('duk_peval_string_noresult('))
        {
            token = line.split("'");
            modules.push({ name: token[1], timestamp: token[7], data: token[3], oversized: false, compressed: line.indexOf('addCompressedModule') >= 0 });
        }
        else
        {
            if (line.startsWith('memcpy_s('))
            {
                encoded += line.split('"')[1];
            }
            if (line.startsWith('ILibDuktape_AddCompressedModuleEx('))
            {
                token = line.split('"');
                modules.push({ name: token[1], timestamp: token[3], data: encoded, oversized: true, compressed: true });
                encoded = '';
            }
        }
    }

    for (i = 0; i < modules.length; ++i)
    {
        if (modules[i].compressed)
        {
            var d = require('compressed-stream').createDecompressor();
            d.on('data', function (c)
            {
                var a = [];
                if (this._buffer != null) { a.push(this._buffer); }
                a.push(c);
                this._buffer = Buffer.concat(a);
            });
            d.end(Buffer.from(modules[i].data, 'base64'));
            modules[i].data = d._buffer.toString();
        }
        else
        {
            modules[i].data = Buffer.from(modules[i].data, 'base64').toString();
        }
    }
    options.modules = modules;
    options.modules.sort(function (a, b) { if (a.name < b.name) { return (-1); } if (a.name > b.name) { return (1); } return (0); });

    writeExpandedModules(options);
}

function writeExpandedModules(options)
{
    if (options.expandedPath == null) { options.expandedPath = 'modules_expanded'; }

    try
    {
        require('fs').mkdirSync(options.expandedPath);
    }
    catch(z)
    {
    }

    var i;
    for(i = 0; i<options.modules.length;++i)
    {
        console.log(options.modules[i].name);
         require('fs').writeFileSync(options.expandedPath + '/' + options.modules[i].name + '.js', options.modules[i].data);
    }
}

module.exports = { expand: expand }

