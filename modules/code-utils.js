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

//
// code-utils is a helper module that enables the ability to compress and decompress on the fly
// to be able to embed and extact JavaScript modules from native C code on the fly.
//

//
// This function will read the specified C file, and decompress(inflate)/extract all the embedded JavaScript modules,
// and save them to the specified path
//
// filePath: C file to read from. By default: ILibDuktape_Polyfills.c
// expandedPath: Destination folder for extracted files. By default: modules_expanded
//
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

//
// This function writes the extracted modules into the specified path
// expandedPath: The destination folder to write the extracted files. By default: modules_expanded
//
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

//
// This function reads all the Javascript files from the specified folder, and creates a table
// expandedPath: The folder to read the files from. By default: modules_expanded
//
function readExpandedModules(options)
{
    var valuex, name;
    var data;
    var i;
    options.modules = [];
    var files = require('fs').readdirSync(options.expandedPath);
    files.sort();

    for (i = 0; i < files.length; ++i)
    {
        if (files[i].endsWith('.js'))
        {
            name = files[i].split('.js')[0];
            try
            {
                valuex = (new Date(require('fs').statSync(options.expandedPath + '/' + files[i]).mtime)).getTime() / 1000;
                if (valuex > 0)
                {
                    valuex = (new Date(valuex * 1000)).toString().split(' ').join('T');
                    valuex = ", '" + valuex + "'";

                }
                else
                {
                    valuex = '';
                }

                data = require('fs').readFileSync(options.expandedPath + '/' + files[i]);
                data = compress(data);
                var ret = "duk_peval_string_noresult(ctx, \"addCompressedModule('" + name + "', Buffer.from('" + data + "', 'base64')" + valuex + ");\");";

                if (ret.length > 16300)
                {
                    // MS Visual Studio has a maxsize limitation
                    ret = '\n\tchar *_' + name.split('-').join('') + ' = ILibMemory_Allocate(' + (data.length + 1) + ', 0, NULL, NULL);\n';
                    var z = 0;
                    while (z < data.length)
                    {
                        var chunk = data.substring(z, z + 16000);
                        ret += ('\tmemcpy_s(_' + name.split('-').join('') + ' + ' + z + ', ' + (data.length - z) + ', "' + chunk + '", ' + chunk.length + ');\n');
                        z += chunk.length;
                    }
                    valuex = valuex.split("'").join('"');
                    ret += ('\tILibDuktape_AddCompressedModuleEx(ctx, "' + name + '", _' + name.split('-').join('') + valuex + ');\n');
                    ret += ('\tfree(_' + name.split('-').join('') + ');\n');
                }

                options.modules.push({ name: files[i], data: ret });
            }
            catch (x)
            {
            }
        }
    }
}

//
// This function reads all the JavaScript files in the specified path, 'modules_expanded' by default, and
// deflates them, and embeds the modules into the specified C file, 'ILibDuktape_Polyfills.c' by default.
//
function shrink(options)
{
    if (options == null) { options = {}; }
    if (options.expandedPath == null) { options.expandedPath = 'modules_expanded'; }
    if (options.filePath == null) { options.filePath = 'C:/GITHub//MeshAgent/microscript/ILibDuktape_Polyfills.c'; }
    if (options.modulesPath == null) { options.modulesPath = 'C:/GITHub/MeshAgent/modules'; }

    readExpandedModules(options);
    insertCompressed(options);
}

//
// This function reads the specified C file, 'ILibDuktape_Polyfills.c' by default, end replaces the embedded JavaScript modules
// with the ones specified in options.
//
function insertCompressed(options)
{
    var inserted = [];
    var file = require('fs').readFileSync(options.filePath);
    var section = file.toString().split('void ILibDuktape_Polyfills_JS_Init(');
    var match1 = section[1].split('// {{ BEGIN AUTO-GENERATED BODY');
    var match2 = match1[1].split('// }} END OF AUTO-GENERATED BODY');
    var i;

    match2[0] = '\n';
    for (i = 0; i < options.modules.length; ++i)
    {
        match2[0] += ('\t' + options.modules[i].data + '\n');
        inserted.push(options.modules[i].name);
    }

    match2 = match2.join('\t// }} END OF AUTO-GENERATED BODY');
    match1[1] = match2;
    match1 = match1.join('// {{ BEGIN AUTO-GENERATED BODY');

    section[1] = match1;
    section = section.join('void ILibDuktape_Polyfills_JS_Init(');

    require('fs').writeFileSync(options.filePath, section);

    inserted.sort();
    require('fs').writeFileSync(options.modulesPath + '/embedded.info', inserted.join('\n'));
}

function update(options)
{
    if (options == null) { options = {}; }
    if (options.modulesFolder == null) { options.modulesFolder = 'C:/GITHub/MeshAgent/modules'; }
    if (options.expandedPath == null) { options.expandedPath = 'modules_expanded'; }

    var files = require('fs').readFileSync(options.modulesFolder + '/embedded.info');
    files = files.toString().split('\r').join('').split('\n');
    for(var i in files)
    {
        try
        {
            var mtime = require('fs').statSync(options.modulesFolder + '/' + files[i]).mtime;
            var etime = require('fs').statSync(options.expandedPath + '/' + files[i]).mtime;

            if ((new Date(mtime)) > (new Date(etime)))
            {
                // Modules version is newer than expanded version, so we should over-write
                require('fs').copyFileSync(options.modulesFolder + '/' + files[i], options.expandedPath + '/' + files[i]);
            }
            else
            {
                // Don't copy modules version, becuase it's older
                console.log('Not copied: ' + files[i], mtime, etime);
            }
        }
        catch(x)
        {
            require('fs').copyFileSync(options.modulesFolder + '/' + files[i], options.expandedPath + '/' + files[i]);
        }
    }

}

//
// This function takes the input and returns the base64 encoding of the deflated input.
//
function compress(data)
{
    var zip = require('compressed-stream').createCompressor();
    zip.buffer = null;
    zip.on('data', function (c)
    {
        if (this.buffer == null)
        {
            this.buffer = Buffer.concat([c]);
        }
        else
        {
            this.buffer = Buffer.concat([this.buffer, c]);
        }
    });
    zip.end(data);
    return(vstring = zip.buffer.toString('base64'));
}

module.exports = { expand: expand, shrink: shrink, update: update }

