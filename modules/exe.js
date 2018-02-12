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

var fs = require('fs');
var exe;

var js;
var exeLen = 0;

var i;
var dependency = [];
var addOn = null;



var localFile;
var localPath;

const exeJavaScriptGuid = 'B996015880544A19B7F7E9BE44914C18';
const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';


// Get the file binary name
if (process.platform == 'win32') {
    // Windows case
    localFile = process.execPath.lastIndexOf('\\') < 0 ? process.execPath.substring(0, process.execPath.length - 4) : process.execPath.substring(process.execPath.lastIndexOf('\\') + 1, process.execPath.length - 4);
    localPath = process.execPath.lastIndexOf('\\') < 0 ? '' : process.execPath.substring(0, 1+process.execPath.lastIndexOf('\\'));
} else {
    // Linux case
    localFile = process.execPath.lastIndexOf('/') < 0 ? process.execPath.substring(0, process.execPath.length) : process.execPath.substring(process.execPath.lastIndexOf('/') + 1, process.execPath.length);
    localPath = process.execPath.lastIndexOf('/') < 0 ? '' : process.execPath.substring(0, 1 + process.execPath.lastIndexOf('/'));
}

var outputFileName;
var sourcejs;
var execPath = process.execPath;

// Process arguments
for (i = 1; i < process.argv.length; ++i)
{
    if (process.argv[i].startsWith('-o'))
    {
        outputFileName = process.argv[i].substring(2);
    }
    if (process.argv[i].startsWith('-x'))
    {
        execPath = process.argv[i].substring(2);
    }
    if (!process.argv[i].startsWith('-') && process.argv[i].endsWith('.js'))
    {
        sourcejs = process.argv[i];
    }
}

console.log('outputfilename= ' + outputFileName);

if (!outputFileName || !sourcejs)
{
    console.log('Usage: ' + localFile + ' -oOUTPUT source.js [-iDependancy.js]');
    process.exit();
}

// Merge dependencies
for (i = 1; i < process.argv.length; ++i)
{
    if(process.argv[i].startsWith('-i'))
    {
        try
        {
            dependency.push({ name:process.argv[i].slice(2,process.argv[i].indexOf('.js')), base64: fs.readFileSync(process.argv[i].slice(2)).toString('base64') });
            process._argv.splice(i, 1);
            i = 0;
        }
        catch(e)
        {
            console.log(e);
            process.exit();
        }
    }
}

if (dependency.length > 0)
{
    console.log("\nIntegrating Dependencies:")
    addOn = "";
    for(i=0;i<dependency.length;++i)
    {
        addOn += ("addModule('" + dependency[i].name + "', Buffer.from('" + dependency[i].base64 + "', 'base64'));\n");
        console.log("   " + dependency[i].name);
    }
    console.log("");
}


// Check if exe is signed
console.log('Executable Path = ' + execPath);
var PE;
try
{
    PE = require('PE_Parser')(execPath);
}
catch(e)
{

}

if(PE && PE.CertificateTableSize > 0)
{
    console.log('This binary is *SIGNED*, it is not allowed to embed a JS to a signed binary');
    process.exit();
}



if (process.argv0.endsWith('.js'))
{
    console.log("Non-integrated executable");
}
else
{
    console.log("Integrated executable");
}

console.log('target = ' + localPath + outputFileName);

// Read the entire binary and javascript file
exe = fs.readFileSync(execPath);
w = fs.createWriteStream(localPath + outputFileName, { flags: "wb" });
js = fs.readFileSync(sourcejs);

// Detect if Javascript already present in the binary, if the binary is not signed
if (exe.slice(exe.length - 16).toString('hex').toUpperCase() == exeJavaScriptGuid) // Guid for JavaScript
{
    // Yes, embedded JS is present. Remove it.
    exeLen -= (20 + exe.readUInt32BE(exeLen - 20));
    console.log("Integrated JavaScript detected");
}
else
{
    // No JS found
    console.log("No integrated JavaScript detected");
    exeLen = exe.length;
}

// Merge the dependencies at start of JS file & write binary
if (addOn != null) { js = Buffer.concat([Buffer.from(addOn), js]); }
console.log("JavaScript Length: " + js.length);
w.write(exe.slice(0, exeLen), OnWroteExe);

function OnWroteExe()
{
    // Write the padding to QuadWord Align the embedded JS
    var padding = Buffer.alloc(8 - ((exeLen + js.length + 16 + 4) % 8));

    // TODO: If no padding needed, we can skip this
    this.write(padding);
    this.write(js, function ()
    {
        // Write the size of the javascript without padding
        var sz = new Buffer(4);
        sz.writeInt32BE(js.length, 0);
        this.write(sz);

        // Write the guid
        this.write(Buffer.from(exeJavaScriptGuid, 'hex'), function () // Guid for JavaScript
        {
            this.end();
            console.log("Finished!");
            process.exit();
        });
    });
}





