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

//
// exe.js -o[output] -i[dependency] -i[dependency] -d[dependencyFolder] -x[inputbinary] [integrationJavaScriptFile]
//
//   -x, -d and -i are optional
//
// For example:
// 
//   MeshAgent.exe -omeshcmd.exe -imodule1.js -xMeshService64.exe meshcmd.js
//

//attachDebugger({ webport: 9095, wait: 1 }).then(function (p) { console.log('debug on port: ' + p); });

var fs = require('fs');
var i, exe, js, exeLen = 0;
var dependency = [];
var addOn = null;
var localFile;
var localPath;

// Magic strings placed at the end of the integrated javascript
const exeJavaScriptGuid = 'B996015880544A19B7F7E9BE44914C18';
const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';

// Get the full path file binary name
if (process.platform == 'win32') {
    // Windows case
    localFile = process.execPath.lastIndexOf('\\') < 0 ? process.execPath.substring(0, process.execPath.length - 4) : process.execPath.substring(process.execPath.lastIndexOf('\\') + 1, process.execPath.length - 4);
    localPath = process.execPath.lastIndexOf('\\') < 0 ? '' : process.execPath.substring(0, 1 + process.execPath.lastIndexOf('\\'));
} else {
    // Linux case
    localFile = process.execPath.lastIndexOf('/') < 0 ? process.execPath.substring(0, process.execPath.length) : process.execPath.substring(process.execPath.lastIndexOf('/') + 1, process.execPath.length);
    localPath = process.execPath.lastIndexOf('/') < 0 ? '' : process.execPath.substring(0, 1 + process.execPath.lastIndexOf('/'));
}

var outputFileName, sourcejs, depPath = null;
var execPath = process.execPath;

// Process arguments
for (i = 1; i < process.argv.length; ++i) {
    if (process.argv[i].startsWith('-o')) { outputFileName = process.argv[i].substring(2); } // Output file
    if (process.argv[i].startsWith('-x')) { execPath = process.argv[i].substring(2); } // Input executable
    if (process.argv[i].startsWith('-d')) { depPath = process.argv[i].substring(2); } // Dependencies path
    if (!process.argv[i].startsWith('-') && process.argv[i].endsWith('.js')) { sourcejs = process.argv[i]; } // JavaScript
}

console.log('Output Filename: ' + outputFileName);

// Check if the output filename is not specified
if (!outputFileName || !sourcejs) {
    console.log('Usage: ' + localFile + ' -oOUTPUT source.js [-iDependancy.js]');
    process.exit();
}

// Reads all the dependencies into an array
for (i = 1; i < process.argv.length; ++i) {
    if (process.argv[i].startsWith('-i')) {
        try {
            dependency.push({ name: process.argv[i].slice(2, process.argv[i].indexOf('.js')), base64: fs.readFileSync(process.argv[i].slice(2)).toString('base64') });
            process._argv.splice(i, 1);
            i = 0;
        } catch (e) { console.log(e); process.exit(); }
    }
}

// Read all dependencies in the path
if (depPath != null)
{
    try
    {
        filenames = fs.readdirSync(depPath +  (process.platform == 'win32' ? '\\*' : '/*'));
        if(filenames.length == 0 && process.platform != 'win32')
        {
            var currentPath = process.execPath.substring(0, process.execPath.lastIndexOf('/'));
            filenames = fs.readdirSync(currentPath + '/' + depPath + '/*');
        }
    } catch (e) { }
    filenames.forEach(function (filename)
    {
        var fname = process.platform == 'win32' ? (depPath + '\\' + filename) : (depPath + '/' + filename);
        try { dependency.push({ name: filename.slice(0, filename.indexOf('.js')), base64: fs.readFileSync(fname).toString('base64') }); } catch (e) { console.log(e); process.exit(); }
    });
}

//console.log(JSON.stringify(dependency));

// Merges all dependencies togeather
if (dependency.length > 0) {
    console.log("\nIntegrating Dependencies: ")
    for (i = 0; i < dependency.length; ++i) {
        if (addOn == null) { addOn = ''; }
        addOn += ("addModule('" + dependency[i].name + "', Buffer.from('" + dependency[i].base64 + "', 'base64'));\n");
        console.log("   " + dependency[i].name);
    }
    console.log("");
}


// Check if exe is signed, if signed we can't merge
console.log('Source Executable: ' + execPath);
var PE;
try { PE = require('PE_Parser')(execPath); } catch (e) { }
if (PE && PE.CertificateTableSize > 0) { console.log('This binary is *SIGNED*, it is not allowed to embed a JS to a signed binary'); process.exit(); }


// Displays if we are using a .exe that is already integrated
//if (process.argv0.endsWith('.js')) { console.log("Non-integrated executable"); } else { console.log("Integrated executable"); }

console.log('Target Executable: ' + localPath + outputFileName);

// Read the entire binary and javascript file
exe = fs.readFileSync(execPath);
w = fs.createWriteStream(localPath + outputFileName, { flags: "wb" });
js = fs.readFileSync(sourcejs);

// Detect if Javascript already present in the binary, if the binary is not signed
if (exe.slice(exe.length - 16).toString('hex').toUpperCase() == exeJavaScriptGuid) { // GUID for JavaScript
    // Yes, embedded JS is present. Remove it.
    exeLen -= (20 + exe.readUInt32BE(exeLen - 20));
    //console.log("Integrated JavaScript detected");
} else {
    // No JS found
    //console.log("No integrated JavaScript detected");
    exeLen = exe.length;
}

// Merge the dependencies at start of JS file & write binary
if (addOn != null) { js = Buffer.concat([Buffer.from(addOn), js]); }
console.log("JavaScript Length: " + js.length);
w.write(exe.slice(0, exeLen), OnWroteExe); // Write original .exe binary

// Called once the .exe is written 
function OnWroteExe() {
    // Write the padding to QuadWord Align the embedded JS
    var padding = Buffer.alloc(8 - ((exeLen + js.length + 16 + 4) % 8));

    // If padding is needed, write it
    if (padding.length > 0) { this.write(padding); } // This is async, but will buffer (lazy)

    this.write(js, function () {
        // Write the size of the javascript without padding
        var sz = new Buffer(4);
        sz.writeInt32BE(js.length, 0);
        this.write(sz);

        // Write the magic GUID
        this.write(Buffer.from(exeJavaScriptGuid, 'hex'), function () { // GUID for JavaScript
            this.end();
            console.log("Done.");
            process.exit();
        });
    });
}
