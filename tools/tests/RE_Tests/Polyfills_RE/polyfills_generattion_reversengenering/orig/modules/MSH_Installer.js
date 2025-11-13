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

const exeJavaScriptGuid = 'B996015880544A19B7F7E9BE44914C18';
const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';



function mshLength()
{
    var exesize = require('fs').statSync(process.execPath).size;
    var fd = require('fs').openSync(process.execPath, "rb");
    var buffer = Buffer.alloc(20);
    require('fs').readSync(fd, buffer, 0, buffer.length, exesize - 20);

    if(buffer.slice(4).toString('hex') == exeMeshPolicyGuid)
    {
        return (buffer.readUInt32BE(0));
    }
    else
    {
        return (0);
    }
}


// Changes a Windows Executable to add the MSH inside of it.
// This method will write to destination stream and close it.
/*
    options = {
        platform: 'win32' or 'linux',
        sourceFileName: 'pathToBinary',
        destinationStream: 'outputStream'
        msh: 'mshContent',
        peinfo {} // Optional, if PE header already parsed place it here.
    }
*/
function addMsh(options)
{
    // TODO, check all inputs
    if (!options.destinationStream)
    {
        throw ('destination stream was not specified');
    }

    if (!options.platform)
    {
        // Try to determine what the platform is
        try
        {
            options.peinfo = require('PE_Parser')(options.sourceFileName);
            options.platform = 'win32';
        }
        catch(e)
        {
            options.platform = 'other';
        }
    }


    // If a Windows binary, parse it if not already parsed
    if (options.platform == 'win32')
    {
        // Windows, check the PE headers
        if(!options.peinfo)
        {
            // We need to parse the PE headers first
            options.peinfo = require('PE_Parser')(options.sourceFileName);
        }
    }

    // If unsigned Windows or Linux, we merge at the end with the GUID and no padding.
    if ((options.platform == 'win32' && options.peinfo.CertificateTableAddress == 0) || options.platform != 'win32')
    {
        // This is not a signed binary, so we can just send over the EXE then the MSH
        options.destinationStream.sourceStream = require('fs').createReadStream(options.sourceFileName, { flags: 'rb' });
        options.destinationStream.sourceStream.options = options;
        options.destinationStream.sourceStream.on('end', function ()
        {
            // Once the binary is streamed, write the msh + length + guid in that order.
            this.options.destinationStream.write(this.options.msh); // MSH
            var sz = Buffer.alloc(4);
            sz.writeUInt32BE(this.options.msh.length, 0);
            this.options.destinationStream.write(sz); // Length in small endian

            var mshBuf = Buffer.from(exeMeshPolicyGuid, 'hex');
            if (this.options.randomGuid) { mshBuf.randomFill(); }
            this.options.destinationStream.write(mshBuf, function () { this.end(); }); // GUID
        });
        // Pipe the entire source binary without ending the stream.
        options.destinationStream.sourceStream.pipe(options.destinationStream, { end: false });
    }
    else if (options.platform == 'win32' && options.peinfo.CertificateTableAddress != 0)
    {
        // This is a signed windows binary, so we need to do some magic
        options.mshPadding = (8 - ((options.peinfo.certificateDwLength + options.msh.length + 20) % 8)) % 8; // Compute the padding with quad-align

        console.log('old table size = ' + options.peinfo.CertificateTableSize);
        options.peinfo.CertificateTableSize += (options.msh.length + 20 + options.mshPadding); // Add to the certificate table size
        console.log('new table size = ' + options.peinfo.CertificateTableSize);
        console.log('old certificate dwLength = ' + options.peinfo.certificateDwLength);
        options.peinfo.certificateDwLength += (options.msh.length + 20 + options.mshPadding); // Add to the certificate size
        console.log('new certificate dwLength = ' + options.peinfo.certificateDwLength);
        console.log('values were padded with ' + options.mshPadding + ' bytes');

        // Read up to the certificate table size and stream that out
        options.destinationStream.sourceStream = require('fs').createReadStream(options.sourceFileName, { flags: 'rb', start: 0, end: options.peinfo.CertificateTableSizePos - 1});
        options.destinationStream.sourceStream.options = options;
        options.destinationStream.sourceStream.on('end', function ()
        {
            // We sent up to the CertificateTableSize, now we need to send the updated certificate table size
            console.log('read first block');
            var sz = Buffer.alloc(4);
            sz.writeUInt32LE(this.options.peinfo.CertificateTableSize, 0);
            this.options.destinationStream.write(sz); // New cert table size
            
            // Stream everything up to the start of the certificate table entry
            var source2 = require('fs').createReadStream(options.sourceFileName, { flags: 'rb', start: this.options.peinfo.CertificateTableSizePos + 4, end: this.options.peinfo.CertificateTableAddress - 1});
            source2.options = this.options;
            source2.on('end', function ()
            {
                // We've sent up to the Certificate DWLength, which we need to update
                console.log('read second block');
                var sz = Buffer.alloc(4);
                sz.writeUInt32LE(this.options.peinfo.certificateDwLength, 0);
                this.options.destinationStream.write(sz); // New certificate length

                // Stream the entire binary until the end
                var source3 = require('fs').createReadStream(options.sourceFileName, { flags: 'rb', start: this.options.peinfo.CertificateTableAddress + 4 });
                source3.options = this.options;
                source3.on('end', function ()
                {
                    // We've sent the entire binary... Now send: Padding + MSH + MSHLength + GUID
                    console.log('read third block');
                    if (this.options.mshPadding > 0)
                    {
                        this.options.destinationStream.write(Buffer.alloc(this.options.mshPadding)); // Padding
                    }

                    this.options.destinationStream.write(this.options.msh); // MSH content
                    var sz = Buffer.alloc(4);
                    sz.writeUInt32BE(this.options.msh.length, 0);
                    this.options.destinationStream.write(sz); // MSH Length, small-endian

                    var mshBuf = Buffer.from(exeMeshPolicyGuid, 'hex');
                    if (this.options.randomGuid) { mshBuf.randomFill(); }
                    this.options.destinationStream.write(mshBuf, function () { this.end(); }); // GUID
                });
                source3.pipe(this.options.destinationStream, { end: false });
                this.options.sourceStream = source3;
            });
            source2.pipe(this.options.destinationStream, { end: false });
            this.options.destinationStream.sourceStream = source2;
        });
        this.options.destinationStream.sourceStream.pipe(this.options.destinationStream, { end: false });
    }
}

try
{
    module.exports = addMsh;
    module.exports.len = mshLength;
}
catch(e)
{
    // We were run from the command line

    var outputFile = null;
    var inputFile = null;
    var msh = null;

    for (var i = 1; i < process.argv.length; i += 2)
    {
        switch (process.argv[i])
        {
            case '-o':
                outputFile = process.argv[i + 1];
                break;
            case '-i':
                inputFile = process.argv[i + 1];
                break;
            case '-mshlen':
                console.log('Integrated MSH Length: ' + mshLength());
                process.exit();
                break;
            default:
                console.log('unrecognized parameter: ' + process.argv[i]);
                break;
        }
    }


    if (process.argv.length != 5 || outputFile == null || inputFile == null)
    {

        console.log('usage: ' + process.execPath.split(process.platform == 'win32' ? '\\' : '/').pop() + ' MSH_Installer.js -o outputFile -i mshFile');
        process.exit();
    }

    try
    {
        msh = require('fs').readFileSync(inputFile);
    }
    catch(e)
    {
        console.log('Unable to read ' + inputFile, e);
        process.exit();
    }

    var options =
        {
            destinationStream: require('fs').createWriteStream(outputFile, { flags: 'wb' }),
            sourceFileName: process.execPath,
            msh: msh
        };

    console.log('Creating MSH integrated binary...');
    options.destinationStream.on('close', function () { console.log('DONE'); process.exit(); });
    addMsh(options);
}
