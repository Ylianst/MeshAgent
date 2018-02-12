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

// Return information about this executable
function parse(exePath)
{
    var retVal = {};
    var fs = require('fs');
    var fd = fs.openSync(exePath, 'rb');
    var bytesRead;
    var dosHeader = Buffer.alloc(64);
    var ntHeader = Buffer.alloc(24);
    var optHeader;

    // Read the DOS header
    bytesRead = fs.readSync(fd, dosHeader, 0, 64, 0);
    if (dosHeader.readUInt16LE(0).toString(16).toUpperCase() != '5A4D')
    {
        throw ('unrecognized binary format');
    }

    // Read the NT header
    bytesRead = fs.readSync(fd, ntHeader, 0, ntHeader.length, dosHeader.readUInt32LE(60));
    if (ntHeader.slice(0, 4).toString('hex') != '50450000')
    {
        throw ('not a PE file');
    }
    switch (ntHeader.readUInt16LE(4).toString(16))
    {
        case '14c': // 32 bit
            retVal.format = 'x86';
            break;
        case '8664': // 64 bit
            retVal.format = 'x64';
            break;
        default: // Unknown
            retVal.format = undefined;
            break;
    }

    retVal.optionalHeaderSize = ntHeader.readUInt16LE(20);
    retVal.optionalHeaderSizeAddress = dosHeader.readUInt32LE(60) + 20;

    // Read the optional header
    optHeader = Buffer.alloc(ntHeader.readUInt16LE(20));
    bytesRead = fs.readSync(fd, optHeader, 0, optHeader.length, dosHeader.readUInt32LE(60) + 24);
    var numRVA = undefined;

    retVal.CheckSumPos = dosHeader.readUInt32LE(60) + 24 + 64;
    retVal.SizeOfCode = optHeader.readUInt32LE(4);
    retVal.SizeOfInitializedData = optHeader.readUInt32LE(8);
    retVal.SizeOfUnInitializedData = optHeader.readUInt32LE(12);

    switch (optHeader.readUInt16LE(0).toString(16).toUpperCase())
    {
        case '10B': // 32 bit binary
            numRVA = optHeader.readUInt32LE(92);
            retVal.CertificateTableAddress = optHeader.readUInt32LE(128);
            retVal.CertificateTableSize = optHeader.readUInt32LE(132);
            retVal.CertificateTableSizePos = dosHeader.readUInt32LE(60) + 24 + 132;
            retVal.rvaStartAddress = dosHeader.readUInt32LE(60) + 24 + 96;
            break;
        case '20B': // 64 bit binary
            numRVA = optHeader.readUInt32LE(108);
            retVal.CertificateTableAddress = optHeader.readUInt32LE(144);
            retVal.CertificateTableSize = optHeader.readUInt32LE(148);
            retVal.CertificateTableSizePos = dosHeader.readUInt32LE(60) + 24 + 148;
            retVal.rvaStartAddress = dosHeader.readUInt32LE(60) + 24 + 112;
            break;
        default:
            throw ('Unknown Value found for Optional Magic: ' + ntHeader.readUInt16LE(24).toString(16).toUpperCase());
            break;
    }
    retVal.rvaCount = numRVA;

    if (retVal.CertificateTableAddress)
    {
        // Read the authenticode certificate, only one cert (only the first entry)
        var hdr = Buffer.alloc(8);
        fs.readSync(fd, hdr, 0, hdr.length, retVal.CertificateTableAddress);
        retVal.certificate = Buffer.alloc(hdr.readUInt32LE(0));
        fs.readSync(fd, retVal.certificate, 0, retVal.certificate.length, retVal.CertificateTableAddress + hdr.length);
        retVal.certificate = retVal.certificate.toString('base64');
        retVal.certificateDwLength = hdr.readUInt32LE(0);
    }
    fs.closeSync(fd);
    return (retVal);
}

module.exports = parse;


