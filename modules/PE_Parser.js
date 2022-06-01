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

// Return information about this executable
function parse(exePath)
{
    var retVal = {};
    var fd = fs.openSync(exePath, 'rb');
    var bytesRead;
    var dosHeader = Buffer.alloc(64);
    var ntHeader = Buffer.alloc(24);
    var optHeader;
    var z;

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
    retVal.optionalHeaderSizeAddress = dosHeader.readUInt32LE(60) + 24;
    retVal.sectionHeadersAddress = retVal.optionalHeaderSizeAddress + retVal.optionalHeaderSize;

    // Read the optional header
    optHeader = Buffer.alloc(ntHeader.readUInt16LE(20));
    bytesRead = fs.readSync(fd, optHeader, 0, optHeader.length, dosHeader.readUInt32LE(60) + 24);
    var numRVA = undefined;
    var rvaStart = 0;
    retVal.CheckSumPos = dosHeader.readUInt32LE(60) + 24 + 64;
    retVal.SizeOfCode = optHeader.readUInt32LE(4);
    retVal.SizeOfInitializedData = optHeader.readUInt32LE(8);
    retVal.SizeOfUnInitializedData = optHeader.readUInt32LE(12);
    retVal.sections = {};

    // read section headers
    var sect = Buffer.alloc(40);
    for (z = 0; z < 16; ++z)
    {
        fs.readSync(fd, sect, 0, sect.length, retVal.sectionHeadersAddress + (z * 40));
        if (sect[0] != 46) { break; }
        var s = {};
        s.sectionName = sect.slice(0, 8).toString().trim('\0');
        s.virtualSize = sect.readUInt32LE(8);
        s.virtualAddr = sect.readUInt32LE(12);
        s.rawSize = sect.readUInt32LE(16);
        s.rawAddr = sect.readUInt32LE(20);
        s.relocAddr = sect.readUInt32LE(24);
        s.lineNumbers = sect.readUInt32LE(28);
        s.relocNumber = sect.readUInt16LE(32);
        s.lineNumbersNumber = sect.readUInt16LE(34);
        s.characteristics = sect.readUInt32LE(36);
        retVal.sections[s.sectionName] = s;
    }

    if (retVal.sections['.rsrc'] != null)
    {
        retVal.resources = readResourceTable(fd, retVal.sections['.rsrc'].rawAddr, 0); // Read all resources recursively
    }

    switch (optHeader.readUInt16LE(0).toString(16).toUpperCase())
    {
        case '10B': // 32 bit binary
            numRVA = optHeader.readUInt32LE(92);
            rvaStart = 96;
            retVal.CertificateTableAddress = optHeader.readUInt32LE(128);
            retVal.CertificateTableSize = optHeader.readUInt32LE(132);
            retVal.CertificateTableSizePos = dosHeader.readUInt32LE(60) + 24 + 132;
            retVal.rvaStartAddress = dosHeader.readUInt32LE(60) + 24 + 96;
            break;
        case '20B': // 64 bit binary
            numRVA = optHeader.readUInt32LE(108);
            rvaStart = 112;
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

    retVal.rva = [];
    for (z = 0; z < retVal.rvaCount && z < 32; ++z)
    {
        retVal.rva.push({ virtualAddress: optHeader.readUInt32LE(rvaStart + (z * 8)), size: optHeader.readUInt32LE(rvaStart + 4 + (z * 8)) });
    }

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
    retVal.versionInfo = getVersionInfo(fd, retVal);

    fs.closeSync(fd);
    return (retVal);
}

// Read a unicode stting that starts with the string length as the first byte.
function readLenPrefixUnicodeString(fd, ptr)
{
    var name = '';
    var tmp = Buffer.alloc(1);
   require('fs').readSync(fd, tmp, 0, 1, 0);
    var nameLen = tmp[0];

    var buf = Buffer.alloc(nameLen * 2);
    require('fs').readSync(fd, buf, 0, buf.length, 1);
    return (require('_GenericMarshal').CreateVariable(buf).Wide2UTF8);
}
// Read a resource item
// ptr: The pointer to the start of the resource section
// offset: The offset start of the resource item to read
function readResourceItem(fd, ptr, offset)
{
    var buf = Buffer.alloc(16);
    require('fs').readSync(fd, buf, 0, buf.length, ptr + offset);
    var r = {};
    r.offsetToData = buf.readUInt32LE(0);
    r.size = buf.readUInt32LE(4);
    r.codePage = buf.readUInt32LE(8);
    r.reserved = buf.readUInt32LE(12);
    return r;
}
function readResourceTable(fd, ptr, offset)
{
    var buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, buf.length, ptr + offset);
    var r = {};
    r.characteristics = buf.readUInt32LE(0);
    r.timeDateStamp = buf.readUInt32LE(4);
    r.majorVersion = buf.readUInt16LE(8);
    r.minorVersion = buf.readUInt16LE(10);
    var numberOfNamedEntries = buf.readUInt16LE(12);
    var numberofIdEntries = buf.readUInt16LE(14);
    r.entries = [];
    var totalResources = numberOfNamedEntries + numberofIdEntries;
    for (var i = 0; i < totalResources; i++)
    {
        buf = Buffer.alloc(8);
        fs.readSync(fd, buf, 0, buf.length, ptr + offset + 16 + (i * 8));
        var resource = {};
        resource.name = buf.readUInt32LE(0);
        var offsetToData = buf.readUInt32LE(4);
        if ((resource.name & 0x80000000) != 0) { resource.name = readLenPrefixUnicodeString(fd, ptr + (resource.name - 0x80000000)); }
        if ((offsetToData & 0x80000000) != 0) { resource.table = readResourceTable(fd, ptr, offsetToData - 0x80000000); } else { resource.item = readResourceItem(fd, ptr, offsetToData); }
        r.entries.push(resource);
    }
    return r;
}
// Return the version info data block
function getVersionInfoData(fd, header)
{
    var ptr = header.sections['.rsrc'].rawAddr;
    for (var i = 0; i < header.resources.entries.length; i++)
    {
        if (header.resources.entries[i].name == 16)
        {
            const verInfo = header.resources.entries[i].table.entries[0].table.entries[0].item;
            const actualPtr = (verInfo.offsetToData - header.sections['.rsrc'].virtualAddr) + ptr;
            var buffer = Buffer.alloc(verInfo.size);
            require('fs').readSync(fd, buffer, 0, buffer.length, actualPtr);
            return (buffer);
        }
    }
    return null;
}

// VS_FIXEDFILEINFO structure: https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
function readFixedFileInfoStruct(buf, ptr)
{
    if (buf.length - ptr < 50) return null;
    var r = {};
    r.dwSignature = buf.readUInt32LE(ptr);
    if (r.dwSignature != 0xFEEF04BD) return null;
    r.dwStrucVersion = buf.readUInt32LE(ptr + 4);
    r.dwFileVersionMS = buf.readUInt32LE(ptr + 8);
    r.dwFileVersionLS = buf.readUInt32LE(ptr + 12);
    r.dwProductVersionMS = buf.readUInt32LE(ptr + 16);
    r.dwProductVersionLS = buf.readUInt32LE(ptr + 20);
    r.dwFileFlagsMask = buf.readUInt32LE(ptr + 24);
    r.dwFileFlags = buf.readUInt32LE(ptr + 28);
    r.dwFileOS = buf.readUInt32LE(ptr + 32);
    r.dwFileType = buf.readUInt32LE(ptr + 36);
    r.dwFileSubtype = buf.readUInt32LE(ptr + 40);
    r.dwFileDateMS = buf.readUInt32LE(ptr + 44);
    r.dwFileDateLS = buf.readUInt32LE(ptr + 48);
    return r;
}

// Trim a string at the first null character
function stringUntilNull(str)
{
    if (str == null) return null;
    const i = str.indexOf('\0');
    if (i >= 0) return str.substring(0, i);
    return str;
}

// StringFileInfo structure: https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo
function readStringFilesStruct(buf, ptr, len)
{
    var t = [], startPtr = ptr;
    while (ptr < (startPtr + len))
    {
        const r = {};
        r.wLength = buf.readUInt16LE(ptr);
        if (r.wLength == 0) return t;
        r.wValueLength = buf.readUInt16LE(ptr + 2);
        r.wType = buf.readUInt16LE(ptr + 4); // 1 = Text, 2 = Binary
        r.szKey = stringUntilNull(require('_GenericMarshal').CreateVariable(buf.slice(ptr + 6, ptr + 6 + (r.wLength - 6))).Wide2UTF8); // String value
        //console.log('readStringFileStruct', r.wLength, r.wValueLength, r.wType, r.szKey.toString());
        if (r.szKey == 'StringFileInfo') { r.stringTable = readStringTableStruct(buf, ptr + 36 + r.wValueLength); }
        if (r.szKey == 'VarFileInfo$') { r.varFileInfo = {}; } // TODO
        t.push(r);
        ptr += r.wLength;
        ptr = padPointer(ptr);
    }
    return t;
}

// StringTable structure: https://docs.microsoft.com/en-us/windows/win32/menurc/stringtable
function readStringTableStruct(buf, ptr)
{
    const r = {};
    r.wLength = buf.readUInt16LE(ptr);
    r.wValueLength = buf.readUInt16LE(ptr + 2);
    r.wType = buf.readUInt16LE(ptr + 4); // 1 = Text, 2 = Binary
    r.szKey = require('_GenericMarshal').CreateVariable(buf.slice(ptr + 6, ptr + 6 + 16)).Wide2UTF8; // An 8-digit hexadecimal number stored as a Unicode string.
    //console.log('readStringTableStruct', r.wLength, r.wValueLength, r.wType, r.szKey);
    r.strings = readStringStructs(buf, ptr + 24 + r.wValueLength, r.wLength - 22);
    return r;
}

// String structure: https://docs.microsoft.com/en-us/windows/win32/menurc/string-str
function readStringStructs(buf, ptr, len)
{
    var t = [], startPtr = ptr;
    while (ptr < (startPtr + len))
    {
        const r = {};
        r.wLength = buf.readUInt16LE(ptr);
        if (r.wLength == 0) return t;
        r.wValueLength = buf.readUInt16LE(ptr + 2);
        r.wType = buf.readUInt16LE(ptr + 4); // 1 = Text, 2 = Binary


        //console.log('tmp', tmp.toString('hex'));
        r.key = require('_GenericMarshal').CreateVariable(buf.slice(ptr + 6, ptr + 6 + (r.wLength - 6))).Wide2UTF8; // String value
        //console.log('keyLen: ' + r.key.length, 'wValueLength: ' + r.wValueLength);
        r.value = require('_GenericMarshal').CreateVariable(buf.slice(ptr + r.wLength - (r.wValueLength*2), ptr + r.wLength)).Wide2UTF8;
        t.push(r);
        ptr += r.wLength;
        ptr = padPointer(ptr);
    }
    return t;
}

// Return the next 4 byte aligned number
function padPointer(ptr) { return ptr + (ptr % 4); }

// VS_VERSIONINFO structure: https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
function readVersionInfo(buf, ptr)
{
    const r = {};
    if (buf.length < 2) return null;
    r.wLength = buf.readUInt16LE(ptr);
    if (buf.length < r.wLength) return null;
    r.wValueLength = buf.readUInt16LE(ptr + 2);
    r.wType = buf.readUInt16LE(ptr + 4);

    r.szKey = require('_GenericMarshal').CreateVariable(buf.slice(ptr + 6, ptr + 36)).Wide2UTF8;
    if (r.szKey != 'VS_VERSION_INFO') return null;
    ////console.log('getVersionInfo', r.wLength, r.wValueLength, r.wType, r.szKey.toString());
    if (r.wValueLength == 52) { r.fixedFileInfo = readFixedFileInfoStruct(buf, ptr + 40); }
    r.stringFiles = readStringFilesStruct(buf, ptr + 40 + r.wValueLength, r.wLength - 40 - r.wValueLength);
    return r;
}
function getVersionInfo(fd, header, resources)
{
    var r = {};
    var b = getVersionInfoData(fd, header, resources);
    var info = readVersionInfo(b, 0);
    if ((info == null) || (info.stringFiles == null)) return null;
    var StringFileInfo = null;
    for (var i in info.stringFiles) { if (info.stringFiles[i].szKey == 'StringFileInfo') { StringFileInfo = info.stringFiles[i]; } }

    if ((StringFileInfo == null) || (StringFileInfo.stringTable == null) || (StringFileInfo.stringTable.strings == null)) return null;
    const strings = StringFileInfo.stringTable.strings;

    for (var i in strings) { r[strings[i].key] = strings[i].value; }
    return r;
}
module.exports = parse;


