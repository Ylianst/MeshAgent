// JavaScript source code

var fs = require('fs');
//var buffer = fs.readFileSync('test.bin');
//var tls = require('tls');

//var pem = tls.loadpkcs7b(buffer);
//console.log(pem.toString());




var fd = fs.openSync(process.execPath.replace('MeshConsole', 'MC2'), 'rb+');
var bytesRead;
var dosHeader = new Buffer(64);
var ntHeader = new Buffer(24);
var optHeader;

console.log(process.execPath.replace('MeshConsole', 'MC2'));

bytesRead = fs.readSync(fd, dosHeader, 0, 64, 0);
if (dosHeader.readUInt16LE(0).toString(16).toUpperCase() != '5A4D')
{
    console.log('unrecognized binary format');
}

bytesRead = fs.readSync(fd, ntHeader, 0, ntHeader.length, dosHeader.readUInt32LE(60));

if (ntHeader.slice(0, 4).toString('hex') != '50450000')
{
    console.log('not PE format');
}

switch (ntHeader.readUInt16LE(4).toString(16))
{
    case '14c':
        console.log('x86 binary');
        break;
    case '8664':
        console.log('x64 binary');
        break;
    default:
        console.log('unknown binary type');
        break;
}

console.log('Optional Size = ' + ntHeader.readUInt16LE(20) + 'bytes');
optHeader = new Buffer(ntHeader.readUInt16LE(20));
bytesRead = fs.readSync(fd, optHeader, 0, optHeader.length, dosHeader.readUInt32LE(60) + 24);
var numRVA = undefined;
var CertificateTableAddress = undefined;
var CertificateTableSize = undefined;

switch (optHeader.readUInt16LE(0).toString(16).toUpperCase())
{
    case '10B':
        console.log('Found IMAGE_NT_OPTIONAL_HDR32_MAGIC');
        numRVA = optHeader.readUInt32LE(92);
        CertificateTableAddress = optHeader.readUInt32LE(128);
        CertificateTableSize = optHeader.readUInt32LE(132);
        break;
    case '20B':
        console.log('Found IMAGE_NT_OPTIONAL_HDR64_MAGIC');
        numRVA = optHeader.readUInt32LE(108);
        CertificateTableAddress = optHeader.readUInt32LE(144);
        CertificateTableSize = optHeader.readUInt32LE(148);
        break;
    default:
        console.log('Unknown Value found for Optional Magic: ' + ntHeader.readUInt16LE(24).toString(16).toUpperCase());
        break;
}

console.log('Number of RVA Entries: ' + numRVA.toString());
console.log('Certificate Table Address: ' + CertificateTableAddress.toString(16).toUpperCase());
console.log('Certificate Table Size: ' + CertificateTableSize.toString());

var hdr = new Buffer(8);
fs.readSync(fd, hdr, 0, hdr.length, CertificateTableAddress);
console.log('dwLength = ' + hdr.readUInt32LE(0).toString());

console.log('Updating Table Entries: ');
optHeader.writeUInt32LE(6848, 132);
hdr.writeUInt32LE(6848, 0);

console.log('written', fs.writeSync(fd, optHeader, 0, optHeader.length, dosHeader.readUInt32LE(60) + 24));
console.log('written', fs.writeSync(fd, hdr, 0, hdr.length, CertificateTableAddress));

console.log('Done!');


fs.closeSync(fd);

//switch (hdr.readUInt16LE(6).toString(16).toUpperCase())
//{
//    case '1':
//        console.log('Cert Type = X509');
//        break;
//    case '2':
//        console.log('Cert Type = PKCS#7')
//        break;
//    case '3':
//        console.log('Cert Type = RESERVED')
//        break;
//    case '4':
//        console.log('Cert Type = TERMINAL_SERVER')
//        break;
//}

//var cert = new Buffer(hdr.readUInt32LE(0) - 8);
//fs.readSync(fd, cert, 0, cert.length, CertificateTableAddress + hdr.length);

//console.log('Cert Length: ' + cert.length);
//console.log(cert.toString());

//console.log(1);
//var ws = fs.createWriteStream("test.txt", { flags: "wb" });
//ws.write(cert);
//console.log(2);
//ws.end();
//console.log(3);


