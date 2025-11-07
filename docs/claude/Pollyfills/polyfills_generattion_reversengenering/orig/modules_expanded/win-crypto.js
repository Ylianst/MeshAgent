// Module: win-crypto
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 6720 bytes
// Decompressed size: 38555 bytes
// Compression ratio: 82.6%

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

var CRYPT_DECODE_NOCOPY_FLAG = 1;
var CERT_X500_NAME_STR = 3;
var CNG_RSA_PUBLIC_KEY_BLOB = 72;
var X509_CERT_TO_BE_SIGNED = 2;
var X509_CERT_REQUEST_TO_BE_SIGNED = 4;
var PROV_RSA_FULL = 1;
var CRYPT_MACHINE_KEYSET = 0x20;
var AT_SIGNATURE = 2;
var PKCS_7_ASN_ENCODING = 0x00010000;
var X509_ASN_ENCODING = 0x00000001;
var X509_DSS_PUBLICKEY = 38;
var X509_PUBLIC_KEY_INFO = 8;
var CERT_V1 = 0;
var CERT_V2 = 1;
var CERT_V3 = 2;
var BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 0x00000001;
var RSA_CSP_PUBLICKEYBLOB = 19;

var CRYPT_ALGORITHMS = {SHA1: "1.2.840.113549.1.1.5", SHA256: "1.2.840.113549.1.1.11", SHA384: "1.2.840.113549.1.1.12", SHA512: "1.2.840.113549.1.1.13"};
var CRYPT_ALGORITHMS_EX = { "1.2.840.113549.1.1.5": "SHA1", "1.2.840.113549.1.1.11": "SHA256", "1.2.840.113549.1.1.12": "SHA384", "1.2.840.113549.1.1.13": "SHA512" };

var CRYPT_EXTENSION_OIDS =
{
    szOID_AUTHORITY_KEY_IDENTIFIER: "2.5.29.1",
    szOID_KEY_ATTRIBUTES: "2.5.29.2",
    szOID_CERT_POLICIES_95: "2.5.29.3",
    szOID_KEY_USAGE_RESTRICTION: "2.5.29.4",
    szOID_SUBJECT_ALT_NAME: "2.5.29.7",
    szOID_ISSUER_ALT_NAME: "2.5.29.8",
    szOID_BASIC_CONSTRAINTS: "2.5.29.10",
    szOID_KEY_USAGE: "2.5.29.15",
    szOID_PRIVATEKEY_USAGE_PERIOD: "2.5.29.16",
    szOID_BASIC_CONSTRAINTS2: "2.5.29.19",
    szOID_CERT_POLICIES: "2.5.29.32",
    szOID_ANY_CERT_POLICY: "2.5.29.32.0",
    szOID_INHIBIT_ANY_POLICY: "2.5.29.54",
    szOID_AUTHORITY_KEY_IDENTIFIER2: "2.5.29.35",
    szOID_SUBJECT_KEY_IDENTIFIER: "2.5.29.14",
    szOID_SUBJECT_ALT_NAME2: "2.5.29.17",
    szOID_ISSUER_ALT_NAME2: "2.5.29.18",
    szOID_CRL_REASON_CODE: "2.5.29.21",
    szOID_REASON_CODE_HOLD: "2.5.29.23",
    szOID_CRL_DIST_POINTS: "2.5.29.31",
    szOID_ENHANCED_KEY_USAGE: "2.5.29.37",
    szOID_ANY_ENHANCED_KEY_USAGE: "2.5.29.37.0"
};

var CRYPT_KEY_ALGORITHMS =
{
    "1.2.840.113549": "RSA",
    "1.2.840.113549.1": "PKCS",
    "1.2.840.113549.2": "RSA_HASH",
    "1.2.840.113549.3": "RSA_ENCRYPT",

    "1.2.840.113549.1.1": "PKCS_1",
    "1.2.840.113549.1.2": "PKCS_2",
    "1.2.840.113549.1.3": "PKCS_3",
    "1.2.840.113549.1.4": "PKCS_4",
    "1.2.840.113549.1.5": "PKCS_5",
    "1.2.840.113549.1.6": "PKCS_6",
    "1.2.840.113549.1.7": "PKCS_7",
    "1.2.840.113549.1.8": "PKCS_8",
    "1.2.840.113549.1.9": "PKCS_9",
    "1.2.840.113549.1.10": "PKCS_10",
    "1.2.840.113549.1.12": "PKCS_12",

    "1.2.840.113549.1.1.1": "RSA_RSA",
    "1.2.840.113549.1.1.2": "RSA_MD2RSA",
    "1.2.840.113549.1.1.3": "RSA_MD4RSA",
    "1.2.840.113549.1.1.4": "RSA_MD5RSA",
    "1.2.840.113549.1.1.5": "RSA_SHA1RSA",
    "1.2.840.113549.1.1.6": "RSA_SETOAEP_RSA",

    "1.2.840.113549.1.1.7": "RSAES_OAEP",
    "1.2.840.113549.1.1.8": "RSA_MGF1",
    "1.2.840.113549.1.1.9": "RSA_PSPECIFIED",
    "1.2.840.113549.1.1.10": "RSA_SSA_PSS",
    "1.2.840.113549.1.1.11": "RSA_SHA256RSA",
    "1.2.840.113549.1.1.12": "RSA_SHA384RSA",
    "1.2.840.113549.1.1.13": "RSA_SHA512RSA",
    "1.2.840.113549.1.3.1": "RSA_DH"
};

var CRYPT_KEY_USAGES =
{
    CERT_DIGITAL_SIGNATURE_KEY_USAGE: 0x80,
    CERT_NON_REPUDIATION_KEY_USAGE: 0x40,
    CERT_KEY_ENCIPHERMENT_KEY_USAGE: 0x20,
    CERT_DATA_ENCIPHERMENT_KEY_USAGE: 0x10,
    CERT_KEY_AGREEMENT_KEY_USAGE: 0x08,
    CERT_KEY_CERT_SIGN_KEY_USAGE: 0x04,
    CERT_OFFLINE_CRL_SIGN_KEY_USAGE: 0x02,
    CERT_CRL_SIGN_KEY_USAGE: 0x02,
    CERT_ENCIPHER_ONLY_KEY_USAGE: 0x01
};

function WinCrypto()
{
    this._ObjectID = 'win-crypto';
    this._marshal = require('_GenericMarshal');
    this._Kernel32 = this._marshal.CreateNativeProxy('Kernel32.dll');
    this._Kernel32.CreateMethod('FileTimeToSystemTime');
    this._Kernel32.CreateMethod('SystemTimeToFileTime');
    this._Kernel32.CreateMethod('GetLastError');
    this._Kernel32.CreateMethod('GetSystemTime');

    this._Bcrypt = this._marshal.CreateNativeProxy('Bcrypt.dll');
    this._Bcrypt.CreateMethod('BCryptGenRandom');
    this._Bcrypt.CreateMethod('BCryptCloseAlgorithmProvider');
    this._Bcrypt.CreateMethod('BCryptOpenAlgorithmProvider');

    this._Crypt32 = this._marshal.CreateNativeProxy('Crypt32.dll');
    this._Crypt32.CreateMethod('CertStrToNameA');
    this._Crypt32.CreateMethod('CertCreateCertificateContext');
    this._Crypt32.CreateMethod('CertCreateSelfSignCertificate');
    this._Crypt32.CreateMethod('CryptAcquireCertificatePrivateKey');
    this._Crypt32.CreateMethod('CryptDecodeObject');
    this._Crypt32.CreateMethod('CryptDecodeObjectEx');
    this._Crypt32.CreateMethod('CryptEncodeObject');
    this._Crypt32.CreateMethod('CryptHashCertificate');
    this._Crypt32.CreateMethod('CryptSignMessage');
    this._Crypt32.CreateMethod('CryptSignAndEncodeCertificate');
    this._Crypt32.CreateMethod('CryptStringToBinaryA');
    this._Crypt32.CreateMethod('CryptVerifyMessageSignature');
    this.CRYPT_KEY_ALGORITHMS_OIDS = {};
    for(var i in CRYPT_KEY_ALGORITHMS)
    {
        this.CRYPT_KEY_ALGORITHMS_OIDS[CRYPT_KEY_ALGORITHMS[i]] = i;
    }
    this.CRYPT_ENHANCED_KEY_USAGES =
    {
        CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
        SERVER_AUTH: '1.3.6.1.5.5.7.3.1'
    };

    this.X509_ASN_ENCODING = 0x00000001;
    this.PKCS_7_ASN_ENCODING = 0x00010000;
    this.BCRYPT_RNG_ALGORITHM = this._marshal.CreateVariable('RNG', { wide: true });

    this.createKeyRestriction = function createKeyRestriction()
    {
        var retVal =
            {
                CERT_DATA_ENCIPHERMENT_KEY_USAGE: false,
                CERT_DIGITAL_SIGNATURE_KEY_USAGE: false,
                CERT_KEY_AGREEMENT_KEY_USAGE: false,
                CERT_KEY_CERT_SIGN_KEY_USAGE: false,
                CERT_KEY_ENCIPHERMENT_KEY_USAGE: false,
                CERT_NON_REPUDIATION_KEY_USAGE: false,
                CERT_OFFLINE_CRL_SIGN_KEY_USAGE: false
            }
        return (retVal);
    }

    this.makeCert = function makeCert(options)
    {
        if (!options._algorithm || !CRYPT_ALGORITHMS[options._algorithm]) { throw ('Invalid Algorithm specified: ' + options._algorithm); }
        var extensions = [];
        var ext = null;

        // CN => Common Name
        // T => Title
        // L => Locality Name
        // O => Organization Name
        // C => Country
        // S => State or Province
        // STREET => Street Address

        var inStr = '';
        var delimiter = '';

        for(var i in options)
        {
            if (!i.startsWith('_'))
            {
                inStr += (delimiter + i + '=' + options[i]);
                if (delimiter == '') { delimiter = ', '; }
            }
        }
        console.log('Certificate Options: ' + inStr);

        // Check Extensions
        if (options._keyRestrictions)
        {
            var restrictions = this._marshal.CreateVariable(1);
            restrictions.byte = restrictions.toBuffer()[0];
            for(var i in options._keyRestrictions)
            {
                if (options._keyRestrictions[i] == true && CRYPT_KEY_USAGES[i]) { restrictions.byte |= CRYPT_KEY_USAGES[i]; }
            }
            if (restrictions.byte != 0)
            {
                var restrictionInfo = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 20 : 40);
                if(this._marshal.PointerSize == 4)
                {
                    restrictionInfo.Deref(8, 4).toBuffer().writeUInt32LE(1);
                    restrictions.pointerBuffer().copy(restrictionInfo.Deref(12, 4).toBuffer());
                }
                else
                {
                    restrictionInfo.Deref(16, 4).toBuffer().writeUInt32LE(1);
                    restrictions.pointerBuffer().copy(restrictionInfo.Deref(24, 8).toBuffer());
                }
                var encodedObject = this.CryptEncodeObject(this.X509_ASN_ENCODING, CRYPT_EXTENSION_OIDS.szOID_KEY_USAGE_RESTRICTION, restrictionInfo);
                encodedObject.oid = CRYPT_EXTENSION_OIDS.szOID_KEY_USAGE_RESTRICTION;
                extensions.push(encodedObject);
            }
        }
        if (extensions.length > 0)
        {
            ext = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? (16 * extensions.length) : (32 * extensions.length));
            ext.stor = [];
            for(var i in extensions)
            {
                var oid = this._marshal.CreateVariable(extensions[i].oid); ext.stor.push(oid);
                var x = this._marshal.PointerSize == 4 ? (16 * i) : (32 * i);
                oid.pointerBuffer().copy(ext.Deref(x, this._marshal.PointerSize).toBuffer());
                
                ext.Deref(x + this._marshal.PointerSize, 4).toBuffer().writeUInt32LE(1);
                ext.Deref(x + this._marshal.PointerSize == 4 ? 8 : 16, 4).toBuffer().writeUInt32LE(extensions[i]._size);
                extensions[i].pointerBuffer().copy(ext.Deref(x + this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize).toBuffer());
            }

            var extContainer = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 8 : 16);
            extContainer.Deref(0, 4).toBuffer().writeUInt32LE(extensions.length);
            ext.pointerBuffer().copy(extContainer.Deref(this._marshal.PointerSize, this._marshal.PointerSize).toBuffer());
            extContainer.ext = ext;
            ext = extContainer;
        }

        var pszX500 = this._marshal.CreateVariable(inStr);
        var cbEncoded = this._marshal.CreateVariable(4);
        var pbEncoded = 0;

        cbEncoded.toBuffer().writeUInt32LE(0);
        if(this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, pbEncoded, cbEncoded, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }

        pbEncoded = this._marshal.CreateVariable(cbEncoded.toBuffer().readUInt32LE());
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, pbEncoded, cbEncoded, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }

        var blob = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 8 : 16);
        blob.toBuffer().writeUInt32LE(cbEncoded.toBuffer().readUInt32LE(), 0);
        pbEncoded.pointerBuffer().copy(blob.toBuffer(), this._marshal.PointerSize);

        var keyProvider = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 28 : 48);
        var containerName = this._marshal.CreateVariable(options.CN, { wide: true });

        containerName.pointerBuffer().copy(keyProvider.toBuffer());
        keyProvider.toBuffer().writeUInt32LE(PROV_RSA_FULL, this._marshal.PointerSize == 4 ? 8 : 16);
        keyProvider.toBuffer().writeUInt32LE(CRYPT_MACHINE_KEYSET, this._marshal.PointerSize == 4 ? 12 : 20);
        keyProvider.toBuffer().writeUInt32LE(AT_SIGNATURE, this._marshal.PointerSize == 4 ? 24 : 40);
        var cryptAlgorithm = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 12 : 24);
        var algo = this._marshal.CreateVariable(CRYPT_ALGORITHMS[options._algorithm]);
        algo.pointerBuffer().copy(cryptAlgorithm.toBuffer());

        var expiration = this._marshal.CreateVariable(16);
        this._Kernel32.GetSystemTime(expiration);
        
        // If today is Feb-29, change the expiration to Feb-28, because that's simpler than dealing with leap-year exception complexity
        if (expiration.toBuffer().readUInt16LE(2) == 2 && expiration.toBuffer().readUInt16LE(6) == 29) { exipiration.toBuffer().writeUInt16LE(28, 6); }
        var year = expiration.toBuffer().readUInt16LE(0);
        year += options._years;
        expiration.toBuffer().writeUInt16LE(year, 0);

        var pCert = this._Crypt32.CertCreateSelfSignCertificate(0, blob, 0, keyProvider, cryptAlgorithm, 0, expiration, ext ? ext : 0);
        if (pCert.Val == 0) {
            console.log('Error Code = ' + this._Kernel32.GetLastError().Val);
        }
        console.log('pCert = ' + pCert.Val);

        var privateKey = this._marshal.CreatePointer();
        var keyspec = this._marshal.CreateVariable(4);
        var needFree = this._marshal.CreateVariable(4);

        if(pCert.Val != 0)
        {
            var keyResult = this._Crypt32.CryptAcquireCertificatePrivateKey(pCert, 0, 0, privateKey, keyspec, needFree);
            pCert.privateKey = privateKey.Deref();
            pCert.privateKey.keySpec = keyspec.toBuffer().readUInt32LE();
            pCert.privateKey.needFree = needFree.toBuffer().readUInt32LE();
            console.log('keyResult=' + keyResult.Val);
            console.log('NeedFree=' + needFree.toBuffer().readUInt32LE());
            console.log('KeySpec=' + keyspec.toBuffer().readUInt32LE());


            var certInfo = pCert.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize).Deref(this._marshal.PointerSize == 4 ? 112 : 208);
            var signatureAlgorithm = certInfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize);
            var publicKeyInfo = certInfo.Deref(this._marshal.PointerSize == 4 ? 56 : 96, this._marshal.PointerSize == 4 ? 24 : 48);
            var keyAlgorithm = publicKeyInfo.Deref(0, this._marshal.PointerSize == 4 ? 12 : 24);
            var keyLen = publicKeyInfo.Deref(this._marshal.PointerSize == 4 ? 12 : 16, 4).toBuffer().readUInt32LE();

            var key = publicKeyInfo.Deref(this._marshal.PointerSize == 4 ? 16 : 32, this._marshal.PointerSize).Deref(keyLen);
            pCert.publicKey = key.toBuffer();
            pCert.publicKey._key = key;
            pCert.publicKey.oid = keyAlgorithm.Deref().String;
            pCert.SubjectPublicKeyInfo = publicKeyInfo;
            pCert.Subject = certInfo.Deref(this._marshal.PointerSize == 4 ? 48 : 80, this._marshal.PointerSize == 4 ? 112 : 208);
            console.log('PublicKey/OID: ' + pCert.publicKey.oid);
        }
        pCert.parent = this;
        pCert.signMessage = function signMessage(message, options)
        {
            var crypto = this.parent;
            var signMessagePara = crypto._marshal.CreateVariable(crypto._marshal.PointerSize == 4 ? 68 : 120);
            var cbSize = signMessagePara.Deref(0, 4);
            var msgEncodingType = signMessagePara.Deref(4, 4);
            var pcertContext = signMessagePara.Deref(8, crypto._marshal.PointerSize);
            var hashAlgorithm = signMessagePara.Deref(crypto._marshal.PointerSize == 4 ? 12 : 16, crypto._marshal.PointerSize == 4 ? 12 : 24);
            var cMsgCert = signMessagePara.Deref(crypto._marshal.PointerSize == 4 ? 28 : 48, 4);
            var rgpMsgCert = signMessagePara.Deref(crypto._marshal.PointerSize == 4 ? 32 : 56, crypto._marshal.PointerSize);
            var algorithm = crypto._marshal.CreateVariable(CRYPT_ALGORITHMS[options.hashAlgorithm]);

            var msgArray = crypto._marshal.CreateVariable(message.length);
            var rgcbToBeSigned = crypto._marshal.CreateVariable(4);
            var signedMessage;
            var signedMessageLen = crypto._marshal.CreateVariable(4);
            signedMessageLen.toBuffer().writeUInt32LE(0);

            rgcbToBeSigned.toBuffer().writeUInt32LE(message.length);
            message.copy(msgArray.toBuffer());

            algorithm.pointerBuffer().copy(hashAlgorithm.toBuffer());
            msgEncodingType.toBuffer().writeUInt32LE(options.encodingType);

            cbSize.toBuffer().writeUInt32LE(crypto._marshal.PointerSize == 4 ? 68 : 120);
            msgEncodingType.toBuffer().writeUInt32LE(PKCS_7_ASN_ENCODING);
            this.pointerBuffer().copy(pcertContext.toBuffer());
            cMsgCert.toBuffer().writeUInt32LE(1);
            pcertContext.getPointerPointer().toBuffer().copy(rgpMsgCert.toBuffer());

            var result = crypto._Crypt32.CryptSignMessage(signMessagePara, 0, 1, msgArray.getPointerPointer(), rgcbToBeSigned, 0, signedMessageLen).Val;
            if (result != 0)
            {
                signedMessage = crypto._marshal.CreateVariable(signedMessageLen.toBuffer().readUInt32LE());
                if(crypto._Crypt32.CryptSignMessage(signMessagePara, 0, 1, msgArray.getPointerPointer(), rgcbToBeSigned, signedMessage, signedMessageLen).Val != 0)
                {
                    var retVal = signedMessage.toBuffer();
                    retVal._owner = signedMessage;
                    return (retVal);
                }
                else
                {
                    throw ('Error Signing Message: ' + crypto._Kernel32.GetLastError().Val);
                }
            }
            else
            {
                throw ('Error Signing Message: ' + crypto._Kernel32.GetLastError().Val);
            }
        };
        return (pCert);
    };
    this.verifyMessage = function verifyMessage(message, options)
    {
        var verifyParam = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 20 : 32);
        var _cbSize = verifyParam.Deref(0, 4);
        var _dwMsgAndCertEncodingType = verifyParam.Deref(4, 4);
        var signedMessage = this._marshal.CreateVariable(message.length);
        message.copy(signedMessage.toBuffer());
        var decodedLength = this._marshal.CreateVariable(4);
        decodedLength.toBuffer().writeUInt32LE(0);

        _cbSize.toBuffer().writeUInt32LE(this._marshal.PointerSize == 4 ? 20 : 32);
        _dwMsgAndCertEncodingType.toBuffer().writeUInt32LE(options.encodingType);

        var result = this._Crypt32.CryptVerifyMessageSignature(verifyParam, 0, signedMessage, message.length, 0, decodedLength, 0).Val;
        if(result != 0)
        {
            var signerCert = this._marshal.CreatePointer();
            var decoded = this._marshal.CreateVariable(decodedLength.toBuffer().readUInt32LE());
            console.log('Decoded Length = ' + decodedLength.toBuffer().readUInt32LE());

            if (this._Crypt32.CryptVerifyMessageSignature(verifyParam, 0, signedMessage, message.length, decoded, decodedLength, 0).Val != 0)
            {
                var retVal = decoded.toBuffer();
                retVal._owner = decoded;
                return (retVal);
            }
            else
            {
                throw ('Error Verifying Message: ' + this._Kernel32.GetLastError().Val);
            }
        }
        else
        {
            throw ('Error Verifying Message2');
        }
    };
    this.loadCert = function loadCert(encodedCert, options)
    {
        console.log('LoadCert: ' + options.encodingType, 'Length: ' + encodedCert.length);
        var pbCertEncoded = this._marshal.CreateVariable(encodedCert.length);
        encodedCert.copy(pbCertEncoded.toBuffer());

        var pcert = this._Crypt32.CertCreateCertificateContext(options.encodingType, pbCertEncoded, encodedCert.length);
        if(pcert.Val == 0)
        {
            throw ('Error loading Certificate: ' + this._Kernel32.GetLastError().Val);
        }
        else
        {
            pcert._marshal = this._marshal;
            pcert._Crypt32 = this._Crypt32;
            pcert._Kernel32 = this._Kernel32;
            pcert._raw = pbCertEncoded;
            pcert.getInfo = getInfo;
            return (pcert);
        }
    };
    this.EncodeString = function EncodeString(inStr)
    {
        var pszX500 = this._marshal.CreateVariable(inStr);
        var dwSize = this._marshal.CreateVariable(4);
        dwSize.toBuffer().writeUInt32LE(0);

        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, 0, dwSize, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }
        var pbEncoded = this._marshal.CreateVariable(dwSize.toBuffer().readUInt32LE());
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, pbEncoded, dwSize, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }
        pbEncoded._size = dwSize.toBuffer().readUInt32LE();
        return (pbEncoded);
    };
    this.CryptEncodeObject = function CryptEncodeObject(encodingType, structType, data)
    {
        var dwBufferSize = this._marshal.CreateVariable(4);
        var stype = typeof (structType) == 'number' ? structType : this._marshal.CreateVariable(structType);

        if(this._Crypt32.CryptEncodeObject(encodingType, stype, data, 0, dwBufferSize).Val == 0)
        {
            throw ('Error Calling CryptEncodeObject (' + this._Kernel32.GetLastError().Val + ')');
        }

        var outData = this._marshal.CreateVariable(dwBufferSize.toBuffer().readUInt32LE());
        if (this._Crypt32.CryptEncodeObject(encodingType, stype, data, outData, dwBufferSize).Val == 0)
        {
            throw ('Error Calling CryptEncodeObject (' + this._Kernel32.GetLastError().Val + ')');
        }
        outData._size = dwBufferSize.toBuffer().readUInt32LE();
        return (outData);
    }
    this.MakeCertFromPublicKey = function MakeCertFromPublicKey(options)
    {
        if (!options.Issuer || !options.Subject || !options.PublicKey || !options.SigningCert || !options.SignatureAlgorithm) { throw ('Missing Parameters: Issuer, Subject, PublicKey, SigningCert, SignatureAlgorithm'); }
        var extensions = [];
        var certinfo = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 112 : 208);
        certinfo.Deref(0, 4).toBuffer().writeUInt32LE(CERT_V3);
        var provider = this._marshal.CreatePointer();
        var r = this._Bcrypt.BCryptOpenAlgorithmProvider(provider, this.BCRYPT_RNG_ALGORITHM, 0, 0).Val;

        if (r != 0)
        {
            throw('Error opening RandomNumberGenerator')
        }
        var serial = this._marshal.CreateVariable(8);
        r = this._Bcrypt.BCryptGenRandom(provider.Deref(), serial, serial._size, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER).Val;
        r = this._Bcrypt.BCryptCloseAlgorithmProvider(provider.Deref(), 0).Val;
        

        // SerialNumber
        certinfo.Deref(this._marshal.PointerSize == 4 ? 4 : 8, 4).toBuffer().writeUInt32LE(serial._size);
        serial.pointerBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 8 : 16, this._marshal.PointerSize).toBuffer());
        certinfo._serial = serial;

        // Signature Algorithm
        certinfo._SignatureAlgorithm = certinfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize == 4 ? 12 : 24);
        certinfo._SignatureAlgorithm.oid = this._marshal.CreateVariable(options.SignatureAlgorithm);
        certinfo._SignatureAlgorithm.oid.pointerBuffer().copy(certinfo._SignatureAlgorithm.Deref(0, this._marshal.PointerSize).toBuffer());

        // Issuer
        certinfo._Issuer_Unencoded = this._marshal.CreateVariable(options.Issuer);
        certinfo._Issuer_encodedSize = this._marshal.CreateVariable(4);
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, certinfo._Issuer_Unencoded, CERT_X500_NAME_STR, 0, 0, certinfo._Issuer_encodedSize, 0).Val == 0) { throw ('Error Calling CertStrToName'); }
        certinfo._Issuer_encoded = this._marshal.CreateVariable(certinfo._Issuer_encodedSize.toBuffer().readUInt32LE());
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, certinfo._Issuer_Unencoded, CERT_X500_NAME_STR, 0, certinfo._Issuer_encoded, certinfo._Issuer_encodedSize, 0).Val == 0) { throw ('Error Calling CertStrToName'); }
        certinfo._Issuer_encoded._size = certinfo._Issuer_encodedSize.toBuffer().readUInt32LE();

        certinfo.Deref(this._marshal.PointerSize == 4 ? 24 : 48, 4).toBuffer().writeUInt32LE(certinfo._Issuer_encoded._size);
        certinfo._Issuer_encoded.pointerBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 28 : 56, this._marshal.PointerSize).toBuffer());

        // Subject
        var delimiter = '';
        var inStr = '';
        for (var i in options.Subject)
        {
            inStr += (delimiter + i + '=' + options.Subject[i]);
            if (delimiter == '') { delimiter = ', '; }
        }

        var pszX500 = this._marshal.CreateVariable(inStr);
        var cbEncoded = this._marshal.CreateVariable(4);
        var pbEncoded = 0;
        cbEncoded.toBuffer().writeUInt32LE(0);
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, pbEncoded, cbEncoded, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }
        pbEncoded = this._marshal.CreateVariable(cbEncoded.toBuffer().readUInt32LE());
        if (this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, 0, pbEncoded, cbEncoded, 0).Val == 0)
        {
            throw ("Error calling 'CertStrToName', Error Code = " + this._Kernel32.GetLastError().Val);
        }
        pbEncoded._size = cbEncoded.toBuffer().readUInt32LE();

        certinfo._Subject = pbEncoded;
        certinfo.Deref(this._marshal.PointerSize == 4 ? 48 : 80, 4).toBuffer().writeUInt32LE(pbEncoded._size);
        pbEncoded.pointerBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 52 : 88, this._marshal.PointerSize).toBuffer());

        // SubjectPublicKeyInfo
        certinfo._pkinfo = certinfo.Deref(this._marshal.PointerSize == 4 ? 56 : 96, this._marshal.PointerSize == 4 ? 24 : 48);
        certinfo._pkinfo._oid = this._marshal.CreateVariable(options.PublicKey.oid);
        certinfo._pkinfo._oid.pointerBuffer().copy(certinfo._pkinfo.Deref(0, this._marshal.PointerSize).toBuffer());
        certinfo._pkinfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, 4).toBuffer().writeUInt32LE(options.PublicKey.length);
        certinfo._pkinfo._key = this._marshal.CreateVariable(options.PublicKey.length);
        options.PublicKey.copy(certinfo._pkinfo._key.toBuffer());
        certinfo._pkinfo._key.pointerBuffer().copy(certinfo._pkinfo.Deref(this._marshal.PointerSize == 4 ? 16 : 32, this._marshal.PointerSize).toBuffer());

        var ft_notBefore_dt = new Date(); ft_notBefore_dt.setTime(Date.now() - 3600000);                        // One Hour Ago
        var ft_notBefore = this.dateToFileTime(ft_notBefore_dt);                     
        ft_notBefore.toBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 32 : 64, 8).toBuffer());
        
        var ft_notAfter_dt = new Date(); ft_notAfter_dt.setTime(Date.now() + (365 * 24 * 60 * 60 * 1000));      // One Year from now
        var ft_notAfter = this.dateToFileTime(ft_notAfter_dt);
        ft_notAfter.toBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 40 : 72, 8).toBuffer());

        // Parse Extensions
        if (options.KeyUsage)
        {
            var restrictionInfo = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 20 : 40);
            restrictionInfo.bitBlob = this._marshal.CreateVariable(1);
            var b = 0;
            for (var i in options.KeyUsage)
            {
                if (CRYPT_KEY_USAGES[options.KeyUsage[i]]) { b |= CRYPT_KEY_USAGES[options.KeyUsage[i]]; }
            }
            restrictionInfo.bitBlob.toBuffer()[0] = b;

            if (this._marshal.PointerSize == 4)
            {
                restrictionInfo.Deref(8, 4).toBuffer().writeUInt32LE(restrictionInfo.bitBlob._size);
                restrictionInfo.bitBlob.pointerBuffer().copy(restrictionInfo.Deref(12, 4).toBuffer());
            }
            else
            {
                restrictionInfo.Deref(16, 4).toBuffer().writeUInt32LE(restrictionInfo.bitBlob._size);
                restrictionInfo.bitBlob.pointerBuffer().copy(restrictionInfo.Deref(24, 8).toBuffer());
            }

            restrictionInfo.encodedObject = this.CryptEncodeObject(this.X509_ASN_ENCODING, CRYPT_EXTENSION_OIDS.szOID_KEY_USAGE_RESTRICTION, restrictionInfo);
            restrictionInfo.encodedObject.oid = CRYPT_EXTENSION_OIDS.szOID_KEY_USAGE_RESTRICTION;
            restrictionInfo.encodedObject.ri = restrictionInfo;
            extensions.push(restrictionInfo.encodedObject);
        }
        if (options.EnhancedKeyUsages)
        {
            var eku = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 8 : 16);
            eku.Deref(0, 4).toBuffer().writeUInt32LE(options.EnhancedKeyUsages.length); // cUsageIdentifier

            eku._array = this._marshal.CreateVariable(options.EnhancedKeyUsages.length * this._marshal.PointerSize);
            for(var i in options.EnhancedKeyUsages)
            {
                eku._array[i] = this._marshal.CreateVariable(options.EnhancedKeyUsages[i]);
                eku._array[i].pointerBuffer().copy(eku._array.Deref(i * this._marshal.PointerSize, this._marshal.PointerSize).toBuffer());
            }

            eku._array.pointerBuffer().copy(eku.Deref(this._marshal.PointerSize, this._marshal.PointerSize).toBuffer()); //rgpszUsageIdentifier
            eku.oid = CRYPT_EXTENSION_OIDS.szOID_ENHANCED_KEY_USAGE;
            
            eku.encodedObject = this.CryptEncodeObject(this.X509_ASN_ENCODING, CRYPT_EXTENSION_OIDS.szOID_ENHANCED_KEY_USAGE, eku);
            eku.encodedObject.oid = CRYPT_EXTENSION_OIDS.szOID_ENHANCED_KEY_USAGE;
            eku.encodedObject.eku = eku;
            extensions.push(eku.encodedObject);
        }


        // Add Extensions
        if (extensions.length > 0)
        {
            var ext = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? (16 * extensions.length) : (32 * extensions.length));
            ext.stor = [];
            for (var i in extensions)
            {
                var oid = this._marshal.CreateVariable(extensions[i].oid); ext.stor.push(oid);
                var x = this._marshal.PointerSize == 4 ? (16 * i) : (32 * i);
                oid.pointerBuffer().copy(ext.Deref(x, this._marshal.PointerSize).toBuffer());

                ext.Deref(x + this._marshal.PointerSize, 4).toBuffer().writeUInt32LE(1);
                ext.Deref(x + (this._marshal.PointerSize == 4 ? 8 : 16), 4).toBuffer().writeUInt32LE(extensions[i]._size);
                extensions[i].pointerBuffer().copy(ext.Deref(x + (this._marshal.PointerSize == 4 ? 12 : 24), this._marshal.PointerSize).toBuffer());
            }

            certinfo._ext = ext;
            certinfo.Deref(this._marshal.PointerSize == 4 ? 104 : 192, 4).toBuffer().writeUInt32LE(extensions.length);                  // cExtension
            ext.pointerBuffer().copy(certinfo.Deref(this._marshal.PointerSize == 4 ? 108 : 200, this._marshal.PointerSize).toBuffer()); // rgExtension
        }


        return (certinfo);
    };
    
    this.SignCertificate = function SignCertificate(signingCert, certinfo)
    {
        var sig = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 12 : 24);
        sig.oid = this._marshal.CreateVariable(CRYPT_ALGORITHMS.SHA1);
        sig.oid.pointerBuffer().copy(sig.Deref(0, this._marshal.PointerSize).toBuffer());
        var dwSize = this._marshal.CreateVariable(4);

        if (this._Crypt32.CryptSignAndEncodeCertificate(signingCert.privateKey, signingCert.privateKey.keySpec, this.X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, certinfo, sig, 0, 0, dwSize).Val != 0)
        {
            // success
            var pbEncoded = this._marshal.CreateVariable(dwSize.toBuffer().readUInt32LE());
            console.log('KeySpec: ' + signingCert.privateKey.keySpec);
            console.log(this._Crypt32.CryptSignAndEncodeCertificate(signingCert.privateKey, signingCert.privateKey.keySpec, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, certinfo, sig, 0, pbEncoded, dwSize).Val);
            console.log('dwSize: ' + dwSize.toBuffer().readUInt32LE());
            pbEncoded._size = dwSize.toBuffer().readUInt32LE();
            return (pbEncoded);
        }
        else {
            throw ('Error: ' + this._Kernel32.GetLastError().Val);
        }
    };
    this.SignCertRequest_old = function SignCertRequest_old(signingCert, publicKeyInfo)
    {
        //var certRequestInfo = this.MakeCertRequestInfo(publicKeyInfo.subject, publicKeyInfo);
        var certRequestInfo = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 44 : 88);
        certRequestInfo.subject = certRequestInfo.Deref(this._marshal.PointerSize == 4 ? 4 : 8, this._marshal.PointerSize == 4 ? 8 : 16);
        certRequestInfo.subjectPublicKeyInfo = certRequestInfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize == 4 ? 24 : 48);

        signingCert.Subject.toBuffer().copy(certRequestInfo.subject.toBuffer());
        signingCert.SubjectPublicKeyInfo.toBuffer().copy(certRequestInfo.subjectPublicKeyInfo.toBuffer());

        var sig = this._marshal.CreateVariable(this._marshal.PointerSize == 4 ? 12 : 24);
        sig.oid = this._marshal.CreateVariable(CRYPT_ALGORITHMS.SHA1);
        sig.oid.pointerBuffer().copy(sig.Deref(0,this._marshal.PointerSize).toBuffer());
        var dwSize = this._marshal.CreateVariable(4);

        if (this._Crypt32.CryptSignAndEncodeCertificate(signingCert.privateKey, signingCert.privateKey.keySpec, this.X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED, certRequestInfo, sig, 0, 0, dwSize).Val != 0)
        {
            // success
            var pbEncoded = this._marshal.CreateVariable(dwSize.toBuffer().readUInt32LE());
            console.log('KeySpec: ' + signingCert.privateKey.keySpec);
            console.log(this._Crypt32.CryptSignAndEncodeCertificate(signingCert.privateKey, signingCert.privateKey.keySpec, X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED, certRequestInfo, sig, 0, pbEncoded, dwSize).Val);
            console.log('dwSize: ' + dwSize.toBuffer().readUInt32LE());
            pbEncoded._size = dwSize.toBuffer().readUInt32LE();
            return (pbEncoded);
        }
        else
        {
            throw ('Error: ' + this._Kernel32.GetLastError().Val);
        }
    };
    this.dateToFileTime = function dateToFileTime(dt)
    {
        var systemtime = this._marshal.CreateVariable(16);
        var filetime = this._marshal.CreateVariable(8);

        systemtime.Deref(0,2).toBuffer().writeUInt16LE(dt.getUTCFullYear());
        systemtime.Deref(2, 2).toBuffer().writeUInt16LE(dt.getUTCMonth() + 1);
        systemtime.Deref(6, 2).toBuffer().writeUInt16LE(dt.getUTCDate());
        systemtime.Deref(8, 2).toBuffer().writeUInt16LE(dt.getUTCHours());
        systemtime.Deref(10, 2).toBuffer().writeUInt16LE(dt.getUTCMinutes());
        systemtime.Deref(12, 2).toBuffer().writeUInt16LE(dt.getUTCSeconds());
        systemtime.Deref(14, 2).toBuffer().writeUInt16LE(dt.getUTCMilliseconds());

        if(this._Kernel32.SystemTimeToFileTime(systemtime, filetime).Val == 0)
        {
            throw ('Error converting time: ' + this._Kernel32.GetLastError().Val);
        }
        return (filetime);
    };
    this.fileTimeToDate = function fileTimeToDate(ft)
    {
        var systemtime = this._marshal.CreateVariable(16);
        if(this._Kernel32.FileTimeToSystemTime(ft, systemtime).Val == 0)
        {
            throw ('Error convertin filetime: ' + this._Kernel32.GetLastError().Val);
        }

        var ret = Date.now();
        var buffer = systemtime.toBuffer();

        ret.setUTCFullYear(buffer.readUInt16LE(0));
        ret.setUTCMonth(buffer.readUInt16LE(2));
        ret.setUTCDate(buffer.readUInt16LE(6));
        ret.setUTCHours(buffer.readUInt16LE(8));
        ret.setUTCMinutes(buffer.readUInt16LE(10));
        ret.setUTCSeconds(buffer.readUInt16LE(12));
        ret.setUTCMilliseconds(buffer.readUInt16LE(14));
        
        return (ret);
    };
}
function getInfo(options)
{
    var certInfo = this.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize).Deref(this._marshal.PointerSize == 4 ? 112 : 208);
    var signatureAlgorithm = certInfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, this._marshal.PointerSize);
    var publicKeyInfo = certInfo.Deref(this._marshal.PointerSize == 4 ? 56 : 96, this._marshal.PointerSize == 4 ? 24 : 48);
    var keyAlgorithm = publicKeyInfo.Deref(0, this._marshal.PointerSize == 4 ? 12 : 24);
    var publicKeyLen = publicKeyInfo.Deref(this._marshal.PointerSize == 4 ? 12 : 24, 4).toBuffer().readUInt32LE();
    var publicKey = publicKeyInfo.Deref(this._marshal.PointerSize == 4 ? 16 : 32, this._marshal.PointerSize).Deref(publicKeyLen).toBuffer().toString('base64');

    var thumbprintHash = 'SHA1Stream';
    if (options)
    {
        switch(options.thumbprint)
        {
            case 'MD5':
                thumbprintHash = 'MD5Stream';
                break;
            case 'SHA1':
                thumbprintHash = 'SHA1Stream';
                break;
            case 'SHA256':
                thumbprintHash = 'SHA256Stream';
                break;
            case 'SHA384':
                thumbprintHash = 'SHA384Stream';
                break;
            case 'SHA512':
                thumbprintHash = 'SHA512Stream';
                break;
        }
    }

    var retVal = {};
    retVal.version = certInfo.toBuffer().readUInt32LE();
    retVal.signatureAlgorithm = CRYPT_ALGORITHMS_EX[signatureAlgorithm.Deref().String];
    retVal.keyAlgorithm = CRYPT_KEY_ALGORITHMS[keyAlgorithm.Deref().String];
    retVal.publicKey = publicKey;
    retVal.thumbprint = require(thumbprintHash).create().syncHash(this._raw.toBuffer()).toString('hex');
    retVal.thumbprintAlgorithm = options ? options.thumbprint : 'SHA1';
    return (retVal);
}



module.exports = new WinCrypto();

//var cng = new WinCrypto();
//var cert = cng.makeCert({ CN: 'Bryan Test', T: 'My Title', _algorithm: 'SHA256', _years: 1 });
//var msg = cert.signMessage(Buffer.from('this is testing'), { hashAlgorithm: 'SHA256', encodingType: PKCS_7_ASN_ENCODING });
//console.log(msg.toString('hex'));

//var pkcs7 = require('pkcs7');
//var result = pkcs7.getSignedDataBlock(msg);
//console.log(result.data, result.signingCertificate.publicKeyHash, result.signingCertificate.fingerprint);

//var decoded = cng.verifyMessage(msg, { encodingType: PKCS_7_ASN_ENCODING });
//console.log(decoded.toString());