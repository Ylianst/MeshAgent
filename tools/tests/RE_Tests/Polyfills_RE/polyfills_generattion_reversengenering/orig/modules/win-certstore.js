/*
Copyright 2019 Intel Corporation

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
const CERT_FIND_SUBJECT_NAME = (2 << 16 | 7);
const CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
const CERT_STORE_PROV_SYSTEM = 10;
const CERT_X500_NAME_STR = 3;
const PKCS_7_ASN_ENCODING = 0x00010000;
const X509_ASN_ENCODING = 0x00000001;
const CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001;
const CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002;

function certstore()
{
    this._ObjectID = 'win-certstore';
    this._marshal = require('_GenericMarshal');
    this._Crypt32 = this._marshal.CreateNativeProxy('Crypt32.dll');
    this._Crypt32.CreateMethod('CertCloseStore');
    this._Crypt32.CreateMethod('CertDeleteCertificateFromStore');
    this._Crypt32.CreateMethod('CertFindCertificateInStore');
    this._Crypt32.CreateMethod('CertOpenStore');
    this._Crypt32.CreateMethod('CertStrToNameA');

    this._Ncrpyt = this._marshal.CreateNativeProxy('Ncrypt.dll');
    this._Ncrpyt.CreateMethod('NCryptFreeObject');
    this._Ncrpyt.CreateMethod('NCryptOpenStorageProvider');
    this.STORE_LOCATION = { LOCAL_MACHINE: 2 << 16, CURRENT_USER: 1 << 16 };
    this.PROVIDERS = [this._marshal.CreateVariable('Microsoft Platform Crypto Provider', { wide: true }), this._marshal.CreateVariable('Microsoft Software Key Storage Provider', { wide: true })];

    this.OpenCryptoProvider = function OpenCryptoProvider()
    {
        var ret = null;
        var p = this._marshal.CreatePointer();
        for(var provider in this.PROVIDERS)
        {
            this._Ncrpyt.NCryptOpenStorageProvider(p, this.PROVIDERS[provider], 0);
            if (p.Deref().Val != 0) { ret = p.Deref(); ret._b = p; break;}
        }
        if (ret == null) { throw ('Unable to open CryptoProvider'); }
        ret._crypt = this;
        ret._finalized = false;
        ret.close = function()
        {
            this._finalized = true;
            this._crypt._Ncrpyt.NCryptFreeObject(this);
        }
        ret.prependOnceListener('~', function ()
        {
            if(!this._finalized)
            {
                this.close();
            }
        });
        return (ret);
    };
    this.OpenStore = function OpenStore(provider, location)
    {
        var hstore = this._Crypt32.CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, provider, location | CERT_STORE_OPEN_EXISTING_FLAG, this._marshal.CreateVariable('MY', {wide: true}));
        if (hstore.Val == 0) { throw ('Error opening CertStore'); }
        hstore._crypt = this;
        hstore._finalized = false;
        hstore.close = function close() { this._finalized = true; this._crypt._Crypt32.CertCloseStore(this, CERT_CLOSE_STORE_CHECK_FLAG); };
        hstore.prependOnceListener('~', function () { if (!this._finalized) { this.close(); } });
        return (hstore);
    };
    this.GetCertificate = function GetCertificate(CN, location)
    {
        var subject = this._marshal.CreateVariable(CN);
        var encodedSize = this._marshal.CreateVariable(4); // DWORD
        if(this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, 0, 0, encodedSize, 0).Val == 0)
        {
            throw('Error calculating CERT_X500_NAME_STR for (' + CN + ')');
        }
        var subjectEncoded = this._marshal.CreateVariable(encodedSize.toBuffer().readUInt32LE());
        if(this._Crypt32.CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, 0, subjectEncoded, encodedSize, 0).Val == 0)
        {
            throw('Error encoding CERT_X500_NAME_STR for (' + CN + ')');
        }
        var provider = this.OpenCryptoProvider();
        var store = this.OpenStore(provider, location);
        var search = this._marshal.CreateVariable(this._marshal.PointerSize * 2);
        search.Deref(0,4).toBuffer().writeUInt32LE(encodedSize.toBuffer().readUInt32LE());
        subjectEncoded.pointerBuffer().copy(search.toBuffer(), this._marshal.PointerSize);

        // Look for cert
        var certctx = this._Crypt32.CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, search, 0);
        if(certctx.Val != 0)
        {
            // Found Certificate
            var cer = certctx.Deref(this._marshal.PointerSize, this._marshal.PointerSize).Deref(certctx.Deref(this._marshal.PointerSize * 2, 4).toBuffer().readUInt32LE()).toBuffer();
            var foundcert = require('tls').loadCertificate({ cer: cer });
            return (foundcert);
        }
        else
        {
            throw ('Not Found');
        }

    };
}

module.exports = new certstore();

