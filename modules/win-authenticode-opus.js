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

const X509_ASN_ENCODING = 0x00000001;
const PKCS_7_ASN_ENCODING = 0x00010000;
const ENCODING = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
const CERT_QUERY_OBJECT_FILE = 0x00000001;
const CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED);
const CERT_QUERY_FORMAT_BINARY = 1;
const CERT_QUERY_FORMAT_FLAG_BINARY = (1 << CERT_QUERY_FORMAT_BINARY);
const CMSG_SIGNER_INFO_PARAM = 6;
const SPC_SP_OPUS_INFO_OBJID = "1.3.6.1.4.1.311.2.1.12";

function read(path)
{
    var GM = require('_GenericMarshal');
    var crypt = GM.CreateNativeProxy('Crypt32.dll');
    crypt.CreateMethod('CryptQueryObject');
    crypt.CreateMethod('CryptMsgGetParam');
    crypt.CreateMethod('CryptDecodeObject');

    var dwEncoding = GM.CreateVariable(4);
    var dwContentType = GM.CreateVariable(4);
    var dwFormatType = GM.CreateVariable(4);
    var hStore = GM.CreatePointer();
    var hMsg = GM.CreatePointer();
    var dwSignerInfo = GM.CreateVariable(4);
    var n, result;

    if (crypt.CryptQueryObject(CERT_QUERY_OBJECT_FILE, GM.CreateVariable(path, { wide: true }),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    dwEncoding,
                    dwContentType,
                    dwFormatType,
                    hStore,
                    hMsg,
                    0).Val != 0 &&
        crypt.CryptMsgGetParam(hMsg.Deref(),
            CMSG_SIGNER_INFO_PARAM,
            0,
            0,
            dwSignerInfo).Val != 0)
    {
        var pSignerInfo = GM.CreateVariable(dwSignerInfo.toBuffer().readUInt32LE());

        if (crypt.CryptMsgGetParam(hMsg.Deref(),
            CMSG_SIGNER_INFO_PARAM,
            0,
            pSignerInfo,
            dwSignerInfo).Val != 0)
        {
            var attr;
            var attributes = pSignerInfo.Deref(GM.PointerSize == 8 ? 104 : 52, GM.PointerSize * 2);
            var attrCount = attributes.toBuffer().readUInt32LE();

            for (n = 0; n < attrCount; n++)
            {
                attr = attributes.Deref(GM.PointerSize, GM.PointerSize).Deref();
                attr = attr.increment(n * (GM.PointerSize == 8 ? 24 : 12));
                if (SPC_SP_OPUS_INFO_OBJID == attr.Deref().String)
                {
                    var blob = attr.Deref(GM.PointerSize * 2, GM.PointerSize).Deref();
                    var dwData = GM.CreateVariable(4);

                    var cb = blob.Deref(0, 4).toBuffer().readUInt32LE();
                    var pb = blob.Deref(GM.PointerSize, GM.PointerSize).Deref();

                    if (crypt.CryptDecodeObject(ENCODING, GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID), pb, cb, 0, 0, dwData).Val != 0)
                    {
                        var opus = GM.CreateVariable(dwData.toBuffer().readUInt32LE());
                        if (crypt.CryptDecodeObject(ENCODING, GM.CreateVariable(SPC_SP_OPUS_INFO_OBJID), pb, cb, 0, opus, dwData).Val != 0)
                        {
                       
                            return ({ description: opus.Deref().Val != 0 ? opus.Deref().Wide2UTF8 : null, url: opus.Deref(GM.PointerSize, GM.PointerSize).Deref().Val != 0 ? opus.Deref(GM.PointerSize, GM.PointerSize).Deref().Deref(GM.PointerSize, GM.PointerSize).Deref().Wide2UTF8 : null });
                        }
                    }
                }
            }
        }
    }
    return (null);
}
function locked(uri)
{
    var f = require('http').parseUri(uri);
    var q = f.path.split('?').pop().split(',');
    while (q.length > 0)
    {
        var tokens = q.pop().split('=');
        if (tokens[0].trim().toLowerCase() == 'serverid')
        {
            return ({ dns: f.host, id: tokens[1] });
        }
    }
    return (null);
}
module.exports = read;
module.exports.locked = locked;