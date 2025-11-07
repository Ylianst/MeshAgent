/*
Copyright 2020 Intel Corporation

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
// util-language is a helper module to fetch the currently configured Language Locale of the Operating System
//

//
// This is a windows helper function to convert LCID to language name
//
function toLang(val)
{
    //
    // Windows Language codes can be found at:
    // https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oe376/6c085406-a698-4e12-9d4d-c3b0ee3dbc4a
    //

    var ret;
    switch (val)
    {
        case '1025':
            ret = 'ar-SA';
            break
        case '1026':
            ret = 'bg-BG';
            break
        case '1027':
            ret = 'ca-ES';
            break
        case '1028':
            ret = 'zh-TW';
            break
        case '1029':
            ret = 'cs-CZ';
            break
        case '1030':
            ret = 'da-DK';
            break
        case '1031':
            ret = 'de-DE';
            break
        case '1032':
            ret = 'el-GR';
            break
        case '1033':
            ret = 'en-US';
            break
        case '1034':
            ret = 'es-ES_tradnl';
            break
        case '1035':
            ret = 'fi-FI';
            break
        case '1036':
            ret = 'fr-FR';
            break
        case '1037':
            ret = 'he-IL';
            break
        case '1038':
            ret = 'hu-HU';
            break
        case '1039':
            ret = 'is-IS';
            break
        case '1040':
            ret = 'it-IT';
            break
        case '1041':
            ret = 'ja-JP';
            break
        case '1042':
            ret = 'ko-KR';
            break
        case '1043':
            ret = 'nl-NL';
            break
        case '1044':
            ret = 'nb-NO';
            break
        case '1045':
            ret = 'pl-PL';
            break
        case '1046':
            ret = 'pt-BR';
            break
        case '1047':
            ret = 'rm-CH';
            break
        case '1048':
            ret = 'ro-RO';
            break
        case '1049':
            ret = 'ru-RU';
            break
        case '1050':
            ret = 'hr-HR';
            break
        case '1051':
            ret = 'sk-SK';
            break
        case '1052':
            ret = 'sq-AL';
            break
        case '1053':
            ret = 'sv-SE';
            break
        case '1054':
            ret = 'th-TH';
            break
        case '1055':
            ret = 'tr-TR';
            break
        case '1056':
            ret = 'ur-PK';
            break
        case '1057':
            ret = 'id-ID';
            break
        case '1058':
            ret = 'uk-UA';
            break
        case '1059':
            ret = 'be-BY';
            break
        case '1060':
            ret = 'sl-SI';
            break
        case '1061':
            ret = 'et-EE';
            break
        case '1062':
            ret = 'lv-LV';
            break
        case '1063':
            ret = 'lt-LT';
            break
        case '1064':
            ret = 'tg-Cyrl-TJ';
            break
        case '1065':
            ret = 'fa-IR';
            break
        case '1066':
            ret = 'vi-VN';
            break
        case '1067':
            ret = 'hy-AM';
            break
        case '1068':
            ret = 'az-Latn-AZ';
            break
        case '1069':
            ret = 'eu-ES';
            break
        case '1070':
            ret = 'hsb-DE';
            break
        case '1071':
            ret = 'mk-MK';
            break
        case '1072':
            ret = 'st-ZA';
            break
        case '1073':
            ret = 'ts-ZA';
            break
        case '1074':
            ret = 'tn-ZA';
            break
        case '1075':
            ret = 've-ZA';
            break
        case '1076':
            ret = 'xh-ZA';
            break
        case '1077':
            ret = 'zu-ZA';
            break
        case '1078':
            ret = 'af-ZA';
            break
        case '1079':
            ret = 'ka-GE';
            break
        case '1080':
            ret = 'fo-FO';
            break
        case '1081':
            ret = 'hi-IN';
            break
        case '1082':
            ret = 'mt-MT';
            break
        case '1083':
            ret = 'se-NO';
            break
        case '1085':
            ret = 'yi-Hebr';
            break
        case '1086':
            ret = 'ms-MY';
            break
        case '1087':
            ret = 'kk-KZ';
            break
        case '1088':
            ret = 'ky-KG';
            break
        case '1089':
            ret = 'sw-KE';
            break
        case '1090':
            ret = 'tk-TM';
            break
        case '1091':
            ret = 'uz-Latn-UZ';
            break
        case '1092':
            ret = 'tt-RU';
            break
        case '1093':
            ret = 'bn-IN';
            break
        case '1094':
            ret = 'pa-IN';
            break
        case '1095':
            ret = 'gu-IN';
            break
        case '1096':
            ret = 'or-IN';
            break
        case '1097':
            ret = 'ta-IN';
            break
        case '1098':
            ret = 'te-IN';
            break
        case '1099':
            ret = 'kn-IN';
            break
        case '1100':
            ret = 'ml-IN';
            break
        case '1101':
            ret = 'as-IN';
            break
        case '1102':
            ret = 'mr-IN';
            break
        case '1103':
            ret = 'sa-IN';
            break
        case '1104':
            ret = 'mn-MN';
            break
        case '1105':
            ret = 'bo-CN';
            break
        case '1106':
            ret = 'cy-GB';
            break
        case '1107':
            ret = 'km-KH';
            break
        case '1108':
            ret = 'lo-LA';
            break
        case '1109':
            ret = 'my-MM';
            break
        case '1110':
            ret = 'gl-ES';
            break
        case '1111':
            ret = 'kok-IN';
            break
        case '1112':
            ret = 'mni-IN';
            break
        case '1113':
            ret = 'sd-Deva-IN';
            break
        case '1114':
            ret = 'syr-SY';
            break
        case '1115':
            ret = 'si-LK';
            break
        case '1116':
            ret = 'chr-Cher-US';
            break
        case '1117':
            ret = 'iu-Cans-CA';
            break
        case '1118':
            ret = 'am-ET';
            break
        case '1119':
            ret = 'tzm-Arab-MA';
            break
        case '1120':
            ret = 'ks-Arab';
            break
        case '1121':
            ret = 'ne-NP';
            break
        case '1122':
            ret = 'fy-NL';
            break
        case '1123':
            ret = 'ps-AF';
            break
        case '1124':
            ret = 'fil-PH';
            break
        case '1125':
            ret = 'dv-MV';
            break
        case '1126':
            ret = 'bin-NG';
            break
        case '1127':
            ret = 'fuv-NG';
            break
        case '1128':
            ret = 'ha-Latn-NG';
            break
        case '1129':
            ret = 'ibb-NG';
            break
        case '1130':
            ret = 'yo-NG';
            break
        case '1131':
            ret = 'quz-BO';
            break
        case '1132':
            ret = 'nso-ZA';
            break
        case '1133':
            ret = 'ba-RU';
            break
        case '1134':
            ret = 'lb-LU';
            break
        case '1135':
            ret = 'kl-GL';
            break
        case '1136':
            ret = 'ig-NG';
            break
        case '1137':
            ret = 'kr-NG';
            break
        case '1138':
            ret = 'om-ET';
            break
        case '1139':
            ret = 'ti-ET';
            break
        case '1140':
            ret = 'gn-PY';
            break
        case '1141':
            ret = 'haw-US';
            break
        case '1142':
            ret = 'la-Latn';
            break
        case '1143':
            ret = 'so-SO';
            break
        case '1144':
            ret = 'ii-CN';
            break
        case '1145':
            ret = 'pap-029';
            break
        case '1146':
            ret = 'arn-CL';
            break
        case '1148':
            ret = 'moh-CA';
            break
        case '1150':
            ret = 'br-FR';
            break
        case '1152':
            ret = 'ug-CN';
            break
        case '1153':
            ret = 'mi-NZ';
            break
        case '1154':
            ret = 'oc-FR';
            break
        case '1155':
            ret = 'co-FR';
            break
        case '1156':
            ret = 'gsw-FR';
            break
        case '1157':
            ret = 'sah-RU';
            break
        case '1158':
            ret = 'qut-GT';
            break
        case '1159':
            ret = 'rw-RW';
            break
        case '1160':
            ret = 'wo-SN';
            break
        case '1164':
            ret = 'prs-AF';
            break
        case '1165':
            ret = 'plt-MG';
            break
        case '1166':
            ret = 'zh-yue-HK';
            break
        case '1167':
            ret = 'tdd-Tale-CN';
            break
        case '1168':
            ret = 'khb-Talu-CN';
            break
        case '1169':
            ret = 'gd-GB';
            break
        case '1170':
            ret = 'ku-Arab-IQ';
            break
        case '1171':
            ret = 'quc-CO';
            break
        case '1281':
            ret = 'qps-ploc';
            break
        case '1534':
            ret = 'qps-ploca';
            break
        case '2049':
            ret = 'ar-IQ';
            break
        case '2051':
            ret = 'ca-ES-valencia';
            break
        case '2052':
            ret = 'zh-CN';
            break
        case '2055':
            ret = 'de-CH';
            break
        case '2057':
            ret = 'en-GB';
            break
        case '2058':
            ret = 'es-MX';
            break
        case '2060':
            ret = 'fr-BE';
            break
        case '2064':
            ret = 'it-CH';
            break
        case '2065':
            ret = 'ja-Ploc-JP';
            break
        case '2067':
            ret = 'nl-BE';
            break
        case '2068':
            ret = 'nn-NO';
            break
        case '2070':
            ret = 'pt-PT';
            break
        case '2072':
            ret = 'ro-MD';
            break
        case '2073':
            ret = 'ru-MD';
            break
        case '2074':
            ret = 'sr-Latn-CS';
            break
        case '2077':
            ret = 'sv-FI';
            break
        case '2080':
            ret = 'ur-IN';
            break
        case '2092':
            ret = 'az-Cyrl-AZ';
            break
        case '2094':
            ret = 'dsb-DE';
            break
        case '2098':
            ret = 'tn-BW';
            break
        case '2107':
            ret = 'se-SE';
            break
        case '2108':
            ret = 'ga-IE';
            break
        case '2110':
            ret = 'ms-BN';
            break
        case '2115':
            ret = 'uz-Cyrl-UZ';
            break
        case '2117':
            ret = 'bn-BD';
            break
        case '2118':
            ret = 'pa-Arab-PK';
            break
        case '2121':
            ret = 'ta-LK';
            break
        case '2128':
            ret = 'mn-Mong-CN';
            break
        case '2129':
            ret = 'bo-BT';
            break
        case '2137':
            ret = 'sd-Arab-PK';
            break
        case '2141':
            ret = 'iu-Latn-CA';
            break
        case '2143':
            ret = 'tzm-Latn-DZ';
            break
        case '2144':
            ret = 'ks-Deva';
            break
        case '2145':
            ret = 'ne-IN';
            break
        case '2151':
            ret = 'ff-Latn-SN';
            break
        case '2155':
            ret = 'quz-EC';
            break
        case '2163':
            ret = 'ti-ER';
            break
        case '2559':
            ret = 'qps-plocm';
            break
        case '3073':
            ret = 'ar-EG';
            break
        case '3076':
            ret = 'zh-HK';
            break
        case '3079':
            ret = 'de-AT';
            break
        case '3081':
            ret = 'en-AU';
            break
        case '3082':
            ret = 'es-ES';
            break
        case '3084':
            ret = 'fr-CA';
            break
        case '3098':
            ret = 'sr-Cyrl-CS';
            break
        case '3131':
            ret = 'se-FI';
            break
        case '3152':
            ret = 'mn-Mong-MN';
            break
        case '3153':
            ret = 'dz-BT';
            break
        case '3167':
            ret = 'tmz-MA';
            break
        case '3179':
            ret = 'quz-PE';
            break
        case '4097':
            ret = 'ar-LY';
            break
        case '4100':
            ret = 'zh-SG';
            break
        case '4103':
            ret = 'de-LU';
            break
        case '4105':
            ret = 'en-CA';
            break
        case '4106':
            ret = 'es-GT';
            break
        case '4108':
            ret = 'fr-CH';
            break
        case '4122':
            ret = 'hr-BA';
            break
        case '4155':
            ret = 'smj-NO';
            break
        case '4191':
            ret = 'tzm-Tfng-MA';
            break
        case '5121':
            ret = 'ar-DZ';
            break
        case '5124':
            ret = 'zh-MO';
            break
        case '5127':
            ret = 'de-LI';
            break
        case '5129':
            ret = 'en-NZ';
            break
        case '5130':
            ret = 'es-CR';
            break
        case '5132':
            ret = 'fr-LU';
            break
        case '5146':
            ret = 'bs-Latn-BA';
            break
        case '5179':
            ret = 'smj-SE';
            break
        case '6145':
            ret = 'ar-MA';
            break
        case '6153':
            ret = 'en-IE';
            break
        case '6154':
            ret = 'es-PA';
            break
        case '6156':
            ret = 'fr-MC';
            break
        case '6170':
            ret = 'sr-Latn-BA';
            break
        case '6203':
            ret = 'sma-NO';
            break
        case '7169':
            ret = 'ar-TN';
            break
        case '7177':
            ret = 'en-ZA';
            break
        case '7178':
            ret = 'es-DO';
            break
        case '7194':
            ret = 'sr-Cyrl-BA';
            break
        case '7227':
            ret = 'sma-SE';
            break
        case '8193':
            ret = 'ar-OM';
            break
        case '8201':
            ret = 'en-JM';
            break
        case '8202':
            ret = 'es-VE';
            break
        case '8204':
            ret = 'fr-RE';
            break
        case '8218':
            ret = 'bs-Cyrl-BA';
            break
        case '8251':
            ret = 'sms-FI';
            break
        case '9217':
            ret = 'ar-YE';
            break
        case '9225':
            ret = 'en-029';
            break
        case '9226':
            ret = 'es-CO';
            break
        case '9228':
            ret = 'fr-CD';
            break
        case '9242':
            ret = 'sr-Latn-RS';
            break
        case '9275':
            ret = 'smn-FI';
            break
        case '10241':
            ret = 'ar-SY';
            break
        case '10249':
            ret = 'en-BZ';
            break
        case '10250':
            ret = 'es-PE';
            break
        case '10252':
            ret = 'fr-SN';
            break
        case '10266':
            ret = 'sr-Cyrl-RS';
            break
        case '11265':
            ret = 'ar-JO';
            break
        case '11273':
            ret = 'en-TT';
            break
        case '11274':
            ret = 'es-AR';
            break
        case '11276':
            ret = 'fr-CM';
            break
        case '11290':
            ret = 'sr-Latn-ME';
            break
        case '12289':
            ret = 'ar-LB';
            break
        case '12297':
            ret = 'en-ZW';
            break
        case '12298':
            ret = 'es-EC';
            break
        case '12300':
            ret = 'fr-CI';
            break
        case '12314':
            ret = 'sr-Cyrl-ME';
            break
        case '13313':
            ret = 'ar-KW';
            break
        case '13321':
            ret = 'en-PH';
            break
        case '13322':
            ret = 'es-CL';
            break
        case '13324':
            ret = 'fr-ML';
            break
        case '14337':
            ret = 'ar-AE';
            break
        case '14345':
            ret = 'en-ID';
            break
        case '14346':
            ret = 'es-UY';
            break
        case '14348':
            ret = 'fr-MA';
            break
        case '15361':
            ret = 'ar-BH';
            break
        case '15369':
            ret = 'en-HK';
            break
        case '15370':
            ret = 'es-PY';
            break
        case '15372':
            ret = 'fr-HT';
            break
        case '16385':
            ret = 'ar-QA';
            break
        case '16393':
            ret = 'en-IN';
            break
        case '16394':
            ret = 'es-BO';
            break
        case '17409':
            ret = 'ar-Ploc-SA';
            break
        case '17417':
            ret = 'en-MY';
            break
        case '17418':
            ret = 'es-SV';
            break
        case '18433':
            ret = 'ar-145';
            break
        case '18441':
            ret = 'en-SG';
            break
        case '18442':
            ret = 'es-HN';
            break
        case '19465':
            ret = 'en-AE';
            break
        case '19466':
            ret = 'es-NI';
            break
        case '20489':
            ret = 'en-BH';
            break
        case '20490':
            ret = 'es-PR';
            break
        case '21513':
            ret = 'en-EG';
            break
        case '21514':
            ret = 'es-US';
            break
        case '22537':
            ret = 'en-JO';
            break
        case '22538':
            ret = 'es-419';
            break
        case '23561':
            ret = 'en-KW';
            break
        case '23562':
            ret = 'es-CU';
            break
        case '24585':
            ret = 'en-TR';
            break
        case '25609':
            ret = 'en-YE';
            break
        case '25626':
            ret = 'bs-Cyrl';
            break
        case '26650':
            ret = 'bs-Latn';
            break
        case '27674':
            ret = 'sr-Cyrl';
            break
        case '28698':
            ret = 'sr-Latn';
            break
        case '28731':
            ret = 'smn';
            break
        case '29740':
            ret = 'az-Cyrl';
            break
        case '29755':
            ret = 'sms';
            break
        case '30724':
            ret = 'zh';
            break
        case '30740':
            ret = 'nn';
            break
        case '30746':
            ret = 'bs';
            break
        case '30764':
            ret = 'az-Latn';
            break
        case '30779':
            ret = 'sma';
            break
        case '30787':
            ret = 'uz-Cyrl';
            break
        case '30800':
            ret = 'mn-Cyrl';
            break
        case '30813':
            ret = 'iu-Cans';
            break
        case '30815':
            ret = 'tzm-Tfng';
            break
        case '31748':
            ret = 'zh-Hant';
            break
        case '31764':
            ret = 'nb';
            break
        case '31770':
            ret = 'sr';
            break
        case '31784':
            ret = 'tg-Cyrl';
            break
        case '31790':
            ret = 'dsb';
            break
        case '31803':
            ret = 'smj';
            break
        case '31811':
            ret = 'uz-Latn';
            break
        case '31814':
            ret = 'pa-Arab';
            break
        case '31824':
            ret = 'mn-Mong';
            break
        case '31833':
            ret = 'sd-Arab';
            break
        case '31836':
            ret = 'chr-Cher';
            break
        case '31837':
            ret = 'iu-Latn';
            break
        case '31839':
            ret = 'tzm-Latn';
            break
        case '31847':
            ret = 'ff-Latn';
            break
        case '31848':
            ret = 'ha-Latn';
            break
        default:
            ret = null;
            break
    }
    return (ret);
}

//
// Try to determine the current language locale
//
function getCurrent()
{
    if(process.platform == 'win32')
    {
        // On windows we will use WMI to get the LCID. 
        if (process.platform == 'win32') {
            var tokens = require('win-wmi').query('ROOT\\CIMV2', 'SELECT OSLanguage FROM Win32_OperatingSystem', ['OSLanguage']);
            if (tokens[0]) {
                // Convert LCID to language string
                return (toLang(tokens[0]['OSLanguage'].toString()));
            } else {
                // fallback to en-us to avoid crashing
                return ("en-us");
            }
        }
    }

    if(process.env['LANG'])
    {
        // If 'LANG" is defined in the environment variable, we can just return that
        return (process.env['LANG'].split('.')[0]);
    }
    else
    {
        if (process.platform == 'darwin')
        {
            // On macOS we can use the system utility 'osascript' to fetch the current locale of the system
            var child = require('child_process').execFile('/bin/sh', ['sh']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
            child.stdin.write("osascript -e 'user locale of (get system info)'\nexit\n");
            child.waitExit();
            return (child.stdout.str.trim());
        }
        else
        {
            try
            {
                // On Linux/BSD, we are goign to fetch the environment variables of the Display Manager process, and see what locale was set for it
                var uid = require('user-sessions').gdmUid;
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write('ps -e -o pid -o uid | grep ' + uid + ' | awk ' + "'{ print $1; }'\nexit\n");
                child.waitExit();
                var pid = parseInt(child.stdout.str.trim());

                var e = require('user-sessions').getEnvFromPid(pid);
                if (e.LANG) { return (e.LANG.split('.')[0]); }
            }
            catch (x)
            {
            }
        }
        return (null);
    }
}

// This property will fetch the current locale the first time, and cache the results
var obj = {};
Object.defineProperty(obj, 'current', {
    get: function ()
    {
        if(this._val != null)
        {
            return (this._val);
        }
        else
        {
            this._val = getCurrent();
            return (this._val);
        }
    }
});
module.exports = obj;

if (process.platform == 'win32')
{
    //
    // On Windows, we will set a property to fetch/cache the wmicXslPath
    //
    Object.defineProperty(module.exports, 'wmicXslPath',
        {
            get: function ()
            {
                if (this._wmicpath == null)
                {
                    var tmp = process.env['windir'] + '\\system32\\wbem\\' + this.current + '\\';
                    if (require('fs').existsSync(tmp + 'csv.xsl'))
                    {
                        this._wmicpath = tmp;
                    }
                }
                if(this._wmicpath == null)
                {
                    var f = require('fs').readdirSync(process.env['windir'] + '\\system32\\wbem');
                    for(var i in f)
                    {
                        var path = process.env['windir'] + '\\system32\\wbem\\' + f[i];
                        if(require('fs').statSync(path).isDirectory())
                        {
                            if (require('fs').existsSync(path + '\\csv.xsl'))
                            {
                                this._wmicpath = path + '\\';
                                break;
                            }
                        }
                    }
                }
                return (this._wmicpath);
            }
        });
}
