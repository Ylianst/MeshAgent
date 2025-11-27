# proxy-helper.js

Comprehensive proxy detection and configuration module for MeshAgent that automatically discovers HTTP/HTTPS proxy settings from system configurations across Windows, Linux, FreeBSD, and macOS platforms. Provides unified APIs for proxy detection, exception checking, and auto-proxy (WPAD) support.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via Windows Registry
- Linux - Full support with multiple package manager integrations
- FreeBSD - Full support via login.conf and system settings
- **macOS (darwin)** - Full support via scutil system configuration

**Platform-Specific Implementations:**

This module implements distinct proxy detection strategies for each operating system:

1. **Windows** - Queries Windows Registry at HKEY_Users\[SID]\Software\Microsoft\Windows\CurrentVersion\Internet Settings to read ProxyEnable and ProxyServer values, with intelligent user detection for service contexts.

2. **Linux** - Comprehensive detection across multiple locations:
   - /etc/environment - Global environment variables
   - /etc/profile.d/proxy_setup - Shell profile settings
   - /etc/apt/apt.conf.d/proxy.conf and /etc/apt/apt.conf - APT package manager
   - /etc/yum.conf - YUM package manager (RedHat/CentOS)
   - /etc/sysconfig/proxy - openSUSE system configuration
   - /etc/login.conf - FreeBSD-style login settings
   - gsettings (GNOME) - Desktop environment proxy settings

3. **FreeBSD** - Uses /etc/login.conf for system-wide proxy configuration, parsing setenv variables for http_proxy/https_proxy settings.

4. **macOS** - Uses scutil --proxy command to query macOS system configuration framework for HTTP/HTTPS proxy settings (lines 508-536).

**macOS Support:**

macOS is fully supported with dedicated implementation (lines 508-536). The module uses Apple's system configuration utility (scutil) to query proxy settings:
- Executes `scutil --proxy` to retrieve proxy configuration
- Parses HTTPEnable, HTTPProxy, HTTPPort, HTTPSEnable, HTTPSProxy, HTTPSPort
- Returns formatted proxy URL (http:// or https://)
- Integrates with macOS System Preferences proxy settings

**Auto-Proxy (WPAD) Support:**

All platforms support Web Proxy Auto-Discovery Protocol (WPAD):
- DNS-based WPAD discovery (resolves wpad.[domain])
- Automatic PAC (Proxy Auto-Config) file download
- JavaScript PAC file execution for per-URL proxy determination
- Configurable via --autoproxy command line parameter

## Functionality

### Purpose

The proxy-helper module serves as a unified proxy detection and configuration system for MeshAgent. It provides:

- **Automatic Proxy Detection** from system configurations across all platforms
- **Proxy Exception Checking** to determine if addresses bypass proxy
- **WPAD/Auto-Proxy Support** for automatic proxy configuration
- **Multi-Source Detection** checking various system locations
- **Authentication Support** for proxy username/password extraction
- **Service Context Awareness** detecting proper user proxy settings when running as system service

This module is used throughout MeshAgent to:
- Configure HTTP/HTTPS requests with appropriate proxy settings
- Determine if direct connections should be used for specific hosts
- Auto-discover proxy configuration in enterprise environments
- Support complex proxy authentication scenarios
- Ensure network connectivity in restricted environments

### Key Functions

#### getAutoProxyDomain() - Lines 47-63

**Purpose:** Retrieves the domain suffix for WPAD auto-proxy discovery.

**Process:**
```javascript
function getAutoProxyDomain() {
    var domain = null;
    try {
        domain = _MSH().autoproxy;  // Check mesh agent config
    } catch (e) { }

    if (domain == null) {
        domain = process.argv.getParameter('autoproxy');  // Check command line
    }

    if (domain == null || domain.indexOf('.') < 0) { return (null); }
    if (domain != null && !domain.startsWith('.')) { domain = '.' + domain; }
    return (domain);
}
```

**Sources:**
1. MeshAgent configuration (_MSH().autoproxy)
2. Command line parameter (--autoproxy=.example.com)

**Validation:**
- Must contain a dot (valid domain)
- Automatically prefixes with dot if missing

**Returns:** Domain string like ".example.com" or null

**Platform Behavior:**
- All platforms supported identically
- No platform-specific logic

---

#### linux_getProxy() - Lines 65-419

**Purpose:** Comprehensive proxy detection for Linux and FreeBSD systems, checking multiple configuration sources in order of precedence.

**Detection Sequence:**

**1. /etc/environment - Lines 70-96**

Checks global environment variables:
```bash
cat /etc/environment | grep = | tr '\n' '`' | awk -F'`' '{
    host=""; port=""; username=""; password="";
    for(i=1;i<NF;++i) {
        if($i~/^#/) { continue; }
        split($i,tokens,"=");
        if(tokens[1]=="HTTP_PROXY") {
            proxy=substr($i,2+length(tokens[1]));
            printf "http://%s", proxy;
            break;
        }
    }
}'
```

**2. /etc/profile.d/proxy_setup - Lines 99-108**

Shell profile proxy settings:
```bash
cat /etc/profile.d/proxy_setup | awk '{
    split($2, tok, "=");
    if(tok[1]=="http_proxy") { print tok[2]; }
}'
```

**3. APT Package Manager - Lines 111-164**

Checks both /etc/apt/apt.conf.d/proxy.conf and /etc/apt/apt.conf:
```bash
cat /etc/apt/apt.conf.d/proxy.conf | tr '\n' '`' | awk -F'`' '{
    for(n=1;n<NF;++n) {
        if($n~/^#/) { continue; }
        if($n~/^Acquire::http::proxy /) {
            split($n, dummy, "Acquire::http::proxy ");
            print substr(dummy[2],2,length(dummy[2])-3);
            break;
        }
    }
}'
```

**4. YUM Package Manager - Lines 168-209**

Extracts proxy configuration from /etc/yum.conf:
```bash
cat /etc/yum.conf | grep "proxy" | tr '\n' '`' | awk -F'`' '{
    host=""; port=""; username=""; password="";
    for(n=1;n<NF;++n) {
        if($n~/^#/) { continue; }
        split($n,tokens,"=");
        if(tokens[1]=="proxy") {
            split(tokens[2],dummy,"://");
            split(dummy[2],url,":");
            host = url[1];
            port = url[2]; if(port=="") { port = "8080"; }
        }
        if(tokens[1]=="proxy_username") { username = tokens[2]; }
        if(tokens[1]=="proxy_password") { password = tokens[2]; }
    }
    if(host!="" && port!="") {
        if(username!="" && password!="") {
            printf "http://%s:%s@%s:%s", username, password, host, port;
        } else {
            printf "http://%s:%s", host, port;
        }
    }
}'
```

**5. openSUSE sysconfig - Lines 212-264**

Checks /etc/sysconfig/proxy and /root/.curlrc:
```bash
cat /etc/sysconfig/proxy /root/.curlrc | grep = | tr '\n' '`' | awk -F'`' '{
    proxy=""; enabled=""; username=""; password="";
    for(i=1;i<NF;++i) {
        if($i~/^#/) { continue; }
        split($i,tokens,"=");
        if(tokens[1]=="PROXY_ENABLED") {
            split(tokens[2],dummy,"\"");
            enabled = dummy[2];
        }
        if(tokens[1]=="HTTP_PROXY") {
            split(tokens[2],dummy,"\"");
            proxy = dummy[2];
        }
        if(tokens[1]~/^proxy-user/) {
            cred = substr($i,1+index($i,"="));
            cred = substr(cred, index(cred, "\""));
            if(cred~/^"/) { cred = substr(cred,2,length(cred)-2); }
            username=substr(cred,0,index(cred,":")-1);
            password=substr(cred,1+index(cred,":"));
        }
    }
    if(enabled=="yes" && proxy!="") {
        if(username=="" || password=="") {
            print proxy;
        } else {
            split(proxy,dummy, "://");
            printf "%s://%s:%s@%s", dummy[1], username, password, dummy[2];
        }
    }
}'
```

**6. FreeBSD login.conf - Lines 266-361**

Parses complex /etc/login.conf format:
```bash
cat /etc/login.conf | tr '\n' '`' | awk -F'`' '{
    printf "{";
    group=""; first=1; firstprop=0;
    for(i=1;i<NF;++i) {
        a=split($i,tok,":");
        if(split(tok[1],dummy,"#")==1 && split(tok[1],dummy2," ")==1) {
            # New group
            if(group != "") { printf "}"; }
            group = tok[1]; firstprop=1;
            printf "%s\"%s\": {", (first==0?",":""), tok[1];
            first=0;
        } else {
            if(group != "" && split($i,dummy3,"\\")>1 && split($i, dummy4, "#")==1) {
                if(split($i,key1,"=")==1) {
                    # Null property
                    split($i,key2,":");
                    if(key2[2]!="\\") {
                        printf "%s\"%s\": null",(firstprop==0?",":""),key2[2];
                        firstprop=0;
                    }
                } else {
                    # Property with value
                    tmp = substr($i,2+length(key1[1]));
                    split(tmp,dummy,"\\");
                    tmp=substr(tmp,0,length(tmp)-2);
                    split(key1[1],keyname,":");
                    printf "%s\"%s\": \"%s\"", (firstprop==0?",":""), keyname[2], tmp;
                    firstprop=0;
                }
            }
        }
    }
    if(group!="") { printf "}"; }
    printf "}";
}'
```

Searches for http_proxy/https_proxy in root or default sections.

**7. GNOME gsettings - Lines 364-416**

Uses linux-gnome-helpers module for desktop environment settings:
```javascript
var checkId = require('user-sessions').Self();
if (checkId == 0) {
    // Running as root - find user who installed
    try {
        checkId = require('MeshAgent').getStartupOptions().installedByUser;
    } catch (e) {
        // Fallback to logged in user
        checkId = require('user-sessions').consoleUid();
    }
}

var setting = require('linux-gnome-helpers').getProxySettings(checkId);
if (setting.mode == 'manual') {
    if (setting.authEnabled) {
        return ('http://' + setting.username + ':' + setting.password + '@' +
                setting.host + ':' + setting.port);
    } else {
        return ('http://' + setting.host + ':' + setting.port);
    }
}
```

**Returns:** Proxy URL string (e.g., "http://proxy.example.com:8080" or "http://user:pass@proxy:8080")

**Platform Behavior:**
- **Linux:** Checks all sources, first match wins
- **FreeBSD:** Checks /etc/login.conf primarily, falls back to other sources
- Throws exception if no proxy found

---

#### posix_proxyCheck(uid, checkAddr) - Lines 420-450

**Purpose:** Determines if an address should bypass the proxy on Unix systems.

**Process:**
```javascript
function posix_proxyCheck(uid, checkAddr) {
    var g;
    var x = process.env['no_proxy'] ? process.env['no_proxy'].split(',') : [];

    // Check GNOME settings if available
    if (require('linux-gnome-helpers').available &&
        (g = require('linux-gnome-helpers').getProxySettings(uid)).mode != 'none') {
        x = g.exceptions;
    }

    for(var i in x) {
        if (x[i] == checkAddr) { return (true); }                // Exact match
        if (checkAddr.endsWith('.' + x[i])) { return (true); }  // Subdomain
        if ((v = x[i].split('/')).length == 2) {
            // CIDR notation - check if IP in subnet
            try {
                if(require('ip-address').Address4.fromString(v[0]).mask(parseInt(v[1])) ==
                   require('ip-address').Address4.fromString(checkAddr).mask(parseInt(v[1]))) {
                    return(true);
                }
            } catch (ex) { }
        }
    }
    return (false);
}
```

**Exception Sources:**
1. no_proxy environment variable
2. GNOME gsettings exceptions list

**Matching Logic:**
- **Exact match:** checkAddr == exception
- **Subdomain match:** checkAddr ends with "." + exception
- **CIDR match:** IP address within subnet range

**Returns:** true if address bypasses proxy, false otherwise

**Platform Behavior:**
- **Linux/FreeBSD/macOS:** All supported (exported for linux/freebsd only)
- Requires ip-address module for CIDR matching

---

#### windows_getUserRegistryKey() - Lines 452-491

**Purpose:** Determines which Windows Registry user key to query for proxy settings.

**Detection Logic:**

```javascript
function windows_getUserRegistryKey() {
    var i;
    if ((i = require('user-sessions').getProcessOwnerName(process.pid)).tsid == 0) {
        // We are a service (Session ID 0)

        // 1. Try installed-by user
        try {
            key = require('win-registry').QueryKey(
                require('win-registry').HKEY.LocalMachine,
                'SYSTEM\\CurrentControlSet\\Services\\Mesh Agent',
                '_InstalledBy'
            );
        } catch (xx) {
            // 2. Try currently logged in user
            try {
                key = require('win-registry').usernameToUserKey(
                    require('user-sessions').getUsername(
                        require('user-sessions').consoleUid()
                    )
                );
            } catch (xxx) {
                // 3. Try last logged in user (any SID with 5+ segments)
                var entries = require('win-registry').QueryKey(
                    require('win-registry').HKEY.Users
                );
                for (i in entries.subkeys) {
                    if (entries.subkeys[i].split('-').length > 5 &&
                        !entries.subkeys[i].endsWith('_Classes')) {
                        key = entries.subkeys[i];
                        break;
                    }
                }
            }
        }
    } else {
        // We are a logged in user
        key = require('win-registry').usernameToUserKey(i.name);
    }

    if (!key) { throw ('Could not determine which user proxy setting to query'); }
    return (key);
}
```

**User Detection Priority:**
1. User who installed MeshAgent service (_InstalledBy registry value)
2. Currently logged in console user
3. Last logged in user (any valid SID)
4. Current process owner (if not running as service)

**Returns:** Registry key path like "S-1-5-21-123456789-123456789-123456789-1001"

**Platform Behavior:**
- **Windows only**
- Critical for service context proxy detection

---

#### windows_proxyCheck(key, checkAddr) - Lines 492-506

**Purpose:** Determines if an address should bypass the proxy on Windows.

**Process:**
```javascript
function windows_proxyCheck(key, checkAddr) {
    if (!key) { key = windows_getUserRegistryKey(); }

    var proxyOverride = require('win-registry').QueryKey(
        require('win-registry').HKEY.Users,
        key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
        'ProxyOverride'
    ).split(';');

    for(var i in proxyOverride) {
        proxyOverride[i] = proxyOverride[i].trim();
        if ((checkAddr == '127.0.0.1' || checkAddr == '::1') &&
            proxyOverride[i] == '<local>') { return (true); }
        if (checkAddr == proxyOverride[i]) { return (true); }           // Exact match
        if (proxyOverride[i].startsWith('*.') &&
            checkAddr.endsWith(proxyOverride[i].substring(1))) { return (true); }  // Wildcard prefix
        if (proxyOverride[i].endsWith('.*') &&
            checkAddr.startsWith(proxyOverride[i].substring(0, proxyOverride[i].length - 1))) {
            return (true);  // Wildcard suffix
        }
    }
    return (false);
}
```

**Registry Location:** HKEY_Users\[SID]\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyOverride

**Exception Patterns:**
- `<local>` - Matches localhost (127.0.0.1, ::1)
- Exact hostnames
- `*.example.com` - Wildcard prefix matching
- `192.168.*` - Wildcard suffix matching

**Returns:** true if address bypasses proxy, false otherwise

**Platform Behavior:**
- **Windows only**
- Mirrors Internet Explorer proxy exception behavior

---

#### macos_getProxy() - Lines 508-536

**Purpose:** Retrieves proxy configuration from macOS system settings.

**Implementation:**
```javascript
function macos_getProxy() {
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = '';
    child.stderr.on('data', function (c) { this.str += c.toString(); });

    // Execute scutil and format output as JSON
    child.stdin.write(
        "scutil --proxy | grep -E '(HTTPEnable|HTTPProxy|HTTPPort|HTTPSEnable|HTTPSProxy|HTTPSPort)' | " +
        "awk -F' : ' '{printf \"%s\\\"%s\\\": \\\"%s\\\"\", " +
        "(NR>1?\",\":\"{\" ), $1, $2} END {printf \"}\"}'"
    );
    child.stdin.write("\nexit\n");
    child.waitExit();

    if(child.stdout.str != '' && child.stdout.str != '{}') {
        try {
            var p = JSON.parse(child.stdout.str);
            if(p.HTTPEnable == "1") {
                return('http://' + p.HTTPProxy + ':' + p.HTTPPort);
            }
            if(p.HTTPSEnable == "1") {
                return('https://' + p.HTTPSProxy + ':' + p.HTTPSPort);
            }
        } catch(e) {
            // Ignore parsing errors - no valid proxy
        }
    }
    throw ('No Proxies');
}
```

**scutil Output Format:**
```
<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example.com
  HTTPSEnable : 1
  HTTPSPort : 8443
  HTTPSProxy : secure-proxy.example.com
}
```

**Parsing Strategy:**
1. Filter lines with grep for proxy-related fields
2. Use awk to convert to JSON format
3. Parse JSON and check enable flags
4. Return first enabled proxy (HTTP preferred over HTTPS)

**Returns:** Proxy URL like "http://proxy.example.com:8080"

**Platform Behavior:**
- **macOS only**
- Integrates with System Preferences > Network > Advanced > Proxies
- Respects per-network proxy configurations

---

#### windows_getProxy() - Lines 538-556

**Purpose:** Retrieves proxy configuration from Windows Registry.

**Implementation:**
```javascript
function windows_getProxy() {
    var isroot = false;
    var key, value;

    key = windows_getUserRegistryKey();
    try {
        if (require('win-registry').QueryKey(
            require('win-registry').HKEY.Users,
            key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
            'ProxyEnable'
        ) == 1) {
            // Proxy is enabled
            return (require('win-registry').QueryKey(
                require('win-registry').HKEY.Users,
                key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                'ProxyServer'
            ));
        }
    } catch(e) {
        throw ('No proxies');
    }
}
```

**Registry Locations:**
- **ProxyEnable** (DWORD): 0 = disabled, 1 = enabled
- **ProxyServer** (String): Proxy URL or "protocol=host:port" format

**Return Formats:**
- Simple: `proxy.example.com:8080`
- Protocol-specific: `http=proxy:8080;https=secure:8443;ftp=ftp-proxy:21`

**Platform Behavior:**
- **Windows only**
- Mirrors Internet Explorer proxy settings
- Supports protocol-specific proxies

---

#### auto_proxy_helper(target) - Lines 558-603

**Purpose:** Implements WPAD (Web Proxy Auto-Discovery) protocol to dynamically determine proxy for a target URL.

**Process:**
```javascript
function auto_proxy_helper(target) {
    // 1. Disable existing proxy settings
    require('global-tunnel').end();

    var promise = require('promise');
    var ret = new promise(promise.defaultInit);
    if (!this.enabled) { ret.resolve(null); return (ret); }

    // 2. Resolve WPAD host
    var wpadip = resolve('wpad' + (this.domain != null ? this.domain : ''));
    if (wpadip.length == 0) {
        ret.resolve(null);
        return (ret);
    }

    // 3. Download PAC file
    ret.target = target;
    ret.r = require('http').get('http://' + wpadip[0] + '/wpad.dat');
    ret.r.p = ret;

    // 4. Handle response
    ret.r.on('response', function (img) {
        if (img.statusCode == 200 &&
            img.headers['Content-Type'] == 'application/x-ns-proxy-autoconfig') {
            img.wpad = '';
            this.i = img;
            this.i.p = this.p;

            img.on('data', function (c) {
                this.wpad += c.toString();
            });

            img.on('end', function () {
                // 5. Execute PAC file
                var z = require('PAC').Create(this.wpad);
                this.p.resolve(z(this.p.target));
            });
        } else {
            this.p.resolve(null);
        }
    });

    ret.r.on('error', function () { this.p.resolve(null); });
    return (ret);
}
```

**WPAD Discovery:**
1. DNS lookup for `wpad.[domain]` (e.g., wpad.example.com)
2. HTTP GET to `http://[wpad-ip]/wpad.dat`
3. Verify Content-Type: application/x-ns-proxy-autoconfig
4. Download PAC JavaScript file
5. Execute PAC file's FindProxyForURL(url, host) function
6. Return proxy string (e.g., "PROXY proxy:8080" or "DIRECT")

**Returns:** Promise resolving to proxy string or null

**Platform Behavior:**
- All platforms supported identically
- Requires PAC module for JavaScript PAC file execution
- Requires global-tunnel module for proxy configuration

---

### Module Exports and Properties

#### Module Exports - Lines 606-621

**Platform-Specific Exports:**

```javascript
switch (process.platform) {
    case 'linux':
    case 'freebsd':
        module.exports = {
            ignoreProxy: posix_proxyCheck,
            getProxy: linux_getProxy
        };
        break;
    case 'win32':
        module.exports = {
            ignoreProxy: windows_proxyCheck,
            getProxy: windows_getProxy
        };
        break;
    case 'darwin':
        module.exports = {
            getProxy: macos_getProxy
        };
        break;
}
module.exports.autoHelper = auto_proxy_helper;
module.exports.domain = getAutoProxyDomain();
```

**Note:** macOS does NOT export ignoreProxy function (proxy exception checking not implemented).

#### Dynamic Properties - Lines 622-658

**auto Property - Lines 622-636:**

```javascript
Object.defineProperty(module.exports, 'auto', {
    get: function () {
        if (this.enabled) {
            var result = resolve('wpad' + (this.domain != null ? this.domain : ''));
            return (result.length > 0);
        } else {
            return (false);
        }
    }
});
```

Returns true if WPAD is enabled and wpad.[domain] resolves via DNS.

**enabled Property - Lines 638-658:**

```javascript
Object.defineProperty(module.exports, 'enabled', {
    get: function () {
        var domain = null;
        try {
            domain = _MSH().autoproxy;
        } catch (e) { }
        if (domain == null) {
            domain = process.argv.getParameter('autoproxy');
        }
        if (domain != null) {
            if (domain.indexOf('.') >= 0) { domain = 1; }
        }
        return (domain == 1 || domain == '"1"');
    }
});
```

Returns true if auto-proxy is enabled via:
- _MSH().autoproxy = 1 or domain string
- --autoproxy=1 or --autoproxy=.domain.com

---

### Usage Examples

#### Basic Proxy Detection

```javascript
var proxyHelper = require('proxy-helper');

// Get proxy settings
try {
    var proxy = proxyHelper.getProxy();
    console.log('Proxy: ' + proxy);
    // Output: "http://proxy.example.com:8080"
    // or: "http://username:password@proxy:8080"
} catch(e) {
    console.log('No proxy configured');
}
```

#### Check Proxy Exceptions

```javascript
var proxyHelper = require('proxy-helper');

// Windows/Linux/FreeBSD only (not available on macOS)
if (proxyHelper.ignoreProxy) {
    if (proxyHelper.ignoreProxy(0, 'internal.company.com')) {
        console.log('Use direct connection');
    } else {
        console.log('Use proxy');
    }
}
```

#### Auto-Proxy (WPAD) Discovery

```javascript
var proxyHelper = require('proxy-helper');

// Check if auto-proxy enabled
if (proxyHelper.enabled) {
    console.log('Auto-proxy domain: ' + proxyHelper.domain);

    // Check if WPAD host resolves
    if (proxyHelper.auto) {
        console.log('WPAD available');

        // Get proxy for specific URL
        proxyHelper.autoHelper('http://www.example.com/page').then(function(proxy) {
            if (proxy) {
                console.log('Use proxy: ' + proxy);
                // Output: "PROXY proxy.company.com:8080"
            } else {
                console.log('Use direct connection');
            }
        });
    }
}
```

#### Configure HTTP Request with Proxy

```javascript
var proxyHelper = require('proxy-helper');
var http = require('http');

try {
    var proxy = proxyHelper.getProxy();
    var proxyUrl = require('url').parse(proxy);

    var options = {
        host: proxyUrl.hostname,
        port: proxyUrl.port,
        path: 'http://www.example.com/page',
        headers: {
            'Host': 'www.example.com'
        }
    };

    if (proxyUrl.auth) {
        options.headers['Proxy-Authorization'] =
            'Basic ' + Buffer.from(proxyUrl.auth).toString('base64');
    }

    http.get(options, function(res) {
        console.log('Connected via proxy');
    });
} catch(e) {
    // No proxy - direct connection
    http.get('http://www.example.com/page', function(res) {
        console.log('Direct connection');
    });
}
```

#### Service Context Proxy Detection (Windows)

```javascript
// Windows service detecting user proxy settings
var proxyHelper = require('proxy-helper');

// Module automatically detects:
// 1. User who installed the service
// 2. Currently logged in user
// 3. Last logged in user
// And queries their proxy settings

try {
    var proxy = proxyHelper.getProxy();
    console.log('Service using proxy: ' + proxy);
} catch(e) {
    console.log('No proxy for service');
}
```

### Dependencies

#### Node.js Core Modules

- **`child_process`** (lines 73, 102, 114, 122, 142, 148, 171, 204, 215, 269, 510)
  - Method: `execFile(path, args)` - Execute shell commands
  - Used for all Unix-like proxy detection (ps, awk, grep, cat)
  - macOS uses for scutil execution

- **`http`** (line 577)
  - Method: `get(url)` - HTTP GET requests
  - Used for WPAD PAC file download

- **`url`** (not directly used, but implied for proxy URL parsing)

#### MeshAgent Module Dependencies

**Cross-Platform:**

- **`promise`** (line 563)
  - Custom promise implementation
  - Used for async auto-proxy helper
  - Method: `defaultInit` - Promise initializer

**Windows-Specific:**

- **`win-registry`** (lines 460, 467, 472, 487, 496, 544, 546, 549)
  - Windows Registry access
  - Methods:
    - `QueryKey(hive, path, value)` - Read registry values
    - `usernameToUserKey(username)` - Convert username to SID
  - Constants:
    - `HKEY.LocalMachine` - HKLM hive
    - `HKEY.Users` - HKU hive

- **`user-sessions`** (lines 455, 467)
  - User and session management
  - Methods:
    - `getProcessOwnerName(pid)` - Get process owner details
    - `getUsername(uid)` - Convert UID to username
    - `consoleUid()` - Get console session UID

**Linux-Specific:**

- **`user-sessions`** (lines 367, 390)
  - Method: `Self()` - Get current user ID
  - Method: `consoleUid()` - Get logged in user ID

- **`MeshAgent`** (line 375)
  - Method: `getStartupOptions()` - Get agent startup configuration
  - Property: `installedByUser` - UID of installing user

- **`linux-gnome-helpers`** (lines 401, 426)
  - GNOME desktop environment integration
  - Method: `getProxySettings(uid)` - Get user's GNOME proxy config
  - Property: `available` - Boolean indicating GNOME availability
  - Returns object:
    ```javascript
    {
        mode: 'manual' | 'auto' | 'none',
        host: 'proxy.example.com',
        port: '8080',
        authEnabled: true,
        username: 'proxyuser',
        password: 'proxypass',
        exceptions: ['localhost', '127.0.0.1', '.internal.com']
    }
    ```

- **`ip-address`** (line 439)
  - IP address manipulation and CIDR support
  - Method: `Address4.fromString(ip)` - Parse IPv4 address
  - Method: `mask(bits)` - Apply subnet mask
  - Used for CIDR-based proxy exception checking

**Auto-Proxy Dependencies:**

- **`PAC`** (line 592)
  - Proxy Auto-Configuration file parser
  - Method: `Create(pacScript)` - Parse PAC JavaScript
  - Returns function: `FindProxyForURL(url, host)` -> proxy string

- **`global-tunnel`** (line 561)
  - Global proxy configuration
  - Method: `end()` - Disable global proxy
  - Required to clear proxy before WPAD PAC download

#### System Binary Dependencies

**Linux:**
- **cat** - File reading (/bin/cat)
- **grep** - Pattern matching (/bin/grep)
- **tr** - Character translation (/usr/bin/tr)
- **awk** - Text processing (/usr/bin/awk or /bin/awk)
- **gsettings** - GNOME settings (/usr/bin/gsettings, optional)

**FreeBSD:**
- Same as Linux (cat, grep, tr, awk)
- **/etc/login.conf** - Login class configuration file

**macOS:**
- **sh** - Bourne shell (/bin/sh)
- **scutil** - System configuration utility (/usr/sbin/scutil)
- **grep** - Pattern matching (/usr/bin/grep)
- **awk** - Text processing (/usr/bin/awk)

**Windows:**
- **PowerShell** - Not directly used, but Registry queries equivalent to Internet Explorer settings
- **Registry** - Windows Registry (always available)

#### System Configuration Files

**Linux:**
- /etc/environment - Global environment variables
- /etc/profile.d/proxy_setup - Shell proxy configuration
- /etc/apt/apt.conf.d/proxy.conf - APT proxy (Debian/Ubuntu)
- /etc/apt/apt.conf - APT main config (Debian/Ubuntu)
- /etc/yum.conf - YUM proxy (RedHat/CentOS/Fedora)
- /etc/sysconfig/proxy - openSUSE proxy configuration
- /root/.curlrc - cURL configuration with proxy credentials

**FreeBSD:**
- /etc/login.conf - Login class configuration with setenv variables

**macOS:**
- System Configuration Framework (accessed via scutil)
- Network preferences (System Preferences > Network > Advanced > Proxies)

**Windows:**
- HKEY_Users\[SID]\Software\Microsoft\Windows\CurrentVersion\Internet Settings
  - ProxyEnable (DWORD): 0 or 1
  - ProxyServer (String): Proxy URL
  - ProxyOverride (String): Semicolon-separated exception list

### Code Structure

The module is organized into functional sections:

1. **Lines 1-46:** Copyright, Array prototype extensions for command line parsing
2. **Lines 47-63:** Auto-proxy domain retrieval
3. **Lines 65-419:** Linux/FreeBSD proxy detection (multiple sources)
4. **Lines 420-450:** Unix proxy exception checking
5. **Lines 452-491:** Windows user registry key detection
6. **Lines 492-506:** Windows proxy exception checking
7. **Lines 508-536:** macOS proxy detection via scutil
8. **Lines 538-556:** Windows proxy detection via Registry
9. **Lines 558-603:** Auto-proxy (WPAD) helper
10. **Lines 606-621:** Platform-specific module exports
11. **Lines 622-658:** Dynamic properties (auto, enabled)

### Technical Notes

**Multi-Source Detection Strategy (Linux):**

The Linux implementation checks multiple configuration sources in order of specificity:
1. Global environment (/etc/environment)
2. Shell profiles (/etc/profile.d)
3. Package managers (apt, yum)
4. System configuration (sysconfig, login.conf)
5. Desktop environments (GNOME gsettings)

This ensures compatibility across various Linux distributions with different configuration conventions.

**Service Context Detection (Windows):**

Windows services run in Session 0 without direct user context. The module implements intelligent user detection:
1. Check service metadata for installing user
2. Query currently logged in user
3. Fall back to last logged in user (any valid SID)

This ensures proper proxy detection even when running as SYSTEM account.

**Shell Script Complexity:**

Unix implementations use sophisticated awk scripts for parsing:
- Handles various file formats (key=value, key "value", key : value)
- Escapes special characters for JSON output
- Filters comments (lines starting with #)
- Handles multi-line configurations
- Supports quoted values with embedded spaces

**WPAD Security Considerations:**

The auto_proxy_helper disables existing proxy settings before WPAD discovery (line 561) to prevent circular dependency where proxy is required to reach WPAD server. This is critical for WPAD to function correctly.

**macOS scutil Integration:**

The scutil command provides direct access to macOS System Configuration Framework:
- Reads current network proxy settings
- Supports per-network configurations
- Respects user preferences from System Preferences
- Returns structured dictionary format

**Proxy URL Formats:**

The module handles various proxy URL formats:
- Simple: `proxy.example.com:8080`
- With protocol: `http://proxy.example.com:8080`
- With authentication: `http://user:pass@proxy:8080`
- Protocol-specific (Windows): `http=proxy:8080;https=secure:8443`

**Error Handling:**

- All getProxy functions throw exceptions when no proxy found
- This allows try/catch pattern for "proxy or direct" logic
- Parsing errors in awk scripts result in empty strings (no proxy)
- WPAD failures resolve to null (use direct connection)

### Platform-Specific Analysis

**What Works on macOS:**

Fully functional features:
- `getProxy()` - System proxy detection via scutil (lines 508-536)
- `autoHelper(target)` - WPAD auto-proxy support
- `auto` property - WPAD availability check
- `enabled` property - Auto-proxy enabled check
- `domain` property - Auto-proxy domain retrieval

**What Doesn't Work on macOS:**

Limited functionality:
- `ignoreProxy(uid, checkAddr)` - **Not exported** (proxy exception checking not implemented)
  - macOS does not provide easy access to proxy exception list via scutil
  - Exception list stored in Network preferences but requires parsing property lists
  - Alternative: Could implement by reading /Library/Preferences/SystemConfiguration/preferences.plist

**macOS-Specific Behavior:**

1. **scutil Command:** Provides reliable proxy detection from System Configuration Framework
2. **Network-Specific:** Proxy settings can vary per network location
3. **No Exception Checking:** Module does not implement proxy bypass logic for macOS
4. **Authentication:** Basic proxy auth supported via scutil output (username/password not typically in system settings)
5. **Protocol Preference:** Returns HTTP proxy if enabled, otherwise HTTPS proxy

**Implementation Comparison:**

| Feature | Windows | Linux | FreeBSD | macOS |
|---------|---------|-------|---------|-------|
| Proxy Detection | Registry | Multiple sources | login.conf | scutil |
| Exception Checking | Yes | Yes | Yes | No |
| Authentication | Yes | Yes | Yes | Limited |
| WPAD Support | Yes | Yes | Yes | Yes |
| Service Context | Yes | Yes | N/A | N/A |
| Multi-Source | No | Yes | Yes | No |
| Desktop Integration | No | GNOME | No | Native |

**macOS Enhancement Opportunities:**

To achieve feature parity with other platforms:

1. **Implement ignoreProxy function:**
   ```javascript
   function macos_proxyCheck(checkAddr) {
       // Read /Library/Preferences/SystemConfiguration/preferences.plist
       // Parse ExceptionsList from Proxies dictionary
       // Match against checkAddr
   }
   ```

2. **Add authentication support:**
   - Read proxy username/password from Keychain
   - Use security command to access Keychain items
   - Parse credentials for authenticated proxy URLs

3. **Support network location awareness:**
   - Detect current network location via scutil --get Setup:/Network/Global/IPv4
   - Query location-specific proxy settings
   - Return appropriate proxy for active network

4. **PAC file support:**
   - Check for automatic proxy configuration URL in scutil output
   - Download and execute PAC file similar to WPAD

## Summary

The proxy-helper.js module is a comprehensive cross-platform proxy detection and configuration tool that provides unified APIs for **Windows, Linux, FreeBSD, and macOS**.

**macOS is partially supported** with full proxy detection capabilities but without proxy exception checking:

**Supported on macOS:**
- Automatic proxy detection via scutil system configuration utility
- WPAD (Web Proxy Auto-Discovery) protocol support
- Auto-proxy configuration with PAC file execution
- Integration with System Preferences network proxy settings
- HTTP and HTTPS proxy detection

**Not Supported on macOS:**
- Proxy exception checking (ignoreProxy function not exported)
- Proxy bypass list parsing
- CIDR-based subnet exception matching

The module implements platform-optimized detection strategies: Windows Registry queries for services and logged-in users, comprehensive multi-source checking on Linux (environment variables, package managers, desktop environments), FreeBSD login.conf parsing, and macOS System Configuration Framework access via scutil.

**Limitations on macOS:**
- No proxy exception list support (would require plist parsing)
- Limited authentication credential extraction (Keychain access needed)
- Single proxy returned (no protocol-specific proxy support)

The module successfully provides production-ready proxy detection for macOS deployments, with the exception checking limitation being minor since most enterprise environments use consistent proxy settings without complex exception rules. For full feature parity, implementing proxy exception checking via preferences.plist parsing would be required.
