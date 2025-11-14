# RecoveryCore.js

MeshAgent recovery/rescue mode core module providing comprehensive remote management capabilities including file operations, terminal/shell access, TCP tunneling, and network diagnostics. Delivers lightweight recovery/rescue console for out-of-band device management when full MeshAgent features unavailable.

## Platform

**Supported Platforms:**
- Windows - Full support including terminal, TCP relay
- Linux - Full support including terminal, TCP relay
- macOS - Partial support (missing native terminal implementation)

**Excluded Platforms:**
- None (module has cross-platform support)

**Placement Reasoning in modules_macos_NEVER:**

Despite having cross-platform code, RecoveryCore.js is in this directory because:

1. **Windows Terminal Implementation Required** - Line 204 shows platform-specific terminal:
```javascript
if (process.platform == "win32") {
    this.httprequest._term = require('win-terminal').Start(80, 25);
```

The Windows version is the primary implementation. macOS path (lines 211-218) falls back to `/bin/sh` which is less integrated.

2. **Enterprise Recovery Focus** - Designed for MeshAgent recovery in enterprise environments where Windows is dominant. macOS rarely appears in recovery/rescue scenarios in enterprise contexts.

3. **TCP Relay for Windows Management** - Lines 116-127 implement TCP relay tunneling, primarily useful for Windows device recovery (RDP, SMB shares, etc.).

4. **Network Diagnostics Context** - File operations, terminal access, and network info (line 398) are typically used in Windows troubleshooting scenarios.

5. **MeshAgent Recovery Architecture** - Recovery mode typically deployed when main agent non-functional, which is primarily Windows use case.

**Code Patterns:**
- Line 202: `if (process.platform == "win32")`
- Line 209: `else` branch with `/bin/sh`
- Platform-specific terminal infrastructure expected

## Functionality

### Core Purpose

Provides lightweight MeshAgent recovery console with remote management capabilities including file operations, shell terminal, TCP tunneling, and network information retrieval. Enables device recovery when primary agent unavailable.

### MeshAgent Integration (Lines 98-104)

```javascript
require('MeshAgent').on('Connected', function () {
    require('os').name().then(function (v) {
        sendConsoleText("Mesh Agent Receovery Console, OS: " + v);
        require('MeshAgent').SendCommand(meshCoreObj);
    });
});
```

**Connection Flow:**
1. Wait for MeshAgent 'Connected' event
2. Query OS name
3. Send capabilities announcement
4. Register command handler

### Capability Announcement (Lines 4, 103)

```javascript
var meshCoreObj = {
    "action": "coreinfo",
    "value": "MeshCore Recovery",
    "caps": 14         // Capability bitmask
};
```

**Capability Bitmask (from line 4 comment):**
```
Bit 0 (1):  Desktop
Bit 1 (2):  Terminal
Bit 2 (4):  Files
Bit 3 (8):  Console
Bit 4 (16): JavaScript
Value 14 = 2 + 4 + 8 = Terminal + Files + Console
```

Advertises: Terminal, File operations, and Console commands

### Command Handler (Lines 130-338)

```javascript
require('MeshAgent').AddCommandHandler(function (data) {
    if (typeof data == 'object') {
        switch (data.action) {
            case 'msg':
                switch (data.type) {
                    case 'console': { /* Console command */ }
                    case 'tunnel': { /* Tunnel request */ }
                }
        }
    }
});
```

**Command Types:**
- 'msg' with type 'console' - Console command execution
- 'msg' with type 'tunnel' - Tunnel establishment for remote access

### Console Command Handler (Lines 340-409)

```javascript
function processConsoleCommand(cmd, args, rights, sessionid) {
    try {
        var response = null;
        switch (cmd) {
            case 'help': // Line 347
            case 'osinfo': // Line 351
            case 'dbkeys': // Line 361
            case 'dbget': // Line 365
            case 'dbset': // Line 374
            case 'dbcompact': // Line 384
            case 'tunnels': // Line 390
            case 'netinfo': // Line 396
        }
    }
}
```

**Commands Implemented (with line numbers):**

#### help (Line 347)
```javascript
case 'help':
    response = 'Available commands are: osinfo, dbkeys, dbget, dbset, dbcompact, netinfo.';
```
Lists available console commands.

#### osinfo (Lines 351-359)
```javascript
case 'osinfo': {
    var i = 1;
    if (args['_'].length > 0) { i = parseInt(args['_'][0]); if (i > 8) { i = 8; } }
    for (var j = 0; j < i; j++) {
        var pr = require('os').name();
        pr.sessionid = sessionid;
        pr.then(function (v) { sendConsoleText("OS: " + v, this.sessionid); });
    }
}
```
Returns OS name, optionally called multiple times.

#### dbkeys (Line 361)
```javascript
case 'dbkeys': {
    response = JSON.stringify(db.Keys);
}
```
Lists all database keys.

#### dbget (Lines 365-371)
```javascript
case 'dbget': {
    if (args['_'].length != 1) {
        response = 'Proper usage: dbget (key)';
    } else {
        response = db.Get(args['_'][0]);
    }
}
```
Retrieve database value by key.

#### dbset (Lines 374-382)
```javascript
case 'dbset': {
    if (args['_'].length != 2) {
        response = 'Proper usage: dbset (key) (value)';
    } else {
        var r = db.Put(args['_'][0], args['_'][1]);
        response = 'Key set: ' + r;
    }
}
```
Set database key-value pair.

#### dbcompact (Lines 384-388)
```javascript
case 'dbcompact': {
    if (db == null) { response = 'Database not accessible.'; break; }
    var r = db.Compact();
    response = 'Database compacted: ' + r;
}
```
Compact database to reclaim space.

#### tunnels (Lines 390-394)
```javascript
case 'tunnels': {
    response = '';
    for (var i in tunnels) { response += 'Tunnel #' + i + ', ' + tunnels[i].url + '\r\n'; }
    if (response == '') { response = 'No websocket sessions.'; }
}
```
List active tunnel sessions.

#### netinfo (Lines 396-400)
```javascript
case 'netinfo': {
    var interfaces = require('os').networkInterfaces();
    response = objToString(interfaces, 0, ' ', true);
}
```
Display network interface information.

### Tunnel Management (Lines 149-325)

**Tunnel Initiation (Lines 149-325):**

```javascript
case 'tunnel':
    if (data.value != null) {
        var xurl = getServerTargetUrlEx(data.value);
        if (xurl != null) {
            var woptions = http.parseUri(xurl);
            woptions.rejectUnauthorized = 0;
            var tunnel = http.request(woptions);
```

**Creates HTTP WebSocket tunnel** to server for remote access.

#### Tunnel Upgrade Handler (Lines 159-178)

```javascript
tunnel.on('upgrade', function (response, s, head) {
    this.s = s;
    s.httprequest = this;
    s.tunnel = this;
    s.on('end', function () {
        // Cleanup and close tunnel
        if (this.httprequest.uploadFile) { fs.closeSync(this.httprequest.uploadFile); }
        if (this.httprequest.downloadFile) { fs.closeSync(this.httprequest.downloadFile); }
        delete tunnels[this.httprequest.index];
        this.removeAllListeners('data');
    });
```

Handles tunnel upgrade (WebSocket), manages active connections.

#### Protocol Detection (Lines 189-232)

```javascript
if (this.httprequest.state == 0) {
    if (data == 'c') {
        this.httprequest.state = 1;
        sendConsoleText("Tunnel #" + this.httprequest.index + " now active");
    }
} else {
    this.httprequest.protocol = parseInt(data);
    if (this.httprequest.protocol == 1) {
        // Terminal protocol
    } else if (this.httprequest.protocol == 5) {
        // Files protocol
    }
}
```

**Protocol Types (from code context):**
- Protocol 1: Remote terminal (Line 199)
- Protocol 5: File operations (Line 234)
- TCP relay: For custom protocols (Lines 116-127)

#### Remote Terminal Implementation (Lines 199-231)

**Windows Terminal (Lines 202-207):**
```javascript
if (process.platform == "win32") {
    this.httprequest._term = require('win-terminal').Start(80, 25);
    this.httprequest._term.pipe(this, { dataTypeSkip: 1 });
    this.pipe(this.httprequest._term, { dataTypeSkip: 1, end: false });
    this.prependListener('end', function () {
        this.httprequest._term.end(function () {
            sendConsoleText('Terminal was closed');
        });
    });
}
```

Uses native Windows terminal with 80x25 size.

**Linux Terminal (Lines 211-218):**
```javascript
else {
    this.httprequest.process = childProcess.execFile("/bin/sh", ["sh"],
        { type: childProcess.SpawnTypes.TERM });
    this.httprequest.process.tunnel = this;
    this.httprequest.process.on('exit', function (ecode, sig) { this.tunnel.end(); });
    this.httprequest.process.stderr.on('data', function (chunk) {
        this.parent.tunnel.write(chunk);
    });
    this.httprequest.process.stdout.pipe(this, { dataTypeSkip: 1 });
    this.pipe(this.httprequest.process.stdin, { dataTypeSkip: 1, end: false });
}
```

Spawns `/bin/sh` for interactive shell.

**Data Forwarding (Line 220-231):**
```javascript
this.on('end', function () {
    if (process.platform == "win32") {
        this.unpipe(this.httprequest._term);
        this.httprequest._term.unpipe(this);
        this.httprequest._term.end();
    }
});
```

Cleanup on tunnel close.

#### File Operations (Lines 248-302)

**Available Commands:**

**ls (Lines 250-254):** List directory contents
```javascript
case 'ls':
    var response = getDirectoryInfo(cmd.path);
    if (cmd.reqid != undefined) { response.reqid = cmd.reqid; }
    this.write(new Buffer(JSON.stringify(response)));
```

**mkdir (Lines 256-259):** Create directory
```javascript
case 'mkdir': {
    fs.mkdirSync(cmd.path);
    break;
}
```

**rm (Lines 261-267):** Delete files/directories
```javascript
case 'rm': {
    for (var i in cmd.delfiles) {
        try { deleteFolderRecursive(path.join(cmd.path, cmd.delfiles[i]), cmd.rec); } catch (e) { }
    }
    break;
}
```

**rename (Lines 269-274):** Rename file/folder
```javascript
case 'rename': {
    var oldfullpath = path.join(cmd.path, cmd.oldname);
    var newfullpath = path.join(cmd.path, cmd.newname);
    try { fs.renameSync(oldfullpath, newfullpath); } catch (e) { }
    break;
}
```

**upload (Lines 276-284):** Upload file from browser
```javascript
case 'upload': {
    if (this.httprequest.uploadFile != undefined) {
        fs.closeSync(this.httprequest.uploadFile);
    }
    var filepath = cmd.name ? path.join(cmd.path, cmd.name) : cmd.path;
    try {
        this.httprequest.uploadFile = fs.openSync(filepath, 'wbN');
    } catch (e) {
        this.write(new Buffer(JSON.stringify({ action: 'uploaderror' })));
    }
    this.httprequest.uploadFileid = cmd.reqid;
}
```

**copy (Lines 286-292):** Copy files
```javascript
case 'copy': {
    for (var i in cmd.names) {
        var sc = path.join(cmd.scpath, cmd.names[i]),
            ds = path.join(cmd.dspath, cmd.names[i]);
        if (sc != ds) { try { fs.copyFileSync(sc, ds); } catch (e) { } }
    }
    break;
}
```

**move (Lines 294-300):** Move files
```javascript
case 'move': {
    for (var i in cmd.names) {
        var sc = path.join(cmd.scpath, cmd.names[i]),
            ds = path.join(cmd.dspath, cmd.names[i]);
        if (sc != ds) { try { fs.copyFileSync(sc, ds); fs.unlinkSync(sc); } catch (e) { } }
    }
    break;
}
```

### Directory Enumeration (Lines 412-450)

```javascript
function getDirectoryInfo(reqpath) {
    var response = { path: reqpath, dir: [] };
    if (((reqpath == undefined) || (reqpath == '')) && (process.platform == 'win32')) {
        // Windows: List drives
        var results = null;
        try { results = fs.readDrivesSync(); } catch (e) { }
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                var drive = { n: results[i].name, t: 1 };
                if (results[i].type == 'REMOVABLE') { drive.dt = 'removable'; }
                response.dir.push(drive);
            }
        }
    } else {
        // List files and folders
        var results = null, xpath = path.join(reqpath, '*');
        try { results = fs.readdirSync(xpath); } catch (e) { }
        if (results != null) {
            for (var i = 0; i < results.length; ++i) {
                if ((results[i] != '.') && (results[i] != '..')) {
                    var stat = null, p = path.join(reqpath, results[i]);
                    try { stat = fs.statSync(p); } catch (e) { }
                    if ((stat != null) && (stat != undefined)) {
                        if (stat.isDirectory() == true) {
                            response.dir.push({ n: results[i], t: 2, d: stat.mtime });
                        } else {
                            response.dir.push({ n: results[i], t: 3, s: stat.size, d: stat.mtime });
                        }
                    }
                }
            }
        }
    }
    return response;
}
```

**Response Format:**
```javascript
{
    path: "/path/to/dir",
    dir: [
        { n: "filename", t: 3, s: 1024, d: timestamp },  // File (t=3)
        { n: "dirname", t: 2, d: timestamp }              // Dir (t=2)
    ]
}
```

**Windows Special (Lines 415-424):** Lists drives (C:, D:, etc.) when path empty.

### TCP Relay for Custom Protocols (Lines 116-127)

```javascript
if (this.tcpport != null) {
    s.pause();
    s.data = onTcpRelayServerTunnelData;
    var connectionOptions = { port: parseInt(this.tcpport) };
    if (this.tcpaddr != null) { connectionOptions.host = this.tcpaddr; }
    else { connectionOptions.host = '127.0.0.1'; }
    s.tcprelay = net.createConnection(connectionOptions, onTcpRelayTargetTunnelConnect);
    s.tcprelay.peerindex = this.index;
}
```

**Enables proxying to local ports** (RDP, SMB, etc.) through tunnel.

### Helper Utilities

**sendConsoleText (Lines 11-14):**
```javascript
function sendConsoleText(msg) {
    require('MeshAgent').SendCommand({
        "action": "msg",
        "type": "console",
        "value": msg
    });
}
```

Sends console output back to management console.

**splitArgs (Lines 56-61):**
```javascript
function splitArgs(str) {
    var myArray = [], myRegexp = /[^\s"]+|"([^"]*)"/gi;
    do {
        var match = myRegexp.exec(str);
        if (match != null) {
            myArray.push(match[1] ? match[1] : match[0]);
        }
    } while (match != null);
    return myArray;
}
```

Parse command line with quoted argument support.

**parseArgs (Lines 64-78):**
```javascript
function parseArgs(argv) {
    var results = { '_': [] }, current = null;
    for (var i = 1, len = argv.length; i < len; i++) {
        var x = argv[i];
        if (x.length > 2 && x[0] == '-' && x[1] == '-') {
            if (current != null) { results[current] = true; }
            current = x.substring(2);
        } else {
            if (current != null) {
                results[current] = toNumberIfNumber(x);
                current = null;
            } else {
                results['_'].push(toNumberIfNumber(x));
            }
        }
    }
    if (current != null) { results[current] = true; }
    return results;
}
```

Convert command array to object with named arguments.

**getDirectoryInfo (Lines 412-450):** Listed above

**deleteFolderRecursive (Lines 452-466):**
```javascript
function deleteFolderRecursive(path, rec) {
    if (fs.existsSync(path)) {
        if (rec == true) {
            fs.readdirSync(path.join(path, '*')).forEach(function (file, index) {
                var curPath = path.join(path, file);
                if (fs.statSync(curPath).isDirectory()) {
                    deleteFolderRecursive(curPath, true);
                } else {
                    fs.unlinkSync(curPath);
                }
            });
        }
        fs.unlinkSync(path);
    }
}
```

Recursive directory deletion with optional recursion.

## Dependencies

### MeshAgent Module Dependencies

#### MeshAgent (Lines 13, 82, 98, 103, 130)

```javascript
require('MeshAgent')
```

**Usage:**
- `.SendCommand(data)` - Send command back to server
- `.AddCommandHandler(function)` - Register command handler
- `.on('Connected', ...)` - Wait for server connection
- `.ServerUrl` - Get server URL (Line 82)

### Node.js Core Module Dependencies

#### http (Lines 2, 86, 155, 158)

```javascript
var http = require('http');
```

**Methods:**
- `http.parseUri(url)` - Parse URL components
- `http.request(options)` - Create HTTP/WebSocket request

#### child_process (Line 3, 211)

```javascript
var childProcess = require('child_process');
childProcess.execFile('/bin/sh', ['sh'], { type: childProcess.SpawnTypes.TERM })
```

**Purpose:** Spawn shell process for terminal access (Linux)

#### fs (Lines 7, 169-170, 184-185, 254, 258, 265, 273, 281-282, 290, 298, 418, 431, 437, 453-461)

```javascript
var fs = require('fs');
```

**Methods:**
- `readDrivesSync()` - List Windows drives
- `readdirSync(path)` - List directory contents
- `readFileSync/writeSync/openSync/closeSync` - File I/O
- `mkdirSync/renameSync/unlinkSync` - File operations
- `statSync/existsSync` - File metadata
- `copyFileSync` - Copy files

### Platform Binary Dependencies

#### win-terminal (Line 204)

```javascript
this.httprequest._term = require('win-terminal').Start(80, 25);
```

**Windows-only module for interactive terminal access**

## Technical Notes

### MeshAgent Recovery Context

**Why Recovery Mode?**
- Main MeshAgent may fail to start
- Network configuration broken
- Agent needs remote repair
- Lightweight fallback mechanism

**Capabilities:**
- File management (copy, delete, upload, download)
- Terminal/shell access
- Network diagnostics
- Database operations
- TCP tunneling to local services

### Tunnel Architecture

**Three-Layer Tunneling:**

1. **WebSocket Tunnel** (Lines 158-306)
   - MeshAgent ↔ Management Server
   - Carries protocol negotiation

2. **Protocol Layer** (Lines 194-302)
   - Terminal (protocol 1)
   - Files (protocol 5)
   - Custom TCP relay (tcpport)

3. **Local Services** (Lines 116-127)
   - Optional: Relay to localhost services
   - Enables RDP, SMB, etc. through tunnel

### Stream-Based Communication

**Bidirectional Piping (Lines 205-206, 215-216):**
```javascript
this.httprequest._term.pipe(this, { dataTypeSkip: 1 });
this.pipe(this.httprequest._term, { dataTypeSkip: 1, end: false });
```

Two-way pipes allow:
- Server → Client → Terminal
- Terminal → Client → Server

**dataTypeSkip: 1** - Ignore type headers, treat as raw data

### Path Helper

**Custom path.join (Lines 18-39):**
```javascript
var path = {
    join: function () {
        var x = [];
        for (var i in arguments) {
            var w = arguments[i];
            if (w != null) {
                while (w.endsWith('/') || w.endsWith('\\')) {
                    w = w.substring(0, w.length - 1);
                }
                if (i != 0) {
                    while (w.startsWith('/') || w.startsWith('\\')) {
                        w = w.substring(1);
                    }
                }
                x.push(w);
            }
        }
        if (x.length == 0) return '/';
        return x.join('/');
    }
};
```

Cross-platform path joining that:
- Handles both `/` and `\` separators
- Strips trailing/leading separators
- Returns normalized path

### Database Access

**References to 'db' object (Lines 362, 366, 370, 375-376, 379, 385-386)** - Suggests local database integration for persistent state storage.

### Windows Drive Listing

**fs.readDrivesSync() (Line 418)** - Windows-specific function to enumerate drives (C:, D:, etc.)

### Upload State Management

**Upload Context Tracking (Lines 278, 281-283):**
```javascript
this.httprequest.uploadFile = fs.openSync(filepath, 'wbN');
this.httprequest.uploadFileid = cmd.reqid;
```

Stores open file descriptor and request ID for streaming uploads.

## Summary

RecoveryCore.js provides lightweight recovery/rescue management console with file operations, remote terminal, network diagnostics, and TCP tunneling. Enables device recovery when primary MeshAgent unavailable.

**Placed in modules_macos_NEVER** because:
- Windows terminal implementation is primary feature (win-terminal)
- Linux fallback uses /bin/sh
- TCP relay tunneling primarily for Windows device management
- Enterprise recovery scenarios dominated by Windows systems
- Designed as fallback when main agent fails

**Key Capabilities:**
- Remote terminal (Windows native + Linux shell)
- File operations (copy, delete, rename, upload, download)
- Console commands (os info, network info, database ops)
- TCP relay tunneling for custom protocols (RDP, etc.)
- Directory enumeration with drive listing on Windows

**Use Cases:**
- Boot-time recovery before main agent loads
- Network configuration recovery
- Emergency file access
- Remote troubleshooting terminal
- Bypass main agent failures

**Related Modules:**
- MeshAgent - Communication with management server
- win-terminal - Windows interactive terminal
