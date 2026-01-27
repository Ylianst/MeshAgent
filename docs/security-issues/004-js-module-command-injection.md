# [CRITICAL] Command Injection in JavaScript Modules

**Labels:** security, critical, vulnerability

## Summary
Multiple JavaScript modules construct shell commands via string concatenation with user-controlled values, enabling command injection attacks.

## Severity
**CRITICAL** - Remote Code Execution via shell command injection

## Affected Files
- `modules/toaster.js` (lines 37, 41, 181, 258, 341)
- `modules/lib-finder.js` (lines 26, 36, 55, 67)
- `modules/linux-dbus.js` (lines 159, 179, 183)
- `modules/linux-cpuflags.js` (line 252)
- `modules/interactive.js` (lines 162-176)
- `modules/service-manager.js` (line 2423)

## Vulnerable Code Examples

### Example 1: toaster.js (line 37)
```javascript
child.stdin.write("whereis " + app + " | awk '{ print $2 }'\nexit\n");
```

### Example 2: toaster.js (line 181) - Multiple injections
```javascript
retVal.child.stdin.write('su - ' + retVal.username + ' -c "export DISPLAY=' +
    retVal.xinfo.display + '; export XDG_RUNTIME_DIR=' + xdg +
    '; notify-send \'' + retVal.title + '\' \'' + retVal.caption + '\'"\nexit\n');
```

**Attack:** If `title` or `caption` contains: `'; malicious_command; echo '`

### Example 3: lib-finder.js (lines 26, 36)
```javascript
child.stdin.write("pkg info " + name + " | tr '\\n' '\\|' | awk '...'");
child.stdin.write('pkg info -l ' + name + ' | grep ' + v.name + ' | awk...');
```

### Example 4: linux-dbus.js (line 159)
```javascript
child.stdin.write('cat /usr/share/dbus-1/services/*.service | grep "' + name +
    '" | awk -F= \'{ if( $2=="' + name + '" ) { print $2; } }\'\nexit\n');
```

### Example 5: interactive.js (lines 162-176) - Windows SCHTASKS
```javascript
var parms = '/C SCHTASKS /CREATE /F /TN MeshUserTask /SC ONCE /ST 00:00 ';
parms += ('/RU ' + options.user + ' ');
parms += ('/TR "\\"' + process.execPath + '\\" -b64exec ' + script + '"');

var child = require('child_process').execFile(
    process.env['windir'] + '\\system32\\cmd.exe', [parms]);
```

**Attack:** `options.user = '"domain\\user" & malicious_command'`

### Example 6: service-manager.js (line 2423) - Code Injection
```javascript
var script = Buffer.from("try{require('service-manager').manager.uninstallService('" +
    options.name + "');}catch(x){}process.exit();").toString('base64');
```

**Attack:** If `options.name` contains: `'); require('child_process').exec('malicious'); ('`

## Recommended Fix

### Use spawn with argument arrays instead of shell strings:
```javascript
// Instead of:
child.stdin.write("whereis " + app + " | awk '{ print $2 }'\nexit\n");

// Use:
const { spawn } = require('child_process');
const whereis = spawn('whereis', [app]);
whereis.stdout.pipe(spawn('awk', ['{ print $2 }']).stdin);
```

### For complex pipelines, validate input:
```javascript
function isValidServiceName(name) {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

if (!isValidServiceName(name)) {
    throw new Error('Invalid service name');
}
```

### For Windows SCHTASKS, use array arguments:
```javascript
const child = require('child_process').spawn('schtasks', [
    '/CREATE', '/F', '/TN', 'MeshUserTask',
    '/SC', 'ONCE', '/ST', '00:00',
    '/RU', options.user,  // Properly escaped by spawn
    '/TR', `"${process.execPath}" -b64exec ${script}`
]);
```

## References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- CWE-94: Improper Control of Generation of Code
- OWASP Command Injection
