# [MEDIUM] Resource Leaks - Unclosed Handles, Streams, and Event Listeners

**Labels:** security, medium, code-quality

## Summary
Multiple JavaScript modules have resource leaks including unclosed file handles, streams, child processes not properly terminated, and event listeners not removed.

## Severity
**MEDIUM** - Can lead to resource exhaustion and denial of service over time

## Affected Files
- `modules/toaster.js` (lines 34, 110, 111, 124, 218-220, 244-246, 310, 339-340)
- `modules/lib-finder.js` (lines 27, 35-37)
- `modules/child-container.js` (lines 71, 113, 167-176, 241-258)
- `modules/interactive.js` (lines 100-124)
- `modules/message-box.js` (lines 220, 282, 800, 897)

## Issues Found

### 1. Event Listeners Not Removed

**toaster.js (lines 110-124):**
```javascript
retVal.child.stdout.on('data', function (c) {
    if (c.toString().includes('<DISMISSED>')) {
        this.stdin.write('exit\n');
    }
});
retVal.child.stdout.once('data', function (c) { ... });
retVal.child.on('exit', function (code) { ... });
// No corresponding removeListener() calls
```

**child-container.js (lines 113-128):**
```javascript
s.on('data', function (c) { ... });
// Socket event handlers never cleaned up
```

### 2. Child Processes Not Properly Closed

**toaster.js - findPath() function (lines 32-47):**
```javascript
function findPath(app) {
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stdin.write("whereis " + app + " | awk '{ print $2 }'\nexit\n");
    child.waitExit();
    return (child.stdout.str);  // No child.kill() or explicit cleanup
}
```

**lib-finder.js (lines 35-37):**
```javascript
for(var i in res) {
    child = require('child_process').execFile('/bin/sh', ['sh']);
    // ... use child ...
    child.waitExit();  // No cleanup before reassigning 'child' in next iteration
}
```

### 3. File Handles Not Properly Managed

**interactive.js (lines 100-124):**
```javascript
var w = require('fs').createWriteStream('interactive', { flags: 'wb' });
w.write(exe, function () {
    this.write(js, function () { ... });
});
// No error handlers on stream
// Stream may not close properly on error
```

### 4. IPC Connections Not Guaranteed to Close

**child-container.js (lines 35, 50, 100, 265):**
```javascript
this._client.end();  // May have buffered data
this._ipc.close();   // Abrupt close
this.end();          // No graceful shutdown sequence
```

### 5. Blocking Operations in Event-Driven Code

**message-box.js (lines 220, 282, 800, 897):**
```javascript
child.waitExit();  // Blocking call in async context
```

## Recommended Fixes

### Remove Event Listeners on Cleanup
```javascript
function showToast(options) {
    var child = require('child_process').execFile('/bin/sh', ['sh']);

    var dataHandler = function(c) { ... };
    var exitHandler = function(code) {
        cleanup();
    };

    function cleanup() {
        child.stdout.removeListener('data', dataHandler);
        child.removeListener('exit', exitHandler);
        child.kill();
    }

    child.stdout.on('data', dataHandler);
    child.on('exit', exitHandler);

    // Set timeout for cleanup
    setTimeout(cleanup, 30000);

    return { cleanup: cleanup };
}
```

### Properly Close Child Processes
```javascript
function findPath(app) {
    var child = require('child_process').execFile('/bin/sh', ['sh']);
    try {
        child.stdout.str = '';
        child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("whereis " + app + " | awk '{ print $2 }'\nexit\n");
        child.waitExit();
        return child.stdout.str;
    } finally {
        try { child.kill(); } catch (e) { }
    }
}
```

### Add Error Handlers to Streams
```javascript
var w = require('fs').createWriteStream('interactive', { flags: 'wb' });

w.on('error', function(err) {
    console.error('Write stream error:', err);
    w.destroy();
});

w.on('finish', function() {
    console.log('Write completed');
});

w.write(exe, function(err) {
    if (err) {
        w.destroy();
        return;
    }
    // Continue...
});
```

### Use Async Patterns Instead of Blocking
```javascript
// Instead of:
child.waitExit();

// Use:
child.on('exit', function(code) {
    // Handle exit
    continueProcessing();
});
```

### Implement Graceful IPC Shutdown
```javascript
function gracefulClose(connection, timeout) {
    return new Promise((resolve) => {
        var timer = setTimeout(() => {
            connection.destroy();
            resolve();
        }, timeout);

        connection.end(() => {
            clearTimeout(timer);
            resolve();
        });
    });
}
```

## References
- CWE-404: Improper Resource Shutdown or Release
- CWE-772: Missing Release of Resource after Effective Lifetime
- CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
