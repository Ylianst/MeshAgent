# daemon.js

Process supervisor utility that monitors and automatically restarts child processes on crash. Provides crash resistance for the MeshAgent by detecting abnormal exits and relaunching the process.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support with SIGTERM handling
- macOS (darwin) - Full support with SIGTERM handling
- FreeBSD - Full support with SIGTERM handling

**Excluded Platforms:**
- None - All platforms supported

## Functionality

### Purpose

Provides process supervision for:
- Automatic crash recovery
- Process restart on unexpected exit
- Graceful shutdown handling
- Infinite uptime via restart loop

### Key Functions

#### start(path, parameters, options) - Lines 36-52 (Start Supervised Process)

Spawns and monitors child process with automatic restart.

**Parameters:**
```javascript
{
  crashRestart: true,     // Enable auto-restart
  exit: 0,                // Expected exit code for intentional shutdown
  stdout: true            // Forward child stdout/stderr
}
```

**Process:**
1. Spawn child via `execFile()`
2. Monitor exit code
3. If code != `options.exit` → Crash → Restart
4. If code == `options.exit` → Intentional → Emit 'done'

#### agent() - Lines 54-59 (Self-Supervision)

Runs current process as supervised agent.

**Process:**
- Uses `process.execPath` with same args
- Exit code 6565 = intentional shutdown
- Any other exit code = crash → restart

### Dependencies

- **child_process** - Process spawning
- **events.EventEmitter** - Event infrastructure

### Usage

```javascript
// Supervise process
var daemon = require('daemon').start('/path/app', ['--arg'], {
  crashRestart: true,
  exit: 0,
  stdout: true
});

daemon.on('done', function() {
  console.log('Intentional exit');
});

// Self-supervision
require('daemon').agent();
```

### Technical Notes

**Signal Handling (Unix):**
- SIGTERM handler installed on Linux/macOS/FreeBSD
- Triggers graceful shutdown via `process.exit()`
- Windows doesn't use Unix signals

**Crash Detection:**
- Exit code != expected → Restart
- Exit code == expected → Done
- No rate limiting (vulnerable to rapid crash loops)

## Summary

The daemon.js module is a simple (61-line) process supervisor for crash resistance. It automatically restarts processes on unexpected exits while allowing graceful shutdowns via exit code checking.

**macOS support:** Full support with SIGTERM handling for graceful shutdown.
