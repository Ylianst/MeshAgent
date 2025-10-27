# macOS Agent Architecture - KVM Split Design

## Overview

The macOS MeshAgent has been refactored to separate KVM (remote desktop) functionality from the main agent, complying with Apple's security requirements while maintaining efficient resource usage.

## Architecture

### Two-Process Design

```
┌─────────────────────────────────────────────────────────────────┐
│  macOS System                                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LaunchDaemon (System-wide, Root)                               │
│  ┌──────────────────────────────────┐                           │
│  │  meshagent                        │                           │
│  │  (Main Agent)                     │                           │
│  ├──────────────────────────────────┤                           │
│  │  • Remote Terminal (root shell)   │                           │
│  │  • File Operations (full disk)    │                           │
│  │  • Service Management             │                           │
│  │  • Server Communication           │                           │
│  │  • Command Routing                │                           │
│  └──────────┬───────────────────────┘                           │
│             │ Unix Socket IPC                                    │
│             │ /usr/local/mesh_services/meshagent/kvm            │
│             │                                                    │
│  LaunchAgent (User Session)                                     │
│  ┌──────────▼───────────────────────┐                           │
│  │  meshagent -kvm1                 │                           │
│  │  (KVM Service)                   │                           │
│  ├──────────────────────────────────┤                           │
│  │  Session: LoginWindow + Aqua     │                           │
│  │                                   │                           │
│  │  IDLE Mode (default):             │                           │
│  │  • Listening on Unix socket       │                           │
│  │  • CPU: ~0%                       │                           │
│  │  • Memory: ~10 MB                 │                           │
│  │  • No screen capture              │                           │
│  │                                   │                           │
│  │  ACTIVE Mode (when connected):    │                           │
│  │  • Screen capture @ 30 FPS        │                           │
│  │  • Mouse/keyboard injection       │                           │
│  │  • JPEG tile compression          │                           │
│  │  • CPU: 15-30%                    │                           │
│  │  • Memory: 50-100 MB              │                           │
│  └──────────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Main Agent (LaunchDaemon)
- **Binary**: `/usr/local/mesh_services/meshagent/meshagent`
- **Plist**: `/Library/LaunchDaemons/com.meshcentral.agent.plist`
- **Context**: Root daemon (system-wide)
- **Responsibilities**:
  - Maintain WebSocket connection to MeshCentral server
  - Execute remote terminal commands
  - Handle file operations
  - **Connect** to KVM service (never spawns it)

### 2. KVM Service (LaunchAgent)
- **Binary**: `/usr/local/mesh_services/meshagent/meshagent -kvm1`
- **Plist**: `/Library/LaunchAgents/com.meshcentral.agent-launchagent.plist`
- **Context**: LoginWindow + Aqua (user sessions)
- **Responsibilities**:
  - Create Unix domain socket on startup
  - Wait for connections from main agent
  - Capture screen when connected
  - Inject mouse/keyboard events
  - Return to idle when disconnected

## Session Context Handling

### macOS Session Types

| Scenario | Session Type | KVM Service State | Screen Access |
|----------|--------------|-------------------|---------------|
| **No user logged in** | LoginWindow | ACTIVE | ✅ Login screen |
| **User logs in** | Aqua | ACTIVE | ✅ User's desktop |
| **Fast User Switching** | Multiple Aqua | One per user | ✅ Each user's desktop |
| **User logs out** | Returns to LoginWindow | ACTIVE | ✅ Login screen |

### How It Works

macOS `launchd` automatically handles session transitions:

1. **Boot**: LaunchAgent starts in `LoginWindow` context
2. **User logs in**: LaunchAgent transitions to `Aqua` context for that user
3. **Fast User Switching**: Multiple LaunchAgent instances (one per logged-in user)
4. **Logout**: Returns to `LoginWindow` context

**The KVM service maintains the same Unix socket path across all session types.**

## Remote Desktop Session Flow

### 1. User Initiates Remote Desktop

```
User clicks "Desktop" in MeshCentral Console
    ↓
MeshCentral Server sends command to Main Agent
    ↓
Main Agent receives "start remote desktop" command
```

### 2. Connection Establishment

```c
// In agentcore.c:
char *socket_path = kvm_relay_setup(...);  // Returns "/usr/local/mesh_services/meshagent/kvm"
net.createConnection({ path: socket_path });  // Connect to KVM service
```

### 3. KVM Service Activation

```c
// In mac_kvm.c kvm_server_mainloop():
accept(KVM_Listener_FD, ...);  // Blocks here in IDLE mode (0% CPU)
                                // Wakes up when main agent connects
kvm_init();                     // Initialize screen capture
// Enter capture loop (15-30% CPU)
```

### 4. Screen Capture Loop

```
Loop every ~33ms (30 FPS):
    1. Capture screen: CGDisplayCreateImage()
    2. Divide into 32x32 pixel tiles
    3. Check each tile for changes (CRC)
    4. Compress changed tiles to JPEG
    5. Send tiles to main agent via socket
    6. Main agent forwards to MeshCentral server
    7. User sees screen in browser
```

### 5. Input Injection

```
User moves mouse in browser
    ↓
Browser → MeshCentral → Main Agent → KVM Service
    ↓
CGEventCreateMouseEvent() / CGEventPost()  // Inject into macOS
```

### 6. Disconnection

```
User closes remote desktop
    ↓
Main Agent closes socket connection
    ↓
KVM Service detects closed socket (read() returns 0)
    ↓
Cleanup screen buffers, return to accept() (IDLE mode, 0% CPU)
```

## IPC Protocol

### Unix Domain Socket

- **Path**: `/usr/local/mesh_services/meshagent/kvm`
- **Type**: `AF_UNIX`, `SOCK_STREAM`
- **Created by**: KVM service (`meshagent -kvm1`)
- **Connected to by**: Main agent

### Message Format

All messages use network byte order (big-endian):

```
┌────────────┬────────────┬─────────────────┐
│ Type       │ Size       │ Data            │
│ (2 bytes)  │ (2 bytes)  │ (variable)      │
└────────────┴────────────┴─────────────────┘
```

### Message Types (from meshdefines.h)

```c
#define MNG_KVM_KEY             1   // Keyboard input
#define MNG_KVM_MOUSE           2   // Mouse movement/clicks
#define MNG_KVM_PICTURE         3   // Screen tile (JPEG compressed)
#define MNG_KVM_COMPRESSION     5   // Compression quality setting
#define MNG_KVM_REFRESH         6   // Force full screen refresh
#define MNG_KVM_SCREEN          7   // Screen resolution change
#define MNG_KVM_PAUSE           8   // Pause/resume capture
#define MNG_KVM_KEYSTATE       18   // Keyboard state (caps/num lock)
```

## Apple Security Compliance

### Why This Architecture?

Apple's security model requires that:
1. **Screen Recording** permission must be requested by the process capturing the screen
2. **LaunchAgents** can request user-facing permissions
3. **LaunchDaemons** (root) cannot properly request screen capture permissions
4. Processes spawned by LaunchDaemons inherit daemon context (no screen access)

### Previous Architecture (Non-Compliant)

```
LaunchDaemon (root)
    └─→ Spawns child: meshagent -kvm0
        └─→ Tries to capture screen
            ❌ FAILS: No screen recording permission
            ❌ FAILS: Not in correct session context
```

### New Architecture (Compliant)

```
LaunchAgent (user session)
    └─→ Runs: meshagent -kvm1
        └─→ Can request Screen Recording permission ✅
        └─→ Runs in correct session context ✅
        └─→ Can capture screen ✅
```

## Permissions Required

### Main Agent (LaunchDaemon)
- ✅ Root privileges (for system commands)
- ✅ Full Disk Access (for file operations)
- ✅ Network access (connect to MeshCentral)

### KVM Service (LaunchAgent)
- ✅ **Screen Recording** (macOS 10.15+)
- ✅ **Accessibility** (for mouse/keyboard injection)
- ❌ NO root privileges
- ❌ NO Full Disk Access

## Installation

### Automatic Installation

The agent installer automatically sets up both components:

```javascript
// In agent-installer.js:
// 1. Install main agent (LaunchDaemon)
require('service-manager').manager.installService(options);

// 2. Install KVM service (LaunchAgent) - macOS only
if (process.platform == 'darwin') {
    require('service-manager').manager.installLaunchAgent({
        name: options.name,
        servicePath: '/usr/local/mesh_services/meshagent/meshagent',
        startType: 'AUTO_START',
        sessionTypes: ['LoginWindow', 'Aqua'],
        parameters: ['-kvm1']
    });
}
```

### Manual Installation

```bash
# 1. Copy binary
sudo cp meshagent_osx-x86-64 /usr/local/mesh_services/meshagent/meshagent

# 2. Install LaunchDaemon (main agent)
sudo cp com.meshcentral.agent.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.meshcentral.agent.plist

# 3. Install LaunchAgent (KVM service)
sudo cp com.meshcentral.agent-launchagent.plist /Library/LaunchAgents/
sudo launchctl bootstrap gui/501 /Library/LaunchAgents/com.meshcentral.agent-launchagent.plist
```

## Logging

### Main Agent Logs
- **Location**: `/var/log/meshagent.log` (or as configured)
- **Contains**: Connection status, terminal commands, file operations

### KVM Service Logs
- **Location**: `/var/log/meshagent-kvm.log`
- **Contains**: Screen capture events, socket connections, errors

### Useful Debug Commands

```bash
# Check if KVM service is running
ps aux | grep "meshagent -kvm1"

# Check if socket exists
ls -la /usr/local/mesh_services/meshagent/kvm

# View KVM service logs
tail -f /var/log/meshagent-kvm.log

# Check LaunchAgent status
launchctl print gui/501/com.meshcentral.agent-launchagent

# Manually start/stop KVM service
launchctl start com.meshcentral.agent-launchagent
launchctl stop com.meshcentral.agent-launchagent
```

## Performance Characteristics

### Resource Usage

| State | CPU | Memory | Network |
|-------|-----|--------|---------|
| **KVM IDLE** (no connection) | ~0% | ~10 MB | 0 KB/s |
| **KVM ACTIVE** (capturing) | 15-30% | 50-100 MB | 500 KB/s - 2 MB/s |
| **Main Agent** | 1-5% | 30-50 MB | Varies |

### Optimization Features

1. **Tile-based encoding**: Only changed 32x32 pixel regions are sent
2. **CRC checking**: Tiles are only encoded if pixels changed
3. **JPEG compression**: Adjustable quality (default 50%)
4. **Idle mode**: 0% CPU when no remote desktop active
5. **Socket reuse**: Multiple connections without process restart

## Troubleshooting

### KVM Not Working

**Symptom**: Remote desktop shows black screen or fails to connect

**Checklist**:
1. Check if KVM service is running:
   ```bash
   ps aux | grep "meshagent -kvm1"
   ```

2. Check if socket exists:
   ```bash
   ls -la /usr/local/mesh_services/meshagent/kvm
   ```

3. Check permissions in System Preferences:
   - Security & Privacy → Privacy → Screen Recording → meshagent ✅
   - Security & Privacy → Privacy → Accessibility → meshagent ✅

4. Check KVM service logs:
   ```bash
   tail -100 /var/log/meshagent-kvm.log
   ```

5. Restart KVM service:
   ```bash
   sudo launchctl stop com.meshcentral.agent-launchagent
   sudo launchctl start com.meshcentral.agent-launchagent
   ```

### Permission Prompts Not Appearing

If macOS doesn't prompt for Screen Recording permission:

```bash
# Reset privacy database (requires reboot)
sudo tccutil reset ScreenCapture
sudo tccutil reset Accessibility

# Reboot
sudo reboot
```

## Code Changes Summary

### Files Modified

1. **modules/agent-installer.js**:
   - Added `'Aqua'` to `sessionTypes` array (line 318)
   - KVM LaunchAgent now runs in both LoginWindow and Aqua contexts

2. **meshcore/KVM/MacOS/mac_kvm.c**:
   - Simplified `kvm_relay_setup()` to always return socket path
   - Removed child process spawning logic
   - Added documentation explaining the new architecture

3. **meshcore/agentcore.c**:
   - Unified socket connection logic for both `console_uid == 0` and `!= 0`
   - All remote desktop connections now use Unix domain socket
   - Added clarifying comments

### Files Created

1. **agents/macos/com.meshcentral.kvm.plist**:
   - Template LaunchAgent plist (for reference)
   - Not directly used (generated by service-manager.js)

2. **docs/MACOS_KVM_ARCHITECTURE.md**:
   - This document

## Future Enhancements

### Potential Improvements

1. **Multi-display support**:
   - Currently only captures main display
   - Could enumerate all displays and create separate streams

2. **ScreenCaptureKit integration** (macOS 12+):
   - Modern API with better performance
   - Would require additional permission handling

3. **Dynamic quality adjustment**:
   - Adjust JPEG quality based on network bandwidth
   - Already has infrastructure via `MNG_KVM_COMPRESSION` messages

4. **Graceful degradation**:
   - If LaunchAgent not installed, fall back to terminal-only mode
   - Inform user about KVM unavailability

## References

- [Apple LaunchDaemons and LaunchAgents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [macOS Screen Capture Permissions](https://developer.apple.com/documentation/avfoundation/avcapturedevice/requesting_authorization_to_capture_and_save_media)
- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [MeshCentral Documentation](https://meshcentral.com/info/)

## License

Apache License 2.0 (same as MeshAgent)
