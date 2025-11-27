# mac_kvm.c

Main KVM implementation for macOS using **reversed socket architecture** where LaunchAgent-spawned -kvm1 process connects to daemon socket (not spawned by daemon), enabling KVM to run in proper user session context.

## Platform
**macOS (darwin) only** - Uses CoreGraphics, LaunchAgent system

## Architecture: Reversed Socket Pattern

**Traditional (Windows/Linux):**
```
daemon spawns → child KVM process
```

**macOS Reversed:**
```
1. Daemon creates /tmp/meshagent-kvm.sock (listening)
2. Daemon creates /var/run/meshagent/session-active (signal file)
3. LaunchAgent watches directory via QueueDirectories
4. LaunchAgent spawns -kvm1 process
5. -kvm1 CONNECTS to daemon socket
6. Signal file removed → LaunchAgent exits -kvm1
```

**Why Reversed?**
- **Bootstrap Namespace:** macOS doesn't allow daemon-spawned processes to access user session
- **Correct Context:** LaunchAgent ensures -kvm1 runs as LoginWindow/Aqua user
- **Clean Lifecycle:** QueueDirectories provides reliable process management

## Functionality

### Daemon Mode (main meshagent)
- Creates Unix domain socket listener
- Handles KVM protocol (tile requests, mouse/keyboard events)
- Manages signal file lifecycle
- Validates connecting clients via code signature

### Client Mode (-kvm1 process)
- Connects to daemon socket
- Captures screen tiles
- Injects mouse/keyboard events
- Requires TCC permissions (Screen Recording, Accessibility)

### Key Functions
- **KVM_Create_Daemon_Listener()** - Daemon creates listener socket
- **KVM_Connect_To_Daemon()** - Client connects to daemon
- **KVM_OnDataReceive()** - Protocol message handler
- **verify_peer_codesign()** - Authenticates connecting client

## Dependencies
- `<CoreGraphics/CoreGraphics.h>` - Screen capture
- `<sys/socket.h>`, `<sys/un.h>` - Unix domain sockets
- `<IOKit/IOKitLib.h>` - Display info
- [mac_kvm_auth.c](mac_kvm_auth.md) - Code signature verification
- [mac_tile.c](mac_tile.md) - Screen tile capture
- [mac_events.c](mac_events.md) - Input injection

## Protocol
KVM protocol messages over Unix socket:
- **MNG_KVM_SCREEN** - Screen size info
- **MNG_KVM_REFRESH** - Tile data (JPEG compressed)
- **MNG_KVM_MOUSE** - Mouse events
- **MNG_KVM_KEYB** - Keyboard events
- **MNG_KVM_PAUSE/RESUME** - Session control

## Security
- **Code Signature Auth:** verify_peer_codesign() ensures only meshagent connects
- **TCC Permissions:** Requires Screen Recording + Accessibility
- **Socket Permissions:** /tmp socket with restricted access

## LaunchAgent Integration
**Plist location:** `/Library/LaunchAgents/meshagent-kvm1.plist`

**QueueDirectories:** Monitors `/var/run/meshagent/` for signal file

**Arguments:** `meshagent -kvm1` connects to daemon socket

## Cross-References
- [macOS KVM Architecture](../macos-KVM-Architecture.md) - Detailed design doc
- [mac_kvm_auth.c](mac_kvm_auth.md) - Socket authentication
- [mac_tile.c](mac_tile.md) - Screen capture
- [mac_events.c](mac_events.md) - Input events

---
**Source:** `meshcore/KVM/MacOS/mac_kvm.c` | **LOC:** 1368 | **Updated:** 2025-11-28 | **Architecture:** Reversed socket (Oct 2025)
