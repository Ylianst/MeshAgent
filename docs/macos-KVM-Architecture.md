# macOS MeshAgent KVM LaunchDaemon/LaunchAgent Architecture

## Introduction

The macOS MeshAgent implements KVM (Keyboard/Video/Mouse) remote access functionality through a sophisticated LaunchDaemon/LaunchAgent architecture. This design enables secure, on-demand screen sharing capabilities while properly handling macOS security restrictions and user context requirements.

The architecture separates system-level daemon operations from user-level agent operations, ensuring that screen capture and input injection occur in the correct user session context while maintaining secure communication between components.

## Architecture Overview

### Current Design: Reversed Architecture

The current implementation uses a **reversed architecture** where the `-kvm1` process is an independent LaunchAgent that **connects to** the daemon's socket rather than being spawned by it.

**Key Components:**
- **LaunchDaemon** (System Service): Main meshagent daemon running as root
- **LaunchAgent** (User Service): On-demand `-kvm1` process running in user context
- **Unix Domain Socket**: Communication channel between daemon and agent
- **QueueDirectories**: Trigger mechanism for agent activation

### Why This Architecture?

**Apple Bootstrap Namespace Restrictions:**
- macOS prevents system daemons from spawning processes in user GUI sessions
- Attempting to spawn directly results in processes that cannot access the user's screen/input
- The LaunchAgent must be registered and started by `launchd` in the user's bootstrap namespace

**Solution:**
- Daemon creates a listening socket and signals readiness
- LaunchAgent monitors a queue directory for activation signals
- When signaled, LaunchAgent starts and connects to daemon's socket
- All screen capture and input injection happens in the user context

## LaunchDaemon Configuration

### File Location

```
Template: /Library/LaunchDaemons/{serviceId}.plist
Examples:
  - /Library/LaunchDaemons/meshagent.plist
  - /Library/LaunchDaemons/meshagent.Company-Name.plist
```

### Plist Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Disabled</key>
    <false/>

    <key>KeepAlive</key>
    <true/>

    <key>Label</key>
    <string>{serviceId}</string>

    <key>ProgramArguments</key>
    <array>
        <string>/path/to/meshagent</string>
    </array>

    <key>RunAtLoad</key>
    <true/>  <!-- or false for DEMAND_START -->

    <key>StandardErrorPath</key>
    <string>/tmp/{serviceId}-daemon.log</string>

    <key>StandardOutPath</key>
    <string>/tmp/{serviceId}-daemon.log</string>

    <key>WorkingDirectory</key>
    <string>/install/path</string>
</dict>
</plist>
```

### Key Properties

| Property | Value | Purpose |
|----------|-------|---------|
| `Label` | `{serviceId}` | Unique identifier for the daemon |
| `KeepAlive` | `true` | Daemon runs continuously |
| `RunAtLoad` | `true`/`false` | Start at boot or on-demand |
| `ProgramArguments` | Path to meshagent binary | Executable to run |
| `StandardOutPath` | `/tmp/{serviceId}-daemon.log` | Output log location |
| `StandardErrorPath` | `/tmp/{serviceId}-daemon.log` | Error log location |

### Creation

**Created by:** `service-manager.js` → `installService()` function (lines 2856-2922)

**Installation command:**
```bash
launchctl bootstrap system /Library/LaunchDaemons/{serviceId}.plist
```

## LaunchAgent Configuration

### File Location

```
Template: /Library/LaunchAgents/{serviceId}-agent.plist
Examples:
  - /Library/LaunchAgents/meshagent-agent.plist
  - /Library/LaunchAgents/meshagent.Company-Name-agent.plist
```

### Plist Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Disabled</key>
    <false/>

    <key>Label</key>
    <string>{serviceId}-agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/path/to/meshagent</string>
        <string>-kvm1</string>
    </array>

    <key>WorkingDirectory</key>
    <string>/install/path</string>

    <key>StandardErrorPath</key>
    <string>/tmp/{serviceId}-agent.log</string>

    <key>StandardOutPath</key>
    <string>/tmp/{serviceId}-agent.log</string>

    <key>LimitLoadToSessionType</key>
    <array>
        <string>Aqua</string>
        <string>LoginWindow</string>
    </array>

    <key>KeepAlive</key>
    <false/>

    <key>QueueDirectories</key>
    <array>
        <string>/var/run/{serviceId}</string>
    </array>
</dict>
</plist>
```

### Key Properties

| Property | Value | Purpose |
|----------|-------|---------|
| `Label` | `{serviceId}-agent` | Unique identifier for the agent |
| `ProgramArguments` | `[meshagent, -kvm1]` | Runs meshagent in KVM mode |
| `KeepAlive` | `false` | Starts on-demand, exits when idle |
| `QueueDirectories` | `/var/run/{serviceId}` | Trigger directory for activation |
| `LimitLoadToSessionType` | `[Aqua, LoginWindow]` | Only run in GUI sessions |
| `StandardOutPath` | `/tmp/{serviceId}-agent.log` | Output log location |

### Creation

**Created by:** `service-manager.js` → `installLaunchAgent()` function (lines 2944-3043)

**Installation command:**
```bash
launchctl bootstrap gui/{uid} /Library/LaunchAgents/{serviceId}-agent.plist
```

## Socket Communication

### Socket Location

```
Template: /tmp/{serviceId}.sock
Examples:
  - /tmp/meshagent-agent.sock
  - /tmp/meshagent.Company-Name.sock
```

**Socket Type:** Unix domain socket (AF_UNIX, SOCK_STREAM)

### Socket Creation Flow

**Created by daemon** in `mac_kvm.c` → `kvm_create_session()` (lines 992-1052):

1. **Create socket:**
   ```c
   int fd = socket(AF_UNIX, SOCK_STREAM, 0);
   ```

2. **Bind to path:**
   ```c
   bind(fd, (struct sockaddr*)&addr, sizeof(addr));
   // Path: /tmp/{serviceId}.sock
   ```

3. **Listen with backlog:**
   ```c
   listen(fd, 2);  // Backlog of 2 for fast user-switching
   ```

4. **Set permissions:**
   ```c
   chmod(KVM_Listener_Path, 0777);
   ```

### Connection Logic

**Initiated by `-kvm1` agent** in `mac_kvm.c` → `kvm_server_connect()` (lines 662-745):

```c
// Retry logic: 30 attempts, 1-second delays
for (int retry = 0; retry < 30; retry++) {
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        // Connected successfully
        return fd;
    }
    sleep(1);
}
// Connection failed after retries
return -1;
```

**On successful connection:**
- Daemon accepts connection (lines 1191-1192)
- Daemon verifies peer code signature for security (line 1202)
- KVM session established, data flows through socket

**On connection loss:**
- Automatic reconnection attempted (lines 758-795)
- If reconnection fails, `-kvm1` process exits

## WatchFolders (QueueDirectories) Mechanism

### Queue Directory

```
Template: /var/run/{serviceId}
Example:  /var/run/meshagent
```

**Purpose:** Trigger directory that signals when LaunchAgent should start

### Signal File

```
Template: /var/run/{serviceId}/session-active
Example:  /var/run/meshagent/session-active
```

**Purpose:** Presence of this file triggers LaunchAgent activation

### How QueueDirectories Works

**macOS launchd behavior:**
- Monitors specified directories
- When directory transitions from empty → non-empty: starts the job
- When directory transitions from non-empty → empty: exits the job

**MeshAgent implementation:**

1. **Activation:**
   ```
   Daemon creates /var/run/{serviceId}/session-active
   → Directory is now non-empty
   → launchd automatically starts {serviceId}-agent
   → Agent executes: meshagent -kvm1
   ```

2. **Deactivation:**
   ```
   Daemon deletes /var/run/{serviceId}/session-active
   → Directory is now empty
   → launchd automatically terminates {serviceId}-agent
   → Agent process exits
   ```

### Why QueueDirectories?

**Advantages:**
- Leverages native launchd functionality
- No direct process spawning needed
- Respects macOS bootstrap namespace restrictions
- Automatic process lifecycle management
- Works correctly with fast user switching

**Code reference:** `service-manager.js` lines 3007-3010

## Process Interaction Flow

### Session Initialization

```
┌─────────────────────────────────────────────────────────────┐
│ User clicks "Connect" in MeshCentral Web Interface          │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ MeshCentral Server sends KVM connect command to agent       │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Daemon: kvm_create_session() (mac_kvm.c:992)                │
│  1. Create Unix socket at /tmp/{serviceId}.sock             │
│  2. Listen on socket (backlog = 2)                          │
│  3. Create directory /var/run/{serviceId}                   │
│  4. Create file /var/run/{serviceId}/session-active         │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ launchd detects QueueDirectory is non-empty                 │
│  → Starts {serviceId}-agent LaunchAgent                     │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Agent: meshagent -kvm1 process starts                       │
│  → Runs kvm_server_connect() (mac_kvm.c:662)                │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Agent: Connect to /tmp/{serviceId}.sock                     │
│  → Retry logic: 30 attempts, 1s delay                       │
│  → Prints: "KVM: Connecting to socket: {path}"              │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Daemon: Accept connection (mac_kvm.c:1191)                  │
│  → Verify peer code signature (line 1202)                   │
│  → Store connection file descriptor                         │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Agent: Initialize KVM (mac_kvm.c:716)                       │
│  → kvm_init() - Set up screen capture                       │
│  → Prints: "KVM: Connected (fd={fd})"                       │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ KVM Session Active                                          │
│  - Agent captures screen, sends tiles to daemon             │
│  - Daemon forwards keyboard/mouse input to agent            │
│  - Data flows through Unix domain socket                    │
└─────────────────────────────────────────────────────────────┘
```

### Session Termination

```
┌─────────────────────────────────────────────────────────────┐
│ User disconnects or session timeout                         │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Daemon: kvm_cleanup_session() (mac_kvm.c:1084)              │
│  1. Close socket connection                                 │
│  2. Remove socket file /tmp/{serviceId}.sock                │
│  3. Delete /var/run/{serviceId}/session-active              │
│  4. Clear all files in /var/run/{serviceId}                 │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ launchd detects QueueDirectory is empty                     │
│  → Terminates {serviceId}-agent LaunchAgent                 │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│ Agent: meshagent -kvm1 process exits                        │
└─────────────────────────────────────────────────────────────┘
```

## File Paths Reference

### Complete Path Matrix

| Component | Path Template | Example |
|-----------|---------------|---------|
| **LaunchDaemon plist** | `/Library/LaunchDaemons/{serviceId}.plist` | `/Library/LaunchDaemons/meshagent.plist` |
| **LaunchAgent plist** | `/Library/LaunchAgents/{serviceId}-agent.plist` | `/Library/LaunchAgents/meshagent-agent.plist` |
| **Unix Socket** | `/tmp/{serviceId}.sock` | `/tmp/meshagent-agent.sock` |
| **Queue Directory** | `/var/run/{serviceId}` | `/var/run/meshagent` |
| **Signal File** | `/var/run/{serviceId}/session-active` | `/var/run/meshagent/session-active` |
| **Daemon Log** | `/tmp/{serviceId}-daemon.log` | `/tmp/meshagent-daemon.log` |
| **Agent Log** | `/tmp/{serviceId}-agent.log` | `/tmp/meshagent-agent.log` |
| **KVM Process Log** | `KVMAgent.log` | `KVMAgent.log` |

### Path Resolution

**ServiceID resolution priority** (from `mac_kvm.c` lines 537-587):
1. Database serviceID (from .msh file)
2. LaunchDaemon plist Label (fallback)
3. Default: "meshagent-agent"

**Path building function:** `kvm_build_dynamic_paths()` at line 584

## Implementation Files Reference

### Core KVM Implementation

| File | Purpose | Key Functions |
|------|---------|---------------|
| `meshcore/KVM/MacOS/mac_kvm.c` | Main KVM socket and session management | `kvm_create_session()` (992)<br>`kvm_cleanup_session()` (1084)<br>`kvm_server_connect()` (662)<br>`kvm_build_dynamic_paths()` (584) |
| `meshcore/KVM/MacOS/mac_kvm.h` | KVM header declarations | Function prototypes |

### Service Management

| File | Purpose | Key Functions |
|------|---------|---------------|
| `modules/service-manager.js` | Plist creation and installation | `installService()` (2856-2922)<br>`installLaunchAgent()` (2944-3043) |
| `modules/agent-installer.js` | Installation orchestration | Installation flow (409-1798) |
| `modules/macOSHelpers.js` | ServiceID utilities | `buildServiceId()` (91-126)<br>Path helpers (75-228) |

### Utilities

| File | Purpose | Key Functions |
|------|---------|---------------|
| `meshcore/MacOS/mac_plist_utils.c` | Secure plist parsing | Plist manipulation (1-228) |
| `meshcore/MacOS/mac_plist_utils.h` | Plist utilities header | Function declarations |
| `meshcore/agentcore.c` | Main agent with KVM integration | KVM socket integration (1037-1595) |

## Logging and Debugging

### Log File Locations

**LaunchDaemon logs:**
```
/tmp/{serviceId}-daemon.log
```
Contains:
- Daemon startup and shutdown
- Socket creation and binding
- Connection acceptance
- Session lifecycle events

**LaunchAgent logs:**
```
/tmp/{serviceId}-agent.log
```
Contains:
- Agent process start/stop
- Socket connection attempts
- Connection success/failure
- Screen capture initialization

**KVM Process logs:**
```
KVMAgent.log
```
Contains:
- Detailed KVM operation logs
- Screen capture events
- Input processing

### Debug Output Examples

**Successful Connection:**
```
KVM: -kvm1 connecting to socket: /tmp/meshagent-agent.sock
KVM: Connected (fd=5)
```

**Connection Retry:**
```
KVM: -kvm1 connecting to socket: /tmp/meshagent-agent.sock
KVM: Connection failed (attempt 1/30), retrying...
KVM: Connection failed (attempt 2/30), retrying...
...
KVM: Connected (fd=5)
```

**Connection Failure:**
```
KVM: -kvm1 connecting to socket: /tmp/meshagent-agent.sock
KVM: Connection failed (attempt 1/30), retrying...
...
KVM: Connection failed (attempt 30/30), giving up
KVM: Fatal: Could not connect to daemon socket
```

### Monitoring Active Sessions

**Check if session is active:**
```bash
# Signal file exists = session active
ls -la /var/run/{serviceId}/session-active

# Socket exists = daemon listening
ls -la /tmp/{serviceId}.sock

# Agent process running
ps aux | grep "meshagent -kvm1"
```

**Check launchd status:**
```bash
# LaunchDaemon status
sudo launchctl print system/{serviceId}

# LaunchAgent status (as user)
launchctl print gui/$(id -u)/{serviceId}-agent
```

## Security Considerations

### Code Signature Verification

The daemon verifies the connecting `-kvm1` process signature before accepting the connection (line 1202 in `mac_kvm.c`). This prevents unauthorized processes from connecting to the KVM socket.

### Socket Permissions

Socket is created with permissions `0777` (line 1042) to allow the user-context agent to connect to the root-owned daemon's socket.

### User Context Isolation

The `-kvm1` process runs entirely in user context, ensuring:
- Screen capture occurs with proper user session access
- Input injection happens in correct user session
- No privilege escalation required for screen access

---

**Document Version:** 1.0
**Last Updated:** 2025-01-27
**Applies to:** Current macOS MeshAgent implementation
