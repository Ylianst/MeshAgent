# macOS MeshAgent Architecture

## Overview

The macOS MeshAgent uses a **dual-service architecture** consisting of two cooperating components:

1. **LaunchDaemon** - System-level service (runs as root)
2. **LaunchAgent** - User-level service (runs in user sessions)

This architecture enables the agent to operate both at the system level (for core functionality) and within user sessions (for KVM/desktop interaction).

---

## Table of Contents

- [Why Two Services?](#why-two-services)
- [LaunchDaemon (System Service)](#launchdaemon-system-service)
- [LaunchAgent (User Session Service)](#launchagent-user-session-service)
- [QueueDirectories: On-Demand Activation](#queuedirectories-on-demand-activation)
- [Socket Communication](#socket-communication)
- [Process Flow](#process-flow)
- [Service Identification](#service-identification)
- [File System Layout](#file-system-layout)
- [Design Benefits](#design-benefits)
- [Comparison with Other Platforms](#comparison-with-other-platforms)

---

## Why Two Services?

macOS security architecture separates **system-level** and **user-level** operations. A single service cannot efficiently handle both:

| Requirement | LaunchDaemon | LaunchAgent |
|-------------|--------------|-------------|
| System-level access | ✅ Yes | ❌ No |
| User session context | ❌ No | ✅ Yes |
| Desktop/GUI access | ❌ No | ✅ Yes |
| Runs at boot | ✅ Yes | ❌ No (login only) |
| Root privileges | ✅ Yes | ❌ No |
| KVM functionality | ❌ No | ✅ Yes |

**Solution:** Use both services working together:
- **LaunchDaemon** handles core agent functionality
- **LaunchAgent** provides KVM support when users log in

---

## LaunchDaemon (System Service)

### Location
```
/Library/LaunchDaemons/{serviceId}.plist
```

### Purpose
The LaunchDaemon is the **primary MeshAgent service** that:
- Maintains connection to MeshCentral server
- Handles remote management commands
- Runs continuously (even without users logged in)
- Operates with root privileges
- Manages agent database and configuration

### Plist Structure

**Code Reference:** `/modules/service-manager.js:2908-2936`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>meshagent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/mesh_services/meshagent/meshagent</string>
        <string>--serviceId=meshagent</string>
    </array>

    <key>KeepAlive</key>
    <true/>

    <key>RunAtLoad</key>
    <true/>

    <key>WorkingDirectory</key>
    <string>/usr/local/mesh_services/meshagent/</string>
</dict>
</plist>
```

### Key Fields Explained

**Label**
- Unique identifier for the service
- Matches the serviceId (e.g., `meshagent`, `meshagent.acme`, `meshagent.tactical.acme`)
- Used by launchd for service management

**ProgramArguments**
- Array of command-line arguments
- First element: Full path to meshagent binary
- Second element: `--serviceId` parameter (CRITICAL - see [naming-and-configuration.md](./naming-and-configuration.md))

**KeepAlive**
- `true` = launchd automatically restarts if the process exits
- Ensures continuous operation

**RunAtLoad**
- `true` = Service starts automatically at system boot
- Does not require user login

**WorkingDirectory**
- Sets current directory for the process
- Where meshagent.db, .msh files are located

### Service Management

**Load Service:**
```bash
sudo launchctl load /Library/LaunchDaemons/meshagent.plist
```

**Unload Service:**
```bash
sudo launchctl unload /Library/LaunchDaemons/meshagent.plist
```

**Check Status:**
```bash
sudo launchctl print system/meshagent
```

**View Logs:**
```bash
# Service stdout/stderr
sudo log show --predicate 'process == "meshagent"' --last 1h

# System log messages
sudo log show --predicate 'subsystem == "com.apple.launchd"' --info --last 1h | grep meshagent
```

---

## LaunchAgent (User Session Service)

### Location
```
/Library/LaunchAgents/{serviceId}-agent.plist
```

Note the `-agent` suffix in the filename and Label.

### Purpose
The LaunchAgent provides **KVM (Keyboard, Video, Mouse) functionality** by:
- Running in user session context (Aqua/GUI)
- Accessing user desktop for screen capture
- Handling keyboard/mouse input
- Starting on-demand (not always running)
- Operating with user-level permissions

### Plist Structure

**Code Reference:** `/modules/service-manager.js:2958-3076`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>meshagent-agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/mesh_services/meshagent/meshagent</string>
        <string>-kvm1</string>
        <string>--serviceId=meshagent</string>
    </array>

    <key>LimitLoadToSessionType</key>
    <array>
        <string>Aqua</string>
        <string>LoginWindow</string>
    </array>

    <key>KeepAlive</key>
    <false/>

    <key>QueueDirectories</key>
    <array>
        <string>/var/run/meshagent</string>
    </array>
</dict>
</plist>
```

### Key Fields Explained

**Label**
- Service identifier with `-agent` suffix
- Example: `meshagent-agent`, `meshagent.acme-agent`

**ProgramArguments**
- First element: Full path to meshagent binary (same as LaunchDaemon)
- Second element: **`-kvm1`** flag (indicates KVM helper mode)
- Third element: `--serviceId` parameter (must match LaunchDaemon)

**LimitLoadToSessionType**
- `Aqua` = Standard user GUI sessions
- `LoginWindow` = Login window context
- Prevents loading in SSH sessions or other non-GUI contexts

**KeepAlive**
- `false` = Process can exit when not needed
- Reduces resource usage when KVM is not active

**QueueDirectories**
- **CRITICAL:** Enables on-demand activation (see next section)
- Path must match serviceId: `/var/run/{serviceId}`

### Service Management

**Load Service (per-user):**
```bash
launchctl load /Library/LaunchAgents/meshagent-agent.plist
```

**Unload Service (per-user):**
```bash
launchctl unload /Library/LaunchAgents/meshagent-agent.plist
```

**Check Status:**
```bash
# Check if loaded for current user
launchctl print gui/$(id -u)/meshagent-agent

# Check all user sessions
sudo launchctl print gui/501/meshagent-agent
```

**Important:** LaunchAgents are loaded PER-USER-SESSION. Each logged-in user has their own instance.

---

## QueueDirectories: On-Demand Activation

### What is QueueDirectories?

**QueueDirectories** is a macOS launchd feature that automatically starts a service when files appear in a specified directory.

**Code Reference:** `/modules/service-manager.js:3050-3053`

```javascript
plist += '      <key>QueueDirectories</key>\n';
plist += '      <array>\n';
plist += ('         <string>/var/run/' + serviceId + '</string>\n');
plist += '      </array>\n';
```

### How It Works

1. **LaunchAgent is loaded** but process is NOT running (KeepAlive=false)
2. **File appears** in `/var/run/{serviceId}/`
3. **launchd automatically starts** the LaunchAgent process
4. **Process handles** the file/request
5. **Process can exit** when done (KeepAlive=false allows this)

### Why Use QueueDirectories?

**Benefits:**
- **Resource efficiency:** LaunchAgent only runs when needed
- **Automatic activation:** No manual process management
- **Clean design:** Main service (LaunchDaemon) can trigger KVM helper by creating files

**Alternative without QueueDirectories:**
- LaunchAgent runs continuously (wastes resources)
- OR manual process spawning (complex IPC)

### Socket Path Structure

The socket/queue directory path is **dynamically generated** based on serviceId:

```
/var/run/{serviceId}/
```

**Examples:**
```bash
# Default installation
/var/run/meshagent/

# Company "acme"
/var/run/meshagent.acme/

# Service "tactical" + company "acme"
/var/run/meshagent.tactical.acme/
```

This ensures **multiple installations don't conflict** - each has its own socket directory.

### Directory Creation

The `/var/run/{serviceId}` directory must be created during installation:

```bash
sudo mkdir -p /var/run/meshagent
sudo chown root:wheel /var/run/meshagent
sudo chmod 755 /var/run/meshagent
```

**Note:** `/var/run` is typically a symlink to `/private/var/run` on macOS.

---

## Socket Communication

### Communication Pattern

```
┌─────────────────────┐
│   LaunchDaemon      │
│  (System Service)   │
│                     │
│  Needs KVM support  │
└──────────┬──────────┘
           │
           │ 1. Creates file in
           │    /var/run/meshagent/
           ↓
┌─────────────────────┐
│   /var/run/         │
│   meshagent/        │  ← QueueDirectories watches here
│                     │
│   trigger.txt       │  ← File appears
└──────────┬──────────┘
           │
           │ 2. launchd detects file
           │    and starts LaunchAgent
           ↓
┌─────────────────────┐
│   LaunchAgent       │
│  (User Service)     │
│                     │
│  Handles KVM        │
└─────────────────────┘
```

### IPC Mechanisms

The two services can communicate via:

1. **File-based signaling** (QueueDirectories)
   - Simple trigger mechanism
   - One-way: LaunchDaemon → LaunchAgent

2. **Unix domain sockets**
   - Bidirectional communication
   - Sockets created in `/var/run/{serviceId}/`

3. **Shared files in installPath**
   - Configuration files (.msh, .db)
   - Both services have access

---

## Process Flow

### System Boot Sequence

```
1. macOS boots
   └─> launchd starts

2. launchd loads all LaunchDaemons
   └─> /Library/LaunchDaemons/meshagent.plist

3. LaunchDaemon service starts (RunAtLoad=true)
   └─> meshagent binary runs with --serviceId parameter
       └─> Reads configuration from .msh and .db
           └─> Connects to MeshCentral server

4. LaunchAgent plist is loaded (but process not started)
   └─> /Library/LaunchAgents/meshagent-agent.plist
       └─> Waits for files in /var/run/meshagent/ (QueueDirectories)
```

### User Login Sequence

```
1. User logs in to macOS
   └─> User session starts (Aqua/GUI)

2. launchd loads LaunchAgents for user session
   └─> meshagent-agent.plist is loaded
       └─> Process NOT started yet (KeepAlive=false)
       └─> Watches /var/run/meshagent/ (QueueDirectories)

3. User session is ready
   └─> LaunchAgent available for on-demand activation
```

### KVM Request Flow

```
1. MeshCentral user requests KVM session
   └─> Command sent to LaunchDaemon

2. LaunchDaemon needs KVM helper
   └─> Creates trigger file in /var/run/meshagent/
       └─> Example: touch /var/run/meshagent/kvm.trigger

3. launchd detects file (QueueDirectories)
   └─> Automatically starts LaunchAgent process
       └─> meshagent -kvm1 --serviceId=meshagent

4. LaunchAgent starts
   └─> Captures desktop
       └─> Streams to LaunchDaemon
           └─> Sent to MeshCentral server

5. KVM session ends
   └─> LaunchAgent can exit (KeepAlive=false)
```

### Update Flow (Server-Initiated)

**CRITICAL:** When MeshCentral sends down an updated meshagent binary, the `-upgrade` function is **automatically called**.

**Code Reference:** `/meshcore/agentcore.c:6449-6453`

```c
case MeshAgent_Posix_PlatformTypes_LAUNCHD:
    if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [running -upgrade to recreate plists]"); }
    sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "\"%s\" -upgrade", agentHost->exePath);
    ignore_result(system(ILibScratchPad));
    break;
```

**Flow:**
```
1. MeshCentral sends AgentUpdate command
   └─> New binary downloaded

2. Agent replaces binary
   └─> Old binary backed up as .meshagent.backup.{timestamp}

3. Agent calls: meshagent -upgrade
   └─> See installation-functions.md for full -upgrade documentation

4. -upgrade function:
   └─> Discovers current configuration (from plists)
       └─> Unloads services
           └─> Kills processes
               └─> Recreates LaunchDaemon plist
                   └─> Recreates LaunchAgent plist
                       └─> Reloads services
```

See [installation-functions.md](./installation-functions.md#upgrade-function) for complete -upgrade documentation.

---

## Service Identification

### The serviceId Concept

Every MeshAgent installation has a unique **serviceId** that identifies it:

```
serviceId = "meshagent" | "meshagent.{name}" | "meshagent.{service}.{company}"
```

The serviceId is used for:
- LaunchDaemon Label and filename
- LaunchAgent Label (with `-agent` suffix)
- QueueDirectories path (`/var/run/{serviceId}`)
- Process identification and management

### serviceId Examples

| Scenario | serviceId | LaunchDaemon | LaunchAgent | Queue Path |
|----------|-----------|--------------|-------------|------------|
| Default | `meshagent` | `/Library/LaunchDaemons/meshagent.plist` | `/Library/LaunchAgents/meshagent-agent.plist` | `/var/run/meshagent/` |
| Company only | `meshagent.acme` | `/Library/LaunchDaemons/meshagent.acme.plist` | `/Library/LaunchAgents/meshagent.acme-agent.plist` | `/var/run/meshagent.acme/` |
| Service only | `meshagent.tactical` | `/Library/LaunchDaemons/meshagent.tactical.plist` | `/Library/LaunchAgents/meshagent.tactical-agent.plist` | `/var/run/meshagent.tactical/` |
| Both | `meshagent.tactical.acme` | `/Library/LaunchDaemons/meshagent.tactical.acme.plist` | `/Library/LaunchAgents/meshagent.tactical.acme-agent.plist` | `/var/run/meshagent.tactical.acme/` |

**For complete serviceId calculation rules, see:** [naming-and-configuration.md](./naming-and-configuration.md#serviceid-calculation)

### Multiple Installations

The serviceId system enables **multiple independent MeshAgent installations** on the same system:

```bash
# Installation 1: Production
serviceId: meshagent.production.acme
Path: /usr/local/mesh_services/meshagent_production/

# Installation 2: Development
serviceId: meshagent.development.acme
Path: /usr/local/mesh_services/meshagent_development/

# Installation 3: Testing
serviceId: meshagent.testing.acme
Path: /usr/local/mesh_services/meshagent_testing/
```

Each installation has:
- Separate LaunchDaemon and LaunchAgent plists
- Separate socket directories
- Separate configuration files
- Independent operation

---

## File System Layout

### Standard Installation (Default serviceId)

```
/usr/local/mesh_services/meshagent/
├── meshagent                      # Main binary
├── meshagent.db                   # Configuration database (SimpleDataStore)
├── meshagent.msh                  # Configuration file (key=value format)
└── .meshagent.backup.{timestamp}  # Backup of previous binary (after updates)

/Library/LaunchDaemons/
└── meshagent.plist               # System service definition

/Library/LaunchAgents/
└── meshagent-agent.plist         # User service definition

/var/run/
└── meshagent/                    # Socket/queue directory for IPC
```

### Custom Installation (Custom serviceId)

```
/opt/tacticalmesh/
├── meshagent                      # Main binary
├── meshagent.db                   # Configuration database
├── meshagent.msh                  # Configuration file
└── .meshagent.backup.{timestamp}  # Backup binary

/Library/LaunchDaemons/
└── meshagent.tacticalmesh.plist  # System service (custom serviceId)

/Library/LaunchAgents/
└── meshagent.tacticalmesh-agent.plist  # User service (custom serviceId)

/var/run/
└── meshagent.tacticalmesh/       # Socket/queue directory
```

### File Permissions

**Critical permissions for proper operation:**

```bash
# Binary
-rwxr-xr-x  root:wheel  /usr/local/mesh_services/meshagent/meshagent

# Database and config (only root can read agent credentials)
-rw-------  root:wheel  /usr/local/mesh_services/meshagent/meshagent.db
-rw-r--r--  root:wheel  /usr/local/mesh_services/meshagent/meshagent.msh

# Plists (must be owned by root for system services)
-rw-r--r--  root:wheel  /Library/LaunchDaemons/meshagent.plist
-rw-r--r--  root:wheel  /Library/LaunchAgents/meshagent-agent.plist

# Socket directory (LaunchAgent needs access)
drwxr-xr-x  root:wheel  /var/run/meshagent/
```

---

## Design Benefits

### Advantages of Dual-Service Architecture

**Security:**
- Principle of least privilege: KVM helper runs without root when possible
- Separation of concerns: System ops vs user ops

**Reliability:**
- Core service (LaunchDaemon) remains stable
- KVM issues don't affect main service

**Resource Efficiency:**
- KVM helper only runs when needed (QueueDirectories + KeepAlive=false)
- Main service is lightweight

**Flexibility:**
- Multiple installations supported via serviceId
- Service rename without reinstallation

**Maintainability:**
- Clear separation of responsibilities
- Independent update of system vs user services

### Challenges Addressed

**Challenge:** macOS restricts desktop access from root processes
**Solution:** LaunchAgent runs in user session context

**Challenge:** KVM functionality needed infrequently
**Solution:** QueueDirectories enables on-demand activation

**Challenge:** Multiple MeshAgent installations may conflict
**Solution:** Dynamic serviceId creates unique identifiers

**Challenge:** Service rename requires full reinstall (traditional approach)
**Solution:** --serviceId parameter + -upgrade function

**Challenge:** Orphaned plists after rename/update
**Solution:** cleanupOrphanedPlists() scans and removes based on binary path

---

## Comparison with Other Platforms

### Windows

**Service Model:** Single Windows Service
- Runs as SYSTEM account
- Desktop interaction via Session 0 separation
- Service name configurable

**Differences:**
- No dual-service architecture needed
- Different IPC mechanisms (named pipes, etc.)

### Linux (systemd)

**Service Model:** Single systemd service
- Runs as root (or specified user)
- Desktop interaction via DISPLAY environment
- Service name configurable

**Differences:**
- No dual-service architecture needed
- Socket activation similar to QueueDirectories concept
- Different service management (systemctl)

### macOS Uniqueness

macOS requires the dual-service approach due to:
- **Security model:** Clear separation of system vs user operations
- **GUI access restrictions:** Root processes cannot easily access user desktop
- **Session isolation:** User sessions are more isolated than other platforms
- **launchd design:** Optimized for on-demand service activation

---

## Troubleshooting

### Common Issues

**Problem:** LaunchAgent not starting when expected
```bash
# Check if LaunchAgent is loaded
launchctl print gui/$(id -u)/meshagent-agent

# Verify QueueDirectories path exists
ls -ld /var/run/meshagent/

# Create if missing
sudo mkdir -p /var/run/meshagent
sudo chmod 755 /var/run/meshagent
```

**Problem:** KVM not working
```bash
# Check LaunchAgent status
launchctl print gui/$(id -u)/meshagent-agent

# Check permissions on socket directory
ls -ld /var/run/meshagent/

# Manually trigger LaunchAgent
touch /var/run/meshagent/test.trigger

# Check if process started
ps aux | grep meshagent | grep kvm1
```

**Problem:** Service won't load
```bash
# Check plist syntax
plutil -lint /Library/LaunchDaemons/meshagent.plist

# Check file permissions
ls -l /Library/LaunchDaemons/meshagent.plist

# Fix permissions if needed
sudo chown root:wheel /Library/LaunchDaemons/meshagent.plist
sudo chmod 644 /Library/LaunchDaemons/meshagent.plist
```

**Problem:** Multiple services running
```bash
# List all meshagent LaunchDaemons
ls -l /Library/LaunchDaemons/meshagent*.plist

# Check which are loaded
sudo launchctl print system | grep meshagent

# Unload extras
sudo launchctl unload /Library/LaunchDaemons/meshagent.old.plist
```

### Diagnostic Commands

**View all meshagent services:**
```bash
# LaunchDaemons
sudo launchctl print system | grep meshagent

# LaunchAgents (current user)
launchctl print gui/$(id -u) | grep meshagent

# All users
sudo launchctl print gui/501 | grep meshagent
```

**Check running processes:**
```bash
# All meshagent processes
ps aux | grep meshagent

# Show full command line
ps auxww | grep meshagent

# Show process tree
pstree -p $(pgrep meshagent)
```

**View logs:**
```bash
# Recent meshagent activity
sudo log show --predicate 'process == "meshagent"' --last 1h

# LaunchAgent activity
log show --predicate 'process == "meshagent" AND subsystem == "com.apple.launchd"' --last 1h

# Error messages only
sudo log show --predicate 'process == "meshagent"' --level error --last 24h
```

---

## Related Documentation

- **[naming-and-configuration.md](./naming-and-configuration.md)** - serviceId calculation, companyName/meshServiceName, configuration priority
- **[installation-functions.md](./installation-functions.md)** - -install, -upgrade, -uninstall functions
- **[TLDReadMe.md](./TLDReadMe.md)** - Quick reference cheat sheet

---

## Code References

### Key Implementation Files

**Agent Installer:**
- `/modules/agent-installer.js:833-867` - createLaunchDaemon/createLaunchAgent functions

**Service Manager:**
- `/modules/service-manager.js:2254-2936` - installService (LaunchDaemon)
- `/modules/service-manager.js:2958-3076` - installLaunchAgent (LaunchAgent)
- `/modules/service-manager.js:3050-3053` - QueueDirectories configuration

**Agent Core:**
- `/meshcore/agentcore.c:6449-6453` - -upgrade invocation during server update

---

*Last Updated: 2025-11-10*
*Documentation Version: 1.0*
