# service-manager.js

Comprehensive cross-platform service management infrastructure providing unified APIs for installing, uninstalling, querying, and controlling system services on Windows (Service Control Manager), Linux (systemd/init/upstart), macOS (launchd), FreeBSD/OpenBSD (rc.d/rcctl), and specialized platforms (pfSense, OPNsense). This is one of the most complex modules in MeshAgent with over 3,500 lines of platform-specific service control code.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via Service Control Manager (SCM) API
- Linux - Full support for multiple init systems:
  - systemd (modern distributions)
  - init/upstart (legacy distributions)
  - OpenRC (Gentoo, Alpine Linux)
  - procd (OpenWrt)
  - Custom mesh_daemons (fallback)
- macOS (darwin) - Full support via launchd (LaunchDaemons and LaunchAgents)
- FreeBSD - Full support via rc.d/service command
- OpenBSD - Full support via rcctl command
- pfSense - Full support via BSD rc.d with pfSense-specific configurations
- OPNsense - Full support via BSD rc.d with OPNsense-specific configurations

**Platform Implementation Status:**

All major platforms are fully supported with native service control integration:

1. **Windows** - Windows Service APIs (Advapi32.dll) for SCM integration
2. **Linux** - Automatic init system detection and appropriate control commands
3. **macOS** - launchd/launchctl with support for both daemons and user agents
4. **BSD Variants** - Native rc.d/rcctl integration with platform detection

**No Exclusions:**
This module has comprehensive cross-platform support for all major operating systems and specialized firewall platforms.

## Functionality

### Purpose

The service-manager module provides a universal service management interface that abstracts platform-specific service control mechanisms behind a consistent API. It enables:

- Service installation with platform-appropriate configuration files
- Service uninstallation with cleanup of binaries and configuration
- Service enumeration and discovery
- Service status querying (running, stopped, PID, etc.)
- Service control operations (start, stop, restart)
- Service configuration management (startup type, failure actions)
- Platform and init system detection
- Administrator/root privilege validation

This module is critical for MeshAgent installation, deployment, and self-management across heterogeneous operating system environments.

### Architecture

The module exports a constructor function `serviceManager()` that creates a service manager instance with platform-specific methods. The singleton instance is also exported as `module.exports.manager` for convenience.

**Platform Detection Flow:**
```
serviceManager() Constructor
  ↓
if (platform == 'win32')
  → Windows SCM Implementation
else
  → Unix-like Implementation
    ↓
    if (platform == 'freebsd')
      → FreeBSD/OpenBSD rc.d
    else if (platform == 'darwin')
      → macOS launchd
    else if (platform == 'linux')
      → Detect: systemd/init/upstart/OpenRC/procd
```

### Key Functions with Line References

#### serviceManager() Constructor - Lines 621-3590

**Purpose:** Creates a service manager instance with platform-specific implementations.

**Windows Implementation (Lines 624-1020):**

Creates native proxies for Windows APIs:
- **Advapi32.dll** (lines 627-642):
  - `OpenSCManagerA` - Opens Service Control Manager
  - `EnumServicesStatusExW` - Enumerates services
  - `OpenServiceW` - Opens specific service
  - `QueryServiceStatusEx` - Queries service status
  - `QueryServiceConfigA` / `QueryServiceConfig2A` - Queries configuration
  - `ControlService` - Sends control codes
  - `StartServiceA` - Starts service
  - `CreateServiceW` - Creates new service
  - `ChangeServiceConfig2W` - Modifies service configuration
  - `DeleteService` - Deletes service
  - `AllocateAndInitializeSid` / `CheckTokenMembership` / `FreeSid` - Admin check

- **Kernel32.dll** (lines 644-645):
  - `GetLastError` - Retrieves error codes

**Unix-like Implementation (Lines 1021-2253):**

Platform-specific service control for Linux, macOS, FreeBSD, OpenBSD.

---

#### isAdmin() / isRoot() - Lines 647-663 (Windows), 1025-1028 (Unix)

**Purpose:** Determines if the current process has administrative/root privileges.

**Windows Implementation (Lines 647-663):**

Uses Security Identifier (SID) checking to determine Administrator group membership:

1. Creates NT Authority SID structure (line 648-649)
2. Initializes Administrators Group SID (BUILTIN\Administrators, RID 544) (line 653)
3. Checks token membership with `CheckTokenMembership()` (line 656)
4. Returns true if current token is member of Administrators group (line 658)
5. Frees SID resources (line 660)

**Process:**
```javascript
// Create NT Authority SID
var NTAuthority = {5, 0, 0, 0, 0, 0}; // SECURITY_NT_AUTHORITY
// RID 544 = DOMAIN_ALIAS_RID_ADMINS (Administrators group)
AllocateAndInitializeSid(NTAuthority, 2, 32, 544, ...)
```

**Unix Implementation (Lines 1025-1028):**

```javascript
return (require('user-sessions').isRoot());
```

Simply checks if effective UID is 0 (root).

---

#### getService(name, [platformType]) - Lines 714-1019 (Windows), 1066-2112 (BSD/Linux), fetchPlist() 234-398 (macOS)

**Purpose:** Retrieves a service object with methods for querying and controlling a specific service.

**Windows Implementation (Lines 714-1019):**

**Process:**

1. **Open Service Control Manager** (line 721)
   - Flags: `SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CREATE_SERVICE`
   - Additional `SC_MANAGER_MODIFY_BOOT_CONFIG` if admin

2. **Open Service Handle** (line 723)
   - Opens service with name (converted to wide-character)
   - Flags: `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG` + admin-only flags

3. **Create Service Object** (lines 726-1010)
   - Stores handles: `_scm`, `_service`
   - Stores proxies: `_GM`, `_proxy`, `_proxy2`

**Service Object Properties (Windows):**

**status** (Lines 734-750) - Getter property:
- Queries current service status via `QueryServiceStatusEx()`
- Returns parsed SERVICE_STATUS structure with:
  - `state` - STOPPED, START_PENDING, RUNNING, STOP_PENDING, etc.
  - `pid` - Process ID
  - `isSharedProcess`, `isOwnProcess`, `isInteractive` - Service type flags
  - `controlsAccepted` - Array of accepted control codes
  - `waitHint` - Estimated operation completion time

**installedBy** (Lines 751-764) - Getter property:
- Reads registry key: `HKLM\SYSTEM\CurrentControlSet\Services\<name>\_InstalledBy`
- Returns installer identifier (e.g., "MeshAgent")

**installedDate** (Lines 766-775):
- Queries registry key last modified time for service ImagePath
- Returns Date object

**Methods:**

**close()** (Lines 779-787):
- Closes service and SCM handles
- Prevents handle leaks

**isMe()** (Lines 789-792):
- Compares service PID with current process.pid
- Returns true if this process is the service

**update()** (Lines 793-813):
- Updates service failure actions
- Uses `ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)`
- Configures up to 3 failure actions with delays
- Actions: NONE, SERVICE_RESTART, REBOOT

**appLocation()** (Lines 814-822):
- Reads ImagePath from registry
- Extracts executable path (up to ".exe")
- Strips quotes if present

**appWorkingDirectory()** (Lines 823-830):
- Extracts directory from appLocation()
- Returns folder containing service executable

**start()** (Lines 831-839):
- Calls `StartServiceA()` with no parameters
- Throws exception if start fails with error code

**stop()** (Lines 840-848):
- Sends `SERVICE_CONTROL_STOP` via `ControlService()`
- Throws exception if stop fails

**restart()** (Lines 849-859):
- Special handling if service is current process (`isMe()`)
  - Extracts command-line parameters
  - Uses `_execve()` to replace current process
- Otherwise: Stops then starts service

**description()** (Lines 860-876):
- Queries `SERVICE_CONFIG_DESCRIPTION` via `QueryServiceConfig2A()`
- Returns service description string

**parameters()** (Lines 877-903):
- Parses ImagePath to extract command-line parameters
- Handles quoted and unquoted paths
- Returns array of parameter strings

**failureActions** (Lines 904-1010) - Getter property:
- Queries `SERVICE_CONFIG_FAILURE_ACTIONS`
- Parses SERVICE_FAILURE_ACTIONS structure:
  - `resetPeriod` - Failure count reset time (seconds)
  - `actions` - Array of up to 3 actions:
    - `type` - NONE, SERVICE_RESTART, REBOOT, OTHER
    - `delay` - Delay before action (milliseconds)
- Returns object with resetPeriod and actions array

---

**FreeBSD/OpenBSD Implementation (Lines 1066-1299):**

**Platform Detection:**
- **OpenBSD**: Checks for absence of `/usr/sbin/daemon` (line 1069)
- **pfSense**: Checks for `/etc/pfSense-rc` or `/etc/platform` containing "pfSense" (lines 1053)
- **OPNsense**: Runs `opnsense-version` command (lines 1037-1042)

**Service Location:**
- Searches `/etc/rc.d/<name>` (line 1071)
- Searches `/usr/local/etc/rc.d/<name>` (line 1075)
- Throws exception if not found (line 1081)

**Service Object Properties (FreeBSD/OpenBSD):**

**startType** (Lines 1083-1108) - Getter property:

FreeBSD:
```bash
service <name> rcvar | grep _enable= | awk '{ split($0, b, "\""); if(b[2]=="YES") print "YES"; }'
```
- Returns `AUTO_START` if enabled, `DEMAND_START` if disabled

OpenBSD:
```bash
rcctl ls on | awk '{ if($0=="<name>") print "AUTO_START"; }'
```

**description()** (Lines 1110-1117):
- Parses rc.d script for `desc=` variable
- Extracts description string from quotes

**appWorkingDirectory()** (Lines 1118-1132):
- Parses `<name>_chdir=` variable from rc.d script
- Returns working directory path with trailing slash

**appLocation()** (Lines 1141-1185):
- Parses `command=` variable from rc.d script
- Handles `/usr/sbin/daemon` wrapper (FreeBSD):
  - Extracts actual binary path from `command_args=` `-f` flag
- Handles `${name}` variable substitution
- Returns executable path

**isRunning()** (Lines 1186-1203):

OpenBSD:
```bash
rcctl ls started | awk '{ if($0=="<name>") print "STARTED"; }'
```

FreeBSD:
```bash
service <name> onestatus | awk '{ print $3 }'
```
- Returns true if "running", false otherwise

**pid()** (Lines 1204-1234):

OpenBSD:
- Reads `/var/run/<name>.pid`
- Returns PID as integer

FreeBSD:
- Runs `service <name> onestatus` to get PID
- Executes `ps -p <pid>` to verify process exists
- Handles daemon wrapper by extracting actual PID from brackets

**isMe()** (Lines 1236-1239):
- Compares `pid()` with `process.pid`

**stop()** (Lines 1240-1256):

OpenBSD: `rcctl stop <name>`
FreeBSD: `service <name> onestop`

**start()** (Lines 1257-1273):

OpenBSD: `rcctl start <name>`
FreeBSD: `service <name> onestart`

**restart()** (Lines 1274-1299):
- If `isMe()`: Uses `_execve()` to replace process
- Otherwise:
  - OpenBSD: `rcctl restart <name>`
  - FreeBSD: `service <name> onerestart`

---

**Linux Implementation (Lines 1301-2112):**

Linux support is highly complex due to multiple init systems. The implementation auto-detects the service type.

**Service Type Detection** (lines 1316-1371):

1. **systemd**: Checks for `/etc/systemd` or `/run/systemd/system` (line 1321-1329)
2. **upstart**: Checks for `/etc/init` and upstart binary (line 1330-1346)
3. **init**: Checks for `/etc/init.d` (line 1348-1353)
4. **OpenRC**: Checks for `/sbin/openrc-run` or `/usr/sbin/openrc-run` (line 1355-1366)
5. **procd**: Checks for `/sbin/procd` (line 1367-1370)
6. **unknown**: Falls back to custom mesh_daemons (line 1374)

**systemd Implementation (Lines 1376-1608):**

**Service File Locations:**
- `/lib/systemd/system/<name>.service`
- `/usr/lib/systemd/system/<name>.service`

**Service Object Properties:**

**startType** (Lines 1393-1430):
```bash
systemctl is-enabled <name>.service
```
- Returns `AUTO_START` if enabled, `DEMAND_START` if disabled

**description()** (Lines 1431-1447):
- Parses `Description=` from service file

**stop()** (Lines 1448-1457):
- If `isMe()`: Uses `_execve()` to replace process
- Otherwise: `systemctl stop <name>.service`

**start()** (Lines 1458-1466):
```bash
systemctl start <name>.service
```

**restart()** (Lines 1467-1482):
- If `isMe()`: `_execve()`
- Otherwise: `systemctl restart <name>.service`

**isRunning()** (Lines 1483-1497):
```bash
systemctl is-active <name>.service
```
- Returns true if "active"

**pid()** (Lines 1498-1515):
```bash
systemctl show -p MainPID <name>.service | awk -F= '{ print $2 }'
```

**isMe()** (Lines 1516-1519):
- Compares `pid()` with `process.pid`

**appWorkingDirectory()** (Lines 1520-1534):
- Parses `WorkingDirectory=` from service file

**appLocation()** (Lines 1535-1569):
- Parses `ExecStart=` from service file
- Extracts binary path (first token)

**parameters()** (Lines 1570-1608):
- Parses `ExecStart=` for parameters
- Returns array of arguments

---

**init/upstart Implementation (Lines 1609-1826):**

**Service File Locations:**
- init.d: `/etc/init.d/<name>`
- upstart: `/etc/init/<name>.conf`

**Similar methods as systemd but using:**
- `service <name> start|stop|status`
- `update-rc.d` for enabling/disabling

---

**OpenRC Implementation (Lines 1827-1886):**

**Service Control:**
- Uses `rc-service <name> start|stop|restart`
- Uses `rc-update add/del <name>` for enabling/disabling

---

**procd Implementation (OpenWrt) (Lines 1887-1938):**

**Service Control:**
- `/etc/init.d/<name> start|stop|restart|enable|disable`

---

**mesh_daemons Implementation (Custom fallback) (Lines 1939-2096):**

For systems without standard init, creates custom daemon infrastructure:

**Service Directory:** `/usr/local/mesh_daemons/<name>/`

**Configuration File:** `<name>.service` - Custom format with:
- `name=`
- `description=`
- `executablePath=`
- `workingDirectory=`
- `parameters=`

**PID File:** `<name>/pid`

**Control:**
- Start: Executes binary and writes PID
- Stop: Reads PID and sends SIGTERM
- Status: Checks if PID exists and process is running

---

**macOS Implementation (fetchPlist) (Lines 234-398):**

**Purpose:** Retrieves LaunchDaemon or LaunchAgent plist information.

**Parameters:**
- `folder` - `/Library/LaunchDaemons` or `/Library/LaunchAgents` or user agents
- `name` - Service name (without .plist extension)
- `userid` - For user-specific LaunchAgents (optional)

**Service Location:**
1. Checks for `<folder>/<name>.plist` (line 238)
2. If not found, enumerates all plists and parses Label key to find match (lines 241-257)

**Service Object Properties:**

**alias** (Lines 263-274) - Getter property:
- Parses plist XML to extract `<key>Label</key>` value
- Returns service label string

**daemon** (Line 276):
- Boolean: true if in LaunchDaemons, false if LaunchAgents

**installedDate** (Lines 278-283):
- Returns plist file creation time

**appWorkingDirectory()** (Lines 284-294):
- Parses `<key>WorkingDirectory</key>` from plist
- Returns path with trailing slash

**appLocation()** (Lines 295-303):
- Parses `<key>ProgramArguments</key>` array
- Returns first `<string>` element (executable path)

**_runAtLoad** (Lines 304-316) - Getter property:
- Parses `<key>RunAtLoad</key>` boolean value
- Returns true if `<true/>`, false otherwise

**startType** (Lines 317-330) - Getter property:
- LaunchDaemons: `AUTO_START` if `_runAtLoad`, else `DEMAND_START`
- LaunchAgents: Always `AUTO_START`

**_keepAlive** (Lines 331-344) - Getter property:
- Parses `<key>KeepAlive</key>` value
- Returns "ALWAYS" or specific condition key name

**getPID(uid, asString)** (Lines 345-382):
- macOS < 10.10: `launchctl list | grep '<alias>'`
- macOS >= 10.10: `launchctl print system|gui/<uid> | grep '<alias>'`
- Returns PID as integer (or string if asString is true)

**isLoaded(uid)** (Lines 383-387):
- Checks if service appears in launchctl list
- Returns true if getPID returns non-empty string

**isRunning(uid)** (Lines 388-392):
- Checks if getPID returns valid integer > 0

**isMe(uid)** (Lines 393-397):
- Compares getPID with process.pid

**load(uid)** (Lines 398-440):
- macOS < 10.10: `launchctl load <plist>`
- macOS >= 10.10: `launchctl bootstrap system|gui/<uid> <plist>`
- LaunchDaemons: Use `system` domain
- LaunchAgents: Use `gui/<uid>` domain

**unload(uid)** (Lines 441-523):
- macOS <= 10.10: `launchctl unload <plist>`
- macOS > 10.10: `launchctl bootout system|gui/<uid> <plist>`
- Handles privilege requirements and context switching

**start(uid)** (Lines 524-567):
- If `_runAtLoad` is true: Calls `load()`
- Otherwise: `launchctl start <alias>`

**stop(uid)** (Lines 568-593):
- If `_keepAlive`: Must `unload()` to stop
- Otherwise: `launchctl stop <alias>`

**restart(uid)** (Lines 594-618):
- If `isMe()`: Uses `_execve()` to replace process
- Otherwise: `stop()` then `start()`

---

#### enumerateService([options]) - Lines 680-713 (Windows), 2114-2252 (Unix)

**Purpose:** Enumerates all services on the system.

**Windows Implementation (Lines 680-713):**

1. Opens SCM with `OpenSCManagerA()`
2. Calls `EnumServicesStatusExW()` twice:
   - First call: Determines buffer size needed
   - Second call: Retrieves actual service data
3. Parses ENUM_SERVICE_STATUS_PROCESS structures:
   - Each entry is 36 bytes + 2 pointers + padding
   - Contains service name, display name, and status
4. Returns array of objects:
   - `name` - Internal service name
   - `displayName` - User-friendly name
   - `status` - Parsed status object (from parseServiceStatus)

**Unix Implementation (Lines 2114-2252):**

**Search Paths by Platform:**

**Linux systemd:**
- `/lib/systemd/system`
- `/usr/lib/systemd/system`
- Filters: `*.service` files

**Linux init:**
- `/etc/init.d`
- All files are potential services

**Linux upstart:**
- `/etc/init`
- Filters: `*.conf` files

**FreeBSD/OpenBSD:**
- `/etc/rc.d`
- `/usr/local/etc/rc.d`

**macOS:**
- `/Library/LaunchDaemons`
- `/System/Library/LaunchDaemons`
- Filters: `*.plist` files

**Process:**
1. Enumerates files in search paths
2. Attempts `getService()` for each file
3. Catches exceptions (invalid service files)
4. For systemd/upstart: Augments with running service table
5. Populates `state` and `pid` properties where available
6. Returns array of service objects

---

#### installService(options) - Lines 2254-3076

**Purpose:** Installs a service with platform-specific configuration.

**Common Options:**
- `name` - Service name (required)
- `displayName` - User-friendly name
- `description` - Service description
- `servicePath` - Path to executable (required)
- `parameters` - Array of command-line arguments
- `startType` - `AUTO_START` or `DEMAND_START`
- `installPath` - Installation directory (optional)
- `installInPlace` - Install without copying binary
- `companyName` - Company/organization name
- `failureActions` - Windows failure recovery actions

**Platform-Specific Sanitization:**

**macOS (Lines 2258-2267):**
- Sanitizes `companyName` and `name`:
  - Replaces spaces with hyphens
  - Removes non-alphanumeric (except hyphens and underscores)
  - Follows reverse DNS naming convention

**Linux (Line 2269):**
- Escapes service name for systemd (if using systemd)

**Installation Process:**

**Windows (Lines 2300-2653):**

1. **Binary Handling** (Lines 2306-2366):
   - If `installInPlace`: Use existing binary location
   - Otherwise:
     - Determine install path (default: `Program Files\<company>\<name>`)
     - Create directories if needed
     - Copy binary to install path
     - Copy additional files if specified

2. **Create Service** (Lines 2368-2377):
   - Calls `CreateServiceW()` with:
     - Service name
     - Display name
     - Service type: `SERVICE_WIN32_OWN_PROCESS`
     - Start type: `SERVICE_AUTO_START` or `SERVICE_DEMAND_START`
     - Error control: `SERVICE_ERROR_NORMAL`
     - Binary path with parameters
     - Dependencies (optional)
     - Account (default: LocalSystem)

3. **Set Description** (Lines 2379-2386):
   - Uses `ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION)`

4. **Configure Failure Actions** (Lines 2390-2445):
   - Defaults to 3 restart actions with 60-second delay
   - Configurable via `options.failureActions`
   - Uses `ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)`

5. **Registry Configuration** (Lines 2447-2653):
   - Creates uninstall registry entry:
     - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<name>`
   - Stores:
     - DisplayName
     - DisplayIcon
     - UninstallString
     - Publisher
     - InstallDate
     - EstimatedSize
     - _InstalledBy (marker)

---

**Linux systemd (Lines 2654-2798):**

1. **Binary Installation** (Lines 2666-2686):
   - Creates install directory if needed
   - Copies binary to install path
   - Sets executable permissions (chmod +x)
   - Copies additional files

2. **Create Unit File** (Lines 2688-2749):

**systemd Service File Template:**
```ini
[Unit]
Description=<description>
After=network.target

[Service]
Type=simple
ExecStart=<servicePath> <parameters>
WorkingDirectory=<workingDirectory>
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. **Write Unit File** (Lines 2751-2753):
   - Path: `/lib/systemd/system/<name>.service` or `/usr/lib/systemd/system/<name>.service`

4. **Enable and Reload** (Lines 2755-2773):
   - If `AUTO_START`: `systemctl enable <name>.service`
   - `systemctl daemon-reload` to reload systemd configuration

---

**Linux init (Lines 2799-2877):**

1. **Binary Installation:** Similar to systemd

2. **Create init.d Script** (Lines 2820-2855):

**init.d Script Template:**
```bash
#!/bin/sh
### BEGIN INIT INFO
# Provides: <name>
# Required-Start: $network
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Description: <description>
### END INIT INFO

start() {
    <servicePath> <parameters> &
}

stop() {
    killall <name>
}

case "$1" in
    start|stop|restart)
        $1
        ;;
esac
```

3. **Install Script** (Lines 2857-2877):
   - Writes to `/etc/init.d/<name>`
   - Sets executable: `chmod +x /etc/init.d/<name>`
   - If `AUTO_START`: `update-rc.d <name> defaults`

---

**Linux upstart (Lines 2878-2925):**

**upstart Configuration File:**
```conf
description "<description>"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

exec <servicePath> <parameters>
```

- Writes to `/etc/init/<name>.conf`

---

**macOS launchd (Lines 2968-3076):**

1. **Service ID Generation** (Lines 2985-3004):
   - With company: `com.<company>.<name>-agent`
   - Without company: `meshagent.<name>-agent` or `meshagent`
   - Sanitizes to follow reverse DNS convention

2. **Create plist File** (Lines 3025-3056):

**LaunchDaemon/LaunchAgent plist Template:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Disabled</key>
    <false/>
    <key>Label</key>
    <string><serviceId>-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string><servicePath></string>
      <string><parameter1></string>
      ...
    </array>
    <key>WorkingDirectory</key>
    <string><workingDirectory></string>
    <key>StandardOutPath</key>
    <string>/tmp/<serviceId>-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/<serviceId>-agent.log</string>
    <key>KeepAlive</key>
    <false/>
    <key>QueueDirectories</key>
    <array>
      <string>/var/run/<serviceId></string>
    </array>
  </dict>
</plist>
```

3. **Determine plist Location** (Lines 3058-3074):
   - System daemon: `/Library/LaunchDaemons/<serviceId>-agent.plist`
   - User agent: `~/Library/LaunchAgents/<serviceId>-agent.plist`
   - Creates directory if needed
   - Sets ownership for user agents: `chown <uid>:<gid>`

---

**FreeBSD/OpenBSD (Lines 2926-2967):**

Similar to Linux init.d but uses BSD rc.d format.

**rc.d Script Template:**
```bash
#!/bin/sh
#
# PROVIDE: <name>
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="<name>"
rcvar="${name}_enable"
command="<servicePath>"
command_args="<parameters>"
pidfile="/var/run/${name}.pid"

load_rc_config $name
run_rc_command "$1"
```

---

#### uninstallService(name, [options]) - Lines 3077-3314

**Purpose:** Uninstalls a service and optionally removes binaries.

**Options:**
- `skipDeleteBinary` - If true, leaves service binary in place

**Common Process:**

1. **Privilege Check** (line 3079):
   - Throws exception if not admin/root

2. **Retrieve Service Info** (lines 3082-3084):
   - Gets service object
   - Extracts `appLocation()` and `appWorkingDirectory()`

3. **Platform-Specific Uninstallation:**

**Windows (Lines 3086-3114):**
1. Delete binary file (unless `skipDeleteBinary`)
   - If file locked, schedules deletion on reboot via cmd.exe
2. Call `DeleteService()` API
3. Close service handles
4. Delete uninstall registry key

**Linux systemd (Lines 3199-3223):**
1. Stop service: `systemctl stop <name>.service`
2. Disable service: `systemctl disable <name>.service`
3. Delete binary (unless `skipDeleteBinary`)
4. Delete unit files from `/lib/systemd/system` and `/usr/lib/systemd/system`
5. Handle escaped service names

**Linux init/upstart (Lines 3143-3198):**
1. Stop service: `service <name> stop`
2. Remove from startup:
   - OpenRC: `rc-update del <name> default`
   - SysV init: `update-rc.d -f <name> remove`
3. Delete `/etc/init.d/<name>` or `/etc/init/<name>.conf`
4. Delete binary (unless `skipDeleteBinary`)

**macOS (Lines 3250-3273):**
1. Unload service via `service.unload()`
2. Delete plist file
3. Delete binary (unless `skipDeleteBinary`)
4. Remove working directory

**FreeBSD/OpenBSD (Lines 3274-3313):**
1. Stop service
2. Delete binary (unless `skipDeleteBinary`)
3. OpenBSD: Disable via `rcctl disable <name>`
4. pfSense: Remove from config.xml
5. Delete rc.d script

---

### Helper Functions

#### parseServiceStatus(token) - Lines 73-127

**Purpose:** Parses Windows SERVICE_STATUS_EX structure into JavaScript object.

**Structure:**
```c
typedef struct _SERVICE_STATUS_PROCESS {
    DWORD dwServiceType;           // Offset 0
    DWORD dwCurrentState;          // Offset 4
    DWORD dwControlsAccepted;      // Offset 8
    DWORD dwWin32ExitCode;         // Offset 12
    DWORD dwServiceSpecificExitCode; // Offset 16
    DWORD dwCheckPoint;            // Offset 20
    DWORD dwWaitHint;              // Offset 24
    DWORD dwProcessId;             // Offset 28
    DWORD dwServiceFlags;          // Offset 32
} SERVICE_STATUS_PROCESS;
```

**Returns Object:**
- `isFileSystemDriver`, `isKernelDriver`, `isSharedProcess`, `isOwnProcess`, `isInteractive` - Service type flags
- `state` - String: "STOPPED", "START_PENDING", "RUNNING", etc.
- `rawState` - Numeric state code
- `controlsAccepted` - Array of strings: "SERVICE_CONTROL_STOP", etc.
- `pid` - Process ID
- `waitHint` - Milliseconds hint for operations

---

#### failureActionToInteger(action) - Lines 19-36

**Purpose:** Converts failure action string to Windows API integer.

**Mapping:**
- `"NONE"` → 0 (SC_ACTION_NONE)
- `"SERVICE_RESTART"` → 1 (SC_ACTION_RESTART)
- `"REBOOT"` → 2 (SC_ACTION_REBOOT)

---

#### extractFileName(filePath) / extractFileSource(filePath) - Lines 38-56

**Purpose:** Helper functions for extracting file names and sources from file path specifications.

Used during service installation when copying files.

---

#### prepareFolders(folderPath) - Lines 58-71

**Purpose:** Recursively creates directory structure.

**Process:**
- Splits path by platform delimiter (`\` or `/`)
- Creates each directory level if it doesn't exist
- Uses `fs.mkdirSync()`

---

#### getServiceType() / getOSVersion() (Linux/macOS specific)

**Purpose:** Detects init system on Linux or OS version on macOS.

**Linux Detection Logic:**
1. Checks for `/etc/systemd` or `/run/systemd/system` → `"systemd"`
2. Checks for `/etc/init` and upstart binary → `"upstart"`
3. Checks for `/etc/init.d` → `"init"`
4. Checks for `/sbin/openrc-run` → `"OpenRC"`
5. Checks for `/sbin/procd` → `"procd"`
6. Default → `"unknown"`

**macOS Version Detection:**
- Runs `sw_vers | grep ProductVersion`
- Parses version string (e.g., "10.15.7")
- Returns object with `compareTo()` method for version comparison

---

#### escape() / unescape() (systemd-specific)

**Purpose:** Escapes/unescapes service names for systemd.

systemd service names with special characters must be escaped:
- `meshagent service` → `meshagent\x20service`

Uses `systemd-escape` command if available.

---

### Usage Examples

#### Example 1: Install Service

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

var options = {
    name: 'MyBackgroundService',
    displayName: 'My Background Service',
    description: 'Performs background tasks',
    servicePath: '/opt/myapp/service',
    parameters: ['--background'],
    startType: 'AUTO_START',
    installPath: '/opt/myapp',
    companyName: 'MyCompany'
};

try {
    manager.installService(options);
    console.log('Service installed successfully');
} catch (e) {
    console.log('Installation failed:', e);
}
```

#### Example 2: Query Service Status

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

try {
    var service = manager.getService('MyBackgroundService');

    console.log('Service Name:', service.name);
    console.log('Running:', service.isRunning());
    console.log('PID:', service.pid ? service.pid() : 'N/A');
    console.log('Location:', service.appLocation());
    console.log('Working Directory:', service.appWorkingDirectory());

    if (process.platform == 'win32') {
        console.log('Status:', service.status.state);
        console.log('Description:', service.description());
    }

    service.close();
} catch (e) {
    console.log('Service not found:', e);
}
```

#### Example 3: Control Service

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

var service = manager.getService('MyBackgroundService');

// Start service
if (!service.isRunning()) {
    console.log('Starting service...');
    service.start();
}

// Stop service
if (service.isRunning()) {
    console.log('Stopping service...');
    service.stop();
}

// Restart service
console.log('Restarting service...');
service.restart();

service.close();
```

#### Example 4: Enumerate All Services

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

var services = manager.enumerateService();

console.log('Found ' + services.length + ' services:');

for (var i in services) {
    var svc = services[i];
    console.log('  ' + svc.name);

    if (svc.description) {
        console.log('    Description: ' + svc.description);
    }

    if (svc.state) {
        console.log('    State: ' + svc.state);
    }
}
```

#### Example 5: Uninstall Service

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

try {
    // Uninstall and remove binary
    manager.uninstallService('MyBackgroundService');
    console.log('Service uninstalled');
} catch (e) {
    console.log('Uninstall failed:', e);
}

// Uninstall but keep binary
try {
    manager.uninstallService('MyBackgroundService', { skipDeleteBinary: true });
    console.log('Service uninstalled (binary preserved)');
} catch (e) {
    console.log('Uninstall failed:', e);
}
```

#### Example 6: Check if Current Process is a Service

```javascript
var serviceManager = require('service-manager');
var manager = new serviceManager();

try {
    var service = manager.getService('MyBackgroundService');

    if (service.isMe()) {
        console.log('This process IS the service');
    } else {
        console.log('This process is NOT the service');
    }

    service.close();
} catch (e) {
    console.log('Service not found');
}
```

---

### Dependencies

#### Node.js Core Modules

- **`child_process`** (Throughout)
  - Methods: `execFile()`, `_execve()`
  - Used for executing shell commands on Unix-like systems
  - Used for process replacement during service restart

- **`fs`** (Throughout)
  - Methods: `readFileSync()`, `writeFileSync()`, `existsSync()`, `unlinkSync()`, `mkdirSync()`, `statSync()`, `readdirSync()`, `chownSync()`
  - File and directory operations for service configuration

#### MeshAgent Module Dependencies

- **`promise`** (line 16)
  - Custom promise implementation for async operations
  - Used in some service operations

- **`_GenericMarshal`** (line 626) - Windows only
  - Native FFI for calling Windows DLLs
  - Methods: `CreateNativeProxy()`, `CreateVariable()`, `CreatePointer()`, `CreateInteger()`

- **`user-sessions`** (lines 94, 95, 1027, 3060, 3064)
  - Methods:
    - `getUsername(uid)` - UID to username
    - `getGroupname(gid)` - GID to group name
    - `isRoot()` - Check if root
    - `Self()` - Get current UID
    - `getHomeFolder(user)` - Get user home directory
    - `getGroupID(uid)` - Get primary group ID

- **`win-registry`** (lines 755, 816, 3109) - Windows only
  - Registry operations
  - Methods: `QueryKey()`, `CreateKey()`, `WriteKey()`, `DeleteKey()`, `QueryKeyLastModified()`

- **`process-manager`** (line 255)
  - Method: `getProcessInfo(1).Name` - Detects init system by PID 1 process name

#### Platform Binary Dependencies

**Windows:**
- None (uses native APIs)

**Linux:**
- **systemctl** - systemd control (systemd systems)
- **service** - SysV init control (init/upstart systems)
- **update-rc.d** - SysV init startup management
- **rc-update** - OpenRC startup management
- **awk** - Text processing for parsing command output
- **/bin/sh** - Shell for command execution
- **ps** - Process listing

**macOS:**
- **launchctl** - launchd control
- **sw_vers** - OS version detection
- **/bin/sh** - Shell
- **awk** - Text processing

**FreeBSD/OpenBSD:**
- **service** - FreeBSD service control
- **rcctl** - OpenBSD service control
- **awk** - Text processing
- **ps** - Process listing
- **/bin/sh** - Shell

---

## Code Structure

The module is organized into major platform sections:

1. **Lines 1-17:** Module imports and globals

2. **Lines 19-127:** Helper functions
   - failureActionToInteger()
   - extractFileName() / extractFileSource()
   - prepareFolders()
   - parseServiceStatus()

3. **Lines 129-194:** Linux init system detection helpers
   - _upstart_GetServiceTable()
   - _systemd_GetServiceTable()

4. **Lines 202-619:** macOS-specific functions
   - getOSVersion()
   - fetchPlist() - LaunchDaemon/LaunchAgent management

5. **Lines 621-1020:** Windows implementation
   - Native API proxies
   - isAdmin()
   - enumerateService()
   - getService()

6. **Lines 1021-2253:** Unix-like implementations
   - isAdmin()
   - FreeBSD/OpenBSD getService()
   - Linux getService() with multi-init support
   - enumerateService()

7. **Lines 2254-3076:** installService()
   - Windows installation
   - Linux systemd/init/upstart installation
   - macOS launchd installation
   - FreeBSD/OpenBSD installation

8. **Lines 3077-3314:** uninstallService()
   - Platform-specific uninstallation
   - Binary removal
   - Configuration cleanup

9. **Lines 3590-3591:** Module exports

---

## Technical Notes

### Windows SERVICE_STATUS State Machine

```
STOPPED (0x00000001)
    ↓
START_PENDING (0x00000002)
    ↓
RUNNING (0x00000004) ← Normal operation
    ↓
STOP_PENDING (0x00000003) or PAUSE_PENDING (0x00000006)
    ↓
PAUSED (0x00000007) or STOPPED (0x00000001)
```

### Windows Failure Actions

Configured via SERVICE_FAILURE_ACTIONS structure:
- `dwResetPeriod` - Seconds before failure count resets
- `lpRebootMsg` - Message displayed before reboot (optional)
- `lpCommand` - Command to execute (optional)
- `cActions` - Number of actions (max 3)
- `lpsaActions` - Array of SC_ACTION structures:
  - `Type` - SC_ACTION_NONE, SC_ACTION_RESTART, SC_ACTION_REBOOT, SC_ACTION_RUN_COMMAND
  - `Delay` - Milliseconds to wait before action

### Linux systemd Unit File Sections

**[Unit]** - Metadata and dependencies
- Description, Documentation, After, Before, Requires, Wants

**[Service]** - Service configuration
- Type: simple, forking, oneshot, notify, dbus
- ExecStart, ExecStop, ExecReload
- WorkingDirectory, User, Group
- Restart: no, on-success, on-failure, always
- RestartSec

**[Install]** - Installation configuration
- WantedBy: multi-user.target, graphical.target
- RequiredBy, Alias

### macOS launchd Versioning

The module handles two launchctl command syntaxes:

**Legacy (macOS < 10.10):**
- `launchctl load <plist>`
- `launchctl unload <plist>`
- `launchctl list`

**Modern (macOS >= 10.10):**
- `launchctl bootstrap system|gui/<uid> <plist>`
- `launchctl bootout system|gui/<uid> <plist>`
- `launchctl print system|gui/<uid>`

### Service Name Escaping

**systemd:**
Special characters in service names must be escaped:
- Space → `\x20`
- Slash → `\x2f`
- Backslash → `\x5c`

Uses `systemd-escape` command when available.

**macOS:**
Service identifiers must follow reverse DNS convention:
- Valid: `com.company.service-name`
- Invalid: `My Service #1!`

### Process Replacement with _execve()

When restarting a service that is the current process, the module uses `_execve()` to replace the process image rather than stopping and starting:

```javascript
var parameters = service.parameters();
parameters.unshift(process.execPath);
require('child_process')._execve(process.execPath, parameters);
```

This preserves the process PID and avoids issues with PID tracking.

---

## Platform-Specific Analysis

### Windows (win32)

**What Works:**
- Full SCM integration via native APIs
- Service enumeration with detailed status
- Service installation with custom configuration
- Failure action configuration (restart, reboot)
- Registry-based uninstall tracking
- Administrator privilege detection via SID checking

**Implementation Details:**
- Uses Advapi32.dll for all SCM operations
- Handles 32-bit and 64-bit Windows
- Supports wide-character strings (Unicode)
- Proper handle management with cleanup

**Limitations:**
- Requires Administrator privileges for most operations
- Service names must be unique in SCM database

**Windows Versions:**
- Windows 7+
- Windows Server 2008 R2+

---

### Linux

**What Works:**
- Multi-init system support (systemd, init, upstart, OpenRC, procd)
- Automatic init system detection
- Service installation with appropriate unit files
- Service enumeration and control
- Root privilege detection

**Implementation Details:**
- Shell command execution for service control
- Text parsing of command output (awk, grep)
- systemd service name escaping
- Supports custom mesh_daemons fallback

**Limitations:**
- Requires root privileges for installation/uninstallation
- Shell command parsing may vary across distributions
- systemd unit file syntax is simplified (not all features)

**Supported Distributions:**
- **systemd**: Ubuntu 16.04+, Debian 8+, CentOS 7+, Fedora 15+, Arch Linux
- **init/upstart**: Ubuntu 14.04, Debian 7, CentOS 6
- **OpenRC**: Gentoo, Alpine Linux
- **procd**: OpenWrt

---

### macOS (darwin)

**What Works:**
- LaunchDaemon and LaunchAgent support
- OS version detection (10.9+)
- Legacy and modern launchctl syntax
- User-specific and system-wide services
- plist parsing and generation

**Implementation Details:**
- Detects macOS version to use appropriate launchctl syntax
- Handles both system daemons and user agents
- Properly manages file ownership for user agents
- Supports QueueDirectories for automatic launching

**Limitations:**
- Service names must follow reverse DNS convention
- User agents require user context
- Complex privilege management for cross-user operations

**Supported Versions:**
- macOS 10.9+ (Mavericks and later)
- Tested up to macOS 14+ (Sonoma)

---

### FreeBSD/OpenBSD

**What Works:**
- rc.d script management
- FreeBSD service command support
- OpenBSD rcctl support
- pfSense and OPNsense detection and integration
- PID file tracking

**Implementation Details:**
- Platform detection (FreeBSD vs OpenBSD)
- Specialized handling for firewall distributions
- rc.d script generation with proper PROVIDE/REQUIRE directives
- daemon wrapper support (FreeBSD)

**Limitations:**
- Requires root privileges
- Shell command parsing for status detection
- pfSense requires XML configuration file manipulation

**Supported Versions:**
- FreeBSD 11+
- OpenBSD 6+
- pfSense 2.4+
- OPNsense 20+

---

### Cross-Platform Consistency

**Unified API:**
All platforms expose the same service object methods:
- `isRunning()` - Check if service is running
- `start()` - Start service
- `stop()` - Stop service
- `restart()` - Restart service
- `isMe()` - Check if current process
- `appLocation()` - Get executable path
- `appWorkingDirectory()` - Get working directory

**Platform Differences:**
- Windows has additional properties: `status`, `failureActions`, `installedBy`, `installedDate`
- macOS has additional properties: `alias`, `daemon`, `_runAtLoad`, `_keepAlive`
- Linux/BSD have platform-specific properties based on init system

**Service Installation:**
- Windows: Binary copied to Program Files, registry entry created
- Linux: Binary copied to /usr/local/mesh_services, unit file created
- macOS: Binary installed in place, plist created in LaunchDaemons/LaunchAgents
- BSD: Binary copied, rc.d script created

---

## Summary

The service-manager.js module is an extremely comprehensive service management library providing unified APIs for installing, uninstalling, querying, and controlling system services across all major operating systems and multiple init systems. With over 3,500 lines of code, it handles the complexities of platform-specific service control mechanisms while exposing a consistent interface.

**Key Capabilities:**
- Universal service installation with platform-appropriate configuration
- Service enumeration and discovery
- Service status monitoring and control
- Administrator/root privilege checking
- Multi-init system support on Linux
- Legacy and modern API support on macOS
- Specialized support for firewall distributions (pfSense, OPNsense)

**Platform Support:**
- **Windows:** Full SCM integration with native APIs
- **Linux:** systemd, init, upstart, OpenRC, procd support
- **macOS:** launchd with version-appropriate commands
- **FreeBSD/OpenBSD:** rc.d/rcctl with firewall distribution support

The module is production-ready and serves as the foundation for MeshAgent service deployment across heterogeneous environments. It properly handles edge cases, privilege requirements, and platform-specific quirks, making it suitable for enterprise-scale deployments requiring robust service management across diverse operating systems.

**Typical Use Cases in MeshAgent:**
- Installing the MeshAgent as a system service during setup
- Uninstalling the agent with cleanup of all artifacts
- Querying agent service status for diagnostics
- Restarting the agent service for updates or configuration changes
- Enumerating system services for security auditing
