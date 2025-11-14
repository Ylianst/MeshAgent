# user-sessions.js

Comprehensive cross-platform user session management module providing real-time session enumeration, lock/unlock detection, user identification, and session state tracking across Windows, Linux, FreeBSD, and macOS. Implements platform-specific session monitoring with event notifications for login, logout, lock, and unlock events.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via WTS APIs, registry, and message pumps
- Linux - Full support via loginctl, who, /proc, and /var/run/utmp
- FreeBSD - Full support via who and procstat
- macOS (darwin) - Full support via dscl, who, and last commands

## Functionality

### Purpose

The user-sessions module provides comprehensive user session management:

- **Session Enumeration** - List all logged-in users with session details
- **Active Session Detection** - Identify currently active (console) sessions
- **Lock State Tracking** - Monitor desktop lock/unlock events
- **User Information** - Get usernames, UIDs, home directories, group IDs
- **Process Ownership** - Determine which user owns a process
- **Environment Access** - Read environment variables from other user processes
- **Real-time Events** - Emit changed/locked/unlocked events

This module is used throughout MeshAgent for:
- Session awareness (don't show UI when no user logged in)
- User context switching
- Desktop interaction gating (locked vs unlocked)
- Audit logging (track who is logged in)
- User-specific operations

### Key Features by Platform

**Windows:**
- WTS (Windows Terminal Services) session enumeration
- Message pump integration for real-time session change events
- Power management events (suspend/resume, AC/battery, display on/off)
- Administrator privilege detection
- Process owner identification

**Linux:**
- loginctl integration for systemd-based systems
- /var/run/utmp monitoring for session changes
- /proc filesystem process environment access
- GDM/LightDM/SDDM display manager UID detection
- Xvfb virtual display detection
- UID min/max parsing from /etc/login.defs

**FreeBSD:**
- who command for session listing
- procstat for process environment access
- UID-based session identification

**macOS:**
- dscl (Directory Service command line) for user database
- last command for session history
- who for active session detection
- id command for UID/GID lookups

### Main Class: UserSessions

#### Constructor - Lines 62-74

**Purpose:** Initializes the UserSessions singleton with event emitter capabilities and lock state tracking.

**Properties:**
- `_ObjectID` - Set to 'user-sessions'
- `_locked` - Boolean tracking desktop lock state

**Events:**
- `changed` - Emitted when session list changes (login/logout)
- `locked` - Emitted when desktop is locked (with user info)
- `unlocked` - Emitted when desktop is unlocked (with user info)

**Methods:**
- `locked()` - Returns true if desktop is currently locked
- `unlocked()` - Returns !locked()

---

### Windows Implementation

#### Session Enumeration - Current() - Lines 278-306

**Purpose:** Enumerates all Windows Terminal Services sessions.

**Process:**
1. Calls WTSEnumerateSessionsA Win32 API (line 283)
2. Iterates through returned session structures (lines 288-299)
3. For each session:
   - Extracts SessionId, StationName, State
   - If Active: Queries username and domain via WTSQuerySessionInformationW
   - Builds session object: `{SessionId, StationName, State, Username, Domain}`
4. Adds `Active` property with filtered active sessions only (line 303)
5. Returns session object or calls callback (lines 304-305)

**Session States (line 138):**
```javascript
['Active', 'Connected', 'ConnectQuery', 'Shadow', 'Disconnected',
 'Idle', 'Listening', 'Reset', 'Down', 'Init']
```

**Return Value:**
```javascript
{
  0: {SessionId: 0, StationName: "Console", State: "Active", Username: "user", Domain: "WORKGROUP"},
  1: {SessionId: 1, StationName: "RDP-Tcp#0", State: "Disconnected"},
  Active: [{SessionId: 0, ...}]  // Only active sessions
}
```

---

#### Message Pump Integration - Lines 307-418

**Purpose:** Receives real-time Windows session and power events.

**Setup (lines 311-330):**
1. Creates win-message-pump filtering for WM_WTSSESSION_CHANGE (line 312)
2. On hwnd created: Registers for session notifications (line 324)
3. Registers for power setting notifications (lines 325-327):
   - AC/DC power source
   - Battery percentage
   - Console display state

**Session Events (lines 335-354):**
```javascript
case WTS_SESSION_LOCK:
    enumerateUsers().then(users => emit('locked', users[sessionId]));
    break;
case WTS_SESSION_UNLOCK:
    enumerateUsers().then(users => emit('unlocked', users[sessionId]));
    break;
case WTS_SESSION_LOGON:
case WTS_SESSION_LOGOFF:
    emit('changed');
    break;
```

**Power Events (lines 356-412):**
- PBT_APMSUSPEND → 'sx', 'SLEEP'
- PBT_APMRESUMESUSPEND → 'sx', 'RESUME_INTERACTIVE'
- PBT_APMRESUMEAUTOMATIC → 'sx', 'RESUME_NON_INTERACTIVE'
- PBT_APMPOWERSTATUSCHANGE → 'changed'
- PBT_POWERSETTINGCHANGE with GUID checks:
  - ACDC_POWER_SOURCE → 'acdc' event
  - BATTERY_PERCENTAGE_REMAINING → 'batteryLevel' event
  - CONSOLE_DISPLAY_STATE → 'display' event

---

#### Process Owner Identification - getProcessOwnerName(pid) - Lines 192-231

**Purpose:** Returns username, domain, and session ID for a process.

**Process:**
1. Opens process handle with PROCESS_QUERY_INFORMATION (line 203)
2. Opens process token (line 206)
3. Gets token information for TokenSessionId and TokenUser (lines 213-217)
4. Looks up account SID to get name and domain (line 218)
5. Returns `{name, domain, tsid}`

---

#### Administrator Check - isRoot() - Lines 173-191

**Purpose:** Determines if current process has administrator privileges.

**Process:**
1. Allocates and initializes SID for Administrators group (line 181)
2. Checks token membership in Administrators group (line 184)
3. Returns true if member, false otherwise

**SID Structure:**
```
NT AUTHORITY (5)
BUILTIN\Administrators (32, 544)
```

---

### Linux/FreeBSD Implementation

#### Session Enumeration - Current() - Lines 625-715

**Purpose:** Lists currently logged-in users using loginctl or who.

**Process:**

**With loginctl (lines 641-683):**
```bash
loginctl list-sessions | tr '\n' '`' | awk '{
    for(i=1;i<n;++i) {
        split(lines[i], tok, " ");
        if(tok[2]>=MIN_UID && tok[4]!="") {
            printf "%s{\"Username\": \"%s\", \"Domain\":\"\", \"SessionId\": \"%s\", \"State\": \"Online\", \"uid\": \"%s\", \"StationName\": \"%s\"}", del, tok[3], tok[1], tok[2], station;
            del=",";
        }
    }
}'
```
Parses loginctl output, filters by minimum UID, builds JSON array.

Then checks session state:
```bash
loginctl show-session -p State <session-ids> | grep State= | awk '{
    for(n=1;n<NF;++n) {
        if($n=="State=active") { print n; break; }
    }
}'
```
Marks active session.

**With who (FreeBSD or no loginctl) (line 634):**
```bash
who | tr '\n' '`' | awk -F'`' '{
    printf "{";
    for(a=1;a<NF;++a) {
        n=split($a, tok, " ");
        printf "%s\"%s\": \"%s\"", (a>1?",":""), tok[2], tok[1];
    }
    printf "}";
}'
```

**Virtual Display Detection (lines 702-707):**
Adds Xvfb sessions (virtual displays) to session list.

**Return Value:**
Array of session objects with `Active` property.

---

#### Console UID Detection - consoleUid() - Lines 843-1025

**Purpose:** Returns UID of user logged into physical console.

**Process:**

**With loginctl (lines 882-972):**
1. Lists sessions filtering by minimum UID
2. Filters out pts/* (SSH sessions)
3. Shows session state to find active session
4. Returns UID of first active console session

**With who (FreeBSD/fallback):**
1. Parses who output
2. Filters non-pts stations
3. Returns UID of first console user

**GDM Fallback (lines 975-1024):**
If no active session found:
1. Gets GDM (Gnome Display Manager) UID via gdmUid property
2. Checks if GDM session has X display environment
3. Returns GDM UID if valid X session found
4. Tries VNC sessions as last resort
5. Throws 'nobody logged into console' if all fail

---

#### GDM UID Detection - gdmUid - Lines 436-546

**Purpose:** Finds UID of display manager (GDM/LightDM/SDDM).

**Process:**

**With loginctl (lines 444-520):**
1. Gets passwd database entries
2. Lists loginctl sessions to get UIDs
3. Filters for UIDs with description containing "Display Manager" or username gdm/lightdm/sddm
4. Returns UID below minimum user UID (system user range)

**Fallback methods:**
- `getent passwd | grep "Gnome Display Manager"` (line 526)
- `getent passwd | grep gdm` with UID < MIN_UID filter (line 533)
- `getent passwd | grep "Light Display Manager"` (line 540)

---

#### Process Environment Access - getEnvFromPid(pid) - Lines 1141-1179

**Purpose:** Reads environment variables from another process.

**Linux (lines 1144-1161):**
```bash
cat /proc/<pid>/environ | tr '\0' '\t' | awk -F"\t" '{
    printf "{";
    for(i=1;i<NF;++i) {
        if(i>1) {printf ",";}
        x=split($i, tok, "=");
        printf "\"%s\": \"%s\"", tok[1], substr($i, 2+length(tok[1]));
    }
    printf "}";
}'
```
Parses null-terminated environment from /proc, converts to JSON.

**FreeBSD (lines 1164-1177):**
```bash
procstat -e <pid> | grep <pid> | awk '{ $1=""; $2=""; print $0 }' | tr " " "\n"
```
Uses procstat utility, parses space-delimited environment.

**Return Value:**
Object mapping environment variable names to values.

---

#### File System Monitoring - Lines 717-735

**Purpose:** Watches /var/run/utmp for session changes.

**Process:**
1. Creates fs.watch() on /var/run/utmp (line 721)
2. On change:
   - If loginctl available: Checks for active sessions before emitting
   - Otherwise: Emits 'changed' immediately

**Why utmp?**
Login programs update /var/run/utmp when users log in/out. Watching this file provides real-time login detection.

---

### macOS Implementation

#### User Database Access - dscl - Lines 1297-1336

**Purpose:** Queries macOS Directory Service for user information.

**_users() - Lines 1297-1318:**
```bash
dscl . list /Users UniqueID
```
Returns object mapping username → UID.

**_uids() - Lines 1319-1336:**
```bash
dscl . list /Users UniqueID
```
Returns object mapping UID → username.

**getUsername(uid) - Lines 1227-1246:**
```bash
dscl . list /Users UniqueID | grep <uid> | awk '{ if($2==<uid>){ print $1 }}'
```

**getGroupname(gid) - Lines 1247-1264:**
```bash
dscl . list /Groups PrimaryGroupID | grep <gid> | awk '{ if($2==<gid>){ print $1 }}'
```

**getHomeFolder(user) - Lines 1281-1296:**
```bash
dscl . -read /Users/<user> | grep NFSHomeDirectory | awk -F: '{ print $2 }'
```

---

#### Session Enumeration - Current() - Lines 1362-1394

**Purpose:** Lists logged-in users with active/inactive state.

**Process:**
1. Runs `last` command to get login history
2. Filters for sessions "still logged in" vs historical
3. Marks state as 'Active' or 'Inactive'
4. Gets UID from _idTable() for each user

**Return Value:**
```javascript
{
  "username": {Username: "username", State: "Active", uid: 501},
  Active: [{Username: "username", ...}]  // Only active
}
```

---

#### Console UID - consoleUid() - Lines 1265-1280

**Purpose:** Returns UID of console user.

**Process:**
```bash
who | tr '\n' '\.' | awk '{ print $1 }'
```
Gets first user from who output, looks up UID.

---

### Cross-Platform Methods

#### enumerateUsers() - Lines 1426-1448

**Purpose:** Promise-based wrapper around Current().

**Returns:** Promise resolving with user enumeration object.

---

#### showActiveOnly(source) - Lines 1450-1473

**Purpose:** Filters session object to only active sessions.

**Process:**
1. Iterates source object
2. Filters for State == 'Active'
3. Builds unique username list with Domain\ prefix if present
4. Returns array with `usernames` property

---

### Helper Functions

#### columnParse(data, delimiter) - Lines 50-59

**Purpose:** Splits string by delimiter, filters empty tokens.

Used for parsing awk/shell output.

---

#### getTokens(str) - Lines 1475-1490

**Purpose:** Parses whitespace-separated columns from string.

Handles variable-width columns by skipping multiple spaces.

---

### Dependencies

#### Node.js Core Modules
- `child_process` (extensive use) - Execute shell commands
- `fs` (line 719, 721) - File system watching (Linux)

#### MeshAgent Module Dependencies

**Windows:**
- **`_GenericMarshal`** - Native API marshaling
- **`win-registry`** - Registry access (proxy settings)
- **`win-message-pump`** (line 311) - Window message handling
  - Used for event handling in user session monitoring
- **`power-monitor`** (lines 363-400) - Power state monitoring
  - Methods: Power state change events
  - Integration with user session management

**Linux/Unix:**
- **`monitor-info`** (lines 977, 1011) - X display information
  - Methods: `getXInfo()`, `getEnvFromPid()`
  - Used for X11 display detection and gdmUid detection

**Cross-platform:**
- **`promise`** - Async operations
- **`events.EventEmitter`** - Event infrastructure

### Technical Notes

**Session vs Console:**
- **Session**: Any logged-in user (local, RDP, SSH, etc.)
- **Console**: Physical machine console (keyboard/monitor)

**Minimum UID Concept (Linux):**
Normal user UIDs start at UID_MIN (typically 1000). System users (daemons, services) have UIDs < UID_MIN. The module filters sessions by UID >= UID_MIN to exclude system users.

**Why loginctl?**
systemd's loginctl provides structured session information on modern Linux distributions. It's more reliable than parsing who/w output.

**GDM Session Handling:**
When a user logs in via GDM (Gnome Display Manager), GDM runs as a low UID. The module checks if this GDM session has valid X environment variables to determine if a user is logged in.

**Virtual Displays (Xvfb):**
Xvfb creates headless X servers for automation. The module detects these and adds them to session lists with special StationName format.

**Windows Session IDs:**
- Session 0: Services (no user)
- Session 1+: User sessions (console, RDP, etc.)
- Active Console Session ID: Retrieved via WTSGetActiveConsoleSessionId()

**macOS last Command:**
The `last` command shows login history. "still logged in" indicates active session. Historical entries show logout time.

**Process Environment Security:**
Reading /proc/<pid>/environ requires either:
- Root privileges, OR
- Same UID as target process

The module assumes root/admin execution.

## Summary

The user-sessions.js module provides comprehensive cross-platform user session management for **Windows, Linux, FreeBSD, and macOS**. It implements platform-specific session enumeration, lock state tracking, and real-time event notifications using native APIs and system utilities.

**Windows** uses WTS APIs with message pump integration for real-time session change events, power management events, and admin privilege detection. **Linux** leverages loginctl, /proc filesystem, and /var/run/utmp monitoring with display manager UID detection and virtual display support. **FreeBSD** uses who and procstat utilities. **macOS** uses dscl (Directory Service) and last command for user database access and session history.

The module emits changed/locked/unlocked events, provides user enumeration with active session filtering, supports process ownership identification, environment variable access from other processes, and UID/username resolution. It's essential for MeshAgent's user-aware operations, desktop interaction gating, and audit logging across all supported platforms.
