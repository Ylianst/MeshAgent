# task-scheduler.js

Cross-platform scheduled task management module for MeshAgent that provides unified API for creating and deleting scheduled tasks across Windows (Task Scheduler), Linux (cron), and macOS (launchd). Enables automated service restart scheduling and maintenance task creation through platform-specific implementations.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support using Windows Task Scheduler (schtasks.exe)
- Linux - Full support using cron daemon (/etc/cron.d/)
- macOS (darwin) - Full support using launchd (LaunchDaemons)
- FreeBSD - Supported via Linux cron implementation

**Exclusion Reasoning:**

This module is **fully supported on macOS** and is not excluded. The macOS implementation (lines 294-438) uses launchd property lists (plists) stored in /Library/LaunchDaemons/ to manage scheduled tasks. macOS support includes:

1. **Native launchd Integration** - Creates and manages launchd jobs using standard plist format
2. **Calendar-Based Scheduling** - Supports StartCalendarInterval for daily/weekly/monthly schedules
3. **Interval-Based Scheduling** - Supports StartInterval for minute/hourly intervals
4. **Service Management** - Automatically loads target services before creating tasks
5. **Proper Cleanup** - Unloads launchd jobs and removes plist files on deletion

The macOS implementation is production-ready and fully functional.

## Functionality

### Purpose

The task-scheduler module provides a unified cross-platform API for managing scheduled tasks that automatically restart MeshAgent services. It abstracts the differences between:

- **Windows Task Scheduler** - Uses schtasks.exe command-line tool
- **Linux cron** - Creates entries in /etc/cron.d/ directory
- **macOS launchd** - Generates and manages LaunchDaemon plist files

This module is typically used to:
- Schedule automatic service restarts after system updates
- Create maintenance windows for agent updates
- Implement watchdog-style service recovery
- Schedule periodic service health checks

### Key Functions

#### create(options) - Lines 134-450

**Purpose:** Creates a new scheduled task with platform-specific implementation.

**Parameters:**
```javascript
{
    name: 'task-name',          // Required: Task identifier
    service: 'service-name',    // Required: Service to start
    MINUTE: 5,                  // Every N minutes (incompatible with TIME)
    HOURLY: 2,                  // Every N hours (incompatible with TIME)
    DAILY: 1,                   // Every N days
    WEEKLY: 1,                  // Once per week (value must be 1)
    MONTHLY: 1,                 // Every N months
    DAY: 0-6,                   // Day of week (0=Sunday) or day of month
    MONTH: 1-12,                // Month of year
    TIME: 'HH:MM'               // Specific time (24-hour format)
}
```

**Process Flow:**

**Windows Implementation (lines 141-178):**
1. Builds schtasks.exe command with parameters
2. Uses '/RU SYSTEM' to run as SYSTEM account
3. Converts options to Task Scheduler flags:
   - `/SC` - Schedule type (MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY)
   - `/MO` - Modifier (frequency value)
   - `/TN` - Task name (converts / to \)
   - `/TR` - Task run command (net start service-name)
   - `/ST` - Start time
4. Executes schtasks.exe and waits for exit code
5. Returns promise that resolves on success (code 0)

**Linux Implementation (lines 180-293):**
1. Checks if task already exists in /etc/cron.d/
2. Builds cron format string: `minute hour day month weekday`
3. Defaults all fields to '*' (any)
4. Applies options to override defaults:
   - `MINUTE`: Sets to `*/N` for intervals
   - `HOURLY`: Sets hour to `*/N`
   - `DAILY`: Sets day to `*/N`
   - `WEEKLY`: Sets weekday (only supports once weekly)
   - `TIME`: Parses HH:MM to set hour and minute
5. Detects service manager type (init, upstart, systemd)
6. Builds appropriate start command:
   - **init**: `service <name> start`
   - **upstart**: `initctl start <name>`
   - **systemd**: `systemctl start <name>`
7. Writes cron file to /etc/cron.d/ with mode 0644
8. Format example:
   ```
   SHELL=/bin/sh
   PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

   0 2 * * *   root   /usr/bin/systemctl start meshagent >/dev/null 2>&1
   ```

**macOS Implementation (lines 294-438):**
1. Generates task name: sanitizes by removing / and . characters
2. Ensures target service is loaded via service-manager
3. Builds plist XML structure with standard Apple DTD
4. Determines scheduling type:
   - **Interval-based** (MINUTE/HOURLY): Uses `StartInterval` in seconds
   - **Calendar-based** (DAILY/WEEKLY/MONTHLY): Uses `StartCalendarInterval` array
5. Handles complex calendar scheduling:
   - **DAILY > 1**: Calculates multiple future days (e.g., every 3 days)
   - **WEEKLY**: Sets specific day of week (0-6)
   - **MONTHLY**: Calculates multiple future months
6. Writes plist to /Library/LaunchDaemons/[taskname].plist
7. Executes `launchctl load` to activate task
8. Example plist for hourly task:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
     <dict>
         <key>Label</key>
         <string>task_name</string>
         <key>ProgramArguments</key>
         <array>
           <string>/bin/launchctl</string>
           <string>start</string>
           <string>service-name</string>
         </array>
         <key>RunAtLoad</key>
         <false/>
         <key>StartInterval</key>
         <integer>3600</integer>
     </dict>
   </plist>
   ```

**Returns:** Promise that resolves on success, rejects with error message on failure.

**Platform-Specific Behavior:**
- **Windows**: Task name supports hierarchy with / (converted to \)
- **Linux**: Only supports once-weekly scheduling (WEEKLY=1)
- **macOS**: Complex calendar intervals create multiple StartCalendarInterval entries
- **All platforms**: Rejects if name or service not provided

---

#### delete(name) - Lines 462-523

**Purpose:** Removes a scheduled task from the system.

**Parameters:**
- `name` (string) - Task name to delete

**Process:**

**Windows (lines 467-473):**
1. Executes `schtasks.exe /Delete /TN "name" /F`
2. Converts / to \ in task name
3. Uses /F flag to force deletion without confirmation
4. Waits for exit code
5. Resolves on code 0, rejects on non-zero

**Linux (lines 475-492):**
1. Sanitizes name (removes / and .)
2. Checks if /etc/cron.d/[name] exists
3. Uses fs.unlinkSync() to delete file
4. Resolves on success
5. Rejects if file doesn't exist or deletion fails

**macOS (lines 494-516):**
1. Sanitizes name (removes / and .)
2. Checks if /Library/LaunchDaemons/[name].plist exists
3. Executes `launchctl unload` to stop task
4. Deletes plist file with fs.unlinkSync()
5. Resolves on success
6. Rejects if task doesn't exist or deletion fails

**Returns:** Promise that resolves on successful deletion, rejects with error.

---

#### info(name) - Lines 451-461

**Purpose:** Retrieves information about a scheduled task.

**Status:** Not implemented on any platform (always rejects).

**Returns:** Promise that rejects with "Not implemented on [platform]"

---

### Windows-Specific Functions

#### getTaskXml(name) - Lines 29-37

**Purpose:** Retrieves the XML definition of a Windows scheduled task.

**Process:**
1. Executes `schtasks.exe /QUERY /TN "name" /XML`
2. Captures stdout as XML string
3. Throws exception if stderr contains errors
4. Returns raw XML string

**Platform:** Windows only

---

#### getActionCommand(name, xml) - Lines 38-52

**Purpose:** Extracts the command line from a task's Action element.

**Process:**
1. If xml parameter not provided, fetches via getTaskXml()
2. Parses XML manually (no XML parser used):
   - Splits on `</Exec>` and `<Exec>` tags
   - Extracts content between `<Command>` and `</Command>`
3. Returns command string

**Platform:** Windows only

**Usage:** Used to read what command a task executes before modifying it.

---

#### editActionCommand(name, action, argString, xml) - Lines 53-109

**Purpose:** Modifies the command and arguments of an existing Windows task.

**Process:**
1. Fetches task XML if not provided
2. Parses and modifies XML structure:
   - Replaces `<Command>` content with new action
   - Replaces `<Arguments>` content with new argString
3. Writes modified XML to temp file with UTF-16 BOM (0xFF 0xFE)
4. Deletes existing task: `SCHTASKS /DELETE /TN name /F`
5. Recreates task from XML: `SCHTASKS /CREATE /TN name /XML tempfile`
6. Deletes temp file
7. All executed via cmd.exe to handle multiple commands

**Platform:** Windows only

**Note:** This is the standard method for modifying tasks on all Windows versions.

---

#### advancedEditActionCommand(name, action, argString) - Lines 111-120

**Purpose:** Uses PowerShell ScheduledTasks module to modify task (modern method).

**Process:**
1. Spawns powershell.exe
2. Creates new ScheduledTaskAction:
   ```powershell
   $Act1 = New-ScheduledTaskAction -Execute "action" -Argument "argString"
   Set-ScheduledTask "name" -Action $Act1
   ```
3. Waits for completion and outputs result

**Platform:** Windows only, requires PowerShell ScheduledTasks module

**Availability:** Checked via `advancedSupport` property

---

#### advancedSupport (property) - Lines 121-130

**Purpose:** Detects if PowerShell ScheduledTasks module is available.

**Process:**
1. Executes PowerShell command:
   ```powershell
   Get-Module -ListAvailable -Name ScheduledTasks
   ```
2. Returns true if module found (output not empty)
3. Returns false if module not available

**Platform:** Windows only

**Note:** Windows 8/Server 2012 and newer have this module. Windows 7/Server 2008 R2 do not.

---

### Usage Examples

#### Create Daily Service Restart at 2 AM

```javascript
var scheduler = require('task-scheduler');

scheduler.create({
    name: 'meshagent-daily-restart',
    service: 'meshagent',
    DAILY: 1,
    TIME: '02:00'
}).then(function() {
    console.log('Task created successfully');
}, function(err) {
    console.log('Error: ' + err);
});
```

**Platform Behavior:**
- **Windows**: Creates task using Task Scheduler, runs `net start meshagent` at 2 AM
- **Linux**: Creates /etc/cron.d/meshagent-daily-restart with entry: `0 2 * * * root systemctl start meshagent`
- **macOS**: Creates /Library/LaunchDaemons/meshagent-daily-restart.plist with StartCalendarInterval

---

#### Create Hourly Service Check

```javascript
scheduler.create({
    name: 'meshagent-hourly',
    service: 'meshagent',
    HOURLY: 1
}).then(function() {
    console.log('Hourly task created');
});
```

**Platform Behavior:**
- **Windows**: Task runs every 1 hour
- **Linux**: Cron entry with `0 */1 * * *`
- **macOS**: StartInterval of 3600 seconds

---

#### Create Weekly Service Restart

```javascript
scheduler.create({
    name: 'meshagent-weekly',
    service: 'meshagent',
    WEEKLY: 1,
    DAY: 0,        // Sunday
    TIME: '03:00'
}).then(function() {
    console.log('Weekly task created');
});
```

**Platform Behavior:**
- **Windows**: Runs every Sunday at 3:00 AM
- **Linux**: Cron entry: `0 3 * * 0 root systemctl start meshagent`
- **macOS**: StartCalendarInterval with Day=0, Hour=3, Minute=0

---

#### Delete Task

```javascript
scheduler.delete('meshagent-daily-restart')
    .then(function() {
        console.log('Task deleted');
    }, function(err) {
        console.log('Deletion failed: ' + err);
    });
```

---

#### Windows: Modify Existing Task

```javascript
// Only on Windows
var scheduler = require('task-scheduler');
var xml = scheduler.getTaskXml('meshagent-restart');
var currentCmd = scheduler.getActionCommand('meshagent-restart', xml);

// Change to different service
scheduler.editActionCommand(
    'meshagent-restart',
    'net',
    'start "Mesh Agent"',
    xml
);
```

---

### Dependencies

#### Module Dependencies

**Core Required Modules:**

- **`promise`** (line 17)
  - Custom promise implementation
  - Used for async task creation/deletion operations
  - All public methods return promises

- **`service-manager`** (line 18)
  - Service management functionality
  - Used on all platforms
  - **Linux**: Detects service type (init/upstart/systemd) - line 246
  - **macOS**: Ensures target service is loaded before creating task - line 316
  - **Windows**: Not actively used but imported
  - Methods: `getServiceType()`, `getService(name)`, `isLoaded()`, `load()`

**Platform-Specific Module Dependencies:**

- **`child_process`** (lines 31, 99, 113, 173, 249, 259, 269, 338, 431, 498)
  - All platforms use this for executing system commands
  - Methods: `execFile()` - spawn system utilities
  - **Windows**: Executes schtasks.exe and powershell.exe
  - **Linux**: Executes /bin/sh for whereis and service commands
  - **macOS**: Executes /bin/sh and launchctl

- **`fs`** (lines 90, 181, 284-285, 429, 476, 480, 496, 504)
  - File system operations
  - **Linux**: Check/write/delete /etc/cron.d/ files
  - **macOS**: Check/write/delete /Library/LaunchDaemons/ plists
  - **Windows**: Write temporary XML files
  - Methods: `existsSync()`, `writeFileSync()`, `unlinkSync()`, `createWriteStream()`, `CHMOD_MODES`

- **`os`** (lines 90, 103)
  - Operating system utilities
  - **Windows only**: Get temp directory for XML file storage
  - Method: `tmpdir()` - returns temp directory path

- **`user-sessions`** (line 246 via service-manager context)
  - Implicit dependency through service-manager
  - Used to detect service locations and user contexts

#### System Binary Dependencies

**Windows:**
- **schtasks.exe** - %windir%\system32\schtasks.exe
  - Task Scheduler command-line interface
  - Used for: /CREATE, /DELETE, /QUERY operations
  - Required for all Windows task operations

- **cmd.exe** - %windir%\system32\cmd.exe (line 99)
  - Windows command processor
  - Used for: Executing batch sequences in editActionCommand()
  - Required for task modification

- **powershell.exe** - %windir%\System32\WindowsPowerShell\v1.0\powershell.exe (lines 113, 124)
  - PowerShell interpreter
  - Used for: Advanced task editing with ScheduledTasks module
  - Optional: Only used if advancedSupport is true

**Linux:**
- **whereis** (lines 249, 259, 269, 273)
  - Utility to locate system binaries
  - Used to find: service, initctl, systemctl
  - Required for: Creating tasks (determines service command)

- **service** / **initctl** / **systemctl** (lines 246-277)
  - Service management utilities (one required based on system)
  - **init systems**: service command
  - **upstart systems**: initctl command
  - **systemd systems**: systemctl command
  - Required for: Task execution (cron calls these to start service)

- **awk** (line 253, 263, 273)
  - Text processing utility
  - Used to parse whereis output
  - Required for: Task creation

- **cron daemon** (implicit)
  - System cron service
  - Reads /etc/cron.d/ directory
  - Required for: Task execution

**macOS:**
- **whereis** (line 41)
  - BSD utility to locate binaries
  - Used in findPath() helper (lines 30-47)
  - Note: macOS whereis behaves differently than Linux (no awk parsing)

- **launchctl** (lines 304, 433, 500)
  - launchd job management utility
  - Used for: Loading and unloading LaunchDaemons
  - Commands: `launchctl start`, `launchctl load`, `launchctl unload`
  - Required for: All macOS task operations

- **launchd** (implicit)
  - macOS service management daemon
  - Reads /Library/LaunchDaemons/ directory
  - Required for: Task execution

**FreeBSD:**
- Same as Linux (uses cron implementation)
- Additional path check: /usr/local/bin/ (line 45)

#### File System Requirements

**Windows:**
- Write access to: %TEMP% directory (for temporary XML files)
- Read/Write access to: Task Scheduler database (via schtasks.exe)

**Linux:**
- Write access to: /etc/cron.d/ directory (root required)
- Read access to: /etc/cron.d/ for checking existing tasks
- File permissions: 0644 (user: rw, group: r, other: r)

**macOS:**
- Write access to: /Library/LaunchDaemons/ (root required)
- Read access to: /Library/LaunchDaemons/ for checking existing tasks
- launchd automatically monitors this directory

#### Permission Requirements

**All Platforms:**
- Root/Administrator privileges required for:
  - Creating system-wide scheduled tasks
  - Writing to system directories
  - Managing system services

**Why Root is Required:**
- **Windows**: Task Scheduler requires admin rights for SYSTEM tasks
- **Linux**: /etc/cron.d/ is root-owned
- **macOS**: /Library/LaunchDaemons/ is root-owned

### Code Structure

The module is organized into functional sections:

1. **Lines 1-21:** License header and core module imports
2. **Lines 23-24:** Main task constructor function definition
3. **Lines 27-131:** Windows-specific helper methods and properties
   - getTaskXml() - Fetch task XML
   - getActionCommand() - Parse command from XML
   - editActionCommand() - Modify task via XML
   - advancedEditActionCommand() - Modify task via PowerShell
   - advancedSupport property - PowerShell module detection
4. **Lines 134-450:** create() method - Platform-specific task creation
   - Lines 141-178: Windows implementation
   - Lines 180-293: Linux implementation
   - Lines 294-438: macOS implementation
5. **Lines 451-461:** info() method - Not implemented stub
6. **Lines 462-523:** delete() method - Platform-specific task deletion
   - Lines 467-473: Windows implementation
   - Lines 475-492: Linux implementation
   - Lines 494-516: macOS implementation
7. **Lines 527-528:** Module export

### Technical Notes

#### Promise-Based API

All public methods return custom promise objects (not native JavaScript promises):

```javascript
var p = scheduler.create(options);
p._res = resolve_function;  // Custom promise internals
p._rej = reject_function;
```

Promises resolve with no value on success, or reject with error string/code on failure.

#### Name Sanitization

Task names are sanitized differently per platform:

- **Windows**: Forward slashes (/) converted to backslashes (\) for hierarchy
- **Linux/macOS**: Both forward slashes and periods removed to create valid filenames

Example:
- Input: `"mesh/agent.restart"`
- Windows: `"mesh\agent.restart"`
- Linux/macOS: `"meshagentrestart"`

#### Time Format Consistency

All platforms use 24-hour time format (HH:MM):
- `"02:00"` = 2:00 AM
- `"14:30"` = 2:30 PM

#### Cron Format (Linux)

Standard cron format: `minute hour day month weekday user command`

Fields:
- `*` = any value
- `*/N` = every N units
- `N` = specific value

Example: `0 2 * * * root systemctl start meshagent`
- Minute: 0
- Hour: 2
- Day: * (any)
- Month: * (any)
- Weekday: * (any)
- User: root
- Command: systemctl start meshagent

#### LaunchDaemon Plist Format (macOS)

Two scheduling modes:

1. **StartInterval** (integer, seconds):
   - Simple interval-based execution
   - Example: 3600 = every hour

2. **StartCalendarInterval** (array of dicts):
   - Calendar-based execution
   - Keys: Minute, Hour, Day, Month, Weekday
   - Multiple entries = multiple execution times

Apple automatically handles:
- Jobs that miss execution time while system is off
- Job persistence across reboots
- Job dependencies

#### UTF-16 Encoding for Windows XML (lines 91-96)

Windows Task Scheduler requires UTF-16 Little Endian encoding for XML files:

```javascript
var b = Buffer.alloc(2);
b[0] = 0xFF;  // Byte Order Mark (BOM)
b[1] = 0xFE;  // UTF-16 LE marker
s.write(b);
s.write(Buffer.from(xml).toString('utf16'));
```

This ensures international characters in task names work correctly.

#### Service Manager Type Detection (Linux)

The module detects which init system is running:

```javascript
require('service-manager').manager.getServiceType()
```

Returns:
- `'init'` - SysV init (legacy)
- `'upstart'` - Upstart (Ubuntu 14.04 and earlier)
- `'systemd'` - systemd (modern Linux)

Each type requires different command syntax.

#### macOS Calendar Math (lines 332-385)

For multi-interval calendar schedules (e.g., every 3 days), the module calculates future dates:

```javascript
// Every 3 days example
var currentDay = (new Date()).getDate();  // Today = 15
var actualDay = currentDay;
do {
    currentDay += 3;  // 18, 21, 24, 27, 30, 33
    if (currentDay > 31) currentDay = currentDay % 31;  // 33 % 31 = 2
    periodic.push('<integer>' + currentDay + '</integer>');
} while (!(currentDay < actualDay && (currentDay + 3) > actualDay));
```

This creates multiple StartCalendarInterval entries to approximate the interval.

#### Error Handling

All methods return promises that reject with descriptive errors:

- `"Invalid Parameters, must at least specify name and service"` - Missing required fields
- `"Task [name] Already exists"` - Linux: Task file already exists
- `"Task [name] does not exist"` - Delete called on non-existent task
- `"Not implemented on [platform]"` - Platform not supported
- `"Invalid Options"` - Incompatible scheduling options
- Exception objects - File system or command execution errors

#### Child Process Handling

All platform implementations use synchronous process execution:

```javascript
var child = require('child_process').execFile(...);
child.stdout.str = '';
child.stdout.on('data', function(chunk) { this.str += chunk.toString(); });
child.stderr.on('data', function(chunk) { });
child.waitExit();  // Blocks until process completes
```

The `waitExit()` method is a MeshAgent extension that synchronously waits for process completion.

## Platform-Specific Analysis

### What Works on macOS

**Fully Functional:**
- ✅ `create()` - Complete implementation with launchd support
- ✅ `delete()` - Proper unload and cleanup
- ✅ Interval scheduling - StartInterval for MINUTE/HOURLY
- ✅ Calendar scheduling - StartCalendarInterval for DAILY/WEEKLY/MONTHLY
- ✅ Service integration - Ensures services are loaded before creating tasks
- ✅ Automatic cleanup - Unloads and removes plist files

**Schedule Types Supported on macOS:**
- ✅ Every N minutes (MINUTE)
- ✅ Every N hours (HOURLY)
- ✅ Daily at specific time (DAILY + TIME)
- ✅ Weekly on specific day (WEEKLY + DAY + TIME)
- ✅ Monthly on specific day (MONTHLY + DAY + TIME)
- ✅ Specific day of month (DAY without WEEKLY)
- ✅ Complex multi-day intervals (calculates multiple calendar entries)

**Example macOS Task Creation:**

```javascript
// Every 2 hours
scheduler.create({
    name: 'meshagent-check',
    service: 'meshagent',
    HOURLY: 2
});
// Creates: StartInterval = 7200

// Every Monday at 3 AM
scheduler.create({
    name: 'meshagent-weekly',
    service: 'meshagent',
    WEEKLY: 1,
    DAY: 1,
    TIME: '03:00'
});
// Creates: StartCalendarInterval with Day=1, Hour=3, Minute=0
```

### What Doesn't Work on macOS

**Not Implemented:**
- ❌ `info()` - Not implemented on any platform (always rejects)

**Limitations:**
- ⚠️ WEEKLY scheduling only supports value of 1 (once per week) - line 355
- ⚠️ Complex multi-day DAILY intervals create multiple calendar entries (workaround for every N days)
- ⚠️ No direct support for multiple weekdays in single task

### Platform Comparison

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Create tasks | ✅ schtasks | ✅ cron | ✅ launchd |
| Delete tasks | ✅ schtasks | ✅ unlink | ✅ launchctl |
| Modify tasks | ✅ XML/PowerShell | ❌ Manual | ❌ Manual |
| Get task info | ❌ Stub | ❌ Stub | ❌ Stub |
| Minute intervals | ✅ | ✅ | ✅ |
| Hour intervals | ✅ | ✅ | ✅ |
| Daily schedules | ✅ | ✅ | ✅ |
| Weekly schedules | ✅ Multiple | ✅ Once only | ✅ Once only |
| Monthly schedules | ✅ | ✅ | ✅ |
| Task hierarchy | ✅ Folders | ❌ | ❌ |
| UTF-16 support | ✅ Required | N/A | N/A |
| Root required | ✅ Admin | ✅ Root | ✅ Root |

### macOS Implementation Quality

The macOS implementation is **production-ready** with these strengths:

1. **Proper plist format** - Uses Apple's DTD and standard structure
2. **Service dependency handling** - Ensures target service is loaded
3. **Flexible scheduling** - Supports both interval and calendar modes
4. **Clean error handling** - Returns descriptive promise rejections
5. **Complete lifecycle** - Both creation and deletion fully implemented
6. **System integration** - Uses official launchctl interface

**Best Practices Followed:**
- Stores plists in /Library/LaunchDaemons/ (system-wide)
- Uses launchctl load/unload (proper lifecycle)
- Sets RunAtLoad to false (prevents immediate execution)
- Sanitizes task names for filesystem compatibility

## Summary

The task-scheduler.js module is a **fully cross-platform** scheduled task management solution supporting **Windows, Linux, and macOS** equally. It provides a unified promise-based API that abstracts the complexities of:

- Windows Task Scheduler (schtasks.exe)
- Linux cron daemon (/etc/cron.d/)
- macOS launchd (LaunchDaemons)

**macOS is fully supported** with a complete implementation (lines 294-438) that creates and manages launchd jobs using property list files. The macOS implementation handles both interval-based (StartInterval) and calendar-based (StartCalendarInterval) scheduling, properly integrates with service-manager to ensure services are loaded, and provides clean cleanup via launchctl unload.

Key capabilities:
- **create()**: Platform-specific task creation with unified API
- **delete()**: Proper cleanup on all platforms
- **Windows-specific helpers**: XML parsing, advanced PowerShell editing
- **Promise-based**: All async operations return promises
- **Root required**: All operations require elevated privileges

The module is production-ready on all three major platforms and is actively used by MeshAgent for scheduling service restarts and maintenance tasks.
