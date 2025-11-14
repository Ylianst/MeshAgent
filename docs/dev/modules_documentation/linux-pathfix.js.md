# linux-pathfix.js

Dynamically modifies the system PATH environment variable by appending additional directories commonly containing system administration and user binaries on Linux. Ensures essential system tools are accessible regardless of how the process was launched.

## Platform

**Supported Platforms:**
- Linux - Primary target
- FreeBSD - Compatible (shares similar path conventions)

**Excluded Platforms:**
- **macOS** - Partially incompatible
- **Windows** - Not applicable

**Exclusion Reasoning:**

**Lines 19-23:** Module appends Linux-specific paths to PATH variable

macOS is partially excluded because:

1. **Different Path Conventions** - The module appends paths that don't exist or have different purposes on macOS:
   - `/usr/local/sbin` - Exists on macOS (Homebrew uses this)
   - `/usr/sbin` - Exists on macOS
   - `/sbin` - Exists on macOS
   - `/snap/bin` - **Does not exist on macOS** (Ubuntu Snap package manager)

2. **Snap Package Manager** - Line 23 adds `/snap/bin` which is specific to Ubuntu's Snap package system. macOS doesn't use Snap packages; it uses:
   - Homebrew (`/usr/local/bin`, `/opt/homebrew/bin`)
   - MacPorts (`/opt/local/bin`)
   - Native apps in `/Applications`

3. **Standard PATH on macOS** - macOS already includes `/usr/local/sbin`, `/usr/sbin`, `/sbin` in the default PATH for most contexts, making this modification less critical.

4. **path_helper Utility** - macOS uses `/usr/libexec/path_helper` which reads `/etc/paths` and `/etc/paths.d/*` to construct the PATH. This is a more macOS-native approach.

**Windows is excluded** because:
- Windows doesn't use Unix-style `/sbin`, `/usr/sbin` paths
- Windows system tools are in `C:\Windows\System32`, `C:\Windows\SysWOW64`
- Windows PATH uses semicolons (`;`) not colons (`:`)

**Why in modules_macos_NEVER:**
While the module won't break on macOS (it would just append paths that mostly already exist), it's designed for Linux environments where PATH may be minimal. The inclusion of `/snap/bin` makes it Linux-specific.

## Functionality

### Core Purpose

Ensures system administration binaries are accessible by adding standard system directories to the PATH environment variable. This is particularly important when:
- Running from cron jobs (minimal PATH)
- Executing via systemd services (restricted PATH)
- Running as daemon processes (limited environment)
- SSH sessions with non-login shells
- Containerized environments

### Path Modification (Lines 19-23)

**Paths Added:**
1. `/usr/local/sbin` - Locally installed system administration tools
2. `/usr/sbin` - System administration binaries (installed by packages)
3. `/sbin` - Essential system binaries (boot, rescue, recovery)
4. `/snap/bin` - Ubuntu Snap package binaries

**Implementation:**
```javascript
process.env['PATH'] = process.env['PATH'] +
    ':/usr/local/sbin' +
    ':/usr/sbin' +
    ':/sbin' +
    ':/snap/bin';
```

**Behavior:**
- Appends to existing PATH (doesn't replace)
- Uses colon (`:`) as separator (Unix convention)
- Modifications affect all subsequent command executions
- Changes persist for lifetime of process

### What This Enables

**System Tools Now Accessible:**
- `ifconfig`, `ip` - Network configuration
- `iptables`, `nftables` - Firewall management
- `systemctl`, `service` - Service management
- `dmidecode` - Hardware information
- `lshw`, `lspci` - Hardware enumeration
- `fdisk`, `parted` - Disk management
- `modprobe`, `insmod` - Kernel module management
- Snap applications - GUI and CLI apps from Snap store

**Example Impact:**
```javascript
// Before path-fix
require('child_process').exec('ifconfig', ...);  // May fail: command not found

require('linux-pathfix');  // Load module

// After path-fix
require('child_process').exec('ifconfig', ...);  // Works: /sbin/ifconfig found
```

### Usage Pattern

**Typical Usage:**
```javascript
// Load early in program startup
require('linux-pathfix');

// Now all subsequent commands can find system tools
var child_process = require('child_process');

child_process.exec('ifconfig', function(err, stdout) {
    if (!err) {
        console.log('Network config:', stdout);
    }
});

child_process.exec('systemctl status sshd', function(err, stdout) {
    console.log('SSH status:', stdout);
});
```

**One-Time Execution:**
- Module executes path modification on first `require()`
- Subsequent `require()` calls use cached module (no additional PATH changes)
- Effects last for entire process lifetime

### Known Usage Context

**MeshAgent Environment:**
MeshAgent may be launched in various contexts with limited PATH:
- systemd service (PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin)
- cron job (PATH=/usr/bin:/bin)
- init script (minimal PATH)
- Container runtime (restricted PATH)

This module ensures MeshAgent can execute system commands for:
- Hardware inventory (`dmidecode`, `lshw`)
- Network information (`ifconfig`, `ip`)
- System diagnostics (`systemctl`, `service`)
- Software management (`snap`)

## Dependencies

### Node.js Core Module Dependencies

**None** - This is a pure environment variable modification module with no dependencies.

### Platform Binary Dependencies

**None Directly** - The module doesn't execute any binaries. It only modifies the PATH variable to make binaries in these directories findable by other modules.

**Indirect Dependencies:**
The paths added are expected to contain system binaries. Standard Linux distributions populate these directories with:

#### /usr/local/sbin
- Locally compiled system administration tools
- Custom system scripts
- Site-specific management utilities

#### /usr/sbin
- Package-managed system administration tools
- Service management utilities (`systemctl`, `service`)
- Network configuration tools (`ifconfig`, `ip`, `ethtool`)
- Hardware tools (`dmidecode`, `lshw`)

#### /sbin
- Essential system binaries (available even in single-user mode)
- Boot-critical tools (`init`, `reboot`, `shutdown`)
- Filesystem tools (`mkfs`, `fsck`, `mount`)
- Low-level system tools (`modprobe`, `insmod`)

#### /snap/bin
- Snap package executables (Ubuntu/Ubuntu-based distributions)
- Both GUI and CLI applications
- Self-contained application packages
- Requires `snapd` daemon to be installed

**Package Managers:**
- **APT** (Debian/Ubuntu): Installs to `/usr/sbin`, `/sbin`
- **YUM/DNF** (Red Hat/Fedora): Installs to `/usr/sbin`, `/sbin`
- **Pacman** (Arch): Installs to `/usr/bin` (merges sbin into bin)
- **Snap** (Ubuntu): Installs to `/snap/bin`

### Dependency Chain

```
linux-pathfix.js
└─── No dependencies (pure environment modification)

Indirect effects:
└─── Enables other modules to find binaries in:
     ├─── /usr/local/sbin
     ├─── /usr/sbin
     ├─── /sbin
     └─── /snap/bin
```

## Technical Notes

### Linux Distribution Differences

**Standard Distributions:**
- Most distributions include `/usr/local/sbin`, `/usr/sbin`, `/sbin` by default
- Root user typically has these in PATH
- Non-root users may not have `/sbin` paths in default PATH

**Arch Linux:**
- Merged `/sbin` into `/bin` and `/usr/sbin` into `/usr/bin`
- Symbolic links exist for compatibility
- This module still works but has no practical effect

**Ubuntu/Debian Snap Support:**
- `/snap/bin` only relevant on systems with snapd installed
- Harmless to add even if snapd not present
- Path entry ignored if directory doesn't exist

### Root vs Non-Root

**Root User:**
- Usually already has `/sbin` and `/usr/sbin` in PATH
- Module provides redundancy but no harm

**Non-Root User:**
- May not have system admin paths in default PATH
- Module makes system tools accessible (still subject to permissions)
- Many tools in `/sbin` require root permissions to execute

### When This Module Is Critical

**High Impact Scenarios:**
1. **systemd Services:**
   ```ini
   [Service]
   ExecStart=/usr/bin/node /opt/meshagent/meshagent.js
   ```
   - systemd provides minimal PATH
   - Without path-fix, system tool execution may fail

2. **Cron Jobs:**
   ```cron
   */5 * * * * /usr/bin/node /opt/meshagent/check.js
   ```
   - Cron provides very minimal PATH (`/usr/bin:/bin`)
   - System tools not findable without path-fix

3. **Docker Containers:**
   - Container PATH often minimal by design
   - System tools may be in unusual locations

**Low Impact Scenarios:**
- Interactive shell sessions (PATH already comprehensive)
- Desktop application launchers (inherit user's full PATH)
- Login shells (PATH set by `/etc/profile`, `~/.bashrc`)

### Security Considerations

**PATH Ordering:**
- Appends to existing PATH (doesn't prepend)
- Existing paths searched first
- Reduces PATH injection risk
- System directories have lowest priority

**Immutable After Load:**
- PATH modified once at module load
- No runtime manipulation
- Predictable behavior

### Performance

- **Execution Time:** Negligible (single string concatenation)
- **Memory Impact:** Minimal (one string operation)
- **Overhead:** Effectively zero
- **Suitable For:** All environments including embedded systems

### Alternative Approaches

**Platform-Specific:**
Instead of this module, you could:

1. **Set PATH in systemd service file:**
   ```ini
   [Service]
   Environment="PATH=/usr/local/sbin:/usr/sbin:/sbin:/snap/bin:/usr/bin:/bin"
   ```

2. **Use absolute paths:**
   ```javascript
   require('child_process').exec('/sbin/ifconfig', ...);
   ```
   - More explicit but less portable

3. **Use env command:**
   ```javascript
   require('child_process').exec('env PATH=$PATH:/sbin ifconfig', ...);
   ```
   - Wordy and error-prone

4. **macOS path_helper:**
   ```bash
   eval `/usr/libexec/path_helper -s`
   ```
   - macOS-specific approach

**This Module's Advantage:** Simple, centralized, one-time setup

## Summary

The linux-pathfix.js module ensures system administration binaries are accessible by appending standard Linux system directories (`/usr/local/sbin`, `/usr/sbin`, `/sbin`, `/snap/bin`) to the PATH environment variable. This is particularly important for daemon processes, systemd services, and cron jobs that run with minimal PATH settings.

**macOS is partially excluded** because:
- The module appends `/snap/bin` which doesn't exist on macOS (Ubuntu Snap package manager)
- macOS typically already includes the other paths (`/usr/local/sbin`, `/usr/sbin`, `/sbin`) in standard PATH
- macOS uses different conventions for PATH management (path_helper, /etc/paths)
- While the module wouldn't break on macOS, it's designed for Linux environments where PATH may be severely limited

The module provides a simple, zero-dependency solution for ensuring system tools are findable in restricted execution environments common on Linux systems.
