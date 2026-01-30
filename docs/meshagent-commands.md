# MeshAgent Command Reference

Comprehensive reference for all MeshAgent command-line arguments across all platforms.

## Table of Contents

- [Information Commands](#information-commands)
- [Installation Commands](#installation-commands)
- [Installation Options](#installation-options)
- [Service Control](#service-control)
- [Interactive Mode](#interactive-mode)
- [Script Execution](#script-execution)
- [Module Management](#module-management)
- [KVM Options](#kvm-options)
- [Network & Proxy](#network--proxy)
- [macOS Specific](#macos-specific)
- [Windows Specific](#windows-specific)
- [Update](#update)
- [Advanced](#advanced)
- [Self-Test & Diagnostics](#self-test--diagnostics)
- [Debug](#debug)
- [Argument Validation](#argument-validation)

---

## Information Commands

| Argument | Description | Privileges |
|----------|-------------|------------|
| `-help`, `--help`, `-h` | Show help message | None |
| `-version` | Show version (`CFBundleShortVersionString` on macOS) | None |
| `-buildver` | Show build version (`CFBundleVersion` on macOS) | None |
| `-buildversion` | Alias for `-buildver` | None |
| `-fullversion` | Show complete version (version + build) | None |
| `-info` | Show detailed agent information (version, node ID, paths) | Root |
| `-licenses` | Show embedded open source licenses | None |
| `-nodeid` | Show agent's unique 64-character hex node ID | Root |
| `-name` | Show agent's service name | Root |
| `-agentHash` | Show SHA384 hash of agent binary (truncated) | None |
| `-agentFullHash` | Show SHA384 hash of agent binary (full) | None |
| `-updaterversion` | Show auto-updater version | None |

---

## Installation Commands

| Argument | Description | Privileges |
|----------|-------------|------------|
| `-install` | Install agent as system service | Root |
| `-finstall` | Full install (with recovery capabilities) | Root |
| `-fullinstall` | Alias for `-finstall` | Root |
| `-upgrade` | Upgrade existing installation (alias for `-install`) | Root |
| `-uninstall` | Uninstall agent service (preserves data files) | Root |
| `-funinstall` | Full uninstall (remove all data) | Root |
| `-fulluninstall` | Alias for `-funinstall` | Root |

### `-install` / `-upgrade`

Installs or upgrades the MeshAgent as a system service.

```bash
# In-place install (requires .msh file in same directory)
sudo ./meshagent -install

# Install to specific location
sudo ./meshagent -install --installPath="/opt/acmemesh/"

# Fresh install with options
sudo ./meshagent -install \
  --installPath="/opt/acmemesh/" \
  --meshServiceName="ACME Mesh" \
  --companyName="ACME, Inc." \
  --copy-msh="1"
```

**Behavior**:
- **Fresh install**: Creates new service, LaunchDaemon/LaunchAgent (macOS), or system service (Windows/Linux)
- **Upgrade**: Updates existing installation, preserving configuration
- **In-place install**: If `.msh` file is present and no `--installPath`, installs in current directory

### `-uninstall`

Removes the service but preserves data files (`.db`, `.msh`). Safe for temporary removal.

### `-funinstall` / `-fulluninstall`

Removes everything including database, configuration, and installation directory. **Irreversible.**

---

## Installation Options

These flags modify the behavior of `-install`, `-finstall`, `-upgrade`, and related commands.

### Paths & Files

| Argument | Description |
|----------|-------------|
| `--installPath=PATH` | Installation directory (e.g., `/opt/acmemesh/`) |
| `--mshPath=PATH` | Explicit path to `.msh` configuration file |
| `--target=PATH` | Target binary path |
| `--fileName=NAME` | Binary file name |
| `--copy-msh=1` | Copy `.msh` file to install location |

### Service Identity

| Argument | Description |
|----------|-------------|
| `--meshServiceName=NAME` | Service name (e.g., `ACME Mesh`) |
| `--serviceName=NAME` | Backward-compatible alias for `--meshServiceName` |
| `--companyName=NAME` | Company name (e.g., `ACME, Inc.`) |
| `--displayName=NAME` | Service display name |
| `--description=TEXT` | Service description |
| `--serviceId=ID` | Unique service identifier for multiple instances |
| `--setServiceID=ID` | Set service identifier during fresh install (macOS). Mapped to `--serviceId` before `.msh` injection. See [ServiceID System](./macOS-ServiceID-System.md) |

### Feature Control

| Argument | Description |
|----------|-------------|
| `--disableUpdate=1` | Disable automatic updates |
| `--allowNoMsh=1` | Allow operation without `.msh` file |
| `--backup`, `--backup=1` | Create backup during install/upgrade |
| `--installedByUser=UID` | Record which user performed the installation |

### macOS Install Options

| Argument | Description |
|----------|-------------|
| `--disableTccCheck=1` | Disable TCC permission check UI |
| `--meshAgentLogging=1` | Enable launchd logging to `/tmp/{serviceId}-daemon.log` and `/tmp/{serviceId}-agent.log` |
| `--appBundle=1` | Running from app bundle |

---

## Service Control

| Argument | Platform | Description |
|----------|----------|-------------|
| `run` | All (not macOS) | Run as console agent in foreground |
| `start` | Linux/BSD/Windows | Start as background daemon/service |
| `-d` | Linux/BSD | Alias for `start` |
| `stop` | Linux/BSD/Windows | Stop background daemon/service |
| `-s` | Linux/BSD | Alias for `stop` |
| `-daemon` | Linux/BSD | Run in foreground daemon mode |
| `-state` | All | Show agent state |
| `-config` | macOS | Update launchd scripts for existing installation |

```bash
# Run in foreground (Linux/BSD)
sudo meshagent run

# Start/stop daemon (Linux/BSD)
sudo meshagent start
sudo meshagent stop

# Foreground daemon mode
sudo meshagent -daemon
```

---

## Interactive Mode

These arguments are parsed by the JavaScript interactive module (`interactive.js`).

| Argument | Description |
|----------|-------------|
| `-mesh` | Print mesh configuration info |
| `-translations` | Print translation strings |
| `-connect` | Connect to server (interactive mode) |
| `-update` | Update/install (interactive mode alias) |
| `--lang=CODE` | Set language (e.g., `--lang=en-us`, `--lang=fr-fr`) |

```bash
# Show mesh configuration
meshagent -mesh

# Connect in interactive mode
meshagent -connect

# Set language
meshagent --lang=en-us -show-install-ui
```

---

## Script Execution

| Argument | Description |
|----------|-------------|
| `script.js` | Execute JavaScript file (positional argument) |
| `-exec CODE` | Execute JavaScript code string |
| `-b64exec CODE` | Execute base64-encoded JavaScript |
| `--script-db PATH` | Database path for script mode |
| `--script-flags FLAGS` | Script execution flags |
| `--script-timeout SEC` | Watchdog timeout (0 = unlimited) |
| `--script-connect` | Enable MeshCentral connection in script mode |

**Important**: `-exec` and `-b64exec` consume the **next** `argv` element as raw JavaScript code. The argument validation system skips validation of whatever follows these flags, since the content is arbitrary code — not a flag.

```bash
# Execute inline JavaScript
sudo meshagent -exec "console.log('Hello World');"

# Execute base64-encoded JavaScript
sudo meshagent -b64exec "Y29uc29sZS5sb2coJ0hlbGxvIFdvcmxkJyk7"

# Run a JavaScript file
sudo meshagent ./myscript.js

# Script mode with database and timeout
sudo meshagent ./myscript.js --script-db /tmp/test.db --script-timeout 30
```

---

## Module Management

| Argument | Description |
|----------|-------------|
| `-export` | Export embedded JavaScript modules to filesystem |
| `-import` | Import modules from filesystem, regenerate polyfills |
| `--no-embedded=1` | Disable embedded JavaScript resources |
| `--expandedPath=PATH` | Expanded path for module export |
| `--filePath=PATH` | File path for polyfills output |
| `--modulesPath=PATH` | Modules directory path |

```bash
# Export all embedded modules
meshagent -export

# Import and regenerate polyfills
meshagent -import --expandedPath="./modules_macos" --filePath="./microscript/ILibDuktape_Polyfills.c"
```

---

## KVM Options

These flags are passed to the KVM subprocess (launched via `-kvm1`).

| Argument | Description |
|----------|-------------|
| `--allowedUIDs=LIST` | Comma-separated list of allowed user IDs for KVM sessions |
| `--virtualDM=1` | Enable virtual display manager mode |

These are typically set by the daemon process when launching the KVM LaunchAgent, not passed manually.

---

## Network & Proxy

| Argument | Description |
|----------|-------------|
| `--slave` | Run as slave agent |
| `--netinfo` | Display network information |
| `connect` | Development mode connection (no dash) |
| `--autoproxy=DOMAIN` | Auto-proxy configuration domain |

---

## macOS Specific

### TCC Permissions

| Argument | Description |
|----------|-------------|
| `-tccCheck` | TCC permissions check subprocess (communicates via pipe) |
| `-check-tcc` | Check TCC permissions, show UI if needed (fire-and-forget) |
| `-show-tcc-ui` | Show TCC permissions window (Accessibility, FDA, Screen Recording). Also auto-launches with SHIFT+double-click on `.app` |
| `-request-accessibility` | Request Accessibility permission (spawned as user) |
| `-request-screenrecording` | Request Screen Recording permission (spawned as user) |
| `-request-fulldiskaccess` | Request Full Disk Access (shows custom dialog) |

**WARNING**: Running `-request-*` arguments from a terminal requests permissions for the **terminal app**, not MeshAgent. These flags are intended to be spawned by the TCC permissions UI, not run manually.

### Installation & KVM

| Argument | Description |
|----------|-------------|
| `-show-install-ui` | Launch Installation Assistant GUI (with elevation). Also auto-launches with CMD+double-click on `.app` |
| `-kvm1` | KVM remote desktop subprocess mode (launched by LaunchAgent via QueueDirectories) |
| `--setServiceID=ID` | Set service identifier during fresh install. See [ServiceID System](./macOS-ServiceID-System.md) |

---

## Windows Specific

### KVM

| Argument | Description |
|----------|-------------|
| `-kvm0` | KVM mode 0 |
| `-kvm1` | KVM mode 1 |
| `-coredump` | Enable core dump (used with `-kvm0`/`-kvm1`) |
| `-remotecursor` | Enable remote cursor (used with `-kvm0`/`-kvm1`) |

### Service Control

| Argument | Description |
|----------|-------------|
| `start`, `-start` | Start Windows service |
| `stop`, `-stop` | Stop Windows service |
| `restart`, `-restart` | Restart Windows service |
| `state` | Show service state |
| `exstate` | Show extended service state |

### Security & Network

| Argument | Description |
|----------|-------------|
| `-nocertstore` | Disable Windows Certificate Store |
| `-recovery` | Set recovery capabilities |
| `-setfirewall` | Set Windows firewall rules |
| `-clearfirewall` | Clear Windows firewall rules |
| `-checkfirewall` | Check Windows firewall rules |

### Other

| Argument | Description |
|----------|-------------|
| `-resetnodeid` | Reset agent node ID |
| `-lang` | Show current language (simple flag, no value) |
| `--hideConsole=1` | Hide console window |
| `--exitPID=PID` | Exit when specified PID terminates |
| `meshcmd` | Enter MeshCmd mode |
| `-netinfo` | Display network information (single-dash form) |

---

## Update

| Argument | Description |
|----------|-------------|
| `-update:URL` | Self-update from URL (e.g., `-update:https://example.com/meshagent`) |

---

## Advanced

| Argument | Description |
|----------|-------------|
| `--readonly=1` | Read-only database mode |
| `--resetnodeid` | Reset node ID (double-dash form) |
| `--verbose=LEVEL` | Verbose logging level |
| `--info=LEVEL` | Info logging level |
| `--quiet=1` | Quiet mode (minimal output) |
| `--silent=1` | Silent mode (no output) |
| `--log=LEVEL` | Log level (0-3) |

---

## Self-Test & Diagnostics

These arguments are used by the agent self-test module (`agent-selftest.js`).

| Argument | Description |
|----------|-------------|
| `--debugMode=1` | Enable debug mode |
| `--dumpOnly=1` | Dump-only mode (no execution) |
| `--cycleCount=N` | Number of test cycles |
| `--showCoreInfo=1` | Show core info |
| `--smbios=1` | Show SMBIOS information |
| `--fakeUpdate=1` | Simulate update (testing only) |

---

## Debug

| Argument | Description |
|----------|-------------|
| `-faddr ADDR` | Memory address debug tool |
| `-fdelta DELTA` | Memory delta debug tool |

These are internal debugging tools for core developers. Not intended for end-user use.

---

## Argument Validation

MeshAgent validates command-line arguments against a master allow list before processing. This prevents typos and malformed arguments from causing unexpected behavior.

### How It Works

1. **Allow lists** are defined in `meshconsole/main.c` as static arrays:
   - `ALL_PLATFORMS_simple_flags[]` — exact-match flags used on all platforms
   - `ALL_PLATFORMS_prefix_flags[]` — prefix-match flags (e.g., `--installPath=`) on all platforms
   - Platform-specific arrays: `WINDOWS_simple_flags[]`, `MACOS_simple_flags[]`, `LINUX_simple_flags[]`, `BSD_simple_flags[]`, and corresponding prefix arrays

2. **Validation runs on macOS** (`ENABLE_ARGUMENT_VALIDATION 1`). Other platforms define the arrays for documentation but do not enforce them at runtime.

3. **Special cases**:
   - Arguments following `-exec` or `-b64exec` are **skipped** (they contain arbitrary JavaScript code)
   - Files ending in `.js` are allowed (script execution)
   - Positional arguments not starting with `-` are allowed (values for preceding flags)
   - Positional arguments containing `=` without a `--` prefix are rejected (likely typos like `LOG=3` instead of `--log=3`)

4. **On validation failure**: the agent prints a warning identifying the unknown argument, suggests using `-help`, and exits with a non-zero status.

### Argument Format Rules

```bash
# Commands use single dash prefix
meshagent -install

# Some commands have no dash (positional)
meshagent run
meshagent connect

# Parameters use double dash with equals sign
meshagent -install --installPath="/opt/acmemesh/"

# Multi-word values must be quoted
meshagent -install --companyName="ACME, Inc."

# Boolean flags use "1" for true, "0" for false
meshagent -install --disableUpdate=1

# -exec/-b64exec take the next argument as raw code
meshagent -exec "console.log('hello');"
```

### Adding New Arguments

When adding a new command-line argument to MeshAgent:

1. Add it to the appropriate allow list array in `meshconsole/main.c`
2. Add it to the `-help` text in the same file
3. Update this document
4. If the argument takes a value via the next `argv` element (like `-exec`), add skip logic in the validation loop
