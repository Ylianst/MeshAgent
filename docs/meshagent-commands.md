# MeshAgent Command Reference

This document provides a comprehensive reference for all MeshAgent command-line options.

## Table of Contents

- [Information Commands](#information-commands)
- [Installation Commands](#installation-commands)
  - [Installation Assistant (GUI)](#installation-assistant-gui)
  - [Command-line Installation](#-install)
- [Execution Commands](#execution-commands)
- [Configuration Commands](#configuration-commands)
- [Development/Testing Commands](#developmenttesting-commands)
- [General Notes](#general-notes)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Appendix: Command Parsing and Validation](#appendix-command-parsing-and-validation)

---

## Information Commands

These commands retrieve information about the MeshAgent installation.

### `-nodeid`

**Description**: Display the agent's unique Node ID

**Usage**:
```bash
sudo meshagent -nodeid
# or
sudo /path/to/MeshAgent.app/Contents/MacOS/meshagent -nodeid
```

**Privileges**: Requires root/sudo

**Output**: Returns the 64-character hex Node ID from the agent's certificate

**Notes**:
- Works with both standalone binaries and app bundles
- Reads Node ID from `meshagent.db` file

---

### `-name`

**Description**: Display the agent's service name

**Usage**:
```bash
sudo meshagent -name
```

**Privileges**: Requires root/sudo

**Output**: Returns the service name (e.g., `meshagent.TacticalRMM.TacticalRMM`)

---

### `-agentHash`

**Description**: Display SHA384 hash of the agent binary

**Usage**:
```bash
meshagent -agentHash
```

**Privileges**: None required

**Output**: Returns the SHA384 hash of the agent executable

---

### `-agentFullHash`

**Description**: Display detailed SHA384 hash information

**Usage**:
```bash
meshagent -agentFullHash
```

**Privileges**: None required

**Output**: Returns extended hash information about the agent binary

---

### `-version`

**Description**: Display agent version information

**Usage**:
```bash
meshagent -version
```

**Privileges**: None required

**Output**: Returns version string (e.g., `5.6.29`)

---

### `-info`

**Description**: Display comprehensive agent information

**Usage**:
```bash
sudo meshagent -info
```

**Privileges**: Requires root/sudo

**Output**: Returns detailed information including:
- Version
- Node ID
- Service name
- Installation path
- Configuration details

---

### `-updaterversion`

**Description**: Display auto-updater version

**Usage**:
```bash
meshagent -updaterversion
```

**Privileges**: None required

**Output**: Returns the version of the auto-updater component

---

### `-licenses`

**Description**: Display all embedded open source licenses

**Usage**:
```bash
meshagent -licenses
```

**Privileges**: None required

**Output**: Prints full text of all third-party licenses

---

### `-lang`

**Description**: Display current agent language setting

**Usage**:
```bash
meshagent -lang
```

**Privileges**: None required

**Output**: Returns the current language code in uppercase with underscore (e.g., `EN_US`, `FR_FR`)

**Notes**:
- Language affects UI elements and messages in the Installation Assistant
- Default language is determined by system locale

---

### `-lang=<code>`

**Description**: Set agent language for interactive elements

**Usage**:
```bash
meshagent -lang=en-us
# or
meshagent -lang=fr-fr
```

**Privileges**: None required

**Format**: Language codes use lowercase with hyphen (e.g., `en-us`, `fr-fr`, `de-de`)

**Notes**:
- Affects Installation Assistant and other GUI elements
- Setting persists for the current session only
- Does not affect installed service language

---

## Installation Commands

These commands manage the installation, upgrade, and removal of the MeshAgent.

### Installation Assistant (GUI)

**Description**: Launch graphical Installation Assistant for easy setup

**Usage**:

**Launch from Finder** (macOS only):
```bash
# Double-click MeshAgent.app while holding CMD key
# OR
open -a MeshAgent.app --args --show-install-ui
```

**Launch from command line**:
```bash
sudo /path/to/MeshAgent.app/Contents/MacOS/meshagent --show-install-ui
```

**Privileges**: Requires root/sudo (will prompt for elevation if needed)

**Features**:
- **Graphical Interface**: User-friendly GUI for installation and upgrade
- **Automatic Elevation**: Prompts for administrator password if not running as root
- **Configuration Discovery**: Automatically searches for .msh files in:
  - Same directory as the app bundle
  - User's Downloads folder
- **Installation Options**:
  - Custom installation path (default: `/usr/local/mesh_services/meshagent/`)
  - Enable/disable automatic updates
  - Enable/disable TCC permission checking
- **Upgrade Detection**: Automatically detects existing installations and offers upgrade
- **Progress Tracking**: Real-time progress display during installation/upgrade
- **Security Permissions**: Checks for required macOS security permissions (Accessibility, Screen Recording)

**Behavior**:
- On launch, searches for existing MeshAgent installation in LaunchDaemons
- If found: Offers upgrade with current installation details
- If not found: Offers fresh installation with .msh file selection
- Validates installation paths for security
- Creates directories recursively if needed
- Provides clear error messages and operation results

**Notes**:
- App bundle only feature (not available in standalone binary)
- Requires .msh configuration file for installation
- Installation path must be in allowed location: `/Applications/`, `/opt/`, `/usr/local/`, or `/Library/`
- For more details, see [macOS Installation Assistant documentation](./macos-install-assistant.md)

---

### `-install`

**Description**: Install or upgrade MeshAgent service

**Usage**:

**In-place install** (requires .msh file in same directory):
```bash
sudo ./meshagent -install
# or
sudo /path/to/MeshAgent.app/Contents/MacOS/meshagent -install
```

**Install to specific location**:
```bash
sudo ./meshagent -install --installPath="/opt/tacticalmesh/"
```

**Fresh install with service name**:
```bash
sudo ./meshagent -install \
  --installPath="/opt/tacticalmesh/" \
  --serviceName="TacticalRMM" \
  --companyName="TacticalRMM" \
  --copy-msh="1"
```

**Privileges**: Requires root/sudo

**Options**:
- `--installPath="/path/"` - Target installation directory (must end with `/`)
- `--serviceName="Name"` - Service name component
- `--companyName="Company"` - Company name component
- `--copy-msh="1"` - Copy .msh configuration file to install location
- `--meshAgentLogging="1"` - Configure meshagent launchd logging to /tmp (macOS only)

**Behavior**:
- **Fresh install**: Installs new agent instance
- **Upgrade**: Updates existing installation
- **In-place install**: If .msh file is present and no --installPath specified, installs in current directory
- **Self-upgrade**: Running installed binary with -install/-upgrade updates configuration without replacing binary

**Notes**:
- For fresh installs, either place .msh file next to binary or use `--copy-msh="1"`
- .msh file can be named:
  - `meshagent.msh` (generic)
  - `meshagent_osx-universal-64.msh` (platform-specific)
  - `MeshAgent.msh` (case-insensitive)
- Service ID format on macOS: `meshagent.ServiceName.CompanyName`
- Creates LaunchDaemon at `/Library/LaunchDaemons/meshagent.ServiceName.CompanyName.plist`
- May create LaunchAgent for user-level features
- When `--meshAgentLogging="1"` is enabled:
  - LaunchDaemon logs to: `/tmp/meshagent-daemon.log` (stdout and stderr)
  - LaunchAgent logs to: `/tmp/meshagent-agent.log` (stdout and stderr)
  - Logging is NOT preserved during upgrades (must re-enable each installation)
  - Useful for debugging installation or runtime issues

---

### `-upgrade`

**Description**: Alias for `-install` - performs upgrade of existing installation

**Usage**:
```bash
sudo meshagent -upgrade
```

**Privileges**: Requires root/sudo

**Behavior**: Identical to `-install` command

**Notes**:
- `-upgrade` and `-install` are interchangeable
- Can be run from installed location (self-upgrade)
- Supports all `-install` options including `--meshAgentLogging="1"`

---

### `-uninstall`

**Description**: Uninstall MeshAgent service while preserving data files

**Usage**:
```bash
sudo meshagent -uninstall
```

**Privileges**: Requires root/sudo

**Behavior**:
- Stops and removes LaunchDaemon/LaunchAgent services
- Removes service plist files
- Removes agent binary/bundle
- Removes backup files (*.TIMESTAMP)
- **Preserves**: `meshagent.db`, `meshagent.msh`, and data directories

**Notes**:
- Safe for temporary removal or reinstallation
- Agent can be reinstalled later with same configuration

---

### `-fulluninstall`

**Description**: Completely remove MeshAgent service and all data

**Usage**:
```bash
sudo meshagent -fulluninstall
```

**Privileges**: Requires root/sudo

**Behavior**:
- Performs all steps from `-uninstall`
- **Additionally removes**:
  - `meshagent.db` (agent database)
  - `meshagent.msh` (configuration file)
  - All data directories
  - Entire installation directory

**Warning**: This operation is irreversible. All agent data will be permanently deleted.

---

## Execution Commands

These commands execute JavaScript code or run the agent in different modes.

### `-exec`

**Description**: Execute JavaScript code string

**Usage**:
```bash
sudo meshagent -exec "console.log('Hello World');"
```

**Privileges**: Typically requires root/sudo

**Notes**:
- Executes code in agent's JavaScript environment
- Has access to all embedded modules
- Output goes to stdout

---

### `-b64exec`

**Description**: Execute base64-encoded JavaScript code

**Usage**:
```bash
sudo meshagent -b64exec "Y29uc29sZS5sb2coJ0hlbGxvIFdvcmxkJyk7"
```

**Privileges**: Typically requires root/sudo

**Notes**:
- Useful for passing complex scripts with special characters
- Code is base64-decoded then executed

---

### `-daemon`

**Description**: Run agent in foreground daemon mode

**Usage**:
```bash
sudo meshagent -daemon
```

**Privileges**: Requires root/sudo

**Behavior**:
- Runs agent in foreground (does not daemonize)
- Logs to stdout/stderr
- Useful for debugging

**Notes**:
- Not typically used manually (LaunchDaemon manages this)
- Press Ctrl+C to stop

---

## Configuration Commands

These commands manage agent configuration and updates.

### `-export`

**Description**: Export all embedded JavaScript modules to the filesystem

**Usage**:
```bash
meshagent -export
```

**Privileges**: None required

**Output**: Creates a `modules_expanded` directory containing all embedded modules

**Notes**:
- Extracts all JavaScript modules embedded in the agent binary
- Useful for inspecting module code or debugging
- Does NOT export agent configuration (use `-info` to view configuration)

---

### `-import`

**Description**: Import JavaScript modules from filesystem and regenerate polyfills

**Usage**:
```bash
meshagent -import --expandedPath="./modules_macos" --filePath="./microscript/ILibDuktape_Polyfills.c"
```

**Privileges**: None required

**Parameters**:
- `--expandedPath` - Directory containing expanded module files
- `--filePath` - Path to polyfills C file to regenerate

**Notes**:
- Inverse operation of `-export`
- Used during build process to regenerate polyfills
- Reads modules from filesystem and packs them back into C code
- Does NOT import agent configuration

---

### `-update`

**Description**: Trigger agent self-update (not functional on macOS)

**Usage**:
```bash
meshagent -update
```

**Privileges**: Platform dependent

**Behavior**:
- **macOS**: This command does not function when called directly
- **Windows/Linux**: Checks for and applies agent updates from server

**Notes**:
- On macOS, agent updates are handled automatically by the server
- Manual update triggering via command line is not supported on macOS
- Use `-install` or `-upgrade` to manually update the agent binary

---

## Development/Testing Commands

These commands are primarily for development and testing purposes.

### `-kvm0`

**Description**: Test KVM (remote desktop) mode 0

**Usage**:
```bash
sudo meshagent -kvm0
```

**Privileges**: Requires root/sudo

**Notes**: Used for testing remote desktop functionality

---

### `-kvm1`

**Description**: Test KVM (remote desktop) mode 1

**Usage**:
```bash
sudo meshagent -kvm1
```

**Privileges**: Requires root/sudo

**Notes**: Used for testing remote desktop functionality

---

### `-faddr`

**Description**: Internal debugging tool (non-functional without parameters)

**Usage**:
```bash
meshagent -faddr <address>
```

**Privileges**: None required

**Notes**:
- Requires specific address parameter
- Internal debugging tool for core developers
- Not intended for end-user use

---

### `-fdelta`

**Description**: Internal debugging tool (non-functional without parameters)

**Usage**:
```bash
meshagent -fdelta <delta>
```

**Privileges**: None required

**Notes**:
- Requires specific delta parameter
- Internal debugging tool for core developers
- Not intended for end-user use

---

### `connect`

**Description**: Development mode connection (non-functional on macOS)

**Usage**:
```bash
meshagent connect
```

**Privileges**: Platform dependent

**Notes**:
- Does not function as expected on macOS
- Primarily for Windows/Linux development testing
- Not intended for production use

---

## General Notes

### File Locations (macOS)

**Standalone Binary Installation**:
- Binary: `/path/to/install/meshagent`
- Database: `/path/to/install/meshagent.db`
- Config: `/path/to/install/meshagent.msh`

**App Bundle Installation**:
- Bundle: `/path/to/install/MeshAgent.app`
- Binary: `/path/to/install/MeshAgent.app/Contents/MacOS/meshagent`
- Database: `/path/to/install/meshagent.db` (in parent directory)
- Config: `/path/to/install/meshagent.msh` (in parent directory)

**Service Files**:
- LaunchDaemon: `/Library/LaunchDaemons/meshagent.ServiceName.CompanyName.plist`
- LaunchAgent: `/Library/LaunchAgents/meshagent.ServiceName.CompanyName.plist`

### Bundle vs Standalone Detection

The agent automatically detects whether it's running from an app bundle or as a standalone binary:
- **Bundle**: Detected by `.app/Contents/MacOS/` in executable path
- **Standalone**: All other cases

When running from a bundle, the agent changes its working directory to the parent of the .app directory, allowing .msh and .db files to be found in the same location as the bundle.

### Exit Codes

- `0` - Success
- `1` - General error
- `2` - Permission denied
- `3` - File not found
- `4` - Invalid arguments

### Logging

Install/uninstall operations use timestamped logging format:
```
[YYYY-MM-DD HH:MM:SS] LEVEL: message
```

Log levels:
- `INFO` - Normal operations
- `WARN` - Warnings (non-fatal)
- `ERROR` - Errors (usually fatal)

---

## Examples

### Example 1: Installation Using GUI (Easiest Method)

```bash
# Download MeshAgent.app and .msh file to same directory
# Double-click MeshAgent.app while holding CMD key
# Follow the graphical Installation Assistant

# OR from command line:
sudo /path/to/MeshAgent.app/Contents/MacOS/meshagent --show-install-ui
```

### Example 2: Fresh Installation (Command-line)

```bash
# Place the .msh file next to the binary
cd /path/to/download
sudo ./meshagent -install --installPath="/opt/tacticalmesh/" --copy-msh="1"
```

### Example 3: In-Place Installation

```bash
# .msh file is in same directory
cd /opt/tacticalmesh
sudo ./meshagent -install
```

### Example 4: Upgrade Existing Installation

```bash
# Run new binary to upgrade existing installation
cd /tmp
sudo ./meshagent-new -install
```

### Example 5: Self-Upgrade

```bash
# Run installed binary to reconfigure
sudo /opt/tacticalmesh/meshagent -upgrade
```

### Example 6: Check Node ID

```bash
sudo /opt/tacticalmesh/MeshAgent.app/Contents/MacOS/meshagent -nodeid
```

### Example 7: Installation with Debug Logging

```bash
# Install with logging enabled for debugging
sudo ./meshagent -install --installPath="/opt/tacticalmesh/" --copy-msh="1" --meshAgentLogging="1"

# After installation, check logs:
tail -f /tmp/meshagent-daemon.log
tail -f /tmp/meshagent-agent.log
```

### Example 8: Complete Removal

```bash
sudo meshagent -fulluninstall
```

---

## Troubleshooting

### Common Issues

**"Permission denied"**
- Ensure you're running with sudo/root privileges
- Check file permissions on binary: `ls -l meshagent`
- Binary should be executable: `chmod +x meshagent`

**".msh file not found"**
- Verify .msh file is in correct location
- Check for platform-specific naming (e.g., `meshagent_osx-universal-64.msh`)
- Filename matching is case-insensitive

**"No installation found"**
- Verify installation path
- Check service is registered: `sudo launchctl list | grep meshagent`
- Verify plist exists: `ls /Library/LaunchDaemons/meshagent.*`

**"Self-upgrade detected but not at install location"**
- This is normal - binary will be copied to install location
- If unexpected, check --installPath parameter

### Debug Mode

For verbose output during installation:
```bash
sudo meshagent -install 2>&1 | tee install.log
```

### Checking Service Status

```bash
# List all meshagent services
sudo launchctl list | grep meshagent

# Check if specific service is loaded
sudo launchctl list meshagent.ServiceName.CompanyName

# View service plist
cat /Library/LaunchDaemons/meshagent.ServiceName.CompanyName.plist
```

### Manual Service Start/Stop

```bash
# Stop service
sudo launchctl stop meshagent.ServiceName.CompanyName

# Start service
sudo launchctl start meshagent.ServiceName.CompanyName

# Unload service
sudo launchctl unload /Library/LaunchDaemons/meshagent.ServiceName.CompanyName.plist

# Load service
sudo launchctl load /Library/LaunchDaemons/meshagent.ServiceName.CompanyName.plist
```

---

## Appendix: Command Parsing and Validation

### Command-Line Argument Parsing

MeshAgent uses strict command-line argument parsing with the following characteristics:

**Argument Validation**:
- Only recognized commands and arguments are accepted
- Unrecognized commands will be ignored or trigger default behavior (help display)
- Command names are **case-insensitive** (e.g., `-Install`, `-install`, and `-INSTALL` are equivalent)
- Arguments must follow the expected format for each command

**Argument Format Rules**:
```bash
# Commands use single dash prefix
meshagent -command

# Parameters use double dash prefix with equals sign
meshagent -install --installPath="/path/" --serviceName="Name"

# Multi-word values must be quoted
meshagent -install --installPath="/path with spaces/"

# Boolean flags use "1" for true, "0" for false
meshagent -install --copy-msh="1"
```

**Parsing Behavior**:
- Arguments are parsed in order from left to right
- First argument (after executable name) is typically the command
- Subsequent arguments are command-specific parameters
- Invalid or malformed arguments may cause the command to fail silently or display usage help

**Security Considerations**:
- Path arguments are validated for:
  - Dangerous characters that could enable command injection
  - Directory traversal sequences (`..`)
  - Allowed installation locations (for `-install` command)
- Only parsable, well-formed commands are executed
- Privilege requirements are enforced (commands requiring root will fail if not elevated)

### Platform-Specific Commands

**macOS-Specific**:
- Installation Assistant GUI (`--show-install-ui`)
- TCC permission checking and validation
- LaunchDaemon/LaunchAgent service management

**Windows-Only Commands** (not available on macOS):
- `-signcheck` - Perform authenticode signature self-check
- `-resetnodeid` - Reset NodeID on next service start
- `-fullinstall` - Copy to Program Files and install
- `-setfirewall`, `-clearfirewall`, `-checkfirewall` - Windows Firewall management
- Service control commands: `start`, `stop`, `restart`, `state`, `run`, `connect`

**Cross-Platform Commands**:
- Most information commands (`-nodeid`, `-version`, `-info`, etc.)
- Installation commands (`-install`, `-uninstall`, `-upgrade`)
- Execution commands (`-exec`, `-b64exec`, `-daemon`)
- Configuration commands (`-export`, `-import`)

### Unknown Arguments

If you provide an unrecognized command or invalid arguments:
- The agent may display usage help (Windows)
- The agent may exit silently with non-zero status
- Check spelling and format of commands and arguments
- Ensure you're using the correct platform-specific commands

---

## Support

For issues, bugs, or feature requests, please visit:
https://github.com/Ylianst/MeshAgent
