# MeshAgent Command Reference

This document provides a comprehensive reference for all MeshAgent command-line options.

## Table of Contents

- [Information Commands](#information-commands)
- [Installation Commands](#installation-commands)
- [Execution Commands](#execution-commands)
- [Configuration Commands](#configuration-commands)
- [Development/Testing Commands](#developmenttesting-commands)

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

## Installation Commands

These commands manage the installation, upgrade, and removal of the MeshAgent.

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

### Example 1: Fresh Installation

```bash
# Place the .msh file next to the binary
cd /path/to/download
sudo ./meshagent -install --installPath="/opt/tacticalmesh/" --copy-msh="1"
```

### Example 2: In-Place Installation

```bash
# .msh file is in same directory
cd /opt/tacticalmesh
sudo ./meshagent -install
```

### Example 3: Upgrade Existing Installation

```bash
# Run new binary to upgrade existing installation
cd /tmp
sudo ./meshagent-new -install
```

### Example 4: Self-Upgrade

```bash
# Run installed binary to reconfigure
sudo /opt/tacticalmesh/meshagent -upgrade
```

### Example 5: Check Node ID

```bash
sudo /opt/tacticalmesh/MeshAgent.app/Contents/MacOS/meshagent -nodeid
```

### Example 6: Complete Removal

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

## Support

For issues, bugs, or feature requests, please visit:
https://github.com/Ylianst/MeshAgent
