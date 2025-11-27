# interactive.js

Interactive graphical installer/setup utility for MeshAgent providing user-friendly dialog-based installation, updating, and connection management with multi-language support (English, Korean, and extensible for others).

## Platform

**Supported Platforms:**
- Linux - Full support (requires Zenity or KDialog for GUI)
- Windows (win32) - Full support (native message boxes)
- macOS (darwin) - Full support (native dialogs)

**Excluded Platforms:**
- FreeBSD - Potentially supported with Zenity/KDialog (untested)

**Exclusion Reasoning:**

This module has no explicit platform exclusions, though the graphical interface requires platform-specific dialog tools:

- **Linux:** Requires Zenity or KDialog for graphical dialogs. Fallback to command-line if unavailable.
- **Windows:** Uses native Windows message boxes via Win32 API.
- **macOS:** Uses native macOS dialog capabilities.

The module automatically detects available dialog tools and falls back to text-based command-line interface if graphical components are unavailable. This ensures functionality across platforms while providing optimal user experience when GUI is available.

## Functionality

### Purpose

The interactive module provides a user-friendly installation and management interface for MeshAgent. It serves multiple purposes:

- **Initial Installation:** Guides users through agent installation with clear prompts
- **Agent Updates:** Allows upgrading to newer agent versions
- **Connection Management:** Temporary "connect mode" for diagnostic sessions
- **Uninstallation:** Clean removal of installed agents
- **Status Display:** Shows current agent state (installed, running, not installed)
- **Multi-Language Support:** Localized UI for different languages
- **Configuration Management:** Handles .msh configuration file parsing

This module is typically used:
- As a standalone installer executable (.msh files embedded in binary)
- For user-initiated agent installation (non-automated deployments)
- During agent updates when GUI confirmation needed
- For temporary diagnostic connections without permanent installation

### Key Features

#### Multi-Language Support (Lines 34-90)

**Supported Languages:**
- **English (en):** Default language
- **Korean (ko):** Full translation provided
- **Extensible:** Translation structure allows adding more languages

**Translation Structure:**
```javascript
{
    en: {
        agent: 'Agent',
        agentVersion: 'New Agent Version',
        group: 'Device Group',
        url: 'Server URL',
        meshName: 'Mesh Name',
        meshId: 'Mesh Identifier',
        serverId: 'Server Identifier',
        setup: 'Setup',
        update: 'Update',
        install: 'Install',
        uninstall: 'Uninstall',
        connect: 'Connect',
        disconnect: 'Disconnect',
        cancel: 'Cancel',
        status: ['NOT INSTALLED', 'RUNNING', 'NOT RUNNING'],
        statusDescription: 'Current Agent Status',
        description: '...'
    },
    ko: { /* Korean translations */ }
}
```

---

#### Configuration File Handling (Lines 21-31)

**MSH File Format:**

The module reads `.msh` configuration files embedded in the executable:
```
MeshName=MyMeshNetwork
MeshType=2
MeshID=ABC123...
ServerID=DEF456...
MeshServer=wss://server.domain.com:443/agent.ashx
displayName=My Mesh Agent
```

**Key-Value Parsing:**
- Simple format: `key=value`
- Line-delimited
- Embedded in executable as `.msh` file

**Configuration Parameters:**
- `MeshName` - Human-readable mesh network name
- `MeshType` - Type identifier (numeric)
- `MeshID` - Unique mesh identifier
- `ServerID` - Server identifier
- `MeshServer` - WebSocket URL for agent connection
- `displayName` - Display name for service
- `translation` - Optional JSON translation object

---

#### Self-Extracting Executable Generation (Lines 99-123)

**Purpose:** Creates standalone installer with embedded configuration.

**Process:**
1. Reads original executable binary
2. Appends JavaScript module code
3. Adds quad-word alignment padding
4. Appends JavaScript size (4 bytes, big-endian)
5. Appends magic GUID: `B996015880544A19B7F7E9BE44914C18`

**Binary Structure:**
```
[Original Executable]
[Padding for alignment]
[JavaScript Module]
[JavaScript Size: 4 bytes]
[Magic GUID: 16 bytes]
```

This creates a self-contained executable that includes both the agent binary and installation logic.

---

#### Installation Modes

**Standard Installation:**
- Installs agent as system service
- Persists across reboots
- Runs with elevated privileges
- Configures auto-start

**Connect-Only Mode:**
- Temporary connection without installation
- No service creation
- Terminates when closed
- Used for diagnostics or temporary management

**Update Mode:**
- Replaces existing agent with newer version
- Preserves configuration
- Minimal downtime

---

### Key Functions/Methods

#### _install(parms) - Installation Function

**Purpose:** Installs MeshAgent with specified parameters.

**Parameters:**
- `parms` - Object containing installation configuration

**Process:**
1. Validates elevated privileges (root/admin)
2. Checks existing agent status
3. Copies binary to installation directory
4. Configures service (using `service-manager`)
5. Starts agent service
6. Displays success/failure message

**Privilege Requirements:**
- **Linux:** Requires `sudo` or root
- **Windows:** Requires administrator
- **macOS:** Requires root/administrator

**Error Handling:**
- Detects insufficient privileges
- Prompts user to retry with elevation
- Shows clear error messages via GUI or console

---

#### _uninstall() - Uninstallation Function

**Purpose:** Removes installed MeshAgent.

**Process:**
1. Validates elevated privileges
2. Stops running agent service
3. Removes service registration
4. Deletes agent binary and configuration
5. Displays confirmation message

**Cleanup:**
- Service files removed
- Configuration data deleted
- Binary files removed
- Registry entries cleaned (Windows)

---

#### Dialog Display Functions

**Platform-Specific Implementation:**

**Linux:**
```javascript
// Uses message-box module with Zenity/KDialog
var dialog = require('message-box').create(
    title,
    caption,
    timeout,
    buttons
);
```

**Windows:**
```javascript
// Native Win32 message boxes via user32.dll
// Displayed via message-box module
```

**macOS:**
```javascript
// osascript for AppleScript dialogs
// Handled by message-box module
```

**Button Configurations:**
- Single button: ['OK']
- Two buttons: ['Install', 'Cancel']
- Three buttons: ['Install', 'Connect', 'Cancel']

---

### Usage

#### Command-Line Interface

```bash
# Show GUI installer (if available)
./meshagent-installer

# Install with GUI
./meshagent-installer -install

# Install via command line (no GUI)
./meshagent-installer -install --console

# Uninstall
./meshagent-installer -uninstall

# Connect mode (temporary, no installation)
./meshagent-installer -connect

# Update to new version
./meshagent-installer -update
```

#### GUI Workflow

1. **Launch Installer:**
   - Executable reads embedded `.msh` configuration
   - Detects current agent status
   - Displays main dialog with options

2. **Main Dialog:**
   - Shows server URL, mesh name, agent status
   - Buttons: Install / Connect / Cancel (or Update if installed)

3. **Installation:**
   - User clicks "Install"
   - Privilege check (prompts for sudo/admin if needed)
   - Installation proceeds
   - Success/failure dialog shown

4. **Connect Mode:**
   - User clicks "Connect"
   - Temporary agent starts
   - Dialog shows "Disconnect" button
   - Agent terminates when disconnected

---

### Dependencies

#### Node.js Core Modules

- **`fs`** (lines 21, 94, 99)
  - Purpose: Read .msh configuration, executable binary, write output
  - Usage: `readFileSync()`, `createWriteStream()`
  - Platform support: Cross-platform

- **`child_process`** (used in installation functions)
  - Purpose: Spawn agent processes
  - Usage: Launch agent, execute system commands
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

- **`service-manager`** (installation/uninstallation)
  - Purpose: Service installation and control
  - Methods: `install()`, `uninstall()`, `start()`, `stop()`, `getService()`
  - Platform support: Windows (Windows Services), Linux (systemd), macOS (launchd)

- **`message-box`** (dialog display)
  - Purpose: Cross-platform dialog boxes
  - Methods: `create()` with title, caption, timeout, buttons
  - Requirements:
    - Linux: Zenity or KDialog
    - Windows: Native Win32
    - macOS: osascript

- **`user-sessions`** (privilege detection)
  - Purpose: Detect user privileges and sessions
  - Methods: Check for root/administrator
  - Platform support: Cross-platform

#### Platform Binary Dependencies

**Linux:**
- **zenity** or **kdialog** (optional, for GUI)
  - Purpose: Display graphical dialogs
  - Fallback: Text-based CLI if unavailable

**Windows:**
- **No external dependencies**
  - Uses native Win32 API

**macOS:**
- **osascript** (standard on macOS)
  - Purpose: AppleScript dialogs
  - Location: `/usr/bin/osascript`

#### Dependency Summary

| Dependency Type | Module/Binary | Required | Platform-Specific |
|----------------|---------------|----------|-------------------|
| Node.js Core | fs | Yes | No |
| Node.js Core | child_process | Yes | No |
| MeshAgent | service-manager | Yes | No |
| MeshAgent | message-box | Yes | No |
| MeshAgent | user-sessions | Yes | No |
| System Binary | zenity/kdialog | Optional (Linux GUI) | Linux only |
| System Binary | osascript | Yes (macOS GUI) | macOS only |

---

### Technical Notes

**Executable Embedding:**

The module uses a clever technique to embed JavaScript and configuration into the executable:
1. Appends module code to binary
2. Adds size metadata
3. Includes magic GUID for validation
4. Runtime extracts and executes embedded code

This creates self-contained installers that don't require separate configuration files.

**Privilege Detection and Elevation:**

The module detects insufficient privileges and provides user-friendly guidance:
- Linux: "Please try again with sudo."
- Windows: "Elevated permissions required" (UAC prompt shown)
- macOS: Similar to Linux

**Localization Architecture:**

The translation object is either:
1. Embedded in `.msh` file as `translation` parameter
2. Defaults to English+Korean if not provided

New languages can be added by extending the translation object structure.

**GUI Fallback:**

If graphical components unavailable:
1. Module detects absence (e.g., no Zenity on Linux)
2. Displays error message with instructions
3. Lists command-line alternatives
4. Users can still use text-based interface

**Installation Safety:**

The installer includes safety checks:
- Detects existing agent before installation
- Prevents duplicate installations
- Validates configuration before proceeding
- Provides clear success/failure feedback

**Connect Mode Use Case:**

Temporary connection mode is useful for:
- Initial diagnostics before committing to installation
- Short-term support sessions
- Testing connectivity and configuration
- Scenarios where persistent installation not desired

## Summary

The interactive.js module is a **cross-platform graphical installer** for MeshAgent, supporting Linux, Windows, and macOS with platform-appropriate UI. It provides user-friendly installation, updating, and connection management with multi-language support.

**Key features:**
- Graphical installation wizard with dialog boxes
- Multi-language support (English, Korean, extensible)
- Self-extracting executable with embedded configuration
- Installation, update, connect, and uninstall modes
- Automatic privilege detection and elevation prompts
- Service management integration
- Status display (installed, running, not installed)
- Fallback to command-line interface if GUI unavailable
- .msh configuration file parsing
- Temporary connect mode without installation

**Platform implementations:**
- **Linux:** Zenity/KDialog dialogs, systemd services
- **Windows:** Native Win32 message boxes, Windows Services
- **macOS:** osascript/AppleScript dialogs, launchd services

The module is used to provide end-users with an intuitive installation experience for MeshAgent, eliminating the need for complex command-line procedures. It bundles configuration directly into the executable, making deployment simple and foolproof for non-technical users.
