# meshcmd.js

Comprehensive command-line utility for MeshCentral and Intel AMT (Active Management Technology) management. Provides extensive functionality for AMT configuration, remote management, router setup, KVM operations, and WebRTC-based remote access.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support for all features
- Linux - Full support with platform-appropriate features
- macOS (darwin) - Full support with platform-appropriate features
- FreeBSD - Partial support

**Excluded Platforms:**
- None - Module is cross-platform

**Exclusion Reasoning:**

This module has no platform exclusions. It is designed as a comprehensive management tool that adapts to platform capabilities:

- **Intel AMT features:** Only available on Intel hardware with AMT
- **MEI operations:** Require Intel Management Engine drivers
- **KVM functionality:** Platform-specific implementations
- **Routing features:** Network stack dependent

The module automatically detects platform capabilities and enables/disables features accordingly. Not all features are available on all platforms, but the module itself runs everywhere.

## Functionality

### Purpose

The meshcmd module is a Swiss Army knife for MeshCentral and Intel AMT management, providing:

**Intel AMT Management:**
- AMT information gathering (version, UUID, state)
- Activation and deactivation (CCM/ACM modes)
- Configuration management
- Certificate handling
- CIRA (Client Initiated Remote Access) setup

**Audit and Logging:**
- AMT audit log reading and parsing
- Event log retrieval
- State saving and restoration

**KVM Operations:**
- Remote desktop (KVM) session management
- KVM data processing
- Screen capture and control

**LMS (Local Management Service):**
- LMS server implementation
- MEI (Management Engine Interface) integration
- Local AMT access

**MEI Scripts:**
- Execute MEI-based configuration scripts
- Batch AMT operations

**Routing:**
- Network routing between interfaces
- Bridge mode for network forwarding

**MeshCommander:**
- Embedded web-based AMT management interface
- Standalone or LMS-integrated modes

**WebRTC:**
- WebRTC-based remote access
- Data channel management
- Peer-to-peer connectivity

This comprehensive tool is typically used:
- For AMT provisioning and configuration
- During troubleshooting and diagnostics
- To access out-of-band management
- For remote KVM access to systems
- To configure CIRA connections
- As a lightweight management alternative

### Key Function Categories

#### AMT Information Gathering

**getAmtInfo()**
- Retrieves comprehensive AMT information
- Version, build number, SKU
- Control mode (CCM/ACM/None)
- Provisioning state
- Network configuration
- TLS certificates

**getAmtUuid()**
- Gets AMT system UUID
- Used for device identification

**getAmtState()**
- Returns current AMT state object
- Configuration, certificates, settings

---

#### AMT Activation/Deactivation

**activateToCCM()**
- Activates AMT to Client Control Mode (CCM)
- Simpler activation, no certificates required
- Local administrator control

**deactivateCCM()**
- Deactivates AMT from CCM
- Returns to unconfigured state

**activateToACM()**
- Activates AMT to Admin Control Mode (ACM)
- Requires provisioning certificates
- Enterprise remote management

---

#### Audit Log Operations

**readAmtAuditLog()**
- Reads AMT audit log entries
- Parses events (logins, configuration changes, KVM access)
- Returns structured event data

**clearAmtAuditLog()**
- Clears AMT audit log
- Requires admin privileges

---

#### KVM Operations

**kvmGetData()**
- Retrieves KVM screen capture data
- Returns bitmap/framebuffer

**kvmSetData()**
- Sends keyboard/mouse input to AMT KVM
- Remote control commands

**kvmProcessData()**
- Processes KVM data packets
- Handles screen updates, input, protocol

---

#### LMS Operations

**startLms()**
- Starts Local Management Service
- HTTP server on port 16992 (default AMT port)
- Provides local AMT access without network

**setupMeiOsAdmin()**
- Configures MEI for OS administrator access
- Required for some AMT operations

---

#### MEI Scripts

**startMeScript()**
- Executes MEI-based scripts
- Batch AMT configuration
- Automated provisioning

---

#### Routing Features

**startRouter()**
- Starts network routing/bridging
- Forwards traffic between interfaces
- Useful for AMT access on isolated networks

---

#### MeshCommander Integration

**startMeshCommander()**
- Launches embedded MeshCommander web interface
- Browser-based AMT management
- Standalone HTTP server

**startMeshCommanderLms()**
- Integrates MeshCommander with LMS
- Combined local management interface

---

#### WebRTC Operations

**webRtcCleanUp()**
- Cleans up WebRTC connections
- Releases resources

**webRtcSetup()**
- Initializes WebRTC for peer connections
- Configures signaling

---

#### State Management

**saveEntireAmtState()**
- Saves complete AMT configuration to file
- Backup before changes
- Migration tool

**restoreAmtState()**
- Restores AMT configuration from file
- Disaster recovery

---

### Usage

#### Display AMT Information

```bash
# Show AMT version and status
node meshcmd.js amtinfo

# Get AMT UUID
node meshcmd.js amtuuid

# Show detailed AMT state
node meshcmd.js amtstate
```

#### Activate/Deactivate AMT

```bash
# Activate to CCM (simple mode)
node meshcmd.js amtactivateccm --password admin

# Deactivate AMT
node meshcmd.js amtdeactivate

# Activate to ACM (enterprise mode, requires certs)
node meshcmd.js amtactivateacm --cert provisioning.pfx --password certpass
```

#### Audit Log Operations

```bash
# Read audit log
node meshcmd.js amtauditlog

# Save audit log to file
node meshcmd.js amtauditlog --output audit.txt

# Clear audit log
node meshcmd.js amtclearauditlog
```

#### KVM Remote Desktop

```bash
# Start KVM session
node meshcmd.js amtkvm --host 192.168.1.100 --user admin --password password

# KVM with VNC server
node meshcmd.js amtkvm --host 192.168.1.100 --vnc 5900
```

#### Local Management Service

```bash
# Start LMS on default port (16992)
node meshcmd.js startlms

# Start LMS on custom port
node meshcmd.js startlms --port 16993

# Start LMS with MeshCommander
node meshcmd.js startlms --commander
```

#### MeshCommander Web Interface

```bash
# Start MeshCommander on port 3000
node meshcmd.js meshcommander --port 3000

# MeshCommander with HTTPS
node meshcmd.js meshcommander --port 3000 --cert server.crt --key server.key
```

#### Network Routing

```bash
# Route between interfaces
node meshcmd.js route --in eth0 --out wlan0
```

#### Save/Restore State

```bash
# Save AMT state
node meshcmd.js savestate --output amt-config.json

# Restore AMT state
node meshcmd.js restorestate --input amt-config.json
```

---

### Dependencies

#### Node.js Core Modules

- **`fs`** - File system operations
- **`net`** - Network/TCP operations
- **`http`** / **`https`** - HTTP servers
- **`crypto`** - Cryptography
- **`child_process`** - Spawn processes
- Platform support: Cross-platform

#### MeshAgent Module Dependencies

**AMT Stack:**
- **`amt-wsman`** - AMT WSMAN protocol
- **`amt-wsman-duk`** - Duktape WSMAN
- **`amt-xml`** - XML parsing for AMT
- **`amt`** - Core AMT functionality
- **`amt-lme`** - LME (LAN Management Engine)
- **`amt-mei`** - MEI interface
- **`amt-heci`** - HECI (Host Embedded Controller Interface)
- **`amt_heci`** - Alternative HECI

**Remote Access:**
- **`ILibWebRTC`** - WebRTC functionality
- **`kvm-helper`** - KVM session management

**Utilities:**
- **`identifiers`** - System identification
- **`user-sessions`** - User management
- **`service-manager`** - Service control

#### Platform Dependencies

**Intel AMT Requirements:**
- Intel CPU with AMT support
- Intel MEI/HECI drivers
- AMT firmware 6.0+ (for full features)

**MEI/HECI Drivers:**
- **Windows:** Intel ME drivers from Intel or OEM
- **Linux:** `mei` kernel module and `mei_me` driver
- **macOS:** Limited MEI support (depends on hardware)

#### Dependency Summary

| Category | Dependencies |
|----------|--------------|
| Node.js Core | fs, net, http, https, crypto, child_process |
| AMT Stack | amt-wsman, amt-xml, amt, amt-lme, amt-mei |
| Remote Access | ILibWebRTC, kvm-helper |
| Utilities | identifiers, user-sessions, service-manager |
| Hardware | Intel CPU with AMT, MEI drivers |

---

### Technical Notes

**Intel AMT Overview:**

Intel Active Management Technology (AMT) provides out-of-band management:
- Access system even when powered off (S3/S4/S5 states)
- Remote KVM (keyboard/video/mouse)
- Remote power control
- Hardware inventory
- Independent of OS state

**Control Modes:**

- **None:** AMT not activated
- **CCM (Client Control Mode):** Local control, simpler setup
- **ACM (Admin Control Mode):** Remote enterprise control, requires certificates

**WSMAN Protocol:**

AMT uses WSMAN (Web Services Management):
- SOAP-based protocol over HTTP/HTTPS
- Port 16992 (HTTP) or 16993 (HTTPS)
- XML request/response

**CIRA (Client Initiated Remote Access):**

Outbound connection from AMT to management server:
- Traverses firewalls (outbound only)
- TLS tunnel
- Enables remote management without VPN

**LMS (Local Management Service):**

Allows OS applications to access AMT:
- HTTP server on localhost:16992
- No network required
- Same WSMAN protocol
- MEI/HECI backend

**MEI/HECI Interface:**

Hardware interface between CPU and Management Engine:
- Character device: `/dev/mei0` (Linux) or driver (Windows)
- Low-level communication
- Kernel driver required

**KVM Protocol:**

AMT KVM uses proprietary protocol:
- RFB (Remote Framebuffer) based
- Compressed bitmap updates
- Keyboard/mouse event encoding
- JPEG compression for efficiency

**WebRTC Integration:**

Provides modern remote access:
- Peer-to-peer connections
- NAT traversal
- Lower latency than HTTP
- Data channels for KVM

**MeshCommander:**

Web-based AMT management interface:
- HTML5 application
- Runs in browser
- No client software required
- Can be embedded or standalone

**Security Considerations:**

- AMT has full hardware access
- Strong passwords essential
- TLS recommended for network access
- Audit logs track all access
- Regular firmware updates important

**Performance:**

- LMS adds minimal overhead (~5MB RAM)
- KVM performance depends on screen resolution
- WSMAN queries are generally fast (<100ms)
- WebRTC provides best remote desktop performance

## Summary

The meshcmd.js module is a **comprehensive management utility** for MeshCentral and Intel AMT, providing command-line and programmatic access to extensive remote management capabilities across all platforms.

**Key features:**
- Complete Intel AMT management suite
- CCM and ACM activation/deactivation
- Audit log reading and analysis
- KVM remote desktop functionality
- Local Management Service (LMS)
- MEI script execution
- Network routing capabilities
- Embedded MeshCommander web interface
- WebRTC-based remote access
- State save/restore functionality
- CIRA configuration
- Certificate management
- Out-of-band system access

**Platform support:**
- **Cross-platform:** Windows, Linux, macOS, FreeBSD
- **AMT features:** Require Intel hardware with AMT
- **MEI operations:** Require appropriate drivers

The module serves as the primary tool for Intel AMT configuration and management within the MeshCentral ecosystem, providing both interactive command-line usage and programmatic integration. It enables administrators to remotely manage Intel-based systems through out-of-band access, offering capabilities even when systems are powered off or the operating system is unresponsive.
