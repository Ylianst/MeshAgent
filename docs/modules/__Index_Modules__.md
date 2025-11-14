# MeshAgent Module Documentation Index

## Overview

This directory contains comprehensive documentation for **100 MeshAgent modules** representing the complete module ecosystem for the MeshCentral remote management platform. This unified collection includes modules from both the `modules_macos_NEVER` (52 modules) and `modules_macos` (48 modules) directories, providing complete visibility into platform compatibility and architectural decisions.

### Repository Organization

The documentation is organized as a **single consolidated reference** combining:
- **Platform-Excluded Modules** (52 modules) - Windows, Linux, Intel AMT/MEI functionality not compatible with macOS
- **Cross-Platform Modules** (48 modules) - Full or partial macOS support with varying capabilities

This documentation serves developers, system administrators, security researchers, and integrators working with MeshAgent deployments across heterogeneous environments.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Module Organization by Platform Support](#module-organization-by-platform-support)
   - [macOS-Compatible Modules](#macos-compatible-modules-full-support)
   - [macOS-Compatible with Limitations](#macos-compatible-modules-limited-support)
   - [macOS-Excluded Modules](#macos-excluded-modules)
3. [Platform Exclusion Categories](#platform-exclusion-categories)
   - [Windows-Only Modules](#windows-only-modules)
   - [Linux-Only Modules](#linux-only-modules)
   - [Intel AMT/MEI Modules](#intel-amtmei-modules)
   - [Cross-Platform But Architecturally Excluded](#cross-platform-but-architecturally-excluded)
4. [Summary Statistics](#summary-statistics)
5. [Quick Reference Tables](#quick-reference-tables)
6. [Module Categories](#module-categories)
7. [Documentation Conventions](#documentation-conventions)

---

## Introduction

### About MeshAgent Modules

MeshAgent is a cross-platform remote management agent that uses a modular architecture for platform-specific and feature-specific functionality. Modules are JavaScript files that may include platform-specific native bindings, system API access, or pure JavaScript implementations.

### Platform Compatibility Philosophy

MeshAgent follows a pragmatic approach to platform support:

**Full Support** - Module works identically across all targeted platforms
**Degraded Support** - Module works but with reduced functionality on some platforms
**No Support** - Module excluded due to fundamental platform limitations

### Why This Documentation Matters

This combined index provides:
- **Deployment Planning** - Understand which features work on which platforms
- **Architecture Decisions** - Learn why modules are excluded from specific platforms
- **Feature Parity Analysis** - Compare capabilities across Windows, Linux, macOS, FreeBSD
- **Security Auditing** - Comprehensive view of agent capabilities
- **Development Guidance** - Platform-specific implementation patterns

---

## Module Organization by Platform Support

### macOS-Compatible Modules (Full Support)

These **48 modules** work fully or substantially on macOS with complete or near-complete feature parity to other platforms.

#### Core Agent Infrastructure (10 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [_agentStatus.js](./_agentStatus.js.md) | Diagnostic tool for querying running agent state via DAIPC | Full support via Unix sockets |
| [_agentNodeId.js](./_agentNodeId.js.md) | Retrieves agent's unique Node ID from installation | Full support |
| [agent-installer.js](./agent-installer.js.md) | Agent installation and upgrade functionality | Full support via launchd |
| [code-utils.js](./code-utils.js.md) | Code utilities and helper functions | Full support (pure JavaScript) |
| [daemon.js](./daemon.js.md) | Service daemonization utilities | Full support with launchd integration |
| [promise.js](./promise.js.md) | Custom Promise/A+ implementation | Full support (pure JavaScript) |
| [update-helper.js](./update-helper.js.md) | Agent self-update orchestration | Full support |
| [util-language.js](./util-language.js.md) | Internationalization and language utilities | Full support |
| [identifiers.js](./identifiers.js.md) | System and hardware identifier generation | Full support |
| [AgentHashTool.js](./AgentHashTool.js.md) | Agent binary hashing and verification | Full support |

#### User Session Management (3 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [user-sessions.js](./user-sessions.js.md) | User session enumeration and lock/unlock detection | Full support via dscl, who, last commands |
| [clipboard.js](./clipboard.js.md) | Cross-platform clipboard access | Full support via message-box integration (pbcopy/pbpaste) |
| [desktop-lock.js](./desktop-lock.js.md) | Desktop lock state detection | Full support via user-sessions |

#### Process and Service Management (2 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [process-manager.js](./process-manager.js.md) | Cross-platform process enumeration | Full support via ps command |
| [service-manager.js](./service-manager.js.md) | Universal service management (3500+ lines) | Full support via launchd with legacy and modern launchctl syntax |

#### Network and Communication (8 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [dhcp.js](./dhcp.js.md) | Mini DHCP client for network configuration queries | Full support (protocol-level implementation) |
| [default_route.js](./default_route.js.md) | Default network route detection | Full support via netstat/route commands |
| [upnp.js](./upnp.js.md) | UPnP discovery and control | Full support (SSDP-based) |
| [proxy-helper.js](./proxy-helper.js.md) | Proxy configuration detection | Full support via scutil |
| [pac.js](./pac.js.md) | Proxy Auto-Configuration (PAC) file parsing | Full support (pure JavaScript) |
| [http-digest.js](./http-digest.js.md) | HTTP Digest authentication | Full support (pure JavaScript) |
| [parseXml.js](./parseXml.js.md) | Lightweight XML parser | Full support (pure JavaScript) |
| [wget.js](./wget.js.md) | HTTP/HTTPS download utility | Full support |

#### File and Archive Operations (5 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [file-search.js](./file-search.js.md) | Recursive file search with pattern matching | Full support |
| [zip-reader.js](./zip-reader.js.md) | ZIP archive reading and extraction | Full support |
| [zip-writer.js](./zip-writer.js.md) | ZIP archive creation | Full support |
| [tar-encoder.js](./tar-encoder.js.md) | TAR archive creation | Full support |
| [crc32-stream.js](./crc32-stream.js.md) | CRC32 checksum calculation for streams | Full support |

#### Utility Modules (10 modules)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [util-descriptors.js](./util-descriptors.js.md) | File descriptor utilities | Full support |
| [util-dns.js](./util-dns.js.md) | DNS resolution utilities | Full support |
| [util-pathHelper.js](./util-pathHelper.js.md) | Path manipulation helpers | Full support |
| [util-agentlog.js](./util-agentlog.js.md) | Agent logging facilities | Full support |
| [util-service-check.js](./util-service-check.js.md) | Service status checking | Full support |
| [dbTool.js](./dbTool.js.md) | Database utilities for agent storage | Full support |
| [child-container.js](./child-container.js.md) | Process isolation and sandboxing | Full support |
| [meshcmd.js](./meshcmd.js.md) | Command-line management tool | Full support |
| [interactive.js](./interactive.js.md) | Interactive agent console | Full support |
| [duktape-debugger.js](./duktape-debugger.js.md) | JavaScript debugger integration | Full support |

#### macOS-Specific Power Management (1 module)

| Module | Description | macOS Status |
|--------|-------------|--------------|
| [mac-powerutil.js](./mac-powerutil.js.md) | macOS power management (sleep/restart/shutdown) | macOS-only, uses osascript and shutdown commands |

---

### macOS-Compatible Modules (Limited Support)

These **10 modules** work on macOS but with degraded functionality or specific limitations.

| Module | Description | macOS Limitations |
|--------|-------------|-------------------|
| [monitor-info.js](./monitor-info.js.md) | Display and monitor information | Partial support; lacks X11-specific features, uses native macOS display APIs |
| [monitor-border.js](./monitor-border.js.md) | Display border detection | Depends on monitor-info, limited without X11 |
| [kvm-helper.js](./kvm-helper.js.md) | KVM (remote desktop) helper functions | Requires macOS-specific screen capture APIs (CGDisplayStream/ScreenCaptureKit) |
| [power-monitor.js](./power-monitor.js.md) | Power state monitoring | Works but uses different APIs than Windows/Linux |
| [message-box.js](./message-box.js.md) | Cross-platform dialog boxes | Full support via osascript or native Cocoa, but implementation differs |
| [toaster.js](./toaster.js.md) | Desktop notification system | Full support via Notification Center, different API than Windows |
| [task-scheduler.js](./task-scheduler.js.md) | Scheduled task management | Limited support; launchd differs from Windows Task Scheduler and cron |
| [smbios.js](./smbios.js.md) | SMBIOS hardware information parsing | Parsing works, but cannot retrieve SMBIOS data on macOS (no system API) |
| [wifi-scanner.js](./wifi-scanner.js.md) | WiFi network scanning | Requires platform-specific implementation (CoreWLAN framework on macOS) |
| [agent-selftest.js](./agent-selftest.js.md) | Comprehensive agent testing | Dialog test explicitly skipped on macOS; other tests would require macOS-specific APIs |

---

### macOS-Excluded Modules

These **42 modules** are fundamentally incompatible with macOS due to platform-specific APIs, hardware limitations, or architectural differences.

#### By Exclusion Reason:

- **Windows-Only**: 25 modules (Windows APIs, Registry, WMI, COM, services)
- **Linux-Only**: 8 modules (Linux kernel, systemd, D-Bus, X11)
- **Intel AMT/MEI**: 10 modules (Intel Management Engine, vPro, AMT firmware)
- **Cross-Platform But Excluded**: 3 modules (Contextual or dependency reasons)

---

## Platform Exclusion Categories

### Windows-Only Modules

**Count: 25 modules**

These modules depend exclusively on Windows-specific APIs, services, or system architecture that have no macOS equivalent.

#### System Management & Configuration (6 modules)

| Module | Windows APIs/Services Used | Why Excluded from macOS |
|--------|---------------------------|------------------------|
| [CSP.js](./CSP.js.md) | Service Control Manager, Intel MEI, Registry | Requires Windows SCM and Intel AMT hardware |
| [DeviceManager.js](./DeviceManager.js.md) | SetupAPI.dll, CfgMgr32.dll | Windows device tree has no macOS equivalent; macOS uses IOKit |
| [win-registry.js](./win-registry.js.md) | Advapi32.dll, Registry APIs | Windows Registry is Windows-exclusive; macOS uses plists and defaults |
| [win-wmi.js](./win-wmi.js.md) | Windows Management Instrumentation | WMI is Windows-only; macOS uses different system information APIs |
| [win-bcd.js](./win-bcd.js.md) | Boot Configuration Data API | Windows boot configuration; macOS uses different boot system |
| [PostBuild.js](./PostBuild.js.md) | Windows build artifact processing | Windows-specific build tools and paths |

#### Security & Cryptography (5 modules)

| Module | Windows APIs Used | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [win-certstore.js](./win-certstore.js.md) | Windows Certificate Store API | macOS uses Keychain Access; completely different architecture |
| [win-crypto.js](./win-crypto.js.md) | CryptAPI, certificate generation | Windows cryptographic APIs; macOS has Security.framework |
| [win-authenticode-opus.js](./win-authenticode-opus.js.md) | Authenticode signature parsing | Windows code signing; macOS uses codesign |
| [win-userconsent.js](./win-userconsent.js.md) | UAC (User Account Control) | UAC is Windows-only; macOS uses TCC (Transparency, Consent, and Control) |
| [win-securitycenter.js](./win-securitycenter.js.md) | Windows Security Center API | Windows Defender/Firewall status; no macOS equivalent |

#### Network & Firewall (3 modules)

| Module | Windows APIs Used | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [win-firewall.js](./win-firewall.js.md) | Windows Firewall COM interface | Windows Firewall API; macOS uses pf (Packet Filter) |
| [wifi-scanner-windows.js](./wifi-scanner-windows.js.md) | Windows WLAN API | Windows WiFi APIs; macOS uses CoreWLAN framework |
| [win-volumes.js](./win-volumes.js.md) | Volume Management API, BitLocker | Windows disk management; macOS uses diskutil and CoreStorage |

#### User Interface & Desktop (7 modules)

| Module | Windows APIs Used | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [win-console.js](./win-console.js.md) | Console API, system tray | Windows console and tray APIs; macOS has different APIs |
| [win-dialog.js](./win-dialog.js.md) | Windows dialog creation APIs | Windows MessageBox etc.; macOS uses Cocoa dialogs |
| [win-deskutils.js](./win-deskutils.js.md) | Desktop wallpaper, mouse trails | Windows desktop APIs; macOS uses different system preferences |
| [win-systray.js](./win-systray.js.md) | System tray icon management | Windows systray API; macOS uses NSStatusItem |
| [win-message-pump.js](./win-message-pump.js.md) | Windows message loop | Windows event model; macOS uses NSRunLoop |
| [win-terminal.js](./win-terminal.js.md) | Windows console terminal emulation | Windows console API; macOS uses /dev/tty |
| [win-virtual-terminal.js](./win-virtual-terminal.js.md) | Windows PseudoConsole (ConPTY) | Windows 10+ feature; macOS has native pty |

#### Process & Task Management (3 modules)

| Module | Windows APIs Used | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [win-tasks.js](./win-tasks.js.md) | Windows Task Scheduler COM | Task Scheduler is Windows-only; macOS uses launchd |
| [win-dispatcher.js](./win-dispatcher.js.md) | IPC framework for user contexts | Windows-specific session architecture |
| [win-com.js](./win-com.js.md) | Component Object Model (COM) | COM is Windows-only technology |

#### Executable Processing (3 modules)

| Module | Windows APIs Used | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [exe.js](./exe.js.md) | PE binary manipulation | Embeds JavaScript in Windows PE binaries |
| [PE_Parser.js](./PE_Parser.js.md) | Windows PE format parsing | Parses Windows executables; macOS uses Mach-O format |
| [MSH_Installer.js](./MSH_Installer.js.md) | PE policy embedding | Modifies Windows PE executables |
| [RecoveryCore.js](./RecoveryCore.js.md) | Recovery mode core with Windows integration | Windows recovery environment integration |

---

### Linux-Only Modules

**Count: 8 modules**

These modules depend on Linux-specific kernel interfaces, systemd, D-Bus, or X Window System.

#### Hardware & System Information (3 modules)

| Module | Linux Dependencies | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [linux-cpuflags.js](./linux-cpuflags.js.md) | /proc/cpuinfo parsing | macOS uses sysctl for CPU information |
| [linux-acpi.js](./linux-acpi.js.md) | acpid daemon, /var/run/acpid.socket | macOS uses IOKit for power management events |
| [lib-finder.js](./lib-finder.js.md) | Linux/FreeBSD shared library discovery | macOS uses different dynamic library system |

#### Desktop Environment & Display (3 modules)

| Module | Linux Dependencies | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [linux-dbus.js](./linux-dbus.js.md) | D-Bus IPC system | macOS uses XPC and distributed notifications |
| [linux-gnome-helpers.js](./linux-gnome-helpers.js.md) | GNOME desktop integration | GNOME is Linux desktop environment |
| [linux-cursors.js](./linux-cursors.js.md) | X11 cursor management | macOS uses Quartz/Cocoa, not X11 |

#### System Configuration (2 modules)

| Module | Linux Dependencies | Why Excluded from macOS |
|--------|-------------------|------------------------|
| [linux-pathfix.js](./linux-pathfix.js.md) | Dynamic PATH modification for systemd | systemd-specific; macOS uses launchd |
| [awk-helper.js](./awk-helper.js.md) | AWK script generation for systemd-logind | systemd-specific session parsing |

---

### Intel AMT/MEI Modules

**Count: 10 modules**

These modules provide Intel Active Management Technology (Intel AMT) and Management Engine Interface (MEI) functionality. macOS hardware fundamentally lacks Intel AMT firmware and MEI interfaces.

#### Core AMT Communication (4 modules)

| Module | Hardware/Firmware Required | Why Excluded from macOS |
|--------|---------------------------|------------------------|
| [amt.js](./amt.js.md) | Intel AMT firmware, vPro chipset | Mac hardware does not include Intel AMT/vPro |
| [amt_heci.js](./amt_heci.js.md) | HECI hardware interface | Mac systems lack HECI hardware interface |
| [amt-mei.js](./amt-mei.js.md) | MEI interface, PTHI communication | Intel Management Engine not present on Macs |
| [amt-lme.js](./amt-lme.js.md) | Local Management Engine | Intel ME exclusive to vPro systems |

#### WSMAN Protocol Stack (3 modules)

| Module | Purpose | Why Excluded from macOS |
|--------|---------|------------------------|
| [amt-wsman.js](./amt-wsman.js.md) | WS-Management protocol for AMT | Pure JavaScript but depends on AMT hardware availability |
| [amt-wsman-duk.js](./amt-wsman-duk.js.md) | WSMAN transport layer | Part of AMT management stack |
| [amt-xml.js](./amt-xml.js.md) | XML parser for WSMAN messages | AMT-specific protocol parsing |

#### AMT Discovery & Scripting (2 modules)

| Module | Purpose | Why Excluded from macOS |
|--------|---------|------------------------|
| [amt-scanner.js](./amt-scanner.js.md) | Network scanner for AMT devices | Discovers AMT-enabled systems (not relevant for Mac management) |
| [amt-script.js](./amt-script.js.md) | Binary script compiler for AMT automation | AMT scripting engine |

#### Hardware Interface (1 module)

| Module | Hardware Required | Why Excluded from macOS |
|--------|------------------|------------------------|
| [heci.js](./heci.js.md) | Host Embedded Controller Interface | HECI hardware only on Intel vPro systems; explicit platform check throws error on macOS |
| [heciRedirector.js](./heciRedirector.js.md) | WebSocket-based HECI redirection | Depends on HECI availability |
| [lme_heci.js](./lme_heci.js.md) | Local MEI protocol with APF tunneling | Intel ME hardware interface |

**Why Intel AMT is Fundamentally Incompatible with macOS:**

1. **Hardware Architecture** - Apple Mac computers use custom firmware and do not include Intel Management Engine (ME) or AMT firmware. Even Intel-based Macs lack the enterprise chipset features required for AMT/vPro.

2. **No HECI Interface** - The Host Embedded Controller Interface (HECI/MEI) is a hardware communication channel that simply doesn't exist on Mac systems.

3. **Apple's Design Philosophy** - Apple provides its own system management technologies rather than supporting Intel's enterprise management platform.

---

### Cross-Platform But Architecturally Excluded

**Count: 4 modules**

These modules are technically cross-platform but excluded from macOS for contextual or dependency reasons.

| Module | Technical Capability | Why Excluded from macOS |
|--------|---------------------|------------------------|
| [smbios.js](./smbios.js.md) | SMBIOS table parsing (pure JavaScript) | Cannot retrieve SMBIOS data on macOS (no system API); primarily used for Intel AMT detection |
| [agent-selftest.js](./agent-selftest.js.md) | Comprehensive agent testing framework | Dialog test explicitly skips macOS; Intel AMT tests not applicable; designed for Windows/Linux testing |
| [RecoveryCore.js](./RecoveryCore.js.md) | Recovery mode operations | Recovery environment differs significantly on macOS (Recovery HD vs WinPE) |
| [service-host.js](./service-host.js.md) | Service hosting infrastructure | Windows service model; macOS uses launchd with different architecture |

---

## Summary Statistics

### Overall Module Distribution

| Category | Count | Percentage |
|----------|-------|------------|
| **macOS-Compatible (Full Support)** | 48 | 48.0% |
| **macOS-Compatible (Limited)** | 10 | 10.0% |
| **macOS-Excluded** | 42 | 42.0% |
| **TOTAL MODULES** | **100** | **100%** |

### Platform Exclusion Breakdown

| Exclusion Reason | Count | Percentage of Excluded |
|------------------|-------|----------------------|
| Windows-Only APIs | 25 | 59.5% |
| Linux-Only Features | 8 | 19.0% |
| Intel AMT/MEI Hardware | 10 | 23.8% |
| Architectural/Contextual | 4 | 9.5% |
| **Total Excluded** | **42** | **100%** |

### Feature Parity Analysis

| Platform | Fully Supported Modules | Limited Support | Not Supported | Total Compatibility |
|----------|------------------------|----------------|---------------|-------------------|
| Windows | 91 | 0 | 9 | 91% |
| Linux | 70 | 0 | 30 | 70% |
| macOS | 48 | 10 | 42 | 58% |
| FreeBSD | 84 | 5 | 11 | 89% |

### Module Categories by Functionality

| Category | Total Modules | macOS-Compatible | Percentage |
|----------|--------------|------------------|------------|
| Core Agent Infrastructure | 10 | 10 | 100% |
| User Session Management | 3 | 3 | 100% |
| Process & Service Management | 2 | 2 | 100% |
| Network & Communication | 8 | 8 | 100% |
| File & Archive Operations | 5 | 5 | 100% |
| Utility Modules | 10 | 10 | 100% |
| Power Management | 2 | 2 | 100% |
| Display & Monitoring | 3 | 1 | 33% |
| Windows System Management | 6 | 0 | 0% |
| Windows Security & Crypto | 5 | 0 | 0% |
| Windows UI & Desktop | 7 | 0 | 0% |
| Windows Process Management | 3 | 0 | 0% |
| Windows Binary Processing | 3 | 0 | 0% |
| Linux Hardware & System | 3 | 0 | 0% |
| Linux Desktop & Display | 3 | 0 | 0% |
| Linux System Configuration | 2 | 0 | 0% |
| Intel AMT Core | 4 | 0 | 0% |
| Intel AMT Protocol | 3 | 0 | 0% |
| Intel AMT Discovery | 2 | 0 | 0% |
| Intel AMT Hardware | 3 | 0 | 0% |
| Diagnostic & Testing | 2 | 0 | 0% |
| Recovery & Specialized | 4 | 0 | 0% |

---

## Quick Reference Tables

### Find a Module by Functionality

#### Core Agent Operations
- Installation: `agent-installer.js`, `daemon.js`, `service-manager.js`
- Updates: `update-helper.js`, `AgentHashTool.js`
- Diagnostics: `_agentStatus.js`, `agent-selftest.js` (Windows/Linux only)
- Service Management: `service-manager.js`, `service-host.js` (Windows only)

#### User & Session Management
- User enumeration: `user-sessions.js`
- Clipboard: `clipboard.js`
- Desktop lock: `desktop-lock.js`, `user-sessions.js`

#### System Information
- Processes: `process-manager.js`
- Hardware: `smbios.js` (Windows/Linux only), `DeviceManager.js` (Windows only)
- CPU: `linux-cpuflags.js` (Linux only)
- Identifiers: `identifiers.js`

#### Network Operations
- DHCP: `dhcp.js`
- Routing: `default_route.js`
- UPnP: `upnp.js`
- Proxy: `proxy-helper.js`, `pac.js`
- HTTP: `http-digest.js`, `wget.js`
- WiFi: `wifi-scanner.js`, `wifi-scanner-windows.js` (Windows only)

#### File Operations
- Search: `file-search.js`
- Archives: `zip-reader.js`, `zip-writer.js`, `tar-encoder.js`
- Checksums: `crc32-stream.js`

#### Windows-Specific
- Registry: `win-registry.js`
- WMI: `win-wmi.js`
- Firewall: `win-firewall.js`
- Certificates: `win-certstore.js`, `win-crypto.js`
- UI: `win-dialog.js`, `win-systray.js`, `win-console.js`
- Tasks: `win-tasks.js`

#### Linux-Specific
- D-Bus: `linux-dbus.js`
- ACPI: `linux-acpi.js`
- GNOME: `linux-gnome-helpers.js`
- X11: `linux-cursors.js`

#### Intel AMT
- Core: `amt.js`, `amt_heci.js`, `amt-mei.js`
- Protocol: `amt-wsman.js`, `amt-wsman-duk.js`, `amt-xml.js`
- Discovery: `amt-scanner.js`, `amt-script.js`
- Hardware: `heci.js`, `heciRedirector.js`, `lme_heci.js`
- Configuration: `CSP.js`

---

### Modules by Platform Support Matrix

| Platform Support | Module Count | Key Modules |
|-----------------|--------------|-------------|
| Windows + Linux + macOS + FreeBSD | 35 | Core utilities, networking, file operations, service management |
| Windows + Linux + FreeBSD | 14 | System-specific utilities, some hardware access |
| Windows + Linux | 20 | SMBIOS, advanced system management |
| Windows Only | 25 | Registry, WMI, Windows UI, COM, Task Scheduler |
| Linux Only | 8 | D-Bus, GNOME, X11, systemd utilities |
| macOS Only | 1 | mac-powerutil.js |
| Intel Hardware Only | 10 | AMT, MEI, HECI modules |

---

## Module Categories

### By Primary Function

#### Agent Core & Infrastructure
- Core operations: 10 modules (100% macOS-compatible)
- Installation and updates: 3 modules (100% macOS-compatible)
- Diagnostics and testing: 2 modules (0% macOS-compatible - platform-specific testing)

#### System Management
- Service control: 2 modules (100% macOS-compatible)
- Process management: 1 module (100% macOS-compatible)
- User sessions: 3 modules (100% macOS-compatible)
- Power management: 2 modules (100% macOS-compatible)

#### Windows Platform Services
- System configuration: 6 modules (0% macOS-compatible)
- Security & cryptography: 5 modules (0% macOS-compatible)
- User interface: 7 modules (0% macOS-compatible)
- Network & firewall: 3 modules (0% macOS-compatible)
- Process & task management: 3 modules (0% macOS-compatible)
- Binary processing: 3 modules (0% macOS-compatible)

#### Linux Platform Services
- Hardware & system info: 3 modules (0% macOS-compatible)
- Desktop environment: 3 modules (0% macOS-compatible)
- System configuration: 2 modules (0% macOS-compatible)

#### Intel Management Platform
- AMT core communication: 4 modules (0% macOS-compatible)
- WSMAN protocol stack: 3 modules (0% macOS-compatible)
- AMT discovery & scripting: 2 modules (0% macOS-compatible)
- Hardware interface: 3 modules (0% macOS-compatible)

#### Cross-Platform Utilities
- Network operations: 8 modules (100% macOS-compatible)
- File operations: 5 modules (100% macOS-compatible)
- Utility libraries: 11 modules (100% macOS-compatible)
- XML/Data parsing: 3 modules (100% macOS-compatible)

---

## Documentation Conventions

### File Organization

Each module is documented in a dedicated Markdown file: `<module-name>.js.md`

### Documentation Structure

Every module documentation file includes:

1. **Module Title** - Name and one-sentence summary
2. **Platform Section** - Supported platforms with detailed exclusion reasoning
3. **Functionality** - Purpose, use cases, and capabilities
4. **Key Functions/Methods** - API reference with line numbers
5. **Dependencies** - Node.js modules, MeshAgent modules, system binaries
6. **Usage Examples** - Practical code examples
7. **Technical Notes** - Implementation details, architecture, limitations
8. **Summary** - Quick reference recap

### Platform Support Indicators

**Supported Platforms:**
- Windows (win32)
- Linux
- macOS (darwin)
- FreeBSD
- OpenBSD (specialized)

**Exclusion Keywords:**
- "Not supported"
- "Explicitly excluded"
- "Implicitly excluded"
- "Limited support"
- "Degraded functionality"

### Line Number References

All function and method descriptions include line number references to the source code for easy cross-referencing during development and auditing.

---

## Finding a Module

### By Filename
All modules are listed alphabetically in the sections above with links to their documentation.

### By Platform Compatibility
- **Need macOS support?** See "macOS-Compatible Modules" sections
- **Windows-specific features?** See "Windows-Only Modules"
- **Linux desktop integration?** See "Linux-Only Modules"
- **Intel AMT/vPro?** See "Intel AMT/MEI Modules"

### By Use Case
- **System Management:** service-manager.js, process-manager.js, user-sessions.js
- **Network Configuration:** dhcp.js, default_route.js, proxy-helper.js, upnp.js
- **Security:** win-certstore.js (Windows), win-crypto.js (Windows), win-firewall.js (Windows)
- **Remote Desktop:** kvm-helper.js, clipboard.js, monitor-info.js
- **Hardware Info:** smbios.js (Windows/Linux), DeviceManager.js (Windows), linux-cpuflags.js (Linux)
- **AMT Management:** amt.js, amt-scanner.js, amt-script.js, CSP.js
- **File Operations:** file-search.js, zip-reader.js, zip-writer.js, tar-encoder.js
- **Agent Operations:** agent-installer.js, update-helper.js, daemon.js, service-manager.js

### By Dependency Chain
Some modules depend on others:
- **AMT Stack:** amt.js → amt-wsman.js → amt-wsman-duk.js → amt-xml.js
- **Service Management:** service-manager.js → user-sessions.js → process-manager.js
- **Windows Services:** CSP.js → DeviceManager.js → win-registry.js
- **Clipboard:** clipboard.js → message-box.js (macOS), monitor-info.js (Linux)

---

## Contributing

When adding or updating module documentation:

1. **Follow Documentation Structure** - Use the standard sections outlined above
2. **Include Platform Support** - Clearly state supported/excluded platforms with reasoning
3. **Explain Why Excluded** - Provide technical reasoning for platform exclusions
4. **Document Dependencies** - List all module, library, and binary dependencies
5. **Provide Examples** - Include practical usage examples
6. **Reference Line Numbers** - Include source code line references for functions
7. **Update This Index** - Add the module to appropriate categories in this index
8. **Test Documentation** - Verify all links and code examples work

---

## Version Information

**Documentation Version:** 2.0 (Unified Index)
**Last Updated:** 2025-11-13
**Module Count:** 100 modules (52 from modules_macos_NEVER + 48 from modules_macos)
**MeshAgent Version:** Core agent modules (all platforms)

---

## Architecture Notes

### Module Loading Strategy

MeshAgent uses selective module loading based on platform detection:

```javascript
if (process.platform === 'win32') {
    require('win-registry');  // Windows only
} else if (process.platform === 'darwin') {
    require('mac-powerutil');  // macOS only
} else if (process.platform === 'linux') {
    require('linux-acpi');  // Linux only
}
```

### Binary vs Pure JavaScript

**Binary Modules** (platform-specific native code):
- Windows: _GenericMarshal for DLL access
- Linux: Native MEI/HECI drivers
- All platforms: Platform-specific system calls

**Pure JavaScript Modules** (cross-platform):
- promise.js, parseXml.js, http-digest.js, code-utils.js
- Network protocols (dhcp.js, upnp.js, pac.js)
- File operations (zip-reader.js, zip-writer.js, tar-encoder.js)

### Security Considerations

Many modules require elevated privileges:
- **Windows:** Administrator rights for Registry, WMI, Service Control Manager
- **Linux:** Root for systemd, /proc access, hardware interfaces
- **macOS:** Root for launchd, system preferences, power management
- **Intel AMT:** Local admin/root for HECI device access

### Performance Characteristics

**Fast (Native APIs):**
- Windows: win-registry.js, DeviceManager.js, win-wmi.js
- macOS: service-manager.js (launchd), process-manager.js (ps)

**Moderate (Shell Commands):**
- Linux: systemd commands, ps parsing, dmidecode
- Cross-platform: file operations, network operations

**Slow (External Tools):**
- dmidecode on Linux
- PowerShell queries on Windows
- Complex awk/grep parsing

---

## Related Documentation

- **MeshAgent Installation Guide** - Agent deployment procedures
- **MeshAgent Module Development Guide** - Creating new modules
- **MeshCentral Server Documentation** - Server-side architecture
- **Intel AMT Documentation** - AMT protocol specifications
- **Platform-Specific APIs:**
  - Windows: Registry, WMI, Service Control Manager references
  - Linux: systemd, D-Bus, X11 documentation
  - macOS: launchd, IOKit, Cocoa framework documentation
  - FreeBSD: rc.d, rcctl documentation

---

## Support Matrix Legend

**Full Support** - Module works identically across all targeted platforms with complete feature parity

**Degraded Support** - Module works but with reduced functionality, performance impact, or feature limitations on some platforms

**Limited Support** - Core functionality available but significant features missing or different implementation

**No Support** - Module fundamentally incompatible due to hardware, OS, or architectural limitations

**Explicit Exclusion** - Module contains platform check and throws error on unsupported platforms

**Implicit Exclusion** - Module will fail when loading dependencies not available on platform

---

## Glossary

**AMT** - Intel Active Management Technology; out-of-band management platform
**HECI** - Host Embedded Controller Interface; communication channel to Intel ME
**MEI** - Management Engine Interface; Intel ME hardware interface
**SCM** - Service Control Manager; Windows service management API
**SMBIOS** - System Management BIOS; firmware-level hardware information
**UAC** - User Account Control; Windows privilege elevation
**WMI** - Windows Management Instrumentation; system information API
**launchd** - macOS service management daemon
**systemd** - Linux init system and service manager
**vPro** - Intel platform with AMT and other enterprise management features

---

**Note:** This documentation covers the complete MeshAgent module ecosystem. For macOS-specific deployments, focus on modules in the "macOS-Compatible" sections. For Windows enterprise management with Intel AMT/vPro, 91 modules are relevant. For Linux deployments, 70 modules are applicable.

For questions, contributions, or clarifications, consult the individual module documentation files or the MeshCentral project documentation.

---

**Last Updated:** November 13, 2025
**Total Modules Documented:** 101
**Platform Coverage:** Windows, Linux, macOS, FreeBSD, OpenBSD, pfSense, OPNsense
