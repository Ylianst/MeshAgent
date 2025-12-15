# MeshAgent Documentation

This directory contains comprehensive documentation for the MeshAgent project, including command reference, architecture documentation, module references, and platform-specific guides.

## Directory Structure

### `meshagent-modules/`
Comprehensive documentation for all 103+ MeshAgent JavaScript modules. Each `.md` file corresponds to a module in the `/modules` directory and contains:
- Complete module API documentation
- Platform support analysis with exclusion reasoning
- Detailed function documentation with line numbers
- Parameters, return values, and exceptions
- Step-by-step process flows
- Usage examples and code samples
- Security considerations and technical notes
- Module dependencies and cross-references

**Recently Added Modules (macOS-specific):**
- `logger.js` - Professional logging with timestamps and log levels
- `macOSHelpers.js` - macOS platform helpers for bundle detection and launchd management
- `security-permissions.js` - Security permissions management for critical MeshAgent files

**Cross-Platform Modules:**
- `agent-installer.js` - Agent installation and upgrade orchestration
- `service-manager.js` - Service lifecycle management across platforms
- `dhcp.js` - DHCP client functionality
- `wifi-scanner.js` - WiFi network scanning
- `DeviceManager.js` - Device management utilities
- `service-host.js` - Service hosting functionality
- `kvm-helper.js` - KVM (Keyboard, Video, Mouse) helpers
- And 95+ more modules...

**Platform-Specific Modules:**
- `mac-*` - macOS-specific utilities (powerutil, etc.)
- `win-*` - Windows-specific utilities (registry, WMI, COM, etc.)
- `linux-*` - Linux-specific utilities (dbus, GNOME helpers, etc.)

See `meshagent-modules/__Index_Modules__.md` for complete module index.

---

## Command Reference

### `meshagent-commands.md`
Complete reference for all MeshAgent command-line options:
- **Information Commands**: `-nodeid`, `-version`, `-info`, `-agentHash`, `-lang`
- **Installation Commands**:
  - Installation Assistant GUI (`-show-install-ui`)
  - Command-line installation (`-install`, `-upgrade`, `-uninstall`, `-fulluninstall`)
- **Execution Commands**: `-exec`, `-b64exec`, `-daemon`
- **Configuration Commands**: `-export`, `-import`, `-update`
- **Development Commands**: `-kvm0`, `-kvm1`, and debugging tools
- **Appendix**: Command parsing, validation, and platform-specific behavior

---

## macOS-Specific Documentation

### Installation & Configuration

- **`macos-install-assistant.md`** - Installation Assistant GUI documentation:
  - Graphical installation wizard features and workflows
  - Installation vs upgrade detection
  - Configuration file discovery
  - Permission checking and validation
  - User interface components and behavior
  - Installation path validation and security
  - Progress tracking and error handling

### Permissions & Security

- **`macos-tcc-permissions.md`** - TCC (Transparency, Consent, and Control) permissions system:
  - Accessibility, Full Disk Access, and Screen Recording permissions
  - Architecture and process model (`-check-tcc` child process via `launchctl asuser`)
  - Real-time permission detection methods
  - TCC permissions window UI implementation
  - Fire-and-forget spawning with direct database access
  - Database storage and preferences
  - Permission verification strategies

### Architecture

- **`macos-KVM-Architecture.md`** - KVM (remote desktop) architecture on macOS:
  - Screen capture and remote desktop implementation
  - Permission requirements and detection
  - Architecture diagrams and component interaction
  - Security considerations

- **`macOS-ServiceID-System.md`** - ServiceID naming and management system:
  - Reverse DNS-style composite format (`meshagent.serviceName.companyName`)
  - Multi-tenancy and service variant support
  - Input sanitization and validation rules
  - Storage mechanisms and resolution priority
  - LaunchDaemon/LaunchAgent identifier management
  - Real-world examples and implementation reference

---

## Original MeshAgent Documentation

### `Ylianst_MeshAgent/`
Original MeshAgent documentation from the Ylianst repository. Contains foundational architecture and design documentation.

#### Architecture & Design
- **`Architecture.md`** - Core architecture documentation:
  - Agent certificates and security model
  - Protocol specifications (WebSocket, binary protocol)
  - Connection handling and tunneling
  - Design decisions and trade-offs
  - Server-Agent-Web application interaction model

- **`Files.md`** - Overview of key source files in the codebase
- **`ReleaseNotes.md`** - Release history and version changelog

#### `files/`
Detailed documentation for core MicroStack library components:
- `ILibAsyncServerSocket.md` - Async server socket implementation
- `ILibAsyncSocket.md` - Async socket handling
- `ILibAsyncUDPSocket.md` - Async UDP socket support
- `ILibCrypto.md` - Cryptographic functions
- `ILibIPAddressMonitor.md` - IP address monitoring
- `ILibMulticastSocket.md` - Multicast socket support
- `ILibParsers.md` - Protocol parsers

#### `testing/`
Testing documentation and quality assurance guides:
- **`ReleaseCheckList.md`** - Pre-release verification checklist
- **`SelfUpdate.md`** - Self-update mechanism testing procedures
- **`UnitTests.md`** - Unit testing guidelines and framework
- **`images/`** - Screenshots and diagrams for testing documentation

---

## Documentation Organization

### For Users
1. **Getting Started**: `meshagent-commands.md` - Learn available commands
2. **Installation**: `macos-install-assistant.md` - GUI installation guide (macOS)
3. **Architecture Overview**: `Ylianst_MeshAgent/Architecture.md` - Understand how MeshAgent works
4. **Release History**: `Ylianst_MeshAgent/ReleaseNotes.md` - Version changes

### For Developers
- **Command Reference**: `meshagent-commands.md` - All CLI commands and options
- **Architecture**: `Ylianst_MeshAgent/Architecture.md` - System design and protocols
- **File Structure**: `Ylianst_MeshAgent/Files.md` - Codebase organization
- **Module APIs**: `meshagent-modules/*.md` - Comprehensive module documentation (103+ modules)
- **Core Libraries**: `Ylianst_MeshAgent/files/*.md` - MicroStack components
- **macOS Specifics**:
  - `macos-tcc-permissions.md` - TCC permissions architecture
  - `macos-install-assistant.md` - Installation GUI implementation
  - `macos-KVM-Architecture.md` - Remote desktop architecture
  - `macOS-ServiceID-System.md` - ServiceID naming and management
  - `meshagent-modules/macOSHelpers.js.md` - macOS helper functions
  - `meshagent-modules/security-permissions.js.md` - Security permissions management
  - `meshagent-modules/logger.js.md` - Logging infrastructure

### For Contributors
- **Testing Guidelines**: `Ylianst_MeshAgent/testing/` - QA procedures
- **Release Checklist**: `Ylianst_MeshAgent/testing/ReleaseCheckList.md` - Pre-release verification
- **Module Documentation**: `meshagent-modules/` - API reference when working with specific modules
- **Code Examples**: `/samples` directory (in project root) - Practical examples

---

## Quick Reference by Topic

### Installation & Deployment
- `meshagent-commands.md` - Command-line installation
- `macos-install-assistant.md` - GUI installation (macOS)
- `meshagent-modules/agent-installer.js.md` - Installation orchestration module
- `meshagent-modules/service-manager.js.md` - Service lifecycle management

### Security & Permissions
- `macos-tcc-permissions.md` - TCC permissions system (macOS)
- `meshagent-modules/security-permissions.js.md` - File permissions management
- `Ylianst_MeshAgent/Architecture.md` - Certificates and protocol security

### Remote Desktop (KVM)
- `macos-KVM-Architecture.md` - KVM architecture on macOS
- `meshagent-modules/kvm-helper.js.md` - KVM helper utilities
- `meshagent-commands.md` - KVM testing commands (`-kvm0`, `-kvm1`)

### Platform-Specific Features
- **macOS**:
  - `macos-install-assistant.md`, `macos-tcc-permissions.md`, `macos-KVM-Architecture.md`
  - `macOS-ServiceID-System.md` - ServiceID naming conventions
  - `meshagent-modules/mac-*.md` - macOS-specific modules
  - `meshagent-modules/macOSHelpers.js.md` - Platform helper functions
- **Windows**: `meshagent-modules/win-*.md` - Windows-specific modules
- **Linux**: `meshagent-modules/linux-*.md` - Linux-specific modules

### Logging & Debugging
- `meshagent-modules/logger.js.md` - Logging infrastructure
- `meshagent-modules/util-agentlog.js.md` - Agent logging utilities
- `meshagent-commands.md` - Debug commands (`-exec`, `-b64exec`)

---

## Module Documentation Format

All module documentation in `meshagent-modules/` follows a consistent, comprehensive format:

1. **Module Overview** - Purpose and brief description
2. **Platform Support** - Supported/excluded platforms with reasoning
3. **Functionality** - Detailed purpose and use cases
4. **Key Functions/Methods** - For each function:
   - Line numbers in source code
   - Purpose and process flow
   - Parameters with types and descriptions
   - Return values and exceptions
   - Platform-specific behavior
   - Technical notes and security considerations
5. **Usage Examples** - Practical code examples
6. **Dependencies** - Required modules and binaries

This format provides developers with everything needed to understand and use each module effectively.

---

## Related Documentation

- **Build Instructions**: See `/README.md` in project root
- **Code Samples**: See `/samples` directory for practical examples
- **Source Code**: See `/modules` for JavaScript modules
- **Tests**: See `/test` directory for test utilities

---

## Generating/Updating Module Documentation

Module documentation in the `meshagent-modules/` directory is comprehensive and manually maintained to ensure accuracy and detail.

When updating module documentation:
1. Follow the established format (see any file in `meshagent-modules/` as template)
2. Include line numbers for all functions
3. Document all exported functions/methods
4. Explain platform-specific behavior
5. Include security considerations
6. Provide usage examples
7. Cross-reference related modules

---

## Contributing to Documentation

When contributing documentation:
1. **Format**: Use Markdown (`.md` files) with consistent heading structures
2. **Code Examples**: Include practical, working code samples
3. **Clarity**: Keep language clear, concise, and technical
4. **Completeness**: Document all parameters, return values, and exceptions
5. **Platform Specifics**: Clearly indicate platform-specific behavior
6. **Security**: Note security implications and best practices
7. **Cross-References**: Link to related documentation
8. **Update README**: Update this file when adding new documentation sections
9. **Screenshots**: Add images to appropriate subdirectories when helpful

---

## Security Documentation

Security-related topics are documented throughout:
- **Agent Certificates**: `Ylianst_MeshAgent/Architecture.md` - Authentication model
- **Protocol Security**: `Ylianst_MeshAgent/Architecture.md` - Encryption mechanisms
- **File Permissions**: `meshagent-modules/security-permissions.js.md` - Secure file handling
- **TCC Permissions**: `macos-tcc-permissions.md` - macOS privacy permissions
- **Installation Security**: `macos-install-assistant.md` - Path validation and elevation

---

## License

Copyright 2022 Intel Corporation

Licensed under the Apache License, Version 2.0. See the LICENSE file in the project root for details.
