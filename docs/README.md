# MeshAgent Documentation

This directory contains all documentation for the MeshAgent project, including architecture documentation, module references, and testing guides.

## Directory Structure

### `modules/`
Auto-generated documentation for MeshAgent JavaScript modules. Each `.md` file corresponds to a module in the `/modules` directory and contains:
- Module API documentation
- Function signatures and parameters
- Usage examples
- Module dependencies

**Example modules documented:**
- `dhcp.js` - DHCP client functionality
- `wifi-scanner.js` - WiFi network scanning
- `DeviceManager.js` - Device management utilities
- `service-host.js` - Service hosting functionality
- `kvm-helper.js` - KVM (Keyboard, Video, Mouse) helpers
- And many more...

### macOS-Specific Documentation

- **`macos-tcc-permissions.md`** - Comprehensive guide to MeshAgent's TCC (Transparency, Consent, and Control) permissions system on macOS:
  - Accessibility, Full Disk Access, and Screen Recording permissions
  - Architecture and process model (-tccCheck child process)
  - Real-time permission detection methods
  - TCC permissions window UI implementation
  - Inter-process communication via pipes
  - Database storage and preferences

- **`fda-tutorial-window.md`** - Full Disk Access tutorial window specification:
  - Visual tutorial implementation with draggable app icon
  - Drag-and-drop to System Settings
  - Button state machine and UI layout
  - Helper functions and resource management
  - Complete implementation guide with code examples

### `Ylianst_MeshAgent/`
Original MeshAgent documentation from the Ylianst repository. Contains comprehensive architecture and design documentation.

#### Architecture & Design
- **`Architecture.md`** - Detailed architecture and design documentation covering:
  - Agent certificates and security model
  - Protocol specifications
  - Connection handling
  - Design decisions and trade-offs
  - Server-Agent-Web application interaction

- **`Files.md`** - Overview of key files in the codebase
- **`ReleaseNotes.md`** - Release history and version changes

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
Testing documentation and guides:
- **`ReleaseCheckList.md`** - Pre-release verification checklist
- **`SelfUpdate.md`** - Self-update mechanism testing
- **`UnitTests.md`** - Unit testing guidelines
- **`images/`** - Screenshots and diagrams for testing documentation

## Documentation Organization

### For Users
- Start with `Ylianst_MeshAgent/Architecture.md` for an overview of how MeshAgent works
- Review `Ylianst_MeshAgent/ReleaseNotes.md` for version history and changes

### For Developers
- **Architecture**: `Ylianst_MeshAgent/Architecture.md`
- **File Structure**: `Ylianst_MeshAgent/Files.md`
- **Module APIs**: `modules/*.md` (auto-generated)
- **Core Libraries**: `Ylianst_MeshAgent/files/*.md`
- **Testing**: `Ylianst_MeshAgent/testing/*.md`
- **macOS TCC Permissions**: `macos-tcc-permissions.md` (architecture and implementation)
- **FDA Tutorial Window**: `fda-tutorial-window.md` (UI specification)

### For Contributors
- Review the testing documentation in `Ylianst_MeshAgent/testing/`
- Follow the release checklist in `Ylianst_MeshAgent/testing/ReleaseCheckList.md`
- Consult module documentation in `modules/` when working with specific modules

## Related Documentation

- **Code Samples**: See `/samples` directory for practical examples
- **Tests**: See `/tests` directory for test utilities
- **Main README**: See `/README.md` for project overview and build instructions

## Generating Module Documentation

Module documentation in the `modules/` directory is auto-generated from the JavaScript source code. To regenerate:

```bash
# Documentation generation process details TBD
# (Add specific commands when available)
```

## Contributing to Documentation

When contributing documentation:
1. Use Markdown format (`.md` files)
2. Include code examples where applicable
3. Keep language clear and concise
4. Update this README when adding new documentation sections
5. Use consistent heading structures
6. Add diagrams/images to `testing/images/` when helpful

## Security Documentation

For security-related documentation, particularly regarding:
- Agent certificates and authentication
- Protocol security
- Encryption mechanisms

See the **Agent Certificates** and **Protocol** sections in `Ylianst_MeshAgent/Architecture.md`.

## License

Copyright 2022 Intel Corporation

Licensed under the Apache License, Version 2.0. See the LICENSE file in the project root for details.
