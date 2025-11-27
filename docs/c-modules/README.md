# MeshAgent C Code Documentation

Comprehensive documentation for all C/Objective-C code in the MeshAgent repository.

**Last Updated:** 2025-11-28
**Documentation Coverage:** Complete (all non-.js code documented)

---

## Documentation Organization

### macOS-Specific Code (Detailed Docs)

**Core Utilities:**
- [mac_bundle_detection.c](mac_bundle_detection.md) - .app bundle detection and working directory management
- [mac_logging_utils.c](mac_logging_utils.md) - Dual-output logging (stderr + file)
- [mac_plist_utils.c](mac_plist_utils.md) - LaunchDaemon plist parsing (CoreFoundation)
- [mac_tcc_detection.c](mac_tcc_detection.md) - TCC permission detection (FDA, Accessibility, Screen Recording)

**KVM (Remote Desktop):**
- [mac_kvm.c](mac_kvm.md) - Main KVM with reversed socket architecture
- [mac_kvm_auth.c](mac_kvm_auth.md) - Code signature authentication for socket connections
- [mac_events.c](mac_events.md) - Keyboard/mouse event injection (CGEvent)
- [mac_tile.c](mac_tile.md) - Screen capture and JPEG/PNG compression

**User Interface (Cocoa/AppKit):**
- [mac_authorized_install.m](mac_authorized_install.md) - Installation Assistant wizard
- [mac_permissions_window.m](mac_permissions_window.md) - TCC permissions UI with real-time polling

**Headers:**
- [_HEADERS_README.md](_HEADERS_README.md) - Quick reference for all macOS headers

---

### Cross-Platform Code (Overview Docs)

**Core Networking Layer:**
- [MICROSTACK_OVERVIEW.md](MICROSTACK_OVERVIEW.md) - **14 files, 35,692 lines**
  - Async I/O (TCP/UDP sockets)
  - HTTP client/server
  - WebRTC data channels
  - Process pipes, crypto, utilities

**JavaScript Runtime:**
- [MICROSCRIPT_OVERVIEW.md](MICROSCRIPT_OVERVIEW.md) - **24 files, 133,214 lines**
  - Duktape JavaScript engine
  - Node.js-compatible APIs (streams, fs, net, child_process)
  - Native function marshaling (FFI)
  - Module system (require())

**Agent Core and KVM:**
- [MESHCORE_OVERVIEW.md](MESHCORE_OVERVIEW.md)
  - agentcore.c - Main agent entry point
  - meshinfo.c - Platform/hardware detection
  - signcheck.c - Code signature verification
  - Linux KVM (4 files) - X11-based remote desktop
  - Windows KVM (2 files) - GDI/DirectX remote desktop
  - zlib (7 files) - Compression library

---

## Quick Navigation

### By Feature

| Feature | Documentation |
|---------|---------------|
| **Installation** | [mac_authorized_install.m](mac_authorized_install.md) |
| **Permissions** | [mac_tcc_detection.c](mac_tcc_detection.md), [mac_permissions_window.m](mac_permissions_window.md) |
| **Remote Desktop (macOS)** | [mac_kvm.c](mac_kvm.md), [macOS KVM Architecture](../macos-KVM-Architecture.md) |
| **Service Management** | [mac_plist_utils.c](mac_plist_utils.md), [macOS ServiceID System](../macOS-ServiceID-System.md) |
| **Networking** | [MICROSTACK_OVERVIEW.md](MICROSTACK_OVERVIEW.md) |
| **JavaScript Engine** | [MICROSCRIPT_OVERVIEW.md](MICROSCRIPT_OVERVIEW.md) |
| **Agent Core** | [MESHCORE_OVERVIEW.md](MESHCORE_OVERVIEW.md) |

### By Platform

**macOS Only:**
- All files in meshcore/MacOS/ and meshcore/KVM/MacOS/
- Requires macOS 10.14+ (most features require 10.15+)
- See [detailed macOS docs](#macos-specific-code-detailed-docs) above

**Linux Only:**
- meshcore/KVM/Linux/ - X11-based KVM
- See [MESHCORE_OVERVIEW.md](MESHCORE_OVERVIEW.md)

**Windows Only:**
- meshcore/KVM/Windows/ - GDI/DirectX KVM
- See [MESHCORE_OVERVIEW.md](MESHCORE_OVERVIEW.md)

**Cross-Platform:**
- microstack/ - Networking (works on all platforms)
- microscript/ - JavaScript runtime (works on all platforms)
- meshcore/agentcore.c - Main agent (cross-platform)

---

## Statistics

| Category | Files | Lines of Code | Documentation |
|----------|-------|---------------|---------------|
| macOS C | 10 | ~3,500 | Detailed (individual .md files) |
| macOS Objective-C | 2 | ~1,400 | Detailed (individual .md files) |
| macOS Headers | 9 | ~400 | Reference doc |
| MicroStack | 14 | 35,692 | Comprehensive overview |
| MicroScript | 24 | 133,214 | Comprehensive overview |
| MeshCore (other) | 11 | ~10,000 | Comprehensive overview |
| **Total** | **70** | **~184,000** | **17 documentation files** |

---

## Documentation Standards

All documentation follows this structure:

**Detailed Docs (macOS files):**
1. **Platform** - Supported platforms and requirements
2. **Functionality** - Purpose and use cases
3. **Dependencies** - Headers, frameworks, libraries
4. **Key Functions** - Function-by-function documentation with signatures
5. **macOS-Specific Details** - Platform quirks, APIs, permissions
6. **Usage Examples** - Working code samples
7. **Technical Notes** - Architecture, performance, security
8. **Cross-References** - Related files and docs
9. **Testing** - How to test functionality

**Overview Docs (microstack/microscript/meshcore):**
1. **Architecture** - Overall design
2. **Components** - File-by-file breakdown
3. **Design Patterns** - Common patterns used
4. **Platform Support** - Cross-platform notes
5. **Performance** - Optimization notes
6. **Security** - Security considerations
7. **Usage** - How MeshAgent uses these modules

---

## Related Documentation

**Architecture Docs:**
- [macOS KVM Architecture](../macos-KVM-Architecture.md) - Reversed socket design
- [macOS ServiceID System](../macOS-ServiceID-System.md) - Service naming and multi-installation
- [macOS Install Assistant](../macos-install-assistant.md) - Installation UI design

**JavaScript Module Docs:**
- [meshagent-modules/](../meshagent-modules/) - JavaScript API documentation
- [macOSHelpers.js](../meshagent-modules/macOSHelpers.js.md) - JavaScript wrapper for C utilities

---

## Contributing

When adding new C code:
1. **macOS-specific:** Create detailed individual .md file
2. **Cross-platform:** Update appropriate OVERVIEW.md file
3. Follow documentation template (see existing files)
4. Update this README.md with new file links

---

## Maintenance

This documentation was generated on 2025-11-28 and covers:
- All C source files (*.c)
- All Objective-C files (*.m)
- All header files (*.h)
- Excludes: JavaScript files (see meshagent-modules/ docs)

**To regenerate:** Re-run documentation process on code changes

---

**Project:** MeshAgent
**Repository:** https://github.com/Ylianst/MeshAgent
**License:** Apache 2.0
**Documented By:** Peet McKinney (with Claude Code)
