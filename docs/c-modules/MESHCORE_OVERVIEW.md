# MeshCore - Agent Core and Platform-Specific Code

Core agent implementation and platform-specific KVM/utilities.

## Agent Core Files

### agentcore.c (6,919 lines)
**Purpose:** Main MeshAgent application entry point

**Key Functions:**
- `main()` - Agent startup, initialization
- Connection management to MeshServer
- Module loading and lifecycle
- Certificate validation
- Update handling

**Platforms:** All (Windows, Linux, macOS, FreeBSD)

**Architecture:**
- Initializes MicroStack chain
- Loads Duktape JavaScript engine
- Executes `agentcore.js` (JavaScript agent logic)
- Manages server WebSocket connections
- Handles updates and self-restart

---

### meshinfo.c
**Purpose:** Agent metadata and identification

**Key Functions:**
- Platform detection (OS, architecture)
- Hardware info (CPU, memory, disk)
- Network interfaces enumeration
- Agent version information

**Used For:** Reported to MeshServer, displayed in console

---

### signcheck.c
**Purpose:** Code signature verification for updates

**Key Functions:**
- Verify Authenticode signatures (Windows)
- Verify code signatures (macOS)
- Update authenticity validation

**Security:** Ensures updates are from trusted source

---

### dummy.c
**Purpose:** Placeholder/stub file (minimal/unused)

---

## Compression (zlib)

**Files:** adler32.c, deflate.c, inflate.c, inffast.c, inftrees.c, trees.c, zutil.c

**Purpose:** zlib compression library (standard deflate/gzip)

**Use Cases:**
- Compress KVM tile data
- HTTP gzip encoding
- File compression

**Third-Party:** zlib library (https://zlib.net)

**Integration:** Linked into agent for compression needs

---

## Linux KVM

### linux_kvm.c
**Purpose:** Linux KVM main implementation

**Architecture:** Uses X11/Wayland for screen capture and input

**Key Features:**
- X11 screen capture (XGetImage)
- Wayland support (future/partial)
- Input injection via XTest extension
- Multi-display support

---

### linux_tile.c
**Purpose:** Linux screen tile capture and compression

**Methods:**
- X11 XGetImage for screen capture
- JPEG/PNG compression
- Delta compression (skip unchanged tiles)

---

### linux_events.c
**Purpose:** Linux input event injection

**Methods:**
- XTest extension for keyboard/mouse
- Event translation (VK codes → X11 keysyms)

**Requires:** X11 DISPLAY environment variable

---

### linux_compression.c
**Purpose:** Linux-specific compression optimizations

---

## Windows KVM

### kvm.c (Windows)
**Purpose:** Windows KVM implementation

**Architecture:** GDI/DirectX screen capture, SendInput for events

**Key Features:**
- GDI/DirectX screen capture
- Multiple monitor support
- Input injection via SendInput
- Desktop switching (UAC/lock screen)

**Platforms:** Windows 7+

---

### input.c (Windows)
**Purpose:** Windows input event handling

**Methods:**
- SendInput API
- Keyboard/mouse event synthesis
- VK code handling

---

## Cross-Platform Comparison

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Screen Capture | GDI/DirectX | X11 | CoreGraphics |
| Input Injection | SendInput | XTest | CGEvent |
| Permissions | None | X11 access | TCC (Screen Recording, Accessibility) |
| Multi-Display | Yes | Yes | Yes |
| Architecture | Child process | Child process | Reversed socket |

---

## Platform Detection

**agentcore.c** detects platform and loads appropriate KVM module:

```c
#ifdef WIN32
    #include "KVM/Windows/kvm.h"
#elif __linux__
    #include "KVM/Linux/linux_kvm.h"
#elif __APPLE__
    #include "KVM/MacOS/mac_kvm.h"
#endif
```

---

## Build System

**makefile targets:**
- `make ARCHID=5` - Windows x64
- `make ARCHID=6` - Linux x64
- `make ARCHID=16` - Linux ARM
- `make ARCHID=29` - macOS Universal (arm64 + x86_64)

**Conditional Compilation:**
- Platform-specific code wrapped in `#ifdef` blocks
- KVM modules only compiled for target platform

---

## Documentation

- **agentcore.c:** See inline comments (no separate doc)
- **KVM implementations:** See platform-specific READMEs
- **macOS KVM:** [macOS KVM Architecture](../macos-KVM-Architecture.md)

---

**Primary Use:** Core agent application and cross-platform KVM
**Maintained:** Active (2025)
