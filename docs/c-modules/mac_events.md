# mac_events.c

Keyboard and mouse event injection for macOS KVM, translating Windows VK_ key codes to macOS virtual keycodes and synthesizing CGEvents for remote input control.

## Platform
**macOS (darwin) only** - Uses CoreGraphics CGEvent APIs

## Functionality
Enables remote keyboard/mouse control for KVM by:
- Mapping 114 Windows VK_ keycodes to macOS kVK_ codes
- Synthesizing CGEvents for keypresses, mouse moves, clicks, scrolls
- Tracking modifier states (Caps Lock, mouse buttons)
- Getting current user session UID

### Key Functions
- **kvm_send_keyevent()** - Inject keyboard events
- **kvm_send_mouseevent()** - Inject mouse events (move, click, scroll)
- **getCurrentSession()** - Get active console user UID

## Dependencies
- `<CoreGraphics/CoreGraphics.h>` - CGEventPost() for event injection
- `<SystemConfiguration/SystemConfiguration.h>` - Console user detection
- Requires **Accessibility permission** to inject events

## Security
Requires macOS Accessibility TCC permission for event injection to work.

## Cross-References
- [mac_kvm.c](mac_kvm.md) - Main KVM that calls event injection
- [mac_tcc_detection.c](mac_tcc_detection.md) - Checks Accessibility permission

---
**Source:** `meshcore/KVM/MacOS/mac_events.c` | **LOC:** 310 | **Updated:** 2025-11-28
