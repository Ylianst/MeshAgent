# win-userconsent.js

Provides Windows User Account Control (UAC) elevation and user consent management. Implements privileged operation execution with user consent dialog support for administrative actions requiring elevation.

## Platform

**Supported Platforms:**
- Windows Vista and later - Full UAC support
- Windows XP and earlier - Limited support (no UAC)

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-userconsent.js is Windows-only** because:

1. **Windows UAC System** - User Account Control is Windows-specific
2. **Privilege Escalation** - Windows elevation model
3. **User Consent Dialogs** - Windows UAC prompts
4. **Registry Elevation** - Windows registry elevation requirements

---

## Functionality

### Core Purpose

win-userconsent.js manages privileged operations:

1. **UAC Elevation** - Execute operations with administrator privileges
2. **User Consent** - Display UAC consent dialogs
3. **Privilege Detection** - Check current privilege level
4. **Registry Access** - Access protected registry keys

### Main Operations

1. **Elevation** - Trigger UAC elevation
2. **Privilege Checks** - Verify current privilege level
3. **Protected Operations** - Execute protected registry/system operations

---

## Summary

win-userconsent.js enables Windows UAC elevation and user consent management for privileged operations requiring administrator approval or execution context switching.
