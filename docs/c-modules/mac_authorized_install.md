# mac_authorized_install.m

Installation Assistant GUI for macOS showing step-by-step installation wizard with authorization prompts, service ID configuration, and TCC permission guidance.

## Platform
**macOS (darwin) only** - Cocoa/AppKit GUI, requires macOS 10.13+

## Functionality
Guides users through meshagent installation:
1. **Welcome Screen** - Introduction and requirements
2. **Service ID Configuration** - Company/service name input
3. **Authorization** - Request root via AuthorizationExecuteWithPrivileges
4. **Installation** - Copy bundle, create LaunchDaemon plist
5. **TCC Permissions** - Launch TCC UI for permission grants
6. **Completion** - Success confirmation

### Key Classes
- **InstallWizardController** - Main NSWindowController
- **NSView** subclasses - Each wizard step (Welcome, Config, Auth, etc.)

### Installation Steps
1. Validates bundle path and working directory
2. Prompts for company name/service name (ServiceID system)
3. Requests root authorization
4. Copies MeshAgent.app to `/Library/Application Support/`
5. Creates LaunchDaemon plist with ServiceID
6. Loads service with `launchctl bootstrap`
7. Launches TCC permissions UI
8. Shows completion screen

## Dependencies
- `<Cocoa/Cocoa.h>` - AppKit GUI framework
- `<Security/Security.h>` - AuthorizationExecuteWithPrivileges
- [mac_bundle_detection.c](mac_bundle_detection.md) - Detects if running from .app
- [mac_plist_utils.c](mac_plist_utils.md) - Plist generation
- [macOSHelpers.js](../meshagent-modules/macOSHelpers.js.md) - ServiceID generation

## Security
- Requires user to authorize with admin password
- Uses AuthorizationExecuteWithPrivileges for root operations
- Validates bundle integrity before installation

## UI Flow
```
Welcome → Config ServiceID → Authorize → Install → TCC Permissions → Done
```

## Cross-References
- [mac_permissions_window.m](mac_permissions_window.md) - TCC UI launched after install
- [macOS ServiceID System](../macOS-ServiceID-System.md) - Service naming
- [macOS Install Assistant](../macos-install-assistant.md) - Design doc

---
**Source:** `meshcore/MacOS/Install_UI/mac_authorized_install.m` | **LOC:** 671 | **Updated:** 2025-11-28
