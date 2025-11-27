# mac_permissions_window.m

TCC Permissions UI for macOS showing real-time permission status with visual checkmarks, "Open Settings" buttons, and polling to detect permission grants without restart.

## Platform
**macOS (darwin) only** - Cocoa/AppKit GUI, requires macOS 10.14+

## Functionality
Displays live TCC permission status:
- **Full Disk Access** - ✓ or ✗ with "Open Settings" button
- **Accessibility** - ✓ or ✗ with "Open Settings" button
- **Screen Recording** - ✓ or ✗ with "Open Settings" button

### Real-Time Updates
- **Polls every 3 seconds** using NSTimer
- Calls check_all_permissions() from [mac_tcc_detection.c](mac_tcc_detection.md)
- Updates checkmarks instantly when user grants permission
- No restart required - live feedback

### Key Classes
- **PermissionsWindowController** - Main NSWindowController
- **NSTextField/NSImageView** - Permission status display
- **NSButton** - "Open System Settings" actions

### Open Settings Buttons
Each permission has button that opens System Settings to exact panel:
- FDA: `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`
- Accessibility: `com.apple.preference.security?Privacy_Accessibility`
- Screen Recording: `com.apple.preference.security?Privacy_ScreenCapture`

## Dependencies
- `<Cocoa/Cocoa.h>` - AppKit GUI
- [mac_tcc_detection.c](mac_tcc_detection.md) - Permission checks
- NSWorkspace - Open System Settings

## UI Design
```
┌─────────────────────────────────────┐
│ MeshAgent Permissions               │
├─────────────────────────────────────┤
│ ✓ Full Disk Access     [Settings]  │
│ ✗ Accessibility        [Settings]  │
│ ✗ Screen Recording     [Settings]  │
│                                     │
│ Grant all permissions to enable     │
│ remote management features.         │
│                                     │
│              [Continue]             │
└─────────────────────────────────────┘
```

## Polling Architecture
```objc
- (void)startPolling {
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:3.0
                                                       target:self
                                                     selector:@selector(updatePermissionStatus)
                                                     userInfo:nil
                                                      repeats:YES];
}
```

## Security
- Read-only permission checks (no modification)
- Opens System Settings for user to grant (doesn't bypass TCC)

## User Experience
1. User sees ✗ for missing permission
2. Clicks "Open Settings" button
3. System Settings opens to exact panel
4. User enables permission
5. Within 3 seconds, ✗ changes to ✓ (no restart!)
6. All ✓ → Continue button enabled

## Cross-References
- [mac_tcc_detection.c](mac_tcc_detection.md) - Permission detection
- [mac_authorized_install.m](mac_authorized_install.md) - Installation UI that launches this

---
**Source:** `meshcore/MacOS/TCC_UI/mac_permissions_window.m` | **LOC:** 770 | **Updated:** 2025-11-28
