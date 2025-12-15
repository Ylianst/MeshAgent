# macOS TCC Permissions System

> **⚠️ DOCUMENTATION STATUS:** This document describes the OLD `-tccCheck` implementation with IPC pipes.
> **NEW IMPLEMENTATION (December 2025):** See `/Users/peet/GitHub/dev_notes/MeshAgent/TCC/` for current implementation:
> - `tccCheck-new-implementation.md` - Current `-check-tcc` with `launchctl asuser`
> - `launchctl-asuser-analysis.md` - Technical analysis of new approach
> - `tccCheck-old-implementation.md` - Historical documentation (this implementation)
>
> This document is kept for historical reference only.

---

## Overview

MeshAgent on macOS requires three critical system permissions to provide full remote access functionality:

1. **Accessibility** - Required for keyboard/mouse control during remote desktop sessions
2. **Full Disk Access (FDA)** - Required for file transfer, drag-and-drop, and accessing protected directories
3. **Screen Recording** - Required for capturing the screen during remote desktop sessions

This document describes MeshAgent's TCC (Transparency, Consent, and Control) permissions architecture and implementation.

## Architecture

### Process Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Main Daemon Process                       │
│                  (runs as root/service)                      │
│                                                              │
│  • Monitors mesh server connection                          │
│  • Detects remote desktop requests                          │
│  • Spawns -tccCheck child process via fork/execv           │
│  • Communicates via Unix pipe (IPC)                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ fork/exec + pipe
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              -tccCheck Child Process                         │
│           (runs in GUI user session)                         │
│                                                              │
│  • Checks all three permissions                             │
│  • Shows custom Cocoa UI if any missing                     │
│  • Triggers permission prompts via macOS APIs               │
│  • Updates in real-time (1-second polling)                  │
│  • Writes result to pipe on window close                    │
│  • Exits cleanly                                            │
└─────────────────────────────────────────────────────────────┘
```

### When -tccCheck is Spawned

The daemon spawns the `-tccCheck` UI in two scenarios:

1. **Startup** (if permissions missing and not disabled):
   - Location: `meshcore/agentcore.c:5222-5261`
   - Checks `disableTccCheck` database key
   - Only spawns if value ≠ "1"

2. **Remote Desktop Connection** (if permissions missing):
   - Location: `meshcore/agentcore.c:1554-1594`
   - Triggered when remote user initiates KVM session
   - Ensures permissions before allowing desktop access

### Spawn Logic

```c
// Check "do not remind" preference
char value_buf[16];
int disabledLen = ILibSimpleDataStore_Get(agent->masterDb,
    "disableTccCheck", value_buf, sizeof(value_buf));
int should_spawn = 1;

if (disabledLen > 0 && disabledLen < sizeof(value_buf)) {
    value_buf[disabledLen] = '\0';
    if (strcmp(value_buf, "1") == 0) {
        should_spawn = 0;  // Only "1" disables UI
    }
}

if (should_spawn) {
    int tcc_pipe_fd = show_tcc_permissions_window_async(agent->exePath);
    if (tcc_pipe_fd >= 0) {
        TCCPipeMonitor_Create(agent->chain, agent->masterDb, tcc_pipe_fd);
    }
}
```

## Permission Detection Methods

### 1. Accessibility Permission

**API**: `AXIsProcessTrusted()` (silent check)

**Implementation**: `meshcore/MacOS/mac_tcc_detection.c:20-42`

```c
TCC_PermissionStatus check_accessibility_permission(void) {
    Boolean isTrusted = AXIsProcessTrusted();
    return isTrusted ? TCC_PERMISSION_GRANTED_USER
                     : TCC_PERMISSION_DENIED;
}
```

**Status Values**:
- `TCC_PERMISSION_GRANTED_USER` - User explicitly granted permission
- `TCC_PERMISSION_DENIED` - Permission not granted

### 2. Full Disk Access (FDA)

**Method**: Attempt to read a protected file (`/Library/Application Support/.fseventsd`)

**Implementation**: `meshcore/MacOS/mac_tcc_detection.c:44-63`

```c
TCC_PermissionStatus check_fda_permission(void) {
    const char* protected_file = "/Library/Application Support/.fseventsd";
    int fd = open(protected_file, O_RDONLY);

    if (fd >= 0) {
        close(fd);
        return TCC_PERMISSION_GRANTED_USER;
    }

    return (errno == EACCES || errno == EPERM)
        ? TCC_PERMISSION_DENIED
        : TCC_PERMISSION_NOT_DETERMINED;
}
```

**Why This Method**:
- No API exists to check FDA status
- File in `/Library/Application Support/.fseventsd` requires FDA to access
- Reliable cross-version compatibility (macOS 10.14+)

### 3. Screen Recording Permission

**Method**: Check if window names from other processes are visible

**Implementation**: `meshcore/MacOS/mac_tcc_detection.c:65-194`

**Industry Standard Approach** (used by TeamViewer, Splashtop):

```c
TCC_PermissionStatus check_screen_recording_permission(void) {
    pid_t currentPID = getpid();

    // Get all on-screen windows
    CFArrayRef windowList = CGWindowListCopyWindowInfo(
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID
    );

    // Check if we can see window names from OTHER processes
    for (each window) {
        if (window.ownerPID == currentPID) continue;  // Skip own windows
        if (owner is "Dock") continue;                // Skip Dock
        if (owner is "Window Server") continue;       // Skip WindowServer

        // If we can read kCGWindowName, we have screen recording permission
        if (window.kCGWindowName exists and not empty) {
            return TCC_PERMISSION_GRANTED_USER;
        }
    }

    return TCC_PERMISSION_DENIED;
}
```

**Why This Method**:
- **Real-time updates** - Detects changes immediately (no restart needed)
- `CGRequestScreenCaptureAccess()` returns cached value (requires restart)
- Window name visibility is the documented behavior change when permission granted
- Used by commercial remote desktop applications

**Critical Detail**: Must filter "Window Server" (with space), not "WindowServer"

## TCC Permissions Window

### UI Implementation

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m`

**Technology**: Native Cocoa (Objective-C) with NSWindow/NSApplication

**Window Specifications**:
- Size: 600×355 pixels
- Position: Upper-right corner of screen (20px from edges)
- Style: Titled, closable, floating level
- Modal: Yes (blocks until closed)

### UI Components

1. **Header**:
   - Shield icon (SF Symbol: `checkmark.shield`)
   - Title: "Security & Privacy Settings"
   - Description text

2. **Three Permission Sections** (each with):
   - Title label (bold, 13pt)
   - Description text (gray, 12pt, wrapped)
   - "Open Settings" button (or checkmark when granted)

3. **Footer**:
   - "Do not remind me again" checkbox
   - "Finish" button (Enter key equivalent)

### Real-Time Updates

**Polling Mechanism** (Lines 194-207):

```objective-c
- (void)startPeriodicUpdates {
    [self updatePermissionStatus];  // Check immediately

    // Create 1-second timer that works in modal windows
    self.updateTimer = [NSTimer timerWithTimeInterval:1.0
                                                target:self
                                              selector:@selector(updatePermissionStatus)
                                              userInfo:nil
                                               repeats:YES];

    // NSRunLoopCommonModes allows timer to fire in modal event loop
    [[NSRunLoop currentRunLoop] addTimer:self.updateTimer
                                 forMode:NSRunLoopCommonModes];
}
```

**Why Polling**:
- No notification API for TCC permission changes
- 1-second interval provides responsive UI without excessive CPU usage
- Required for screen recording real-time detection

### Button Behavior (Current Implementation)

**Accessibility & Screen Recording Buttons**:

When clicked, these buttons:
1. **Trigger system permission prompt** (adds app to permission list)
2. **Open System Settings** to the appropriate pane

```objective-c
// Accessibility button handler (Lines 218-239)
- (void)openAccessibilitySettings:(id)sender {
    // Trigger prompt
    if (__builtin_available(macOS 10.9, *)) {
        const void *keys[] = { kAXTrustedCheckOptionPrompt };
        const void *values[] = { kCFBooleanTrue };
        CFDictionaryRef options = CFDictionaryCreate(...);

        AXIsProcessTrustedWithOptions(options);  // Shows system dialog
        CFRelease(options);
    }

    // Open Settings
    NSURL* url = [NSURL URLWithString:
        @"x-apple.systempreferences:...Privacy_Accessibility"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

// Screen Recording button handler (Lines 246-259)
- (void)openScreenRecordingSettings:(id)sender {
    // Trigger prompt if not granted
    if (__builtin_available(macOS 10.15, *)) {
        if (!CGPreflightScreenCaptureAccess()) {
            CGRequestScreenCaptureAccess();
        }
    }

    // Open Settings
    NSURL* url = [NSURL URLWithString:
        @"x-apple.systempreferences:...Privacy_ScreenCapture"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}
```

**Full Disk Access Button**:

No API exists to trigger FDA prompt, so it only opens System Settings:

```objective-c
- (void)openFullDiskAccessSettings:(id)sender {
    NSURL* url = [NSURL URLWithString:
        @"x-apple.systempreferences:...Privacy_AllFiles"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}
```

### Button State Transitions

```
Permission Check (every 1 second)
         ↓
    ┌────────────────┐
    │ Not Granted    │ → Shows "Open Settings" button
    │                │   (or "More Info" for FDA - see FDA Tutorial doc)
    └────────────────┘
         ↓ (user grants permission in Settings)
    ┌────────────────┐
    │ Granted        │ → Replaces button with green checkmark icon
    │                │   (SF Symbol: checkmark.circle.fill, 28pt)
    └────────────────┘
```

## Inter-Process Communication (IPC)

### Pipe-Based Communication

**Parent → Child**: Passes pipe file descriptor as `argv[2]`

**Child → Parent**: Writes single byte result before exit

**Implementation**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:483-542`

```c
int show_tcc_permissions_window_async(const char* exe_path) {
    // Create pipe
    int pipefd[2];
    pipe(pipefd);
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);  // Non-blocking read
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);  // Non-blocking write

    pid_t pid = fork();

    if (pid == 0) {
        // Child: close read end, exec with write FD
        close(pipefd[0]);
        char fd_str[16];
        snprintf(fd_str, sizeof(fd_str), "%d", pipefd[1]);

        execv(exe_path, (char*[]){
            "meshagent",
            "-tccCheck",
            fd_str,      // Pipe write FD
            NULL
        });
    }

    // Parent: close write end, return read FD
    close(pipefd[1]);
    return pipefd[0];  // Parent monitors this FD
}
```

### Pipe Monitoring

**Implementation**: `meshcore/agentcore.c:1313-1394`

Uses `TCCPipeMonitor` integrated into MicroStack event loop:

```c
typedef struct TCCPipeMonitor {
    ILibChain_Link;
    int pipe_fd;
    void* masterDb;
} TCCPipeMonitor;

void TCCPipeMonitor_Create(void* chain, void* masterDb, int pipe_fd) {
    TCCPipeMonitor* monitor = malloc(sizeof(TCCPipeMonitor));
    monitor->pipe_fd = pipe_fd;
    monitor->masterDb = masterDb;

    // Register with event loop
    ILibChain_Link_SetupFD(monitor, pipe_fd);
    ILibChain_SafeAdd(chain, monitor);
}

// Called by event loop when data available
void TCCPipeMonitor_ReadHandler(TCCPipeMonitor* monitor) {
    char result;
    ssize_t bytes = read(monitor->pipe_fd, &result, 1);

    if (bytes == 1) {
        if (result == '1') {
            // User checked "Do not remind me again"
            ILibSimpleDataStore_Put(monitor->masterDb,
                "disableTccCheck", "1", 1);
        }
    }

    close(monitor->pipe_fd);
    // Cleanup...
}
```

## Lock File Protection

Prevents multiple TCC UI instances from spawning simultaneously.

**Lock File**: `/tmp/meshagent_tcccheck.lock`

**Implementation**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:22-58`

```c
static int is_tcc_ui_running(void) {
    FILE* f = fopen(TCC_LOCK_FILE, "r");
    if (f == NULL) return 0;

    pid_t pid;
    if (fscanf(f, "%d", &pid) == 1) {
        fclose(f);
        if (kill(pid, 0) == 0) {
            return 1;  // Process is running
        } else {
            unlink(TCC_LOCK_FILE);  // Stale lock, remove
            return 0;
        }
    }

    fclose(f);
    return 0;
}

static void create_lock_file(void) {
    FILE* f = fopen(TCC_LOCK_FILE, "w");
    if (f != NULL) {
        fprintf(f, "%d", getpid());
        fclose(f);
    }
}
```

**Cleanup**: Lock file automatically removed on normal window close

**Stale Locks**: Automatically detected and cleaned by checking if PID still exists

## Disabled Legacy Code

### kvm_check_permission()

**Location**: `meshcore/KVM/MacOS/mac_kvm.c:1341-1377`

**Status**: DISABLED (commented out in `meshcore/agentcore.c:4820`)

**Why Disabled**:
- Old approach showed jarring system prompts at startup
- Replaced by -tccCheck custom UI with better UX
- Would trigger accessibility prompt when launched from Finder (before LAUNCHED_FROM_FINDER check)

**What it did**:
```c
void kvm_check_permission() {
    // Request screen recording (macOS 10.15+)
    if (!CGPreflightScreenCaptureAccess()) {
        CGRequestScreenCaptureAccess();
    }

    // Request accessibility WITH PROMPT (this was the problem)
    const void *keys[] = { kAXTrustedCheckOptionPrompt };
    const void *values[] = { kCFBooleanTrue };
    CFDictionaryRef options = CFDictionaryCreate(...);
    AXIsProcessTrustedWithOptions(options);  // Showed system dialog
}
```

## Database Storage

MeshAgent stores the "Do not remind me again" preference in its database.

**Database Format**: ILibSimpleDataStore (custom binary format, not SQLite)

**Key**: `disableTccCheck`

**Values**:
- `"1"` - Don't show TCC UI (user checked "do not remind")
- `"0"` or missing - Show TCC UI when needed

**Reading**:
```c
char value_buf[16];
int len = ILibSimpleDataStore_Get(db, "disableTccCheck",
                                  value_buf, sizeof(value_buf));
if (len > 0) {
    value_buf[len] = '\0';
    if (strcmp(value_buf, "1") == 0) {
        // UI disabled
    }
}
```

**Writing** (from pipe monitor):
```c
ILibSimpleDataStore_Put(db, "disableTccCheck", "1", 1);
```

## LAUNCHED_FROM_FINDER Protection

Prevents accessibility prompts when user double-clicks MeshAgent.app.

**Implementation**: `meshconsole/main.c:375-382`

**Early Check** (before any TCC API calls):
```c
#ifdef __APPLE__
    // Check VERY EARLY - before MeshAgent_Create() which might call TCC APIs
    if (getenv("LAUNCHED_FROM_FINDER") != NULL) {
        fprintf(stderr, "\nMeshAgent must be installed as a system service.\n");
        fprintf(stderr, "Please run: sudo %s -install\n\n", argv[0]);
        return 0;  // Clean exit
    }
#endif
```

**Environment Variable Set By**: `Info.plist` → `LSEnvironment` dictionary

**Why Important**: Without this early check, `kvm_check_permission()` (now disabled) would show accessibility prompt before we could exit.

## File Structure

```
meshcore/
├── MacOS/
│   ├── mac_tcc_detection.h          # TCC permission checking APIs
│   ├── mac_tcc_detection.c          # Permission detection implementations
│   └── TCC_UI/
│       ├── mac_permissions_window.h # UI function declarations
│       ├── mac_permissions_window.m # Cocoa UI implementation
│       └── tcc_ui_test              # Standalone test executable
├── agentcore.c                      # Main daemon (spawns -tccCheck, pipe monitor)
└── KVM/MacOS/
    └── mac_kvm.c                    # KVM functionality (kvm_check_permission disabled)

meshconsole/
└── main.c                           # Entry point (-tccCheck handler, LAUNCHED_FROM_FINDER)
```

## Build Integration

**Makefile** (lines 1006-1009):
```makefile
-framework Cocoa \
-framework CoreFoundation \
-framework ApplicationServices \
-framework CoreGraphics \
```

**Compile TCC UI**:
```bash
# Compiled as part of main meshagent binary
gcc ... -c -o meshcore/MacOS/TCC_UI/mac_permissions_window.o \
    meshcore/MacOS/TCC_UI/mac_permissions_window.m
```

**Test Executable**:
```bash
# Standalone test for TCC UI development
gcc -framework Cocoa -framework ApplicationServices -framework CoreGraphics \
    meshcore/MacOS/TCC_UI/tcc_ui_test.m \
    meshcore/MacOS/mac_tcc_detection.c \
    -o meshcore/MacOS/TCC_UI/tcc_ui_test
```

## Testing

### Manual Testing

**Test -tccCheck standalone**:
```bash
# Reset permissions first (in System Settings)
./build/output/meshagent_osx-arm-64 -tccCheck 1
```

**Test with lock file protection**:
```bash
# Start first instance
./build/output/meshagent_osx-arm-64 -tccCheck 1 &

# Try to start second (should be prevented)
./build/output/meshagent_osx-arm-64 -tccCheck 1
# Output: "[TCC-SPAWN] TCC UI already running - not spawning"
```

**Test real-time screen recording detection**:
1. Launch -tccCheck with screen recording denied
2. Screen Recording section shows "Open Settings" button
3. Click button → system prompt appears + Settings opens
4. Grant permission in Settings
5. Within 1 second, button transforms to green checkmark ✓

### Database Testing

**Read current preference**:
```bash
./build/tools/code-utils/macos/meshagent_code-utils -db-get \
    /opt/tacticalmesh/meshagent.db disableTccCheck
```

**Manually disable UI**:
```bash
./build/tools/code-utils/macos/meshagent_code-utils -db-put \
    /opt/tacticalmesh/meshagent.db disableTccCheck "1"
```

**Clear preference**:
```bash
./build/tools/code-utils/macos/meshagent_code-utils -db-delete \
    /opt/tacticalmesh/meshagent.db disableTccCheck
```

## Known Issues and Limitations

### 1. Full Disk Access Detection Timing

**Issue**: FDA check happens BEFORE app has permission

**Scenario**:
1. User sees TCC UI
2. Clicks FDA button → Settings opens
3. User drags app to FDA list
4. User enables toggle
5. **Button doesn't immediately show checkmark**

**Why**: macOS doesn't notify when FDA granted. Next poll (1 second) will detect it.

**Workaround**: 1-second polling acceptable for UX

### 2. Screen Recording Cached Value

`CGPreflightScreenCaptureAccess()` returns cached value that doesn't update until restart.

**Solution**: Use `CGWindowListCopyWindowInfo()` instead (implemented)

### 3. Window Server Name Variation

WindowServer process name is "Window Server" (with space) on some macOS versions.

**Solution**: Filter both "WindowServer" and "Window Server" (lines 85-88)

### 4. Bundle vs. Binary Execution

**Issue**: Resource loading fails when running binary directly (not from .app bundle)

**Scenario**: Development testing with `./meshagent -tccCheck`

**Solution**: Use fallbacks in resource loading functions

### 5. Multiple Instances Prevention

**Issue**: If app crashes, stale lock file prevents new instance

**Solution**: Check if PID in lock file is still alive (implemented)

## Security Considerations

### 1. Executable Path Validation

`exe_path` is obtained via `_NSGetExecutablePath()`, which is trusted system API.

No user input in path → no injection risk.

### 2. Pipe File Descriptor Inheritance

Child process inherits write-end FD from parent via `execv()`.

**Safe** because:
- FD is created by parent
- Child only writes single byte
- Parent validates before using result

### 3. Lock File Race Conditions

**Potential Race**: Two processes check lock file simultaneously

**Mitigation**:
- Check is atomic (file exists or doesn't)
- PID validation prevents stale locks
- Consequence of race is minor (two windows appear briefly)

### 4. Resource Loading

Screenshot image loaded from bundle `Contents/Resources/` (code-signed).

**Safe** because:
- Bundle signature validates all resources
- No user-controlled paths
- Failure to load image is graceful (no crash)

## Future Enhancements

### Proposed: FDA Tutorial Window

See `fda-tutorial-window.md` for detailed specification.

**Summary**:
- Visual tutorial with System Settings screenshot
- Draggable MeshAgent icon
- Step-by-step instructions
- "More Info" button when FDA not granted

### Proposed: Notification-Based Updates

Replace polling with distributed notifications (if API becomes available).

**Current**: No macOS API exists for TCC change notifications

**Future**: Monitor for new APIs in macOS releases

### Proposed: Accessibility Quick Actions

Add ability to request permissions via command-line flags:
```bash
meshagent -request-accessibility
meshagent -request-screen-recording
```

**Use Case**: MDM/deployment automation scripts

## References

### Apple Documentation

- [TCC Framework](https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources)
- [Accessibility API](https://developer.apple.com/documentation/applicationservices/1426690-axisprocesstrusted)
- [Screen Capture API](https://developer.apple.com/documentation/avfoundation/cameras_and_media_capture/requesting_authorization_for_media_capture_on_macos)
- [CGWindowListCopyWindowInfo](https://developer.apple.com/documentation/coregraphics/1455137-cgwindowlistcopywindowinfo)

### Related Code

- **Pipe Monitor**: `meshcore/agentcore.c:1313-1394`
- **Permission Detection**: `meshcore/MacOS/mac_tcc_detection.c`
- **UI Implementation**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m`
- **Entry Point**: `meshconsole/main.c:651-712`

### External Resources

- [macOS TCC Database Structure](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive) (for understanding system TCC)
- [SF Symbols Reference](https://developer.apple.com/sf-symbols/) (for UI icons)

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-21 | 1.0 | Initial documentation covering TCC architecture, permission detection, and UI implementation |
