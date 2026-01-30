#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import "mac_permissions_window.h"
#import "../mac_tcc_detection.h"
#include "../../../microstack/ILibSimpleDataStore.h"
#include "../../../microstack/ILibProcessPipe.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <execinfo.h>
#include <crt_externs.h>
#include <spawn.h>
#import "../mac_ui_helpers.h"  // Shared UI helpers
#include <time.h>
#include "../mac_logging_utils.h"  // Logging utilities
#include <sqlite3.h>
#include <pwd.h>  // For getpwuid

// Lock file to prevent multiple TCC UI processes (built dynamically from executable name)
#include <libgen.h>
#include <mach-o/dyld.h>

static const char* getTCCLockFilePath(void) {
    static char lockPath[PATH_MAX];
    static int initialized = 0;
    if (!initialized) {
        char exePath[PATH_MAX];
        uint32_t size = sizeof(exePath);
        if (_NSGetExecutablePath(exePath, &size) == 0) {
            char *base = basename(exePath);
            if (base != NULL && strlen(base) > 0 && strcmp(base, ".") != 0) {
                snprintf(lockPath, sizeof(lockPath), "/tmp/%s_tcccheck.lock", base);
            } else {
                snprintf(lockPath, sizeof(lockPath), "/tmp/agent_tcccheck.lock");
            }
        } else {
            snprintf(lockPath, sizeof(lockPath), "/tmp/agent_tcccheck.lock");
        }
        initialized = 1;
    }
    return lockPath;
}

// Button tags for identification
#define BUTTON_TAG_ACCESSIBILITY 1
#define BUTTON_TAG_FDA 2
#define BUTTON_TAG_SCREEN_RECORDING 3

// Window layout constants
#define WINDOW_WIDTH 600
#define WINDOW_HEIGHT 355
#define WINDOW_MARGIN 20

// Button layout
#define BUTTON_YPOS_ACCESSIBILITY 235
#define BUTTON_YPOS_FDA 165
#define BUTTON_YPOS_SCREEN_RECORDING 100
#define BUTTON_FRAME_X 440
#define BUTTON_FRAME_WIDTH 140
#define BUTTON_FRAME_HEIGHT 28

// Checkmark layout
#define CHECKMARK_X_OFFSET 494
#define CHECKMARK_SIZE 32

// Icon layout
#define ICON_X 40
#define ICON_Y 295
#define ICON_SIZE 40

// Title label layout
#define TITLE_LABEL_X 90
#define TITLE_LABEL_Y 315
#define TITLE_LABEL_WIDTH 490
#define TITLE_LABEL_HEIGHT 24

// Helper functions for lock file management
static int is_process_running(pid_t pid) {
    return kill(pid, 0) == 0;
}

static int is_tcc_ui_running(void) {
    FILE* f = fopen(getTCCLockFilePath(), "r");
    if (f == NULL) {
        return 0; // No lock file
    }

    pid_t pid;
    if (fscanf(f, "%d", &pid) == 1) {
        fclose(f);
        if (is_process_running(pid)) {
            return 1; // Process is running
        } else {
            // Stale lock, remove it
            unlink(getTCCLockFilePath());
            return 0;
        }
    }

    fclose(f);
    return 0;
}

static void create_lock_file(void) {
    FILE* f = fopen(getTCCLockFilePath(), "w");
    if (f != NULL) {
        fprintf(f, "%d", getpid());
        fclose(f);
    }
}

static void remove_lock_file(void) {
    unlink(getTCCLockFilePath());
}

// Button action handler class
@interface TCCButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, assign) BOOL cancelled;  // Flag to indicate handler is being deallocated
@property (nonatomic, copy) NSString *exePath;  // Path to meshagent executable
@property (nonatomic, assign) uid_t consoleUID;  // Console user ID

- (instancetype)initWithContentView:(NSView*)view exePath:(const char*)path uid:(uid_t)uid;
- (void)openAccessibilitySettings:(id)sender;
- (void)openFullDiskAccessSettings:(id)sender;
- (void)openScreenRecordingSettings:(id)sender;
- (void)updatePermissionStatus;
- (void)updateButtonsWithAccessibility:(TCC_PermissionStatus)accessibility
                                    fda:(TCC_PermissionStatus)fda
                         screenRecording:(TCC_PermissionStatus)screenRecording
                         updateAllButtons:(BOOL)updateAll;
- (void)startPeriodicUpdates;
- (void)stopPeriodicUpdates;
@end

@implementation TCCButtonHandler

- (instancetype)initWithContentView:(NSView*)view exePath:(const char*)path uid:(uid_t)uid {
    self = [super init];
    if (self) {
        _contentView = view;
        _updateTimer = nil;
        _cancelled = NO;
        _exePath = path ? [NSString stringWithUTF8String:path] : nil;
        _consoleUID = uid;
    }
    return self;
}

- (void)dealloc {
    self.cancelled = YES;  // Signal to async blocks that handler is being deallocated
    [self stopPeriodicUpdates];
    [super dealloc];
}

/**
 * Shared helper to update permission buttons based on status
 * Eliminates duplication across updatePermissionStatus, accessibilityPermissionChanged, and checkScreenRecordingAndFDA
 *
 * @param accessibility Accessibility permission status (or TCC_PERMISSION_NOT_DETERMINED to skip)
 * @param fda FDA permission status (or TCC_PERMISSION_NOT_DETERMINED to skip)
 * @param screenRecording Screen Recording permission status (or TCC_PERMISSION_NOT_DETERMINED to skip)
 * @param updateAll If YES, update all buttons; if NO, only update buttons with non-NOT_DETERMINED status
 */
- (void)updateButtonsWithAccessibility:(TCC_PermissionStatus)accessibility
                                    fda:(TCC_PermissionStatus)fda
                         screenRecording:(TCC_PermissionStatus)screenRecording
                         updateAllButtons:(BOOL)updateAll {
    if (self.cancelled || !self.contentView) {
        return;
    }

    // Snapshot subviews to avoid issues if view hierarchy changes during iteration
    NSArray *subviews = [self.contentView subviews];
    for (NSView *subview in subviews) {
        if ([subview isKindOfClass:[NSButton class]]) {
            NSButton *button = (NSButton*)subview;
            NSInteger tag = [button tag];

            // Map button tag to corresponding permission status
            TCC_PermissionStatus status = TCC_PERMISSION_NOT_DETERMINED;
            if (tag == BUTTON_TAG_ACCESSIBILITY) {
                status = accessibility;
            } else if (tag == BUTTON_TAG_FDA) {
                status = fda;
            } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
                status = screenRecording;
            } else {
                continue; // Not a permission button
            }

            // Skip if we're not updating this button and updateAll is NO
            if (!updateAll && status == TCC_PERMISSION_NOT_DETERMINED) {
                continue;
            }

            // Update button display based on status
            if (status == TCC_PERMISSION_GRANTED_USER || status == TCC_PERMISSION_GRANTED_MDM) {
                [self replaceButtonWithSuccessIcon:button];
            } else {
                [self showButton:button];
            }
        }
    }
}

- (void)replaceButtonWithSuccessIcon:(NSButton*)button {
    // Check if button is already showing checkmark (avoid re-applying transformation)
    if ([button image] != nil) {
        return; // Already converted to checkmark
    }

    // Get button's tag to determine original position
    NSInteger tag = [button tag];
    CGFloat yPos;
    if (tag == BUTTON_TAG_ACCESSIBILITY) {
        yPos = BUTTON_YPOS_ACCESSIBILITY;
    } else if (tag == BUTTON_TAG_FDA) {
        yPos = BUTTON_YPOS_FDA;
    } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
        yPos = BUTTON_YPOS_SCREEN_RECORDING;
    } else {
        return;
    }

    // Create filled circle-check icon
    NSImage* icon = mesh_lucideCircleCheckFillIcon(CHECKMARK_SIZE, [NSColor systemGreenColor]);

    // Change button to show checkmark icon instead of text
    [button setImage:icon];
    [button setImagePosition:NSImageOnly];
    [button setTitle:@""];
    [button setBordered:NO];
    [button setBezelStyle:NSBezelStyleRegularSquare];

    // Center checkmark where the button used to be
    [button setFrame:NSMakeRect(CHECKMARK_X_OFFSET, yPos - 20 + (BUTTON_FRAME_HEIGHT - CHECKMARK_SIZE) / 2, CHECKMARK_SIZE, CHECKMARK_SIZE)];
}

- (void)showButton:(NSButton*)button {
    // Check if button is already showing "Open Settings" (avoid re-applying transformation)
    if ([button image] == nil && [[button title] isEqualToString:@"Open Settings"]) {
        return; // Already showing button
    }

    // Restore button to original "Open Settings" appearance
    [button setTitle:@"Open Settings"];
    [button setImage:nil];
    [button setImagePosition:NSImageLeft];
    [button setBordered:YES];
    [button setBezelStyle:NSBezelStyleRounded];

    // Restore original size and position
    NSInteger tag = [button tag];
    CGFloat yPos;
    if (tag == BUTTON_TAG_ACCESSIBILITY) {
        yPos = BUTTON_YPOS_ACCESSIBILITY;
    } else if (tag == BUTTON_TAG_FDA) {
        yPos = BUTTON_YPOS_FDA;
    } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
        yPos = BUTTON_YPOS_SCREEN_RECORDING;
    } else {
        return;
    }

    [button setFrame:NSMakeRect(BUTTON_FRAME_X, yPos - 20, BUTTON_FRAME_WIDTH, BUTTON_FRAME_HEIGHT)];
}

- (void)updatePermissionStatus {
    // Retain self for block's lifetime to prevent use-after-free
    __block TCCButtonHandler *blockSelf = [self retain];

    // Check permissions on background thread to avoid blocking UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            // Check if handler was cancelled
            if (blockSelf.cancelled) {
                [blockSelf release];
                return;
            }

            // Check all permissions for the calling process
            TCC_PermissionStatus accessibility = check_accessibility_permission();
            TCC_PermissionStatus fda = check_fda_permission();
            TCC_PermissionStatus screen_recording = check_screen_recording_permission();

            // Update UI on main thread
            dispatch_async(dispatch_get_main_queue(), ^{
                // Update all buttons using shared helper
                [blockSelf updateButtonsWithAccessibility:accessibility
                                                       fda:fda
                                            screenRecording:screen_recording
                                           updateAllButtons:YES];
                [blockSelf release];  // Release after UI update
            });
        }
    });
}

- (void)startPeriodicUpdates {
    // Check immediately
    [self updatePermissionStatus];

    // Use NSDistributedNotificationCenter to get real-time updates for Accessibility
    // This is how Splashtop and other apps do it - no polling needed!
    [[NSDistributedNotificationCenter defaultCenter]
        addObserver:self
        selector:@selector(accessibilityPermissionChanged:)
        name:@"com.apple.accessibility.api"
        object:nil
        suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];

    // For Screen Recording and FDA, we need light polling since there's no notification
    // Use 3-second interval since we have real-time updates for Accessibility via notification
    // Use __unsafe_unretained to avoid retain cycles (matches Install UI pattern)
    __unsafe_unretained TCCButtonHandler *weakSelf = self;
    self.updateTimer = [NSTimer timerWithTimeInterval:3.0
                                               repeats:YES
                                                 block:^(NSTimer *timer) {
        if (!weakSelf || weakSelf.cancelled) {
            [timer invalidate];
            return;
        }
        // Only check Screen Recording and FDA (Accessibility updated via notification)
        [weakSelf checkScreenRecordingAndFDA];
    }];

    [[NSRunLoop currentRunLoop] addTimer:self.updateTimer forMode:NSRunLoopCommonModes];
}

// Called when Accessibility permission changes (real-time notification)
- (void)accessibilityPermissionChanged:(NSNotification *)notification {
    // Retain self for block's lifetime to prevent use-after-free
    __block TCCButtonHandler *blockSelf = [self retain];

    // Small delay to let the change settle, then check on background thread
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            // Check if handler was cancelled
            if (blockSelf.cancelled) {
                [blockSelf release];
                return;
            }

            TCC_PermissionStatus accessibility = check_accessibility_permission();

            // Update UI on main thread
            dispatch_async(dispatch_get_main_queue(), ^{
                // Update only accessibility button using shared helper
                [blockSelf updateButtonsWithAccessibility:accessibility
                                                       fda:TCC_PERMISSION_NOT_DETERMINED
                                            screenRecording:TCC_PERMISSION_NOT_DETERMINED
                                           updateAllButtons:NO];
                [blockSelf release];  // Release after UI update
            });
        }
    });
}

// Check all permissions (called by timer every 3 seconds)
// This provides a polling fallback for changes that don't fire notifications (e.g., removing via '-' button)
- (void)checkScreenRecordingAndFDA {
    // Retain self for block's lifetime to prevent use-after-free
    __block TCCButtonHandler *blockSelf = [self retain];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            // Check if handler was cancelled before doing expensive work
            if (blockSelf.cancelled) {
                [blockSelf release];
                return;
            }

            // Check all three permissions
            // Accessibility: Catches removal via '-' button (notification doesn't fire for this)
            // FDA: No notification available, polling required
            // Screen Recording: No notification available, polling required
            TCC_PermissionStatus accessibility = check_accessibility_permission();
            TCC_PermissionStatus fda = check_fda_permission();
            TCC_PermissionStatus screen_recording = check_screen_recording_permission();

            dispatch_async(dispatch_get_main_queue(), ^{
                // Update all three buttons using shared helper
                [blockSelf updateButtonsWithAccessibility:accessibility
                                                       fda:fda
                                            screenRecording:screen_recording
                                           updateAllButtons:NO];
                [blockSelf release];  // Release after UI update
            });
        }
    });
}

- (void)stopPeriodicUpdates {
    // Prevent double-stop (called from both windowWillClose and dealloc)
    if (self.cancelled) {
        return;
    }

    // Signal to all async blocks that we're stopping
    self.cancelled = YES;

    // CRITICAL: Clear contentView reference to prevent dangling pointer access
    // After window closes, contentView is deallocated but async blocks might still
    // be queued on the main thread. By nilling this, the check in
    // updateButtonsWithAccessibility: will return early instead of accessing freed memory.
    self.contentView = nil;

    // Remove notification observer
    [[NSDistributedNotificationCenter defaultCenter] removeObserver:self];

    if (self.updateTimer) {
        [self.updateTimer invalidate];
        self.updateTimer = nil;
        // Balance the retain from startPeriodicUpdates (line ~306)
        // Timer block retained self but won't release if externally invalidated
        [self release];
    }
}

- (void)openAccessibilitySettings:(id)sender {
    // Spawn meshagent -request-accessibility as the console user to trigger system prompt
    // Use su to actually run the process as the user (not just audit session)
    if (self.exePath && self.consoleUID > 0) {
        pid_t pid;

        // Get username from UID
        struct passwd *pw = getpwuid(self.consoleUID);
        if (!pw) {
            NSLog(@"[TCC_UI] ERROR: Could not get username for UID %d", self.consoleUID);
            return;
        }

        const char* username = pw->pw_name;
        const char* exePathCStr = [self.exePath UTF8String];

        // Build command string for su -c flag (needs to be single string)
        char commandStr[2048];
        snprintf(commandStr, sizeof(commandStr), "%s -request-accessibility", exePathCStr);

        char* argv[] = {
            "/usr/bin/su",
            "-l",
            (char*)username,
            "-c",
            commandStr,
            NULL
        };

        // Spawn via su (actually changes to user credentials)
        posix_spawn(&pid, "/usr/bin/su", NULL, NULL, argv, NULL);
    }

    // Also open System Settings so user can see MeshAgent in the Accessibility list
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)openFullDiskAccessSettings:(id)sender {
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)openScreenRecordingSettings:(id)sender {
    // Trigger the system permission prompt to add MeshAgent to the Screen Recording list
    if (__builtin_available(macOS 10.15, *)) {
        // Check current permission status
        Boolean hasPermission = CGPreflightScreenCaptureAccess();

        if (!hasPermission) {
            // Call on background thread to avoid blocking UI (API blocks until user responds)
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                @autoreleasepool {
                    CGRequestScreenCaptureAccess();
                }
            });
        }
    }

    // Also open System Settings so user can see MeshAgent was added to the list
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

@end

// Window delegate to handle events
@interface TCCPermissionsWindowDelegate : NSObject <NSWindowDelegate>
@property (nonatomic, assign) BOOL doNotRemindAgain;
@property (nonatomic, assign) BOOL windowClosed;
@property (nonatomic, strong) TCCButtonHandler *buttonHandler;
- (void)checkboxToggled:(NSButton*)sender;
@end

@implementation TCCPermissionsWindowDelegate

- (id)init {
    self = [super init];
    if (self) {
        _doNotRemindAgain = NO;
        _windowClosed = NO;
    }
    return self;
}

- (void)windowWillClose:(NSNotification *)notification {
    _windowClosed = YES;

    [self.buttonHandler stopPeriodicUpdates];

    // Defer stopModal to next run loop iteration to avoid race conditions
    // Allows window closing sequence to complete cleanly before exiting modal loop
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp stopModal];
    });
}

- (void)checkboxToggled:(NSButton*)sender {
    self.doNotRemindAgain = ([sender state] == NSControlStateValueOn);
}

@end

// Helper function to create section with permission name, description, and button
static void createPermissionSection(NSView* contentView, NSString* title, NSString* description, CGFloat yPos, SEL action, id target, NSInteger buttonTag) {
    // Title label (bold)
    NSTextField* titleLabel = mesh_createLabel(title, NSMakeRect(40, yPos, 380, 20), YES);
    [contentView addSubview:titleLabel];

    // Description label (gray, wrapped)
    NSTextField* descLabel = mesh_createLabel(description, NSMakeRect(40, yPos - 35, 380, 32), NO);
    [descLabel setLineBreakMode:NSLineBreakByWordWrapping];
    [[descLabel cell] setWraps:YES];
    [contentView addSubview:descLabel];

    // "Open Settings" button (shifted down 12px from text)
    NSButton* settingsButton = mesh_createRoundedButton(@"Open Settings",
        NSMakeRect(BUTTON_FRAME_X, yPos - 20, BUTTON_FRAME_WIDTH, BUTTON_FRAME_HEIGHT),
        target, action, buttonTag);
    [contentView addSubview:settingsButton];
}

int show_tcc_permissions_window(int show_reminder_checkbox, const char* exe_path, int uid) {
    @autoreleasepool {
        // Create lock file to prevent multiple instances
        create_lock_file();

        // Create the application if it doesn't exist
        [NSApplication sharedApplication];

        // Set activation policy to allow window to show
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        // Create window (upper-right floating)
        NSRect frame = NSMakeRect(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        NSWindow* window = mesh_createFloatingWindow(frame,
            [NSString stringWithFormat:@"%@ - Security & Privacy Settings", mesh_getAgentDisplayName()],
            NSWindowStyleMaskTitled | NSWindowStyleMaskClosable, NO);

        // Get content view
        NSView* contentView = [window contentView];

        // Create button handler with exe_path and uid for spawning permission requests
        TCCButtonHandler* buttonHandler = [[TCCButtonHandler alloc] initWithContentView:contentView exePath:exe_path uid:uid];

        // Create delegate and link button handler
        TCCPermissionsWindowDelegate* delegate = [[TCCPermissionsWindowDelegate alloc] init];
        delegate.buttonHandler = buttonHandler;
        [window setDelegate:delegate];

        // Add shield-check icon (Lucide "shield-check")
        NSImageView* iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(ICON_X, ICON_Y, ICON_SIZE, ICON_SIZE)];
        [iconView setImage:mesh_lucideShieldCheckIcon(ICON_SIZE)];
        [iconView setContentTintColor:[NSColor colorWithWhite:0.2 alpha:1.0]];
        [contentView addSubview:iconView];

        // Add header title
        NSTextField* titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(TITLE_LABEL_X, TITLE_LABEL_Y, TITLE_LABEL_WIDTH, TITLE_LABEL_HEIGHT)];
        [titleLabel setStringValue:@"Security & Privacy Settings"];
        [titleLabel setBezeled:NO];
        [titleLabel setDrawsBackground:NO];
        [titleLabel setEditable:NO];
        [titleLabel setSelectable:NO];
        [titleLabel setFont:[NSFont systemFontOfSize:16 weight:NSFontWeightBold]];
        [titleLabel setTextColor:[NSColor labelColor]];
        [contentView addSubview:titleLabel];

        // Add header description
        NSTextField* headerLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(90, 280, 490, 32)];
        [headerLabel setStringValue:[NSString stringWithFormat:@"Please grant %@ all the required permissions for complete access functionality.", mesh_getAgentDisplayName()]];
        [headerLabel setBezeled:NO];
        [headerLabel setDrawsBackground:NO];
        [headerLabel setEditable:NO];
        [headerLabel setSelectable:NO];
        [headerLabel setFont:[NSFont systemFontOfSize:12]];
        [headerLabel setTextColor:[NSColor secondaryLabelColor]];
        [headerLabel setLineBreakMode:NSLineBreakByWordWrapping];
        [[headerLabel cell] setWraps:YES];
        [contentView addSubview:headerLabel];

        // Add permission sections
        createPermissionSection(
            contentView,
            @"Accessibility",
            @"Accessibility permission is required for this computer to be controlled during a remote session.",
            235,
            @selector(openAccessibilitySettings:),
            buttonHandler,
            BUTTON_TAG_ACCESSIBILITY
        );

        createPermissionSection(
            contentView,
            @"Full Disk Access",
            @"Full Disk Access permission is required for features such as file transfer and drag-and-drop.",
            165,
            @selector(openFullDiskAccessSettings:),
            buttonHandler,
            BUTTON_TAG_FDA
        );

        createPermissionSection(
            contentView,
            @"Screen & System Audio Recording",
            @"Screen & System Audio Recording permission is required for this computer's screen to be viewed during a remote session.",
            100,
            @selector(openScreenRecordingSettings:),
            buttonHandler,
            BUTTON_TAG_SCREEN_RECORDING
        );

        // Add "Do not remind me again" checkbox (only if requested)
        if (show_reminder_checkbox) {
            NSButton* checkbox = mesh_createCheckbox(@"Do not remind me again",
                NSMakeRect(20, 15, 250, 20), NSControlStateValueOff, delegate, @selector(checkboxToggled:));
            [contentView addSubview:checkbox];
        }

        // Add "Finish" button
        NSButton* finishButton = mesh_createRoundedButton(@"Finish", NSMakeRect(490, 15, 90, 32),
            window, @selector(close), 0);
        [finishButton setKeyEquivalent:@"\r"]; // Enter key
        [contentView addSubview:finishButton];

        // Start real-time monitoring using notifications + light polling
        // Accessibility uses NSDistributedNotificationCenter (instant updates like Splashtop!)
        // Screen Recording uses 5-second polling (no notification available)
        [buttonHandler startPeriodicUpdates];

        // Show window and run modal
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];

        [NSApp runModalForWindow:window];

        // Get result
        int result = delegate.doNotRemindAgain ? 1 : 0;

        // Cleanup - window already closed by Finish button, no need to close again
        // [window close];  // Removed: duplicate close causes issues
        remove_lock_file();

        return result;
    }
}

// Async wrapper using posix_spawn() to launch via launchctl asuser
// Spawns: launchctl asuser <uid> <exe_path> -check-tcc
// Fire-and-forget: child handles DB read/write, returns -1 (no pipe)
int show_tcc_permissions_window_async(const char* exe_path, void* pipeManager, int uid) {

    // CRITICAL SAFETY CHECK: NEVER spawn TCC UI during install/upgrade/uninstall operations
    // Check command line arguments for forbidden flags
    char*** argvPtr = _NSGetArgv();
    int* argcPtr = _NSGetArgc();

    if (argvPtr && argcPtr) {
        char** argv = *argvPtr;
        int argc = *argcPtr;

        const char* forbidden_flags[] = {
            "-upgrade", "-install", "-fullinstall",
            "-uninstall", "-fulluninstall", "-update"
        };

        for (int i = 0; i < argc; i++) {
            for (int j = 0; j < 6; j++) {
                if (strcmp(argv[i], forbidden_flags[j]) == 0) {
                    return -1; // Refuse to spawn during install/upgrade operations
                }
            }
        }
    }

    // Check if TCC UI is already running
    if (is_tcc_ui_running()) {
        return -1; // Don't spawn another instance
    }

    // Create pipe for IPC (child writes result, parent reads)
    // NOTE: Currently unused (fire-and-forget mode), but kept for future temp file approach
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }

    // Set read end to non-blocking
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);

    // Convert write-end fd to string for passing via argv
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", pipefd[1]);

    // Build argv for launchctl asuser to spawn TCC check
    // Format: launchctl asuser <uid> <exe_path> -check-tcc
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%d", uid);

    char* const argv[] = {
        "launchctl",        // argv[0]
        "asuser",           // argv[1]
        uid_str,            // argv[2] (user ID)
        (char*)exe_path,    // argv[3] (path to meshagent)
        "-check-tcc",       // argv[4] (flag)
        NULL                // argv terminator
    };


    // Fire-and-forget spawn using posix_spawn
    // This avoids responsible process attribution issues on macOS 15 and earlier
    pid_t pid;
    extern char **environ;
    int spawn_result = posix_spawn(&pid, "/bin/launchctl", NULL, NULL, argv, environ);

    if (spawn_result != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }


    // Close both pipe ends (fire-and-forget mode - no IPC)
    close(pipefd[0]);
    close(pipefd[1]);

    return 0;
}

/**
 * Request Accessibility permission (called by -request-accessibility flag)
 *
 * Calls AXIsProcessTrustedWithOptions with kAXTrustedCheckOptionPrompt to
 * trigger the macOS system dialog:
 * "MeshAgent.app would like to control this computer using accessibility features"
 *
 * This function should be called from a process running as the console user
 * (spawned via posix_spawn with setuid).
 *
 * Returns:
 *   0 on success
 */
int request_accessibility_permission(void) {
    // Check for --log=3 debug mode
    int debug = 0;
    char*** argvPtr = _NSGetArgv();
    int* argcPtr = _NSGetArgc();
    if (argvPtr && argcPtr) {
        for (int i = 0; i < *argcPtr; i++) {
            if (strcmp((*argvPtr)[i], "--log=3") == 0) {
                debug = 1;
                break;
            }
        }
    }

    if (debug) {
        printf("[DEBUG] request_accessibility_permission: Starting\n");
        printf("[DEBUG] request_accessibility_permission: macOS version check...\n");
    }

    if (__builtin_available(macOS 10.9, *)) {
        if (debug) printf("[DEBUG] request_accessibility_permission: macOS 10.9+ detected\n");

        const void *keys[] = { kAXTrustedCheckOptionPrompt };
        const void *values[] = { kCFBooleanTrue };

        if (debug) printf("[DEBUG] request_accessibility_permission: Creating options dictionary\n");
        CFDictionaryRef options = CFDictionaryCreate(
            kCFAllocatorDefault,
            keys,
            values,
            1,
            &kCFCopyStringDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );

        if (debug) printf("[DEBUG] request_accessibility_permission: Calling AXIsProcessTrustedWithOptions\n");
        AXIsProcessTrustedWithOptions(options);

        if (debug) printf("[DEBUG] request_accessibility_permission: Releasing options\n");
        CFRelease(options);

        if (debug) printf("[DEBUG] request_accessibility_permission: Success\n");
    } else {
        if (debug) printf("[DEBUG] request_accessibility_permission: macOS version < 10.9, skipping\n");
    }

    return 0;
}

/**
 * Request Screen Recording permission (called by -request-screenrecording flag)
 *
 * Checks if Screen Recording permission is already granted via CGPreflightScreenCaptureAccess.
 * If not granted, calls CGRequestScreenCaptureAccess to trigger the macOS system dialog.
 *
 * This function should be called from a process running as the console user
 * (spawned via posix_spawn with setuid).
 *
 * Returns:
 *   0 on success
 */
int request_screen_recording_permission(void) {
    // Check for --log=3 debug mode
    int debug = 0;
    char*** argvPtr = _NSGetArgv();
    int* argcPtr = _NSGetArgc();
    if (argvPtr && argcPtr) {
        for (int i = 0; i < *argcPtr; i++) {
            if (strcmp((*argvPtr)[i], "--log=3") == 0) {
                debug = 1;
                break;
            }
        }
    }

    if (debug) {
        printf("[DEBUG] request_screen_recording_permission: Starting\n");
        printf("[DEBUG] request_screen_recording_permission: macOS version check...\n");
    }

    if (__builtin_available(macOS 10.15, *)) {
        if (debug) printf("[DEBUG] request_screen_recording_permission: macOS 10.15+ detected\n");

        if (debug) printf("[DEBUG] request_screen_recording_permission: Checking current permission status\n");
        Boolean hasPermission = CGPreflightScreenCaptureAccess();

        if (debug) printf("[DEBUG] request_screen_recording_permission: Current status = %s\n",
                          hasPermission ? "granted" : "not granted");

        if (!hasPermission) {
            if (debug) printf("[DEBUG] request_screen_recording_permission: Requesting permission via CGRequestScreenCaptureAccess\n");
            CGRequestScreenCaptureAccess();
            if (debug) printf("[DEBUG] request_screen_recording_permission: Request completed\n");
        } else {
            if (debug) printf("[DEBUG] request_screen_recording_permission: Permission already granted, no dialog needed\n");
        }

        if (debug) printf("[DEBUG] request_screen_recording_permission: Success\n");
    } else {
        if (debug) printf("[DEBUG] request_screen_recording_permission: macOS version < 10.15, skipping\n");
    }

    return 0;
}

/**
 * Request Full Disk Access permission (called by -request-fulldiskaccess flag)
 *
 * Checks if FDA is already granted by attempting to open TCC.db read-only.
 * If not granted, shows a custom NSAlert dialog with buttons:
 * - "Open System Settings" - Opens System Settings to FDA pane
 * - "Deny" (default) - Closes dialog
 *
 * Features a composite icon (lock + FDA drive icon).
 * Includes fallback for macOS < 11.0.
 *
 * Returns:
 *   0 on success (dialog shown or FDA already granted)
 */
int request_fda_permission(void) {
    // Check for --log=3 debug mode
    int debug = 0;
    char*** argvPtr = _NSGetArgv();
    int* argcPtr = _NSGetArgc();
    if (argvPtr && argcPtr) {
        for (int i = 0; i < *argcPtr; i++) {
            if (strcmp((*argvPtr)[i], "--log=3") == 0) {
                debug = 1;
                break;
            }
        }
    }

    if (debug) {
        printf("[DEBUG] request_fda_permission: Starting\n");
        printf("[DEBUG] request_fda_permission: Checking current FDA status via TCC.db access test\n");
    }

    // Check if we already have FDA by trying to open TCC.db read-only
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(
        "/Library/Application Support/com.apple.TCC/TCC.db",
        &db,
        SQLITE_OPEN_READONLY,
        NULL
    );

    if (debug) printf("[DEBUG] request_fda_permission: sqlite3_open_v2 result = %d\n", rc);

    if (rc == SQLITE_OK && db != NULL) {
        if (debug) printf("[DEBUG] request_fda_permission: FDA already granted (TCC.db accessible)\n");
        sqlite3_close(db);
        return 0;  // Already have FDA
    }

    if (debug) printf("[DEBUG] request_fda_permission: FDA not granted, will show dialog\n");

    if (db != NULL) {
        sqlite3_close(db);
    }

    // Show custom FDA dialog
    if (debug) printf("[DEBUG] request_fda_permission: Creating NSApplication\n");

    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        if (debug) printf("[DEBUG] request_fda_permission: Creating custom window\n");

        if (debug) printf("[DEBUG] request_fda_permission: Creating composite icon\n");
        // Create composite icon: Lock with FDA icon inset
        NSImage *compositeIcon = [[NSImage alloc] initWithSize:NSMakeSize(64, 64)];
        [compositeIcon lockFocus];

        if (@available(macOS 11.0, *)) {
            if (debug) printf("[DEBUG] request_fda_permission: macOS 11.0+ - using SF Symbols icons\n");

            // Draw orange lock icon (main)
            NSImage *lockIcon = [NSImage imageWithSystemSymbolName:@"lock.fill" accessibilityDescription:nil];
            if (lockIcon) {
                if (debug) printf("[DEBUG] request_fda_permission: Drawing lock icon\n");
                NSImageSymbolConfiguration *lockConfig = [NSImageSymbolConfiguration configurationWithPointSize:64 weight:NSFontWeightRegular];
                lockIcon = [lockIcon imageWithSymbolConfiguration:lockConfig];

                // Tint orange
                [lockIcon lockFocus];
                [[NSColor colorWithRed:1.0 green:0.6 blue:0.0 alpha:1.0] set];
                NSRect lockRect = NSMakeRect(0, 0, lockIcon.size.width, lockIcon.size.height);
                NSRectFillUsingOperation(lockRect, NSCompositingOperationSourceAtop);
                [lockIcon unlockFocus];

                [lockIcon drawInRect:NSMakeRect(0, 0, 64, 64)];
            }

            // Draw blue FDA icon (inset in bottom-right)
            NSImage *fdaIcon = [NSImage imageWithSystemSymbolName:@"internaldrive.fill" accessibilityDescription:nil];
            if (fdaIcon) {
                if (debug) printf("[DEBUG] request_fda_permission: Drawing FDA icon\n");
                // Shrunk to 16pt (20% smaller than original 20pt)
                NSImageSymbolConfiguration *fdaConfig = [NSImageSymbolConfiguration configurationWithPointSize:16 weight:NSFontWeightRegular];
                fdaIcon = [fdaIcon imageWithSymbolConfiguration:fdaConfig];

                // Tint gray
                [fdaIcon lockFocus];
                [[NSColor colorWithRed:0.5 green:0.5 blue:0.5 alpha:1.0] set];
                NSRect fdaRect = NSMakeRect(0, 0, fdaIcon.size.width, fdaIcon.size.height);
                NSRectFillUsingOperation(fdaRect, NSCompositingOperationSourceAtop);
                [fdaIcon unlockFocus];

                // Draw squircle background with light gray fill and subtle border (sized for 16pt icon)
                // Positioned lower to hang below the lock
                NSRect squircleRect = NSMakeRect(36, 0, 24, 24);
                NSBezierPath *squirclePath = [NSBezierPath bezierPathWithRoundedRect:squircleRect
                                                                             xRadius:5.0
                                                                             yRadius:5.0];

                // Fill with medium gray for better contrast
                [[NSColor colorWithWhite:0.85 alpha:1.0] setFill];
                [squirclePath fill];

                // Add subtle border
                [[NSColor colorWithWhite:0.65 alpha:1.0] setStroke];
                [squirclePath setLineWidth:0.5];
                [squirclePath stroke];

                // Draw FDA icon on top of squircle (centered in 24x24 squircle)
                [fdaIcon drawInRect:NSMakeRect(40, 4, 16, 16)];
            }
        } else {
            if (debug) printf("[DEBUG] request_fda_permission: macOS < 11.0 - using fallback caution icon\n");
            // Fallback for macOS < 11.0
            NSImage *cautionIcon = [NSImage imageNamed:NSImageNameCaution];
            if (cautionIcon) {
                [cautionIcon drawInRect:NSMakeRect(0, 0, 64, 64)];
            }
        }

        [compositeIcon unlockFocus];

        if (debug) printf("[DEBUG] request_fda_permission: Creating window with custom layout\n");

        // Create custom panel (styled like system dialog)
        NSPanel *panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 450, 150)
                                                     styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
                                                       backing:NSBackingStoreBuffered
                                                         defer:NO];
        [panel setTitle:@"Full Disk Access"];
        [panel setLevel:NSFloatingWindowLevel];
        [panel center];

        // Create content view with manual layout
        NSView *contentView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 450, 150)];

        // Icon on the left (20px from left, centered vertically in upper area)
        NSImageView *iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(20, 75, 64, 64)];
        [iconView setImage:compositeIcon];
        [contentView addSubview:iconView];

        // Text on the right (with bold first line, positioned lower to add top padding)
        NSTextField *messageField = [[NSTextField alloc] initWithFrame:NSMakeRect(100, 52, 330, 85)];

        // Create attributed string with bold first line and controlled spacing
        NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] init];

        // First line (bold) with paragraph spacing
        NSFont *boldFont = [NSFont boldSystemFontOfSize:13];
        NSMutableParagraphStyle *paragraphStyle = [[NSMutableParagraphStyle alloc] init];
        [paragraphStyle setParagraphSpacing:8.0];  // 8pt space after first line
        NSAttributedString *boldText = [[NSAttributedString alloc] initWithString:@"\"MeshAgent.app\" would like full disk access to this computer's storage.\n"
                                                                        attributes:@{NSFontAttributeName: boldFont,
                                                                                    NSParagraphStyleAttributeName: paragraphStyle}];
        [attrString appendAttributedString:boldText];

        // Second line (regular)
        NSFont *regularFont = [NSFont systemFontOfSize:13];
        NSAttributedString *regularText = [[NSAttributedString alloc] initWithString:@"Grant access to this application in Privacy & Security settings, located in System Settings."
                                                                          attributes:@{NSFontAttributeName: regularFont}];
        [attrString appendAttributedString:regularText];

        [messageField setAttributedStringValue:attrString];
        [messageField setBezeled:NO];
        [messageField setDrawsBackground:NO];
        [messageField setEditable:NO];
        [messageField setSelectable:NO];
        [[messageField cell] setWraps:YES];
        [contentView addSubview:messageField];

        // Buttons at bottom right
        __block BOOL openSettings = NO;

        NSButton *denyButton = [[NSButton alloc] initWithFrame:NSMakeRect(350, 20, 80, 32)];
        [denyButton setTitle:@"Deny"];
        [denyButton setBezelStyle:NSBezelStyleRounded];
        [denyButton setKeyEquivalent:@"\r"];  // Return key
        [denyButton setTarget:nil];
        [denyButton setAction:@selector(stopModalWithCode:)];
        [denyButton setTag:NSModalResponseCancel];
        [contentView addSubview:denyButton];

        NSButton *openButton = [[NSButton alloc] initWithFrame:NSMakeRect(180, 20, 160, 32)];
        [openButton setTitle:@"Open System Settings"];
        [openButton setBezelStyle:NSBezelStyleRounded];
        [openButton setKeyEquivalent:@""];
        [openButton setTarget:nil];
        [openButton setAction:@selector(stopModalWithCode:)];
        [openButton setTag:NSModalResponseOK];
        [contentView addSubview:openButton];

        [panel setContentView:contentView];

        // Activate app and show window
        [NSApp activateIgnoringOtherApps:YES];

        if (debug) printf("[DEBUG] request_fda_permission: Showing modal dialog (blocking)\n");
        NSModalResponse response = [NSApp runModalForWindow:panel];
        [panel orderOut:nil];

        if (debug) printf("[DEBUG] request_fda_permission: User response = %ld (OK=Open Settings, Cancel=Deny)\n", (long)response);

        if (response == NSModalResponseOK) {
            if (debug) printf("[DEBUG] request_fda_permission: Opening System Settings to FDA pane\n");
            // Open System Settings to FDA pane
            NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
            [[NSWorkspace sharedWorkspace] openURL:url];
            if (debug) printf("[DEBUG] request_fda_permission: System Settings opened\n");
        } else {
            if (debug) printf("[DEBUG] request_fda_permission: User clicked Deny\n");
        }
    }

    if (debug) printf("[DEBUG] request_fda_permission: Completed\n");
    return 0;
}
