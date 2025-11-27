#import <Cocoa/Cocoa.h>
#import "mac_permissions_window.h"
#import "../mac_tcc_detection.h"
#include "../../../microstack/ILibSimpleDataStore.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

// Lock file to prevent multiple TCC UI processes
#define TCC_LOCK_FILE "/tmp/meshagent_tcccheck.lock"

// Button tags for identification
#define BUTTON_TAG_ACCESSIBILITY 1
#define BUTTON_TAG_FDA 2
#define BUTTON_TAG_SCREEN_RECORDING 3

// Helper functions for lock file management
static int is_process_running(pid_t pid) {
    return kill(pid, 0) == 0;
}

static int is_tcc_ui_running(void) {
    FILE* f = fopen(TCC_LOCK_FILE, "r");
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
            unlink(TCC_LOCK_FILE);
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

static void remove_lock_file(void) {
    unlink(TCC_LOCK_FILE);
}

// Button action handler class
@interface TCCButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, strong) NSTimer *updateTimer;

- (instancetype)initWithContentView:(NSView*)view;
- (void)openAccessibilitySettings:(id)sender;
- (void)openFullDiskAccessSettings:(id)sender;
- (void)openScreenRecordingSettings:(id)sender;
- (void)updatePermissionStatus;
- (void)startPeriodicUpdates;
- (void)stopPeriodicUpdates;
@end

@implementation TCCButtonHandler

- (instancetype)initWithContentView:(NSView*)view {
    self = [super init];
    if (self) {
        _contentView = view;
        _updateTimer = nil;
    }
    return self;
}

- (void)dealloc {
    [self stopPeriodicUpdates];
}

- (void)replaceButtonWithSuccessIcon:(NSButton*)button {
    // Check if button is already showing checkmark (avoid re-applying transformation)
    if ([button image] != nil) {
        return; // Already converted to checkmark
    }

    if (@available(macOS 11.0, *)) {
        // Get button's tag to determine original position
        NSInteger tag = [button tag];
        CGFloat yPos;
        if (tag == BUTTON_TAG_ACCESSIBILITY) {
            yPos = 235;
        } else if (tag == BUTTON_TAG_FDA) {
            yPos = 165;
        } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
            yPos = 100;
        } else {
            return;
        }

        // Create checkmark icon (32×32 with 28pt icon)
        NSImageSymbolConfiguration* config = [NSImageSymbolConfiguration configurationWithPointSize:28 weight:NSFontWeightRegular];
        NSImage* icon = [NSImage imageWithSystemSymbolName:@"checkmark.circle.fill" accessibilityDescription:@"Permission Granted"];
        NSImage* configuredIcon = [icon imageWithSymbolConfiguration:config];

        // Change button to show checkmark icon instead of text
        [button setImage:configuredIcon];
        [button setImagePosition:NSImageOnly];
        [button setContentTintColor:[NSColor systemGreenColor]];
        [button setTitle:@""];
        [button setBordered:NO];
        [button setBezelStyle:NSBezelStyleRegularSquare];

        // Center checkmark where the button used to be (shifted down 12px)
        // Button was at x=440 with width=140, so center is at 440 + 70 = 510
        // Checkmark is 32 wide, so center it: 510 - 16 = 494
        [button setFrame:NSMakeRect(494, yPos - 20 + (28 - 32) / 2, 32, 32)];
    } else {
        // Fallback for older macOS
        [button setTitle:@"✓ Granted"];
    }
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
        yPos = 235;
    } else if (tag == BUTTON_TAG_FDA) {
        yPos = 165;
    } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
        yPos = 100;
    } else {
        return;
    }

    [button setFrame:NSMakeRect(440, yPos - 20, 140, 28)];
}

- (void)updatePermissionStatus {
    // Check all permissions for the calling process
    TCC_PermissionStatus accessibility = check_accessibility_permission();
    TCC_PermissionStatus fda = check_fda_permission();
    TCC_PermissionStatus screen_recording = check_screen_recording_permission();

    // Update UI for each permission
    for (NSView *subview in [self.contentView subviews]) {
        if ([subview isKindOfClass:[NSButton class]]) {
            NSButton *button = (NSButton*)subview;
            NSInteger tag = [button tag];

            TCC_PermissionStatus status = TCC_PERMISSION_NOT_DETERMINED;
            if (tag == BUTTON_TAG_ACCESSIBILITY) {
                status = accessibility;
            } else if (tag == BUTTON_TAG_FDA) {
                status = fda;
            } else if (tag == BUTTON_TAG_SCREEN_RECORDING) {
                status = screen_recording;
            } else {
                continue; // Not a permission button
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

- (void)startPeriodicUpdates {
    // Check immediately
    [self updatePermissionStatus];

    // Create timer that works in modal windows
    self.updateTimer = [NSTimer timerWithTimeInterval:1.0
                                                target:self
                                              selector:@selector(updatePermissionStatus)
                                              userInfo:nil
                                               repeats:YES];

    // Add timer to run loop with NSRunLoopCommonModes so it fires in modal windows
    [[NSRunLoop currentRunLoop] addTimer:self.updateTimer forMode:NSRunLoopCommonModes];
}

- (void)stopPeriodicUpdates {
    if (self.updateTimer) {
        [self.updateTimer invalidate];
        self.updateTimer = nil;
    }
}

- (void)openAccessibilitySettings:(id)sender {
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)openFullDiskAccessSettings:(id)sender {
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)openScreenRecordingSettings:(id)sender {
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
    [NSApp stopModal];
}

- (void)checkboxToggled:(NSButton*)sender {
    self.doNotRemindAgain = ([sender state] == NSControlStateValueOn);
}

@end

// Helper function to create label text
static NSTextField* createLabel(NSString* text, NSRect frame, BOOL bold) {
    NSTextField* label = [[NSTextField alloc] initWithFrame:frame];
    [label setStringValue:text];
    [label setBezeled:NO];
    [label setDrawsBackground:NO];
    [label setEditable:NO];
    [label setSelectable:NO];

    if (bold) {
        [label setFont:[NSFont boldSystemFontOfSize:13]];
    } else {
        [label setFont:[NSFont systemFontOfSize:12]];
        [label setTextColor:[NSColor secondaryLabelColor]];
    }

    return label;
}

// Helper function to create section with permission name, description, and button
static void createPermissionSection(NSView* contentView, NSString* title, NSString* description, CGFloat yPos, SEL action, id target, NSInteger buttonTag) {
    // Title label (bold)
    NSTextField* titleLabel = createLabel(title, NSMakeRect(40, yPos, 380, 20), YES);
    [contentView addSubview:titleLabel];

    // Description label (gray, wrapped)
    NSTextField* descLabel = createLabel(description, NSMakeRect(40, yPos - 35, 380, 32), NO);
    [descLabel setLineBreakMode:NSLineBreakByWordWrapping];
    [[descLabel cell] setWraps:YES];
    [contentView addSubview:descLabel];

    // "Open Settings" button (shifted down 12px from text)
    NSButton* settingsButton = [[NSButton alloc] initWithFrame:NSMakeRect(440, yPos - 20, 140, 28)];
    [settingsButton setTitle:@"Open Settings"];
    [settingsButton setBezelStyle:NSBezelStyleRounded];
    [settingsButton setTarget:target];
    [settingsButton setAction:action];
    [settingsButton setTag:buttonTag];
    [contentView addSubview:settingsButton];
}

int show_tcc_permissions_window(void) {
    @autoreleasepool {
        // Create lock file to prevent multiple instances
        create_lock_file();

        // Create the application if it doesn't exist
        [NSApplication sharedApplication];

        // Set activation policy to allow window to show
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        // Create window
        NSRect frame = NSMakeRect(0, 0, 600, 355);
        NSWindow* window = [[NSWindow alloc]
            initWithContentRect:frame
            styleMask:(NSWindowStyleMaskTitled |
                      NSWindowStyleMaskClosable)
            backing:NSBackingStoreBuffered
            defer:NO];

        [window setTitle:@"MeshAgent - Security & Privacy Settings"];

        // Position in upper-right area to stay out of the way
        NSScreen* mainScreen = [NSScreen mainScreen];
        NSRect screenFrame = [mainScreen visibleFrame];
        NSRect windowFrame = [window frame];

        // Position 20 pixels from right edge and 20 pixels from top
        CGFloat xPos = screenFrame.origin.x + screenFrame.size.width - windowFrame.size.width - 20;
        CGFloat yPos = screenFrame.origin.y + screenFrame.size.height - windowFrame.size.height - 20;

        [window setFrameOrigin:NSMakePoint(xPos, yPos)];
        [window setLevel:NSFloatingWindowLevel];

        // Get content view
        NSView* contentView = [window contentView];

        // Create button handler
        TCCButtonHandler* buttonHandler = [[TCCButtonHandler alloc] initWithContentView:contentView];

        // Create delegate and link button handler
        TCCPermissionsWindowDelegate* delegate = [[TCCPermissionsWindowDelegate alloc] init];
        delegate.buttonHandler = buttonHandler;
        [window setDelegate:delegate];

        // Add icon using SF Symbols (macOS 11+)
        if (@available(macOS 11.0, *)) {
            NSImageView* iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(40, 295, 40, 40)];
            NSImage* icon = [NSImage imageWithSystemSymbolName:@"checkmark.shield" accessibilityDescription:@"Security"];
            [iconView setImage:icon];
            [iconView setSymbolConfiguration:[NSImageSymbolConfiguration configurationWithPointSize:32 weight:NSFontWeightRegular]];
            [contentView addSubview:iconView];
        }

        // Add header title
        NSTextField* titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(90, 315, 490, 24)];
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
        [headerLabel setStringValue:@"Please grant MeshAgent all the required permissions for complete access functionality."];
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

        // Add "Do not remind me again" checkbox
        NSButton* checkbox = [[NSButton alloc] initWithFrame:NSMakeRect(20, 15, 250, 20)];
        [checkbox setButtonType:NSButtonTypeSwitch];
        [checkbox setTitle:@"Do not remind me again"];
        [checkbox setTarget:delegate];
        [checkbox setAction:@selector(checkboxToggled:)];
        [contentView addSubview:checkbox];

        // Add "Finish" button
        NSButton* finishButton = [[NSButton alloc] initWithFrame:NSMakeRect(490, 15, 90, 32)];
        [finishButton setTitle:@"Finish"];
        [finishButton setBezelStyle:NSBezelStyleRounded];
        [finishButton setKeyEquivalent:@"\r"]; // Enter key
        [finishButton setTarget:window];
        [finishButton setAction:@selector(close)];
        [contentView addSubview:finishButton];

        // Start periodic permission checks
        [buttonHandler startPeriodicUpdates];

        // Show window and run modal
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp runModalForWindow:window];

        // Get result
        int result = delegate.doNotRemindAgain ? 1 : 0;

        // Cleanup
        [window close];
        remove_lock_file();

        return result;
    }
}

// Async wrapper implementation using fork + execv
// This spawns a child process with "-tccCheck" flag to show the UI
void show_tcc_permissions_window_async(const char* exe_path, const char* db_path) {
    // Check if TCC UI is already running
    if (is_tcc_ui_running()) {
        return; // Don't spawn another instance
    }

    pid_t pid = fork();

    if (pid == 0) {
        // Child process - re-exec self with -tccCheck flag
        // The child's main thread will be free for Cocoa/NSWindow
        execv(exe_path, (char*[]){
            "meshagent",     // argv[0] (program name)
            "-tccCheck",     // argv[1] (flag)
            (char*)db_path,  // argv[2] (database path)
            NULL             // argv terminator
        });

        // If execv fails, exit
        _exit(1);
    }
    // Parent process continues immediately (non-blocking)
}
