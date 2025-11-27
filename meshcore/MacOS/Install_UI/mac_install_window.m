#import <Cocoa/Cocoa.h>
#import "mac_install_window.h"
#import "mac_authorized_install.h"
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <mach-o/dyld.h>
#include "../mac_logging_utils.h"  // Shared logging utility
#include "../mac_plist_utils.h"    // Shared plist parsing utility
#import "../mac_ui_helpers.h"      // Shared UI helpers

// Button tag constants for view lookup
#define BUTTON_TAG_BROWSE_UPGRADE 100
#define BUTTON_TAG_BROWSE_INSTALL 101
#define BUTTON_TAG_BROWSE_MSH 102

// Button handler class
@interface InstallButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, assign) InstallMode selectedMode;
@property (nonatomic, strong) NSTextField *upgradePathField;
@property (nonatomic, strong) NSTextField *installPathField;
@property (nonatomic, strong) NSTextField *mshFileField;
@property (nonatomic, strong) NSButton *enableUpdateCheckbox;
@property (nonatomic, assign) InstallResult *result;
@property (nonatomic, strong) NSWindow *progressWindow;
@property (nonatomic, strong) NSTextView *progressTextView;
@property (nonatomic, strong) NSProgressIndicator *progressSpinner;
@property (nonatomic, strong) NSTextField *statusLabel;
@property (nonatomic, strong) NSButton *okButton;

- (instancetype)initWithContentView:(NSView*)view result:(InstallResult*)result;
- (void)modeChanged:(NSButton*)sender;
- (void)browseUpgradePath:(id)sender;
- (void)browseInstallPath:(id)sender;
- (void)browseMshFile:(id)sender;
- (void)installClicked:(id)sender;
- (void)showProgressWindow;
- (void)appendProgressText:(NSString*)text;
- (void)completeWithSuccess:(BOOL)success exitCode:(int)exitCode;
- (void)okButtonClicked:(id)sender;
@end

@implementation InstallButtonHandler

- (instancetype)initWithContentView:(NSView*)view result:(InstallResult*)result {
    self = [super init];
    if (self) {
        _contentView = view;
        _result = result;
        _selectedMode = INSTALL_MODE_UPGRADE;
    }
    return self;
}

- (void)modeChanged:(NSButton*)sender {
    NSInteger tag = [sender tag];
    self.selectedMode = (InstallMode)tag;

    // Enable/disable appropriate fields based on selection
    BOOL isUpgrade = (tag == INSTALL_MODE_UPGRADE);

    [self.upgradePathField setEnabled:isUpgrade];
    [[self.upgradePathField.superview viewWithTag:BUTTON_TAG_BROWSE_UPGRADE] setEnabled:isUpgrade]; // Browse button

    [self.installPathField setEnabled:!isUpgrade];
    [[self.installPathField.superview viewWithTag:BUTTON_TAG_BROWSE_INSTALL] setEnabled:!isUpgrade]; // Browse button
    [self.mshFileField setEnabled:!isUpgrade];
    [[self.mshFileField.superview viewWithTag:BUTTON_TAG_BROWSE_MSH] setEnabled:!isUpgrade]; // Browse button
}

- (void)browseUpgradePath:(id)sender {
    NSString* selectedPath = mesh_showFileDialog(NO, YES,
        @"Select the existing MeshAgent installation directory", nil);

    if (selectedPath != nil) {
        [self.upgradePathField setStringValue:selectedPath];

        // Read existing update setting and update checkbox
        char installPath[2048];
        snprintf(installPath, sizeof(installPath), "%s/", [selectedPath UTF8String]);
        int enableUpdate = read_existing_update_setting(installPath);

        if (enableUpdate >= 0) {
            // Update checkbox: enableUpdate=1 means updates enabled (checkbox unchecked)
            //                  enableUpdate=0 means updates disabled (checkbox checked)
            [self.enableUpdateCheckbox setState:(enableUpdate == 0) ? NSControlStateValueOn : NSControlStateValueOff];
        }
    }
}

- (void)browseInstallPath:(id)sender {
    NSString* path = mesh_showFileDialog(NO, YES,
        @"Select the directory where MeshAgent will be installed", nil);
    if (path != nil) {
        [self.installPathField setStringValue:path];
    }
}

- (void)browseMshFile:(id)sender {
    NSString* path = mesh_showFileDialog(YES, NO,
        @"Select the .msh configuration file", @[@"msh"]);
    if (path != nil) {
        [self.mshFileField setStringValue:path];
    }
}

- (void)showProgressWindow {
    mesh_log_message("[INSTALL-UI] Showing progress window for %s mode\n",
                     (self.selectedMode == INSTALL_MODE_UPGRADE ? "UPGRADE" : "INSTALL"));

    NSWindow* mainWindow = (NSWindow*)[self.contentView window];

    // Create progress window (taller to fit status label and OK button)
    NSRect frame = NSMakeRect(0, 0, 500, 420);
    self.progressWindow = [[NSWindow alloc]
        initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled)
        backing:NSBackingStoreBuffered
        defer:NO];

    [self.progressWindow setTitle:(self.selectedMode == INSTALL_MODE_UPGRADE ? @"Upgrading MeshAgent" : @"Installing MeshAgent")];
    [self.progressWindow center];
    [self.progressWindow setLevel:NSFloatingWindowLevel];

    NSView* contentView = [self.progressWindow contentView];

    // Add title label
    NSTextField* titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 380, 460, 24)];
    [titleLabel setStringValue:(self.selectedMode == INSTALL_MODE_UPGRADE ? @"Upgrading MeshAgent..." : @"Installing MeshAgent...")];
    [titleLabel setBezeled:NO];
    [titleLabel setDrawsBackground:NO];
    [titleLabel setEditable:NO];
    [titleLabel setSelectable:NO];
    [titleLabel setFont:[NSFont systemFontOfSize:14 weight:NSFontWeightBold]];
    [contentView addSubview:titleLabel];

    // Add progress spinner
    self.progressSpinner = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(20, 345, 20, 20)];
    [self.progressSpinner setStyle:NSProgressIndicatorStyleSpinning];
    [self.progressSpinner setIndeterminate:YES];
    [self.progressSpinner startAnimation:nil];
    [contentView addSubview:self.progressSpinner];

    // Add "Please wait" label
    NSTextField* waitLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(50, 345, 430, 20)];
    [waitLabel setStringValue:@"Please wait..."];
    [waitLabel setBezeled:NO];
    [waitLabel setDrawsBackground:NO];
    [waitLabel setEditable:NO];
    [waitLabel setSelectable:NO];
    [contentView addSubview:waitLabel];

    // Add scrollable text view for output using shared helper
    NSScrollView* scrollView = mesh_createMonospaceScrollView(NSMakeRect(20, 90, 460, 240), 10.0);
    self.progressTextView = (NSTextView*)[scrollView documentView];
    [self.progressTextView setString:@"Starting...\n"];
    [contentView addSubview:scrollView];

    // Add status label (initially hidden)
    self.statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 50, 460, 30)];
    [self.statusLabel setStringValue:@""];
    [self.statusLabel setBezeled:NO];
    [self.statusLabel setDrawsBackground:NO];
    [self.statusLabel setEditable:NO];
    [self.statusLabel setSelectable:NO];
    [self.statusLabel setFont:[NSFont systemFontOfSize:13 weight:NSFontWeightMedium]];
    [self.statusLabel setAlignment:NSTextAlignmentCenter];
    [self.statusLabel setHidden:YES];
    [contentView addSubview:self.statusLabel];

    // Add OK button (initially disabled)
    self.okButton = [[NSButton alloc] initWithFrame:NSMakeRect(200, 15, 100, 28)];
    [self.okButton setTitle:@"OK"];
    [self.okButton setBezelStyle:NSBezelStyleRounded];
    [self.okButton setTarget:self];
    [self.okButton setAction:@selector(okButtonClicked:)];
    [self.okButton setEnabled:NO];
    [contentView addSubview:self.okButton];

    // Show as sheet attached to main window
    [mainWindow beginSheet:self.progressWindow completionHandler:nil];
}

- (void)appendProgressText:(NSString*)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Use attributes that match the text view's current appearance
        NSDictionary* attrs = @{
            NSForegroundColorAttributeName: [NSColor textColor],
            NSFontAttributeName: [NSFont fontWithName:@"Menlo" size:10]
        };
        NSAttributedString* attrStr = [[NSAttributedString alloc] initWithString:text attributes:attrs];
        [[self.progressTextView textStorage] appendAttributedString:attrStr];
        [self.progressTextView scrollRangeToVisible:NSMakeRange([[self.progressTextView string] length], 0)];
    });
}

- (void)completeWithSuccess:(BOOL)success exitCode:(int)exitCode {
    mesh_log_message("[INSTALL-UI] Installation completed: %s (exit code: %d)\n",
                     (success ? "SUCCESS" : "FAILED"), exitCode);

    dispatch_async(dispatch_get_main_queue(), ^{
        // Stop spinner
        [self.progressSpinner stopAnimation:nil];
        [self.progressSpinner setHidden:YES];

        // Show status message
        if (success) {
            NSString* message = (self.selectedMode == INSTALL_MODE_UPGRADE ?
                @"✓ MeshAgent has been upgraded successfully." :
                @"✓ MeshAgent has been installed successfully.");
            [self.statusLabel setStringValue:message];
            [self.statusLabel setTextColor:[NSColor colorWithRed:0.0 green:0.6 blue:0.0 alpha:1.0]];
        } else {
            NSString* message = [NSString stringWithFormat:@"✗ Operation failed with exit code %d. Check the log for details.", exitCode];
            [self.statusLabel setStringValue:message];
            [self.statusLabel setTextColor:[NSColor redColor]];
        }
        [self.statusLabel setHidden:NO];

        // Enable OK button
        [self.okButton setEnabled:YES];
        [self.okButton setKeyEquivalent:@"\r"]; // Make it respond to Enter key
    });
}

- (void)okButtonClicked:(id)sender {
    NSWindow* mainWindow = (NSWindow*)[self.contentView window];
    [mainWindow endSheet:self.progressWindow];
    [self.progressWindow close];
    [mainWindow close];
}

- (void)installClicked:(id)sender {
    // Validate inputs
    if (self.selectedMode == INSTALL_MODE_UPGRADE) {
        NSString* path = [self.upgradePathField stringValue];
        if (path == nil || [path length] == 0) {
            mesh_showAlert(@"Installation Path Required",
                          @"Please select the existing MeshAgent installation directory.",
                          NSAlertStyleWarning);
            return;
        }

        // Validate the upgrade path exists and is a directory
        BOOL isDir;
        if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] || !isDir) {
            mesh_showAlert(@"Installation Not Found",
                          [NSString stringWithFormat:@"No MeshAgent installation found at:\n%@\n\nPlease select a valid installation directory.", path],
                          NSAlertStyleWarning);
            return;
        }

        // Check for valid installation: minimum is meshagent.db OR meshagent.msh
        NSString* dbPath = [path stringByAppendingPathComponent:@"meshagent.db"];
        NSString* mshPathCheck = [path stringByAppendingPathComponent:@"meshagent.msh"];
        BOOL hasDb = [[NSFileManager defaultManager] fileExistsAtPath:dbPath];
        BOOL hasMsh = [[NSFileManager defaultManager] fileExistsAtPath:mshPathCheck];

        if (!hasDb && !hasMsh) {
            mesh_showAlert(@"Invalid Installation Directory",
                          [NSString stringWithFormat:@"The directory does not contain a valid MeshAgent installation:\n%@\n\nExpected meshagent.db or meshagent.msh", path],
                          NSAlertStyleWarning);
            return;
        }

        // Copy to result
        strncpy(self.result->installPath, [path UTF8String], sizeof(self.result->installPath) - 1);
        self.result->installPath[sizeof(self.result->installPath) - 1] = '\0';
        self.result->mshFilePath[0] = '\0';

    } else {
        NSString* installPath = [self.installPathField stringValue];
        NSString* mshPath = [self.mshFileField stringValue];

        if (installPath == nil || [installPath length] == 0) {
            mesh_showAlert(@"Installation Path Required",
                          @"Please select where to install MeshAgent.",
                          NSAlertStyleWarning);
            return;
        }

        // Check if install path exists
        BOOL isDir;
        if (![[NSFileManager defaultManager] fileExistsAtPath:installPath isDirectory:&isDir]) {
            // Path doesn't exist - ask user to confirm creation
            NSAlert* alert = [[NSAlert alloc] init];
            [alert setMessageText:@"Create Installation Directory?"];
            [alert setInformativeText:[NSString stringWithFormat:@"The directory does not exist:\n%@\n\nIt will be created during installation.", installPath]];
            [alert addButtonWithTitle:@"Continue"];
            [alert addButtonWithTitle:@"Cancel"];
            [alert setAlertStyle:NSAlertStyleInformational];

            if ([alert runModal] != NSAlertFirstButtonReturn) {
                return;  // User cancelled
            }
        } else if (!isDir) {
            // Path exists but is a file, not a directory
            mesh_showAlert(@"Invalid Installation Path",
                          [NSString stringWithFormat:@"The path exists but is not a directory:\n%@", installPath],
                          NSAlertStyleWarning);
            return;
        }

        if (mshPath == nil || [mshPath length] == 0) {
            mesh_showAlert(@"Configuration File Required",
                          @"Please select the meshagent.msh configuration file.",
                          NSAlertStyleWarning);
            return;
        }

        // Validate the .msh file exists
        if (![[NSFileManager defaultManager] fileExistsAtPath:mshPath]) {
            mesh_showAlert(@"Configuration File Not Found",
                          [NSString stringWithFormat:@"The selected .msh file does not exist:\n%@", mshPath],
                          NSAlertStyleWarning);
            return;
        }

        // Copy to result
        strncpy(self.result->installPath, [installPath UTF8String], sizeof(self.result->installPath) - 1);
        self.result->installPath[sizeof(self.result->installPath) - 1] = '\0';

        strncpy(self.result->mshFilePath, [mshPath UTF8String], sizeof(self.result->mshFilePath) - 1);
        self.result->mshFilePath[sizeof(self.result->mshFilePath) - 1] = '\0';
    }

    self.result->mode = self.selectedMode;
    self.result->enableDisableUpdate = ([self.enableUpdateCheckbox state] == NSControlStateValueOn) ? 0 : 1;
    self.result->cancelled = 0;

    mesh_log_message("[INSTALL-UI] Starting %s: path=%s, updates=%s\n",
                     (self.selectedMode == INSTALL_MODE_UPGRADE ? "UPGRADE" : "INSTALL"),
                     self.result->installPath,
                     (self.result->enableDisableUpdate ? "disabled" : "enabled"));

    // Show progress window
    [self showProgressWindow];

    // Set up progress callback to stream output to UI
    // Note: Using __unsafe_unretained is safe here because:
    // 1. Callback is set, used immediately in dispatch_async block below, then cleared
    // 2. Callback lifetime is controlled within this method's scope
    // 3. Self is guaranteed to outlive the callback since we're modal
    __unsafe_unretained typeof(self) unretainedSelf = self;
    set_progress_callback(^(const char* line) {
        [unretainedSelf appendProgressText:[NSString stringWithUTF8String:line]];
    });

    // Execute upgrade/install in background thread
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int exitCode = 0;

        if (self.selectedMode == INSTALL_MODE_UPGRADE) {
            [self appendProgressText:[NSString stringWithFormat:@"Upgrading MeshAgent at: %s\n", self.result->installPath]];
            [self appendProgressText:[NSString stringWithFormat:@"Automatic updates: %s\n\n",
                self.result->enableDisableUpdate ? "enabled" : "disabled"]];

            exitCode = execute_meshagent_upgrade(self.result->installPath, self.result->enableDisableUpdate);
        } else {
            [self appendProgressText:[NSString stringWithFormat:@"Installing MeshAgent to: %s\n", self.result->installPath]];
            [self appendProgressText:[NSString stringWithFormat:@"Configuration file: %s\n", self.result->mshFilePath]];
            [self appendProgressText:[NSString stringWithFormat:@"Automatic updates: %s\n\n",
                self.result->enableDisableUpdate ? "enabled" : "disabled"]];

            exitCode = execute_meshagent_install(self.result->installPath, self.result->mshFilePath, self.result->enableDisableUpdate);
        }

        // Clear callback
        set_progress_callback(NULL);

        [self appendProgressText:[NSString stringWithFormat:@"\nOperation completed with exit code: %d\n", exitCode]];
        [self completeWithSuccess:(exitCode == 0) exitCode:exitCode];
    });
}

@end

// Window delegate
@interface InstallWindowDelegate : NSObject <NSWindowDelegate>
@property (nonatomic, assign) BOOL windowClosed;
@property (nonatomic, strong) InstallButtonHandler *buttonHandler;
@property (nonatomic, assign) InstallResult *result;
@end

@implementation InstallWindowDelegate

- (void)windowWillClose:(NSNotification *)notification {
    mesh_log_message("[INSTALL-UI] [%ld] windowWillClose called, stopping modal loop\n", time(NULL));
    _windowClosed = YES;
    [NSApp stopModal];
    mesh_log_message("[INSTALL-UI] [%ld] Modal loop stopModal called\n", time(NULL));
}

- (void)cancelClicked:(id)sender {
    self.result->cancelled = 1;
    NSWindow* window = [(NSView*)sender window];
    [window close];
}

@end

// Helper function to check if a file exists
static BOOL fileExists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// Legacy parsing function removed - now using shared mac_plist_utils.h

// Helper function to find existing MeshAgent installation by scanning LaunchDaemons
// Returns NULL if not found, otherwise returns the installation directory path
static char* findExistingInstallation(void) {
    DIR* dir = opendir("/Library/LaunchDaemons");
    if (!dir) {
        mesh_log_message("[INSTALL-UI] Failed to open /Library/LaunchDaemons: %s\n", strerror(errno));
        return NULL;
    }

    MeshPlistInfo plists[100];
    int plistCount = 0;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && plistCount < 100) {
        // Only process .plist files
        if (strstr(entry->d_name, ".plist") == NULL) continue;

        char plistPath[1024];
        snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(plistPath, &info)) {
            mesh_log_message("[INSTALL-UI] Found MeshAgent plist: %s (program: %s)\n",
                             entry->d_name, info.programPath);
            plists[plistCount++] = info;
        }
    }
    closedir(dir);

    if (plistCount == 0) {
        mesh_log_message("[INSTALL-UI] No existing MeshAgent installation found in LaunchDaemons\n");
        return NULL;
    }

    // Find the newest plist by modification time
    int newestIndex = 0;
    for (int i = 1; i < plistCount; i++) {
        if (plists[i].modTime > plists[newestIndex].modTime) {
            newestIndex = i;
        }
    }

    // Extract installation directory from meshagent path
    char pathCopy[1024];
    strncpy(pathCopy, plists[newestIndex].programPath, sizeof(pathCopy) - 1);
    pathCopy[sizeof(pathCopy) - 1] = '\0';

    // Check if path contains .app bundle
    char* appPos = strstr(pathCopy, ".app/");
    if (appPos != NULL) {
        // For .app bundles, return parent of .app
        *appPos = '\0';
        char* lastSlash = strrchr(pathCopy, '/');
        if (lastSlash != NULL) {
            *lastSlash = '\0';
            return strdup(pathCopy);
        }
    } else {
        // For standalone binaries, return the directory containing the binary
        char* lastSlash = strrchr(pathCopy, '/');
        if (lastSlash != NULL) {
            *lastSlash = '\0';
            return strdup(pathCopy);
        }
    }

    return NULL;
}

// Helper function to get default installation path
static const char* getDefaultInstallPath(void) {
    // Check if TacticalAgent is installed
    if (fileExists("/opt/tacticalagent/tacticalagent")) {
        return "/opt/tacticalmesh";
    }

    // Otherwise use standard location
    return "/usr/local/mesh_services/meshagent";
}

// Helper function to find .msh file in same directory as current binary
// Returns NULL if not found, otherwise returns full path to .msh file
static char* findMshFile(void) {
    char exePath[1024];
    uint32_t size = sizeof(exePath);

    // Get path to current executable
    if (_NSGetExecutablePath(exePath, &size) != 0) {
        mesh_log_message("[INSTALL-UI] Failed to get executable path (buffer too small: %u)\n", size);
        return NULL;
    }

    // Get directory containing executable
    char* dir = dirname(exePath);
    mesh_log_message("[INSTALL-UI] Searching for .msh file in directory: %s\n", dir);

    // Look for .msh files in the same directory
    char mshPath[2048];

    // First try meshagent.msh
    snprintf(mshPath, sizeof(mshPath), "%s/meshagent.msh", dir);
    if (fileExists(mshPath)) {
        // TODO: Validate .msh file has appropriate install info
        // For now, just check if it exists and is readable
        mesh_log_message("[INSTALL-UI] Found .msh file: %s\n", mshPath);
        return strdup(mshPath);
    }

    // Try any .msh file in the directory
    DIR* dirp = opendir(dir);
    if (dirp != NULL) {
        struct dirent* entry;
        while ((entry = readdir(dirp)) != NULL) {
            if (strstr(entry->d_name, ".msh") != NULL) {
                snprintf(mshPath, sizeof(mshPath), "%s/%s", dir, entry->d_name);
                closedir(dirp);
                mesh_log_message("[INSTALL-UI] Found .msh file: %s\n", mshPath);
                return strdup(mshPath);
            }
        }
        closedir(dirp);
    }

    mesh_log_message("[INSTALL-UI] No .msh file found in executable directory\n");
    return NULL;
}

InstallResult show_install_assistant_window(void) {
    @autoreleasepool {
        InstallResult result = {0};
        result.cancelled = 1; // Default to cancelled

        // Create the application if it doesn't exist
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        // Create Edit menu for standard keyboard shortcuts (Cmd+A/C/V/X)
        NSMenu* mainMenu = [[NSMenu alloc] init];
        NSMenuItem* editMenuItem = [[NSMenuItem alloc] initWithTitle:@"Edit" action:nil keyEquivalent:@""];
        NSMenu* editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
        [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
        [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
        [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
        [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
        [editMenuItem setSubmenu:editMenu];
        [mainMenu addItem:editMenuItem];
        [NSApp setMainMenu:mainMenu];

        // Create window
        NSRect frame = NSMakeRect(0, 0, 600, 400);
        NSWindow* window = [[NSWindow alloc]
            initWithContentRect:frame
            styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
            backing:NSBackingStoreBuffered
            defer:NO];

        [window setTitle:@"MeshAgent Deployment Assistant"];

        // Center window
        [window center];
        [window setLevel:NSFloatingWindowLevel];

        // Get content view
        NSView* contentView = [window contentView];

        // Detect existing installation and .msh file
        char* existingInstall = findExistingInstallation();
        char* mshFile = findMshFile();
        const char* defaultInstallPath = getDefaultInstallPath();

        BOOL hasExistingInstall = (existingInstall != NULL);
        InstallMode initialMode = hasExistingInstall ? INSTALL_MODE_UPGRADE : INSTALL_MODE_NEW;

        // Create button handler
        InstallButtonHandler* buttonHandler = [[InstallButtonHandler alloc] initWithContentView:contentView result:&result];
        buttonHandler.selectedMode = initialMode;

        // Create delegate
        InstallWindowDelegate* delegate = [[InstallWindowDelegate alloc] init];
        delegate.buttonHandler = buttonHandler;
        delegate.result = &result;
        [window setDelegate:delegate];

        // Add icon (macOS 11+)
        if (@available(macOS 11.0, *)) {
            NSImageView* iconView = [[NSImageView alloc] initWithFrame:NSMakeRect(40, 330, 40, 40)];
            NSImage* icon = [NSImage imageWithSystemSymbolName:@"arrow.down.circle" accessibilityDescription:@"Install"];
            [iconView setImage:icon];
            [iconView setSymbolConfiguration:[NSImageSymbolConfiguration configurationWithPointSize:32 weight:NSFontWeightRegular]];
            [contentView addSubview:iconView];
        }

        // Add title
        NSTextField* titleLabel = mesh_createLabel(@"MeshAgent Deployment Assistant", NSMakeRect(90, 350, 490, 24), YES);
        [titleLabel setFont:[NSFont systemFontOfSize:16 weight:NSFontWeightBold]];
        [contentView addSubview:titleLabel];

        // Add description
        NSTextField* descLabel = mesh_createLabel(@"Install or upgrade MeshAgent", NSMakeRect(90, 325, 490, 20), NO);
        [contentView addSubview:descLabel];

        // Radio buttons for mode selection - Install first, then Upgrade
        NSButton* newInstallRadio = [[NSButton alloc] initWithFrame:NSMakeRect(40, 270, 300, 20)];
        [newInstallRadio setButtonType:NSButtonTypeRadio];
        [newInstallRadio setTitle:@"Install MeshAgent"];
        [newInstallRadio setState:(initialMode == INSTALL_MODE_NEW) ? NSControlStateValueOn : NSControlStateValueOff];
        [newInstallRadio setTag:INSTALL_MODE_NEW];
        [newInstallRadio setTarget:buttonHandler];
        [newInstallRadio setAction:@selector(modeChanged:)];
        [contentView addSubview:newInstallRadio];

        // Install path field
        NSTextField* installPathLabel = mesh_createLabel(@"Install path:", NSMakeRect(60, 240, 520, 20), NO);
        [contentView addSubview:installPathLabel];

        NSTextField* installPathField = [[NSTextField alloc] initWithFrame:NSMakeRect(60, 215, 380, 24)];
        [installPathField setPlaceholderString:@"/usr/local/mesh_services/meshagent"];
        [installPathField setEnabled:(initialMode == INSTALL_MODE_NEW)];
        if (initialMode == INSTALL_MODE_NEW) {
            [installPathField setStringValue:[NSString stringWithUTF8String:defaultInstallPath]];
        }
        buttonHandler.installPathField = installPathField;
        [contentView addSubview:installPathField];

        NSButton* browseInstall = [[NSButton alloc] initWithFrame:NSMakeRect(450, 215, 100, 24)];
        [browseInstall setTitle:@"Browse..."];
        [browseInstall setBezelStyle:NSBezelStyleRounded];
        [browseInstall setTarget:buttonHandler];
        [browseInstall setAction:@selector(browseInstallPath:)];
        [browseInstall setTag:BUTTON_TAG_BROWSE_INSTALL];
        [browseInstall setEnabled:(initialMode == INSTALL_MODE_NEW)];
        [contentView addSubview:browseInstall];

        // MSH file field (grouped with Install)
        NSTextField* mshFileLabel = mesh_createLabel(@"Configuration file (.msh):", NSMakeRect(60, 185, 520, 20), NO);
        [contentView addSubview:mshFileLabel];

        NSTextField* mshFileField = [[NSTextField alloc] initWithFrame:NSMakeRect(60, 160, 380, 24)];
        [mshFileField setPlaceholderString:@"meshagent.msh"];
        [mshFileField setEnabled:(initialMode == INSTALL_MODE_NEW)];
        if (mshFile != NULL && initialMode == INSTALL_MODE_NEW) {
            [mshFileField setStringValue:[NSString stringWithUTF8String:mshFile]];
        }
        buttonHandler.mshFileField = mshFileField;
        [contentView addSubview:mshFileField];

        NSButton* browseMsh = [[NSButton alloc] initWithFrame:NSMakeRect(450, 160, 100, 24)];
        [browseMsh setTitle:@"Browse..."];
        [browseMsh setBezelStyle:NSBezelStyleRounded];
        [browseMsh setTarget:buttonHandler];
        [browseMsh setAction:@selector(browseMshFile:)];
        [browseMsh setTag:BUTTON_TAG_BROWSE_MSH];
        [browseMsh setEnabled:(initialMode == INSTALL_MODE_NEW)];
        [contentView addSubview:browseMsh];

        // Upgrade radio
        NSButton* upgradeRadio = [[NSButton alloc] initWithFrame:NSMakeRect(40, 115, 300, 20)];
        [upgradeRadio setButtonType:NSButtonTypeRadio];
        [upgradeRadio setTitle:@"Upgrade MeshAgent"];
        [upgradeRadio setState:(initialMode == INSTALL_MODE_UPGRADE) ? NSControlStateValueOn : NSControlStateValueOff];
        [upgradeRadio setTag:INSTALL_MODE_UPGRADE];
        [upgradeRadio setTarget:buttonHandler];
        [upgradeRadio setAction:@selector(modeChanged:)];
        [contentView addSubview:upgradeRadio];

        // Upgrade path field
        NSTextField* upgradePathLabel = mesh_createLabel(@"Current install path:", NSMakeRect(60, 85, 520, 20), NO);
        [contentView addSubview:upgradePathLabel];

        NSTextField* upgradePathField = [[NSTextField alloc] initWithFrame:NSMakeRect(60, 60, 380, 24)];
        [upgradePathField setPlaceholderString:@"/usr/local/mesh_services/meshagent"];
        [upgradePathField setEnabled:(initialMode == INSTALL_MODE_UPGRADE)];
        int existingEnableUpdate = 1;  // Default to updates enabled
        if (existingInstall != NULL) {
            [upgradePathField setStringValue:[NSString stringWithUTF8String:existingInstall]];

            // Read existing update setting from installation
            char installPath[2048];
            snprintf(installPath, sizeof(installPath), "%s/", existingInstall);
            existingEnableUpdate = read_existing_update_setting(installPath);
            if (existingEnableUpdate < 0) {
                existingEnableUpdate = 1;  // Default to enabled on error
            }
        }
        buttonHandler.upgradePathField = upgradePathField;
        [contentView addSubview:upgradePathField];

        NSButton* browseUpgrade = [[NSButton alloc] initWithFrame:NSMakeRect(450, 60, 100, 24)];
        [browseUpgrade setTitle:@"Browse..."];
        [browseUpgrade setBezelStyle:NSBezelStyleRounded];
        [browseUpgrade setTarget:buttonHandler];
        [browseUpgrade setAction:@selector(browseUpgradePath:)];
        [browseUpgrade setTag:BUTTON_TAG_BROWSE_UPGRADE];
        [browseUpgrade setEnabled:(initialMode == INSTALL_MODE_UPGRADE)];
        [contentView addSubview:browseUpgrade];

        // Enable/Disable Update checkbox
        NSButton* enableUpdateCheckbox = [[NSButton alloc] initWithFrame:NSMakeRect(40, 30, 520, 20)];
        [enableUpdateCheckbox setButtonType:NSButtonTypeSwitch];
        [enableUpdateCheckbox setTitle:@"Disable automatic updates"];
        // For upgrade mode: use existing setting; For new install: default to enabled (unchecked)
        if (initialMode == INSTALL_MODE_UPGRADE) {
            [enableUpdateCheckbox setState:(existingEnableUpdate == 0) ? NSControlStateValueOn : NSControlStateValueOff];
        } else {
            [enableUpdateCheckbox setState:NSControlStateValueOff];  // Default to unchecked (updates enabled)
        }
        buttonHandler.enableUpdateCheckbox = enableUpdateCheckbox;
        [contentView addSubview:enableUpdateCheckbox];

        // Bottom buttons
        NSButton* cancelButton = [[NSButton alloc] initWithFrame:NSMakeRect(390, 15, 90, 32)];
        [cancelButton setTitle:@"Cancel"];
        [cancelButton setBezelStyle:NSBezelStyleRounded];
        [cancelButton setKeyEquivalent:@"\033"]; // ESC key
        [cancelButton setTarget:delegate];
        [cancelButton setAction:@selector(cancelClicked:)];
        [contentView addSubview:cancelButton];

        NSButton* installButton = [[NSButton alloc] initWithFrame:NSMakeRect(490, 15, 90, 32)];
        [installButton setTitle:@"Install"];
        [installButton setBezelStyle:NSBezelStyleRounded];
        [installButton setKeyEquivalent:@"\r"]; // Enter key
        [installButton setTarget:buttonHandler];
        [installButton setAction:@selector(installClicked:)];
        [contentView addSubview:installButton];

        // Show window and run modal
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        mesh_log_message("[INSTALL-UI] [%ld] Entering modal loop...\n", time(NULL));
        [NSApp runModalForWindow:window];
        mesh_log_message("[INSTALL-UI] [%ld] Modal loop returned, cleaning up\n", time(NULL));

        // Cleanup
        [window close];

        if (existingInstall != NULL) {
            free(existingInstall);
        }
        if (mshFile != NULL) {
            free(mshFile);
        }

        return result;
    }
}
