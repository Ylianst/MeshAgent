#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
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

// Data source for .msh viewer table
@interface MshViewerDataSource : NSObject <NSTableViewDataSource, NSTableViewDelegate>
@property (nonatomic, strong) NSArray* entries;
- (instancetype)initWithEntries:(NSArray*)entries;
@end

@implementation MshViewerDataSource
- (instancetype)initWithEntries:(NSArray*)entries {
    self = [super init];
    if (self) {
        _entries = entries;
    }
    return self;
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView {
    return [self.entries count];
}

- (id)tableView:(NSTableView*)tableView objectValueForTableColumn:(NSTableColumn*)column row:(NSInteger)row {
    if (row < 0 || row >= (NSInteger)[self.entries count]) return nil;
    NSDictionary* entry = self.entries[row];
    NSString* value = entry[[column identifier]];

    // Truncate long values (over 100 chars) for readability
    if ([[column identifier] isEqualToString:@"value"] && [value length] > 100) {
        value = [[value substringToIndex:97] stringByAppendingString:@"..."];
    }
    return value;
}

- (BOOL)tableView:(NSTableView*)tableView shouldEditTableColumn:(NSTableColumn*)column row:(NSInteger)row {
    return NO;  // Read-only
}
@end

// Forward declarations
// Agent display name provided by mesh_getAgentDisplayName() in mac_ui_helpers

// Button tag constants for view lookup
#define BUTTON_TAG_BROWSE_UPGRADE 100
#define BUTTON_TAG_BROWSE_INSTALL 101
#define BUTTON_TAG_BROWSE_MSH 102
#define BUTTON_TAG_BROWSE_UNINSTALL 103

// Button handler class
@interface InstallButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, assign) InstallMode selectedMode;
@property (nonatomic, strong) NSTextField *upgradePathField;
@property (nonatomic, strong) NSTextField *installedVersionLabel;
@property (nonatomic, strong) NSTextField *installPathField;
@property (nonatomic, strong) NSTextField *mshFileField;
@property (nonatomic, strong) NSButton *editMshButton;
@property (nonatomic, strong) NSWindow *mshViewerWindow;
@property (nonatomic, strong) NSButton *enableUpdateCheckbox;
@property (nonatomic, strong) NSButton *disableTccCheckCheckbox;
@property (nonatomic, strong) NSButton *verboseLoggingCheckbox;
@property (nonatomic, strong) NSButton *meshAgentLoggingCheckbox;
@property (nonatomic, strong) NSTextField *uninstallPathField;
@property (nonatomic, strong) NSButton *standardUninstallRadio;
@property (nonatomic, strong) NSButton *fullUninstallRadio;
@property (nonatomic, strong) NSButton *installButton;
@property (nonatomic, strong) NSImageView *installIcon;
@property (nonatomic, strong) NSImageView *upgradeIcon;
@property (nonatomic, strong) NSImageView *uninstallIcon;
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
- (void)browseUninstallPath:(id)sender;
- (void)uninstallTypeChanged:(NSButton*)sender;
- (void)editMshFile:(id)sender;
- (void)closeViewerSheet:(id)sender;
- (void)updateInstalledVersionLabel:(NSString*)installPath;
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

// Get the base name of the agent executable (e.g., "meshagent" or "acmemesh")
- (NSString *)getAgentBaseName {
    NSString *execPath = [[NSBundle mainBundle] executablePath];
    if (!execPath) {
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            execPath = [NSString stringWithUTF8String:path];
        } else {
            return nil;  // Caller must handle failure
        }
    }
    return [[execPath lastPathComponent] stringByDeletingPathExtension];
}

// Get the display name for the agent (e.g., "MeshAgent" or "AcmeMesh")
// Priority: 1. CFBundleDisplayName  2. CFBundleName  3. .app bundle name  4. Binary name
- (NSString *)getAgentDisplayName {
    return mesh_getAgentDisplayName();
}

// Get the .msh filename based on executable name (e.g., "meshagent.msh" or "acmemesh.msh")
- (NSString *)getAgentMshName {
    NSString *base = [self getAgentBaseName];
    return base ? [base stringByAppendingString:@".msh"] : nil;
}

// Get the .db filename based on executable name (e.g., "meshagent.db" or "acmemesh.db")
- (NSString *)getAgentDbName {
    NSString *base = [self getAgentBaseName];
    return base ? [base stringByAppendingString:@".db"] : nil;
}

- (void)modeChanged:(NSButton*)sender {
    NSInteger tag = [sender tag];

    // Validate tag before casting to enum
    if (tag != INSTALL_MODE_UPGRADE && tag != INSTALL_MODE_NEW && tag != INSTALL_MODE_UNINSTALL) {
        mesh_log_message("[INSTALL-UI] ERROR: Invalid mode tag: %ld\n", (long)tag);
        return;
    }

    self.selectedMode = (InstallMode)tag;

    BOOL isUpgrade = (tag == INSTALL_MODE_UPGRADE);
    BOOL isInstall = (tag == INSTALL_MODE_NEW);
    BOOL isUninstall = (tag == INSTALL_MODE_UNINSTALL);

    // Upgrade fields
    [self.upgradePathField setEnabled:isUpgrade];
    [[self.upgradePathField.superview viewWithTag:BUTTON_TAG_BROWSE_UPGRADE] setEnabled:isUpgrade];

    // Install fields
    [self.installPathField setEnabled:isInstall];
    [[self.installPathField.superview viewWithTag:BUTTON_TAG_BROWSE_INSTALL] setEnabled:isInstall];
    [self.mshFileField setEnabled:isInstall];
    [[self.mshFileField.superview viewWithTag:BUTTON_TAG_BROWSE_MSH] setEnabled:isInstall];

    // Edit button: only enabled if install mode AND a file is selected
    BOOL hasFile = [[self.mshFileField stringValue] length] > 0;
    [self.editMshButton setEnabled:(isInstall && hasFile)];

    // Uninstall fields
    [self.uninstallPathField setEnabled:isUninstall];
    [[self.uninstallPathField.superview viewWithTag:BUTTON_TAG_BROWSE_UNINSTALL] setEnabled:isUninstall];
    [self.standardUninstallRadio setEnabled:isUninstall];
    [self.fullUninstallRadio setEnabled:isUninstall];

    // Disable install/upgrade-specific checkboxes when uninstall selected (verbose logging stays)
    [self.enableUpdateCheckbox setEnabled:!isUninstall];
    [self.disableTccCheckCheckbox setEnabled:!isUninstall];
    [self.meshAgentLoggingCheckbox setEnabled:!isUninstall];

    // Update radio icon tints: selected mode gets black, others get secondaryLabelColor
    [self.installIcon setContentTintColor:isInstall ? [NSColor blackColor] : [NSColor secondaryLabelColor]];
    [self.upgradeIcon setContentTintColor:isUpgrade ? [NSColor blackColor] : [NSColor secondaryLabelColor]];
    [self.uninstallIcon setContentTintColor:isUninstall ? [NSColor blackColor] : [NSColor secondaryLabelColor]];

    // Dynamic button text
    if (isUninstall) {
        [self.installButton setTitle:@"Uninstall"];
    } else if (isUpgrade) {
        [self.installButton setTitle:@"Upgrade"];
    } else {
        [self.installButton setTitle:@"Install"];
    }
}

- (void)browseUpgradePath:(id)sender {
    NSString* selectedPath = mesh_showFileDialog(NO, YES,
        [NSString stringWithFormat:@"Select the existing %@ installation directory", [self getAgentDisplayName]], nil);

    if (selectedPath != nil) {
        [self.upgradePathField setStringValue:selectedPath];

        // Read existing settings and update checkboxes
        char installPath[2048];
        snprintf(installPath, sizeof(installPath), "%s/", [selectedPath UTF8String]);

        // Read disableUpdate setting
        int enableUpdate = read_existing_update_setting(installPath);
        if (enableUpdate >= 0) {
            // enableUpdate=1 means updates enabled (checkbox unchecked)
            // enableUpdate=0 means updates disabled (checkbox checked)
            [self.enableUpdateCheckbox setState:(enableUpdate == 0) ? NSControlStateValueOn : NSControlStateValueOff];
        }

        // Read disableTccCheck setting
        int enableTccCheck = read_existing_tcc_check_setting(installPath);
        if (enableTccCheck >= 0) {
            // enableTccCheck=1 means TCC check enabled (checkbox unchecked)
            // enableTccCheck=0 means TCC check disabled (checkbox checked)
            [self.disableTccCheckCheckbox setState:(enableTccCheck == 0) ? NSControlStateValueOn : NSControlStateValueOff];
        }

        // Update installed version label
        [self updateInstalledVersionLabel:selectedPath];
    }
}

- (void)browseUninstallPath:(id)sender {
    NSString* selectedPath = mesh_showFileDialog(NO, YES,
        [NSString stringWithFormat:@"Select the %@ installation directory to uninstall", [self getAgentDisplayName]], nil);

    if (selectedPath != nil) {
        [self.uninstallPathField setStringValue:selectedPath];
    }
}

- (void)uninstallTypeChanged:(NSButton*)sender {
    [self.standardUninstallRadio setState:(sender == self.standardUninstallRadio) ? NSControlStateValueOn : NSControlStateValueOff];
    [self.fullUninstallRadio setState:(sender == self.fullUninstallRadio) ? NSControlStateValueOn : NSControlStateValueOff];
}

- (void)browseInstallPath:(id)sender {
    NSString* path = mesh_showFileDialog(NO, YES,
        [NSString stringWithFormat:@"Select the directory where %@ will be installed", [self getAgentDisplayName]], nil);
    if (path != nil) {
        [self.installPathField setStringValue:path];
    }
}

- (void)browseMshFile:(id)sender {
    NSString* path = mesh_showFileDialog(YES, NO,
        @"Select the .msh configuration file", @[@"msh"]);
    if (path != nil) {
        [self.mshFileField setStringValue:path];
        // Enable Edit button when a file is selected
        [self.editMshButton setEnabled:YES];
    }
}

- (void)editMshFile:(id)sender {
    mesh_log_message("[INSTALL-UI] Edit button clicked\n");
    NSString* mshPath = [self.mshFileField stringValue];
    if (mshPath == nil || [mshPath length] == 0) {
        mesh_log_message("[INSTALL-UI] No msh path set, returning\n");
        return;
    }
    mesh_log_message("[INSTALL-UI] Opening viewer for: %s\n", [mshPath UTF8String]);

    // Check file size before reading to prevent memory exhaustion
    NSError* error = nil;
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:mshPath error:&error];
    if (attrs == nil) {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setMessageText:@"Cannot Access File"];
        [alert setInformativeText:[NSString stringWithFormat:@"Could not get attributes for: %@\n%@", mshPath, [error localizedDescription]]];
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        return;
    }

    unsigned long long fileSize = [attrs fileSize];
    const unsigned long long maxSize = 10 * 1024 * 1024;  // 10 MB limit
    if (fileSize > maxSize) {
        mesh_log_message("[INSTALL-UI] File too large: %llu bytes (max: %llu)\n", fileSize, maxSize);
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setMessageText:@"File Too Large"];
        [alert setInformativeText:[NSString stringWithFormat:@"Configuration file is too large (%llu MB). Maximum size is 10 MB.", fileSize / (1024 * 1024)]];
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        return;
    }

    // Read and parse the .msh file
    NSString* contents = [NSString stringWithContentsOfFile:mshPath encoding:NSUTF8StringEncoding error:&error];
    if (contents == nil) {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setMessageText:@"Cannot Read File"];
        [alert setInformativeText:[NSString stringWithFormat:@"Could not read: %@\n%@", mshPath, [error localizedDescription]]];
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        return;
    }

    // Parse key=value pairs
    NSMutableArray* entries = [NSMutableArray array];
    NSArray* lines = [contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString* line in lines) {
        NSString* trimmed = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([trimmed length] == 0) continue;
        if ([trimmed hasPrefix:@"#"]) continue;  // Skip comments

        NSRange eqRange = [trimmed rangeOfString:@"="];
        if (eqRange.location != NSNotFound) {
            NSString* key = [trimmed substringToIndex:eqRange.location];
            NSString* value = [trimmed substringFromIndex:eqRange.location + 1];
            [entries addObject:@{@"key": key, @"value": value}];
        }
    }

    // Sort alphabetically by key
    NSSortDescriptor* sortDesc = [NSSortDescriptor sortDescriptorWithKey:@"key" ascending:YES selector:@selector(caseInsensitiveCompare:)];
    [entries sortUsingDescriptors:@[sortDesc]];

    // Create viewer window (store in property to prevent ARC deallocation)
    NSRect windowFrame = NSMakeRect(0, 0, 500, 350);
    self.mshViewerWindow = [[NSWindow alloc]
        initWithContentRect:windowFrame
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
        backing:NSBackingStoreBuffered
        defer:NO];
    [self.mshViewerWindow setTitle:[NSString stringWithFormat:@"Configuration: %@", [mshPath lastPathComponent]]];
    [self.mshViewerWindow center];
    [self.mshViewerWindow setLevel:NSFloatingWindowLevel];

    NSView* contentView = [self.mshViewerWindow contentView];

    // Create table view with scroll view
    NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 60, 460, 270)];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setBorderType:NSBezelBorder];

    NSTableView* tableView = [[NSTableView alloc] initWithFrame:NSMakeRect(0, 0, 460, 270)];
    [tableView setRowHeight:20];
    [tableView setGridStyleMask:NSTableViewSolidHorizontalGridLineMask];

    // Key column
    NSTableColumn* keyColumn = [[NSTableColumn alloc] initWithIdentifier:@"key"];
    [keyColumn setWidth:160];
    [[keyColumn headerCell] setStringValue:@"Key"];
    [tableView addTableColumn:keyColumn];

    // Value column
    NSTableColumn* valueColumn = [[NSTableColumn alloc] initWithIdentifier:@"value"];
    [valueColumn setWidth:280];
    [[valueColumn headerCell] setStringValue:@"Value"];
    [tableView addTableColumn:valueColumn];

    // Store entries for data source (use associated object)
    objc_setAssociatedObject(tableView, "entries", entries, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    // Set data source using block-based approach via a simple helper object
    MshViewerDataSource* dataSource = [[MshViewerDataSource alloc] initWithEntries:entries];
    objc_setAssociatedObject(tableView, "dataSource", dataSource, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [tableView setDataSource:dataSource];
    [tableView setDelegate:dataSource];

    [scrollView setDocumentView:tableView];
    [contentView addSubview:scrollView];

    // Close button
    NSButton* closeButton = mesh_createRoundedButton(@"Close", NSMakeRect(390, 20, 90, 30),
        self, @selector(closeViewerSheet:), 0);
    [closeButton setKeyEquivalent:@"\r"];
    [contentView addSubview:closeButton];

    // Entry count label
    NSTextField* countLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 25, 200, 20)];
    [countLabel setStringValue:[NSString stringWithFormat:@"%lu entries", (unsigned long)[entries count]]];
    [countLabel setBezeled:NO];
    [countLabel setDrawsBackground:NO];
    [countLabel setEditable:NO];
    [countLabel setSelectable:NO];
    [countLabel setTextColor:[NSColor secondaryLabelColor]];
    [contentView addSubview:countLabel];

    // Show as sheet attached to main window (same pattern as showProgressWindow)
    NSWindow* parentWindow = (NSWindow*)[self.contentView window];
    if (parentWindow) {
        [parentWindow beginSheet:self.mshViewerWindow completionHandler:nil];
        mesh_log_message("[INSTALL-UI] Viewer sheet shown with %lu entries\n", (unsigned long)[entries count]);
    } else {
        // Fallback if window not available
        [self.mshViewerWindow orderFrontRegardless];
        [self.mshViewerWindow makeKeyWindow];
        mesh_log_message("[INSTALL-UI] Viewer window (fallback) shown with %lu entries\n", (unsigned long)[entries count]);
    }
}

- (void)closeViewerSheet:(id)sender {
    NSWindow* parentWindow = (NSWindow*)[self.contentView window];
    if (parentWindow && self.mshViewerWindow) {
        [parentWindow endSheet:self.mshViewerWindow];
    }
    [self.mshViewerWindow close];
    self.mshViewerWindow = nil;
}

// Helper to run meshagent with an argument and return output
- (NSString*)runMeshagent:(NSString*)binaryPath withArg:(NSString*)arg {
    NSTask* task = [[NSTask alloc] init];
    [task setLaunchPath:binaryPath];
    [task setArguments:@[arg]];

    // Strip LAUNCHED_FROM_FINDER from environment so the child process
    // doesn't think it was launched from Finder and show its own install UI
    NSMutableDictionary* env = [[[NSProcessInfo processInfo] environment] mutableCopy];
    [env removeObjectForKey:@"LAUNCHED_FROM_FINDER"];
    [task setEnvironment:env];

    NSPipe* pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task setStandardError:[NSPipe pipe]];  // Suppress stderr

    @try {
        [task launch];
        [task waitUntilExit];

        if ([task terminationStatus] != 0) {
            return nil;
        }

        NSData* data = [[pipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return [output stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    } @catch (NSException* e) {
        mesh_log_message("[INSTALL-UI] Failed to run meshagent %s: %s\n", [arg UTF8String], [[e reason] UTF8String]);
        return nil;
    }
}

// Parse "Compiled on: HH:MM:SS, Mon DD YYYY" to "YY.MM.DD (HH.MM.SS)"
- (NSString*)parseCompiledOnLine:(NSString*)line {
    // Expected format: "Compiled on: 10:48:25, Dec 10 2025"
    NSRange colonRange = [line rangeOfString:@": "];
    if (colonRange.location == NSNotFound) return nil;

    NSString* dateStr = [line substringFromIndex:colonRange.location + 2];
    // dateStr is now "10:48:25, Dec 10 2025"

    // Parse time
    NSRange commaRange = [dateStr rangeOfString:@", "];
    if (commaRange.location == NSNotFound) return nil;

    NSString* timeStr = [dateStr substringToIndex:commaRange.location];  // "10:48:25"
    NSString* restStr = [dateStr substringFromIndex:commaRange.location + 2];  // "Dec 10 2025"

    // Parse date parts
    NSArray* dateParts = [restStr componentsSeparatedByString:@" "];
    if ([dateParts count] < 3) return nil;

    NSString* monthStr = dateParts[0];
    NSString* dayStr = dateParts[1];
    NSString* yearStr = dateParts[2];

    // Convert month name to number
    NSDictionary* months = @{
        @"Jan": @"01", @"Feb": @"02", @"Mar": @"03", @"Apr": @"04",
        @"May": @"05", @"Jun": @"06", @"Jul": @"07", @"Aug": @"08",
        @"Sep": @"09", @"Oct": @"10", @"Nov": @"11", @"Dec": @"12"
    };
    NSString* monthNum = months[monthStr];
    if (monthNum == nil) return nil;

    // Format day with leading zero
    int day = [dayStr intValue];
    NSString* dayNum = [NSString stringWithFormat:@"%02d", day];

    // Get 2-digit year
    NSString* yearShort = [yearStr substringFromIndex:[yearStr length] - 2];

    // Convert time HH:MM:SS to HH.MM.SS
    NSString* timeDotted = [timeStr stringByReplacingOccurrencesOfString:@":" withString:@"."];

    return [NSString stringWithFormat:@"%@.%@.%@ (%@)", yearShort, monthNum, dayNum, timeDotted];
}

// Find meshagent binary path from install directory
// Checks: LaunchDaemon plist programPath, .app bundles, bare binary
- (NSString*)findMeshagentBinary:(NSString*)installPath {
    if (installPath == nil || [installPath length] == 0) {
        return nil;
    }

    NSFileManager* fm = [NSFileManager defaultManager];

    // First: scan LaunchDaemons to find the actual program path
    DIR* dir = opendir("/Library/LaunchDaemons");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, ".plist") == NULL) continue;

            char plistPath[1024];
            snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

            MeshPlistInfo info;
            if (mesh_parse_launchdaemon_plist(plistPath, &info, [[self getAgentBaseName] UTF8String])) {
                // Check if this plist's program path is under our install path
                NSString* programPath = [NSString stringWithUTF8String:info.programPath];
                if ([programPath hasPrefix:installPath] && [fm isExecutableFileAtPath:programPath]) {
                    closedir(dir);
                    return programPath;
                }
            }
        }
        closedir(dir);
    }

    // Second: look for any .app bundle containing our agent binary
    NSString* baseName = [self getAgentBaseName];
    if (!baseName) baseName = @"meshagent";

    NSError* error = nil;
    NSArray* contents = [fm contentsOfDirectoryAtPath:installPath error:&error];
    if (contents != nil) {
        for (NSString* item in contents) {
            if ([item hasSuffix:@".app"]) {
                NSString* candidate = [NSString stringWithFormat:@"%@/%@/Contents/MacOS/%@", installPath, item, baseName];
                if ([fm isExecutableFileAtPath:candidate]) {
                    return candidate;
                }
            }
        }
    }

    // Third: look for bare agent binary in install path
    NSString* bareBinary = [NSString stringWithFormat:@"%@/%@", installPath, baseName];
    if ([fm isExecutableFileAtPath:bareBinary]) {
        return bareBinary;
    }

    return nil;
}

- (void)updateInstalledVersionLabel:(NSString*)installPath {
    if (installPath == nil || [installPath length] == 0) {
        [self.installedVersionLabel setStringValue:@""];
        return;
    }

    // Find the meshagent binary (from plist, .app bundle, or bare binary)
    NSString* binaryPath = [self findMeshagentBinary:installPath];

    if (binaryPath == nil) {
        [self.installedVersionLabel setStringValue:@"Installed: Version unknown"];
        return;
    }

    // Try -fullversion first (output: "XX.XX.XX XX.XX.XX")
    NSString* output = [self runMeshagent:binaryPath withArg:@"-fullversion"];

    if (output != nil && [output length] > 0) {
        NSArray* parts = [output componentsSeparatedByString:@" "];
        if ([parts count] >= 2) {
            [self.installedVersionLabel setStringValue:
                [NSString stringWithFormat:@"Installed: %@ (%@)", parts[0], parts[1]]];
            return;
        } else if ([parts count] == 1 && [parts[0] length] > 0) {
            [self.installedVersionLabel setStringValue:
                [NSString stringWithFormat:@"Installed: %@", parts[0]]];
            return;
        }
    }

    // Fallback: try -info and parse "Compiled on:" line
    output = [self runMeshagent:binaryPath withArg:@"-info"];

    if (output != nil) {
        NSArray* lines = [output componentsSeparatedByString:@"\n"];
        for (NSString* line in lines) {
            if ([line hasPrefix:@"Compiled on:"]) {
                NSString* parsed = [self parseCompiledOnLine:line];
                if (parsed != nil) {
                    [self.installedVersionLabel setStringValue:
                        [NSString stringWithFormat:@"Installed: %@", parsed]];
                    return;
                }
            }
        }
    }

    [self.installedVersionLabel setStringValue:@"Installed: Version unknown"];
}

- (void)showProgressWindow {
    const char* modeStr = (self.selectedMode == INSTALL_MODE_UPGRADE ? "UPGRADE" :
                           (self.selectedMode == INSTALL_MODE_UNINSTALL ? "UNINSTALL" : "INSTALL"));
    mesh_log_message("[INSTALL-UI] Showing progress window for %s mode\n", modeStr);

    NSWindow* mainWindow = (NSWindow*)[self.contentView window];

    // Create progress window (taller to fit status label and OK button)
    NSRect frame = NSMakeRect(0, 0, 500, 420);
    self.progressWindow = [[NSWindow alloc]
        initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled)
        backing:NSBackingStoreBuffered
        defer:NO];

    NSString* displayName = [self getAgentDisplayName];
    NSString* actionVerb = (self.selectedMode == INSTALL_MODE_UPGRADE ? @"Upgrading" :
                            (self.selectedMode == INSTALL_MODE_UNINSTALL ?
                             (self.result->fullUninstall ? @"Fully Uninstalling" : @"Uninstalling") : @"Installing"));
    [self.progressWindow setTitle:[NSString stringWithFormat:@"%@ %@", actionVerb, displayName]];
    [self.progressWindow center];
    [self.progressWindow setLevel:NSFloatingWindowLevel];

    NSView* contentView = [self.progressWindow contentView];

    // Add title label
    NSTextField* titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 380, 460, 24)];
    [titleLabel setStringValue:[NSString stringWithFormat:@"%@ %@...", actionVerb, displayName]];
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
            NSString* dName = [self getAgentDisplayName];
            NSString* actionPast = (self.selectedMode == INSTALL_MODE_UPGRADE ? @"upgraded" :
                                    (self.selectedMode == INSTALL_MODE_UNINSTALL ?
                                     (self.result->fullUninstall ? @"fully uninstalled" : @"uninstalled") : @"installed"));
            NSString* message = [NSString stringWithFormat:@"✓ %@ has been %@ successfully.",
                dName, actionPast];
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
                          [NSString stringWithFormat:@"Please select the existing %@ installation directory.", [self getAgentDisplayName]],
                          NSAlertStyleWarning);
            return;
        }

        // Validate the upgrade path exists and is a directory
        BOOL isDir;
        if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] || !isDir) {
            mesh_showAlert(@"Installation Not Found",
                          [NSString stringWithFormat:@"No %@ installation found at:\n%@\n\nPlease select a valid installation directory.", [self getAgentDisplayName], path],
                          NSAlertStyleWarning);
            return;
        }

        // Check for valid installation: minimum is <agent>.db OR <agent>.msh
        NSString* agentDbName = [self getAgentDbName];
        NSString* agentMshName = [self getAgentMshName];
        if (!agentDbName || !agentMshName) {
            mesh_showAlert(@"Internal Error",
                          @"Failed to determine agent configuration file names.",
                          NSAlertStyleCritical);
            return;
        }
        NSString* dbPath = [path stringByAppendingPathComponent:agentDbName];
        NSString* mshPathCheck = [path stringByAppendingPathComponent:agentMshName];
        BOOL hasDb = [[NSFileManager defaultManager] fileExistsAtPath:dbPath];
        BOOL hasMsh = [[NSFileManager defaultManager] fileExistsAtPath:mshPathCheck];

        if (!hasDb && !hasMsh) {
            mesh_showAlert(@"Invalid Installation Directory",
                          [NSString stringWithFormat:@"The directory does not contain a valid %@ installation:\n%@\n\nExpected %@ or %@", [self getAgentDisplayName], path, agentDbName, agentMshName],
                          NSAlertStyleWarning);
            return;
        }

        // Validate path length before copying
        const char* pathCStr = [path UTF8String];
        if (strlen(pathCStr) >= sizeof(self.result->installPath)) {
            mesh_showAlert(@"Path Too Long",
                          [NSString stringWithFormat:@"Installation path exceeds maximum length of %lu characters:\n%@",
                           (unsigned long)(sizeof(self.result->installPath) - 1), path],
                          NSAlertStyleWarning);
            return;
        }

        // Copy to result
        strncpy(self.result->installPath, pathCStr, sizeof(self.result->installPath) - 1);
        self.result->installPath[sizeof(self.result->installPath) - 1] = '\0';
        self.result->mshFilePath[0] = '\0';

    } else if (self.selectedMode == INSTALL_MODE_UNINSTALL) {
        NSString* path = [self.uninstallPathField stringValue];
        if (path == nil || [path length] == 0) {
            mesh_showAlert(@"Installation Path Required",
                          [NSString stringWithFormat:@"Please select the %@ installation directory to uninstall.", [self getAgentDisplayName]],
                          NSAlertStyleWarning);
            return;
        }

        // Validate the path exists and is a directory
        BOOL isDir;
        if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] || !isDir) {
            mesh_showAlert(@"Installation Not Found",
                          [NSString stringWithFormat:@"No %@ installation found at:\n%@\n\nPlease select a valid installation directory.", [self getAgentDisplayName], path],
                          NSAlertStyleWarning);
            return;
        }

        // Validate path length before copying
        const char* pathCStr = [path UTF8String];
        if (strlen(pathCStr) >= sizeof(self.result->installPath)) {
            mesh_showAlert(@"Path Too Long",
                          [NSString stringWithFormat:@"Installation path exceeds maximum length of %lu characters:\n%@",
                           (unsigned long)(sizeof(self.result->installPath) - 1), path],
                          NSAlertStyleWarning);
            return;
        }

        // Set fullUninstall from sub-radio state
        self.result->fullUninstall = ([self.fullUninstallRadio state] == NSControlStateValueOn) ? 1 : 0;

        // Confirmation dialog
        NSAlert* alert = [[NSAlert alloc] init];
        if (self.result->fullUninstall) {
            [alert setMessageText:@"Confirm Full Uninstall"];
            [alert setInformativeText:[NSString stringWithFormat:@"This will fully uninstall %@ and remove all associated data from:\n%@\n\nThis action cannot be undone.", [self getAgentDisplayName], path]];
            [alert setAlertStyle:NSAlertStyleCritical];
        } else {
            [alert setMessageText:@"Confirm Uninstall"];
            [alert setInformativeText:[NSString stringWithFormat:@"This will uninstall %@ from:\n%@\n\nThis action cannot be undone.", [self getAgentDisplayName], path]];
            [alert setAlertStyle:NSAlertStyleWarning];
        }
        [alert addButtonWithTitle:self.result->fullUninstall ? @"Full Uninstall" : @"Uninstall"];
        [alert addButtonWithTitle:@"Cancel"];

        if ([alert runModal] != NSAlertFirstButtonReturn) {
            return;  // User cancelled
        }

        // Copy to result
        strncpy(self.result->installPath, pathCStr, sizeof(self.result->installPath) - 1);
        self.result->installPath[sizeof(self.result->installPath) - 1] = '\0';
        self.result->mshFilePath[0] = '\0';

    } else {
        NSString* installPath = [self.installPathField stringValue];
        NSString* mshPath = [self.mshFileField stringValue];

        if (installPath == nil || [installPath length] == 0) {
            mesh_showAlert(@"Installation Path Required",
                          [NSString stringWithFormat:@"Please select where to install %@.", [self getAgentDisplayName]],
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
                          [NSString stringWithFormat:@"Please select the %@ configuration file.", [self getAgentMshName] ?: @".msh"],
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

        // Validate path lengths before copying
        const char* installPathCStr = [installPath UTF8String];
        const char* mshPathCStr = [mshPath UTF8String];

        if (strlen(installPathCStr) >= sizeof(self.result->installPath)) {
            mesh_showAlert(@"Path Too Long",
                          [NSString stringWithFormat:@"Installation path exceeds maximum length of %lu characters:\n%@",
                           (unsigned long)(sizeof(self.result->installPath) - 1), installPath],
                          NSAlertStyleWarning);
            return;
        }

        if (strlen(mshPathCStr) >= sizeof(self.result->mshFilePath)) {
            mesh_showAlert(@"Path Too Long",
                          [NSString stringWithFormat:@"Configuration file path exceeds maximum length of %lu characters:\n%@",
                           (unsigned long)(sizeof(self.result->mshFilePath) - 1), mshPath],
                          NSAlertStyleWarning);
            return;
        }

        // Copy to result
        strncpy(self.result->installPath, installPathCStr, sizeof(self.result->installPath) - 1);
        self.result->installPath[sizeof(self.result->installPath) - 1] = '\0';

        strncpy(self.result->mshFilePath, mshPathCStr, sizeof(self.result->mshFilePath) - 1);
        self.result->mshFilePath[sizeof(self.result->mshFilePath) - 1] = '\0';
    }

    self.result->mode = self.selectedMode;
    self.result->disableUpdate = ([self.enableUpdateCheckbox state] == NSControlStateValueOn) ? 1 : 0;
    self.result->disableTccCheck = ([self.disableTccCheckCheckbox state] == NSControlStateValueOn) ? 1 : 0;
    self.result->verboseLogging = ([self.verboseLoggingCheckbox state] == NSControlStateValueOn) ? 1 : 0;
    self.result->meshAgentLogging = ([self.meshAgentLoggingCheckbox state] == NSControlStateValueOn) ? 1 : 0;
    self.result->cancelled = 0;

    mesh_log_message("[INSTALL-UI] Starting %s: path=%s, updates=%s, tccCheck=%s, verboseLog=%s, meshAgentLog=%s\n",
                     (self.selectedMode == INSTALL_MODE_UPGRADE ? "UPGRADE" :
                      (self.selectedMode == INSTALL_MODE_UNINSTALL ? "UNINSTALL" : "INSTALL")),
                     self.result->installPath,
                     (self.result->disableUpdate ? "disabled" : "enabled"),
                     (self.result->disableTccCheck ? "disabled" : "enabled"),
                     (self.result->verboseLogging ? "enabled" : "disabled"),
                     (self.result->meshAgentLogging ? "enabled" : "disabled"));

    // Request admin authorization (shows system password dialog)
    if (acquire_admin_authorization() != 0) {
        mesh_log_message("[INSTALL-UI] Admin authorization denied or cancelled\n");
        mesh_showAlert(@"Authorization Required",
                      [NSString stringWithFormat:@"Administrator privileges are required to %@.",
                       (self.selectedMode == INSTALL_MODE_UPGRADE ? @"upgrade" :
                        (self.selectedMode == INSTALL_MODE_UNINSTALL ? @"uninstall" : @"install"))],
                      NSAlertStyleWarning);
        return;
    }

    // Show progress window
    [self showProgressWindow];

    // Set up progress callback to stream output to UI
    // Use unsafe_unretained pattern for MRC (Manual Reference Counting)
    // Modal window context ensures self remains valid during operation
    __unsafe_unretained typeof(self) weakSelf = self;
    set_progress_callback(^(const char* line) {
        typeof(self) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf appendProgressText:[NSString stringWithUTF8String:line]];
        }
    });

    // Execute upgrade/install in background thread
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int exitCode = 0;

        if (self.selectedMode == INSTALL_MODE_UNINSTALL) {
            [self appendProgressText:[NSString stringWithFormat:@"%@ %@ at: %s\n",
                (self.result->fullUninstall ? @"Fully uninstalling" : @"Uninstalling"),
                [self getAgentDisplayName], self.result->installPath]];
            [self appendProgressText:[NSString stringWithFormat:@"Verbose installer logging: %s\n\n",
                self.result->verboseLogging ? "enabled" : "disabled"]];

            exitCode = execute_meshagent_uninstall(self.result->installPath, self.result->fullUninstall, self.result->verboseLogging);
        } else if (self.selectedMode == INSTALL_MODE_UPGRADE) {
            [self appendProgressText:[NSString stringWithFormat:@"Upgrading %@ at: %s\n", [self getAgentDisplayName], self.result->installPath]];
            [self appendProgressText:[NSString stringWithFormat:@"Automatic updates: %s\n",
                self.result->disableUpdate ? "disabled" : "enabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"TCC Check UI: %s\n",
                self.result->disableTccCheck ? "disabled" : "enabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"Verbose installer logging: %s\n",
                self.result->verboseLogging ? "enabled" : "disabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"Agent logging: %s\n\n",
                self.result->meshAgentLogging ? "enabled" : "disabled"]];

            exitCode = execute_meshagent_upgrade(self.result->installPath, self.result->disableUpdate, self.result->disableTccCheck, self.result->verboseLogging, self.result->meshAgentLogging);
        } else {
            [self appendProgressText:[NSString stringWithFormat:@"Installing %@ to: %s\n", [self getAgentDisplayName], self.result->installPath]];
            [self appendProgressText:[NSString stringWithFormat:@"Configuration file: %s\n", self.result->mshFilePath]];
            [self appendProgressText:[NSString stringWithFormat:@"Automatic updates: %s\n",
                self.result->disableUpdate ? "disabled" : "enabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"TCC Check UI: %s\n",
                self.result->disableTccCheck ? "disabled" : "enabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"Verbose installer logging: %s\n",
                self.result->verboseLogging ? "enabled" : "disabled"]];
            [self appendProgressText:[NSString stringWithFormat:@"Agent logging: %s\n\n",
                self.result->meshAgentLogging ? "enabled" : "disabled"]];

            exitCode = execute_meshagent_install(self.result->installPath, self.result->mshFilePath, self.result->disableUpdate, self.result->disableTccCheck, self.result->verboseLogging, self.result->meshAgentLogging);
        }

        // Clear callback and release admin authorization
        set_progress_callback(NULL);
        release_admin_authorization();

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

// Get base filename from executable path for dynamic .msh/.db naming (C function)
static void getAgentBaseNameC(char *baseName, size_t baseNameSize) {
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);

    if (_NSGetExecutablePath(execPath, &size) != 0) {
        baseName[0] = '\0';  // Empty on failure - caller must handle
        return;
    }

    char *lastSlash = strrchr(execPath, '/');
    const char *filename = lastSlash ? lastSlash + 1 : execPath;

    strncpy(baseName, filename, baseNameSize - 1);
    baseName[baseNameSize - 1] = '\0';

    char *dot = strrchr(baseName, '.');
    if (dot) *dot = '\0';
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

    // Get agent base name for plist matching
    char agentBaseName[256];
    getAgentBaseNameC(agentBaseName, sizeof(agentBaseName));

    MeshPlistInfo plists[100];
    int plistCount = 0;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && plistCount < 100) {
        // Only process .plist files
        if (strstr(entry->d_name, ".plist") == NULL) continue;

        char plistPath[1024];
        snprintf(plistPath, sizeof(plistPath), "/Library/LaunchDaemons/%s", entry->d_name);

        MeshPlistInfo info;
        if (mesh_parse_launchdaemon_plist(plistPath, &info, agentBaseName)) {
            mesh_log_message("[INSTALL-UI] Found agent plist: %s (program: %s)\n",
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
    // Validate path length before copying
    if (strlen(plists[newestIndex].programPath) >= 1024) {
        mesh_log_message("[INSTALL-UI] ERROR: Program path too long in plist\n");
        return NULL;
    }

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
            char* result = strdup(pathCopy);
            if (result == NULL) {
                mesh_log_message("[INSTALL-UI] ERROR: Memory allocation failed in findExistingInstallation\n");
            }
            return result;
        }
    } else {
        // For standalone binaries, return the directory containing the binary
        char* lastSlash = strrchr(pathCopy, '/');
        if (lastSlash != NULL) {
            *lastSlash = '\0';
            char* result = strdup(pathCopy);
            if (result == NULL) {
                mesh_log_message("[INSTALL-UI] ERROR: Memory allocation failed in findExistingInstallation\n");
            }
            return result;
        }
    }

    return NULL;
}

// Helper function to get default installation path
static const char* getDefaultInstallPath(void) {
    // Check if ACMEAgent is installed
    if (fileExists("/opt/acmeagent/acmeagent")) {
        return "/opt/acmemesh";
    }

    // Build path from executable name
    static char defaultPath[PATH_MAX];
    char exePath[PATH_MAX];
    uint32_t size = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &size) == 0) {
        char *base = basename(exePath);
        if (base != NULL && strlen(base) > 0 && strcmp(base, ".") != 0 && strcmp(base, "/") != 0) {
            snprintf(defaultPath, sizeof(defaultPath), "/usr/local/mesh_services/%s", base);
            return defaultPath;
        }
    }
    return "/usr/local/mesh_services/agent";
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

    // Get directory to search for .msh file
    // If running from inside an .app bundle (path contains ".app/Contents/MacOS/"),
    // search the directory containing the .app bundle, not the MacOS directory inside it
    char searchDir[1024];
    char* appPos = strstr(exePath, ".app/Contents/MacOS/");
    if (appPos != NULL) {
        // Truncate at .app to get bundle path, then strip bundle name to get parent dir
        *appPos = '\0'; // exePath is now e.g. "/path/to/ACMEmesh"
        char* lastSlash = strrchr(exePath, '/');
        if (lastSlash != NULL && lastSlash != exePath) {
            *lastSlash = '\0';
            strlcpy(searchDir, exePath, sizeof(searchDir));
        } else {
            strlcpy(searchDir, ".", sizeof(searchDir));
        }
    } else {
        strlcpy(searchDir, dirname(exePath), sizeof(searchDir));
    }
    char* dir = searchDir;
    mesh_log_message("[INSTALL-UI] Searching for .msh file in directory: %s\n", dir);

    // Look for .msh files in the same directory
    char mshPath[2048];

    // Get agent base name for dynamic file naming
    char agentBaseName[256];
    getAgentBaseNameC(agentBaseName, sizeof(agentBaseName));

    // First try <agentname>.msh (e.g., meshagent.msh or acmemesh.msh)
    if (agentBaseName[0] != '\0') {
        snprintf(mshPath, sizeof(mshPath), "%s/%s.msh", dir, agentBaseName);
        if (fileExists(mshPath)) {
            // .msh file validation is performed by meshagent binary during install execution
            // UI-level check for file existence and readability is sufficient
            // File format validation happens in the install/upgrade process with proper error handling
            mesh_log_message("[INSTALL-UI] Found .msh file: %s\n", mshPath);
            char* result = strdup(mshPath);
            if (result == NULL) {
                mesh_log_message("[INSTALL-UI] ERROR: Memory allocation failed in findMshFile\n");
            }
            return result;
        }
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
                char* result = strdup(mshPath);
                if (result == NULL) {
                    mesh_log_message("[INSTALL-UI] ERROR: Memory allocation failed in findMshFile\n");
                }
                return result;
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

        // Get display name for dynamic UI labels
        NSString* agentName = mesh_getAgentDisplayName();

        // Create window
        NSRect frame = NSMakeRect(0, 0, 600, 620);
        NSWindow* window = [[NSWindow alloc]
            initWithContentRect:frame
            styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
            backing:NSBackingStoreBuffered
            defer:NO];

        [window setTitle:[NSString stringWithFormat:@"%@ Deployment Assistant", agentName]];

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

        // Add header icon (Lucide "network")
        NSImageView* headerIcon = [[NSImageView alloc] initWithFrame:NSMakeRect(40, 550, 40, 40)];
        [headerIcon setImage:mesh_lucideNetworkIcon(40)];
        [headerIcon setContentTintColor:[NSColor blackColor]];
        [contentView addSubview:headerIcon];

        // Add title
        NSTextField* titleLabel = mesh_createLabel([NSString stringWithFormat:@"%@ Deployment Assistant", agentName], NSMakeRect(90, 570, 490, 24), YES);
        [titleLabel setFont:[NSFont systemFontOfSize:16 weight:NSFontWeightBold]];
        [contentView addSubview:titleLabel];

        // Add description (tight spacing below title)
        NSTextField* descLabel = mesh_createLabel([NSString stringWithFormat:@"Install, upgrade, or uninstall %@", agentName], NSMakeRect(90, 554, 490, 20), NO);
        [contentView addSubview:descLabel];

        // Add version info (prominently displayed)
        NSString* version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        NSString* build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
        NSString* versionString = [NSString stringWithFormat:@"Version %@ (Build %@)",
            version ?: @"Unknown", build ?: @"Unknown"];
        NSTextField* versionLabel = mesh_createLabel(versionString, NSMakeRect(90, 538, 490, 20), NO);
        [versionLabel setFont:[NSFont systemFontOfSize:14 weight:NSFontWeightRegular]];
        [versionLabel setTextColor:[NSColor secondaryLabelColor]];
        [contentView addSubview:versionLabel];

        // Radio buttons for mode selection - Install first, then Upgrade
        NSButton* newInstallRadio = [[NSButton alloc] initWithFrame:NSMakeRect(40, 493, 300, 20)];
        [newInstallRadio setButtonType:NSButtonTypeRadio];
        [newInstallRadio setTitle:[NSString stringWithFormat:@"Install %@", agentName]];
        [newInstallRadio setState:(initialMode == INSTALL_MODE_NEW) ? NSControlStateValueOn : NSControlStateValueOff];
        [newInstallRadio setTag:INSTALL_MODE_NEW];
        [newInstallRadio setTarget:buttonHandler];
        [newInstallRadio setAction:@selector(modeChanged:)];
        [contentView addSubview:newInstallRadio];
        buttonHandler.installIcon = mesh_addRadioIcon(mesh_lucideImportIcon(20), newInstallRadio, contentView);
        [buttonHandler.installIcon setContentTintColor:(initialMode == INSTALL_MODE_NEW) ? [NSColor blackColor] : [NSColor secondaryLabelColor]];

        // Install path field
        NSTextField* installPathLabel = mesh_createLabel(@"Install path:", NSMakeRect(60, 460, 520, 20), NO);
        [contentView addSubview:installPathLabel];

        NSTextField* installPathField = mesh_createPathField(NSMakeRect(60, 435, 380, 24),
            [NSString stringWithUTF8String:getDefaultInstallPath()]);
        [installPathField setEnabled:(initialMode == INSTALL_MODE_NEW)];
        [installPathField setStringValue:[NSString stringWithUTF8String:defaultInstallPath]];
        buttonHandler.installPathField = installPathField;
        [contentView addSubview:installPathField];

        NSButton* browseInstall = mesh_createRoundedButton(@"Browse...", NSMakeRect(450, 435, 100, 24),
            buttonHandler, @selector(browseInstallPath:), BUTTON_TAG_BROWSE_INSTALL);
        [browseInstall setEnabled:(initialMode == INSTALL_MODE_NEW)];
        [contentView addSubview:browseInstall];

        // MSH file field (grouped with Install)
        NSTextField* mshFileLabel = mesh_createLabel(@"Configuration file (.msh):", NSMakeRect(60, 405, 520, 20), NO);
        [contentView addSubview:mshFileLabel];

        // View button (left of field) - initially disabled, enabled when file selected
        NSButton* editMsh = [[NSButton alloc] initWithFrame:NSMakeRect(20, 380, 36, 24)];
        [editMsh setTitle:@"View"];
        [editMsh setBezelStyle:NSBezelStyleRounded];
        [editMsh setTarget:buttonHandler];
        [editMsh setAction:@selector(editMshFile:)];
        [editMsh setEnabled:NO];  // Disabled until file is selected
        [editMsh setFont:[NSFont systemFontOfSize:11]];
        buttonHandler.editMshButton = editMsh;
        [contentView addSubview:editMsh];

        NSTextField* mshFileField = mesh_createPathField(NSMakeRect(60, 380, 380, 24),
            [buttonHandler getAgentMshName] ?: @"agent.msh");
        [mshFileField setEnabled:(initialMode == INSTALL_MODE_NEW)];
        if (mshFile != NULL) {
            [mshFileField setStringValue:[NSString stringWithUTF8String:mshFile]];
            if (initialMode == INSTALL_MODE_NEW) {
                [editMsh setEnabled:YES];  // Enable if file already provided and in install mode
            }
        }
        buttonHandler.mshFileField = mshFileField;
        [contentView addSubview:mshFileField];

        NSButton* browseMsh = mesh_createRoundedButton(@"Browse...", NSMakeRect(450, 380, 100, 24),
            buttonHandler, @selector(browseMshFile:), BUTTON_TAG_BROWSE_MSH);
        [browseMsh setEnabled:(initialMode == INSTALL_MODE_NEW)];
        [contentView addSubview:browseMsh];

        // Upgrade radio
        NSButton* upgradeRadio = [[NSButton alloc] initWithFrame:NSMakeRect(40, 335, 300, 20)];
        [upgradeRadio setButtonType:NSButtonTypeRadio];
        [upgradeRadio setTitle:[NSString stringWithFormat:@"Upgrade %@", agentName]];
        [upgradeRadio setState:(initialMode == INSTALL_MODE_UPGRADE) ? NSControlStateValueOn : NSControlStateValueOff];
        [upgradeRadio setTag:INSTALL_MODE_UPGRADE];
        [upgradeRadio setTarget:buttonHandler];
        [upgradeRadio setAction:@selector(modeChanged:)];
        [contentView addSubview:upgradeRadio];
        buttonHandler.upgradeIcon = mesh_addRadioIcon(mesh_lucideUploadIcon(20), upgradeRadio, contentView);
        [buttonHandler.upgradeIcon setContentTintColor:(initialMode == INSTALL_MODE_UPGRADE) ? [NSColor blackColor] : [NSColor secondaryLabelColor]];

        // Upgrade path field
        NSTextField* upgradePathLabel = mesh_createLabel(@"Current install path:", NSMakeRect(60, 305, 520, 20), NO);
        [contentView addSubview:upgradePathLabel];

        NSTextField* upgradePathField = mesh_createPathField(NSMakeRect(60, 280, 380, 24),
            [NSString stringWithUTF8String:getDefaultInstallPath()]);
        [upgradePathField setEnabled:(initialMode == INSTALL_MODE_UPGRADE)];
        int existingEnableUpdate = 1;  // Default to updates enabled
        int existingEnableTccCheck = 1;  // Default to TCC check enabled
        if (existingInstall != NULL) {
            [upgradePathField setStringValue:[NSString stringWithUTF8String:existingInstall]];

            // Read existing settings from installation
            char installPath[2048];
            snprintf(installPath, sizeof(installPath), "%s/", existingInstall);

            existingEnableUpdate = read_existing_update_setting(installPath);
            if (existingEnableUpdate < 0) {
                existingEnableUpdate = 1;  // Default to enabled on error
            }

            existingEnableTccCheck = read_existing_tcc_check_setting(installPath);
            if (existingEnableTccCheck < 0) {
                existingEnableTccCheck = 1;  // Default to enabled on error
            }
        }
        buttonHandler.upgradePathField = upgradePathField;
        [contentView addSubview:upgradePathField];

        NSButton* browseUpgrade = mesh_createRoundedButton(@"Browse...", NSMakeRect(450, 280, 100, 24),
            buttonHandler, @selector(browseUpgradePath:), BUTTON_TAG_BROWSE_UPGRADE);
        [browseUpgrade setEnabled:(initialMode == INSTALL_MODE_UPGRADE)];
        [contentView addSubview:browseUpgrade];

        // Installed version label (updated dynamically when path changes)
        NSTextField* installedVersionLabel = mesh_createLabel(@"", NSMakeRect(60, 266, 490, 14), NO);
        [installedVersionLabel setFont:[NSFont systemFontOfSize:11]];
        [installedVersionLabel setTextColor:[NSColor secondaryLabelColor]];
        buttonHandler.installedVersionLabel = installedVersionLabel;
        [contentView addSubview:installedVersionLabel];

        // Set initial installed version if we have an existing installation
        if (existingInstall != NULL) {
            [buttonHandler updateInstalledVersionLabel:[NSString stringWithUTF8String:existingInstall]];
        }

        // Settings card (very light grey NSBox with 2x2 checkbox grid)
        NSBox* settingsCard = [[NSBox alloc] initWithFrame:NSMakeRect(20, 190, 560, 70)];
        [settingsCard setBoxType:NSBoxCustom];
        [settingsCard setBorderType:NSLineBorder];
        [settingsCard setCornerRadius:8.0];
        [settingsCard setFillColor:[NSColor colorWithWhite:0.95 alpha:1.0]];
        [settingsCard setBorderColor:[NSColor colorWithWhite:0.88 alpha:1.0]];
        [settingsCard setContentViewMargins:NSMakeSize(8, 6)];
        [settingsCard setTitlePosition:NSNoTitle];
        [contentView addSubview:settingsCard];
        NSView* cardContent = [settingsCard contentView];

        // Row 1 (top row inside card)
        NSControlStateValue updateState = (initialMode == INSTALL_MODE_UPGRADE && existingEnableUpdate == 0) ? NSControlStateValueOn : NSControlStateValueOff;
        NSButton* enableUpdateCheckbox = mesh_createCheckbox(@"Disable automatic updates",
            NSMakeRect(12, 28, 250, 20), updateState, nil, NULL);
        buttonHandler.enableUpdateCheckbox = enableUpdateCheckbox;
        [cardContent addSubview:enableUpdateCheckbox];

        NSButton* meshAgentLoggingCheckbox = mesh_createCheckbox(
            [NSString stringWithFormat:@"Enable %@ logging", [buttonHandler getAgentBaseName] ?: @"agent"],
            NSMakeRect(272, 28, 260, 20), NSControlStateValueOff, nil, NULL);
        buttonHandler.meshAgentLoggingCheckbox = meshAgentLoggingCheckbox;
        [cardContent addSubview:meshAgentLoggingCheckbox];

        // Row 2 (bottom row inside card)
        NSControlStateValue tccState = (initialMode == INSTALL_MODE_UPGRADE && existingEnableTccCheck == 0) ? NSControlStateValueOn : NSControlStateValueOff;
        NSButton* disableTccCheckCheckbox = mesh_createCheckbox(@"Disable TCC permission check UI",
            NSMakeRect(12, 4, 250, 20), tccState, nil, NULL);
        buttonHandler.disableTccCheckCheckbox = disableTccCheckCheckbox;
        [cardContent addSubview:disableTccCheckCheckbox];

        NSButton* verboseLoggingCheckbox = mesh_createCheckbox(@"Enable verbose installer logging",
            NSMakeRect(272, 4, 260, 20), NSControlStateValueOff, nil, NULL);
        buttonHandler.verboseLoggingCheckbox = verboseLoggingCheckbox;
        [cardContent addSubview:verboseLoggingCheckbox];

        // Uninstall radio
        NSButton* uninstallRadio = [[NSButton alloc] initWithFrame:NSMakeRect(40, 155, 300, 20)];
        [uninstallRadio setButtonType:NSButtonTypeRadio];
        [uninstallRadio setTitle:[NSString stringWithFormat:@"Uninstall %@", agentName]];
        [uninstallRadio setState:NSControlStateValueOff];
        [uninstallRadio setTag:INSTALL_MODE_UNINSTALL];
        [uninstallRadio setTarget:buttonHandler];
        [uninstallRadio setAction:@selector(modeChanged:)];
        [contentView addSubview:uninstallRadio];
        buttonHandler.uninstallIcon = mesh_addRadioIcon(mesh_lucideTrashIcon(20), uninstallRadio, contentView);
        [buttonHandler.uninstallIcon setContentTintColor:[NSColor secondaryLabelColor]];

        // Uninstall path label
        NSTextField* uninstallPathLabel = mesh_createLabel(@"Current install path:", NSMakeRect(60, 127, 520, 20), NO);
        [contentView addSubview:uninstallPathLabel];

        // Uninstall path field
        NSTextField* uninstallPathField = mesh_createPathField(NSMakeRect(60, 102, 380, 24),
            [NSString stringWithUTF8String:getDefaultInstallPath()]);
        [uninstallPathField setEnabled:NO];
        if (existingInstall != NULL) {
            [uninstallPathField setStringValue:[NSString stringWithUTF8String:existingInstall]];
        }
        buttonHandler.uninstallPathField = uninstallPathField;
        [contentView addSubview:uninstallPathField];

        // Uninstall browse button
        NSButton* browseUninstall = mesh_createRoundedButton(@"Browse...", NSMakeRect(450, 102, 100, 24),
            buttonHandler, @selector(browseUninstallPath:), BUTTON_TAG_BROWSE_UNINSTALL);
        [browseUninstall setEnabled:NO];
        [contentView addSubview:browseUninstall];

        // Sub-radios for uninstall type (in separate NSView to form their own radio group)
        NSView* uninstallTypeContainer = [[NSView alloc] initWithFrame:NSMakeRect(60, 75, 300, 24)];

        NSButton* standardUninstallRadio = [[NSButton alloc] initWithFrame:NSMakeRect(0, 0, 120, 20)];
        [standardUninstallRadio setButtonType:NSButtonTypeRadio];
        [standardUninstallRadio setTitle:@"Uninstall"];
        [standardUninstallRadio setState:NSControlStateValueOn];
        [standardUninstallRadio setEnabled:NO];
        [standardUninstallRadio setTarget:buttonHandler];
        [standardUninstallRadio setAction:@selector(uninstallTypeChanged:)];
        buttonHandler.standardUninstallRadio = standardUninstallRadio;
        [uninstallTypeContainer addSubview:standardUninstallRadio];

        NSButton* fullUninstallRadio = [[NSButton alloc] initWithFrame:NSMakeRect(130, 0, 150, 20)];
        [fullUninstallRadio setButtonType:NSButtonTypeRadio];
        [fullUninstallRadio setTitle:@"Full Uninstall"];
        [fullUninstallRadio setState:NSControlStateValueOff];
        [fullUninstallRadio setEnabled:NO];
        [fullUninstallRadio setTarget:buttonHandler];
        [fullUninstallRadio setAction:@selector(uninstallTypeChanged:)];
        buttonHandler.fullUninstallRadio = fullUninstallRadio;
        [uninstallTypeContainer addSubview:fullUninstallRadio];

        [contentView addSubview:uninstallTypeContainer];

        // Bottom buttons
        NSButton* cancelButton = mesh_createRoundedButton(@"Cancel", NSMakeRect(390, 15, 90, 32),
            delegate, @selector(cancelClicked:), 0);
        [cancelButton setKeyEquivalent:@"\033"]; // ESC key
        [contentView addSubview:cancelButton];

        NSButton* installButton = mesh_createRoundedButton(
            (initialMode == INSTALL_MODE_UPGRADE ? @"Upgrade" : @"Install"),
            NSMakeRect(490, 15, 90, 32), buttonHandler, @selector(installClicked:), 0);
        [installButton setKeyEquivalent:@"\r"]; // Enter key
        buttonHandler.installButton = installButton;
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
