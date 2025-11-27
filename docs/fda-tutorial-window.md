# FDA Tutorial Window Implementation Specification

## Overview

This document specifies the implementation of an interactive Full Disk Access (FDA) tutorial window for MeshAgent on macOS. The tutorial provides visual guidance to help users grant FDA permission through a drag-and-drop interface.

## Rationale

Unlike Accessibility and Screen Recording permissions, FDA cannot be triggered via API. Users must manually:
1. Open System Settings
2. Navigate to Privacy & Security → Full Disk Access
3. Click the lock icon to authenticate
4. Drag the application into the list (or use + button)
5. Enable the toggle switch

This multi-step process is confusing for many users. The tutorial window provides visual guidance and a draggable icon to simplify the process.

## User Experience Flow

```
User clicks "More Info" button on FDA section
         ↓
Tutorial window opens (800×550px)
         ↓
Left: Screenshot of System Settings showing FDA pane
Right: Instructions + draggable MeshAgent icon
         ↓
User drags icon to System Settings
  OR
User clicks "Open System Settings" button
         ↓
User grants permission in Settings
         ↓
Within 1 second: Main TCC window shows green checkmark
         ↓
User clicks "Finish" to close windows
```

## Button State Machine

### FDA Button States

The FDA button in the main TCC window has two states based on permission status:

```
┌─────────────────────────────────┐
│  TCC Window FDA Section         │
├─────────────────────────────────┤
│                                 │
│  Full Disk Access               │ ← Title
│  Full Disk Access permission... │ ← Description
│                                 │
│  [Permission Status]            │ ← Button (state below)
└─────────────────────────────────┘

Permission NOT granted:
┌─────────────┐
│  More Info  │ ← Rounded button
└─────────────┘
        ↓ Click
    Opens Tutorial Window

Permission GRANTED:
    ✓               ← Green checkmark icon (SF Symbol)
```

### State Transition

**Implementation Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:163-194`

**Current Code**:
```objective-c
- (void)updatePermissionStatus {
    TCC_PermissionStatus fda = check_fda_permission();

    for (NSView *subview in [self.contentView subviews]) {
        if ([subview isKindOfClass:[NSButton class]]) {
            NSButton *button = (NSButton*)subview;

            if ([button tag] == BUTTON_TAG_FDA) {
                if (fda == TCC_PERMISSION_GRANTED_USER ||
                    fda == TCC_PERMISSION_GRANTED_MDM) {
                    [self replaceButtonWithSuccessIcon:button];
                } else {
                    [self showButton:button];  // Currently shows "Open Settings"
                }
            }
        }
    }
}
```

**Modified Code**:
```objective-c
- (void)updatePermissionStatus {
    TCC_PermissionStatus fda = check_fda_permission();

    for (NSView *subview in [self.contentView subviews]) {
        if ([subview isKindOfClass:[NSButton class]]) {
            NSButton *button = (NSButton*)subview;

            if ([button tag] == BUTTON_TAG_FDA) {
                if (fda == TCC_PERMISSION_GRANTED_USER ||
                    fda == TCC_PERMISSION_GRANTED_MDM) {
                    [self replaceButtonWithSuccessIcon:button];
                } else {
                    // CHANGED: Show "More Info" instead of "Open Settings"
                    [self showMoreInfoButton:button];
                }
            }
        }
    }
}

// NEW METHOD: Show "More Info" button state
- (void)showMoreInfoButton:(NSButton*)button {
    // Check if already showing "More Info" (avoid redundant updates)
    if ([button image] == nil && [[button title] isEqualToString:@"More Info"]) {
        return;
    }

    [button setTitle:@"More Info"];
    [button setImage:nil];
    [button setImagePosition:NSImageLeft];
    [button setBordered:YES];
    [button setBezelStyle:NSBezelStyleRounded];

    // Same position as original button (yPos for FDA = 165)
    [button setFrame:NSMakeRect(440, 165 - 20, 140, 28)];
}
```

## Tutorial Window Specification

### Window Properties

| Property | Value |
|----------|-------|
| Width | 800px |
| Height | 550px |
| Style | Titled, Closable |
| Title | "Full Disk Access - Setup Guide" |
| Position | Centered on screen |
| Level | `NSFloatingWindowLevel` (stays on top) |
| Modal | Yes |
| Resizable | No |

### Layout

```
┌────────────────────────────────────────────────────────────────┐
│  Full Disk Access - Setup Guide                          [×]   │ ← Title bar
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  How to Grant Full Disk Access                                │ ← Header (18pt bold)
│                                                                │
│  ┌────────────────────┐   Instructions:                       │
│  │                    │                                        │
│  │   System Settings  │   1. Drag the MeshAgent icon below   │
│  │    Screenshot      │      to the Full Disk Access list in  │
│  │                    │      System Settings (shown on left)  │
│  │   [Privacy pane]   │                                        │
│  │   [FDA selected]   │   2. Toggle the switch next to        │
│  │   [Lock icon]      │      MeshAgent to enable access       │
│  │   [App list]       │                                        │
│  │                    │                                        │
│  │                    │         🐟 MeshAgent.app              │
│  │                    │      Drag me →   [64×64 icon]         │
│  │                    │                                        │
│  │                    │                                        │
│  └────────────────────┘   ┌─────────────────────┐            │
│   380×370px screenshot     │ Open System Settings │            │
│                           └─────────────────────┘            │
│                                                                │
│  ☐ Don't show this tutorial again                             │
│                                           [    Close    ]     │
└────────────────────────────────────────────────────────────────┘
  800×550px
```

### Component Positions

| Component | Frame (x, y, width, height) |
|-----------|-----------------------------|
| Header | (20, 510, 760, 24) |
| Screenshot | (20, 120, 380, 370) |
| Instructions Title | (420, 460, 360, 20) |
| Step 1 Text | (420, 400, 360, 60) |
| Step 2 Text | (420, 350, 360, 40) |
| Draggable Icon | (500, 250, 80, 80) |
| "Drag me" Label | (460, 280, 120, 20) |
| Open Settings Button | (420, 180, 200, 32) |
| Checkbox | (20, 20, 400, 20) |
| Close Button | (690, 20, 90, 32) |

## Draggable Icon Implementation

### Class: DraggableAppIconView

**Purpose**: NSImageView subclass that allows dragging the MeshAgent app bundle to System Settings

**Protocols**: `NSDraggingSource`, `NSPasteboardItemDataProvider`

**Properties**:
- `appBundlePath` (NSString*) - Path to MeshAgent.app bundle

### Complete Implementation

```objective-c
// Add to mac_permissions_window.m after TCCButtonHandler implementation

@interface DraggableAppIconView : NSImageView <NSDraggingSource, NSPasteboardItemDataProvider>
@property (nonatomic, strong) NSString *appBundlePath;
@end

@implementation DraggableAppIconView

- (void)mouseDown:(NSEvent *)event {
    if (!self.appBundlePath) {
        NSLog(@"[FDA-Tutorial] No app bundle path set, cannot drag");
        return;
    }

    NSLog(@"[FDA-Tutorial] Starting drag for bundle: %@", self.appBundlePath);

    // Create pasteboard item
    NSPasteboardItem *pbItem = [[NSPasteboardItem alloc] init];

    // Register this object as data provider
    [pbItem setDataProvider:self forTypes:@[NSPasteboardTypeFileURL]];

    // Create dragging item with the app icon
    NSDraggingItem *dragItem = [[NSDraggingItem alloc] initWithPasteboardWriter:pbItem];

    // Set drag image to the app icon
    NSRect dragFrame = NSMakeRect(0, 0, self.bounds.size.width, self.bounds.size.height);
    [dragItem setDraggingFrame:dragFrame contents:self.image];

    // Begin dragging session
    NSDraggingSession *session = [self beginDraggingSessionWithItems:@[dragItem]
                                                               event:event
                                                              source:self];

    // Animate back to starting position if drag fails/cancels
    session.animatesToStartingPositionsOnCancelOrFail = YES;
    session.draggingFormation = NSDraggingFormationNone;

    NSLog(@"[FDA-Tutorial] Drag session started");
}

#pragma mark - NSPasteboardItemDataProvider

- (void)pasteboard:(NSPasteboard *)pasteboard
              item:(NSPasteboardItem *)item
provideDataForType:(NSPasteboardType)type {

    if ([type isEqualToString:NSPasteboardTypeFileURL]) {
        NSURL *fileURL = [NSURL fileURLWithPath:self.appBundlePath];

        NSLog(@"[FDA-Tutorial] Providing file URL: %@", [fileURL absoluteString]);

        // Provide the file URL as data
        NSData *data = [[fileURL absoluteString] dataUsingEncoding:NSUTF8StringEncoding];
        [pasteboard setData:data forType:NSPasteboardTypeFileURL];

        // Also set as string for compatibility
        [pasteboard setString:[fileURL absoluteString] forType:NSPasteboardTypeFileURL];
    }
}

#pragma mark - NSDraggingSource

- (NSDragOperation)draggingSession:(NSDraggingSession *)session
    sourceOperationMaskForDraggingContext:(NSDraggingContext)context {

    // Allow copy operation (default for dragging apps)
    return NSDragOperationCopy;
}

- (void)draggingSession:(NSDraggingSession *)session
           endedAtPoint:(NSPoint)screenPoint
              operation:(NSDragOperation)operation {

    if (operation == NSDragOperationCopy) {
        NSLog(@"[FDA-Tutorial] Drag completed successfully at point: (%.0f, %.0f)",
              screenPoint.x, screenPoint.y);
    } else if (operation == NSDragOperationNone) {
        NSLog(@"[FDA-Tutorial] Drag cancelled or failed");
    }
}

@end
```

### Usage

```objective-c
// In show_fda_tutorial_window() function:

// Get app icon and bundle path
NSString *bundlePath = getBundlePathFromExecutable(exe_path);
NSImage *appIcon = getAppIcon(exe_path);

if (!appIcon) {
    // Fallback: use generic application icon
    appIcon = [[NSWorkspace sharedWorkspace] iconForFileType:NSFileTypeForHFSTypeCode(kGenericApplicationIcon)];
}

// Create draggable icon view
DraggableAppIconView *iconView = [[DraggableAppIconView alloc]
    initWithFrame:NSMakeRect(500, 250, 80, 80)];
[iconView setImage:appIcon];
[iconView setImageScaling:NSImageScaleProportionallyUpOrDown];
[iconView setAppBundlePath:bundlePath];

// Make it look draggable (add visual hint)
[iconView setImageFrameStyle:NSImageFramePhoto];  // Optional: adds border

[contentView addSubview:iconView];
```

## Helper Functions

### 1. Bundle Path Detection

**Purpose**: Convert executable path to .app bundle path

**Input**: `/opt/tacticalmesh/MeshAgent.app/Contents/MacOS/meshagent`

**Output**: `/opt/tacticalmesh/MeshAgent.app`

```objective-c
// Add to mac_permissions_window.m before show_fda_tutorial_window

static NSString* getBundlePathFromExecutable(const char* exe_path) {
    if (exe_path == NULL) {
        NSLog(@"[FDA-Tutorial] exe_path is NULL, using main bundle");
        return [[NSBundle mainBundle] bundlePath];
    }

    NSString *exePath = [NSString stringWithUTF8String:exe_path];
    NSLog(@"[FDA-Tutorial] Converting exe path: %@", exePath);

    // Split path into components
    NSArray *components = [exePath pathComponents];
    NSMutableArray *bundleComponents = [NSMutableArray array];

    // Walk path until we find .app bundle
    for (NSString *component in components) {
        [bundleComponents addObject:component];
        if ([component hasSuffix:@".app"]) {
            NSString *bundlePath = [NSString pathWithComponents:bundleComponents];
            NSLog(@"[FDA-Tutorial] Found bundle path: %@", bundlePath);
            return bundlePath;
        }
    }

    // Fallback: use main bundle
    NSLog(@"[FDA-Tutorial] No .app found in path, using main bundle");
    return [[NSBundle mainBundle] bundlePath];
}
```

### 2. App Icon Retrieval

**Purpose**: Get the MeshAgent application icon

```objective-c
static NSImage* getAppIcon(const char* exe_path) {
    NSString *bundlePath = getBundlePathFromExecutable(exe_path);

    if (bundlePath) {
        NSLog(@"[FDA-Tutorial] Getting icon for bundle: %@", bundlePath);

        // Get icon from bundle path
        NSImage *icon = [[NSWorkspace sharedWorkspace] iconForFile:bundlePath];

        if (icon) {
            // Set explicit size for consistency (Retina-compatible)
            [icon setSize:NSMakeSize(80, 80)];
            NSLog(@"[FDA-Tutorial] Retrieved app icon successfully");
            return icon;
        }
    }

    // Fallback: generic application icon
    NSLog(@"[FDA-Tutorial] Using generic application icon as fallback");
    return [[NSWorkspace sharedWorkspace] iconForFileType:NSFileTypeForHFSTypeCode(kGenericApplicationIcon)];
}
```

### 3. Tutorial Screenshot Loading

**Purpose**: Load the System Settings screenshot from bundle resources

**Resource Path**: `MeshAgent.app/Contents/Resources/fda_tutorial.png`

```objective-c
static NSImage* loadTutorialImage(const char* exe_path) {
    NSString *bundlePath = getBundlePathFromExecutable(exe_path);

    if (bundlePath) {
        // Load from bundle resources
        NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
        NSString *imagePath = [bundle pathForResource:@"fda_tutorial" ofType:@"png"];

        if (imagePath) {
            NSLog(@"[FDA-Tutorial] Loading screenshot from: %@", imagePath);
            NSImage *image = [[NSImage alloc] initWithContentsOfFile:imagePath];

            if (image) {
                NSLog(@"[FDA-Tutorial] Screenshot loaded successfully");
                return image;
            } else {
                NSLog(@"[FDA-Tutorial] Failed to load screenshot from path");
            }
        } else {
            NSLog(@"[FDA-Tutorial] Screenshot not found in bundle resources");
        }
    }

    // Fallback: try main bundle
    NSString *imagePath = [[NSBundle mainBundle] pathForResource:@"fda_tutorial" ofType:@"png"];
    if (imagePath) {
        NSLog(@"[FDA-Tutorial] Loading screenshot from main bundle: %@", imagePath);
        return [[NSImage alloc] initWithContentsOfFile:imagePath];
    }

    NSLog(@"[FDA-Tutorial] WARNING: Tutorial screenshot not found");
    return nil;  // Graceful degradation: window still works without screenshot
}
```

## Main Tutorial Window Function

### Function Signature

```objective-c
static void show_fda_tutorial_window(const char* exe_path, NSWindow* parentWindow);
```

**Parameters**:
- `exe_path` - Path to meshagent executable (used to find bundle and icon)
- `parentWindow` - Parent TCC window (not currently used, for future modal sheet support)

### Complete Implementation

```objective-c
// Add to mac_permissions_window.m after helper functions

static void show_fda_tutorial_window(const char* exe_path, NSWindow* parentWindow) {
    @autoreleasepool {
        NSLog(@"[FDA-Tutorial] Opening tutorial window");

        // Create window
        NSRect frame = NSMakeRect(0, 0, 800, 550);
        NSWindow* window = [[NSWindow alloc]
            initWithContentRect:frame
            styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
            backing:NSBackingStoreBuffered
            defer:NO];

        [window setTitle:@"Full Disk Access - Setup Guide"];
        [window center];
        [window setLevel:NSFloatingWindowLevel];

        NSView* contentView = [window contentView];

        // ===== HEADER =====
        NSTextField* headerLabel = createLabel(
            @"How to Grant Full Disk Access",
            NSMakeRect(20, 510, 760, 24),
            YES  // bold
        );
        [headerLabel setFont:[NSFont systemFontOfSize:18 weight:NSFontWeightBold]];
        [contentView addSubview:headerLabel];

        // ===== LEFT SIDE: SCREENSHOT =====
        NSImage *screenshot = loadTutorialImage(exe_path);
        if (screenshot) {
            NSImageView *screenshotView = [[NSImageView alloc]
                initWithFrame:NSMakeRect(20, 120, 380, 370)];
            [screenshotView setImage:screenshot];
            [screenshotView setImageScaling:NSImageScaleProportionallyUpOrDown];
            [screenshotView setWantsLayer:YES];
            [screenshotView.layer setBorderWidth:1.0];
            [screenshotView.layer setBorderColor:[[NSColor separatorColor] CGColor]];
            [screenshotView.layer setCornerRadius:4.0];
            [contentView addSubview:screenshotView];
        } else {
            // Show placeholder if screenshot missing
            NSTextField* placeholderLabel = createLabel(
                @"[System Settings Screenshot]\n\nPrivacy & Security >\nFull Disk Access",
                NSMakeRect(20, 120, 380, 370),
                NO
            );
            [placeholderLabel setAlignment:NSTextAlignmentCenter];
            [placeholderLabel setBackgroundColor:[NSColor controlBackgroundColor]];
            [placeholderLabel setDrawsBackground:YES];
            [placeholderLabel setBezeled:YES];
            [contentView addSubview:placeholderLabel];
        }

        // ===== RIGHT SIDE: INSTRUCTIONS =====
        NSTextField* instructionTitle = createLabel(
            @"Instructions:",
            NSMakeRect(420, 460, 360, 20),
            YES
        );
        [contentView addSubview:instructionTitle];

        // Step 1
        NSTextField* step1 = createLabel(
            @"1. Drag the MeshAgent icon below to the Full Disk Access list in System Settings (shown on the left)",
            NSMakeRect(420, 400, 360, 60),
            NO
        );
        [step1 setLineBreakMode:NSLineBreakByWordWrapping];
        [[step1 cell] setWraps:YES];
        [contentView addSubview:step1];

        // Step 2
        NSTextField* step2 = createLabel(
            @"2. Toggle the switch next to MeshAgent to enable access",
            NSMakeRect(420, 350, 360, 40),
            NO
        );
        [step2 setLineBreakMode:NSLineBreakByWordWrapping];
        [[step2 cell] setWraps:YES];
        [contentView addSubview:step2];

        // ===== DRAGGABLE APP ICON =====
        NSString *bundlePath = getBundlePathFromExecutable(exe_path);
        NSImage *appIcon = getAppIcon(exe_path);

        DraggableAppIconView *iconView = [[DraggableAppIconView alloc]
            initWithFrame:NSMakeRect(500, 250, 80, 80)];
        [iconView setImage:appIcon];
        [iconView setImageScaling:NSImageScaleProportionallyUpOrDown];
        [iconView setAppBundlePath:bundlePath];
        [contentView addSubview:iconView];

        // "Drag me" label
        NSTextField* dragLabel = createLabel(
            @"Drag me →",
            NSMakeRect(410, 285, 80, 20),
            NO
        );
        [dragLabel setAlignment:NSTextAlignmentRight];
        [dragLabel setFont:[NSFont systemFontOfSize:11]];
        [dragLabel setTextColor:[NSColor secondaryLabelColor]];
        [contentView addSubview:dragLabel];

        // App name label below icon
        NSTextField* appNameLabel = createLabel(
            @"MeshAgent.app",
            NSMakeRect(460, 230, 160, 16),
            NO
        );
        [appNameLabel setAlignment:NSTextAlignmentCenter];
        [appNameLabel setFont:[NSFont systemFontOfSize:11]];
        [contentView addSubview:appNameLabel];

        // ===== OPEN SYSTEM SETTINGS BUTTON =====
        NSButton* openSettingsBtn = [[NSButton alloc]
            initWithFrame:NSMakeRect(420, 180, 200, 32)];
        [openSettingsBtn setTitle:@"Open System Settings"];
        [openSettingsBtn setBezelStyle:NSBezelStyleRounded];
        [openSettingsBtn setTarget:nil];
        [openSettingsBtn setAction:@selector(openFDASettingsAction:)];
        [contentView addSubview:openSettingsBtn];

        // Alternative text
        NSTextField* orLabel = createLabel(
            @"or click the button above",
            NSMakeRect(420, 160, 200, 16),
            NO
        );
        [orLabel setFont:[NSFont systemFontOfSize:11]];
        [orLabel setTextColor:[NSColor tertiaryLabelColor]];
        [contentView addSubview:orLabel];

        // ===== FOOTER =====

        // "Don't show again" checkbox
        NSButton* checkbox = [[NSButton alloc]
            initWithFrame:NSMakeRect(20, 20, 450, 20)];
        [checkbox setButtonType:NSButtonTypeSwitch];
        [checkbox setTitle:@"Don't show this tutorial again (you can still use 'More Info')"];
        [checkbox setFont:[NSFont systemFontOfSize:12]];
        [contentView addSubview:checkbox];

        // Close button
        NSButton* closeBtn = [[NSButton alloc]
            initWithFrame:NSMakeRect(690, 20, 90, 32)];
        [closeBtn setTitle:@"Close"];
        [closeBtn setBezelStyle:NSBezelStyleRounded];
        [closeBtn setKeyEquivalent:@"\r"];  // Enter key
        [closeBtn setTarget:window];
        [closeBtn setAction:@selector(close)];
        [contentView addSubview:closeBtn];

        // ===== WINDOW DELEGATE =====
        // Reuse existing delegate class for window close handling
        TCCPermissionsWindowDelegate *delegate = [[TCCPermissionsWindowDelegate alloc] init];
        [window setDelegate:delegate];

        // ===== SHOW MODAL =====
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp runModalForWindow:window];

        // ===== HANDLE CHECKBOX =====
        // Note: Currently checkbox is for visual indication only
        // "Do not remind" is controlled by main TCC window checkbox
        // Could be enhanced to set a separate "fda_tutorial_disabled" preference

        [window close];
        NSLog(@"[FDA-Tutorial] Tutorial window closed");
    }
}

// Action handler for "Open System Settings" button
@interface NSObject (FDASettingsAction)
- (void)openFDASettingsAction:(id)sender;
@end

@implementation NSObject (FDASettingsAction)
- (void)openFDASettingsAction:(id)sender {
    NSLog(@"[FDA-Tutorial] Opening System Settings for Full Disk Access");
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}
@end
```

## Modified Button Click Handler

### Update openFullDiskAccessSettings:

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:241-244`

**Current Code**:
```objective-c
- (void)openFullDiskAccessSettings:(id)sender {
    NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
    [[NSWorkspace sharedWorkspace] openURL:url];
}
```

**Modified Code**:
```objective-c
- (void)openFullDiskAccessSettings:(id)sender {
    NSButton *button = (NSButton*)sender;

    // Check button title to determine action
    if ([[button title] isEqualToString:@"More Info"]) {
        NSLog(@"[TCC-UI] FDA 'More Info' clicked - showing tutorial");

        // Show tutorial window
        NSWindow *parentWindow = [button window];
        show_fda_tutorial_window(self.exePath, parentWindow);

        NSLog(@"[TCC-UI] Tutorial window closed, returning to main window");
    } else {
        // Fallback: if button somehow says "Open Settings", use old behavior
        NSLog(@"[TCC-UI] FDA button clicked - opening System Settings");
        NSURL* url = [NSURL URLWithString:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
        [[NSWorkspace sharedWorkspace] openURL:url];
    }
}
```

## Passing exe_path to Button Handler

### 1. Add Property to TCCButtonHandler

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:61-72`

**Current Interface**:
```objective-c
@interface TCCButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, strong) NSTimer *updateTimer;

- (instancetype)initWithContentView:(NSView*)view;
// ...
@end
```

**Modified Interface**:
```objective-c
@interface TCCButtonHandler : NSObject
@property (nonatomic, assign) NSView *contentView;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, assign) const char *exePath;  // ADD THIS

- (instancetype)initWithContentView:(NSView*)view;
// ...
@end
```

### 2. Update show_tcc_permissions_window Signature

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.h:21`

**Current**:
```objective-c
int show_tcc_permissions_window(void);
```

**Modified**:
```objective-c
int show_tcc_permissions_window(const char* exe_path);
```

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:335`

**Current**:
```objective-c
int show_tcc_permissions_window(void) {
```

**Modified**:
```objective-c
int show_tcc_permissions_window(const char* exe_path) {
```

### 3. Store exe_path in Button Handler

**Location**: `meshcore/MacOS/TCC_UI/mac_permissions_window.m:373`

**Current**:
```objective-c
TCCButtonHandler* buttonHandler = [[TCCButtonHandler alloc] initWithContentView:contentView];
```

**Modified**:
```objective-c
TCCButtonHandler* buttonHandler = [[TCCButtonHandler alloc] initWithContentView:contentView];
buttonHandler.exePath = exe_path;  // ADD THIS LINE
```

### 4. Update Caller in main.c

**Location**: `meshconsole/main.c:698`

**Current**:
```c
int result = show_tcc_permissions_window();
```

**Modified**:
```c
int result = show_tcc_permissions_window(argv[0]);
```

**Note**: `argv[0]` contains the executable path passed by `execv()` from parent process

## Resource Management

### Screenshot Image

**Source File**: User provides modern System Settings screenshot showing FDA pane

**Specifications**:
- Format: PNG (with transparency if desired)
- Recommended size: 760×740px (scales to 380×370 in UI)
- Content: macOS System Settings window showing:
  - Privacy & Security selected in sidebar
  - Full Disk Access pane visible
  - Lock icon (locked state)
  - Empty or sample app list
  - Clear view of drag target area

**Source Location**: `/Users/peet/GitHub/MeshAgent/build/resources/images/fda_tutorial.png`

**Destination in Bundle**: `MeshAgent.app/Contents/Resources/fda_tutorial.png`

### Build Script Modification

**File**: `/Users/peet/GitHub/MeshAgent/build/tools/macos_build/create-app-bundle.sh`

**Add After Line 85** (after copying icon file):

```bash
# Copy tutorial images
echo "Copying tutorial resources..."
TUTORIAL_IMAGE_SRC="$PROJECT_ROOT/build/resources/images/fda_tutorial.png"
TUTORIAL_IMAGE_DST="$BUNDLE_NAME/Contents/Resources/fda_tutorial.png"

if [ -f "$TUTORIAL_IMAGE_SRC" ]; then
    cp "$TUTORIAL_IMAGE_SRC" "$TUTORIAL_IMAGE_DST"
    echo "  ✓ Copied FDA tutorial screenshot: fda_tutorial.png"
else
    echo "  ⚠ Warning: Tutorial screenshot not found at $TUTORIAL_IMAGE_SRC"
    echo "  Tutorial window will work but won't show screenshot"
fi
```

### Directory Structure

```
build/
└── resources/
    └── images/
        └── fda_tutorial.png  ← User provides this screenshot

        ↓ (build script copies to)

MeshAgent.app/
└── Contents/
    └── Resources/
        ├── AppIcon.icns
        └── fda_tutorial.png  ← Bundled with app
```

## Testing

### Unit Testing (Standalone)

**Test without full app bundle**:

```bash
# Compile test executable with tutorial code
gcc -framework Cocoa -framework ApplicationServices -framework CoreGraphics \
    -DTEST_TUTORIAL_WINDOW \
    meshcore/MacOS/TCC_UI/mac_permissions_window.m \
    meshcore/MacOS/mac_tcc_detection.c \
    -o test_fda_tutorial

# Run
./test_fda_tutorial
```

**Test Code** (add to `mac_permissions_window.m` with `#ifdef TEST_TUTORIAL_WINDOW`):

```objective-c
#ifdef TEST_TUTORIAL_WINDOW
int main(int argc, const char* argv[]) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        // Test with dummy path
        show_fda_tutorial_window("/opt/tacticalmesh/MeshAgent.app/Contents/MacOS/meshagent", nil);

        return 0;
    }
}
#endif
```

### Integration Testing

**Test with full TCC UI**:

```bash
# Build app bundle
bash build/macos/build-osx-app-universal.sh

# Run -tccCheck
./build/output/osx-universal-64-app/MeshAgent.app/Contents/MacOS/meshagent -tccCheck 1
```

**Test Steps**:
1. Verify FDA button shows "More Info" (if FDA not granted)
2. Click "More Info" button
3. Verify tutorial window opens
4. Verify screenshot loads (or placeholder if missing)
5. Verify app icon is correct MeshAgent icon
6. Test dragging icon (drag to desktop to verify draggability)
7. Click "Open System Settings" button → Settings opens
8. Click "Close" → Tutorial window closes
9. Back on main TCC window, FDA button still shows "More Info"
10. Grant FDA in System Settings
11. Within 1 second, FDA button → green checkmark ✓

### Drag-and-Drop Testing

**Verify drag works to System Settings**:

1. Open System Settings → Privacy & Security → Full Disk Access
2. Click lock icon to authenticate
3. Open tutorial window
4. Drag MeshAgent icon from tutorial to FDA list in Settings
5. Verify MeshAgent appears in list
6. Enable toggle

**Alternative Test** (drag to Finder):

1. Drag icon from tutorial to Desktop
2. Verify alias/link to MeshAgent.app is created
3. Confirms drag payload is correct

## Known Issues and Limitations

### 1. Screenshot Dependency

**Issue**: Window degrades gracefully if screenshot missing, but looks unprofessional

**Mitigation**: Show placeholder with text if image fails to load (implemented)

**Solution**: Ensure screenshot is in build resources before release

### 2. Bundle Path Detection

**Issue**: `getBundlePathFromExecutable()` assumes path contains `.app`

**Scenario**: If executable is run outside of bundle (development testing)

**Mitigation**: Fallback to `[[NSBundle mainBundle] bundlePath]` (implemented)

### 3. Drag Target Compatibility

**Issue**: Some macOS versions may restrict drag targets for security

**Scenario**: User drags icon but System Settings doesn't accept it

**Mitigation**: "Open System Settings" button provides alternative method

**Known Compatible**: macOS 11+ (Big Sur and later)

### 4. Icon Resolution

**Issue**: App icon may appear pixelated if bundle path detection fails

**Mitigation**: `NSWorkspace iconForFile:` returns Retina icons automatically

**Fallback**: Generic application icon used if custom icon unavailable

### 5. Window Sizing on Small Screens

**Issue**: 800×550 window may be too large for MacBooks with low resolution

**Current**: Window not resizable, uses fixed size

**Future Enhancement**: Make window resizable with minimum size constraints

## Future Enhancements

### 1. Animated Instructions

Add animated arrows pointing to drag target:

```objective-c
// Create animated arrow using Core Animation
CAShapeLayer *arrow = [CAShapeLayer layer];
// ... configure arrow path
// Add pulsing animation
```

### 2. Permission State Synchronization

Close tutorial automatically when FDA is granted:

```objective-c
// In tutorial window, add timer to check FDA status
- (void)checkFDAStatus {
    TCC_PermissionStatus fda = check_fda_permission();
    if (fda == TCC_PERMISSION_GRANTED_USER) {
        // Close tutorial, show success message
        [self.window close];
    }
}
```

### 3. Localization

Support multiple languages for instructions:

```objective-c
NSLocalizedString(@"FDA_TUTORIAL_STEP1", @"Drag the MeshAgent icon...")
```

### 4. Video Tutorial

Embed short video showing drag-and-drop process:

```objective-c
AVPlayerView *playerView = [[AVPlayerView alloc] initWithFrame:...];
// Load tutorial video from bundle
```

### 5. Separate "Don't Show" Preference

Add dedicated database key for tutorial (separate from main TCC UI):

```c
// User can disable tutorial but still see main TCC window
ILibSimpleDataStore_Put(db, "fdaTutorialDisabled", "1", 1);
```

## Implementation Checklist

- [ ] Add `DraggableAppIconView` class to `mac_permissions_window.m`
- [ ] Add helper functions (bundle path, icon, screenshot loading)
- [ ] Implement `show_fda_tutorial_window()` function
- [ ] Add `showMoreInfoButton:` method to `TCCButtonHandler`
- [ ] Modify `updatePermissionStatus` to show "More Info" for FDA
- [ ] Modify `openFullDiskAccessSettings:` to check button title
- [ ] Add `exePath` property to `TCCButtonHandler`
- [ ] Update `show_tcc_permissions_window()` signature
- [ ] Store `exe_path` in button handler
- [ ] Update `main.c` to pass `argv[0]`
- [ ] Create `/build/resources/images/` directory
- [ ] Add FDA tutorial screenshot PNG
- [ ] Update `create-app-bundle.sh` to copy screenshot
- [ ] Test standalone tutorial window
- [ ] Test full integration with TCC UI
- [ ] Test drag-and-drop to System Settings
- [ ] Test fallback behavior (no screenshot, no bundle)
- [ ] Update `mac_permissions_window.h` header
- [ ] Add logging for debugging
- [ ] Document in `docs/fda-tutorial-window.md` (this file)
- [ ] Update `docs/README.md` with link to this document

## File Summary

### Files to Modify

1. `meshcore/MacOS/TCC_UI/mac_permissions_window.h`
   - Update function signature: `int show_tcc_permissions_window(const char* exe_path);`

2. `meshcore/MacOS/TCC_UI/mac_permissions_window.m`
   - Add `DraggableAppIconView` class (~80 lines)
   - Add helper functions (~60 lines)
   - Add `show_fda_tutorial_window()` function (~150 lines)
   - Modify `TCCButtonHandler` interface (add `exePath` property)
   - Add `showMoreInfoButton:` method (~15 lines)
   - Modify `updatePermissionStatus` (~5 lines changed)
   - Modify `openFullDiskAccessSettings:` (~10 lines changed)
   - Update `show_tcc_permissions_window` signature and store exe_path (~3 lines)

3. `meshconsole/main.c`
   - Update line 698: Pass `argv[0]` to `show_tcc_permissions_window()`

4. `build/tools/macos_build/create-app-bundle.sh`
   - Add tutorial image copying logic after line 85 (~10 lines)

### Files to Create

1. `build/resources/images/fda_tutorial.png`
   - User-provided System Settings screenshot

### Total Lines of Code

**New Code**: ~330 lines (Objective-C)
**Modified Code**: ~20 lines
**Build Script**: ~10 lines

## References

- **Main TCC Documentation**: `docs/macos-tcc-permissions.md`
- **Drag-and-Drop Programming Guide**: [Apple Developer Documentation](https://developer.apple.com/documentation/appkit/drag_and_drop)
- **NSPasteboardItemDataProvider**: [Apple Developer Documentation](https://developer.apple.com/documentation/appkit/nspasteboarditemdataprovider)
- **NSDraggingSource**: [Apple Developer Documentation](https://developer.apple.com/documentation/appkit/nsdraggingsource)

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-21 | 1.0 | Initial specification for FDA tutorial window with draggable icon implementation |
