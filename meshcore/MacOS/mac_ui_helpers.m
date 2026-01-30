/*
Shared UI helper functions for macOS

Provides common UI element creation functions used across
TCC permissions and installation assistant windows.
*/

#import "mac_ui_helpers.h"
#include <mach-o/dyld.h>
#include <sys/param.h>

NSTextField* mesh_createLabel(NSString* text, NSRect frame, BOOL bold) {
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

void mesh_showAlert(NSString* title, NSString* message, NSAlertStyle style) {
    NSAlert* alert = [[NSAlert alloc] init];
    [alert setMessageText:title];
    [alert setInformativeText:message];
    [alert addButtonWithTitle:@"OK"];
    [alert setAlertStyle:style];
    [alert runModal];
    [alert release];
}

NSString* mesh_showFileDialog(BOOL chooseFiles, BOOL chooseDirectories,
                               NSString* message, NSArray* allowedTypes) {
    NSOpenPanel* panel = [NSOpenPanel openPanel];
    [panel setCanChooseFiles:chooseFiles];
    [panel setCanChooseDirectories:chooseDirectories];
    [panel setAllowsMultipleSelection:NO];
    [panel setMessage:message];
    [panel setPrompt:@"Select"];

    if (allowedTypes != nil) {
        [panel setAllowedFileTypes:allowedTypes];
    }

    if ([panel runModal] == NSModalResponseOK) {
        NSURL* url = [[panel URLs] objectAtIndex:0];
        return [url path];
    }

    return nil;
}

NSWindow* mesh_createFloatingWindow(NSRect frame, NSString* title, NSWindowStyleMask styleMask, BOOL centerOnScreen) {
    NSWindow* window = [[NSWindow alloc]
        initWithContentRect:frame
        styleMask:styleMask
        backing:NSBackingStoreBuffered
        defer:NO];

    [window setTitle:title];
    [window setLevel:NSFloatingWindowLevel];

    if (centerOnScreen) {
        // Center the window on screen
        [window center];
    } else {
        // Position in upper-right area (stay out of the way)
        NSScreen* mainScreen = [NSScreen mainScreen];
        NSRect screenFrame = [mainScreen visibleFrame];
        NSRect windowFrame = [window frame];

        // Position 20 pixels from right edge and 20 pixels from top
        CGFloat xPos = screenFrame.origin.x + screenFrame.size.width - windowFrame.size.width - 20;
        CGFloat yPos = screenFrame.origin.y + screenFrame.size.height - windowFrame.size.height - 20;

        [window setFrameOrigin:NSMakePoint(xPos, yPos)];
    }

    return window;
}

NSImageView* mesh_createSymbolIcon(NSString* symbolName, NSRect frame, CGFloat pointSize, NSFontWeight weight) API_AVAILABLE(macos(11.0)) {
    if (@available(macOS 11.0, *)) {
        NSImageView* iconView = [[NSImageView alloc] initWithFrame:frame];
        NSImage* icon = [NSImage imageWithSystemSymbolName:symbolName accessibilityDescription:nil];

        if (icon) {
            [iconView setImage:icon];
            [iconView setSymbolConfiguration:[NSImageSymbolConfiguration configurationWithPointSize:pointSize weight:weight]];
            return iconView;
        }
    }

    return nil;
}

NSString* mesh_getAgentDisplayName(void) {
    // Try CFBundleDisplayName from Info.plist
    NSString *displayName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"];
    if (displayName && [displayName length] > 0) {
        return displayName;
    }

    // Try CFBundleName from Info.plist
    NSString *bundleName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"];
    if (bundleName && [bundleName length] > 0) {
        if ([bundleName hasSuffix:@".app"]) {
            bundleName = [bundleName substringToIndex:[bundleName length] - 4];
        }
        return bundleName;
    }

    // Try to extract .app bundle name from binary path
    char execPath[PATH_MAX];
    uint32_t size = sizeof(execPath);
    if (_NSGetExecutablePath(execPath, &size) == 0) {
        char *appPos = strstr(execPath, ".app/");
        if (appPos != NULL) {
            *appPos = '\0';
            char *lastSlash = strrchr(execPath, '/');
            const char *appName = lastSlash ? lastSlash + 1 : execPath;
            if (appName[0] != '\0') {
                return [NSString stringWithUTF8String:appName];
            }
        }

        // Fall back to binary name
        char *lastSlash = strrchr(execPath, '/');
        const char *filename = lastSlash ? lastSlash + 1 : execPath;
        if (filename[0] != '\0') {
            return [NSString stringWithUTF8String:filename];
        }
    }

    return @"Agent";
}

// --- Vector icon helpers ---

NSImage* mesh_createVectorIcon(CGFloat viewBoxSize, CGFloat iconSize, void(^drawBlock)(CGFloat scale)) {
    NSImage* image = [NSImage imageWithSize:NSMakeSize(iconSize, iconSize) flipped:YES drawingHandler:^BOOL(NSRect dstRect) {
        CGFloat scale = dstRect.size.width / viewBoxSize;
        NSAffineTransform* xform = [NSAffineTransform transform];
        [xform scaleXBy:scale yBy:scale];
        [xform concat];

        [[NSColor blackColor] setStroke];
        drawBlock(scale);
        return YES;
    }];
    [image setTemplate:YES];
    return image;
}

void mesh_lucideStroke(NSBezierPath* path) {
    [path setLineWidth:2.0];
    [path setLineCapStyle:NSLineCapStyleRound];
    [path setLineJoinStyle:NSLineJoinStyleRound];
    [path stroke];
}

NSImage* mesh_createLucideIcon(CGFloat size, void (^drawBlock)(void)) {
    return mesh_createVectorIcon(24.0, size, ^(CGFloat scale) {
        (void)scale;
        drawBlock();
    });
}

NSImage* mesh_lucideNetworkIcon(CGFloat size) {
    return mesh_createLucideIcon(size, ^{
        NSBezierPath* nodes = [NSBezierPath bezierPath];
        [nodes appendBezierPathWithRoundedRect:NSMakeRect(9, 2, 6, 6) xRadius:1 yRadius:1];
        [nodes appendBezierPathWithRoundedRect:NSMakeRect(2, 16, 6, 6) xRadius:1 yRadius:1];
        [nodes appendBezierPathWithRoundedRect:NSMakeRect(16, 16, 6, 6) xRadius:1 yRadius:1];
        mesh_lucideStroke(nodes);

        NSBezierPath* vert = [NSBezierPath bezierPath];
        [vert moveToPoint:NSMakePoint(12, 8)];
        [vert lineToPoint:NSMakePoint(12, 12)];
        mesh_lucideStroke(vert);

        NSBezierPath* bracket = [NSBezierPath bezierPath];
        [bracket moveToPoint:NSMakePoint(5, 16)];
        [bracket lineToPoint:NSMakePoint(5, 13)];
        [bracket curveToPoint:NSMakePoint(6, 12) controlPoint1:NSMakePoint(5, 12.448) controlPoint2:NSMakePoint(5.448, 12)];
        [bracket lineToPoint:NSMakePoint(18, 12)];
        [bracket curveToPoint:NSMakePoint(19, 13) controlPoint1:NSMakePoint(18.552, 12) controlPoint2:NSMakePoint(19, 12.448)];
        [bracket lineToPoint:NSMakePoint(19, 16)];
        mesh_lucideStroke(bracket);
    });
}

NSImage* mesh_lucideImportIcon(CGFloat size) {
    return mesh_createLucideIcon(size, ^{
        NSBezierPath* shaft = [NSBezierPath bezierPath];
        [shaft moveToPoint:NSMakePoint(12, 3)];
        [shaft lineToPoint:NSMakePoint(12, 15)];
        mesh_lucideStroke(shaft);

        NSBezierPath* head = [NSBezierPath bezierPath];
        [head moveToPoint:NSMakePoint(8, 11)];
        [head lineToPoint:NSMakePoint(12, 15)];
        [head lineToPoint:NSMakePoint(16, 11)];
        mesh_lucideStroke(head);

        NSBezierPath* box = [NSBezierPath bezierPath];
        [box moveToPoint:NSMakePoint(8, 5)];
        [box lineToPoint:NSMakePoint(4, 5)];
        [box curveToPoint:NSMakePoint(2, 7) controlPoint1:NSMakePoint(2.895, 5) controlPoint2:NSMakePoint(2, 5.895)];
        [box lineToPoint:NSMakePoint(2, 17)];
        [box curveToPoint:NSMakePoint(4, 19) controlPoint1:NSMakePoint(2, 18.105) controlPoint2:NSMakePoint(2.895, 19)];
        [box lineToPoint:NSMakePoint(20, 19)];
        [box curveToPoint:NSMakePoint(22, 17) controlPoint1:NSMakePoint(21.105, 19) controlPoint2:NSMakePoint(22, 18.105)];
        [box lineToPoint:NSMakePoint(22, 7)];
        [box curveToPoint:NSMakePoint(20, 5) controlPoint1:NSMakePoint(22, 5.895) controlPoint2:NSMakePoint(21.105, 5)];
        [box lineToPoint:NSMakePoint(16, 5)];
        mesh_lucideStroke(box);
    });
}

NSImage* mesh_lucideUploadIcon(CGFloat size) {
    return mesh_createLucideIcon(size, ^{
        NSBezierPath* shaft = [NSBezierPath bezierPath];
        [shaft moveToPoint:NSMakePoint(12, 3)];
        [shaft lineToPoint:NSMakePoint(12, 15)];
        mesh_lucideStroke(shaft);

        NSBezierPath* head = [NSBezierPath bezierPath];
        [head moveToPoint:NSMakePoint(17, 8)];
        [head lineToPoint:NSMakePoint(12, 3)];
        [head lineToPoint:NSMakePoint(7, 8)];
        mesh_lucideStroke(head);

        NSBezierPath* tray = [NSBezierPath bezierPath];
        [tray moveToPoint:NSMakePoint(21, 15)];
        [tray lineToPoint:NSMakePoint(21, 19)];
        [tray curveToPoint:NSMakePoint(19, 21) controlPoint1:NSMakePoint(21, 20.105) controlPoint2:NSMakePoint(20.105, 21)];
        [tray lineToPoint:NSMakePoint(5, 21)];
        [tray curveToPoint:NSMakePoint(3, 19) controlPoint1:NSMakePoint(3.895, 21) controlPoint2:NSMakePoint(3, 20.105)];
        [tray lineToPoint:NSMakePoint(3, 15)];
        mesh_lucideStroke(tray);
    });
}

NSImage* mesh_lucideTrashIcon(CGFloat size) {
    return mesh_createLucideIcon(size, ^{
        NSBezierPath* lines = [NSBezierPath bezierPath];
        [lines moveToPoint:NSMakePoint(10, 11)];
        [lines lineToPoint:NSMakePoint(10, 17)];
        [lines moveToPoint:NSMakePoint(14, 11)];
        [lines lineToPoint:NSMakePoint(14, 17)];
        mesh_lucideStroke(lines);

        NSBezierPath* body = [NSBezierPath bezierPath];
        [body moveToPoint:NSMakePoint(19, 6)];
        [body lineToPoint:NSMakePoint(19, 20)];
        [body curveToPoint:NSMakePoint(17, 22) controlPoint1:NSMakePoint(19, 21.105) controlPoint2:NSMakePoint(18.105, 22)];
        [body lineToPoint:NSMakePoint(7, 22)];
        [body curveToPoint:NSMakePoint(5, 20) controlPoint1:NSMakePoint(5.895, 22) controlPoint2:NSMakePoint(5, 21.105)];
        [body lineToPoint:NSMakePoint(5, 6)];
        mesh_lucideStroke(body);

        NSBezierPath* lid = [NSBezierPath bezierPath];
        [lid moveToPoint:NSMakePoint(3, 6)];
        [lid lineToPoint:NSMakePoint(21, 6)];
        mesh_lucideStroke(lid);

        NSBezierPath* handle = [NSBezierPath bezierPath];
        [handle moveToPoint:NSMakePoint(8, 6)];
        [handle lineToPoint:NSMakePoint(8, 4)];
        [handle curveToPoint:NSMakePoint(10, 2) controlPoint1:NSMakePoint(8, 2.895) controlPoint2:NSMakePoint(8.895, 2)];
        [handle lineToPoint:NSMakePoint(14, 2)];
        [handle curveToPoint:NSMakePoint(16, 4) controlPoint1:NSMakePoint(15.105, 2) controlPoint2:NSMakePoint(16, 2.895)];
        [handle lineToPoint:NSMakePoint(16, 6)];
        mesh_lucideStroke(handle);
    });
}

NSImage* mesh_lucideShieldCheckIcon(CGFloat size) {
    return mesh_createVectorIcon(24.0, size, ^(CGFloat scale) {
        (void)scale;

        // Shield outline: M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z
        NSBezierPath* shield = [NSBezierPath bezierPath];
        [shield moveToPoint:NSMakePoint(20, 13)];
        // Right side curving down to bottom
        [shield curveToPoint:NSMakePoint(12.34, 21.95) controlPoint1:NSMakePoint(20, 18) controlPoint2:NSMakePoint(16.5, 20.5)];
        // Bottom center (tiny arc approximated as line)
        [shield lineToPoint:NSMakePoint(11.67, 21.94)];
        // Left side curving up from bottom
        [shield curveToPoint:NSMakePoint(4, 13) controlPoint1:NSMakePoint(7.5, 20.5) controlPoint2:NSMakePoint(4, 18)];
        // Left wall up
        [shield lineToPoint:NSMakePoint(4, 6)];
        // Top-left corner (arc r=1)
        [shield curveToPoint:NSMakePoint(5, 5) controlPoint1:NSMakePoint(4, 5.448) controlPoint2:NSMakePoint(4.448, 5)];
        // Left shoulder curve to top center
        [shield curveToPoint:NSMakePoint(11.24, 2.28) controlPoint1:NSMakePoint(7, 5) controlPoint2:NSMakePoint(9.5, 3.8)];
        // Top center arc
        [shield curveToPoint:NSMakePoint(12.76, 2.28) controlPoint1:NSMakePoint(10.80, 1.90) controlPoint2:NSMakePoint(13.20, 1.90)];
        // Right shoulder curve
        [shield curveToPoint:NSMakePoint(19, 5) controlPoint1:NSMakePoint(14.51, 3.81) controlPoint2:NSMakePoint(17, 5)];
        // Top-right corner (arc r=1)
        [shield curveToPoint:NSMakePoint(20, 6) controlPoint1:NSMakePoint(19.552, 5) controlPoint2:NSMakePoint(20, 5.448)];
        [shield closePath];
        mesh_lucideStroke(shield);

        // Checkmark: m9 12 2 2 4-4
        NSBezierPath* check = [NSBezierPath bezierPath];
        [check moveToPoint:NSMakePoint(9, 12)];
        [check lineToPoint:NSMakePoint(11, 14)];
        [check lineToPoint:NSMakePoint(15, 10)];
        mesh_lucideStroke(check);
    });
}

NSImage* mesh_lucideCircleCheckFillIcon(CGFloat size, NSColor* fillColor) {
    NSImage* image = [NSImage imageWithSize:NSMakeSize(size, size) flipped:YES drawingHandler:^BOOL(NSRect dstRect) {
        CGFloat scale = dstRect.size.width / 24.0;
        NSAffineTransform* xform = [NSAffineTransform transform];
        [xform scaleXBy:scale yBy:scale];
        [xform concat];

        // Filled circle (cx=12, cy=12, r=10)
        NSBezierPath* circle = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(2, 2, 20, 20)];
        [fillColor setFill];
        [circle fill];

        // White checkmark (m9 12 2 2 4-4)
        NSBezierPath* check = [NSBezierPath bezierPath];
        [check moveToPoint:NSMakePoint(9, 12)];
        [check lineToPoint:NSMakePoint(11, 14)];
        [check lineToPoint:NSMakePoint(15, 10)];
        [[NSColor whiteColor] setStroke];
        [check setLineWidth:2.0];
        [check setLineCapStyle:NSLineCapStyleRound];
        [check setLineJoinStyle:NSLineJoinStyleRound];
        [check stroke];

        return YES;
    }];
    // NOT a template — colors are baked in
    return image;
}

NSImageView* mesh_addRadioIcon(NSImage* icon, NSButton* radio, NSView* parent) {
    NSString* title = [radio title];
    NSDictionary* attrs = @{ NSFontAttributeName: [radio font] ?: [NSFont systemFontOfSize:13] };
    CGFloat textWidth = [title sizeWithAttributes:attrs].width;
    NSRect radioFrame = [radio frame];
    CGFloat iconX = radioFrame.origin.x + 22 + textWidth + 6;
    CGFloat iconSize = 20;
    NSImageView* iv = [[NSImageView alloc] initWithFrame:NSMakeRect(iconX, radioFrame.origin.y, iconSize, iconSize)];
    [iv setImage:icon];
    [parent addSubview:iv];
    return iv;
}

NSTextField* mesh_createPathField(NSRect frame, NSString* placeholder) {
    NSTextField* field = [[NSTextField alloc] initWithFrame:frame];
    [field setPlaceholderString:placeholder];
    return field;
}

NSButton* mesh_createRoundedButton(NSString* title, NSRect frame,
                                   id target, SEL action, NSInteger tag) {
    NSButton* button = [[NSButton alloc] initWithFrame:frame];
    [button setTitle:title];
    [button setBezelStyle:NSBezelStyleRounded];
    if (target) {
        [button setTarget:target];
    }
    if (action) {
        [button setAction:action];
    }
    [button setTag:tag];
    return button;
}

NSButton* mesh_createCheckbox(NSString* title, NSRect frame, NSControlStateValue initialState,
                              id target, SEL action) {
    NSButton* checkbox = [[NSButton alloc] initWithFrame:frame];
    [checkbox setButtonType:NSButtonTypeSwitch];
    [checkbox setTitle:title];
    [checkbox setState:initialState];
    if (target) {
        [checkbox setTarget:target];
    }
    if (action) {
        [checkbox setAction:action];
    }
    return checkbox;
}

NSScrollView* mesh_createMonospaceScrollView(NSRect frame, CGFloat fontSize) {
    // Create scroll view with vertical scrolling
    NSScrollView* scrollView = [[NSScrollView alloc] initWithFrame:frame];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setHasHorizontalScroller:NO];
    [scrollView setAutohidesScrollers:NO];
    [scrollView setBorderType:NSBezelBorder];

    // Create text view with monospace font
    NSTextView* textView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, frame.size.width, frame.size.height)];
    [textView setEditable:NO];
    [textView setFont:[NSFont fontWithName:@"Menlo" size:fontSize]];

    // Use system colors that adapt to light/dark mode
    [textView setTextColor:[NSColor textColor]];
    [textView setBackgroundColor:[NSColor textBackgroundColor]];

    [scrollView setDocumentView:textView];

    return scrollView;
}
