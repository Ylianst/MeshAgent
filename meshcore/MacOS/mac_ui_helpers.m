/*
Shared UI helper functions for macOS

Provides common UI element creation functions used across
TCC permissions and installation assistant windows.
*/

#import "mac_ui_helpers.h"

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
