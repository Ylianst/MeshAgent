#ifndef MAC_UI_HELPERS_H
#define MAC_UI_HELPERS_H

#import <Cocoa/Cocoa.h>

/**
 * Shared UI helper functions for macOS
 *
 * Provides common UI element creation functions used across
 * TCC permissions and installation assistant windows.
 */

/**
 * Create a configured NSTextField label
 *
 * Creates a non-editable, non-selectable label with consistent styling.
 * Bold labels use 13pt bold system font, regular labels use 12pt system font
 * with secondary label color.
 *
 * @param text The text to display in the label
 * @param frame The frame (position and size) for the label
 * @param bold YES for bold text, NO for regular text with gray color
 * @return An autoreleased NSTextField configured as a label
 */
NSTextField* mesh_createLabel(NSString* text, NSRect frame, BOOL bold);

/**
 * Show a modal alert dialog with standardized styling
 *
 * Displays a modal alert with OK button and specified style.
 * Blocks until user dismisses the alert.
 *
 * @param title Alert window title (main message)
 * @param message Detailed informative text
 * @param style Alert style (NSAlertStyleWarning, NSAlertStyleCritical, NSAlertStyleInformational)
 */
void mesh_showAlert(NSString* title, NSString* message, NSAlertStyle style);

/**
 * Show file/directory selection dialog
 *
 * Displays a modal NSOpenPanel for selecting files or directories.
 * Blocks until user selects or cancels.
 *
 * @param chooseFiles YES to allow file selection
 * @param chooseDirectories YES to allow directory selection
 * @param message Dialog message prompt
 * @param allowedTypes Array of allowed file extensions (or nil for all)
 * @return Selected file path, or nil if cancelled
 */
NSString* mesh_showFileDialog(BOOL chooseFiles, BOOL chooseDirectories,
                               NSString* message, NSArray* allowedTypes);

/**
 * Create a floating window with standard configuration
 *
 * Creates an NSWindow with floating level, specified style mask, and optional positioning.
 * Floating windows stay above normal windows but below the menu bar.
 *
 * @param frame Window frame (size and initial position)
 * @param title Window title
 * @param styleMask Window style (e.g., NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
 * @param centerOnScreen YES to center window, NO to position in upper-right
 * @return An autoreleased NSWindow configured as floating window
 */
NSWindow* mesh_createFloatingWindow(NSRect frame, NSString* title, NSWindowStyleMask styleMask, BOOL centerOnScreen);

/**
 * Create an SF Symbols icon image view (macOS 11+)
 *
 * Creates an NSImageView with SF Symbols icon at specified size and weight.
 * Falls back gracefully on older macOS versions.
 *
 * @param symbolName SF Symbols name (e.g., "checkmark.shield", "gearshape")
 * @param frame Image view frame
 * @param pointSize Icon point size (e.g., 32.0)
 * @param weight Icon weight (NSFontWeightRegular, NSFontWeightBold, etc.)
 * @return An autoreleased NSImageView with SF Symbols icon, or nil if unavailable
 */
NSImageView* mesh_createSymbolIcon(NSString* symbolName, NSRect frame, CGFloat pointSize, NSFontWeight weight) API_AVAILABLE(macos(11.0));

/**
 * Create a monospace scrollable text view for log output
 *
 * Creates an NSScrollView containing an NSTextView configured for:
 * - Monospace font (Menlo) for log readability
 * - Read-only with vertical scrolling
 * - System colors that adapt to light/dark mode
 *
 * @param frame Scroll view frame
 * @param fontSize Font size for monospace text (e.g., 10.0)
 * @return An autoreleased NSScrollView containing configured NSTextView
 *         Access text view via: [(NSTextView*)[scrollView documentView] ...]
 */
NSScrollView* mesh_createMonospaceScrollView(NSRect frame, CGFloat fontSize);

#endif // MAC_UI_HELPERS_H
