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
 * Create a vector icon image from a drawing block with configurable viewBox
 *
 * Creates an NSImage by scaling a drawing block from a source viewBox size
 * to the requested icon size. The image is marked as a template for tinting.
 *
 * @param viewBoxSize The coordinate space size for the drawing block (e.g., 24 for Lucide, 16 for Bootstrap)
 * @param iconSize The output image size in points
 * @param drawBlock Block that draws the icon paths (receives scale factor)
 * @return An autoreleased template NSImage
 */
NSImage* mesh_createVectorIcon(CGFloat viewBoxSize, CGFloat iconSize, void(^drawBlock)(CGFloat scale));

/**
 * Apply standard Lucide stroke style to a path
 *
 * Sets line width 2.0, round caps, and round joins, then strokes.
 *
 * @param path The NSBezierPath to stroke
 */
void mesh_lucideStroke(NSBezierPath* path);

/**
 * Create a Lucide icon (24x24 viewBox)
 *
 * Convenience wrapper around mesh_createVectorIcon for Lucide icons.
 *
 * @param size Output image size in points
 * @param drawBlock Block that draws the icon paths
 * @return An autoreleased template NSImage
 */
NSImage* mesh_createLucideIcon(CGFloat size, void (^drawBlock)(void));

/** Lucide "network" icon */
NSImage* mesh_lucideNetworkIcon(CGFloat size);
/** Lucide "import" icon */
NSImage* mesh_lucideImportIcon(CGFloat size);
/** Lucide "upload" icon */
NSImage* mesh_lucideUploadIcon(CGFloat size);
/** Lucide "trash-2" icon */
NSImage* mesh_lucideTrashIcon(CGFloat size);
/** Lucide "shield-check" icon */
NSImage* mesh_lucideShieldCheckIcon(CGFloat size);

/**
 * Create a filled circle-check icon (Lucide circle-check variant)
 *
 * Draws a filled circle with a white checkmark on top.
 * This is NOT a template image — it renders with the specified fill color
 * and a white stroke checkmark, suitable for "granted" / "success" indicators.
 *
 * @param size Output image size in points
 * @param fillColor The fill color for the circle background
 * @return An autoreleased NSImage (non-template)
 */
NSImage* mesh_lucideCircleCheckFillIcon(CGFloat size, NSColor* fillColor);

/**
 * Place an icon NSImageView next to a radio button
 *
 * Calculates position based on radio button title width and places
 * a 20x20 icon view to the right of the title text.
 *
 * @param icon The icon image to display
 * @param radio The radio button to position next to
 * @param parent The parent view to add the image view to
 * @return An autoreleased NSImageView added to parent
 */
NSImageView* mesh_addRadioIcon(NSImage* icon, NSButton* radio, NSView* parent);

/**
 * Create a text field for file/directory path input
 *
 * Creates a standard editable text field with placeholder text,
 * suitable for displaying file or directory paths.
 *
 * @param frame Text field frame
 * @param placeholder Placeholder text shown when empty
 * @return An autoreleased NSTextField configured for path input
 */
NSTextField* mesh_createPathField(NSRect frame, NSString* placeholder);

/**
 * Create a rounded bezel push button
 *
 * @param title Button title text
 * @param frame Button frame
 * @param target Action target (or nil)
 * @param action Action selector (or NULL)
 * @param tag Button tag for identification
 * @return An autoreleased NSButton with NSBezelStyleRounded
 */
NSButton* mesh_createRoundedButton(NSString* title, NSRect frame,
                                   id target, SEL action, NSInteger tag);

/**
 * Create a checkbox (NSButtonTypeSwitch)
 *
 * @param title The checkbox label text
 * @param frame The frame for the checkbox
 * @param initialState Initial checked state (NSControlStateValueOn or NSControlStateValueOff)
 * @param target The target for the action (or nil)
 * @param action The action selector (or NULL)
 * @return An autoreleased NSButton configured as a checkbox
 */
NSButton* mesh_createCheckbox(NSString* title, NSRect frame, NSControlStateValue initialState,
                              id target, SEL action);

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

/**
 * Get the agent display name for UI labels
 *
 * Priority: CFBundleDisplayName > CFBundleName > .app bundle name > binary name > "Agent"
 *
 * @return Display name string (never nil)
 */
NSString* mesh_getAgentDisplayName(void);

#endif // MAC_UI_HELPERS_H
