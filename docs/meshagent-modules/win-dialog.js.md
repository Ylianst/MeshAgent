# win-dialog.js

Provides Windows user interface dialog creation including message boxes, input dialogs, and custom dialogs. Implements dialog window management with event handling and multi-threaded support for non-blocking dialog operations.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-dialog.js is Windows-only** because:

1. **Windows Dialog APIs** - User32.dll dialog functions
2. **Message Box System** - Windows MB_* constants and dialog models
3. **Window Messaging** - Windows window message handling
4. **User Interface Model** - Windows GDI and window management

---

## Functionality

### Core Purpose

win-dialog.js creates user interface dialogs:

1. **Message Boxes** - Display messages with buttons
2. **Input Dialogs** - Prompt user for text input
3. **File Dialogs** - File selection dialogs
4. **Custom Dialogs** - Create custom dialog windows
5. **Non-blocking Execution** - Async dialog operations

### Main Operations

1. **Message Dialog** - msgBox(title, message, buttons, options)
2. **Input Dialog** - inputBox(title, prompt, defaultValue)
3. **File Selection** - fileDialog(options)
4. **Custom Dialogs** - createDialog(options)

---

## Architecture

The module provides comprehensive dialog functionality with:

1. **Synchronous Mode** - Blocking dialog execution
2. **Asynchronous Mode** - Non-blocking with promise
3. **Session Dispatch** - Dialogs in specific user sessions
4. **Event Handling** - Button clicks and input events

---

## Message Box Constants

### Button Types:
```javascript
MB_OK (0)                  // OK button only
MB_OKCANCEL (1)           // OK, Cancel
MB_YESNO (4)              // Yes, No
MB_YESNOCANCEL (3)        // Yes, No, Cancel
MB_RETRYCANCEL (5)        // Retry, Cancel
MB_ABORTRETRYIGNORE (2)   // Abort, Retry, Ignore
```

### Icon Types:
```javascript
MB_ICONINFORMATION (0x40)
MB_ICONQUESTION (0x20)
MB_ICONWARNING (0x30)
MB_ICONERROR (0x10)
MB_ICONEXCLAMATION (0x30)
```

### Return Values:
```javascript
IDOK (1)          // OK clicked
IDCANCEL (2)      // Cancel clicked
IDYES (6)         // Yes clicked
IDNO (7)          // No clicked
IDRETRY (4)       // Retry clicked
IDIGNORE (5)      // Ignore clicked
IDABORT (3)       // Abort clicked
```

---

## Core API Methods

### msgBox(title, message, buttons, options) - Message Dialog

**Purpose:** Display message box dialog

**Parameters:**
```javascript
{
    title: 'Dialog Title',
    message: 'Message text',
    buttons: MB_YESNO,        // Button configuration
    icon: MB_ICONQUESTION,    // Icon type
    defaultButton: 1,         // Default button (1, 2, 3)
    modal: true               // Modal dialog
}
```

**Returns:** Integer button ID (IDOK, IDYES, IDNO, etc.)

**Process:**
1. Creates window with specified title
2. Displays message text
3. Shows buttons based on button type
4. Waits for user interaction
5. Returns button ID of clicked button

---

### inputBox(title, prompt, defaultValue) - Input Dialog

**Purpose:** Prompt user for text input

**Parameters:**
- `title` - Dialog title
- `prompt` - Prompt text
- `defaultValue` - Initial text value (optional)

**Returns:** String - user input or null if canceled

**Process:**
1. Creates input dialog window
2. Displays prompt text
3. Shows text field with optional default value
4. OK/Cancel buttons
5. Returns input text or null

---

### fileDialog(options) - File Selection Dialog

**Purpose:** File selection dialog

**Parameters:**
```javascript
{
    title: 'Select File',
    initialDir: 'C:\\',
    filter: '*.txt|Text Files|*..*|All Files',
    multiSelect: false,
    defaultExtension: '.txt'
}
```

**Returns:** String or array of file paths

---

### createDialog(options) - Custom Dialog

**Purpose:** Create custom dialog window

**Parameters:**
```javascript
{
    title: 'Custom Dialog',
    width: 400,
    height: 300,
    controls: [
        { type: 'label', text: 'Name:', x: 10, y: 10 },
        { type: 'textbox', id: 'name', x: 100, y: 10 },
        { type: 'button', text: 'OK', id: 'ok', x: 150, y: 250 }
    ]
}
```

**Returns:** Promise resolving to dialog results

---

## Session Dispatch

For dialogs in specific user sessions:

```javascript
// Create dialog in user session 1
var dialog = require('win-dialog');
var result = dialog.msgBox('Title', 'Message', dialog.MB_YESNO, { tsid: 1 });
```

The module automatically:
1. Detects current process context
2. Dispatches to specified user session if needed
3. Returns result to parent process

---

## Dependencies

### Native DLLs

**User32.dll** - Dialog and window functions
- MessageBoxA() / MessageBoxExA()
- CreateWindowA() / DestroyWindow()
- ShowWindow() / UpdateWindow()
- GetMessage() / DispatchMessage()
- GetDlgItemText() / SetDlgItemText()
- DialogBoxParam()

### Module Dependencies

**require('_GenericMarshal')**
- CreateNativeProxy() - Load User32
- CreateVariable() - Memory buffers
- CreateMethod() - Define DLL functions

---

## Error Handling

1. **Dialog Creation Failure** - Throws error if window creation fails
2. **User Cancellation** - Returns null or IDCANCEL
3. **Session Not Available** - Throws error if user session unavailable
4. **Invalid Parameters** - Validates button/icon types

---

## Technical Notes

### Modal vs Modeless

- **Modal** - Blocks parent window until dialog closed
- **Modeless** - Parent continues, dialog independent

### Message Pump

Dialogs require Windows message pump:
- GetMessage() retrieves messages
- TranslateMessage() converts virtual keys
- DispatchMessage() routes to window procedure

### Window Procedures

Dialogs use window procedures to handle:
- Button clicks
- Text input
- Window close
- Keyboard events

---

## Usage Examples

### Simple Message Box

```javascript
var dialog = require('win-dialog');
var result = dialog.msgBox('Confirm', 'Continue?', dialog.MB_YESNO);
if (result == dialog.IDYES) {
    console.log('User clicked Yes');
}
```

### Input from User

```javascript
var input = dialog.inputBox('Enter Name', 'Name:', 'Default');
if (input != null) {
    console.log('User entered:', input);
}
```

### File Selection

```javascript
var file = dialog.fileDialog({
    title: 'Open File',
    filter: '*.txt|Text|*..*|All',
    multiSelect: false
});
```

### Custom Dialog

```javascript
var result = dialog.createDialog({
    title: 'Settings',
    controls: [
        { type: 'label', text: 'Value:', x: 10, y: 10 },
        { type: 'textbox', id: 'value', x: 100, y: 10, width: 200 },
        { type: 'button', text: 'OK', id: 'ok', x: 150, y: 100 }
    ]
});

result.then(function(values) {
    console.log('Dialog result:', values);
});
```

---

## Advanced Features

### Non-blocking Dialogs

Dialogs can be created asynchronously:

```javascript
dialog.msgBoxAsync('Title', 'Message')
    .then(function(result) {
        console.log('User clicked:', result);
    });
```

### Custom Message Box Styles

Combine button and icon constants:

```javascript
var flags = dialog.MB_YESNOCANCEL | dialog.MB_ICONQUESTION;
var result = dialog.msgBox('Confirm', 'Proceed?', flags);
```

### Multi-select File Dialog

```javascript
var files = dialog.fileDialog({
    multiSelect: true,
    title: 'Select Files'
});
// Returns array of selected file paths
```

---

## Summary

win-dialog.js provides comprehensive Windows dialog functionality including message boxes, input dialogs, file selection, and custom dialogs. The module supports both synchronous blocking and asynchronous non-blocking execution with optional user session dispatch. Complete button/icon configuration and return value handling enable flexible user interaction.
