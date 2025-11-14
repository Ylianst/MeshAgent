# exe.js

Executable integration tool that embeds JavaScript and dependencies directly into Windows PE (Portable Executable) binaries, enabling standalone executable creation with integrated script support. Provides command-line utilities for packaging JavaScript code with optional dependencies into native executables.

## Platform

**Supported Platforms:**
- Windows - Full support with PE binary embedding
- Linux - Partial support (reads executable, handles dependency directories)

**Excluded Platforms:**
- macOS - No support

**Placement in modules_macos_NEVER:**

macOS is excluded because:

1. **PE Binary Format Dependency** - The module specifically handles Windows PE (Portable Executable) file format. macOS uses Mach-O binary format, which requires completely different header parsing and embedding techniques (Lines 39-46 show platform-specific path handling, but core PE functionality at Lines 115-140 is Windows-only).

2. **Binary Signing Verification** - Lines 118-119 check for Authenticode signatures using PE_Parser, which is specific to Windows executable signing. macOS uses code signing with different mechanisms.

3. **Designed for .exe Output** - The entire workflow assumes creating .exe files. macOS doesn't produce .exe files; it uses .app bundles, Mach-O binaries, or shell scripts.

**Technical Note:** While the file I/O and some utility functions are cross-platform, the core purpose is PE binary manipulation, which is inherently Windows-specific.

## Functionality

### Core Purpose

Merges JavaScript source files and dependency modules into Windows executable binaries at build time. Enables distribution of JavaScript-based applications as single .exe files without requiring separate module files.

### Integration Methods

**Method 1: Object-Oriented Constructor:**
```javascript
var obj = require('exe')({
    outputFile: 'meshcmd.exe',
    sourceJS: 'meshcmd.js',
    executablePath: 'MeshService64.exe',
    dependencies: ['module1.js', 'module2.js']
});
```

**Method 2: Command-Line Usage (Lines 53-75):**
```bash
exe.js -omeshcmd.exe -imodule1.js -xMeshService64.exe meshcmd.js

Options:
  -o <filename>    Output executable filename (REQUIRED)
  -x <path>        Input binary path (optional, uses process.execPath default)
  -d <path>        Directory containing dependencies (optional)
  -i <filename>    Individual dependency file (repeatable)
  <source.js>      Input JavaScript file (REQUIRED, .js or .zip)
```

### Key Components

#### Magic GUIDs (Lines 35-36)

**JavaScript Embedding Marker:**
```javascript
const exeJavaScriptGuid = 'B996015880544A19B7F7E9BE44914C18';
const exeMeshPolicyGuid = 'B996015880544A19B7F7E9BE44914C19';
```

**Purpose:**
- Unique identifiers appended to binaries to mark embedded JavaScript
- Allows detection of already-integrated executables
- Enables removal/replacement of existing embedded scripts

#### Dependency Loading (Lines 69-97)

**Individual Files (Lines 70-77):**
```javascript
for (i = 1; i < process.argv.length; ++i) {
    if (process.argv[i].startsWith('-i')) {
        dependency.push({ name: process.argv[i].slice(2, ...), base64: fs.readFileSync(...) });
    }
}
```

**Directory Path Loading (Lines 80-97):**
```javascript
if (depPath != null) {
    filenames = fs.readdirSync(depPath + '\\*');
    filenames.forEach(function (filename) {
        var fname = process.platform == 'win32' ? (depPath + '\\' + filename) : (depPath + '/' + filename);
        dependency.push({ name: filename.slice(0, ...), str: fs.readFileSync(fname).toString() });
    });
}
```

**Dependency Injection (Lines 102-112):**
```javascript
if (dependency.length > 0) {
    for (i = 0; i < dependency.length; ++i) {
        if (addOn == null) { addOn = ''; }
        addOn += ("addModule('" + dependency[i].name + "', \"" + escapeCodeString(dependency[i].str) + "\");\n");
    }
}
```

#### Binary Signing Check (Lines 115-119)

```javascript
var PE;
try { PE = require('PE_Parser')(execPath); } catch (e) { }
if (PE && PE.CertificateTableSize > 0) {
    console.log('This binary is *SIGNED*, it is not allowed to embed a JS to a signed binary');
    process.exit();
}
```

**Security Requirement:** Cannot embed JavaScript into Authenticode-signed executables. Unsigned binaries only.

#### Binary Merging Process (Lines 128-171)

**Step 1: Read Source Files (Lines 128-130):**
```javascript
exe = fs.readFileSync(execPath);              // Read binary
w = fs.createWriteStream(localPath + outputFileName, { flags: "wb" });
js = fs.readFileSync(sourcejs);               // Read JavaScript
```

**Step 2: Check for Existing Embedded JavaScript (Lines 133-141):**
```javascript
if (exe.slice(exe.length - 16).toString('hex').toUpperCase() == exeJavaScriptGuid) {
    // Yes, embedded JS is present. Remove it.
    exeLen -= (20 + exe.readUInt32BE(exeLen - 20));
} else {
    // No JS found
    exeLen = exe.length;
}
```

**Step 3: Prepend Dependencies to JavaScript (Line 144):**
```javascript
if (addOn != null) { js = Buffer.concat([Buffer.from(addOn), js]); }
```

**Step 4: Write Binary + Padding + JavaScript + Size + GUID (Lines 148-171):**

The OnWroteExe callback implements the final write sequence:
1. Write original executable (Line 148)
2. Calculate QuadWord alignment padding (Line 153): `padding = 8 - ((exeLen + js.length + 16 + 4) % 8)`
3. Write padding if needed (Line 156)
4. Write JavaScript content (Line 158)
5. Write JavaScript size as 32-bit big-endian integer (Lines 159-162)
6. Write magic GUID (Line 165)

**Binary Layout:**
```
[Original Binary] [Padding] [JavaScript] [Size(4)] [GUID(16)]
```

#### String Escaping (Lines 174-184)

```javascript
function escapeCodeString(str) {
    const escapeCodeStringTable = { 39: '\\\'', 34: '\\"', 92: '\\\\', 8: '\\b', 12: '\\f', 10: '\\n', 13: '\\r', 9: '\\t' };
    var r = '', c, cr, table;
    for (var i = 0; i < str.length; i++) {
        c = str[i];
        cr = c.charCodeAt(0);
        table = escapeCodeStringTable[cr];
        if (table != null) { r += table; } else { if ((cr >= 32) && (cr <= 127)) { r += c; } }
    }
    return r;
}
```

**Purpose:** Escapes special characters in dependency source code for embedding in generated addModule() calls. Handles quotes, backslashes, and control characters.

#### Path Handling (Lines 39-47)

**Windows Paths (Lines 39-42):**
```javascript
localFile = process.execPath.lastIndexOf('\\') < 0 ?
    process.execPath.substring(0, process.execPath.length - 4) :
    process.execPath.substring(process.execPath.lastIndexOf('\\') + 1, process.execPath.length - 4);
localPath = process.execPath.lastIndexOf('\\') < 0 ? '' :
    process.execPath.substring(0, 1 + process.execPath.lastIndexOf('\\'));
```

**Linux Paths (Lines 44-46):**
```javascript
localFile = process.execPath.lastIndexOf('/') < 0 ?
    process.execPath.substring(0, process.execPath.length) :
    process.execPath.substring(process.execPath.lastIndexOf('/') + 1, process.execPath.length);
localPath = process.execPath.lastIndexOf('/') < 0 ? '' :
    process.execPath.substring(0, 1 + process.execPath.lastIndexOf('/'));
```

## Dependencies

### MeshAgent Module Dependencies

#### PE_Parser (Line 118)

```javascript
var PE;
try { PE = require('PE_Parser')(execPath); } catch (e) { }
```

**Purpose:** Parses Windows PE executable headers to extract certificate information

**Usage:**
- Checks if binary is signed: `PE.CertificateTableSize > 0`
- Reads certificate table address and size
- Prevents embedding into Authenticode-signed binaries

**Source:** Custom MeshAgent module for PE binary analysis

### Node.js Core Module Dependencies

#### fs (Line 27)

```javascript
var fs = require('fs');
```

**Methods Used:**
- `readFileSync(path)` - Read executable, JavaScript, and dependency files
- `readdirSync(path)` - List files in dependency directory
- `createWriteStream(path, options)` - Write output executable
- `existsSync(path)` - Check if paths exist

**Purpose:** File system I/O for reading binaries and writing merged output

### No External Binary Dependencies

**Pure JavaScript Implementation:** The module uses only Node.js core fs module. All binary manipulation is done in JavaScript using Buffer objects.

## Technical Notes

### QuadWord Alignment

**Why Padding? (Line 153)**
```javascript
var padding = Buffer.alloc(8 - ((exeLen + js.length + 16 + 4) % 8));
```

- Binary data benefits from alignment boundaries (8-byte chunks)
- Improves performance for some binary loaders
- Ensures predictable memory layout

### Multiple Embedding Support

The tool detects and replaces existing embedded JavaScript (Lines 133-141):
- Checks for exeJavaScriptGuid at end of binary
- Calculates previous embedded JavaScript size from 4-byte length field
- Strips old JavaScript before adding new version
- Allows iterative builds and updates

### Unsigned Binary Requirement

**Security Policy (Lines 118-119):**
- Cannot embed JavaScript into Authenticode-signed executables
- Signing process calculates hash of entire binary
- Adding JavaScript after signing invalidates the signature
- Must use unsigned binaries or sign after integration

### Dependency Integration

**Generated Code Pattern (Line 108):**
```javascript
addModule('moduleName', "module content escaped as string");
```

Dependencies are prepended to the user's JavaScript file, making them available via `require()` before the main script runs.

### Output File Location

**Default Location (Lines 41-42, 45-46):**
- Uses same directory as running executable
- Windows: Uses backslash path separator
- Linux: Uses forward slash path separator
- Removes .exe extension from binary name for Windows default naming

## Summary

The exe.js module is a Windows-focused executable integration tool that creates standalone .exe files containing embedded JavaScript and dependencies. It reads PE binaries, validates they're unsigned, injects JavaScript with QuadWord alignment padding, and appends metadata GUIDs for tracking.

**Placed in modules_macos_NEVER** because:
- Windows PE binary format is fundamentally incompatible with macOS
- Authenticode signing verification is Windows-specific
- Output format (.exe) is Windows-only
- No equivalent functionality for macOS Mach-O binaries

**Key Features:**
- Supports iterative embedding (replaces existing embedded JS)
- Command-line and object-based APIs
- Automatic dependency injection from files or directories
- Binary signing detection with error prevention
- Cross-platform path handling with appropriate separators

Alternative approaches would be needed for macOS app bundling or Mach-O binary manipulation.
