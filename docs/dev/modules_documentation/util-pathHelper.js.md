# util-pathHelper.js

Cross-platform path manipulation utility that provides consistent path construction across Windows, Linux, macOS, and FreeBSD. This helper module handles platform-specific path separators and enables creation of paths with optional current working directory substitution and file extension handling.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support with backslash separator
- Linux - Full support with forward slash separator
- macOS (darwin) - Full support with forward slash separator
- FreeBSD - Full support with forward slash separator

## Functionality

### Purpose

The util-pathHelper module provides cross-platform path construction to ensure consistent file path handling regardless of the operating system. It:

- Creates paths using platform-appropriate separators (backslash on Windows, forward slash elsewhere)
- Optionally substitutes paths with the current working directory
- Handles file extension substitution (particularly for .exe files)
- Simplifies path construction by handling delimiter conversions
- Prevents path separator inconsistencies across platforms

This module is used throughout MeshAgent wherever file paths need to be constructed dynamically while maintaining cross-platform compatibility.

### Path Construction Logic

The `makePath(path1, path2, useCWD)` function constructs paths using the following logic:

**When useCWD is true (lines 26-35):**
1. Ignores `path1` parameter
2. Uses `process.cwd()` to get current working directory
3. Extracts the leaf folder name from `path1`
4. Combines CWD parent with path1's leaf folder

**When path2 starts with '.' (lines 37-42):**
1. Treats `path2` as a file extension
2. Removes '.exe' from `path1` if present
3. Appends `path2` extension to `path1`

**Otherwise (lines 44-50):**
1. Removes the filename from `path1` (keeps directory)
2. Appends `path2` as the new filename
3. Converts all separators to platform-specific delimiter

### Key Functions

#### makePath(path1, path2, useCWD) - Lines 24-52

**Purpose:** Constructs a file path from components with platform-specific separators.

**Parameters:**
- `path1` (string) - Base path or file path
- `path2` (string) - Filename or extension (if starts with '.')
- `useCWD` (boolean, optional) - Use current working directory instead of path1

**Process:**

**CWD Mode (useCWD = true):**
```javascript
// Example: path1 = '/opt/mesh/agent', path2 = 'config.json', useCWD = true
// CWD = '/home/user'
// Result: '/home/mesh/config.json'
```
1. Gets current working directory via `process.cwd()` (line 31)
2. Splits CWD by platform separator (line 31)
3. Removes last token from CWD (line 32)
4. Extracts leaf folder from `path1` (line 33)
5. Combines CWD parent + path1 leaf (line 34)

**Extension Mode (path2 starts with '.'):**
```javascript
// Example: path1 = '/opt/mesh/agent.exe', path2 = '.bak'
// Result: '/opt/mesh/agent.bak'
```
1. Removes '.exe' extension from `path1` if present (line 40)
2. Appends `path2` to `path1` (line 41)

**Normal Mode (path2 is filename):**
```javascript
// Example: path1 = '/opt/mesh/agent', path2 = 'config.json'
// Result: '/opt/mesh/config.json'
```
1. Splits `path1` by platform separator (line 46)
2. Removes last token (filename/leaf) (line 47)
3. Appends `path2` as new filename (line 48)
4. Joins with platform-specific separator (line 49)

**Platform Behavior:**
- **Windows**: Uses backslash (`\\`) as separator
- **Unix-like (Linux, macOS, FreeBSD)**: Uses forward slash (`/`) as separator
- Automatically detects platform via `process.platform` (lines 31, 33, 46, 49)

**Return Value:**
- Returns constructed path string with platform-appropriate separators

---

### Dependencies

#### Node.js Core Modules
- `process` (global) - Used for:
  - `process.platform` (lines 31, 33, 46, 49) - Platform detection
  - `process.cwd()` (line 31) - Current working directory

#### MeshAgent Module Dependencies

**None** - This is a standalone utility with no MeshAgent-specific dependencies.

### Technical Notes

**Platform Detection Pattern:**
```javascript
process.platform == 'win32' ? '\\' : '/'
```
This ternary pattern appears throughout the code to select the appropriate path separator. Windows uses backslash, all other platforms use forward slash.

**String Manipulation Strategy:**
The module uses JavaScript's `split()`, `pop()`, `push()`, and `join()` array methods to manipulate path components:
1. Split path by separator into array
2. Modify array (pop/push tokens)
3. Join back into string with separator

**Case Sensitivity:**
The `.exe` extension check uses `toLowerCase()` (line 40), making it case-insensitive:
```javascript
if (path1.toLowerCase().endsWith('.exe'))
```
This handles variations like `.EXE`, `.Exe`, `.exe`.

**CWD Substitution Use Case:**
The CWD substitution feature (useCWD parameter) enables paths to be constructed relative to the current working directory while preserving a folder structure from another path. This is useful when:
- Moving files between directory hierarchies
- Creating parallel directory structures
- Testing in different working directories

**No Error Handling:**
The module does not perform validation on inputs:
- Does not check if paths exist
- Does not verify path format validity
- Does not handle null/undefined parameters
- Assumes caller provides valid string inputs

**Export Pattern:**
The module exports a single function directly:
```javascript
module.exports = makePath;
```

Usage example:
```javascript
var makePath = require('util-pathHelper');
var configPath = makePath('/opt/mesh/agent', 'config.json');
// Linux/macOS: '/opt/mesh/config.json'
// Windows: Would convert to 'C:\\opt\\mesh\\config.json'
```

## Summary

The util-pathHelper.js module is a cross-platform utility for **Windows, Linux, macOS, and FreeBSD** that provides consistent path construction with platform-appropriate separators. It handles three distinct modes of path creation: current working directory substitution, file extension replacement, and standard filename substitution.

The module is platform-agnostic and automatically adapts to the operating system by detecting `process.platform` and using the correct path separator (backslash on Windows, forward slash elsewhere). It requires no dependencies beyond Node.js core modules, making it lightweight and portable.

This utility is used throughout MeshAgent for constructing file paths dynamically while maintaining cross-platform compatibility, eliminating the need for manual path separator handling in higher-level code.
