# code-utils.js

Build system utility for managing embedded JavaScript modules in the MeshAgent C codebase. Provides functions to extract, compress, and re-embed modules in ILibDuktape_Polyfills.c, enabling module development outside the compiled binary with seamless synchronization.

## Platform

**Supported Platforms:**
- Platform-agnostic (all platforms) - Pure JavaScript file manipulation
- Windows, Linux, macOS, FreeBSD - Works identically on all platforms

**Excluded Platforms:**
- None - Pure JavaScript, no platform dependencies

## Functionality

### Purpose

The code-utils module serves the build system for:

- Extracting embedded modules from C source to editable .js files
- Re-embedding modified modules back into C source
- Handling compression and base64 encoding
- Managing MSVC string length limitations (16KB)
- Syncing modules folder with expanded folder
- Generating embedded module manifests

### Key Functions

#### expand(options) - Lines 168-232 (Extract Modules from C)

Extracts embedded modules from ILibDuktape_Polyfills.c to modules_expanded/ directory.

**Process:**
1. Read ILibDuktape_Polyfills.c
2. Parse C code between `// {{ BEGIN AUTO-GENERATED BODY` markers
3. Extract base64-encoded module data
4. Decompress using compressed-stream
5. Write .js files to modules_expanded/

#### shrink(options) - Lines 325-334 (Re-embed Modules)

Re-embeds modules from modules_expanded/ back into C source.

#### compress(data) - Lines 406-423 (Compression Helper)

Compresses and base64-encodes JavaScript module data.

### Dependencies

- **fs** - File system operations
- **compressed-stream** - Gzip compression/decompression

### Usage

```bash
# Extract modules
node code-utils.js --expandedPath=modules_expanded --filePath=microscript/ILibDuktape_Polyfills.c

# Re-embed after editing
require('code-utils').shrink();
```

### Technical Notes

**MSVC String Limitation:**
- MSVC has 16KB string literal limit
- Large modules split into chunks using memcpy
- Generates ILibMemory_Allocate + memcpy_s code

**C Code Generation:**
```c
// Small module
duk_peval_string_noresult(ctx, "addCompressedModule('name', Buffer.from('base64', 'base64'));");

// Large module
char *_name = ILibMemory_Allocate(5000, 0, NULL, NULL);
memcpy_s(_name + 0, 5000, "chunk1...", 4000);
ILibDuktape_AddCompressedModuleEx(ctx, "name", _name);
```

## Summary

The code-utils.js module is a build system utility for managing embedded MeshAgent JavaScript modules. It provides extraction, compression, and re-embedding functionality enabling module development outside the C codebase.

**macOS support:** Full support, platform-agnostic JavaScript file operations.
