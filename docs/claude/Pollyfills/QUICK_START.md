# Polyfills Regeneration - Quick Start Guide

Quick reference for common tasks. For detailed information, see [Polyfills-Regeneration.md](Polyfills-Regeneration.md).

## TL;DR

**Status**: ✅ COMPLETED - Byte-perfect regeneration achieved
**Verification**: MD5 `ce4bc256fa5d3d1eaab7a9dc2ee4ceb1`
**What**: System to extract/modify/regenerate 100 JavaScript modules embedded in `microscript/ILibDuktape_Polyfills.c`

## Quick Commands

### Regenerate C File (Python - Recommended)

```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 regenerate_polyfills_complete.py
```

**Expected output**: `✓ File sizes match! MD5: ce4bc256fa5d3d1eaab7a9dc2ee4ceb1`

### Extract Modules from Agent (Built-in)

```bash
./meshagent -export
# Creates: modules_expanded/*.js
```

### Embed Modules into C File (Built-in)

```bash
./meshagent -import
# Reads: modules_expanded/*.js
# Updates: microscript/ILibDuktape_Polyfills.c
```

### Verify Byte-Perfect Match

```bash
md5 microscript/ILibDuktape_Polyfills.c
md5 docs/claude/Pollyfills/polyfills_generattion_reversengenering/orig/ILibDuktape_Polyfills.c_NEW_withLargeModules.txt

diff microscript/ILibDuktape_Polyfills.c docs/claude/Pollyfills/polyfills_generattion_reversengenering/orig/ILibDuktape_Polyfills.c_NEW_withLargeModules.txt
# No output = identical
```

## File Locations

### Production Files
- **C File**: `microscript/ILibDuktape_Polyfills.c`
- **Source Modules**: `modules/*.js`
- **Expanded Modules**: `modules_expanded/*.js`

### Test/Working Files
- **Scripts**: `docs/claude/Pollyfills/polyfills_generattion_reversengenering/`
- **Test C File**: `docs/claude/Pollyfills/polyfills_generattion_reversengenering/orig/ILibDuktape_Polyfills.c`
- **Test Modules**: `docs/claude/Pollyfills/polyfills_generattion_reversengenering/orig/modules/`

## Two Methods

### Method 1: Built-in Node.js (Canonical)

**Extract**:
```bash
./meshagent -export
```

**Embed**:
```bash
./meshagent -import
```

**Pros**: Official tooling, used in production
**Cons**: Requires compiled agent, no verification

### Method 2: Python Script (Standalone)

**Regenerate**:
```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 regenerate_polyfills_complete.py
```

**Pros**: Works on source files, MD5 verification, better diagnostics
**Cons**: External tool (not built-in)

## Module Formats

### Standard Format (92 modules)
- Single-line C code
- Used when compressed module < 16,300 characters

### Chunked Format (8 large modules)
- Multi-line with memory allocation
- Used when compressed module ≥ 16,300 characters
- **The 8 large modules**:
  1. agent-selftest.js
  2. amt.js
  3. duktape-debugger.js
  4. meshcmd.js (largest - 528KB compressed)
  5. notifybar-desktop.js
  6. service-manager.js
  7. win-dialog.js
  8. win-userconsent.js

## Common Workflows

### Modify a Module

```bash
# 1. Extract modules (if not already done)
./meshagent -export

# 2. Edit a module
vim modules_expanded/some-module.js

# 3. Re-embed (choose one method)

# Method A: Built-in
./meshagent -import

# Method B: Python script (with verification)
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 regenerate_polyfills_complete.py
# Then copy the generated file to microscript/

# 4. Rebuild agent
make linux ARCHID=6
```

### Verify Current C File

```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering

# Extract what's embedded
python3 extract_modules.py

# Regenerate from extracted
python3 regenerate_polyfills_complete.py

# Compare
diff orig/ILibDuktape_Polyfills.c orig/ILibDuktape_Polyfills.c_NEW_withLargeModules.txt
```

## Troubleshooting

### ❌ MD5 Doesn't Match

**Check**:
1. Using `regenerate_polyfills_complete.py` (not `regenerate_polyfills.py`)
2. code-utils source is `code-utils-new.js` (relative paths)
3. Large modules read from `orig/modules/`, standard from `orig/modules_expanded/`

### ❌ File Size Differs

**Usually means**:
- Missing the 8 large chunked-format modules
- Use `regenerate_polyfills_complete.py` instead of `regenerate_polyfills.py`

### ❌ Script Can't Find Files

**Make sure**:
```bash
cd /Users/peet/GitHub/MeshAgent_dynamicNames/docs/claude/Pollyfills/polyfills_generattion_reversengenering
pwd  # Should show the full path above
```

### ❌ Compression Size Different

**Check**:
- Python using zlib level 6: `zlib.compress(data, level=6)`
- Reading correct source file (not a different version)

## Key Technical Facts

| Item | Value |
|------|-------|
| **Total Modules** | 100 |
| **Standard Format** | 92 modules |
| **Chunked Format** | 8 modules |
| **Compression** | zlib level 6 |
| **Encoding** | base64 |
| **Format Threshold** | 16,300 characters |
| **Chunk Size** | 16,000 bytes |
| **C File Size** | 1,515,283 bytes |
| **MD5 Checksum** | ce4bc256fa5d3d1eaab7a9dc2ee4ceb1 |

## Auto-Generated Section

Everything happens between these markers in the C file:

```c
// {{ BEGIN AUTO-GENERATED BODY
<100 embedded modules go here>
// }} END OF AUTO-GENERATED BODY
```

**Important**: There's a hardcoded old code-utils (2022-12-14) AFTER the END marker. This is NOT part of the auto-generated section and is correctly preserved during regeneration.

## Custom Paths (Built-in Tooling)

```bash
# Export to custom directory
./meshagent -export --expandedPath=my_modules

# Import from custom directory
./meshagent -import --expandedPath=my_modules --filePath=path/to/Polyfills.c
```

## Documentation Links

- **[Project Overview](README.md)** - Project summary and status
- **[Complete Technical Docs](Polyfills-Regeneration.md)** - Deep dive into everything
- **[Project Status](STATUS.md)** - Current state and timeline
- **[Working Directory](polyfills_generattion_reversengenering/README.md)** - Scripts and files

## Quick Checks

### Is regeneration working?
```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 regenerate_polyfills_complete.py | grep "File sizes match"
# Should see: ✓ File sizes match!
```

### Are all 100 modules present?
```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 regenerate_polyfills_complete.py | grep "Extracted"
# Should see: Extracted 100 modules from original C file
```

### What modules are currently embedded?
```bash
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 extract_modules.py
cat orig/modules_expanded/_modules_metadata.json | grep '"name"'
```

## Emergency Reset

If everything is broken:

```bash
# 1. Copy fresh C file from microscript/
cp microscript/ILibDuktape_Polyfills.c docs/claude/Pollyfills/polyfills_generattion_reversengenering/orig/

# 2. Extract modules
cd docs/claude/Pollyfills/polyfills_generattion_reversengenering
python3 extract_modules.py

# 3. Verify extraction worked
ls orig/modules_expanded/*.js | wc -l
# Should show: 93 (92 modules + code-utils-new.js)

# 4. Test regeneration
python3 regenerate_polyfills_complete.py
# Should see: ✓ File sizes match!
```

---

**Quick Start Guide** | Polyfills Regeneration System
**Last Updated**: 2025-11-07
**Status**: COMPLETED - Byte-perfect regeneration verified
