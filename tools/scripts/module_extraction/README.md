# Module Extraction Tools

This directory contains tools for extracting JavaScript modules embedded in MeshAgent binaries.

## Scripts

### `decode_compressed_modules.py`

Decodes and decompresses JavaScript modules from `addCompressedModule()` calls extracted from MeshAgent binaries.

**Usage:**
```bash
python3 decode_compressed_modules.py <input_file> <output_dir>
```

**Example:**
```bash
# First, extract the addCompressedModule strings from the binary
strings meshagent_binary | grep "addCompressedModule" > module_strings.txt

# Then decode them
python3 decode_compressed_modules.py module_strings.txt ./extracted_modules
```

**What it does:**
- Parses `addCompressedModule()` function calls containing base64-encoded, zlib-compressed JavaScript
- Decodes base64 → decompresses zlib → extracts JavaScript code
- Saves each module as a separate `.js` file with metadata header
- Generates `modules_metadata.json` with statistics and module information
- Provides summary of compression ratios and largest modules

### `extract_modules_from_binary.py`

Attempts to extract embedded JavaScript modules directly from a MeshAgent binary by searching for zlib-compressed data patterns.

**Usage:**
```bash
python3 extract_modules_from_binary.py <binary_path> <output_dir>
```

**Example:**
```bash
python3 extract_modules_from_binary.py /path/to/meshagent ./extracted_modules
```

**What it does:**
- Scans binary for zlib compression headers (0x78 0x9c, 0x78 0xda, etc.)
- Attempts to decompress and validate as JavaScript code
- Extracts modules with offset information
- Less reliable than `decode_compressed_modules.py` but useful when strings are not accessible

## Recommended Workflow

1. **Extract module strings from binary:**
   ```bash
   strings /path/to/meshagent | grep "addCompressedModule" > module_strings.txt
   ```

2. **Decode and extract modules:**
   ```bash
   python3 decode_compressed_modules.py module_strings.txt ./extracted_modules
   ```

3. **Review extracted modules:**
   ```bash
   cd extracted_modules
   ls -lh *.js
   cat modules_metadata.json
   ```

## Output Format

Each extracted module includes a metadata header:
```javascript
// Module: module-name
// Timestamp: 2022-06-28T11:11:27.000-07:00
// Original compressed size: 8104 bytes
// Decompressed size: 36976 bytes
// Compression ratio: 78.1%

// ... actual JavaScript code ...
```

## Notes

- The modules are embedded in MeshAgent binaries using the `addCompressedModule()` function
- Modules are base64-encoded and zlib-compressed for space efficiency
- The extracted modules show the internal JavaScript code that MeshAgent uses for various functionality
- Common modules include: agent-installer, clipboard, user-sessions, monitor-info, process-manager, etc.
