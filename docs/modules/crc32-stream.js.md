# crc32-stream.js

Writable stream implementation for calculating CRC32 or CRC32C checksums of streaming data. Provides a simple interface for integrity verification of file transfers and data streams in the MeshAgent.

## Platform

**Supported Platforms:**
- Platform-agnostic (all platforms) - Pure JavaScript stream wrapper

**Excluded Platforms:**
- None - Works on all platforms

## Functionality

### Purpose

Provides streaming CRC checksum calculation for:
- File transfer integrity verification
- Data stream validation
- Download/upload verification

### Key Functions

#### create(useCRC32c) - Lines 20-38 (Create CRC Stream)

Creates writable stream with CRC calculation.

**Parameters:**
- `useCRC32c` - boolean: use CRC32C vs CRC32

**Return Value:** Writable stream with `.value` property

**Process:**
- Calls global `crc32c()` or `crc32()` function
- Accumulates checksum in `this._current`
- Exposes `value` read-only getter

### Dependencies

- **stream.Writable** - Base stream class
- **Global Functions:** `crc32c()`, `crc32()` (from native module)

### Usage

```javascript
var crcStream = require('crc32-stream').create(true);
fileStream.pipe(crcStream);

crcStream.on('finish', function() {
  console.log('CRC32C:', this.value.toString(16));
});
```

### Technical Notes

**CRC Variants:**
- **CRC32:** Standard CRC-32 algorithm
- **CRC32C:** Castagnoli variant (hardware-accelerated on modern CPUs)

**Global CRC Functions:**
- Provided by native module (SHA384Stream or similar)
- Not defined in this file
- `crc32c(chunk, previous)` - Calculates CRC32C
- `crc32(chunk, previous)` - Calculates CRC32

## Summary

The crc32-stream.js module is a minimal (41-line) writable stream wrapper for CRC checksum calculation. Used by agent-selftest.js and file transfer operations for integrity verification.

**macOS support:** Full support, platform-agnostic stream implementation.
