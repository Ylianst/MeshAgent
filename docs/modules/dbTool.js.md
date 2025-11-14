# dbTool.js

Command-line utility for interacting with the MeshAgent's SimpleDataStore database. Provides CRUD operations, key enumeration, import/export functionality, and database compaction without requiring the agent to be running.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support (.exe.db path)
- Linux - Full support (.db path)
- macOS (darwin) - Full support (.db path)
- FreeBSD - Full support (.db path)

**Excluded Platforms:**
- None - All platforms supported

## Functionality

### Purpose

Provides database management for:
- Direct database access without running agent
- Key/value inspection and modification
- Module import/export
- Database compaction
- Configuration management

### Key Commands

#### compact - Lines 49-53 (Database Defragmentation)

Compacts and optimizes database file.

#### put/putx - Lines 54-63 (Store Data)

- `put <KEY> <VALUE>` - Store string
- `putx <KEY> <HEXVALUE>` - Store hex-encoded binary

#### get/getx - Lines 64-77 (Retrieve Data)

- `get <KEY>` - Get and display as string
- `getx <KEY>` - Get and display as hex

#### list/keys - Lines 78-106 (Enumerate Keys)

Displays sorted list of all keys with index numbers.

#### export - Lines 112-123 (Export to File)

- CoreModule/RecoveryModule → Slices 4-byte header, writes .js
- Other keys → Writes raw binary

#### import - Lines 124-139 (Import from File)

- CoreModule/RecoveryModule → Adds 4-byte prefix, compresses
- Other keys → Compresses and stores

#### delete - Lines 107-111 (Remove Key)

Deletes key from database.

### Dependencies

- **SimpleDataStore** - Database access
- **fs** - File I/O for import/export

### Usage

```bash
# List all keys
./meshagent list

# Read value
./meshagent get MeshServer

# Write value
./meshagent put disableUpdate 1

# Export module
./meshagent export CoreModule  # Creates CoreModule.js

# Import module
./meshagent import CoreModule  # Reads CoreModule.js

# Compact database
./meshagent compact

# Delete key
./meshagent delete someKey
```

### Technical Notes

**Database Path:**
- Windows: `process.execPath.replace('.exe', '.db')`
- Unix: `process.execPath + '.db'`

**Read-Only Mode:**
- Auto-detects write operations
- Opens read-only unless: compact, put, putx, delete, import

**Special Keys:**
- **CoreModule** - Compressed JavaScript core (4-byte header)
- **RecoveryModule** - Recovery/update module (4-byte header)
- **disableUpdate** - Disable auto-update
- **noUpdateCoreModule** - Prevent CoreModule updates

## Summary

The dbTool.js module is a command-line database management utility for MeshAgent's SimpleDataStore. It provides complete CRUD operations, module import/export, and database maintenance.

**macOS support:** Full support with .db file path.

**Important:** Requires agent to be stopped for write operations (file locking).
