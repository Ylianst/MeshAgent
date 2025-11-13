# MeshAgent Database Dump Utilities

This directory contains utilities for dumping and inspecting the contents of `meshagent.db` files.

## Overview

MeshAgent stores its configuration in a binary database file (`meshagent.db`) using the SimpleDataStore format. These utilities help you inspect the contents of this database for debugging, troubleshooting, or understanding the agent's configuration.

## Scripts

### 1. `dump-db.sh` (Recommended)

**Proper database dump using meshagent's SimpleDataStore module.**

This script uses the meshagent binary itself to properly read and dump the database contents. This is the **recommended** method as it correctly interprets the database structure.

**Usage:**
```bash
# Dump default database to console
./dump-db.sh

# Dump specific database file to console
./dump-db.sh /opt/tacticalmesh/meshagent.db

# Dump all .db files in a directory
./dump-db.sh /opt/tacticalmesh/

# Save dump to file
./dump-db.sh /opt/tacticalmesh/meshagent.db output.txt

# Save directory of databases to file
./dump-db.sh /opt/tacticalmesh/ all-databases.txt
```

**Features:**
- ✅ Uses meshagent's SimpleDataStore module for accurate parsing
- ✅ Shows all key-value pairs with proper type detection
- ✅ Handles binary data, buffers, and special characters
- ✅ Can process single files or entire directories
- ✅ Outputs to console or saves to file

**Requirements:**
- Meshagent binary must exist at: `build/macos/universal/meshagent`

**Output Example:**
```
========================================
MeshAgent Database Dump
========================================
Database: /opt/tacticalmesh/meshagent.db
Size: 129K

Total keys in database: 15

Database Contents:
------------------------------------------
ServiceID = meshagent.tacticalmesh
meshServiceName = TacticalMesh
companyName = <empty string>
MeshServer = wss://mesh.example.com
MeshID = <binary string, 48 bytes>
------------------------------------------

Dump complete: 15 keys
```

---

### 2. `dump-db-strings.sh` (Quick & Dirty)

**Quick inspection using the `strings` command.**

This script extracts readable ASCII strings from the database file. It's faster but less accurate than `dump-db.sh` because it doesn't properly parse the database structure.

**Usage:**
```bash
# Dump to console
./dump-db-strings.sh

# Dump specific file
./dump-db-strings.sh /opt/tacticalmesh/meshagent.db

# Save to file
./dump-db-strings.sh /opt/tacticalmesh/meshagent.db output.txt
```

**Features:**
- ✅ Fast - no meshagent binary required
- ✅ Shows readable strings
- ⚠️ May show deleted/historical values
- ⚠️ Doesn't show proper key-value structure
- ⚠️ Can't handle binary data properly

**When to use:**
- Quick check without access to meshagent binary
- Emergency debugging when binary is unavailable
- Getting a rough idea of database contents

**Output Example:**
```
=== Configuration Keys ===

meshServiceName=TacticalMesh
companyName=
MeshServer=wss://mesh.example.com
ServiceID=meshagent.tacticalmesh

=== All Readable Strings (first 100) ===
meshagent
TacticalMesh
wss://mesh.example.com
...
```

---

## What's in meshagent.db?

The database typically contains:

| Key | Description | Example |
|-----|-------------|---------|
| `ServiceID` | LaunchDaemon/LaunchAgent identifier | `meshagent.tacticalmesh` |
| `meshServiceName` | Human-readable service name | `TacticalMesh` |
| `companyName` | Organization name | `MyCompany` or empty |
| `MeshServer` | WebSocket URL to MeshCentral server | `wss://mesh.example.com` |
| `MeshName` | Mesh group name | `Production Servers` |
| `MeshID` | Unique mesh identifier (binary) | 48-byte hash |
| `ServerID` | Server certificate hash (binary) | SHA384 hash |
| `NodeID` | Agent's unique identifier (binary) | 48-byte hash |
| `InstallFlags` | Installation flags | Numeric value |

## Common Use Cases

### Verify Service Configuration
```bash
# Check what serviceId is stored
./dump-db.sh /opt/tacticalmesh/meshagent.db | grep -i serviceid
```

### Compare Databases
```bash
# Dump multiple databases
./dump-db.sh /opt/tacticalmesh/ all-databases.txt

# Then inspect differences
grep "ServiceID" all-databases.txt
```

### Troubleshoot Installation Issues
```bash
# See full configuration
./dump-db.sh /opt/tacticalmesh/meshagent.db
```

### Quick Check During Development
```bash
# Fast check without binary
./dump-db-strings.sh
```

## Troubleshooting

### Error: "meshagent binary not found"
**Problem:** `dump-db.sh` can't find the meshagent binary.

**Solution:** 
1. Build meshagent: `make macos ARCHID=universal`
2. Or update the `MESHAGENT_BINARY` path in the script
3. Or use `dump-db-strings.sh` instead (doesn't need binary)

### Error: "Database not found"
**Problem:** The database file doesn't exist at the specified path.

**Solution:**
1. Check the installation directory: `ls -la /opt/tacticalmesh/`
2. Provide the correct path as argument
3. The database is only created after agent runs for the first time

### Shows Historical/Deleted Values
**Problem:** `dump-db-strings.sh` shows old values that aren't in the current database.

**Solution:** Use `dump-db.sh` instead - it only shows current active values.

## Technical Details

### Database Format
- **Type:** SimpleDataStore (custom key-value store)
- **Format:** Binary, not SQLite or JSON
- **Keys:** ASCII strings
- **Values:** Can be strings, buffers, or binary data
- **Access:** Must use SimpleDataStore module to read properly

### Why Two Scripts?

1. **dump-db.sh** - Proper method
   - Uses meshagent's `SimpleDataStore` module
   - Accurate parsing of active values
   - Requires meshagent binary

2. **dump-db-strings.sh** - Quick method
   - Uses Unix `strings` command
   - No binary required
   - May show garbage/historical data

## Related Files

- **Production Database:** `/opt/tacticalmesh/meshagent.db` (or wherever agent is installed)
- **Test Databases:** Created during development testing
- **Backup Databases:** Created by agent during updates

## See Also

- MeshAgent Installation: `modules/agent-installer.js`
- SimpleDataStore Implementation: `microscript/ILibDuktape_SimpleDataStore.c`
- Database Usage: Search for `require('SimpleDataStore')` in modules
