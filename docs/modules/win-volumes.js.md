# win-volumes.js

Provides Windows volume and partition information including BitLocker encryption status. Retrieves disk volume metadata through WMI queries with support for both basic volume properties and security/encryption information.

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

**win-volumes.js is Windows-only** because:

1. **Windows WMI** - Uses win-wmi module for Windows Management Instrumentation
2. **Win32_Volume Class** - Windows disk volume WMI class
3. **BitLocker Integration** - Windows encryption technology
4. **Partition Model** - Windows-specific volume model

---

## Functionality

### Core Purpose

win-volumes.js provides disk volume information:

1. **Volume Enumeration** - Get all volumes and partitions
2. **Volume Properties** - Size, free space, filesystem
3. **Encryption Status** - BitLocker and volume encryption
4. **Device Information** - Device IDs and types

### Main Operations

1. **Volume Query** - getVolumes()

---

## Core Methods

### getVolumes() - Lines 33-61

**Purpose:** Retrieve all disk volumes with encryption status

**Returns:** Object mapping device IDs to volume info

**Process:**
1. Queries Win32_Volume class via WMI (line 38):
   - Namespace: ROOT\CIMV2
   - Query: SELECT * FROM Win32_Volume
2. Cleans each volume object (line 45):
   - Removes null/empty properties
   - Removes private properties (__*)
   - Normalizes serial numbers
3. Queries encryption status via WMI (line 51):
   - Namespace: ROOT\CIMV2\Security\MicrosoftVolumeEncryption
   - Class: Win32_EncryptableVolume
4. Merges encryption properties into volume objects (lines 52-59)
5. Returns mapped object by DeviceID

**Return Format:**
```javascript
{
    '\\\\?\\Volume{GUID}': {
        DeviceID: '\\\\?\\Volume{GUID}',
        DriveLetter: 'C:',
        FileSystem: 'NTFS',
        Capacity: 1099511627776,  // Bytes
        FreeSpace: 549755813888,
        Serial: 1234567890,
        // ... BitLocker properties if encrypted
    }
}
```

---

### trimObject(j) - Lines 19-28

**Purpose:** Clean volume object properties

**Implementation:**
1. Removes null values (line 24)
2. Removes empty strings (line 24)
3. Removes private properties (__*) (line 24)
4. Converts negative serial numbers to unsigned (lines 26-27):
   - Handles Int32 to UInt32 conversion
   - Uses 4-byte buffer for conversion

---

## Volume Properties

### Win32_Volume Properties

- **DeviceID** - Unique volume identifier (\\\\?\Volume{GUID})
- **DriveLetter** - Assigned drive letter (C:, D:, etc.)
- **FileSystem** - Filesystem type (NTFS, FAT32, exFAT)
- **Capacity** - Total size in bytes
- **FreeSpace** - Available space in bytes
- **SerialNumber** - Volume serial number

---

### BitLocker Properties (Win32_EncryptableVolume)

Merged from ROOT\CIMV2\Security\MicrosoftVolumeEncryption:
- **EncryptionMethod** - BitLocker encryption method
- **ConversionStatus** - Encryption progress
- **ProtectionStatus** - Protection state
- **EncryptionPercentage** - Encryption progress percentage
- And other encryption-related fields

---

## Dependencies

### Module Dependencies - Lines 21, 38, 51

**require('win-wmi')** - Lines 38, 51
- query(namespace, queryString) - Execute WMI query
- Returns array of result objects

---

## Error Handling

### Graceful Degradation - Lines 62

```javascript
module.exports = {
    getVolumes: function () {
        try {
            return (getVolumes());
        } catch (x) {
            return ({});  // Returns empty object on error
        }
    }
};
```

If WMI query fails, returns empty object instead of throwing.

---

## Technical Notes

### WMI Namespaces

1. **ROOT\CIMV2** - Standard system classes (volumes)
2. **ROOT\CIMV2\Security\MicrosoftVolumeEncryption** - BitLocker classes

### Device IDs

Windows uses long GUIDs for volume identification:
- Format: \\\\?\Volume{GUID}
- Unique per volume
- Persists across mounts
- Used for programmatic identification

### Serial Numbers

- Win32_Volume.SerialNumber may be negative (Int32)
- Converted to unsigned for display/comparison
- Uses Buffer readInt32LE/writeUInt32LE for conversion

---

## WMI Query Details

### Volume Query

```sql
SELECT * FROM Win32_Volume
```

Returns all volumes including:
- Mounted partitions
- Unmounted partitions
- System volumes
- Recovery partitions

### Encryption Query

```sql
SELECT * FROM Win32_EncryptableVolume
```

Returns only encryptable volumes (typically NTFS volumes):
- BitLocker status
- Encryption method
- Conversion status

---

## Usage Examples

### Get All Volumes

```javascript
var volumes = require('win-volumes');
var allVolumes = volumes.getVolumes();
for (var id in allVolumes) {
    console.log(id, allVolumes[id].DriveLetter);
}
```

### Check BitLocker Status

```javascript
var volumes = require('win-volumes');
var allVolumes = volumes.getVolumes();
for (var id in allVolumes) {
    var vol = allVolumes[id];
    if (vol.ConversionStatus !== undefined) {
        console.log(vol.DriveLetter, 'encrypted:', vol.EncryptionPercentage);
    }
}
```

### Calculate Total Capacity

```javascript
var volumes = require('win-volumes');
var vols = volumes.getVolumes();
var totalCapacity = 0;
for (var id in vols) {
    totalCapacity += parseInt(vols[id].Capacity || 0);
}
console.log('Total:', totalCapacity / (1024*1024*1024), 'GB');
```

---

## Summary

win-volumes.js provides comprehensive disk volume and partition information through WMI queries. The module retrieves both basic volume properties and BitLocker encryption status, with graceful error handling returning empty results on failure. Proper data cleaning and serial number conversion ensure reliable volume enumeration.
