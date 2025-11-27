# identifiers.js

Comprehensive system identification module that gathers extensive hardware and system information across different platforms. Collects BIOS/UEFI details, motherboard information, CPU specifications, GPU data, storage devices, memory configuration, TPM status, and system metadata for device fingerprinting and inventory management.

## Platform

**Supported Platforms:**
- Linux - Full support with DMI/SMBIOS or devicetree (Raspberry Pi)
- Windows (win32) - Full support via WMI
- macOS (darwin) - Full support via system utilities

**Excluded Platforms:**
- FreeBSD - Not implemented (would require similar DMI approach as Linux)

**Exclusion Reasoning:**

FreeBSD is not currently supported, though it could theoretically be added using a similar approach to Linux (reading DMI/SMBIOS data). The platform detection logic (line 66, 525, 628) only handles Linux, Windows, and macOS.

Each platform has fundamentally different system introspection mechanisms:

1. **Linux:** Reads DMI/SMBIOS data from `/sys/class/dmi/id` filesystem or devicetree for ARM devices (Raspberry Pi)
2. **Windows:** Queries WMI (Windows Management Instrumentation) for system information
3. **macOS:** Executes system utilities (`ioreg`, `sysctl`, `system_profiler`, `diskutil`)

These platform-specific approaches reflect the different system architectures and APIs available on each operating system.

## Functionality

### Purpose

The identifiers module serves as a comprehensive system identification and hardware inventory tool. It provides detailed information about:

- **BIOS/UEFI:** Vendor, version, release date, UEFI mode detection
- **Motherboard:** Manufacturer, product name, version, serial number
- **System:** Manufacturer, model, SKU, serial number, UUID
- **CPU:** Model, cores, threads, architecture, flags
- **GPU:** Graphics cards with vendor, model, memory
- **Storage:** Drives, partitions, filesystems, capacity, BitLocker status (Windows)
- **Memory:** Slots, capacity, manufacturer, part numbers, speed
- **TPM:** Trusted Platform Module version and status
- **System Metadata:** Last boot time, Wayland status (Linux), virtual machine detection, battery detection, Docker detection

This module is typically used:
- During agent installation to fingerprint the device
- For asset inventory and management
- To detect hardware changes
- For security auditing (TPM, secure boot, UEFI mode)
- To identify system capabilities and limitations

### Key Functions/Methods

#### get() - Platform-specific implementations

**Purpose:** Main entry point that returns comprehensive system identifiers.

**Implementation:**
- **Linux:** `linux_identifiers()` - Line 66
- **Windows:** `windows_identifiers()` - Line 525
- **macOS:** `macos_identifiers()` - Line 628

**Return Value:**
Object containing system information with standardized structure:
```javascript
{
    bios_vendor: 'American Megatrends Inc.',
    bios_version: 'F10',
    bios_date: '12/15/2020',
    board_vendor: 'Gigabyte Technology Co., Ltd.',
    board_name: 'B450M DS3H',
    board_version: 'x.x',
    board_serial: 'ABC123456',
    product_uuid: '12345678-1234-1234-1234-123456789ABC',
    cpu: [{
        Model: 'AMD Ryzen 5 3600',
        Cores: '6',
        Threads: '12'
    }],
    gpu: [{
        Vendor: 'NVIDIA Corporation',
        Model: 'GeForce GTX 1660',
        Memory: '6GB'
    }],
    storage: [{
        Device: '/dev/sda',
        Capacity: '500GB',
        Type: 'SSD'
    }],
    memory: {
        Memory_Device: [{
            Locator: 'DIMM_A1',
            Size: '8192 MB',
            Manufacturer: 'Corsair',
            PartNumber: 'CMK16GX4M2B3200C16',
            Speed: '3200 MHz'
        }]
    },
    tpm: {
        version: '2.0',
        present: true
    },
    system_manufacturer: 'Custom Build',
    system_model: 'Desktop',
    boot_uefi: true,
    last_boot: '2025-01-10T12:34:56Z',
    wayland: false  // Linux only
}
```

---

#### linux_identifiers() - Line 66

**Purpose:** Gathers system information on Linux platforms.

**Process:**

1. **DMI/SMBIOS Detection:**
   - Checks if `/sys/class/dmi/id` exists
   - Reads all DMI fields from sysfs (board_vendor, bios_version, etc.)

2. **Raspberry Pi Detection (ARM):**
   - If DMI not available, checks `/sys/firmware/devicetree/base/model`
   - Detects Raspberry Pi devices
   - Reads model, serial number, memory split (ARM/GPU)

3. **CPU Information:**
   - Executes commands via `lib-finder` to locate tools
   - Parses `/proc/cpuinfo` or uses `lscpu`
   - Extracts model, cores, threads, flags

4. **GPU Information:**
   - Uses `lspci` to enumerate PCI devices
   - Filters for VGA/3D controllers
   - Extracts vendor and model

5. **Storage Information:**
   - Uses `lsblk`, `lshw`, or parses `/proc` filesystem
   - Enumerates block devices
   - Retrieves capacity, type, model

6. **Memory Information:**
   - Attempts `dmidecode` for detailed DIMM information
   - Falls back to `/proc/meminfo` for total memory
   - Includes slot, size, manufacturer, part number, speed

7. **TPM Detection:**
   - Checks `/sys/class/tpm/tpm0/tpm_version_major`
   - Determines TPM 1.2 or 2.0

**Platform-Specific Details:**
- **Raspberry Pi:** Uses `vcgencmd` for memory split information
- **Standard Linux:** Relies on DMI/SMBIOS via sysfs
- **Wayland Detection:** Checks display server type

---

#### windows_identifiers() - Line 525

**Purpose:** Gathers system information on Windows platforms.

**Process:**

1. **WMI Queries:**
   - Win32_BIOS - BIOS information
   - Win32_BaseBoard - Motherboard details
   - Win32_ComputerSystem - System manufacturer/model
   - Win32_Processor - CPU information
   - Win32_VideoController - GPU information
   - Win32_DiskDrive - Storage devices
   - Win32_PhysicalMemory - Memory modules
   - Win32_Tpm - TPM information

2. **Registry Queries:**
   - UEFI boot mode from firmware environment
   - System information from various registry keys

3. **PowerShell Integration:**
   - Executes `Get-Volume` for volume information
   - Retrieves BitLocker status
   - Gathers filesystem details

4. **Last Boot Time:**
   - Calculates from `Win32_OperatingSystem.LastBootUpTime`

**Platform-Specific Features:**
- BitLocker encryption status for volumes
- Chassis type detection (desktop, laptop, tablet, etc.)
- Form factor identification
- System type (x86, x64, ARM64)

**Helper Functions:**
- `windows_wmic_results(str)` - Parses WMIC output
- `windows_volumes()` - PowerShell volume enumeration
- `win_chassisType()` - Maps chassis type codes to descriptions
- `win_systemType()` - Maps system type codes to architectures
- `win_formFactor()` - Determines form factor from chassis type

---

#### macos_identifiers() - Line 628

**Purpose:** Gathers system information on macOS platforms.

**Process:**

1. **ioreg (I/O Registry):**
   - Executes `ioreg -l` to dump hardware tree
   - Extracts:
     - Model identifier (e.g., "MacBookPro15,1")
     - Board serial number
     - Hardware UUID

2. **sysctl:**
   - Queries kernel parameters
   - CPU model: `machdep.cpu.brand_string`
   - CPU cores: `hw.ncpu`
   - Memory: `hw.memsize`

3. **system_profiler:**
   - Runs `system_profiler SPHardwareDataType` for detailed info
   - Extracts manufacturer (Apple), model, serial number
   - Supplements ioreg data

4. **diskutil:**
   - Enumerates storage devices
   - Lists volumes and partitions
   - Retrieves filesystem types and sizes

**Platform-Specific Features:**
- Apple-specific model identifiers
- Hardware UUID from ioreg
- T2 chip detection (on applicable models)

---

#### isVM() - Line 932

**Purpose:** Detects if code is running in a virtual machine.

**Detection Methods:**

**Linux:**
- Checks for "hypervisor" in `/proc/cpuinfo` CPU flags
- Reads `/sys/class/dmi/id/sys_vendor` for known VM vendors:
  - VMware, VirtualBox, QEMU, Xen, KVM, Microsoft Corporation (Hyper-V)
  - Parallels, Oracle Corporation

**Windows:**
- Queries `Win32_ComputerSystem.Model` via WMI
- Checks for VM indicators in model name

**macOS:**
- Executes `sysctl hw.model`
- Checks for virtualization indicators

**Return Value:** Boolean - `true` if running in VM, `false` otherwise

---

#### isBatteryPowered() - Line 884

**Purpose:** Detects if system has a battery (laptop, tablet, etc.).

**Detection Methods:**

**Linux:**
- Checks `/sys/class/power_supply/` for battery entries
- Looks for `BAT0`, `BAT1`, etc.

**Windows:**
- Queries `Win32_Battery` via WMI
- Battery present if query returns results

**macOS:**
- Executes `ioreg -l | grep -i battery`
- Checks for battery in I/O Registry

**Return Value:** Boolean - `true` if battery detected, `false` otherwise

---

#### isDocker() - Line 874

**Purpose:** Detects if code is running inside a Docker container.

**Detection Method:**
- Checks for `.dockerenv` file in root directory: `require('fs').existsSync('/.dockerenv')`

**Return Value:** Boolean - `true` if running in Docker, `false` otherwise

---

### Usage

#### Basic System Identification

```javascript
var identifiers = require('identifiers');

var sysInfo = identifiers.get();

console.log('Manufacturer:', sysInfo.system_manufacturer);
console.log('Model:', sysInfo.system_model);
console.log('Serial:', sysInfo.board_serial);
console.log('BIOS Version:', sysInfo.bios_version);
console.log('UEFI Boot:', sysInfo.boot_uefi);
```

#### CPU Information

```javascript
var sysInfo = identifiers.get();

if (sysInfo.cpu && sysInfo.cpu.length > 0) {
    sysInfo.cpu.forEach(function(cpu) {
        console.log('CPU Model:', cpu.Model);
        console.log('Cores:', cpu.Cores);
        console.log('Threads:', cpu.Threads);
    });
}
```

#### Memory Inventory

```javascript
var sysInfo = identifiers.get();

if (sysInfo.memory && sysInfo.memory.Memory_Device) {
    var totalMemory = 0;
    sysInfo.memory.Memory_Device.forEach(function(dimm) {
        console.log('Slot:', dimm.Locator);
        console.log('Size:', dimm.Size);
        console.log('Manufacturer:', dimm.Manufacturer);
        console.log('Speed:', dimm.Speed);
        console.log('---');
    });
}
```

#### Virtual Machine Detection

```javascript
var identifiers = require('identifiers');

if (identifiers.isVM()) {
    console.log('Running in virtual machine');
} else {
    console.log('Running on physical hardware');
}
```

#### Battery Detection

```javascript
if (identifiers.isBatteryPowered()) {
    console.log('This is a mobile device (laptop/tablet)');
} else {
    console.log('This is a desktop/server');
}
```

#### Docker Detection

```javascript
if (identifiers.isDocker()) {
    console.log('Running inside Docker container');
} else {
    console.log('Running on host system');
}
```

---

### Dependencies

#### Node.js Core Modules

- **`fs`** - File system operations
  - Reading DMI/sysfs files (Linux)
  - Checking file existence
  - Platform support: Cross-platform

- **`child_process`** - Execute system commands
  - Shell commands for hardware detection
  - Platform support: Cross-platform

#### MeshAgent Module Dependencies

**Linux:**
- **`lib-finder`** - Locates system binaries
  - Finds: `dmidecode`, `lspci`, `lshw`, `lsblk`, `usb-devices`, `lscpu`

**Windows:**
- **`win-wmi`** - WMI query interface
  - Queries all Win32_* classes
- **`child_process`** - PowerShell for volumes

**macOS:**
- **`child_process`** - System utilities
  - Executes: `ioreg`, `sysctl`, `system_profiler`, `diskutil`

#### Platform Binary Dependencies

**Linux:**
- `/usr/sbin/dmidecode` - DMI/SMBIOS decoder
- `/usr/bin/lspci` - PCI device lister
- `/usr/bin/lshw` - Hardware lister
- `/bin/lsblk` - Block device lister
- `vcgencmd` - Raspberry Pi utility (ARM only)

**Windows:**
- PowerShell - Volume and BitLocker information
- WMI - All hardware queries

**macOS:**
- `/usr/sbin/ioreg` - I/O Registry dumper
- `/usr/sbin/sysctl` - Kernel parameter query
- `/usr/sbin/system_profiler` - System information
- `/usr/sbin/diskutil` - Disk utility

#### Dependency Summary

| Platform | Core Deps | MeshAgent Deps | System Binaries |
|----------|-----------|----------------|-----------------|
| Linux | fs, child_process | lib-finder | dmidecode, lspci, lshw, lsblk |
| Windows | fs, child_process | win-wmi | PowerShell, WMI |
| macOS | fs, child_process | None | ioreg, sysctl, system_profiler, diskutil |

---

### Technical Notes

**Data Normalization:**

The module uses helper functions to clean and normalize data:
- `trimIdentifiers(val)` - Removes empty/null/"None" values
- `trimResults(val)` - Removes private fields (starting with `_`) and null values
- `brief(headers, obj)` - Filters objects to include only specified headers

**Platform Detection Priority:**

The module exports different `get()` functions based on platform, determined at module load time.

**Raspberry Pi Support:**

Special handling for ARM devices that don't have traditional DMI/SMBIOS. Uses devicetree and `vcgencmd` for hardware details.

**UEFI Detection:**

- **Windows:** Checks registry firmware environment variables
- **Linux:** Checks for `/sys/firmware/efi` directory
- **macOS:** All modern Macs use UEFI

**TPM Version Detection:**

- TPM 1.2: Legacy, being phased out
- TPM 2.0: Modern standard, required for Windows 11

**BitLocker Status (Windows):**

Queries PowerShell `Get-Volume` for encrypted volumes, providing visibility into drive encryption status.

**Wayland vs X11 (Linux):**

Detects display server type, important for GUI features and remote desktop functionality.

## Summary

The identifiers.js module is a **cross-platform system identification tool** supporting Linux (including Raspberry Pi), Windows, and macOS. It provides comprehensive hardware and system information for device fingerprinting, inventory management, and capability detection.

**Key features:**
- BIOS/UEFI information with boot mode detection
- Motherboard and system manufacturer details
- CPU, GPU, storage, and memory enumeration
- TPM detection and version identification
- Virtual machine detection
- Battery detection for mobile devices
- Docker container detection
- Platform-specific optimizations (WMI, DMI/SMBIOS, ioreg)
- BitLocker status reporting (Windows)
- Raspberry Pi support via devicetree
- Comprehensive storage volume information

The module is used within MeshAgent for device identification, asset inventory, security auditing (TPM, UEFI), and capability detection. It provides the foundational system information needed for remote management and monitoring of diverse hardware platforms.
