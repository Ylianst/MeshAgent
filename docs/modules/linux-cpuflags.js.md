# linux-cpuflags.js

Linux-specific CPU feature detection utility that extracts and parses CPU flags from `/proc/cpuinfo` to identify supported processor capabilities and instruction sets. Provides comprehensive mapping of x86/x64 CPU features including SSE, AVX, virtualization extensions, security features, and performance counters.

## Platform

**Supported Platforms:**
- Linux - Full support

**Excluded Platforms:**
- **macOS** - Explicitly excluded
- **Windows** - Explicitly excluded
- **FreeBSD** - Explicitly excluded

**Exclusion Reasoning:**

**Line 256:** `if (process.platform == 'linux')` - Hard platform check

**Lines 273-274:** Returns `null` for all non-Linux platforms

The module is Linux-only because:

1. **Requires /proc/cpuinfo** - Line 252 reads from `/proc/cpuinfo`, a Linux-specific procfs virtual filesystem that doesn't exist on macOS, Windows, or FreeBSD.

2. **macOS Alternative** - Darwin/macOS provides CPU information through:
   - `sysctl machdep.cpu.features` - CPU feature flags
   - `sysctl hw.optional.*` - Capability detection
   - Completely different data format and access method
   - No file-based interface like /proc/cpuinfo

3. **Windows Alternative** - Windows provides CPU info through:
   - CPUID instruction directly
   - WMI queries
   - Registry entries
   - No /proc filesystem

4. **FreeBSD Alternative** - FreeBSD uses:
   - `sysctl` for CPU information
   - `/var/run/dmesg.boot` for boot messages
   - Different format than Linux's /proc/cpuinfo

5. **Tool Incompatibility** - The awk/grep/tr pipeline (Line 252) expects Linux-specific output format and would require complete rewrite for other platforms.

## Functionality

### Module Export Structure

**Export Type:** Data structure (not function)

The module exports an **array of CPU flag objects** - one object per logical CPU core. Each object contains CPU feature flags as properties with value `1`.

**Export Format:**
```javascript
[
  { fpu: 1, vme: 1, de: 1, pse: 1, tsc: 1, msr: 1, pae: 1, ... },  // Core 0
  { fpu: 1, vme: 1, de: 1, pse: 1, tsc: 1, msr: 1, pae: 1, ... },  // Core 1
  // ... one object per logical core
]
```

**Additional Property:**
- `defines` - Object containing symbolic constants for all CPU features (Lines 17-248)

### CPU Feature Constants (Lines 17-248)

The module defines **200+ individual CPU feature flags** organized by CPUID register groups:

#### Intel CPUID Level 0x00000001 (EDX) - Lines 20-49

Basic processor features:
- **X86_FEATURE_FPU (0)** - Onboard x87 FPU
- **X86_FEATURE_VME (1)** - Virtual 8086 mode enhancements
- **X86_FEATURE_DE (2)** - Debugging extensions
- **X86_FEATURE_PSE (3)** - Page Size Extension
- **X86_FEATURE_TSC (4)** - Time Stamp Counter
- **X86_FEATURE_MSR (5)** - Model-Specific Registers
- **X86_FEATURE_PAE (6)** - Physical Address Extension
- **X86_FEATURE_MCE (7)** - Machine Check Exception
- **X86_FEATURE_CX8 (8)** - CMPXCHG8 instruction
- **X86_FEATURE_APIC (9)** - Onboard APIC
- **X86_FEATURE_SEP (11)** - SYSENTER/SYSEXIT
- **X86_FEATURE_MTRR (12)** - Memory Type Range Registers
- **X86_FEATURE_PGE (13)** - Page Global Enable
- **X86_FEATURE_MCA (14)** - Machine Check Architecture
- **X86_FEATURE_CMOV (15)** - CMOV instructions
- **X86_FEATURE_PAT (16)** - Page Attribute Table
- **X86_FEATURE_PSE36 (17)** - 36-bit PSEs
- **X86_FEATURE_PN (18)** - Processor serial number
- **X86_FEATURE_CLFLUSH (19)** - CLFLUSH instruction
- **X86_FEATURE_DS (21)** - Debug Store
- **X86_FEATURE_ACPI (22)** - ACPI via MSR
- **X86_FEATURE_MMX (23)** - Multimedia Extensions
- **X86_FEATURE_FXSR (24)** - FXSAVE/FXRSTOR
- **X86_FEATURE_XMM (25)** - SSE
- **X86_FEATURE_XMM2 (26)** - SSE2
- **X86_FEATURE_SELFSNOOP (27)** - CPU self snoop
- **X86_FEATURE_HT (28)** - Hyper-Threading
- **X86_FEATURE_ACC (29)** - Automatic clock control
- **X86_FEATURE_IA64 (30)** - IA-64 processor
- **X86_FEATURE_PBE (31)** - Pending Break Enable

#### AMD CPUID Level 0x80000001 (EDX) - Lines 52-61

AMD-specific features:
- **X86_FEATURE_SYSCALL (43)** - SYSCALL/SYSRET
- **X86_FEATURE_MP (51)** - MP Capable
- **X86_FEATURE_NX (52)** - Execute Disable
- **X86_FEATURE_MMXEXT (54)** - AMD MMX extensions
- **X86_FEATURE_FXSR_OPT (57)** - FXSAVE/FXRSTOR optimizations
- **X86_FEATURE_GBPAGES (58)** - GB pages
- **X86_FEATURE_RDTSCP (59)** - RDTSCP instruction
- **X86_FEATURE_LM (61)** - Long Mode (x86-64)
- **X86_FEATURE_3DNOWEXT (62)** - AMD 3DNow extensions
- **X86_FEATURE_3DNOW (63)** - 3DNow

#### Intel CPUID Level 0x00000001 (ECX) - Lines 100-131

Extended features:
- **X86_FEATURE_XMM3 (128)** - SSE3
- **X86_FEATURE_PCLMULQDQ (129)** - PCLMULQDQ instruction
- **X86_FEATURE_DTES64 (130)** - 64-bit Debug Store
- **X86_FEATURE_MWAIT (131)** - MONITOR/MWAIT
- **X86_FEATURE_DSCPL (132)** - CPL-qualified Debug Store
- **X86_FEATURE_VMX (133)** - Hardware virtualization
- **X86_FEATURE_SMX (134)** - Safer Mode Extensions
- **X86_FEATURE_EST (135)** - Enhanced SpeedStep
- **X86_FEATURE_TM2 (136)** - Thermal Monitor 2
- **X86_FEATURE_SSSE3 (137)** - Supplemental SSE3
- **X86_FEATURE_CID (138)** - Context ID
- **X86_FEATURE_SDBG (139)** - Silicon Debug
- **X86_FEATURE_FMA (140)** - Fused multiply-add
- **X86_FEATURE_CX16 (141)** - CMPXCHG16B
- **X86_FEATURE_XTPR (142)** - Send Task Priority Messages
- **X86_FEATURE_PDCM (143)** - Performance Capabilities
- **X86_FEATURE_PCID (145)** - Process Context Identifiers
- **X86_FEATURE_DCA (146)** - Direct Cache Access
- **X86_FEATURE_XMM4_1 (147)** - SSE4.1
- **X86_FEATURE_XMM4_2 (148)** - SSE4.2
- **X86_FEATURE_X2APIC (149)** - x2APIC
- **X86_FEATURE_MOVBE (150)** - MOVBE instruction
- **X86_FEATURE_POPCNT (151)** - POPCNT instruction
- **X86_FEATURE_TSC_DEADLINE_TIMER (152)** - TSC deadline timer
- **X86_FEATURE_AES (153)** - AES instructions
- **X86_FEATURE_XSAVE (154)** - XSAVE/XRSTOR/XSETBV/XGETBV
- **X86_FEATURE_AVX (156)** - Advanced Vector Extensions
- **X86_FEATURE_F16C (157)** - 16-bit FP conversions
- **X86_FEATURE_RDRAND (158)** - RDRAND instruction
- **X86_FEATURE_HYPERVISOR (159)** - Running on a hypervisor

#### Intel CPUID Level 0x00000007:0 (EBX) - Lines 218-248

Advanced features:
- **X86_FEATURE_FSGSBASE (224)** - RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
- **X86_FEATURE_TSC_ADJUST (225)** - TSC adjustment MSR
- **X86_FEATURE_SGX (226)** - Software Guard Extensions
- **X86_FEATURE_BMI1 (227)** - Bit Manipulation Instruction Set 1
- **X86_FEATURE_HLE (228)** - Hardware Lock Elision
- **X86_FEATURE_AVX2 (229)** - AVX2 instructions
- **X86_FEATURE_FDP_EXCPTN_ONLY (230)** - FPU Data Pointer updated only on x87 exceptions
- **X86_FEATURE_SMEP (231)** - Supervisor Mode Execution Protection
- **X86_FEATURE_BMI2 (232)** - Bit Manipulation Instruction Set 2
- **X86_FEATURE_ERMS (233)** - Enhanced REP MOVSB/STOSB
- **X86_FEATURE_INVPCID (234)** - Invalidate Processor Context ID
- **X86_FEATURE_RTM (235)** - Restricted Transactional Memory
- **X86_FEATURE_CQM (236)** - Cache QoS Monitoring
- **X86_FEATURE_ZERO_FCS_FDS (237)** - Zero FPU CS/DS
- **X86_FEATURE_MPX (238)** - Memory Protection Extension
- **X86_FEATURE_RDT_A (239)** - Resource Director Technology Allocation
- **X86_FEATURE_AVX512F (240)** - AVX-512 Foundation
- **X86_FEATURE_AVX512DQ (241)** - AVX-512 Doubleword and Quadword Instructions
- **X86_FEATURE_RDSEED (242)** - RDSEED instruction
- **X86_FEATURE_ADX (243)** - ADCX and ADOX instructions
- **X86_FEATURE_SMAP (244)** - Supervisor Mode Access Prevention
- **X86_FEATURE_AVX512IFMA (245)** - AVX-512 Integer Fused Multiply-Add
- **X86_FEATURE_CLFLUSHOPT (247)** - CLFLUSHOPT instruction
- **X86_FEATURE_CLWB (248)** - CLWB instruction
- **X86_FEATURE_INTEL_PT (249)** - Intel Processor Trace
- **X86_FEATURE_AVX512PF (250)** - AVX-512 Prefetch
- **X86_FEATURE_AVX512ER (251)** - AVX-512 Exponential and Reciprocal
- **X86_FEATURE_AVX512CD (252)** - AVX-512 Conflict Detection
- **X86_FEATURE_SHA_NI (253)** - SHA extensions
- **X86_FEATURE_AVX512BW (254)** - AVX-512 Byte and Word
- **X86_FEATURE_AVX512VL (255)** - AVX-512 Vector Length Extensions

### Data Extraction Process (Lines 250-272)

**Shell Command Pipeline (Line 252):**
```bash
cat /proc/cpuinfo | grep flags | tr '\n' '~' | awk -F~ '{
    printf "[";
    for(i=1;i<=NF-1;++i) {
        split($i, line, ":");
        x=split(line[2], vals, " ");
        printf "%s{", (i!=1?",":"");
        for(j=1;j<=x;++j) {
            printf "%s\"%s\": 1", (j!=1?",":""), vals[j];
        }
        printf "}";
    }
    printf "]";
}'
```

**Processing Steps:**
1. **cat /proc/cpuinfo** - Read CPU information file
2. **grep flags** - Extract lines containing "flags" (CPU features)
3. **tr '\n' '~'** - Convert newlines to tilde for single-line processing
4. **awk** - Parse and convert to JSON:
   - Split by tilde (one entry per logical core)
   - Extract flags portion after colon
   - Build JSON object with each flag set to `1`
   - Output array of objects

**Result Parsing (Lines 260-268):**
- Try to parse JSON output
- On success: Export array with `defines` property
- On error: Export `null`

### Platform Check (Lines 256-274)

```javascript
if (process.platform == 'linux')
{
    try
    {
        module.exports = JSON.parse(child.stdout.str.trim());
    }
    catch (x)
    {
        module.exports = null;
    }
    if(module.exports)
    {
        Object.defineProperty(module.exports, "defines", { value: cpu_feature });
    }
}
else
{
    module.exports = null;  // Non-Linux platforms get null
}
```

## Dependencies

### Node.js Core Module Dependencies

#### child_process (Line 250)

```javascript
var child = require('child_process').execFile('/bin/sh', ['sh']);
```

**Purpose:** Execute shell commands for parsing /proc/cpuinfo

**Usage:** Single shell invocation to run command pipeline

### Platform Binary Dependencies

**Critical Dependencies:**

1. **/proc/cpuinfo** - Linux procfs virtual file (Line 252)
   - **Critical requirement** - Module completely non-functional without it
   - Contains CPU feature flags in "flags" lines
   - Format: `flags : fpu vme de pse tsc msr pae mce cx8 ...`

2. **cat** - Concatenate files (Line 252)
   - Read /proc/cpuinfo contents
   - Standard Unix utility

3. **grep** - Pattern matching (Line 252)
   - Extract lines containing "flags"
   - GNU grep or compatible

4. **tr** - Character translation (Line 252)
   - Convert newlines to tildes
   - Enables single-line awk processing

5. **awk** - Text processing language (Line 252)
   - Complex JSON generation
   - Field splitting and formatting
   - GNU awk (gawk) or mawk

6. **/bin/sh** - POSIX shell (Line 250)
   - Command executor
   - Runs the pipeline

### Dependency Chain

```
linux-cpuflags.js
└─── child_process (Line 250) - Shell execution
     └─── /bin/sh - POSIX shell
          └─── Command pipeline (Line 252)
               ├─── cat - Read /proc/cpuinfo
               ├─── grep - Filter flags lines
               ├─── tr - Convert newlines
               └─── awk - Generate JSON
```

## Usage Examples

### Example 1: Basic Usage

```javascript
var cpuflags = require('linux-cpuflags');

// Check if module loaded (null on non-Linux)
if (cpuflags) {
    console.log("Number of logical cores:", cpuflags.length);
    console.log("Core 0 flags:", Object.keys(cpuflags[0]).length, "features");

    // Access specific flag
    if (cpuflags[0].avx) {
        console.log("AVX support detected");
    }
}
```

### Example 2: Feature Detection

```javascript
var cpuflags = require('linux-cpuflags');

if (cpuflags) {
    // Check for AVX2 support across all cores
    var hasAVX2 = cpuflags.every(function(core) {
        return core.avx2 === 1;
    });

    if (hasAVX2) {
        console.log("All cores support AVX2 - enabling optimized code path");
        // Use AVX2-optimized algorithms
    } else {
        console.log("AVX2 not universally available - using fallback");
    }

    // Check virtualization support
    var hasVMX = cpuflags.some(function(core) {
        return core.vmx === 1;  // Intel VT-x
    });

    var hasSVM = cpuflags.some(function(core) {
        return core.svm === 1;  // AMD-V
    });

    if (hasVMX || hasSVM) {
        console.log("Hardware virtualization supported");
    }
}
```

### Example 3: Using Symbolic Constants

```javascript
var cpuflags = require('linux-cpuflags');

if (cpuflags && cpuflags.defines) {
    // Access feature flag numbers
    var SSE4_1_FLAG = cpuflags.defines.X86_FEATURE_XMM4_1;  // 147
    var AVX_FLAG = cpuflags.defines.X86_FEATURE_AVX;        // 156
    var AES_FLAG = cpuflags.defines.X86_FEATURE_AES;        // 153

    console.log("SSE4.1 flag number:", SSE4_1_FLAG);
    console.log("AVX flag number:", AVX_FLAG);
    console.log("AES-NI flag number:", AES_FLAG);

    // List all available feature constants
    console.log("Total feature constants defined:",
                Object.keys(cpuflags.defines).length);
}
```

### Example 4: Security Feature Detection

```javascript
var cpuflags = require('linux-cpuflags');

if (cpuflags && cpuflags[0]) {
    var core0 = cpuflags[0];

    // Check security features
    var security = {
        nx: core0.nx === 1,           // No-Execute (DEP)
        smep: core0.smep === 1,       // Supervisor Mode Execution Protection
        smap: core0.smap === 1,       // Supervisor Mode Access Prevention
        aesni: core0.aes === 1,       // AES-NI encryption
        rdrand: core0.rdrand === 1,   // Hardware RNG
        rdseed: core0.rdseed === 1,   // Enhanced RNG
        sgx: core0.sgx === 1          // Software Guard Extensions
    };

    console.log("Security features:", security);

    if (security.aesni) {
        console.log("Hardware AES encryption available");
    }

    if (security.rdrand || security.rdseed) {
        console.log("Hardware random number generator available");
    }
}
```

### Example 5: Per-Core Analysis

```javascript
var cpuflags = require('linux-cpuflags');

if (cpuflags) {
    // Analyze each core
    cpuflags.forEach(function(core, index) {
        var features = Object.keys(core);
        console.log("Core", index + ":", features.length, "features");

        // Check for asymmetric cores (big.LITTLE, etc.)
        if (index > 0) {
            var prevCore = cpuflags[index - 1];
            var prevFeatures = Object.keys(prevCore);

            if (features.length !== prevFeatures.length) {
                console.log("WARNING: Asymmetric CPU detected!");
                console.log("Core", index - 1, "has", prevFeatures.length, "features");
                console.log("Core", index, "has", features.length, "features");
            }
        }
    });
}
```

### Example 6: Conditional Module Loading

```javascript
var cpuflags = require('linux-cpuflags');

// Select optimal implementation based on CPU features
var cryptoModule;

if (cpuflags && cpuflags[0]) {
    if (cpuflags[0].aes && cpuflags[0].avx2) {
        console.log("Loading AVX2+AES-NI optimized crypto");
        cryptoModule = require('./crypto-avx2-aes');
    } else if (cpuflags[0].aes) {
        console.log("Loading AES-NI optimized crypto");
        cryptoModule = require('./crypto-aes');
    } else if (cpuflags[0].sse2) {
        console.log("Loading SSE2 optimized crypto");
        cryptoModule = require('./crypto-sse2');
    } else {
        console.log("Loading generic crypto");
        cryptoModule = require('./crypto-generic');
    }
} else {
    console.log("Not on Linux - using generic crypto");
    cryptoModule = require('./crypto-generic');
}

module.exports = cryptoModule;
```

## Technical Notes

### /proc/cpuinfo Format

The module parses Linux /proc/cpuinfo which has this format:

```
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
...
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d

processor	: 1
...
```

Only the "flags" lines are extracted and parsed.

### Feature Flag Consistency

Most systems have identical flags across all logical cores, but some scenarios can differ:
- **Asymmetric CPUs** - big.LITTLE architectures (rare on x86)
- **Disabled features** - BIOS/firmware may disable features on specific cores
- **Kernel parameters** - Boot options can disable features (e.g., `nosmep`)

### Performance

- **One-time execution** - Module runs command once at require() time
- **Cached result** - Subsequent requires return cached data
- **Fast parsing** - Single shell pipeline execution
- **Low memory** - Only stores flags as properties with value 1

### Error Handling

- Returns `null` on non-Linux platforms (Line 274)
- Returns `null` if JSON parsing fails (Line 264)
- No error thrown - graceful degradation

## Summary

The linux-cpuflags.js module provides comprehensive CPU feature detection for Linux systems by parsing `/proc/cpuinfo`. It exports an array of CPU flag objects (one per logical core) with 200+ feature flag constants for x86/x64 processors.

**macOS is excluded** because:
- Requires `/proc/cpuinfo` - Linux-specific procfs virtual filesystem
- macOS provides CPU info via sysctl with completely different format
- Tool pipeline (cat/grep/tr/awk) expects Linux-specific output
- Would require complete rewrite using `sysctl machdep.cpu.features`

The module is useful for runtime CPU capability detection, enabling optimized code paths based on available instruction sets (SSE, AVX, AES-NI, etc.) and security features (NX, SMEP, SMAP).
