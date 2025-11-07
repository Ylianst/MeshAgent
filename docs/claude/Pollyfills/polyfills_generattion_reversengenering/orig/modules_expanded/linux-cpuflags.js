// Module: linux-cpuflags
// Timestamp: 2025-08-19T13:12:47.000-06:00
// Original compressed size: 5607 bytes
// Decompressed size: 18945 bytes
// Compression ratio: 70.4%

/*
Copyright 2019 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

var cpu_feature = {};

/* Intel-defined CPU features, CPUID level 0x00000001 (EDX), word 0 */
cpu_feature.X86_FEATURE_FPU			= ( 0*32+ 0); /* Onboard FPU */
cpu_feature.X86_FEATURE_VME			= ( 0*32+ 1); /* Virtual Mode Extensions */
cpu_feature.X86_FEATURE_DE			= ( 0*32+ 2); /* Debugging Extensions */
cpu_feature.X86_FEATURE_PSE			= ( 0*32+ 3); /* Page Size Extensions */
cpu_feature.X86_FEATURE_TSC			= ( 0*32+ 4); /* Time Stamp Counter */
cpu_feature.X86_FEATURE_MSR			= ( 0*32+ 5); /* Model-Specific Registers */
cpu_feature.X86_FEATURE_PAE			= ( 0*32+ 6); /* Physical Address Extensions */
cpu_feature.X86_FEATURE_MCE			= ( 0*32+ 7); /* Machine Check Exception */
cpu_feature.X86_FEATURE_CX8			= ( 0*32+ 8); /* CMPXCHG8 instruction */
cpu_feature.X86_FEATURE_APIC		= ( 0*32+ 9); /* Onboard APIC */
cpu_feature.X86_FEATURE_SEP			= ( 0*32+11); /* SYSENTER/SYSEXIT */
cpu_feature.X86_FEATURE_MTRR		= ( 0*32+12); /* Memory Type Range Registers */
cpu_feature.X86_FEATURE_PGE			= ( 0*32+13); /* Page Global Enable */
cpu_feature.X86_FEATURE_MCA			= ( 0*32+14); /* Machine Check Architecture */
cpu_feature.X86_FEATURE_CMOV		= ( 0*32+15); /* CMOV instructions (plus FCMOVcc, FCOMI with FPU) */
cpu_feature.X86_FEATURE_PAT			= ( 0*32+16); /* Page Attribute Table */
cpu_feature.X86_FEATURE_PSE36		= ( 0*32+17); /* 36-bit PSEs */
cpu_feature.X86_FEATURE_PN			= ( 0*32+18); /* Processor serial number */
cpu_feature.X86_FEATURE_CLFLUSH		= ( 0*32+19); /* CLFLUSH instruction */
cpu_feature.X86_FEATURE_DS			= ( 0*32+21); /* "dts" Debug Store */
cpu_feature.X86_FEATURE_ACPI		= ( 0*32+22); /* ACPI via MSR */
cpu_feature.X86_FEATURE_MMX			= ( 0*32+23); /* Multimedia Extensions */
cpu_feature.X86_FEATURE_FXSR		= ( 0*32+24); /* FXSAVE/FXRSTOR, CR4.OSFXSR */
cpu_feature.X86_FEATURE_XMM			= ( 0*32+25); /* "sse" */
cpu_feature.X86_FEATURE_XMM2		= ( 0*32+26); /* "sse2" */
cpu_feature.X86_FEATURE_SELFSNOOP	= ( 0*32+27); /* "ss" CPU self snoop */
cpu_feature.X86_FEATURE_HT			= ( 0*32+28); /* Hyper-Threading */
cpu_feature.X86_FEATURE_ACC			= ( 0*32+29); /* "tm" Automatic clock control */
cpu_feature.X86_FEATURE_IA64		= ( 0*32+30); /* IA-64 processor */
cpu_feature.X86_FEATURE_PBE         = (0 * 32 + 31); /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
cpu_feature.X86_FEATURE_SYSCALL		= ( 1*32+11); /* SYSCALL/SYSRET */
cpu_feature.X86_FEATURE_MP			= ( 1*32+19); /* MP Capable */
cpu_feature.X86_FEATURE_NX			= ( 1*32+20); /* Execute Disable */
cpu_feature.X86_FEATURE_MMXEXT		= ( 1*32+22); /* AMD MMX extensions */
cpu_feature.X86_FEATURE_FXSR_OPT	= ( 1*32+25); /* FXSAVE/FXRSTOR optimizations */
cpu_feature.X86_FEATURE_GBPAGES		= ( 1*32+26); /* "pdpe1gb" GB pages */
cpu_feature.X86_FEATURE_RDTSCP		= ( 1*32+27); /* RDTSCP */
cpu_feature.X86_FEATURE_LM			= ( 1*32+29); /* Long Mode (x86-64, 64-bit support) */
cpu_feature.X86_FEATURE_3DNOWEXT	= ( 1*32+30); /* AMD 3DNow extensions */
cpu_feature.X86_FEATURE_3DNOW       = (1 * 32 + 31); /* 3DNow */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
cpu_feature.X86_FEATURE_RECOVERY	= ( 2*32+ 0); /* CPU in recovery mode */
cpu_feature.X86_FEATURE_LONGRUN		= ( 2*32+ 1); /* Longrun power control */
cpu_feature.X86_FEATURE_LRTI        = (2 * 32 + 3); /* LongRun table interface */

/* Other features, Linux-defined mapping, word 3 */
cpu_Feature.X86_FEATURE_CXMMX		= ( 3*32+ 0); /* Cyrix MMX extensions */
cpu_Feature.X86_FEATURE_K6_MTRR		= ( 3*32+ 1); /* AMD K6 nonstandard MTRRs */
cpu_Feature.X86_FEATURE_CYRIX_ARR	= ( 3*32+ 2); /* Cyrix ARRs (= MTRRs) */
cpu_Feature.X86_FEATURE_CENTAUR_MCR = (3 * 32 + 3); /* Centaur MCRs (= MTRRs) */
cpu_feature.X86_FEATURE_K8			= ( 3*32+ 4); /* "" Opteron, Athlon64 */
cpu_feature.X86_FEATURE_K7			= ( 3*32+ 5); /* "" Athlon */
cpu_feature.X86_FEATURE_P3			= ( 3*32+ 6); /* "" P3 */
cpu_feature.X86_FEATURE_P4 = (3 * 32 + 7); /* "" P4 */
cpu_feature.X86_FEATURE_CONSTANT_TSC = (3 * 32 + 8); /* TSC ticks at a constant rate */
cpu_feature.X86_FEATURE_UP			= ( 3*32+ 9); /* SMP kernel running on UP */
cpu_feature.X86_FEATURE_ART = (3 * 32 + 10); /* Always running timer (ART) */
cpu_feature.X86_FEATURE_ARCH_PERFMON = (3 * 32 + 11); /* Intel Architectural PerfMon */
cpu_feature.X86_FEATURE_PEBS		= ( 3*32+12); /* Precise-Event Based Sampling */
cpu_feature.X86_FEATURE_BTS = (3 * 32 + 13); /* Branch Trace Store */
cpu_feature.X86_FEATURE_SYSCALL32	= 	( 3*32+14); /* "" syscall in IA32 userspace */
cpu_feature.X86_FEATURE_SYSENTER32	= 	( 3*32+15); /* "" sysenter in IA32 userspace */
cpu_feature.X86_FEATURE_REP_GOOD	= 	( 3*32+16); /* REP microcode works well */
cpu_feature.X86_FEATURE_LFENCE_RDTSC= 	( 3*32+18); /* "" LFENCE synchronizes RDTSC */
cpu_feature.X86_FEATURE_ACC_POWER = (3 * 32 + 19); /* AMD Accumulated Power Mechanism */
cpu_feature.X86_FEATURE_NOPL		= ( 3*32+20); /* The NOPL (0F 1F) instructions */
cpu_feature.X86_FEATURE_ALWAYS = (3 * 32 + 21); /* "" Always-present feature */
cpu_feature.X86_FEATURE_XTOPOLOGY	= 	( 3*32+22); /* CPU topology enum extensions */
cpu_feature.X86_FEATURE_TSC_RELIABLE= 	( 3*32+23); /* TSC is known to be reliable */
cpu_feature.X86_FEATURE_NONSTOP_TSC = (3 * 32 + 24); /* TSC does not stop in C states */
cpu_feature.X86_FEATURE_CPUID = (3 * 32 + 25); /* CPU has CPUID instruction itself */
cpu_feature.X86_FEATURE_EXTD_APICID = (3 * 32 + 26); /* Extended APICID (8 bits) */
cpu_feature.X86_FEATURE_AMD_DCM = (3 * 32 + 27); /* AMD multi-node processor */
cpu_feature.X86_FEATURE_APERFMPERF = (3 * 32 + 28); /* P-State hardware coordination feedback capability (APERF/MPERF MSRs) */
cpu_feature.X86_FEATURE_NONSTOP_TSC_S3	= ( 3*32+30); /* TSC doesn't stop in S3 state */
cpu_feature.X86_FEATURE_TSC_KNOWN_FREQ = (3 * 32 + 31); /* TSC has known frequency */

/* Intel-defined CPU features, CPUID level 0x00000001 (ECX), word 4 */
cpu_feature.X86_FEATURE_XMM3		= ( 4*32+ 0);/* "pni" SSE-3 */
cpu_feature.X86_FEATURE_PCLMULQDQ	= ( 4*32+ 1);/* PCLMULQDQ instruction */
cpu_feature.X86_FEATURE_DTES64		= ( 4*32+ 2);/* 64-bit Debug Store */
cpu_feature.X86_FEATURE_MWAIT		= ( 4*32+ 3);/* "monitor" MONITOR/MWAIT support */
cpu_feature.X86_FEATURE_DSCPL		= ( 4*32+ 4);/* "ds_cpl" CPL-qualified (filtered) Debug Store */
cpu_feature.X86_FEATURE_VMX			= ( 4*32+ 5);/* Hardware virtualization */
cpu_feature.X86_FEATURE_SMX			= ( 4*32+ 6);/* Safer Mode eXtensions */
cpu_feature.X86_FEATURE_EST			= ( 4*32+ 7);/* Enhanced SpeedStep */
cpu_feature.X86_FEATURE_TM2			= ( 4*32+ 8);/* Thermal Monitor 2 */
cpu_feature.X86_FEATURE_SSSE3		= ( 4*32+ 9);/* Supplemental SSE-3 */
cpu_feature.X86_FEATURE_CID			= ( 4*32+10);/* Context ID */
cpu_feature.X86_FEATURE_SDBG		= ( 4*32+11);/* Silicon Debug */
cpu_feature.X86_FEATURE_FMA			= ( 4*32+12);/* Fused multiply-add */
cpu_feature.X86_FEATURE_CX16		= ( 4*32+13);/* CMPXCHG16B instruction */
cpu_feature.X86_FEATURE_XTPR		= ( 4*32+14);/* Send Task Priority Messages */
cpu_feature.X86_FEATURE_PDCM		= ( 4*32+15);/* Perf/Debug Capabilities MSR */
cpu_feature.X86_FEATURE_PCID		= ( 4*32+17);/* Process Context Identifiers */
cpu_feature.X86_FEATURE_DCA			= ( 4*32+18);/* Direct Cache Access */
cpu_feature.X86_FEATURE_XMM4_1		= ( 4*32+19);/* "sse4_1" SSE-4.1 */
cpu_feature.X86_FEATURE_XMM4_2		= ( 4*32+20);/* "sse4_2" SSE-4.2 */
cpu_feature.X86_FEATURE_X2APIC		= ( 4*32+21);/* X2APIC */
cpu_feature.X86_FEATURE_MOVBE		= ( 4*32+22);/* MOVBE instruction */
cpu_feature.X86_FEATURE_POPCNT = (4 * 32 + 23);/* POPCNT instruction */
cpu_feature.X86_FEATURE_TSC_DEADLINE_TIMER = (4 * 32 + 24); /* TSC deadline timer */
cpu_feature.X86_FEATURE_AES			= ( 4*32+25); /* AES instructions */
cpu_feature.X86_FEATURE_XSAVE		= ( 4*32+26); /* XSAVE/XRSTOR/XSETBV/XGETBV instructions */
cpu_feature.X86_FEATURE_OSXSAVE		= ( 4*32+27); /* "" XSAVE instruction enabled in the OS */
cpu_feature.X86_FEATURE_AVX			= ( 4*32+28); /* Advanced Vector Extensions */
cpu_feature.X86_FEATURE_F16C		= ( 4*32+29); /* 16-bit FP conversions */
cpu_feature.X86_FEATURE_RDRAND = (4 * 32 + 30); /* RDRAND instruction */
cpu_feature.X86_FEATURE_HYPERVISOR = (4 * 32 + 31); /* Running on a hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001, word 5 */
cpu_feature.X86_FEATURE_XSTORE		= ( 5*32+ 2); /* "rng" RNG present (xstore) */
cpu_feature.X86_FEATURE_XSTORE_EN	= ( 5*32+ 3); /* "rng_en" RNG enabled */
cpu_feature.X86_FEATURE_XCRYPT		= ( 5*32+ 6); /* "ace" on-CPU crypto (xcrypt) */
cpu_feature.X86_FEATURE_XCRYPT_EN	= ( 5*32+ 7); /* "ace_en" on-CPU crypto enabled */
cpu_feature.X86_FEATURE_ACE2		= ( 5*32+ 8); /* Advanced Cryptography Engine v2 */
cpu_feature.X86_FEATURE_ACE2_EN		= ( 5*32+ 9); /* ACE v2 enabled */
cpu_feature.X86_FEATURE_PHE			= ( 5*32+10); /* PadLock Hash Engine */
cpu_feature.X86_FEATURE_PHE_EN		= ( 5*32+11); /* PHE enabled */
cpu_feature.X86_FEATURE_PMM			= ( 5*32+12); /* PadLock Montgomery Multiplier */
cpu_feature.X86_FEATURE_PMM_EN      = (5 * 32 + 13); /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ECX, word 6 */
cpu_feature.X86_FEATURE_LAHF_LM		    = ( 6*32+ 0); /* LAHF/SAHF in long mode */
cpu_feature.X86_FEATURE_CMP_LEGACY		= ( 6*32+ 1); /* If yes HyperThreading not valid */
cpu_feature.X86_FEATURE_SVM			    = ( 6*32+ 2); /* Secure Virtual Machine */
cpu_feature.X86_FEATURE_EXTAPIC		    = ( 6*32+ 3); /* Extended APIC space */
cpu_feature.X86_FEATURE_CR8_LEGACY		= ( 6*32+ 4); /* CR8 in 32-bit mode */
cpu_feature.X86_FEATURE_ABM			    = ( 6*32+ 5); /* Advanced bit manipulation */
cpu_feature.X86_FEATURE_SSE4A		    = ( 6*32+ 6); /* SSE-4A */
cpu_feature.X86_FEATURE_MISALIGNSSE		= ( 6*32+ 7); /* Misaligned SSE mode */
cpu_feature.X86_FEATURE_3DNOWPREFETCH	= ( 6*32+ 8); /* 3DNow prefetch instructions */
cpu_feature.X86_FEATURE_OSVW		    = ( 6*32+ 9); /* OS Visible Workaround */
cpu_feature.X86_FEATURE_IBS			    = ( 6*32+10); /* Instruction Based Sampling */
cpu_feature.X86_FEATURE_XOP			    = ( 6*32+11); /* extended AVX instructions */
cpu_feature.X86_FEATURE_SKINIT		    = ( 6*32+12); /* SKINIT/STGI instructions */
cpu_feature.X86_FEATURE_WDT			    = ( 6*32+13); /* Watchdog timer */
cpu_feature.X86_FEATURE_LWP			    = ( 6*32+15); /* Light Weight Profiling */
cpu_feature.X86_FEATURE_FMA4		    = ( 6*32+16); /* 4 operands MAC instructions */
cpu_feature.X86_FEATURE_TCE			    = ( 6*32+17); /* Translation Cache Extension */
cpu_feature.X86_FEATURE_NODEID_MSR		= ( 6*32+19); /* NodeId MSR */
cpu_feature.X86_FEATURE_TBM			    = ( 6*32+21); /* Trailing Bit Manipulations */
cpu_feature.X86_FEATURE_TOPOEXT		    = ( 6*32+22); /* Topology extensions CPUID leafs */
cpu_feature.X86_FEATURE_PERFCTR_CORE	= ( 6*32+23); /* Core performance counter extensions */
cpu_feature.X86_FEATURE_PERFCTR_NB		= ( 6*32+24); /* NB performance counter extensions */
cpu_feature.X86_FEATURE_BPEXT		    = ( 6*32+26); /* Data breakpoint extension */
cpu_feature.X86_FEATURE_PTSC		    = ( 6*32+27); /* Performance time-stamp counter */
cpu_feature.X86_FEATURE_PERFCTR_LLC		= ( 6*32+28); /* Last Level Cache performance counter extensions */
cpu_feature.X86_FEATURE_MWAITX          = (6 * 32 + 29); /* MWAIT extension (MONITORX/MWAITX instructions) */

/* Auxiliary flags */
cpu_feature.X86_FEATURE_RING3MWAIT		= ( 7*32+ 0); /* Ring 3 MONITOR/MWAIT instructions */
cpu_feature.X86_FEATURE_CPUID_FAULT		= ( 7*32+ 1); /* Intel CPUID faulting */
cpu_feature.X86_FEATURE_CPB			    = ( 7*32+ 2); /* AMD Core Performance Boost */
cpu_feature.X86_FEATURE_EPB			    = ( 7*32+ 3); /* IA32_ENERGY_PERF_BIAS support */
cpu_feature.X86_FEATURE_CAT_L3		    = ( 7*32+ 4); /* Cache Allocation Technology L3 */
cpu_feature.X86_FEATURE_CAT_L2		    = ( 7*32+ 5); /* Cache Allocation Technology L2 */
cpu_feature.X86_FEATURE_CDP_L3		    = ( 7*32+ 6); /* Code and Data Prioritization L3 */
cpu_feature.X86_FEATURE_INVPCID_SINGLE	= ( 7*32+ 7); /* Effectively INVPCID && CR4.PCIDE=1 */
cpu_feature.X86_FEATURE_HW_PSTATE		= ( 7*32+ 8); /* AMD HW-PState */
cpu_feature.X86_FEATURE_PROC_FEEDBACK	= ( 7*32+ 9); /* AMD ProcFeedbackInterface */
cpu_feature.X86_FEATURE_SME			    = ( 7*32+10); /* AMD Secure Memory Encryption */
cpu_feature.X86_FEATURE_PTI			    = ( 7*32+11); /* Kernel Page Table Isolation enabled */
cpu_feature.X86_FEATURE_RETPOLINE		= ( 7*32+12); /* "" Generic Retpoline mitigation for Spectre variant 2 */
cpu_feature.X86_FEATURE_RETPOLINE_AMD	= ( 7*32+13); /* "" AMD Retpoline mitigation for Spectre variant 2 */
cpu_feature.X86_FEATURE_INTEL_PPIN		= ( 7*32+14); /* Intel Processor Inventory Number */
cpu_feature.X86_FEATURE_CDP_L2		    = ( 7*32+15); /* Code and Data Prioritization L2 */
cpu_feature.X86_FEATURE_MSR_SPEC_CTRL	= ( 7*32+16); /* "" MSR SPEC_CTRL is implemented */
cpu_feature.X86_FEATURE_SSBD		    = ( 7*32+17); /* Speculative Store Bypass Disable */
cpu_feature.X86_FEATURE_MBA			    = ( 7*32+18); /* Memory Bandwidth Allocation */
cpu_feature.X86_FEATURE_RSB_CTXSW		= ( 7*32+19); /* "" Fill RSB on context switches */
cpu_feature.X86_FEATURE_SEV			    = ( 7*32+20); /* AMD Secure Encrypted Virtualization */
cpu_feature.X86_FEATURE_USE_IBPB		= ( 7*32+21); /* "" Indirect Branch Prediction Barrier enabled */
cpu_feature.X86_FEATURE_USE_IBRS_FW = (7 * 32 + 22); /* "" Use IBRS during runtime firmware calls */
cpu_feature.X86_FEATURE_SPEC_STORE_BYPASS_DISABLE = (7 * 32 + 23);/* "" Disable Speculative Store Bypass. */
cpu_feature.X86_FEATURE_LS_CFG_SSBD		= ( 7*32+24); /* "" AMD SSBD implementation via LS_CFG MSR */
cpu_feature.X86_FEATURE_IBRS		    = ( 7*32+25);/* Indirect Branch Restricted Speculation */
cpu_feature.X86_FEATURE_IBPB		    = ( 7*32+26);/* Indirect Branch Prediction Barrier */
cpu_feature.X86_FEATURE_STIBP		    = ( 7*32+27);/* Single Thread Indirect Branch Predictors */
cpu_feature.X86_FEATURE_ZEN			    = ( 7*32+28);/* "" CPU is AMD family 0x17 (Zen) */
cpu_feature.X86_FEATURE_L1TF_PTEINV		= ( 7*32+29);/* "" L1TF workaround PTE inversion */
cpu_feature.X86_FEATURE_IBRS_ENHANCED = (7 * 32 + 30);/* Enhanced IBRS */

/* Virtualization flags: Linux defined, word 8 */
cpu_feature.X86_FEATURE_TPR_SHADOW		= ( 8*32+ 0); /* Intel TPR Shadow */
cpu_feature.X86_FEATURE_VNMI		    = ( 8*32+ 1); /* Intel Virtual NMI */
cpu_feature.X86_FEATURE_FLEXPRIORITY	= ( 8*32+ 2); /* Intel FlexPriority */
cpu_feature.X86_FEATURE_EPT			    = ( 8*32+ 3); /* Intel Extended Page Table */
cpu_feature.X86_FEATURE_VPID		    = ( 8*32+ 4); /* Intel Virtual Processor ID */
cpu_feature.X86_FEATURE_VMMCALL		    = ( 8*32+15); /* Prefer VMMCALL to VMCALL */
cpu_feature.X86_FEATURE_XENPV		    = ( 8*32+16); /* "" Xen paravirtual guest */
cpu_feature.X86_FEATURE_EPT_AD		    = ( 8*32+17); /* Intel Extended Page Table access-dirty bit */
cpu_feature.X86_FEATURE_VMCALL		    = ( 8*32+18); /* "" Hypervisor supports the VMCALL instruction */
cpu_feature.X86_FEATURE_VMW_VMMCALL = (8 * 32 + 19); /* "" VMware prefers VMMCALL hypercall instruction */

/* Intel-defined CPU features, CPUID level 0x00000007:0 (EBX), word 9 */
cpu_feature.X86_FEATURE_FSGSBASE		= ( 9*32+ 0); /* RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE instructions*/
cpu_feature.X86_FEATURE_TSC_ADJUST		= ( 9*32+ 1); /* TSC adjustment MSR 0x3B */
cpu_feature.X86_FEATURE_BMI1		    = ( 9*32+ 3); /* 1st group bit manipulation extensions */
cpu_feature.X86_FEATURE_HLE			    = ( 9*32+ 4); /* Hardware Lock Elision */
cpu_feature.X86_FEATURE_AVX2		    = ( 9*32+ 5); /* AVX2 instructions */
cpu_feature.X86_FEATURE_FDP_EXCPTN_ONLY	= ( 9*32+ 6); /* "" FPU data pointer updated only on x87 exceptions */
cpu_feature.X86_FEATURE_SMEP		    = ( 9*32+ 7); /* Supervisor Mode Execution Protection */
cpu_feature.X86_FEATURE_BMI2		    = ( 9*32+ 8); /* 2nd group bit manipulation extensions */
cpu_feature.X86_FEATURE_ERMS		    = ( 9*32+ 9); /* Enhanced REP MOVSB/STOSB instructions */
cpu_feature.X86_FEATURE_INVPCID		    = ( 9*32+10); /* Invalidate Processor Context ID */
cpu_feature.X86_FEATURE_RTM			    = ( 9*32+11); /* Restricted Transactional Memory */
cpu_feature.X86_FEATURE_CQM			    = ( 9*32+12); /* Cache QoS Monitoring */
cpu_feature.X86_FEATURE_ZERO_FCS_FDS	= ( 9*32+13); /* "" Zero out FPU CS and FPU DS */
cpu_feature.X86_FEATURE_MPX			    = ( 9*32+14); /* Memory Protection Extension */
cpu_feature.X86_FEATURE_RDT_A		    = ( 9*32+15); /* Resource Director Technology Allocation */
cpu_feature.X86_FEATURE_AVX512F		    = ( 9*32+16); /* AVX-512 Foundation */
cpu_feature.X86_FEATURE_AVX512DQ		= ( 9*32+17); /* AVX-512 DQ (Double/Quad granular) Instructions */
cpu_feature.X86_FEATURE_RDSEED		    = ( 9*32+18); /* RDSEED instruction */
cpu_feature.X86_FEATURE_ADX			    = ( 9*32+19); /* ADCX and ADOX instructions */
cpu_feature.X86_FEATURE_SMAP		    = ( 9*32+20); /* Supervisor Mode Access Prevention */
cpu_feature.X86_FEATURE_AVX512IFMA		= ( 9*32+21); /* AVX-512 Integer Fused Multiply-Add instructions */
cpu_feature.X86_FEATURE_CLFLUSHOPT		= ( 9*32+23); /* CLFLUSHOPT instruction */
cpu_feature.X86_FEATURE_CLWB		    = ( 9*32+24); /* CLWB instruction */
cpu_feature.X86_FEATURE_INTEL_PT		= ( 9*32+25); /* Intel Processor Trace */
cpu_feature.X86_FEATURE_AVX512PF		= ( 9*32+26); /* AVX-512 Prefetch */
cpu_feature.X86_FEATURE_AVX512ER		= ( 9*32+27); /* AVX-512 Exponential and Reciprocal */
cpu_feature.X86_FEATURE_AVX512CD		= ( 9*32+28); /* AVX-512 Conflict Detection */
cpu_feature.X86_FEATURE_SHA_NI		    = ( 9*32+29); /* SHA1/SHA256 Instruction Extensions */
cpu_feature.X86_FEATURE_AVX512BW		= ( 9*32+30); /* AVX-512 BW (Byte/Word granular) Instructions */
cpu_feature.X86_FEATURE_AVX512VL = (9 * 32 + 31); /* AVX-512 VL (128/256 Vector Length) Extensions */

var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("cat /proc/cpuinfo | grep flags | tr '\\n' '~' | awk -F~ '{ printf " + '"["; for(i=1;i<=NF-1;++i) { split($i, line, ":"); x=split(line[2], vals, " "); printf "%s{", (i!=1?",":""); for(j=1;j<=x;++j) { printf "%s\\"%s\\": 1", (j!=1?",":""), vals[j];  } printf "}";  } printf "]"; }\'\nexit\n');
child.stderr.on('data', function (c) { });
child.waitExit();

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
    module.exports = null;
}

