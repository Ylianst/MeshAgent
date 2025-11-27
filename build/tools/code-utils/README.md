# Code-Utils MeshAgent Binaries

This directory stores minimal MeshAgent binaries used to regenerate `ILibDuktape_Polyfills.c` before building/compiling the full agent.

> **📖 For detailed documentation on building and using code-utils binaries, see:**
> **[`/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/README.md`](/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/README.md)**

## Quick Reference

### What Are Code-Utils Binaries?

Code-utils binaries are **minimal** MeshAgent builds containing only 8 essential modules needed for polyfill generation:
- `_agentNodeId.js`, `_agentStatus.js`, `AgentHashTool.js`
- `code-utils.js`, `daemon.js`, `identifiers.js`
- `promise.js`, `util-agentlog.js`

**Key Features:**
- KVM=0 (no remote desktop)
- 8 modules instead of 50
- Smaller binary size
- Purpose: Polyfill generation **only**

### Build Code-Utils Binary

```bash
cd /Users/peet/GitHub/MeshAgent_installer
sudo ./build/tools/macos_build/macos-build_with_test.sh --code-utils --skip-sign --skip-notary
```

### Store for Reuse

After building, copy to this directory for version control and reuse:

```bash
# macOS
cp build/output/meshagent_code-utils_osx-universal-64 build/tools/code-utils/macos/meshagent_code-utils
```

### Use Code-Utils Binary

The build script automatically uses the binary stored at:
```
build/tools/code-utils/macos/meshagent_code-utils
```

When polyfill regeneration is enabled (default), it runs:
```bash
./build/tools/code-utils/macos/meshagent_code-utils -import \
  --expandedPath="./modules_macos" \
  --filePath="./microscript/ILibDuktape_Polyfills.c"
```

## Directory Structure

```
build/tools/code-utils/
├── README.md                      # This file
├── macos/
│   └── meshagent_code-utils       # Universal macOS code-utils binary
├── linux/                         # Linux code-utils binaries (future)
└── windows/                       # Windows code-utils binaries (future)
```

## Module Comparison

| Build Type | Modules | KVM | Size | Purpose |
|------------|---------|-----|------|---------|
| **Code-Utils** | 8 | No | Small | Polyfill generation |
| **Full Build** | 50 | Yes | Large | Production deployment |

## See Also

- **Main Documentation:** [`build/tools/macos_build/README.md`](/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/README.md)
- **Build Script:** [`build/tools/macos_build/macos-build_with_test.sh`](/Users/peet/GitHub/MeshAgent_installer/build/tools/macos_build/macos-build_with_test.sh)
- **Module Lists:**
  - Minimal: [`modules/.modules_macos_minimal`](/Users/peet/GitHub/MeshAgent_installer/modules/.modules_macos_minimal) (8 modules)
  - Full: [`modules/.modules_macos`](/Users/peet/GitHub/MeshAgent_installer/modules/.modules_macos) (50 modules)
