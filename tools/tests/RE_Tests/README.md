# Reverse Engineering (RE) Tests

This directory contains proof-of-concept (PoC) tests used during the reverse engineering process to understand how MeshAgent embeds and loads JavaScript modules.

## Purpose

These tests were created to:
- Understand the module embedding mechanism in MeshAgent
- Reverse engineer how `ILibDuktape_Polyfills.c` is generated from JavaScript modules
- Validate the `-import` and `-exec` functionality
- Document the polyfills generation workflow for future development

## Contents

### Polyfills_RE/

Contains reverse engineering tests and proof-of-concept implementations:

- **`meshagent_IMPORT_TESTS/`** - Tests for the `-import` functionality that extracts embedded modules from compiled binaries
- **`polyfills_generattion_reversengenering/`** - Analysis and tests of how polyfills are generated from source modules

## Documentation

**For comprehensive documentation on the polyfills system, see:**

📖 **[docs/claude/Pollyfills/](../../docs/claude/Pollyfills/)**

That directory contains:
- **README.md** - Overview of the polyfills system
- **QUICK_START.md** - Quick reference for working with polyfills
- **Polyfills-Regeneration.md** - Detailed regeneration workflow
- **module-embedding-2021-workflow.md** - Historical context and workflow
- **STATUS.md** - Current implementation status

## What Are Polyfills?

In MeshAgent context, "polyfills" refers to the mechanism that embeds all JavaScript modules into the binary as C code (`ILibDuktape_Polyfills.c`). This allows:
- Single-binary deployment without external `.js` files
- Embedded modules are pre-parsed and ready to execute
- Security through code embedding in compiled binary

## Workflow Summary

```
JavaScript modules (modules/*.js)
    ↓
code-utils.shrink() via meshagent -exec
    ↓
ILibDuktape_Polyfills.c (C file with embedded JS)
    ↓
Compiled into meshagent binary
    ↓
Modules accessible via require('module-name')
```

## Test Usage

**⚠️ Note:** These are proof-of-concept tests for research/understanding purposes, not production code.

For actual development:
- Use the production workflow documented in `docs/claude/Pollyfills/`
- Use `bin/test-macos-meshagent.sh` for building with polyfill regeneration
- Use `tools/scripts/Polyfills_update/` for demonstration scripts

## Related Tools

- **Polyfills Update Script:** `tools/scripts/Polyfills_update/Polyfills_update.sh`
- **Development Build Script:** `bin/test-macos-meshagent.sh`
- **Database Dump Tools:** `tools/scripts/meshagentDB_dump/`

## See Also

- Main polyfills documentation: `docs/claude/Pollyfills/README.md`
- Quick start guide: `docs/claude/Pollyfills/QUICK_START.md`
- Regeneration workflow: `docs/claude/Pollyfills/Polyfills-Regeneration.md`
