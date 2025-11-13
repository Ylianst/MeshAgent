# Polyfills Update Demonstration

This directory contains a simple demonstration script that shows how MeshAgent's `-exec` command is used to regenerate `ILibDuktape_Polyfills.c` from JavaScript modules.

## Purpose

**This is for educational/demonstration purposes only.**

For actual development work, use the full development workflow:
```bash
sudo ./bin/test-macos-meshagent.sh
```

## What This Demonstrates

The `Polyfills_update.sh` script shows the core mechanism of how JavaScript modules are compiled into the MeshAgent binary:

1. **JavaScript modules** (in `modules/`) contain the agent's functionality
2. The **meshagent binary** can execute JavaScript code via the `-exec` command
3. The **code-utils module** (embedded in meshagent) shrinks all JS modules into a single C file
4. This **ILibDuktape_Polyfills.c** file is then compiled into the next build of the binary

## Usage

```bash
# Run from anywhere - script will find repo root
./tools/scripts/Polyfills_update/Polyfills_update.sh
```

## What It Does

1. Creates `tools/test_ILibDuktape_Polyfills/modules_expanded/` directory
2. Copies all `*.js` files from `modules/` to the expanded directory
3. Runs meshagent with `-exec` to generate the polyfills C file:
   ```bash
   meshagent -exec "require('code-utils').shrink({
       expandedPath: './tools/test_ILibDuktape_Polyfills/modules_expanded',
       filePath: './tools/test_ILibDuktape_Polyfills/ILibDuktape_Polyfills.c'
   });process.exit();"
   ```

## Output

The generated file will be in:
```
tools/test_ILibDuktape_Polyfills/ILibDuktape_Polyfills.c
```

This is a **test output** directory. The actual production polyfills are at:
```
microscript/ILibDuktape_Polyfills.c
```

## Requirements

- A meshagent binary must exist at: `tools/meshagent/macos/meshagent`
- This is a minimal build of meshagent that contains the `code-utils` module

## The Full Development Workflow

For actual development, you should use:

```bash
# Full workflow: regenerate polyfills, build, sign, and deploy
sudo ./bin/test-macos-meshagent.sh
```

That script:
1. Regenerates polyfills from `modules/` → `microscript/ILibDuktape_Polyfills.c`
2. Builds the meshagent binary
3. Signs the binary (if configured)
4. Deploys to the system
5. Manages LaunchDaemon/LaunchAgent services

See `bin/test-macos-meshagent.sh --help` for all options.

## Understanding the Flow

```
modules/*.js (JavaScript source)
    ↓
    [Copy to modules_expanded/]
    ↓
meshagent -exec "require('code-utils').shrink(...)"
    ↓
ILibDuktape_Polyfills.c (C file with embedded JS)
    ↓
    [Compile with make]
    ↓
meshagent binary (contains all modules)
```

The binary can then execute the embedded JavaScript without needing external `.js` files!

## Why This Matters

- **Single binary deployment**: No need to distribute separate `.js` files
- **Security**: JavaScript code is embedded in the binary
- **Performance**: Modules are pre-parsed and ready to execute
- **Simplicity**: Just one file to deploy, sign, and notarize
