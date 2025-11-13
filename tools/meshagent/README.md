# MeshAgent Binaries for Polyfill Generation

This directory contains minimal MeshAgent binaries used to regenerate `ILibDuktape_Polyfills.c` before building/compiling the full agent.

## Purpose

These binaries are **NOT** the final build output. Instead, they are pre-built minimal agents used as tools in the build process to:

1. Read JavaScript modules from `modules/` or `modules_expanded/`
2. Process and shrink them using the `code-utils` module
3. Generate/update the `microscript/ILibDuktape_Polyfills.c` file

## Usage

The polyfill generation is typically done via:

```bash
./tools/meshagent/macos/meshagent -exec "require('code-utils').shrink({expandedPath: './modules_expanded', filePath: './microscript/ILibDuktape_Polyfills.c'});process.exit();"
```

This step must be completed **before** running `make` to build the final meshagent binary.

## Build Workflow

1. **Polyfill Generation** (uses these binaries)
   - Copy modules from `modules/` to `modules_expanded/`
   - Run the command above to update `ILibDuktape_Polyfills.c`

2. **Compilation** (creates final binary)
   - Run `make macos ARCHID=<archid>` to build the final agent
   - Output: `build/macos/<arch>/meshagent`

## Directory Structure

```
tools/meshagent/
├── README.md          # This file
├── linux/             # Linux binaries for polyfill generation
├── macos/             # macOS binaries for polyfill generation
└── windows/           # Windows binaries for polyfill generation
```

## Note

These are minimal binaries with just enough functionality to run the `code-utils.shrink()` function. They are version-controlled and updated separately from the main build process.
