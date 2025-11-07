# Claude AI Documentation

This folder contains comprehensive documentation designed for Claude AI to understand the MeshAgent project's internals and continue work across multiple sessions.

## Purpose

This documentation exists to prevent knowledge loss and avoid having to re-learn or reverse-engineer project internals. All documentation here is designed to be:

- **Self-contained** - Everything needed is in this folder
- **Committable** - Can be checked into the repository
- **Comprehensive** - Includes context, examples, and references
- **Discoverable** - Easy for new Claude sessions to navigate

## Current Projects

### Polyfills Regeneration System ✅ COMPLETED

**Status**: Byte-perfect regeneration achieved (MD5: `ce4bc256fa5d3d1eaab7a9dc2ee4ceb1`)

**Location**: [`Pollyfills/`](Pollyfills/)

**Summary**: Complete system for programmatically regenerating the `ILibDuktape_Polyfills.c` file from JavaScript source modules. Includes both the original Node.js tooling and a standalone Python implementation.

**Quick Links**:
- [Project Overview](Pollyfills/README.md)
- [Complete Technical Documentation](Pollyfills/Polyfills-Regeneration.md)
- [Quick Start Guide](Pollyfills/QUICK_START.md)
- [Working Scripts](Pollyfills/polyfills_generattion_reversengenering/)

## Documentation Standards

When creating new documentation in this folder:

1. **Assume zero context** - A new Claude session should be able to understand everything
2. **Include file paths** - Absolute paths from repo root
3. **Show exact commands** - Copy-pasteable examples with expected output
4. **Document the "why"** - Not just what, but why decisions were made
5. **Include verification steps** - How to confirm something works
6. **Cross-reference** - Link to related docs and source code

## For New Claude Sessions

If you're a new Claude session starting work on this project:

1. **Start here** - Read this README first
2. **Identify your task** - Check the project folders for relevant documentation
3. **Read the overview** - Each project has a README.md with context
4. **Use the detailed docs** - Dive into technical documentation as needed
5. **Check status** - Look for STATUS.md files to understand current state

## Structure

```
docs/claude/
├── README.md (this file)
└── Pollyfills/
    ├── README.md                           # Project overview and navigation
    ├── STATUS.md                           # Current status and achievements
    ├── QUICK_START.md                      # One-page quick reference
    ├── Polyfills-Regeneration.md          # Complete technical documentation
    ├── module-embedding-2021-workflow.md  # Historical context
    └── polyfills_generattion_reversengenering/
        ├── README.md                       # Working directory documentation
        ├── regenerate_polyfills_complete.py  # Main regeneration script
        ├── regenerate_polyfills.py         # Original partial script
        ├── extract_modules.py              # Module extraction script
        ├── compare_modules.py              # Module comparison script
        └── orig/                           # Test data and verification files
            ├── ILibDuktape_Polyfills.c    # Original C file (test copy)
            ├── modules/                    # Original source modules
            └── modules_expanded/           # Extracted modules
```

## Contributing Documentation

When adding new documentation:

1. Create a new subfolder for the project (e.g., `docs/claude/ProjectName/`)
2. Add a README.md with project overview
3. Create detailed technical documentation as needed
4. Update this file to list the new project
5. Include all working scripts and test data in the subfolder

## Maintenance

This documentation should be updated whenever:

- New features are added
- Bugs are fixed and the solution is non-obvious
- Build processes change
- New tools or workflows are discovered
- Questions arise that aren't answered in existing docs

---

**Last Updated**: 2025-11-07
**Maintained By**: Development team + Claude AI sessions
