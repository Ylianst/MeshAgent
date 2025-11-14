# MeshAgent Tests

This directory contains test utilities and verification tools for the MeshAgent project.

## Test Files

### `authtest.js`
Simple utility to extract X server authentication tokens on Linux systems.
- Parses the process list to find X server processes
- Extracts the `-auth` parameter value
- Useful for testing X11-related functionality

**Usage:**
```bash
./meshagent authtest.js
```

### `leaktest.js`
Interactive memory and resource leak testing tool for development and debugging.

**Features:**
- Tests various subsystems for memory/handle leaks
- Monitors Windows handle counts using kernel32.dll
- Tests IPC, child processes, web sockets, Windows dispatcher, WMI tasks, registry access, and user sessions
- Interactive command-line interface

**Usage:**
```bash
./meshagent leaktest.js
```

**Available Commands:**
- `dispatch` - Start Windows Dispatcher
- `wmi` - Use WMI to create Task (Windows)
- `ps` - Win-Virtual-Terminal test (Windows)
- `reg` - win-reg test (Windows)
- `user` - Windows User ID test
- `server` - Start IPC Server
- `client` - Start IPC Client
- `start` - Spawn Child Process
- `end` - Close spawned process
- `exit` - Exit Test

### `self-test.js`
Comprehensive self-test suite for MeshAgent functionality.

**Features:**
- Tests mesh protocol commands (authentication, core modules, updates, etc.)
- Validates agent functionality before deployment
- Embedded test data and resources
- Command definitions for mesh communication protocol

**Usage:**
```bash
./meshagent self-test.js [options]
```

### `update-test.js`
Agent self-update mechanism testing tool.

**Features:**
- Tests the self-update mechanism
- Simulates receiving agent binary updates
- Verifies update state transitions and binary transfer
- Tests update cycling between multiple agent sources
- Recovery core path handling

**Usage:**
```bash
./meshagent update-test.js [--RecoveryCore=path]
```

## Running Tests

All tests are designed to be run with the MeshAgent executable:

```bash
# On Windows
MeshService64.exe tests/testname.js

# On Linux
./meshagent_x86_64 tests/testname.js
```

## Contributing

When adding new tests:
1. Follow the existing code style and structure
2. Include appropriate copyright headers
3. Document usage and available options
4. Update this README with test descriptions
