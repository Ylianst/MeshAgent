# MeshAgent Code Samples

This directory contains code samples and examples demonstrating how to use various MeshAgent features and APIs.

## Directory Structure

### `snippets/`
JavaScript code samples demonstrating MeshAgent runtime features and module usage.

### `webrtc/`
WebRTC implementation samples in both C and C#, including rendezvous server examples and browser-based testing utilities.

## JavaScript Snippets

Located in `snippets/`, these examples demonstrate core MeshAgent functionality:

### `pwdtest.js`
Demonstrates secure password input from stdin.

**Features:**
- Disables console echo and canonical mode
- Implements password masking (displays `*` for each character)
- Proper backspace handling
- Cross-platform (Windows/Linux)

**Usage:**
```bash
# On Windows
MeshService64.exe samples/snippets/pwdtest.js

# On Linux
./meshagent_x86_64 samples/snippets/pwdtest.js
```

### `service-manager-test.js`
Shows how to interact with system services using the `service-manager` module.

**Features:**
- Get service information (location, working directory, start type)
- Check if service is running
- Platform-aware service management

**Usage:**
```bash
# On Windows
MeshService64.exe samples/snippets/service-manager-test.js "Mesh Agent"

# On Linux
./meshagent_x86_64 samples/snippets/service-manager-test.js meshagent
```

### `shelltest.js`
Demonstrates capturing stdout from child processes.

**Features:**
- Cross-platform child process spawning
- Stdout capture and handling
- Platform-specific command execution (cmd.exe on Windows, ls on Linux)

**Usage:**
```bash
# On Windows
MeshService64.exe samples/snippets/shelltest.js

# On Linux
./meshagent_x86_64 samples/snippets/shelltest.js
```

## WebRTC Samples

Located in `webrtc/`, these samples demonstrate WebRTC functionality for peer-to-peer communication.

### C Sample (`webrtc/C Sample/`)
Native C implementation of WebRTC functionality.

**Contents:**
- `WebRTC_MicroStackSample.c` - Main C sample implementation
- `SimpleRendezvousServer.c/h` - Rendezvous server for WebRTC signaling
- HTML test pages for browser-based testing
- Makefile and Visual Studio project files

**Build:**
```bash
cd samples/webrtc/C\ Sample
make
```

### C# Sample (`webrtc/C# Sample/`)
Windows Forms application demonstrating WebRTC in C#.

**Contents:**
- Full Windows Forms UI (`MainForm.cs`, `SessionForm.cs`, etc.)
- `WebRTC.cs` - Core WebRTC wrapper/implementation
- `SimpleRendezvousServer.cs` - Rendezvous server implementation
- Visual Studio solution and project files

**Build:**
Open `WebRTC CSharp Sample.sln` in Visual Studio and build.

### HTML Test Pages
Both C and C# samples include HTML test pages for browser-based WebRTC testing:
- `webrtcsample.html` - Active WebRTC peer example
- `webrtcpassivesample.html` - Passive WebRTC peer example
- `websocketsample.html` - WebSocket testing (C sample only)

## Contributing

When adding new samples:
1. Include appropriate copyright headers
2. Add inline comments explaining key concepts
3. Provide usage examples
4. Update this README with sample descriptions
5. Ensure cross-platform compatibility where applicable

## License

Copyright 2022 Intel Corporation

Licensed under the Apache License, Version 2.0. See the LICENSE file in the project root for details.
