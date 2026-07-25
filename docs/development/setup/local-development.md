# Local Development Guide

This guide covers cloning, building, running, and debugging MeshAgent on your local machine.

---

## Clone and Initial Setup

```bash
# Clone the repository
git clone https://github.com/flamingo-stack/meshagent.git
cd meshagent

# Install JavaScript tooling dependencies
npm install
```

The repository contains no submodule initialization needed — OpenSSL headers and libjpeg-turbo headers are bundled directly in the source tree.

---

## Building the Native Agent

### Linux

```bash
make
```

This compiles all C sources from `meshcore/`, `microstack/`, and `microscript/`, links them with system OpenSSL and zlib, and produces the `meshagent` binary in the project root.

#### Debug Build

```bash
CFLAGS="-g -O0 -DDEBUG" make clean && make
```

#### Verbose Build (see all compiler invocations)

```bash
make V=1
```

### macOS

```bash
make
```

Ensure Xcode Command Line Tools are installed:

```bash
xcode-select --install
```

The macOS build links against CoreGraphics and IOKit for KVM support.

#### macOS Code Signing (Development)

When developing the KVM engine on macOS, the binary needs to be signed to use CoreGraphics and receive TCC permissions. For local development, an ad-hoc signature is sufficient:

```bash
codesign --force --sign - ./meshagent
```

Grant Screen Recording and Accessibility permissions in **System Settings → Privacy & Security** to your signed binary.

### Windows

Open a **Developer Command Prompt for Visual Studio**, then:

```bash
nmake
```

Or build via the Visual Studio IDE using the solution file if present. The Windows build includes:
- `meshconsole/` — Console application
- `meshservice/` — Windows Service host
- `meshreset/` — Reset utility
- Windows KVM engine (GDI/DXGI, secure desktop)
- Windows cryptography (`wincrypto`)

---

## Running the Agent Locally

### Minimal Local Configuration

Create a `meshagent.msh` file for local development. Point it to a local or development management server:

```text
MeshServer=wss://dev-server.local/agent.ashx
MeshID=your-dev-mesh-id
MeshType=2
```

### Run the Agent

```bash
./meshagent
```

On first run, the agent auto-generates `meshagent.db` (identity store). Subsequent runs reuse the stored identity.

### Run with Verbose Logging

The JavaScript logging layer defaults to `INFO`. To see all debug output, set the log level before running scripts:

```javascript
const logger = require('./modules/logger');
logger.setLevel('DEBUG');
```

For the native C layer, build with `-DDEBUG` to enable additional print statements from the Microstack and Meshcore subsystems.

### Run Against a Local MeshCentral Server

For full end-to-end development, run a local MeshCentral server:

```bash
# Install MeshCentral (Node.js required)
npm install meshcentral

# Start MeshCentral
node node_modules/meshcentral
```

MeshCentral listens on port `4430` (HTTPS) by default. After creating a mesh group in the web UI, copy the `MeshServer` URL and `MeshID` into your `meshagent.msh`.

---

## Watching for Changes

MeshAgent is a compiled native binary — there is no hot-reload for C code. The standard development loop is:

```bash
# Edit C source files, then rebuild
make && ./meshagent
```

### Faster Incremental Builds

`make` only recompiles changed files (via dependency tracking in the Makefile). A typical incremental build after modifying a single `.c` file takes a few seconds.

### JavaScript Module Development

JavaScript modules in `modules/` are interpreted at runtime by the embedded Duktape engine. Changes to `.js` files take effect on the next agent restart — no recompile needed:

```bash
# Edit modules/logger.js, then restart the agent
./meshagent
```

For the `CoreModule.js` (the main agent JavaScript entrypoint), the agent loads and executes it fresh each time it reconnects to the server.

---

## Debug Configuration

### GDB (Linux)

```bash
# Build with debug symbols
CFLAGS="-g -O0" make clean && make

# Run under GDB
gdb ./meshagent
(gdb) run

# On crash, print stack trace
(gdb) bt

# Set a breakpoint by function name
(gdb) break MeshAgent_Start
(gdb) run
```

### LLDB (macOS)

```bash
lldb ./meshagent
(lldb) run
(lldb) bt all
(lldb) breakpoint set --name kvm_relay_setup
```

### Valgrind (Linux — memory leak detection)

```bash
valgrind --leak-check=full --track-origins=yes ./meshagent
```

> **Note:** Valgrind is slow. Use it for targeted memory safety investigations rather than routine runs.

### Duktape JavaScript Debugger

Enable the JavaScript debugger by setting the port in the agent data store:

Add to `meshagent.db` or pass via configuration:

```text
jsDebugPort=9090
```

The agent will listen on TCP port `9090` for a debugger connection. Connect with:
- The **Duktape Debugger** VS Code extension
- The `duk-debug` command-line tool
- Any Duktape debug protocol compatible client

---

## Verifying the Build

After a successful build:

```bash
# Check the binary exists and is executable
ls -la meshagent

# Check what it was built against (Linux)
ldd meshagent

# Check binary architecture
file meshagent

# Check it starts without crashing (no .msh file = exits cleanly)
./meshagent --help 2>&1 || true
```

---

## Common Build Issues

| Issue | Cause | Fix |
|---|---|---|
| `ssl.h: No such file or directory` | Missing OpenSSL dev headers | Install `libssl-dev` (Debian) or `openssl-devel` (RPM) |
| `undefined reference to X11*` | Missing X11 dev headers | Install `libx11-dev`, `libxtst-dev` |
| `undefined reference to gzopen` | Missing zlib | Install `zlib1g-dev` |
| `codesign: error` (macOS) | Missing Xcode tools | Run `xcode-select --install` |
| `CC: command not found` | No C compiler | Install `build-essential` or Xcode |

For additional help, join the [OpenMSP Slack](https://join.slack.com/t/openmsp/shared_invite/zt-36bl7mx0h-3~U2nFH6nqHqoTPXMaHEHA).

---

## Project Layout for Developers

```text
meshagent/
├── meshcore/agentcore.h       # MeshAgentHostContainer — the central agent state struct
├── meshcore/agentcore.c       # Agent lifecycle: Create, Start, Stop, Destroy
├── meshcore/meshdefines.h     # Protocol constants (port 16990, command opcodes)
├── microstack/ILibChain.*     # Reactor event loop (ILibChain) — the async core
├── microstack/ILibWebRTC.*    # WebRTC (ICE, DTLS, SCTP)
├── microscript/duktape.*      # Duktape JavaScript engine
├── modules/CoreModule.js      # Primary JavaScript entrypoint executed by the server
├── openframe/token_extractor.*# AES-256 token decryption for OpenFrame
└── package.json               # Node.js tooling dependencies
```
