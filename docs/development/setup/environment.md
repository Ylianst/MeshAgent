# Development Environment Setup

This guide covers the recommended IDEs, editor configuration, required development tools, and environment variables for contributing to MeshAgent.

---

## Recommended IDEs and Editors

### Visual Studio Code (Recommended for all platforms)

VS Code works well for both the C/C++ native code and the JavaScript modules.

**Recommended extensions:**

| Extension | Publisher | Purpose |
|---|---|---|
| C/C++ | Microsoft | IntelliSense, debugging, code navigation for C/C++ |
| C/C++ Extension Pack | Microsoft | CMake, themes, and full C/C++ suite |
| clangd | LLVM | Fast code completion and diagnostics |
| EditorConfig for VS Code | EditorConfig | Consistent formatting across contributors |
| GitLens | GitKraken | Enhanced Git history and blame |
| ESLint | Microsoft | JavaScript linting |

**Workspace settings** (`.vscode/settings.json`):

```json
{
  "editor.formatOnSave": false,
  "editor.tabSize": 4,
  "editor.insertSpaces": true,
  "C_Cpp.intelliSenseEngine": "default",
  "files.associations": {
    "*.h": "c",
    "*.c": "c"
  }
}
```

### Visual Studio (Windows)

For Windows-native development, Visual Studio 2019 or 2022 provides the full MSVC toolchain along with built-in debugger support for the Windows KVM engine (GDI/DXGI), Windows service host (`meshservice/`), and Windows cryptography (`wincrypto`).

### Xcode (macOS)

For macOS KVM development involving CoreGraphics, TCC permission handling, and LaunchAgent integration, Xcode provides the best debugging experience for system-level APIs.

---

## Required Development Tools

### C/C++ Development

| Tool | Version | Installation |
|---|---|---|
| `gcc` or `clang` | 7.0+ | System package manager (see Prerequisites) |
| `make` | 4.0+ | System package manager |
| `gdb` or `lldb` | Any | GNU Debugger (`gdb`) for Linux, `lldb` for macOS |
| `valgrind` | 3.x+ | Memory leak detection (Linux) |
| `strace` / `dtrace` | Any | System call tracing |

### JavaScript / Node.js Tooling

| Tool | Version | Installation |
|---|---|---|
| Node.js | 18+ | https://nodejs.org or via `nvm` |
| npm | 9+ | Included with Node.js |

Install Node.js via `nvm` (recommended for managing versions):

```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Reload shell, then install Node.js 18
nvm install 18
nvm use 18

# Verify
node --version
npm --version
```

### OpenSSL Development Headers

The MeshAgent bundles OpenSSL 1.1.1f headers in `openssl-1.1.1f/`, but system OpenSSL headers are also referenced. Install development headers:

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS (via Homebrew)
brew install openssl

# Red Hat / Fedora
sudo dnf install openssl-devel
```

---

## Environment Variables

The following environment variables influence the build and runtime behavior of MeshAgent.

### Build-time Variables

| Variable | Description | Example |
|---|---|---|
| `CC` | C compiler override | `CC=clang make` |
| `CXX` | C++ compiler override | `CXX=clang++ make` |
| `CFLAGS` | Additional C compiler flags | `CFLAGS="-g -O0"` for debug builds |
| `LDFLAGS` | Additional linker flags | `LDFLAGS="-L/usr/local/lib"` |
| `OPENSSL_DIR` | Override OpenSSL installation path | `/usr/local/opt/openssl` |

Build with debug symbols and no optimization:

```bash
CFLAGS="-g -O0" make
```

### Runtime Variables

| Variable | Description |
|---|---|
| `MESH_AGENT_PORT` | Override default agent port (default: `16990`) |
| `MESH_DEBUG` | Enable additional runtime debug output when set |

### OpenFrame Integration

| Variable | Description |
|---|---|
| `OPENFRAME_TOKEN_PATH` | Path to the AES-256 encrypted token file (default: `/etc/openframe/token.txt`) |
| `OPENFRAME_SECRET` | 32-byte AES-256 key for token decryption |

> **Security Note:** Never commit `OPENFRAME_SECRET` or any decryption keys to source control. Use your environment's secrets manager.

---

## Editor Configuration for C Code Style

MeshAgent follows a consistent C code style. Create or reference a `.editorconfig` at the project root:

```text
root = true

[*.{c,h}]
indent_style = space
indent_size = 4
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[*.js]
indent_style = space
indent_size = 4
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[Makefile]
indent_style = tab
```

---

## Setting Up the Debugger

### GDB (Linux)

Build with debug symbols:

```bash
CFLAGS="-g -O0" make
```

Launch under GDB:

```bash
gdb ./meshagent
(gdb) run
(gdb) bt       # backtrace on crash
(gdb) info locals
```

Attach to a running agent process:

```bash
gdb -p $(pidof meshagent)
```

### LLDB (macOS)

```bash
lldb ./meshagent
(lldb) run
(lldb) bt      # backtrace
(lldb) frame variable
```

### JavaScript Debugger (Duktape)

The embedded Duktape engine supports remote debugging via a TCP socket. Enable it by setting `jsDebugPort` in the agent's data store:

```text
jsDebugPort=9090
```

Connect with a Duktape-compatible debugger client on `localhost:9090`. The VS Code **Duktape Debugger** extension (`HaroldBrenes.duk-debug`) can attach to this port.

---

## Verifying Your Development Setup

```bash
# Verify C compiler
gcc --version || clang --version

# Verify make
make --version

# Verify Node.js
node --version && npm --version

# Verify OpenSSL headers present
ls /usr/include/openssl/ssl.h 2>/dev/null || \
  ls /usr/local/opt/openssl/include/openssl/ssl.h 2>/dev/null && \
  echo "OpenSSL headers found"

# Verify repository clone is complete
ls meshcore/agentcore.h microstack/ILibAsyncSocket.h microscript/duktape.h
```

All commands should complete without errors before beginning development.

---

## Community and Support

For environment setup issues, reach out in the **OpenMSP Slack**:

- [https://www.openmsp.ai/](https://www.openmsp.ai/)
- [Join Slack](https://join.slack.com/t/openmsp/shared_invite/zt-36bl7mx0h-3~U2nFH6nqHqoTPXMaHEHA)
