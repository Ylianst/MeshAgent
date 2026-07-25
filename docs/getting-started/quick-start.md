# Quick Start

Get MeshAgent cloned, built, and connected to a management server in minutes.

---

## TL;DR — 5-Minute Setup

```bash
# 1. Clone the repository
git clone https://github.com/flamingo-stack/meshagent.git
cd meshagent

# 2. Install JavaScript dependencies (for tooling)
npm install

# 3. Build the native agent (Linux example)
make

# 4. Create a minimal .msh configuration
cat > meshagent.msh << 'EOF'
MeshServer=wss://your-server.example.com/agent.ashx
MeshID=your-mesh-id-here
MeshType=2
EOF

# 5. Run the agent
./meshagent
```

> **Note:** Replace `wss://your-server.example.com/agent.ashx` and `your-mesh-id-here` with the actual values from your MeshCentral or OpenFrame management server. Refer to your environment configuration for the correct credentials.

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/flamingo-stack/meshagent.git
cd meshagent
```

This downloads the full MeshAgent source, including:
- `meshcore/` — Agent core in C
- `microstack/` — Async networking stack in C
- `microscript/` — Duktape JavaScript engine bindings in C
- `modules/` — JavaScript automation modules
- `openssl-1.1.1f/` — Bundled OpenSSL cryptography headers
- `samples/` — WebRTC reference implementations

---

## Step 2: Install JavaScript Dependencies

```bash
npm install
```

This installs the AI-assisted development tooling. It is not required to build the native agent binary, but is recommended for contributing to the project.

---

## Step 3: Build the Native Agent

### Linux

```bash
make
```

The Makefile compiles the C sources, links against OpenSSL and zlib, and produces the `meshagent` binary.

### macOS

```bash
make
```

Ensure Xcode Command Line Tools are installed first (`xcode-select --install`).

### Windows

Open a **Developer Command Prompt** for Visual Studio, then:

```bash
nmake
```

Or open the appropriate `.sln` or `.vcxproj` file in Visual Studio and build from the IDE.

---

## Step 4: Configure the Agent

Create a `meshagent.msh` configuration file alongside the binary:

```text
MeshServer=wss://your-server.example.com/agent.ashx
MeshID=your-mesh-id-here
MeshType=2
```

| Key | Description |
|---|---|
| `MeshServer` | WebSocket URL of your management server |
| `MeshID` | Unique identifier for your mesh network group |
| `MeshType` | Agent type (typically `2` for managed agent) |

The agent also supports additional configuration keys written to its internal `SimpleDataStore` (`meshagent.db`):

| Key | Description |
|---|---|
| `disableUpdate` | Set to `1` to prevent auto-updates |
| `jsDebugPort` | Port for Duktape JavaScript debugger |
| `controlChannelIdleTimeout` | Seconds before idle channel is closed |
| `coreDumpEnabled` | Enable core dump on crash |

---

## Step 5: Run the Agent

```bash
./meshagent
```

On first run, the agent will:

1. Generate an RSA/EC key pair and self-signed certificate (stored in `meshagent.db`)
2. Connect to the management server via TLS WebSocket on port `16990`
3. Perform certificate-based mutual authentication
4. Register itself with the server and begin accepting commands

### Expected Output

```text
2024-11-01T12:00:00.000Z INFO Starting agent tool_id=meshcentral-agent
2024-11-01T12:00:00.100Z INFO Connecting to wss://your-server.example.com/agent.ashx
2024-11-01T12:00:00.500Z INFO WebSocket upgrade successful
2024-11-01T12:00:00.600Z INFO AuthVerify sent
2024-11-01T12:00:00.700Z INFO AuthConfirm received — agent online
```

---

## Running as a Service

### Linux (systemd)

MeshAgent includes service management utilities in `modules/service-manager.js`. The agent-installer module can register the binary as a system service:

```bash
./meshagent --install
```

This registers `meshagent` with systemd (or the appropriate init system detected at runtime — systemd, init.d, launchd, etc.).

### macOS (LaunchAgent)

The macOS KVM engine uses a LaunchAgent reverse-connection model. The installer creates the appropriate plist file in `~/Library/LaunchAgents/` or `/Library/LaunchDaemons/`.

### Windows (Service)

The Windows service host (`meshservice/`) registers MeshAgent as a Windows Service via the Service Control Manager.

---

## Verifying Connectivity

Once the agent is running, log into your MeshCentral or OpenFrame management server. The device should appear online in the device list within a few seconds.

You can also check the local log file:

```text
meshcentral-agent.log
```

Logs rotate automatically at 10 MB and are archived as `meshcentral-agent.log.old.gz`.

---

## Next Steps

After the agent is running, you may want to explore:

- The **First Steps** guide for common configuration tasks
- The **Architecture Overview** in the development section for design details
- WebRTC samples in `samples/webrtc/` for peer-to-peer connectivity examples
- The [OpenMSP Slack community](https://join.slack.com/t/openmsp/shared_invite/zt-36bl7mx0h-3~U2nFH6nqHqoTPXMaHEHA) for help and discussion
