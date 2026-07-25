# Development Documentation

Welcome to the MeshAgent development documentation. This section covers everything you need to contribute to or build on top of MeshAgent — from environment setup to architecture deep-dives, security practices, testing, and contribution guidelines.

---

## What You'll Find Here

| Document | Description |
|---|---|
| [Environment Setup](setup/environment.md) | IDE recommendations, editor configuration, required tools, and environment variables |
| [Local Development](setup/local-development.md) | Clone, build, run locally, hot reload, and debug configuration |
| [Architecture Overview](architecture/README.md) | High-level architecture diagrams, core components, and key design decisions |
| [Security Guidelines](security/README.md) | Auth patterns, cryptography, input validation, secrets management, and security testing |
| [Testing Overview](testing/README.md) | Test structure, running tests, writing new tests, and coverage |
| [Contributing Guidelines](contributing/guidelines.md) | Code style, branch naming, commit format, and PR review process |

---

## Technology Stack

MeshAgent is primarily a **native C/C++ project** with an embedded JavaScript scripting layer:

| Layer | Technology | Purpose |
|---|---|---|
| Agent core | C | Event-driven reactor, control channel, KVM, self-update |
| Networking | C (Microstack) | Async TCP/UDP, HTTP, WebSocket, WebRTC (ICE/DTLS/SCTP) |
| Scripting | C + JavaScript (Duktape) | Sandboxed automation engine, Node.js-like JS APIs |
| Cryptography | C (OpenSSL 1.1.1f / 3.x) | TLS, X.509 certificates, RSA/EC, HMAC, AES |
| KVM engines | C | Platform-specific screen capture and input injection |
| Agent modules | JavaScript | Cross-platform automation, installers, utilities |
| Build tooling | Node.js + npm | AI-assisted documentation and analysis tooling |

---

## Quick Navigation

### Getting Started with Development

1. Follow the [Environment Setup](setup/environment.md) guide to configure your IDE and tools
2. Follow the [Local Development](setup/local-development.md) guide to build and run the agent locally
3. Read the [Architecture Overview](architecture/README.md) to understand the codebase structure

### Contributing

1. Read the [Contributing Guidelines](contributing/guidelines.md) for code style and PR process
2. Review the [Security Guidelines](security/README.md) before touching crypto or auth code
3. Run the [Test Suite](testing/README.md) before submitting a pull request

---

## Repository Structure

```text
meshagent/
├── meshcore/          # Agent core (C) — control channel, KVM, auth
│   ├── KVM/
│   │   ├── Linux/     # X11/XShm screen capture and input
│   │   ├── MacOS/     # CoreGraphics capture, TCC handling
│   │   └── Windows/   # GDI/DXGI capture, secure desktop
│   └── MacOS/         # macOS-specific utilities
├── microstack/        # Async networking stack (C)
├── microscript/       # Duktape JS engine bindings (C)
├── modules/           # JavaScript automation modules
├── openframe/         # OpenFrame/Flamingo integration (C)
├── openssl-1.1.1f/   # Pinned OpenSSL 1.1.1f headers
├── openssl/           # OpenSSL 3.x interface headers
├── lib-jpeg-turbo/   # TurboJPEG compression headers
├── meshconsole/       # Console application (Windows)
├── meshservice/       # Windows service host
├── meshreset/         # Reset utility
├── samples/           # WebRTC C and C# reference samples
├── tests/             # Self-test and diagnostic scripts
├── scripts/           # Build/post-build utilities
└── package.json       # Node.js tooling dependencies
```

---

## Community

Development questions and discussions happen in the **OpenMSP Slack community**:

- **Join Slack:** [https://www.openmsp.ai/](https://www.openmsp.ai/)
- **Invite link:** [https://join.slack.com/t/openmsp/shared_invite/zt-36bl7mx0h-3~U2nFH6nqHqoTPXMaHEHA](https://join.slack.com/t/openmsp/shared_invite/zt-36bl7mx0h-3~U2nFH6nqHqoTPXMaHEHA)

All support, bug reports, and feature discussions are managed via Slack — not GitHub Issues.
