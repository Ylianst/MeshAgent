# MeshAgent Documentation

Welcome to the MeshAgent documentation. MeshAgent is a cross-platform, high-performance remote management agent written in native C/C++ that powers the [Flamingo](https://flamingo.run) / [OpenFrame](https://openframe.ai) platform and MeshCentral-compatible infrastructures.

---

## 📚 Table of Contents

- [Getting Started](#-getting-started)
- [Development](#-development)
- [Reference Architecture](#-reference-architecture)
- [Architecture Diagrams](#-architecture-diagrams)
- [Quick Links](#-quick-links)

---

## 🚀 Getting Started

New to MeshAgent? Start here to understand the platform and get an agent running.

| Guide | Description |
|---|---|
| [Introduction](./getting-started/introduction.md) | What MeshAgent is, key features, and how it fits the OpenFrame ecosystem |
| [Prerequisites](./getting-started/prerequisites.md) | System requirements, build toolchain, and networking prerequisites by platform |
| [Quick Start](./getting-started/quick-start.md) | Clone, build, configure, and run MeshAgent in minutes |
| [First Steps](./getting-started/first-steps.md) | Verify agent identity, configure logging, explore JavaScript modules, and manage self-updates |

---

## 🛠 Development

Guides for contributors and integrators building on or extending MeshAgent.

| Guide | Description |
|---|---|
| [Development Overview](./development/README.md) | Technology stack, repository structure, and navigation for contributors |
| [Environment Setup](./development/setup/environment.md) | IDE recommendations, editor configuration, required tools, and environment variables |
| [Local Development](./development/setup/local-development.md) | Clone, build, debug, and run the agent locally across all platforms |
| [Architecture Overview](./development/architecture/README.md) | High-level architecture diagrams, core components, lifecycle, and key design decisions |

---

## 📖 Reference Architecture

Deep-dive technical reference documentation for each major module, generated from CodeWiki source analysis.

### Core Agent

| Reference | Description |
|---|---|
| [MeshAgent Overview](./reference/architecture/README.md) | End-to-end architecture, module map, and design principles |
| [Meshcore Agent](./reference/architecture/meshcore-agent/meshcore-agent.md) | Orchestrator — control channel, Duktape hosting, auth, KVM routing, self-update |

### Networking Stack

| Reference | Description |
|---|---|
| [Microstack Core](./reference/architecture/microstack-core/microstack-core.md) | ILibChain reactor, async sockets, HTTP, WebSocket, WebRTC |
| [Async Sockets](./reference/architecture/microstack-core/Async%20Sockets.md) | Non-blocking TCP client, server, and UDP socket abstractions |
| [Web Client and Server](./reference/architecture/microstack-core/Web%20Client%20and%20Server.md) | HTTP/1.1 client and server with WebSocket and Digest authentication |
| [WebRTC](./reference/architecture/microstack-core/WebRTC.md) | Full WebRTC stack: ICE, STUN, TURN, DTLS, and SCTP data channels |
| [Cryptography](./reference/architecture/microstack-core/Cryptography.md) | TLS, certificate management, hashing, and no-SSL fallback primitives |
| [Data Store](./reference/architecture/microstack-core/Data%20Store.md) | Persistent key-value store with SHA-384 integrity verification |
| [Remote Logging](./reference/architecture/microstack-core/Remote%20Logging.md) | Structured, verbosity-controlled remote logging over WebSocket |
| [Process Pipe](./reference/architecture/microstack-core/Process%20Pipe.md) | Cross-platform child process spawning and pipe I/O |
| [Parsers and Chain](./reference/architecture/microstack-core/Parsers%20and%20Chain.md) | Core event loop, data structures, HTTP/XML parsing, and memory management |

### Remote Desktop (KVM)

| Reference | Description |
|---|---|
| [KVM Linux](./reference/architecture/meshcore-kvm-linux/meshcore-kvm-linux.md) | X11/XShm capture, tile encoding, XTest input injection, process isolation |
| [KVM macOS](./reference/architecture/meshcore-kvm-macos/meshcore-kvm-macos.md) | CoreGraphics capture, LaunchAgent model, TCC permission handling |
| [KVM Windows](./reference/architecture/meshcore-kvm-windows/meshcore-kvm-windows.md) | GDI/DXGI capture, multi-monitor, secure desktop, touch injection |

### Cryptography

| Reference | Description |
|---|---|
| [OpenSSL Core](./reference/architecture/openssl-core/openssl-core.md) | OpenSSL 1.1.1f — TLS/SSL, X.509, ASN.1, RSA/EC/DH, AES, CMS |
| [OpenSSL Include](./reference/architecture/openssl-include/openssl-include.md) | OpenSSL 3.x header interface — provider architecture, EVP_KDF, EVP_MAC |
| [TLS and SSL](./reference/architecture/openssl-core/TLS%20and%20SSL.md) | TLS/SSL session management |
| [X.509 and Certificate Management](./reference/architecture/openssl-core/X.509%20and%20Certificate%20Management.md) | Certificate lifecycle, validation, and storage |
| [Public Key Infrastructure](./reference/architecture/openssl-core/Public%20Key%20Infrastructure.md) | RSA, EC, DH key operations |
| [Digest and MAC](./reference/architecture/openssl-core/Digest%20and%20MAC.md) | Hashing and message authentication |
| [Symmetric Ciphers](./reference/architecture/openssl-core/Symmetric%20Ciphers.md) | AES and symmetric encryption |
| [ASN.1 Engine](./reference/architecture/openssl-core/ASN.1%20Engine.md) | DER/BER encoding and decoding |
| [BIO and IO](./reference/architecture/openssl-core/BIO%20and%20IO.md) | OpenSSL I/O abstraction layer |
| [Type System](./reference/architecture/openssl-core/Type%20System.md) | OpenSSL type definitions and object model |

### Compression

| Reference | Description |
|---|---|
| [Jpeg Turbo Core](./reference/architecture/jpeg-turbo-core/jpeg-turbo-core.md) | High-performance JPEG tile compression for screen streaming |

### WebRTC Samples

| Reference | Description |
|---|---|
| [WebRTC Samples](./reference/architecture/samples-webrtc/samples-webrtc.md) | C rendezvous server, native Microstack console, and C# WinForms samples |

---

## 🗂 Architecture Diagrams

Visual Mermaid diagrams generated from source analysis are available in the `docs/diagrams/architecture/` directory. Key diagrams include:

| Diagram | Path |
|---|---|
| Meshcore Agent | `docs/diagrams/architecture/meshcore-agent.mmd` |
| Microstack Core | `docs/diagrams/architecture/microstack-core.mmd` |
| WebRTC Stack | `docs/diagrams/architecture/webrtc.mmd` |
| Async Sockets | `docs/diagrams/architecture/async_sockets.mmd` |
| TLS and SSL | `docs/diagrams/architecture/tls_and_ssl.mmd` |
| X.509 Certificates | `docs/diagrams/architecture/x509_and_certificate_management.mmd` |
| Public Key Infrastructure | `docs/diagrams/architecture/public_key_infrastructure.mmd` |
| Cryptography | `docs/diagrams/architecture/cryptography.mmd` |
| Web Client and Server | `docs/diagrams/architecture/web_client_and_server.mmd` |
| Data Store | `docs/diagrams/architecture/data_store.mmd` |
| Process Pipe | `docs/diagrams/architecture/process_pipe.mmd` |
| KVM Linux | `docs/diagrams/architecture/meshcore-kvm-linux.mmd` |
| KVM macOS | `docs/diagrams/architecture/meshcore-kvm-macos.mmd` |
| KVM Windows | `docs/diagrams/architecture/meshcore-kvm-windows.mmd` |
| Jpeg Turbo Core | `docs/diagrams/architecture/jpeg-turbo-core.mmd` |
| WebRTC Samples | `docs/diagrams/architecture/samples-webrtc.mmd` |

Diagrams can be rendered in any Mermaid-compatible viewer (GitHub, VS Code Mermaid extension, mermaid.live).

---

## 🔗 Quick Links

| Resource | Link |
|---|---|
| Project README | [../README.md](../README.md) |
| Contributing Guide | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| OpenMSP Slack Community | [https://www.openmsp.ai/](https://www.openmsp.ai/) |
| Flamingo Platform | [https://flamingo.run](https://flamingo.run) |
| OpenFrame | [https://openframe.ai](https://openframe.ai) |
| Source Repository | [https://github.com/flamingo-stack/meshagent](https://github.com/flamingo-stack/meshagent) |

---

*Documentation generated by [🦩 Flamingo AI Technical Writer](https://flamingo.run)*
