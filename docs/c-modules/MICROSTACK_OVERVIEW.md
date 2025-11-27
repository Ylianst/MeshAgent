# MicroStack - Core Networking Layer

**35,692 lines** of cross-platform C networking code providing async I/O, HTTP, WebRTC, and utility functions for MeshAgent.

## Architecture

MicroStack is a single-threaded, event-driven networking stack that powers all MeshAgent communication. Originally from Intel's MicroStack project, it provides:

- **Async I/O:** Non-blocking TCP/UDP sockets
- **HTTP:** Client and server implementations
- **WebRTC:** Data channel support
- **Utilities:** Parsers, crypto, logging

## Core Components

### ILibParsers.c (11,485 lines)
**Purpose:** Core event loop and parsing utilities

**Key Functions:**
- `ILibCreateChain()` - Create event loop
- `ILibStartChain()` - Start event processing
- `ILibStopChain()` - Graceful shutdown
- HTTP/XML/URI parsing utilities

**Why Large:** Contains the entire event loop, packet parsers, string utilities, and HTTP protocol implementation.

---

### ILibAsyncSocket.c (TCP Client)
**Purpose:** Asynchronous TCP client connections

**Key Functions:**
- `ILibAsyncSocket_Connect()` - Non-blocking connect
- `ILibAsyncSocket_Send()` - Async send with buffering
- `OnData/OnConnect/OnDisconnect` callbacks

**Use Case:** MeshAgent server connections

---

### ILibAsyncServerSocket.c (TCP Server)
**Purpose:** Asynchronous TCP server (listening socket)

**Key Functions:**
- `ILibCreateAsyncServerSocketModule()` - Create listener
- `OnConnection` callback - Accept new clients

**Use Case:** Local KVM socket server (macOS)

---

### ILibAsyncUDPSocket.c (UDP)
**Purpose:** Asynchronous UDP sockets

**Key Functions:**
- `ILibAsyncUDPSocket_SendTo()` - Non-blocking UDP send
- `OnData` callback - Receive packets

**Use Case:** STUN/discovery, peer-to-peer

---

### ILibMulticastSocket.c
**Purpose:** UDP multicast/broadcast

**Key Functions:**
- `ILibMulticastSocket_Create()` - Join multicast group
- Broadcast discovery packets

**Use Case:** LAN discovery protocols

---

### ILibIPAddressMonitor.c
**Purpose:** Network interface change detection

**Key Functions:**
- `ILibIPAddressMonitor_Create()` - Monitor network changes
- `OnInterfaceChange` callback - Network state updates

**Use Case:** Reconnect when network changes

---

### ILibWebServer.c (HTTP Server)
**Purpose:** Lightweight HTTP/1.1 server

**Key Functions:**
- `ILibWebServer_Create()` - Create HTTP server
- `OnSession` callback - Handle HTTP requests
- `ILibWebServer_Send()` - Send HTTP responses

**Use Case:** Local web UI, REST APIs

---

### ILibWebClient.c (HTTP Client)
**Purpose:** Lightweight HTTP/1.1 client

**Key Functions:**
- `ILibWebClient_PipelineRequest()` - HTTP GET/POST
- `OnResponse` callback - Handle responses

**Use Case:** MeshServer API calls, updates

---

### ILibWebRTC.c (7,400+ lines)
**Purpose:** WebRTC data channel implementation

**Key Functions:**
- `ILibWrapper_WebRTC_CreateConnection()` - Create peer connection
- `ILibWrapper_WebRTC_DataChannel_Send()` - Send data
- STUN/TURN/ICE protocol implementation

**Use Case:** Peer-to-peer agent connections

**Why Large:** Full WebRTC stack (ICE, DTLS, SCTP)

---

### ILibWrapperWebRTC.c
**Purpose:** Object-oriented WebRTC wrapper

**Key Functions:**
- Higher-level API over ILibWebRTC.c
- Connection management
- Data channel abstraction

---

### ILibCrypto.c
**Purpose:** Platform-agnostic cryptography wrapper

**Key Functions:**
- `util_md5()`, `util_sha1()`, `util_sha256()` - Hashing
- `util_encrypt()`, `util_decrypt()` - AES encryption
- Certificate validation helpers

**Backend:** Uses OpenSSL or Apple Security.framework

---

### ILibProcessPipe.c
**Purpose:** Child process spawning and IPC

**Key Functions:**
- `ILibProcessPipe_Spawn()` - Execute child process
- `OnData` callback - Read child stdout/stderr
- `ILibProcessPipe_Send()` - Write to child stdin

**Use Case:** Spawn helper processes (deprecated for macOS KVM)

---

### ILibRemoteLogging.c
**Purpose:** Web-based logging for native components

**Key Functions:**
- `ILibRemoteLogging_printf()` - Log to web console
- HTTP server for viewing logs in browser

**Use Case:** Development/debugging

---

### ILibSimpleDataStore.c
**Purpose:** Lightweight key-value persistence

**Key Functions:**
- `ILibSimpleDataStore_Get/Put/Delete()` - CRUD operations
- File-based storage

**Use Case:** Agent configuration persistence

---

## Design Patterns

### Event-Driven Architecture
All I/O is non-blocking with callbacks:
```c
void OnData(char* buffer, int len, void* user) {
    // Process received data
}
```

### Chain Objects
All modules live in an `ILibChain` event loop:
```c
void* chain = ILibCreateChain();
void* socket = ILibAsyncSocket_Create(chain, ...);
ILibStartChain(chain);  // Runs until ILibStopChain()
```

### User Pointers
Modules accept `void* user` for context:
```c
ILibAsyncSocket_Create(chain, bufferSize, OnData, NULL, user);
```

## Platform Support

**Cross-Platform:**
- Windows (Winsock)
- Linux (epoll/select)
- macOS (kqueue/select)
- FreeBSD (kqueue)

**Abstractions:**
- Socket APIs unified across platforms
- Event loop uses best available (kqueue > epoll > select)
- Crypto adapts to platform (OpenSSL vs Security.framework)

## Threading Model

**Single-Threaded:**
- All callbacks execute on chain thread
- No mutex required within chain
- Multiple chains possible (rare)

**Thread Safety:**
- Chain functions not thread-safe
- Use ILibChain_RunOnMicrostackThread() to marshal calls

## Performance

**Optimizations:**
- Zero-copy where possible (sendfile, scatter-gather I/O)
- Pre-allocated buffers
- Minimal allocations in hot paths

**Scalability:**
- Tested with 1000+ concurrent connections
- Low memory per connection (~4KB)

## Security

**TLS Support:**
- ILibAsyncSocket supports TLS via OpenSSL
- Certificate validation
- SNI (Server Name Indication)

**Input Validation:**
- All parsers check bounds
- No string vulnerabilities (uses bounded functions)

## Usage in MeshAgent

| Component | MicroStack Modules |
|-----------|-------------------|
| Server connection | ILibAsyncSocket, ILibWebClient |
| KVM (macOS socket) | ILibAsyncServerSocket |
| WebRTC P2P | ILibWebRTC, ILibWrapperWebRTC |
| Discovery | ILibMulticastSocket, ILibAsyncUDPSocket |
| Network changes | ILibIPAddressMonitor |
| Child processes | ILibProcessPipe (Windows/Linux) |

## Documentation

Each microstack module has:
- Header file with API documentation
- Some have separate .md docs in `docs/Ylianst_MeshAgent/files/`

For detailed API reference, see header files in `/microstack/*.h`

---

**Total LOC:** 35,692
**Files:** 14
**Primary Use:** MeshAgent networking layer
**Origin:** Intel MicroStack (Apache 2.0)
**Maintained:** Active (2025)
