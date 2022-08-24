## Project Files

### Abstract
This document highlights what each of the files in the project are, and what they do at a higher level.

### Microstack
The files in this folder makeup the native core of the Mesh Agent. It is what provides the underlying plumbing as well
as the main event loop. It is inherently single threaded using Asynchronous I/O throughout.

- **[ILibAsyncSocket](files/ILibAsyncSocket.md)**
Provides the underyling TCP socket functionality
- **[ILibAsyncSocket](files/ILibAsyncUDPSocket.md)**
Provides the underlying UDP socket functionality
- **ILibAsyncServerSocket**
Provides the underlying TCP Server functionality
- ILibCrypto
- **ILibIPAddressMonitor**
Provides events for Network state changes
- **ILibMulticastSocket** 
Provides UDP Multicast/Broadcast functionality
- **[ILibParsers](files/ILibParsers.md)**
Provides the core event loop implementation, as well as some helper methods
- **ILibProcessPipe**
Provides child process dispatching functionality
- **ILibRemoteLogging**
Provides a web based logging mechanism, for native components
- **ILibSimpleDataStore**
Provides a lightweight data store for use by the agent
- **ILibWebClient**
Provides a lightweight HTTP/1.1 client implementation
- **ILibWebRTC**
Provides lightweight WebRTC Data Channel implementation
- **ILibWebServer**
Provides a lightweight HTTP/1.1 server implementation
- **ILibWrapperWebRTC**
Provides a pseudo object oriented abstraction for WebRTC Data Channel Setup/Creation
