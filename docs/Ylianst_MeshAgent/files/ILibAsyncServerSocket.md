## ILibAsyncServerSocket.c

### Abstract
ILibAsyncUDPSocket provides the underyling TCP Server implementation for the Mesh Agent.

### Functions

void ILibAsyncServerSocket_SetReAllocateNotificationCallback(ILibAsyncServerSocket_ServerModule AsyncServerSocketToken, ILibAsyncServerSocket_ConnectionToken ConnectionToken, ILibAsyncServerSocket_BufferReAllocated Callback);

**ILibCreateAsyncServerSocketModule(Chain, MaxConnections, PortNumber, initialBufferSize, loopbackFlag, OnConnect, OnDisconnect, OnReceive, OnInterrupt, OnSendOK)**  
**ILibCreateAsyncServerSocketModuleWithMemory(Chain, MaxConnections, PortNumber, initialBufferSize, loopbackFlag, OnConnect, OnDisconnect, OnReceive, OnInterrupt, OnSendOK, ServerUserMappedMemorySize, SessionUserMappedMemorySize)**  
**ILibCreateAsyncServerSocketModuleWithMemoryEx(Chain, MaxConnections, initialBufferSize, local, OnConnect, OnDisconnect, OnReceive, OnInterrupt, OnSendOK, ServerUserMappedMemorySize, SessionUserMappedMemorySize)**  
**ILibCreateAsyncServerSocketModuleWithMemoryExMOD(Chain, MaxConnections, initialBufferSize, local, OnConnect, OnDisconnect, OnReceive, OnInterrupt, OnSendOK, mod, ServerUserMappedMemorySize, SessionUserMappedMemorySize)**  
Instantiates a new ILibAsyncServerSocket, adding it to the specified chain, capping the maximum number of simultaneous connections to the value specified. ServerAutoFreeMemorySize Size of AutoFreeMemory on Server to co-allocate. SessionAutoFreeMemorySize Size of AutoFreeMemory on Session to co-allocate

**ILibAsyncServerSocket_GetConnections(server, connections, connectionsSize)**  
Fetches a list of all the connected sockets

**ILibAsyncServerSocket_GetUser(ILibAsyncServerSocket_ConnectionToken *token)**  
Fetches the user object associated with a connection object

**ILibAsyncServerSocket_GetTag(ILibAsyncSocketModule)**  
**ILibAsyncServerSocket_GetTag2(ILibAsyncSocketModule)**  
Fetches the Tag associated with a connection object.

**ILibAsyncServerSocket_SetTag(ILibAsyncSocketModule, *user)**  
**ILibAsyncServerSocket_SetTag2(ILibAsyncSocketModule, user)**  
Associates a Tag value with a connection object

**ILibAsyncServerSocket_SSL_SetSink(AsyncServerSocketModule, SSLHandler)**  
Associates a handler with a connection object, that will be called when an SSL object has been set

**ILibAsyncServerSocket_GetSSL(connectiontoken)**  
Fetches the associated OpenSSL object from the connection object

**ILibAsyncServerSocket_GetSSL_CTX(ILibAsyncSocketModule)**  
Fetches the associated OpenSSL Context Object from the connection object

**ILibAsyncServerSocket_SetSSL_CTX(ILibAsyncSocketModule, ssl_ctx, enableTLSDetect)**  
Sets an OpenSSL Context Object to the connection object

**ILibAsyncServerSocket_StopListening(module)**  
**ILibAsyncServerSocket_ResumeListening(module)**  
Pause/Resume Socket I/O on the server object

**ILibAsyncServerSocket_GetPortNumber(ServerSocketModule)**  
Fetches the port number that the TCP server is listening on

**ILibAsyncServerSocket_GetLocal(ServerSocketModule, addr, addrLen)**  
Fetches the local IPEndPoint that the TCP server is bound.

**ILibAsyncServerSocket_Send(ServerSocketModule, ConnectionToken, buffer, bufferLength, UserFreeBuffer)**  
Sends data onto the TCP stream

**ILibAsyncServerSocket_Disconnect(ServerSocketModule, ConnectionToken)**  
Disconnects a TCP stream

**ILibAsyncServerSocket_GetPendingBytesToSend(ServerSocketModule, ConnectionToken)**  
Fetches the outstanding number of bytes to be sent

**ILibAsyncServerSocket_GetTotalBytesSent(ServerSocketModule, ConnectionToken)**  
Fetches the total number of bytes that have been sent on a TCP stream, since the last reset

**ILibAsyncServerSocket_ResetTotalBytesSent(ServerSocketModule, ConnectionToken)**  
Resets the total bytes sent counter