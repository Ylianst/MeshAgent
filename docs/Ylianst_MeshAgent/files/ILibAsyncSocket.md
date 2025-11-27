## ILibAsyncSocket.c

### Abstract
ILibAsyncSocket provides the underyling TCP socket implementation for the Mesh Agent.

### Functions

**ILibCreateAsyncSocketModule()**  
**ILibCreateAsyncSocketModuleWithMemory()**  
Creates an ILibAsyncSocket object, with an optional memory allocation for use by the user.

**ILibAsyncSocket_IsUsingTls(token)**  
Evaluates to true if the specified connection is a TLS connection

**ILibAsyncSocket_SetReAllocateNotificationCallback(AsyncSocketToken, Callback)**  
Triggers the specified callback when a realloc() results in the data buffer being moved to a different address.

**ILibAsyncSocket_GetUser(socketModule)**  
**ILibAsyncSocket_GetUser2(socketModule)**  
**ILibAsyncSocket_GetUser3(socketModule)**  
Sets a user object to the specified socket object

**ILibAsyncSocket_SetUser(socketModule, user)**  
**ILibAsyncSocket_SetUser2(socketModule, user)**  
**ILibAsyncSocket_SetUser3(socketModule, user)**  
Fetches the user object associated with the specified socket object

**ILibAsyncSocket_UpdateOnData(module, OnData)**  
Replaces the existing data handler with the specified OnData handler for the socket object

**ILibAsyncSocket_UpdateCallbacks(module, OnData, OnConnect, OnDisconnect, OnSendOK)**  
Replaces all the existing handlers with the specified handlers, for the specified socket object

**ILibAsyncSocket_GetSocket(module)**  
Fetches the internal socket descriptor for the specified socket object

**ILibAsyncSocket_GetPendingBytesToSend(socketModule)**  
Fetches the number of bytes pending to be sent by the socket object

**ILibAsyncSocket_GetTotalBytesSent(socketModule)**  
Fetches the total number of bytes that have been sent by the specified socket object

**ILibAsyncSocket_ResetTotalBytesSent(socketModule)**  
Resets the TotalBytesSent counter, for the specified socket object

**ILibAsyncSocket_ConnectTo(socketModule, localInterface, remoteAddress, InterruptPtr, user)**  
Connects the socket object to the specified address using the specified interface

**ILibAsyncSocket_SendTo_MultiWrite(socketModule, remoteAddress, count, ...)** 
Sends data to the specified address, specifying the number of triplets passed in the ellipses, where a triplet consists of **(buffer, length, userFree)**

**ILibAsyncSocket_Disconnect(socketModule)**  
Disconnects the specified socket object

**ILibAsyncSocket_GetBuffer(socketModule, buffer, BeginPointer, EndPointer)** 
Returns the buffer associated with an ILibAsyncSocket

**ILibAsyncSocket_UseThisSocket(socketModule, UseThisSocket, InterruptPtr, user)** 
Associates an already connected socket with the ILibAsyncSocket object

**ILibAsyncSocket_SetSSLContext(socketModule, ssl_ctx, tlsMode)**  
**ILibAsyncSocket_SetSSLContextEx(socketModule, ssl_ctx, tlsMode, hostname)**  
Associate an OpenSSL Context Object with the specified ILibAsyncSocket object

**ILibAsyncSocket_GetSSL(socketModule)**  
**ILibAsyncSocket_GetSSLContext(socketModule)**  
Fetches the OpenSSL Object and Context associated with the specified ILibAsyncSocket object

**ILibAsyncSocket_SetRemoteAddress(socketModule, remoteAddress)**  
Updates the remote address of the specified ILibAsyncSocket object

**ILibAsyncSocket_GetRemoteInterface(socketModule, remoteAddress)**  
Fetches the associated remote interface of the specified ILibAsyncSocket object, and writes it to **remoteAddress**, returning the number of bytes written.

**ILibAsyncSocket_SetLocalInterface(module, localAddress)**  
Updates the local interface of the specified ILibAsyncSocket object

**ILibAsyncSocket_GetLocalInterface(socketModule, localAddress)**  
Fetches the associated local interface of the specified ILibAsyncSocketObject, and writes it to **localAddress**, returning the number of bytes written.

**ILibAsyncSocket_IsFree(socketModule)**  
Returns non-zero if the specified ILibAsyncSocket object is in use

**ILibAsyncSocket_IsConnected(socketModule)**  
Returns non-zero if the specified ILibAsyncSocket object is connected

int ILibAsyncSocket_IsDomainSocket(ILibAsyncSocket_SocketModule socketModule);
unsigned short ILibAsyncSocket_GetLocalPort(ILibAsyncSocket_SocketModule socketModule);

**ILibAsyncSocket_Resume(socketModule)**  
Resumes socket I/O of the specified ILibAsyncSocket object

**ILibAsyncSocket_Pause(socketModule)**  
Suspends the socket I/O of the specified ILibAsyncSocket object

**ILibAsyncSocket_WasClosedBecauseBufferSizeExceeded(socketModule)**  
Returns non-zero if the specified ILibAsyncSocket object was disconnected because the underlying buffer size was exceeded

**ILibAsyncSocket_SetMaximumBufferSize(module, maxSize, OnBufferSizeExceededCallback, user)**  
Sets a maximum buffer size for the specified ILibAsyncSocket object, triggering the specified handler if the buffer size is exceeded.

**ILibAsyncSocket_SetSendOK(module, OnSendOK)**  
Updates the OnSendOK handler, which is triggered whenever a pending write operation is completed.

**ILibAsyncSocket_IsIPv6LinkLocal(LocalAddress)**  
Returns non-zero if the specified address is an IPv6 Link Local Address

**ILibAsyncSocket_IsModuleIPv6LinkLocal(module)**  
Returns non-zero if the associated socket with the specified ILibAsyncSocket object is an IPv6 Link Local socket.

**ILibAsyncSocket_SetTimeout(module, timeoutSeconds, timeoutHandler)**  
**ILibAsyncSocket_SetTimeoutEx(module, timeoutMilliseconds, timeoutHandler)**  
Sets an idle timeout handler for the specified ILibAsyncSocket object, which triggers after the specified amount of inactivity

**ILibAsyncSocket_SslGetCert(socketModule)**  
Returns the Peer's TLS Certificate, NULL if none was presented. Must call **X509_free()** when done with the certificate._

**ILibAsyncSocket_SslGetCerts(socketModule)**  
Returns the Certificate Chain presented by the Peer. NULL if none was presented. **NOTE:** X509 Cert's Reference Count is not incremented.
