## ILibAsyncUDPSocket.c

### Abstract
ILibAsyncUDPSocket provides the underyling UDP socket implementation for the Mesh Agent.

### Functions

**ILibAsyncUDPSocket_JoinMulticastGroupV4(module, multicastAddr, localAddr)**  
Joins an IPv4 Multicast group, using the specified interface

**ILibAsyncUDPSocket_JoinMulticastGroupV6(module, multicastAddr, ifIndex)**  
Joins an IPv6 Multicast group, using the specified interface index

**ILibAsyncUDPSocket_DropMulticastGroupV4(module, multicastAddr, localAddr)**  
**ILibAsyncUDPSocket_DropMulticastGroupV6(module, multicastAddr, ifIndex)**  
Leaves the specified multicast group, on the specified interface/index.

**ILibAsyncUDPSocket_SetMulticastInterface(module, localInterface)**  
Sets the local interface to use, when multicasting

**ILibAsyncUDPSocket_SetMulticastTTL(module, TTL)**  
Sets the Multicast TTL value

**ILibAsyncUDPSocket_SetMulticastLoopback(module, loopback)**  
Sets whether or not outbound multicasts are received on the local machine

**ILibAsyncUDPSocket_SetBroadcast(module, enable)**  
Enable/Disable the broadcast flag for the ILibAsyncUDPSocket object

**ILibAsyncUDPSocket_GetPendingBytesToSend(socketModule)**  
Returns the number of bytes that are pending to be sent

**ILibAsyncUDPSocket_GetTotalBytesSent(socketModule)**  
Returns the total number of bytes that have been sent, since the last reset

**ILibAsyncUDPSocket_ResetTotalBytesSent(socketModule)**  
Resets the total bytes sent counter

**ILibAsyncUDPSocket_SendTo(socketModule, remoteInterface, buffer, length, UserFree)**  
Sends a UDP packet to the specified address and port

**ILibAsyncUDPSocket_GetLocalInterface(socketModule, localAddress)**  
Fetches the bounded IP address in network order

**ILibAsyncUDPSocket_SetLocalInterface(socketModule, localAddress)**  
Sets the bounded IP address of the ILibAsyncUDPSocket object

**ILibAsyncUDPSocket_GetLocalPort(socketModule)**  
Fetches the bounded port in host order

**ILibAsyncUDPSocket_Resume(socketModule)**  
Resumes socket I/O of the ILibAsyncUDPSocket object

**ILibAsyncUDPSocket_GetSocket(module)**  
Fetches the associated socket descriptor of the ILibAsyncUDPSocket object
