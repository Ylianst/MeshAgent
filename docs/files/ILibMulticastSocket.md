## ILibMulticastSocket.c

### Abstract
ILibMulticastSocket provides core UDP/Multicast/Broadcast network functionality

### Functions

**ILibMulticastSocket_Create(Chain, BufferSize, LocalPort, MulticastAddr, MulticastAddr6, OnData, user, loopback)**  
Creates an ILibMulticastSocket object, bound to the specified interface, and joining the specified multicast groups. *OnData* is emitted on data reception. If *loopback* is specified, outbound multicasts will be received on the local socket.

**ILibMulticastSocket_Unicast(module, target, data, datalen)**  
Unicast a datagram to the specified *target*

**ILibMulticastSocket_BroadcastIF(module, data, datalen, count, localif)**  
Broadcast a datagram packet on the specified interface, *count* number of times

**ILibMulticastSocket_Broadcast(module, data, datalen, count)**  
Broadcast a datagram packet on the default interface

**ILibMulticastSocket_ResetMulticast(module, cleanuponly)**  
This function should be called whenever the local network has changed. This function will check the local network addresses, to determine if any multicast interfaces need to be added/removed.

**ILibMulticastSocket_WakeOnLan(module, mac)**  
Broadcasts a Wake On Lan Magic Packet, for the specified *mac* address.

**ILibSetTTL(module, ttl)**  
Sets the MulticastTTL for the ILibMulticastSocket object
