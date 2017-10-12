#ifndef __ILIBIPADDRESSMONITOR__
#define __ILIBIPADDRESSMONITOR__

typedef void* ILibIPAddressMonitor;
typedef void(*ILibIPAddressMonitor_Handler)(ILibIPAddressMonitor sender, void *user);


extern int ILibMemory_IPAddressMonitor_CONTAINER_SIZE;
ILibIPAddressMonitor ILibIPAddressMonitor_Create(void *chain, ILibIPAddressMonitor_Handler handler, void *user);

#endif
