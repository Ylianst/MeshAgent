# [HIGH] Memory Safety Issues - NULL Checks, Leaks, and Use-After-Free

**Labels:** security, high, memory-safety

## Summary
Multiple memory safety issues including missing NULL pointer checks after allocation, memory leaks in error paths, and potential use-after-free conditions.

## Severity
**HIGH** - Can lead to crashes, denial of service, or potentially exploitable conditions

## Affected Files
- `meshcore/agentcore.c`
- `meshcore/meshinfo.c` (line 85)
- `meshcore/signcheck.c` (lines 176-220)
- `meshcore/KVM/MacOS/mac_kvm.c` (lines 947-948)
- `microstack/ILibAsyncSocket.c` (lines 1202, 1231, 1235)

## Issues Found

### 1. Missing NULL Checks After malloc()

**meshinfo.c (line 85-88):**
```c
pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS)
{
    free(pAdapterInfo);
    if (ulOutBufLen == 0) return 0;
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);  // NO NULL CHECK!
}
```

**mac_kvm.c (lines 947-948):**
```c
strcat(strcpy(malloc(strlen(userHomeFolderPath) + 30), userHomeFolderPath),
       "/Library/Safari/CloudTabs.db")  // malloc not checked
```

### 2. Memory Leaks in Error Paths

**signcheck.c (lines 176-220):**
```c
if ((signatureblock = (char*)malloc(endblock[0])) == NULL) goto error;
// ...
if ((buf = (char*)malloc(4096)) == NULL) goto error;

error:
    util_freecert(&cert);
    if (certbuf != NULL) free(certbuf);
    if (hashs != NULL) free(hashs);
    if (pFile != NULL) fclose(pFile);
    if (signatureblock != NULL) free(signatureblock);
    // BUG: 'buf' is NOT freed if error occurs!
```

**mac_kvm.c:** Array of malloc'd strings never freed:
```c
const char *testFiles[] = {
    strcat(strcpy(malloc(...), ...), ...),  // Never freed
    strcat(strcpy(malloc(...), ...), ...),  // Never freed
    // ...
};
```

### 3. Potential Use-After-Free

**ILibAsyncSocket.c (lines 1202-1235):**
```c
bytesReceived = recv(Reader->internalSocket,
    Reader->buffer, Reader->MallocSize, MSG_PEEK | MSG_NOSIGNAL);

// In async environment, Reader could be freed by another callback
// before the next recv call:
bytesReceived = recv(Reader->internalSocket,
    Reader->readBioBuffer_mem + Reader->readBioBuffer->length, ...);
```

### 4. Integer Overflow in Size Calculations

**agentcore.c (line 2938):**
```c
memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE,
    sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE,  // Could underflow!
    agent->serverNonce, UTIL_SHA384_HASHSIZE);
```

### 5. Uninitialized Variables

**agentcore.c (line 3584):**
```c
char idleBuffer[64];  // UNINITIALIZED
idleBuffer[ILibSimpleDataStore_Get(...)] = 0;
// If Get() fails or returns unexpected value, buffer contains garbage
```

## Recommended Fixes

### Add NULL Checks
```c
pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
if (pAdapterInfo == NULL) {
    return -1;  // or handle error appropriately
}
```

### Fix Memory Leaks
```c
error:
    util_freecert(&cert);
    if (certbuf != NULL) free(certbuf);
    if (hashs != NULL) free(hashs);
    if (pFile != NULL) fclose(pFile);
    if (signatureblock != NULL) free(signatureblock);
    if (buf != NULL) free(buf);  // ADD THIS
    return result;
```

### Add Overflow Checks
```c
if (sizeof(ILibScratchPad) < UTIL_SHA384_HASHSIZE) {
    // Handle error - buffer too small
    return -1;
}
size_t remaining = sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE;
memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE, remaining, ...);
```

### Initialize Variables
```c
char idleBuffer[64] = {0};  // Zero-initialize
```

## References
- CWE-476: NULL Pointer Dereference
- CWE-401: Missing Release of Memory after Effective Lifetime
- CWE-416: Use After Free
- CWE-190: Integer Overflow or Wraparound
