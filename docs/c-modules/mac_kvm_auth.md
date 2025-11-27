# mac_kvm_auth.c

Code signature verification for KVM Unix socket connections, ensuring only legitimate meshagent binaries can establish reversed socket connections. Uses Apple's Code Signing APIs to verify connecting processes match the server's code signature, preventing unauthorized KVM access.

## Description

Security module for macOS KVM reversed socket architecture that prevents unauthorized processes from connecting to the KVM server socket by comparing code signatures of connecting clients with the server process.

## Platform

**Supported:** macOS (darwin) - Exclusive, 10.7+
**Excluded:** Windows, Linux, FreeBSD - No Security.framework

**Reason:** Uses macOS-specific Code Signing APIs (SecCode*, Security.framework)

## Functionality

### Purpose

Enables secure KVM reversed socket architecture by:
1. **Verifying Client Identity:** Connecting process must be same meshagent binary
2. **Preventing Hijacking:** Malicious processes can't connect to KVM socket
3. **Code Integrity:** Ensures connecting binary hasn't been tampered with
4. **Self-Authentication:** Only meshagent can connect to meshagent's KVM server

### Security Model

**Threat:** Malicious process connects to `/var/tmp/meshagent_kvm.sock` to intercept KVM data

**Defense:**
1. Get PID of connecting process from socket (`LOCAL_PEERPID`)
2. Get code signature of connecting process (`SecCodeCreateWithPID`)
3. Verify signature is valid (`SecCodeCheckValidity`)
4. Compare with our own code signature hash (`kSecCodeInfoUnique`)
5. Accept connection only if signatures match

### Integration

- **mac_kvm.c:** Calls `verify_peer_codesign()` on accept() before allowing KVM data transfer
- **KVM Reversed Socket:** Server validates client before establishing session

## Dependencies

### System Headers
- `<sys/socket.h>`, `<sys/un.h>` - Socket APIs, LOCAL_PEERPID (Line 13-14, header)
- `<unistd.h>` - getpid() (Line 15, header)
- `<Security/Security.h>`, `<Security/SecCode.h>` - Code Signing APIs (Lines 18-19, header)
- `<stdio.h>`, `<string.h>` - Standard I/O (Lines 12-13)

### MeshAgent Headers
- `mac_logging_utils.h` - mesh_log_message() for auth failures (Line 11)

### System Frameworks
- **Security.framework** - Required

## Key Functions

### get_self_code() - Lines 18-31

**Purpose:** Get code signature reference for current process

**Signature:**
```c
SecCodeRef get_self_code(void);
```

**Return:** SecCodeRef for this process (caller must CFRelease), NULL on error

**Implementation:**
- `SecCodeCopySelf()` gets code signature of running process
- Returns reference for comparison with connecting clients

---

### codesign_matches() - Lines 36-73

**Purpose:** Compare two code signatures for equality

**Signature:**
```c
int codesign_matches(SecCodeRef code1, SecCodeRef code2);
```

**Parameters:**
- `code1`, `code2` - Code signature references to compare

**Return:** 1 if match (same binary), 0 if different or error

**Implementation:**
1. Get signing information from both codes (`SecCodeCopySigningInformation`)
2. Extract code directory hashes (`kSecCodeInfoUnique`)
3. Compare hashes with `CFEqual()`
4. Match = same binary (even if different paths/copies)

**Security Note:** Uses cryptographic hash comparison (CDHash), not just path comparison

---

### verify_peer_codesign() - Lines 78-131

**Purpose:** Verify connecting process is legitimate meshagent binary

**Signature:**
```c
int verify_peer_codesign(int socket_fd);
```

**Parameters:**
- `socket_fd` - Connected Unix domain socket

**Return:** 1 if valid meshagent, 0 if invalid/unauthorized

**Implementation:**
1. **Get Peer PID** (Lines 87-95):
   - `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` retrieves connecting process PID
   - Validates PID > 0
2. **Get Own Code** (Lines 98-101):
   - Call `get_self_code()` for comparison baseline
3. **Get Peer Code** (Lines 104-109):
   - `SecCodeCreateWithPID()` gets peer's code signature
4. **Validate Peer** (Lines 112-117):
   - `SecCodeCheckValidity()` ensures signature valid (not tampered)
5. **Compare** (Lines 120-124):
   - `codesign_matches()` ensures peer is same binary
   - Logs mismatch for debugging

**Thread Safety:** Thread-safe (no shared state)

**Error Handling:** Logs detailed errors, returns 0 on any failure

## macOS-Specific Implementation

### Code Signing APIs

**SecCodeCopySelf:**
- Returns code signature of current process
- Works for signed and unsigned binaries (ad-hoc signature)

**SecCodeCreateWithPID:**
- Gets code signature from another process by PID
- Requires no special entitlements
- PID must exist when called (race condition possible)

**SecCodeCheckValidity:**
- Verifies signature is valid (not expired, not tampered)
- Checks cryptographic integrity

**kSecCodeInfoUnique (CDHash):**
- Code Directory Hash - cryptographic hash of binary
- Unique identifier for exact binary version
- Changes if binary modified (even 1 byte)

### LOCAL_PEERPID

**macOS Unix Domain Socket Feature:**
- `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` returns PID of peer process
- macOS-specific (not POSIX standard)
- Atomic operation (no TOCTOU)

**Security Consideration:**
- PID can be reused after process exits
- Race condition: Process exits → PID reused → wrong verification
- **Mitigation:** Audit token method (currently commented out, Lines 137-163)

### Alternative: Audit Token Method

**More Secure (commented out code):**
```c
// Use LOCAL_PEERTOKEN to get audit token
// SecCodeCreateWithAuditToken() - immune to PID reuse
```

**Why Not Used:**
- LOCAL_PEERTOKEN availability unclear on all macOS versions
- PID method sufficient for MeshAgent use case (rapid verification)

## Usage Examples

### Example 1: KVM Server Accept

```c
#include "mac_kvm_auth.h"

int accept_kvm_connection(int listen_fd) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        return -1;
    }

    // CRITICAL: Verify client before exchanging data
    if (!verify_peer_codesign(client_fd)) {
        mesh_log_message("[KVM] Unauthorized connection attempt blocked\n");
        close(client_fd);
        return -1;
    }

    mesh_log_message("[KVM] Authorized meshagent client connected\n");
    return client_fd;
}
```

### Example 2: Testing Code Signature Match

```c
#include "mac_kvm_auth.h"

void test_codesign_verification(void) {
    SecCodeRef self1 = get_self_code();
    SecCodeRef self2 = get_self_code();

    if (codesign_matches(self1, self2)) {
        printf("Same binary (as expected)\n");
    }

    CFRelease(self1);
    CFRelease(self2);
}
```

## Technical Notes

### Security Properties

**Prevents:**
- Unauthorized process connecting to KVM socket
- Man-in-the-middle attacks on KVM data
- Malicious binary spoofing meshagent

**Does Not Prevent:**
- Legitimate meshagent being compromised before signature check
- Kernel-level attacks (rootkit)
- Physical access attacks

### Performance

- Verification: ~5-10ms per connection
- Acceptable for KVM (connections infrequent)
- No overhead after connection established

### Limitations

**PID Reuse Race:**
- Theoretical: Process exits → PID reused → verification uses wrong process
- Probability: Low (PIDs cycle slowly, verification is fast)
- Impact: Single failed auth (connection rejected, no data leak)

**Ad-Hoc Signatures:**
- Unsigned binaries get ad-hoc signature (hash of binary)
- Still provides tamper detection
- No identity verification (any meshagent binary matches any other)

## Cross-References

### Related C Files
- [`mac_kvm.c`](mac_kvm.c) - KVM server that calls verify_peer_codesign()
- [`mac_logging_utils.c`](mac_logging_utils.md) - Logging for auth failures

### Documentation
- [macOS KVM Architecture](../macos-KVM-Architecture.md) - Reversed socket design

## Summary

mac_kvm_auth.c provides code signature-based authentication for KVM reversed socket connections, ensuring only legitimate meshagent binaries can connect to the KVM server. Using Apple's Code Signing APIs, it verifies connecting processes match the server's code signature by comparing cryptographic hashes, preventing unauthorized access to KVM data.

---

**Last Updated:** 2025-11-28
**Documented By:** Peet McKinney
**Source:** `meshcore/KVM/MacOS/mac_kvm_auth.c`
**LOC:** 166
**Security:** Code signature verification, PID-based peer identification
