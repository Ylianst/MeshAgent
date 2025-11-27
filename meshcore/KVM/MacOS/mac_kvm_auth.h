/*
 * mac_kvm_auth.h
 *
 * Code signature verification for KVM socket connections
 * Verifies connecting process is a legitimate meshagent binary
 */

#ifndef MAC_KVM_AUTH_H
#define MAC_KVM_AUTH_H

#ifdef __APPLE__

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Security framework headers
#include <Security/Security.h>
#include <Security/SecCode.h>

// Forward declarations for Code Signing APIs (may not be in all SDK versions)
#ifndef CODESIGNING_APIS_DECLARED
extern OSStatus SecCodeCreateWithPID(pid_t pid, SecCSFlags flags, SecCodeRef *code);
#define CODESIGNING_APIS_DECLARED 1
#endif

/**
 * Verify that the peer process connected to the socket is a legitimate
 * meshagent binary by comparing code signatures.
 *
 * @param socket_fd Connected socket file descriptor
 * @return 1 if valid, 0 if invalid/error
 */
int verify_peer_codesign(int socket_fd);

/**
 * Get our own code signature for comparison
 *
 * @return SecCodeRef for this process (caller must CFRelease)
 */
SecCodeRef get_self_code(void);

/**
 * Check if two code signatures match (same binary)
 *
 * @param code1 First code reference
 * @param code2 Second code reference
 * @return 1 if match, 0 if no match
 */
int codesign_matches(SecCodeRef code1, SecCodeRef code2);

#endif /* __APPLE__ */

#endif /* MAC_KVM_AUTH_H */
