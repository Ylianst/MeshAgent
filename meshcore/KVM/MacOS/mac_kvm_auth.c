/*
 * mac_kvm_auth.c
 *
 * Code signature verification for KVM socket connections
 * Ensures only the same meshagent binary can connect
 */

#ifdef __APPLE__

#include "mac_kvm_auth.h"
#include <stdio.h>
#include <string.h>

/**
 * Get our own code signature for comparison
 */
SecCodeRef get_self_code(void) {
    SecCodeRef self_code = NULL;
    OSStatus status;

    // Get reference to our own running process
    status = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);

    if (status != errSecSuccess) {
        fprintf(stderr, "KVM Auth: Failed to get self code signature: %d\n", status);
        return NULL;
    }

    return self_code;
}

/**
 * Check if two code signatures match (same binary)
 */
int codesign_matches(SecCodeRef code1, SecCodeRef code2) {
    OSStatus status;
    CFDictionaryRef info1 = NULL, info2 = NULL;
    CFDataRef cdhash1 = NULL, cdhash2 = NULL;
    int result = 0;

    if (!code1 || !code2) {
        return 0;
    }

    // Get signing information from both codes
    status = SecCodeCopySigningInformation(code1, kSecCSSigningInformation, &info1);
    if (status != errSecSuccess) {
        goto cleanup;
    }

    status = SecCodeCopySigningInformation(code2, kSecCSSigningInformation, &info2);
    if (status != errSecSuccess) {
        goto cleanup;
    }

    // Get code directory hashes (unique identifier for the binary)
    cdhash1 = (CFDataRef)CFDictionaryGetValue(info1, kSecCodeInfoUnique);
    cdhash2 = (CFDataRef)CFDictionaryGetValue(info2, kSecCodeInfoUnique);

    if (cdhash1 && cdhash2) {
        // Compare the unique code directory hashes
        if (CFEqual(cdhash1, cdhash2)) {
            result = 1;  // Match!
        }
    }

cleanup:
    if (info1) CFRelease(info1);
    if (info2) CFRelease(info2);

    return result;
}

/**
 * Verify peer process connected to socket is legitimate meshagent
 */
int verify_peer_codesign(int socket_fd) {
    pid_t peer_pid = 0;
    socklen_t len = sizeof(peer_pid);
    OSStatus status;
    SecCodeRef self_code = NULL;
    SecCodeRef peer_code = NULL;
    int result = 0;

    // Get PID of connecting process
    if (getsockopt(socket_fd, SOL_LOCAL, LOCAL_PEERPID, &peer_pid, &len) < 0) {
        fprintf(stderr, "KVM Auth: Failed to get peer PID: %s\n", strerror(errno));
        return 0;
    }

    if (peer_pid <= 0) {
        fprintf(stderr, "KVM Auth: Invalid peer PID: %d\n", peer_pid);
        return 0;
    }

    // Get our own code signature
    self_code = get_self_code();
    if (!self_code) {
        return 0;
    }

    // Get peer process code signature
    status = SecCodeCreateWithPID(peer_pid, kSecCSDefaultFlags, &peer_code);
    if (status != errSecSuccess) {
        fprintf(stderr, "KVM Auth: Failed to get peer code signature (PID %d): %d\n",
                peer_pid, status);
        goto cleanup;
    }

    // Verify peer code is valid (signed, not tampered)
    status = SecCodeCheckValidity(peer_code, kSecCSDefaultFlags, NULL);
    if (status != errSecSuccess) {
        fprintf(stderr, "KVM Auth: Peer code signature invalid (PID %d): %d\n",
                peer_pid, status);
        goto cleanup;
    }

    // Compare code signatures - must be same binary
    if (codesign_matches(self_code, peer_code)) {
        printf("KVM Auth: Peer verified - same meshagent binary (PID %d)\n", peer_pid);
        result = 1;
    } else {
        fprintf(stderr, "KVM Auth: Peer code signature mismatch (PID %d)\n", peer_pid);
    }

cleanup:
    if (self_code) CFRelease(self_code);
    if (peer_code) CFRelease(peer_code);

    return result;
}

/**
 * Alternative: Verify using audit token (more secure, avoids PID reuse)
 * Requires macOS 10.14+
 */
#if 0  // Enable if needed
int verify_peer_codesign_audit(int socket_fd) {
    struct xucred cred;
    socklen_t len = sizeof(cred);
    audit_token_t audit_token;
    OSStatus status;
    SecCodeRef self_code = NULL;
    SecCodeRef peer_code = NULL;
    int result = 0;

    // Get peer credentials including audit token
    if (getsockopt(socket_fd, 0, LOCAL_PEERCRED, &cred, &len) < 0) {
        return 0;
    }

    // Note: Getting audit_token requires different approach
    // This is placeholder - actual implementation needs LOCAL_PEERTOKEN (iOS)
    // or parsing /proc/$PID/audit_token

    // Use audit token instead of PID (prevents PID reuse attacks)
    // status = SecCodeCreateWithAuditToken(&audit_token, kSecCSDefaultFlags, &peer_code);

    // ... rest similar to verify_peer_codesign()

    return result;
}
#endif

#endif /* __APPLE__ */
