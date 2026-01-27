# [CRITICAL] Buffer Overflow from unsafe strcpy/strcat operations

**Labels:** security, critical, vulnerability

## Summary
Multiple locations use unsafe `strcpy()` and `strcat()` without bounds checking, leading to potential buffer overflows.

## Severity
**CRITICAL** - Stack buffer overflow leading to potential code execution or crash

## Affected Files
- `meshcore/agentcore.c` (lines 4136-4138)
- `meshcore/KVM/MacOS/mac_kvm.c` (lines 947-948)

## Vulnerable Code Examples

### Example 1: agentcore.c (lines 4136-4138)
```c
const char* FieldData = "MeshAgent ";
char combined[40];
strcpy(combined, FieldData);              // UNSAFE - no bounds check
strcat(combined, SOURCE_COMMIT_DATE);     // UNSAFE - can overflow
```

**Issue:** Fixed buffer of 40 bytes with no validation that `SOURCE_COMMIT_DATE` fits.

### Example 2: mac_kvm.c (lines 947-948)
```c
const char *testFiles[] = {
    strcat(strcpy(malloc(strlen(userHomeFolderPath) + 30), userHomeFolderPath),
           "/Library/Safari/CloudTabs.db"),
    strcat(strcpy(malloc(strlen(userHomeFolderPath) + 30), userHomeFolderPath),
           "/Library/Safari/Bookmarks.plist"),
    // ...
};
```

**Issues:**
1. `malloc()` result not checked for NULL
2. Buffer size calculation assumes paths fit in +30 bytes
3. Memory is never freed (leak)
4. If `userHomeFolderPath` is longer than expected, overflow occurs

## Recommended Fix

### For agentcore.c:
```c
const char* FieldData = "MeshAgent ";
char combined[40];
snprintf(combined, sizeof(combined), "%s%s", FieldData, SOURCE_COMMIT_DATE);
```

### For mac_kvm.c:
```c
// Use a helper function with proper error handling
static char* build_path(const char* base, const char* suffix) {
    size_t len = strlen(base) + strlen(suffix) + 1;
    char* result = malloc(len);
    if (result == NULL) return NULL;
    snprintf(result, len, "%s%s", base, suffix);
    return result;
}

// Then use with cleanup
char *cloudTabs = build_path(userHomeFolderPath, "/Library/Safari/CloudTabs.db");
if (cloudTabs) {
    // use it
    free(cloudTabs);
}
```

## References
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
