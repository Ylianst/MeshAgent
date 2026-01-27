# [HIGH] Inadequate Error Handling - Silent Failures and Missing Validation

**Labels:** security, high, code-quality

## Summary
Multiple files have empty catch blocks, missing error handling, and silent failures that can hide security issues and make debugging difficult.

## Severity
**HIGH** - Silent failures can mask security issues and cause unexpected behavior

## Affected Files

### JavaScript Modules
- `modules/RecoveryCore.js` (lines 238, 265, 273, 290, 298, 431, 437)
- `modules/service-manager.js` (line 2423)
- `modules/toaster.js` (multiple locations)
- `modules/message-box.js` (line 58)
- `modules/meshcmd.js` (line 101)
- `modules/proxy-helper.js` (lines 54, 673)
- `modules/child-container.js` (lines 117, 249)
- `modules/win-dispatcher.js` (lines 300, 326)
- `modules/heciRedirector.js` (lines 68, 139)

### C Code
- `meshcore/agentcore.c` (inconsistent patterns throughout)

## Issues Found

### 1. Empty Catch Blocks (JavaScript)

**RecoveryCore.js (line 238):**
```javascript
try { cmd = JSON.parse(data); } catch (e) { };  // Parse error silently ignored
```

**RecoveryCore.js (lines 265, 273, 290, 298):**
```javascript
try { fs.unlinkSync(fn); } catch (e) { }  // File deletion errors ignored
try { fs.mkdirSync(target); } catch (e) { }  // Directory creation errors ignored
```

**service-manager.js (line 2423):**
```javascript
"try{require('service-manager').manager.uninstallService('" +
    options.name + "');}catch(x){}process.exit();"  // Uninstall errors hidden
```

### 2. Unprotected JSON.parse

**child-container.js (lines 117, 249):**
```javascript
var cmd = JSON.parse(c.slice(4, cLen).toString());  // No try-catch
```

**win-dispatcher.js (lines 300, 326):**
```javascript
var cmd = JSON.parse(c.slice(4, cLen).toString());  // Crash on malformed JSON
```

**heciRedirector.js (lines 68, 139):**
```javascript
var cmd = JSON.parse(chunk);  // Unprotected
```

### 3. Inconsistent C Error Handling

Different patterns used inconsistently:
```c
// Pattern 1: Abrupt termination
if ((*buffer = malloc(sz)) == NULL) { ILIBCRITICALEXIT(254); }

// Pattern 2: goto error
if ((signatureblock = malloc(size)) == NULL) goto error;

// Pattern 3: Ignore result entirely
ignore_result(system(ILibScratchPad));

// Pattern 4: No check at all
pAdapterInfo = malloc(ulOutBufLen);  // May be NULL
```

### 4. Missing Return Value Checks

**agentcore.c (line 6246):**
```c
if (system(ILibScratchPad)) {}  // Empty if body - return value ignored
```

## Recommended Fixes

### Add Error Logging to Catch Blocks
```javascript
// Instead of:
try { cmd = JSON.parse(data); } catch (e) { };

// Use:
try {
    cmd = JSON.parse(data);
} catch (e) {
    console.error('Failed to parse command:', e.message);
    return;  // or handle appropriately
}
```

### Protect JSON.parse
```javascript
function safeJsonParse(str, defaultValue = null) {
    try {
        return JSON.parse(str);
    } catch (e) {
        console.error('JSON parse error:', e.message);
        return defaultValue;
    }
}

var cmd = safeJsonParse(c.slice(4, cLen).toString());
if (cmd === null) return;  // Handle parse failure
```

### Standardize C Error Handling
```c
// Create consistent error handling macros
#define CHECK_ALLOC(ptr) do { \
    if ((ptr) == NULL) { \
        log_error("Memory allocation failed at %s:%d", __FILE__, __LINE__); \
        goto cleanup; \
    } \
} while(0)

// Usage:
char *buf = malloc(size);
CHECK_ALLOC(buf);
```

### Check System Call Returns
```c
int ret = system(cmd);
if (ret != 0) {
    log_error("Command failed with code %d: %s", ret, cmd);
    // Handle error
}
```

## References
- CWE-391: Unchecked Error Condition
- CWE-252: Unchecked Return Value
- CWE-754: Improper Check for Unusual or Exceptional Conditions
