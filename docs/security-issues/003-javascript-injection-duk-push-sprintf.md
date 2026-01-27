# [CRITICAL] JavaScript Injection via duk_push_sprintf in C code

**Labels:** security, critical, vulnerability

## Summary
User-controlled values are directly interpolated into JavaScript code strings via `duk_push_sprintf()`, enabling JavaScript injection attacks in the Duktape runtime.

## Severity
**CRITICAL** - Code injection leading to arbitrary JavaScript execution

## Affected Files
- `meshcore/agentcore.c` (lines 961, 1315, 1321, 3865, 4286, 5068, 5107)

## Vulnerable Code Examples

### Example 1: User login command (line 961)
```c
duk_push_sprintf(ptrs->ctx,
    "var _tmp=require('child_process').execFile('/bin/sh', ['sh']);"
    "_tmp.stdout.on('data', function (){});"
    "_tmp.stdin.write('loginctl kill-user %s\\nexit\\n');"
    "_tmp.waitExit();", user);
```

**Attack:** If `user` contains: `root'); require('child_process').exec('malicious'); ('`

### Example 2: Console UID (line 1315)
```c
duk_push_sprintf(ctx, "require('kvm-helper').createVirtualSession(%d);", console_uid);
```

### Example 3: Proxy helper (line 3865)
```c
duk_push_sprintf(agent->meshCoreCtx,
    "require('proxy-helper').autoHelper(require('http').parseUri('%s').host);",
    ILibScratchPad2);
```

**Attack:** If URL contains: `'); require('fs').writeFileSync('/tmp/pwned',''); ('`

### Example 4: Service name (lines 5068, 5107)
```c
duk_push_sprintf(tmpCtx,
    "require('service-manager').manager.getService('%s').isMe();",
    agentHost->meshServiceName);

duk_push_sprintf(tmpCtx,
    "require('_agentNodeId').checkResetNodeId('%s');",
    agentHost->meshServiceName);
```

### Example 5: Authenticode URL (line 4286)
```c
duk_push_sprintf(agent->meshCoreCtx,
    "require('win-authenticode-opus').locked('%s');", url);
```

## Recommended Fix

Create a proper escaping function for JavaScript strings:

```c
// Helper to escape JavaScript string literals
static char* js_escape_string(const char* input, char* output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < output_size - 2; i++) {
        switch (input[i]) {
            case '\'': case '"': case '\\':
                if (j < output_size - 3) {
                    output[j++] = '\\';
                    output[j++] = input[i];
                }
                break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            default: output[j++] = input[i];
        }
    }
    output[j] = '\0';
    return output;
}

// Usage:
char escaped[256];
js_escape_string(serviceName, escaped, sizeof(escaped));
duk_push_sprintf(ctx, "require('service-manager').manager.getService('%s').isMe();", escaped);
```

Or better yet, use Duktape's native APIs to pass values safely:
```c
duk_get_global_string(ctx, "require");
duk_push_string(ctx, "service-manager");
duk_call(ctx, 1);
// ... push args as native values, not strings
```

## References
- CWE-94: Improper Control of Generation of Code
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
