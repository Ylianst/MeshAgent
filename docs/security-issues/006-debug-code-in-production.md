# [HIGH] Debug Code and Remote Logging Enabled in Production Builds

**Labels:** security, high, build

## Summary
Release/Production builds include Duktape debugger support and remote logging functionality that should be disabled for security.

## Severity
**HIGH** - Debug functionality enables runtime inspection and potential manipulation of the agent

## Affected Files
- `meshservice/MeshService.vcxproj` (lines 375, 546+)
- `meshservice/MeshService-2022.vcxproj` (lines 546+)
- `meshconsole/MeshConsole.vcxproj` (line 429+)

## Vulnerable Configuration

### Duktape Debugger Flags in Release Builds
```xml
<PreprocessorDefinitions>
    DUK_USE_DEBUGGER_SUPPORT;
    DUK_USE_INTERRUPT_COUNTER;
    DUK_USE_DEBUGGER_INSPECT;
    DUK_USE_DEBUGGER_PAUSE_UNCAUGHT;
    DUK_USE_DEBUGGER_DUMPHEAP;
    ...
</PreprocessorDefinitions>
```

**Impact:**
- Allows attachment of debuggers to running agent
- Enables heap inspection and memory dumps
- Can pause execution and inspect variables
- Potential for runtime code modification

### Remote Logging in Release Builds
```xml
<PreprocessorDefinitions>
    _REMOTELOGGING;
    _REMOTELOGGINGSERVER;
    ...
</PreprocessorDefinitions>
```

**Impact:**
- Sensitive data may be logged and transmitted
- Log destination may not be secured
- Network traffic generated for logging

## Recommended Fix

### Create Separate Debug and Release Preprocessor Definitions

For Release configurations, remove debug-related flags:

```xml
<ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
        <PreprocessorDefinitions>
            WIN32;
            NDEBUG;
            _CONSOLE;
            MICROSTACK_NO_STDAFX;
            <!-- Remove all DUK_USE_DEBUGGER_* flags -->
            <!-- Remove _REMOTELOGGING flags -->
            %(PreprocessorDefinitions)
        </PreprocessorDefinitions>
    </ClCompile>
</ItemDefinitionGroup>
```

### Keep Debug Flags Only in Debug Configuration
```xml
<ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
        <PreprocessorDefinitions>
            WIN32;
            _DEBUG;
            DUK_USE_DEBUGGER_SUPPORT;
            DUK_USE_DEBUGGER_INSPECT;
            _REMOTELOGGING;
            %(PreprocessorDefinitions)
        </PreprocessorDefinitions>
    </ClCompile>
</ItemDefinitionGroup>
```

### Add Compile-Time Check
In C code, add verification:
```c
#if defined(NDEBUG) && defined(DUK_USE_DEBUGGER_SUPPORT)
#error "Debugger support should not be enabled in release builds"
#endif
```

## References
- CWE-489: Active Debug Code
- OWASP: Leftover Debug Code
