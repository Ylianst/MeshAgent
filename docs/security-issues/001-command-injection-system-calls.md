# [CRITICAL] Command Injection via system() calls in agentcore.c

**Labels:** security, critical, vulnerability

## Summary
Multiple locations in `agentcore.c` pass user-controlled values directly to `system()` calls without sanitization, enabling arbitrary command execution.

## Severity
**CRITICAL** - Remote Code Execution (RCE) with agent privileges (often root/SYSTEM)

## Affected Files
- `meshcore/agentcore.c` (lines 6245-6300, 6388-6400)

## Vulnerable Code Examples

### Example 1: Service restart commands (lines 6251-6275)
```c
sprintf_s(ILibScratchPad, sizeof(ILibScratchPad),
    "service %s onerestart", agentHost->meshServiceName);
ignore_result(system(ILibScratchPad));

sprintf_s(ILibScratchPad, sizeof(ILibScratchPad),
    "launchctl kickstart -k system/%s", agentHost->meshServiceName);
ignore_result(system(ILibScratchPad));

sprintf_s(ILibScratchPad, sizeof(ILibScratchPad),
    "initctl restart %s", agentHost->meshServiceName);
ignore_result(MeshAgent_System(ILibScratchPad));
```

### Example 2: File operations (lines 6245-6246, 6388)
```c
sprintf_s(ILibScratchPad, sizeof(ILibScratchPad),
    "mv \"%s\" \"%s\"", updateFilePath, agentHost->exePath);
if (system(ILibScratchPad)) {}

sprintf_s(ILibScratchPad2, 6000, "cp \"%s\" \"%s\"", selfpath, exepath);
while (system(ILibScratchPad2) != 0) { ... }
```

## Attack Vector
If `meshServiceName` or file paths contain shell metacharacters:
```
meshServiceName = "test; rm -rf /; echo"
Result: service test; rm -rf /; echo restart
```

Even with quotes, newlines or backticks can escape:
```
exePath = "test`malicious_command`"
```

## Recommended Fix
Replace `system()` with `execve()` using argument arrays:

```c
// Instead of:
sprintf_s(cmd, sizeof(cmd), "service %s restart", serviceName);
system(cmd);

// Use:
char *args[] = {"service", serviceName, "restart", NULL};
pid_t pid = fork();
if (pid == 0) {
    execve("/usr/sbin/service", args, environ);
    _exit(1);
}
waitpid(pid, &status, 0);
```

Or use a helper function that validates input:
```c
int safe_service_restart(const char *serviceName) {
    // Validate serviceName contains only alphanumeric and dash/underscore
    if (!is_valid_service_name(serviceName)) return -1;
    // Then use execve with args array
}
```

## References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- OWASP Command Injection
