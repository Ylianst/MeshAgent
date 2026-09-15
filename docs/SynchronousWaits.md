# Synchronous waits: `waitExit()` and `promise.wait()`

This document explains how the agent makes a script wait for a child process or a promise.
It is written in simple English. Each section starts with the main idea, then gives the details.

## Words used in this document

| Word | Meaning |
|---|---|
| chain | The agent's event loop. One chain runs on one thread. |
| wait | A call to `child.waitExit()` or `promise.wait()`. The script stops at this line until the wait ends. |
| nested wait | A wait that starts while another wait is still running. |
| continuation | One run of `ILibChain_Continue()`. Every wait uses exactly one continuation. |
| tag | A pointer that identifies who started a continuation. |
| reap | Collect the exit status of a finished child with `waitpid()`. |

## 1. How a wait works

A script is single-threaded. So a wait cannot simply sleep, because then nothing else can happen: no timers, no network, no child output.

Instead, a wait runs a second copy of the event loop. This is `ILibChain_Continue()`. The loop keeps timers, sockets and child processes working. It stops when the wait is finished, for example when the child exits.

## 2. The old problem

The chain stored the state of a continuation in one global value. This had two effects.

1. **Only one wait at a time.** Code that runs inside a wait can start its own wait. Examples are a timer, an `'exit'` event handler, or a stream `'data'` handler. The second wait failed with the error `waitExit() already in progress`.
2. **The wrong wait could end.** When a child exited, it ended the innermost continuation. It did not check if that continuation was waiting for this child.

## 3. The new design

### 3.1 A stack of continuations

Every call to `ILibChain_Continue()` creates one entry, `ILibChain_ContinueEntry`. The entry lives on the C stack of that call. The entries are linked from the innermost to the outermost. So they form a stack, and the order of the stack is the same as the order of the calls.

| Field | Meaning |
|---|---|
| `previous` | The next outer entry. It is `NULL` for the outermost entry. |
| `tag` | Who started this continuation. |
| `depth` | 1 for the outermost entry, 2 for the next one, and so on. |
| `ended` | Set when this continuation must stop. |
| `aborted` | Set when the script is exiting. The call then returns an error. |

The chain keeps a pointer to the innermost entry, `continueTop`. It is `NULL` when no wait is running.

### 3.2 Ending a continuation by tag

The caller of `ILibChain_Continue()` passes a tag. The tag is a pointer to the caller's own object.

- `child.waitExit()` uses the child object as its tag.
- `promise.wait()` uses a small state object as its tag. A new state object is made for each call.

`ILibChain_EndContinue_ByTag(chain, tag)` marks every live entry with this tag as ended. It does not touch any other entry.

This design has three good properties.

1. **The right wait ends.** A child's exit ends only the waits for this child.
2. **Several waits on one child all end.** A handler inside a wait can call `waitExit()` on the same child again. When the child exits, both waits end.
3. **A late call does no harm.** When a wait is already over, its entry is gone. A later call with the same tag finds nothing, so it does nothing.

### 3.3 What was removed

`ILibChain_GetContinuationState()` and its enum were removed. They could only describe the innermost continuation, and that is not useful when waits are nested.

## 4. Limits

### 4.1 Depth limit

A nested wait uses C stack. A deep chain of waits could use all of the stack and crash the agent. So there are two checks before a new continuation starts.

1. **Depth.** At most `ILibChain_MaxContinueDepth` continuations can be active. The default is 16. When the limit is reached, the wait throws `nesting depth limit reached`.
2. **Free stack.** A nested wait is refused when less than `ILibChain_ContinueStackHeadroom` bytes of stack are free. The default is 192 KB. The wait then throws `not enough C stack left for a nested wait`.

The first wait is never refused because of the stack. A single wait always worked, also on threads with a small stack.

Both values are build-time settings. A build can set them with `-D`.

Measured cost of one nested level:

| Build | C stack per level |
|---|---|
| Linux, gcc Release | about 35 KB |
| FreeBSD, clang Debug `-O0` | about 61 KB |
| Windows x64, MSVC Debug | about 13 KB |
| Linux x86 32-bit, zig Debug `-O0` | about 36 KB |

Realistic scripts nest 2 to 4 levels. A depth near 16 is almost always a bug in the script.

### 4.2 How the agent finds the stack size

The agent asks the operating system where the stack of the current thread ends. This happens once per chain.

| Platform | Method |
|---|---|
| Windows | `VirtualQuery()` on a local variable gives the start of the stack reservation. |
| macOS | `pthread_get_stackaddr_np()` and `pthread_get_stacksize_np()`. |
| Linux | `pthread_getattr_np()`. On the main thread the size is corrected with `RLIMIT_STACK`, see below. |
| FreeBSD | `pthread_attr_get_np()`. |
| OpenBSD | `pthread_stackseg_np()`. |

**Linux main thread.** glibc reports the full stack size from `RLIMIT_STACK`. musl reports only the part of the stack that is already in use, and this value changes when the stack grows. So on the Linux main thread the agent computes the limit from `RLIMIT_STACK` itself.

**FreeBSD and OpenBSD.** The agent uses the reported range only when a local variable is inside it. Otherwise it uses no stack limit, and only the depth limit applies.

When a platform gives no usable answer, only the depth limit applies.

Debug builds have `child_process._stackRemaining()`. It returns the free stack in bytes, or -1 when the size is not known. `test/waitExitTest.js` prints this value for each nesting level.

## 5. What scripts see

### 5.1 `child.waitExit([timeout])`

| Call | Result |
|---|---|
| `waitExit()` | Waits up to 60 seconds, the value of `ILibDuktape_ChildProcess_DefaultWaitExitTimeout`. Then it throws. |
| `waitExit(ms)` | Waits up to `ms` milliseconds. Then it throws. |
| `waitExit(-1)` or `waitExit(0)` | Waits with no time limit. |
| Child has already exited | Returns at once. |

The timeout error is: `waitExit() timed out after Nms, child (pid=P) still running`.

The agent does not kill the child after a timeout. The script decides what to do: call `kill()`, wait again, or continue.

A timeout throws an error. It does not return a value. The reason: after a timeout the child is still running, so there is no exit code and no `'exit'` event yet. Most callers ignore the return value, so a returned error would be lost. The script would then continue as if the child had finished. Node.js `execSync()` throws on a timeout for the same reason.

The throw happens only when the child is really still running. When the child exits at the same moment as the timeout, the call returns normally.

### 5.2 `promise.wait(p[, timeout])`

| Call | Result |
|---|---|
| `promise.wait(p)` | Waits until `p` is resolved or rejected, with no time limit. But when a timer is pending in the chain, the limit is 60 seconds. |
| `promise.wait(p, ms)` | Waits up to `ms` milliseconds. |

The timeout error is: `wait() timeout`.

### 5.3 Other errors

| Error | When |
|---|---|
| `nesting depth limit reached` | The depth limit is reached, see 4.1. |
| `not enough C stack left for a nested wait` | Too little free stack, see 4.1. |
| `aborted because the script is exiting` | The script called `process.exit()` while this wait was running, see 6. |
| `aborted because thread is exiting` | The chain stops. |
| `cannot wait on empty set` | Windows only. There is nothing to wait for. |

### 5.4 Nested waits end in reverse order

Waits end from the inside to the outside.

Example: the outer wait is for child A. Inside it, a handler waits for child B. Child A exits first.

1. A's `'exit'` event fires at once.
2. The outer wait is marked as ended.
3. But the outer `waitExit()` call returns only after the inner wait for B returns.

This cannot be avoided with nested loops on one thread. An outer wait can therefore take longer than its own timeout. The inner wait's timeout limits this. Only a wait with no time limit, `-1` or `0`, can keep the outer wait open for a long time.

## 6. `process.exit()` inside a wait

`process.exit()` does not stop the agent at once. It starts a timer that destroys the script engine later.

When a wait is running, that timer runs inside the wait's loop. Before this fix, the engine was destroyed while the wait was still active. The wait then tried to throw an error on a destroyed engine, and the agent crashed.

Now the exit timer first calls `ILibChain_AbortContinues()`. This marks every active continuation as ended and aborted. Each wait throws `aborted because the script is exiting`, and the C stack unwinds. The timer then starts again. The engine is destroyed only when no wait is active. Each round ends at least one level, so this finishes within the depth limit.

## 7. Child exit on POSIX

On Linux, macOS and the BSDs, the agent learns about a child's exit in two ways.

1. **Pipe close.** The child's stdout and stderr pipes close. The agent then calls `waitpid()` to get the exit status.
2. **SIGCHLD.** The kernel sends SIGCHLD. A signal handler writes a message to an internal pipe. The event loop reads it and calls `waitpid()`.

The first path that collects the status reports the `'exit'` event. Testing with many children at once found these defects, which are now fixed.

| Defect | Effect | Fix |
|---|---|---|
| The pipe-close `waitpid()` did not repeat on `EINTR`. | The pipes can close before the child has fully exited. The child's own SIGCHLD then interrupts `waitpid()`. On FreeBSD and OpenBSD the call returns -1. The unset status was used as the exit code, for example 0 or 121 instead of 5. | Start `status` at 0 and repeat `waitpid()` while it fails with `EINTR`. |
| The SIGCHLD path gave the raw status to the `'exit'` event. | `exit 5` was reported as 1280. | Convert the status with `WEXITSTATUS()`. |
| The pipe-close path could reap the same child twice, once for each pipe. | A second `waitpid()` could block on a new child that got the same pid. | Clear the exit handler before `waitpid()`. |
| `SoftKill()` and the SIGCHLD path used a blocking `waitpid()`. | The same risk of blocking on a reused pid. | Use `WNOHANG`. |
| A closed pipe stayed in the pipe list until the next loop pass. | A new pipe could get the same file descriptor number. The event was then given to the old pipe, and the new child's exit was lost. | Remove the pipe from the list at once. |
| The pipe list walk stopped when a continuation ended. | Pipes of other waits were not served in that loop pass. | Serve every pipe. Start the walk again when a handler changed the list. |
| The SIGCHLD message read asked for the full message length a second time. | It read the start of the next message. The message stream was broken after that. | Read only the remaining part. |

On macOS, `WEXITSTATUS()` needs a variable as its argument, because the macro takes the address of its argument. So the code stores the status in a local variable first.

## 8. Timer precision

The wait timeout uses `ILibGetUptime()`, the same millisecond clock as `setTimeout()`. Two related defects are fixed in a separate commit.

1. **The clock.** On POSIX, `ILibGetUptime()` returned `(tv_nsec / 1000) % 1000` as the millisecond part. That is the microseconds inside the current millisecond, not the milliseconds. The clock advanced only once per second, and timers fired too early or too late. The value is now `tv_nsec / 1000000`.
2. **The 1000 ms minimum.** `ILibLifeTime_Check()` did not let `select()` sleep less than 1000 ms. So every timer shorter than one second fired up to one second late. The minimum is now 1 ms.

Measured after the fix: `setTimeout(100)` fires after about 101 ms in the main loop and after about 103 ms inside a wait.

On macOS, and on builds that define `_MIPS`, `ILibGetUptime()` still has whole-second precision.

## 9. Windows notes

`waitExit()` passes the child's process and pipe handles to `ILibChain_Continue()`. An inner wait does not know the outer child's handles. The outer child's exit is still detected, because the agent also adds every child's handles to the chain-wide wait list, and every loop, nested or not, uses that list.

Windows x64 Release and Debug pass all tests. The Debug build reports 993 KB of free stack at the start, which is the default 1 MB stack, and uses about 13 KB per nested level. So 16 levels use about 200 KB, and the free-stack check does not limit nesting on Windows.

## 10. Tests

`test/waitExitTest.js` checks:

1. A wait inside another wait, started from a timer.
2. The timeout throws after about the requested time.
3. A late exit of a timed-out child does not end a later wait.
4. `waitExit(-1)` waits for the full child run.
5. `waitExit(0)` waits for the full child run. Before the fix, it did not sleep in `select()` and used 100% CPU.
6. `waitExit()` on a child that has already exited returns at once.
7. Two waits on the same child both end when the child exits.
8. `promise.wait()` inside `waitExit()`.
9. A child agent calls `process.exit(3)` from a timer two waits deep. It must end with exit code 3, and no wait may return normally.
10. 16 nested waits work, and the 17th throws `nesting depth limit reached`.
11. A normal wait works after all nested waits have ended.

When check 1 fails, it prints extra details: the exit code, the number of `'exit'` events, and whether the child still exists.

Run it from the repository root:

```bash
./meshagent_x86-64 test/waitExitTest.js
```

On Windows, give the full path of the script. The agent changes its working directory to the folder of the `.exe` before it opens the script, so a relative path does not work:

```powershell
.\build\win-x64-Release\MeshConsole64.exe D:\repos\ma-makeover-v2\test\waitExitTest.js
```

Results on 2026-09-15:

| Platform | Result |
|---|---|
| Linux x86-64, glibc | 20 of 20 runs passed, stress module passed |
| Linux x86-64, musl (Alpine) | 20 of 20 runs passed |
| Linux x86, glibc | (Debug) 20 of 20 runs passed |
| FreeBSD x86-64 | 20 of 20 runs passed |
| OpenBSD x86-64 | 20 of 20 runs passed |
| macOS arm64 | 20 of 20 runs passed |
| Windows x64 | 20 of 20 runs passed, stress test module passed |
| Windows x86 | (Debug) 20 of 20 runs passed, stress test module passed |
| Linux riscv32, under qemu | 20 of 20 runs passed, stress test module passed |
