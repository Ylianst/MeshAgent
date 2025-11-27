# win-tasks.js

Provides Windows Task Scheduler management through COM interface (ITaskService). Enables creation, execution, and deletion of scheduled tasks with user context support, trigger configuration, and action execution.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support

**Excluded Platforms:**
- **macOS** - Not supported (Windows-only)
- **Linux** - Not supported (Windows-only)
- **FreeBSD** - Not supported (Windows-only)

**Exclusion Reasoning:**

Windows-specific module requiring Windows APIs/DLLs unavailable on other platforms.

**Platform Notes:**

**win-tasks.js is Windows-only** because:

1. **Task Scheduler COM API** - ITaskService interface specific to Windows
2. **OleAut32.dll Dependency** - Windows OLE Automation
3. **Scheduled Task Model** - Windows task scheduling infrastructure

---

## Functionality

### Core Purpose

win-tasks.js manages scheduled tasks:

1. **Task Creation** - Create one-time or recurring tasks
2. **Task Execution** - Run task immediately
3. **Task Deletion** - Remove task
4. **User Context** - Schedule as specific user

### Main Operations

1. **addTask(task)** - Create scheduled task
2. **getTask(options)** - Get task reference
3. **deleteTask(taskName)** - Delete task
4. **run()** - Execute task

---

## Task Object Structure

**Required Properties:**
```javascript
{
    name: 'TaskName',      // Task name
    user: 'username',      // User to run as
    domain: 'domain',      // Domain (optional)
    execPath: process.execPath,   // Executable path
    arguments: ['-args']   // Command arguments
}
```

---

## Dependencies

### Native DLLs - Lines 65-73

**OleAut32.dll Methods:**
- SafeArrayAccessData() - Access array data
- SafeArrayCreate() - Create array
- SafeArrayCreateVector() - Create vector array
- SafeArrayPutElement() - Add array element
- SafeArrayDestroy() - Release array
- VariantClear() - Clear variant
- VariantInit() - Initialize variant
- SysAllocString() - Allocate string

### Module Dependencies

**require('win-com')**
- createInstance() - Create COM objects
- marshalFunctions() - Create callable interfaces
- CLSIDFromString() - Convert CLSID
- IID_IUnknown - Base interface

### COM Interfaces

**ITaskService** - Main scheduler interface
**ITaskFolder** - Task folder operations
**ITaskDefinition** - Task configuration
**IPrincipal** - User context
**ITriggerCollection** - Triggers
**IActionCollection** - Actions
**IExecAction** - Executable action

---

## Constants - Lines 18-63

### Task Logon Types:
- TASK_LOGON_NONE (0)
- TASK_LOGON_PASSWORD (1)
- TASK_LOGON_S4U (2)
- TASK_LOGON_INTERACTIVE_TOKEN (3)
- TASK_LOGON_GROUP (4)
- TASK_LOGON_SERVICE_ACCOUNT (5)
- TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD (6)

### Task Trigger Types:
- TASK_TRIGGER_EVENT (0)
- TASK_TRIGGER_TIME (1)
- TASK_TRIGGER_DAILY (2)
- TASK_TRIGGER_WEEKLY (3)
- TASK_TRIGGER_MONTHLY (4)
- TASK_TRIGGER_LOGON (9)

### Task Flags:
- TASK_CREATE (0x2)
- TASK_UPDATE (0x4)
- TASK_CREATE_OR_UPDATE (0x6)

---

## Key Functions

### ConvertStringArray(strarr) - Lines 79-109

**Purpose:** Convert string array to COM VARIANT array

**Parameters:**
- strarr - JavaScript string array

**Returns:** VARIANT structure containing BSTR array

**Process:**
1. Creates SafeArray of BSTR (line 89)
2. For each string:
   - Allocates BSTR via SysAllocString()
   - Stores in array via SafeArrayPutElement()
3. Returns VARIANT wrapping array

---

## Error Handling

1. **SafeArray Creation Failure** - Throws 'Error creating SafeArray'
2. **COM Operation Failures** - Check return values from COM calls

---

## Technical Notes

### Task Scheduler Model

- Root folder holds all tasks
- Tasks have triggers (when to run) and actions (what to run)
- Principal defines user context
- Settings control task behavior

### User Context Execution

Tasks run with:
- Username (required)
- Domain (optional, defaults to local)
- LogonType defines authentication method

### COM Threading

- Thread-safe COM operations
- Proper ref counting with AddRef/Release
- Cleanup on object finalization

---

## Usage Examples

### Create and Run Task

```javascript
var tasks = require('win-tasks');
tasks.addTask({
    name: 'MyTask',
    user: 'username',
    domain: 'domain',
    execPath: 'C:\\path\\to\\app.exe',
    arguments: ['-flag']
});

var task = tasks.getTask({ name: 'MyTask' });
task.run();
```

### Delete Task

```javascript
tasks.deleteTask('MyTask');
```

---

## Summary

win-tasks.js provides Windows Task Scheduler access through COM interfaces. The module enables task creation with user context, immediate execution, and cleanup. Proper VARIANT handling and COM ref counting ensure robust task scheduling operations.
