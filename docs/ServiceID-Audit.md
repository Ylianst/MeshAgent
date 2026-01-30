# ServiceId Derivation — Exhaustive Audit

## What is serviceId?

A machine-readable identifier that uniquely names a MeshAgent installation on macOS. It drives:
- LaunchDaemon/LaunchAgent plist filenames and `Label` fields
- Unix domain socket path (`/tmp/{serviceId}.sock`)
- QueueDirectories path (`/var/run/{serviceId}/`)
- Session signal file (`/var/run/{serviceId}/session-active`)
- Log file paths (`/tmp/{serviceId}-daemon.log`, `/tmp/{serviceId}-agent.log`)
- Install directory structure (`/usr/local/mesh_services/{company}/{service}/`)
- `launchctl` commands (`launchctl kickstart -k system/{serviceId}`)
- JavaScript runtime property (`require('MeshAgent').serviceId`)
- Service lookup (`require('service-manager').manager.getService(serviceId)`)

---

## Part 1: How serviceId is CREATED (Installation Time — JavaScript)

### Source: `modules/macOSHelpers.js` — `buildServiceId()`

Default: executable base name (e.g., `meshagent`) via `agent-paths.getAgentBaseName()`, passed through `sanitizeIdentifier()`.

If `options.explicitServiceId` is provided, it is returned verbatim.

The `serviceName` and `companyName` parameters are accepted for API compatibility but **ignored** — they no longer contribute to the serviceId. They still affect install directory structure via `service-manager.js`.

### Source: `modules/agent-installer.js` — Resolution priority

**Fresh install / finstall:**

1. `--setServiceID=VALUE` (user-facing flag, mapped to `--serviceId` by `checkParameters()`)
2. `.msh` file key `ServiceID` (or `serviceId`, case-insensitive)
3. Default: `baseName` (executable filename, e.g., `meshagent`)

**Upgrade:**

Without `--setServiceID`: serviceId is inherited from the existing installation. Discovery priority:

1. Existing plist `ProgramArguments` `--serviceId=` value
2. Existing `.msh` file `ServiceID` key
3. Existing `.db` database `ServiceID` key
4. Fallback: `buildServiceId()` → baseName

With `--setServiceID=VALUE`: old plists are cleaned up using the discovered serviceId, then new plists are created with the new value. This effectively renames the service.

**Removed flags:** `--launchdLabel` (was highest-priority override, removed).

**Unchanged flags:** `--meshServiceName`, `--companyName` — still used for install directory structure, but no longer affect serviceId.

### Where serviceId is STORED after installation

| Storage | Key/Field | Example Value |
|---------|-----------|---------------|
| LaunchDaemon plist Label | `<key>Label</key>` | `meshagent` |
| LaunchAgent plist Label | `<key>Label</key>` | `meshagent-agent` |
| `.msh` config file | `ServiceID=` | `meshagent` |
| `.db` database | key `"ServiceID"` | `meshagent` |
| LaunchDaemon ProgramArguments | `--meshServiceName=`, `--companyName=` | (component parts, not composite) |

**Note:** The LaunchAgent Label has `-agent` suffix appended: `{serviceId}-agent`. This is the only place where the suffix is added. The daemon plist Label, database, and .msh all store the **base** serviceId without suffix.

---

## Part 2: How serviceId is LOADED at Runtime (C Layer)

### Context A: Main daemon process (`agentcore.c`)

**Load sequence** in `MeshAgent_Start()` (`agentcore.c:5616-5641`):

```
Step 1: Read database key "ServiceID" → agentHost->serviceID
Step 2: Scan argv for --serviceId=VALUE → overrides Step 1
Result: agentHost->serviceID (may be NULL if neither source has it)
```

The struct field is `MeshAgentHostContainer.serviceID` (`agentcore.h:255`).

**Consumers of `agent->serviceID` in the daemon:**

| Location | Usage |
|----------|-------|
| `agentcore.c:1520` | Passed to `kvm_relay_setup(..., agent->serviceID)` → builds KVM socket/queue paths |
| `agentcore.c:2437-2440` | Exposed to JS as `require('MeshAgent').serviceId` (read-only property) |
| `agentcore.c:5653-5655` | Used for service lookup: `getService(serviceID \|\| meshServiceName).isMe()` |
| `agentcore.c:6961` | Freed in `MeshAgent_Destroy()` |

### Context B: KVM daemon side (`mac_kvm.c`)

**Function: `kvm_relay_setup()`** (`mac_kvm.c:1260`)
- Receives `serviceID` from `agentcore.c`
- Calls `kvm_create_session(serviceID, exePath)`

**Function: `kvm_create_session()`** (`mac_kvm.c:1047`)
- Calls `kvm_build_dynamic_paths(serviceID, exePath)` if paths not yet built

**Function: `kvm_build_dynamic_paths()`** (`mac_kvm.c:533`)
- **Priority 1:** Use `serviceID` parameter directly (from database/CLI)
- **Priority 2:** Call `mesh_plist_find_service_id("/Library/LaunchDaemons", exePath)` — scans for plist with matching `ProgramArguments[0]`, returns its `Label`
- **Fallback:** `"unknown-agent"`

Builds three paths:
```
/tmp/{serviceId}.sock                    ← KVM_Listener_Path
/var/run/{serviceId}/                    ← KVM_Queue_Directory
/var/run/{serviceId}/session-active      ← KVM_Session_Signal_File
```

### Context C: `-kvm1` LaunchAgent process (`main.c`)

**Resolution sequence** (`main.c:1182-1262`):

```
Step 1: Parse argv for --serviceId=VALUE → serviceId
Step 2: If NULL, call mesh_plist_find_service_id("/Library/LaunchAgents", binaryPath)
        — scans for plist with matching ProgramArguments[0]
        — returns its Label (which has -agent suffix!)
Step 3: If NULL, fallback → "unknown-agent"
Step 4: Strip trailing "-agent" suffix (so paths match daemon)
Step 5: Pass to kvm_server_mainloop() → kvm_build_dynamic_paths()
```

**Inside kvm_server_mainloop** (`mac_kvm.c:675`):
- Calls `kvm_build_dynamic_paths(serviceID, exePathToUse)` if `KVM_Listener_Path == NULL`
- This will use Priority 1 (the already-resolved serviceID from main.c)
- Connects to `/tmp/{serviceId}.sock`

---

## Part 3: Every Consumer of serviceId

### Socket/Path Consumers
| Path | Created by | Used by |
|------|-----------|---------|
| `/tmp/{serviceId}.sock` | daemon (`kvm_create_session`) | `-kvm1` connects to it |
| `/var/run/{serviceId}/` | daemon (`kvm_create_session`) | launchd QueueDirectories monitors it |
| `/var/run/{serviceId}/session-active` | daemon (`kvm_create_session`) | launchd starts `-kvm1` when non-empty |

### Plist Consumers
| Plist | Label | ProgramArguments |
|-------|-------|------------------|
| `/Library/LaunchDaemons/{serviceId}.plist` | `{serviceId}` | `[binary, --meshServiceName=X, --companyName=Y]` |
| `/Library/LaunchAgents/{serviceId}-agent.plist` | `{serviceId}-agent` | `[binary, -kvm1, --serviceId={serviceId}]` |

### launchctl Consumers
| Command | Location |
|---------|----------|
| `launchctl kickstart -k system/{serviceId}` | `main.c:1382` (TCC check restart) |
| `launchctl load/unload` | `service-manager.js` (install/uninstall) |

### JavaScript Consumers
| Property/Call | Location |
|---------------|----------|
| `require('MeshAgent').serviceId` | `agentcore.c:2440` (read-only property) |
| `getService(serviceId).isMe()` | `agentcore.c:5655` (service identity check) |

---

## Part 4: Inconsistencies and Surprises Found

### ✅ 1. Two different plist directories scanned (RESOLVED — DRYed)

Both the daemon and `-kvm1` agent need to scan plists to discover their serviceId as a fallback, but they scan different directories (`/Library/LaunchDaemons/` vs `/Library/LaunchAgents/`). Previously this was two near-identical functions. Now both call the shared `mesh_plist_find_service_id(directory, binaryPath)` in `mac_plist_utils.c`, passing the appropriate directory.

### ⚠️ 2. `-agent` suffix stripping uses `strcmp` not `endsWith`

`main.c`: The strip logic uses `strcmp(serviceId + len - 6, "-agent")` which correctly checks only the end. No issues here.

### ✅ 3. Dead code: `parse_service_id()` (RESOLVED — removed)

Was defined in `main.c` but never called. Removed.

### ✅ 4. Dead code: `sanitize_identifier()` in C (RESOLVED — removed)

Was defined in `mac_kvm.c` but never called. All sanitization happens in JavaScript at install time. Removed.

### ⚠️ 5. Database key casing: `"ServiceID"` (capital S, capital ID)

The C code reads `ILibSimpleDataStore_Get(db, "ServiceID", ...)` — note capital "S" and capital "ID". The .msh file uses `ServiceID=`. The JavaScript reads both `config.ServiceID || config.serviceId` (case-insensitive fallback). This is consistent but worth noting — the canonical key is `"ServiceID"`.

### ⚠️ 6. Daemon fallback if `serviceID` is NULL at KVM time

If the daemon has no serviceID (not in database, not on CLI), `kvm_build_dynamic_paths` falls through to Priority 2 (scan LaunchDaemons plist). If that also fails, paths become `/tmp/unknown-agent.sock` etc. This should never happen in practice because the installer always writes ServiceID to .msh → database.

### ⚠️ 7. `-kvm1` fallback `"unknown-agent"` won't match daemon

If `-kvm1` can't resolve serviceId (no `--serviceId=` flag, no plist found), it falls back to `"unknown-agent"`. If the daemon also fell back to `"unknown-agent"`, they'd match. But if the daemon resolved a real serviceId and `-kvm1` couldn't, they'd mismatch. In practice this shouldn't happen because the LaunchAgent plist includes `--serviceId=` in ProgramArguments.

### ✅ 8. `--serviceId=` on LaunchAgent plist ProgramArguments

The installer writes `--serviceId={serviceId}` into the LaunchAgent plist's ProgramArguments (`service-manager.js:3281`). This means `-kvm1` should always get the serviceId via CLI arg (Priority 1), making the plist-scanning fallback (Priority 2) a safety net only.

---

## Part 5: Data Flow Diagram

```
INSTALL TIME (JavaScript):
  --setServiceID (fresh install only) → mapped to --serviceId
  .msh ServiceID
  baseName (default)
           ↓
  agent-installer.js resolves priority chain
           ↓
  macOSHelpers.buildServiceId() returns baseName (or explicitServiceId)
           ↓
  Writes to:
    ├─ .msh file:    ServiceID={serviceId}
    ├─ LaunchDaemon:  Label={serviceId}, ProgramArguments=[binary, --meshServiceName=X, --companyName=Y]
    └─ LaunchAgent:   Label={serviceId}-agent, ProgramArguments=[binary, -kvm1, --serviceId={serviceId}]
                                                                                    ↑ KEY: passes serviceId to -kvm1

DAEMON RUNTIME (C):
  .msh imported into .db → key "ServiceID"
           ↓
  agentcore.c: db.Get("ServiceID") → agentHost->serviceID
  agentcore.c: --serviceId= CLI overrides db value
           ↓
  agentHost->serviceID consumed by:
    ├─ kvm_relay_setup() → kvm_create_session() → kvm_build_dynamic_paths()
    │     → /tmp/{serviceId}.sock (listen)
    │     → /var/run/{serviceId}/ (create)
    │     → /var/run/{serviceId}/session-active (create)
    ├─ JS property: require('MeshAgent').serviceId
    └─ Service lookup: getService(serviceId).isMe()

-KVM1 RUNTIME (C, separate process):
  main.c: --serviceId= from argv (placed there by LaunchAgent plist)
    OR: mesh_plist_find_service_id("/Library/LaunchAgents", ...) → strip -agent suffix
           ↓
  kvm_server_mainloop() → kvm_build_dynamic_paths()
    → /tmp/{serviceId}.sock (connect)
```

---

## Part 6: Cleanup Status

| Item | Status | Resolution |
|------|--------|------------|
| Dead code: `parse_service_id()` in `main.c` | **Removed** | Was never called |
| Dead code: `sanitize_identifier()` in `mac_kvm.c` | **Removed** | Was never called; all sanitization happens in JS |
| Two near-identical plist-scan functions | **DRYed** | Replaced with shared `mesh_plist_find_service_id()` in `mac_plist_utils.c` |
| `-agent` suffix stripping in `main.c` | Works correctly | No change needed |
| `"unknown-agent"` fallback | Safety net only, never hit in practice | No change needed |
