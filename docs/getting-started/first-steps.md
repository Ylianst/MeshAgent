# First Steps

After installing and connecting MeshAgent, here are the first five things to do to get the most out of the platform.

---

## 1. Verify Agent Identity and Connectivity

Confirm the agent has generated its identity and established a connection to your management server.

### Check the log file

```bash
tail -f meshcentral-agent.log
```

Look for lines confirming a successful TLS handshake and authentication:

```text
INFO Connecting to wss://your-server.example.com/agent.ashx
INFO WebSocket upgrade successful
INFO AuthVerify sent
INFO AuthConfirm received — agent online
```

### Inspect the identity database

The agent stores its certificate and node ID in `meshagent.db`. You can verify it exists:

```bash
ls -la meshagent.db
```

If this file is present and non-empty, the agent has successfully generated its identity. Do not delete `meshagent.db` — it contains the unique certificate that identifies this agent to your server.

---

## 2. Review and Harden File Permissions

MeshAgent stores sensitive configuration and identity data. After installation, verify and correct file permissions using the built-in security utilities.

### Critical files and their required permissions

| File | Permission | Reason |
|---|---|---|
| `meshagent.msh` | `0600` (owner read/write only) | Contains server URL and mesh credentials |
| `meshagent.db` | `0600` (owner read/write only) | Contains agent private key and certificate |
| `meshagent` (binary) | `0755` | Executable by all |
| `meshcentral-agent.log` | `0644` | Readable for diagnostics |

### Verify permissions manually

```bash
ls -la meshagent.msh meshagent.db meshagent
```

### Fix permissions

```bash
chmod 600 meshagent.msh meshagent.db
chmod 755 meshagent
```

> **Note:** On macOS, the agent bundle directory also requires `0755`. Verify using the `security-permissions.js` module if you are running from a JavaScript-driven installer context.

---

## 3. Configure Logging

MeshAgent logs to both the console and a rotating log file (`meshcentral-agent.log`). The default log level is `INFO`.

### Adjust the log level via the JavaScript logger

If you are using the agent's JavaScript module layer, you can change verbosity:

```javascript
const logger = require('./modules/logger');

// Enable verbose debug output
logger.setLevel('DEBUG');

// Or silence to warnings and errors only
logger.setLevel('WARN');
```

### Log rotation behavior

Logs rotate automatically when `meshcentral-agent.log` exceeds **10 MB**. The previous log is compressed to `meshcentral-agent.log.old.gz`. Only one archive is kept at a time.

To direct logs to a specific directory, call `enable_file_logging` with the target path when starting the agent from C:

```c
enable_file_logging("/var/log/meshagent", NULL);
```

---

## 4. Explore the JavaScript Module System

MeshAgent includes an embedded Duktape JavaScript engine with a rich library of platform modules in the `modules/` directory. These are the primary extension point for automation and customization.

### Key modules to know

| Module | Path | Purpose |
|---|---|---|
| `agent-installer` | `modules/agent-installer.js` | Install/manage the agent as a system service |
| `logger` | `modules/logger.js` | Structured log output |
| `security-permissions` | `modules/security-permissions.js` | File permission management |
| `service-manager` | `modules/service-manager.js` | Manage the agent service on all platforms |
| `update-helper` | `modules/update-helper.js` | Handle ZIP-compressed OTA updates |
| `daemon` | `modules/daemon.js` | Daemonize the agent process |
| `power-monitor` | `modules/power-monitor.js` | Monitor device power state |
| `wifi-scanner` | `modules/wifi-scanner.js` | Scan for nearby Wi-Fi networks |

### Parse the `.msh` configuration in scripts

```javascript
const installer = require('./modules/agent-installer');

// Read and parse the agent configuration
const msh = installer.parseMshFile('./meshagent.msh');
console.log('Connected to:', msh.MeshServer);
console.log('Mesh ID:', msh.MeshID);
```

### Update `.msh` configuration keys without rewriting the file

```javascript
installer.updateMshFile('./meshagent.msh', {
    Tag: 'production',
    MeshName: 'My Device Fleet'
});
```

---

## 5. Review the Self-Update Configuration

MeshAgent supports secure over-the-air self-updates. Understanding how this works prevents unintended upgrades or breakage.

### How self-update works

1. The management server sends an **agent hash** command with the expected binary hash
2. MeshAgent compares the hash against its own binary
3. If a mismatch is detected, the server sends the new binary
4. The agent verifies the **digital signature** (`signcheck_verifysign`) before applying the update
5. The binary is replaced in-place, and the agent restarts

### Disable automatic updates (optional)

To prevent the agent from self-updating (useful in locked-down environments):

Set `disableUpdate=1` in your `meshagent.db` key-value store, or pass it as a configuration flag. Refer to your environment configuration for the exact mechanism supported by your management server.

### Manual update preparation

The `update-helper.js` module handles ZIP-compressed update packages:

```javascript
const updateHelper = require('./modules/update-helper');

updateHelper.start('/path/to/new-meshagent.zip')
  .then(function(result) {
    if (result === 'done') {
      console.log('Update binary extracted and ready');
    }
  })
  .catch(function(err) {
    console.error('Update preparation failed:', err);
  });
```

---

## Where to Get Help

- **OpenMSP Community Slack:** [https://www.openmsp.ai/](https://www.openmsp.ai/) — Join for technical support, discussion, and announcements
- **Flamingo Platform:** [https://flamingo.run](https://flamingo.run)
- **OpenFrame:** [https://openframe.ai](https://openframe.ai)
- **Source Code:** [https://github.com/flamingo-stack/meshagent](https://github.com/flamingo-stack/meshagent)

---

## Quick Reference Card

| Task | Command / File |
|---|---|
| View live logs | `tail -f meshcentral-agent.log` |
| Check agent identity | `ls -la meshagent.db` |
| Fix `.msh` permissions | `chmod 600 meshagent.msh` |
| Fix `.db` permissions | `chmod 600 meshagent.db` |
| Enable debug logging | `logger.setLevel('DEBUG')` in JS modules |
| Parse `.msh` config | `installer.parseMshFile('./meshagent.msh')` |
| Disable auto-updates | Set `disableUpdate=1` in agent config |
