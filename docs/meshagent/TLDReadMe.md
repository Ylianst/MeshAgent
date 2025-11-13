# macOS MeshAgent: TL;DR Edition

> *"Too Long; Didn't Read" - The quick reference for humans who have things to do*

## The 30-Second Explanation

macOS MeshAgent uses **TWO services** (LaunchDaemon + LaunchAgent) with a **dynamic naming system** (serviceId) that lets you run **multiple instances** without them fighting each other.

**When MeshCentral updates your agent, it auto-runs `-upgrade`** to recreate the service plists. You probably won't need to touch it.

**Most important thing:** The serviceId comes from `companyName` and `meshServiceName`, and determines EVERYTHING (plist names, socket paths, service labels).

---

## Table of Contents

- [What You Actually Need to Know](#what-you-actually-need-to-know)
- [The serviceId Calculator](#the-serviceid-calculator)
- [Common Tasks (Copy-Paste Ready)](#common-tasks-copy-paste-ready)
- [The Two Services Explained](#the-two-services-explained)
- [When Things Break](#when-things-break)
- [Diagnostic One-Liners](#diagnostic-one-liners)
- [Fun Facts](#fun-facts)

---

## What You Actually Need to Know

### The Core Concepts (In Order of Importance)

**1. Two Services, Not One**
- **LaunchDaemon** = Main service (runs as root, always on)
- **LaunchAgent** = KVM helper (runs in user session, on-demand)
- Both needed for full functionality

**2. serviceId Controls Everything**
```
serviceId = "meshagent" + optional(".serviceName") + optional(".companyName")
```
Examples:
- `meshagent` (default)
- `meshagent.acme` (company only)
- `meshagent.tactical` (service only)
- `meshagent.tactical.acme` (both)

**3. Auto-Upgrade During Updates**
When MeshCentral pushes an update, the agent automatically runs:
```bash
./meshagent -upgrade
```
This recreates both plists with the correct --serviceId parameter.

**You don't manually run -upgrade during server updates. It's automatic.**

**4. Multi-Instance Support**
Different serviceIds = different installations = no conflicts
```bash
meshagent.production.acme    # Production
meshagent.staging.acme       # Staging
meshagent.development.acme   # Development
# All run simultaneously ✓
```

---

## The serviceId Calculator

**Use this flowchart to predict your serviceId:**

```
Do you have companyName?
├─ YES ──> Do you have custom serviceName?
│          ├─ YES ──> meshagent.{serviceName}.{companyName}
│          └─ NO  ──> meshagent.{companyName}
│
└─ NO ───> Do you have custom serviceName?
           ├─ YES ──> meshagent.{serviceName}
           └─ NO  ──> meshagent
```

### Quick Examples

| Input | Output |
|-------|--------|
| serviceName: (none)<br>companyName: (none) | `meshagent` |
| serviceName: (none)<br>companyName: "ACME Corp" | `meshagent.acme-corp` |
| serviceName: "Tactical"<br>companyName: (none) | `meshagent.tactical` |
| serviceName: "Tactical"<br>companyName: "ACME Corp" | `meshagent.tactical.acme-corp` |

**Remember:** Special characters get sanitized (removed), spaces become hyphens, everything lowercase.

---

## Common Tasks (Copy-Paste Ready)

### Install Agent

```bash
# Standard installation (downloads config from MeshCentral)
sudo ./meshagent -fullinstall \
  --url="https://mesh.example.com/agent.ashx?id=xxxxx"

# Custom serviceId
sudo ./meshagent -fullinstall \
  --url="https://mesh.example.com/agent.ashx?id=xxxxx" \
  --companyName="acme" \
  --installPath=/opt/tacticalmesh/
```

### Check What's Running

```bash
# List all meshagent services
sudo launchctl print system | grep meshagent

# Check specific service
sudo launchctl print system/meshagent.tacticalmesh

# See running processes
ps aux | grep meshagent

# Where's the binary?
sudo lsof -p $(pgrep meshagent) | grep meshagent
```

### Upgrade/Repair Service

```bash
# Recreate plists (fixes broken configs)
sudo /opt/tacticalmesh/meshagent -upgrade

# Change serviceId (rename service)
sudo /opt/tacticalmesh/meshagent -upgrade \
  --meshServiceName=production \
  --companyName=acme
```

### Uninstall

```bash
# Remove everything
sudo ./meshagent -fulluninstall

# Custom service
sudo ./meshagent -fulluninstall \
  --companyName=tacticalmesh
```

### Restart Service

```bash
# Method 1: Unload/load
sudo launchctl unload /Library/LaunchDaemons/meshagent.plist
sudo launchctl load /Library/LaunchDaemons/meshagent.plist

# Method 2: Kickstart (preferred)
sudo launchctl kickstart -k system/meshagent
```

### View Logs

```bash
# Recent activity
sudo log show --predicate 'process == "meshagent"' --last 1h

# Errors only
sudo log show --predicate 'process == "meshagent"' --level error --last 24h

# Streaming (like tail -f)
sudo log stream --predicate 'process == "meshagent"'
```

---

## The Two Services Explained

### LaunchDaemon (The Workhorse)

**File:** `/Library/LaunchDaemons/{serviceId}.plist`

**What it does:**
- Main agent service
- Connects to MeshCentral server
- Handles remote management
- Runs as root
- Always running (KeepAlive=true)

**Key plist contents:**
```xml
<key>Label</key>
<string>meshagent.tacticalmesh</string>

<key>ProgramArguments</key>
<array>
    <string>/opt/tacticalmesh/meshagent</string>
    <string>--serviceId=meshagent.tacticalmesh</string>  ← IMPORTANT
</array>
```

### LaunchAgent (The KVM Helper)

**File:** `/Library/LaunchAgents/{serviceId}-agent.plist`

**What it does:**
- KVM (remote desktop) functionality
- Runs in user session
- Starts on-demand (QueueDirectories magic)
- Not always running (KeepAlive=false)

**Key plist contents:**
```xml
<key>Label</key>
<string>meshagent.tacticalmesh-agent</string>

<key>ProgramArguments</key>
<array>
    <string>/opt/tacticalmesh/meshagent</string>
    <string>-kvm1</string>                                    ← KVM mode
    <string>--serviceId=meshagent.tacticalmesh</string>
</array>

<key>QueueDirectories</key>
<array>
    <string>/var/run/meshagent.tacticalmesh</string>         ← Magic trigger
</array>
```

**QueueDirectories magic:**
When a file appears in `/var/run/{serviceId}/`, launchd automatically starts the LaunchAgent.
This is how the main service tells the KVM helper "I need you now!"

---

## When Things Break

### Problem: "Service won't start"

**Quick fix:**
```bash
# Check plist syntax
sudo plutil -lint /Library/LaunchDaemons/meshagent.plist

# Check permissions
ls -l /Library/LaunchDaemons/meshagent.plist
# Should be: -rw-r--r-- root:wheel

# Fix permissions
sudo chown root:wheel /Library/LaunchDaemons/meshagent.plist
sudo chmod 644 /Library/LaunchDaemons/meshagent.plist

# Force reload
sudo launchctl unload /Library/LaunchDaemons/meshagent.plist
sudo launchctl load /Library/LaunchDaemons/meshagent.plist
```

### Problem: "KVM doesn't work"

**Quick checks:**
```bash
# Is LaunchAgent loaded?
launchctl print gui/$(id -u)/meshagent-agent

# Does socket directory exist?
ls -ld /var/run/meshagent/
# Should be: drwxr-xr-x root:wheel

# Create if missing
sudo mkdir -p /var/run/meshagent
sudo chmod 755 /var/run/meshagent

# Manually trigger (test)
touch /var/run/meshagent/test.trigger
ps aux | grep "kvm1"  # Should see process start
```

### Problem: "Multiple services running"

**Quick fix:**
```bash
# List all meshagent plists
ls -1 /Library/LaunchDaemons/meshagent*.plist

# Unload the extras
sudo launchctl unload /Library/LaunchDaemons/meshagent.old.plist
sudo rm /Library/LaunchDaemons/meshagent.old.plist

# Or use -upgrade to auto-clean
sudo /opt/tacticalmesh/meshagent -upgrade
```

### Problem: "Wrong serviceId / Service renamed"

**Quick fix:**
```bash
# Just run -upgrade with new config
sudo /opt/tacticalmesh/meshagent -upgrade \
  --meshServiceName=newservice \
  --companyName=newcompany

# It will:
# 1. Clean up old plists
# 2. Create new plists with new serviceId
# 3. Update socket paths
```

### Problem: "Can't find installation"

**Quick debug:**
```bash
# Where is it running from?
sudo lsof -p $(pgrep meshagent) | grep meshagent

# What's in LaunchDaemon?
sudo plutil -p /Library/LaunchDaemons/meshagent.plist | grep -A 5 ProgramArguments

# Check default path
ls -la /usr/local/mesh_services/meshagent/

# Override with --installPath
sudo ./meshagent -upgrade --installPath=/path/to/actual/location/
```

---

## Diagnostic One-Liners

### Is it running?
```bash
pgrep meshagent && echo "YES" || echo "NO"
```

### What serviceId am I using?
```bash
sudo plutil -p /Library/LaunchDaemons/meshagent*.plist | grep -A 1 Label
```

### Where's the binary?
```bash
sudo lsof -p $(pgrep meshagent) | awk '/meshagent$/ {print $9}' | head -1
```

### What's the config?
```bash
grep -E "MeshServiceName|CompanyName" /opt/tacticalmesh/meshagent.msh
```

### Is launchd happy?
```bash
sudo launchctl print system/meshagent 2>&1 | grep -E "state|pid"
```

### Database peek
```bash
/opt/tacticalmesh/meshagent -exec "var db=require('SimpleDataStore').Create('./meshagent.db'); console.log('ServiceName:', db.Get('meshServiceName')); console.log('Company:', db.Get('companyName')); process.exit(0);"
```

### Clean slate (nuclear option)
```bash
# DANGER: This removes EVERYTHING
sudo launchctl unload /Library/LaunchDaemons/meshagent*.plist
sudo launchctl unload /Library/LaunchAgents/meshagent*.plist
sudo rm /Library/LaunchDaemons/meshagent*.plist
sudo rm /Library/LaunchAgents/meshagent*.plist
sudo rm -rf /usr/local/mesh_services/meshagent/
sudo rm -rf /var/run/meshagent*
# Now reinstall from scratch
```

---

## Fun Facts

### Did You Know?

**"Why QueueDirectories instead of KeepAlive?"**
- Resource efficiency! KVM helper only runs when needed
- KeepAlive=true would waste CPU/memory when no one's watching
- QueueDirectories = "Wake up when I create a file" (smart!)

**"Can I run multiple instances?"**
- YES! Different serviceIds = different installations
- Common use case: production vs staging vs development
- Each has separate configs, separate sockets, separate everything

**"What happens if I delete the .msh file?"**
- Agent keeps running (config is in .db database)
- But -upgrade will auto-migrate it back from plist/db
- Plist is the "source of truth" for serviceId

**"Why --serviceId in ProgramArguments?"**
- Agent needs to know its identity when it starts
- Used for socket paths, service management
- Survives reboots, updates, everything

**"What's the actual difference between serviceName and companyName?"**
- Technically? Nothing. Both are just strings.
- Conceptually? serviceName = what it is, companyName = who owns it
- In practice? Use whatever makes sense for your organization

**"Can I change serviceId without reinstalling?"**
- YES! That's what -upgrade is for
- `sudo ./meshagent -upgrade --companyName=newcompany`
- Old plists deleted, new plists created, same binary

**"Why does MeshCentral auto-call -upgrade?"**
- Ensures plists always have correct --serviceId parameter
- Fixes any plist corruption during update
- Handles QueueDirectories path updates
- Keeps LaunchAgent in sync with LaunchDaemon

---

## File Location Quick Reference

### Plist Files
```
/Library/LaunchDaemons/{serviceId}.plist          ← Main service
/Library/LaunchAgents/{serviceId}-agent.plist     ← KVM helper
```

### Installation Files
```
{installPath}/meshagent                           ← Binary
{installPath}/meshagent.db                        ← Database
{installPath}/meshagent.msh                       ← Config file
{installPath}/.meshagent.backup.{timestamp}       ← Backup (after update)
```

### Socket/Queue Directory
```
/var/run/{serviceId}/                             ← IPC directory
```

### Common Install Paths
```
/usr/local/mesh_services/meshagent/               ← Default
/opt/tacticalmesh/                                ← TacticalRMM common
/opt/mesh/                                        ← Alternative
```

---

## Decision Tree: Which Command Do I Need?

### "I want to install MeshAgent"
```
Do you have a MeshCentral invite URL?
├─ YES ──> sudo ./meshagent -fullinstall --url="..."
└─ NO  ──> Get URL from MeshCentral first
```

### "MeshCentral sent an update"
```
Do nothing! It auto-runs -upgrade for you.
```

### "My plists are broken/missing"
```bash
sudo /path/to/meshagent -upgrade
```

### "I want to change the serviceId"
```bash
sudo /path/to/meshagent -upgrade \
  --meshServiceName=new \
  --companyName=new
```

### "I want to completely remove it"
```bash
sudo ./meshagent -fulluninstall
```

### "I have multiple copies and I'm confused"
```bash
# List everything
ls -1 /Library/LaunchDaemons/meshagent*.plist
ls -1 /Library/LaunchAgents/meshagent*.plist

# Run -upgrade to clean up orphans
sudo /path/to/meshagent -upgrade
```

---

## The "I'm In A Hurry" Checklist

**Installation:**
- [ ] Got MeshCentral invite URL?
- [ ] Running as root? (`sudo`)
- [ ] Picked serviceId (companyName/serviceName)?
- [ ] Run: `sudo ./meshagent -fullinstall --url="..."`
- [ ] Check: `sudo launchctl print system/meshagent`

**Troubleshooting:**
- [ ] Is it running? `pgrep meshagent`
- [ ] Check logs: `sudo log show --predicate 'process == "meshagent"' --last 30m`
- [ ] Plists exist? `ls /Library/LaunchDaemons/meshagent*.plist`
- [ ] Plists valid? `sudo plutil -lint /Library/LaunchDaemons/meshagent.plist`
- [ ] Try: `sudo /path/to/meshagent -upgrade`

**Cleanup:**
- [ ] Unload services first: `sudo launchctl unload /Library/LaunchDaemons/meshagent.plist`
- [ ] Delete plists: `sudo rm /Library/LaunchDaemons/meshagent*.plist`
- [ ] Delete install dir: `sudo rm -rf /opt/tacticalmesh/`
- [ ] Delete socket dir: `sudo rm -rf /var/run/meshagent*`

---

## The serviceId Cheat Sheet (Printable)

```
┌─────────────────────────────────────────────────────────────┐
│ serviceId Quick Reference                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Inputs:                                                    │
│  • meshServiceName (or serviceName)                         │
│  • companyName                                              │
│                                                             │
│  Rules:                                                     │
│  1. Spaces → hyphens                                        │
│  2. Special chars → removed                                 │
│  3. Uppercase → lowercase                                   │
│  4. "meshagent" serviceName = treated as (none)             │
│                                                             │
│  Formula:                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ IF companyName:                                     │   │
│  │   IF serviceName (not "meshagent"):                 │   │
│  │     → meshagent.{service}.{company}                 │   │
│  │   ELSE:                                             │   │
│  │     → meshagent.{company}                           │   │
│  │ ELSE IF serviceName (not "meshagent"):              │   │
│  │   → meshagent.{service}                             │   │
│  │ ELSE:                                               │   │
│  │   → meshagent                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Examples:                                                  │
│  • (none, none)        → meshagent                          │
│  • (none, "ACME")      → meshagent.acme                     │
│  • ("prod", none)      → meshagent.prod                     │
│  • ("prod", "ACME")    → meshagent.prod.acme                │
│                                                             │
│  This determines:                                           │
│  ✓ LaunchDaemon: /Library/LaunchDaemons/{serviceId}.plist  │
│  ✓ LaunchAgent: /Library/LaunchAgents/{serviceId}-agent... │
│  ✓ Socket dir: /var/run/{serviceId}/                       │
│  ✓ Service label in launchctl                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## When to Read the Full Docs

**You probably need the detailed docs if:**
- You're setting up multiple instances on one machine
- You're debugging upgrade failures
- You're writing automation/deployment scripts
- You're contributing code to the project
- You're curious how QueueDirectories actually works
- You want to understand the configuration priority chain
- You're investigating weird edge cases

**Full documentation:**
- [architecture.md](./architecture.md) - Deep dive into LaunchDaemon/LaunchAgent design
- [naming-and-configuration.md](./naming-and-configuration.md) - serviceId calculation details
- [installation-functions.md](./installation-functions.md) - Complete function reference

**You probably DON'T need the full docs if:**
- You just want to install MeshAgent → Use `-fullinstall`
- MeshCentral sent an update → Does it automatically
- You want to uninstall → Use `-fulluninstall`
- Everything is working → Leave it alone!

---

## Emergency Contact

**Things are REALLY broken and nothing works:**

1. **Collect diagnostics:**
   ```bash
   # Save to file
   {
     echo "=== Services ==="
     sudo launchctl print system | grep meshagent
     echo ""
     echo "=== Processes ==="
     ps auxww | grep meshagent
     echo ""
     echo "=== Plists ==="
     ls -l /Library/LaunchDaemons/meshagent*.plist
     ls -l /Library/LaunchAgents/meshagent*.plist
     echo ""
     echo "=== Logs (last 1h) ==="
     sudo log show --predicate 'process == "meshagent"' --last 1h
   } > ~/meshagent-diagnostics.txt
   ```

2. **Try nuclear option:**
   ```bash
   # Complete removal
   sudo ./meshagent -fulluninstall

   # Clean up any remnants
   sudo rm -rf /Library/LaunchDaemons/meshagent*.plist
   sudo rm -rf /Library/LaunchAgents/meshagent*.plist
   sudo rm -rf /var/run/meshagent*

   # Fresh install
   sudo ./meshagent -fullinstall --url="..."
   ```

3. **Check MeshCentral server**
   - Can you reach the server? `ping mesh.example.com`
   - Is the invite URL still valid?
   - Check server logs for connection attempts

4. **GitHub Issues**
   - https://github.com/Ylianst/MeshAgent/issues
   - Include diagnostics from step 1
   - Mention macOS version and serviceId

---

## TL;DR of the TL;DR

- **Two services:** LaunchDaemon (main) + LaunchAgent (KVM)
- **serviceId = naming system:** Lets you run multiple installations
- **Auto-upgrade:** MeshCentral updates trigger automatic `-upgrade`
- **Common command:** `sudo ./meshagent -fullinstall --url="..."`
- **When broken:** `sudo /path/to/meshagent -upgrade`
- **Full docs:** Read [architecture.md](./architecture.md) if you need details

**Most common mistake:** Forgetting to run commands with `sudo` (needs root)

**Most confusing thing:** Two services instead of one (but it makes sense - read architecture.md)

**Most useful command:** `sudo /path/to/meshagent -upgrade` (fixes most config issues)

**Most important file:** The LaunchDaemon plist (it's the "source of truth")

---

*Last Updated: 2025-11-10*
*TL;DR Documentation Version: 1.0*
*For the full story, see the other docs. For the quick version, you're already here!*
