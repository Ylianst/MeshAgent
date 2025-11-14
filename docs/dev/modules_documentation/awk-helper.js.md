# awk-helper.js

Development utility that generates and copies to clipboard a complex AWK script for parsing systemd-logind session information on Linux systems. This is a code generation tool for developers working with session management, not a runtime component of the MeshAgent software.

## Platform

**Supported Platforms:**
- Linux - Primary target (generates loginctl/AWK parsing script)

**Excluded Platforms:**
- **macOS (darwin)** - Not supported
- **Windows (win32)** - Not supported
- **FreeBSD** - Not supported

**Exclusion Reasoning:**

macOS and other platforms are excluded from this utility for several technical reasons:

1. **Linux-Specific Command Dependency** - The generated script uses `loginctl list-sessions`, which is part of systemd-logind and only available on Linux systems with systemd. macOS does not use systemd for session management.

2. **systemd-logind Not on macOS** - macOS uses its own session management system through the Security framework and Open Directory, not systemd's loginctl. The entire premise of the script (parsing loginctl output) is irrelevant on macOS.

3. **Development Tool, Not Runtime Component** - This is a clipboard utility for developers to generate AWK parsing scripts. It's not required for MeshAgent operation. The generated script itself is what would be used in production code.

4. **Platform-Specific Session Management** - Each platform has different session management:
   - **Linux (systemd):** `loginctl list-sessions` with systemd-logind
   - **macOS:** `who` or Security framework APIs for session enumeration
   - **FreeBSD:** `who`, `w`, or login.conf
   - **Windows:** Windows Session Manager via WTS APIs

5. **AWK Script Design** - The AWK script specifically parses the column-based output format of `loginctl list-sessions`, which has a unique structure not found in macOS session commands.

## Functionality

### Purpose

The awk-helper module serves as a development utility to generate a complex command pipeline that:

1. Retrieves all systemd-logind sessions via `loginctl list-sessions`
2. Parses the multi-line columnar output using AWK
3. Filters for regular user sessions (UID >= 1000) with graphical displays
4. Formats the results as a JSON array
5. Copies the complete command to the system clipboard for 5 seconds

This tool is designed for developers who need to:
- Create scripts that enumerate active user sessions
- Parse loginctl output programmatically
- Generate JSON-formatted session data
- Understand AWK parsing techniques for systemd tools

### Generated Command Structure

The module builds a single-line shell command with this structure:

```bash
loginctl list-sessions | tr '\n' '`' | awk '{
    printf "[";
    del="";
    n=split($0, lines, "`");
    for(i=1;i<n;++i) {
        split(lines[i], tok, " ");
        if((tok[2]+0)>=1000) {
            if(tok[4]=="" || tok[4]~/^pts\//) { continue; }
            printf "%s{\"uid\": \"%s\", \"sid\": \"%s\"}", del, tok[2], tok[1];
            del=",";
        }
    }
    printf "]";
}'
```

### Command Breakdown

#### loginctl list-sessions Output Format

Example output:
```
   SESSION  UID USER      SEAT  TTY
       c1  1000 john      seat0
       c2  1001 jane      seat0 tty7
        2   120 gdm       seat0 tty1
       15  1000 john            pts/0
```

Columns:
- **Column 1 (tok[1]):** SESSION ID (e.g., "c1", "2")
- **Column 2 (tok[2]):** UID (user ID number)
- **Column 3 (tok[3]):** USERNAME
- **Column 4 (tok[4]):** SEAT (e.g., "seat0")
- **Column 5 (tok[5]):** TTY (terminal identifier)

#### Step-by-Step Processing

**1. Convert newlines to backticks** (line 18):
```javascript
child.stdin.write("loginctl list-sessions | tr '\\n' '`' | awk '{");
```
- Uses `tr` to replace all newlines with backtick (`) characters
- Converts multi-line output into a single-line string
- Enables AWK to process the entire output as one record

**2. Initialize JSON array** (line 19):
```javascript
child.stdin.write('printf "[";');
```
- Opens JSON array bracket

**3. Initialize delimiter variable** (line 20):
```javascript
child.stdin.write('del="";');
```
- Empty for first element, comma for subsequent elements
- Ensures proper JSON formatting

**4. Split into lines** (line 21):
```javascript
child.stdin.write('n=split($0, lines, "`");');
```
- Splits the backtick-delimited string back into lines
- Stores lines in `lines[]` array
- Returns count in `n`

**5. Iterate through lines** (lines 22-23):
```javascript
child.stdin.write('for(i=1;i<n;++i)');
child.stdin.write('{');
```
- Loops through each line (starting at 1, AWK arrays are 1-indexed)
- Skips last element (empty line after final newline)

**6. Parse columns** (line 24):
```javascript
child.stdin.write('   split(lines[i], tok, " ");');
```
- Splits each line by spaces into `tok[]` array
- tok[1] = SESSION ID
- tok[2] = UID
- tok[3] = USERNAME
- tok[4] = SEAT
- tok[5] = TTY

**7. Filter by UID** (line 25):
```javascript
child.stdin.write('   if((tok[2]+0)>=1000)');
```
- Converts UID to number with `+0`
- Filters for UIDs >= 1000 (regular users, not system accounts)
- Excludes system users like gdm (UID 120), nobody, daemon, etc.

**8. Filter by session type** (lines 26-27):
```javascript
child.stdin.write('   {');
child.stdin.write('      if(tok[4]=="" || tok[4]~/^pts\\//) { continue; }');
```
- Skips if SEAT column (tok[4]) is empty
- Skips if SEAT starts with "pts/" (pseudo-terminal sessions)
- **Only includes sessions with physical seats** (graphical sessions)
- Filters out SSH sessions, terminal multiplexer sessions, etc.

**9. Format JSON object** (line 28):
```javascript
child.stdin.write('      printf "%s{\\"uid\\": \\"%s\\", \\"sid\\": \\"%s\\"}", del, tok[2], tok[1];');
```
- Outputs delimiter (empty for first, comma for rest)
- Creates JSON object: `{"uid": "1000", "sid": "c1"}`
- Uses escaped quotes (`\"`) for JSON string formatting

**10. Set delimiter for next iteration** (line 29):
```javascript
child.stdin.write('      del=",";');
```
- After first element, set delimiter to comma

**11. Close JSON array** (line 32):
```javascript
child.stdin.write('printf "]";');
```
- Closes JSON array bracket

### Example Output

Given this `loginctl list-sessions` output:
```
   SESSION  UID USER      SEAT  TTY
       c1  1000 john      seat0
       c2  1001 jane      seat0 tty7
        2   120 gdm       seat0 tty1
       15  1000 john            pts/0
```

The generated command produces:
```json
[{"uid": "1000", "sid": "c1"},{"uid": "1001", "sid": "c2"}]
```

**Filtered out:**
- Session `2` (UID 120 < 1000, system user)
- Session `15` (no SEAT value, pts/0 session)

**Included:**
- Session `c1` (UID 1000, has seat0)
- Session `c2` (UID 1001, has seat0)

### Clipboard Functionality

#### Clipboard Module Integration (line 37)

```javascript
require('clipboard')(child.stdin.str);
```

The module uses MeshAgent's `clipboard` module to copy the generated command to the system clipboard. The `child.stdin.str` accumulator contains the complete command string built through multiple `write()` calls.

#### Platform-Specific Timeout (lines 39-47)

**Linux** (lines 39-42):
```javascript
if (process.platform == 'linux')
{
    console.log('clipboard active for 5 seconds');
    var t = setTimeout(function () { process.exit(); }, 5000);
}
```
- Keeps process alive for 5 seconds
- Allows clipboard manager time to capture content
- Linux clipboard requires process to remain active temporarily
- Console message informs user they have 5 seconds to paste

**Other Platforms** (lines 44-46):
```javascript
else
{
    process.exit();
}
```
- Exits immediately
- Clipboard content persists after process termination on non-Linux platforms

### Code Structure

The module uses a simulated child process object pattern:

**Lines 17-36: Command Construction**
```javascript
var child = { stdin: { str: '', write: function (v) { this.str += v.trim(); } } };
```
- Creates mock child process object
- `stdin.str` accumulates the complete command string
- `stdin.write()` appends each fragment (with trimming)
- Pattern allows building complex commands incrementally

**Building Strategy:**
1. Start with `loginctl` command and pipe setup
2. Add AWK script opening
3. Incrementally add AWK logic (printf, split, for loop, conditionals)
4. Close AWK script
5. Add trailing newlines for clean formatting
6. Copy complete command to clipboard

### Dependencies

#### Node.js Core Modules
- **`setTimeout`** (global, line 42) - Timer for clipboard persistence on Linux
- **`process`** (global, lines 39, 42, 46) - Platform detection and process exit

#### MeshAgent Module Dependencies

**Required Modules:**

- **`clipboard`** (line 37)
  - Copies text to system clipboard
  - Platform-specific implementation:
    - **Linux:** Uses X11 clipboard (xclip/xsel) or Wayland clipboard
    - **macOS:** Uses `pbcopy` command
    - **Windows:** Uses Windows clipboard APIs
  - **Not applicable on macOS for this tool:** While the clipboard module supports macOS, this specific tool generates Linux-specific commands making macOS execution pointless

#### Platform Binary Dependencies

**Linux (when using generated command):**
- **loginctl** - Part of systemd package
  - Command: `/usr/bin/loginctl` or `/bin/loginctl`
  - Package: systemd (standard on most modern Linux distributions)
  - Required for session enumeration

- **awk** - AWK text processing language
  - Command: `/usr/bin/awk` or `/bin/awk`
  - Usually GNU AWK (gawk) on Linux
  - Standard utility on all Unix-like systems

- **tr** - Translate characters utility
  - Command: `/usr/bin/tr` or `/bin/tr`
  - Part of coreutils package
  - Standard on all Unix-like systems

**Linux (when running this helper):**
- **xclip** or **xsel** (if using X11)
  - Required by clipboard module for X11 clipboard access
  - Package: `xclip` or `xsel`
  - May not be installed by default

- **wl-copy** (if using Wayland)
  - Required for Wayland clipboard access
  - Package: `wl-clipboard`
  - Wayland alternative to X11 clipboard tools

**macOS (clipboard module capability, though tool not designed for macOS):**
- **pbcopy** - Built-in clipboard utility
  - Path: `/usr/bin/pbcopy`
  - Standard on all macOS systems
  - Used by clipboard module

### Usage

#### Command Line Invocation

```bash
# Generate and copy AWK command to clipboard
node awk-helper.js
```

**On Linux:**
```bash
$ node awk-helper.js
clipboard active for 5 seconds
# Command is now in clipboard for 5 seconds
# Paste with Ctrl+V or middle-click

# After pasting, you can execute the command:
$ loginctl list-sessions | tr '\n' '`' | awk '{ ... }'
[{"uid": "1000", "sid": "c1"},{"uid": "1001", "sid": "c2"}]
```

**Expected Workflow:**
1. Developer runs `node awk-helper.js`
2. Command is copied to clipboard
3. Developer has 5 seconds to paste into editor/terminal
4. Developer can then use or modify the generated command

#### Generated Command Usage

Once pasted from clipboard, the command can be:

**Used directly in shell:**
```bash
# Execute to get JSON session data
loginctl list-sessions | tr '\n' '`' | awk '{...}'

# Pipe to jq for pretty printing
loginctl list-sessions | tr '\n' '`' | awk '{...}' | jq .

# Save to variable
SESSIONS=$(loginctl list-sessions | tr '\n' '`' | awk '{...}')

# Use in script
#!/bin/bash
sessions=$(loginctl list-sessions | tr '\n' '`' | awk '{...}')
echo "$sessions" | jq -r '.[] | .uid'
```

**Integrated into MeshAgent code:**
```javascript
var child = require('child_process').execFile('/bin/sh', ['sh']);
child.stdout.str = '';
child.stdout.on('data', function (c) { this.str += c.toString(); });
child.stdin.write("loginctl list-sessions | tr '\\n' '`' | awk '{...}'\n");
child.stdin.write('exit\n');
child.waitExit();
var sessions = JSON.parse(child.stdout.str.trim());
// sessions = [{"uid": "1000", "sid": "c1"}, ...]
```

### Technical Notes

**AWK Array Indexing:**
AWK arrays are 1-indexed, not 0-indexed like most programming languages:
```awk
split(str, arr, delim)  # arr[1] is first element, not arr[0]
for(i=1; i<=n; ++i)     # Loops from 1 to n (inclusive)
```

**Backtick Delimiter Choice:**
The backtick character (`) is used as a temporary delimiter because:
- Unlikely to appear in loginctl output
- Not a special character in AWK
- Easy to split on
- Doesn't conflict with quotes or spaces

**UID >= 1000 Convention:**
On most Linux systems:
- UIDs 0-99: System reserved
- UIDs 100-999: System users (services, daemons)
- UIDs 1000+: Regular user accounts

The filter `(tok[2]+0)>=1000` targets regular user sessions only.

**Session Type Filtering Logic:**
```awk
if(tok[4]=="" || tok[4]~/^pts\//) { continue; }
```
This double condition filters out:
1. `tok[4]==""` - Sessions without a SEAT (headless, SSH)
2. `tok[4]~/^pts\//` - Pseudo-terminal sessions (terminal multiplexers, SSH)

**Only graphical sessions with physical seats** (seat0, seat1, etc.) are included.

**Regex Pattern Explanation:**
- `~/^pts\//` - AWK regex match operator
- `^` - Start of string
- `pts\/` - Literal "pts/" (slash escaped)
- Matches: "pts/0", "pts/1", "pts/2", etc.

**String to Number Conversion:**
```awk
(tok[2]+0) >= 1000
```
Adding `+0` forces AWK to convert the string to a number for comparison. Without this, string comparison might give incorrect results.

**JSON Formatting:**
The AWK script manually constructs JSON without using a JSON library:
```awk
printf "%s{\"uid\": \"%s\", \"sid\": \"%s\"}", del, tok[2], tok[1];
```
- `\"` - Escaped quote in AWK printf (produces `"` in output)
- `%s` - String format specifier
- Manual delimiter handling ensures proper comma placement

### Mock Child Process Pattern

**Pattern Explanation:**
```javascript
var child = {
    stdin: {
        str: '',
        write: function (v) { this.str += v.trim(); }
    }
};
```

This pattern simulates a child process object without actually spawning one:
- **Purpose:** Accumulate command string fragments
- **Benefits:**
  - Clean syntax for building complex multi-line commands
  - Similar to how real child_process.stdin.write() works
  - Easy to read and maintain
  - Mimics pattern used elsewhere in MeshAgent code

**Usage:**
```javascript
child.stdin.write("first part ");
child.stdin.write("second part");
// child.stdin.str now contains: "first partsecond part"
```

### macOS-Specific Analysis

**Why macOS Cannot Use This Tool:**

1. **loginctl Not Available** - macOS does not use systemd, so `loginctl` command doesn't exist
   - Alternative: `who`, `w`, `users`, or Console framework APIs

2. **Different Session Management** - macOS uses different session architecture:
   - **GUI Sessions:** Managed by WindowServer and loginwindow
   - **Console Sessions:** Tracked in `/var/run/utmpx`
   - **Fast User Switching:** Managed by loginwindow process
   - **Session Enumeration:** Via `who` command or Security framework

3. **Output Format Differences** - macOS `who` output:
   ```
   user     console  Nov 13 10:30
   user     ttys001  Nov 13 11:45
   ```
   Completely different column structure than loginctl

4. **UID Conventions May Differ** - macOS UIDs:
   - System: 0-500
   - Regular users: 501+
   - Would need different UID threshold

**macOS Equivalent Approach:**

If this concept were adapted for macOS:

```bash
# Using 'who' command
who | awk '{
    if($1 != "") {
        cmd = "id -u " $1;
        cmd | getline uid;
        close(cmd);
        if(uid >= 501 && $2 == "console") {
            printf "{\"user\": \"%s\", \"uid\": \"%s\"}\n", $1, uid;
        }
    }
}'
```

Or using native APIs:
```javascript
// Theoretical macOS approach
var child = require('child_process').execFile('/usr/bin/who', ['who']);
// Parse output differently
// Or use Security framework bindings
```

**Clipboard Module on macOS:**

While the `clipboard` module DOES work on macOS (via `pbcopy`), running this specific tool on macOS would be pointless because:
- The generated command only works on Linux
- macOS developers would need a different command for macOS session enumeration
- The tool would successfully copy to clipboard, but the command would fail when executed

## Summary

The awk-helper.js module is a development utility specifically designed for **Linux systems with systemd** that generates a complex AWK-based command pipeline for parsing systemd-logind session information. It creates a single-line command that retrieves active user sessions, filters for regular users (UID >= 1000) with graphical displays, and outputs JSON-formatted data.

**macOS and other platforms are not supported** because:
- The generated command uses `loginctl`, which only exists on systemd-based Linux systems
- macOS uses completely different session management (Security framework, not systemd-logind)
- The output format and column structure of loginctl is Linux-specific
- This is a development utility for generating Linux-specific scripts, not a runtime component
- macOS would require entirely different session enumeration commands and parsing logic

The module uses a mock child process pattern to incrementally build a complex multi-line command, then copies it to the system clipboard for 5 seconds (on Linux) allowing developers to paste and use or modify the generated command. While the clipboard module supports macOS, the generated command is Linux-only and would not execute successfully on macOS.

For macOS session enumeration, developers would need to create similar tools using `who`, `w`, or native Security framework APIs with completely different parsing logic appropriate for macOS session management architecture.
