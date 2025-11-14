# amt-script.js

Binary script compiler, decompiler, and runtime interpreter for Intel AMT automation. Enables creation of compiled AMT management scripts that can execute WSMAN operations, perform calculations, implement control flow, and interact with AMT firmware through a custom bytecode format with integrated WSMAN stack integration.

## Platform

**Supported Platforms:**
- Windows (all versions) - Full support
- Linux (all distributions) - Full support

**Excluded Platforms:**
- **macOS** - Excluded (technically compatible, contextually irrelevant)

**Exclusion Reasoning:**

While **technically cross-platform and fully compatible**, this module is excluded from macOS builds because:

1. **Part of Intel AMT Automation Infrastructure** - Component of the Intel AMT scripting and automation ecosystem, which is not typically deployed on macOS systems in enterprise environments.

2. **Limited Use Case on macOS** - Intel AMT scripting infrastructure is predominantly deployed on Windows/Linux management servers. macOS workstations are rarely used as AMT automation platforms in enterprise IT operations.

3. **Architectural Decision** - The entire Intel AMT module suite is excluded from macOS builds to maintain consistent platform targeting, even though this scripting module has no technical limitations.

**Technical Capability:**

Despite the exclusion, the module is fully cross-platform because:
- **Pure JavaScript Implementation** - All compilation, decompilation, and execution logic is portable JavaScript with no platform-specific code or binary dependencies
- **No Hardware Dependencies** - Script runtime does not require Intel AMT hardware, executes in standard Node.js environment
- **Network-Only WSMAN** - Scripts can call WSMAN operations on remote AMT devices over the network (lines 213-243)
- **No Binary Modules** - Uses only core Node.js modules and pure JavaScript

---

## Functionality

### Core Purpose

amt-script.js provides a complete scripting environment for AMT automation:

1. **Script Compilation** - Convert human-readable script text to binary bytecode
2. **Script Decompilation** - Reverse binary to readable format for debugging
3. **Script Execution** - Run compiled scripts with step-by-step control
4. **WSMAN Integration** - Call AMT management operations from scripts
5. **Control Flow** - Jumps, conditionals, loops
6. **Data Manipulation** - Variables, strings, arrays, JSON
7. **Error Handling** - Exception catching and status reporting

### Script Format

**Binary Script Structure:**
```
Bytes 0-3:   Magic Header (0x247D2945)
Bytes 4-5:   Version (1)
Bytes 6+:    Compiled commands
```

**Command Format:**
```
Bytes 0-1:   Command ID
Bytes 2-3:   Command Length (including this header)
Bytes 4-5:   Argument Count
Bytes 6+:    Arguments (variable length)
```

**Argument Format:**
```
Bytes 0-1:   Argument Length
Bytes 2:     Argument Type (0=variable, 1=string, 2=integer, 3=label)
Bytes 3+:    Argument Data
```

---

## Core Functions

### Function Tables

#### Core Functions (Table 1) - Line 24

**script_functionTable1** - Basic operations (IDs 0-25):

| ID | Function | Purpose |
|----|----------|---------|
| 0 | nop | No operation |
| 1 | jump | Unconditional or conditional jump |
| 2 | set | Set variable value |
| 3 | print | Print message to console |
| 4 | dialog | Show dialog (not used in headless) |
| 5 | getitem | Get item from array by property |
| 6 | substr | Extract substring |
| 7 | indexof | Find substring position |
| 8 | split | Split string into array |
| 9 | join | Join array into string |
| 10 | length | Get string/array length |
| 11 | jsonparse | Parse JSON string |
| 12 | jsonstr | Convert to JSON string |
| 13 | add | Add two values |
| 14 | substract | Subtract values |
| 15 | parseint | Parse integer |
| 16 | wsbatchenum | WSMAN batch enumerate |
| 17 | wsput | WSMAN put operation |
| 18 | wscreate | WSMAN create operation |
| 19 | wsdelete | WSMAN delete operation |
| 20 | wsexec | WSMAN execute method |
| 21 | scriptspeed | Set execution speed |
| 22 | wssubscribe | WSMAN event subscribe |
| 23 | wsunsubscribe | WSMAN event unsubscribe |
| 24 | readchar | Read character code from string |
| 25 | signwithdummyca | Sign with CA (not supported) |

#### Extended Functions (Table 2) - Lines 27, 30

**script_functionTable2** - Extended operations (IDs 10000-10018):

| ID | Function | Purpose |
|----|----------|---------|
| 10000 | encodeuri | Encode URI component |
| 10001 | decodeuri | Decode URI component |
| 10002 | passwordcheck | Validate password complexity |
| 10003 | atob | Base64 decode |
| 10004 | btoa | Base64 encode |
| 10005 | hex2str | Convert hex to string |
| 10006 | str2hex | Convert string to hex |
| 10007 | random | Generate random number |
| 10008 | md5 | Calculate MD5 hash |
| 10009 | maketoarray | Convert to array |
| 10010 | readshort | Read 16-bit big-endian |
| 10011 | readshortx | Read 16-bit little-endian |
| 10012 | readint | Read 32-bit big-endian |
| 10013 | readsint | Read 32-bit signed big-endian |
| 10014 | readintx | Read 32-bit little-endian |
| 10015 | shorttostr | Convert 16-bit to big-endian string |
| 10016 | shorttostrx | Convert 16-bit to little-endian string |
| 10017 | inttostr | Convert 32-bit to big-endian string |
| 10018 | inttostrx | Convert 32-bit to little-endian string |

---

## API - Script Setup and Control

### module.exports.setup(binary, startvars) - Lines 68-298

**Purpose:** Initialize script runtime from compiled binary

**Parameters:**
- `binary` - Buffer containing compiled script with magic header
- `startvars` - Object with initial variable values

**Returns:** Script execution object or `null` if invalid

**Validation - Lines 70-73:**
- Minimum 6 bytes (header)
- Magic: 0x247D2945
- Version: Must be 1

**Returned Object Structure:**
```javascript
{
    startvars: { ... },        // Initial variables
    script: Buffer,            // Script bytecode (without header)
    ip: 0,                     // Instruction pointer
    variables: { ... },        // Current variable values
    state: 1,                  // 0=done, 1=running, 2=waiting, 9=error
    onCompleted: null,         // Completion callback
    onConsole: null,           // Console output handler
    onStep: null,              // Single-step callback
    amtstack: null,            // WSMAN stack for AMT operations
    stepspeed: 0,              // Milliseconds per step (0=manual)
    timer: null,               // setInterval timer
    dialog: false              // Dialog visible flag
}
```

---

### Object Methods

#### reset(stepspeed) - Lines 76-81

**Purpose:** Reset script to beginning

**Process:**
- Stops timer
- Sets instruction pointer to 0
- Restores initial variables
- Sets state to 1 (running)

#### start(stepspeed) - Lines 84-88

**Purpose:** Begin automatic script execution

**Parameters:**
- `stepspeed` - Milliseconds between steps (default: 10)

**Behavior:**
- If `stepspeed > 0`: Creates interval timer
- Timer calls `step()` at specified interval
- If `stepspeed = 0`: Manual stepping only

#### stop() - Lines 91-95

**Purpose:** Stop automatic execution

**Behavior:**
- Clears interval timer
- Sets `stepspeed = 0`
- Does not reset instruction pointer

---

### Variable Management

#### getVar(name) - Line 98

**Purpose:** Retrieve variable value with dotted path support

**Parameters:**
- `name` - Variable name (e.g., "config.network.ip")

**Returns:** Variable value or `undefined`

**Implementation:**
- Splits name by '.'
- Recursively traverses object hierarchy
- Returns `null` if path doesn't exist

**Example:**
```javascript
obj.variables = {
    config: {
        network: {
            ip: "192.168.1.1"
        }
    }
};
obj.getVar("config.network.ip"); // Returns "192.168.1.1"
```

#### getVarEx(name, val) - Line 99

**Purpose:** Recursive variable path traversal

**Internal helper for getVar()**

#### setVar(name, val) - Line 100

**Purpose:** Set variable value with dotted path support

**Parameters:**
- `name` - Variable name (e.g., "config.network.ip")
- `val` - Value to set

**Behavior:**
- Creates intermediate objects if needed
- Supports deep assignment

**Example:**
```javascript
obj.setVar("config.network.ip", "10.0.0.1");
// Creates obj.variables.config.network.ip
```

#### setVarEx(name, vars, val) - Line 101

**Purpose:** Recursive variable path assignment

**Internal helper for setVar()**

---

### Script Execution

#### step() - Lines 104-278

**Purpose:** Execute single script instruction

**Returns:** Script object (`obj`)

**State Handling:**
- Only executes if `state === 1` (running)
- Sets `state = 0` when script completes (line 275)
- Sets `state = 2` when waiting (WSMAN calls, dialog)
- Sets `state = 9` on error (line 253)

**Execution Flow:**

1. **Check State** (line 105)
   - Skip if not running

2. **Read Command** (lines 107-111)
   - Command ID (2 bytes)
   - Command length (2 bytes)
   - Argument count (2 bytes)
   - Argument pointer

3. **Clear Temp Variables** (line 114)
   - Delete all variables starting with "__"

4. **Parse Arguments** (lines 117-134)
   - Read each argument's length, type, value
   - Type 0: Variable reference
   - Type 1: String literal (stored in temp variable)
   - Type 2/3: Integer literal (stored in temp variable)
   - Support variable substitution: `{varname}` replaced with value

5. **Advance Instruction Pointer** (line 137)
   - Move IP forward by command length

6. **Get Argument Values** (lines 140-141)
   - Resolve all variable references
   - Build array of actual values

7. **Execute Command** (lines 143-267)
   - Dispatch based on command ID
   - Core functions (0-25): Direct implementation
   - Extended functions (10000+): Function table lookup
   - Store result in ARG0 if applicable

8. **Handle Exceptions** (lines 269-272)
   - Catch errors, store in `_exception` variable

9. **Check Completion** (line 275)
   - If IP >= script length: Set state to 0, call `onCompleted`

10. **Call onStep** (line 276)
    - Notify application of step completion

---

## Command Implementations

### Control Flow Commands

#### nop (0) - Line 147
**Purpose:** No operation, skip to next instruction

#### jump (1) - Lines 149-164

**Purpose:** Unconditional or conditional jump to label

**Syntax:**
- `jump :label` - Unconditional
- `jump :label, value1, operator, value2` - Conditional

**Operators:**
- `<` - Less than
- `<=` - Less than or equal
- `!=` - Not equal
- `=` - Equal
- `>=` - Greater than or equal
- `>` - Greater than

**Behavior:**
- Sets instruction pointer to label address
- Conditional: Only jumps if comparison true

**Example:**
```
set counter 0
:loop
print "Counter: {counter}"
add counter counter 1
jump :loop counter < 10
```

---

### Variable Commands

#### set (2) - Line 166

**Purpose:** Set variable value or delete variable

**Syntax:**
- `set variable value` - Assign value
- `set variable` - Delete variable (ARG1 undefined)

**Example:**
```
set hostname "amt-device-1"
set ipaddr 192.168.1.100
set count 0
```

---

### Output Commands

#### print (3) - Lines 168-174

**Purpose:** Output message to console

**Behavior:**
- Converts value to string
- Strips "INFO: " and "SUCCESS: " prefixes
- Calls `onConsole` callback if set, otherwise `console.log()`

**Example:**
```
print "Starting AMT configuration..."
print "INFO: Connected to {hostname}"
print "SUCCESS: Configuration complete"
```

#### dialog (4) - Lines 176-179

**Purpose:** Show dialog box (interactive mode)

**Syntax:** `dialog title content buttons`

**Behavior:**
- Sets state to 2 (waiting)
- Calls `setDialogMode()` (external)
- Result stored in `DialogSelect` variable
- Not typically used in headless scripts

---

### String/Array Commands

#### substr (6) - Lines 183-185

**Syntax:** `substr dest source index length`

**Example:**
```
set text "Hello World"
substr first text 0 5      # first = "Hello"
```

#### indexof (7) - Lines 186-188

**Syntax:** `indexof dest source substring`

**Example:**
```
set text "Hello World"
indexof pos text "World"   # pos = 6
```

#### split (8) - Lines 189-191

**Syntax:** `split dest source separator`

**Example:**
```
set csv "a,b,c,d"
split parts csv ","        # parts = ["a","b","c","d"]
```

#### join (9) - Lines 192-194

**Syntax:** `join dest source separator`

**Example:**
```
set parts ["a","b","c"]
join csv parts ","         # csv = "a,b,c"
```

#### length (10) - Lines 195-197

**Syntax:** `length dest source`

**Example:**
```
set text "Hello"
length len text            # len = 5
```

---

### JSON Commands

#### jsonparse (11) - Lines 198-200

**Syntax:** `jsonparse dest json_string`

**Example:**
```
set json_text "{\"name\":\"device1\",\"ip\":\"192.168.1.1\"}"
jsonparse config json_text
# config = {name: "device1", ip: "192.168.1.1"}
```

#### jsonstr (12) - Lines 201-203

**Syntax:** `jsonstr dest object`

**Example:**
```
set config {"name":"device1"}
jsonstr json config
# json = "{\"name\":\"device1\"}"
```

---

### Arithmetic Commands

#### add (13) - Lines 204-206

**Syntax:** `add dest value1 value2`

**Example:**
```
set a 10
set b 20
add c a b              # c = 30
add a a 1              # a = 11
```

#### substract (14) - Lines 207-209

**Syntax:** `substract dest value1 value2`

**Example:**
```
set total 100
set used 35
substract free total used  # free = 65
```

#### parseint (15) - Lines 210-212

**Syntax:** `parseint dest string`

**Example:**
```
set text "12345"
parseint num text      # num = 12345
```

---

### WSMAN Commands

**Prerequisites:**
- `obj.amtstack` must be set to initialized WSMAN stack
- AMT device must be reachable and authenticated

#### wsbatchenum (16) - Lines 213-216

**Purpose:** Batch enumerate multiple WSMAN classes

**Syntax:** `wsbatchenum result_var class_list`

**Behavior:**
- Sets state to 2 (waiting)
- Calls `amtstack.BatchEnum()`
- Result stored in result_var
- WSMAN status in `wsman_result` and `wsman_result_str`

**Example:**
```
set classes ["AMT_GeneralSettings", "AMT_SetupAndConfigurationService"]
wsbatchenum settings classes
```

#### wsput (17) - Lines 217-220

**Purpose:** WSMAN Put operation (update object)

**Syntax:** `wsput class_name properties`

**Example:**
```
set props {"HostName":"new-hostname"}
wsput "AMT_GeneralSettings" props
```

#### wscreate (18) - Lines 221-224

**Purpose:** WSMAN Create operation (new instance)

**Syntax:** `wscreate class_name properties`

**Example:**
```
set user {"Username":"admin2","Password":"P@ssw0rd"}
wscreate "AMT_AuthorizationService" user
```

#### wsdelete (19) - Lines 225-228

**Purpose:** WSMAN Delete operation (remove instance)

**Syntax:** `wsdelete class_name selectors`

**Example:**
```
set selectors {"Name":"old-profile"}
wsdelete "AMT_WiFiPortConfigurationService" selectors
```

#### wsexec (20) - Lines 229-232

**Purpose:** WSMAN Execute method

**Syntax:** `wsexec class_name method_name arguments [selectors]`

**Example:**
```
set args {"PowerState":8}  # 8 = power on
wsexec "CIM_PowerManagementService" "RequestPowerStateChange" args
```

#### wssubscribe (22) - Lines 237-240

**Purpose:** Subscribe to AMT events

**Syntax:** `wssubscribe name delivery url selectors opaque user pass`

**Example:**
```
wssubscribe "AMT_AlertIndication" "Push" "http://server/events" "" "" "" ""
```

#### wsunsubscribe (23) - Lines 241-244

**Purpose:** Unsubscribe from AMT events

**Syntax:** `wsunsubscribe name selectors`

---

### Utility Commands

#### scriptspeed (21) - Lines 233-236

**Purpose:** Change script execution speed

**Syntax:** `scriptspeed milliseconds`

**Behavior:**
- Updates `stepspeed`
- Restarts timer with new interval

**Example:**
```
scriptspeed 1000  # Slow down to 1 step/second
# ... slow operations ...
scriptspeed 10    # Speed up to 100 steps/second
```

#### readchar (24) - Lines 245-248

**Purpose:** Get character code from string

**Syntax:** `readchar dest string position`

**Example:**
```
set text "ABC"
readchar code text 0   # code = 65 (ASCII 'A')
```

---

### WSMAN Callback Handling

#### xxWsmanReturn(stack, name, responses, status) - Lines 287-293

**Purpose:** Internal callback for WSMAN operations

**Behavior:**
- Stores responses in specified variable
- Sets `wsman_result` to HTTP status code
- Sets `wsman_result_str` to human-readable message (line 290)
- Resumes script execution (state = 1)
- Calls `onStep` if defined

**Error Table - Lines 56-65:**

| Status | Message |
|--------|---------|
| 200 | OK |
| 401 | Authentication Error |
| 408 | Timeout Error |
| 601 | WSMAN Parsing Error |
| 602 | Unable to parse HTTP response header |
| 603 | Unexpected HTTP enum response |
| 604 | Unexpected HTTP pull response |
| 998 | Invalid TLS certificate |

---

## API - Script Compilation

### module.exports.compile(script, onmsg) - Lines 302-346

**Purpose:** Compile text script to binary bytecode

**Parameters:**
- `script` - Multi-line string containing script source
- `onmsg` - Callback for error messages

**Returns:** Binary Buffer with compiled script or empty string on error

**Script Syntax:**

**Comments and Blank Lines:**
```
# This is a comment
## This is also a comment

set variable value  # inline comment (not supported)
```

**Labels:**
```
:label_name
jump :label_name
```

**Swaps (Macros) - Line 307:**
```
##SWAP {old_text} {new_text}
set variable {old_text}  # Replaced with new_text
```

**Commands:**
```
command_name arg1 arg2 "string arg" 12345
```

**Compilation Process:**

1. **Split into lines** (line 303)

2. **Process each line:**
   - Parse swaps: `##SWAP old new` (line 307)
   - Skip comments: Lines starting with '#' (line 308)
   - Apply swaps: Replace text patterns (line 309)
   - Tokenize: Split into keywords respecting quotes (line 310)
   - Process labels: `:labelname` (line 312)
   - Encode commands: Build binary representation (lines 313-336)

3. **Argument Encoding:**
   - Labels → Type 3, placeholder 0xFFFFFFFF (lines 320-322)
   - Integers → Type 2, 32-bit value (lines 324-326)
   - Quoted strings → Type 1, unquoted content (lines 328-329)
   - Variables → Type 0, variable name (lines 331-332)

4. **Label Resolution:**
   - Replace label placeholders with actual addresses (lines 339-343)

5. **Add Header:**
   - Magic: 0x247D2945
   - Version: 1
   - Bytecode follows (line 345)

**Example Compilation:**

Source:
```
set counter 0
:loop
print "Count: {counter}"
add counter counter 1
jump :loop counter < 10
print "Done!"
```

Process:
1. Line 1: `set counter 0`
   - Command: 2 (set)
   - Arg 0: Type 0, "counter"
   - Arg 1: Type 2, integer 0

2. Line 2: `:loop`
   - Creates label "LOOP" at current position

3. Line 3: `print "Count: {counter}"`
   - Command: 3 (print)
   - Arg 0: Type 1, "Count: {counter}"
   - Runtime replaces {counter} with value

4. Line 4: `add counter counter 1`
   - Command: 13 (add)
   - Arg 0: Type 0, "counter"
   - Arg 1: Type 0, "counter"
   - Arg 2: Type 2, integer 1

5. Line 5: `jump :loop counter < 10`
   - Command: 1 (jump)
   - Arg 0: Type 3, address of :LOOP
   - Arg 1: Type 0, "counter"
   - Arg 2: Type 1, "<"
   - Arg 3: Type 2, integer 10

6. Line 6: `print "Done!"`
   - Command: 3 (print)
   - Arg 0: Type 1, "Done!"

---

## API - Script Decompilation

### module.exports.decompile(binary, onecmd) - Lines 349-401

**Purpose:** Convert binary bytecode back to readable script

**Parameters:**
- `binary` - Buffer containing compiled script
- `onecmd` - If >= 0, decompile only that command position

**Returns:** String containing decompiled script

**Validation - Lines 354-358:**
- Check magic header
- Check version
- Return error message if invalid

**Decompilation Process:**

1. **Initialize** (line 350)
   - Create label tracking
   - Set pointer to command start (byte 6)

2. **Process each command** (lines 361-391)
   - Read command ID, length, argument count
   - Generate label: `:label{position}` (line 367)
   - Process arguments:
     - Type 0: Variable name
     - Type 1: Quoted string
     - Type 2: Integer
     - Type 3: Label reference
   - Look up command name from function tables
   - Build command line with arguments

3. **Label Optimization** (lines 394-399)
   - Remove unused labels
   - Keep only referenced labels

**Example Output:**

Binary input → Text output:
```
:label0
set counter 0
:label4
print "Count: {counter}"
add counter counter 1
jump :label4 counter < 10
print "Done!"
```

---

## Helper Functions

### Extended Function Implementations - Lines 33-54

#### MakeToArray(v) - Line 33
Converts single values to arrays, leaves arrays unchanged

#### ReadShort(v, p) - Line 34
Reads 16-bit big-endian from buffer at position

#### ReadShortX(v, p) - Line 35
Reads 16-bit little-endian from buffer at position

#### ReadInt(v, p) - Line 36
Reads 32-bit big-endian from buffer at position

#### ReadSInt(v, p) - Line 37
Reads 32-bit signed big-endian from buffer at position

#### ReadIntX(v, p) - Line 38
Reads 32-bit little-endian from buffer at position

#### ShortToStr(v) - Line 39
Converts 16-bit value to 2-byte big-endian string

#### ShortToStrX(v) - Line 40
Converts 16-bit value to 2-byte little-endian string

#### IntToStr(v) - Line 41
Converts 32-bit value to 4-byte big-endian string

#### IntToStrX(v) - Line 42
Converts 32-bit value to 4-byte little-endian string

#### btoa(x) - Line 47
Base64 encode string/buffer

#### atob(x) - Line 48
Base64 decode to string

#### passwordcheck(p) - Line 49
Validates password has uppercase, lowercase, number, and special character

#### hex2rstr(x) - Line 50
Convert hex string to raw string

#### rstr2hex(x) - Line 51
Convert raw string to hex string

#### random() - Line 52
Generate random number (implementation incomplete)

#### rstr_md5(str) - Line 53
Calculate MD5 hash and return as raw string

#### getItem(x, y, z) - Line 54
Find first object in array where property y equals value z

---

## Dependencies

### JavaScript Module Dependencies

**No external module dependencies** - Uses only core Node.js modules:

- String manipulation (built-in)
- Buffer operations (built-in)
- JSON parsing (built-in)
- Array operations (built-in)
- setTimeout/setInterval (built-in)

### Optional External Dependencies

The script runtime can integrate with:

1. **WSMAN Stack** (lines 213-243)
   - Set via `obj.amtstack`
   - Enables WSMAN commands
   - Not required for non-WSMAN scripts

2. **MeshAgent** (optional)
   - Dialog functionality (line 178)
   - Not used in headless scripts

---

## Relationship to Other AMT Modules

### Script Integration Architecture

```
┌─────────────────────────────────────────┐
│         AMT Script Source Code          │
│   (Human-readable automation script)    │
└──────────────┬──────────────────────────┘
               │
               │ compile()
               ▼
┌─────────────────────────────────────────┐
│       Compiled Binary Script            │
│   (Portable bytecode with header)       │
└──────────────┬──────────────────────────┘
               │
               │ setup()
               ▼
┌─────────────────────────────────────────┐
│       Script Runtime (This Module)      │
│   - Variable management                 │
│   - Control flow execution              │
│   - WSMAN command dispatch              │
└──────────────┬──────────────────────────┘
               │
               │ WSMAN commands
               ▼
┌─────────────────────────────────────────┐
│       amt-wsman.js (WSMAN Stack)        │
│   - HTTP/HTTPS transport                │
│   - XML generation/parsing              │
│   - AMT protocol implementation         │
└──────────────┬──────────────────────────┘
               │
               │ Network (HTTP/HTTPS)
               ▼
┌─────────────────────────────────────────┐
│   Remote Intel AMT Device               │
│   (Target of automation)                │
└─────────────────────────────────────────┘
```

### Module Relationships

1. **amt-wsman.js** - WSMAN protocol implementation
   - Script calls WSMAN operations via `obj.amtstack`
   - Script provides high-level automation
   - WSMAN provides low-level AMT communication

2. **amt.js** - High-level AMT wrapper
   - May use amt-script for complex automation
   - Provides class wrappers for AMT features
   - Script provides procedural automation

3. **amt-scanner.js** - Network discovery
   - Can be used before script execution to find targets
   - Script can process scanner results
   - Complementary tools for fleet management

**Independent of Hardware Modules:**
- Does not use amt-lme.js, amt-mei.js, or heci
- Targets remote devices, not local AMT hardware
- Cross-platform portable

---

## Usage Examples

### Basic Script Execution

```javascript
var amtScript = require('amt-script');
var fs = require('fs');

// Load compiled script
var binary = fs.readFileSync('automation.bin');

// Setup runtime
var runtime = amtScript.setup(binary, {
    hostname: 'amt-device-1',
    ip: '192.168.1.100'
});

if (!runtime) {
    console.error('Invalid script');
    return;
}

// Handle console output
runtime.onConsole = function(message) {
    console.log('[SCRIPT]', message);
};

// Handle completion
runtime.onCompleted = function() {
    console.log('Script completed');
    console.log('Final variables:', runtime.variables);
};

// Start execution
runtime.start(10);  // 10ms per step
```

### Compiling a Script

```javascript
var amtScript = require('amt-script');
var fs = require('fs');

var source = `
# AMT Power Control Script
print "Connecting to {hostname}..."

# Get current power state
wsexec "CIM_PowerManagementService" "GetPowerState" {} result
print "Current power state: {result}"

# Power on the system
set powerOnArgs {"PowerState": 2}
wsexec "CIM_PowerManagementService" "RequestPowerStateChange" powerOnArgs status

jump :success status = 0
print "ERROR: Failed to power on"
jump :end

:success
print "SUCCESS: System powered on"

:end
print "Done"
`;

// Compile
var binary = amtScript.compile(source, function(error) {
    console.error('Compile error:', error);
});

if (binary) {
    fs.writeFileSync('power-on.bin', binary);
    console.log('Script compiled successfully');
}
```

### Script with WSMAN Integration

```javascript
var amtScript = require('amt-script');
var amtWsman = require('amt-wsman');

// Create WSMAN stack
var wsman = amtWsman({
    host: '192.168.1.100',
    port: 16992,
    user: 'admin',
    pass: 'password',
    tls: false
});

// Setup script
var runtime = amtScript.setup(compiledBinary, {});

// Connect WSMAN stack
runtime.amtstack = wsman;

// Execute
runtime.start();
```

### Decompiling for Analysis

```javascript
var amtScript = require('amt-script');
var fs = require('fs');

var binary = fs.readFileSync('unknown-script.bin');
var source = amtScript.decompile(binary);

if (source.startsWith('#')) {
    console.error(source);  // Error message
} else {
    console.log('Decompiled script:');
    console.log(source);
    fs.writeFileSync('decompiled.txt', source);
}
```

### Step-by-Step Execution

```javascript
var runtime = amtScript.setup(binary, {});

runtime.onStep = function(obj) {
    console.log('IP:', obj.ip, 'State:', obj.state);
    console.log('Variables:', obj.variables);

    // Manual stepping
    if (obj.state === 1 && obj.ip < obj.script.length) {
        setTimeout(function() {
            obj.step();
        }, 1000);
    }
};

// Start manual stepping
runtime.state = 1;
runtime.step();
```

---

## Script Language Reference

### Variable Substitution

Variables in strings are replaced using `{varname}` syntax:

```
set hostname "amt-pc-01"
print "Connecting to {hostname}"
# Output: "Connecting to amt-pc-01"
```

### Temporary Variables

Variables starting with `__` are automatically cleared before each command:

```
# These are cleared each step:
__0, __1, __2, etc.
```

Temporary variables are used internally for literal values.

### Reserved Variables

| Variable | Purpose |
|----------|---------|
| `wsman_result` | HTTP status code from last WSMAN operation |
| `wsman_result_str` | Human-readable status message |
| `_exception` | Exception message if error occurred |
| `DialogSelect` | Button selected in dialog (if used) |

### Operators (for jump)

```
<    Less than
<=   Less than or equal
!=   Not equal
=    Equal
>=   Greater than or equal
>    Greater than
```

### Data Types

1. **Strings:** "quoted text" or unquoted variable references
2. **Integers:** Numeric literals (no decimals)
3. **Objects:** Created via `jsonparse` or returned from WSMAN
4. **Arrays:** Created via `split` or returned from WSMAN
5. **Null/Undefined:** Variable deletion

---

## Performance Considerations

### Execution Speed

1. **Step Speed Control** - `scriptspeed` command adjusts timing
   - Faster speeds reduce delays between operations
   - Slower speeds useful for debugging
   - Default: 10ms per step

2. **WSMAN Operations** - Slowest operations
   - Network latency adds delay
   - Scripts block waiting for WSMAN responses
   - State set to 2 (waiting) during WSMAN calls

3. **Variable Operations** - Very fast
   - In-memory operations
   - Minimal overhead

### Script Size Limits

- No explicit size limits
- Limited by JavaScript memory
- Typical scripts: < 10KB compiled

---

## Security Considerations

### Script Execution Risks

1. **Arbitrary Code** - Scripts can perform any WSMAN operation
   - Unprovision AMT
   - Change configurations
   - Power control systems
   - Read sensitive data

2. **No Sandboxing** - Full access to provided WSMAN stack
   - Scripts must be trusted
   - Validate script sources
   - Review before execution

3. **Credential Exposure** - Variables may contain credentials
   - `runtime.variables` accessible
   - WSMAN stack has authentication
   - Protect script runtime objects

### Best Practices

1. **Script Validation** - Decompile and review before execution
2. **Source Control** - Version and audit all scripts
3. **Least Privilege** - Use WSMAN credentials with minimal permissions
4. **Logging** - Capture all `onConsole` output for audit
5. **Error Handling** - Check `_exception` and `wsman_result`

---

## Limitations

1. **No Functions** - No subroutine/function definitions
   - Use labels and jumps instead
   - Difficult to write modular code

2. **No Error Handling** - No try/catch equivalent
   - Check `_exception` variable manually
   - Errors stored but not trapped

3. **Limited Data Types** - No floats, booleans
   - Use integers (0/1) for boolean logic
   - String representations for floats

4. **No Debugging Features** - No breakpoints or watches
   - Use `print` statements
   - Step execution manually
   - Review variables in `onStep`

5. **WSMAN Only** - No other protocol support
   - Can't call PTHI/LME directly
   - Must use network WSMAN

6. **Synchronous WSMAN** - One WSMAN call at a time
   - Parallel operations not supported
   - Scripts wait for each response

---

## Error Handling

### Compilation Errors

```javascript
var binary = amtScript.compile(source, function(error) {
    // error examples:
    // "Unabled to compile, unknown command: badcmd"
    // "Unabled to compile, unknown label: :missinglabel"
});

if (!binary || binary.length === 0) {
    console.error('Compilation failed');
}
```

### Runtime Errors

```javascript
runtime.onStep = function(obj) {
    // Check for errors
    if (obj.state === 9) {
        console.error('Script error state');
    }

    if (obj.variables._exception) {
        console.error('Exception:', obj.variables._exception);
    }

    // Check WSMAN results
    if (obj.variables.wsman_result !== 200) {
        console.error('WSMAN error:', obj.variables.wsman_result_str);
    }
};
```

### WSMAN Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Authentication failed |
| 408 | Request timeout |
| 601 | WSMAN XML parsing error |
| 602 | HTTP header parsing error |
| 603 | Unexpected enum response |
| 604 | Unexpected pull response |
| 998 | TLS certificate invalid |

---

## Advanced Features

### Macro System (Swaps)

Define text replacements for code reuse:

```
##SWAP {SERVER_IP} 192.168.1.100
##SWAP {ADMIN_USER} administrator
##SWAP {ADMIN_PASS} P@ssw0rd

# Later in script:
set target_ip {SERVER_IP}
set username {ADMIN_USER}
set password {ADMIN_PASS}
```

Swaps applied before compilation, improving code maintainability.

### Binary Portability

Compiled scripts are portable:
- Same binary runs on Windows, Linux, macOS
- Cross-platform script distribution
- Version-independent (version 1 format)

### Variable Persistence

Variables persist across steps:
- State maintained in `runtime.variables`
- Can save and restore state
- Enables script pause/resume

```javascript
// Save state
var state = {
    variables: runtime.variables,
    ip: runtime.ip
};
fs.writeFileSync('state.json', JSON.stringify(state));

// Restore state
var saved = JSON.parse(fs.readFileSync('state.json'));
runtime.variables = saved.variables;
runtime.ip = saved.ip;
runtime.state = 1;
```

---

## Troubleshooting

### Script Won't Compile

**Symptoms:** `compile()` returns empty string

**Common Causes:**
- Unknown command names
- Missing labels referenced by jump
- Syntax errors in arguments

**Solutions:**
- Check error callback message
- Verify all commands in function tables
- Ensure all labels defined before use

### Script Hangs

**Symptoms:** Execution stops, state remains 1

**Common Causes:**
- WSMAN stack not connected
- Network issues to AMT device
- AMT device not responding

**Solutions:**
- Check `runtime.state` (2 = waiting for WSMAN)
- Verify WSMAN stack configuration
- Test AMT connectivity separately
- Add timeout handling

### Variable Substitution Not Working

**Symptoms:** `{varname}` appears literally in output

**Common Causes:**
- Variable not defined
- Incorrect variable name
- Nested object access not working

**Solutions:**
- Use `runtime.getVar()` to verify variable exists
- Check exact variable name spelling
- Use dotted notation for nested objects: `{config.ip}`

### WSMAN Commands Fail

**Symptoms:** `wsman_result ≠ 200`

**Common Causes:**
- Authentication failure (401)
- AMT not reachable
- Invalid WSMAN class/method names
- Incorrect arguments

**Solutions:**
- Verify credentials in WSMAN stack
- Test WSMAN stack separately
- Check AMT documentation for correct class names
- Validate argument format (objects, strings, integers)

This module provides a complete scripting environment for complex AMT automation workflows that can run on any platform and target remote AMT devices over the network.
