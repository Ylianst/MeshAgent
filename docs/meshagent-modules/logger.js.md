# logger.js

Professional logging module with timestamps and configurable log levels supporting DEBUG, INFO, WARN, and ERROR severity levels with automatic filtering based on minimum log threshold.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- macOS (darwin) - Full support
- FreeBSD - Full support
- All platforms - Cross-platform compatible

**Excluded Platforms:**
- None

**Exclusion Reasoning:**

This module has no platform exclusions. It uses only standard JavaScript and Node.js console APIs, making it universally compatible across all platforms where Node.js or Duktape runs. The timestamp formatting uses Date object methods that are consistent across all platforms.

## Functionality

### Purpose

The logger module provides a professional logging system with automatic timestamp formatting and configurable log levels. It serves as a centralized logging utility for MeshAgent components, replacing direct console.log calls with structured, filterable logging.

This module is typically used:
- Throughout MeshAgent modules for consistent log formatting
- In security-critical modules (security-permissions.js, agent-installer.js)
- During installation, upgrade, and service management operations
- For debugging (DEBUG level can be enabled dynamically)
- For production monitoring (INFO/WARN/ERROR levels)

All log messages include timestamps in `YYYY-MM-DD HH:MM:SS` format and severity level prefixes, enabling easy parsing and filtering of log files.

### Key Features

- **Configurable Log Levels:** Four severity levels (DEBUG, INFO, WARN, ERROR)
- **Automatic Filtering:** Messages below minimum level are suppressed
- **Timestamp Formatting:** Consistent ISO-like format with zero-padding
- **Dynamic Level Changes:** Log level can be changed at runtime
- **Simple API:** Familiar interface matching console.log patterns
- **No Dependencies:** Pure JavaScript with no external dependencies

### Key Functions/Methods

#### pad(num) - Lines 34-36 (Private Helper)

**Purpose:** Zero-pads single-digit numbers for timestamp formatting.

**Process:**
1. Checks if number is less than 10
2. If yes, prepends '0' to number string
3. If no, returns number string as-is
4. Used for months, days, hours, minutes, seconds

**Parameters:**
- `num` (number) - Integer to pad (0-99)

**Return Value:** String with zero-padding (e.g., "01", "09", "10", "23")

**Technical Notes:**
- Simple ternary operator for efficiency
- Handles all timestamp components (month, day, hour, minute, second)
- Does not validate input range

---

#### getTimestamp() - Lines 38-48

**Purpose:** Generates formatted timestamp string for log messages.

**Process:**
1. Creates new Date object (current time)
2. Extracts year (4 digits)
3. Extracts month (1-12) → converts to 0-padded string (01-12)
4. Extracts day (1-31) → converts to 0-padded string (01-31)
5. Extracts hours (0-23) → converts to 0-padded string (00-23)
6. Extracts minutes (0-59) → converts to 0-padded string (00-59)
7. Extracts seconds (0-59) → converts to 0-padded string (00-59)
8. Concatenates into format: `YYYY-MM-DD HH:MM:SS`

**Parameters:** None

**Return Value:** String in format `"2025-11-27 14:23:45"`

**Technical Notes:**
- Uses Date object methods: `getFullYear()`, `getMonth()`, `getDate()`, `getHours()`, `getMinutes()`, `getSeconds()`
- Month is 0-indexed (0-11), so adds 1 for human-readable format
- All components are zero-padded via `pad()` helper
- Format is similar to ISO 8601 but with space separator instead of 'T'
- Local timezone (not UTC) for easier correlation with system logs

---

#### log(level, levelValue, message) - Lines 50-55 (Private Core Function)

**Purpose:** Core logging function that applies level filtering and outputs formatted messages.

**Process:**
1. Compares message `levelValue` with `currentLevel` (minimum threshold)
2. If `levelValue >= currentLevel`: Message is logged
3. If `levelValue < currentLevel`: Message is suppressed (early return)
4. Formats output as: `[timestamp] LEVEL: message`
5. Outputs to console using `console.log()`

**Parameters:**
- `level` (string) - Level name for display ("DEBUG", "INFO", "WARN", "ERROR")
- `levelValue` (number) - Numeric severity (0-3) for comparison
- `message` (string) - Log message content

**Return Value:** None (void)

**Technical Notes:**
- Level filtering happens before string concatenation (performance optimization)
- All output goes to stdout via console.log (not console.warn/console.error)
- Format is consistent: `[YYYY-MM-DD HH:MM:SS] LEVEL: message`
- No line buffering - each call generates one output line

---

#### debug(message) - Lines 57-59

**Purpose:** Logs debug-level messages (suppressed by default).

**Process:**
1. Calls `log('DEBUG', LOG_LEVELS.DEBUG, message)`
2. Message only outputs if currentLevel <= 0 (DEBUG level enabled)

**Parameters:**
- `message` (string) - Debug message content

**Return Value:** None

**Exceptions:** None

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Default behavior: DEBUG messages are suppressed (currentLevel = 1 = INFO)
- Enable debug logging: `logger.setLevel('DEBUG')`
- Use for verbose debugging information not needed in production
- Examples:
  - Function entry/exit tracing
  - Variable state inspection
  - Detailed operation progress
- No performance impact when disabled (early return in log())

**Usage Example:**
```javascript
var logger = require('./logger');
logger.debug('Entering upgradeAgent() with params: ' + JSON.stringify(params));
logger.debug('Found 3 plist files for cleanup');
logger.debug('Binary path verification: /usr/local/mesh/meshagent');
```

---

#### info(message) - Lines 61-63

**Purpose:** Logs informational messages (default minimum level).

**Process:**
1. Calls `log('INFO', LOG_LEVELS.INFO, message)`
2. Always outputs when using default log level
3. Suppressed only if level set to WARN or ERROR

**Parameters:**
- `message` (string) - Informational message content

**Return Value:** None

**Exceptions:** None

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Default minimum level (currentLevel = 1 = INFO)
- Use for normal operational messages
- Should not be overly verbose (avoid spamming logs)
- Examples:
  - Service installation completed
  - Configuration file updated
  - Agent started successfully
  - Network connection established
- Visible by default in production deployments

**Usage Example:**
```javascript
var logger = require('./logger');
logger.info('MeshAgent service installed successfully');
logger.info('Upgrade completed, restarting service');
logger.info('Connected to MeshCentral server: wss://example.com');
```

---

#### warn(message) - Lines 65-67

**Purpose:** Logs warning messages indicating potential issues.

**Process:**
1. Calls `log('WARN', LOG_LEVELS.WARN, message)`
2. Always outputs unless level set to ERROR
3. Indicates problems that don't prevent operation

**Parameters:**
- `message` (string) - Warning message content

**Return Value:** None

**Exceptions:** None

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Used for recoverable errors and suspicious conditions
- Higher priority than INFO (levelValue = 2)
- Examples:
  - Permission denied (but operation continued)
  - Configuration file missing (using defaults)
  - Deprecated feature usage
  - Resource constraints (low disk space)
  - Failed but retrying operations
- Should not be used for expected conditions
- Visible even when INFO logging disabled

**Usage Example:**
```javascript
var logger = require('./logger');
logger.warn('Failed to set ownership, continuing anyway');
logger.warn('Configuration file not found, using defaults');
logger.warn('Low disk space: 100MB remaining');
logger.warn('Service restart took longer than expected: 15 seconds');
```

---

#### error(message) - Lines 69-71

**Purpose:** Logs error messages indicating failures requiring attention.

**Process:**
1. Calls `log('ERROR', LOG_LEVELS.ERROR, message)`
2. Always outputs (highest priority level)
3. Indicates operation failures or critical problems

**Parameters:**
- `message` (string) - Error message content

**Return Value:** None

**Exceptions:** None

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Highest severity level (levelValue = 3)
- Cannot be suppressed (always visible)
- Use for failures that prevent successful operation
- Should include context and error details
- Examples:
  - Failed to install service
  - Cannot connect to server
  - File I/O errors
  - Invalid configuration
  - Security violations
- Consider including error codes or exception messages
- May trigger alerts in monitoring systems

**Usage Example:**
```javascript
var logger = require('./logger');
logger.error('Failed to install service: ' + error.message);
logger.error('Cannot connect to MeshCentral server after 5 attempts');
logger.error('Invalid .msh file format: missing MeshServer');
logger.error('Security violation: binary ownership changed to non-root');
```

---

#### setLevel(level) - Lines 80-92

**Purpose:** Changes the minimum log level at runtime.

**Process:**
1. **String Input** (lines 81-88):
   - Converts level string to uppercase
   - Validates against LOG_LEVELS keys
   - If valid: Sets currentLevel to numeric value
   - If invalid: Logs warning with valid options
2. **Numeric Input** (lines 89-91):
   - Validates range (0-3)
   - Directly sets currentLevel
3. **Confirmation** (line 85):
   - Logs INFO message confirming level change

**Parameters:**
- `level` (string or number) - New log level
  - String: "DEBUG", "INFO", "WARN", "ERROR" (case-insensitive)
  - Number: 0 (DEBUG), 1 (INFO), 2 (WARN), 3 (ERROR)

**Return Value:** None

**Exceptions:** None (invalid levels generate warning)

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Case-insensitive for string input (automatically converts to uppercase)
- Invalid string levels generate WARN message but don't throw exception
- Numeric input bypasses validation (trusts caller)
- Level change is immediate (affects subsequent log calls)
- Confirmation message uses INFO level (may not be visible if setting to WARN/ERROR)
- Common use cases:
  - Enable DEBUG during troubleshooting
  - Reduce to WARN/ERROR in production
  - Temporarily increase verbosity for specific operations

**Usage Examples:**
```javascript
var logger = require('./logger');

// Enable debug logging
logger.setLevel('DEBUG');  // Case-insensitive
logger.debug('Now you can see debug messages');

// Reduce noise in production
logger.setLevel('WARN');
logger.info('This will not be visible');
logger.warn('This will be visible');

// Using numeric levels
logger.setLevel(0);  // Same as 'DEBUG'
logger.setLevel(1);  // Same as 'INFO'

// Invalid level (generates warning)
logger.setLevel('TRACE');  // Warns: "Invalid log level: TRACE. Valid levels: DEBUG, INFO, WARN, ERROR"
```

---

#### getLevel() - Lines 98-105

**Purpose:** Retrieves the current minimum log level as a string.

**Process:**
1. Iterates through LOG_LEVELS object
2. Compares each value with currentLevel
3. Returns matching level name
4. Falls back to 'INFO' if no match (safety)

**Parameters:** None

**Return Value:** String - Current log level name ("DEBUG", "INFO", "WARN", "ERROR")

**Exceptions:** None

**Platform Behavior:** Consistent across all platforms

**Technical Notes:**
- Uses reverse lookup (value → key)
- Fallback to 'INFO' prevents returning undefined
- Useful for:
  - Saving log level in configuration
  - Displaying current level in diagnostics
  - Conditional logic based on verbosity
  - Testing log level changes
- Returns uppercase string matching LOG_LEVELS keys

**Usage Example:**
```javascript
var logger = require('./logger');

console.log('Current log level: ' + logger.getLevel());
// Output: "Current log level: INFO"

logger.setLevel('DEBUG');
console.log('Current log level: ' + logger.getLevel());
// Output: "Current log level: DEBUG"

// Save to config
var config = { logLevel: logger.getLevel() };

// Check verbosity
if (logger.getLevel() === 'DEBUG') {
    // Perform expensive debug operations
}
```

---

### Module Exports - Lines 107-115

**Purpose:** Exports public API for use by other modules.

**Exported Properties:**
```javascript
module.exports = {
    debug: debug,         // Function: Log DEBUG messages
    info: info,           // Function: Log INFO messages
    warn: warn,           // Function: Log WARN messages
    error: error,         // Function: Log ERROR messages
    setLevel: setLevel,   // Function: Change minimum level
    getLevel: getLevel,   // Function: Get current level
    LOG_LEVELS: LOG_LEVELS // Object: Level constants (read-only reference)
};
```

**LOG_LEVELS Object:**
```javascript
{
    DEBUG: 0,  // Most verbose
    INFO: 1,   // Default level
    WARN: 2,   // Warnings only
    ERROR: 3   // Errors only (least verbose)
}
```

**Technical Notes:**
- LOG_LEVELS exported for reference, but modifying it won't affect filtering
- All functions are exported directly (not bound, so 'this' is not an issue)
- Module state is private (currentLevel not exported)
- No constructor function (stateless API)

---

## Usage

### Basic Usage

```javascript
var logger = require('./logger');

// Log messages at different levels
logger.debug('Detailed debugging information');
logger.info('Service started successfully');
logger.warn('Configuration file missing, using defaults');
logger.error('Failed to connect to server');
```

### Configuring Log Level

```javascript
var logger = require('./logger');

// Default: INFO level (debug messages suppressed)
logger.debug('Not visible');
logger.info('Visible');

// Enable debug logging
logger.setLevel('DEBUG');
logger.debug('Now visible');

// Only errors and warnings
logger.setLevel('WARN');
logger.info('Not visible');
logger.warn('Visible');
logger.error('Visible');

// Check current level
console.log('Current level: ' + logger.getLevel());
```

### Integration with Error Handling

```javascript
var logger = require('./logger');

function installService(options) {
    logger.info('Installing service: ' + options.name);

    try {
        // Perform installation
        logger.debug('Creating service directories');
        createDirectories(options.installPath);

        logger.debug('Copying binaries');
        copyBinaries(options.sourcePath, options.installPath);

        logger.info('Service installed successfully');
    } catch (e) {
        logger.error('Installation failed: ' + e.message);
        throw e;
    }
}
```

### Module Integration Pattern

```javascript
// In security-permissions.js
var logger = require('./logger');

function setSecurePermissions(filePath, fileType, options) {
    logger.debug('[SECURITY-PERMS] setSecurePermissions(' + filePath + ', ' + fileType + ')');

    // ... perform operations ...

    logger.info('[SECURITY-PERMS] Set permissions: ' + filePath);
}

// In agent-installer.js
var logger = require('./logger');

function upgradeAgent(params) {
    logger.info('[INSTALLER] Starting upgrade process');
    logger.debug('[INSTALLER] Parameters: ' + JSON.stringify(params));

    // ... upgrade logic ...

    logger.info('[INSTALLER] Upgrade completed successfully');
}
```

### Dynamic Level Control

```javascript
var logger = require('./logger');

// Read from configuration file
var config = loadConfig();
if (config.debugMode) {
    logger.setLevel('DEBUG');
}

// Temporary verbosity increase
var originalLevel = logger.getLevel();
logger.setLevel('DEBUG');

// Perform complex operation
performComplexOperation();

// Restore original level
logger.setLevel(originalLevel);
```

---

## Dependencies

### Node.js Core Modules

**None** - This module has zero external dependencies.

### Built-in JavaScript APIs

- **console.log** (line 53)
  - Purpose: Output formatted log messages
  - Available in all JavaScript environments
  - No configuration needed

- **Date** (line 39)
  - Purpose: Generate timestamps
  - Methods used:
    - `getFullYear()` - 4-digit year
    - `getMonth()` - Month (0-11)
    - `getDate()` - Day of month (1-31)
    - `getHours()` - Hour (0-23)
    - `getMinutes()` - Minute (0-59)
    - `getSeconds()` - Second (0-59)
  - Uses local timezone (not UTC)

### Dependency Summary

| Dependency Type | Module/API | Required | Platform-Specific |
|----------------|------------|----------|-------------------|
| Node.js Core | None | N/A | No |
| JavaScript Built-in | console | Yes | No |
| JavaScript Built-in | Date | Yes | No |

---

## Technical Notes

**Performance Considerations:**

1. **Early Return Optimization:**
   - Level filtering in `log()` happens before string concatenation
   - Suppressed messages have minimal overhead (one comparison)
   - String formatting only occurs for visible messages

2. **No String Building:**
   - Uses simple concatenation (not string builder)
   - Acceptable for log messages (not performance-critical path)

3. **Global State:**
   - Module maintains single global `currentLevel` variable
   - Shared across all modules using logger
   - No per-instance state (module is singleton)

**Thread Safety:**

- JavaScript is single-threaded, so no synchronization needed
- Module state is safe in Node.js event loop model
- No file I/O or async operations (all synchronous)

**Timestamp Accuracy:**

- Timestamp generated at call time (not when message is filtered)
- For suppressed messages, timestamp generation is skipped
- Timestamp reflects local system time (not UTC)
- Format is human-readable, not ISO 8601 compliant

**Output Destination:**

- All output goes to stdout via console.log
- No file logging (use shell redirection if needed)
- No log rotation built-in
- No remote logging support
- Consider using process output redirection:
  ```bash
  meshagent > /var/log/meshagent.log 2>&1
  ```

**Log Level Persistence:**

- Log level is not persisted across restarts
- Defaults to INFO on module load
- Applications should call setLevel() during initialization
- Consider loading from configuration file

**Message Formatting:**

- No message interpolation (use string concatenation)
- No structured logging (JSON, key-value pairs)
- No log metadata (caller location, stack traces)
- Simple format optimized for readability

**Internationalization:**

- Level names are English only
- Timestamp format is fixed (not localized)
- No timezone notation in timestamps

**Alternative Implementations:**

For more advanced logging, consider:
- Winston (npm package) - Feature-rich logger
- Bunyan (npm package) - JSON structured logging
- Pino (npm package) - High-performance logger
- Custom file logging with rotation

**Why This Simple Implementation:**

- Zero dependencies (embedded MeshAgent environment)
- Minimal code size (<100 lines)
- Easy to understand and maintain
- Sufficient for MeshAgent use cases
- No external configuration needed
- Works in restricted environments (Duktape, embedded systems)

---

## Summary

The logger.js module is a lightweight, zero-dependency logging utility providing professional log formatting with timestamps and configurable severity levels. It serves as the standard logging interface throughout MeshAgent, replacing direct console.log calls with filterable, timestamped output.

**Key features:**
- Four log levels: DEBUG, INFO (default), WARN, ERROR
- Automatic timestamp formatting: `YYYY-MM-DD HH:MM:SS`
- Runtime level configuration via setLevel()
- Zero external dependencies (pure JavaScript)
- Simple, familiar API matching console patterns
- Cross-platform compatible (all operating systems)

**Design philosophy:**
- Simplicity over features
- Zero configuration needed
- Minimal performance overhead
- Readable output format
- No external dependencies

**Common usage patterns:**
- Import once: `var logger = require('./logger');`
- Use throughout: `logger.info('message')`
- Configure once: `logger.setLevel('DEBUG')` (if needed)
- Check level: `logger.getLevel()` (for diagnostics)

The module represents a practical, minimal logging solution suitable for embedded environments where full-featured logging frameworks would add unnecessary complexity and dependencies. It provides just enough functionality for effective debugging and monitoring without requiring external packages or complex configuration.
