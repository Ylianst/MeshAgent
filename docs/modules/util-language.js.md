# util-language.js

Cross-platform system language detection utility that provides consistent language code retrieval across Windows, Linux, macOS, and FreeBSD. Returns standardized two-letter language codes (ISO 639-1 format) using platform-specific system APIs and environment variables.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support via kernel32.dll GetUserDefaultLCID() API
- Linux - Full support via LANG environment variable
- macOS (darwin) - Full support via defaults system utility
- FreeBSD - Full support via LANG environment variable

## Functionality

### Purpose

The util-language module provides a unified interface for determining the system's configured language across different operating systems. Each platform uses its native method:

- **Windows**: Windows API GetUserDefaultLCID() to query user locale
- **Linux/FreeBSD**: Parse LANG environment variable (e.g., "en_US.UTF-8")
- **macOS**: Query system defaults database via `defaults read -g AppleLanguages`

This module is used by MeshAgent to:
- Display localized user interfaces
- Generate localized notifications
- Select appropriate language for messages
- Adapt to user's system language preferences

### Platform-Specific Implementations

#### Windows Implementation - Lines 19-45

Uses Windows kernel32.dll GetUserDefaultLCID() API to retrieve locale identifier:

**API Reference:**
https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getuserdefaultlcid

**Process:**
1. Loads kernel32.dll via native marshaler (line 22)
2. Creates method marshal for GetUserDefaultLCID() (line 23)
3. Calls API to get LCID (Locale Identifier) (line 25)
4. Extracts primary language ID from LCID (line 26)
   - Formula: `LCID & 0xFF` (lowest 8 bits)
5. Maps primary language ID to two-letter ISO 639-1 code (lines 29-44)
6. Returns language code or 'en' as default (line 44)

**Language Mapping Table (lines 29-43):**
```javascript
switch(lid)
{
    case 0x01: return ('ar');  // Arabic
    case 0x02: return ('bg');  // Bulgarian
    case 0x03: return ('ca');  // Catalan
    case 0x04: return ('zh');  // Chinese
    case 0x05: return ('cs');  // Czech
    case 0x06: return ('da');  // Danish
    case 0x07: return ('de');  // German
    case 0x08: return ('el');  // Greek
    case 0x09: return ('en');  // English
    case 0x0a: return ('es');  // Spanish
    case 0x0b: return ('fi');  // Finnish
    case 0x0c: return ('fr');  // French
    case 0x10: return ('it');  // Italian
    case 0x11: return ('ja');  // Japanese
    case 0x12: return ('ko');  // Korean
    case 0x13: return ('nl');  // Dutch
    case 0x15: return ('pl');  // Polish
    case 0x16: return ('pt');  // Portuguese
    case 0x19: return ('ru');  // Russian
    default: return ('en');    // Default to English
}
```

**LCID Structure:**
- Bits 0-9: Language ID
- Bits 0-7: Primary Language ID
- Bits 8-9: Sublanguage ID

**Example:**
```
LCID: 0x0409 (US English)
Primary Language ID: 0x09 (English)
Result: 'en'
```

---

#### Linux/FreeBSD Implementation - Lines 47-61

Parses LANG environment variable to extract language code:

**Process:**
1. Reads LANG environment variable (line 51)
2. Splits on underscore '_' to separate language from locale (line 53)
3. Returns first part (language code) in lowercase (line 54)

**LANG Format:**
```
language_TERRITORY.ENCODING
```

**Examples:**
```
en_US.UTF-8       → 'en'
fr_FR.UTF-8       → 'fr'
de_DE.ISO-8859-1  → 'de'
zh_CN.UTF-8       → 'zh'
```

**Error Handling:**
- If LANG is undefined or empty → Returns 'en' (default)
- If LANG has no underscore → Returns entire value (line 57)
- Wrapped in try-catch → Returns 'en' on error (line 59)

---

#### macOS Implementation - Lines 63-87

Uses `defaults read` system utility to query Apple's language preferences:

**Process:**
1. Spawns `/bin/sh` subprocess (line 68)
2. Executes command:
   ```bash
   defaults read -g AppleLanguages | tr '\n' '`' | awk -F'`' '{ print $2 }'
   ```
3. Parses output which is an array like:
   ```
   (
       "en-US",
       "fr-FR"
   )
   ```
4. Extracts first language (second line of output) (line 79)
5. Splits on hyphen '-' to get language code (line 80)
6. Returns language code in lowercase (line 81)

**AppleLanguages Format:**
```
"language-REGION"
```

**Examples:**
```
en-US    → 'en'
fr-FR    → 'fr'
zh-Hans  → 'zh'
es-ES    → 'es'
```

**Error Handling:**
- If command fails → Returns 'en' (default)
- If output is empty → Returns 'en' (line 84)
- Wrapped in try-catch → Returns 'en' on error (line 84)

---

### Module Export - Lines 89-100

The module exports the appropriate function based on platform:

```javascript
switch(process.platform)
{
    case 'linux':
    case 'freebsd':
        module.exports = linux_lang;
        break;
    case 'win32':
        module.exports = windows_lang;
        break;
    case 'darwin':
        module.exports = macos_lang;
        break;
    default:
        module.exports = function () { return ('en'); };
}
```

**Usage:**
```javascript
var getLanguage = require('util-language');
var lang = getLanguage();
// Returns: 'en', 'fr', 'de', 'es', etc.
```

---

### Dependencies

#### Node.js Core Modules
- `child_process` (lines 68) - Used on macOS:
  - `execFile('/bin/sh', ['sh'])` - Executes shell commands

#### MeshAgent Module Dependencies

**Core Required Modules:**

- **`_GenericMarshal`** (line 22) - **Windows only**
  - Native code marshaling for Windows API calls
  - Methods used:
    - `CreateNativeProxy('Kernel32.dll')` - Load Windows kernel library
  - Used to call GetUserDefaultLCID() API

**Platform System Dependencies:**

**Linux/FreeBSD:**
- **LANG environment variable** - Must be set (typically set by system)
- If not set → Defaults to 'en'

**macOS:**
- **`defaults`** - System Configuration utility (standard on macOS)
- Reads from: Global domain (`-g`) AppleLanguages key
- Shell tools: `tr`, `awk`

**Windows:**
- **Kernel32.dll** - Windows system library (always available)
- GetUserDefaultLCID() API

### Technical Notes

**ISO 639-1 Language Codes:**

The module returns two-letter language codes per ISO 639-1 standard:
- `en` - English
- `fr` - French
- `de` - German
- `es` - Spanish
- `zh` - Chinese
- `ja` - Japanese
- `ar` - Arabic
- etc.

These are standard codes used across internationalization frameworks.

**Windows LCID Structure:**

LCID (Locale Identifier) is a 32-bit value:
```
Bits 31-20: Sort ID
Bits 19-16: Reserved
Bits 15-10: Sort version
Bits  9- 0: Language ID
```

Primary Language ID extraction:
```javascript
var lid = lcid & 0xFF;  // Mask lowest 8 bits
```

This gets the primary language, ignoring sublanguage (e.g., US vs UK English).

**Default Language Strategy:**

All implementations default to 'en' (English) on error:
- Maximum compatibility
- Prevents errors in language-dependent code
- Common fallback in internationalization

**Why Different Methods:**

Each platform stores language preferences differently:
- **Windows**: System registry, accessed via API
- **Linux/FreeBSD**: Environment variables (POSIX standard)
- **macOS**: System configuration database (Apple proprietary)

**LANG Environment Variable:**

On Unix-like systems, LANG follows this format:
```
language[_territory][.codeset][@modifier]
```

Examples:
```
en                    # Just language
en_US                 # Language + territory
en_US.UTF-8          # + character encoding
en_US.UTF-8@euro     # + modifier
```

The module extracts only the language part.

**macOS Language List:**

macOS maintains an ordered list of preferred languages:
```
AppleLanguages = (
    "en-US",
    "fr-FR",
    "de-DE"
);
```

The module returns only the first (most preferred) language.

**Locale vs Language:**

The module returns language, not full locale:
- **Language**: 'en', 'fr', 'de' (2-letter code)
- **Locale**: 'en_US', 'fr_FR', 'de_DE' (includes territory)

For full locale info, use platform-specific APIs directly.

**Error Resilience:**

All implementations use try-catch:
```javascript
try {
    // Platform-specific code
} catch(e) {
    return ('en');
}
```

This ensures the function never throws, always returning a valid language code.

**Performance:**

- **Windows**: Single API call (fast)
- **Linux/FreeBSD**: Environment variable read (very fast)
- **macOS**: Shell command execution (slower, but cached by system)

For performance-critical code, cache the result:
```javascript
global.systemLanguage = global.systemLanguage || require('util-language')();
```

**Synchronous Operation:**

All implementations are synchronous:
- No callbacks
- No promises
- Immediate return
- Safe to call during module initialization

## Summary

The util-language.js module provides cross-platform system language detection for **Windows, Linux, macOS, and FreeBSD**, returning standardized two-letter ISO 639-1 language codes.

Each platform uses its native method:
- **Windows**: GetUserDefaultLCID() API to query user locale
- **Linux/FreeBSD**: LANG environment variable parsing
- **macOS**: `defaults read -g AppleLanguages` system configuration query

The module handles errors gracefully by defaulting to 'en' (English) if language cannot be determined, ensuring it never throws exceptions. All implementations are synchronous and return immediately with a valid language code.

This module is used throughout MeshAgent to adapt user-facing messages and interfaces to the system's configured language, providing a consistent internationalization foundation across all supported platforms.
