/*
Copyright 2024 Intel Corporation
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// Professional logging module with timestamps and log levels
//
// Supports: DEBUG, INFO, WARN, ERROR
// Default level: INFO (DEBUG messages are suppressed unless setLevel('DEBUG') is called)
//

// Log level constants
var LOG_LEVELS = {
    DEBUG: 0,
    INFO: 1,
    WARN: 2,
    ERROR: 3
};

// Output mode constants (most verbose wins on collision)
// verbose > info > quiet > silent
var OUTPUT_MODES = {
    VERBOSE: 0,  // Everything (debug, info, warnings, errors)
    INFO: 1,     // Info, warnings, errors
    QUIET: 2,    // Success/failure message only
    SILENT: 3    // Nothing (exit code only)
};

// Current minimum log level (default: INFO)
var currentLevel = LOG_LEVELS.INFO;

// Current output mode (default: INFO - shows info, warnings, errors)
var currentOutputMode = OUTPUT_MODES.INFO;

function pad(num) {
    return num < 10 ? '0' + num : '' + num;
}

function getTimestamp() {
    var d = new Date();
    var year = d.getFullYear();
    var month = pad(d.getMonth() + 1);
    var day = pad(d.getDate());
    var hours = pad(d.getHours());
    var minutes = pad(d.getMinutes());
    var seconds = pad(d.getSeconds());

    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
}

function log(level, levelValue, message) {
    // Silent mode: suppress all output
    if (currentOutputMode === OUTPUT_MODES.SILENT) {
        return;
    }

    // Quiet mode: suppress debug/info/warn (errors still shown)
    if (currentOutputMode === OUTPUT_MODES.QUIET && levelValue < LOG_LEVELS.ERROR) {
        return;
    }

    // Only log if message level is >= current minimum level
    if (levelValue >= currentLevel) {
        console.log('[' + getTimestamp() + '] ' + level + ': ' + message);
    }
}

function debug(message) {
    log('DEBUG', LOG_LEVELS.DEBUG, message);
}

function info(message) {
    log('INFO', LOG_LEVELS.INFO, message);
}

function warn(message) {
    log('WARN', LOG_LEVELS.WARN, message);
}

function error(message) {
    log('ERROR', LOG_LEVELS.ERROR, message);
}

/**
 * Set the minimum log level
 * @param {string} level - One of: 'DEBUG', 'INFO', 'WARN', 'ERROR'
 * @example
 *   logger.setLevel('DEBUG');  // Enable debug logging
 *   logger.setLevel('WARN');   // Only show warnings and errors
 */
function setLevel(level) {
    if (typeof level === 'string') {
        level = level.toUpperCase();
        if (LOG_LEVELS.hasOwnProperty(level)) {
            currentLevel = LOG_LEVELS[level];
            info('Log level set to: ' + level);
        } else {
            warn('Invalid log level: ' + level + '. Valid levels: DEBUG, INFO, WARN, ERROR');
        }
    } else if (typeof level === 'number' && level >= 0 && level <= 3) {
        currentLevel = level;
    }
}

/**
 * Get the current log level
 * @returns {string} Current log level name
 */
function getLevel() {
    for (var name in LOG_LEVELS) {
        if (LOG_LEVELS[name] === currentLevel) {
            return name;
        }
    }
    return 'INFO';
}

/**
 * Set the output mode
 * @param {string} mode - One of: 'VERBOSE', 'INFO', 'QUIET', 'SILENT'
 * Most verbose wins on collision (call with lowest mode value)
 */
function setOutputMode(mode) {
    if (typeof mode === 'string') {
        mode = mode.toUpperCase();
        if (OUTPUT_MODES.hasOwnProperty(mode)) {
            // Most verbose wins: only change if new mode is more verbose (lower value)
            var newMode = OUTPUT_MODES[mode];
            if (newMode < currentOutputMode) {
                currentOutputMode = newMode;
            }
        }
    } else if (typeof mode === 'number' && mode >= 0 && mode <= 3) {
        if (mode < currentOutputMode) {
            currentOutputMode = mode;
        }
    }
}

/**
 * Force set output mode (ignores most-verbose-wins)
 * @param {string} mode - One of: 'VERBOSE', 'INFO', 'QUIET', 'SILENT'
 */
function forceOutputMode(mode) {
    if (typeof mode === 'string') {
        mode = mode.toUpperCase();
        if (OUTPUT_MODES.hasOwnProperty(mode)) {
            currentOutputMode = OUTPUT_MODES[mode];
        }
    } else if (typeof mode === 'number' && mode >= 0 && mode <= 3) {
        currentOutputMode = mode;
    }
}

/**
 * Get the current output mode
 * @returns {string} Current output mode name
 */
function getOutputMode() {
    for (var name in OUTPUT_MODES) {
        if (OUTPUT_MODES[name] === currentOutputMode) {
            return name;
        }
    }
    return 'QUIET';
}

/**
 * Output a result message (success/failure) - shown in all modes except SILENT
 * Use this for the final success/failure message
 * @param {boolean} success - Whether the operation succeeded
 * @param {string} message - The result message
 */
function result(success, message) {
    if (currentOutputMode === OUTPUT_MODES.SILENT) {
        return;
    }
    var prefix = success ? 'SUCCESS' : 'FAILED';
    console.log('[' + getTimestamp() + '] ' + prefix + ': ' + message);
}

module.exports = {
    debug: debug,
    info: info,
    warn: warn,
    error: error,
    setLevel: setLevel,
    getLevel: getLevel,
    setOutputMode: setOutputMode,
    forceOutputMode: forceOutputMode,
    getOutputMode: getOutputMode,
    result: result,
    LOG_LEVELS: LOG_LEVELS,
    OUTPUT_MODES: OUTPUT_MODES
};
