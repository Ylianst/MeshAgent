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
// Helper module to derive configuration filenames from executable name.
// This allows binaries with different names (e.g., 'lithium-remote' vs 'meshagent')
// to use matching configuration files (.msh, .db).
//

var cachedBaseName = null;

// Get the base name of the agent executable (without path or extension)
// Examples:
//   /usr/local/bin/lithium-remote -> "lithium-remote"
//   /path/to/LithiumRemote.app/Contents/MacOS/lithium-remote -> "lithium-remote"
//   C:\Program Files\meshagent.exe -> "meshagent"
function getAgentBaseName() {
    if (cachedBaseName !== null) {
        return cachedBaseName;
    }

    var execPath = process.execPath;

    // Get basename (portion after last path separator)
    var baseName = execPath;
    var lastSlash = execPath.lastIndexOf('/');
    var lastBackslash = execPath.lastIndexOf('\\');
    var lastSep = Math.max(lastSlash, lastBackslash);
    if (lastSep >= 0) {
        baseName = execPath.substring(lastSep + 1);
    }

    // Strip .exe extension on Windows
    if (process.platform === 'win32' && baseName.toLowerCase().endsWith('.exe')) {
        baseName = baseName.substring(0, baseName.length - 4);
    }

    cachedBaseName = baseName;
    return baseName;
}

// Get the .db filename matching the agent executable
// Examples:
//   lithium-remote -> "lithium-remote.db"
//   meshagent -> "meshagent.db"
function getAgentDbName() {
    return getAgentBaseName() + '.db';
}

// Get the .msh filename matching the agent executable
// Examples:
//   lithium-remote -> "lithium-remote.msh"
//   meshagent -> "meshagent.msh"
function getAgentMshName() {
    return getAgentBaseName() + '.msh';
}

// Get the base name pattern for file matching (for uninstall, etc.)
// Returns the base name for use in pattern matching like "baseName.*"
function getAgentFilePattern() {
    return getAgentBaseName() + '.';
}

module.exports = {
    getAgentBaseName: getAgentBaseName,
    getAgentDbName: getAgentDbName,
    getAgentMshName: getAgentMshName,
    getAgentFilePattern: getAgentFilePattern
};
