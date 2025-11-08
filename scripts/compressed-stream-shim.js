#!/usr/bin/env node

/*
Copyright 2024 Intel Corporation
@author Claude (Anthropic)

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
// compressed-stream-shim.js
//
// This is a Node.js shim that provides a compressed-stream interface
// compatible with MeshAgent's native compressed-stream module.
//
// PURPOSE:
//   MeshAgent includes a native C module called 'compressed-stream' that
//   is used by code-utils.js to compress JavaScript modules before embedding
//   them into the C source code. This shim allows developers to use Node.js's
//   built-in zlib module instead of requiring a compiled MeshAgent binary.
//
// USAGE:
//   This file should be copied to node_modules/compressed-stream.js
//   Use the setup script: ./scripts/setup-build-tools.sh
//
// COMPATIBILITY:
//   - Uses Node.js zlib.deflateRawSync() for compression (synchronous)
//   - Uses Node.js zlib.createInflateRaw() for decompression (streaming)
//   - Compatible with modules/code-utils.js compress() function
//
// NOTE:
//   This shim uses Node.js's standard deflate implementation. The output
//   may differ slightly from MeshAgent's native implementation, but the
//   compression format is compatible and the differences are negligible.
//

var zlib = require('zlib');
var { EventEmitter } = require('events');

//
// createCompressor()
// Returns an EventEmitter-like object that compresses data using deflate
//
function createCompressor() {
    var emitter = new EventEmitter();

    emitter.end = function(data) {
        // Use synchronous compression to match code-utils.js expectations
        // code-utils.js expects the 'data' event to fire before end() returns
        var compressed = zlib.deflateRawSync(data);

        // Emit the compressed data synchronously
        emitter.emit('data', compressed);
    };

    emitter.on = function(event, callback) {
        EventEmitter.prototype.on.call(this, event, callback);
        return this;
    };

    return emitter;
}

//
// createDecompressor()
// Returns an EventEmitter-like object that decompresses data using inflate
//
function createDecompressor() {
    var emitter = new EventEmitter();
    var inflate = zlib.createInflateRaw();

    inflate.on('data', function(chunk) {
        emitter.emit('data', chunk);
    });

    inflate.on('end', function() {
        emitter.emit('end');
    });

    emitter.end = function(data) {
        inflate.end(data);
    };

    emitter.on = function(event, callback) {
        EventEmitter.prototype.on.call(this, event, callback);
        return this;
    };

    return emitter;
}

module.exports = {
    createCompressor: createCompressor,
    createDecompressor: createDecompressor
};
