# promise.js

Custom Promise implementation for MeshAgent that provides ES6-style promise functionality with enhanced memory management, event-driven architecture, and uncaught rejection detection. This module serves as a polyfill for environments where native promises may be unavailable or inconsistent.

## Platform

**Supported Platforms:**
- Windows (win32) - Full support
- Linux - Full support
- FreeBSD - Full support
- **macOS (darwin)** - Full support

**Platform Independence:**

This module is completely platform-agnostic JavaScript code with no platform-specific dependencies or implementations. It provides identical functionality across all operating systems.

**Universal Compatibility:**

The promise module is a pure JavaScript implementation that:
- Does not use any native bindings or system calls
- Does not depend on platform-specific modules
- Does not access file systems or operating system APIs
- Relies only on Node.js core EventEmitter functionality
- Works identically on all platforms supported by MeshAgent

**macOS Support:**

macOS is fully supported with zero platform-specific code. The module operates identically on macOS as on any other platform, providing complete promise functionality without any modifications or special handling.

## Functionality

### Purpose

The promise module implements a custom Promise/A+ compatible promise system specifically designed for MeshAgent's needs. It provides:

- **Promise Creation and Chaining** - Full then/catch/finally support
- **Memory Management** - Automatic cleanup of resolved promises
- **Uncaught Rejection Detection** - Immediate notification of unhandled rejections
- **Parent-Child Relationships** - Tracking promise chains for proper cleanup
- **Event-Based Architecture** - Built on Node.js EventEmitter for flexibility
- **Static Methods** - Promise.resolve, Promise.reject, Promise.all
- **Reference Tracking** - Prevents garbage collection of pending promises

This module is used throughout MeshAgent to:
- Coordinate asynchronous operations
- Chain multiple async tasks sequentially
- Handle errors in async workflows
- Manage complex state machines
- Provide consistent async API patterns

### Key Functions and Classes

#### Promise(promiseFunc) Constructor - Lines 62-344

**Purpose:** Creates a new Promise object with resolver/rejector functions and establishes event-based completion handling.

**Constructor Process:**

```javascript
function Promise(promiseFunc) {
    // 1. Setup internal state
    this._ObjectID = 'promise';
    this.promise = this;
    this._internal = {
        _ObjectID: 'promise.internal',
        promise: this,
        completed: false,
        errors: false,
        completedArgs: [],
        internalCount: 0,
        _up: null
    };

    // 2. Make internal object an EventEmitter
    require('events').EventEmitter.call(this._internal);

    // 3. Define parent promise tracking
    Object.defineProperty(this, "parentPromise", {
        get: function () { return (this._up); },
        set: function (value) {
            if (value != null && this._up == null) {
                // Clear uncaught rejection timer when adopted
                if (this._internal.uncaught != null) {
                    clearImmediate(this._internal.uncaught);
                    this._internal.uncaught = null;
                }
            }
            this._up = value;
        }
    });

    // 4. Execute promise function
    try {
        promiseFunc.call(this,
            this._internal.resolver.bind(this._internal),
            this._internal.rejector.bind(this._internal)
        );
    } catch (e) {
        // Synchronous error - reject immediately
        this._internal.errors = true;
        this._internal.completed = true;
        this._internal.completedArgs = [e];
        this._internal.emit('rejected', e);
        this._internal.emit('settled');
    }

    // 5. Track active promises
    if(!this._internal.completed) {
        refTable[this._internal._hashCode()] = this._internal;
        this._internal.once('settled', function () {
            delete refTable[this._hashCode()];
        });
    }
}
```

**Parameters:**
- `promiseFunc` (function) - Executor function receiving (resolve, reject) parameters

**Internal State Properties:**
- `completed` (boolean) - Whether promise has resolved or rejected
- `errors` (boolean) - Whether promise rejected (true) or resolved (false)
- `completedArgs` (array) - Arguments passed to resolve/reject
- `uncaught` (immediate ID) - Timer for uncaught rejection detection

**Memory Management:**
- Pending promises stored in `refTable` to prevent garbage collection
- Removed from refTable on settlement (line 306-310)
- Parent references cleared on settlement (line 334-340)
- Event listeners removed on completion (line 341-342)

---

#### resolver() - Lines 147-178

**Purpose:** Internal function that resolves the promise with success values.

**Process:**
```javascript
this._internal.resolver = function _resolver() {
    if (this.completed) { return; }  // Ignore if already settled

    // 1. Mark as resolved
    this.errors = false;
    this.completed = true;
    this.completedArgs = [];

    // 2. Build arguments
    var args = ['resolved'];
    if (this.emit_returnValue && this.emit_returnValue('resolved') != null) {
        // Handler returned a value
        this.completedArgs.push(this.emit_returnValue('resolved'));
        args.push(this.emit_returnValue('resolved'));
    } else {
        // Use provided arguments
        for (var a in arguments) {
            this.completedArgs.push(arguments[a]);
            args.push(arguments[a]);
        }
    }

    // 3. Check if resolved with another promise
    if (args.length == 2 && args[1] != null &&
        typeof(args[1]) == 'object' && args[1]._ObjectID == 'promise') {
        // Chain to the returned promise
        var pr = getRootPromise(this.promise);
        args[1]._XSLF = this;
        args[1].then(return_resolved, return_rejected);
    } else {
        // Normal resolution
        this.emit.apply(this, args);
        this.emit('settled');
    }
};
```

**Behavior:**
- Ignores multiple resolution attempts (idempotent)
- Stores arguments for late-binding handlers
- Handles promise-returning handlers specially
- Emits 'resolved' and 'settled' events

---

#### rejector() - Lines 180-201

**Purpose:** Internal function that rejects the promise with error values.

**Process:**
```javascript
this._internal.rejector = function _rejector() {
    if (this.completed) { return; }  // Ignore if already settled

    // 1. Mark as rejected
    this.errors = true;
    this.completed = true;
    this.completedArgs = [];

    // 2. Build arguments
    var args = ['rejected'];
    for (var a in arguments) {
        this.completedArgs.push(arguments[a]);
        args.push(arguments[a]);
    }

    // 3. Setup uncaught rejection detection
    var r = getRootPromise(this.promise);
    if ((r._internal.external == null || r._internal.external == false) &&
        r._internal.uncaught == null) {
        // No rejection handler registered yet - schedule uncaught warning
        r._internal.uncaught = setImmediate(emitreject, arguments[0]);
    }

    // 4. Emit rejection
    this.emit.apply(this, args);
    this.emit('settled');
};
```

**Uncaught Rejection Detection:**
- Sets immediate timer for uncaught rejection (line 196)
- Timer cleared if rejection handler added (lines 119-133, 228, 246-249)
- Emits 'uncaughtException' if no handler registered (line 60)

---

#### then(resolved, rejected) - Lines 235-288

**Purpose:** Registers handlers for promise resolution/rejection and returns a new promise for chaining.

**Process:**
```javascript
this.then = function (resolved, rejected) {
    // 1. Register resolved handler
    if (resolved) {
        this._internal.once('resolved', event_switcher(this, resolved).func.internal);
    }

    // 2. Register rejected handler
    if (rejected) {
        if (this._internal.completed) {
            // Already rejected - clear uncaught timer
            var r = getRootPromise(this);
            if(r._internal.uncaught != null) {
                clearImmediate(r._internal.uncaught);
            }
        }
        this._internal.once('rejected', event_switcher(this, rejected).func.internal);
    }

    // 3. Create child promise for chaining
    var retVal = new Promise(promiseInitializer);
    retVal.parentPromise = this;

    // 4. Setup handler return value inspection
    if (this._internal.completed) {
        // Promise already resolved - handle immediately
        var rv = this._internal.emit_returnValue('resolved');
        if(rv != null) {
            if(rv._ObjectID == 'promise') {
                // Handler returned a promise - chain it
                rv.parentPromise = this;
                rv._internal.once('resolved', retVal._internal.resolver.bind(retVal._internal).internal);
                rv._internal.once('rejected', retVal._internal.rejector.bind(retVal._internal).internal);
            } else {
                // Handler returned a value - resolve with it
                retVal._internal.resolver.call(retVal._internal, rv);
            }
        } else {
            // No return value - propagate original
            this._internal.once('resolved', retVal._internal.resolver.bind(retVal._internal).internal);
            this._internal.once('rejected', retVal._internal.rejector.bind(retVal._internal).internal);
        }
    } else {
        // Promise not yet resolved - setup inspection
        this._internal.once('resolved', this._internal.resolveInspector);
        this._internal.once('rejected', retVal._internal.rejector.bind(retVal._internal).internal);
    }

    // 5. Store child reference
    this.__childPromise = retVal;
    return(retVal);
};
```

**Parameters:**
- `resolved` (function, optional) - Handler for successful resolution
- `rejected` (function, optional) - Handler for rejection

**Returns:** New promise that resolves/rejects based on handler behavior

**Handler Behavior:**
- If handler returns a promise, chain to it
- If handler returns a value, resolve child with value
- If handler returns nothing, propagate parent resolution
- If handler throws, reject child with error

---

#### catch(func) - Lines 225-230

**Purpose:** Registers rejection handler (syntactic sugar for then(null, func)).

**Implementation:**
```javascript
this.catch = function(func) {
    var rt = getRootPromise(this);
    if (rt._internal.uncaught != null) {
        clearImmediate(rt._internal.uncaught);
    }
    this._internal.once('rejected', event_switcher(this, func).func.internal);
}
```

**Behavior:**
- Clears uncaught rejection timer
- Does NOT return a new promise (differs from ES6)
- Calls handler with rejection reason

---

#### finally(func) - Lines 231-234

**Purpose:** Registers handler for promise settlement (resolved or rejected).

**Implementation:**
```javascript
this.finally = function (func) {
    this._internal.once('settled', event_switcher(this, func).func.internal);
};
```

**Behavior:**
- Called regardless of resolution or rejection
- Useful for cleanup operations
- Does NOT receive resolution/rejection value

---

#### Promise.resolve(...args) - Lines 346-356

**Purpose:** Static method that creates an immediately resolved promise.

**Implementation:**
```javascript
Promise.resolve = function resolve() {
    var retVal = new Promise(function (r, j) { });
    var args = [];
    for (var i in arguments) {
        args.push(arguments[i]);
    }
    retVal._internal.resolver.apply(retVal._internal, args);
    return (retVal);
};
```

**Usage:**
```javascript
var p = Promise.resolve('success', {data: 123});
p.then(function(val, obj) {
    console.log(val);  // 'success'
    console.log(obj);  // {data: 123}
});
```

---

#### Promise.reject(...args) - Lines 357-365

**Purpose:** Static method that creates an immediately rejected promise.

**Implementation:**
```javascript
Promise.reject = function reject() {
    var retVal = new Promise(function (r, j) { });
    var args = [];
    for (var i in arguments) {
        args.push(arguments[i]);
    }
    retVal._internal.rejector.apply(retVal._internal, args);
    return (retVal);
};
```

**Usage:**
```javascript
var p = Promise.reject('error message', 404);
p.catch(function(msg, code) {
    console.log(msg);   // 'error message'
    console.log(code);  // 404
});
```

---

#### Promise.all(promiseList) - Lines 366-402

**Purpose:** Static method that waits for all promises to resolve or any to reject.

**Implementation:**
```javascript
Promise.all = function all(promiseList) {
    var ret = new Promise(function (res, rej) {
        this.__rejector = rej;
        this.__resolver = res;
        this.__promiseList = promiseList;
        this.__done = false;
        this.__count = 0;
    });

    for (var i in promiseList) {
        promiseList[i].then(function () {
            // Success - increment count
            if(++ret.__count == ret.__promiseList.length) {
                ret.__done = true;
                ret.__resolver(ret.__promiseList);
            }
        }, function (arg) {
            // Failure - reject immediately
            if(!ret.__done) {
                ret.__done = true;
                ret.__rejector(arg);
            }
        });
    }

    if (promiseList.length == 0) {
        ret.__resolver(promiseList);
    }

    return (ret);
};
```

**Behavior:**
- Resolves when ALL promises resolve (passes array of promises)
- Rejects immediately on FIRST rejection (fail-fast)
- Empty array resolves immediately
- Does NOT unwrap promise results (returns promise array)

---

#### Helper Functions

**getRootPromise(obj)** - Lines 25-32
- Traverses parentPromise chain to find root
- Used for uncaught rejection tracking
- Ensures only root promise schedules uncaught warnings

**event_switcher(desired_callee, target)** - Lines 34-37
- Binds handler function to promise object context
- Marks function as internal to prevent double-wrapping
- Returns object with bound func property

**event_forwarder(sourceObj, sourceName, targetObj, targetName)** - Lines 39-42
- Forwards events between objects
- Used for event propagation in promise chains

**promiseInitializer(r,j)** - Lines 19-23
- Default initializer for child promises
- Stores resolve/reject functions as _res/_rej

---

### Usage Examples

#### Basic Promise Creation

```javascript
var Promise = require('promise');

// Create a promise
var p = new Promise(function(resolve, reject) {
    setTimeout(function() {
        resolve('success', {data: 123});
    }, 1000);
});

// Handle resolution
p.then(function(message, obj) {
    console.log(message);  // 'success'
    console.log(obj.data); // 123
});
```

#### Promise Chaining

```javascript
var Promise = require('promise');

function asyncOperation() {
    return new Promise(function(res, rej) {
        res('step1');
    });
}

asyncOperation()
    .then(function(val) {
        console.log(val);  // 'step1'
        return 'step2';
    })
    .then(function(val) {
        console.log(val);  // 'step2'
        return new Promise(function(res, rej) {
            res('step3');
        });
    })
    .then(function(val) {
        console.log(val);  // 'step3'
    });
```

#### Error Handling

```javascript
var Promise = require('promise');

var p = new Promise(function(res, rej) {
    rej('error occurred');
});

// Using catch
p.catch(function(err) {
    console.log('Caught: ' + err);
});

// Using then with rejection handler
var p2 = new Promise(function(res, rej) {
    rej('error 2');
});

p2.then(function(val) {
    console.log('Success');
}, function(err) {
    console.log('Failed: ' + err);
});
```

#### Promise.all

```javascript
var Promise = require('promise');

var p1 = new Promise(function(res, rej) {
    setTimeout(function() { res('p1 done'); }, 100);
});

var p2 = new Promise(function(res, rej) {
    setTimeout(function() { res('p2 done'); }, 200);
});

var p3 = new Promise(function(res, rej) {
    setTimeout(function() { res('p3 done'); }, 150);
});

Promise.all([p1, p2, p3]).then(function(promises) {
    // All promises resolved
    console.log('All completed');

    // Note: promises array contains promise objects, not results
    // To get results, access promises[i]._internal.completedArgs
}).catch(function(err) {
    console.log('One failed: ' + err);
});
```

#### Static Methods

```javascript
var Promise = require('promise');

// Immediate resolution
Promise.resolve('immediate').then(function(val) {
    console.log(val);  // 'immediate'
});

// Immediate rejection
Promise.reject('error').catch(function(err) {
    console.log(err);  // 'error'
});
```

#### Finally for Cleanup

```javascript
var Promise = require('promise');

var file = null;

new Promise(function(res, rej) {
    file = require('fs').openSync('/path/file', 'r');
    // ... do work
    res('done');
})
.finally(function() {
    if (file) {
        require('fs').closeSync(file);
    }
});
```

### Dependencies

#### Node.js Core Modules

- **`events`** (line 67, 89, 93)
  - EventEmitter class
  - Used as base for promise._internal object
  - Provides event registration and emission
  - Methods used:
    - `EventEmitter.call(obj)` - Initialize as EventEmitter
    - `emit(event, ...args)` - Emit events
    - `once(event, handler)` - One-time event listener
    - `removeAllListeners(event)` - Cleanup handlers
    - `getProperty.call(obj, name)` - Get object property
    - `setProperty.call(obj, name, value)` - Set object property

#### MeshAgent Module Dependencies

None - This module is self-contained and does not require any other MeshAgent modules.

#### System Dependencies

None - Pure JavaScript implementation with no native bindings or system calls.

### Code Structure

The module is organized into functional sections:

1. **Lines 1-16:** Copyright and license header
2. **Lines 17-23:** Reference tracking and initializer
3. **Lines 25-42:** Helper functions (getRootPromise, event_switcher, event_forwarder)
4. **Lines 45-61:** Return value forwarding functions
5. **Lines 62-344:** Main Promise class
   - Lines 64-96: Object initialization and properties
   - Lines 96-146: Event handling and late binding
   - Lines 147-178: Resolver implementation
   - Lines 180-201: Rejector implementation
   - Lines 202-224: Resolve inspector for chaining
   - Lines 225-234: catch() and finally() methods
   - Lines 235-288: then() method with chaining
   - Lines 290-343: Cleanup and settlement handling
6. **Lines 346-402:** Static methods (resolve, reject, all)
7. **Lines 404-407:** Module exports

### Technical Notes

**Memory Management Strategy:**

The module implements sophisticated memory management to prevent premature garbage collection:

```javascript
// Reference table holds all pending promises
var refTable = {};

// On creation, add to reference table
if(!this._internal.completed) {
    refTable[this._internal._hashCode()] = this._internal;
    this._internal.once('settled', function () {
        delete refTable[this._hashCode()];
    });
}
```

This ensures pending promises remain in memory even without external references, preventing resolution handlers from being garbage collected before execution.

**Uncaught Rejection Detection:**

The module implements immediate uncaught rejection detection:

```javascript
// On rejection without handler
r._internal.uncaught = setImmediate(emitreject, arguments[0]);

// emitreject function
function emitreject(a) {
    process.emit('uncaughtException', 'promise.uncaughtRejection: ' + JSON.stringify(a));
}

// Cleared when handler added
if (rt._internal.uncaught != null) {
    clearImmediate(rt._internal.uncaught);
    rt._internal.uncaught = null;
}
```

This provides immediate feedback for unhandled rejections, unlike ES6 promises which may delay reporting.

**Parent-Child Promise Chains:**

The module tracks promise relationships for proper cleanup:

```javascript
// Child promise references parent
retVal.parentPromise = this;

// Parent tracks child
this.__childPromise = retVal;

// Cleanup on settlement
delete this.promise._up;
delete this.promise.__childPromise;
```

This allows traversing the promise chain (getRootPromise) and ensures proper memory release.

**Event-Based Architecture:**

The module leverages Node.js EventEmitter for flexible handler management:

- `resolved` event - Promise resolved successfully
- `rejected` event - Promise rejected with error
- `settled` event - Promise completed (resolved or rejected)
- `newListener2` event - Custom event for late-binding handlers

This allows handlers to be added after promise settlement and still execute.

**Late-Binding Support:**

Handlers can be added after promise resolution:

```javascript
// Promise already resolved
if (eventName == 'resolved' && !this.errors && this.completed) {
    r = eventCallback.apply(this, this.completedArgs);
    // ... handle return value
}
```

The module stores completion arguments (`completedArgs`) to replay for late-added handlers.

**Descriptor Metadata:**

The module supports debugging metadata:

```javascript
Object.defineProperty(this, "descriptorMetadata", {
    get: function () {
        return (require('events').getProperty.call(this._internal, '?_FinalizerDebugMessage'));
    },
    set: function (value) {
        require('events').setProperty.call(this._internal, '?_FinalizerDebugMessage', value);
    }
});
```

This allows attaching debug information to promises for troubleshooting.

**Differences from ES6 Promises:**

| Feature | This Module | ES6 Promises |
|---------|-------------|--------------|
| Multiple arguments | Supported | Single value only |
| catch() returns promise | No | Yes |
| Uncaught rejection timing | Immediate | Next tick |
| Promise.all result | Promise array | Values array |
| Late binding | Supported | Supported |
| finally() | Supported | Supported (ES2018) |

### Platform-Specific Analysis

**Platform Independence:**

This module contains zero platform-specific code:
- No platform detection (no process.platform checks)
- No native module dependencies
- No file system or OS API usage
- Pure JavaScript implementation
- Relies only on Node.js core EventEmitter

**What Works on All Platforms:**

All features work identically on every platform:
- Promise creation and initialization
- Resolution and rejection
- Promise chaining with then/catch/finally
- Static methods (resolve, reject, all)
- Memory management and garbage collection prevention
- Uncaught rejection detection
- Parent-child promise relationships
- Event-based handler registration
- Late-binding support

**macOS-Specific Analysis:**

macOS behavior is identical to all other platforms:
- No special considerations needed
- No platform-specific code paths
- No performance differences
- No compatibility issues
- No macOS-specific bugs or limitations

**Cross-Platform Guarantee:**

The module provides absolute cross-platform compatibility because:
1. It's pure JavaScript with no native dependencies
2. It uses only Node.js core modules (events)
3. It doesn't interact with the operating system
4. It doesn't use platform-specific APIs
5. All behavior is deterministic and platform-independent

## Summary

The promise.js module is a sophisticated custom Promise implementation that provides ES6-style promise functionality with enhanced memory management, immediate uncaught rejection detection, and event-driven architecture. It is **fully supported on all platforms** including **Windows, Linux, FreeBSD, and macOS** without any platform-specific code or behavior differences.

**Universal Platform Support:**
- Pure JavaScript implementation
- No native dependencies or system calls
- Identical behavior across all operating systems
- Based solely on Node.js EventEmitter
- Zero platform-specific considerations

**Key Features:**
- Complete promise lifecycle management
- Sophisticated memory management preventing premature garbage collection
- Immediate uncaught rejection detection via setImmediate
- Support for multiple resolution/rejection arguments
- Promise chaining with return value inspection
- Static methods for convenience (resolve, reject, all)
- Late-binding handler support
- Parent-child relationship tracking for proper cleanup

The module serves as a reliable promise polyfill for MeshAgent, providing consistent promise behavior across all platforms while offering features beyond standard ES6 promises such as multiple arguments, immediate uncaught rejection warnings, and sophisticated reference tracking. It is production-ready and platform-agnostic, making it suitable for cross-platform JavaScript applications requiring robust asynchronous operation coordination.
