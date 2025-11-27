/**
 * Unit tests for security-permissions module
 *
 * Run with: node tests/security-permissions-test.js
 *
 * Note: Some tests require root privileges to test chown functionality
 */

var fs = require('fs');
var path = require('path');

// Test helpers
var testsPassed = 0;
var testsFailed = 0;
var testsSkipped = 0;

function assert(condition, message) {
    if (!condition) {
        throw new Error('Assertion failed: ' + message);
    }
}

function test(name, fn) {
    try {
        console.log('\n  Testing: ' + name);
        fn();
        console.log('    ✓ PASS');
        testsPassed++;
    } catch (e) {
        console.log('    ✗ FAIL: ' + e.message);
        if (e.stack) {
            console.log('    ' + e.stack.split('\n').slice(1, 3).join('\n    '));
        }
        testsFailed++;
    }
}

function skip(name, reason) {
    console.log('\n  Skipping: ' + name);
    console.log('    (Reason: ' + reason + ')');
    testsSkipped++;
}

// Setup: Load module
console.log('Loading security-permissions module...');
var secPerms;
try {
    // Try to load from modules directory
    secPerms = require('../modules/security-permissions.js');
    console.log('✓ Module loaded successfully\n');
} catch (e) {
    console.log('✗ Failed to load module: ' + e.message);
    process.exit(1);
}

// Test suite
console.log('=== Security Permissions Module Tests ===\n');

// Test 1: Module exports
test('Module exports all required functions', function() {
    assert(typeof secPerms.setSecurePermissions === 'function', 'setSecurePermissions should be a function');
    assert(typeof secPerms.verifyPermissions === 'function', 'verifyPermissions should be a function');
    assert(typeof secPerms.verifyInstallation === 'function', 'verifyInstallation should be a function');
    assert(typeof secPerms.createFileSecure === 'function', 'createFileSecure should be a function');
    assert(typeof secPerms.getSecurityMode === 'function', 'getSecurityMode should be a function');
    assert(typeof secPerms.PERMISSIONS === 'object', 'PERMISSIONS should be an object');
});

// Test 2: Permission definitions
test('Permission definitions are valid', function() {
    var perms = secPerms.PERMISSIONS;

    assert(perms['.msh'], '.msh permissions should be defined');
    assert(perms['.msh'].mode === 0o600, '.msh should be 0600');
    assert(perms['.msh'].critical === true, '.msh should be critical');

    assert(perms['.db'], '.db permissions should be defined');
    assert(perms['.db'].mode === 0o600, '.db should be 0600');
    assert(perms['.db'].critical === true, '.db should be critical');

    assert(perms['binary'], 'binary permissions should be defined');
    assert(perms['binary'].mode === 0o755, 'binary should be 0755');
    assert(perms['binary'].critical === true, 'binary should be critical');

    assert(perms['.log'], '.log permissions should be defined');
    assert(perms['.log'].mode === 0o640, '.log should be 0640');
});

// Test 3: setSecurePermissions with non-existent file
test('setSecurePermissions fails gracefully for non-existent file', function() {
    var result = secPerms.setSecurePermissions('/tmp/nonexistent-test-file-12345', '.msh');
    assert(result.success === false, 'Should fail for non-existent file');
    assert(result.errors.length > 0, 'Should have error messages');
});

// Test 4: setSecurePermissions with invalid file type
test('setSecurePermissions rejects invalid file type', function() {
    var result = secPerms.setSecurePermissions('/tmp/test', 'invalid-type');
    assert(result.success === false, 'Should fail for invalid type');
    assert(result.errors.length > 0, 'Should have error messages');
    assert(result.errors[0].indexOf('Unknown file type') >= 0, 'Should mention unknown file type');
});

// Test 5: setSecurePermissions dry-run mode
test('setSecurePermissions dry-run mode does not modify files', function() {
    var testFile = '/tmp/security-perms-test-' + Date.now();
    fs.writeFileSync(testFile, 'test content', { mode: 0o644 });

    var result = secPerms.setSecurePermissions(testFile, '.msh', { dryRun: true });

    assert(result.success === true, 'Dry run should succeed');
    assert(result.actions.length > 0, 'Should report actions');

    // Verify file was NOT modified
    var stats = fs.statSync(testFile);
    var mode = stats.mode & parseInt('777', 8);
    assert(mode === 0o644, 'File should still be 0644 in dry-run mode');

    fs.unlinkSync(testFile);
});

// Test 6: setSecurePermissions actually sets permissions
test('setSecurePermissions actually changes file mode', function() {
    var testFile = '/tmp/security-perms-test-' + Date.now();
    fs.writeFileSync(testFile, 'test content', { mode: 0o644 });

    var result = secPerms.setSecurePermissions(testFile, '.msh', { skipChown: true });

    assert(result.success === true, 'Should succeed');

    // Verify file was modified
    var stats = fs.statSync(testFile);
    var mode = stats.mode & parseInt('777', 8);
    assert(mode === 0o600, 'File should now be 0600');

    fs.unlinkSync(testFile);
});

// Test 7: verifyPermissions detects wrong permissions
test('verifyPermissions detects incorrect permissions', function() {
    var testFile = '/tmp/security-perms-test-' + Date.now();
    fs.writeFileSync(testFile, 'test', { mode: 0o644 });

    var result = secPerms.verifyPermissions(testFile, '.msh');

    assert(result.valid === false, 'Should detect wrong permissions');
    assert(result.issues.length > 0, 'Should have issues');
    assert(result.stats !== null, 'Should include stats');
    assert(result.stats.mode === '0644', 'Should report current mode');

    fs.unlinkSync(testFile);
});

// Test 8: verifyPermissions accepts correct permissions
test('verifyPermissions accepts correct permissions', function() {
    var testFile = '/tmp/security-perms-test-' + Date.now();
    fs.writeFileSync(testFile, 'test', { mode: 0o600 });

    var result = secPerms.verifyPermissions(testFile, '.msh');

    // May still fail on ownership if not root, but mode should be correct
    if (result.issues.length > 0) {
        // Check that mode is not in issues (only ownership might be)
        var hasModeIssue = result.issues.some(function(issue) {
            return issue.indexOf('Incorrect mode') >= 0;
        });
        assert(!hasModeIssue, 'Mode should be correct even if ownership is wrong');
    } else {
        assert(result.valid === true, 'Should be valid');
    }

    fs.unlinkSync(testFile);
});

// Test 9: createFileSecure creates file with correct permissions
test('createFileSecure creates file with correct permissions atomically', function() {
    var testFile = '/tmp/security-perms-test-' + Date.now();

    secPerms.createFileSecure(testFile, 'test content', '.msh');

    // Verify file exists
    assert(fs.existsSync(testFile), 'File should exist');

    // Verify content
    var content = fs.readFileSync(testFile, 'utf8');
    assert(content === 'test content', 'Content should match');

    // Verify permissions
    var stats = fs.statSync(testFile);
    var mode = stats.mode & parseInt('777', 8);
    assert(mode === 0o600, 'File should be created with 0600');

    fs.unlinkSync(testFile);
});

// Test 10: verifyInstallation on non-existent directory
test('verifyInstallation handles non-existent directory', function() {
    var result = secPerms.verifyInstallation('/tmp/nonexistent-dir-' + Date.now() + '/');

    // Should not crash, just report no issues (no files to check)
    assert(typeof result === 'object', 'Should return result object');
    assert(typeof result.allValid === 'boolean', 'Should have allValid property');
});

// Test 11: verifyInstallation detects and reports issues
test('verifyInstallation detects permission issues', function() {
    var testDir = '/tmp/security-perms-install-test-' + Date.now() + '/';
    fs.mkdirSync(testDir);

    // Create files with wrong permissions
    fs.writeFileSync(testDir + 'meshagent.msh', 'test', { mode: 0o644 });
    fs.writeFileSync(testDir + 'meshagent.db', 'test', { mode: 0o644 });

    var result = secPerms.verifyInstallation(testDir, { autoFix: false });

    assert(result.allValid === false, 'Should detect issues');
    assert(Object.keys(result.files).length > 0, 'Should check files');

    // Cleanup
    fs.unlinkSync(testDir + 'meshagent.msh');
    fs.unlinkSync(testDir + 'meshagent.db');
    fs.rmdirSync(testDir);
});

// Test 12: verifyInstallation auto-fix
test('verifyInstallation auto-fix corrects permissions', function() {
    var testDir = '/tmp/security-perms-install-test-' + Date.now() + '/';
    fs.mkdirSync(testDir);

    // Create file with wrong permissions
    fs.writeFileSync(testDir + 'meshagent.msh', 'test', { mode: 0o644 });

    var result = secPerms.verifyInstallation(testDir, { autoFix: true });

    assert(result.allValid === false, 'Should detect initial issues');
    assert(result.fixed.length > 0, 'Should fix files');
    assert(result.fixed.indexOf(testDir + 'meshagent.msh') >= 0, 'Should fix .msh file');

    // Verify actually fixed
    var stats = fs.statSync(testDir + 'meshagent.msh');
    var mode = stats.mode & parseInt('777', 8);
    assert(mode === 0o600, 'File should be fixed to 0600');

    // Cleanup
    fs.unlinkSync(testDir + 'meshagent.msh');
    fs.rmdirSync(testDir);
});

// Test 13: getSecurityMode returns default
test('getSecurityMode returns default value', function() {
    var mode = secPerms.getSecurityMode();
    assert(typeof mode === 'string', 'Should return string');
    assert(mode === 'fix', 'Default should be "fix"');
});

// Test 14: Permission normalization
test('verifyInstallation normalizes path with trailing slash', function() {
    var testDir = '/tmp/security-perms-install-test-' + Date.now();
    fs.mkdirSync(testDir);

    // Call without trailing slash
    var result = secPerms.verifyInstallation(testDir);

    // Should not crash
    assert(typeof result === 'object', 'Should handle path without trailing slash');

    fs.rmdirSync(testDir);
});

// Test 15: Multiple file types in one installation
test('verifyInstallation handles multiple file types', function() {
    var testDir = '/tmp/security-perms-install-test-' + Date.now() + '/';
    fs.mkdirSync(testDir);

    // Create multiple files
    fs.writeFileSync(testDir + 'meshagent.msh', 'test', { mode: 0o644 });
    fs.writeFileSync(testDir + 'meshagent.db', 'test', { mode: 0o644 });
    fs.writeFileSync(testDir + 'meshagent', 'binary', { mode: 0o755 });

    var result = secPerms.verifyInstallation(testDir, { autoFix: true });

    // Should check all files
    assert(Object.keys(result.files).length >= 2, 'Should check multiple files');

    // .msh and .db should be fixed, binary should be OK
    var mshFixed = result.fixed.indexOf(testDir + 'meshagent.msh') >= 0;
    var dbFixed = result.fixed.indexOf(testDir + 'meshagent.db') >= 0;
    assert(mshFixed, '.msh should be fixed');
    assert(dbFixed, '.db should be fixed');

    // Cleanup
    fs.unlinkSync(testDir + 'meshagent.msh');
    fs.unlinkSync(testDir + 'meshagent.db');
    fs.unlinkSync(testDir + 'meshagent');
    fs.rmdirSync(testDir);
});

// Conditional tests (require root)
if (process.getuid && process.getuid() === 0) {
    console.log('\n  Running as root - testing ownership functions');

    test('setSecurePermissions sets ownership (root test)', function() {
        var testFile = '/tmp/security-perms-test-' + Date.now();
        fs.writeFileSync(testFile, 'test', { mode: 0o644 });

        var result = secPerms.setSecurePermissions(testFile, '.msh');

        assert(result.success === true, 'Should succeed');
        assert(result.actions.some(function(a) { return a.indexOf('chown') >= 0; }),
               'Should execute chown');

        // Verify ownership
        var stats = fs.statSync(testFile);
        assert(stats.uid === 0, 'Should be owned by root');

        fs.unlinkSync(testFile);
    });

    test('verifyPermissions checks ownership (root test)', function() {
        var testFile = '/tmp/security-perms-test-' + Date.now();

        // Create with correct mode and ownership
        secPerms.createFileSecure(testFile, 'test', '.msh');

        var result = secPerms.verifyPermissions(testFile, '.msh');

        assert(result.valid === true, 'Should be valid with correct ownership');
        assert(result.issues.length === 0, 'Should have no issues');

        fs.unlinkSync(testFile);
    });
} else {
    skip('Ownership tests', 'Requires root privileges (use: sudo node ' + process.argv[1] + ')');
}

// Platform-specific tests
if (process.platform === 'darwin') {
    test('Uses "wheel" group on macOS', function() {
        var perms = secPerms.PERMISSIONS['.msh'];
        assert(perms.group === 'wheel', 'Should use wheel group on macOS');
    });
} else {
    skip('macOS-specific tests', 'Not running on macOS');
}

// Summary
console.log('\n=== Test Summary ===');
console.log('  Passed:  ' + testsPassed);
console.log('  Failed:  ' + testsFailed);
console.log('  Skipped: ' + testsSkipped);
console.log('  Total:   ' + (testsPassed + testsFailed + testsSkipped));

if (testsFailed > 0) {
    console.log('\n✗ Some tests failed');
    process.exit(1);
} else {
    console.log('\n✓ All tests passed!');
    process.exit(0);
}
