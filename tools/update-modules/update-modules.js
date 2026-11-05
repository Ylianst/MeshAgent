/*
Copyright 2026 MeshAgent contributors

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
// Updates the embedded JS modules with the corresponding files in modules/*.js.
// The file changed (in microscript, ILibDuktape_Polyfills.c or ILibDuktape_EmbeddedModules.c)
// depends on which is used: while ILibDuktape_Polyfills.c still carries its addCompressedModule()
// statements, those are what the agent runs, so they are read and written back in that file's own
// format (an inline duk_peval_string_noresult(), or an allocate/memcpy_s/AddCompressedModuleEx/free
// block chunked by LEGACY_CHUNK bytes for large ones). Once stripped, the generated file is the target.
//
// Run through tools/update-modules.sh or tools/update-modules.ps1, which pass these environment variables:
//
//   UPDATE_UPDATE=1            update every entry whose modules/<name>.js changed. Without it, an add or remove
//                              touches only the names given
//   UPDATE_ADD, UPDATE_REMOVE  comma-separated module names to add (or update) and to remove
//   UPDATE_SYNC=1              update, and also add every modules/*.js with no entry yet and drop entries whose file is gone
//   UPDATE_DRYRUN=1            only report what would change
//   UPDATE_CHECK=1             dry run that exits 1 when anything would change, for CI
//   UPDATE_EXPORT=dir          save the embedded scripts, decompressed, into dir
//   UPDATE_LIST=1              print the embedded module names and sizes
//   UPDATE_STRIP_LEGACY=1      write this run's result to ILibDuktape_EmbeddedModules.c, cut the
//                              addCompressedModule() statements out of ILibDuktape_Polyfills.c and add
//                              a call to ILibDuktape_Polyfills_EmbeddedModules(ctx) instead
//
// With none of those, every entry whose modules/<name>.js changed is updated in place. The table is
// re-rendered as a whole, so an unchanged entry produces no diff.
//
// An entry's stamp is the date of the commit that last touched its modules/<name>.js, from one 'git log' over
// modules/. A file git does not know, or one with uncommitted changes, gets its mtime instead, as does everything
// when git is not available.
//
// Module content is embedded with LF line endings whatever the checkout has, so the bytes do not depend on
// which machine regenerated an entry. The C files are read as LF and written back with the line ending they had.
//
// The agent's compressed-stream and Node's zlib speak the same zlib-deflate format, so either runtime works.
//

var fs = require('fs');
var UPDATE_EXIT_CODE = 0;
var CFILE = 'microscript/ILibDuktape_EmbeddedModules.c';
var LEGACY = 'microscript/ILibDuktape_Polyfills.c';
var LEGACYHEADER = 'microscript/ILibDuktape_Polyfills.h';
var MODULEDIR = 'modules';
var isNode = (typeof process != 'undefined' && process.versions != null && process.versions.node != null);

// Above this many base64 characters a legacy entry is chunked into an allocated buffer, because a single
// C string literal that long risks the compiler's literal length limit. Matches the file's existing large entries.
var LEGACY_CHUNK = 16000;

// Pushes data through an agent compressed-stream, which emits synchronously, and returns everything it produced.
function pump(stream, data)
{
    var out = null;
    stream.on('data', function (c) { out = (out == null) ? Buffer.concat([c]) : Buffer.concat([out, c]); });
    stream.end(data);
    return (out);
}
// Node's zlib is Chromium's fork (a different match finder since Node 12.17/14.0), so its deflate stream is valid but not
// byte-equal to the agent's stock zlib, and an entry would change bytes with the engine that regenerated it. pako is a port
// of stock zlib and reproduced all 100 of the agent's entries exactly, so under node it is used whenever it is installed.
var pako;
function loadPako()
{
    if (pako !== undefined) { return (pako); }
    pako = null;
    var paths = ['pako', process.cwd() + '/tools/update-modules/node_modules/pako'], i;
    for (i = 0; i < paths.length && pako == null; ++i) { try { pako = require(paths[i]); } catch (e) { } }
    if (pako == null) { console.log('pako not found (npm install in tools/update-modules/), node\'s own zlib is used: its bytes differ from the agent\'s.'); }
    return (pako);
}
function compress(data)
{
    if (!isNode) { return (pump(require('compressed-stream').createCompressor(), data)); }
    return (loadPako() != null ? Buffer.from(pako.deflate(data)) : require('zlib').deflateSync(data));
}
function decompress(data)
{
    return (isNode ? require('zlib').inflateSync(data) : pump(require('compressed-stream').createDecompressor(), data));
}

// Upstream entries were compressed from CRLF sources and a checkout may have either, so everything embedded or compared goes through lf().
function lf(buf)
{
    return (buf.toString().split('\r\n').join('\n'));
}
// With core.autocrlf a Windows checkout has CRLF C files and a Linux one LF, so a rewritten file keeps what it had.
function eolOf(text)
{
    return (text.indexOf('\r\n') >= 0 ? '\r\n' : '\n');
}
function readOrNull(path)
{
    try { return (fs.readFileSync(path)); } catch (e) { return (null); }
}
function readModule(path)
{
    var buf = readOrNull(path);
    return (buf == null ? null : Buffer.from(lf(buf)));
}
function modulePath(name)
{
    return (MODULEDIR + '/' + name + '.js');
}
// The Windows agent's fs.readdirSync() is a JS wrapper that calls require('os').arch(), and on an agent without
// the alloca fix, loading 'os' takes the whole process down with a native STATUS_BREAKPOINT that no try/catch sees.
// The native _readdirSync() underneath it is fine. It wants a wildcard, takes forward slashes, and drops '.' and '..'.
function readdir(dir)
{
    return (typeof fs._readdirSync == 'function' ? fs._readdirSync(dir + '/*') : fs.readdirSync(dir));
}
function byName(a, b)
{
    return (a.name < b.name ? -1 : (a.name > b.name ? 1 : 0));
}

function pad(n, width)
{
    var s = String(n);
    while (s.length < (width || 2)) { s = '0' + s; }
    return (s);
}
// The stamp is local time as '2026-09-02T15:36:17.000+02:00', which is what clipboard.js's toString().split(' ').join('T') gives on Duktape.
// Node's toString() is 'Wed Sep 02 2026 15:36:17 GMT+0200 (...)' instead, and new Date() of that with T's for spaces is NaN,
// so a node-written stamp left the agent's ModuleFileDate unusable. Rendered by hand here so both engines agree, to the second like the agent.
function isoStamp(seconds)
{
    var d = new Date(seconds * 1000);
    if (!(d.getTime() > 0)) { return (null); }
    var off = -d.getTimezoneOffset(), sign = (off < 0 ? '-' : '+');
    off = Math.abs(off);
    return (d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + '.000' + sign + pad(Math.floor(off / 60)) + ':' + pad(off % 60));
}
function envStr(name)
{
    var v = process.env[name];
    return (v == null ? '' : String(v));
}
function findOnPath(exe)
{
    var win = (process.platform == 'win32'), dirs = (envStr('PATH') || envStr('Path')).split(win ? ';' : ':'), i;
    for (i = 0; i < dirs.length; ++i)
    {
        if (dirs[i] != '' && fs.existsSync(dirs[i] + '/' + exe + (win ? '.exe' : ''))) { return (dirs[i] + '/' + exe + (win ? '.exe' : '')); }
    }
    return (null);
}
// Runs git and returns its stdout, or null when git is missing or fails. The agent's execFile does not search PATH
// on Windows and takes argv[0] as its first argument, so the path is looked up by hand and the name repeated.
function runGit(args)
{
    try
    {
        if (isNode) { return (require('child_process').execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })); }
        var git = findOnPath('git');
        if (git == null) { return (null); }
        var child = require('child_process').execFile(git, ['git'].concat(args)), out = '';
        child.stdout.on('data', function (c) { out += c.toString(); });
        child.stderr.on('data', function (c) { });
        child.waitExit();
        return (out);
    }
    catch (e) { return (null); }
}
// Commit dates for every file under modules/ from one 'git log', and the set of files whose working copy differs
// from HEAD, so an edited file is stamped with its mtime rather than with the commit it no longer matches.
var gitDates = null, gitDirty = null, gitMissing = false;
function gitDate(path)
{
    var lines, i, ts = null;
    if (gitDates == null)
    {
        gitDates = {}; gitDirty = {};
        var log = runGit(['log', '--format=%ct', '--name-only', '--', MODULEDIR]);
        var status = (log != null ? runGit(['status', '--porcelain', '--', MODULEDIR]) : null);
        if (log == null || status == null) { gitMissing = true; return (null); }
        lines = log.split(/\r?\n/);
        for (i = 0; i < lines.length; ++i)
        {
            if (/^[0-9]+$/.test(lines[i])) { ts = parseInt(lines[i], 10); }
            else if (lines[i] != '' && ts != null && gitDates[lines[i]] == null) { gitDates[lines[i]] = ts; }
        }
        lines = status.split(/\r?\n/);
        for (i = 0; i < lines.length; ++i) { if (lines[i].length > 3) { gitDirty[lines[i].substring(3)] = true; } }
    }
    return (gitDirty[path] || gitDates[path] == null ? null : gitDates[path]);
}
// The POSIX agent's fs.statSync() formats the mtime with localtime() but still appends 'Z', so east of UTC it reads 1 to 2 hours late.
// A file written just now shows whether the running agent does that, so a fixed agent or a machine on UTC gets no correction.
var mtimeIsLocal = null;
function agentMtimeIsLocal()
{
    if (mtimeIsLocal != null) { return (mtimeIsLocal); }
    var off = -(new Date()).getTimezoneOffset(), probe = 'tools/update-modules/.mtime-probe.tmp';
    mtimeIsLocal = false;
    if (isNode || off == 0) { return (mtimeIsLocal); }
    try
    {
        fs.writeFileSync(probe, 'x');
        mtimeIsLocal = (Math.abs((new Date(fs.statSync(probe).mtime)).getTime() - Date.now() - off * 60000) < 60000);
    }
    catch (e) { }
    try { fs.unlinkSync(probe); } catch (e) { }
    return (mtimeIsLocal);
}
function mtimeSeconds(path)
{
    var m = fs.statSync(path).mtime, p;
    if (typeof m == 'string' && (p = /^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)Z$/.exec(m)) != null && agentMtimeIsLocal())
    {
        // Read back as local wall-clock time, so the offset is the one in force on the file's own date, not today's.
        return (Math.floor((new Date(+p[1], p[2] - 1, +p[3], +p[4], +p[5], +p[6])).getTime() / 1000));
    }
    return (Math.floor((new Date(m)).getTime() / 1000));
}
function moduleStamp(path)
{
    var seconds = gitDate(path);
    if (seconds == null) { seconds = mtimeSeconds(path); }
    return (isoStamp(seconds));
}
// mkdir -p, without the recursive option node has and the agent does not.
function mkdirp(dir)
{
    var parts = dir.split(/[\\\/]/), p = '', i;
    for (i = 0; i < parts.length; ++i)
    {
        p += (i > 0 ? '/' : '') + parts[i];
        if (parts[i] == '' || /^[A-Za-z]:$/.test(parts[i])) { continue; }
        try { fs.mkdirSync(p); } catch (e) { }
    }
}

// C identifier for a module name. The generated file turns every other character into '_', the legacy
// blocks drop it, matching their existing names ("notifybar-desktop" becomes "_notifybardesktop").
function identifier(name, prefix, replacement)
{
    return (prefix + name.replace(/[^A-Za-z0-9_]/g, replacement));
}
function symbolName(name) { return (identifier(name, '_embedded_', '_')); }
function legacySymbolName(name) { return (identifier(name, '_', '')); }

// Reads the entries of ILibDuktape_EmbeddedModules.c: the byte arrays by symbol, then the table rows, in table order.
function parseGenerated(text)
{
    var lines = text.split(/\r?\n/);
    var arrays = {}, entries = [], i, m, sym = null, hex = '';

    for (i = 0; i < lines.length; ++i)
    {
        if (sym != null)
        {
            if (lines[i] == '};') { arrays[sym] = Buffer.from(hex, 'hex'); sym = null; hex = ''; continue; }
            hex += lines[i].split('0x').join('').split(',').join('').trim();
            continue;
        }
        m = lines[i].match(/^static const unsigned char (_embedded_[A-Za-z0-9_]+)\[\] = \{$/);
        if (m != null) { sym = m[1]; continue; }
        m = lines[i].match(/^\t\{ "([^"]+)", (NULL|"([^"]*)"), (_embedded_[A-Za-z0-9_]+), sizeof\(/);
        if (m != null)
        {
            if (arrays[m[4]] == null) { throw ('table row for ' + m[1] + ' references ' + m[4] + ', which has no byte array'); }
            entries.push({ name: m[1], stamp: (m[2] == 'NULL' ? null : m[3]), data: arrays[m[4]] });
        }
    }
    if (sym != null) { throw ('unterminated byte array ' + sym + ' in ' + CFILE); }
    return (entries);
}

// Reads the legacy addCompressedModule() entries of ILibDuktape_Polyfills.c, with the line range each one
// occupies and the BEGIN/END AUTO-GENERATED BODY marker lines, so they can be rewritten or cut out.
function parseLegacy(text)
{
    var lines = text.split(/\r?\n/);
    var initStart = -1, initEnd = -1, beginMarker = -1, endMarker = -1, i, t, q, g = null, entries = [], ranges = [];

    for (i = 0; i < lines.length; ++i)
    {
        if (initStart < 0) { if (lines[i].indexOf('void ILibDuktape_Polyfills_JS_Init(') >= 0) { initStart = i; } continue; }
        if (lines[i] == '}') { initEnd = i; break; }
        if (lines[i].indexOf('BEGIN AUTO-GENERATED BODY') >= 0) { beginMarker = i; }
        else if (lines[i].indexOf('END OF AUTO-GENERATED BODY') >= 0) { endMarker = i; }
    }
    if (initStart < 0 || initEnd < 0) { throw ('could not find ILibDuktape_Polyfills_JS_Init() in ' + LEGACY); }

    for (i = initStart; i < initEnd; ++i)
    {
        t = lines[i].trim();
        if (g == null)
        {
            if (t.indexOf('duk_peval_string_noresult(') == 0 && t.indexOf("addCompressedModule('") >= 0)
            {
                q = t.split("'");
                entries.push({ name: q[1], stamp: (q[7] != null ? q[7] : null), data: Buffer.from(q[3], 'base64') });
                ranges.push([i, i]);
            }
            else if (t.indexOf('char *_') == 0 && t.indexOf('ILibMemory_Allocate(') >= 0)
            {
                g = { name: null, stamp: null, b64: '', start: i };
            }
        }
        else if (t.indexOf('memcpy_s(') == 0) { g.b64 += t.split('"')[1]; }
        else if (t.indexOf('ILibDuktape_AddCompressedModule') == 0) { q = t.split('"'); g.name = q[1]; g.stamp = (q[3] != null ? q[3] : null); }
        else if (t.indexOf('free(') == 0) { entries.push({ name: g.name, stamp: g.stamp, data: Buffer.from(g.b64, 'base64') }); ranges.push([g.start, i]); g = null; }
    }
    if (g != null) { throw ('unterminated ILibMemory_Allocate block in ' + LEGACY); }
    return ({ entries: entries, ranges: ranges, beginMarker: beginMarker, endMarker: endMarker });
}

// The line numbers the legacy entries occupy, as a lookup. With padBlank a multi-line block also claims
// one blank line on each side, since that padding belongs to the block and not to the surrounding text.
function legacyLineSet(lines, legacy, padBlank)
{
    var set = {}, i, r, start, end;
    for (i = 0; i < legacy.ranges.length; ++i)
    {
        start = legacy.ranges[i][0]; end = legacy.ranges[i][1];
        for (r = start; r <= end; ++r) { set[r] = true; }
        if (padBlank && start != end)
        {
            if (lines[start - 1] != null && lines[start - 1].trim() == '') { set[start - 1] = true; }
            if (lines[end + 1] != null && lines[end + 1].trim() == '') { set[end + 1] = true; }
        }
    }
    return (set);
}

// Inserts lines right after the opening brace of ILibDuktape_Polyfills_JS_Init(), for a file without markers.
function insertAfterInitBrace(out, lines)
{
    var i;
    for (i = 0; i < out.length; ++i)
    {
        if (out[i].indexOf('void ILibDuktape_Polyfills_JS_Init(') >= 0) { return (out.slice(0, i + 2).concat(lines, out.slice(i + 2))); }
    }
    return (out);
}

// Cuts the legacy statements and both markers out of ILibDuktape_Polyfills.c and puts one call to
// ILibDuktape_Polyfills_EmbeddedModules(ctx) where the BEGIN marker was.
function stripLegacyModules(text, legacy)
{
    var lines = text.split(/\r?\n/);
    var remove = legacyLineSet(lines, legacy, false);
    var n = legacy.ranges.length;
    var first = (n > 0 ? legacy.ranges[0][0] : -1), last = (n > 0 ? legacy.ranges[n - 1][1] : -1);
    var zoneStart = (legacy.beginMarker >= 0 && (first < 0 || legacy.beginMarker < first)) ? legacy.beginMarker : first;
    var zoneEnd = Math.max(legacy.endMarker, last);
    var call = ['\tILibDuktape_Polyfills_EmbeddedModules(ctx);'];
    var out = [], i;

    for (i = 0; i < lines.length; ++i)
    {
        if (i == legacy.beginMarker) { out.push(call[0]); continue; }
        if (i == legacy.endMarker || remove[i]) { continue; }
        // Collapses the blank-line runs a removed block leaves behind, but only inside the migrated zone.
        if (i >= zoneStart && i <= zoneEnd && lines[i].trim() == '' && out.length > 0 && out[out.length - 1].trim() == '') { continue; }
        out.push(lines[i]);
    }
    return ((legacy.beginMarker >= 0 ? out : insertAfterInitBrace(out, call)).join(eolOf(text)));
}

// Renders one entry in ILibDuktape_Polyfills.c's own format. Large blocks get a blank line on each side, like the existing ones.
function legacyEntryLines(entry)
{
    var b64 = entry.data.toString('base64'), out = [], sym, offset = 0, chunkLen;
    if (b64.length <= LEGACY_CHUNK)
    {
        return (['\tduk_peval_string_noresult(ctx, "addCompressedModule(\'' + entry.name + '\', Buffer.from(\'' + b64 + '\', \'base64\')' + (entry.stamp != null ? ', \'' + entry.stamp + '\'' : '') + ');");']);
    }

    sym = legacySymbolName(entry.name);
    out.push('');
    out.push('\tchar *' + sym + ' = ILibMemory_Allocate(' + (b64.length + 1) + ', 0, NULL, NULL);');
    while (offset < b64.length)
    {
        chunkLen = Math.min(LEGACY_CHUNK, b64.length - offset);
        out.push('\tmemcpy_s(' + sym + ' + ' + offset + ', ' + (b64.length - offset) + ', "' + b64.substring(offset, offset + chunkLen) + '", ' + chunkLen + ');');
        offset += chunkLen;
    }
    out.push(entry.stamp != null
        ? '\tILibDuktape_AddCompressedModuleEx(ctx, "' + entry.name + '", ' + sym + ', "' + entry.stamp + '");'
        : '\tILibDuktape_AddCompressedModule(ctx, "' + entry.name + '", ' + sym + ');');
    out.push('\tfree(' + sym + ');');
    out.push('');
    return (out);
}

// Rewrites the whole legacy region of ILibDuktape_Polyfills.c from result, keeping the markers in place so a later strip still finds them.
function writeLegacyBody(text, legacy, result)
{
    var lines = text.split(/\r?\n/);
    var remove = legacyLineSet(lines, legacy, true);
    var fresh = [], out = [], i;

    for (i = 0; i < result.length; ++i) { fresh = fresh.concat(legacyEntryLines(result[i])); }
    // Two adjacent large entries would otherwise leave a double blank line, since each brings its own padding.
    for (i = fresh.length - 1; i > 0; --i)
    {
        if (fresh[i].trim() == '' && fresh[i - 1].trim() == '') { fresh.splice(i, 1); }
    }

    for (i = 0; i < lines.length; ++i)
    {
        if (i == legacy.beginMarker) { out.push(lines[i]); out = out.concat(fresh); continue; }
        if (!remove[i]) { out.push(lines[i]); }
    }
    return ((legacy.beginMarker >= 0 ? out : insertAfterInitBrace(out, fresh)).join(eolOf(text)));
}

// The generated file is #included from ILibDuktape_Polyfills.c, never compiled on its own, so no project or makefile lists it.
function ensureLegacyInclude(text)
{
    var inc = '#include "' + CFILE.split('/').pop() + '"';
    return (text.indexOf(inc) >= 0 ? text : text.replace('#include "duktape.h"', '#include "duktape.h"' + eolOf(text) + inc));
}
function ensureLegacyPrototype(text)
{
    var marker = 'void ILibDuktape_Polyfills_JS_Init(duk_context *ctx);';
    return (text.indexOf('ILibDuktape_Polyfills_EmbeddedModules') >= 0 ? text : text.split(marker).join(marker + eolOf(text) + 'void ILibDuktape_Polyfills_EmbeddedModules(duk_context *ctx);'));
}

function writeGenerated(entries, eol)
{
    var out = [], i, j, e, hex;

    out.push('/*');
    out.push(' * ILibDuktape_EmbeddedModules.c - GENERATED FILE, do not edit by hand.');
    out.push(' *');
    out.push(' * Holds the deflated content of every embedded JS module as a byte array, plus the table');
    out.push(' * and the loader that registers them through the global addCompressedModule().');
    out.push(' * Regenerate with tools/update-modules.sh or tools/update-modules.ps1.');
    out.push(' *');
    out.push(' * #included from ILibDuktape_Polyfills.c. Do not add this file to a project or makefile');
    out.push(' */');
    out.push('');
    out.push('#include <string.h>');
    out.push('#include "duktape.h"');
    out.push('#include "ILibDuktape_Polyfills.h"');
    out.push('');
    out.push('typedef struct ILibDuktape_EmbeddedModule');
    out.push('{');
    out.push('\tconst char *name;');
    out.push('\tconst char *timestamp;');
    out.push('\tconst unsigned char *data;');
    out.push('\tduk_size_t length;');
    out.push('} ILibDuktape_EmbeddedModule;');

    for (i = 0; i < entries.length; ++i)
    {
        e = entries[i];
        out.push('');
        out.push('// ' + e.name + (e.stamp != null ? (' (' + e.stamp + ')') : ''));
        out.push('static const unsigned char ' + symbolName(e.name) + '[] = {');
        // The agent's Buffer.toString('hex') is upper case, node's lower case, so the file would otherwise depend on the engine.
        hex = e.data.toString('hex').toLowerCase();
        for (j = 0; j < hex.length; j += 64)
        {
            out.push('0x' + hex.substring(j, j + 64).match(/../g).join(',0x') + ',');
        }
        out.push('};');
    }

    out.push('');
    out.push('static const ILibDuktape_EmbeddedModule ILibDuktape_EmbeddedModules_Table[] =');
    out.push('{');
    for (i = 0; i < entries.length; ++i)
    {
        e = entries[i];
        out.push('\t{ "' + e.name + '", ' + (e.stamp != null ? ('"' + e.stamp + '"') : 'NULL') + ', ' + symbolName(e.name) + ', sizeof(' + symbolName(e.name) + ') },');
    }
    out.push('};');
    out.push('');
    out.push('// Registers every embedded module. Called from ILibDuktape_Polyfills_JS_Init().');
    out.push('void ILibDuktape_Polyfills_EmbeddedModules(duk_context *ctx)');
    out.push('{');
    out.push('\tsize_t i;');
    out.push('\tfor (i = 0; i < sizeof(ILibDuktape_EmbeddedModules_Table) / sizeof(ILibDuktape_EmbeddedModules_Table[0]); ++i)');
    out.push('\t{');
    out.push('\t\tconst ILibDuktape_EmbeddedModule *m = &ILibDuktape_EmbeddedModules_Table[i];');
    out.push('\t\tduk_push_global_object(ctx);\t\t\t\t\t\t\t\t\t\t// [g]');
    out.push('\t\tduk_get_prop_string(ctx, -1, "addCompressedModule");\t\t\t\t// [g][func]');
    out.push('\t\tduk_swap_top(ctx, -2);\t\t\t\t\t\t\t\t\t\t\t// [func][this]');
    out.push('\t\tduk_push_string(ctx, m->name);\t\t\t\t\t\t\t\t\t// [func][this][name]');
    out.push('\t\tmemcpy(duk_push_fixed_buffer(ctx, m->length), m->data, m->length);\t// [func][this][name][buffer]');
    out.push('\t\tif (m->timestamp != NULL) { duk_push_string(ctx, m->timestamp); }');
    out.push('\t\tduk_pcall_method(ctx, m->timestamp != NULL ? 3 : 2);');
    out.push('\t\tduk_pop(ctx);\t\t\t\t\t\t\t\t\t\t\t\t\t// pop the return value');
    out.push('\t}');
    out.push('}');
    out.push('');
    return (out.join(eol));
}

function listModules(entries)
{
    var i, e;
    for (i = 0; i < entries.length; ++i)
    {
        e = entries[i];
        console.log(e.name + ' (' + decompress(e.data).length + ' bytes' + (e.stamp != null ? ', ' + e.stamp : '') + ')');
    }
    console.log(entries.length + ' embedded module(s).');
}

// Saves the embedded scripts, decompressed, into dir. With names, only those (and each must be embedded).
function exportModules(entries, dir, names)
{
    var i, e, saved = 0, savedNames = {}, notEmbedded;
    mkdirp(dir);
    for (i = 0; i < entries.length; ++i)
    {
        e = entries[i];
        if (names.length > 0 && names.indexOf(e.name) < 0) { continue; }
        fs.writeFileSync(dir + '/' + e.name + '.js', decompress(e.data));
        console.log('saved:     ' + e.name);
        savedNames[e.name] = true;
        ++saved;
    }
    notEmbedded = names.filter(function (n) { return (!savedNames[n]); });
    if (notEmbedded.length > 0) { throw ('module(s) not embedded: ' + notEmbedded.join(', ')); }
    console.log(saved + ' embedded module(s) saved to ' + dir + '/, nothing else changed.');
}

function updateModules(entries, legacy, legacyText, opt)
{
    var updated = [], missing = [], removed = [], removedReason = {}, added = [], discovered = [], unchanged = 0;
    var result = [], addFound = {}, i, g, src, srcPath;
    // Without update or sync, an add or remove leaves every other entry alone.
    var restrictedToAdd = (opt.add.length > 0 && !opt.update);
    var restrictedToRemove = (opt.remove.length > 0 && !opt.update && !restrictedToAdd);

    for (i = 0; i < entries.length; ++i)
    {
        g = entries[i];
        if (opt.remove.indexOf(g.name) >= 0) { removed.push(g.name); removedReason[g.name] = 'explicit'; continue; }
        if (restrictedToAdd && opt.add.indexOf(g.name) < 0) { result.push(g); ++unchanged; continue; }
        if (restrictedToRemove) { result.push(g); ++unchanged; continue; }
        addFound[g.name] = true;

        srcPath = modulePath(g.name);
        src = readModule(srcPath);
        if (src == null)
        {
            // No source file left for this entry. Only dropped when sync was explicitly requested.
            if (opt.sync && !restrictedToAdd) { removed.push(g.name); removedReason[g.name] = 'gone'; continue; }
            missing.push(g.name);
            result.push(g);
            continue;
        }
        if (lf(decompress(g.data)) == src.toString()) { ++unchanged; result.push(g); continue; }
        result.push({ name: g.name, stamp: moduleStamp(srcPath), data: compress(src) });
        updated.push(g.name);
    }

    // A name passed to add that is not embedded yet becomes a new entry, sorted into place below.
    for (i = 0; i < opt.add.length; ++i)
    {
        if (addFound[opt.add[i]]) { continue; }
        srcPath = modulePath(opt.add[i]);
        src = readModule(srcPath);
        if (src == null) { throw ('module ' + opt.add[i] + ' is not embedded and ' + srcPath + ' does not exist'); }
        result.push({ name: opt.add[i], stamp: moduleStamp(srcPath), data: compress(src) });
        added.push(opt.add[i]);
    }

    // sync also picks up every modules/*.js with no entry yet.
    if (opt.sync)
    {
        var known = {}, files, name;
        for (i = 0; i < result.length; ++i) { known[result[i].name] = true; }
        files = readdir(MODULEDIR);
        for (i = 0; i < files.length; ++i)
        {
            if (files[i].substring(files[i].length - 3) != '.js') { continue; }
            name = files[i].substring(0, files[i].length - 3);
            if (known[name] || opt.remove.indexOf(name) >= 0) { continue; }
            srcPath = modulePath(name);
            result.push({ name: name, stamp: moduleStamp(srcPath), data: compress(readModule(srcPath)) });
            discovered.push(name);
        }
    }
    result.sort(byName);

    // While ILibDuktape_Polyfills.c is not stripped it is the live source, so the result goes back into it
    // in its own format. striplegacy always migrates into the generated file instead.
    var notStripped = (legacy != null);
    var writeToLegacy = notStripped && !opt.stripLegacy;
    var targetFile = writeToLegacy ? LEGACY : CFILE;
    var current = readOrNull(targetFile);
    // The generated file keeps its own line ending. Only when it does not exist yet does it follow ILibDuktape_Polyfills.c from the same checkout.
    var output = writeToLegacy ? writeLegacyBody(legacyText, legacy, result) : writeGenerated(result, eolOf(current != null ? current.toString() : legacyText));
    var wouldWrite = (current == null || output != current.toString());
    if (!opt.dry && wouldWrite) { fs.writeFileSync(targetFile, output); }

    var would = opt.dry ? 'would ' : '';
    if (notStripped) { console.log(LEGACY + ' still holds ' + entries.length + ' legacy addCompressedModule entries (not migrated to ' + CFILE + ' yet).'); }
    if (opt.stripLegacy && !notStripped) { console.log(LEGACY + ' has no legacy addCompressedModule statements left to strip.'); }
    if (opt.stripLegacy && notStripped)
    {
        var legacyOut = ensureLegacyInclude(stripLegacyModules(legacyText, legacy));
        var headerOut = ensureLegacyPrototype(fs.readFileSync(LEGACYHEADER).toString());
        if (!opt.dry) { fs.writeFileSync(LEGACY, legacyOut); fs.writeFileSync(LEGACYHEADER, headerOut); }
        console.log(would + 'strip:    ' + legacy.ranges.length + ' legacy addCompressedModule statement(s) from ' + LEGACY + ', added a call to ILibDuktape_Polyfills_EmbeddedModules(ctx).');
    }
    for (i = 0; i < updated.length; ++i) { console.log(would + 'update:   ' + updated[i]); }
    for (i = 0; i < removed.length; ++i) { console.log(would + 'remove:   ' + removed[i] + (removedReason[removed[i]] == 'explicit' ? ' (explicitly removed)' : ' (no ' + modulePath(removed[i]) + ' any more)')); }
    for (i = 0; i < missing.length; ++i) { console.log('no source: ' + missing[i] + ' (no ' + modulePath(missing[i]) + ', entry kept as-is)'); }
    for (i = 0; i < discovered.length; ++i) { console.log(would + 'add:      ' + discovered[i] + ' (new ' + modulePath(discovered[i]) + ', not embedded yet)'); }
    for (i = 0; i < added.length; ++i) { console.log(would + 'add:      ' + added[i]); }
    for (i = 0; i < opt.remove.length; ++i) { if (removed.indexOf(opt.remove[i]) < 0) { console.log(opt.remove[i] + ' is not embedded, nothing to remove.'); } }
    if (gitMissing && (updated.length + added.length + discovered.length) > 0) { console.log('stamps: git not available, file mtimes used.'); }
    if (opt.dry && !opt.check) { console.log('dry run, ' + targetFile + ' not written.'); }
    console.log((entries.length - removed.length + added.length + discovered.length) + ' embedded modules: ' + updated.length + ' updated, ' + unchanged + ' unchanged, ' + removed.length + ' removed, ' + missing.length + ' kept without source file, ' + (added.length + discovered.length) + ' newly added.');
    if (opt.check)
    {
        var pending = wouldWrite || (opt.stripLegacy && notStripped);
        console.log(pending ? 'check: ' + targetFile + ' is out of date.' : 'check: ' + targetFile + ' is up to date.');
        // The launcher exits with this, because the agent's own process.exit() unwinds through the launcher's catch and logs itself.
        if (pending) { UPDATE_EXIT_CODE = 1; }
    }
}

// The launcher scripts pass the UPDATE_* settings as environment variables. Each one is optional.
function nameList(v)
{
    return (v != '' ? v.split(',').filter(function (n) { return (n != ''); }) : []);
}
var opt = {
    update: (envStr('UPDATE_UPDATE') == '1' || envStr('UPDATE_SYNC') == '1'),
    add: nameList(envStr('UPDATE_ADD')),
    remove: nameList(envStr('UPDATE_REMOVE')),
    sync: (envStr('UPDATE_SYNC') == '1'),
    dry: (envStr('UPDATE_DRYRUN') == '1' || envStr('UPDATE_CHECK') == '1'),
    check: (envStr('UPDATE_CHECK') == '1'),
    list: (envStr('UPDATE_LIST') == '1'),
    stripLegacy: (envStr('UPDATE_STRIP_LEGACY') == '1'),
    exportDir: envStr('UPDATE_EXPORT')
};

// Whatever ILibDuktape_EmbeddedModules.c holds, ILibDuktape_Polyfills.c is the live source as long as
// its legacy entries (or at least the markers) are still there, so it is checked first.
var legacyText = fs.readFileSync(LEGACY).toString();
var legacy = parseLegacy(legacyText);
if (legacy.ranges.length == 0 && legacy.beginMarker < 0) { legacy = null; }
var entries = (legacy != null) ? legacy.entries : parseGenerated(fs.readFileSync(CFILE).toString());

if (opt.list) { listModules(entries); }
else if (opt.exportDir != '') { exportModules(entries, opt.exportDir, opt.add); }
else { updateModules(entries, legacy, legacyText, opt); }
