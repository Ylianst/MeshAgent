import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {inflateSync} from 'node:zlib';
import {renderBundle, renderEmbedding} from '../addons/gnome-shell/generate-assets.mjs';

const require = createRequire(import.meta.url);
const assetURL = new URL('../modules/linux-gnome-companion-assets.js', import.meta.url);
assert.equal(fs.readFileSync(assetURL, 'utf8'), renderBundle(), 'Generated assets must not lag the qualified source');
const assets = require(fileURLToPath(assetURL));
assert.equal(assets.uuid, 'meshagent-console@meshcentral.com');
assert.ok(Number.isInteger(assets.version) && assets.version >= 1 && assets.version <= 0xffffffff);
assert.deepEqual(Object.keys(assets.files).sort(), ['extension.js', 'metadata.json', 'protocol.js']);
let bytes = 0;
for (const [name, file] of Object.entries(assets.files)) {
    assert.equal(file.encoding, 'base64');
    const decoded = Buffer.from(file.data, 'base64');
    assert.equal(decoded.length, file.bytes);
    assert.equal(createHash('sha256').update(decoded).digest('hex'), file.sha256);
    assert.deepEqual(decoded, fs.readFileSync(new URL('../addons/gnome-shell/' + assets.uuid + '/' + name, import.meta.url)));
    bytes += decoded.length;
}
const metadata = JSON.parse(Buffer.from(assets.files['metadata.json'].data, 'base64'));
assert.equal(metadata.uuid, assets.uuid);
assert.equal(metadata.version, assets.version);
assert.deepEqual(metadata['shell-version'], ['46', '48', '49', '50', '51']);
assert.deepEqual(metadata['session-modes'], ['user', 'unlock-dialog', 'gdm']);
const embedded = fs.readFileSync(new URL('../microscript/ILibDuktape_Polyfills.c', import.meta.url), 'utf8');
assert.equal(renderEmbedding(embedded), embedded, 'The executable payload must match the generated module');
const matches = [...embedded.matchAll(/addCompressedModule\('linux-gnome-companion-assets', Buffer.from\('([^']+)'/g)];
assert.equal(matches.length, 1);
assert.equal(inflateSync(Buffer.from(matches[0][1], 'base64')).toString(), renderBundle());
assert.throws(() => renderEmbedding(''), /Cannot locate/);
assert.throws(() => renderEmbedding(embedded + '\n' + embedded), /Duplicate/);
const changed = embedded.replace(matches[0][1], 'stale');
assert.notEqual(renderEmbedding(changed), changed, 'Regeneration must replace stale executable payloads');
console.log('GNOME companion bundle: exact three-file payload verified (' + bytes + ' bytes)');
