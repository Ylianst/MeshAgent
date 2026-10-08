'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');

async function inspect(filename) {
    const before = await fs.promises.lstat(filename);
    if (!before.isFile() || !before.size || before.size > 128 * 1024 * 1024) throw new Error('Invalid release file: ' + filename);
    const hash = crypto.createHash('sha384');
    for await (const chunk of fs.createReadStream(filename)) hash.update(chunk);
    const after = await fs.promises.lstat(filename);
    if (before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error('Release file changed: ' + filename);
    return { size: after.size, sha384: hash.digest('hex') };
}

async function main() {
    const [mode, repository, version, directory, sourceDirectory] = process.argv.slice(2);
    if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repository || '') || !directory) throw new Error('Usage: node .github/scripts/agent-release.js manifest|migrate owner/repository tag|profile directory [source-directory]');
    let release;
    if (mode === 'manifest') {
        if (!/^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version || '')) throw new Error('Use a versioned release tag.');
        const names = require('../release-files.json');
        release = { repository, tag: version, files: [] };
        for (const name of names) {
            release.files.push({ filename: name, asset: name, ...await inspect(path.join(directory, name)) });
        }
        const extra = (await fs.promises.readdir(directory)).filter(name => !names.includes(name));
        if (extra.length) throw new Error('Unexpected release files: ' + extra.join(', '));
        if (/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA || '')) release.commit = process.env.GITHUB_SHA;
    } else if (mode === 'migrate') {
        const profile = require('../release-migration.json')[version];
        if (!profile) throw new Error('Unknown migration profile.');
        release = { repository, ...profile };
        await fs.promises.mkdir(directory, { recursive: false });
        for (const file of release.files) {
            const target = path.join(directory, file.filename);
            if (sourceDirectory) {
                await fs.promises.copyFile(path.join(sourceDirectory, file.filename), target, fs.constants.COPYFILE_EXCL);
            } else {
                const url = 'https://raw.githubusercontent.com/' + release.sourceRepository + '/' + release.sourceCommit + '/' + release.sourceDirectory + '/' + file.filename;
                const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
                if (!response.ok) throw new Error('Unable to retrieve ' + file.filename + ': HTTP ' + response.status);
                let received = 0;
                const meter = new Transform({ transform(chunk, encoding, callback) {
                    received += chunk.length;
                    callback(received > file.size ? new Error('Migration file exceeds its expected size.') : null, chunk);
                } });
                await pipeline(Readable.fromWeb(response.body), meter, fs.createWriteStream(target, { flags: 'wx' }));
            }
            const actual = await inspect(target);
            if (actual.size !== file.size || actual.sha384 !== file.sha384) throw new Error('Migration checksum mismatch: ' + file.filename);
        }
    } else {
        throw new Error('Unknown release operation.');
    }
    await fs.promises.writeFile(path.join(directory, 'agent-release.json'), JSON.stringify({ schemaVersion: 1, releases: [release] }, null, 2) + '\n', { flag: 'wx' });
    console.log('Prepared ' + release.files.length + ' files for ' + repository + ' ' + release.tag);
}

main().catch(err => { console.error(err.message); process.exitCode = 1; });
