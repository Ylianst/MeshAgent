const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Label mappings
const LABELS = {
    macos: { hex: '08', name: 'macOS (Blue)' },
    windows: { hex: '02', name: 'Windows (Gray)' },
    linux: { hex: '06', name: 'Linux (Purple)' }
};

function extractPlatform(filepath) {
    try {
        const content = fs.readFileSync(filepath, 'utf8');

        // Extract Supported Platforms section
        const supportedMatch = content.match(/\*\*Supported Platforms:\*\*(.+?)(?:\*\*|##)/s);
        const excludedMatch = content.match(/\*\*Excluded Platforms:\*\*(.+?)(?:\*\*|##)/s);

        if (!supportedMatch) {
            return null;
        }

        const supported = supportedMatch[1].toLowerCase();
        const excluded = excludedMatch ? excludedMatch[1].toLowerCase() : '';

        // Check platform support
        const hasMacOS = (supported.includes('macos') || supported.includes('darwin')) &&
                        !excluded.includes('macos') && !excluded.includes('darwin');
        const hasWindows = supported.includes('windows') || supported.includes('win32');
        const hasLinux = supported.includes('linux');

        // Determine primary platform
        if (hasMacOS) {
            return 'macos';
        } else if (hasWindows && !hasLinux) {
            return 'windows';
        } else if (hasLinux && !hasWindows) {
            return 'linux';
        } else if (hasWindows && hasLinux) {
            // Cross-platform without macOS - default to windows
            return 'windows';
        }

        return null;
    } catch (err) {
        console.error(`Error reading ${filepath}: ${err.message}`);
        return null;
    }
}

function applyLabel(filepath, platform) {
    if (!LABELS[platform]) {
        return false;
    }

    const label = LABELS[platform];
    const hexValue = `000000000000000000${label.hex}00000000000000000000000000000000000000000000`;

    try {
        execSync(`xattr -wx com.apple.FinderInfo "${hexValue}" "${filepath}"`, { stdio: 'pipe' });
        return true;
    } catch (err) {
        console.error(`Error applying label to ${filepath}: ${err.message}`);
        return false;
    }
}

function main() {
    const docDir = '/Users/peet/GitHub/MeshAgent_installer/bin/modules_documentation';

    console.log('Processing module documentation files...');
    console.log('='.repeat(60));

    const stats = {
        macos: 0,
        windows: 0,
        linux: 0,
        skipped: 0,
        error: 0
    };

    const files = fs.readdirSync(docDir)
        .filter(f => f.endsWith('.md') && f !== '__Index.md')
        .sort();

    for (const filename of files) {
        const filepath = path.join(docDir, filename);

        // Extract platform
        const platform = extractPlatform(filepath);

        if (!platform) {
            console.log(`⊘ SKIPPED (unknown platform): ${filename}`);
            stats.skipped++;
            continue;
        }

        // Apply label
        if (applyLabel(filepath, platform)) {
            console.log(`✓ Applied ${LABELS[platform].name}: ${filename}`);
            stats[platform]++;
        } else {
            console.log(`✗ ERROR applying label: ${filename}`);
            stats.error++;
        }
    }

    console.log('='.repeat(60));
    console.log('\nSummary:');
    console.log(`  macOS (Blue):     ${stats.macos} files`);
    console.log(`  Windows (Gray):   ${stats.windows} files`);
    console.log(`  Linux (Purple):   ${stats.linux} files`);
    console.log(`  Skipped:          ${stats.skipped} files`);
    console.log(`  Errors:           ${stats.error} files`);
    console.log(`  Total processed:  ${Object.values(stats).reduce((a, b) => a + b, 0)} files`);
}

main();
