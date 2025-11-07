#!/usr/bin/env python3
"""
Extract embedded JavaScript modules from ILibDuktape_Polyfills.c

This script:
1. Parses addCompressedModule() calls from the C source
2. Base64 decodes and zlib decompresses each module
3. Saves individual .js files with metadata headers
4. Generates metadata JSON and extraction report
"""

import re
import base64
import zlib
import json
import os
from pathlib import Path
from typing import List, Dict, Tuple


def extract_modules_from_c_file(c_file_path: str) -> List[Dict]:
    """Extract all embedded modules from ILibDuktape_Polyfills.c"""

    with open(c_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Pattern for addCompressedModule() calls
    # Format: addCompressedModule('name', Buffer.from('base64data', 'base64'), 'timestamp')
    pattern = r"addCompressedModule\('([^']+)',\s*Buffer\.from\('([^']+)',\s*'base64'\)(?:,\s*'([^']+)')?\)"

    modules = []
    matches = re.finditer(pattern, content)

    for match in matches:
        module_name = match.group(1)
        base64_data = match.group(2)
        timestamp = match.group(3) if match.group(3) else None

        try:
            # Decode base64
            compressed_data = base64.b64decode(base64_data)
            compressed_size = len(compressed_data)

            # Decompress with zlib
            decompressed_data = zlib.decompress(compressed_data)
            decompressed_size = len(decompressed_data)

            # Decode to string
            js_code = decompressed_data.decode('utf-8', errors='replace')

            modules.append({
                'name': module_name,
                'timestamp': timestamp,
                'compressed_size': compressed_size,
                'decompressed_size': decompressed_size,
                'compression_ratio': (1 - compressed_size / decompressed_size) * 100 if decompressed_size > 0 else 0,
                'js_code': js_code,
                'success': True
            })

        except Exception as e:
            modules.append({
                'name': module_name,
                'timestamp': timestamp,
                'error': str(e),
                'success': False
            })

    return modules


def save_modules(modules: List[Dict], output_dir: str):
    """Save each module as individual .js file with metadata header"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for module in modules:
        if not module['success']:
            continue

        filename = f"{module['name']}.js"
        filepath = output_path / filename

        # Create metadata header
        header = f"""// Module: {module['name']}
// Timestamp: {module['timestamp'] or 'Not specified'}
// Original compressed size: {module['compressed_size']} bytes
// Decompressed size: {module['decompressed_size']} bytes
// Compression ratio: {module['compression_ratio']:.1f}%

"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(module['js_code'])

        print(f"Extracted: {filename} ({module['decompressed_size']} bytes)")


def generate_metadata(modules: List[Dict], output_dir: str):
    """Generate metadata JSON file"""

    metadata = {
        'extraction_date': '2025-11-07',
        'total_modules': len(modules),
        'successful_extractions': sum(1 for m in modules if m['success']),
        'failed_extractions': sum(1 for m in modules if not m['success']),
        'modules': [
            {
                'name': m['name'],
                'timestamp': m['timestamp'],
                'compressed_size': m.get('compressed_size', 0),
                'decompressed_size': m.get('decompressed_size', 0),
                'compression_ratio': m.get('compression_ratio', 0),
                'success': m['success'],
                'error': m.get('error')
            }
            for m in modules
        ]
    }

    metadata_path = Path(output_dir) / '_modules_metadata.json'
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    print(f"\nMetadata saved to: {metadata_path}")


def generate_report(modules: List[Dict], output_dir: str):
    """Generate extraction report in Markdown"""

    successful = [m for m in modules if m['success']]
    failed = [m for m in modules if not m['success']]

    total_compressed = sum(m.get('compressed_size', 0) for m in successful)
    total_decompressed = sum(m.get('decompressed_size', 0) for m in successful)
    avg_compression = (1 - total_compressed / total_decompressed) * 100 if total_decompressed > 0 else 0

    # Sort by decompressed size
    largest = sorted(successful, key=lambda m: m['decompressed_size'], reverse=True)[:10]

    report = f"""# Module Extraction Report

**Extraction Date**: 2025-11-07
**Source File**: `private/orig/ILibDuktape_Polyfills.c`
**Output Directory**: `private/orig/modules_expanded/`

## Summary

- **Total Modules**: {len(modules)}
- **Successfully Extracted**: {len(successful)}
- **Failed Extractions**: {len(failed)}
- **Total Compressed Size**: {total_compressed:,} bytes ({total_compressed/1024:.1f} KB)
- **Total Decompressed Size**: {total_decompressed:,} bytes ({total_decompressed/1024:.1f} KB)
- **Average Compression Ratio**: {avg_compression:.1f}%

## Largest Modules (Top 10)

| Module | Decompressed Size | Compressed Size | Ratio |
|--------|------------------|-----------------|-------|
"""

    for m in largest:
        report += f"| {m['name']} | {m['decompressed_size']:,} bytes | {m['compressed_size']:,} bytes | {m['compression_ratio']:.1f}% |\n"

    if failed:
        report += f"\n## Failed Extractions ({len(failed)})\n\n"
        for m in failed:
            report += f"- **{m['name']}**: {m.get('error', 'Unknown error')}\n"

    # Group by timestamp
    timestamp_groups = {}
    for m in successful:
        ts = m['timestamp'] or 'No timestamp'
        if ts not in timestamp_groups:
            timestamp_groups[ts] = []
        timestamp_groups[ts].append(m['name'])

    report += f"\n## Modules by Timestamp\n\n"
    for ts in sorted(timestamp_groups.keys(), reverse=True):
        report += f"### {ts} ({len(timestamp_groups[ts])} modules)\n\n"
        if len(timestamp_groups[ts]) <= 10:
            for name in sorted(timestamp_groups[ts]):
                report += f"- {name}\n"
        else:
            report += f"*{len(timestamp_groups[ts])} modules (too many to list individually)*\n"
        report += "\n"

    report += f"\n## All Modules Alphabetically\n\n"
    for m in sorted(successful, key=lambda m: m['name']):
        report += f"- **{m['name']}** ({m['decompressed_size']:,} bytes, {m['timestamp'] or 'no timestamp'})\n"

    report_path = Path(output_dir) / 'EXTRACTION_REPORT.md'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"Report saved to: {report_path}")


def main():
    # Paths
    c_file = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/ILibDuktape_Polyfills.c'
    output_dir = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded'

    print(f"Extracting modules from: {c_file}")
    print(f"Output directory: {output_dir}\n")

    # Extract modules
    modules = extract_modules_from_c_file(c_file)

    print(f"\nFound {len(modules)} modules")
    print(f"Successful: {sum(1 for m in modules if m['success'])}")
    print(f"Failed: {sum(1 for m in modules if not m['success'])}\n")

    # Save individual files
    save_modules(modules, output_dir)

    # Generate metadata
    generate_metadata(modules, output_dir)

    # Generate report
    generate_report(modules, output_dir)

    print("\nExtraction complete!")


if __name__ == '__main__':
    main()
