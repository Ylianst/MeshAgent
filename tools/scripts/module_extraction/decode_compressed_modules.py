#!/usr/bin/env python3
"""
Decode addCompressedModule() calls extracted from MeshAgent binary
"""

import re
import base64
import zlib
import json
from pathlib import Path
import sys

def decode_modules(input_file: str, output_dir: str):
    """Decode compressed modules from strings file"""

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Pattern for addCompressedModule() calls
    # Format: addCompressedModule('name', Buffer.from('base64data', 'base64'))
    # or: addCompressedModule('name', Buffer.from('base64data', 'base64'), 'timestamp')
    pattern = r"addCompressedModule\('([^']+)',\s*Buffer\.from\('([^']+)',\s*'base64'\)(?:,\s*'([^']+)')?\)"

    modules = []
    matches = re.finditer(pattern, content)

    print(f"Parsing modules from {input_file}...")

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

            compression_ratio = (1 - compressed_size / decompressed_size) * 100 if decompressed_size > 0 else 0

            modules.append({
                'name': module_name,
                'timestamp': timestamp,
                'compressed_size': compressed_size,
                'decompressed_size': decompressed_size,
                'compression_ratio': compression_ratio,
                'js_code': js_code,
                'success': True
            })

            print(f"  ✓ {module_name}: {decompressed_size:,} bytes (compression: {compression_ratio:.1f}%)")

        except Exception as e:
            modules.append({
                'name': module_name,
                'timestamp': timestamp,
                'error': str(e),
                'success': False
            })
            print(f"  ✗ {module_name}: ERROR - {e}")

    print(f"\nSuccessfully decoded: {sum(1 for m in modules if m['success'])}/{len(modules)} modules")

    # Save modules
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

    # Save metadata
    metadata = {
        'total_modules': len(modules),
        'successful': sum(1 for m in modules if m['success']),
        'failed': sum(1 for m in modules if not m['success']),
        'total_decompressed_size': sum(m.get('decompressed_size', 0) for m in modules if m['success']),
        'total_compressed_size': sum(m.get('compressed_size', 0) for m in modules if m['success']),
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

    metadata_file = output_path / 'modules_metadata.json'
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    print(f"\n✓ Saved {sum(1 for m in modules if m['success'])} modules to: {output_dir}")
    print(f"✓ Metadata saved to: {metadata_file}")

    # Print summary
    total_compressed = metadata['total_compressed_size']
    total_decompressed = metadata['total_decompressed_size']
    avg_compression = (1 - total_compressed / total_decompressed) * 100 if total_decompressed > 0 else 0

    print(f"\nSummary:")
    print(f"  Total compressed size:   {total_compressed:,} bytes ({total_compressed/1024:.1f} KB)")
    print(f"  Total decompressed size: {total_decompressed:,} bytes ({total_decompressed/1024:.1f} KB)")
    print(f"  Average compression:     {avg_compression:.1f}%")

    # Print largest modules
    successful = [m for m in modules if m['success']]
    if successful:
        largest = sorted(successful, key=lambda m: m['decompressed_size'], reverse=True)[:10]
        print(f"\nLargest modules:")
        for m in largest:
            print(f"  {m['name']:30s} {m['decompressed_size']:>8,} bytes")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python decode_compressed_modules.py <input_file> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    decode_modules(input_file, output_dir)
