#!/usr/bin/env python3
"""
Extract embedded JavaScript modules from MeshAgent binary

This script searches the binary for compressed JavaScript modules and extracts them.
"""

import re
import zlib
import os
import sys
from pathlib import Path

def extract_modules_from_binary(binary_path: str, output_dir: str):
    """Extract JavaScript modules from the MeshAgent binary"""

    print(f"Reading binary: {binary_path}")
    with open(binary_path, 'rb') as f:
        binary_data = f.read()

    print(f"Binary size: {len(binary_data):,} bytes")

    # Convert to string for pattern matching (will fail on non-UTF8, that's okay)
    # We'll search in chunks to handle large binaries

    modules = []

    # Look for zlib compressed data (starts with 0x78 0x9C or 0x78 0xDA or other zlib headers)
    # followed by JavaScript-like content when decompressed
    print("\nSearching for compressed modules...")

    # Common zlib compression headers
    zlib_patterns = [
        b'\x78\x9c',  # Default compression
        b'\x78\x01',  # No compression
        b'\x78\xda',  # Best compression
        b'\x78\x5e',  # Fast compression
    ]

    potential_modules = []

    for pattern in zlib_patterns:
        offset = 0
        while True:
            pos = binary_data.find(pattern, offset)
            if pos == -1:
                break

            # Try to decompress data starting at this position
            # Try various lengths
            for length in [100, 500, 1000, 5000, 10000, 50000, 100000, 500000]:
                if pos + length > len(binary_data):
                    length = len(binary_data) - pos

                try:
                    chunk = binary_data[pos:pos + length]
                    decompressed = zlib.decompress(chunk)

                    # Check if decompressed data looks like JavaScript
                    try:
                        decoded = decompressed.decode('utf-8', errors='strict')

                        # Look for JavaScript patterns
                        if any(keyword in decoded for keyword in ['function', 'var ', 'const ', 'require(', 'module.exports', 'return']):
                            potential_modules.append({
                                'offset': pos,
                                'compressed_size': len(chunk),
                                'decompressed_size': len(decompressed),
                                'content': decoded
                            })
                            print(f"Found potential module at offset {pos}, size {len(decoded)} bytes")
                            break  # Found valid module, move to next offset
                    except UnicodeDecodeError:
                        pass

                except zlib.error:
                    pass

            offset = pos + 1

    print(f"\nFound {len(potential_modules)} potential modules")

    if len(potential_modules) == 0:
        print("No modules found. The binary may use a different compression or encoding.")
        return

    # Save modules
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for i, module in enumerate(potential_modules):
        filename = f"module_{i:03d}_offset_{module['offset']}.js"
        filepath = output_path / filename

        header = f"""// Extracted from binary offset: {module['offset']}
// Compressed size: {module['compressed_size']} bytes
// Decompressed size: {module['decompressed_size']} bytes
// Compression ratio: {(1 - module['compressed_size'] / module['decompressed_size']) * 100:.1f}%

"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(module['content'])

        print(f"Saved: {filename}")

    print(f"\n✓ Extracted {len(potential_modules)} modules to {output_dir}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python extract_modules_from_binary.py <binary_path> <output_dir>")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(binary_path):
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    extract_modules_from_binary(binary_path, output_dir)

if __name__ == '__main__':
    main()
