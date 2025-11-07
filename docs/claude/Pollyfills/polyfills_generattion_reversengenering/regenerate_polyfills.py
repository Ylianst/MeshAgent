#!/usr/bin/env python3
"""
Regenerate ILibDuktape_Polyfills.c from JavaScript modules

This proof-of-concept script demonstrates that we can programmatically
recreate the ILibDuktape_Polyfills.c file byte-for-byte from the
source JavaScript modules.

Based on analysis of clipboard.js and code-utils.js compression logic.
"""

import os
import re
import base64
import zlib
import json
from pathlib import Path
from typing import List, Dict, Tuple


def compress_module(js_code: str) -> str:
    """
    Compress JavaScript code using zlib and return base64-encoded string.

    This mimics the Node.js compression:
    ```javascript
    var zip = require('compressed-stream').createCompressor();
    zip.end(data);
    return zip.buffer.toString('base64');
    ```

    The 'compressed-stream' module uses zlib compression with level 6 (default).
    """
    # Convert string to bytes
    js_bytes = js_code.encode('utf-8')

    # Compress using zlib with level 6 (default, matches Node.js)
    compressed = zlib.compress(js_bytes, level=6)

    # Base64 encode
    base64_str = base64.b64encode(compressed).decode('ascii')

    return base64_str


def extract_module_order_from_original(c_file_path: str) -> List[Tuple[str, str]]:
    """
    Extract the exact module order and timestamps from the original C file.

    Returns list of (module_name, timestamp) tuples in the order they appear.
    """
    with open(c_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Find the auto-generated section
    lines = content.split('\n')

    modules = []
    in_section = False

    for line in lines:
        if '{{ BEGIN AUTO-GENERATED BODY' in line:
            in_section = True
            continue

        if '}} END OF AUTO-GENERATED BODY' in line:
            break

        if in_section and 'duk_peval_string_noresult' in line:
            # Extract module name and timestamp using regex
            # Format: addCompressedModule('name', Buffer.from('...', 'base64'), 'timestamp')
            match = re.search(r"addCompressedModule\('([^']+)', Buffer\.from\('[^']+', 'base64'\), '([^']+)'\)", line)
            if match:
                module_name = match.group(1)
                timestamp = match.group(2)
                modules.append((module_name, timestamp))

    print(f"Extracted {len(modules)} modules from original C file")
    return modules


def load_metadata(metadata_path: str) -> Dict[str, Dict]:
    """Load module metadata including timestamps and sizes"""
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)

    # Create lookup dict by module name
    lookup = {}
    for mod in metadata['modules']:
        lookup[mod['name']] = mod

    return lookup


def generate_c_line(module_name: str, base64_data: str, timestamp: str) -> str:
    """
    Generate a single C line for embedding a module.

    Format: \tduk_peval_string_noresult(ctx, "addCompressedModule('name', Buffer.from('data', 'base64'), 'timestamp');");
    """
    line = f'\tduk_peval_string_noresult(ctx, "addCompressedModule(\'{module_name}\', Buffer.from(\'{base64_data}\', \'base64\'), \'{timestamp}\');");\n'
    return line


def read_javascript_module(module_path: str, strip_header: bool = False) -> str:
    """
    Read JavaScript source code from file

    Args:
        module_path: Path to the .js file
        strip_header: If True, strip extraction metadata header (lines starting with //)
    """
    with open(module_path, 'r', encoding='utf-8') as f:
        content = f.read()

    if strip_header:
        # Strip metadata header added by extraction script
        lines = content.split('\n')
        while lines and lines[0].strip().startswith('//'):
            lines.pop(0)
        # Skip empty line after header
        if lines and not lines[0].strip():
            lines.pop(0)
        content = '\n'.join(lines)

    return content


def extract_file_parts(c_file_path: str) -> Tuple[str, str, str]:
    """
    Extract the 3 parts of the C file:
    - Part A: Everything before BEGIN marker (including the BEGIN marker line)
    - Part B: The auto-generated section (we'll regenerate this)
    - Part C: Everything after END marker (including the END marker and the 3 special lines after)

    Returns (part_a, part_b_original, part_c)
    """
    with open(c_file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    lines = content.split('\n')

    begin_idx = None
    end_idx = None

    for i, line in enumerate(lines):
        if '{{ BEGIN AUTO-GENERATED BODY' in line:
            begin_idx = i
        if '}} END OF AUTO-GENERATED BODY' in line:
            end_idx = i
            break

    if begin_idx is None or end_idx is None:
        raise ValueError("Could not find BEGIN/END markers in C file")

    # Part A: Lines 0 to begin_idx (inclusive)
    part_a = '\n'.join(lines[:begin_idx + 1]) + '\n'

    # Part B: Lines begin_idx+1 to end_idx-1 (the module lines)
    part_b_original = '\n'.join(lines[begin_idx + 1:end_idx])
    if part_b_original:
        part_b_original += '\n'

    # Part C: Lines end_idx onwards (END marker + rest of file)
    part_c = '\n'.join(lines[end_idx:])

    print(f"Part A: {begin_idx + 1} lines")
    print(f"Part B (original): {end_idx - begin_idx - 1} lines")
    print(f"Part C: {len(lines) - end_idx} lines")

    return part_a, part_b_original, part_c


def main():
    # Paths
    original_c_file = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/ILibDuktape_Polyfills.c'
    output_c_file = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/ILibDuktape_Polyfills.c_NEW.txt'
    modules_dir = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded'
    newer_code_utils = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded/code-utils-new.js'
    metadata_path = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded/_modules_metadata.json'

    print("="*80)
    print("REGENERATING ILibDuktape_Polyfills.c")
    print("="*80)
    print()

    # Step 1: Extract module order from original
    print("Step 1: Extracting module order from original C file...")
    module_order = extract_module_order_from_original(original_c_file)

    # Step 2: Extract file structure
    print("\nStep 2: Extracting file structure...")
    part_a, part_b_original, part_c = extract_file_parts(original_c_file)

    # Step 3: Load metadata for timestamps
    print("\nStep 3: Loading metadata...")
    metadata = load_metadata(metadata_path)

    # Step 4: Process each module
    print("\nStep 4: Processing modules...")
    part_b_new = ""

    for i, (module_name, original_timestamp) in enumerate(module_order, 1):
        print(f"  [{i:2d}/{len(module_order)}] {module_name}...", end=" ")

        # Determine which file to read
        if module_name == 'code-utils':
            # Use the newer version with relative paths (need to strip header)
            module_path = newer_code_utils
            strip_header = True
        else:
            # Use extracted modules (need to strip extraction header)
            module_path = os.path.join(modules_dir, f"{module_name}.js")
            strip_header = True

        # Read JavaScript source
        try:
            js_code = read_javascript_module(module_path, strip_header=strip_header)
        except FileNotFoundError:
            print(f"ERROR: File not found: {module_path}")
            continue

        # Compress and encode
        base64_data = compress_module(js_code)

        # Generate C line
        c_line = generate_c_line(module_name, base64_data, original_timestamp)
        part_b_new += c_line

        # Check if matches metadata
        if module_name in metadata:
            meta = metadata[module_name]
            original_size = meta['compressed_size']
            new_size = len(base64.b64decode(base64_data))
            if original_size == new_size:
                print(f"✓ ({new_size} bytes)")
            else:
                print(f"✗ SIZE MISMATCH (original: {original_size}, new: {new_size})")
        else:
            print(f"✓ (not in metadata)")

    # Step 5: Assemble the file
    print("\nStep 5: Assembling new C file...")
    new_content = part_a + part_b_new + part_c

    # Write to output file
    with open(output_c_file, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"\nGenerated: {output_c_file}")
    print(f"Original size: {os.path.getsize(original_c_file):,} bytes")
    print(f"New size: {os.path.getsize(output_c_file):,} bytes")

    # Step 6: Compare
    print("\n" + "="*80)
    print("VERIFICATION")
    print("="*80)

    if os.path.getsize(original_c_file) == os.path.getsize(output_c_file):
        print("✓ File sizes match!")
    else:
        print("✗ File sizes differ!")

    print("\nRun this command to check if files are identical:")
    print(f"  diff {original_c_file} {output_c_file}")
    print("\nOr for detailed comparison:")
    print(f"  diff -u {original_c_file} {output_c_file} | head -100")


if __name__ == '__main__':
    main()
