#!/usr/bin/env python3
"""
Complete regeneration of ILibDuktape_Polyfills.c including large chunked modules

This script regenerates the ILibDuktape_Polyfills.c file byte-for-byte from the
source JavaScript modules, handling BOTH:
1. Standard format modules (duk_peval_string_noresult)
2. Large chunked format modules (ILibMemory_Allocate + memcpy_s)

Based on analysis of code-utils.js readExpandedModules() function.
"""

import os
import re
import base64
import zlib
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime


def compress_module(js_code: str) -> str:
    """
    Compress JavaScript code using zlib and return base64-encoded string.

    This mimics the Node.js compression with level 6 (default).
    """
    js_bytes = js_code.encode('utf-8')
    compressed = zlib.compress(js_bytes, level=6)
    base64_str = base64.b64encode(compressed).decode('ascii')
    return base64_str


def extract_module_order_from_original(c_file_path: str) -> List[Tuple[str, str, str]]:
    """
    Extract the exact module order and timestamps from the original C file.

    Returns list of (module_name, timestamp, format_type) tuples in the order they appear.
    format_type is either 'standard' or 'chunked'
    """
    with open(c_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    lines = content.split('\n')

    modules = []
    in_section = False
    i = 0

    while i < len(lines):
        line = lines[i]

        if '{{ BEGIN AUTO-GENERATED BODY' in line:
            in_section = True
            i += 1
            continue

        if '}} END OF AUTO-GENERATED BODY' in line:
            break

        if in_section:
            # Check for standard format
            if 'duk_peval_string_noresult' in line and 'addCompressedModule' in line:
                match = re.search(r"addCompressedModule\('([^']+)', Buffer\.from\('[^']+', 'base64'\), '([^']+)'\)", line)
                if match:
                    module_name = match.group(1)
                    timestamp = match.group(2)
                    modules.append((module_name, timestamp, 'standard'))

            # Check for chunked format (ILibMemory_Allocate line)
            elif 'ILibMemory_Allocate' in line:
                # Extract module name from variable: char *_modulename = ILibMemory_Allocate(...)
                match = re.search(r'char \*_([a-zA-Z0-9]+) = ILibMemory_Allocate', line)
                if match:
                    var_name = match.group(1)
                    # Convert variable name back to module name (add hyphens back)
                    # We'll need to scan forward to find the ILibDuktape_AddCompressedModuleEx line
                    # to get the actual module name with hyphens

                    # Scan forward to find ILibDuktape_AddCompressedModuleEx
                    j = i + 1
                    while j < len(lines) and 'ILibDuktape_AddCompressedModuleEx' not in lines[j]:
                        j += 1

                    if j < len(lines):
                        add_line = lines[j]
                        # Extract module name and timestamp
                        # Format: ILibDuktape_AddCompressedModuleEx(ctx, "module-name", _varname, "timestamp");
                        match2 = re.search(r'ILibDuktape_AddCompressedModuleEx\(ctx, "([^"]+)", _[a-zA-Z0-9]+(?:, "([^"]+)")?\)', add_line)
                        if match2:
                            module_name = match2.group(1)
                            timestamp = match2.group(2) if match2.group(2) else ''
                            modules.append((module_name, timestamp, 'chunked'))

        i += 1

    print(f"Extracted {len(modules)} modules from original C file")
    standard_count = sum(1 for _, _, fmt in modules if fmt == 'standard')
    chunked_count = sum(1 for _, _, fmt in modules if fmt == 'chunked')
    print(f"  - Standard format: {standard_count}")
    print(f"  - Chunked format: {chunked_count}")

    return modules


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


def generate_standard_c_line(module_name: str, base64_data: str, timestamp: str) -> str:
    """
    Generate standard C line for embedding a module.

    Format: \tduk_peval_string_noresult(ctx, "addCompressedModule('name', Buffer.from('data', 'base64'), 'timestamp');");
    """
    line = f'\tduk_peval_string_noresult(ctx, "addCompressedModule(\'{module_name}\', Buffer.from(\'{base64_data}\', \'base64\'), \'{timestamp}\');");\n'
    return line


def generate_chunked_c_lines(module_name: str, base64_data: str, timestamp: str) -> str:
    """
    Generate chunked C lines for embedding a large module.

    This mimics the code-utils.js logic:
    - Blank line with tab BEFORE chunked module
    - ILibMemory_Allocate for the buffer
    - Multiple memcpy_s calls with 16000-byte chunks
    - ILibDuktape_AddCompressedModuleEx to add the module
    - free() to release the buffer
    - Blank line (no tab) AFTER chunked module

    Args:
        module_name: Module name (with hyphens, e.g. "agent-selftest")
        base64_data: Base64-encoded compressed data
        timestamp: Timestamp string (will be converted to double quotes)

    Returns:
        Multi-line C code string
    """
    # Convert module name to variable name (remove hyphens)
    var_name = module_name.replace('-', '')

    # Data length
    data_length = len(base64_data)

    # Start with blank line (tab+newline) before chunked module, then allocation
    lines = []
    lines.append('\t')
    lines.append(f'\tchar *_{var_name} = ILibMemory_Allocate({data_length + 1}, 0, NULL, NULL);')

    # Add memcpy_s chunks (16000 bytes each)
    chunk_size = 16000
    z = 0
    while z < data_length:
        chunk = base64_data[z:z + chunk_size]
        remaining = data_length - z
        lines.append(f'\tmemcpy_s(_{var_name} + {z}, {remaining}, "{chunk}", {len(chunk)});')
        z += len(chunk)

    # Convert timestamp: single quotes to double quotes
    timestamp_converted = timestamp.replace("'", '"')

    # Add the module
    if timestamp:
        lines.append(f'\tILibDuktape_AddCompressedModuleEx(ctx, "{module_name}", _{var_name}, "{timestamp_converted}");')
    else:
        lines.append(f'\tILibDuktape_AddCompressedModuleEx(ctx, "{module_name}", _{var_name});')

    # Free the buffer
    lines.append(f'\tfree(_{var_name});')
    # Add blank line after chunked module (just newline, no tab)
    lines.append('')

    return '\n'.join(lines) + '\n'


def extract_file_parts(c_file_path: str) -> Tuple[str, str, str]:
    """
    Extract the 3 parts of the C file:
    - Part A: Everything before BEGIN marker (including the BEGIN marker line)
    - Part B: The auto-generated section (we'll regenerate this)
    - Part C: Everything after END marker (including the END marker)

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
    output_c_file = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/ILibDuktape_Polyfills.c_NEW_withLargeModules.txt'
    modules_source_dir = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded'
    code_utils_newer = '/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded/code-utils-new.js'

    print("=" * 80)
    print("COMPLETE REGENERATION OF ILibDuktape_Polyfills.c")
    print("Including both standard and large chunked-format modules")
    print("=" * 80)
    print()

    # Step 1: Extract module order from original (both standard and chunked)
    print("Step 1: Extracting complete module order from original C file...")
    module_order = extract_module_order_from_original(original_c_file)

    # Step 2: Extract file structure
    print("\nStep 2: Extracting file structure...")
    part_a, part_b_original, part_c = extract_file_parts(original_c_file)

    # Step 3: Process each module
    print("\nStep 3: Processing all modules...")
    part_b_new = ""

    for i, (module_name, timestamp, format_type) in enumerate(module_order, 1):
        print(f"  [{i:3d}/{len(module_order)}] {module_name:30s} ({format_type:8s})...", end=" ")

        # Determine which file to read
        if module_name == 'code-utils':
            # Use the newer version with relative paths (need to strip header)
            module_path = code_utils_newer
            strip_header = True
        elif format_type == 'chunked':
            # Large chunked modules are in the original modules directory (not extracted)
            module_path = os.path.join('/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules', f"{module_name}.js")
            strip_header = False
        else:
            # Standard modules: use extracted modules (need to strip extraction header)
            module_path = os.path.join(modules_source_dir, f"{module_name}.js")
            strip_header = True

        try:
            js_code = read_javascript_module(module_path, strip_header=strip_header)
        except FileNotFoundError:
            print(f"ERROR: File not found: {module_path}")
            continue

        # Compress and encode
        base64_data = compress_module(js_code)
        compressed_size = len(base64.b64decode(base64_data))

        # Generate C code based on format type
        if format_type == 'standard':
            c_code = generate_standard_c_line(module_name, base64_data, timestamp)
        else:  # chunked
            c_code = generate_chunked_c_lines(module_name, base64_data, timestamp)

        part_b_new += c_code

        print(f"✓ ({compressed_size:,} bytes compressed)")

    # Step 4: Assemble the file
    print("\nStep 4: Assembling complete C file...")
    new_content = part_a + part_b_new + part_c

    # Write to output file
    with open(output_c_file, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"\nGenerated: {output_c_file}")

    # Step 5: Verification
    print("\n" + "=" * 80)
    print("VERIFICATION")
    print("=" * 80)

    original_size = os.path.getsize(original_c_file)
    new_size = os.path.getsize(output_c_file)

    print(f"Original size: {original_size:,} bytes")
    print(f"New size:      {new_size:,} bytes")
    print(f"Difference:    {abs(original_size - new_size):,} bytes")

    if original_size == new_size:
        print("\n✓ File sizes match!")
    else:
        print(f"\n✗ File sizes differ by {abs(original_size - new_size)} bytes")

    print("\nRun these commands to verify:")
    print(f"  md5 {original_c_file}")
    print(f"  md5 {output_c_file}")
    print("\nOr check if files are identical:")
    print(f"  diff {original_c_file} {output_c_file}")


if __name__ == '__main__':
    main()
