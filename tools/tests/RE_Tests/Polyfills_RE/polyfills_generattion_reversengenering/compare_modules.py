#!/usr/bin/env python3
"""
Compare modules between private/orig/modules and private/orig/modules_expanded

This script compares:
1. Which modules exist in each directory
2. File size differences
3. Content differences (ignoring headers)
"""

import os
import re
import difflib
from pathlib import Path
from typing import Dict, Set, Tuple


def get_module_files(directory: str) -> Set[str]:
    """Get set of .js files in directory (excluding metadata files)"""
    path = Path(directory)
    if not path.exists():
        return set()

    files = set()
    for item in path.iterdir():
        if item.is_file() and item.suffix == '.js':
            # Exclude metadata files
            if not item.name.startswith('_') and item.name != 'EXTRACTION_REPORT.md':
                files.add(item.stem)  # stem = filename without extension

    return files


def strip_header(content: str) -> str:
    """Remove extraction header from modules_expanded files"""
    lines = content.split('\n')

    # Skip lines starting with '//' at the beginning
    while lines and lines[0].strip().startswith('//'):
        lines.pop(0)

    # Skip empty line after header
    if lines and not lines[0].strip():
        lines.pop(0)

    return '\n'.join(lines)


def compare_file_content(file1: Path, file2: Path, is_expanded: bool) -> Tuple[bool, str]:
    """
    Compare two files' content

    Args:
        file1: First file path
        file2: Second file path
        is_expanded: True if file2 is from modules_expanded (has header to strip)

    Returns:
        (identical, difference_summary)
    """
    try:
        with open(file1, 'r', encoding='utf-8', errors='replace') as f:
            content1 = f.read()

        with open(file2, 'r', encoding='utf-8', errors='replace') as f:
            content2 = f.read()

        # Strip header from expanded version
        if is_expanded:
            content2 = strip_header(content2)

        # Normalize line endings
        content1 = content1.replace('\r\n', '\n').replace('\r', '\n')
        content2 = content2.replace('\r\n', '\n').replace('\r', '\n')

        # Compare
        if content1 == content2:
            return True, "Identical"

        # Calculate diff stats
        lines1 = content1.split('\n')
        lines2 = content2.split('\n')

        differ = difflib.Differ()
        diff = list(differ.compare(lines1, lines2))

        additions = sum(1 for line in diff if line.startswith('+ '))
        deletions = sum(1 for line in diff if line.startswith('- '))

        size1 = len(content1)
        size2 = len(content2)
        size_diff = abs(size1 - size2)

        return False, f"+{additions} -{deletions} lines, size diff: {size_diff} bytes ({size1} vs {size2})"

    except Exception as e:
        return False, f"Error comparing: {str(e)}"


def main():
    modules_dir = Path('/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules')
    expanded_dir = Path('/Users/peet/GitHub/MeshAgent_dynamicNames/private/orig/modules_expanded')

    print("=" * 80)
    print("MODULE COMPARISON REPORT")
    print("=" * 80)
    print(f"\nOriginal modules: {modules_dir}")
    print(f"Expanded modules: {expanded_dir}")
    print()

    # Get module lists
    original_modules = get_module_files(str(modules_dir))
    expanded_modules = get_module_files(str(expanded_dir))

    print(f"Original modules count: {len(original_modules)}")
    print(f"Expanded modules count: {len(expanded_modules)}")
    print()

    # Find modules only in one directory
    only_original = original_modules - expanded_modules
    only_expanded = expanded_modules - original_modules
    common = original_modules & expanded_modules

    if only_original:
        print(f"\n{'='*80}")
        print(f"MODULES ONLY IN ORIGINAL ({len(only_original)})")
        print(f"{'='*80}")
        for module in sorted(only_original):
            filepath = modules_dir / f"{module}.js"
            size = filepath.stat().st_size if filepath.exists() else 0
            print(f"  - {module}.js ({size:,} bytes)")

    if only_expanded:
        print(f"\n{'='*80}")
        print(f"MODULES ONLY IN EXPANDED ({len(only_expanded)})")
        print(f"{'='*80}")
        for module in sorted(only_expanded):
            filepath = expanded_dir / f"{module}.js"
            size = filepath.stat().st_size if filepath.exists() else 0
            print(f"  - {module}.js ({size:,} bytes)")

    print(f"\n{'='*80}")
    print(f"COMMON MODULES COMPARISON ({len(common)})")
    print(f"{'='*80}\n")

    identical_count = 0
    different_count = 0
    differences = []

    for module in sorted(common):
        original_file = modules_dir / f"{module}.js"
        expanded_file = expanded_dir / f"{module}.js"

        is_identical, diff_info = compare_file_content(original_file, expanded_file, is_expanded=True)

        if is_identical:
            identical_count += 1
            print(f"✓ {module}.js - {diff_info}")
        else:
            different_count += 1
            print(f"✗ {module}.js - {diff_info}")
            differences.append((module, diff_info))

    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total modules in original: {len(original_modules)}")
    print(f"Total modules in expanded: {len(expanded_modules)}")
    print(f"Common modules: {len(common)}")
    print(f"  - Identical: {identical_count}")
    print(f"  - Different: {different_count}")
    print(f"Only in original: {len(only_original)}")
    print(f"Only in expanded: {len(only_expanded)}")

    if differences:
        print(f"\n{'='*80}")
        print(f"DETAILED DIFFERENCES ({len(differences)} modules)")
        print(f"{'='*80}")
        for module, diff_info in differences:
            print(f"\n{module}.js:")
            print(f"  {diff_info}")

            # Show first few lines of diff for context
            original_file = modules_dir / f"{module}.js"
            expanded_file = expanded_dir / f"{module}.js"

            with open(original_file, 'r', encoding='utf-8', errors='replace') as f:
                orig_preview = f.read(500)
            with open(expanded_file, 'r', encoding='utf-8', errors='replace') as f:
                exp_content = f.read()
                exp_preview = strip_header(exp_content)[:500]

            print(f"  Original preview: {orig_preview[:100]}...")
            print(f"  Expanded preview: {exp_preview[:100]}...")

    print("\n" + "="*80)
    print("Comparison complete!")
    print("="*80)


if __name__ == '__main__':
    main()
