#!/usr/bin/env python3

import os
import subprocess
import re

# Label mappings
LABELS = {
    'macos': ('08', 'macOS (Blue)'),
    'windows': ('02', 'Windows (Gray)'),
    'linux': ('06', 'Linux (Purple)')
}

def extract_platform(filepath):
    """Extract platform support from markdown file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find Supported Platforms section
        supported_match = re.search(r'\*\*Supported Platforms:\*\*(.+?)(?:\*\*|##)', content, re.DOTALL)
        excluded_match = re.search(r'\*\*Excluded Platforms:\*\*(.+?)(?:\*\*|##)', content, re.DOTALL)

        if not supported_match:
            return None

        supported = supported_match.group(1).lower()
        excluded = excluded_match.group(1).lower() if excluded_match else ""

        # Check platform support
        has_macos = ('macos' in supported or 'darwin' in supported) and 'macos' not in excluded and 'darwin' not in excluded
        has_windows = 'windows' in supported or 'win32' in supported
        has_linux = 'linux' in supported

        # Determine primary platform
        if has_macos:
            return 'macos'
        elif has_windows and not has_linux:
            return 'windows'
        elif has_linux and not has_windows:
            return 'linux'
        elif has_windows and has_linux:
            # Cross-platform without macOS - default to windows
            return 'windows'

        return None

    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def apply_label(filepath, platform):
    """Apply Finder label using xattr"""
    if platform not in LABELS:
        return False

    label_hex, label_name = LABELS[platform]
    hex_value = f"000000000000000000{label_hex}00000000000000000000000000000000000000000000"

    try:
        subprocess.run(
            ['xattr', '-wx', 'com.apple.FinderInfo', hex_value, filepath],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error applying label to {filepath}: {e}")
        return False

def main():
    doc_dir = '/Users/peet/GitHub/MeshAgent_installer/bin/modules_documentation'

    print("Processing module documentation files...")
    print("=" * 60)

    stats = {'macos': 0, 'windows': 0, 'linux': 0, 'skipped': 0, 'error': 0}

    for filename in sorted(os.listdir(doc_dir)):
        if not filename.endswith('.md') or filename == '__Index.md':
            continue

        filepath = os.path.join(doc_dir, filename)

        # Extract platform
        platform = extract_platform(filepath)

        if platform is None:
            print(f"⊘ SKIPPED (unknown platform): {filename}")
            stats['skipped'] += 1
            continue

        # Apply label
        if apply_label(filepath, platform):
            label_name = LABELS[platform][1]
            print(f"✓ Applied {label_name}: {filename}")
            stats[platform] += 1
        else:
            print(f"✗ ERROR applying label: {filename}")
            stats['error'] += 1

    print("=" * 60)
    print(f"\nSummary:")
    print(f"  macOS (Blue):     {stats['macos']} files")
    print(f"  Windows (Gray):   {stats['windows']} files")
    print(f"  Linux (Purple):   {stats['linux']} files")
    print(f"  Skipped:          {stats['skipped']} files")
    print(f"  Errors:           {stats['error']} files")
    print(f"  Total processed:  {sum(stats.values())} files")

if __name__ == '__main__':
    main()
