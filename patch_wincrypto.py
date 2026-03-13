#!/usr/bin/env python3
"""Patch wincrypto.cpp: add bcrypt/ncrypt includes and strip extern "C" wrapper."""
import re
import sys
import os

src = sys.argv[1] if len(sys.argv) > 1 else "/src/meshcore/wincrypto.cpp"
dst = sys.argv[2] if len(sys.argv) > 2 else "/tmp/wincfix/wincrypto.c"

os.makedirs(os.path.dirname(dst), exist_ok=True)

code = open(src).read()

# Add bcrypt/ncrypt headers right after <wincrypt.h>
code = code.replace(
    "#include <wincrypt.h>",
    "#include <wincrypt.h>\n#include <bcrypt.h>\n#include <ncrypt.h>"
)

# Remove the extern "C" opening (line with just 'extern "C"' followed by '{')
code = re.sub(r'extern\s+"C"\s*\n\{', "", code)

# Remove the lone } that closes the extern "C" block.
# It is the first lone } walking backward from the #endif at EOF.
lines = code.split("\n")
for i in range(len(lines) - 1, -1, -1):
    if lines[i].strip() == "#endif":
        for j in range(i - 1, -1, -1):
            if lines[j].strip() == "}":
                del lines[j]
                break
        break

open(dst, "w").write("\n".join(lines))
print("Patched: {} -> {}".format(src, dst))
