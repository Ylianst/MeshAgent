#!/usr/bin/env python3
"""Patch ILibParsers.c:
  - ILibInet_ntop: change definition param to const void*, add local csrc cast
  - ILibInet_pton: change dst param to void* in definition
Both fixes align the implementation with the header declarations.
"""
import re
import sys
import os

src = sys.argv[1] if len(sys.argv) > 1 else "/src/microstack/ILibParsers.c"
dst = sys.argv[2] if len(sys.argv) > 2 else "/tmp/parsersfix/ILibParsers.c"

os.makedirs(os.path.dirname(dst), exist_ok=True)

code = open(src).read()

# Fix 1: ILibInet_ntop definition — change const char *src to const void *src
# and insert a local cast so the body can still index it as char*
ntop_def_old = "char* ILibInet_ntop(int af, const char *src, char *dst, size_t dstsize)"
ntop_def_new = "char* ILibInet_ntop(int af, const void *src, char *dst, size_t dstsize)"
code = code.replace(ntop_def_old, ntop_def_new, 1)

# Insert "const char *csrc = (const char *)src;" after the opening brace of ntop
# Find the function body: ntop_def_new followed by whitespace/newline and '{'
def insert_cast_after_brace(text, func_sig, cast_stmt):
    """Insert cast_stmt as the first statement inside the function body."""
    idx = text.find(func_sig)
    if idx == -1:
        return text
    brace_pos = text.find("{", idx + len(func_sig))
    if brace_pos == -1:
        return text
    # Insert after the '{' and a newline
    insert_at = brace_pos + 1
    return text[:insert_at] + "\n\tconst char *csrc = (const char *)src;" + text[insert_at:]

code = insert_cast_after_brace(code, ntop_def_new, "\n\tconst char *csrc = (const char *)src;")

# Replace src[0], src[1], etc. inside the ntop function body only
# (until the next top-level function definition)
# Simpler: replace all src[ occurrences after the cast insertion point
ntop_body_start = code.find(ntop_def_new)
ntop_body_end = code.find("\nchar* ILibInet_ntop2", ntop_body_start)
if ntop_body_end == -1:
    ntop_body_end = len(code)

before = code[:ntop_body_start]
ntop_body = code[ntop_body_start:ntop_body_end]
after = code[ntop_body_end:]

# Replace (unsigned char)src[ with (unsigned char)csrc[ in ntop body
ntop_body = ntop_body.replace("(unsigned char)src[", "(unsigned char)csrc[")
ntop_body = ntop_body.replace("(char)src[", "(char)csrc[")

code = before + ntop_body + after

# Fix 2: ILibInet_pton definition — change char *dst to void *dst
pton_def_old = "ILibInet_pton(int af, const char *src, char *dst)"
pton_def_new = "ILibInet_pton(int af, const char *src, void *dst)"
code = code.replace(pton_def_old, pton_def_new, 1)

# Fix 3: Replace MSVC _get_timezone / _get_daylight calls with POSIX equivalents.
# MinGW declares these as __declspec(dllimport) (no static lib), but exposes the
# POSIX 'timezone' and 'daylight' globals directly.
code = code.replace("\t_get_timezone(&tz);", "\ttz = timezone;  /* MinGW: use POSIX global */")
code = code.replace("\t_get_daylight(&dl);", "\tdl = daylight;  /* MinGW: use POSIX global */")

open(dst, "w").write(code)
print("Patched: {} -> {}".format(src, dst))
