#!/usr/bin/env python3
"""Test the built Agent in a private mount namespace; no real GNOME is used."""
from pathlib import Path
import os,sys,subprocess,json
if len(sys.argv) not in (2,4) or os.geteuid()!=0:
    raise SystemExit('Usage (local root): python3 test/linux-gnome-store-runtime-tests.py /absolute/path/to/meshagent [--case store|rollback|installer-ownership]')
case='store'
if len(sys.argv)==4:
    if sys.argv[2]!='--case':raise SystemExit('Expected --case')
    case=sys.argv[3]
cases={'store':(None,47),'rollback':('linux-gnome-owner-rollback-runtime.js',24),'installer-ownership':('linux-gnome-installer-ownership-runtime.js',13)}
if case not in cases:raise SystemExit('Unknown runtime case')
script_name,expected=cases[case]
binary=Path(sys.argv[1]).resolve(strict=True)
if not binary.is_file():raise SystemExit('Agent binary must be a regular file')
fixture=Path(__file__).resolve().with_name('linux-gnome-store-fixture.py')
baseline=os.readlink('/proc/self/ns/mnt')
args=['unshare','--mount','--propagation','private','--','python3',str(fixture),str(binary),baseline]
if script_name:args.append(script_name)
p=subprocess.run(args,capture_output=True,text=True,timeout=90)
if p.returncode:
    print(p.stdout);print(p.stderr,file=sys.stderr);raise SystemExit(p.returncode)
results=json.loads(p.stdout)
assert results['transactions']['passed']==expected and results['private_directory_removed'] and results['isolated_namespace']
print(json.dumps(results))
