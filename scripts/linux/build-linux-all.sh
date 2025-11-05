#!/bin/bash
# Build MeshAgent for all supported Linux architectures
# Builds sequentially with clean between each arch

# Get the repository root directory (script is in scripts/linux, repo is two levels up)
REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"
cd "$REPO_DIR"

make clean
make linux ARCHID=5 -j8
make clean
make linux ARCHID=6 -j8
make clean
make linux ARCHID=7 -j8
make clean
make linux ARCHID=9 -j8
make clean
make linux ARCHID=13 -j8
make clean
make linux ARCHID=15 -j8
make clean
make linux ARCHID=18 -j8
make clean
make linux ARCHID=19 -j8
make clean
make linux ARCHID=20 -j8
make clean
make linux ARCHID=24 -j8
make clean
make linux ARCHID=25 -j8
make clean