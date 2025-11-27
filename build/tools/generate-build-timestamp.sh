#!/bin/bash
# Generate build timestamp components for consistent versioning
# Outputs shell variables that can be sourced/eval'd

set -e

# Generate timestamp once to ensure consistency
BUILD_TIMESTAMP=$(date +%y.%m.%d.%H.%M.%S)
BUILD_DATE=$(echo "$BUILD_TIMESTAMP" | cut -d. -f1-3)
BUILD_TIME_ONLY=$(echo "$BUILD_TIMESTAMP" | cut -d. -f4-6)

# Output variables in shell-sourceable format
echo "BUILD_TIMESTAMP=$BUILD_TIMESTAMP"
echo "BUILD_DATE=$BUILD_DATE"
echo "BUILD_TIME_ONLY=$BUILD_TIME_ONLY"
