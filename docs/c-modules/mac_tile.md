# mac_tile.c

Screen capture and tile compression for macOS KVM, capturing display regions using CoreGraphics and compressing tiles with JPEG/PNG for efficient network transmission.

## Platform
**macOS (darwin) only** - Uses CoreGraphics CGDisplayCreateImage APIs

## Functionality
Enables remote screen viewing for KVM by:
- Capturing screen regions (tiles) using CGDisplayCreateImage()
- Compressing tiles to JPEG (fast) or PNG (lossless)
- Implementing desktop scaling/quality adjustments
- Supporting multi-display capture

### Key Functions
- **KVM_GetScreen()** - Capture single display into tiles
- **KVM_GetScreenSize()** - Get display dimensions
- **getTilesPerRow/Column()** - Calculate tile grid
- **compressTile()** - JPEG/PNG compression

## Dependencies
- `<CoreGraphics/CoreGraphics.h>` - Screen capture APIs
- `<ImageIO/ImageIO.h>` - JPEG/PNG compression
- `../../lib-jpeg-turbo/` - Optional turbo-jpeg (faster compression)
- Requires **Screen Recording permission** (macOS 10.15+)

## Performance
- JPEG quality 40-75% for network efficiency
- Tile size 256x256 or configurable
- Skips unchanged tiles (delta compression)

## Security
Requires macOS Screen Recording TCC permission for capture to work.

## Cross-References
- [mac_kvm.c](mac_kvm.md) - Main KVM that requests tiles
- [mac_tcc_detection.c](mac_tcc_detection.md) - Checks Screen Recording permission

---
**Source:** `meshcore/KVM/MacOS/mac_tile.c` | **LOC:** 546 | **Updated:** 2025-11-28
