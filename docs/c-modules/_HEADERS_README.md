# macOS Header Files

Header files declare public APIs - see corresponding .c/.m documentation for implementation details.

| Header | Implementation | Purpose |
|--------|----------------|---------|
| mac_bundle_detection.h | [mac_bundle_detection.c](mac_bundle_detection.md) | Bundle path detection |
| mac_logging_utils.h | [mac_logging_utils.c](mac_logging_utils.md) | Logging utilities |
| mac_plist_utils.h | [mac_plist_utils.c](mac_plist_utils.md) | Plist parsing |
| mac_tcc_detection.h | [mac_tcc_detection.c](mac_tcc_detection.md) | TCC permissions |
| mac_kvm_auth.h | [mac_kvm_auth.c](mac_kvm_auth.md) | KVM authentication |
| mac_events.h | [mac_events.c](mac_events.md) | Input events |
| mac_tile.h | [mac_tile.c](mac_tile.md) | Screen tiles |
| mac_kvm.h | [mac_kvm.c](mac_kvm.md) | Main KVM |
| mac_ui_helpers.h | Objective-C UI helpers | Cocoa utilities |

All headers use standard include guards and extern "C" for C++ compatibility where needed.
