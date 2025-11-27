#import <Cocoa/Cocoa.h>
#import "mac_install_window.h"
#include <stdio.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        printf("=== MeshAgent Installation Assistant Test ===\n\n");

        InstallResult result = show_install_assistant_window();

        printf("\n=== Installation Assistant Result ===\n");
        if (result.cancelled) {
            printf("User cancelled installation\n");
        } else {
            printf("Mode: %s\n", result.mode == INSTALL_MODE_UPGRADE ? "UPGRADE" : "NEW INSTALL");
            printf("Install Path: %s\n", result.installPath);
            if (result.mode == INSTALL_MODE_NEW) {
                printf("MSH File: %s\n", result.mshFilePath);
            }

            printf("\nCommand that would be executed:\n");
            if (result.mode == INSTALL_MODE_UPGRADE) {
                printf("sudo meshagent -upgrade --installPath=\"%s\"\n", result.installPath);
            } else {
                printf("sudo meshagent -install --installPath=\"%s\" --mshPath=\"%s\"\n",
                       result.installPath, result.mshFilePath);
            }
        }
    }
    return 0;
}
