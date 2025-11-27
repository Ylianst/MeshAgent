#include <stdio.h>
#include "mac_permissions_window.h"

int main(int argc, char* argv[]) {
    printf("Launching TCC Permissions Window...\n");

    int result = show_tcc_permissions_window();

    if (result == 1) {
        printf("User selected: Do not remind me again\n");
    } else {
        printf("User closed window normally\n");
    }

    return 0;
}
