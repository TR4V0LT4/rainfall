#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buf1[65];       // corresponds to local_98
    char buf2[66];       // corresponds to local_56
    FILE *f;

    // Open password file
    f = fopen("/home/user/end/.pass", "r");
    if (!f || argc != 2) {
        return -1;
    }

    // Clear buf1 (first 0x21 blocks of 4 bytes each)
    memset(buf1, 0, sizeof(buf1));

    // Read first part (password) from file
    fread(buf1, 1, 0x42, f);

    // Get user input index as integer
    int idx = atoi(argv[1]);

    // Null-terminate at user-specified index
    if (idx >= 0 && idx < sizeof(buf1)) {
        buf1[idx] = '\0';
    }

    // Read second part (message) from file
    fread(buf2, 1, 0x41, f);
    fclose(f);

    // Compare input (argv[1]) with password
    if (strcmp(buf1, argv[1]) == 0) {
        // If correct, spawn shell
        execl("/bin/sh", "sh", NULL);
    } else {
        // Otherwise, print message from file
        puts(buf2);
    }

    return 0;
}
