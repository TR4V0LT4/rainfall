#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <number>\n", argv[0]);
        return 1;
    }

    int input = atoi(argv[1]);

    if (input != 0x1a7) {  // 423  in decimal
        fprintf(stderr, "No !\n");
        return 1;
    }
    
    // If the number is correct, give a shell
    execl("/bin/sh", "/bin/sh", NULL);

    // If exec fails
    perror("execl");
    return 1;
}
