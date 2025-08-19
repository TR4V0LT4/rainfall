#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void n(void) {
    // Secret function: prints the password
    system("/bin/cat /home/user/level7/.pass");
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5) {
    // Default function pointer target
    puts("Nope");
}

int main(int argc, char **argv) {
    char *buf;        // malloc(0x40) = 64 bytes
    void (**fp)();    // malloc(4) = pointer to function

    buf = malloc(0x40);   // buffer for strcpy
    fp = malloc(4);       // function pointer storage

    *fp = (void (*)())m;  // initialize function pointer to m

    strcpy(buf, argv[1]); // unsafe copy → buffer overflow possible

    (*fp)();              // call the function pointer (m or overwritten)
    return 0;
}
