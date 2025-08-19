#include <stdio.h>
#include <stdlib.h>

// vulnerable helper
void run(void) {
    fwrite("Good... Wait what?\n", 1, 0x13, stdout);
    system("/bin/sh");
}

// entry point
int main(void) {
    char local_50[76];   // buffer on the stack
    gets(local_50);      // unsafe input (overflowable)
    return;
}
