void p(void) {
    char buffer[76];   // Local buffer (76 bytes)
    unsigned int ret;  // Return address (saved EIP)

    fflush(stdout);    // Flush stdout before input
    gets(buffer);      // UNSAFE: allows buffer overflow

    // Check the saved return address (EIP after p() returns)
    // If it starts with 0xb..., program exits. (Stack execution protection)
    ret = __builtin_return_address(0);  
    if ((ret & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", (void*)ret);
        _exit(1);
    }

    // Otherwise, print input and duplicate string
    puts(buffer);
    strdup(buffer);
}

int main(void) {
    p();
    return 0;
}