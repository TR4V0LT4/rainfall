/* call a shell and exit */
void o(void) {
    system("/bin/sh");
    _exit(1);   /* never returns */
}

/* read a line and print it (format-string vulnerability) then exit */
void n(void) {
    char buf[520];

    /* read up to 0x200 (512) chars + null */
    fgets(buf, 0x200, stdin);

    /* vulnerable: user input used directly as format string */
    printf(buf);

    /* terminate */
    exit(1);   /* never returns */
}

int main(void) {
    n();
    return 0;
}


