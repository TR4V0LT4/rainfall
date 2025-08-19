int m; // global variable

void v(void) {
    char buf[520];

    fgets(buf, 0x200, stdin);   // read input
    printf(buf);                // format string vuln

    if (m == 0x40) {            // check
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");      // spawn shell
    }
}

int main(void) {
    v();
    return 0;
}
