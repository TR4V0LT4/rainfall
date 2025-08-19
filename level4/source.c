int m; // global variable

void p(char *s) {
    printf(s);                 // format string vuln
}

void n(void) {
    char buf[520];

    fgets(buf, 0x200, stdin);  // read input
    p(buf);                    // unsafe print

    if (m == 0x1025544) {      // check magic value
        system("/bin/cat /home/user/level5/.pass");
    }
}

int main(void) {
    n();
    return 0;
}
