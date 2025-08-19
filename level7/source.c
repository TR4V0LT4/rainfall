char c[68]; // global buffer for fgets

void n(void) {
    // hidden function – reads and prints password
    system("/bin/cat /home/user/level9/.pass");
}

void m(void *param1, int param2, char *param3, int param4, int param5) {
    time_t t;
    t = time(NULL);
    printf("%s - %ld\n", c, t);
}

int main(int argc, char **argv) {
    void **a, **b;
    FILE *f;

    // allocate 2 chunks (struct-like)
    a = malloc(8);
    *a = (void *)1;
    a[1] = malloc(8);

    b = malloc(8);
    *b = (void *)2;
    b[1] = malloc(8);

    // vulnerable copies
    strcpy((char *)a[1], argv[1]);
    strcpy((char *)b[1], argv[2]);

    // load secret password into global buffer
    f = fopen("/home/user/level8/.pass", "r");
    fgets(c, 0x44, f);

    puts("~~");
    return 0;
}
