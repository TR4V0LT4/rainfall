char c[68]; // global buffer for fgets

void m(void *param1, int param2, char *param3, int param4, int param5) {
    time_t t;
    t = time(NULL);
    printf("%s - %ld\n", c, t);
}

int main(int argc, char **argv) {
    void **a, **b;
    FILE *f;

    // allocate 2 chunks (struct-like)
    a = malloc(8); // Chunk A
    *a = (void *)1;
    a[1] = malloc(8); // Chunk B

    b = malloc(8); // Chunk C
    *b = (void *)2;
    b[1] = malloc(8); // Chunk D

    // vulnerable copies
    strcpy((char *)a[1], argv[1]); // copy argv[1] into Chunk B
    strcpy((char *)b[1], argv[2]); // copy argv[1] into Chunk D

    // load secret password into global buffer
    f = fopen("/home/user/level8/.pass", "r");
    fgets(c, 0x44, f);

    puts("~~");
    return 0;
}
