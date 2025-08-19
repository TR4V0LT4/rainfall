int main(int argc, char **argv) {
    char buffer[40];
    int num = atoi(argv[1]);

    if (num < 10) {
        memcpy(buffer, argv[2], num * 4);

        if (num == 0x574f4c46) {   // "WOLF"
            execl("/bin/sh", "sh", NULL);
        }
        return 0;
    } else {
        return 1;
    }
}


