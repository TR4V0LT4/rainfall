
char *auth = NULL;
char *service = NULL;
char acStack_89[125]; // some service buffer

int main(void) {
    char input[5];
    char local_8b[2];

    while (1) {
        printf("%p, %p\n", auth, service);

        if (!fgets(input, sizeof(input), stdin)) {
            return 0;
        }

        // "auth" command
        if (strncmp(input, "auth", 4) == 0) {
            auth = malloc(4);
            auth[0] = auth[1] = auth[2] = auth[3] = '\0';

            if (strlen(local_8b) < 0x1f) {
                strcpy(auth, local_8b);
            }
        }

        // "reset" command
        if (strncmp(input, "reset", 5) == 0) {
            free(auth);
            auth = NULL;
        }

        // "service" command
        if (strncmp(input, "service", 6) == 0) {
            service = strdup(acStack_89);
        }

        // "login" command
        if (strncmp(input, "login", 5) == 0) {
            // vulnerable check: if auth+0x20 is nonzero → spawn shell
            if (*(int *)(auth + 0x20) != 0) {
                system("/bin/sh"); // execute shell
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }

    return 0;
}
