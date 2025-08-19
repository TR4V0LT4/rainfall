#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int language = 0; // 0 = default, 1 = Finnish, 2 = Dutch

void greetuser(const char *input) {
    char greeting_prefix[4];
    char greeting_msg[64];

    if (language == 1) {
        // Finnish
        greeting_prefix[0] = 'H';
        greeting_prefix[1] = 'y';
        greeting_prefix[2] = 'v';
        greeting_prefix[3] = -0x3d;  // some UTF-8 continuation byte
        strncpy(greeting_msg, "päivää ", 11);
    } else if (language == 2) {
        // Dutch
        strncpy(greeting_prefix, "Goed", 4);
        greeting_msg[0] = 'e';
        greeting_msg[1] = 'm';
        greeting_msg[2] = 'i';
        greeting_msg[3] = 'd';
        strncpy(greeting_msg, "dag!", 4);
        greeting_msg[4] = ' ';
        greeting_msg[5] = '\0';
    } else {
        // Default / English
        strncpy(greeting_prefix, "Hell", 4);
        greeting_msg[0] = 'o';
        greeting_msg[1] = ' ';
        greeting_msg[2] = '\0';
    }

    // Append input (argv stuff) to the greeting
    strcat(greeting_prefix, input);
    puts(greeting_prefix);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 1;
    }

    char buf1[40];
    char buf2[36];

    // Clear buf1
    memset(buf1, 0, sizeof(buf1));

    // Copy user input
    strncpy(buf1, argv[1], 40);
    strncpy(buf2, argv[2], 32);

    // Detect language
    char *lang_env = getenv("LANG");
    if (lang_env) {
        if (memcmp(lang_env, "fi", 2) == 0) {
            language = 1;
        } else if (memcmp(lang_env, "nl", 2) == 0) {
            language = 2;
        }
    }

    // Stack copy (some kind of internal memory operation)
    for (int i = 0; i < 19; i++) {
        ((int *)(&buf1[i*4]))[0] = ((int *)(&buf1[i*4]))[0];
    }

    // Call greetuser with user input
    greetuser(buf1);

    return 0;
}