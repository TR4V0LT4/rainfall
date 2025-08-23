<h1 align="center"> BONUS 3 </h1>

## 🔍 Analysis of Decompiled [bonus3](./source.c)
The bonus3 binary is designed to read a password from a file, then compare user input against the password to either spawn a shell or display a message.
## 💥 Exploit

- buf1 (65 bytes) stores the first part of the password.
- buf2 (66 bytes) stores the second part of the password.
- The program converts the user argument (argv[1]) to an integer:
    - int idx = atoi(argv[1]);
    - It then does: buf1[idx] = '\0';.
    - This null-termination is intended to truncate buf1 at a certain point.
- strcmp compares the password in buf1 to argv[1]. If the input is an empty string "", the function behaves unexpectedly:
    - atoi("") returns 0, so buf1[0] = '\0' — truncating the password to an empty string.
    - strcmp(buf1, argv[1]) becomes strcmp("", ""), which returns 0, so the condition is true.

This bypasses the need for knowing the password.

```sh
./bonus3 ""
$ whoami
end
```
