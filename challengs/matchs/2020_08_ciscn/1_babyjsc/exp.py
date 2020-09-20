from pwn import *

sh = process('/usr/bin/python2', 'server.py')
sh.interactive()
