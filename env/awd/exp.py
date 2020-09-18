#!/usr/bin/env python3
#-*- coding:utf-8 -*-
# author: i0gan
# a script for awd exp
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

elf_path  = 'pwn'
arch = '64'
libc_v = '2.27'
MODIFY_LD = 0
LOCAL = 0
LIBC  = 0

if(len(sys.argv) < 3):
	LOCAL = 1
	context.log_level='debug'
else:
	server_ip = sys.argv[1]
	server_port = int(sys.argv[2], 10)

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

#--------------------------func-----------------------------
def db():
	if(LOCAL):
		gdb.attach(io)

def cat_flag(io):
	sleep(1)
	sl('cat flag')
	flag = b'flag{'  + ru('}') + b'}'
	wd  = flag
	wd += b'\n'
	fd = open('./flags', 'a')
	fd.write(wd.decode())
	fd.close()

#--------------------------exploit--------------------------
def exploit():
	li('exploit...')
	
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
